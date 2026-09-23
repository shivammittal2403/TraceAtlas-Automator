from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import ssl
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .events import Event, child


class SpiderModule(ABC):
    name = "base"
    description = ""
    watches: frozenset[str] = frozenset()
    produces: frozenset[str] = frozenset()
    passive = True

    @abstractmethod
    def handle(self, event: Event) -> list[Event]:
        raise NotImplementedError


def _public_host(host: str) -> bool:
    """Deny local/private network pivots to reduce SSRF and accidental scope expansion."""
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False
    for raw in addresses:
        addr = ipaddress.ip_address(raw)
        if not addr.is_global:
            return False
    return bool(addresses)


class EmailDomain(SpiderModule):
    name = "email_domain"
    description = "Extract the domain from a syntactically valid email address."
    watches = frozenset({"EMAIL_ADDRESS"})
    produces = frozenset({"DOMAIN"})

    def handle(self, event: Event) -> list[Event]:
        value = str(event.data).strip()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            return []
        return [child(event, "DOMAIN", value.rsplit("@", 1)[1].lower(), self.name, confidence=95)]


class URLDomain(SpiderModule):
    name = "url_domain"
    description = "Extract a normalized domain from a public HTTP(S) URL."
    watches = frozenset({"URL"})
    produces = frozenset({"DOMAIN"})

    def handle(self, event: Event) -> list[Event]:
        parsed = urlparse(str(event.data))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return []
        return [child(event, "DOMAIN", parsed.hostname.lower(), self.name, confidence=100)]


class DomainURL(SpiderModule):
    name = "domain_url"
    description = "Create the canonical HTTPS URL for a public domain seed."
    watches = frozenset({"DOMAIN"})
    produces = frozenset({"URL"})

    def handle(self, event: Event) -> list[Event]:
        host = str(event.data).strip().lower()
        if not _public_host(host):
            return []
        return [child(event, "URL", f"https://{host}/", self.name, confidence=95)]


class DNSResolve(SpiderModule):
    name = "dns_resolve"
    description = "Resolve public domain/hostname events to IP address events."
    watches = frozenset({"DOMAIN", "HOSTNAME"})
    produces = frozenset({"IP_ADDRESS"})

    def handle(self, event: Event) -> list[Event]:
        try:
            addresses = sorted({x[4][0] for x in socket.getaddrinfo(str(event.data), None)})
        except socket.gaierror:
            return []
        output = []
        for address in addresses:
            addr = ipaddress.ip_address(address)
            output.append(child(
                event, "IP_ADDRESS", address, self.name, confidence=90,
                risk="medium" if not addr.is_global else "info",
                tags=["non-public"] if not addr.is_global else ["dns"],
            ))
        return output


class ReverseDNS(SpiderModule):
    name = "reverse_dns"
    description = "Resolve PTR names for public IP addresses."
    watches = frozenset({"IP_ADDRESS"})
    produces = frozenset({"HOSTNAME"})

    def handle(self, event: Event) -> list[Event]:
        addr = ipaddress.ip_address(str(event.data))
        if not addr.is_global:
            return []
        try:
            hostname = socket.gethostbyaddr(str(addr))[0].rstrip(".").lower()
        except (socket.herror, socket.gaierror):
            return []
        return [child(event, "HOSTNAME", hostname, self.name, confidence=70, tags=["ptr"])]


class TLSCertificate(SpiderModule):
    name = "tls_certificate"
    description = "Read the public TLS certificate without sending application data."
    watches = frozenset({"DOMAIN", "HOSTNAME"})
    produces = frozenset({"TLS_CERTIFICATE", "CERTIFICATE_NAME"})

    def handle(self, event: Event) -> list[Event]:
        host = str(event.data)
        if not _public_host(host):
            return []
        try:
            with socket.create_connection((host, 443), timeout=6) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as conn:
                    cert = conn.getpeercert()
        except (OSError, ssl.SSLError):
            return []
        summary = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "notBefore": cert.get("notBefore"), "notAfter": cert.get("notAfter"),
        }
        output = [child(event, "TLS_CERTIFICATE", summary, self.name, confidence=90)]
        for kind, name in cert.get("subjectAltName", [])[:50]:
            if kind == "DNS":
                output.append(child(event, "CERTIFICATE_NAME", name.lower(), self.name,
                                    confidence=90, tags=["san"]))
        return output


class HTTPSnapshot(SpiderModule):
    name = "http_snapshot"
    description = "Fetch up to 1 MiB from public HTTP(S) targets and emit metadata."
    watches = frozenset({"URL"})
    produces = frozenset({"HTTP_RESPONSE", "TECHNOLOGY", "LINKED_URL"})

    def handle(self, event: Event) -> list[Event]:
        url = str(event.data)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or not _public_host(parsed.hostname):
            return []
        request = Request(url, headers={"User-Agent": "TraceAtlas-Spider/0.2"})
        try:
            with urlopen(request, timeout=10) as response:
                body = response.read(1024 * 1024)
                status, final_url, headers = response.status, response.geturl(), dict(response.headers.items())
        except HTTPError as exc:
            body, status, final_url, headers = exc.read(1024 * 1024), exc.code, exc.geturl(), dict(exc.headers.items())
        except URLError:
            return []
        metadata = {
            "requested_url": url, "final_url": final_url, "status": status,
            "content_type": headers.get("Content-Type"), "sample_size": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "security_headers": {k: v for k, v in headers.items() if k.lower() in {
                "strict-transport-security", "content-security-policy", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy"
            }},
        }
        output = [child(event, "HTTP_RESPONSE", metadata, self.name, confidence=90)]
        for key in ("Server", "X-Powered-By", "Via", "X-Generator"):
            if headers.get(key):
                output.append(child(event, "TECHNOLOGY", {"header": key, "value": headers[key]},
                                    self.name, confidence=60))
        if final_url != url:
            output.append(child(event, "LINKED_URL", final_url, self.name, confidence=95,
                                tags=["redirect"]))
        return output


class FileMetadata(SpiderModule):
    name = "file_metadata"
    description = "Hash a local file and emit basic metadata."
    watches = frozenset({"FILE"})
    produces = frozenset({"FILE_HASH", "FILE_METADATA"})

    def handle(self, event: Event) -> list[Event]:
        path = Path(str(event.data))
        if not path.is_file():
            return []
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return [
            child(event, "FILE_HASH", {"algorithm": "sha256", "value": digest.hexdigest()},
                  self.name, confidence=100),
            child(event, "FILE_METADATA", {"name": path.name, "size": path.stat().st_size,
                  "suffix": path.suffix.lower()}, self.name, confidence=100),
        ]


class UsernamePivots(SpiderModule):
    name = "username_pivots"
    description = "Generate unverified candidate account URLs without scraping platforms."
    watches = frozenset({"USERNAME"})
    produces = frozenset({"ACCOUNT_CANDIDATE"})

    def handle(self, event: Event) -> list[Event]:
        name = str(event.data)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            return []
        sites = {"github": f"https://github.com/{name}", "reddit": f"https://www.reddit.com/user/{name}"}
        return [child(event, "ACCOUNT_CANDIDATE", {"platform": site, "url": url}, self.name,
                      confidence=25, tags=["unverified", "candidate"]) for site, url in sites.items()]


MODULES: dict[str, SpiderModule] = {
    module.name: module for module in (
        EmailDomain(), URLDomain(), DomainURL(), DNSResolve(), ReverseDNS(), TLSCertificate(),
        HTTPSnapshot(), FileMetadata(), UsernamePivots(),
    )
}
