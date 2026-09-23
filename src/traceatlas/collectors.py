from __future__ import annotations

import email
import hashlib
import json
import os
import platform
import socket
import ssl
from email import policy
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen

from .models import Finding
from .policy import Target


Collector = Callable[[Target], list[Finding]]


def _url(target: Target) -> str:
    return target.value if target.kind == "url" else f"https://{target.value}"


def dns(target: Target) -> list[Finding]:
    host = urlparse(_url(target)).hostname or target.value
    findings: list[Finding] = []
    try:
        records = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        findings.append(Finding("Resolved addresses", records, f"dns://{host}", 90))
    except socket.gaierror as exc:
        findings.append(Finding("DNS resolution failed", str(exc), f"dns://{host}", 80, "low"))
    return findings


def tls(target: Target) -> list[Finding]:
    host = urlparse(_url(target)).hostname or target.value
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
        value = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "notBefore": cert.get("notBefore"), "notAfter": cert.get("notAfter"),
            "subjectAltName": cert.get("subjectAltName", [])[:25],
        }
        return [Finding("TLS certificate", value, f"tls://{host}:443", 90)]
    except (OSError, ssl.SSLError) as exc:
        return [Finding("TLS inspection failed", str(exc), f"tls://{host}:443", 70, "low")]


def http(target: Target) -> list[Finding]:
    url = _url(target)
    req = Request(url, headers={"User-Agent": "TraceAtlas-Automator/0.1 (+evidence-first OSINT)"})
    try:
        with urlopen(req, timeout=12) as response:
            body = response.read(1024 * 1024)
            final_url = response.geturl()
            headers = dict(response.headers.items())
            status = response.status
    except HTTPError as exc:
        body, final_url, headers, status = exc.read(1024 * 1024), exc.geturl(), dict(exc.headers.items()), exc.code
    except URLError as exc:
        return [Finding("HTTP collection failed", str(exc.reason), url, 75, "low")]
    tech = []
    signature_headers = {"server", "x-powered-by", "via", "x-generator"}
    for key, value in headers.items():
        if key.lower() in signature_headers:
            tech.append(f"{key}: {value}")
    value = {
        "requested_url": url, "final_url": final_url, "status": status,
        "content_type": headers.get("Content-Type"), "content_length_sampled": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(), "technology_hints": tech,
        "security_headers": {k: v for k, v in headers.items() if k.lower() in {
            "strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options", "referrer-policy", "permissions-policy"
        }},
    }
    return [Finding("HTTP snapshot", value, final_url, 85)]


def file_metadata(target: Target) -> list[Finding]:
    path = Path(target.value)
    stat = path.stat()
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    digest = hasher.hexdigest()
    value = {
        "name": path.name, "size": stat.st_size, "sha256": digest,
        "modified_epoch": stat.st_mtime, "suffix": path.suffix.lower(),
    }
    return [Finding("File metadata", value, str(path.resolve()), 100)]


def email_basic(target: Target) -> list[Finding]:
    local, domain = target.value.rsplit("@", 1)
    return [Finding("Email structure", {
        "domain": domain.lower(), "local_length": len(local),
        "plus_alias": "+" in local, "normalized_domain": domain.encode("idna").decode(),
    }, "local-validation", 100)]


def email_headers(target: Target) -> list[Finding]:
    raw = Path(target.value).read_bytes()
    msg = email.message_from_bytes(raw, policy=policy.default)
    auth = {key: msg.get_all(key, []) for key in (
        "Received", "Authentication-Results", "Received-SPF", "DKIM-Signature",
        "From", "To", "Date", "Message-ID", "Return-Path"
    )}
    return [Finding("Parsed email headers", auth, str(Path(target.value).resolve()), 95,
                    observation="Header presence is evidence; attribution still needs corroboration.")]


def ip_basic(target: Target) -> list[Finding]:
    import ipaddress
    addr = ipaddress.ip_address(target.value)
    try:
        reverse = socket.gethostbyaddr(target.value)[0]
    except socket.herror:
        reverse = None
    return [Finding("IP properties", {
        "version": addr.version, "is_private": addr.is_private,
        "is_global": addr.is_global, "is_reserved": addr.is_reserved,
        "reverse_dns": reverse,
    }, f"ip://{addr}", 95)]


def username_links(target: Target) -> list[Finding]:
    name = quote_plus(target.value)
    sites = {
        "GitHub": f"https://github.com/{name}", "Reddit": f"https://www.reddit.com/user/{name}",
        "Mastodon lookup": f"https://mastodon.social/@{name}",
    }
    return [Finding("Candidate profile pivots", sites, "generated-pivots", 35,
                    observation="URLs are candidates, not proof of common ownership.")]


def archive_links(target: Target) -> list[Finding]:
    url = quote_plus(_url(target))
    return [Finding("Archive pivots", {
        "Wayback index": f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&filter=statuscode:200",
        "Wayback calendar": f"https://web.archive.org/web/*/{url}",
    }, "generated-pivots", 80)]


def search_queries(target: Target) -> list[Finding]:
    escaped = target.value.replace('"', "")
    queries = [f'"{escaped}"', f'"{escaped}" -site:facebook.com -site:pinterest.com']
    if target.kind in {"domain", "url"}:
        domain = urlparse(_url(target)).hostname or escaped
        queries.extend([f"site:{domain}", f'"{domain}" (fraud OR scam OR breach)'])
    return [Finding("Reproducible search queries", queries, "generated-queries", 100)]


def environment_check(target: Target) -> list[Finding]:
    checks = {
        "platform": platform.platform(), "python": platform.python_version(),
        "running_as_root": getattr(os, "geteuid", lambda: -1)() == 0,
        "proxy_configured": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
        "recommended_controls": [
            "Separate research browser profile", "Encrypted case storage",
            "No subject contact without approval", "VPN/Tor only when policy permits",
            "Record collection timestamps and provenance",
        ],
    }
    return [Finding("Research environment review", checks, "local-environment", 90)]


def timeline(target: Target) -> list[Finding]:
    if target.kind != "file":
        return [Finding("Timeline template", ["timestamp", "timezone", "event", "source", "confidence"],
                        "generated-template", 100)]
    data = json.loads(Path(target.value).read_text(encoding="utf-8"))
    events = data if isinstance(data, list) else data.get("events", [])
    ordered = sorted(events, key=lambda x: str(x.get("timestamp", "")))
    return [Finding("Normalized timeline", ordered, str(Path(target.value).resolve()), 80)]


COLLECTORS: dict[str, Collector] = {
    "dns": dns, "tls": tls, "http": http, "file_metadata": file_metadata,
    "email_basic": email_basic, "email_headers": email_headers, "ip_basic": ip_basic,
    "username_links": username_links, "archive_links": archive_links,
    "search_queries": search_queries, "environment_check": environment_check,
    "timeline": timeline,
}
