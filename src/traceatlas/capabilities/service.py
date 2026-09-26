from __future__ import annotations

import json
import os
import re
from ipaddress import ip_address
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from ..policy import PolicyError, validate_target


MAX_SERVICE_BYTES = 4 * 1024 * 1024
CRAWL4AI_FORBIDDEN = {"hooks", "js_code", "cookies", "headers", "proxy_config", "session_id", "user_agent"}
FIRECRAWL_ACTIONS = {"search", "scrape", "map", "extract"}
SCRAPEGRAPH_FORBIDDEN = {
    "script", "script_code", "code", "cookies", "headers", "proxy", "proxy_config",
    "browser_profile", "session_id", "credentials", "api_key",
}


class ServiceClient:
    """Bounded HTTP bridge for separately deployed acquisition workers."""

    @staticmethod
    def _loopback_base(value: str) -> str:
        parsed = urlparse(value.rstrip("/"))
        if parsed.scheme != "http" or not parsed.hostname:
            raise PolicyError("Local worker URL must use HTTP and include a host")
        try:
            address = ip_address(parsed.hostname)
        except ValueError:
            address = None
        if parsed.hostname != "localhost" and not (address and address.is_loopback):
            raise PolicyError("Acquisition workers must bind to a loopback URL")
        return value.rstrip("/")

    @staticmethod
    def _public_url(value: str) -> None:
        validate_target("url", value)
        parsed = urlparse(value)
        assert parsed.hostname is not None
        if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
            raise PolicyError("Localhost acquisition targets are blocked")
        try:
            address = ip_address(parsed.hostname)
        except ValueError:
            address = None
        if address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
            raise PolicyError("Private, loopback, link-local and reserved acquisition targets are blocked")

    @staticmethod
    def _post(url: str, payload: dict[str, Any], headers: dict[str, str], timeout: int) -> Any:
        body = json.dumps(payload, separators=(",", ":")).encode()
        if len(body) > 256 * 1024:
            raise PolicyError("Service payload exceeds 256 KiB")
        request = Request(url, data=body, headers={"Content-Type": "application/json", **headers}, method="POST")
        try:
            with urlopen(request, timeout=max(2, min(timeout, 120))) as response:
                raw = response.read(MAX_SERVICE_BYTES + 1)
        except HTTPError as exc:
            raise ValueError(f"Worker returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise ValueError(f"Worker connection failed: {exc.reason}") from exc
        if len(raw) > MAX_SERVICE_BYTES:
            raise ValueError("Worker response exceeds 4 MiB")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Worker returned invalid JSON") from exc

    @staticmethod
    def _get(url: str, timeout: int, headers: dict[str, str] | None = None) -> Any:
        request = Request(url, headers={"Accept": "application/json", **(headers or {})}, method="GET")
        try:
            with urlopen(request, timeout=max(2, min(timeout, 120))) as response:
                raw = response.read(MAX_SERVICE_BYTES + 1)
        except HTTPError as exc:
            raise ValueError(f"Worker returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise ValueError(f"Worker connection failed: {exc.reason}") from exc
        if len(raw) > MAX_SERVICE_BYTES:
            raise ValueError("Worker response exceeds 4 MiB")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Worker returned invalid JSON") from exc

    @classmethod
    def crawl4ai(cls, target: str, options: dict[str, Any], timeout: int = 60) -> Any:
        cls._public_url(target)
        forbidden = CRAWL4AI_FORBIDDEN.intersection(options)
        if forbidden:
            raise PolicyError("Unsafe Crawl4AI option(s): " + ", ".join(sorted(forbidden)))
        base = cls._loopback_base(os.environ.get("CRAWL4AI_URL", "http://127.0.0.1:11235"))
        return cls._post(base + "/crawl", {"url": target, **options}, {}, timeout)

    @classmethod
    def firecrawl(cls, action: str, target: str, options: dict[str, Any], timeout: int = 60) -> Any:
        if action not in FIRECRAWL_ACTIONS:
            raise PolicyError("Unsupported Firecrawl action")
        key = os.environ.get("FIRECRAWL_API_KEY")
        if not key:
            raise PolicyError("FIRECRAWL_API_KEY is not configured")
        if action == "search":
            if not 2 <= len(target.strip()) <= 500:
                raise PolicyError("Search query must be 2-500 characters")
            payload = {"query": target, **options}
        else:
            cls._public_url(target)
            payload = {"url": target, **options}
        base = os.environ.get("FIRECRAWL_URL", "https://api.firecrawl.dev/v1").rstrip("/")
        parsed = urlparse(base)
        if parsed.scheme != "https" or parsed.hostname not in {"api.firecrawl.dev"}:
            raise PolicyError("FIRECRAWL_URL must be the approved HTTPS service endpoint")
        return cls._post(base + "/" + action, payload, {"Authorization": f"Bearer {key}"}, timeout)

    @classmethod
    def searxng(cls, query: str, options: dict[str, Any], timeout: int = 60) -> Any:
        if not 2 <= len(query.strip()) <= 500:
            raise PolicyError("Search query must be 2-500 characters")
        allowed = {"categories", "language", "time_range", "safesearch", "pageno", "engines"}
        unknown = set(options) - allowed
        if unknown:
            raise PolicyError("Unsupported SearXNG option(s): " + ", ".join(sorted(unknown)))
        params: dict[str, Any] = {"q": query.strip(), "format": "json", **options}
        if int(params.get("pageno", 1)) not in range(1, 11):
            raise PolicyError("SearXNG page must be between 1 and 10")
        if str(params.get("safesearch", "1")) not in {"0", "1", "2"}:
            raise PolicyError("SearXNG safesearch must be 0, 1 or 2")
        base = cls._loopback_base(os.environ.get("SEARXNG_URL", "http://127.0.0.1:8080"))
        return cls._get(base + "/search?" + urlencode(params), timeout)

    @classmethod
    def scrapegraph(cls, target: str, options: dict[str, Any], timeout: int = 60) -> Any:
        cls._public_url(target)
        forbidden = SCRAPEGRAPH_FORBIDDEN.intersection(key.lower() for key in options)
        if forbidden:
            raise PolicyError("Unsafe ScrapeGraphAI option(s): " + ", ".join(sorted(forbidden)))
        allowed = {"prompt", "schema", "model", "max_pages"}
        unknown = set(options) - allowed
        if unknown:
            raise PolicyError("Unsupported ScrapeGraphAI option(s): " + ", ".join(sorted(unknown)))
        if len(str(options.get("prompt", ""))) > 4000:
            raise PolicyError("ScrapeGraphAI prompt exceeds 4,000 characters")
        if int(options.get("max_pages", 1)) not in range(1, 11):
            raise PolicyError("ScrapeGraphAI max_pages must be between 1 and 10")
        base = cls._loopback_base(os.environ.get("SCRAPEGRAPH_URL", "http://127.0.0.1:8001"))
        return cls._post(base + "/extract", {"url": target, **options}, {}, timeout)

    @staticmethod
    def _intelowl_base(value: str) -> str:
        parsed = urlparse(value.rstrip("/"))
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PolicyError("INTELOWL_URL must be a clean service base URL")
        try:
            address = ip_address(parsed.hostname)
        except ValueError:
            address = None
        if parsed.scheme == "http" and (
            parsed.hostname == "localhost" or (address and address.is_loopback)
        ):
            return value.rstrip("/")
        approved = {
            host.strip().lower() for host in os.environ.get("TRACEATLAS_SERVICE_HOSTS", "").split(",")
            if host.strip()
        }
        if parsed.scheme != "https" or parsed.hostname.lower() not in approved:
            raise PolicyError(
                "Remote IntelOwl requires HTTPS and its hostname in TRACEATLAS_SERVICE_HOSTS"
            )
        return value.rstrip("/")

    @staticmethod
    def _misp_base(value: str) -> str:
        parsed = urlparse(value.rstrip("/"))
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PolicyError("MISP_URL must be a clean service base URL")
        try:
            address = ip_address(parsed.hostname)
        except ValueError:
            address = None
        if parsed.scheme == "http" and (
            parsed.hostname == "localhost" or (address and address.is_loopback)
        ):
            return value.rstrip("/")
        approved = {
            host.strip().lower() for host in os.environ.get("TRACEATLAS_SERVICE_HOSTS", "").split(",")
            if host.strip()
        }
        if parsed.scheme != "https" or parsed.hostname.lower() not in approved:
            raise PolicyError("Remote MISP requires HTTPS and its hostname in TRACEATLAS_SERVICE_HOSTS")
        return value.rstrip("/")

    @classmethod
    def intelowl(cls, target: str, options: dict[str, Any], timeout: int = 60) -> Any:
        """Submit one bounded observable to a separately deployed IntelOwl service."""
        allowed = {"observable_classification", "analyzers_requested", "connectors_requested", "tlp"}
        unknown = set(options) - allowed
        if unknown:
            raise PolicyError("Unsupported IntelOwl option(s): " + ", ".join(sorted(unknown)))
        classification = str(options.get("observable_classification", "")).lower()
        if classification not in {"domain", "ip", "url", "hash"}:
            raise PolicyError("IntelOwl observable_classification is invalid")
        if classification == "url":
            cls._public_url(target)
        elif classification in {"domain", "ip"}:
            validate_target(classification, target)
            if classification == "ip" and not ip_address(target).is_global:
                raise PolicyError("IntelOwl accepts public IPs only")
        elif classification == "hash":
            if len(target) not in {32, 40, 64} or not re.fullmatch(r"[0-9a-fA-F]+", target):
                raise PolicyError("IntelOwl hash must be MD5, SHA-1 or SHA-256")
            target = target.lower()
        analyzers = options.get("analyzers_requested")
        connectors = options.get("connectors_requested", [])
        name_pattern = re.compile(r"[A-Za-z0-9_.:-]{1,96}")
        if not isinstance(analyzers, list) or not 1 <= len(analyzers) <= 25:
            raise PolicyError("IntelOwl requires 1-25 explicit analyzers_requested")
        if not all(isinstance(name, str) and name_pattern.fullmatch(name) for name in analyzers):
            raise PolicyError("IntelOwl analyzer names are invalid")
        if not isinstance(connectors, list) or len(connectors) > 10 or not all(
            isinstance(name, str) and name_pattern.fullmatch(name) for name in connectors
        ):
            raise PolicyError("IntelOwl connector names are invalid")
        tlp = str(options.get("tlp", "AMBER")).upper()
        if tlp not in {"CLEAR", "GREEN", "AMBER", "RED"}:
            raise PolicyError("IntelOwl TLP is invalid")
        key = os.environ.get("INTELOWL_API_KEY")
        if not key or len(key) > 512 or any(char.isspace() for char in key):
            raise PolicyError("INTELOWL_API_KEY is not configured correctly")
        base = cls._intelowl_base(os.environ.get("INTELOWL_URL", "http://127.0.0.1:80"))
        payload = {
            "observable_name": target.strip(),
            "observable_classification": classification,
            "analyzers_requested": analyzers,
            "connectors_requested": connectors,
            "tlp": tlp,
        }
        return cls._post(
            base + "/api/analyze_observable", payload,
            {"Authorization": f"Token {key}"}, timeout,
        )

    @classmethod
    def intelowl_analyzer_configs(cls, timeout: int = 30) -> Any:
        """Discover exact analyzer names and observable contracts from IntelOwl."""
        key = os.environ.get("INTELOWL_API_KEY")
        if not key or len(key) > 512 or any(char.isspace() for char in key):
            raise PolicyError("INTELOWL_API_KEY is not configured correctly")
        base = cls._intelowl_base(os.environ.get("INTELOWL_URL", "http://127.0.0.1:80"))
        return cls._get(
            base + "/api/get_analyzer_configs", timeout,
            {"Authorization": f"Token {key}"},
        )

    @classmethod
    def misp(cls, target: str, options: dict[str, Any], timeout: int = 60) -> Any:
        """Search one exact owned observable in an operator-controlled MISP instance."""
        allowed = {"observable_classification", "publish_timestamp", "tags", "limit", "page", "to_ids"}
        unknown = set(options) - allowed
        if unknown:
            raise PolicyError("Unsupported MISP option(s): " + ", ".join(sorted(unknown)))
        classification = str(options.get("observable_classification", "")).lower()
        if classification == "url":
            cls._public_url(target)
            attribute_type = "url"
        elif classification in {"domain", "ip"}:
            validate_target(classification, target)
            if classification == "ip" and not ip_address(target).is_global:
                raise PolicyError("MISP accepts public IPs only")
            attribute_type = "domain" if classification == "domain" else "ip-dst"
        elif classification == "hash":
            if len(target) not in {32, 40, 64} or not re.fullmatch(r"[0-9a-fA-F]+", target):
                raise PolicyError("MISP hash must be MD5, SHA-1 or SHA-256")
            target = target.lower()
            attribute_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(target)]
        else:
            raise PolicyError("MISP observable_classification is invalid")
        limit = options.get("limit", 100)
        page = options.get("page", 1)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise PolicyError("MISP limit must be between 1 and 500")
        if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= 20:
            raise PolicyError("MISP page must be between 1 and 20")
        published = str(options.get("publish_timestamp", "30d"))
        if not re.fullmatch(r"\d{1,4}[dhm]", published):
            raise PolicyError("MISP publish_timestamp must be a bounded duration such as 30d")
        tags = options.get("tags", [])
        if not isinstance(tags, list) or len(tags) > 10 or not all(
            isinstance(tag, str) and re.fullmatch(r"[A-Za-z0-9_.:+! -]{1,96}", tag) for tag in tags
        ):
            raise PolicyError("MISP tags must be a list of up to ten safe tag names")
        key = os.environ.get("MISP_API_KEY", "")
        if not key or len(key) > 512 or any(char.isspace() for char in key):
            raise PolicyError("MISP_API_KEY is not configured correctly")
        base = cls._misp_base(os.environ.get("MISP_URL", "http://127.0.0.1:8081"))
        payload = {
            "returnFormat": "json", "value": target.strip(), "type": attribute_type,
            "publish_timestamp": published, "limit": limit, "page": page,
            "to_ids": bool(options.get("to_ids", True)), "enforceWarninglist": True,
            "includeEventTags": True, "withAttachments": False,
        }
        if tags:
            payload["tags"] = tags
        return cls._post(
            base + "/attributes/restSearch", payload,
            {"Authorization": key, "Accept": "application/json"}, timeout,
        )
