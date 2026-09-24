from __future__ import annotations

import json
import os
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
    def _get(url: str, timeout: int) -> Any:
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
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
