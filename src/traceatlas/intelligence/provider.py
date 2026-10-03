from __future__ import annotations

import json
import hashlib
import time
import urllib.error
from dataclasses import dataclass
from typing import Any, Callable


Requester = Callable[[str, dict[str, str], int], tuple[int, bytes]]
Sleeper = Callable[[float], None]


class ProviderError(RuntimeError):
    """Secret-safe connector failure with stable operational classification."""

    def __init__(self, code: str, *, retryable: bool = False, attempts: int = 0):
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.attempts = attempts


@dataclass(frozen=True, slots=True)
class ProviderResult:
    data: dict[str, Any] | list[Any]
    attempts: int
    bytes_received: int
    response_sha256: str
    raw: bytes | None = None


def _validate_shape(source: str, data: Any) -> None:
    """Reject provider error pages and schema drift before evidence ingestion."""
    valid = isinstance(data, (dict, list))
    if source == "gleif":
        rows = data.get("data") if isinstance(data, dict) else None
        rows = [rows] if isinstance(rows, dict) else rows
        valid = isinstance(rows, list) and len(rows) <= 3 and all(
            isinstance(r, dict) and isinstance(r.get("id"), str) and isinstance(r.get("attributes"), dict)
            and isinstance(r["attributes"].get("entity"), dict) for r in rows)
    elif source == "ripestat":
        value = data.get("data") if isinstance(data, dict) else None
        valid = isinstance(value, dict) and data.get("status") == "ok" and isinstance(value.get("asns"), list) and isinstance(value.get("prefix"), str)
    elif source == "epss":
        rows = data.get("data") if isinstance(data, dict) else None
        valid = isinstance(rows, list) and len(rows) <= 1 and data.get("status") == "OK"
        if valid:
            try:
                valid = all(isinstance(r, dict) and isinstance(r.get("cve"), str)
                            and 0 <= float(r["epss"]) <= 1 and isinstance(r.get("date"), str) for r in rows)
            except (ValueError, TypeError, KeyError):
                valid = False
    elif source == "osv":
        valid = isinstance(data, dict) and isinstance(data.get("id"), str) and isinstance(data.get("modified"), str) and isinstance(data.get("affected"), list)
    elif source == "github":
    if source in {"cloudflare_dns", "crtsh", "ripestat", "gleif", "companieshouse", "sec", "opencorporates"}:
        from .registry_requests import validate_shape
        validate_shape(source, data)
        return
    if source == "github":
        valid = isinstance(data, dict) and isinstance(data.get("login"), str)
    elif source == "youtube":
        valid = isinstance(data, dict) and isinstance(data.get("items"), list)
    elif source == "discord":
        valid = isinstance(data, dict) and isinstance(data.get("code"), str)
    elif source == "shodan":
        valid = isinstance(data, dict) and isinstance(data.get("ip_str"), str)
    elif source == "censys":
        valid = isinstance(data, dict) and isinstance(data.get("result"), dict)
    elif source == "virustotal":
        valid = isinstance(data, dict) and isinstance(data.get("data"), dict)
    elif source == "rdap":
        valid = isinstance(data, dict) and isinstance(data.get("objectClassName"), str)
    elif source == "rdap_bootstrap":
        valid = isinstance(data, dict) and data.get("version") == "1.0" and isinstance(data.get("services"), list)
    elif source == "urlscan":
        valid = isinstance(data, dict) and isinstance(data.get("results"), list) and len(data["results"]) <= 20
    elif source == "brave":
        valid = (isinstance(data, dict) and isinstance(data.get("query"), dict)
                 and isinstance(data["query"].get("original"), str)
                 and isinstance(data.get("web", {}), dict)
                 and isinstance(data.get("web", {}).get("results", []), list)
                 and len(data.get("web", {}).get("results", [])) <= 10)
    elif source == "searxng":
        valid = (isinstance(data, dict) and isinstance(data.get("query"), str)
                 and isinstance(data.get("results"), list) and len(data["results"]) <= 100)
    elif source == "dns":
        valid = isinstance(data, dict) and isinstance(data.get("Status"), int)
    elif source == "wayback":
        valid = (
            isinstance(data, list) and (not data or isinstance(data[0], list))
            and len(data) <= 101
        )
    elif source == "internetdb":
        valid = isinstance(data, dict) and isinstance(data.get("ip"), str)
    elif source == "ipwhois":
        if isinstance(data, dict) and data.get("success") is False:
            raise ProviderError("provider_record_not_found")
        valid = (
            isinstance(data, dict) and data.get("success") is True
            and isinstance(data.get("ip"), str)
        )
    elif source == "ipdata":
        valid = isinstance(data, dict) and isinstance(data.get("ip"), str)
    elif source == "greynoise":
        valid = (
            isinstance(data, dict) and isinstance(data.get("ip"), str)
            and isinstance(data.get("noise"), bool) and isinstance(data.get("riot"), bool)
            and data.get("classification") in {"benign", "malicious", "unknown"}
        )
    elif source == "bluesky":
        valid = isinstance(data, dict) and isinstance(data.get("handle"), str)
    elif source == "gitlab":
        valid = (
            isinstance(data, list) and len(data) <= 1
            and all(isinstance(row, dict) and isinstance(row.get("username"), str) for row in data)
        )
    elif source == "hackernews":
        valid = isinstance(data, dict) and isinstance(data.get("id"), str)
    elif source == "mastodon":
        valid = (
            isinstance(data, dict) and isinstance(data.get("id"), str)
            and isinstance(data.get("acct"), str) and isinstance(data.get("url"), str)
        )
    elif source == "stackexchange":
        valid = (
            isinstance(data, dict) and isinstance(data.get("items"), list)
            and len(data.get("items", [])) <= 1 and isinstance(data.get("has_more"), bool)
            and all(isinstance(row, dict) and isinstance(row.get("user_id"), int)
                    for row in data.get("items", []))
        )
    elif source == "dockerhub":
        valid = (
            isinstance(data, dict) and isinstance(data.get("count"), int)
            and isinstance(data.get("results"), list) and len(data.get("results", [])) <= 25
            and all(isinstance(row, dict) and isinstance(row.get("name"), str)
                    for row in data.get("results", []))
        )
    elif source == "nvd":
        valid = (
            isinstance(data, dict) and isinstance(data.get("totalResults"), int)
            and isinstance(data.get("vulnerabilities"), list)
            and len(data.get("vulnerabilities", [])) <= 2
        )
    elif source == "npm":
        valid = (
            isinstance(data, dict) and isinstance(data.get("name"), str)
            and isinstance(data.get("version"), str)
        )
    elif source == "crossref":
        valid = (
            isinstance(data, dict) and data.get("status") == "ok"
            and isinstance(data.get("message"), dict)
            and isinstance(data.get("message", {}).get("DOI"), str)
        )
    elif source == "orcid":
        valid = (
            isinstance(data, dict) and isinstance(data.get("path"), str)
            and isinstance(data.get("name"), (dict, type(None)))
        )
    if not valid:
        raise ProviderError("provider_schema_mismatch")


class ResilientJSONClient:
    """Bounded retry/size/schema layer for official public provider APIs.

    URLs, headers and response bodies are intentionally absent from every raised
    error so API keys cannot leak through logs or connector-health records.
    """

    def __init__(self, requester: Requester, *, sleeper: Sleeper = time.sleep,
                 max_attempts: int = 3, max_body_bytes: int = 5 * 1024 * 1024,
                 clock: Callable[[], float] = time.monotonic, retry_rate_limits: bool = True):
        self.requester = requester
        self.sleeper = sleeper
        self.clock = clock
        self.max_attempts = max(1, min(int(max_attempts), 3))
        self.max_body_bytes = max(1024, min(int(max_body_bytes), 10 * 1024 * 1024))
        self.retry_rate_limits = retry_rate_limits

    @staticmethod
    def _status_error(status: int) -> ProviderError:
        if status in {401, 403}:
            return ProviderError("provider_authentication_rejected")
        if status == 404:
            return ProviderError("provider_record_not_found")
        if status == 429:
            return ProviderError("provider_rate_limited", retryable=True)
        if 500 <= status <= 599:
            return ProviderError("provider_unavailable", retryable=True)
        return ProviderError("provider_request_rejected")

    def get(self, source: str, url: str, headers: dict[str, str], timeout: int = 30) -> ProviderResult:
        last_error = ProviderError("provider_request_failed")
        budget = max(0, min(float(timeout), 30))
        deadline = self.clock() + budget
        for attempt in range(1, self.max_attempts + 1):
            # Give the first request the exact declared budget. Besides keeping
            # adapter contracts deterministic, this avoids shaving a few
            # microseconds off every configured timeout before any I/O starts.
            # Retries still receive only the shared deadline remainder.
            remaining = budget if attempt == 1 else deadline - self.clock()
            if remaining <= 0:
                raise ProviderError("provider_deadline_exceeded", attempts=attempt - 1)
            try:
                status, raw = self.requester(url, headers, remaining)
                if self.clock() >= deadline:
                    raise ProviderError("provider_deadline_exceeded")
                if status != 200:
                    raise self._status_error(int(status))
                if len(raw) > self.max_body_bytes:
                    raise ProviderError("provider_response_too_large")
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ProviderError("provider_invalid_json") from exc
                _validate_shape(source, data)
                return ProviderResult(data=data, attempts=attempt, bytes_received=len(raw),
                                      response_sha256=hashlib.sha256(raw).hexdigest(), raw=raw)
            except ProviderError as exc:
                last_error = exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = ProviderError("provider_transport_failure", retryable=True)
                last_error.__cause__ = exc
            last_error.attempts = attempt
            if last_error.code == "provider_rate_limited" and not self.retry_rate_limits:
                raise last_error
            if not last_error.retryable or attempt >= self.max_attempts:
                raise last_error
            delay = 0.25 * attempt
            if self.clock() + delay >= deadline:
                raise ProviderError("provider_deadline_exceeded", attempts=attempt)
            self.sleeper(delay)
        raise last_error
