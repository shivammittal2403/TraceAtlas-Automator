from __future__ import annotations

import json
import time
import urllib.error
from dataclasses import dataclass
from typing import Any, Callable


Requester = Callable[[str, dict[str, str], int], tuple[int, bytes]]
Sleeper = Callable[[float], None]


class ProviderError(RuntimeError):
    """Secret-safe connector failure with stable operational classification."""

    def __init__(self, code: str, *, retryable: bool = False):
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class ProviderResult:
    data: dict[str, Any] | list[Any]
    attempts: int
    bytes_received: int


def _validate_shape(source: str, data: Any) -> None:
    """Reject provider error pages and schema drift before evidence ingestion."""
    valid = isinstance(data, (dict, list))
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
    if not valid:
        raise ProviderError("provider_schema_mismatch")


class ResilientJSONClient:
    """Bounded retry/size/schema layer for official public provider APIs.

    URLs, headers and response bodies are intentionally absent from every raised
    error so API keys cannot leak through logs or connector-health records.
    """

    def __init__(self, requester: Requester, *, sleeper: Sleeper = time.sleep,
                 max_attempts: int = 3, max_body_bytes: int = 5 * 1024 * 1024):
        self.requester = requester
        self.sleeper = sleeper
        self.max_attempts = max(1, min(int(max_attempts), 3))
        self.max_body_bytes = max(1024, min(int(max_body_bytes), 10 * 1024 * 1024))

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
        for attempt in range(1, self.max_attempts + 1):
            try:
                status, raw = self.requester(url, headers, timeout)
                if status != 200:
                    raise self._status_error(int(status))
                if len(raw) > self.max_body_bytes:
                    raise ProviderError("provider_response_too_large")
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ProviderError("provider_invalid_json") from exc
                _validate_shape(source, data)
                return ProviderResult(data=data, attempts=attempt, bytes_received=len(raw))
            except ProviderError as exc:
                last_error = exc
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = ProviderError("provider_transport_failure", retryable=True)
                last_error.__cause__ = exc
            if not last_error.retryable or attempt >= self.max_attempts:
                raise last_error
            self.sleeper(0.25 * attempt)
        raise last_error
