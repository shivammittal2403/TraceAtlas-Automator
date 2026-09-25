"""Dependency-free Vercel/Supabase control-plane helpers.

Authentication is proxied through same-origin endpoints. The browser never
receives a Supabase secret key and access tokens live in short-lived HttpOnly
cookies scoped to ``/api``.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from typing import Any


MAX_BODY = 16 * 1024
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.I,
)
HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{20,8192}$")
JOB_KINDS = {"domain_passive", "ip_passive", "url_metadata", "hash_reputation"}
ASSET_TYPES = {"domain", "ip", "url", "hash"}


class ControlPlaneError(RuntimeError):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def _config() -> tuple[str, str]:
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip()
    if not url or not key:
        raise ControlPlaneError(503, "control_plane_not_configured")
    parsed = urllib.parse.urlparse(url)
    local = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
    hosted = parsed.scheme == "https" and bool(parsed.hostname) and parsed.hostname.endswith(".supabase.co")
    if not hosted and not (local and os.environ.get("TRACEATLAS_ALLOW_LOCAL_SUPABASE") == "1"):
        raise ControlPlaneError(503, "invalid_control_plane_endpoint")
    if len(key) > 4096 or any(char.isspace() for char in key):
        raise ControlPlaneError(503, "invalid_publishable_key")
    return url, key


def configured() -> bool:
    try:
        _config()
    except ControlPlaneError:
        return False
    return True


def send_json(handler: Any, status: int, payload: dict[str, Any], *, cookies: list[str] | None = None) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Content-Length", str(len(body)))
    for cookie in cookies or []:
        handler.send_header("Set-Cookie", cookie)
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: Any, *, max_bytes: int = MAX_BODY) -> dict[str, Any]:
    content_type = handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise ControlPlaneError(415, "content_type_must_be_application_json")
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise ControlPlaneError(400, "invalid_content_length") from exc
    if length <= 0 or length > max_bytes:
        raise ControlPlaneError(413 if length > max_bytes else 400, "invalid_body_size")
    try:
        payload = json.loads(handler.rfile.read(length))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ControlPlaneError(400, "invalid_json") from exc
    if not isinstance(payload, dict):
        raise ControlPlaneError(400, "json_body_must_be_object")
    return payload


def require_same_origin(handler: Any) -> None:
    origin = handler.headers.get("Origin", "").rstrip("/")
    host = handler.headers.get("Host", "").strip().lower()
    if not origin or not host:
        raise ControlPlaneError(403, "same_origin_required")
    allowed = {
        item.strip().rstrip("/")
        for item in os.environ.get("TRACEATLAS_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    }
    derived = {f"https://{host}"}
    if host.startswith(("localhost:", "127.0.0.1:")):
        derived.add(f"http://{host}")
    if origin not in allowed | derived:
        raise ControlPlaneError(403, "origin_not_allowed")


def access_token(headers: Any) -> str:
    token = ""
    authorization = headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    if not token:
        cookie = SimpleCookie()
        try:
            cookie.load(headers.get("Cookie", ""))
        except Exception as exc:
            raise ControlPlaneError(401, "invalid_session") from exc
        morsel = cookie.get("ta_access")
        token = morsel.value if morsel else ""
    if not SAFE_TOKEN_RE.fullmatch(token):
        raise ControlPlaneError(401, "authentication_required")
    return token


def session_cookie(token: str, max_age: int) -> str:
    if not SAFE_TOKEN_RE.fullmatch(token):
        raise ControlPlaneError(502, "invalid_auth_response")
    lifetime = max(60, min(int(max_age), 3600))
    return (
        f"ta_access={token}; Max-Age={lifetime}; Path=/api; HttpOnly; Secure; "
        "SameSite=Strict; Priority=High"
    )


def clear_session_cookie() -> str:
    return "ta_access=; Max-Age=0; Path=/api; HttpOnly; Secure; SameSite=Strict; Priority=High"


def require_uuid(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not UUID_RE.fullmatch(text):
        raise ControlPlaneError(400, f"invalid_{field}")
    return text


def require_text(value: Any, field: str, *, minimum: int = 1, maximum: int = 500) -> str:
    text = str(value or "").strip()
    if len(text) < minimum or len(text) > maximum or any(ord(char) < 32 for char in text):
        raise ControlPlaneError(400, f"invalid_{field}")
    return text


def validate_asset(target_type: Any, target_value: Any) -> tuple[str, str]:
    kind = str(target_type or "").strip().lower()
    value = str(target_value or "").strip()
    if kind not in ASSET_TYPES or not value or len(value) > 2048 or any(char in value for char in "\r\n\0"):
        raise ControlPlaneError(400, "invalid_asset")
    if kind == "domain":
        if not DOMAIN_RE.fullmatch(value):
            raise ControlPlaneError(400, "invalid_public_domain")
        value = value.lower()
    elif kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ControlPlaneError(400, "invalid_public_ip") from exc
        if not address.is_global:
            raise ControlPlaneError(400, "private_or_reserved_ip_rejected")
        value = str(address)
    elif kind == "url":
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ControlPlaneError(400, "invalid_public_url")
        if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
            raise ControlPlaneError(400, "private_or_local_url_rejected")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address = None
        if address and not address.is_global:
            raise ControlPlaneError(400, "private_or_reserved_url_rejected")
    elif kind == "hash":
        if not HASH_RE.fullmatch(value):
            raise ControlPlaneError(400, "invalid_file_hash")
        value = value.lower()
    return kind, value


class SupabaseGateway:
    """Narrow allowlisted Supabase Auth and Data API client."""

    def __init__(self, token: str | None = None, timeout: int = 8):
        self.url, self.publishable_key = _config()
        self.token = token
        self.timeout = max(2, min(timeout, 15))

    def _request(self, method: str, path: str, *, payload: Any = None,
                 query: dict[str, str] | None = None, prefer: str | None = None) -> Any:
        if not path.startswith(("/auth/v1/", "/rest/v1/")) or ".." in path:
            raise ControlPlaneError(500, "blocked_backend_path")
        url = f"{self.url}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query, safe="(),.*:")
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json", "apikey": self.publishable_key,
                   "User-Agent": "TraceAtlas-Control/1.1"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if prefer:
            headers["Prefer"] = prefer
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            status = 401 if exc.code in {400, 401, 403} and path.startswith("/auth/") else exc.code
            if status < 400 or status > 599:
                status = 502
            code = "authentication_failed" if path.startswith("/auth/") else "backend_request_rejected"
            raise ControlPlaneError(status, code) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ControlPlaneError(503, "backend_unavailable") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ControlPlaneError(502, "invalid_backend_response") from exc

    def login(self, email: str, password: str) -> dict[str, Any]:
        return self._request("POST", "/auth/v1/token", payload={"email": email, "password": password},
                             query={"grant_type": "password"})

    def user(self) -> dict[str, Any]:
        if not self.token:
            raise ControlPlaneError(401, "authentication_required")
        return self._request("GET", "/auth/v1/user")

    def select(self, table: str, query: dict[str, str]) -> list[dict[str, Any]]:
        if table not in {"organisations", "cases", "assets", "investigation_jobs", "job_events",
                         "evidence_items", "graph_entities", "graph_edges"}:
            raise ControlPlaneError(500, "blocked_table")
        data = self._request("GET", f"/rest/v1/{table}", query=query)
        return data if isinstance(data, list) else []

    def insert(self, table: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        if table not in {"organisations", "cases", "assets"}:
            raise ControlPlaneError(500, "blocked_table")
        data = self._request("POST", f"/rest/v1/{table}", payload=payload, prefer="return=representation")
        return data if isinstance(data, list) else []

    def rpc(self, function: str, payload: dict[str, Any]) -> Any:
        if function != "enqueue_investigation_job":
            raise ControlPlaneError(500, "blocked_function")
        return self._request("POST", f"/rest/v1/rpc/{function}", payload=payload)


def authenticated_gateway(handler: Any) -> tuple[SupabaseGateway, dict[str, Any]]:
    gateway = SupabaseGateway(access_token(handler.headers))
    user = gateway.user()
    if not isinstance(user, dict) or not UUID_RE.fullmatch(str(user.get("id", ""))):
        raise ControlPlaneError(401, "authentication_required")
    return gateway, user


def handle_error(handler: Any, exc: Exception) -> None:
    if isinstance(exc, ControlPlaneError):
        send_json(handler, exc.status, {"error": exc.code})
    else:
        send_json(handler, 500, {"error": "internal_error"})
