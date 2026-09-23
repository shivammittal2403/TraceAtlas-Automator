from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from vercel_app_data import build_plan


MAX_BODY = 4096


class handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._send(415, {"error": "content_type_must_be_application_json"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "invalid_content_length"})
            return
        if length <= 0 or length > MAX_BODY:
            self._send(413 if length > MAX_BODY else 400, {"error": "invalid_body_size"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            result = build_plan(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, {"error": "invalid_json"})
            return
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
            return
        self._send(200, result)

    def do_GET(self) -> None:
        self._send(405, {"error": "method_not_allowed"})
