from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from vercel_app_data import VERSION


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

    def do_GET(self) -> None:
        self._send(200, {
            "ok": True,
            "service": "redkross-traceatlas-fusion",
            "version": VERSION,
            "scan_execution": False,
        })

    def do_POST(self) -> None:
        self._send(405, {"error": "method_not_allowed"})
