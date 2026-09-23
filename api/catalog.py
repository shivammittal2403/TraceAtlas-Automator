from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from vercel_app_data import CATALOG


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = json.dumps(CATALOG, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "public, max-age=300, s-maxage=3600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self.send_error(405)
