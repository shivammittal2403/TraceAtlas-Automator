"""Regression checks for the single-IP gateway's private application boundary."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from traceatlas.employee.console import make_server
from traceatlas.policy import PolicyError


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "T" * 48
GATEWAY_ORIGIN = "http://127.0.0.1:8780"


class EnterpriseGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.environment = patch.dict(os.environ, {
            "TRACEATLAS_CONSOLE_GATEWAY_TOKEN": TOKEN,
            "TRACEATLAS_CONSOLE_GATEWAY_ORIGIN": GATEWAY_ORIGIN,
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.server = make_server(Path(self.temp.name), port=0, enabled=True)
        self.addCleanup(self.server.server_close)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def _stop(self):
        self.server.shutdown()
        self.thread.join(timeout=5)

    def request(self, path, headers=None):
        req = Request(self.origin + path, headers=headers or {})
        try:
            with urlopen(req, timeout=4) as response:
                return response.status, response.read(), dict(response.headers)
        except HTTPError as error:
            return error.code, error.read(), dict(error.headers)

    def test_gateway_requires_internal_token_even_for_console_html(self):
        status, _, _ = self.request("/")
        self.assertNotEqual(status, 200)
        status, _, _ = self.request("/api/session")
        self.assertNotEqual(status, 200)
        status, _, _ = self.request("/", {"X-TraceAtlas-Internal-Token": "wrong"})
        self.assertNotEqual(status, 200)
        status, data, headers = self.request(
            "/", {"X-TraceAtlas-Internal-Token": TOKEN, "Origin": GATEWAY_ORIGIN})
        self.assertEqual(status, 200)
        self.assertIn(b"TraceAtlas", data)
        self.assertIn("no-store", headers.get("Cache-Control", ""))

    def test_strict_origins_also_apply_to_authenticated_gateway(self):
        status, _, _ = self.request("/api/session", {
            "X-TraceAtlas-Internal-Token": TOKEN, "Origin": "https://attacker.invalid"})
        self.assertNotEqual(status, 200)
        status, data, _ = self.request("/api/session", {
            "X-TraceAtlas-Internal-Token": TOKEN, "Origin": GATEWAY_ORIGIN})
        self.assertEqual(status, 200)
        self.assertIn(b"csrf_token", data)

    def test_direct_local_origin_still_needs_gateway_token(self):
        status, _, _ = self.request("/api/session", {"Origin": self.origin})
        self.assertNotEqual(status, 200)

    def test_invalid_gateway_setup_fails_closed(self):
        with patch.dict(os.environ, {"TRACEATLAS_CONSOLE_GATEWAY_TOKEN": "short",
                                     "TRACEATLAS_CONSOLE_GATEWAY_ORIGIN": GATEWAY_ORIGIN}):
            with self.assertRaises(PolicyError):
                make_server(Path(self.temp.name), port=0, enabled=True)
        with patch.dict(os.environ, {"TRACEATLAS_CONSOLE_GATEWAY_TOKEN": "",
                                     "TRACEATLAS_CONSOLE_GATEWAY_ORIGIN": GATEWAY_ORIGIN}):
            with self.assertRaises(PolicyError):
                make_server(Path(self.temp.name), port=0, enabled=True)
        with patch.dict(os.environ, {"TRACEATLAS_CONSOLE_GATEWAY_TOKEN": TOKEN,
                                     "TRACEATLAS_CONSOLE_GATEWAY_ORIGIN": "http://0.0.0.0:8780"}):
            with self.assertRaises(PolicyError):
                make_server(Path(self.temp.name), port=0, enabled=True)

    def test_gateway_launcher_has_valid_shell_syntax(self):
        if not shutil.which("bash"):
            self.skipTest("bash is not available on this test platform")
        process = subprocess.run(
            ["bash", "-n", str(ROOT / "deploy/gateway/start-local.sh")],
            capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_reverse_proxy_configuration_does_not_publish_private_services(self):
        config = (ROOT / "deploy/gateway/Caddyfile").read_text(encoding="utf-8")
        launcher = (ROOT / "deploy/gateway/start-local.sh").read_text(encoding="utf-8")
        html = (ROOT / "src/traceatlas/employee/static/console.html").read_text(encoding="utf-8")
        self.assertIn("http://127.0.0.1:8780", config)
        self.assertIn("bind 127.0.0.1", config)
        self.assertIn("basic_auth", config)
        self.assertIn("reverse_proxy 127.0.0.1:8765", config)
        self.assertIn("header_up -Authorization", config)
        self.assertIn("X-TraceAtlas-Internal-Token", config)
        self.assertNotIn("reverse_proxy 127.0.0.1:11434", config)
        self.assertNotIn("0.0.0.0:8780", config)
        self.assertIn("TRACEATLAS_GATEWAY_PASSWORD_HASH", launcher)
        self.assertIn("TRACEATLAS_CONSOLE_GATEWAY_ORIGIN", launcher)
        self.assertIn("const API_BASE=", html)
        self.assertIn("fetch(API_BASE+path", html)
