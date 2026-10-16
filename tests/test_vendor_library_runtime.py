"""Real repository bridge regression tests: bounded search, Ollama, localhost and isolation."""
from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.employee.vendor_library import VendorLibrary
from traceatlas.employee.console import make_server


def fixture(root: Path) -> VendorLibrary:
    skills = root / "skills"
    skill = skills / "dns-analysis"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: dns-analysis\ndescription: Review DNS records\ndomain: cybersecurity\n"
        "license: Apache-2.0\n---\n# DNS analysis\nNever execute automatically.\n",
        encoding="utf-8")
    (skills / "invalid-skill").mkdir()
    csv_path = root / "osint.csv"
    csv_path.write_text(
        "Project,Repository,Description,Categories,License,Target Input\n"
        "DNS Research,https://github.com/example/dns,Review public DNS history,Infrastructure,MIT,Domain\n"
        "Media Archive,https://codeberg.org/example/archive,Review media archives,Media,MIT,URL\n"
        "Open Docs,https://gitlab.com/example/public/docs,Read project documents,Web,MIT,URL\n",
        encoding="utf-8")
    return VendorLibrary(skills, csv_path)


class VendorRuntimeTests(unittest.TestCase):
    def test_scans_reference_assets_without_activating_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = fixture(Path(tmp))
            status = lib.status()
            self.assertEqual(status["skills_indexed"], 1)
            self.assertEqual(status["repositories_indexed"], 3)
            self.assertEqual(status["invalid_skills"], 1)
            self.assertFalse(status["execution_enabled"])
            found = lib.search("dns")
            self.assertEqual(found["matched"], 2)
            self.assertEqual(lib.search("archive", kind="repository")["matched"], 1)
            self.assertTrue(all(not row["execution_enabled"] for row in found["results"]))
            self.assertIn("Never execute automatically", lib.reference("skill:dns-analysis")["markdown"])

    def test_rejects_untrusted_paths_and_content_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = fixture(Path(tmp))
            with self.assertRaises(ValueError):
                lib.reference("skill:../../etc/passwd")
            (Path(tmp) / "skills/dns-analysis/SKILL.md").write_text("tampered")
            with self.assertRaises(ValueError):
                lib.reference("skill:dns-analysis")

    def test_ollama_reorders_only_known_ids_without_executing(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = fixture(Path(tmp))
            observed = []
            def fake(url, body, headers, timeout):
                observed.append((url, json.loads(body), timeout))
                return 200, json.dumps({"response": json.dumps({
                    "ids": ["repo:1", "skill:dns-analysis"],
                    "rationale": "Review DNS registry context first."
                })}).encode()
            result = lib.plan("Investigate public DNS records", model="qwen2.5:7b",
                              use_ollama=True, requester=fake)
            self.assertEqual(result["status"], "ollama-advisory")
            self.assertEqual([r["ref"] for r in result["suggestions"]],
                             ["repo:1", "skill:dns-analysis"])
            self.assertFalse(result["may_execute"])
            self.assertFalse(result["source_collection_started"])
            self.assertEqual(observed[0][0], "http://127.0.0.1:11434/api/generate")
            self.assertNotIn("Never execute automatically", observed[0][1]["prompt"])

    def test_forged_model_actions_and_offline_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = fixture(Path(tmp))
            def forged(*_args):
                return 200, json.dumps({"response": json.dumps({
                    "ids": ["repo:1", "execute:rm-all"],
                    "rationale": "Dangerous, unknown tool"
                })}).encode()
            result = lib.plan("Investigate public DNS records", use_ollama=True, requester=forged)
            self.assertEqual(result["status"], "model-unavailable-or-invalid")
            self.assertFalse(result["may_execute"])
            def offline(*_args):
                raise TimeoutError("synthetic unavailable model")
            result = lib.plan("Investigate public DNS records", use_ollama=True, requester=offline)
            self.assertEqual(result["status"], "model-unavailable-or-invalid")
            with self.assertRaises(ValueError):
                lib.plan("Investigate public DNS records", model="http://evil.local")
            with self.assertRaises(ValueError):
                lib.search("../")
            with self.assertRaises(ValueError):
                lib.search("dns", limit=9999)

    def test_console_library_api_and_csrf(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = fixture(Path(tmp))
            with patch("traceatlas.employee.console.shared_library", return_value=lib):
                server = make_server(Path(tmp), port=0, enabled=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    host = "127.0.0.1:" + str(server.server_port)
                    def request(method, path, payload=None, csrf=""):
                        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                        body = json.dumps(payload).encode() if payload is not None else None
                        headers = {"Host": host}
                        if body is not None:
                            headers.update({"Content-Type": "application/json",
                                            "X-TraceAtlas-CSRF": csrf})
                        conn.request(method, path, body=body, headers=headers)
                        resp = conn.getresponse()
                        raw = resp.read()
                        code = resp.status
                        conn.close()
                        return code, json.loads(raw)
                    code, session = request("GET", "/api/session")
                    self.assertEqual(code, 200)
                    code, found = request("GET", "/api/library/search?q=dns")
                    self.assertEqual(code, 200)
                    self.assertEqual(found["matched"], 2)
                    code, found = request("GET", "/api/library/status")
                    self.assertEqual(code, 200)
                    self.assertEqual(found["skills_indexed"], 1)
                    code, _ = request("POST", "/api/library/plan",
                                      {"objective": "Investigate DNS sources"})
                    self.assertEqual(code, 403)
                    code, plan = request("POST", "/api/library/plan",
                                         {"objective": "Investigate DNS sources"},
                                         session["csrf_token"])
                    self.assertEqual(code, 200)
                    self.assertFalse(plan["may_execute"])
                    code, _ = request("GET", "/api/library/reference?ref=skill:../hidden")
                    self.assertEqual(code, 400)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)

    def test_real_both_vendored_libraries_are_indexed(self):
        lib = VendorLibrary()
        status = lib.status()
        self.assertGreaterEqual(status["skills_indexed"], 2500)
        self.assertEqual(status["repositories_indexed"], 497)
        self.assertFalse(status["execution_enabled"])
        self.assertTrue(lib.search("domain")["matched"] > 0)
        self.assertTrue(lib.search("dns", kind="repository")["matched"] > 0)


if __name__ == "__main__":
    unittest.main()
