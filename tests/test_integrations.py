from __future__ import annotations

import json
import gzip
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.integrations.parsers import in_scope, parse_output, redact_sensitive
from traceatlas.integrations.registry import PROFILES, TOOLS
from traceatlas.integrations.runner import IntegrationRunner
from traceatlas.integrations.catalog import CatalogStore
from traceatlas.policy import PolicyError
from traceatlas.report import build_report


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = CaseDB(self.root / "traceatlas.db")
        self.db.create_case("case-1", "Integration", "Authorized test")
        self.runner = IntegrationRunner(self.db, self.root)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_registry_has_major_tools_and_profiles(self):
        self.assertGreaterEqual(len(TOOLS), 30)
        for name in ("recon-ng", "amass", "subfinder", "httpx", "nuclei", "nmap"):
            self.assertIn(name, TOOLS)
        self.assertIn("passive-domain", PROFILES)
        self.assertEqual(TOOLS["masscan"].mode, "blocked")

    def test_command_is_argument_array_not_shell_string(self):
        spec = TOOLS["amass"]
        command, output = self.runner.build_command(
            spec, "/usr/bin/amass", "example.com", "case-1", self.root, {}
        )
        self.assertIsInstance(command, list)
        self.assertEqual(command[:3], ["/usr/bin/amass", "enum", "-passive"])
        self.assertEqual(output, self.root / "amass.txt")

    def test_jsonl_normalization_and_scope_filter(self):
        raw = "\n".join([
            json.dumps({"host": "api.example.com", "source": "crtsh"}),
            json.dumps({"host": "outside.test", "source": "other"}),
        ])
        events = parse_output(TOOLS["subfinder"], raw)
        scoped = [event for event in events if in_scope(event, "domain", "example.com")]
        self.assertEqual(len(events), 2)
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0]["data"], "api.example.com")

    def test_secret_values_are_not_persisted_in_normalized_event(self):
        output = redact_sensitive({"DetectorName": "AWS", "Raw": "AKIA-SECRET-VALUE"})
        self.assertNotIn("AKIA-SECRET-VALUE", json.dumps(output))
        self.assertTrue(output["Raw"]["redacted"])

    def test_active_and_blocked_policy_gates(self):
        with self.assertRaises(PolicyError):
            self.runner.run("case-1", "masscan", "ip", "8.8.8.8", authorized=True)
        with patch.object(self.runner, "resolve_binary", return_value="/usr/bin/httpx"):
            with self.assertRaises(PolicyError):
                self.runner.run(
                    "case-1", "httpx", "domain", "example.com", authorized=True
                )

    def test_mocked_external_run_creates_spider_events_and_evidence(self):
        completed = subprocess.CompletedProcess(
            args=["subfinder"], returncode=0,
            stdout='{"host":"api.example.com","source":"crtsh"}\n', stderr="",
        )
        with patch.object(self.runner, "resolve_binary", return_value="/usr/bin/subfinder"), \
             patch("traceatlas.integrations.runner.subprocess.run", return_value=completed) as run:
            result = self.runner.run(
                "case-1", "subfinder", "domain", "example.com", authorized=True
            )
        self.assertEqual(result["status"], "completed")
        events = self.db.spider_events(result["scan_id"])
        self.assertEqual([event["event_type"] for event in events], ["DOMAIN", "DOMAIN"])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertGreaterEqual(len(self.db.evidence("case-1")), 1)
        report = build_report(self.db, "case-1")
        self.assertEqual(report["spider_scans"][0]["id"], result["scan_id"])
        self.assertEqual(len(report["spider_scans"][0]["events"]), 2)

    def test_catalog_import_gzip_search_and_stats(self):
        source = self.root / "recon-data.json.gz"
        rows = [
            {"name": "Amass", "url": "https://github.com/owasp-amass/amass",
             "desc": "Attack surface mapping", "cat": "Domain", "src": "test"},
            {"name": "Recon-ng", "url": "https://github.com/lanmaster53/recon-ng",
             "desc": "OSINT framework", "cat": "Framework", "src": "test"},
        ]
        source.write_bytes(gzip.compress(json.dumps(rows).encode()))
        catalog = CatalogStore(self.root)
        result = catalog.import_file(source)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(catalog.search("attack")[0]["name"], "Amass")
        self.assertEqual(catalog.stats()["tools"], 2)

    def test_catalog_rejects_empty_remote_loader_html(self):
        source = self.root / "recon.html"
        source.write_text(
            '<html><script id="tool-data" type="application/json">[]</script></html>',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "zero usable tools"):
            CatalogStore(self.root).import_file(source)

    def test_pipeline_requires_authorization_and_can_skip_missing_tools(self):
        with self.assertRaises(PolicyError):
            self.runner.run_domain_pipeline("case-1", "example.com", authorized=False)
        with patch.object(self.runner, "resolve_binary", return_value=None):
            result = self.runner.run_domain_pipeline(
                "case-1", "example.com", authorized=True, verify=False
            )
        self.assertEqual(result["assets_selected"], ["example.com"])
        self.assertEqual(result["discovery"]["completed"], 0)


if __name__ == "__main__":
    unittest.main()
