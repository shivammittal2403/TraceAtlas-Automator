from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from traceatlas.capabilities import CAPABILITIES, CapabilityHub
from traceatlas.db import CaseDB
from traceatlas.policy import PolicyError


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = CaseDB(self.root / "traceatlas.db")
        self.db.create_case("case-1", "Capability", "Authorized fixture test")
        self.hub = CapabilityHub(self.db, self.root)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_all_analyzed_repositories_are_registered(self):
        self.assertEqual(len(CAPABILITIES), 19)
        for name in ("agent-reach", "crawl4ai", "firecrawl-mcp", "mcp-maigret",
                     "osint-mcp-server", "openosint", "browser-use"):
            self.assertIn(name, CAPABILITIES)

    def test_licence_boundaries_are_machine_enforced(self):
        self.assertFalse(CAPABILITIES["iop-mvp"].executable)
        self.assertEqual(CAPABILITIES["firecrawl"].integration, "service")
        self.assertFalse(CAPABILITIES["gpt-researcher"].executable)
        self.assertIn("not vendored", CAPABILITIES["firecrawl"].restriction)

    def test_doctor_is_secret_safe(self):
        encoded = json.dumps(self.hub.doctor())
        self.assertNotIn("API_KEY=", encoded)
        self.assertEqual(self.hub.doctor()["upstream_engines"], 19)

    def test_ingest_requires_authorization_and_consent(self):
        export = self.root / "agent.json"
        export.write_text('{"username":"alice"}', encoding="utf-8")
        with self.assertRaises(PolicyError):
            self.hub.ingest("case-1", "agent-reach", export, authorized=False)
        with self.assertRaisesRegex(PolicyError, "subject-consent"):
            self.hub.ingest("case-1", "agent-reach", export, authorized=True)

    def test_ingest_redacts_secrets_and_separates_inferences(self):
        export = self.root / "exa.jsonl"
        export.write_text(
            '{"title":"public result","api_key":"never-store","home_address":"private"}\n',
            encoding="utf-8",
        )
        result = self.hub.ingest(
            "case-1", "exa-mcp", export, authorized=True, subject_consent=True
        )
        data = json.loads(Path(result["output"]).read_text(encoding="utf-8"))
        self.assertEqual(data["facts"][0]["api_key"], "[REDACTED]")
        self.assertEqual(data["facts"][0]["home_address"], "[REMOVED]")
        self.assertEqual(data["inferences"], [])
        self.assertEqual(len(self.db.evidence("case-1")), 1)


if __name__ == "__main__":
    unittest.main()
