from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.engine import Engine
from traceatlas.openosint_bridge import OpenOSINTBridge, SAFE_DIRECT_COMMANDS, UPSTREAM_TOOLS
from traceatlas.policy import PolicyError


ROOT = Path(__file__).resolve().parents[1]


class OpenOSINTBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name) / "cases"
        self.engine = Engine(self.workspace)
        self.engine.db.create_case("rk-test", "Bridge test", "Authorised unit test")
        self.bridge = OpenOSINTBridge(self.engine.db, self.workspace, ROOT)

    def tearDown(self):
        self.engine.close()
        self.tmp.cleanup()

    def test_upstream_source_and_license_are_preserved(self):
        self.assertEqual(len(UPSTREAM_TOOLS), 20)
        self.assertEqual(len(SAFE_DIRECT_COMMANDS), 10)
        self.assertTrue((ROOT / "packages/openosint/openosint/cli.py").is_file())
        self.assertIn("MIT License", (ROOT / "packages/openosint/LICENSE").read_text())
        with patch.object(self.bridge, "runtime", return_value=None):
            doctor = self.bridge.doctor()
        self.assertEqual(doctor["upstream_version"], "2.29.0")
        self.assertFalse(doctor["public_web_exposed"])

    def test_authorization_consent_and_allowlist_are_mandatory(self):
        with self.assertRaisesRegex(PolicyError, "--authorized"):
            self.bridge.run("rk-test", ["email", "user@example.com"])
        with self.assertRaisesRegex(PolicyError, "--subject-consent"):
            self.bridge.run("rk-test", ["email", "user@example.com"], authorized=True)
        with self.assertRaisesRegex(PolicyError, "permits only"):
            self.bridge.run(
                "rk-test", ["web"], authorized=True, subject_consent=True
            )
        with self.assertRaisesRegex(PolicyError, "Credentials"):
            self.bridge.run(
                "rk-test", ["--api-key", "secret", "email", "user@example.com"],
                authorized=True, subject_consent=True,
            )

    def test_successful_result_is_normalized_into_evidence_graph(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=json.dumps({"email": "person@example.com", "status": "found"}),
            stderr="",
        )
        with patch.object(self.bridge, "runtime", return_value=Path(sys.executable)), \
             patch("traceatlas.openosint_bridge.subprocess.run", return_value=completed):
            result = self.bridge.run(
                "rk-test", ["email", "person@example.com"],
                authorized=True, subject_consent=True,
            )
        self.assertEqual(result["status"], "completed")
        events = self.engine.db.spider_events(result["scan_id"])
        self.assertEqual([row["event_type"] for row in events], ["TEXT", "OPENOSINT_RESULT"])
        self.assertTrue(result["stats"]["redacted"])


if __name__ == "__main__":
    unittest.main()
