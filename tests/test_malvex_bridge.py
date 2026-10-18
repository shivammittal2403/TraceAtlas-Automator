from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.engine import Engine
from traceatlas.malvex_bridge import MalvexBridge, PINNED_COMMIT
from traceatlas.policy import PolicyError


class MalvexBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.engine = Engine(self.root / "workspace")
        self.engine.db.create_case("case-1", "Malware sample", "Authorized offline analysis")
        self.bridge = MalvexBridge(self.engine.db, self.engine.workspace, binary="/usr/bin/malvex")

    def tearDown(self):
        self.engine.close()
        self.temp.cleanup()

    def test_import_requires_authorization_and_existing_case(self):
        report = self.root / "findings.json"
        report.write_text("[]", encoding="utf-8")
        with self.assertRaises(PolicyError):
            self.bridge.import_findings("case-1", report, authorized=False)
        with self.assertRaises(PolicyError):
            self.bridge.import_findings("missing", report, authorized=True)

    def test_external_confirmed_never_becomes_verified_traceatlas_finding(self):
        report = self.root / "findings.json"
        report.write_text(json.dumps([{
            "id": "m-1", "title": "Fake confirmation", "severity": "HIGH",
            "verdict": "confirmed", "evidence": [{"kind": "strings", "detail": "demo"}],
        }]), encoding="utf-8")
        result = self.bridge.import_findings("case-1", report, authorized=True)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["candidates"][0]["traceatlas_status"], "unverified_external_candidate")
        self.assertEqual(result["candidates"][0]["upstream_verdict"], "confirmed")
        self.assertFalse(result["automatic_confirmation"])
        self.assertEqual(len(self.engine.db.evidence("case-1")), 1)
        self.assertEqual(len(self.engine.db.findings("case-1")), 0)

    def test_non_json_or_bad_shape_rejected(self):
        report = self.root / "findings.json"
        report.write_text('{"findings": "wrong"}', encoding="utf-8")
        with self.assertRaises(PolicyError):
            self.bridge.import_findings("case-1", report, authorized=True)

    def test_dry_run_cannot_call_live_run(self):
        root = self.root / "malvex"
        root.mkdir()
        sample = self.root / "inert.bin"
        sample.write_bytes(b"not-malware")
        output = subprocess.CompletedProcess(args=[], returncode=0, stdout="triage then static", stderr="")
        with patch("traceatlas.malvex_bridge.subprocess.run", return_value=output) as call:
            result = self.bridge.plan("case-1", sample, authorized=True, source_root=root)
        argv = call.call_args.args[0]
        self.assertIn("--dry-run", argv)
        self.assertEqual(argv[argv.index("--runtime") + 1], "ollama")
        self.assertFalse(call.call_args.kwargs["shell"])
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["executed_sample"])
        self.assertEqual(len(self.engine.db.evidence("case-1")), 0)

    def test_plan_rejects_missing_authorization_before_subprocess(self):
        sample = self.root / "fixture.bin"
        sample.write_bytes(b"fixture")
        with patch("traceatlas.malvex_bridge.subprocess.run") as call:
            with self.assertRaises(PolicyError):
                self.bridge.plan("case-1", sample, authorized=False, source_root=self.root)
            call.assert_not_called()

    def test_missing_binary_is_explicit(self):
        bridge = MalvexBridge(self.engine.db, self.engine.workspace, binary="not-a-real-path")
        with patch("traceatlas.malvex_bridge.subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(PolicyError):
                bridge.doctor()

    def test_pin_is_exact_commit(self):
        self.assertEqual(len(PINNED_COMMIT), 40)


if __name__ == "__main__":
    unittest.main()
