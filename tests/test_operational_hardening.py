from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.automation import AutomationManager
from traceatlas.deployment import DeploymentDoctor
from traceatlas.engine import Engine
from traceatlas.integrations.runner import IntegrationRunner
from traceatlas.policy import PolicyError


class OperationalHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.engine = Engine(self.root / "cases")
        self.engine.db.create_case("case-1", "Automation", "Authorised regression test")

    def tearDown(self):
        self.engine.close()
        self.tmp.cleanup()

    def test_sqlite_foreign_keys_are_enforced(self):
        enabled = self.engine.db.conn.execute("PRAGMA foreign_keys").fetchone()[0]
        self.assertEqual(enabled, 1)

    def test_schedule_baseline_history_disable_and_no_arbitrary_commands(self):
        manager = AutomationManager(self.engine)
        schedule = manager.add(
            "case-1", "Search baseline", "advanced-search", "text", "safe query",
            60, "Written approval from the test asset owner", authorized=True,
        )
        result = manager.run_due()
        self.assertEqual(result["claimed"], 1)
        self.assertTrue(result["results"][0]["baseline"])
        self.assertFalse(result["results"][0]["changed"])
        self.assertEqual(self.engine.db.alerts("case-1"), [])
        self.assertEqual(len(self.engine.db.automation_runs(schedule["id"])), 1)
        self.assertTrue(self.engine.db.set_automation_enabled(schedule["id"], False))
        self.assertEqual(manager.run_due()["claimed"], 0)

    def test_schedule_rejects_sensitive_assisted_and_file_workflows(self):
        manager = AutomationManager(self.engine)
        with self.assertRaisesRegex(PolicyError, "Sensitive workflows"):
            manager.add("case-1", "Breach watch", "credential-monitoring", "email",
                        "analyst@example.com", 60, "Consented account owner approval", authorized=True)
        with self.assertRaisesRegex(PolicyError, "Sensitive workflows"):
            manager.add("case-1", "Person research", "person-profile", "text",
                        "Example Person", 60, "Consented subject approval record", authorized=True)
        with self.assertRaisesRegex(PolicyError, "File targets"):
            manager.add("case-1", "File watch", "file-metadata", "file", __file__,
                        60, "Owned local test file approval", authorized=True)

    def test_schedule_failure_creates_redacted_acknowledgeable_alert(self):
        manager = AutomationManager(self.engine)
        schedule = manager.add(
            "case-1", "Failing baseline", "advanced-search", "text", "safe query",
            60, "Written approval from the test asset owner", authorized=True,
        )
        with patch.object(self.engine, "run", side_effect=RuntimeError("secret value")):
            result = manager.run_due()
        self.assertEqual(result["failed"], 1)
        alert = self.engine.db.alerts("case-1", open_only=True)[0]
        self.assertNotIn("secret value", str(alert))
        self.assertEqual(alert["details"]["error_type"], "RuntimeError")
        self.assertTrue(self.engine.db.acknowledge_alert(alert["id"]))
        self.assertEqual(self.engine.db.alerts("case-1", open_only=True), [])
        self.assertEqual(self.engine.db.automation_job(schedule["id"])["last_status"], "failed")

    def test_partial_schedule_omits_raw_collector_errors(self):
        manager = AutomationManager(self.engine)
        manager.add(
            "case-1", "Partial baseline", "advanced-search", "text", "safe query",
            60, "Written approval from the test asset owner", authorized=True,
        )
        with patch.object(self.engine, "run", return_value={
            "status": "partial", "errors": ["provider secret should not persist"],
            "findings_collected": 0, "findings_added": 0,
        }):
            result = manager.run_due()
        serialized = str(result) + str(self.engine.db.automation_runs()) + str(self.engine.db.alerts())
        self.assertNotIn("provider secret should not persist", serialized)
        self.assertEqual(result["results"][0]["result"]["error_count"], 1)
        self.assertEqual(self.engine.db.alerts()[0]["kind"], "execution_partial")

    def test_adapter_readiness_distinguishes_installation_and_execution(self):
        runner = IntegrationRunner(self.engine.db, self.root)
        with patch.object(runner, "resolve_binary", return_value=None):
            amass = next(row for row in runner.inventory() if row["name"] == "amass")
        self.assertEqual(amass["readiness"], "unavailable")
        self.assertEqual(amass["verification"], "untested")

        completed = subprocess.CompletedProcess(args=["amass"], returncode=0, stdout="", stderr="")
        with patch.object(runner, "resolve_binary", return_value="/usr/bin/amass"), \
             patch("traceatlas.integrations.runner.subprocess.run", return_value=completed):
            runner.run("case-1", "amass", "domain", "example.com", authorized=True)
        with patch.object(runner, "resolve_binary", return_value="/usr/bin/amass"):
            amass = next(row for row in runner.inventory() if row["name"] == "amass")
        self.assertEqual(amass["readiness"], "ready")
        self.assertEqual(amass["verification"], "verified")

    def test_deployment_doctor_is_non_mutating_and_flags_missing_prod_env(self):
        repo = Path(__file__).resolve().parents[1]
        before = {path: path.stat().st_mtime_ns for path in (repo / "public").glob("*") if path.is_file()}
        with patch.dict(os.environ, {}, clear=True):
            result = DeploymentDoctor(repo).run(production=True)
        after = {path: path.stat().st_mtime_ns for path in (repo / "public").glob("*") if path.is_file()}
        self.assertFalse(result["ready"])
        self.assertGreaterEqual(result["summary"]["failed"], 2)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
