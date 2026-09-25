from __future__ import annotations

import json
import io
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.intelligence.hub import IntelligenceHub, _request
from traceatlas.intelligence.provider import ProviderError, ResilientJSONClient
from traceatlas.integrations import IntegrationLock, IntegrationRunner
from traceatlas.integrations.registry import TOOLS
from traceatlas.policy import PolicyError
from traceatlas.readiness import ReadinessScorecard
from traceatlas.resolution import ResolutionService


ROOT = Path(__file__).resolve().parents[1]


class RemediationReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "traceatlas.db")
        self.db.create_case("case-1", "Remediation", "Authorised defensive review")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_provider_retries_rate_limit_and_validates_schema(self):
        responses = [(429, b'{}'), (200, b'{"login":"example"}')]
        sleeps = []
        client = ResilientJSONClient(
            lambda *_: responses.pop(0), sleeper=sleeps.append, max_attempts=3,
        )
        result = client.get("github", "https://example.invalid", {})
        self.assertEqual(result.attempts, 2)
        self.assertEqual(sleeps, [0.25])
        with self.assertRaisesRegex(ProviderError, "provider_schema_mismatch"):
            ResilientJSONClient(lambda *_: (200, b'{"message":"changed"}')).get(
                "github", "https://example.invalid", {},
            )

    def test_default_transport_surfaces_http_status_without_secret_details(self):
        error = urllib.error.HTTPError(
            "https://provider.invalid/?key=secret", 429, "limited", {}, io.BytesIO(b'{"error":"x"}'),
        )
        with patch("traceatlas.intelligence.hub.urlopen", side_effect=error):
            status, body = _request("https://provider.invalid", {"Authorization": "secret"}, 3)
        self.assertEqual(status, 429)
        self.assertEqual(body, b'{"error":"x"}')

    def test_connector_failure_is_classified_without_url_or_key(self):
        secret = "provider-secret-value"
        hub = IntelligenceHub(
            self.db, self.root,
            requester=lambda *_: (401, json.dumps({"secret": secret}).encode()),
            sleeper=lambda _: None,
        )
        with patch.dict("os.environ", {"GITHUB_TOKEN": secret}), \
             self.assertRaisesRegex(ProviderError, "provider_authentication_rejected"):
            hub.collect("case-1", "github", "username", "example",
                        authorized=True, subject_consent=True)
        serialized = json.dumps(self.db.connector_health())
        self.assertNotIn(secret, serialized)
        self.assertNotIn("api.github.com", serialized)
        self.assertIn("provider_authentication_rejected", serialized)

    def test_resolution_queue_is_deduplicated_and_human_decided(self):
        service = ResolutionService(self.db)
        left = {"name": "Jane Example", "organization": "Example Labs", "username": "jane"}
        right = {"name": "Jane A Example", "organization": "Example Labs", "username": "jane"}
        first = service.propose(
            "case-1", left, right, source="approved public exports",
            authority="Written approval held by the case owner", authorized=True,
        )
        second = service.propose(
            "case-1", right, left, source="approved public exports",
            authority="Written approval held by the case owner", authorized=True,
        )
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertFalse(first["automatic_merge"])
        self.assertEqual(len(service.queue("case-1")), 1)
        decided = service.decide(
            first["id"], "accepted", reviewer="analyst-1",
            rationale="Two independently sourced public attributes agree.", authorized=True,
        )
        self.assertEqual(decided["status"], "accepted")
        self.assertFalse(decided["automatic_merge"])
        self.assertEqual(service.queue("case-1"), [])

    def test_resolution_rejects_sensitive_identifiers_and_weak_decisions(self):
        service = ResolutionService(self.db)
        with self.assertRaises(PolicyError):
            service.propose(
                "case-1", {"name": "A", "email": "a@example.com", "organization": "X"},
                {"name": "A", "organization": "X"}, source="test",
                authority="Documented test authority", authorized=True,
            )
        with self.assertRaises(PolicyError):
            service.propose(
                "case-1", {"name": "A", "organization": "X"},
                {"name": "A", "organization": "X"}, source="test",
                authority="Documented test authority", authorized=False,
            )

    def test_case_notes_cascade_with_case(self):
        row = {"id": "note-1", "case_id": "case-1", "author": "analyst",
               "classification": "question", "body": "Validate this observation",
               "created_at": "2026-09-25T00:00:00+00:00"}
        self.db.add_case_note(row)
        self.assertEqual(self.db.case_notes("case-1")[0]["body"], row["body"])
        self.db.conn.execute("DELETE FROM cases WHERE id='case-1'")
        self.db.conn.commit()
        self.assertEqual(self.db.case_notes("case-1"), [])

    def test_supabase_workflow_has_rls_narrow_grants_and_definer_guard(self):
        sql = (ROOT / "supabase/migrations/20260925000300_analyst_workflow.sql").read_text()
        self.assertEqual(sql.count(" enable row level security;"), 2)
        self.assertIn("revoke all on public.case_notes, public.review_tasks from anon, authenticated", sql)
        self.assertIn("security definer set search_path = ''", sql)
        self.assertIn("private.is_org_member(v_organisation_id", sql)
        self.assertNotIn("grant update on public.review_tasks to authenticated", sql)
        self.assertIn("grant execute on function public.decide_review_task", sql)

    def test_browser_review_paths_use_safe_dom(self):
        script = (ROOT / "public/app.js").read_text()
        page = (ROOT / "public/index.html").read_text()
        self.assertNotIn("innerHTML", script)
        self.assertIn('/api/reviews', script)
        self.assertIn('/api/notes', script)
        self.assertIn('id="review-decision-form"', page)
        self.assertIn('id="note-form"', page)

    def test_readiness_cannot_claim_competitive_without_execution_evidence(self):
        with patch("traceatlas.readiness.DeploymentDoctor.run", return_value={
            "ready": True, "production_ready": False,
            "summary": {"passed": 10, "warnings": 2, "failed": 0},
        }), patch("traceatlas.readiness.OpenOSINTBridge.doctor", return_value={
            "runtime_ready": True,
        }), patch("traceatlas.readiness.IntegrationRunner.inventory", return_value=[]), \
             patch("traceatlas.readiness.CapabilityHub.doctor", return_value={
                 "ready": 0, "upstream_engines": 40,
             }), patch("traceatlas.readiness.MediaAnalyzer.capabilities", return_value={}):
            result = ReadinessScorecard(self.db, self.root, ROOT).run()
        self.assertFalse(result["competitive_ready"])
        self.assertFalse(result["production_ready"])
        self.assertTrue(any(row["name"] == "external_tool_pack" and row["state"] == "fail"
                            for row in result["gates"]))

    def test_external_binary_lock_detects_drift(self):
        binary = self.root / "whois"
        binary.write_text("#!/bin/sh\necho whois-test 1.0\n", encoding="utf-8")
        binary.chmod(0o755)
        runner = IntegrationRunner(self.db, self.root)
        lock_path = self.root / "tools.lock.json"
        with patch.dict("traceatlas.integrations.lockfile.TOOLS", {"whois": TOOLS["whois"]}, clear=True), \
             patch.object(runner, "resolve_binary", return_value=str(binary)):
            created = IntegrationLock(runner).write(lock_path)
            self.assertEqual(created["locked"], 1)
            self.assertTrue(IntegrationLock(runner).verify(lock_path)["valid"])
            binary.write_text("#!/bin/sh\necho whois-test 2.0\n", encoding="utf-8")
            changed = IntegrationLock(runner).verify(lock_path)
        self.assertFalse(changed["valid"])
        self.assertEqual(changed["checks"][0]["state"], "changed")


if __name__ == "__main__":
    unittest.main()
