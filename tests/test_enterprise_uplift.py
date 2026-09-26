from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.capabilities import CapabilityHub, ServiceClient
from traceatlas.db import CaseDB
from traceatlas.intelligence import CollectionOrchestrator, IntelligenceHub
from traceatlas.intelligence.ai import ANALYSIS_KEYS, validate_ai_advisory
from traceatlas.investigation import InvestigationWorkspace
from traceatlas.policy import PolicyError
from traceatlas.sensitive import SensitiveRunner


ROOT = Path(__file__).resolve().parents[1]


class EnterpriseUpliftTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "traceatlas.db")
        self.db.create_case("case-1", "Enterprise uplift", "Authorised defensive review")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_new_live_sources_use_fixed_provider_hosts_and_validate_schema(self):
        responses = {
            "rdap.org": {"objectClassName": "domain", "ldhName": "example.com"},
            "dns.google": {"Status": 0, "Answer": [{"name": "example.com.", "data": "93.184.216.34"}]},
            "web.archive.org": [["timestamp", "original"], ["20240101", "https://example.com/"]],
            "internetdb.shodan.io": {"ip": "8.8.8.8", "ports": [53]},
            "public.api.bsky.app": {"handle": "example.test", "displayName": "Example"},
        }

        def requester(url, _headers, _timeout):
            for host, payload in responses.items():
                if host in url:
                    return 200, json.dumps(payload).encode()
            return 404, b"{}"

        hub = IntelligenceHub(self.db, self.root, requester=requester)
        for source, kind, target, gates in (
            ("rdap", "domain", "example.com", {"owned_asset": True, "public_record_basis": True}),
            ("dns", "domain", "example.com", {"owned_asset": True}),
            ("wayback", "domain", "example.com", {"owned_asset": True}),
            ("internetdb", "ip", "8.8.8.8", {"owned_asset": True}),
            ("bluesky", "username", "example.test", {"subject_consent": True}),
        ):
            result = hub.collect("case-1", source, kind, target, authorized=True, **gates)
            self.assertEqual(result["status"], "completed")
            self.assertTrue(result["provider"]["schema_validated"])

    def test_batch_budget_and_circuit_breaker_are_explicit(self):
        hub = IntelligenceHub(
            self.db, self.root,
            requester=lambda *_: (200, json.dumps({"Status": 0, "Answer": []}).encode()),
        )
        for _ in range(3):
            self.db.record_connector_result("dns", False, "provider_unavailable")
        result = CollectionOrchestrator(hub).run(
            "case-1", [{"source": "dns", "target_type": "domain", "target": "example.com"}],
            authorized=True, owned_asset=True,
        )
        self.assertEqual(result["outcomes"][0]["reason"], "circuit_open")
        self.assertNotIn("example.com", json.dumps(result))

    def test_intelowl_bridge_requires_explicit_analyzers_and_trusted_endpoint(self):
        with patch.dict("os.environ", {"INTELOWL_API_KEY": "test-token", "INTELOWL_URL": "http://127.0.0.1:80"}, clear=False):
            with patch.object(ServiceClient, "_post", return_value={"job_id": 42}) as post:
                result = ServiceClient.intelowl("example.com", {
                    "observable_classification": "domain",
                    "analyzers_requested": ["DNSResolver"], "tlp": "AMBER",
                })
            self.assertEqual(result["job_id"], 42)
            self.assertEqual(post.call_args.args[0], "http://127.0.0.1:80/api/analyze_observable")
            self.assertEqual(post.call_args.args[2]["Authorization"], "Token test-token")
        with self.assertRaisesRegex(PolicyError, "explicit analyzers"):
            with patch.dict("os.environ", {"INTELOWL_API_KEY": "test-token"}, clear=False):
                ServiceClient.intelowl("example.com", {"observable_classification": "domain"})

    def test_ai_contract_rejects_unstructured_or_incomplete_output(self):
        valid = {key: ([] if kind is list else "summary") for key, kind in ANALYSIS_KEYS.items()}
        self.assertEqual(validate_ai_advisory(valid, ANALYSIS_KEYS)["executive_summary"], "summary")
        with self.assertRaisesRegex(ValueError, "missing"):
            validate_ai_advisory({"executive_summary": "only prose"}, ANALYSIS_KEYS)

    def test_workspace_links_coverage_health_timeline_and_review_queue(self):
        export = self.root / "registry.json"
        export.write_text('[{"company":"Example Ltd"}]', encoding="utf-8")
        IntelligenceHub(self.db, self.root).ingest(
            "case-1", "business_registry", export,
            authorized=True, public_record_basis=True,
        )
        self.db.record_connector_result("dns", False, "provider_unavailable")
        view = InvestigationWorkspace(self.db).build("case-1")
        self.assertEqual(view["overview"]["distinct_sources"], 2)
        self.assertEqual(view["review_queue"]["connector_failures"], 1)
        self.assertTrue(view["timeline"])
        self.assertTrue(view["next_actions"])

    def test_darkweb_feed_keeps_only_fingerprints_and_counts(self):
        feed = self.root / "feed.json"
        feed.write_text(json.dumps({"objects": [{
            "indicator": "example.com seen at abcdefghijklmnop.onion",
            "password": "must-not-survive", "hash": "a" * 64,
        }]}), encoding="utf-8")
        result = SensitiveRunner(self.db, self.root).darkweb_feed(
            "case-1", "example.com", feed, "stix",
            lawful_purpose="Monitor an owned domain for approved threat-feed mentions",
            authorized=True, allow_sensitive=True, owned_domain=True, source_permission=True,
        )
        events = json.dumps(self.db.spider_events(result["scan_id"]))
        self.assertIn("DARKWEB_FEED_MENTION", events)
        self.assertNotIn("must-not-survive", events)
        self.assertNotIn("abcdefghijklmnop.onion", events)

    def test_enterprise_migration_fixes_policy_and_adds_hard_controls(self):
        analyst = (ROOT / "supabase/migrations/20260925000300_analyst_workflow.sql").read_text()
        enterprise = (ROOT / "supabase/migrations/20260926000100_enterprise_controls.sql").read_text()
        self.assertNotIn("and assigned_to is null", analyst)
        for marker in (
            "create table public.source_runs", "create table public.case_retention",
            "audit_events_append_only", "cases_legal_hold", "set_case_retention",
            "enable row level security", "revoke all on public.source_runs",
        ):
            self.assertIn(marker, enterprise)

    def test_service_result_is_preserved_as_evidence(self):
        hub = CapabilityHub(self.db, self.root)
        with patch.object(ServiceClient, "intelowl", return_value={"job_id": 9, "status": "accepted"}):
            result = hub.service_call(
                "case-1", "intelowl", "analyze", "example.com",
                {"observable_classification": "domain", "analyzers_requested": ["DNSResolver"]},
                authorized=True, owned_org=True,
            )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(self.db.evidence("case-1")), 1)
        self.assertEqual(self.db.source_runs(case_id="case-1")[0]["status"], "completed")
        self.assertEqual(self.db.source_runs(case_id="case-1")[0]["source"], "intelowl")
        health = {row["tool"]: row for row in self.db.integration_health()}
        self.assertEqual(health["intelowl"]["consecutive_failures"], 0)
        self.assertIsNotNone(health["intelowl"]["last_success_at"])


if __name__ == "__main__":
    unittest.main()
