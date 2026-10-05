from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from traceatlas.benchmark import GuardrailBenchmark
from traceatlas.collaboration import CollaborationService
from traceatlas.db import CaseDB
from traceatlas.intelligence import IntelligenceHub, SOURCES
from traceatlas.intelligence.provider import ProviderError, _validate_shape
from traceatlas.maturity import ProductMaturityScorecard
from traceatlas.operations import SQLiteRestoreDrill
from traceatlas.policy import PolicyError


ROOT = Path(__file__).resolve().parents[1]


class EnterpriseMaturityV18Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name)
        self.db = CaseDB(self.workspace / "traceatlas.db")
        self.db.create_case("case-1", "Enterprise", "Authorised defensive research")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_six_new_live_sources_have_fixed_official_hosts(self):
        self.assertEqual(len(SOURCES), 51)
        self.assertEqual(sum(item.live_connector for item in SOURCES.values()), 37)
        expected = {"mastodon", "stackexchange", "dockerhub", "npm", "crossref", "orcid"}
        self.assertTrue(expected.issubset(SOURCES))
        hub = IntelligenceHub(self.db, self.workspace)
        cisa_url, _ = hub._live_request(SOURCES["cisa_kev"], "cve", "CVE-2024-12345")
        self.assertEqual(cisa_url, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        with self.assertRaises(PolicyError):
            hub._live_request(SOURCES["cisa_kev"], "cve", "CVE-2024-12345 OR 1=1")
        cases = [
            ("stackexchange", "user_id", "22656", "https://api.stackexchange.com/"),
            ("dockerhub", "username", "library", "https://hub.docker.com/"),
            ("npm", "package", "express", "https://registry.npmjs.org/"),
            ("crossref", "doi", "10.5555/12345678", "https://api.crossref.org/"),
        ]
        for source, kind, target, prefix in cases:
            with self.subTest(source=source):
                url, _ = hub._live_request(SOURCES[source], kind, target)
                self.assertTrue(url.startswith(prefix))
        with patch.dict(os.environ, {
            "MASTODON_ACCESS_TOKEN": "m" * 40,
            "ORCID_ACCESS_TOKEN": "o" * 40,
        }, clear=False):
            mastodon_url, mastodon_headers = hub._live_request(
                SOURCES["mastodon"], "username", "example"
            )
            orcid_url, orcid_headers = hub._live_request(
                SOURCES["orcid"], "orcid", "0000-0002-1825-0097"
            )
        self.assertTrue(mastodon_url.startswith("https://mastodon.social/"))
        self.assertTrue(orcid_url.startswith("https://pub.orcid.org/"))
        self.assertTrue(mastodon_headers["Authorization"].startswith("Bearer "))
        self.assertTrue(orcid_headers["Authorization"].startswith("Bearer "))

    def test_new_provider_schemas_reject_drift(self):
        valid = {
            "mastodon": {"id": "1", "acct": "example", "url": "https://mastodon.social/@example"},
            "stackexchange": {"items": [{"user_id": 1}], "has_more": False},
            "dockerhub": {"count": 1, "results": [{"name": "image"}]},
            "npm": {"name": "package", "version": "1.0.0"},
            "crossref": {"status": "ok", "message": {"DOI": "10.5555/example"}},
            "orcid": {"path": "0000-0002-1825-0097", "name": None},
            "cisa_kev": {"title": "Known Exploited Vulnerabilities Catalog", "catalogVersion": "2026.10.04",
                "dateReleased": "2026-10-04T00:00:00Z", "count": 1, "vulnerabilities": [{
                    "cveID": "CVE-2024-12345", "vendorProject": "Fixture Vendor", "product": "Fixture Product",
                    "vulnerabilityName": "Fixture KEV record", "dateAdded": "2025-01-02",
                    "shortDescription": "Synthetic fixture.", "requiredAction": "Apply vendor mitigations",
                    "dueDate": "2025-01-31"}]},
        }
        for source, payload in valid.items():
            with self.subTest(source=source):
                _validate_shape(source, payload)
                with self.assertRaises(ProviderError):
                    _validate_shape(source, {"unexpected": True})

    def test_saved_views_are_persistent_and_revision_conflict_safe(self):
        service = CollaborationService(self.db)
        created = service.save_view(
            "case-1", view_id="view-one", name="Primary graph", actor="analyst@example.org",
            layout={"positions": {"entity-1": {"x": 10, "y": 20}}},
            filters={"risk": ["high"]}, expected_revision=0, authorized=True,
        )
        self.assertEqual(created["revision"], 1)
        updated = service.save_view(
            "case-1", view_id="view-one", name="Primary graph", actor="analyst@example.org",
            layout={"positions": {}}, filters={}, expected_revision=1, authorized=True,
        )
        self.assertEqual(updated["revision"], 2)
        with self.assertRaisesRegex(PolicyError, "revision conflict"):
            service.save_view(
                "case-1", view_id="view-one", name="Stale", actor="analyst@example.org",
                layout={}, filters={}, expected_revision=1, authorized=True,
            )
        with self.assertRaisesRegex(PolicyError, "non-finite"):
            service.save_view(
                "case-1", view_id="view-two", name="Unsafe", actor="analyst@example.org",
                layout={"zoom": float("nan")}, filters={}, expected_revision=0, authorized=True,
            )
        events = service.events("case-1")
        self.assertEqual([row["operation"] for row in events], ["created", "updated"])
        self.assertNotIn("positions", json.dumps(events))

    def test_collaboration_migration_uses_rls_rpc_and_realtime_event_envelope(self):
        sql = (ROOT / "supabase/migrations/20260926000300_collaboration_views.sql").read_text()
        for marker in (
            "create table public.case_views", "create table public.collaboration_events",
            "enable row level security", "view revision conflict", "for update",
            "supabase_realtime", "revoke all on function public.save_case_view",
        ):
            self.assertIn(marker, sql)
        api = (ROOT / "api/views.py").read_text()
        self.assertIn("require_same_origin(self)", api)
        self.assertIn('gateway.rpc("save_case_view"', api)
        self.assertNotIn("gateway.insert", api)
        self.assertNotIn("gateway.update", api)

    def test_versioned_guardrail_benchmark_passes_and_states_limit(self):
        packaged = files("traceatlas.benchmark_data").joinpath("ai_advisory_v1.json").read_bytes()
        self.assertEqual(packaged, (ROOT / "benchmarks/ai_advisory_v1.json").read_bytes())
        result = GuardrailBenchmark().run()
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["passed"], result["cases"])
        self.assertGreaterEqual(result["cases"], 8)
        self.assertIn("not model factual accuracy", result["limitations"][0])

    def test_local_restore_drill_creates_integrity_receipt_without_mutation(self):
        before = self.db.get_case("case-1")
        result = SQLiteRestoreDrill(self.db).run(self.workspace / "drill")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["integrity_check"], "ok")
        self.assertTrue(result["table_counts_match"])
        self.assertEqual(self.db.get_case("case-1"), before)
        restored = sqlite3.connect(self.workspace / "drill" / "traceatlas-restored.sqlite3")
        try:
            self.assertEqual(restored.execute("select count(*) from cases").fetchone()[0], 1)
        finally:
            restored.close()
        with self.assertRaises(FileExistsError):
            SQLiteRestoreDrill(self.db).run(self.workspace / "drill")

    def test_scorecard_counts_only_implemented_repository_gates(self):
        result = ProductMaturityScorecard(self.db, self.workspace, ROOT).run()
        dimensions = {row["area"]: row for row in result["dimensions"]}
        live = {gate["name"]: gate for gate in dimensions["live_source_depth"]["gates"]}
        ai = {gate["name"]: gate for gate in dimensions["ai_media_intelligence"]["gates"]}
        ux = {gate["name"]: gate for gate in dimensions["investigation_ux"]["gates"]}
        self.assertEqual(live["twenty_coded_contracts"]["state"], "pass")
        self.assertEqual(ai["model_guardrail_benchmark"]["state"], "pass")
        self.assertEqual(ux["saved_graph_views"]["state"], "pass")
        self.assertEqual(ux["realtime_collaboration"]["state"], "pass")
        self.assertFalse(result["ten_of_ten"])


if __name__ == "__main__":
    unittest.main()
