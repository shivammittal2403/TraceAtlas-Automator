from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.capabilities import ServiceClient
from traceatlas.db import CaseDB
from traceatlas.intelligence import IntelligenceAnalyzer, IntelligenceHub
from traceatlas.intelligence.ai import ANALYSIS_CLAIM_FIELDS, ANALYSIS_KEYS, validate_ai_advisory
from traceatlas.intelligence.modules import (
    MODULE_CATALOG, catalog_rows, normalize_remote_configs, reconcile_catalog,
    resolve_remote_modules,
)
from traceatlas.maturity import ProductMaturityScorecard
from traceatlas.policy import PolicyError
from traceatlas.sensitive import SensitiveRunner


ROOT = Path(__file__).resolve().parents[1]


class EnterpriseMaturityV17Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp.name)
        self.db = CaseDB(self.workspace / "traceatlas.db")
        self.db.create_case("case-1", "Maturity", "Authorised organisation review")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_supplied_intelowl_inventory_is_complete_and_truthful(self):
        self.assertEqual(len(MODULE_CATALOG), 187)
        self.assertEqual(len({item.id for item in MODULE_CATALOG.values()}), 187)
        self.assertEqual(len(catalog_rows(kind="analyzer")), 173)
        self.assertEqual(len(catalog_rows(kind="connector")), 13)
        self.assertEqual(len(catalog_rows(kind="framework")), 1)
        self.assertEqual(MODULE_CATALOG["pe-info"].execution, "file-route-blocked")
        self.assertEqual(MODULE_CATALOG["misp-connector"].execution, "catalogued")

    def test_remote_module_resolution_requires_exact_enabled_target_contract(self):
        remote = [
            {"name": "AbuseIPDB", "disabled": False, "observable_supported": ["ip"]},
            {"name": "OTXQuery", "disabled": False, "observable_supported": ["domain", "ip"]},
        ]
        self.assertEqual(resolve_remote_modules(["abuseipdb"], remote, "ip"), ["AbuseIPDB"])
        self.assertEqual(resolve_remote_modules(["otx"], remote, "domain"), ["OTXQuery"])
        with self.assertRaisesRegex(PolicyError, "does not advertise"):
            resolve_remote_modules(["abuseipdb"], remote, "domain")
        with self.assertRaisesRegex(PolicyError, "not enabled"):
            resolve_remote_modules(["pe-info"], remote, "hash")

    def test_remote_config_shapes_are_bounded_and_discovery_is_not_execution(self):
        rows = normalize_remote_configs({
            "AbuseIPDB": {"disabled": False, "observable_supported": ["ip", "unknown"]},
            "bad name with spaces": {"observable_supported": ["domain"]},
        })
        self.assertEqual(rows, [{
            "name": "AbuseIPDB", "disabled": False, "observable_supported": ["ip"],
        }])
        report = reconcile_catalog(rows)
        self.assertEqual(report["catalogued"], 187)
        self.assertFalse(report["execution_verified"])

    def test_intelowl_config_discovery_uses_fixed_endpoint_and_environment_secret(self):
        with patch.dict("os.environ", {
            "INTELOWL_API_KEY": "secret-token", "INTELOWL_URL": "http://127.0.0.1:80",
        }, clear=False):
            with patch.object(ServiceClient, "_get", return_value=[]) as request:
                ServiceClient.intelowl_analyzer_configs(17)
        self.assertEqual(request.call_args.args[0], "http://127.0.0.1:80/api/get_analyzer_configs")
        self.assertEqual(request.call_args.args[1], 17)
        self.assertEqual(request.call_args.args[2]["Authorization"], "Token secret-token")

    def test_new_profile_sources_normalize_and_record_source_run(self):
        payload = [{
            "id": 7, "username": "example", "name": "Example", "web_url": "https://gitlab.com/example",
        }]
        hub = IntelligenceHub(
            self.db, self.workspace,
            requester=lambda *_: (200, json.dumps(payload).encode()),
        )
        result = hub.collect(
            "case-1", "gitlab", "username", "example", authorized=True, subject_consent=True,
        )
        self.assertEqual(result["status"], "completed")
        events = self.db.spider_events(result["scan_id"])
        profile = next(row["data"]["normalized_profile"] for row in events if "normalized_profile" in row["data"])
        self.assertEqual(profile["handle"], "example")
        self.assertIn("not proof", profile["identity_warning"])
        runs = self.db.source_runs(case_id="case-1")
        self.assertEqual(runs[0]["source"], "gitlab")
        self.assertEqual(runs[0]["status"], "completed")
        self.assertNotIn("example", json.dumps(runs))

    def test_ai_claims_require_real_evidence_ids(self):
        value = {
            key: ([] if expected is list else "bounded summary")
            for key, expected in ANALYSIS_KEYS.items()
        }
        value["patterns"] = [{
            "statement": "Two facts overlap", "confidence": 70, "evidence_ids": ["event-1"],
        }]
        result = validate_ai_advisory(
            value, ANALYSIS_KEYS, evidence_ids={"event-1"}, claim_fields=ANALYSIS_CLAIM_FIELDS,
        )
        self.assertEqual(result["patterns"][0]["evidence_ids"], ["event-1"])
        value["patterns"][0]["evidence_ids"] = ["invented"]
        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            validate_ai_advisory(
                value, ANALYSIS_KEYS, evidence_ids={"event-1"}, claim_fields=ANALYSIS_CLAIM_FIELDS,
            )

    def test_successful_local_model_call_records_operational_evidence(self):
        source = self.workspace / "business.json"
        source.write_text('[{"company":"Example Ltd"}]', encoding="utf-8")
        scan = IntelligenceHub(self.db, self.workspace).ingest(
            "case-1", "business_registry", source,
            authorized=True, public_record_basis=True,
        )
        advisory = {
            key: ([] if expected is list else "reviewed summary")
            for key, expected in ANALYSIS_KEYS.items()
        }
        requester = lambda *_: (200, json.dumps({
            "response": json.dumps(advisory),
        }).encode())
        result = IntelligenceAnalyzer(self.db, requester=requester).analyze(
            scan["scan_id"], use_ollama=True,
        )
        self.assertTrue(result["ai_analysis"]["enabled"])
        health = {row["tool"]: row for row in self.db.integration_health()}
        self.assertEqual(health["ollama"]["last_status"], "completed")

    def test_maturity_is_gate_based_and_does_not_fake_ten(self):
        result = ProductMaturityScorecard(self.db, self.workspace, ROOT).run()
        self.assertEqual(len(result["dimensions"]), 6)
        self.assertTrue(all(len(row["gates"]) == 10 for row in result["dimensions"]))
        self.assertFalse(result["ten_of_ten"])
        self.assertLess(result["overall"], 10)

    def test_identity_governance_has_mfa_last_owner_and_concurrency_controls(self):
        sql = (ROOT / "supabase/migrations/20260926000200_identity_governance.sql").read_text()
        for marker in (
            "auth.jwt() ->> 'aal'", "aal2 required", "last owner cannot be demoted",
            "last owner cannot be removed", "role = 'owner' for update",
            "revoke all on function", "grant execute on function",
        ):
            self.assertIn(marker, sql)

    def test_darkweb_misp_records_run_and_retains_only_fingerprints(self):
        response = {"Attribute": [{
            "value": "example.com appeared near abcdefghijklmnop.onion",
            "password": "must-not-survive",
        }]}
        with patch.object(ServiceClient, "misp", return_value=response):
            result = SensitiveRunner(self.db, self.workspace).darkweb_misp(
                "case-1", "example.com",
                lawful_purpose="Monitor an owned domain in an approved MISP instance",
                authorized=True, allow_sensitive=True, owned_domain=True,
                source_permission=True,
            )
        self.assertEqual(result["status"], "completed")
        run = self.db.source_runs(case_id="case-1")[0]
        self.assertEqual((run["source"], run["status"]), ("misp", "completed"))
        events = json.dumps(self.db.spider_events(result["scan_id"]))
        self.assertNotIn("must-not-survive", events)
        self.assertNotIn("abcdefghijklmnop.onion", events)


if __name__ == "__main__":
    unittest.main()
