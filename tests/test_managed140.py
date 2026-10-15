"""Offline regression tests; deliberately no network or subprocess scans."""
from __future__ import annotations
import unittest
from traceatlas.skills.managed140 import CATALOG, analyze, verify
from traceatlas.skills.managed140.registry import load
from traceatlas.skills.managed140.spiderfoot_adapter import imported_records
from traceatlas.skills.managed140.bridge import to_skill_result

class Managed140Tests(unittest.TestCase):
    def test_all_140_modules_import_and_execute(self):
        self.assertEqual(len(CATALOG), 140)
        for code, spec in CATALOG.items():
            with self.subTest(code=code):
                module = load(code)
                self.assertEqual(module.CODE, code)
                report = module.run({"records": [{"source_id":"fixture", "authorization_reference":"fixture",
                    "data": {spec["fields"][0]: "example", "collection_authority":"fixture"}}]},
                    authorized=True)
                self.assertTrue(verify(report))
                self.assertEqual(report["module_id"], code)
                self.assertIn(report["status"], {"completed", "partial"})
    def test_sensitive_permission_gate(self):
        report = analyze("SIGINT", [{"source_id": "fixture", "data":{"frequency_hz": 100}}])
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(verify(report))
    def test_independent_claims_and_contradictions(self):
        records = [{"source_id": s, "independence_group": s, "data": {
            "domain":"example.org", "claim_subject": "example.org", "claim_predicate":"status",
            "claim_value": v}} for s,v in [("a","up"),("b","up"),("c","down")]]
        report = analyze("DOMAININT", records)
        self.assertEqual(len(report["corroborations"]),1)
        self.assertEqual(len(report["contradictions"]),1)
        self.assertTrue(verify(report))
        report["status"]="failed"
        self.assertFalse(verify(report))
    def test_spiderfoot_offline_import(self):
        grouped = imported_records([{"type":"DOMAIN_NAME","data":"example.org","module":"sfp_test"},
                                    {"type":"PASSWORD","data":"do-not-ingest"}],scan_id="fixture")
        self.assertEqual(len(grouped["DOMAININT"]),1)
        self.assertEqual(len(grouped),1)
        self.assertEqual(grouped["DOMAININT"][0]["data"]["domain"],"example.org")
    def test_canonical_skill_result_bridge(self):
        result = to_skill_result(analyze("DOMAININT",[{"source_id":"fixture",
                 "data":{"domain":"example.org"}}]))
        self.assertEqual(result.status, "completed")
        self.assertTrue(result.evidence_ids)

if __name__ == "__main__":
    unittest.main()
