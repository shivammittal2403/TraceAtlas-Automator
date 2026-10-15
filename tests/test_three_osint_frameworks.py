"""Offline isolation and canonical-evidence integration tests for three uploaded frameworks."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from traceatlas.db import CaseDB
from traceatlas.policy import PolicyError
from traceatlas.integrations.thirdparty_osint import SOURCES, catalog, normalize, import_file


class ThreeOsintFrameworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = CaseDB(self.root / "test.db")
        self.db.create_case("case-1", "Domain provenance", "Approved offline import")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_all_three_sources_pinned_and_not_represented_as_verified(self):
        self.assertEqual(set(SOURCES), {"theharvester", "osint-spy", "mr-holmes"})
        rows = catalog(repository_root=self.root)
        self.assertEqual(len(rows), 3)
        self.assertFalse(any(x["live_verified"] for x in rows))
        self.assertFalse(any(x["source_present"] for x in rows))
        from traceatlas.integrations.registry import TOOLS
        self.assertEqual(TOOLS["osint-spy"].mode, "blocked")
        self.assertEqual(TOOLS["mr-holmes"].mode, "blocked")

    def test_harvester_native_jsonl_filters_out_of_scope_and_emails(self):
        raw = "\n".join(json.dumps(x) for x in [
            {"type":"summary","target":"example.org","result_count":5},
            {"type":"hostname","value":"www.example.org","sources":["crtsh"]},
            {"type":"hostname","value":"outside.test","sources":["crtsh"]},
            {"type":"email","value":"alice@example.org"},
            {"type":"url","value":"https://api.example.org/p?access_token=secret#frag"},
        ])
        report = normalize("theharvester", raw, target_type="domain", target="example.org")
        self.assertEqual([(x["event_type"],x["data"]) for x in report["observations"]],
                         [("DOMAIN","www.example.org"),("URL","https://api.example.org/")])
        self.assertEqual(report["counts"]["invalid_or_out_of_scope_dropped"],1)
        self.assertNotIn("access_token",json.dumps(report))
        self.assertNotIn("alice@",json.dumps(report))
        self.assertFalse(report["live_verified"])

    def test_legacy_source_import_accepts_domain_fields_only(self):
        raw=json.dumps({"results":[{"host":"a.example.org","api_key":"PRIVATE"},
                                       {"host":"elsewhere.test","user":"real_person"},
                                       {"domain":"b.example.org","email":"n@example.org"}]})
        for name in ("osint-spy","mr-holmes"):
            with self.subTest(source=name):
                out=normalize(name,raw,target_type="domain",target="example.org")
                self.assertEqual([x["data"] for x in out["observations"]],
                                 ["a.example.org","b.example.org"])
                self.assertNotIn("PRIVATE",json.dumps(out))
                self.assertNotIn("n@example.org",json.dumps(out))

    def test_non_domain_identity_scope_rejected(self):
        with self.assertRaises(PolicyError):
            normalize("mr-holmes", '{}',target_type="username",target="victim")
        with self.assertRaises(ValueError):
            normalize("unknown", '{}',target_type="domain",target="example.org")

    def test_requires_existing_case_and_authorization(self):
        p=self.root/"sample.json"
        p.write_text('{"hostname":"www.example.org"}')
        with self.assertRaises(PolicyError):
            import_file(self.db,self.root,case_id="case-1",source="osint-spy",
                        file_path=p,target="example.org")
        with self.assertRaises(PolicyError):
            import_file(self.db,self.root,case_id="does-not-exist",source="osint-spy",
                        file_path=p,target="example.org",authorized=True)

    def test_actual_case_evidence_and_no_raw_secret_persistence(self):
        secret="SUPERSECRET-MUST-NOT-BE-IN-EVIDENCE-123"
        file=self.root/"export.json"
        file.write_text(json.dumps({"results":[{"domain":"a.example.org",
                                                 "api_key":secret},{"domain":"x.evil.test"}]}))
        receipt=import_file(self.db,self.root,case_id="case-1",source="osint-spy",
                            file_path=file,target="example.org",authorized=True)
        self.assertEqual(receipt["accepted"],1)
        self.assertEqual(receipt["status"],"completed")
        self.assertEqual(receipt["raw_sha256"],hashlib.sha256(file.read_bytes()).hexdigest())
        events=self.db.spider_events(receipt["scan_id"])
        self.assertEqual([x["data"] for x in events],["example.org","a.example.org"])
        self.assertGreaterEqual(len(self.db.evidence("case-1")),1)
        evidence_files=[Path(row["path"]) for row in self.db.evidence("case-1")]
        self.assertTrue(all(p.exists() for p in evidence_files))
        self.assertNotIn(secret,"".join(x.read_text() for x in evidence_files))

    def test_bounded_invalid_and_symlink_fail_closed(self):
        with self.assertRaises(ValueError):
            normalize("theharvester",b"\xff",target_type="domain",target="example.org")
        with self.assertRaises(ValueError):
            normalize("theharvester","[]",target_type="domain",target="example.org")
        file=self.root/"input.json"
        file.write_text('{"domain":"example.org"}')
        link=self.root/"alias.json"
        link.symlink_to(file)
        with self.assertRaises(ValueError):
            import_file(self.db,self.root,case_id="case-1",source="osint-spy",
                        file_path=link,target="example.org",authorized=True)


if __name__ == "__main__":
    unittest.main()
