from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from traceatlas.engine import Engine
from traceatlas.evidence import EvidenceStore
from traceatlas.cli import main
from traceatlas.playbooks import METHODS, get_method
from traceatlas.policy import PolicyError, validate_target
from traceatlas.report import build_report, write_reports
from traceatlas.spider import SpiderEngine
from traceatlas.spider.export import export_scan


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.engine = Engine(self.root / "cases")
        self.engine.db.create_case("case-1", "Test", "Authorized unit test")

    def tearDown(self):
        self.engine.close()
        self.tmp.cleanup()

    def test_all_40_methods_are_present_and_unique(self):
        self.assertEqual(len(METHODS), 40)
        self.assertEqual({m.id for m in METHODS}, set(range(40)))
        self.assertEqual(len({m.slug for m in METHODS}), 40)
        self.assertEqual(get_method("domain-map").id, 4)

    def test_target_validation(self):
        self.assertEqual(validate_target("domain", "example.com").value, "example.com")
        with self.assertRaises(PolicyError):
            validate_target("url", "file:///etc/passwd")
        with self.assertRaises(PolicyError):
            validate_target("email", "not-an-email")

    def test_authorization_gate(self):
        with self.assertRaises(PolicyError):
            self.engine.run("case-1", "domain-map", "domain", "example.com")

    def test_sensitive_methods_cannot_bypass_redacted_runner(self):
        with self.assertRaisesRegex(PolicyError, "dedicated redacted command"):
            self.engine.run(
                "case-1", "credential-monitoring", "email",
                "analyst@example.com", authorized=True,
            )
        self.assertEqual(self.engine.db.runs("case-1"), [])

    def test_file_preservation_and_dedupe(self):
        source = self.root / "sample.txt"
        source.write_text("evidence", encoding="utf-8")
        first = self.engine.run("case-1", "file-metadata", "file", str(source))
        second = self.engine.run("case-1", "file-metadata", "file", str(source))
        self.assertEqual(first["findings_added"], 1)
        self.assertEqual(second["findings_added"], 0)
        store = EvidenceStore(self.root / "cases", self.engine.db, "case-1")
        valid, entries = store.verify_ledger()
        self.assertTrue(valid)
        self.assertEqual(entries, 2)

    def test_email_header_parser_and_reports(self):
        message = self.root / "message.eml"
        message.write_text(
            "From: analyst@example.org\nTo: team@example.com\n"
            "Date: Tue, 01 Sep 2026 10:00:00 +0000\n"
            "Message-ID: <test@example.org>\n\nHello\n", encoding="utf-8"
        )
        result = self.engine.run("case-1", "email-headers", "file", str(message))
        self.assertEqual(result["status"], "completed")
        report = build_report(self.engine.db, "case-1")
        self.assertEqual(len(report["findings"]), 1)
        json_path, md_path = write_reports(self.engine.db, "case-1", self.root / "reports")
        self.assertTrue(json_path.exists())
        self.assertIn("OSINT Case Report", md_path.read_text(encoding="utf-8"))
        json.loads(json_path.read_text(encoding="utf-8"))

    def test_monitor_is_stable_when_findings_do_not_change(self):
        argv = [
            "--workspace", str(self.root / "cases"), "monitor",
            "--case", "case-1", "--method", "advanced-search",
            "--target-type", "text", "--target", "unchanged subject",
        ]
        self.assertEqual(main(argv), 0)
        self.assertEqual(main(argv), 0)
        rows = self.engine.db.conn.execute(
            "SELECT content_hash FROM snapshots ORDER BY id"
        ).fetchall()
        self.assertEqual(rows[0]["content_hash"], rows[1]["content_hash"])

    def test_spider_event_cascade_dedup_and_exports(self):
        result = SpiderEngine(self.engine.db).scan(
            "case-1", "EMAIL_ADDRESS", "analyst@example.org",
            enabled_modules=["email_domain"], max_depth=3,
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["stats"]["events"], 2)
        events = self.engine.db.spider_events(result["scan_id"])
        self.assertEqual([e["event_type"] for e in events], ["EMAIL_ADDRESS", "DOMAIN"])
        json_path = export_scan(
            self.engine.db, result["scan_id"], self.root / "graph.json", "json"
        )
        gexf_path = export_scan(
            self.engine.db, result["scan_id"], self.root / "graph.gexf", "gexf"
        )
        self.assertTrue(json_path.exists())
        self.assertIn("gexf", gexf_path.read_text(encoding="utf-8"))

    def test_spider_bounds(self):
        with self.assertRaises(PolicyError):
            SpiderEngine(self.engine.db).scan(
                "case-1", "TEXT", "seed", max_events=0
            )


if __name__ == "__main__":
    unittest.main()
