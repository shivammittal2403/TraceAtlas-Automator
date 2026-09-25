from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from traceatlas.db import CaseDB
from traceatlas.fusion_board import FusionBoard
from traceatlas.integrations.registry import TOOLS
from traceatlas.integrations.runner import DEFAULT_THEHARVESTER_SOURCES, IntegrationRunner
from traceatlas.report import humanize_event
from traceatlas.search_index import bm25_search
from traceatlas.spider.correlation import correlate
from traceatlas.spider.events import Event
from traceatlas.spider.export import export_scan


class VerifiedImprovementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = CaseDB(self.root / "traceatlas.db")
        self.db.create_case("case-1", "Verified improvements", "Authorized test")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    @staticmethod
    def _event(event_id: str, kind: str, data, parent: str | None = None,
               confidence: int = 90, risk: str = "info") -> dict:
        return {"id": event_id, "event_type": kind, "data": data, "parent_id": parent,
                "source_module": "fixture", "confidence": confidence, "risk": risk, "tags": []}

    def test_modular_correlations_find_exact_overlap_only(self):
        events = [
            self._event("d1", "DOMAIN", "a.example"),
            self._event("d2", "DOMAIN", "b.example"),
            self._event("ip", "IP_ADDRESS", "203.0.113.8"),
            self._event("h1", "HTTP_RESPONSE", {
                "requested_url": "https://a.example", "final_url": "https://shared.example",
                "security_headers": {},
            }),
            self._event("h2", "HTTP_RESPONSE", {
                "requested_url": "https://b.example", "final_url": "https://shared.example",
                "security_headers": {},
            }),
        ]
        edges = [
            {"parent_id": "d1", "child_id": "ip", "module": "dns"},
            {"parent_id": "d2", "child_id": "ip", "module": "dns"},
        ]
        names = {row["rule"] for row in correlate(events, edges)}
        self.assertIn("shared_infrastructure", names)
        self.assertIn("redirect_chain_convergence", names)
        self.assertTrue(all(row["requires_review"] for row in correlate(events, edges)))

    def test_case_search_and_automatic_fusion(self):
        self.db.start_spider_scan("scan-1", "case-1", "DOMAIN", "example.com", "passive")
        event = Event("DOMAIN", "rare-search-term.example", "fixture", "scan-1", "case-1",
                      confidence=92)
        self.db.add_spider_event(event.to_dict())
        self.db.end_spider_scan("scan-1", "completed", {"events": 1})
        results = bm25_search(self.db.searchable_documents("case-1"), "rare search term", limit=5)
        self.assertEqual(results[0]["id"], event.id)
        ranked = FusionBoard(self.db, self.root).auto_rank(
            "case-1", "infrastructure", authorized=True, owned_org=True,
        )
        self.assertEqual(ranked["signals"], 1)
        self.assertTrue(Path(ranked["output"]).is_file())

    def test_theharvester_sources_are_configurable_and_validated(self):
        runner = IntegrationRunner(self.db, self.root)
        spec = TOOLS["theharvester"]
        default, _ = runner.build_command(spec, "/bin/theHarvester", "example.com",
                                          "case-1", self.root, {})
        custom, _ = runner.build_command(spec, "/bin/theHarvester", "example.com",
                                         "case-1", self.root, {"sources": "crtsh,otx"})
        self.assertEqual(default[default.index("-b") + 1], DEFAULT_THEHARVESTER_SOURCES)
        self.assertEqual(custom[custom.index("-b") + 1], "crtsh,otx")

    def test_connector_health_tracks_streak_without_provider_secrets(self):
        self.db.record_connector_result("github", False, "ValueError: connector request failed")
        self.db.record_connector_result("github", False, "ValueError: connector request failed")
        self.assertEqual(self.db.connector_health()[0]["consecutive_failures"], 2)
        self.db.record_connector_result("github", True)
        row = self.db.connector_health()[0]
        self.assertEqual(row["consecutive_failures"], 0)
        self.assertIsNone(row["last_error_message"])

    def test_offline_html_graph_and_humanized_report_text(self):
        self.db.start_spider_scan("scan-2", "case-1", "DOMAIN", "example.com", "passive")
        event = Event("DOMAIN", "example.com", "seed", "scan-2", "case-1", confidence=100)
        self.db.add_spider_event(event.to_dict())
        self.db.end_spider_scan("scan-2", "completed", {"events": 1})
        output = export_scan(self.db, "scan-2", self.root / "graph.html", "html")
        html = output.read_text(encoding="utf-8")
        self.assertIn("Export PNG", html)
        self.assertIn("example.com", html)
        sentence = humanize_event({"event_type": "DOMAIN", "data": "example.com",
                                   "confidence": 100, "risk": "info"})
        self.assertEqual(sentence, "Domain observed: example.com (confidence 100%, risk: info)")


if __name__ == "__main__":
    unittest.main()
