from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

from traceatlas.policy import PolicyError
from traceatlas.research import ResearchCatalog, explainable_entity_match, temporal_analysis
from traceatlas.research.catalog import _load_jsonl
from traceatlas.research_cli import main as research_main


class ResearchPackTests(unittest.TestCase):
    def setUp(self):
        self.catalog = ResearchCatalog()

    def test_pack_contains_4096_unique_audited_papers(self):
        status = self.catalog.status(verify=True)
        self.assertTrue(status["valid"])
        self.assertEqual(status["datasets"]["papers"]["records"], 4096)
        self.assertEqual(status["datasets"]["patents"]["records"], 500)
        self.assertEqual(status["datasets"]["gaps"]["records"], 1000)
        self.assertEqual(status["datasets"]["matches"]["records"], 959)
        self.assertEqual(status["selection"]["source_cross_match_records"], 1000)
        self.assertEqual(status["selection"]["excluded_cross_match_records"], 41)
        papers = _load_jsonl("papers.jsonl.gz")
        self.assertEqual(len({row["id"] for row in papers}), 4096)
        self.assertEqual(len({" ".join(row["title"].casefold().split()) for row in papers}), 4096)
        self.assertTrue(all(1900 <= row["year"] <= 2026 for row in papers))
        self.assertTrue(all("abstract" not in row for row in papers))

    def test_all_gap_research_evidence_is_resolvable(self):
        paper_ids = {row["id"] for row in _load_jsonl("papers.jsonl.gz")}
        evidence_ids = {
            paper_id
            for gap in _load_jsonl("gaps.jsonl.gz")
            for paper_id in gap["evidence_research_ids"]
        }
        self.assertTrue(evidence_ids)
        self.assertEqual(evidence_ids - paper_ids, set())
        match_paper_ids = {row["paper_id"] for row in _load_jsonl("matches.jsonl.gz")}
        patent_ids = {row["id"] for row in _load_jsonl("patents.jsonl.gz")}
        match_patent_ids = {row["patent_id"] for row in _load_jsonl("matches.jsonl.gz")}
        self.assertEqual(match_paper_ids - paper_ids, set())
        self.assertEqual(match_patent_ids - patent_ids, set())

    def test_bm25_search_is_explainable_filtered_and_deterministic(self):
        first = self.catalog.search(
            "entity resolution", limit=8, subtopic="Entity resolution", min_year=2000
        )
        second = self.catalog.search(
            "entity resolution", limit=8, subtopic="Entity resolution", min_year=2000
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 8)
        self.assertTrue(all(row["subtopic"] == "Entity resolution" for row in first))
        self.assertTrue(all(row["matched_terms"] for row in first))
        self.assertEqual(len({row["id"] for row in first}), len(first))

    def test_gap_plan_and_prior_art_keep_limitations_visible(self):
        gaps = self.catalog.gaps("privacy provenance", limit=5)
        self.assertEqual(len(gaps), 5)
        self.assertTrue(all("proof of novelty" in row["caveat"] for row in gaps))
        plan = self.catalog.collection_plan("cross-platform evidence provenance", limit=5)
        self.assertTrue(plan["review_required"])
        self.assertLessEqual(len(plan["steps"]), 5)
        link = self.catalog.prior_art("RES-NEW-01645")
        self.assertTrue(link["candidate_patent_links"])
        self.assertIn("not", link["caveat"])

    def test_entity_resolution_is_explainable_and_never_auto_merges(self):
        result = explainable_entity_match(
            {
                "name": "Red Kross Research Foundation",
                "organization": "RedKross Research Foundation",
                "domain": "redkross.example",
            },
            {
                "name": "RedKross Research Foundation",
                "organization": "Red Kross Research Foundation",
                "domain": "redkross.example",
            },
        )
        self.assertEqual(result["classification"], "strong_candidate")
        self.assertFalse(result["automatic_merge"])
        self.assertTrue(result["review_required"])
        with self.assertRaisesRegex(PolicyError, "sensitive"):
            explainable_entity_match({"email": "a@example.com"}, {"email": "a@example.com"})

    def test_temporal_analysis_detects_conflicts_and_scores_freshness(self):
        result = temporal_analysis([
            {
                "subject": "asset-1", "predicate": "owner", "value": "Org A",
                "source": "registry-a", "observed_at": "2026-09-20T00:00:00Z",
                "valid_from": "2026-01-01", "valid_to": "2026-12-31",
            },
            {
                "subject": "asset-1", "predicate": "owner", "value": "Org B",
                "source": "registry-b", "observed_at": "2026-09-01T00:00:00Z",
                "valid_from": "2026-06-01", "valid_to": "2026-10-01",
            },
        ], as_of=date(2026, 9, 25), half_life_days=30)
        self.assertEqual(len(result["conflicts"]), 1)
        self.assertEqual(len(result["freshness"]), 2)
        self.assertTrue(result["review_required"])

    def test_standalone_cli_reads_json_without_network(self):
        with tempfile.TemporaryDirectory() as temp:
            left = Path(temp) / "left.json"
            right = Path(temp) / "right.json"
            left.write_text(json.dumps({"name": "Example", "domain": "example.org"}))
            right.write_text(json.dumps({"name": "Example", "domain": "example.org"}))
            output = io.StringIO()
            with redirect_stdout(output):
                result = research_main(["match", "--left", str(left), "--right", str(right)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["classification"], "strong_candidate")


if __name__ == "__main__":
    unittest.main()
