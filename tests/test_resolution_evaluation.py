from __future__ import annotations

import json
import unittest
from pathlib import Path

from traceatlas.policy import PolicyError
from traceatlas.resolution_evaluation import evaluate_entity_resolution


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "src" / "traceatlas" / "benchmark_data" / "entity_resolution_synthetic.json"


class EntityResolutionEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.dataset = json.loads(DATASET.read_text(encoding="utf-8"))

    def test_checked_in_suite_is_synthetic_deterministic_and_never_merges(self):
        payload = self.dataset
        report = evaluate_entity_resolution(payload["cases"])
        self.assertEqual(report, evaluate_entity_resolution(payload["cases"]))
        self.assertEqual(report["cases"], 6)
        self.assertEqual(report["candidate_pairs"], 24)
        self.assertEqual(report["positive_pairs"], 4)
        self.assertEqual(report["negative_pairs"], 20)
        self.assertEqual(report["automatic_merge_attempts"], 0)
        self.assertEqual(report["false_automatic_merges"], 0)
        self.assertIsNone(report["false_merge_rate"])
        self.assertEqual(report["false_merge_rate_status"], "NOT_MEASURABLE_ZERO_AUTOMATIC_MERGE_DENOMINATOR")
        false_positives = [
            (case["case_id"], candidate["candidate_id"], candidate["score"])
            for case in report["case_results"]
            for candidate in case["ranked_candidates"]
            if candidate["predicted_candidate"] and not candidate["expected_match"]
        ]
        self.assertEqual(false_positives, [("company-namesake-03", "namesake", 0.7258)])
        self.assertIn("synthetic", payload["notice"].lower())

    def test_top_k_metrics_only_use_cases_with_a_known_positive(self):
        report = evaluate_entity_resolution(self.dataset["cases"])
        self.assertEqual(report["ranking_query_count"], 4)
        self.assertGreaterEqual(report["ranking_recall"]["recall_at_3"], report["ranking_recall"]["recall_at_1"])
        self.assertLessEqual(report["ranking_recall"]["recall_at_3"], 1.0)

    def test_rejects_ambiguous_or_malformed_labels(self):
        cases = self.dataset["cases"]
        duplicate_id = json.loads(json.dumps(cases[0]))
        duplicate_id["candidates"][1]["candidate_id"] = duplicate_id["candidates"][0]["candidate_id"]
        with self.assertRaises(PolicyError):
            evaluate_entity_resolution([duplicate_id])

        multiple_positive = json.loads(json.dumps(cases[0]))
        multiple_positive["candidates"][1]["is_match"] = True
        with self.assertRaises(PolicyError):
            evaluate_entity_resolution([multiple_positive])

        false_label = json.loads(json.dumps(cases[0]))
        false_label["expected_match_id"] = "not-a-candidate"
        with self.assertRaises(PolicyError):
            evaluate_entity_resolution([false_label])

    def test_sensitive_fields_are_rejected_by_the_existing_ranker(self):
        case = json.loads(json.dumps(self.dataset["cases"][0]))
        case["query"]["email"] = "analyst@example.test"
        with self.assertRaises(PolicyError):
            evaluate_entity_resolution([case])

    def test_rejects_invalid_thresholds_and_top_k(self):
        cases = self.dataset["cases"]
        for threshold in (-0.1, 1.1, float("nan")):
            with self.subTest(threshold=threshold), self.assertRaises(PolicyError):
                evaluate_entity_resolution(cases, threshold=threshold)
        with self.assertRaises(PolicyError):
            evaluate_entity_resolution(cases, top_k=(0,))

    def test_custom_threshold_is_not_misreported_as_the_default_boundary(self):
        report = evaluate_entity_resolution(self.dataset["cases"], threshold=0.8)
        self.assertEqual(report["threshold"], 0.8)
        self.assertIn("caller-supplied", report["threshold_provenance"])

    def test_false_merge_rate_is_not_misreported_as_zero_percent(self):
        report = evaluate_entity_resolution(self.dataset["cases"])
        self.assertIsNone(report["false_merge_rate"])
        self.assertEqual(report["automatic_merge_attempts"], 0)
        self.assertTrue(any("zero denominator" in item.lower() for item in report["limitations"]))


if __name__ == "__main__":
    unittest.main()
