from __future__ import annotations

import unittest

from traceatlas.workforce.lineage_evaluation import evaluate_source_independence


class SourceIndependenceEvaluationTests(unittest.TestCase):
    def test_synthetic_suite_reports_pairwise_metrics(self):
        report = evaluate_source_independence()
        self.assertEqual(report["case_count"], 12)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["counts"], {"tp": 7, "fp": 0, "tn": 5, "fn": 0})
        self.assertEqual(report["metrics"]["precision"], 1.0)
        self.assertEqual(report["metrics"]["recall"], 1.0)
        false_merges = [row["id"] for row in report["results"]
                        if row["predicted_same_group"] and not row["expected_same_origin"]]
        self.assertEqual(false_merges, [])
        self.assertTrue(any("contradiction" in item for item in report["limitations"]))

    def test_evaluation_is_deterministic(self):
        self.assertEqual(evaluate_source_independence(), evaluate_source_independence())


if __name__ == "__main__":
    unittest.main()
