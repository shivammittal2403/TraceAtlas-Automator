import unittest

from traceatlas.evidence_evaluation import evaluate_evidence_integrity


class EvidenceIntegrityEvaluationTests(unittest.TestCase):
    def test_synthetic_evaluation_detects_unanchored_rewrite_gap(self):
        result = evaluate_evidence_integrity()
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["cases"], 9)
        self.assertEqual(result["passed"], 8)
        self.assertEqual(result["confusion"], {
            "accepted_expected_valid": 3,
            "accepted_expected_invalid": 1,
            "rejected_expected_invalid": 5,
            "rejected_expected_valid": 0,
        })
        self.assertEqual(result["adversarial_rejection_rate"], 0.8333)
        reanchoring = next(row for row in result["results"] if row["id"] == "local-rewrite-reanchored")
        self.assertTrue(reanchoring["limitation_demonstrated"])
        self.assertFalse(reanchoring["pass"])

    def test_report_discloses_semantic_citation_and_anchor_limitations(self):
        result = evaluate_evidence_integrity()
        limitations = " ".join(result["limitations"])
        self.assertIn("semantically support", limitations)
        self.assertIn("external ledger anchoring", limitations)
        self.assertTrue(all(len(row["id"]) <= 80 for row in result["results"]))


if __name__ == "__main__":
    unittest.main()
