"""Regression tests for evidence-bound competing hypotheses in legacy offline adapters."""
import unittest

from traceatlas.skills.managed140 import analyze, verify


class CompetingHypothesisTests(unittest.TestCase):
    def test_two_explicit_conflicting_assertions_yield_cited_alternatives(self):
        records = [
            {"source_id": "alpha", "independence_group": "upstream-1",
             "data": {"domain": "example.org", "claim_subject": "example.org",
                      "claim_predicate": "status", "claim_value": "available"}},
            {"source_id": "beta", "independence_group": "upstream-2",
             "data": {"domain": "example.org", "claim_subject": "example.org",
                      "claim_predicate": "status", "claim_value": "unavailable"}}
        ]
        result = analyze("DOMAININT", records)
        self.assertTrue(verify(result))
        self.assertEqual(len(result["contradictions"]), 1)
        self.assertEqual(len(result["hypotheses"]), 2)
        evidence = {item["evidence_id"] for item in result["evidence"]}
        for alternative in result["hypotheses"]:
            self.assertEqual(alternative["status"], "UNVERIFIED_COMPETING_ASSERTION")
            self.assertTrue(alternative["requires_human_review"])
            self.assertEqual(len(alternative["supporting_evidence_ids"]), 1)
            self.assertEqual(len(alternative["contrary_evidence_ids"]), 1)
            self.assertLessEqual(len(alternative["supporting_evidence_ids"]), 1)
            self.assertTrue(set(alternative["supporting_evidence_ids"]) <= evidence)
            self.assertTrue(set(alternative["contrary_evidence_ids"]) <= evidence)
            self.assertTrue(alternative["falsification_tests"])
            self.assertTrue(alternative["alternative_explanations"])
        result["hypotheses"][0]["status"] = "VERIFIED"
        self.assertFalse(verify(result))

    def test_one_assertion_is_not_an_excuse_to_invent_competition(self):
        result = analyze("DOMAININT", [{"source_id": "alpha",
            "data": {"domain": "example.org", "claim_subject": "example.org",
                     "claim_predicate": "status", "claim_value": "available"}}])
        self.assertTrue(verify(result))
        self.assertEqual(result["hypotheses"], [])

    def test_invalid_nonfinite_numbers_are_not_valid_json_evidence(self):
        for invalid in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(invalid=str(invalid)), self.assertRaises(ValueError):
                analyze("FININT", [{"source_id": "alpha", "data": {"amount": invalid}}])


if __name__ == "__main__":
    unittest.main()
