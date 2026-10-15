"""Offline regression contracts for the optional COLRF review overlay."""
from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace

from traceatlas.workforce.colrf import (
    COLRF_DIMENSIONS, COLRF_SCHEMA, COLRF_STAGES, build_colrf_review,
)


class COLRFReviewTests(unittest.TestCase):
    def make_input(self, status="SUPPORTED", same_group=False):
        task = SimpleNamespace(case_id="case-1", task_id="task-1", objective="Assess approved sample DNS evidence", target_entities=("domain:example.org",))
        docs = tuple(SimpleNamespace(source_id=s) for s in ("alpha", "beta"))
        evidence = tuple(SimpleNamespace(case_id="case-1", source_id=source, evidence_id="e" + str(i), acquisition_id="a" + str(i))
                         for i, source in enumerate(("alpha", "beta"), 1))
        analysis = {
            "observations": [
                {"observation_id": "o1", "evidence_id": "e1", "acquisition_id": "a1", "observed_at": "2026-01-01T00:00:00+00:00"},
                {"observation_id": "o2", "evidence_id": "e2", "acquisition_id": "a2", "observed_at": "2026-01-02T00:00:00+00:00"}],
            "claims": [{"claim_id": "c1", "observation_ids": ["o1", "o2"]}],
            "source_lineage": [
                {"source_id": "alpha", "independence_group": "g1"},
                {"source_id": "beta", "independence_group": "g1" if same_group else "g2"}],
            "verification": [{"claim_id": "c1", "status": status, "integrity_passed": True,
                              "independent_groups": ["g1"] if same_group else ["g1", "g2"],
                              "contradicting_observation_ids": ["o2"] if status == "DISPUTED" else []}],
        }
        outcomes = [{"source_id": "alpha", "status": "captured"}, {"source_id": "beta", "status": "captured"}]
        return task, analysis, docs, evidence, outcomes

    def test_nine_stages_eight_independent_dimensions_and_review_gate(self):
        result = build_colrf_review(*self.make_input())
        self.assertEqual(result["schema"], COLRF_SCHEMA)
        self.assertEqual(tuple(result["stages"]), COLRF_STAGES)
        self.assertEqual(set(result["claim_reviews"][0]["dimensions"]), set(COLRF_DIMENSIONS))
        self.assertEqual(result["claim_reviews"][0]["dimensions"]["corroboration"], "CORROBORATED")
        self.assertEqual(result["claim_reviews"][0]["dimensions"]["source_reliability"], "NOT_EMPIRICALLY_MEASURED")
        self.assertEqual(result["stages"]["operational_feedback"], "NOT_COLLECTED")
        self.assertEqual(result["release_gate"], "DRAFT_REQUIRES_HUMAN_RELEASE")

    def test_repeated_source_lineage_is_not_independent(self):
        result = build_colrf_review(*self.make_input("PARTIALLY_SUPPORTED", same_group=True))
        self.assertEqual(result["source_summary"]["independence_groups"], 1)
        self.assertEqual(result["claim_reviews"][0]["dimensions"]["corroboration"], "INSUFFICIENT_OR_UNVERIFIED")

    def test_dispute_and_partial_collection_are_visible(self):
        args = list(self.make_input("DISPUTED"))
        args[4][1] = {"source_id": "beta", "status": "restricted"}
        result = build_colrf_review(*args)
        self.assertEqual(result["stages"]["collection"], "PARTIAL")
        self.assertEqual(result["claim_reviews"][0]["dimensions"]["corroboration"], "DISPUTED")
        self.assertEqual(result["claim_reviews"][0]["contradicting_observation_ids"], ["o2"])
        self.assertEqual(result["source_summary"]["failed_or_restricted_sources"], ["beta"])

    def test_replay_is_deterministic_and_stale_lineage_fails_closed(self):
        args = self.make_input()
        self.assertEqual(build_colrf_review(*args), build_colrf_review(*args))
        edited = copy.deepcopy(args[1])
        edited["verification"][0]["independent_groups"] = ["fake"]
        with self.assertRaisesRegex(ValueError, "independence-group mismatch"):
            build_colrf_review(args[0], edited, *args[2:])

    def test_cross_case_and_missing_claims_fail_closed(self):
        args = list(self.make_input())
        args[3] = (SimpleNamespace(case_id="other", source_id="alpha", evidence_id="e1"), args[3][1])
        with self.assertRaisesRegex(ValueError, "cross-case"):
            build_colrf_review(*args)
        args = list(self.make_input())
        args[1]["verification"] = []
        with self.assertRaisesRegex(ValueError, "claim binding"):
            build_colrf_review(*args)


if __name__ == "__main__":
    unittest.main()
