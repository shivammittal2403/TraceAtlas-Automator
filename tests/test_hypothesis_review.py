"""Pair-specific canonical alternatives preserve witnesses, scope and honest bounds."""
import json
import unittest

from traceatlas.workforce.contracts import Observation, SemanticClass
from traceatlas.workforce.documents import DOCUMENT_SCHEMA, SourceDocument, StructuredFact
from traceatlas.workforce.hypothesis_review import build_hypothesis_review, project_hypotheses

STAMP = "2026-10-16T00:00:00+00:00"


def row(identity, value, *, predicate="registered_country",
        lower="2026-10-01T00:00:00Z", upper=None):
    fact = StructuredFact("domain:example.org", predicate, value, lower, upper)
    source = "source-" + str(identity)
    observation = Observation(
        "observation-" + str(identity), "evidence-" + str(identity),
        "acquisition-" + str(identity), "Source assertion: " + value,
        SemanticClass.OBSERVATION, fact.valid_from)
    content = json.dumps({
        "schema": "traceatlas-structured-source/v1",
        "facts": [fact.to_dict()]}, sort_keys=True)
    document = SourceDocument(
        DOCUMENT_SCHEMA, source, "urn:fixture:" + str(identity), STAMP,
        content, (fact,), None, None)
    return fact, observation, document


def review(*rows, case_id="case-a", task_id="task-a", lineage=None):
    groups = lineage if lineage is not None else {
        doc.source_id: "group-" + doc.source_id for _, _, doc in rows}
    return build_hypothesis_review(case_id, task_id, rows, groups)


class HypothesisReviewTests(unittest.TestCase):
    def test_conflict_yields_two_cited_candidates_and_pending_falsification_checks(self):
        result = review(row("a", "US"), row("b", "CA"))
        self.assertEqual(result["comparisons_total"], 1)
        self.assertEqual(len(result["hypotheses"]), 2)
        self.assertEqual(result["comparisons_omitted"], 0)
        self.assertFalse(result["source_independence_verified"])
        self.assertFalse(result["probabilities_calibrated"])
        projected = project_hypotheses(result)
        self.assertEqual(len(projected), 2)
        for candidate, contract in zip(result["hypotheses"], projected):
            self.assertEqual(candidate["status"], "UNVERIFIED_COMPETING_ASSERTION")
            self.assertFalse(candidate["hypothesis_proven_true"])
            self.assertNotEqual(candidate["supporting_observation_ids"],
                                candidate["contrary_observation_ids"])
            self.assertEqual(set(contract.evidence_ids), {"evidence-a", "evidence-b"})
            self.assertEqual(contract.next_checks,
                             tuple(check["check_id"] for check in candidate["next_checks"]))
            self.assertTrue(all(
                check["state"] == "PENDING_HUMAN_REVIEW" and not check["automatic_execution"]
                for check in candidate["next_checks"]))
            check = candidate["next_checks"][0]
            self.assertEqual(check["kind"], "test-candidate-against-primary-record")
            self.assertEqual(check["operator"], "not_equals")
            self.assertEqual(check["expected_value"], candidate["candidate_value"])
            self.assertEqual(check["expected_scope"], {
                "subject": "domain:example.org", "predicate": "registered_country",
                "valid_from": "2026-10-01T00:00:00+00:00", "valid_to": None,
                "inclusive": True, "cardinality": "one"})
            self.assertEqual(check["current_counterexample_observation_ids"],
                             candidate["contrary_observation_ids"])
            self.assertEqual(check["current_counterexample_evidence_ids"],
                             candidate["contrary_evidence_ids"])
            self.assertEqual(check["evaluation"], "CAPTURED_COUNTERASSERTION_ONLY")
            self.assertEqual(check["next_evaluation"], "PENDING_AUTHENTICATED_PRIMARY_REVIEW")
            self.assertFalse(check["hypothesis_proven_true"])

    def test_lone_agreeing_historical_and_multivalue_rows_do_not_invent_competition(self):
        inputs = [
            [row("a", "US")],
            [row("a", "US"), row("b", "US")],
            [row("a", "US", upper="2026-10-02T00:00:00Z"),
             row("b", "CA", lower="2026-10-03T00:00:00Z")],
            [row("a", "192.0.2.1", predicate="resolves_to"),
             row("b", "192.0.2.2", predicate="resolves_to")],
        ]
        for rows in inputs:
            with self.subTest(rows=len(rows)):
                result = review(*rows)
                self.assertEqual(result["hypotheses"], [])
                self.assertEqual(project_hypotheses(result), ())

    def test_disjoint_chain_does_not_imply_transitive_competition(self):
        result = review(
            row("a", "US", lower="2026-10-01T00:00:00Z", upper="2026-10-03T00:00:00Z"),
            row("b", "CA", lower="2026-10-02T00:00:00Z", upper="2026-10-05T00:00:00Z"),
            row("c", "GB", lower="2026-10-04T00:00:00Z", upper="2026-10-06T00:00:00Z"))
        self.assertEqual(result["comparisons_total"], 2)
        groups = result["comparison_groups"]
        self.assertEqual([g["observation_ids"] for g in groups], [
            ["observation-a", "observation-b"], ["observation-b", "observation-c"]])
        self.assertEqual([(g["valid_from"], g["valid_to"]) for g in groups], [
            ("2026-10-02T00:00:00+00:00", "2026-10-03T00:00:00+00:00"),
            ("2026-10-04T00:00:00+00:00", "2026-10-05T00:00:00+00:00")])
        self.assertEqual(len(result["hypotheses"]), 4)
        self.assertEqual(len({h["hypothesis_id"] for h in result["hypotheses"]}), 4)
        by_id = {g["comparison_id"]: g for g in groups}
        for candidate in result["hypotheses"]:
            group = by_id[candidate["comparison_id"]]
            check = candidate["next_checks"][0]
            self.assertEqual(check["expected_scope"]["valid_from"], group["valid_from"])
            self.assertEqual(check["expected_scope"]["valid_to"], group["valid_to"])
            self.assertEqual(
                set(candidate["supporting_observation_ids"] + candidate["contrary_observation_ids"]),
                set(group["observation_ids"]))

    def test_inclusive_touching_endpoints_preserve_existing_rule(self):
        result = review(
            row("a", "US", upper="2026-10-03T00:00:00Z"),
            row("b", "CA", lower="2026-10-03T00:00:00Z"))
        group = result["comparison_groups"][0]
        self.assertEqual(group["valid_from"], group["valid_to"])
        self.assertEqual(group["interval_endpoints"], "inclusive")

    def test_copied_origin_is_reported_without_weight_or_verified_independence(self):
        result = review(row("a", "US"), row("b", "CA"),
                        lineage={"source-a": "shared-origin", "source-b": "shared-origin"})
        for candidate in result["hypotheses"]:
            self.assertEqual(candidate["source_groups_reported"], ["shared-origin"])
            self.assertNotIn("probability", candidate)
            self.assertNotIn("support_weight", candidate)

    def test_identifiers_are_order_stable_and_bound_to_case_and_task(self):
        a, b = row("a", "US"), row("b", "CA")
        first = review(a, b)
        self.assertEqual(first, review(b, a))
        ids = {h["hypothesis_id"] for h in first["hypotheses"]}
        self.assertTrue(ids.isdisjoint(
            h["hypothesis_id"] for h in review(a, b, case_id="case-b")["hypotheses"]))
        self.assertTrue(ids.isdisjoint(
            h["hypothesis_id"] for h in review(a, b, task_id="task-b")["hypotheses"]))

    def test_output_bounds_disclose_every_omitted_comparison(self):
        result = review(*(row(
            str(index), "name-" + str(index), predicate="registered_name")
            for index in range(200)))
        self.assertEqual(result["comparisons_total"], 19900)
        self.assertEqual(len(result["comparison_groups"]), 50)
        self.assertEqual(len(project_hypotheses(result)), 100)
        self.assertEqual(result["comparisons_omitted"], 19850)
        self.assertEqual(result["hypotheses_omitted"], 39700)
        self.assertIn("hypothesis-review-budget-exhausted", result["information_gaps"])

    def test_duplicate_observations_missing_lineage_and_unknown_versions_fail_closed(self):
        a, b = row("a", "US"), row("b", "CA")
        with self.assertRaisesRegex(ValueError, "unique observations"):
            review(a, a)
        with self.assertRaisesRegex(ValueError, "lineage is missing"):
            review(a, b, lineage={})
        result = review(a, b)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            project_hypotheses({**result, "version": "unknown"})


if __name__ == "__main__":
    unittest.main()
