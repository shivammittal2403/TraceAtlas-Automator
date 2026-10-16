"""Bounded competing assertions from existing canonical contradiction witnesses."""
from __future__ import annotations

import hashlib
import json

from .contracts import Hypothesis, _id
from .contradictions import contradiction_pairs

SCHEMA = "traceatlas.hypothesis-review/v1"
VERSION = "canonical-competing-assertions/1"
MAX_FACT_ROWS = 200
MAX_COMPARISONS = 50


def _identity(prefix, value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return prefix + "-" + hashlib.sha256(encoded).hexdigest()[:24]


def build_hypothesis_review(case_id, task_id, fact_rows, lineage_index):
    """Compare eligible (StructuredFact, Observation, SourceDocument) rows.

    Eligibility, evidence acquisition and authority remain owned by the caller.
    Every pair uses canonical contradiction semantics and its exact overlap;
    transitive graph connectivity never establishes competing assertions.
    """
    case_id, task_id = _id(case_id, "case_id"), _id(task_id, "task_id")
    rows = tuple(fact_rows)
    if len(rows) > MAX_FACT_ROWS or len({o.observation_id for _, o, _ in rows}) != len(rows):
        raise ValueError("hypothesis review requires at most 200 unique observations")
    rows = tuple(sorted(rows, key=lambda row: row[1].observation_id))
    if any(doc.source_id not in lineage_index for _, _, doc in rows):
        raise ValueError("hypothesis review source lineage is missing")
    pairs = contradiction_pairs(fact for fact, _, _ in rows)
    groups, hypotheses = [], []
    for left, right in pairs[:MAX_COMPARISONS]:
        a, b = rows[left], rows[right]
        observation_ids = [a[1].observation_id, b[1].observation_id]
        comparison_id = _identity("comparison", [case_id, task_id, observation_ids])
        valid_from = max(a[0].valid_from, b[0].valid_from)
        ends = [row[0].valid_to for row in (a, b) if row[0].valid_to is not None]
        valid_to = min(ends) if ends else None
        hypothesis_ids = []
        for support, contrary in ((a, b), (b, a)):
            fact, observation, document = support
            _, other_observation, other_document = contrary
            hypothesis_id = _identity("hypothesis", [
                case_id, task_id, comparison_id, observation.observation_id])
            hypothesis_ids.append(hypothesis_id)
            kind = "test-candidate-against-primary-record"
            checks = [{
                "check_id": _identity("check", [hypothesis_id, kind]), "kind": kind,
                "description": (
                    "An authenticated dated primary record with a different exclusive value for "
                    "this subject and predicate during the stated overlap would challenge this "
                    "candidate. Nonoverlapping records or predicates permitting multiple values "
                    "do not meet this condition."),
                "expected_scope": {
                    "subject": fact.subject, "predicate": fact.predicate,
                    "valid_from": valid_from, "valid_to": valid_to,
                    "inclusive": True, "cardinality": "one"},
                "operator": "not_equals", "expected_value": fact.value,
                "current_counterexample_observation_ids": [other_observation.observation_id],
                "current_counterexample_evidence_ids": [other_observation.evidence_id],
                "evaluation": "CAPTURED_COUNTERASSERTION_ONLY",
                "next_evaluation": "PENDING_AUTHENTICATED_PRIMARY_REVIEW",
                "state": "PENDING_HUMAN_REVIEW", "automatic_execution": False,
                "hypothesis_proven_true": False,
            }]
            for kind, description in (
                ("review-primary-record",
                 "Review the dated primary records underlying both captured assertions."),
                ("review-comparison-scope",
                 "Check the predicate meaning and exact overlapping validity interval before choosing an assertion."),
                ("seek-independent-counterevidence",
                 "Consider separately authorized collection of primary evidence that could contradict this candidate."),
            ):
                checks.append({
                    "check_id": _identity("check", [hypothesis_id, kind]), "kind": kind,
                    "description": description, "state": "PENDING_HUMAN_REVIEW",
                    "automatic_execution": False})
            hypotheses.append({
                "hypothesis_id": hypothesis_id, "comparison_id": comparison_id,
                "statement": (
                    "Candidate assertion within the recorded overlap: " + fact.subject
                    + " " + fact.predicate + " " + fact.value),
                "subject": fact.subject, "predicate": fact.predicate,
                "candidate_value": fact.value, "status": "UNVERIFIED_COMPETING_ASSERTION",
                "supporting_observation_ids": [observation.observation_id],
                "contrary_observation_ids": [other_observation.observation_id],
                "supporting_evidence_ids": [observation.evidence_id],
                "contrary_evidence_ids": [other_observation.evidence_id],
                "supporting_source_ids": [document.source_id],
                "contrary_source_ids": [other_document.source_id],
                "source_groups_reported": sorted({
                    lineage_index[document.source_id], lineage_index[other_document.source_id]}),
                "hypothesis_proven_true": False, "requires_human_review": True,
                "next_checks": checks})
        groups.append({
            "comparison_id": comparison_id, "subject": a[0].subject, "predicate": a[0].predicate,
            "valid_from": valid_from, "valid_to": valid_to, "interval_endpoints": "inclusive",
            "observation_ids": observation_ids,
            "evidence_ids": sorted({a[1].evidence_id, b[1].evidence_id}),
            "hypothesis_ids": hypothesis_ids})
    omitted = max(0, len(pairs) - MAX_COMPARISONS)
    return {
        "schema": SCHEMA, "version": VERSION, "case_id": case_id, "task_id": task_id,
        "comparison_groups": groups, "hypotheses": hypotheses, "eligible_observations": len(rows),
        "comparisons_total": len(pairs), "comparisons_omitted": omitted,
        "hypotheses_omitted": omitted * 2,
        "information_gaps": (
            (["hypothesis-review-budget-exhausted"] if omitted else [])
            + (["no-comparable-conflicting-assertions"] if not pairs else [])),
        "requires_human_review": True, "source_independence_verified": False,
        "probabilities_calibrated": False,
        "limitations": [
            "Alternatives describe captured source assertions, not verified real-world conclusions.",
            "Each comparison is pair-specific; overlapping comparison chains do not establish transitive competition.",
            "Reported lineage groups are not proof of independence; no vote, probability or attribution is computed.",
            "Proposed checks are pending human review and grant no collection or execution authority."]}


def project_hypotheses(review):
    """Project an internally recomputed review to the existing strict contract."""
    if review.get("schema") != SCHEMA or review.get("version") != VERSION:
        raise ValueError("unsupported hypothesis review version")
    if len(review["hypotheses"]) > MAX_COMPARISONS * 2:
        raise ValueError("hypothesis review exceeds canonical result bounds")
    return tuple(Hypothesis(
        row["hypothesis_id"], row["statement"],
        tuple(sorted(set(row["supporting_evidence_ids"] + row["contrary_evidence_ids"]))),
        tuple(check["check_id"] for check in row["next_checks"]))
        for row in review["hypotheses"])
