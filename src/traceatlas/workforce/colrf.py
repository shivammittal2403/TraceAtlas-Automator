"""Deterministic COLRF review overlay for a captured TraceAtlas investigation.

Conceptual mapping of Agrahari's Cybersecurity OSINT Lifecycle and Reliability
Framework. This module never collects data, approves scope or releases claims.
All outputs are derivative review aids; evidence and authorizations remain owned
by the canonical workforce pipeline.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

COLRF_SCHEMA = "traceatlas-colrf-review/v1"
COLRF_STAGES = (
    "intelligence_requirement", "source_planning", "collection",
    "preservation_and_provenance", "normalization", "correlation_and_hypotheses",
    "verification", "confidence_and_reporting", "operational_feedback",
)
COLRF_DIMENSIONS = (
    "relevance", "source_reliability", "temporal_validity", "provenance",
    "corroboration", "analytical_confidence", "legal_ethical_compliance",
    "actionability",
)


def build_colrf_review(task: Any, analysis: dict, documents: tuple,
                       evidence: tuple, outcomes: list | tuple) -> dict:
    """Describe the nine lifecycle stages and eight non-aggregated dimensions.

    Operates only on the canonical pipeline's captured inputs and decisions.
    Never treats source count as corroboration, timestamps as freshness proof,
    policy approval as blanket legal clearance or model confidence as evidence.
    It is deliberately independent of wall-clock time, to permit offline replay.
    """
    if len(documents) != len(evidence):
        raise ValueError("COLRF source/evidence cardinality mismatch")
    if any(item.case_id != task.case_id or doc.source_id != item.source_id
           for doc, item in zip(documents, evidence)):
        raise ValueError("COLRF cross-case or source/evidence mismatch")
    if len({doc.source_id for doc in documents}) != len(documents):
        raise ValueError("COLRF duplicate source identifiers")

    observations = {row["observation_id"]: row for row in analysis["observations"]}
    decisions = {row["claim_id"]: row for row in analysis["verification"]}
    evidences = {item.evidence_id: item for item in evidence}
    lineage = {row["source_id"]: row for row in analysis["source_lineage"]}
    if len(lineage) != len(documents) or len(decisions) != len(analysis["claims"]):
        raise ValueError("COLRF analysis/source/claim binding mismatch")
    for doc in documents:
        if doc.source_id not in lineage:
            raise ValueError("COLRF missing source lineage")

    review = []
    for claim in analysis["claims"]:
        claim_id = claim["claim_id"]
        if claim_id not in decisions:
            raise ValueError("COLRF claim has no verification decision")
        decision = decisions[claim_id]
        ids = claim["observation_ids"]
        if not ids or any(oid not in observations for oid in ids):
            raise ValueError("COLRF claim has no grounded observations")
        supporting = [observations[oid] for oid in ids]
        if any(row["evidence_id"] not in evidences for row in supporting):
            raise ValueError("COLRF observation has no captured evidence")
        evidence_ids = sorted({row["evidence_id"] for row in supporting})
        groups = sorted({lineage[evidences[eid].source_id]["independence_group"]
                         for eid in evidence_ids})
        if groups != sorted(decision["independent_groups"]):
            raise ValueError("COLRF independence-group mismatch")
        status = decision["status"]
        if status not in {"SUPPORTED", "PARTIALLY_SUPPORTED", "DISPUTED", "INCONCLUSIVE", "UNSUPPORTED"}:
            raise ValueError("COLRF unknown verification status")
        provenance_ok = bool(decision["integrity_passed"])
        timestamps_present = all(bool(row.get("observed_at")) for row in supporting)
        review.append({
            "claim_id": claim_id,
            "verification_status": status,
            "observation_ids": list(ids),
            "evidence_ids": evidence_ids,
            "independent_groups": groups,
            "contradicting_observation_ids": list(decision["contradicting_observation_ids"]),
            "dimensions": {
                "relevance": "IN_SCOPE_RECORD" if provenance_ok else "REQUIRES_REVIEW",
                "source_reliability": "NOT_EMPIRICALLY_MEASURED",
                "temporal_validity": "TIMESTAMPS_RECORDED_FRESHNESS_UNASSESSED" if timestamps_present else "MISSING_OBSERVATION_TIME",
                "provenance": "INTEGRITY_CHECK_PASSED" if provenance_ok else "INTEGRITY_OR_BINDING_FAILED",
                "corroboration": "CORROBORATED" if status == "SUPPORTED" else "DISPUTED" if status == "DISPUTED" else "INSUFFICIENT_OR_UNVERIFIED",
                "analytical_confidence": "UNCALIBRATED_" + status,
                "legal_ethical_compliance": "AUTHORIZED_WORKFLOW_NOT_LEGAL_CERTIFICATION",
                "actionability": "ANALYST_REVIEW_ONLY" if status == "SUPPORTED" else "DO_NOT_AUTO_ACT",
            },
            "review_required": True,
        })
    captured = len(evidence)
    failures = [row["source_id"] for row in outcomes if row["status"] not in {"captured", "not_needed"}]
    counts = dict(sorted(Counter(row["verification_status"] for row in review).items()))
    stages = {
        "intelligence_requirement": "DEFINED" if task.objective and task.target_entities else "INCOMPLETE",
        "source_planning": "RECORDED" if outcomes else "NO_SOURCE_OUTCOMES",
        "collection": "PARTIAL" if failures and captured else "CAPTURED" if captured else "NO_EVIDENCE",
        "preservation_and_provenance": "CAPTURED_WITH_RECEIPTS" if captured else "NO_EVIDENCE",
        "normalization": "OBSERVATIONS_PRESENT" if observations else "NO_OBSERVATIONS",
        "correlation_and_hypotheses": "CORRELATED_ALTERNATIVES_NOT_TESTED" if review else "NO_CLAIMS",
        "verification": "CLAIM_DECISIONS_RECORDED" if review else "NO_CLAIMS",
        "confidence_and_reporting": "UNCALIBRATED_HUMAN_REVIEW_PENDING",
        "operational_feedback": "NOT_COLLECTED",
    }
    return {
        "schema": COLRF_SCHEMA,
        "framework": "Cybersecurity OSINT Lifecycle and Reliability Framework (COLRF)",
        "case_id": task.case_id,
        "task_id": task.task_id,
        "requirement": {"objective": task.objective, "target_entities": list(task.target_entities)},
        "stages": stages,
        "claim_reviews": review,
        "source_summary": {"captured_sources": captured,
                           "independence_groups": len({r["independence_group"] for r in lineage.values()}),
                           "failed_or_restricted_sources": sorted(failures)},
        "verification_counts": counts,
        "release_gate": "DRAFT_REQUIRES_HUMAN_RELEASE",
        "limitations": [
            "COLRF is a proposed conceptual research framework, not an empirically validated score.",
            "Source reliability, timeliness thresholds and confidence calibration were not independently measured.",
            "Distinct lineage groups do not by themselves prove source independence.",
            "Alternative hypotheses and actual operational outcomes require separate analyst review.",
            "Authorization of a bounded collection does not establish universal legal compliance.",
        ],
    }
