"""Deterministic pair-ranking metrics for explicitly labelled ER cases.

This evaluator is diagnostic. Its metrics are not identity probabilities and a
candidate rank is never an accepted identity link or an automatic merge.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from typing import Any

from .policy import PolicyError
from .research.analysis import MATCH_FIELDS, explainable_entity_match


def evaluate_entity_resolution(
    cases: Iterable[Mapping[str, Any]],
    *,
    threshold: float = 0.72,
    top_k: tuple[int, ...] = (1, 3),
) -> dict[str, Any]:
    """Evaluate the current ranker on labelled query/candidate groups.

    ``threshold`` is the existing ``possible_candidate`` boundary. This function
    deliberately does not tune it. Top-k is ranking recall over the candidates
    supplied in each case; it is not candidate-generation recall.
    """
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
        raise PolicyError("Entity-resolution threshold must be numeric")
    if not math.isfinite(float(threshold)) or not 0 <= threshold <= 1:
        raise PolicyError("Entity-resolution threshold must be finite and between 0 and 1")
    if not isinstance(top_k, tuple) or not top_k or any(
        isinstance(k, bool) or not isinstance(k, int) or k < 1 for k in top_k
    ):
        raise PolicyError("top_k must be a non-empty tuple of positive integers")
    if len(set(top_k)) != len(top_k):
        raise PolicyError("top_k values must be unique")

    rows = list(cases)
    if not rows or len(rows) > 10_000:
        raise PolicyError("Entity-resolution evaluation needs 1-10,000 labelled cases")
    seen_case_ids: set[str] = set()
    true_positive = false_positive = true_negative = false_negative = 0
    ranking_ranks: list[int] = []
    case_results: list[dict[str, Any]] = []
    pair_count = positive_pairs = 0

    for case in rows:
        if not isinstance(case, Mapping):
            raise PolicyError("Each entity-resolution case must be an object")
        case_id = case.get("case_id")
        query = case.get("query")
        candidates = case.get("candidates")
        if not isinstance(case_id, str) or not case_id.strip() or case_id in seen_case_ids:
            raise PolicyError("Entity-resolution case IDs must be non-empty and unique")
        seen_case_ids.add(case_id)
        if not isinstance(query, Mapping) or not isinstance(candidates, list) or not candidates:
            raise PolicyError(f"Case {case_id} needs a query and at least one candidate")
        if len(candidates) > 500:
            raise PolicyError(f"Case {case_id} exceeds the 500-candidate evaluation bound")

        ids: set[str] = set()
        positives: list[str] = []
        scored: list[tuple[str, float | None, bool]] = []
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                raise PolicyError(f"Case {case_id} candidates must be objects")
            candidate_id, record, is_match = (
                candidate.get("candidate_id"), candidate.get("record"), candidate.get("is_match")
            )
            if not isinstance(candidate_id, str) or not candidate_id.strip() or candidate_id in ids:
                raise PolicyError(f"Case {case_id} candidate IDs must be non-empty and unique")
            ids.add(candidate_id)
            if not isinstance(is_match, bool):
                raise PolicyError(f"Case {case_id} candidate labels must be booleans")
            if not isinstance(record, Mapping):
                raise PolicyError(f"Case {case_id} candidate {candidate_id} needs a record")
            # Reuse the production ranker, including its sensitive-field guard.
            result = explainable_entity_match(dict(query), dict(record))
            score = result.get("similarity_score")
            if score is None:
                raise PolicyError(f"Case {case_id} candidate {candidate_id} has insufficient comparison fields")
            scored.append((candidate_id, score, is_match))
            pair_count += 1
            positive_pairs += int(is_match)
            predicted = score >= threshold
            if predicted and is_match:
                true_positive += 1
            elif predicted:
                false_positive += 1
            elif is_match:
                false_negative += 1
            else:
                true_negative += 1
            if is_match:
                positives.append(candidate_id)

        if len(positives) > 1:
            raise PolicyError(f"Case {case_id} must have at most one expected matching candidate")
        expected = case.get("expected_match_id")
        if (positives[0] if positives else None) != expected:
            raise PolicyError(f"Case {case_id} expected_match_id does not match its candidate labels")
        ranked = sorted(scored, key=lambda item: (-item[1], item[0]))
        expected_candidate_rank = None
        if positives:
            expected_candidate_rank = next(i for i, item in enumerate(ranked, 1) if item[0] == positives[0])
            ranking_ranks.append(expected_candidate_rank)
        case_results.append({
            "case_id": case_id,
            "expected_match_id": expected,
            "expected_candidate_rank": expected_candidate_rank,
            "ranked_candidates": [
                {"candidate_id": candidate_id, "score": score, "expected_match": is_match,
                 "predicted_candidate": score >= threshold}
                for candidate_id, score, is_match in ranked
            ],
        })

    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    fpr_denominator = false_positive + true_negative
    precision = true_positive / precision_denominator if precision_denominator else None
    recall = true_positive / recall_denominator if recall_denominator else None
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None

    return {
        "schema": "traceatlas-entity-resolution-evaluation/v1",
        "dataset_kind": "labelled-pair-ranking",
        "cases": len(rows),
        "candidate_pairs": pair_count,
        "positive_pairs": positive_pairs,
        "negative_pairs": pair_count - positive_pairs,
        "threshold": float(threshold),
        "threshold_provenance": (
            "existing possible_candidate score boundary; not tuned on this dataset"
            if float(threshold) == 0.72
            else "caller-supplied diagnostic threshold; not tuned on this dataset"
        ),
        "pair_metrics": {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": false_positive / fpr_denominator if fpr_denominator else None,
        },
        "ranking_recall": {
            f"recall_at_{k}": sum(rank <= k for rank in ranking_ranks) / len(ranking_ranks)
            if ranking_ranks else None
            for k in sorted(top_k)
        },
        "ranking_query_count": len(ranking_ranks),
        "case_results": case_results,
        "automatic_merge_attempts": 0,
        "false_automatic_merges": 0,
        "false_merge_rate": None,
        "false_merge_rate_status": "NOT_MEASURABLE_ZERO_AUTOMATIC_MERGE_DENOMINATOR",
        "limitations": [
            "Candidate similarity scores are ranks, not calibrated identity probabilities.",
            "Synthetic results do not estimate operational identity precision or recall.",
            "Ranking recall is conditional on supplied candidates, not candidate-generation recall.",
            "No automatic merges are attempted; false-merge rate has a zero denominator.",
            "The evaluator does not adjudicate identity or change analyst-review policy.",
        ],
    }
