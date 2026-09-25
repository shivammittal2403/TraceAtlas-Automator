from __future__ import annotations

import math
import re
import unicodedata
from collections import defaultdict
from datetime import date, datetime, timezone
from typing import Any

from ..policy import PolicyError


MATCH_FIELDS = {
    "name": 0.35,
    "organization": 0.25,
    "domain": 0.25,
    "username": 0.10,
    "location": 0.05,
}
SENSITIVE_FIELD = re.compile(
    r"email|phone|address|password|secret|token|cookie|credential|government.?id|ssn",
    re.I,
)


def _normalize(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold().strip()
    return " ".join(re.findall(r"[^\W_]+", text, re.UNICODE))


def _jaro_winkler(left: str, right: str) -> float:
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    distance = max(len(left), len(right)) // 2 - 1
    distance = max(0, distance)
    left_match = [False] * len(left)
    right_match = [False] * len(right)
    matches = 0
    for index, char in enumerate(left):
        start, end = max(0, index - distance), min(index + distance + 1, len(right))
        for other in range(start, end):
            if not right_match[other] and char == right[other]:
                left_match[index] = True
                right_match[other] = True
                matches += 1
                break
    if not matches:
        return 0.0
    left_chars = [char for index, char in enumerate(left) if left_match[index]]
    right_chars = [char for index, char in enumerate(right) if right_match[index]]
    transpositions = sum(a != b for a, b in zip(left_chars, right_chars)) / 2
    jaro = (
        matches / len(left) + matches / len(right)
        + (matches - transpositions) / matches
    ) / 3
    prefix = 0
    for a, b in zip(left[:4], right[:4]):
        if a != b:
            break
        prefix += 1
    return jaro + prefix * 0.1 * (1 - jaro) if jaro > 0.7 else jaro


def explainable_entity_match(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Compare non-sensitive public labels; never create an identity link automatically."""
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise PolicyError("Entity-match inputs must be JSON objects")
    if any(SENSITIVE_FIELD.search(str(key)) for key in set(left) | set(right)):
        raise PolicyError("Entity matching rejects sensitive identifiers and credentials")
    comparisons = []
    numerator = 0.0
    denominator = 0.0
    for field, weight in MATCH_FIELDS.items():
        a, b = _normalize(left.get(field)), _normalize(right.get(field))
        if not a or not b:
            continue
        similarity = _jaro_winkler(a, b)
        if field in {"domain", "username"} and a != b:
            similarity *= 0.35
        contribution = weight * similarity
        numerator += contribution
        denominator += weight
        comparisons.append({
            "field": field,
            "similarity": round(similarity, 4),
            "weight": weight,
            "contribution": round(contribution, 4),
        })
    if len(comparisons) < 2:
        return {
            "classification": "insufficient_evidence",
            "similarity_score": None,
            "comparisons": comparisons,
            "review_required": True,
            "automatic_merge": False,
        }
    score = numerator / denominator
    classification = (
        "strong_candidate" if score >= 0.88
        else "possible_candidate" if score >= 0.72
        else "weak_candidate"
    )
    return {
        "classification": classification,
        "similarity_score": round(score, 4),
        "comparisons": comparisons,
        "review_required": True,
        "automatic_merge": False,
        "limitations": [
            "The score is an explainable similarity rank, not a probability of identity.",
            "Resolve strong and possible candidates with independent evidence and consent rules.",
        ],
    }


def _moment(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PolicyError(f"Invalid ISO date/time: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _overlaps(left_start: datetime | None, left_end: datetime | None,
              right_start: datetime | None, right_end: datetime | None) -> bool:
    floor = datetime.min.replace(tzinfo=timezone.utc)
    ceiling = datetime.max.replace(tzinfo=timezone.utc)
    return max(left_start or floor, right_start or floor) <= min(left_end or ceiling, right_end or ceiling)


def temporal_analysis(records: list[dict[str, Any]], *, as_of: date | datetime,
                      half_life_days: int = 90) -> dict[str, Any]:
    if not isinstance(records, list) or len(records) > 10_000:
        raise PolicyError("Temporal analysis accepts at most 10,000 records")
    if not 1 <= half_life_days <= 3650:
        raise PolicyError("half_life_days must be between 1 and 3650")
    if isinstance(as_of, date) and not isinstance(as_of, datetime):
        current = datetime.combine(as_of, datetime.min.time(), tzinfo=timezone.utc)
    else:
        current = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
        current = current.astimezone(timezone.utc)
    normalized = []
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for index, row in enumerate(records):
        if not isinstance(row, dict):
            continue
        subject = str(row.get("subject") or "").strip()[:300]
        predicate = str(row.get("predicate") or "").strip()[:200]
        value = str(row.get("value") or row.get("object") or "").strip()[:1000]
        source = str(row.get("source") or "").strip()[:300]
        if not subject or not predicate or not value or not source:
            continue
        observed = _moment(row.get("observed_at"))
        start, end = _moment(row.get("valid_from")), _moment(row.get("valid_to"))
        if start and end and end < start:
            raise PolicyError(f"Record {index} has valid_to before valid_from")
        age = max(0.0, (current - observed).total_seconds() / 86400) if observed else None
        freshness = 0.5 ** (age / half_life_days) if age is not None else None
        item = {
            "index": index,
            "subject": subject,
            "predicate": predicate,
            "value": value,
            "source": source,
            "observed_at": observed,
            "valid_from": start,
            "valid_to": end,
            "freshness": round(freshness, 4) if freshness is not None else None,
        }
        normalized.append(item)
        groups[(subject.casefold(), predicate.casefold())].append(item)
    conflicts = []
    for group in groups.values():
        for offset, left in enumerate(group):
            for right in group[offset + 1:]:
                if left["value"].casefold() == right["value"].casefold():
                    continue
                if _overlaps(left["valid_from"], left["valid_to"], right["valid_from"], right["valid_to"]):
                    conflicts.append({
                        "subject": left["subject"],
                        "predicate": left["predicate"],
                        "left": {"index": left["index"], "value": left["value"], "source": left["source"]},
                        "right": {"index": right["index"], "value": right["value"], "source": right["source"]},
                    })
                    if len(conflicts) >= 500:
                        break
            if len(conflicts) >= 500:
                break
    return {
        "records_received": len(records),
        "records_accepted": len(normalized),
        "conflicts": conflicts,
        "freshness": [
            {"index": item["index"], "freshness": item["freshness"]}
            for item in normalized if item["freshness"] is not None
        ],
        "as_of": current.isoformat(),
        "half_life_days": half_life_days,
        "review_required": True,
        "limitations": [
            "Freshness is exponential time decay, not a truth or source-reliability score.",
            "Conflicts are overlapping unequal values and require analyst adjudication.",
        ],
    }
