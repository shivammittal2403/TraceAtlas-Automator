from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from uuid import uuid4

from .db import CaseDB
from .models import utc_now
from .policy import PolicyError
from .research.analysis import MATCH_FIELDS, SENSITIVE_FIELD, explainable_entity_match


SAFE_VALUE = re.compile(r"^[^\x00-\x1f\x7f]{1,500}$")
DECISIONS = {"accepted", "rejected"}


def _public_record(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise PolicyError("Resolution records must be JSON objects")
    if any(SENSITIVE_FIELD.search(str(key)) for key in value):
        raise PolicyError("Resolution records reject contact, credential and government-ID fields")
    record: dict[str, str] = {}
    for field in MATCH_FIELDS:
        raw = value.get(field)
        if raw in (None, ""):
            continue
        if isinstance(raw, (dict, list)):
            raise PolicyError(f"Resolution field {field} must be a scalar")
        text = str(raw).strip()
        if not SAFE_VALUE.fullmatch(text):
            raise PolicyError(f"Resolution field {field} is invalid or too long")
        record[field] = text
    if len(record) < 2:
        raise PolicyError("Resolution records need at least two non-sensitive comparison fields")
    return record


class ResolutionService:
    """Persistent human-review queue for non-sensitive public entity candidates."""

    def __init__(self, db: CaseDB):
        self.db = db

    def propose(self, case_id: str, left: Any, right: Any, *, source: str,
                authority: str, authorized: bool = False) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("Entity-resolution proposals require explicit authorization")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        source = str(source).strip()
        authority = str(authority).strip()
        if not SAFE_VALUE.fullmatch(source) or len(authority) < 10 or len(authority) > 1000:
            raise PolicyError("A valid source and documented authority are required")
        safe_left, safe_right = _public_record(left), _public_record(right)
        match = explainable_entity_match(safe_left, safe_right)
        canonical = json.dumps([safe_left, safe_right], sort_keys=True, ensure_ascii=False)
        reverse = json.dumps([safe_right, safe_left], sort_keys=True, ensure_ascii=False)
        candidate = {
            "id": str(uuid4()), "case_id": case_id, "source": source,
            "left": safe_left, "right": safe_right,
            "classification": match["classification"],
            "score": match.get("similarity_score"),
            "comparisons": match.get("comparisons", []),
            "fingerprint": hashlib.sha256(min(canonical, reverse).encode()).hexdigest(),
            "authority": authority, "created_at": utc_now(),
        }
        created = self.db.add_resolution_candidate(candidate)
        if not created:
            existing = next(
                row for row in self.db.resolution_candidates(case_id)
                if row["left"] in (safe_left, safe_right) and row["right"] in (safe_left, safe_right)
            )
            return {**existing, "created": False, "automatic_merge": False}
        stored = self.db.resolution_candidate(candidate["id"])
        return {**(stored or candidate), "created": True, "automatic_merge": False}

    def queue(self, case_id: str, *, status: str = "pending") -> list[dict[str, Any]]:
        if status not in {"pending", "accepted", "rejected", "all"}:
            raise PolicyError("Resolution status must be pending, accepted, rejected or all")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        return self.db.resolution_candidates(case_id, None if status == "all" else status)

    def decide(self, candidate_id: str, decision: str, *, reviewer: str,
               rationale: str, authorized: bool = False) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("Resolution decisions require explicit authorization")
        if decision not in DECISIONS:
            raise PolicyError("Resolution decision must be accepted or rejected")
        reviewer, rationale = str(reviewer).strip(), str(rationale).strip()
        if not 2 <= len(reviewer) <= 120 or not SAFE_VALUE.fullmatch(reviewer):
            raise PolicyError("Reviewer must contain 2-120 printable characters")
        if not 10 <= len(rationale) <= 1000 or any(ord(char) < 32 and char not in "\n\t" for char in rationale):
            raise PolicyError("Decision rationale must contain 10-1000 printable characters")
        candidate = self.db.resolution_candidate(candidate_id)
        if not candidate:
            raise PolicyError("Unknown resolution candidate")
        if not self.db.decide_resolution_candidate(
            candidate_id, decision, reviewer=reviewer, rationale=rationale,
        ):
            raise PolicyError("Resolution candidate was already decided")
        decided = self.db.resolution_candidate(candidate_id)
        return {
            **(decided or candidate),
            "automatic_merge": False,
            "effect": "human-reviewed-link-recorded" if decision == "accepted" else "candidate-dismissed",
            "limitation": "Acceptance records an analyst judgement; it is not proof of identity or wrongdoing.",
        }
