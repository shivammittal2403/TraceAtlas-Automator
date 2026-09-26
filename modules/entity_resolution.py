"""Governed entity resolution queue.

Implements high-priority features from the 687 registry:
- Entity types (PERSON, ORGANIZATION, LOCATION, EVENT, DOCUMENT, DEVICE,
  EMAIL, PHONE, DOMAIN, VEHICLE, CRYPTO, GENERIC)
- Confidence 0-1
- Exact name matching for relations
- Source attribution + isVerified flag
- Explicit analyst accept/reject with rationale (no automatic identity merge)

This module never claims two entities are the same person. It only records
public-label candidates and analyst decisions for the review queue.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EntityType(str, Enum):
    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    LOCATION = "LOCATION"
    EVENT = "EVENT"
    DOCUMENT = "DOCUMENT"
    DEVICE = "DEVICE"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    DOMAIN = "DOMAIN"
    VEHICLE = "VEHICLE"
    CRYPTO = "CRYPTO"
    GENERIC = "GENERIC"


class Decision(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass
class Entity:
    id: str
    type: EntityType
    name: str
    confidence: float = 0.5
    source: str = ""
    is_verified: bool = False
    description: str = ""
    lat: Optional[float] = None
    lng: Optional[float] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if isinstance(self.type, str):
            self.type = EntityType(self.type)


@dataclass
class Relation:
    source_name: str
    target_name: str
    type: str
    label: str = ""
    confidence: float = 0.5


@dataclass
class ResolutionCandidate:
    id: str
    case_id: str
    left: Entity
    right: Entity
    decision: Decision = Decision.PENDING
    reviewer: str = ""
    rationale: str = ""
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    source: str = ""
    authority: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["left"]["type"] = self.left.type.value
        d["right"]["type"] = self.right.type.value
        d["decision"] = self.decision.value
        return d


def _stable_id(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"cand_{h}"


class EntityResolutionQueue:
    """In-memory / serializable resolution queue.

    In production this should be backed by the case SQLite ledger.
    """

    def __init__(self) -> None:
        self._candidates: Dict[str, ResolutionCandidate] = {}

    def propose(
        self,
        case_id: str,
        left: Entity,
        right: Entity,
        source: str = "",
        authority: str = "",
        authorized: bool = False,
    ) -> ResolutionCandidate:
        if not authorized:
            raise PermissionError("explicit --authorized flag required")
        if not authority.strip():
            raise ValueError("authority / lawful purpose must be recorded")

        cid = _stable_id(case_id, left.name, right.name, left.type.value, right.type.value)
        cand = ResolutionCandidate(
            id=cid,
            case_id=case_id,
            left=left,
            right=right,
            source=source,
            authority=authority,
        )
        self._candidates[cid] = cand
        return cand

    def decide(
        self,
        candidate_id: str,
        decision: Decision,
        reviewer: str,
        rationale: str,
        authorized: bool = False,
    ) -> ResolutionCandidate:
        if not authorized:
            raise PermissionError("explicit --authorized flag required")
        if not reviewer.strip() or not rationale.strip():
            raise ValueError("reviewer and rationale are mandatory")

        cand = self._candidates.get(candidate_id)
        if cand is None:
            raise KeyError(f"candidate {candidate_id} not found")

        if decision not in (Decision.ACCEPTED, Decision.REJECTED):
            raise ValueError("decision must be accepted or rejected")

        cand.decision = decision
        cand.reviewer = reviewer
        cand.rationale = rationale
        cand.decided_at = time.time()
        return cand

    def list_pending(self, case_id: Optional[str] = None) -> List[ResolutionCandidate]:
        items = [
            c for c in self._candidates.values()
            if c.decision == Decision.PENDING
            and (case_id is None or c.case_id == case_id)
        ]
        return sorted(items, key=lambda c: c.created_at)

    def export_json(self, case_id: Optional[str] = None) -> str:
        items = [
            c.to_dict() for c in self._candidates.values()
            if case_id is None or c.case_id == case_id
        ]
        return json.dumps(items, indent=2, ensure_ascii=False)
