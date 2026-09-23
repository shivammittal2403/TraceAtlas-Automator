from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from ..models import utc_now


SEED_TYPES = {
    "DOMAIN", "URL", "IP_ADDRESS", "EMAIL_ADDRESS", "USERNAME", "FILE", "TEXT"
}


@dataclass(slots=True)
class Event:
    event_type: str
    data: Any
    source_module: str
    scan_id: str
    case_id: str
    parent_id: str | None = None
    depth: int = 0
    confidence: int = 50
    risk: str = "info"
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: str = field(default_factory=utc_now)

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            [self.event_type, self.data], sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["fingerprint"] = self.fingerprint
        result["confidence"] = max(0, min(100, self.confidence))
        return result


def child(parent: Event, event_type: str, data: Any, module: str, *,
          confidence: int = 70, risk: str = "info", tags: list[str] | None = None) -> Event:
    return Event(
        event_type=event_type, data=data, source_module=module,
        scan_id=parent.scan_id, case_id=parent.case_id, parent_id=parent.id,
        depth=parent.depth + 1, confidence=confidence, risk=risk, tags=tags or [],
    )

