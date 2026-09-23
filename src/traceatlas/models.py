from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Finding:
    title: str
    value: Any
    source: str
    confidence: int = 50
    severity: str = "info"
    observation: str = ""
    id: str = field(default_factory=lambda: str(uuid4()))
    collected_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Method:
    id: int
    slug: str
    title: str
    summary: str
    level: str
    minutes: int
    automation: str
    target_types: tuple[str, ...]
    collectors: tuple[str, ...]
    risk: str = "low"
    review_gate: bool = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["target_types"] = list(self.target_types)
        data["collectors"] = list(self.collectors)
        return data

