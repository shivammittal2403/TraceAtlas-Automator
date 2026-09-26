"""Multi-source timeline auto-generation.

Implements features 221-231 from the 687 registry:
- Timeline events from entities, relations, activity log, chat dates, vault uploads
- Date parsers: ISO-8601 datetime, ISO date, US MM/DD/YYYY, European DD/MM/YYYY,
  relative (yesterday / last week)
- TimelineEvent schema with confidence, tags, location, coordinates
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional


@dataclass
class TimelineEvent:
    id: str
    title: str
    date: datetime
    end_date: Optional[datetime] = None
    type: str = "generic"
    entity_name: str = ""
    entity_type: str = ""
    description: str = ""
    source: str = ""
    confidence: float = 0.5
    tags: List[str] = field(default_factory=list)
    location_name: Optional[str] = None
    coordinates: Optional[Dict[str, float]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["date"] = self.date.isoformat()
        if self.end_date:
            d["end_date"] = self.end_date.isoformat()
        return d


# Order matters — more specific patterns first
_DATE_PATTERNS = [
    (re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"), "iso-datetime"),
    (re.compile(r"\b(\d{4}-\d{2}-\d{2})\b"), "iso-date"),
    (re.compile(r"\b(\d{1,2}/\d{1,2}/\d{4})\b"), "us"),
    (re.compile(r"\b(\d{1,2}[./]\d{1,2}[./]\d{4})\b"), "eu"),
]

_RELATIVE = {
    "yesterday": timedelta(days=1),
    "last week": timedelta(days=7),
    "last month": timedelta(days=30),
}


def parse_date(text: str, now: Optional[datetime] = None) -> Optional[datetime]:
    """Parse the first date found in text. Returns None if none found."""
    now = now or datetime.now(timezone.utc)
    lower = text.lower()

    for phrase, delta in _RELATIVE.items():
        if phrase in lower:
            return now - delta

    for pattern, fmt in _DATE_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        raw = m.group(1)
        try:
            if fmt == "iso-datetime":
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if fmt == "iso-date":
                return datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
            if fmt == "us":
                month, day, year = map(int, raw.split("/"))
                return datetime(year, month, day, tzinfo=timezone.utc)
            if fmt == "eu":
                parts = re.split(r"[./]", raw)
                day, month, year = map(int, parts)
                return datetime(year, month, day, tzinfo=timezone.utc)
        except (ValueError, OverflowError):
            continue
    return None


def build_timeline(
    entities: List[Dict[str, Any]] = None,
    relations: List[Dict[str, Any]] = None,
    activity_log: List[Dict[str, Any]] = None,
    chat_messages: List[str] = None,
    vault_uploads: List[Dict[str, Any]] = None,
) -> List[TimelineEvent]:
    """Build a sorted list of TimelineEvent from multiple sources."""
    events: List[TimelineEvent] = []
    idx = 0

    def _add(title: str, dt: datetime, **kwargs: Any) -> None:
        nonlocal idx
        idx += 1
        events.append(
            TimelineEvent(
                id=f"evt_{idx:04d}",
                title=title,
                date=dt,
                **kwargs,
            )
        )

    for ent in entities or []:
        for key in ("start_date", "end_date", "startDate", "endDate"):
            raw = ent.get(key)
            if not raw:
                continue
            dt = parse_date(str(raw))
            if dt:
                _add(
                    title=ent.get("name", "entity"),
                    dt=dt,
                    type=ent.get("type", "generic"),
                    entity_name=ent.get("name", ""),
                    entity_type=ent.get("type", ""),
                    source="entity",
                    confidence=float(ent.get("confidence", 0.5)),
                )

    for rel in relations or []:
        raw = rel.get("date") or rel.get("timestamp")
        if raw:
            dt = parse_date(str(raw))
            if dt:
                _add(
                    title=f"{rel.get('source_name', '')} → {rel.get('target_name', '')}",
                    dt=dt,
                    type=rel.get("type", "relation"),
                    source="relation",
                    confidence=float(rel.get("confidence", 0.5)),
                )

    for log in activity_log or []:
        ts = log.get("timestamp") or log.get("ts")
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            _add(
                title=log.get("message", log.get("action", "activity")),
                dt=dt,
                type="activity",
                source="activity_log",
                confidence=0.9,
            )

    for msg in chat_messages or []:
        dt = parse_date(msg)
        if dt:
            _add(
                title=msg[:80],
                dt=dt,
                type="chat",
                source="chat",
                confidence=0.4,
            )

    for upload in vault_uploads or []:
        raw = upload.get("uploaded_at") or upload.get("uploadedAt")
        if raw:
            dt = parse_date(str(raw))
            if dt:
                _add(
                    title=upload.get("name", "vault upload"),
                    dt=dt,
                    type="vault",
                    source="vault",
                    confidence=0.95,
                )

    events.sort(key=lambda e: e.date)
    return events
