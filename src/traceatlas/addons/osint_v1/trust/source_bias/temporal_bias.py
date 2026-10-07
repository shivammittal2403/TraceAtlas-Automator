"""Temporal/staleness bias detector."""
from __future__ import annotations

from datetime import datetime, timezone

from traceatlas.addons.osint_v1.trust.model import BiasType, SourceRecord
from traceatlas.addons.osint_v1.trust.source_bias.model import BiasFlags

_STALE_DAYS = 365


def detect(source: SourceRecord, flags: BiasFlags, now: datetime | None = None) -> BiasFlags:
    ref = source.event_time or source.captured_at
    try:
        dt = datetime.fromisoformat(ref)
    except (TypeError, ValueError):
        return flags
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    age_days = ((now or datetime.now(timezone.utc)) - dt).days
    if age_days >= _STALE_DAYS:
        flags.add(
            BiasType.TEMPORAL,
            incentive="",
            limitation=f"source is ~{age_days} days old: configuration/ownership may have changed since",
        )
    return flags
