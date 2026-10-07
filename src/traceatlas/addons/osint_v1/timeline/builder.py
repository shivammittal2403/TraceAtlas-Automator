"""Build a Timeline from events."""

from __future__ import annotations

from traceatlas.addons.osint_v1.core.event import Event
from traceatlas.addons.osint_v1.core.timeline import Timeline
from traceatlas.addons.osint_v1.timeline.model import sorted_events


def build_timeline(case_id: str, events: list[Event], name: str = "primary") -> Timeline:
    ordered = sorted_events(events)
    return Timeline(case_id=case_id, name=name, event_ids=[e.id for e in ordered])
