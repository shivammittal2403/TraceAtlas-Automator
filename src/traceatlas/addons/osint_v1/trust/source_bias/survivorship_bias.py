"""Survivorship bias: archives/datasets show what survived, not what existed."""
from __future__ import annotations

from traceatlas.addons.osint_v1.trust.model import BiasType, SourceRecord
from traceatlas.addons.osint_v1.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    if source.kind == "archive":
        flags.add(
            BiasType.SURVIVORSHIP,
            incentive="",
            limitation="only captured/preserved snapshots exist here; absence in archive ≠ absence in reality",
        )
    return flags
