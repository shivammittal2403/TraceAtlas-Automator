"""Geographic coverage bias detector."""
from __future__ import annotations

from traceatlas.addons.osint_v1.trust.model import BiasType, SourceRecord
from traceatlas.addons.osint_v1.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    if source.country and source.country.lower() not in ("", "global"):
        flags.add(
            BiasType.GEOGRAPHIC,
            incentive="",
            limitation=f"coverage centred on {source.country}: local events over-represented elsewhere under-covered",
        )
    return flags
