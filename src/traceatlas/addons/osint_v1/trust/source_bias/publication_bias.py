"""Publication-type bias: secondary media repeating primary documents."""
from __future__ import annotations

from traceatlas.addons.osint_v1.trust.model import BiasType, SourceRecord
from traceatlas.addons.osint_v1.trust.source_bias.model import BiasFlags


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    if source.derived_from_id or source.upstream_source_id:
        flags.add(
            BiasType.PUBLICATION,
            incentive="publication economics reward fast republication over re-verification",
            limitation="content likely repeats an upstream document rather than independently verifying it",
        )
    return flags
