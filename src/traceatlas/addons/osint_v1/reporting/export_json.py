"""JSON export of a built report."""

from __future__ import annotations

from traceatlas.addons.osint_v1.core.serialization import to_json


def export_json(report: dict) -> str:
    return to_json(report, indent=2)
