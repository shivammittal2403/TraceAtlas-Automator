"""Bounded multi-source execution with budgets and connector circuit breaking."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..policy import PolicyError
from .hub import IntelligenceHub
from .sources import SOURCES


class CollectionOrchestrator:
    def __init__(self, hub: IntelligenceHub):
        self.hub = hub

    @staticmethod
    def load_plan(path: Path) -> list[dict[str, str]]:
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            raise PolicyError("Collection plan must be a JSON file up to 64 KiB")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError("Collection plan is not valid JSON") from exc
        rows = data.get("sources") if isinstance(data, dict) else data
        if not isinstance(rows, list) or not 1 <= len(rows) <= 12:
            raise PolicyError("Collection plan requires 1-12 source entries")
        result = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"source", "target_type", "target"}:
                raise PolicyError("Each plan entry needs only source, target_type and target")
            if not all(isinstance(row[key], str) for key in row):
                raise PolicyError("Collection plan values must be strings")
            source = row["source"]
            if source not in SOURCES or not SOURCES[source].live_connector:
                raise PolicyError(f"Plan source is not a live connector: {source}")
            result.append({key: row[key] for key in ("source", "target_type", "target")})
        return result

    def run(self, case_id: str, plan: list[dict[str, str]], *, budget_seconds: int = 180,
            authorized: bool = False, subject_consent: bool = False,
            owned_org: bool = False, owned_asset: bool = False,
            public_record_basis: bool = False) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("Batch collection requires explicit --authorized confirmation")
        budget_seconds = max(10, min(int(budget_seconds), 900))
        unhealthy = {
            row["source"] for row in self.hub.db.connector_health()
            if row["consecutive_failures"] >= 3
        }
        started = time.monotonic()
        outcomes: list[dict[str, Any]] = []
        for index, item in enumerate(plan, start=1):
            source = item["source"]
            if time.monotonic() - started >= budget_seconds:
                outcomes.append({"index": index, "source": source, "state": "skipped", "reason": "budget_exhausted"})
                continue
            if source in unhealthy:
                outcomes.append({"index": index, "source": source, "state": "skipped", "reason": "circuit_open"})
                continue
            try:
                result = self.hub.collect(
                    case_id, source, item["target_type"], item["target"],
                    authorized=True, subject_consent=subject_consent, owned_org=owned_org,
                    owned_asset=owned_asset, public_record_basis=public_record_basis,
                )
                outcomes.append({
                    "index": index, "source": source, "state": "completed",
                    "scan_id": result["scan_id"], "records": result["stats"]["records_stored"],
                })
            except Exception as exc:
                outcomes.append({
                    "index": index, "source": source, "state": "failed",
                    "reason": getattr(exc, "code", type(exc).__name__),
                })
        counts = {
            state: sum(row["state"] == state for row in outcomes)
            for state in ("completed", "failed", "skipped")
        }
        return {
            "case_id": case_id, "state": "completed" if not counts["failed"] else "partial",
            "budget_seconds": budget_seconds, "counts": counts, "outcomes": outcomes,
            "limitations": "A skipped or unavailable source is a coverage gap, not negative evidence.",
        }
