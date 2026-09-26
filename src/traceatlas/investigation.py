"""Unified, evidence-linked analyst workspace for one local case."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .db import CaseDB
from .models import utc_now
from .policy import PolicyError


class InvestigationWorkspace:
    """Build a deterministic case view without turning correlations into facts."""

    def __init__(self, db: CaseDB):
        self.db = db

    def build(self, case_id: str) -> dict[str, Any]:
        case = self.db.get_case(case_id)
        if not case:
            raise PolicyError(f"Unknown case: {case_id}")
        scans = self.db.spider_scans(case_id)
        events = [event for scan in scans for event in self.db.spider_events(scan["id"])]
        findings = self.db.findings(case_id)
        evidence = self.db.evidence(case_id)
        notes = self.db.case_notes(case_id)
        audits = self.db.sensitive_audits(case_id)
        resolutions = self.db.resolution_candidates(case_id)
        alerts = self.db.alerts(case_id, limit=500)
        source_runs = self.db.source_runs(case_id, limit=2000)

        source_counts = Counter(event["source_module"] for event in events)
        type_counts = Counter(event["event_type"] for event in events)
        risk_counts = Counter(event["risk"] for event in events)
        status_counts = Counter(scan["status"] for scan in scans)
        timeline: list[dict[str, Any]] = []
        for scan in scans:
            timeline.append({
                "at": scan["started_at"], "kind": "scan-started", "id": scan["id"],
                "label": scan["mode"], "state": scan["status"],
            })
            if scan.get("completed_at"):
                timeline.append({
                    "at": scan["completed_at"], "kind": "scan-completed", "id": scan["id"],
                    "label": scan["mode"], "state": scan["status"],
                })
        for item in evidence:
            timeline.append({
                "at": item["captured_at"], "kind": "evidence-preserved",
                "id": item["sha256"], "label": item["source"], "state": "immutable-hash",
            })
        for item in notes:
            timeline.append({
                "at": item["created_at"], "kind": "analyst-note", "id": item["id"],
                "label": item["classification"], "state": "analyst-authored",
            })
        for item in source_runs:
            timeline.append({
                "at": item["started_at"], "kind": "source-run", "id": item["id"],
                "label": item["source"], "state": item["status"],
            })
        timeline.sort(key=lambda row: (row["at"], row["kind"], row["id"]))

        failed_sources = [
            {"source": row["source"], "consecutive_failures": row["consecutive_failures"],
             "last_failure_at": row["last_failure_at"], "error": row["last_error_message"]}
            for row in self.db.connector_health() if row["consecutive_failures"]
        ]
        pending_resolutions = sum(row["status"] == "pending" for row in resolutions)
        open_alerts = sum(row["status"] == "open" for row in alerts)
        source_run_states = Counter(row["status"] for row in source_runs)
        source_run_coverage: dict[str, dict[str, Any]] = {}
        for source in sorted({row["source"] for row in source_runs}):
            rows = [row for row in source_runs if row["source"] == source]
            completed = sum(row["status"] == "completed" for row in rows)
            terminal = sum(row["status"] != "running" for row in rows)
            durations = sorted(
                row["duration_ms"] for row in rows if isinstance(row.get("duration_ms"), int)
            )
            percentile_index = max(0, round(0.95 * len(durations)) - 1) if durations else 0
            source_run_coverage[source] = {
                "runs": len(rows), "completed": completed,
                "success_rate": round(completed / terminal, 3) if terminal else None,
                "p95_duration_ms": durations[percentile_index] if durations else None,
                "last_state": rows[0]["status"],
            }
        review_queue = {
            "pending_entity_resolutions": pending_resolutions,
            "open_alerts": open_alerts,
            "partial_or_failed_scans": sum(
                state in {"partial", "failed"} for state in (scan["status"] for scan in scans)
            ),
            "connector_failures": len(failed_sources),
            "failed_source_runs": source_run_states.get("failed", 0),
        }
        next_actions = []
        if pending_resolutions:
            next_actions.append("Adjudicate pending entity-resolution candidates before merging identities.")
        if open_alerts:
            next_actions.append("Review and acknowledge open monitoring alerts.")
        if failed_sources:
            next_actions.append("Repair or disable unhealthy connectors; do not treat missing sources as negative evidence.")
        if evidence and not events:
            next_actions.append("Normalize preserved evidence into reviewable observations.")
        if len(source_counts) < 2 and events:
            next_actions.append("Corroborate material observations with a second independent source.")
        if not next_actions:
            next_actions.append("Perform human review and document limitations before sharing conclusions.")

        return {
            "schema_version": "1.0", "generated_at": utc_now(), "case": case,
            "overview": {
                "findings": len(findings), "scans": len(scans), "events": len(events),
                "evidence_items": len(evidence), "notes": len(notes),
                "sensitive_workflows": len(audits), "distinct_sources": len(source_counts),
                "source_runs": len(source_runs),
            },
            "coverage": {
                "sources": dict(sorted(source_counts.items())),
                "event_types": dict(sorted(type_counts.items())),
                "risk": dict(sorted(risk_counts.items())),
                "scan_status": dict(sorted(status_counts.items())),
                "source_runs": source_run_coverage,
            },
            "review_queue": review_queue,
            "source_health": {"unhealthy": failed_sources},
            "timeline": timeline[-500:],
            "next_actions": next_actions,
            "limitations": [
                "A source observation is not proof of identity, ownership, employment or wrongdoing.",
                "Coverage is incomplete where access, licensing, consent or provider availability is absent.",
                "AI and model outputs remain advisory until linked evidence is reviewed by an analyst.",
            ],
        }

    def write(self, case_id: str, output: Path) -> dict[str, Any]:
        workspace = self.build(case_id)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(workspace, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"case_id": case_id, "output": str(output), "workspace": workspace}
