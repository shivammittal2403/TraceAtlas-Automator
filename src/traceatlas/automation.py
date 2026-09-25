"""Durable, local-only scheduling and change-alert lifecycle."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .db import CaseDB
from .engine import Engine, SENSITIVE_METHOD_COMMANDS
from .models import utc_now
from .playbooks import get_method
from .policy import PolicyError, require_authorization, validate_target


SCHEDULABLE_AUTOMATION = {"high", "partial"}


def _future(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


class AutomationManager:
    """Runs fixed playbooks; it never stores arbitrary commands or provider secrets."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.db: CaseDB = engine.db

    def add(self, case_id: str, name: str, method_key: str, target_kind: str,
            target_value: str, interval_minutes: int, authority: str, *,
            authorized: bool) -> dict[str, Any]:
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        method = get_method(method_key)
        if method.id in SENSITIVE_METHOD_COMMANDS:
            raise PolicyError("Sensitive workflows cannot be persisted as unattended schedules")
        if method.automation not in SCHEDULABLE_AUTOMATION:
            raise PolicyError("Only high or partial deterministic playbooks can be scheduled")
        require_authorization(method.risk, authorized)
        target = validate_target(target_kind, target_value)
        if target.kind == "file":
            raise PolicyError("File targets cannot be scheduled because paths are not durable evidence scope")
        if method.target_types and target.kind not in method.target_types:
            raise PolicyError(
                f"Method {method.id} accepts {', '.join(method.target_types)}; got {target.kind}."
            )
        if not 5 <= interval_minutes <= 525600:
            raise PolicyError("Schedule interval must be between 5 and 525600 minutes")
        name = name.strip()
        authority = authority.strip()
        if not 3 <= len(name) <= 120:
            raise PolicyError("Schedule name must contain 3-120 characters")
        if not 10 <= len(authority) <= 500:
            raise PolicyError("Recorded authority must contain 10-500 characters")
        now = utc_now()
        row = {
            "id": str(uuid4()), "case_id": case_id, "name": name,
            "method_key": method.slug, "target_kind": target.kind,
            "target_value": target.value, "authority": authority,
            "interval_minutes": interval_minutes, "next_run_at": now, "created_at": now,
        }
        self.db.add_automation_job(row)
        return {**row, "enabled": True, "state": "due"}

    @staticmethod
    def _stable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {key: item[key] for key in (
                "title", "value", "source", "confidence", "severity", "observation"
            )}
            for item in findings
        ]

    def _execute(self, job: dict[str, Any]) -> dict[str, Any]:
        run_id = self.db.start_automation_run(str(job["id"]))
        status, result, error_type = "failed", None, None
        baseline = changed = False
        try:
            result = self.engine.run(
                str(job["case_id"]), str(job["method_key"]), str(job["target_kind"]),
                str(job["target_value"]), authorized=True,
            )
            payload = self._stable_findings(self.db.findings(str(job["case_id"])))
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            key = f"automation:{job['id']}"
            previous = self.db.latest_snapshot_hash(str(job["case_id"]), key)
            baseline = previous is None
            changed = previous is not None and previous != digest
            self.db.snapshot(str(job["case_id"]), key, digest, payload)
            status = str(result.get("status", "completed"))
            raw_errors = result.get("errors", [])
            result = {key: value for key, value in result.items() if key != "errors"}
            result.update({"error_count": len(raw_errors) if isinstance(raw_errors, list) else 0,
                           "baseline": baseline, "changed": changed,
                           "snapshot_sha256": digest})
            if changed:
                self.db.add_alert({
                    "id": str(uuid4()), "case_id": str(job["case_id"]),
                    "source": f"automation:{job['id']}", "kind": "evidence_changed",
                    "severity": "medium", "message": f"Scheduled evidence changed: {job['name']}",
                    "details": {"job_id": job["id"], "method": job["method_key"],
                                "run_id": run_id, "snapshot_sha256": digest},
                    "created_at": utc_now(),
                })
            if status == "partial":
                self.db.add_alert({
                    "id": str(uuid4()), "case_id": str(job["case_id"]),
                    "source": f"automation:{job['id']}", "kind": "execution_partial",
                    "severity": "warning", "message": f"Scheduled workflow completed partially: {job['name']}",
                    "details": {"job_id": job["id"], "method": job["method_key"],
                                "run_id": run_id, "error_count": result["error_count"]},
                    "created_at": utc_now(),
                })
        except Exception as exc:
            error_type = type(exc).__name__
            result = {"error": "scheduled_execution_failed", "error_type": error_type}
            self.db.add_alert({
                "id": str(uuid4()), "case_id": str(job["case_id"]),
                "source": f"automation:{job['id']}", "kind": "execution_failed",
                "severity": "high", "message": f"Scheduled workflow failed: {job['name']}",
                "details": {"job_id": job["id"], "method": job["method_key"],
                            "run_id": run_id, "error_type": error_type},
                "created_at": utc_now(),
            })
        finally:
            self.db.finish_automation_run(
                run_id, str(job["id"]), status, baseline=baseline, changed=changed,
                result=result, error_type=error_type,
                next_run_at=_future(int(job["interval_minutes"])),
            )
        return {"job_id": job["id"], "run_id": run_id, "status": status,
                "baseline": baseline, "changed": changed, "result": result}

    def run_due(self, limit: int = 10) -> dict[str, Any]:
        if not 1 <= limit <= 100:
            raise PolicyError("Due-run limit must be between 1 and 100")
        now = utc_now()
        jobs = self.db.claim_due_automation_jobs(now, _future(15), limit)
        results = [self._execute(job) for job in jobs]
        return {"claimed": len(jobs), "completed": sum(
            row["status"] in {"completed", "partial"} for row in results
        ), "failed": sum(row["status"] == "failed" for row in results), "results": results}
