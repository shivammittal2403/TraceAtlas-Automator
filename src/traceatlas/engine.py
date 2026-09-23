from __future__ import annotations

from pathlib import Path

from .collectors import COLLECTORS
from .db import CaseDB
from .evidence import EvidenceStore
from .playbooks import get_method
from .policy import PolicyError, require_authorization, validate_target


SENSITIVE_METHOD_COMMANDS = {
    22: "sensitive darkweb-monitor",
    26: "sensitive breach-catalog, breach-domain, breach-account, or breach-artifact",
    29: "sensitive person-profile",
    33: "sensitive breach-account, breach-domain, or password-hash",
    34: "sensitive wifi-locate",
}


class Engine:
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.db = CaseDB(workspace / "traceatlas.db")

    def close(self) -> None:
        self.db.close()

    def run(self, case_id: str, method_key: str, target_kind: str, target_value: str,
            authorized: bool = False) -> dict:
        method = get_method(method_key)
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}. Create it first.")
        if method.id in SENSITIVE_METHOD_COMMANDS:
            raise PolicyError(
                f"Method {method.id} must use the dedicated redacted command: "
                f"traceatlas {SENSITIVE_METHOD_COMMANDS[method.id]}. "
                "The generic runner is disabled for sensitive targets."
            )
        require_authorization(method.risk, authorized)
        target = validate_target(target_kind, target_value)
        if method.target_types and target.kind not in method.target_types:
            raise PolicyError(
                f"Method {method.id} accepts {', '.join(method.target_types)}; got {target.kind}."
            )
        run_id = self.db.start_run(case_id, method.id, target.kind, target.value)
        findings = []
        errors = []
        try:
            if target.kind == "file":
                EvidenceStore(self.workspace, self.db, case_id).preserve_file(
                    Path(target.value), f"method:{method.id}"
                )
            for collector_name in method.collectors:
                try:
                    findings.extend(COLLECTORS[collector_name](target))
                except Exception as exc:  # isolate adapters so a partial run remains useful
                    errors.append(f"{collector_name}: {type(exc).__name__}: {exc}")
            added = self.db.add_findings(case_id, run_id, findings)
            status = "partial" if errors else "completed"
            self.db.end_run(run_id, status, "; ".join(errors) or None)
            return {
                "run_id": run_id, "status": status, "findings_collected": len(findings),
                "findings_added": added, "errors": errors, "review_required": method.review_gate,
                "automation": method.automation,
            }
        except Exception as exc:
            self.db.end_run(run_id, "failed", str(exc))
            raise
