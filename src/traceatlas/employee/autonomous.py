"""Persisted, bounded public-source investigation coordinator.

The manifest is an operator authorization, never a model-generated permission.
Only existing fixed-host IntelligenceHub connectors are executable skills.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from ..intelligence.contracts import source_contract
from ..intelligence.hub import IntelligenceHub
from ..intelligence.sources import SOURCES
from ..policy import PolicyError
from ..filesystem import path_component
from ..workforce.service import workforce_enabled
from .brief import clean, digest
from .service import ATTESTATIONS, COLLECTION, plan_collection

SCHEMA = """
CREATE TABLE IF NOT EXISTS autonomous_investigations (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
 manifest_json TEXT NOT NULL, manifest_hash TEXT NOT NULL, status TEXT NOT NULL,
 elapsed REAL NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0,
 lease_until TEXT, report_json TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS autonomous_actions (
 investigation_id TEXT NOT NULL REFERENCES autonomous_investigations(id),
 action_id TEXT NOT NULL, state TEXT NOT NULL, outcome_json TEXT NOT NULL,
 PRIMARY KEY(investigation_id,action_id)
);
CREATE TABLE IF NOT EXISTS autonomous_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL,
 at TEXT NOT NULL, kind TEXT NOT NULL, detail_json TEXT NOT NULL
);
"""


def now():
    return datetime.now(timezone.utc)


def executable_skills():
    """Versioned procedures mapped to existing, validated connector contracts."""
    rows = []
    for kind, sources in COLLECTION.items():
        for source in sources:
            contract = source_contract(source)
            rows.append({"skill_id": f"{kind}.{source}", "version": 1,
                         "target_type": kind, "source": source,
                         "contract": contract.to_dict(), "mode": "passive-provider-query",
                         "limitation": SOURCES[source].limitation})
    return rows


def skill_contract_digest(source_fabric=False):
    if source_fabric:
        from ..source_fabric.registry import manifest
        return digest([manifest(source) for source in sorted(SOURCES)])
    return digest(executable_skills())


class AutonomousInvestigator:
    def __init__(self, db, workspace: Path, *, hub=None, enabled=None, model_requester=None):
        self.db, self.workspace = db, workspace
        self.hub = hub or IntelligenceHub(db, workspace)
        self.enabled = workforce_enabled() if enabled is None else enabled
        self.model_requester = model_requester
        self.fabric_requester = hub.requester if hub is not None else None
        db.conn.executescript(SCHEMA)
        db.conn.commit()

    def _event(self, investigation_id, kind, detail):
        self.db.conn.execute("INSERT INTO autonomous_events(investigation_id,at,kind,detail_json) VALUES(?,?,?,?)",
                             (investigation_id, now().isoformat(), kind, json.dumps(detail)))
        self.db.conn.commit()

    def _enabled(self):
        if not self.enabled or os.getenv("TRACEATLAS_WORKFORCE_KILL_SWITCH", "").casefold() in {"1", "yes", "true"}:
            raise PolicyError("Autonomous research is disabled or the kill switch is active")

    def create(self, case_id, objective, seeds, *, actor, attestations, authorized=False,
               subject_type="asset", subject_label="", max_actions=8, runtime_seconds=120,
               hours=24, model=None, source_fabric=False):
        self._enabled()
        if not authorized or not self.db.get_case(case_id):
            raise PolicyError("An existing case and explicit authorization are required")
        if not isinstance(objective, str) or not 10 <= len(objective.strip()) <= 1000:
            raise PolicyError("Objective must contain 10-1000 characters")
        if not isinstance(actor, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{2,80}", actor):
            raise PolicyError("Actor must be a 2-80 character analyst identifier")
        for value, low, high in ((max_actions, 1, 12), (runtime_seconds, 5, 900), (hours, 1, 168)):
            if type(value) is not int or not low <= value <= high:
                raise PolicyError("Invalid action, runtime or authorization duration budget")
        if subject_type not in {"asset", "person", "company"}:
            raise PolicyError("Subject type must be asset, person or company")
        if not isinstance(subject_label, str) or len(subject_label) > 160:
            raise PolicyError("Subject label must be at most 160 characters")
        if not isinstance(attestations, dict) or set(attestations) - ATTESTATIONS or any(type(v) is not bool for v in attestations.values()):
            raise PolicyError("Invalid authorization attestations")
        if subject_type == "person" and not attestations.get("subject_consent"):
            raise PolicyError("Person investigation requires subject consent")
        if subject_type == "company" and not (attestations.get("owned_org") or attestations.get("public_record_basis")):
            raise PolicyError("Company investigation requires an owned organization or public-record basis")
        if not isinstance(seeds, list) or not 1 <= len(seeds) <= 10:
            raise PolicyError("Supply 1-10 explicit typed seeds; a name alone cannot authorize identity discovery")
        if model is not None and (not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,120}", model)):
            raise PolicyError("Invalid local model name")
        normalized, actions, routing_plans = [], [], []
        for seed in seeds:
            if not isinstance(seed, dict) or set(seed) != {"type", "value"}:
                raise PolicyError("Each seed requires only type and value")
            kind, value = seed["type"], seed["value"]
            if not isinstance(value, str):
                raise PolicyError("Seed value must be text")
            value = value.strip()
            if kind in {"domain", "hash"}:
                value = value.lower()
            if kind == "ip":
                value = str(ipaddress.ip_address(value))
            if source_fabric:
                from ..source_fabric.router import SourceRouter
                routing = SourceRouter(self.db).plan(objective, kind, value, attestations)
                steps = routing["actions"]
                routing_plans.append({"seed": {"type": kind, "value": value}, **routing})
            else:
                steps = plan_collection(kind, value, mode="osint", attestations=attestations)
            normalized_seed = {"type": kind, "value": value}
            if normalized_seed in normalized:
                continue
            normalized.append(normalized_seed)
            for step in steps:
                contract = source_contract(step["source"])
                if kind not in contract.inputs or not contract.allowed_hosts:
                    raise PolicyError("Source contract does not accept seed")
                action = {"source": step["source"], "target_type": kind, "target": value,
                          "skill_id": f"{kind}.{step['source']}", "contract_version": contract.contract_version}
                if source_fabric:
                    action.update({k: step[k] for k in ("wave", "capabilities", "score", "provider", "rationale")})
                action["action_id"] = "action-" + digest(action)[:20]
                actions.append(action)
        manifest = {"schema": "traceatlas.autonomous.v1", "case_id": case_id,
                    "objective": clean(objective, 1000), "actor": actor,
                    "subject_type": subject_type, "subject_label": clean(subject_label, 160),
                    "seeds": normalized, "actions": actions, "attestations": attestations,
                    "max_actions": max_actions, "runtime_seconds": runtime_seconds,
                    "expires_at": (now() + timedelta(hours=hours)).isoformat(), "model": model,
                    "skills_digest": skill_contract_digest(source_fabric), "external_actions": False,
                    "scope_expansion": False, "human_release_required": True}
        manifest["source_fabric"] = bool(source_fabric)
        manifest["routing_plans"] = routing_plans
        identifier = "investigation-" + uuid4().hex
        self.db.conn.execute("INSERT INTO autonomous_investigations(id,case_id,manifest_json,manifest_hash,status,created_at) VALUES(?,?,?,?,?,?)",
                             (identifier, case_id, json.dumps(manifest), digest(manifest), "ready", now().isoformat()))
        self.db.conn.commit()
        self._event(identifier, "authorization_recorded", {"actor": actor, "manifest_hash": digest(manifest)})
        return self.get(case_id, identifier)

    def get(self, case_id, investigation_id):
        case_id, investigation_id = path_component(case_id), path_component(investigation_id)
        row = self.db.conn.execute("SELECT * FROM autonomous_investigations WHERE id=? AND case_id=?", (investigation_id, case_id)).fetchone()
        if row is None:
            raise PolicyError("Investigation not found in this case")
        result = dict(row)
        result["id"] = path_component(result["id"])
        result["case_id"] = path_component(result["case_id"])
        result["manifest"] = json.loads(result.pop("manifest_json"))
        if digest(result["manifest"]) != result["manifest_hash"]:
            raise PolicyError("Investigation authorization manifest changed")
        result["report"] = json.loads(result.pop("report_json") or "null")
        result["actions"] = [{"action_id": r["action_id"], "state": r["state"], "outcome": json.loads(r["outcome_json"])}
                             for r in self.db.conn.execute("SELECT * FROM autonomous_actions WHERE investigation_id=? ORDER BY rowid", (investigation_id,))]
        result["events"] = [{"at": r["at"], "kind": r["kind"], "detail": json.loads(r["detail_json"])}
                            for r in self.db.conn.execute("SELECT * FROM autonomous_events WHERE investigation_id=? ORDER BY id", (investigation_id,))]
        return result

    def cancel(self, case_id, investigation_id, *, actor, authorized=False):
        current = self.get(case_id, investigation_id)
        if not authorized or actor != current["manifest"]["actor"]:
            raise PolicyError("Cancellation requires the authorizing analyst")
        self.db.conn.execute("UPDATE autonomous_investigations SET cancel_requested=1 WHERE id=?", (investigation_id,))
        self.db.conn.commit()
        self._event(investigation_id, "cancel_requested", {"actor": actor})
        return self.get(case_id, investigation_id)

    @staticmethod
    def _rank(action, objective, outcomes):
        # Only rank pre-authorized actions. Source content never supplies tools or targets.
        hints = {"dns": ("dns", "infrastructure", "resolve"), "rdap": ("ownership", "registration", "company"),
                 "wayback": ("history", "archive", "timeline"), "internetdb": ("exposure", "ports", "risk"),
                 "nvd": ("cve", "vulnerability"), "github": ("repository", "professional", "profile")}
        value = 10 + 5 * sum(term in objective.casefold() for term in hints.get(action["source"], ()))
        value -= sum(r["outcome"].get("source") == action["source"] for r in outcomes) * 2
        return (-value, action["action_id"])

    def run(self, case_id, investigation_id, *, actor, authorized=False, resume=False):
        from .autonomous_analysis import build_report, add_model_advisory
        self._enabled()
        current = self.get(case_id, investigation_id)
        manifest = current["manifest"]
        if not authorized or actor != manifest["actor"]:
            raise PolicyError("Execution requires the authorizing analyst")
        if now() >= datetime.fromisoformat(manifest["expires_at"]):
            raise PolicyError("Investigation authorization expired")
        if skill_contract_digest(manifest.get("source_fabric", False)) != manifest["skills_digest"]:
            raise PolicyError("Executable skill contracts changed; authorize a new investigation")
        if current["status"] in {"completed", "partial", "cancelled"}:
            return current
        if current["status"] == "running" and current["lease_until"] and now() < datetime.fromisoformat(current["lease_until"]):
            raise PolicyError("Investigation is already running")
        if current["status"] != "ready" and not resume:
            raise PolicyError("Interrupted investigation requires explicit resume")
        previous_status = current["status"]
        with self.db.conn:
            changed = self.db.conn.execute("""UPDATE autonomous_investigations SET status='running',lease_until=?
                WHERE id=? AND status=? AND (status!='running' OR lease_until<=?)
                AND NOT EXISTS (SELECT 1 FROM autonomous_investigations other
                  WHERE other.case_id=? AND other.id!=? AND other.status='running' AND other.lease_until>?)""",
                ((now() + timedelta(seconds=manifest["runtime_seconds"] + 60)).isoformat(), investigation_id,
                 previous_status, now().isoformat(), case_id, investigation_id, now().isoformat()))
            if changed.rowcount != 1:
                raise PolicyError("Investigation or case is already claimed by another worker")
            self.db.conn.execute("UPDATE autonomous_actions SET state='uncertain' WHERE investigation_id=? AND state='running'", (investigation_id,))
        if manifest.get("source_fabric"):
            from ..source_fabric.execution import execute
            return execute(self, case_id, investigation_id)
        stop = "sources_exhausted"
        try:
            while True:
                self._enabled()
                current = self.get(case_id, investigation_id)
                if current["cancel_requested"]:
                    stop = "cancelled"
                    break
                if now() >= datetime.fromisoformat(manifest["expires_at"]):
                    stop = "authorization_expired"
                    break
                actions = current["actions"]
                spent = sum(a["state"] != "skipped" for a in actions)
                remaining = manifest["runtime_seconds"] - current["elapsed"]
                pending = [a for a in manifest["actions"] if a["action_id"] not in {r["action_id"] for r in actions}]
                if not pending:
                    break
                if spent >= manifest["max_actions"] or remaining < 1:
                    stop = "action_budget_reached" if spent >= manifest["max_actions"] else "runtime_budget_reached"
                    break
                action = sorted(pending, key=lambda a: self._rank(a, manifest["objective"], actions))[0]
                contract = source_contract(action["source"])
                health = next((r for r in self.db.connector_health() if r["source"] == action["source"]), {})
                reason = "circuit_open" if health.get("consecutive_failures", 0) >= 3 else None
                # Paid/credential-required services need an explicit pricing/entitlement contract.
                credentialed = contract.authentication == "secret-reference" or any(
                    os.environ.get(name) for name in contract.credential_env)
                if credentialed and not contract.unattended_paid_calls:
                    reason = "unattended_provider_entitlement_required"
                if reason:
                    self.db.conn.execute("INSERT INTO autonomous_actions VALUES(?,?,?,?)", (investigation_id, action["action_id"], "skipped", json.dumps({"source": action["source"], "reason": reason})))
                    self.db.conn.commit()
                    self._event(investigation_id, "source_skipped", {"source": action["source"], "reason": reason})
                    continue
                timeout = min(30, remaining, (datetime.fromisoformat(manifest["expires_at"])-now()).total_seconds())
                # Reserve before network I/O: a killed process consumes this reservation.
                with self.db.conn:
                    self.db.conn.execute("INSERT INTO autonomous_actions VALUES(?,?,?,?)", (investigation_id, action["action_id"], "running", json.dumps({"source": action["source"]})))
                    self.db.conn.execute("UPDATE autonomous_investigations SET elapsed=elapsed+? WHERE id=?", (timeout, investigation_id))
                self._event(investigation_id, "source_started", {"action": action, "timeout_seconds": timeout})
                started = time.monotonic()
                try:
                    outcome = self.hub.collect(case_id, action["source"], action["target_type"], action["target"], authorized=True,
                                               timeout_seconds=timeout, **manifest["attestations"])
                    outcome = {"source": action["source"], "scan_id": outcome["scan_id"],
                               "evidence_refs": outcome["evidence_refs"], "stats": outcome["stats"]}
                    state = "completed"
                except Exception as exc:
                    # Exception messages may contain URLs/credentials: store the class only.
                    outcome, state = {"source": action["source"], "error_type": type(exc).__name__}, "failed"
                elapsed = time.monotonic() - started
                with self.db.conn:
                    self.db.conn.execute("UPDATE autonomous_actions SET state=?,outcome_json=? WHERE investigation_id=? AND action_id=?",
                                         (state, json.dumps(outcome), investigation_id, action["action_id"]))
                    self.db.conn.execute("UPDATE autonomous_investigations SET elapsed=max(0,elapsed+?) WHERE id=?", (elapsed-timeout, investigation_id))
                self._event(investigation_id, "source_finished", {"source": action["source"], "state": state})
            current = self.get(case_id, investigation_id)
            report = build_report(self.db, self.workspace, current, stop)
            if manifest["model"] and stop != "cancelled" and not current["cancel_requested"]:
                self._enabled()
                remaining = manifest["runtime_seconds"] - current["elapsed"]
                if remaining >= 1 and now() < datetime.fromisoformat(manifest["expires_at"]):
                    timeout = min(30, remaining)
                    self.db.conn.execute("UPDATE autonomous_investigations SET elapsed=elapsed+? WHERE id=?", (timeout, investigation_id))
                    self.db.conn.commit()
                    started = time.monotonic()
                    report["model_advisory"] = add_model_advisory(report, manifest["model"], timeout, self.model_requester)
                    self.db.conn.execute("UPDATE autonomous_investigations SET elapsed=elapsed+? WHERE id=?", (time.monotonic()-started-timeout, investigation_id))
                else:
                    report["model_advisory"] = {"status": "budget_or_authorization_exhausted", "may_execute": False}
            self._enabled()
            if self.get(case_id, investigation_id)["cancel_requested"]:
                stop = report["stop_reason"] = "cancelled"
            status = "cancelled" if stop == "cancelled" else "partial" if report["unknowns"] else "completed"
            self._event(investigation_id, "investigation_finished", {"stop_reason": stop, "status": status})
            report["events"] = self.get(case_id, investigation_id)["events"]
            report["runtime_seconds"] = self.get(case_id, investigation_id)["elapsed"]
            report["report_digest"] = digest(report)
            self.db.conn.execute("UPDATE autonomous_investigations SET status=?,report_json=?,lease_until=NULL WHERE id=?",
                                 (status, json.dumps(report), investigation_id))
            self.db.conn.commit()
        except BaseException:
            self.db.conn.execute("UPDATE autonomous_investigations SET status='interrupted',lease_until=NULL WHERE id=?", (investigation_id,))
            self.db.conn.commit()
            raise
        return self.get(case_id, investigation_id)

    def export(self, case_id, investigation_id, output: Path):
        from .autonomous_analysis import export_report
        current = self.get(case_id, investigation_id)
        if not current["report"]:
            raise PolicyError("Run the investigation before exporting its report")
        return export_report(self.db, self.workspace, current, output)
