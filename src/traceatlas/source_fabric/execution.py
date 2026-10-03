"""Capability waves inside the existing digest-bound employee investigation."""
from __future__ import annotations

import json
import time
from datetime import datetime

from ..employee.autonomous import now
from ..employee.autonomous_analysis import build_report, add_model_advisory
from ..employee.brief import digest
from .gateway import SourceGateway


def execute(employee, case_id, identifier):
    db = employee.db
    current = employee.get(case_id, identifier)
    manifest = current["manifest"]
    gateway = SourceGateway(db, employee.workspace, requester=employee.fabric_requester)
    stop = "sources_exhausted"
    try:
        while True:
            employee._enabled()
            current = employee.get(case_id, identifier)
            if current["cancel_requested"]:
                stop = "cancelled"
                break
            if now() >= datetime.fromisoformat(manifest["expires_at"]):
                stop = "authorization_expired"
                break
            done = {a["action_id"]: a for a in current["actions"]}
            remaining_actions = manifest["max_actions"]-sum(a["state"] != "skipped" for a in done.values())
            remaining_time = manifest["runtime_seconds"]-current["elapsed"]
            pending = [a for a in manifest["actions"] if a["action_id"] not in done]
            if not pending:
                break
            if remaining_actions <= 0 or remaining_time < 1:
                stop = "action_budget_reached" if remaining_actions <= 0 else "runtime_budget_reached"
                break
            # Coverage is scoped to a typed seed; one domain's evidence cannot cover another.
            covered = {}
            for a in manifest["actions"]:
                result = done.get(a["action_id"], {})
                if result.get("state") == "completed" and result.get("outcome", {}).get("stats", {}).get("records_stored", 0):
                    covered.setdefault((a["target_type"], a["target"]), set()).update(a["capabilities"])
            available = []
            for a in pending:
                if a["wave"] > 1 and set(a["capabilities"]).issubset(covered.get((a["target_type"], a["target"]), set())):
                    db.conn.execute("INSERT INTO autonomous_actions VALUES(?,?,?,?)", (identifier, a["action_id"], "skipped", json.dumps({"source": a["source"], "reason": "sufficient_capability_coverage"})))
                else:
                    available.append(a)
            db.conn.commit()
            if not available:
                stop = "low_expected_information_gain"
                break
            wave = min(a["wave"] for a in available)
            batch, batch_coverage, providers = [], {}, set()
            for a in sorted((a for a in available if a["wave"] == wave), key=lambda a: (-a["score"], a["action_id"])):
                seed_key = (a["target_type"], a["target"])
                if a["provider"] in providers:
                    continue
                if wave > 1 and set(a["capabilities"]).issubset(batch_coverage.get(seed_key, set())):
                    continue
                batch.append(a)
                providers.add(a["provider"])
                batch_coverage.setdefault(seed_key, set()).update(a["capabilities"])
                if len(batch) >= min(3, remaining_actions):
                    break
            timeout = min(30, remaining_time/len(batch), (datetime.fromisoformat(manifest["expires_at"])-now()).total_seconds())
            with db.conn:
                for a in batch:
                    db.conn.execute("INSERT INTO autonomous_actions VALUES(?,?,?,?)", (identifier, a["action_id"], "running", json.dumps({"source": a["source"]})))
                db.conn.execute("UPDATE autonomous_investigations SET elapsed=elapsed+? WHERE id=?", (timeout*len(batch), identifier))
            employee._event(identifier, "wave_started", {"wave": wave, "sources": [a["source"] for a in batch],
                "justification": "initial capability cover" if wave == 1 else "earlier source failed or returned no records",
                "scope_expansion": False})
            outcomes = gateway.collect_batch(case_id, batch, manifest["attestations"], current["manifest_hash"], timeout=timeout)
            measured = 0
            with db.conn:
                for result in outcomes:
                    measured += result.get("duration_seconds", 0)
                    db.conn.execute("UPDATE autonomous_actions SET state=?,outcome_json=? WHERE investigation_id=? AND action_id=?",
                        (result["state"], json.dumps(result["outcome"]), identifier, result["action_id"]))
                db.conn.execute("UPDATE autonomous_investigations SET elapsed=max(0,elapsed+?) WHERE id=?", (measured-timeout*len(batch), identifier))
            employee._event(identifier, "wave_finished", {"wave": wave, "states": [r["state"] for r in outcomes]})
        current = employee.get(case_id, identifier)
        report = build_report(db, employee.workspace, current, stop)
        report["source_fabric"] = {"routing_plans": manifest["routing_plans"], "parallel_limit": 3,
                                   "coverage_semantics": "nonempty provider records, not proof of the investigation objective"}
        if manifest["model"] and stop != "cancelled":
            remaining = manifest["runtime_seconds"]-current["elapsed"]
            if remaining >= 1 and now() < datetime.fromisoformat(manifest["expires_at"]):
                employee._enabled()
                timeout = min(30, remaining)
                db.conn.execute("UPDATE autonomous_investigations SET elapsed=elapsed+? WHERE id=?", (timeout, identifier))
                db.conn.commit()
                started = time.monotonic()
                report["model_advisory"] = add_model_advisory(report, manifest["model"], timeout, employee.model_requester)
                db.conn.execute("UPDATE autonomous_investigations SET elapsed=elapsed+? WHERE id=?", (time.monotonic()-started-timeout, identifier))
                db.conn.commit()
            else:
                report["model_advisory"] = {"status": "budget_or_authorization_exhausted", "may_execute": False}
        employee._enabled()
        if employee.get(case_id, identifier)["cancel_requested"]:
            stop = report["stop_reason"] = "cancelled"
        status = "cancelled" if stop == "cancelled" else "partial" if report["unknowns"] else "completed"
        employee._event(identifier, "investigation_finished", {"stop_reason": stop, "status": status})
        final = employee.get(case_id, identifier)
        report.update({"events": final["events"], "runtime_seconds": final["elapsed"]})
        report["report_digest"] = digest(report)
        db.conn.execute("UPDATE autonomous_investigations SET status=?,report_json=?,lease_until=NULL WHERE id=?", (status, json.dumps(report), identifier))
        db.conn.commit()
        return employee.get(case_id, identifier)
    except BaseException:
        db.conn.execute("UPDATE autonomous_investigations SET status='interrupted',lease_until=NULL WHERE id=?", (identifier,))
        db.conn.commit()
        raise
