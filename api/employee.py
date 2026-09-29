"""Authenticated case analysis. This endpoint cannot collect, probe or run models."""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# The employee-specific Vercel bundle includes the shared dependency-free core.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from traceatlas.employee.brief import build_brief, clean
from traceatlas.employee.skills import REFERENCES, skill_catalog
from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, read_json,
    require_same_origin, require_text, require_uuid, send_json,
)


def _case(gateway, case_id):
    cases = gateway.select("cases", {"id": f"eq.{case_id}", "select": "id,organisation_id", "limit": "1"})
    if len(cases) != 1:
        raise ControlPlaneError(404, "case_not_found")
    return cases[0]


def _brief(gateway, case_id, objective, mode):
    def evidence():
        return gateway.select("evidence_items", {
            "case_id": f"eq.{case_id}", "select": "id,source,classification,payload,content_hash,created_at",
            "order": "created_at.desc,id", "limit": "201",
        })
    def runs():
        return gateway.select("source_runs", {
            "case_id": f"eq.{case_id}", "select": "source,status,failure_code,started_at",
            "order": "started_at.desc", "limit": "500",
        })
    with ThreadPoolExecutor(max_workers=2) as pool:
        one, two = pool.submit(evidence), pool.submit(runs)
        rows, source_runs = one.result(), two.result()
    observations = []
    for item in rows[:200]:
        payload = item.get("payload") or {}
        children = payload.get("observations") if isinstance(payload, dict) else None
        if isinstance(children, list):
            for index, child in enumerate(children):
                if len(observations) == 200:
                    break
                if not isinstance(child, dict):
                    continue
                tags = child.get("tags") or []
                classification = item.get("classification", "unclassified")
                if any(str(t).lower() in {"inference", "model-output", "correlation"} for t in tags):
                    classification = "inference"
                observations.append({"id": f"{item['id']}/observations/{index}",
                    "source": item["source"], "title": child.get("title") or child.get("type") or "Worker observation",
                    "data": child, "classification": classification, "collected_at": item.get("created_at")})
        elif len(observations) < 200:
            observations.append({"id": item["id"], "source": item["source"], "title": "Stored source record",
                                 "data": payload, "classification": item.get("classification", "unclassified"),
                                 "collected_at": item.get("created_at")})
    total = sum(len(r.get("payload", {}).get("observations", [r])) if isinstance(r.get("payload"), dict) and
                isinstance(r["payload"].get("observations", [r]), list) else 1 for r in rows)
    try:
        return build_brief(case_id, objective, observations, mode=mode,
                           source_runs=source_runs, truncated=len(rows) > 200 or total > 200)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ControlPlaneError(422, "employee_evidence_contract_invalid") from exc


def review_snapshot(brief):
    # Fit the existing 16 KiB review context, retaining a digest of the full set.
    context = {"type": "employee-brief", "schema": brief["schema"], "objective": brief["objective"],
               "mode": brief["mode"], "evidence_digest": brief["evidence_digest"],
               "brief_digest": brief["brief_digest"], "summary": brief["summary"],
               "generated_at": brief["generated_at"], "decision_owner": "human", "auto_execute": False,
               "scenarios": brief["scenarios"][:3], "insights": brief["insights"][:3],
               "facts": [{"id": f["id"], "source": f["source"], "excerpt": f["excerpt"][:250]}
                         for f in brief["facts"][:10]],
               "snapshot_is_excerpt": True, "limitations": brief["limitations"]}
    while len(json.dumps(context, ensure_ascii=False).encode()) > 14000:
        if context["facts"]:
            context["facts"].pop()
        elif context["scenarios"]:
            context["scenarios"].pop()
        else:
            context["insights"].pop()
    return context


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            gateway, _ = authenticated_gateway(self)
            query = parse_qs(urlparse(self.path).query)
            if query.get("catalog") == ["1"]:
                send_json(self, 200, {"skills": skill_catalog(), "references": REFERENCES,
                                     "hosted_capability": "stored-case-analysis", "executes_scans": False})
                return
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            _case(gateway, case_id)
            rows = gateway.select("review_tasks", {"case_id": f"eq.{case_id}",
                "select": "id,case_id,title,status,context,decision_rationale,decided_by,decided_at,created_at",
                "context->>type": "eq.employee-brief", "order": "created_at.desc", "limit": "100"})
            send_json(self, 200, {"reviews": rows, "case_id": case_id})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self):
        try:
            require_same_origin(self)
            gateway, user = authenticated_gateway(self)
            payload = read_json(self, max_bytes=8192)
            if set(payload) - {"action", "case_id", "objective", "mode", "expected_evidence_digest"}:
                raise ControlPlaneError(400, "unsupported_employee_fields")
            action = payload.get("action", "brief")
            if action not in {"brief", "queue-review"} or payload.get("mode", "osint") not in {"osint", "pt"}:
                raise ControlPlaneError(400, "invalid_employee_action_or_mode")
            case_id = require_uuid(payload.get("case_id"), "case_id")
            objective = require_text(payload.get("objective"), "objective", minimum=10, maximum=1000)
            case = _case(gateway, case_id)
            brief = _brief(gateway, case_id, objective, payload.get("mode", "osint"))
            if action == "brief":
                send_json(self, 200, {"brief": brief})
                return
            if payload.get("expected_evidence_digest") != brief["evidence_digest"]:
                raise ControlPlaneError(409, "case_evidence_changed_rebuild_brief")
            rows = gateway.insert("review_tasks", {
                "organisation_id": case["organisation_id"], "case_id": case_id,
                "created_by": user["id"], "kind": "model-output",
                "title": "Employee brief: " + clean(objective, 210), "priority": "normal",
                "context": review_snapshot(brief),
            })
            send_json(self, 201, {"review": rows[0] if rows else None, "executes_actions": False})
        except Exception as exc:
            handle_error(self, exc)
