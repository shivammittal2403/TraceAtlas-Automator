"""Authenticated read/review surface for server-created workforce tasks."""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from traceatlas.workforce.registry import EmployeeRegistry
from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, read_json, require_same_origin,
    require_text, require_uuid, send_json,
)


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            gateway, _ = authenticated_gateway(self)
            query = parse_qs(urlparse(self.path).query)
            if query.get("registry") == ["1"]:
                send_json(self, 200, {"employees": [item.to_dict() for item in EmployeeRegistry().list()]})
                return
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            cases = gateway.select("cases", {"id": f"eq.{case_id}", "select": "id", "limit": "1"})
            if len(cases) != 1:
                raise ControlPlaneError(404, "case_not_found")
            tasks = gateway.select("workforce_tasks", {
                "case_id": f"eq.{case_id}",
                "select": "id,case_id,employee_id,envelope_digest,trace_id,status,created_at,approved_at,completed_at",
                "order": "created_at.desc", "limit": "100",
            })
            send_json(self, 200, {"case_id": case_id, "tasks": tasks})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self):
        try:
            require_same_origin(self)
            gateway, _ = authenticated_gateway(self)
            payload = read_json(self, max_bytes=4096)
            if set(payload) != {"action", "task_id", "envelope_digest", "rationale"} or payload["action"] != "approve":
                raise ControlPlaneError(400, "invalid_workforce_action")
            task_id = require_uuid(payload["task_id"], "task_id")
            digest = require_text(payload["envelope_digest"], "envelope_digest", minimum=64, maximum=64).lower()
            if any(char not in "0123456789abcdef" for char in digest):
                raise ControlPlaneError(400, "invalid_envelope_digest")
            rationale = require_text(payload["rationale"], "rationale", minimum=10, maximum=2000)
            rows = gateway.rpc("approve_workforce_task", {
                "p_task_id": task_id, "p_envelope_digest": digest, "p_rationale": rationale,
            })
            send_json(self, 200, {"task": rows[0] if isinstance(rows, list) and rows else None,
                                  "executes_actions": False})
        except Exception as exc:
            handle_error(self, exc)
