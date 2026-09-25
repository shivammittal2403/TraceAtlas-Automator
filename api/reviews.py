import urllib.parse
from http.server import BaseHTTPRequestHandler

from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, read_json,
    require_same_origin, require_text, require_uuid, send_json,
)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("review_tasks", {
                "case_id": f"eq.{case_id}",
                "select": "id,case_id,evidence_id,assigned_to,kind,title,priority,status,context,decision_rationale,decided_by,decided_at,created_at",
                "order": "created_at.desc", "limit": "200",
            })
            send_json(self, 200, {"reviews": rows})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            gateway, _ = authenticated_gateway(self)
            payload = read_json(self)
            decision = str(payload.get("decision", "")).strip().lower()
            if decision not in {"accepted", "rejected"}:
                raise ControlPlaneError(400, "invalid_review_decision")
            result = gateway.rpc("decide_review_task", {
                "p_task_id": require_uuid(payload.get("task_id"), "task_id"),
                "p_decision": decision,
                "p_rationale": require_text(
                    payload.get("rationale"), "review_rationale", minimum=10, maximum=2000,
                ),
            })
            task = result[0] if isinstance(result, list) and result else result
            send_json(self, 200, {"review": task})
        except Exception as exc:
            handle_error(self, exc)
