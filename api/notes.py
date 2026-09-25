import urllib.parse
from http.server import BaseHTTPRequestHandler

from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, read_json,
    require_same_origin, require_text, require_uuid, send_json,
)


CLASSIFICATIONS = {"fact", "analysis", "question"}


def _case(gateway, case_id):
    rows = gateway.select("cases", {
        "id": f"eq.{case_id}", "select": "id,organisation_id", "limit": "1",
    })
    if len(rows) != 1:
        raise ControlPlaneError(404, "case_not_found")
    return rows[0]


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("case_notes", {
                "case_id": f"eq.{case_id}",
                "select": "id,case_id,created_by,classification,body,created_at",
                "order": "created_at.desc", "limit": "200",
            })
            send_json(self, 200, {"notes": rows})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            gateway, _ = authenticated_gateway(self)
            payload = read_json(self)
            case_id = require_uuid(payload.get("case_id"), "case_id")
            case = _case(gateway, case_id)
            classification = str(payload.get("classification", "")).strip().lower()
            if classification not in CLASSIFICATIONS:
                raise ControlPlaneError(400, "invalid_note_classification")
            body = require_text(payload.get("body"), "note_body", maximum=4000)
            rows = gateway.insert("case_notes", {
                "organisation_id": case["organisation_id"], "case_id": case_id,
                "classification": classification, "body": body,
            })
            send_json(self, 201, {"note": rows[0] if rows else None})
        except Exception as exc:
            handle_error(self, exc)
