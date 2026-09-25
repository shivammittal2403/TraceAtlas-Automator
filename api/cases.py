from http.server import BaseHTTPRequestHandler

from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, read_json,
    require_same_origin, require_text, require_uuid, send_json,
)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("cases", {
                "select": "id,organisation_id,title,purpose,status,created_at,updated_at",
                "order": "created_at.desc", "limit": "100",
            })
            send_json(self, 200, {"cases": rows})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            gateway, _ = authenticated_gateway(self)
            payload = read_json(self)
            if payload.get("authorization_confirmed") is not True:
                raise ControlPlaneError(400, "authorization_confirmation_required")
            organisation_id = require_uuid(payload.get("organisation_id"), "organisation_id")
            title = require_text(payload.get("title"), "title", minimum=3, maximum=160)
            purpose = require_text(payload.get("purpose"), "purpose", minimum=10, maximum=1000)
            scope = {"cloud_targets": ["domain", "ip", "url", "hash"], "identity_targets": False}
            rows = gateway.insert("cases", {"organisation_id": organisation_id, "title": title,
                                             "purpose": purpose, "scope": scope})
            send_json(self, 201, {"case": rows[0] if rows else None})
        except Exception as exc:
            handle_error(self, exc)
