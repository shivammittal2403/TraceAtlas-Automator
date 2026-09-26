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
            organisation_id = require_uuid(
                (query.get("organisation_id") or [""])[0], "organisation_id"
            )
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("organisation_members", {
                "organisation_id": f"eq.{organisation_id}",
                "select": "organisation_id,user_id,role,created_at",
                "order": "created_at.asc", "limit": "200",
            })
            send_json(self, 200, {"members": rows})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            payload = read_json(self, max_bytes=4096)
            organisation_id = require_uuid(payload.get("organisation_id"), "organisation_id")
            user_id = require_uuid(payload.get("user_id"), "user_id")
            action = require_text(payload.get("action"), "action", maximum=20)
            gateway, _ = authenticated_gateway(self)
            if action == "set_role":
                role = require_text(payload.get("role"), "role", maximum=20)
                if role not in {"owner", "admin", "analyst", "viewer"}:
                    raise ControlPlaneError(400, "invalid_role")
                result = gateway.rpc("set_organisation_member_role", {
                    "p_organisation_id": organisation_id, "p_user_id": user_id,
                    "p_role": role,
                })
            elif action == "remove":
                result = gateway.rpc("remove_organisation_member", {
                    "p_organisation_id": organisation_id, "p_user_id": user_id,
                })
            else:
                raise ControlPlaneError(400, "invalid_action")
            send_json(self, 200, {"result": result, "mfa_assurance": "aal2-required"})
        except Exception as exc:
            handle_error(self, exc)

    def do_DELETE(self) -> None:
        send_json(self, 405, {"error": "method_not_allowed"})
