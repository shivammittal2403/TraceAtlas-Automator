from http.server import BaseHTTPRequestHandler

from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, read_json,
    require_same_origin, require_text, require_uuid, send_json, validate_asset,
)


OWNERSHIP_BASES = {"owned_asset", "written_authorization"}


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("assets", {
                "select": "id,organisation_id,label,target_type,target_value,target_fingerprint,ownership_basis,verified_at,created_at",
                "order": "created_at.desc", "limit": "100",
            })
            send_json(self, 200, {"assets": rows})
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
            target_type, target_value = validate_asset(payload.get("target_type"), payload.get("target_value"))
            ownership_basis = str(payload.get("ownership_basis", "")).strip()
            if ownership_basis not in OWNERSHIP_BASES:
                raise ControlPlaneError(400, "invalid_ownership_basis")
            label = require_text(payload.get("label", target_type), "label", maximum=120)
            rows = gateway.insert("assets", {"organisation_id": organisation_id, "label": label,
                                              "target_type": target_type, "target_value": target_value,
                                              "ownership_basis": ownership_basis})
            send_json(self, 201, {"asset": rows[0] if rows else None})
        except Exception as exc:
            handle_error(self, exc)
