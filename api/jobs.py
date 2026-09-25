from http.server import BaseHTTPRequestHandler
import re

from vercel_control import (
    ControlPlaneError, JOB_KINDS, authenticated_gateway, handle_error, read_json,
    require_same_origin, require_text, require_uuid, send_json,
)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("investigation_jobs", {
                "select": "id,case_id,asset_id,kind,status,attempt,worker_id,created_at,started_at,completed_at,result",
                "order": "created_at.desc", "limit": "100",
            })
            send_json(self, 200, {"jobs": rows})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            gateway, _ = authenticated_gateway(self)
            payload = read_json(self)
            if payload.get("authorization_confirmed") is not True:
                raise ControlPlaneError(400, "authorization_confirmation_required")
            kind = str(payload.get("kind", "")).strip().lower()
            if kind not in JOB_KINDS:
                raise ControlPlaneError(400, "unsupported_job_kind")
            idempotency_key = require_text(payload.get("idempotency_key"), "idempotency_key",
                                           minimum=16, maximum=128)
            if not re.fullmatch(r"[A-Za-z0-9._:-]+", idempotency_key):
                raise ControlPlaneError(400, "invalid_idempotency_key")
            result = gateway.rpc("enqueue_investigation_job", {
                "p_case_id": require_uuid(payload.get("case_id"), "case_id"),
                "p_asset_id": require_uuid(payload.get("asset_id"), "asset_id"),
                "p_kind": kind,
                "p_idempotency_key": idempotency_key,
            })
            job = result[0] if isinstance(result, list) and result else result
            send_json(self, 202, {"job": job})
        except Exception as exc:
            handle_error(self, exc)
