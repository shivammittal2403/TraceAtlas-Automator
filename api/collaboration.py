import urllib.parse
from http.server import BaseHTTPRequestHandler

from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, require_uuid, send_json,
)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            try:
                after = int((query.get("after") or ["0"])[0])
                limit = int((query.get("limit") or ["200"])[0])
            except ValueError as exc:
                raise ControlPlaneError(400, "invalid_collaboration_cursor") from exc
            if after < 0 or not 1 <= limit <= 500:
                raise ControlPlaneError(400, "invalid_collaboration_cursor")
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("collaboration_events", {
                "case_id": f"eq.{case_id}", "sequence": f"gt.{after}",
                "select": "sequence,case_id,actor_id,object_type,object_id,operation,base_revision,resulting_revision,created_at",
                "order": "sequence.asc", "limit": str(limit),
            })
            cursor = rows[-1]["sequence"] if rows else after
            send_json(self, 200, {
                "events": rows, "next_cursor": cursor,
                "transport": "supabase_realtime_or_bounded_poll",
            })
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        send_json(self, 405, {"error": "method_not_allowed"})
