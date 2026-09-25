from http.server import BaseHTTPRequestHandler

from vercel_control import authenticated_gateway, handle_error, read_json, require_same_origin, require_text, send_json


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("organisations", {"select": "id,name,created_at",
                                                     "order": "created_at.desc", "limit": "50"})
            send_json(self, 200, {"organisations": rows})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            gateway, _ = authenticated_gateway(self)
            name = require_text(read_json(self).get("name"), "organisation_name", minimum=2, maximum=120)
            rows = gateway.insert("organisations", {"name": name})
            send_json(self, 201, {"organisation": rows[0] if rows else None})
        except Exception as exc:
            handle_error(self, exc)
