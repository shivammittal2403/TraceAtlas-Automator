import json
import math
import urllib.parse
from http.server import BaseHTTPRequestHandler
from uuid import uuid4

from vercel_control import (
    ControlPlaneError, authenticated_gateway, handle_error, read_json,
    require_same_origin, require_text, require_uuid, send_json,
)


def _bounded_object(value, field, maximum):
    if not isinstance(value, dict):
        raise ControlPlaneError(400, f"invalid_{field}")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > maximum:
        raise ControlPlaneError(413, f"{field}_too_large")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 8:
            raise ControlPlaneError(400, f"invalid_{field}")
        if isinstance(item, dict):
            if len(item) > 500:
                raise ControlPlaneError(400, f"invalid_{field}")
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 80 or key in {
                    "__proto__", "constructor", "prototype",
                }:
                    raise ControlPlaneError(400, f"invalid_{field}")
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            if len(item) > 2000:
                raise ControlPlaneError(400, f"invalid_{field}")
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ControlPlaneError(400, f"invalid_{field}")
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise ControlPlaneError(400, f"invalid_{field}")
        elif isinstance(item, str) and len(item) > 2000:
            raise ControlPlaneError(400, f"invalid_{field}")
    return value


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            case_id = require_uuid((query.get("case_id") or [""])[0], "case_id")
            gateway, _ = authenticated_gateway(self)
            rows = gateway.select("case_views", {
                "case_id": f"eq.{case_id}",
                "select": "id,case_id,name,layout,filters,revision,created_by,updated_by,created_at,updated_at",
                "order": "updated_at.desc", "limit": "100",
            })
            send_json(self, 200, {"views": rows, "conflict_policy": "expected_revision"})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            gateway, _ = authenticated_gateway(self)
            payload = read_json(self, max_bytes=96 * 1024)
            expected = payload.get("expected_revision")
            if not isinstance(expected, int) or isinstance(expected, bool) or not 0 <= expected <= 1_000_000:
                raise ControlPlaneError(400, "invalid_expected_revision")
            view_id = require_uuid(payload.get("view_id") or str(uuid4()), "view_id")
            result = gateway.rpc("save_case_view", {
                "p_case_id": require_uuid(payload.get("case_id"), "case_id"),
                "p_view_id": view_id,
                "p_name": require_text(payload.get("name"), "view_name", minimum=2, maximum=120),
                "p_layout": _bounded_object(payload.get("layout"), "layout", 64 * 1024),
                "p_filters": _bounded_object(payload.get("filters"), "filters", 16 * 1024),
                "p_expected_revision": expected,
            })
            view = result[0] if isinstance(result, list) and result else result
            send_json(self, 200 if expected else 201, {"view": view})
        except Exception as exc:
            handle_error(self, exc)
