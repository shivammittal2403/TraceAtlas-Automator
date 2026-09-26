from http.server import BaseHTTPRequestHandler

from vercel_app_data import VERSION
from vercel_control import configured, send_json


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        send_json(self, 200, {
            "version": VERSION,
            "control_plane": "configured" if configured() else "local_planner_only",
            "cloud_target_types": ["domain", "ip", "url", "hash"],
            "identity_targets_cloud_enabled": False,
            "authentication": "supabase_http_only_session" if configured() else "disabled",
            "privileged_membership_changes": "aal2_required" if configured() else "disabled",
        })

    def do_POST(self) -> None:
        send_json(self, 405, {"error": "method_not_allowed"})
