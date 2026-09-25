from http.server import BaseHTTPRequestHandler

from vercel_control import (
    ControlPlaneError, SupabaseGateway, access_token, authenticated_gateway,
    clear_session_cookie, handle_error, read_json, require_same_origin,
    send_json, session_cookie,
)


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            _, user = authenticated_gateway(self)
            send_json(self, 200, {"authenticated": True,
                                  "user": {"id": user.get("id"), "email": user.get("email")}})
        except Exception as exc:
            handle_error(self, exc)

    def do_POST(self) -> None:
        try:
            require_same_origin(self)
            payload = read_json(self, max_bytes=4096)
            email = str(payload.get("email", "")).strip().lower()
            password = str(payload.get("password", ""))
            if len(email) > 254 or "@" not in email or not 8 <= len(password) <= 1024:
                raise ControlPlaneError(401, "authentication_failed")
            result = SupabaseGateway().login(email, password)
            token = str(result.get("access_token", ""))
            expires = int(result.get("expires_in", 3600))
            user = result.get("user") if isinstance(result.get("user"), dict) else {}
            send_json(self, 200, {"authenticated": True,
                                  "user": {"id": user.get("id"), "email": user.get("email")}},
                      cookies=[session_cookie(token, expires)])
        except Exception as exc:
            handle_error(self, exc)

    def do_DELETE(self) -> None:
        try:
            require_same_origin(self)
            try:
                access_token(self.headers)
            except ControlPlaneError:
                pass
            send_json(self, 200, {"authenticated": False}, cookies=[clear_session_cookie()])
        except Exception as exc:
            handle_error(self, exc)
