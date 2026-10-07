"""Single-user loopback console for the local autonomous investigator."""
from __future__ import annotations

import io
import json
import re
import secrets
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ..engine import Engine
from ..policy import PolicyError
from ..filesystem import path_component
from ..workforce.service import workforce_enabled
from .autonomous import AutonomousInvestigator


def make_server(workspace: Path, port=8765, *, enabled=None):
    enabled = workforce_enabled() if enabled is None else enabled
    if not enabled:
        raise PolicyError("Set TRACEATLAS_WORKFORCE_ENABLED=1 before starting the console")
    token = secrets.token_urlsafe(32)
    jobs_lock = threading.Lock()
    active = set()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Case identifiers, objectives and URLs do not enter HTTP logs.

        def respond(self, status, value, content_type="application/json"):
            raw = json.dumps(value).encode() if content_type == "application/json" else value
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(raw)

        def validate_origin(self):
            expected = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != expected:
                raise PolicyError("Use the displayed 127.0.0.1 console URL")
            origin = self.headers.get("Origin")
            if origin and origin != "http://" + expected:
                raise PolicyError("Cross-origin access rejected")

        def do_GET(self):
            engine = None
            try:
                self.validate_origin()
                url = urlsplit(self.path)
                if url.path == "/":
                    raw = (Path(__file__).parent / "static" / "console.html").read_bytes()
                    return self.respond(200, raw, "text/html; charset=utf-8")
                if url.path == "/api/session":
                    return self.respond(200, {"csrf_token": token})
                if url.path not in {"/api/cases", "/api/investigation"}:
                    return self.respond(404, {"error": "Not found"})
                engine = Engine(workspace)
                if url.path == "/api/cases":
                    cases = [dict(r) for r in engine.db.conn.execute("SELECT id,title,purpose FROM cases ORDER BY created_at DESC LIMIT 100")]
                    return self.respond(200, {"cases": cases})
                query = parse_qs(url.query)
                service = AutonomousInvestigator(engine.db, workspace, enabled=enabled)
                result = service.get(query.get("case", [""])[0], query.get("id", [""])[0])
                return self.respond(200, result)
            except (PolicyError, ValueError, KeyError):
                self.respond(400, {"error": "Invalid request, case or investigation"})
            except Exception:
                self.respond(500, {"error": "Local storage error; inspect the case before retrying"})
            finally:
                if engine:
                    engine.close()

        def do_POST(self):
            engine = None
            try:
                # Consume only a bounded, framed body before rejecting headers.
                # Closing with unread client bytes can discard the 403 response
                # on Windows. Parsing and storage still follow origin/CSRF checks.
                self.connection.settimeout(5)
                lengths = self.headers.get_all('Content-Length', [])
                if self.headers.get('Transfer-Encoding') or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,5}', lengths[0]):
                    raise ValueError('Invalid request framing')
                length = int(lengths[0])
                if not 0 < length <= 16384:
                    raise ValueError('Invalid body size')
                raw_body = self.rfile.read(length)
                if len(raw_body) != length:
                    raise ValueError('Incomplete request body')
                self.validate_origin()
                if not secrets.compare_digest(self.headers.get("X-TraceAtlas-CSRF", ""), token):
                    return self.respond(403, {"error": "Invalid console session"})
                if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise ValueError("JSON required")
                body = json.loads(raw_body)
                if not isinstance(body, dict):
                    raise ValueError("Object required")
                engine = Engine(workspace)
                service = AutonomousInvestigator(engine.db, workspace, enabled=enabled)
                case = path_component(body.get("case_id", ""))
                if self.path == "/api/cases":
                    if not isinstance(case, str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", case):
                        raise ValueError("Invalid case identifier")
                    title, purpose = body.get("title"), body.get("purpose")
                    if not isinstance(title, str) or not 2 <= len(title) <= 160 or not isinstance(purpose, str) or not 10 <= len(purpose) <= 1000:
                        raise ValueError("Case title and lawful purpose are required")
                    engine.db.create_case(case, title, purpose)
                    return self.respond(201, {"case_id": case})
                if self.path in {"/api/investigate", "/api/resume"}:
                    with jobs_lock:
                        if active:
                            return self.respond(409, {"error": "One investigation is already running in this console"})
                        if self.path == "/api/investigate":
                            # HTTP input never supplies a local filesystem seed.
                            # The legacy local CLI retains explicit file/path use.
                            seeds = body.get("seeds")
                            kinds = {k: k for k in ("domain", "ip", "username", "hash", "cve", "doi", "package")}
                            if not isinstance(seeds, list) or not 1 <= len(seeds) <= 8:
                                raise PolicyError("One to eight supported public identifiers are required")
                            normalized = []
                            for seed in seeds:
                                if not isinstance(seed, dict) or seed.get("type") not in kinds:
                                    raise PolicyError("Local filesystem seeds are not accepted by the console")
                                normalized.append({"type": kinds[seed["type"]], "value": seed.get("value")})
                            current = service.create(case, body.get("objective"), normalized,
                                actor=body.get("actor"), authorized=body.get("authorized") is True,
                                attestations=body.get("attestations"), subject_type=body.get("subject_type", "asset"),
                                subject_label=body.get("subject_label", ""), max_actions=body.get("max_actions", 8),
                                runtime_seconds=body.get("runtime_seconds", 120), model=body.get("model") or None,
                                source_fabric=body.get("source_fabric") is True)
                        else:
                            current = service.get(case, body.get("investigation_id", ""))
                            if not body.get("authorized") is True or body.get("actor") != current["manifest"]["actor"]:
                                raise PolicyError("The authorizing analyst is required")
                        identifier = current["id"]
                        active.add(identifier)
                    def run():
                        worker = None
                        try:
                            worker = Engine(workspace)
                            AutonomousInvestigator(worker.db, workspace, enabled=enabled).run(case, identifier,
                                actor=body.get("actor"), authorized=body.get("authorized") is True, resume=True)
                        except Exception as exc:
                            if worker:
                                # Pre-dispatch errors also need a visible, resumable checkpoint.
                                worker.db.conn.execute("UPDATE autonomous_investigations SET status='interrupted' WHERE id=? AND status='ready'", (identifier,))
                                worker.db.conn.commit()
                                AutonomousInvestigator(worker.db, workspace, enabled=enabled)._event(
                                    identifier, "console_worker_stopped", {"error_type": type(exc).__name__})
                        finally:
                            if worker:
                                worker.close()
                            with jobs_lock:
                                active.discard(identifier)
                    threading.Thread(target=run, daemon=True).start()
                    return self.respond(202, {"investigation_id": identifier, "case_id": case})
                if self.path == "/api/cancel":
                    current = service.cancel(case, body.get("investigation_id", ""), actor=body.get("actor"), authorized=body.get("authorized") is True)
                    return self.respond(200, {"cancel_requested": bool(current["cancel_requested"])})
                if self.path == "/api/export":
                    result = service.export(case, body.get("investigation_id", ""), workspace / "reports")
                    folder = Path(result["directory"])
                    output = io.BytesIO()
                    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                        for path in folder.rglob("*"):
                            if path.is_file():
                                archive.write(path, path.relative_to(folder).as_posix())
                    return self.respond(200, output.getvalue(), "application/zip")
                self.respond(404, {"error": "Not found"})
            except (PolicyError, ValueError, KeyError, TypeError) as exc:
                self.respond(400, {"error": str(exc)[:250]})
            except Exception:
                self.respond(500, {"error": "Local operation failed; inspect saved status before retrying"})
            finally:
                if engine:
                    engine.close()

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(workspace, port=8765):
    server = make_server(Path(workspace), port)
    print(f"TraceAtlas local investigation console: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
