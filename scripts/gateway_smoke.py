#!/usr/bin/env python3
"""Live LOCAL gateway smoke check. No remote requests or target collection.

Only run after deploy/gateway/start-local.sh is serving on this same machine.
Gateway password is read via an interactive terminal and never printed.
"""
from __future__ import annotations

import base64
import getpass
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, ProxyHandler, build_opener

GATEWAY = "http://127.0.0.1:8780"
CONSOLE = "http://127.0.0.1:8765"
opener = build_opener(ProxyHandler({}))


def probe(url: str, *, password: str | None = None):
    headers = {"Accept": "text/html,application/json"}
    if password is not None:
        raw = ("analyst:" + password).encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    request = Request(url, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=4) as response:
            return response.status, response.read(64 * 1024), response.headers
    except HTTPError as error:
        return error.code, error.read(4096), error.headers


def run() -> int:
    results = []
    try:
        for path in ("/", "/hub/", "/employee/", "/gateway/healthz", "/api/health"):
            code, _, _ = probe(GATEWAY + path)
            results.append({"probe": "anonymous" + path, "passed": code == 401,
                            "status": code})
        code, _, _ = probe(CONSOLE + "/api/session")
        results.append({"probe": "direct_console_without_internal_token",
                        "passed": code != 200, "status": code})

        password = getpass.getpass("Local gateway password: ")
        if not password:
            raise ValueError("A password is required")
        code, page, headers = probe(GATEWAY + "/hub/", password=password)
        results.append({"probe": "authenticated_hub",
                        "passed": code == 200 and b"TraceAtlas" in page
                        and headers.get("X-Frame-Options", "").upper() == "DENY",
                        "status": code})
        code, page, _ = probe(GATEWAY + "/employee/", password=password)
        results.append({"probe": "authenticated_employee",
                        "passed": code == 200 and b"TraceAtlas" in page,
                        "status": code})
        code, body, _ = probe(GATEWAY + "/employee/api/session", password=password)
        try:
            csrf = json.loads(body).get("csrf_token")
        except (ValueError, TypeError):
            csrf = None
        results.append({"probe": "authenticated_employee_session",
                        "passed": code == 200 and isinstance(csrf, str) and len(csrf) >= 32,
                        "status": code})
        code, _, _ = probe(GATEWAY + "/api/health", password=password)
        results.append({"probe": "unmounted_cloud_api_fails_explicitly",
                        "passed": code == 503, "status": code})
    except (URLError, OSError, ValueError) as exc:
        results.append({"probe": "gateway_unavailable",
                        "passed": False, "error_type": type(exc).__name__})

    print(json.dumps({"gateway": GATEWAY, "passed": all(x["passed"] for x in results),
                      "checks": results}, indent=2))
    return 0 if all(x["passed"] for x in results) else 1


if __name__ == "__main__":
    sys.exit(run())
