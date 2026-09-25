"""Static production-readiness checks; this module never deploys resources."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__


class DeploymentDoctor:
    def __init__(self, root: Path | None = None):
        self.root = (root or Path(__file__).resolve().parents[2]).resolve()

    def run(self, production: bool = False) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        def add(name: str, passed: bool, detail: str, *, required: bool = True) -> None:
            state = "pass" if passed else "fail" if required else "warn"
            checks.append({"name": name, "state": state, "detail": detail})

        required_files = (
            "vercel.json", "public/index.html", "api/health.py", "worker/Dockerfile",
            "supabase/migrations/20260925000100_traceatlas_control_plane.sql",
            "supabase/tests/traceatlas_rls.test.sql",
        )
        for relative in required_files:
            add(f"file:{relative}", (self.root / relative).is_file(), "required deployment artifact")

        dockerfile = self.root / "worker/Dockerfile"
        worker_text = dockerfile.read_text(encoding="utf-8") if dockerfile.is_file() else ""
        add("worker:non-root", bool(re.search(r"(?im)^USER\s+(?!root\b)\S+", worker_text)),
            "worker image must declare a non-root USER")

        url = os.environ.get("SUPABASE_URL", "").strip()
        parsed = urlparse(url) if url else None
        valid_url = bool(parsed and parsed.scheme == "https" and parsed.hostname and
                         parsed.hostname.endswith(".supabase.co"))
        add("env:SUPABASE_URL", valid_url, "approved hosted Supabase HTTPS URL",
            required=production)
        publishable = os.environ.get("SUPABASE_PUBLISHABLE_KEY", "").strip()
        add("env:SUPABASE_PUBLISHABLE_KEY", len(publishable) >= 20 and not any(
            char.isspace() for char in publishable
        ), "publishable browser/server key", required=production)
        if os.environ.get("VERCEL"):
            add("env:no-worker-secret-on-vercel", not bool(os.environ.get("SUPABASE_SECRET_KEY")),
                "SUPABASE_SECRET_KEY must exist only on the isolated worker")

        version_files = {
            "pyproject.toml": self.root / "pyproject.toml",
            "public/index.html": self.root / "public/index.html",
            "README.md": self.root / "README.md",
        }
        for label, path in version_files.items():
            text = path.read_text(encoding="utf-8") if path.is_file() else ""
            add(f"version:{label}", __version__ in text, f"must advertise {__version__}")

        public_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in (self.root / "public").glob("*") if path.is_file()
        )
        add("client:no-service-role", "SUPABASE_SECRET_KEY" not in public_text and
            "service_role" not in public_text, "browser bundle contains no privileged key names")

        failed = [row for row in checks if row["state"] == "fail"]
        warnings = [row for row in checks if row["state"] == "warn"]
        return {
            "version": __version__, "mode": "production" if production else "repository",
            "ready": not failed, "production_ready": production and not failed and not warnings,
            "summary": {"passed": sum(row["state"] == "pass" for row in checks),
                        "warnings": len(warnings), "failed": len(failed)},
            "checks": checks,
            "limitations": [
                "Static checks do not prove a Vercel/Supabase/worker deployment is reachable.",
                "Run hosted tenant-isolation, queue, backup and restore tests before production sign-off.",
            ],
        }
