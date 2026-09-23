from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from uuid import uuid4

from .db import CaseDB
from .evidence import EvidenceStore
from .intelligence.sanitize import sanitize_record, sanitize_text
from .policy import PolicyError
from .spider.events import Event, child


UPSTREAM_TOOLS: tuple[str, ...] = (
    "search_email", "search_username", "search_breach", "search_whois",
    "search_ip", "search_domain", "generate_dorks", "search_paste",
    "search_phone", "search_shodan", "search_virustotal", "search_censys",
    "search_ip2location", "search_abuseipdb", "search_github", "search_dns",
    "search_gdelt_geo", "search_dorks_live", "scrape_url", "search_footprint",
)

SAFE_DIRECT_COMMANDS: frozenset[str] = frozenset({
    "email", "username", "shodan", "virustotal", "censys", "github",
    "dns", "abuseipdb", "ip2location", "playbook",
})


class OpenOSINTBridge:
    """Run the preserved upstream package in a separate Python environment.

    The bridge deliberately excludes the upstream interactive shell, public web
    server, proxy commands and anti-bot scraping commands. Results enter the
    TraceAtlas evidence graph only after contact/secret redaction.
    """

    def __init__(self, db: CaseDB, workspace: Path, project_root: Path | None = None):
        self.db = db
        self.workspace = workspace
        self.project_root = project_root or self._discover_root()
        self.package_root = self.project_root / "packages" / "openosint"

    @staticmethod
    def _discover_root() -> Path:
        explicit = os.environ.get("TRACEATLAS_PROJECT_ROOT", "").strip()
        if explicit:
            return Path(explicit).resolve()
        cwd = Path.cwd().resolve()
        if (cwd / "packages" / "openosint").is_dir():
            return cwd
        source_root = Path(__file__).resolve().parents[2]
        return source_root

    def _runtime_candidates(self) -> list[Path]:
        state = self.project_root / ".traceatlas"
        return [
            state / "openosint-venv" / "bin" / "python",
            state / "openosint-venv" / "Scripts" / "python.exe",
            Path(sys.executable),
        ]

    def runtime(self) -> Path | None:
        for candidate in self._runtime_candidates():
            if not candidate.is_file():
                continue
            result = subprocess.run(
                [str(candidate), "-c", "import openosint, mcp, fastapi, requests"],
                cwd=self.package_root if self.package_root.is_dir() else None,
                capture_output=True, text=True, timeout=15, check=False,
                env={**os.environ, "PYTHONPATH": str(self.package_root)},
            )
            if result.returncode == 0:
                return candidate
        return None

    def doctor(self) -> dict[str, Any]:
        version = "unknown"
        pyproject = self.package_root / "pyproject.toml"
        if pyproject.is_file():
            try:
                import tomllib
                version = str(tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"])
            except (KeyError, ValueError):
                pass
        runtime = self.runtime()
        return {
            "bundled": self.package_root.is_dir(),
            "upstream_version": version,
            "upstream_license": "MIT",
            "tools_preserved": len(UPSTREAM_TOOLS),
            "bridge_commands": sorted(SAFE_DIRECT_COMMANDS),
            "runtime_ready": runtime is not None,
            "runtime": str(runtime) if runtime else None,
            "install_hint": (
                None if runtime else "Run ./set.sh; set TRACEATLAS_SKIP_OPENOSINT=1 to skip optional installation."
            ),
            "public_web_exposed": False,
        }

    @staticmethod
    def _command_name(arguments: list[str]) -> str:
        value_options = {
            "--api-key", "--provider", "--ollama-model", "--ollama-host",
            "--openai-base-url", "--openai-model", "--openai-api-key", "--proxy",
        }
        index = 0
        while index < len(arguments):
            token = arguments[index]
            if token in value_options:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            return token
        return ""

    def run(self, case_id: str, arguments: list[str], *, authorized: bool = False,
            subject_consent: bool = False, owned_asset: bool = False,
            timeout: int = 300) -> dict[str, Any]:
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        if not authorized:
            raise PolicyError("OpenOSINT compatibility runs require --authorized")
        if not (subject_consent or owned_asset):
            raise PolicyError("Add --subject-consent or --owned-asset for the requested target")
        if not arguments:
            raise PolicyError("Supply one direct OpenOSINT command after --")
        forbidden_flags = {"--api-key", "--openai-api-key", "--proxy", "--allow-remote"}
        if any(item in forbidden_flags for item in arguments):
            raise PolicyError("Credentials, proxies and remote-server flags must not be passed on the command line")
        command_name = self._command_name(arguments)
        if command_name not in SAFE_DIRECT_COMMANDS:
            raise PolicyError(
                "The bridge permits only: " + ", ".join(sorted(SAFE_DIRECT_COMMANDS))
            )
        runtime = self.runtime()
        if not runtime:
            raise PolicyError("Bundled OpenOSINT runtime is not ready; run ./set.sh")
        effective_timeout = max(1, min(timeout, 900))
        target_fingerprint = hashlib.sha256(
            json.dumps(arguments, separators=(",", ":")).encode()
        ).hexdigest()
        scan_id = str(uuid4())
        seed_value = f"openosint:{command_name}:{target_fingerprint[:16]}"
        self.db.start_spider_scan(scan_id, case_id, "TEXT", seed_value, "compat:openosint")
        seed = Event(
            "TEXT", seed_value, "compat:openosint", scan_id, case_id,
            confidence=100, tags=["redacted-seed", "authorized"],
        )
        self.db.add_spider_event(seed.to_dict())
        env = {**os.environ, "PYTHONPATH": str(self.package_root)}
        command = [str(runtime), "-m", "openosint.cli", "--json", *arguments]
        try:
            completed = subprocess.run(
                command, cwd=self.package_root, env=env, capture_output=True,
                text=True, shell=False, check=False, timeout=effective_timeout,
            )
            stdout = sanitize_text(completed.stdout[:10 * 1024 * 1024], 10 * 1024 * 1024)
            stderr = sanitize_text(completed.stderr[:1024 * 1024], 1024 * 1024)
            try:
                parsed: Any = json.loads(stdout)
            except json.JSONDecodeError:
                parsed = {"text": stdout}
            normalized = {
                "upstream": "OpenOSINT",
                "upstream_version": self.doctor()["upstream_version"],
                "command": command_name,
                "result": sanitize_record(parsed),
                "stderr": stderr,
                "exit_code": completed.returncode,
                "target_fingerprint": target_fingerprint,
            }
            self.db.add_spider_event(child(
                seed, "OPENOSINT_RESULT", normalized, "compat:openosint",
                confidence=65 if completed.returncode == 0 else 35,
                risk="info" if completed.returncode == 0 else "medium",
                tags=["upstream-tool", "analyst-review-required", "redacted"],
            ).to_dict())
            with tempfile.TemporaryDirectory(prefix="traceatlas-openosint-") as temp:
                evidence = Path(temp) / "normalized.json"
                evidence.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
                EvidenceStore(self.workspace, self.db, case_id).preserve_file(
                    evidence, "compat:openosint:normalized"
                )
            status = "completed" if completed.returncode == 0 else "partial"
            stats = {
                "command": command_name, "exit_code": completed.returncode,
                "events": 2, "redacted": True,
            }
            self.db.end_spider_scan(scan_id, status, stats)
            return {"scan_id": scan_id, "status": status, "stats": stats}
        except subprocess.TimeoutExpired:
            stats = {"command": command_name, "timed_out": True, "events": 1}
            self.db.end_spider_scan(scan_id, "failed", stats)
            return {"scan_id": scan_id, "status": "failed", "stats": stats}

