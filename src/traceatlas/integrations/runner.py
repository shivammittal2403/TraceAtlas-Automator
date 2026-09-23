from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from ..db import CaseDB
from ..evidence import EvidenceStore
from ..policy import PolicyError, validate_target
from ..spider.events import Event, child
from .parsers import in_scope, parse_output
from .registry import PROFILES, TOOLS, ToolSpec


MAX_CAPTURE_BYTES = 10 * 1024 * 1024


class ToolUnavailable(ValueError):
    pass


class IntegrationRunner:
    def __init__(self, db: CaseDB, workspace: Path):
        self.db = db
        self.workspace = workspace

    @staticmethod
    def resolve_binary(spec: ToolSpec) -> str | None:
        for binary in spec.binaries:
            resolved = shutil.which(binary)
            if resolved:
                return resolved
        return None

    def inventory(self) -> list[dict[str, Any]]:
        rows = []
        for spec in TOOLS.values():
            binary = self.resolve_binary(spec)
            rows.append({
                **spec.to_dict(), "installed": binary is not None,
                "binary_path": binary, "executable": spec.mode != "blocked",
                "env_configured": {key: bool(os.environ.get(key)) for key in spec.optional_env},
            })
        return rows

    def build_command(self, spec: ToolSpec, binary: str, target: str, case_id: str,
                      temp_dir: Path, options: dict[str, str]) -> tuple[list[str], Path | None]:
        missing = [key for key in spec.required_options if not options.get(key)]
        if missing:
            raise PolicyError(f"{spec.name} requires option(s): {', '.join(missing)}")
        for key in ("wordlist", "resolvers"):
            if options.get(key) and not Path(options[key]).is_file():
                raise PolicyError(f"{key} file does not exist: {options[key]}")
        if options.get("module"):
            module = options["module"]
            if ".." in module or not re.fullmatch(r"[A-Za-z0-9_./-]+", module):
                raise PolicyError("Recon-ng module name contains unsupported characters")
        output_path = temp_dir / spec.output_file if spec.output_file else None
        values = {
            "binary": binary, "target": target, "case": case_id,
            "output": str(output_path) if output_path else "",
            **options,
        }
        command: list[str] = []
        for token in spec.command:
            try:
                command.append(token.format_map(values))
            except KeyError as exc:
                raise PolicyError(f"Missing tool option: {exc.args[0]}") from exc
        return command, output_path

    def run(self, case_id: str, tool_name: str, target_type: str, target: str, *,
            authorized: bool = False, allow_active: bool = False,
            options: dict[str, str] | None = None, timeout: int | None = None) -> dict[str, Any]:
        if tool_name not in TOOLS:
            raise ValueError(f"Unknown integration: {tool_name}")
        spec = TOOLS[tool_name]
        if spec.mode == "blocked":
            raise PolicyError(f"{tool_name} is blocked: {spec.blocked_reason}")
        if target_type not in spec.target_types:
            raise PolicyError(f"{tool_name} accepts {', '.join(spec.target_types)}; got {target_type}")
        if target_type in {"path", "file"}:
            validate_target(target_type, target)
        else:
            validate_target(target_type, target)
        if spec.mode in {"passive", "active", "identity"} and not authorized:
            raise PolicyError("External network/identity tools require explicit --authorized confirmation")
        if spec.mode == "active" and not allow_active:
            raise PolicyError(f"{tool_name} performs direct probing; add --allow-active after confirming scope")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        binary = self.resolve_binary(spec)
        if not binary:
            raise ToolUnavailable(f"{tool_name} is not installed. {spec.install_hint}")
        scan_id = str(uuid4())
        seed_type = {"ip": "IP_ADDRESS", "email": "EMAIL_ADDRESS", "path": "FILE"}.get(
            target_type, target_type.upper()
        )
        self.db.start_spider_scan(scan_id, case_id, seed_type, target, f"external:{spec.mode}")
        seed = Event(seed_type, target, f"integration:{tool_name}", scan_id, case_id, confidence=100)
        self.db.add_spider_event(seed.to_dict())
        store = EvidenceStore(self.workspace, self.db, case_id)
        if target_type in {"file", "path"} and Path(target).is_file():
            store.preserve_file(Path(target), f"integration-input:{tool_name}")
        effective_timeout = min(max(timeout or spec.timeout, 1), 3600)
        opts = options or {}
        try:
            with tempfile.TemporaryDirectory(prefix=f"traceatlas-{tool_name}-") as tmp:
                temp_dir = Path(tmp)
                command, output_path = self.build_command(spec, binary, target, case_id, temp_dir, opts)
                stdin = target + "\n" if spec.stdin_target else None
                try:
                    completed = subprocess.run(
                        command, input=stdin, text=True, capture_output=True,
                        timeout=effective_timeout, check=False, shell=False,
                        env=os.environ.copy(), cwd=temp_dir,
                    )
                    timed_out = False
                except subprocess.TimeoutExpired as exc:
                    completed = None
                    timed_out = True
                    stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
                    stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
                else:
                    stdout, stderr = completed.stdout or "", completed.stderr or ""
                stdout = stdout[:MAX_CAPTURE_BYTES]
                stderr = stderr[:MAX_CAPTURE_BYTES]
                stdout_path = temp_dir / "stdout.txt"
                stderr_path = temp_dir / "stderr.txt"
                stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
                stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
                raw = stdout
                if output_path and output_path.is_file():
                    raw = output_path.read_text(encoding="utf-8", errors="replace")[:MAX_CAPTURE_BYTES]
                parsed = parse_output(spec, raw)
                scoped = [event for event in parsed if in_scope(event, target_type, target)]
                if spec.emitted_type == "SECRET_CANDIDATE":
                    # Scanner output can contain live credentials. Preserve only the
                    # normalized, redacted representation; values are represented by hashes.
                    redacted_path = temp_dir / "redacted-findings.json"
                    redacted_path.write_text(json.dumps(scoped, indent=2), encoding="utf-8")
                    store.preserve_file(redacted_path, f"integration-output:{tool_name}:redacted")
                else:
                    if stdout:
                        store.preserve_file(stdout_path, f"integration-output:{tool_name}:stdout")
                    if stderr:
                        store.preserve_file(stderr_path, f"integration-output:{tool_name}:stderr")
                    if output_path and output_path.is_file():
                        store.preserve_file(output_path, f"integration-output:{tool_name}:file")
                for item in scoped:
                    event = child(
                        seed, item["event_type"], item["data"], f"external:{tool_name}",
                        confidence=item.get("confidence", 70), risk=item.get("risk", "info"),
                        tags=item.get("tags", []),
                    )
                    self.db.add_spider_event(event.to_dict())
                exit_code = None if completed is None else completed.returncode
                status = "failed" if timed_out else "completed" if exit_code == 0 else "partial"
                stats = {
                    "tool": tool_name, "mode": spec.mode, "events": len(scoped) + 1,
                    "parsed": len(parsed), "out_of_scope_dropped": len(parsed) - len(scoped),
                    "exit_code": exit_code, "timed_out": timed_out,
                    "stdout_bytes": len(stdout.encode()), "stderr_bytes": len(stderr.encode()),
                    "command": [Path(command[0]).name, *command[1:]],
                }
                self.db.end_spider_scan(scan_id, status, stats)
                return {"scan_id": scan_id, "status": status, "stats": stats}
        except Exception:
            self.db.end_spider_scan(scan_id, "failed", {"tool": tool_name, "events": 1})
            raise

    def run_profile(self, case_id: str, profile: str, target_type: str, target: str, *,
                    authorized: bool = False, allow_active: bool = False,
                    options: dict[str, str] | None = None) -> dict[str, Any]:
        if profile not in PROFILES:
            raise ValueError(f"Unknown integration profile: {profile}")
        results, skipped = [], []
        for tool_name in PROFILES[profile]:
            spec = TOOLS[tool_name]
            if target_type not in spec.target_types:
                skipped.append({"tool": tool_name, "reason": "incompatible target type"})
                continue
            if not self.resolve_binary(spec):
                skipped.append({"tool": tool_name, "reason": "not installed"})
                continue
            try:
                results.append(self.run(
                    case_id, tool_name, target_type, target, authorized=authorized,
                    allow_active=allow_active, options=options,
                ))
            except (PolicyError, ValueError) as exc:
                skipped.append({"tool": tool_name, "reason": str(exc)})
        return {"profile": profile, "completed": len(results), "results": results, "skipped": skipped}

    def run_domain_pipeline(self, case_id: str, domain: str, *, authorized: bool,
                            verify: bool = False, allow_active: bool = False,
                            max_assets: int = 25) -> dict[str, Any]:
        validate_target("domain", domain)
        if not authorized:
            raise PolicyError("The domain pipeline requires explicit --authorized confirmation")
        if verify and not allow_active:
            raise PolicyError("Verification performs direct probes; add --allow-active")
        max_assets = max(1, min(max_assets, 100))
        discovery = self.run_profile(
            case_id, "passive-domain", "domain", domain,
            authorized=True, allow_active=False,
        )
        assets = {domain.lower()}
        for result in discovery["results"]:
            for event in self.db.spider_events(result["scan_id"]):
                if event["event_type"] != "DOMAIN":
                    continue
                value = str(event["data"]).lower().rstrip(".")
                if value == domain.lower() or value.endswith("." + domain.lower()):
                    assets.add(value)
        selected_assets = sorted(assets)[:max_assets]
        validation: list[dict[str, Any]] = []
        validation_skipped: list[dict[str, str]] = []
        if verify:
            for asset in selected_assets:
                for tool_name in PROFILES["surface-validation"]:
                    spec = TOOLS[tool_name]
                    if "domain" not in spec.target_types:
                        continue
                    if not self.resolve_binary(spec):
                        if not any(row["tool"] == tool_name for row in validation_skipped):
                            validation_skipped.append({"tool": tool_name, "reason": "not installed"})
                        continue
                    validation.append(self.run(
                        case_id, tool_name, "domain", asset, authorized=True,
                        allow_active=True,
                    ))
        return {
            "root_domain": domain, "discovery": discovery,
            "assets_discovered": len(assets), "assets_selected": selected_assets,
            "asset_limit_reached": len(assets) > max_assets,
            "verification_enabled": verify, "validation_runs": validation,
            "validation_skipped": validation_skipped,
        }
