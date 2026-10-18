"""Governed, opt-in Malvex bridge. Malware samples are NEVER executed here."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .evidence import EvidenceStore, sha256_file
from .policy import PolicyError

UPSTREAM = "https://github.com/JoasASantos/Malvex"
PINNED_COMMIT = "75d86748c185aea0171b38682ab6a2bf15a5240c"
MAX_FINDINGS_BYTES = 5 * 1024 * 1024
MAX_SAMPLE_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class MalvexBridge:
    """Local CLI integration with no auto-install, no detonation and no shell."""

    def __init__(self, db: Any, workspace: Path, *, binary: str | None = None):
        self.db = db
        self.workspace = Path(workspace)
        self.binary = binary or shutil.which("malvex")

    def inventory(self) -> dict[str, Any]:
        return {
            "tool": "malvex",
            "installed": bool(self.binary),
            "binary": self.binary,
            "source": UPSTREAM,
            "pinned_commit": PINNED_COMMIT,
            "mode": "opt-in; read-only diagnostics, dry-run planning, offline report import",
            "sample_execution_enabled": False,
            "production_qualified": False,
        }

    def _case(self, case_id: str, authorized: bool) -> None:
        if not authorized:
            raise PolicyError("Malvex case operations require explicit --authorized approval")
        if not self.db.get_case(case_id):
            raise PolicyError("Unknown TraceAtlas case: " + case_id)

    @staticmethod
    def _regular_file(path: Path, limit: int) -> Path:
        if path.is_symlink() or not path.is_file():
            raise PolicyError("Expected an existing regular non-symlink input file")
        if path.stat().st_size > limit:
            raise PolicyError("Input file exceeds the configured byte limit")
        return path.resolve(strict=True)

    def _command(self, arguments: list[str], timeout: int) -> str:
        if not self.binary:
            raise PolicyError("Malvex is not installed; initialize the pinned third_party/malvex submodule and build it separately")
        allowed = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "MALVEX_OLLAMA_MODEL")
        env = {key: os.environ[key] for key in allowed if key in os.environ}
        try:
            completed = subprocess.run(
                [self.binary, *arguments],
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PolicyError("Malvex command exceeded its time limit") from exc
        except OSError as exc:
            raise PolicyError("Malvex executable could not be started") from exc
        if completed.returncode != 0:
            raise PolicyError("Malvex returned a non-zero status: " + str(completed.returncode))
        output = completed.stdout
        if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise PolicyError("Malvex output exceeded the response limit")
        return output

    def doctor(self) -> dict[str, Any]:
        info = self.inventory()
        if not self.binary:
            return info
        output = self._command(["doctor", "--json"], timeout=45)
        try:
            info["diagnostics"] = json.loads(output)
        except json.JSONDecodeError:
            info["diagnostics_text"] = output[:4000]
        return info

    def coverage(self, source_root: Path) -> dict[str, Any]:
        root = Path(source_root)
        if not root.is_dir():
            raise PolicyError("Malvex source root not found; initialize the submodule")
        output = self._command(["coverage", "--root", str(root.resolve())], timeout=45)
        return {"mode": "read-only", "coverage_text": output, "pinned_commit": PINNED_COMMIT}

    def plan(self, case_id: str, sample: Path, *, authorized: bool, source_root: Path) -> dict[str, Any]:
        self._case(case_id, authorized)
        input_path = self._regular_file(Path(sample), MAX_SAMPLE_BYTES)
        root = Path(source_root)
        if not root.is_dir():
            raise PolicyError("Malvex source root not found; initialize the submodule")
        # Malvex documents --dry-run as printing a plan without agent/tool execution.
        # Never remove --dry-run or add an automatic execution action to this bridge.
        output = self._command(
            ["run", str(input_path), "--dry-run", "--runtime", "ollama", "--root", str(root.resolve())],
            timeout=60,
        )
        return {
            "case_id": case_id,
            "sample_sha256": sha256_file(input_path),
            "source": "malvex",
            "runtime": "ollama",
            "dry_run": True,
            "executed_sample": False,
            "plan_text": output,
            "warning": "Untrusted source CLI invoked in dry-run mode; validate upstream before use. This is not a sandbox.",
        }

    def import_findings(self, case_id: str, input_file: Path, *, authorized: bool) -> dict[str, Any]:
        self._case(case_id, authorized)
        path = self._regular_file(Path(input_file), MAX_FINDINGS_BYTES)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyError("Malvex findings must be valid UTF-8 JSON") from exc
        raw = data.get("findings") if isinstance(data, dict) else data
        if not isinstance(raw, list) or len(raw) > 500:
            raise PolicyError("Malvex report must contain an array with at most 500 findings")
        candidates = []
        for item in raw:
            if not isinstance(item, dict):
                raise PolicyError("Every Malvex finding must be an object")
            severity = str(item.get("severity", "info")).lower()
            candidates.append({
                "id": str(item.get("id", ""))[:128],
                "title": str(item.get("title", ""))[:512],
                "vuln_class": str(item.get("vuln_class", ""))[:128],
                "severity": severity if severity in ALLOWED_SEVERITIES else "info",
                "upstream_verdict": str(item.get("verdict", "pending"))[:32],
                "traceatlas_status": "unverified_external_candidate",
                "evidence_count": len(item["evidence"]) if isinstance(item.get("evidence"), list) else 0,
            })
        receipt = EvidenceStore(self.workspace, self.db, case_id).preserve_file(
            path, "external:malvex:unverified-findings"
        )
        return {
            "case_id": case_id,
            "source": "malvex",
            "imported_as": "unverified_candidates",
            "candidates": candidates,
            "count": len(candidates),
            "evidence_sha256": receipt["sha256"],
            "review_required": True,
            "automatic_confirmation": False,
            "warning": "External verdicts and model output are not independently verified by TraceAtlas.",
        }


def add_malvex_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser("malvex", help="Governed, opt-in Malvex malware-analysis bridge")
    commands = parser.add_subparsers(dest="malvex_command", required=True)
    commands.add_parser("doctor", help="Read-only local Malvex diagnostics")
    cov = commands.add_parser("coverage", help="Show upstream skills and agent coverage")
    cov.add_argument("--source-root", type=Path, default=Path("third_party/malvex"))
    plan = commands.add_parser("plan", help="Authorized dry-run ONLY: no sample execution")
    plan.add_argument("--case", required=True)
    plan.add_argument("--sample", type=Path, required=True)
    plan.add_argument("--authorized", action="store_true")
    plan.add_argument("--source-root", type=Path, default=Path("third_party/malvex"))
    imp = commands.add_parser("import-findings", help="Preserve JSON findings as unverified external evidence")
    imp.add_argument("--case", required=True)
    imp.add_argument("--file", type=Path, required=True)
    imp.add_argument("--authorized", action="store_true")


def run_malvex(args: Any, engine: Any) -> dict[str, Any]:
    bridge = MalvexBridge(engine.db, engine.workspace)
    if args.malvex_command == "doctor":
        return bridge.doctor()
    if args.malvex_command == "coverage":
        return bridge.coverage(args.source_root)
    if args.malvex_command == "plan":
        return bridge.plan(args.case, args.sample, authorized=args.authorized, source_root=args.source_root)
    if args.malvex_command == "import-findings":
        return bridge.import_findings(args.case, args.file, authorized=args.authorized)
    raise PolicyError("Unsupported Malvex action")
