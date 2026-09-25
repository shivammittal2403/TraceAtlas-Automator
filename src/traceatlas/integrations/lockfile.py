from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from ..models import utc_now
from ..policy import PolicyError
from .registry import TOOLS
from .runner import IntegrationRunner


MAX_LOCK_BYTES = 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version(binary: Path) -> str | None:
    try:
        completed = subprocess.run(
            [str(binary), "--version"], capture_output=True, text=True, timeout=5,
            check=False, shell=False,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0][:300] if text else None


class IntegrationLock:
    """Integrity snapshot for explicitly installed external tool binaries."""

    def __init__(self, runner: IntegrationRunner):
        self.runner = runner

    def snapshot(self) -> dict[str, Any]:
        locked: dict[str, Any] = {}
        missing: list[str] = []
        for name, spec in sorted(TOOLS.items()):
            if spec.mode == "blocked":
                continue
            resolved = self.runner.resolve_binary(spec)
            if not resolved:
                missing.append(name)
                continue
            path = Path(resolved).resolve()
            if not path.is_file() or path.is_symlink():
                missing.append(name)
                continue
            stat = path.stat()
            locked[name] = {
                "binary": path.name, "sha256": _sha256(path), "size": stat.st_size,
                "version_output": _version(path),
            }
        return {"schema": 1, "generated_at": utc_now(), "tools": locked,
                "missing": missing, "limitations": [
                    "A hash lock proves binary continuity, not upstream safety or licence compliance.",
                    "Recreate and review this lock only after an intentional tool upgrade.",
                ]}

    def write(self, path: Path) -> dict[str, Any]:
        snapshot = self.snapshot()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"output": str(path), "locked": len(snapshot["tools"]),
                "missing": len(snapshot["missing"])}

    def verify(self, path: Path) -> dict[str, Any]:
        if not path.is_file() or path.stat().st_size > MAX_LOCK_BYTES:
            raise PolicyError("Integration lock must be a regular JSON file up to 1 MiB")
        try:
            lock = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError("Integration lock is invalid JSON") from exc
        if not isinstance(lock, dict) or lock.get("schema") != 1 or not isinstance(lock.get("tools"), dict):
            raise PolicyError("Unsupported integration lock schema")
        checks = []
        for name, expected in sorted(lock["tools"].items()):
            if not isinstance(name, str) or not isinstance(expected, dict) or not isinstance(
                expected.get("sha256"), str
            ):
                raise PolicyError("Integration lock contains an invalid tool record")
            spec = TOOLS.get(name)
            resolved = self.runner.resolve_binary(spec) if spec else None
            if not resolved:
                checks.append({"tool": name, "state": "missing"})
                continue
            path_now = Path(resolved).resolve()
            actual = _sha256(path_now) if path_now.is_file() and not path_now.is_symlink() else None
            checks.append({"tool": name, "state": "pass" if actual == expected.get("sha256") else "changed",
                           "binary": path_now.name})
        installed_now = {
            name for name, spec in TOOLS.items()
            if spec.mode != "blocked" and self.runner.resolve_binary(spec)
        }
        untracked = sorted(installed_now - set(lock["tools"]))
        return {"valid": all(row["state"] == "pass" for row in checks) and not untracked,
                "checks": checks, "untracked_installed": untracked}
