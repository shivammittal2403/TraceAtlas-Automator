"""Governed bridge for the pinned OpenCTI connector ecosystem.

The connector source is pinned as a Git submodule under ``third_party`` and remains an
external-service integration. TraceAtlas never imports or silently executes a
connector package in its own process.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

from .policy import PolicyError


MAX_RESULTS = 1000


class OpenCTIConnectorCatalog:
    def __init__(self, registry: dict[str, Any] | None = None):
        self.registry = registry or self._load_registry()
        rows = self.registry.get("connectors", [])
        if not isinstance(rows, list):
            raise ValueError("OpenCTI connector registry is malformed")
        self._rows = [dict(row) for row in rows if isinstance(row, dict)]
        self._by_id = {str(row["id"]): row for row in self._rows}
        if len(self._by_id) != len(self._rows):
            raise ValueError("OpenCTI connector registry contains duplicate IDs")

    @staticmethod
    def _load_registry() -> dict[str, Any]:
        text = resources.files("traceatlas.data").joinpath("opencti_connectors.json").read_text(
            encoding="utf-8"
        )
        value = json.loads(text)
        if not isinstance(value, dict):
            raise ValueError("OpenCTI connector registry must be a JSON object")
        return value

    @property
    def snapshot(self) -> dict[str, Any]:
        return dict(self.registry.get("snapshot", {}))

    def list(
        self, query: str = "", category: str = "", *, verified_only: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= MAX_RESULTS:
            raise PolicyError(f"Connector result limit must be between 1 and {MAX_RESULTS}")
        query = query.strip().lower()
        category = category.strip().lower()
        rows = []
        for row in self._rows:
            if category and row.get("category") != category:
                continue
            if verified_only and row.get("verified_upstream") is not True:
                continue
            haystack = " ".join(
                str(row.get(key, "")) for key in ("id", "title", "description", "container_image")
            ).lower()
            if query and query not in haystack:
                continue
            rows.append(dict(row))
            if len(rows) >= limit:
                break
        return rows

    def get(self, connector_id: str) -> dict[str, Any]:
        try:
            return dict(self._by_id[connector_id.strip()])
        except KeyError as exc:
            raise PolicyError(f"Unknown OpenCTI connector: {connector_id}") from exc

    def doctor(self, vendor_root: Path) -> dict[str, Any]:
        root = vendor_root.resolve()
        present = root.is_dir()
        compose_present = 0
        source_present = 0
        if present:
            for row in self._rows:
                connector = root / PurePosixPath(str(row["id"]))
                source_present += connector.is_dir()
                compose_present += (connector / "docker-compose.yml").is_file()
        return {
            "schema": self.registry.get("schema"),
            "catalogued_connectors": len(self._rows),
            "category_counts": self.snapshot.get("category_counts", {}),
            "license_counts": self.snapshot.get("license_counts", {}),
            "vendor_source_present": present,
            "vendor_packages_present": source_present,
            "compose_files_present": compose_present,
            "docker_available": shutil.which("docker") is not None,
            "opencti_url_configured": bool(os.environ.get("OPENCTI_URL")),
            "opencti_token_configured": bool(os.environ.get("OPENCTI_TOKEN")),
            "execution_gate_enabled": os.environ.get("TRACEATLAS_OPENCTI_CONNECTORS_ENABLED") == "1",
            "execution_default": "disabled",
            "live_verified_by_traceatlas": 0,
            "limitations": [
                "Catalogued packages are not live-verified TraceAtlas connectors.",
                "Each connector requires an external OpenCTI deployment and its provider credentials.",
                "Upstream verified flags are metadata claims and not TraceAtlas execution evidence.",
            ],
        }

    def plan(
        self, connector_id: str, vendor_root: Path, *, authorized: bool, owned_org: bool,
    ) -> dict[str, Any]:
        if not authorized or not owned_org:
            raise PolicyError("Connector planning requires --authorized and --owned-org")
        row = self.get(connector_id)
        root = vendor_root.resolve()
        connector = (root / PurePosixPath(str(row["id"]))).resolve()
        if root not in connector.parents or not connector.is_dir():
            raise PolicyError("Pinned connector source is missing or outside the approved root")
        compose = connector / "docker-compose.yml"
        required = [str(name) for name in row.get("required_env", [])]
        # Test presence without reading credential values into this process. The
        # resulting plan contains environment-variable names only.
        configured = sorted(name for name in required if name in os.environ)
        missing = sorted(set(required) - set(configured))
        docker = shutil.which("docker")
        gate = os.environ.get("TRACEATLAS_OPENCTI_CONNECTORS_ENABLED") == "1"
        ready = bool(compose.is_file() and docker and not missing and gate)
        return {
            "connector": row["id"],
            "title": row["title"],
            "runtime_boundary": row["runtime_boundary"],
            "license": row["license"],
            "compose_file": str(compose),
            "compose_available": compose.is_file(),
            "required_env": required,
            "secret_env": row.get("secret_env", []),
            "configured_env_names": configured,
            "missing_env_names": missing,
            "docker_available": bool(docker),
            "execution_gate_enabled": gate,
            "launch_ready": ready,
            "validation_command": ["docker", "compose", "-f", str(compose), "config"],
            "launch_command": ["docker", "compose", "-f", str(compose), "up", "-d"],
            "executed": False,
            "next_action": (
                "Review license and provider terms, configure missing environment variables, "
                "validate the Compose model, then run in an isolated worker environment."
            ),
        }

    @staticmethod
    def verify(vendor_root: Path, sums_file: Path) -> dict[str, Any]:
        root = vendor_root.resolve()
        if not root.is_dir() or not sums_file.is_file():
            raise PolicyError("Pinned source or checksum manifest is missing")
        checked = 0
        failures: list[dict[str, str]] = []
        expected_paths: set[str] = set()
        for line in sums_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                expected, relative = line.split("  ", 1)
            except ValueError as exc:
                raise PolicyError("Checksum manifest is malformed") from exc
            if not re.fullmatch(r"[a-f0-9]{64}", expected) or relative in expected_paths:
                raise PolicyError("Checksum manifest contains an invalid digest or duplicate path")
            expected_paths.add(relative)
            rel = PurePosixPath(relative)
            if rel.is_absolute() or ".." in rel.parts:
                raise PolicyError("Checksum manifest contains an unsafe path")
            path = (root / rel).resolve()
            if root not in path.parents:
                raise PolicyError("Checksum path escapes the vendor root")
            checked += 1
            if not path.is_file():
                failures.append({"path": relative, "error": "missing"})
                continue
            observed = hashlib.sha256(path.read_bytes()).hexdigest()
            if observed != expected:
                failures.append({"path": relative, "error": "digest-mismatch"})
        actual_paths = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(root).parts
        }
        for relative in sorted(actual_paths - expected_paths):
            failures.append({"path": relative, "error": "unexpected-file"})
        return {"valid": not failures, "checked_files": checked, "failures": failures[:100]}
