from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from ..db import CaseDB
from ..evidence import EvidenceStore
from ..policy import PolicyError
from .registry import CAPABILITIES


MAX_IMPORT_BYTES = 10 * 1024 * 1024
SECRET_KEYS = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|cookie|authorization|credential)", re.I)
PII_KEYS = re.compile(r"(?:home[_-]?address|government[_-]?id|ssn|national[_-]?id)", re.I)


class CapabilityHub:
    """Inventory and evidence bridge; optional engines remain isolated upstream."""

    def __init__(self, db: CaseDB, workspace: Path):
        self.db = db
        self.workspace = workspace

    @staticmethod
    def _binary(spec: Any) -> str | None:
        return next((path for name in spec.binaries if (path := shutil.which(name))), None)

    def inventory(self) -> list[dict[str, Any]]:
        rows = []
        for spec in CAPABILITIES.values():
            binary = self._binary(spec)
            bundled = spec.integration == "bundled"
            rows.append({
                **spec.to_dict(),
                "installed": bundled or binary is not None,
                "binary_path": binary,
                "ready": spec.executable and (bundled or binary is not None or spec.integration in {"workflow", "service"}),
                "credentials": {key: bool(os.environ.get(key)) for key in spec.credential_env},
            })
        return rows

    def doctor(self) -> dict[str, Any]:
        rows = self.inventory()
        return {
            "upstream_engines": len(rows),
            "ready": sum(bool(row["ready"]) for row in rows),
            "installed_adapters": [row["id"] for row in rows if row["installed"]],
            "restricted": {row["id"]: row["restriction"] for row in rows if row["restriction"]},
            "integration_modes": {
                mode: sum(row["integration"] == mode for row in rows)
                for mode in sorted({row["integration"] for row in rows})
            },
            "security_defaults": [
                "authorization required for imports and execution",
                "private/session data and browser-cookie import disabled",
                "secrets and high-risk personal identifiers removed on import",
                "optional engines execute outside the core process",
            ],
        }

    @classmethod
    def _sanitize(cls, value: Any, *, depth: int = 0) -> Any:
        if depth > 12:
            return "[DEPTH_LIMIT]"
        if isinstance(value, dict):
            result = {}
            for raw_key, child in list(value.items())[:500]:
                key = str(raw_key)[:160]
                if SECRET_KEYS.search(key):
                    result[key] = "[REDACTED]"
                elif PII_KEYS.search(key):
                    result[key] = "[REMOVED]"
                else:
                    result[key] = cls._sanitize(child, depth=depth + 1)
            return result
        if isinstance(value, list):
            return [cls._sanitize(item, depth=depth + 1) for item in value[:1000]]
        if isinstance(value, str):
            return value[:10000]
        return value if value is None or isinstance(value, (bool, int, float)) else str(value)[:1000]

    @staticmethod
    def _load(path: Path) -> Any:
        if not path.is_file():
            raise PolicyError("Capability export file does not exist")
        if path.stat().st_size > MAX_IMPORT_BYTES:
            raise PolicyError("Capability export exceeds the 10 MiB import limit")
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            if path.suffix.lower() != ".jsonl":
                return json.loads(text)
        except json.JSONDecodeError:
            pass
        try:
            rows = []
            for number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise PolicyError(f"Invalid JSON/JSONL at line {number}") from exc
            return rows
        except PolicyError:
            raise

    def ingest(self, case_id: str, source: str, path: Path, *, authorized: bool,
               subject_consent: bool = False, owned_org: bool = False) -> dict[str, Any]:
        if source not in CAPABILITIES:
            raise PolicyError(f"Unknown capability source: {source}")
        if not authorized:
            raise PolicyError("Capability ingestion requires explicit --authorized confirmation")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        spec = CAPABILITIES[source]
        if "subject-consent" in spec.safety and not (subject_consent or owned_org):
            raise PolicyError("This source requires --subject-consent or --owned-org")
        normalized = self._sanitize(self._load(path))
        output_dir = self.workspace / "capability-imports" / case_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{source}-{path.stem}.normalized.json"
        output.write_text(json.dumps({
            "source": source,
            "upstream": spec.upstream,
            "classification": "unverified observations; analyst review required",
            "facts": normalized,
            "inferences": [],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, f"capability:{source}")
        return {"status": "ingested", "source": source, "output": str(output),
                "sha256": record["sha256"], "facts_separated_from_inferences": True}
