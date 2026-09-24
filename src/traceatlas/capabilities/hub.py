from __future__ import annotations

import json
import os
import re
import shutil
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..db import CaseDB
from ..evidence import EvidenceStore
from ..policy import PolicyError
from .registry import CAPABILITIES
from .mcp import MCPClient
from .workflow import ResearchWorkflow
from .service import ServiceClient


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

    @staticmethod
    def _validate_arguments(value: Any, *, depth: int = 0) -> None:
        if depth > 10:
            raise PolicyError("MCP arguments exceed nesting limit")
        if isinstance(value, dict):
            for key, child in value.items():
                if SECRET_KEYS.search(str(key)):
                    raise PolicyError("Credentials and session material cannot be passed in MCP arguments")
                CapabilityHub._validate_arguments(child, depth=depth + 1)
        elif isinstance(value, list):
            if len(value) > 500:
                raise PolicyError("MCP argument arrays are limited to 500 entries")
            for child in value:
                CapabilityHub._validate_arguments(child, depth=depth + 1)
        elif isinstance(value, str):
            if len(value) > 10000:
                raise PolicyError("MCP string argument is too long")
            parsed = urlparse(value)
            host = parsed.hostname if parsed.scheme in {"http", "https"} else value
            try:
                address = ip_address(host)
            except ValueError:
                address = None
            if address and (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved):
                raise PolicyError("Private, loopback, link-local and reserved network targets are blocked")
            if parsed.hostname and parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
                raise PolicyError("Localhost targets are blocked")

    def _mcp_client(self, source: str, timeout: int) -> MCPClient:
        if source not in CAPABILITIES:
            raise PolicyError(f"Unknown capability source: {source}")
        spec = CAPABILITIES[source]
        if spec.protocol != "mcp":
            raise PolicyError(f"{source} is not an MCP server integration")
        binary = self._binary(spec)
        if not binary:
            raise PolicyError(f"{source} is not installed; run capabilities doctor")
        return MCPClient(spec, binary, timeout)

    def mcp_tools(self, source: str, *, authorized: bool, timeout: int = 30) -> list[dict[str, Any]]:
        if not authorized:
            raise PolicyError("MCP discovery requires explicit --authorized confirmation")
        return self._mcp_client(source, timeout).list_tools()

    def mcp_call(self, case_id: str, source: str, tool: str, arguments: dict[str, Any], *,
                 authorized: bool, subject_consent: bool = False, owned_org: bool = False,
                 timeout: int = 30) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("MCP execution requires explicit --authorized confirmation")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        spec = CAPABILITIES.get(source)
        if not spec:
            raise PolicyError(f"Unknown capability source: {source}")
        if "subject-consent" in spec.safety and not (subject_consent or owned_org):
            raise PolicyError("This MCP source requires --subject-consent or --owned-org")
        self._validate_arguments(arguments)
        raw = self._mcp_client(source, timeout).call_tool(tool, arguments)
        normalized = self._sanitize(raw)
        output_dir = self.workspace / "capability-imports" / case_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{source}-{tool}.normalized.json"
        output.write_text(json.dumps({
            "source": source, "tool": tool,
            "classification": "unverified MCP observations; analyst review required",
            "facts": normalized, "inferences": [],
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, f"mcp:{source}:{tool}")
        return {"status": "completed", "source": source, "tool": tool,
                "output": str(output), "sha256": record["sha256"], "review_required": True}

    @staticmethod
    def research_plan(objective: str, scope_type: str, authority: str,
                      subject_consent: bool = False) -> dict[str, Any]:
        return ResearchWorkflow.plan(objective, scope_type, authority, subject_consent=subject_consent)

    def research_brief(self, case_id: str, path: Path, *, authorized: bool) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("Research synthesis requires explicit --authorized confirmation")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        data = self._load(path)
        if isinstance(data, dict):
            data = data.get("records", data.get("facts", [data]))
        if not isinstance(data, list):
            raise PolicyError("Research input must be a JSON/JSONL record list")
        brief = ResearchWorkflow.brief(self._sanitize(data))
        output_dir = self.workspace / "research" / case_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{path.stem}.brief.json"
        output.write_text(json.dumps(brief, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, "research:brief")
        return {**brief, "output": str(output), "sha256": record["sha256"]}

    def service_call(self, case_id: str, source: str, action: str, target: str,
                     options: dict[str, Any], *, authorized: bool,
                     owned_org: bool = False, timeout: int = 60) -> dict[str, Any]:
        if not authorized or not owned_org:
            raise PolicyError("Acquisition service calls require --authorized and --owned-org")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        self._validate_arguments(options)
        if source == "crawl4ai":
            if action != "crawl":
                raise PolicyError("Crawl4AI supports only the bounded crawl action")
            raw = ServiceClient.crawl4ai(target, options, timeout)
        elif source == "firecrawl":
            raw = ServiceClient.firecrawl(action, target, options, timeout)
        else:
            raise PolicyError("Unsupported acquisition service")
        normalized = self._sanitize(raw)
        output_dir = self.workspace / "capability-imports" / case_id
        output_dir.mkdir(parents=True, exist_ok=True)
        output = output_dir / f"{source}-{action}.normalized.json"
        output.write_text(json.dumps({
            "source": source, "action": action, "target": "[HASHED]",
            "target_sha256": __import__("hashlib").sha256(target.encode()).hexdigest(),
            "facts": normalized, "inferences": [], "review_required": True,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, f"service:{source}:{action}")
        return {"status": "completed", "source": source, "action": action,
                "output": str(output), "sha256": record["sha256"], "review_required": True}

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
