"""Pinned Recon-ng marketplace bridge. Catalog != permission to execute.

No marketplace network fetch, no arbitrary module imports, and no credential records.
Only two independently reviewed passive DNS/CT modules are executable, with
explicit case approval through canonical IntegrationRunner.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from ..policy import PolicyError, validate_target

RECON_UPSTREAM_SHA = "32b08fe7b6993ca1f2d8f76ba8f5d23c7f34a11d"
MARKETPLACE_SHA = "9527714d2bb38886422bab5f1c4724d4a20d3057"
RECON_LICENSE = "GPL-3.0"
MAX_MARKETPLACE_MODULES = 500
MAX_WORKSPACE_BYTES = 16 * 1024 * 1024
MAX_ROWS = 2000
HOST_RE = re.compile(r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MODULE_RE = re.compile(r"^recon/[a-z0-9-]+/[a-z0-9_]+$")

# Deliberately narrow runtime allowlist. The remaining 107 upstream modules
# are *available in the pinned source tree* but NOT execution-qualified.
APPROVED_MODULES: dict[str, dict[str, str]] = {
    "recon/domains-hosts/certificate_transparency": {
        "description": "Read certificate-transparency DNS names from crt.sh (third-party API).",
        "target_type": "domain",
    },
    "recon/domains-hosts/hackertarget": {
        "description": "Read DNS host results from HackerTarget public hostsearch API.",
        "target_type": "domain",
    },
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def marketplace_root() -> Path:
    return repo_root() / "third_party" / "recon-ng-marketplace"


def workspace_alias(case_id: str) -> str:
    if not isinstance(case_id, str) or not case_id.strip():
        raise PolicyError("Recon-ng requires a nonempty existing case ID.")
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:20]
    return "ta_" + digest


def validate_module(module: str, target_type: str, target: str) -> str:
    if not isinstance(module, str) or not MODULE_RE.fullmatch(module):
        raise PolicyError("Invalid Recon-ng module path.")
    if module not in APPROVED_MODULES:
        raise PolicyError("Recon-ng module is catalog-only, not execution-qualified.")
    if target_type != APPROVED_MODULES[module]["target_type"]:
        raise PolicyError("Recon-ng module is approved only for its declared target type.")
    validate_target(target_type, target)
    return module


def _safe_module_path(root: Path, module: str) -> Path:
    if not MODULE_RE.fullmatch(module):
        raise ValueError("Unsupported module path.")
    base = (root / "modules").resolve(strict=True)
    source = root / "modules" / (module + ".py")
    if source.is_symlink() or not source.is_file():
        raise FileNotFoundError("Pinned module missing or is a symlink.")
    absolute = source.resolve(strict=True)
    if not absolute.is_relative_to(base):
        raise ValueError("Source escapes pinned marketplace root.")
    if source.stat().st_size > 128 * 1024:
        raise ValueError("Excessively large marketplace module.")
    return absolute


def _metadata(source: Path) -> dict[str, Any]:
    """Read static module descriptions; never import third-party Python code."""
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=source.name)
    except (SyntaxError, UnicodeError):
        return {"description": "", "name": "", "parse_status": "invalid"}
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef) and cls.name == "Module":
            for statement in cls.body:
                if isinstance(statement, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "meta" for t in statement.targets
                ):
                    if isinstance(statement.value, ast.Dict):
                        pairs = {}
                        for key, value in zip(statement.value.keys, statement.value.values):
                            if isinstance(key, ast.Constant) and key.value in {"name", "description", "version"}:
                                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                                    pairs[key.value] = value.value[:500]
                        return {**pairs, "parse_status": "parsed"}
    return {"description": "", "name": "", "parse_status": "unknown"}


def catalog_marketplace(root: Path | None = None) -> list[dict[str, Any]]:
    """Inventory every local marketplace module without importing or executing any."""
    root = marketplace_root() if root is None else Path(root)
    source_dir = root / "modules"
    if not source_dir.is_dir():
        return []
    modules = sorted(source_dir.rglob("*.py"))
    if len(modules) > MAX_MARKETPLACE_MODULES:
        raise ValueError("Marketplace exceeds catalog limit.")
    output = []
    for file in modules:
        if file.is_symlink() or not file.resolve().is_relative_to(source_dir.resolve()):
            continue
        module_id = file.relative_to(source_dir).with_suffix("").as_posix()
        approved = module_id in APPROVED_MODULES
        raw = file.read_bytes()
        info = _metadata(file)
        output.append({
            "module_id": module_id,
            "name": info.get("name", ""),
            "description": info.get("description", ""),
            "parse_status": info.get("parse_status"),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "execution": "approved_passive" if approved else "catalog_only",
            "source": "pinned_recon_ng_marketplace",
            "license": RECON_LICENSE,
            "runtime_tested": False,
        })
    return output


def stage_approved_module(root: Path, isolated_home: Path, module: str) -> Path:
    """Copy exactly one pinned, approved module into a temporary HOME.

    Destination must be the temporary subprocess sandbox chosen by the caller.
    Staging is not a module installation for the developer's real account.
    """
    if module not in APPROVED_MODULES:
        raise PolicyError("Module not approved for runtime.")
    source = _safe_module_path(Path(root), module)
    home = Path(isolated_home)
    if not home.is_dir() or home.is_symlink():
        raise ValueError("Isolated Recon-ng HOME must already exist as a real directory.")
    destination = home / ".recon-ng" / "modules" / (module + ".py")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Isolated module destination already exists.")
    shutil.copyfile(source, destination)
    if hashlib.sha256(destination.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
        raise OSError("Staged Recon-ng module failed SHA-256 integrity check.")
    return destination


def _domain_event(host: Any, scope_domain: str, module: str) -> dict[str, Any] | None:
    if not isinstance(host, str):
        return None
    name = host.strip().rstrip(".").lower()
    root = scope_domain.lower().rstrip(".")
    if not HOST_RE.fullmatch(name) or (name != root and not name.endswith("." + root)):
        return None
    return {"event_type": "DOMAIN", "data": name, "confidence": 65,
            "risk": "info", "tags": ["external-tool", "recon-ng", "workspace-db", module]}


def read_workspace_events(db_path: Path, *, target_type: str, target: str,
                          module: str, max_rows: int = MAX_ROWS) -> dict[str, Any]:
    """Read allowlisted domain/host columns only from a Recon-ng v5 workspace DB.

    Credentials, contacts, pushpins, profiles, vulnerabilities and private notes
    are deliberately NOT ingested. SQLite is read-only/immutable; no SQL from input.
    """
    validate_module(module, target_type, target)
    path = Path(db_path)
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= MAX_WORKSPACE_BYTES:
        raise ValueError("Recon-ng workspace database missing, symbolic or exceeds limit.")
    if not 1 <= max_rows <= MAX_ROWS:
        raise ValueError("Invalid workspace row budget.")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    omitted = 0
    with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True) as db:
        db.execute("PRAGMA query_only = ON")
        tables = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, column in (("domains", "domain"), ("hosts", "host")):
            if table not in tables:
                continue
            fields = {x[1] for x in db.execute(f"PRAGMA table_info({table})")}
            if column not in fields:
                continue
            for row in db.execute(f"SELECT {column} FROM {table} LIMIT ?", (max_rows + 1,)):
                event = _domain_event(row[0], target, module)
                if event is None:
                    omitted += 1
                    continue
                if event["data"] in seen:
                    continue
                seen.add(event["data"])
                if len(events) >= max_rows:
                    omitted += 1
                    continue
                events.append(event)
    receipt = {
        "schema": "traceatlas.recon_ng/sanitized-workspace-v1",
        "origin": "recon-ng-sqlite-workspace",
        "upstream_sha": RECON_UPSTREAM_SHA,
        "marketplace_sha": MARKETPLACE_SHA,
        "module": module,
        "workspace_db_sha256": digest,
        "target": target,
        "source_independence_verified": False,
        "records": events,
        "out_of_scope_or_invalid_dropped": omitted,
        "qualification": "source_reported_not_independently_verified",
    }
    return receipt


def cli(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="TraceAtlas safe offline Recon-ng marketplace inventory")
    parser.add_argument("--marketplace", type=Path, default=marketplace_root())
    parser.add_argument("--module", help="Optional module identifier for info")
    args = parser.parse_args(argv)
    rows = catalog_marketplace(args.marketplace)
    if args.module:
        rows = [x for x in rows if x["module_id"] == args.module]
        if not rows:
            parser.error("Module not present in pinned local marketplace")
    print(json.dumps({"modules": rows, "count": len(rows),
                      "approved_execution": len([x for x in rows if x["execution"] == "approved_passive"])},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
