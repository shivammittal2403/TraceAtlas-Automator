"""Governed inventory of 45 upstream reconnaissance projects and services.

This module never imports third-party sources or executes scanners.
Source pinning, adapter availability, and live qualification are distinct.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

CATALOG_FILE = Path(__file__).resolve().parents[3] / "docs" / "integrations" / "EXTREME_RECON_CATALOG.json"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
KINDS = {"github_gitlink", "existing_vendor", "external_git_unpinned", "external_service"}

def catalog() -> list[dict[str, Any]]:
    obj = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    if obj.get("schema") != "traceatlas.extreme_recon/source-catalog-v1":
        raise ValueError("Unknown source catalog schema")
    rows = obj.get("entries")
    if not isinstance(rows, list) or len(rows) != 45 or obj.get("total") != 45:
        raise ValueError("The audited list must include exactly 45 items")
    ids: set[str] = set()
    paths: set[str] = set()
    counts: dict[str, int] = {}
    for item in rows:
        ident = item.get("id")
        kind = item.get("source_kind")
        if not isinstance(ident, str) or not SAFE_ID.fullmatch(ident) or ident in ids:
            raise ValueError("Duplicate or invalid catalog ID")
        ids.add(ident)
        if kind not in KINDS:
            raise ValueError("Unsupported catalog source kind")
        counts[kind] = counts.get(kind, 0) + 1
        sha, path = item.get("pinned_commit"), item.get("source_path")
        if kind in {"github_gitlink", "existing_vendor"}:
            if not isinstance(path, str) or not path.startswith("third_party/"):
                raise ValueError("Unsafe or missing gitlink path")
            if ".." in Path(path).parts or path in paths or not COMMIT.fullmatch(str(sha)):
                raise ValueError("Unsafe pin, path reuse or missing full commit")
            paths.add(path)
        elif path is not None or sha is not None:
            raise ValueError("Unpinned service must not claim tracked source")
        if item.get("automatic_execution") is not False or item.get("live_verified") is not False:
            raise ValueError("Catalog must never confer authority or claim live verification")
    if counts != {"github_gitlink":33, "existing_vendor":1,
                  "external_git_unpinned":1, "external_service":10}:
        raise ValueError("Unexpected audited source distribution")
    return [dict(x) for x in rows]

def inventory(*, query: str = "", kind: str | None = None) -> list[dict[str, Any]]:
    from .registry import TOOLS
    needle = query.casefold().strip()
    results: list[dict[str, Any]] = []
    for item in catalog():
        if kind is not None and item["source_kind"] != kind:
            continue
        if needle and needle not in (item["id"]+" "+item["name"]+" "+item["url"]).casefold():
            continue
        spec = TOOLS.get(item["id"])
        if spec is None:
            execution = "catalog_only"
        elif spec.mode == "blocked":
            execution = "blocked"
        else:
            execution = "existing_governed_adapter"
        results.append({**item,
                        "execution_status": execution,
                        "source_qualification": "commit_pinned" if item["pinned_commit"] else "not_pinned",
                        "runtime_tested_by_this_change": False})
    return results

def summary() -> dict[str, Any]:
    rows = inventory()
    return {
        "total": len(rows),
        "pinned_sources": sum(x["pinned_commit"] is not None for x in rows),
        "new_github_source_links": sum(x["source_kind"] == "github_gitlink" for x in rows),
        "existing_governed_adapters": sum(x["execution_status"] == "existing_governed_adapter" for x in rows),
        "live_verified_new_providers": 0,
        "unreviewed_execution_enabled": 0,
        "note": "Source catalog is not installation, network authorization or production validation.",
    }

def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="45-source reconnaissance catalog (read-only)")
    parser.add_argument("--query", default="")
    parser.add_argument("--kind", choices=sorted(KINDS))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    items = inventory(query=args.query, kind=args.kind)
    if args.json:
        print(json.dumps({"summary": summary(), "entries": items}, indent=2))
    else:
        for item in items:
            print(f'{item["id"]:18} {item["source_kind"]:23} {item["execution_status"]:26} {item["risk"]}')
        print(f"{len(items)} matching entries of 45 audited sources")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
