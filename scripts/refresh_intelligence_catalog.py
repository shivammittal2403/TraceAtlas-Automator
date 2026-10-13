#!/usr/bin/env python3
"""Explicitly refresh reviewed maintained-module hashes; preserve archive provenance.

Usage: python scripts/refresh_intelligence_catalog.py --module orgint --module osint
Then run scripts/verify_intelligence_suite.py and the regression suites.
Runtime loaders and CI never refresh hashes automatically.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src/traceatlas/addons/intelligence_v1"


def refresh(root: Path, module_ids: list[str]) -> list[str]:
    path = root / "catalog.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in catalog["modules"]}
    requested = sorted(set(module_ids))
    unknown = set(requested) - rows.keys()
    if unknown:
        raise ValueError("Unknown module IDs: " + ", ".join(sorted(unknown)))
    updated = []
    for module_id in requested:
        # Only catalog IDs can resolve files; arbitrary paths are rejected.
        if not module_id.isidentifier():
            raise ValueError("Invalid catalog module ID")
        source = root / "modules" / (module_id + ".py")
        content = source.read_bytes()
        compile(content, str(source), "exec")
        digest = hashlib.sha256(content).hexdigest()
        if rows[module_id]["file_sha256"] != digest:
            rows[module_id]["file_sha256"] = digest
            updated.append(module_id)
    if updated:
        path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", action="append", required=True, dest="modules")
    args = parser.parse_args()
    try:
        updated = refresh(ROOT, args.modules)
    except (ValueError, OSError, SyntaxError) as exc:
        parser.exit(1, str(exc) + "\n")
    print("Updated maintained hashes: " + (", ".join(updated) or "none"))


if __name__ == "__main__":
    main()
