#!/usr/bin/env python3
"""Generate a reproducible role+hash ledger for EVERY tracked vendored file.

The inventory deliberately does not import, execute or trust vendor scripts.
A role is an accounting classification, never production qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDORS = {
    "agentic": "integrations/traceatlas-agentic-skills-library",
    "osint": "integrations/awesome-osint-repos",
}
EXPECTED = {"agentic": 26731, "osint": 39}


def role(vendor: str, parts: tuple[str, ...]) -> str:
    if vendor == "agentic":
        if len(parts) == 3 and parts[0] == "skills" and parts[2] == "SKILL.md":
            return "canonical-skill-reference"
        if parts[0] == "skills":
            if "scripts" in parts or parts[-1].endswith((".py", ".sh", ".js", ".ts")):
                return "unqualified-skill-helper"
            return "skill-attachment-or-reference"
        if parts[0] in ("plugins", ".agents", ".claude-plugin"):
            return "plugin-mirror-not-activated"
        if parts[0] in (".github", "tools", "scripts", "tests", "apps"):
            return "upstream-developer-tooling-disabled"
        if parts[0] in ("docs", "data", ".catalog"):
            return "upstream-docs-and-metadata"
        return "upstream-other-preserved"
    if parts[0] == ".catalog":
        return "osint-catalogue-data-or-tooling"
    if parts[0] == ".github":
        return "upstream-workflows-disabled"
    if parts[0] == "osint-repositories.csv":
        return "osint-provider-metadata-index"
    return "osint-docs-and-tests"


def tracked_files(subpath: str) -> list[str]:
    completed = subprocess.run(["git", "ls-files", "-z", "--", subpath], cwd=ROOT,
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rows = [p.decode("utf-8") for p in completed.stdout.split(b"\0") if p]
    return sorted(rows)


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def audit() -> dict:
    counts: dict[str, int] = {}
    roles: Counter = Counter()
    file_rows = []
    errors = []
    for vendor, prefix in VENDORS.items():
        paths = tracked_files(prefix)
        counts[vendor] = len(paths)
        if len(paths) != EXPECTED[vendor]:
            errors.append(f"{vendor}: expected {EXPECTED[vendor]} tracked files, found {len(paths)}")
        base = (ROOT / prefix).resolve()
        for relative in paths:
            path = ROOT / relative
            sub = Path(relative).relative_to(prefix)
            parts = sub.parts
            category = role(vendor, parts)
            roles[category] += 1
            if not path.is_file() and not path.is_symlink():
                errors.append(relative + ": missing file")
                continue
            if path.is_symlink():
                target = path.resolve()
                if not target.is_relative_to(base) or not target.exists():
                    errors.append(relative + ": broken/escaping symlink")
                digest = hashlib.sha256(os.readlink(path).encode()).hexdigest()
                size = path.lstat().st_size
                category += "-symlink"
            else:
                digest = hash_file(path)
                size = path.stat().st_size
            file_rows.append({"path": relative, "source": vendor, "role": category,
                              "bytes": size, "sha256": digest})
    return {"schema": "traceatlas.vendor-file-ledger.v1",
            "tracked_count": counts, "roles": dict(sorted(roles.items())),
            "total": len(file_rows), "files": file_rows,
            "errors": errors, "source_execution_enabled": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="artifacts/vendor-file-ledger.json")
    args = parser.parse_args()
    result = audit()
    out = ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "files"}, indent=2))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
