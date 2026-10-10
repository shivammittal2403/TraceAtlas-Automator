"""Verify the complete upload mapping, pinned code, and enum references."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "src/traceatlas/addons/intelligence_v1"


def main():
    manifest = json.loads((SUITE / "catalog.json").read_text())
    sources = ROOT / "packages/archive_sources/intelligence-suite"
    errors = []
    expected = manifest["stored_files"]
    if set(expected) != {path.name for path in sources.glob("*.source")} or len(expected) != 136:
        errors.append("Supplied source inventory differs from the manifest")
    for name, digest in expected.items():
        if hashlib.sha256((sources / name).read_bytes()).hexdigest() != digest:
            errors.append("Stored source identity differs: " + name)
    if len(manifest["modules"]) != 135 or len({item["id"] for item in manifest["modules"]}) != 135:
        errors.append("The intelligence catalog must contain 135 distinct supplied modules")
    for name, digest in manifest["support_files_sha256"].items():
        if hashlib.sha256((SUITE / "modules" / (name + ".py")).read_bytes()).hexdigest() != digest:
            errors.append("Support module identity differs: " + name)
    for item in manifest["modules"]:
        path = SUITE / "modules" / (item["id"] + ".py")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["file_sha256"]:
            errors.append("Maintained module identity differs: " + item["id"])
        source = path.read_text()
        compile(source, str(path), "exec")
        tree = ast.parse(source)
        enums = {node.name: {member.targets[0].id for member in node.body
                            if isinstance(member, ast.Assign) and isinstance(member.targets[0], ast.Name)}
                 for node in tree.body if isinstance(node, ast.ClassDef) and any(
                     isinstance(base, ast.Name) and base.id == "Enum" for base in node.bases)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id in enums and node.attr.isupper()
                    and node.attr not in enums[node.value.id]):
                errors.append(f"{item['id']}:{node.lineno}: missing enum {node.value.id}.{node.attr}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Intelligence suite: 136 stored files, 135 pinned modules; mappings, syntax and enum references verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
