#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 inventory without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def project(path: Path) -> dict:
    data = tomllib.loads(path.read_text(encoding="utf-8"))["project"]
    return {"type": "application" if path == ROOT / "pyproject.toml" else "library",
            "name": data["name"], "version": data["version"],
            "purl": f"pkg:pypi/{data['name'].replace('_', '-')}@{data['version']}",
            "properties": [{"name": "traceatlas:source", "value": str(path.relative_to(ROOT))}]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/sbom.cdx.json"))
    args = parser.parse_args()
    components = [project(ROOT / "pyproject.toml"), project(ROOT / "packages/openosint/pyproject.toml")]
    serial = hashlib.sha256(json.dumps(components, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    payload = {"bomFormat": "CycloneDX", "specVersion": "1.5",
               "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-4{serial[13:16]}-a{serial[17:20]}-{serial[20:32]}",
               "version": 1, "metadata": {"component": components[0]}, "components": components}
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
