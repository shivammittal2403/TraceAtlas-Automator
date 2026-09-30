#!/usr/bin/env python3
"""Build the governed TraceAtlas registry for the pinned OpenCTI connectors."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


CATEGORIES = (
    "external-import",
    "internal-enrichment",
    "internal-export-file",
    "internal-import-file",
    "stream",
)
LICENSE_OVERRIDES = {
    "external-import/alienvault": "AGPL-3.0-only",
    "external-import/crowdstrike": "AGPL-3.0-only",
    "external-import/kaspersky": "AGPL-3.0-only",
    "external-import/portspoof": "MIT",
    "external-import/socprime": "AGPL-3.0-only",
}


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _tree_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(
        candidate for candidate in path.rglob("*")
        if candidate.is_file() and ".git" not in candidate.relative_to(path).parts
    ):
        digest.update(item.relative_to(path).as_posix().encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(item.read_bytes()).digest())
    return digest.hexdigest()


def build(root: Path, archive_sha256: str, upstream_commit: str) -> dict[str, Any]:
    root = root.resolve()
    connectors: list[dict[str, Any]] = []
    for category in CATEGORIES:
        category_root = root / category
        if not category_root.is_dir():
            raise ValueError(f"Missing connector category: {category}")
        for connector in sorted(path for path in category_root.iterdir() if path.is_dir()):
            relative = connector.relative_to(root).as_posix()
            metadata = _json(connector / "__metadata__" / "connector_manifest.json")
            schema = _json(connector / "__metadata__" / "connector_config_schema.json")
            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                properties = {}
            required = schema.get("required", [])
            if not isinstance(required, list):
                required = []
            required_env = sorted(
                str(item) for item in required if isinstance(item, str) and item in properties
            )
            secret_env = sorted(
                str(name)
                for name, details in properties.items()
                if isinstance(name, str)
                and isinstance(details, dict)
                and (details.get("writeOnly") is True or details.get("format") == "password")
            )
            compose = connector / "docker-compose.yml"
            dockerfile = connector / "Dockerfile"
            connectors.append({
                "id": relative,
                "slug": str(metadata.get("slug") or connector.name),
                "title": str(metadata.get("title") or connector.name.replace("-", " ").title()),
                "description": str(
                    metadata.get("short_description")
                    or metadata.get("description")
                    or "OpenCTI connector package"
                )[:2000],
                "category": category,
                "path": f"third_party/opencti-connectors/{relative}",
                "source_code": str(metadata.get("source_code") or ""),
                "container_image": str(metadata.get("container_image") or ""),
                "container_type": str(metadata.get("container_type") or ""),
                "verified_upstream": metadata.get("verified") is True,
                "last_verified_date": metadata.get("last_verified_date"),
                "manager_supported": metadata.get("manager_supported") is True,
                "playbook_supported": metadata.get("playbook_supported") is True,
                "use_cases": metadata.get("use_cases", [])
                if isinstance(metadata.get("use_cases", []), list) else [],
                "solution_categories": metadata.get("solution_categories", [])
                if isinstance(metadata.get("solution_categories", []), list) else [],
                "compose_available": compose.is_file(),
                "dockerfile_available": dockerfile.is_file(),
                "config_schema_available": bool(schema),
                "required_env": required_env,
                "secret_env": secret_env,
                "license": LICENSE_OVERRIDES.get(relative, "Apache-2.0"),
                "source_sha256": _tree_digest(connector),
                "runtime_boundary": "external-opencti-service",
                "execution_enabled": False,
            })

    if len({row["id"] for row in connectors}) != len(connectors):
        raise ValueError("Duplicate OpenCTI connector IDs detected")
    category_counts = dict(sorted(Counter(row["category"] for row in connectors).items()))
    license_counts = dict(sorted(Counter(row["license"] for row in connectors).items()))
    return {
        "schema": "traceatlas-opencti-connectors-1.0",
        "snapshot": {
            "origin": "OpenCTI-Platform/connectors pinned Git source plus supplied archive",
            "upstream_commit": upstream_commit,
            "archive_sha256": archive_sha256,
            "connector_count": len(connectors),
            "category_counts": category_counts,
            "license_counts": license_counts,
            "execution_default": "disabled",
            "integration_model": "catalog, configuration validation, integrity verification, and external-service launch planning",
        },
        "connectors": connectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--upstream-commit", required=True)
    args = parser.parse_args()
    result = build(args.root, args.archive_sha256, args.upstream_commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result["snapshot"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
