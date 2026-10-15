#!/usr/bin/env python3
"""Create a portable, source-complete OSINT bundle with pinned module bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = ("OSINT PYTHON.py", "OSINT_README.md", "README.md", "LICENSE",
                  "pyproject.toml", "examples/osint140/academic.json",
                  "scripts/build_osint_bundle.py", "tests/test_osint_bundle.py",
                  "tests/test_osint_cli.py", "tests/test_osint_taxonomy.py",
                  "tests/test_academic_input_integrity.py", "tests/test_intelligence_portability.py",
                  "tests/intelligence/fixture_inputs.py", "tests/intelligence/test_contracts.py")
CATALOG = "src/traceatlas/addons/intelligence_v1/catalog.json"
MODULES = "src/traceatlas/addons/intelligence_v1/modules/"


def _checked_path(root, relative):
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Source symlinks are not supported: " + relative)
    return current


def _sources(root):
    files = {}
    for relative in REQUIRED_FILES:
        source = _checked_path(root, relative)
        if not source.is_file():
            raise FileNotFoundError("Required source is missing: " + relative)
        files[relative] = source
    package = _checked_path(root, "src/traceatlas")
    if not package.is_dir():
        raise FileNotFoundError("Required source package src/traceatlas is missing")

    def visit(directory):
        for source in sorted(directory.iterdir()):
            relative = source.relative_to(root).as_posix()
            if source.is_symlink():
                raise ValueError("Source symlinks are not supported: " + relative)
            if source.name == "__pycache__" or source.suffix.lower() in {".pyc", ".pyo"}:
                continue
            if source.is_dir():
                visit(source)
            elif source.is_file():
                files[relative] = source
            else:
                raise ValueError("Unsupported source entry: " + relative)

    visit(package)
    if CATALOG not in files:
        raise FileNotFoundError("Pinned intelligence catalog is missing")
    return files


def _pins(files):
    raw = files[CATALOG].read_bytes()
    try:
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise ValueError("Pinned intelligence catalog must be an object")
        rows = manifest["modules"]
        support = manifest["support_files_sha256"]
        if (not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
                or not isinstance(support, dict)):
            raise ValueError("Pinned intelligence catalog collections are malformed")
        identities = [(row["id"], row["file_sha256"]) for row in rows]
        if not identities or len(identities) != len({name for name, _ in identities}):
            raise ValueError("Pinned catalog module inventory is invalid")
        identities.extend(support.items())
        expected = {}
        for name, digest in identities:
            if not isinstance(name, str) or not name.isidentifier():
                raise ValueError("Pinned catalog contains an invalid source ID")
            relative = MODULES + name + ".py"
            if relative not in files:
                raise FileNotFoundError("Pinned source is missing: " + relative)
            if relative in expected and expected[relative] != digest:
                raise ValueError("Pinned catalog contains conflicting source identities")
            expected[relative] = digest
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("Pinned intelligence catalog is malformed") from exc
    return raw, expected


def build_bundle(root, output):
    root, output = Path(root).resolve(), Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output already exists; choose a new path")
    files = _sources(root)
    catalog_bytes, expected = _pins(files)
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b") as spool:
        with zipfile.ZipFile(spool, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for relative, source in sorted(files.items()):
                if source.is_symlink():
                    raise ValueError("Source symlinks are not supported: " + relative)
                content = catalog_bytes if relative == CATALOG else source.read_bytes()
                if relative in expected and hashlib.sha256(content).hexdigest() != expected[relative]:
                    raise ValueError("Pinned source differs from its catalog: " + relative)
                entry = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
        spool.seek(0)
        output.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        with output.open("xb") as destination:
            while True:
                chunk = spool.read(1024 * 1024)
                if not chunk:
                    break
                destination.write(chunk)
                digest.update(chunk)
    return {"status": "CREATED", "path": str(output.resolve()),
            "sha256": digest.hexdigest(), "file_count": len(files)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build_bundle(ROOT, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
