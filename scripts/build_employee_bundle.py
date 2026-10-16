#!/usr/bin/env python3
"""Build a portable source bundle for all dedicated TraceAtlas employees."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "EMPLOYEES PYTHON.py",
    "EMPLOYEES_README.md",
    "EMPLOYEE_INPUTS.md",
    "scripts/build_employee_bundle.py",
    "tests/test_discipline_bundle.py",
    "examples/employees/all140.json",
    "examples/employees/recipes/DNSINT.json",
)


def _base_builder():
    # Load the adjacent trusted builder, never Python from a supplied source root.
    path = Path(__file__).resolve().with_name("build_osint_bundle.py")
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError("Adjacent build_osint_bundle.py is required")
    spec = importlib.util.spec_from_file_location("_traceatlas_employee_bundle_base", path)
    if spec is None or spec.loader is None:
        raise ValueError("Unable to load the adjacent OSINT bundle builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _employee_paths(root, base):
    included = set(REQUIRED_FILES)
    for relative in REQUIRED_FILES:
        if not base._checked_path(root, relative).is_file():
            raise FileNotFoundError("Required employee source is missing: " + relative)
    examples = base._checked_path(root, "examples/employees")
    tests = base._checked_path(root, "tests")
    if not examples.is_dir() or not tests.is_dir():
        raise FileNotFoundError("Employee examples and tests directories are required")

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
                included.add(relative)
            else:
                raise ValueError("Unsupported employee source entry: " + relative)

    visit(examples)
    for pattern in ("test_discipline*.py", "test_*employees.py"):
        for source in sorted(tests.glob(pattern)):
            relative = source.relative_to(root).as_posix()
            if not base._checked_path(root, relative).is_file():
                raise FileNotFoundError("Employee test source is missing: " + relative)
            included.add(relative)
    return included


def build_bundle(root, output):
    """Preserve source bytes and pinned legacy integrity in an exclusive ZIP."""
    source_root = Path(root)
    if source_root.is_symlink():
        raise ValueError("Source root symlinks are not supported")
    source_root = source_root.resolve(strict=True)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output already exists; choose a new path")
    base = _base_builder()
    additional = _employee_paths(source_root, base)
    base.REQUIRED_FILES = tuple(sorted(set(base.REQUIRED_FILES) | additional))
    return base.build_bundle(source_root, output)


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
