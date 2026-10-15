#!/usr/bin/env python3
"""Verify and safely unpack the TraceAtlas module-only recovery archive."""
from __future__ import annotations
import argparse
import base64
import binascii
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PART_COUNT = 75
EXPECTED_BYTES = 3564702
EXPECTED_SHA256 = "646d1416f23e9d26ab45026eedf44427e51f05b7fd358290768822fdc11c173d"
EXPECTED_MODULES = 137
VERSION = "traceatlas-module-recovery/v1"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def decode_archive():
    expected = [HERE / "parts" / ("part_%04d.b64" % i) for i in range(1, PART_COUNT + 1)]
    actual = sorted((HERE / "parts").glob("part_*.b64"))
    if actual != expected:
        raise ValueError("missing or unexpected source chunks")
    chunks = []
    for file in expected:
        if file.is_symlink() or file.stat().st_size > 65000:
            raise ValueError("invalid source chunk")
        content = file.read_text(encoding="ascii").strip()
        if not 1 <= len(content) <= 64000 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", content):
            raise ValueError("invalid source encoding")
        chunks.append(content)
    try:
        data = base64.b64decode("".join(chunks), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("source chunks could not be decoded") from exc
    if len(data) != EXPECTED_BYTES or sha256(data) != EXPECTED_SHA256:
        raise ValueError("source archive failed SHA-256 verification")
    return data


def validate(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) != len(set(info.filename for info in infos)):
            raise ValueError("archive contains duplicated names")
        if sum(info.file_size for info in infos) > 32000000:
            raise ValueError("uncompressed size exceeds limit")
        for info in infos:
            name = info.filename
            if (info.is_dir() or info.file_size > 1000000 or
                    not name or name.startswith("/") or "\\" in name or
                    ".." in Path(name).parts):
                raise ValueError("unsafe archive member")
            if not ((name.startswith("modules/") and len(Path(name).parts) == 2
                     and name.endswith(".py")) or name in {
                        "README.md", "TESTING.md", "repair_ledger.json",
                        "functional_repairs_report.json", "INTEGRITY.json"
                     }):
                raise ValueError("unexpected archive content: " + name)
        integrity = json.loads(z.read("INTEGRITY.json"))
        hashes = integrity.get("module_files")
        modules = [info for info in infos if info.filename.startswith("modules/")]
        if not isinstance(hashes, dict) or len(hashes) != EXPECTED_MODULES or len(modules) != EXPECTED_MODULES:
            raise ValueError("module inventory count mismatch")
        for info in modules:
            content = z.read(info.filename)
            filename = Path(info.filename).name
            if sha256(content) != hashes.get(filename):
                raise ValueError("module checksum mismatch: " + filename)
            try:
                compile(content, info.filename, "exec")
            except SyntaxError as exc:
                raise ValueError("module syntax invalid: " + filename) from exc
    return {
        "schema": VERSION, "status": "PASS",
        "recovered_modules": EXPECTED_MODULES - 1, "validator": 1,
        "sha256": EXPECTED_SHA256, "source_sha256": integrity["source_sha256"],
        "redacted_aws_shaped_fixtures": sum(row["aws_shaped_fixture_count"]
            for row in integrity.get("redactions", [])),
        "runtime_certified": False,
        "limitations": ["36 original sections contained incomplete source tails",
                        "136 module entrypoints have not all been functionally verified",
                        "This archive is not connected to production employees"],
    }


def extract(data, out):
    out = out.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("refusing to overwrite nonempty extraction directory")
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            target = out / info.filename
            if not target.resolve().is_relative_to(out):
                raise ValueError("archive path escaped extraction directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(info))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extract", action="store_true")
    parser.add_argument("--output", type=Path, default=HERE / "_extracted")
    args = parser.parse_args()
    try:
        raw = decode_archive()
        report = validate(raw)
        if args.extract:
            extract(raw, args.output)
            report["output"] = str(args.output.resolve())
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, UnicodeError, KeyError) as exc:
        print("Module recovery blocked: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
