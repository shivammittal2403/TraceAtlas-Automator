#!/usr/bin/env python3
"""Reconstruct and verify the maintained TraceAtlas Studio standalone program."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PARTS = HERE / "parts"
EXPECTED_PARTS = 110
EXPECTED_SHA256 = "93883144c84a3c37861f47f69b20171ffabaec51a5217a4cdb5dec9341d88c97"
OUTPUT = HERE / "TraceAtlas_AllInOne_Studio.py"

def pieces():
    paths = sorted(PARTS.glob("part_*.txt"))
    expected = [PARTS / f"part_{i:04d}.txt" for i in range(1, EXPECTED_PARTS + 1)]
    if paths != expected:
        missing = [p.name for p in expected if p not in paths]
        extra = [p.name for p in paths if p not in expected]
        raise RuntimeError(f"Source chunk inventory mismatch: missing={missing}, unexpected={extra}")
    return paths

def checksum():
    digest = hashlib.sha256()
    count = 0
    for path in pieces():
        with path.open("rb") as source:
            for data in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(data)
                count += len(data)
    return digest.hexdigest(), count

def verify():
    actual, size = checksum()
    print(f"TraceAtlas source parts={EXPECTED_PARTS} bytes={size} sha256={actual}")
    if actual != EXPECTED_SHA256:
        raise RuntimeError("SHA256 mismatch: refusing to execute or assemble altered source.")
    print("Source integrity: VERIFIED")
    return actual

def assemble(force=False):
    verify()
    if OUTPUT.exists():
        current = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
        if current == EXPECTED_SHA256:
            print(f"Already assembled: {OUTPUT}")
            return OUTPUT
        if not force:
            raise FileExistsError(f"Existing output differs: {OUTPUT}. Use --force explicitly.")
    fd, name = tempfile.mkstemp(prefix=".traceatlas-", suffix=".py", dir=HERE)
    try:
        with os.fdopen(fd, "wb") as out:
            for path in pieces():
                with path.open("rb") as src:
                    for data in iter(lambda: src.read(1024 * 1024), b""):
                        out.write(data)
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != EXPECTED_SHA256:
            raise RuntimeError("Assembled output SHA256 failed; file not installed.")
        os.replace(name, OUTPUT)
        print(f"Assembled: {OUTPUT}")
        return OUTPUT
    finally:
        if os.path.exists(name):
            os.unlink(name)

def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify and reconstruct TraceAtlas Studio without modifying existing repository code.")
    parser.add_argument("--verify", action="store_true", help="Verify the 110 source chunks; do not create a file.")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing mismatching assembled output.")
    parser.add_argument("--run", action="store_true", help="Run the assembled standalone application.")
    args, child_argv = parser.parse_known_args(argv)
    try:
        if args.verify and not args.run:
            verify()
            return 0
        output = assemble(force=args.force)
        if args.run:
            if child_argv and child_argv[0] == "--":
                child_argv = child_argv[1:]
            return subprocess.call([sys.executable, str(output), *child_argv])
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"TraceAtlas Studio: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
