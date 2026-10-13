#!/usr/bin/env python3
"""Minimal repeatable integrity and standalone smoke test (stdlib only)."""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if subprocess.call([sys.executable, str(HERE / "assemble.py"), "--verify"]) != 0:
    raise SystemExit("Source integrity failed")
if subprocess.call([sys.executable, str(HERE / "assemble.py")]) != 0:
    raise SystemExit("Assembly failed")
if subprocess.call([sys.executable, str(HERE / "TraceAtlas_AllInOne_Studio.py"), "--self-test"]) != 0:
    raise SystemExit("Native engine smoke test failed")
print("TraceAtlas Studio integration smoke test PASSED")
