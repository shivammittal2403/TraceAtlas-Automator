#!/usr/bin/env python3
"""Fail CI when common credential formats are committed."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", ".traceatlas", "build", "dist", "cases", "__pycache__"}
PATTERNS = {
    "GitHub token": re.compile(rb"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})"),
    "OpenAI-style key": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Supabase secret key": re.compile(rb"\bsb_secret_[A-Za-z0-9_-]{20,}\b"),
}


def files() -> list[Path]:
    return [path for path in ROOT.rglob("*") if path.is_file()
            and not any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts)]


def main() -> int:
    findings: list[str] = []
    for path in files():
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:4096] or len(data) > 5 * 1024 * 1024:
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(data):
                findings.append(f"{path.relative_to(ROOT)}: possible {name}")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("Secret scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
