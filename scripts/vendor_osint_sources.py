#!/usr/bin/env python3
"""Vendor pinned third-party source as *real tracked files*, never execute it.

This is a one-shot export of upstream Git submodules, to make their code
navigable in this repository without requiring submodule support in the UI.
No code is imported into the first-party runtime and licenses are preserved.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "vendor_sources"
SOURCES = {
    "theHarvester": ("third_party/theHarvester", "49a38f8d33c32336bbf6a111ea723ea223116265"),
    "OSINT-SPY": ("third_party/OSINT-SPY", "03dcf4868f7a63a2d863996c4bbc62db1c60bc82"),
    "Mr.Holmes": ("third_party/Mr.Holmes", "028bffba615c8b95db4cf1babe1b0e5925237eb4"),
}
# Binary executable payloads are unnecessary for source review, and should not
# become trusted artifacts simply by being stored in a Git repository.
BLOCK_EXT = {".exe", ".dll", ".so", ".dylib", ".pyd", ".pyc", ".class"}
MAX_FILE_SIZE = 5 * 1024 * 1024
SECRET_PATTERNS = (
    re.compile(rb"ghp_[A-Za-z0-9]{36}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bsb_secret_[A-Za-z0-9_-]{20,}\b"),
)


def cmd(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        list(args), cwd=cwd, check=True, capture_output=True, text=True, timeout=45
    )
    return result.stdout.strip()


def main() -> None:
    DEST.mkdir(exist_ok=True)
    summary = {
        "schema": "traceatlas.vendor_sources/v1",
        "generated_from": "pinned verified upstream Git commits",
        "non_executable": True,
        "license_separation": "third-party LICENSE files govern these copies",
        "projects": {},
    }
    checksum_lines = []
    total = 0
    for label, (relative, pinned) in SOURCES.items():
        src = ROOT / relative
        if not src.is_dir():
            raise SystemExit(f"Missing submodule: {relative}; run git submodule update --init")
        actual = cmd("git", "rev-parse", "HEAD", cwd=src)
        if actual != pinned:
            raise SystemExit(f"Pinned SHA mismatch for {relative}: {actual}")
        records = subprocess.run(
            ["git", "ls-files", "-z", "--cached"],
            cwd=src, check=True, capture_output=True, timeout=45,
        ).stdout.split(b"\x00")
        dest = DEST / label
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        kept = 0
        excluded = []
        for encoded in records:
            if not encoded:
                continue
            rel = Path(encoded.decode("utf-8", errors="strict"))
            if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                raise SystemExit("Invalid upstream Git path")
            origin = src / rel
            if origin.is_symlink() or not origin.is_file():
                excluded.append({"path": rel.as_posix(), "reason": "symlink-or-nonfile"})
                continue
            if rel.suffix.lower() in BLOCK_EXT:
                excluded.append({"path": rel.as_posix(), "reason": "executable-binary"})
                continue
            if origin.stat().st_size > MAX_FILE_SIZE:
                excluded.append({"path": rel.as_posix(), "reason": "large-asset"})
                continue
            content = origin.read_bytes()
            if any(p.search(content) for p in SECRET_PATTERNS):
                excluded.append({"path": rel.as_posix(), "reason": "credential-pattern"})
                continue
            dst = dest / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            checksum_lines.append(f"{digest}  {label}/{rel.as_posix()}")
            kept += 1
        total += kept
        summary["projects"][label] = {
            "original_upstream_repo": relative,
            "pinned_commit": pinned,
            "files_copied": kept,
            "files_excluded": excluded,
            "status": "vendored-for-source-review-not-runtime-qualified",
        }
    summary["total_files_copied"] = total
    if total < 250:
        raise SystemExit("Unexpectedly small third-party source export")
    (DEST / "MANIFEST.json").write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    (DEST / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    (DEST / "README.md").write_text(
        "# Readable vendor source snapshots\n\n"
        "These are **actual Git-tracked files**, not submodule pointers. "
        "They were copied byte-for-byte from the three pinned upstream source "
        "repositories, with explicit exclusions documented in MANIFEST.json. "
        "Git submodules under third_party/ remain the authoritative upstream references.\n\n"
        "Each source tree retains its original LICENSE and authorship. "
        "Do not import or execute unreviewed third-party scripts inside TraceAtlas. "
        "OSINT-SPY and Mr.Holmes executable integrations remain blocked; "
        "theHarvester requires a separately maintained Python environment. "
        "See docs/integrations/THREE_OSINT_FRAMEWORKS.md.\n",
        encoding="utf-8",
    )
    print(json.dumps({k: {"files": v["files_copied"], "excluded": len(v["files_excluded"])}
                      for k,v in summary["projects"].items()}, indent=2))
    print(f"Total vendored source files: {total}")


if __name__ == "__main__":
    main()
