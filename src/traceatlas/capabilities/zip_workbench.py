"""Reconcile root ZIP archives with governed TraceAtlas capability contracts.

No archived source is imported, installed or executed. Optional extraction is
isolated from the working checkout and never activated automatically.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile

from .archive import audit_archives, MAX_ARCHIVE_BYTES, MAX_MEMBERS, MAX_UNCOMPRESSED_BYTES
from .registry import CAPABILITIES

MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_TOTAL_STAGED = 2 * 1024 * 1024 * 1024
MAX_SOURCE_PARSE = 1024 * 1024
MAX_PARSE_FILES = 5000


def _valid_member(info: zipfile.ZipInfo) -> bool:
    raw = info.filename.replace("\\", "/")
    parts = PurePosixPath(raw).parts
    if not parts or raw.startswith("/") or "\x00" in raw or ".." in parts:
        return False
    if ":" in parts[0] or any(part in ("", ".", "..") for part in parts):
        return False
    if info.flag_bits & 1 or stat.S_ISLNK(info.external_attr >> 16):
        return False
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
        return False
    return True


def _archive_members(path: Path) -> tuple[list[zipfile.ZipInfo], int]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("not a supported regular ZIP archive")
    with zipfile.ZipFile(path) as zf:
        members = zf.infolist()
    if len(members) > MAX_MEMBERS:
        raise ValueError("too many archive members")
    total = 0
    seen = set()
    for info in members:
        if not _valid_member(info):
            raise ValueError("unsafe archive member")
        normalized = info.filename.replace("\\", "/").rstrip("/")
        folded = normalized.casefold()
        if folded in seen:
            raise ValueError("duplicate or colliding member path")
        seen.add(folded)
        if info.file_size > MAX_MEMBER_SIZE:
            raise ValueError("oversized member")
        total += info.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("excessive uncompressed size")
        if info.file_size and info.compress_size and info.file_size / info.compress_size > 1000:
            raise ValueError("suspicious compression ratio")
    return members, total


def _stage(path: Path, root: Path, digest: str) -> dict:
    members, total = _archive_members(path)
    destination = root / digest
    if destination.is_symlink():
        raise ValueError("staging destination is a symlink")
    marker = destination / ".traceatlas-stage.json"
    if destination.exists():
        if marker.is_file():
            try:
                prior = json.loads(marker.read_text(encoding="utf-8"))
                if prior["sha256"] == digest and prior["members"] == len(members):
                    return {"state": "already-staged", "path": str(destination), "members": len(members)}
            except (ValueError, KeyError, OSError):
                pass
        raise ValueError("existing destination requires manual review")
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".zip-stage-", dir=root) as tmp:
        temp = Path(tmp)
        with zipfile.ZipFile(path) as zf:
            for info in members:
                rel = PurePosixPath(info.filename.replace("\\", "/"))
                target = temp.joinpath(*rel.parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                if target.stat().st_size != info.file_size:
                    raise ValueError("member length mismatch")
                target.chmod(0o444)
        marker.write_text(json.dumps({"sha256": digest, "members": len(members),
                                      "uncompressed_bytes": total}, indent=2) + "\n",
                          encoding="utf-8")
        os.replace(temp, destination)
    return {"state": "staged-inert", "path": str(destination), "members": len(members)}


def _syntax_check(root: Path) -> dict:
    checked = 0
    errors = []
    if not root.is_dir():
        return {"checked_python": 0, "errors": []}
    for path in sorted(root.rglob("*.py")):
        if checked >= MAX_PARSE_FILES:
            break
        if path.is_symlink() or path.stat().st_size > MAX_SOURCE_PARSE:
            continue
        checked += 1
        try:
            ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (SyntaxError, UnicodeError, ValueError) as exc:
            if len(errors) < 30:
                errors.append({"file": str(path.relative_to(root)), "error": type(exc).__name__})
    return {"checked_python": checked, "errors": errors,
            "note": "AST-only syntax validation; no imported code or tools executed"}


def reconcile(repository: Path, *, stage_root: Path | None = None,
              syntax_check: bool = False) -> dict:
    repo = repository.resolve()
    archives = sorted(repo.glob("*.zip"), key=lambda path: path.name.casefold())
    if not archives:
        raise ValueError("No root-level ZIP archives found")
    report = audit_archives(archives)
    report["schema"] = "traceatlas.zip-workbench/v1"
    report["repository"] = str(repo)
    report["policy"]["archives_executed"] = False
    report["policy"]["archives_extracted"] = stage_root is not None
    report["policy"]["staged_sources_importable"] = False
    report["policy"]["live_calls_executed"] = False
    staged_total = 0
    by_hash: dict[str, dict] = {}
    for entry, path in zip(report["archives"], archives):
        contract = CAPABILITIES.get(entry.get("capability_id") or "")
        entry["ready_for_live_execution"] = False
        entry["contract_exists"] = contract is not None
        entry["next_gate"] = ("verify-credentials-install-and-authorization" if contract and contract.executable
                              else "license-and-source-review")
        entry["stage"] = {"state": "not-requested"}
        if stage_root is None:
            continue
        digest = entry.get("sha256")
        if not entry["accepted"] or not digest:
            entry["stage"] = {"state": "blocked", "issues": entry["issues"]}
            continue
        if digest in by_hash:
            entry["stage"] = {"state": "duplicate-skipped", "same_as": by_hash[digest]["filename"]}
            continue
        try:
            _, total = _archive_members(path)
            if staged_total + total > MAX_TOTAL_STAGED:
                raise ValueError("batch-staging-size-limit")
            entry["stage"] = _stage(path, stage_root, digest)
            staged_total += total
            if syntax_check:
                entry["syntax"] = _syntax_check(Path(entry["stage"]["path"]))
        except (ValueError, OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
            entry["stage"] = {"state": "blocked", "reason": str(exc)[:180]}
        by_hash[digest] = entry
    report["summary"]["staged_unique"] = sum(
        entry["stage"]["state"] in ("staged-inert", "already-staged")
        for entry in report["archives"])
    report["summary"]["blocked_staging"] = sum(
        entry["stage"]["state"] == "blocked" for entry in report["archives"])
    report["summary"]["staged_uncompressed_bytes"] = staged_total
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TraceAtlas ZIP capability workbench")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--stage-dir", type=Path, help="Isolated extraction directory; never runtime-imported")
    parser.add_argument("--syntax-check", action="store_true", help="AST parse extracted Python without execution")
    parser.add_argument("--output", type=Path, help="Write provenance and readiness report")
    args = parser.parse_args(argv)
    if args.syntax_check and not args.stage_dir:
        parser.error("--syntax-check requires --stage-dir")
    if args.stage_dir:
        stage_root = args.stage_dir.resolve()
        if stage_root == args.repository.resolve() or args.repository.resolve() in stage_root.parents:
            parser.error("Staging must be outside the repository to protect main/runtime integrity")
    report = reconcile(args.repository, stage_root=args.stage_dir, syntax_check=args.syntax_check)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0 if not report["summary"]["blocked_staging"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
