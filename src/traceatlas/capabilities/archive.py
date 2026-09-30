from __future__ import annotations

import hashlib
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from ..policy import PolicyError
from .registry import CAPABILITIES


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 20_000
MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024

# Routes identify an interoperability contract only. Supplied archives are never
# imported as executable code and their documentation never grants authority.
ARCHIVE_ROUTES: tuple[tuple[re.Pattern[str], str | None], ...] = tuple(
    (re.compile(pattern, re.I), capability)
    for pattern, capability in (
        (r"^abster-intelligence", "abster-intelligence"),
        (r"^agent-reach", "agent-reach"),
        (r"^agent-toolkit", "datacommons-mcp"),
        (r"^agentic-osint-agent", "agentic-osint-agent"),
        (r"^alethia", "alethia"),
        (r"^api-mega-list", "api-mega-list"),
        (r"^apify-mcp-server", "apify-mcp"),
        (r"^browser-use", "browser-use"),
        (r"^citra", "citra"),
        (r"^claude-osint", "claude-osint"),
        (r"^connectors", "opencti-connectors"),
        (r"^crawl4ai", "crawl4ai"),
        (r"^ctinexus", "ctinexus"),
        (r"^cti-to-mitre-with-nlp", "cti-to-mitre-nlp"),
        (r"^deer-flow", "deerflow"),
        (r"^exa-mcp-server", "exa-mcp"),
        (r"^firecrawl-mcp-server", "firecrawl-mcp"),
        (r"^firecrawl", "firecrawl"),
        (r"^freeosint", "freeosint"),
        (r"^geo-clip", "geoclip"),
        (r"^geo-sleuth", "geo-sleuth"),
        (r"^geoai", "geoai"),
        (r"^gpt-researcher", "gpt-researcher"),
        (r"^intelowl", "intelowl"),
        (r"^iop-python-mvp", "iop-mvp"),
        (r"^iop-python", "iop-python"),
        (r"^mcp-searxng", "mcp-searxng"),
        (r"^osint-agent", "osint-agent"),
        (r"^osint-mcp-server", "osint-mcp-server"),
        (r"^osint-vision-agent", "osint-vision-agent"),
        (r"^osintiq", "osintiq"),
        (r"^scrapegraph-ai", "scrapegraph-ai"),
        (r"^searxng", "searxng"),
        (r"^sida", "sida"),
        (r"^skopia", "skopia"),
        (r"^stagehand", "stagehand"),
        (r"^storm", "storm"),
        (r"^threatwatch", "threatwatch"),
        (r"^traceatlas[_-]9of10[_-]blueprint", None),
        (r"^watcher", "watcher"),
        (r"^xalgorix", "xalgorix"),
        (r"^zettelforge", "zettelforge"),
    )
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _route(filename: str) -> tuple[str | None, str]:
    stem = filename[:-4] if filename.lower().endswith(".zip") else filename
    stem = re.sub(r"\s+-\s+copy$|\s+\(\d+\)$", "", stem, flags=re.I)
    for pattern, capability in ARCHIVE_ROUTES:
        if pattern.search(stem):
            return capability, "blueprint" if capability is None else "registered-boundary"
    return None, "unregistered"


def _detect_license(text: str) -> str | None:
    lowered = text.lower()
    if "non-commercial license" in lowered or "noncommercial license" in lowered:
        return "NON-COMMERCIAL"
    if "gnu affero general public license" in lowered:
        return "AGPL-3.0"
    if "apache license" in lowered and "version 2.0" in lowered:
        return "Apache-2.0"
    if "permission is hereby granted, free of charge" in lowered:
        return "MIT"
    if re.search(
        r'(?im)^\s*(?:license\s*=\s*(?:\{[^}\n]*text\s*=\s*)?|["\']license["\']\s*:\s*)["\']mit["\']',
        text,
    ):
        return "MIT"
    if "creative commons attribution-sharealike" in lowered:
        return "CC-BY-SA"
    return None


def _member_is_unsafe(info: zipfile.ZipInfo) -> str | None:
    raw = info.filename.replace("\\", "/")
    if "\x00" in raw or raw.startswith(("/", "//")) or re.match(r"^[a-zA-Z]:", raw):
        return "absolute-or-invalid-path"
    if ".." in PurePosixPath(raw).parts:
        return "path-traversal"
    if stat.S_ISLNK(info.external_attr >> 16):
        return "symbolic-link"
    if info.flag_bits & 0x1:
        return "encrypted-member"
    return None


def audit_archive(path: Path) -> dict[str, Any]:
    supplied_path = path
    filename = supplied_path.name
    capability_id, integration_state = _route(filename)
    result: dict[str, Any] = {
        "filename": filename,
        "capability_id": capability_id,
        "integration_state": integration_state,
        "instruction_authority": "none",
        "execution_enabled_by_archive": False,
        "accepted": False,
        "issues": [],
    }
    if supplied_path.is_symlink() or not supplied_path.is_file() or supplied_path.suffix.lower() != ".zip":
        result["issues"].append("not-a-regular-zip-file")
        return result
    path = supplied_path.resolve()
    size = path.stat().st_size
    result.update({"size": size, "sha256": _sha256(path)})
    if size > MAX_ARCHIVE_BYTES:
        result["issues"].append("archive-size-limit-exceeded")
        return result
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            total_uncompressed = sum(member.file_size for member in members)
            result.update({
                "members": len(members),
                "uncompressed_size": total_uncompressed,
            })
            if len(members) > MAX_MEMBERS:
                result["issues"].append("member-count-limit-exceeded")
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                result["issues"].append("uncompressed-size-limit-exceeded")
            unsafe = []
            detected: set[str] = set()
            metadata_files: list[str] = []
            for member in members:
                reason = _member_is_unsafe(member)
                if reason and len(unsafe) < 50:
                    unsafe.append({"member": member.filename, "reason": reason})
                normalized = member.filename.replace("\\", "/").strip("/")
                parts = PurePosixPath(normalized).parts
                basename = parts[-1].lower() if parts else ""
                is_license = (
                    len(parts) <= 2
                    and (basename.startswith("license") or basename.startswith("copying"))
                )
                is_manifest = len(parts) <= 2 and basename in {
                    "pyproject.toml", "package.json", "setup.py", "setup.cfg", "cargo.toml"
                }
                if (is_license or is_manifest) and member.file_size <= MAX_METADATA_BYTES:
                    metadata_files.append(member.filename)
                    try:
                        text = archive.read(member).decode("utf-8", errors="replace")
                    except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
                        result["issues"].append(f"metadata-unreadable:{member.filename}")
                    else:
                        found = _detect_license(text)
                        if found:
                            detected.add(found)
            result["unsafe_members"] = unsafe
            result["metadata_files"] = metadata_files
            result["detected_licenses"] = sorted(detected)
            if unsafe:
                result["issues"].append("unsafe-members-present")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        result["issues"].append(f"invalid-zip:{type(exc).__name__}")
        return result

    spec = CAPABILITIES.get(capability_id or "")
    if spec:
        detected_licenses = result.get("detected_licenses", [])
        expected_lower = spec.license.lower()
        if spec.license == "CONFLICTING":
            license_alignment = "review-required"
        elif not detected_licenses:
            license_alignment = "missing" if "no-license" not in expected_lower else "missing-as-expected"
        elif any(detected.lower() in expected_lower for detected in detected_licenses):
            license_alignment = "matched"
        else:
            license_alignment = "mismatch-review-required"
        result["contract"] = {
            "license": spec.license,
            "license_alignment": license_alignment,
            "integration": spec.integration,
            "executable": spec.executable,
            "restriction": spec.restriction,
        }
    elif integration_state == "unregistered":
        result["issues"].append("no-integration-contract")
    result["accepted"] = not any(
        issue.startswith(("archive-", "member-", "uncompressed-", "invalid-zip", "not-a-regular"))
        or issue == "unsafe-members-present"
        for issue in result["issues"]
    )
    return result


def audit_archives(paths: Iterable[Path]) -> dict[str, Any]:
    path_list = list(paths)
    if not path_list:
        raise PolicyError("At least one --archive path is required")
    rows = [audit_archive(path) for path in path_list]
    first_by_hash: dict[str, str] = {}
    for row in rows:
        digest = row.get("sha256")
        if not digest:
            continue
        if digest in first_by_hash:
            row["duplicate_of"] = first_by_hash[digest]
        else:
            first_by_hash[digest] = row["filename"]
    return {
        "schema": "traceatlas.supplied-archive-audit/v1",
        "policy": {
            "archives_executed": False,
            "archives_extracted": False,
            "embedded_instructions_authoritative": False,
            "limits": {
                "archive_bytes": MAX_ARCHIVE_BYTES,
                "members": MAX_MEMBERS,
                "uncompressed_bytes": MAX_UNCOMPRESSED_BYTES,
                "metadata_bytes": MAX_METADATA_BYTES,
            },
        },
        "summary": {
            "archives": len(rows),
            "accepted": sum(bool(row["accepted"]) for row in rows),
            "registered": sum(row["integration_state"] == "registered-boundary" for row in rows),
            "duplicates": sum("duplicate_of" in row for row in rows),
            "unsafe": sum(bool(row.get("unsafe_members")) for row in rows),
            "unregistered": sum(row["integration_state"] == "unregistered" for row in rows),
        },
        "archives": rows,
    }
