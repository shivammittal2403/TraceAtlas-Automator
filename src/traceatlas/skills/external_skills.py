"""Read analyst-supplied third-party skill ZIPs as untrusted references only.

No Python scripts, referenced commands or external tools are executed here.
TraceAtlas' canonical workforce registry and case authorizations stay authoritative.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILES = 10000
MAX_SKILL_BYTES = 128 * 1024
MAX_RATIO = 250
SLUG = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
FIELDS = ("name", "description", "domain", "subdomain", "license", "author", "version")


class SkillArchiveError(ValueError):
    """Invalid input or unsafe archive layout."""


@dataclass(frozen=True)
class ImportedSkill:
    name: str
    description: str
    subdomain: str
    license: str
    source_path: str
    sha256: str

    def as_dict(self):
        return {"skill_id": self.name, "title": self.name.replace("-", " "),
                "description": self.description, "subdomain": self.subdomain,
                "license": self.license, "source_path": self.source_path,
                "sha256": self.sha256, "execution_mode": "UNTRUSTED_REFERENCE_ONLY",
                "executable": False, "live_verified": False,
                "registered_tool": None, "requires_human_review": True}


def _safe_zip_path(name: str) -> bool:
    if (not name or len(name) > 512 or "\\" in name or name.startswith("/")
            or any(ord(c) < 32 for c in name)):
        return False
    parts = PurePosixPath(name).parts
    if any(part in ("..", ".") for part in parts):
        return False
    if not parts or parts[0] != "skills":
        return False
    return all(part not in ("", "..") for part in parts)


def _metadata(content: str) -> dict:
    if not content.startswith("---\n"):
        raise SkillArchiveError("SKILL.md requires YAML-like frontmatter")
    header, separator, _ = content[4:].partition("\n---\n")
    if not separator or len(header) > 32768:
        raise SkillArchiveError("SKILL.md frontmatter is incomplete")
    result = {}
    for line in header.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in FIELDS and key not in result:
            result[key] = value.strip().strip("'\"")
    if not result.get("name") or result.get("domain") != "cybersecurity":
        raise SkillArchiveError("SKILL.md has invalid or missing name/domain")
    return result


class ExternalSkillArchive:
    """Bounded ZIP reader, exposing non-executable descriptions by default."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_file() or self.path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise SkillArchiveError("Skill ZIP absent or exceeds bounded archive size")
        self.archive_sha256 = sha256(self.path.read_bytes()).hexdigest()
        self._index = self._scan()

    def _scan(self) -> dict[str, ImportedSkill]:
        with zipfile.ZipFile(self.path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES:
                raise SkillArchiveError("Too many entries")
            total, seen, names, skills = 0, set(), set(), {}
            for info in entries:
                name = info.filename
                if not _safe_zip_path(name):
                    raise SkillArchiveError("Unsafe entry path")
                lowered = name.casefold()
                if lowered in seen:
                    raise SkillArchiveError("Duplicate or ambiguous case-insensitive path")
                seen.add(lowered)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise SkillArchiveError("Symlinks are not allowed")
                if info.flag_bits & 1:
                    raise SkillArchiveError("Encrypted entries are not allowed")
                if info.file_size < 0 or info.compress_size < 0:
                    raise SkillArchiveError("Invalid entry sizes")
                if info.file_size > MAX_SKILL_BYTES * 8:
                    raise SkillArchiveError("Individual entry exceeds archive policy")
                if info.file_size and info.file_size / max(1, info.compress_size) > MAX_RATIO:
                    raise SkillArchiveError("Suspicious compression ratio")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise SkillArchiveError("Archive uncompressed total exceeds policy")
                parts = PurePosixPath(name).parts
                if len(parts) >= 2 and not SLUG.fullmatch(parts[1]):
                    raise SkillArchiveError("Invalid skill directory identifier")
                if len(parts) >= 2:
                    names.add(parts[1])
                if len(parts) == 3 and parts[2] == "SKILL.md":
                    if info.file_size > MAX_SKILL_BYTES:
                        raise SkillArchiveError("SKILL.md exceeds read limit")
                    try:
                        body = archive.read(info).decode("utf-8")
                    except (UnicodeError, RuntimeError, zipfile.BadZipFile) as exc:
                        raise SkillArchiveError("Unreadable SKILL.md") from exc
                    meta = _metadata(body)
                    slug = parts[1]
                    if meta["name"] != slug or slug in skills:
                        raise SkillArchiveError("Directory and skill identities do not match")
                    description = meta.get("description", "")
                    if len(description) > 2000:
                        description = description[:2000]
                    skills[slug] = ImportedSkill(
                        slug, description, meta.get("subdomain", "unknown"),
                        meta.get("license", "unverified"), name,
                        sha256(body.encode("utf-8")).hexdigest())
            if not skills:
                raise SkillArchiveError("No valid SKILL.md files found")
            self.files_total = len(entries)
            self.uncompressed_bytes = total
            self.without_skill_md = sorted(names - set(skills))
            return dict(sorted(skills.items()))

    def catalog(self, *, query: str = "", limit: int = 50) -> dict:
        if not isinstance(query, str) or len(query) > 120 or not 1 <= limit <= 1000:
            raise SkillArchiveError("Invalid catalog filter or result limit")
        needle = query.casefold()
        matched = [item.as_dict() for item in self._index.values()
                   if needle in item.name.casefold() or needle in item.subdomain.casefold()]
        return {"schema": "traceatlas.external-skills.catalog.v1",
                "archive_sha256": self.archive_sha256,
                "registered_external_skills": len(self._index),
                "matched": len(matched), "returned": min(limit, len(matched)),
                "missing_primary_skill_files": self.without_skill_md,
                "mode": "REFERENCE_ONLY", "execution_enabled": False,
                "skills": matched[:limit]}

    def reference(self, slug: str) -> dict:
        if not isinstance(slug, str) or not SLUG.fullmatch(slug) or slug not in self._index:
            raise SkillArchiveError("Unknown skill identifier")
        info = self._index[slug]
        with zipfile.ZipFile(self.path) as archive:
            content = archive.read(info.source_path).decode("utf-8")
        if sha256(content.encode("utf-8")).hexdigest() != info.sha256:
            raise SkillArchiveError("Skill bytes differ from archive manifest")
        return {**info.as_dict(), "markdown": content,
                "warning": "Untrusted third-party procedure. Reading this reference does not authorize tool use or execute its scripts."}
