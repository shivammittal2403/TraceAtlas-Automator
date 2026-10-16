"""Read and validate shipped discipline procedures; never execute Markdown as code."""
from __future__ import annotations

from hashlib import sha256
from importlib.resources import files
import re

from .discipline_registry import supported_disciplines

_FIELDS = ("id", "discipline", "version", "employee", "allowed_tool",
           "execution_mode", "live_verified")
_HEADINGS = ("## Purpose and Selection", "## Inputs and Preconditions",
             "## Scope and Permissions", "## Procedure", "## Evidence and Output",
             "## Hypothesis and Falsification", "## Failure and Tests")


def parse_guide(markdown: str, discipline: str) -> dict:
    if not isinstance(markdown, str) or len(markdown.encode("utf-8")) > 16384:
        raise ValueError("Procedure must be bounded UTF-8 text")
    if not markdown.startswith("---\n"):
        raise ValueError("Missing procedure frontmatter")
    header, separator, body = markdown[4:].partition("\n---\n")
    if not separator or not body.strip():
        raise ValueError("Incomplete procedure")
    metadata = {}
    for line in header.splitlines():
        key, sep, value = line.partition(": ")
        if not sep or not re.fullmatch("[a-z_]+", key) or key in metadata or not value:
            raise ValueError("Invalid or duplicate procedure metadata")
        metadata[key] = value
    label = discipline.upper()
    if tuple(metadata) != _FIELDS or (
        metadata["id"] != label.lower() or metadata["discipline"] != label or
        metadata["employee"] != "discipline-" + label.lower() or
        metadata["allowed_tool"] != "discipline.analyze" or
        metadata["execution_mode"] != "authorized_supplied_records" or
        metadata["live_verified"] != "false"
    ):
        raise ValueError("Procedure cannot change its identity or tool authority")
    if re.search(r"\$\{[^}\n]+\}", body):
        raise ValueError("Procedure contains unresolved template placeholders")
    if any(body.count(heading) != 1 for heading in _HEADINGS):
        raise ValueError("Procedure lacks required operational sections")
    return metadata


def get_skill_guide(discipline: str) -> dict:
    if not isinstance(discipline, str):
        raise ValueError("Discipline must be a registered label")
    label = discipline.strip().upper()
    if not re.fullmatch("[A-Z][A-Z0-9]{1,39}", label) or label not in supported_disciplines():
        raise ValueError("Unknown discipline procedure")
    try:
        md = files("traceatlas.skills").joinpath("procedures", label.lower(),
                                                  "SKILL.md").read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("Installed discipline procedure is missing") from exc
    meta = parse_guide(md, label)
    return {"schema": "traceatlas.discipline.skill-guide.v1", "discipline": label,
            "employee": meta["employee"], "allowed_tool": meta["allowed_tool"],
            "execution_mode": meta["execution_mode"], "live_verified": False,
            "sha256": sha256(md.encode("utf-8")).hexdigest(), "markdown": md}


def skill_inventory() -> dict:
    labels = supported_disciplines()
    rows = []
    for label in labels:
        guide = get_skill_guide(label)
        rows.append({"discipline": label, "sha256": guide["sha256"],
                     "live_verified": False})
    return {"schema": "traceatlas.discipline.skill-inventory.v1", "requested": len(labels),
            "guides_available": len(rows), "guides": rows,
            "note": "No source collector is qualified by a Markdown skill."}
