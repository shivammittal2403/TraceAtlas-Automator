"""Validate inert installed procedures for the opt-in coordination roles."""
from __future__ import annotations

from hashlib import sha256
from importlib.resources import files

HEADINGS = (
    "## Purpose and Selection", "## Inputs and Preconditions", "## Scope and Permissions",
    "## Procedure", "## Evidence and Provenance", "## Failure and Escalation", "## Output and Review",
)


def _locations():
    return {"coordination-manager": ("manager", "manager", "ALL"),
            **{"coordination-lead-" + str(group): ("lead-" + str(group), "team_lead", str(group))
               for group in range(1, 11)}}


def _validate(employee_id, text):
    locations = _locations()
    if not isinstance(employee_id, str) or employee_id not in locations:
        raise ValueError("Unknown coordination employee")
    if len(text.encode("utf-8")) > 64 * 1024 or not text.startswith("---\n"):
        raise ValueError("Coordination procedure metadata or size is invalid")
    parts = text.split("---\n", 2)
    if len(parts) != 3:
        raise ValueError("Coordination procedure requires bounded frontmatter")
    metadata = {}
    for line in parts[1].splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError("Coordination procedure metadata must be literal scalar fields")
        key, value = line.split(":", 1)
        if key.strip() in metadata:
            raise ValueError("Coordination procedure has duplicate metadata")
        metadata[key.strip()] = value.strip()
    _, role, group = locations[employee_id]
    expected = {"id": employee_id, "employee_id": employee_id, "version": "1.0.0", "role": role,
                "execution_mode": "supplied_record_coordination",
                "live_verified": "false", "domain_group": group}
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise ValueError("Coordination procedure metadata does not match its registered role")
    if any(heading not in parts[2].splitlines() for heading in HEADINGS) or "${" in text:
        raise ValueError("Coordination procedure headings or unresolved scope are invalid")
    return metadata


def get_coordination_skill(employee_id):
    if not isinstance(employee_id, str) or employee_id not in _locations():
        raise ValueError("Unknown coordination employee")
    directory, _, _ = _locations()[employee_id]
    raw = files("traceatlas.skills").joinpath("coordination", directory, "SKILL.md").read_bytes()
    text = raw.decode("utf-8").replace("\r\n", "\n")
    metadata = _validate(employee_id, text)
    return {"employee_id": employee_id, "metadata": metadata, "markdown": text,
            "path": "src/traceatlas/skills/coordination/" + directory + "/SKILL.md",
            "sha256": sha256(raw).hexdigest(), "execution_mode": "supplied_record_coordination",
            "grants_authority": False, "live_verified": False}


def coordination_skill_inventory():
    from .coordination_registry import build_coordination_definitions
    registered = {item.employee_id for item in build_coordination_definitions()}
    if registered != set(_locations()):
        raise ValueError("Coordination procedures differ from the opt-in role registry")
    guides = [get_coordination_skill(employee_id) for employee_id in sorted(registered)]
    return {"schema": "traceatlas.coordination.skills.v1", "count": len(guides),
            "validated": len(guides), "guides": [
                {key: value for key, value in guide.items() if key != "markdown"}
                for guide in guides], "grants_authority": False, "live_verified": False}
