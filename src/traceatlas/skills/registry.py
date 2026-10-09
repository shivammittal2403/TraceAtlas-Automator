"""Deterministic capability registry for AI-employee skill routing.

The model may request capabilities. This registry decides which registered skill
definitions are eligible. It never grants authority or executes tools.
"""
from __future__ import annotations

from dataclasses import asdict

from .contracts import SkillDefinition
from .domains import FAMILIES, BY_ID


class SkillRegistry:
    def __init__(self, skills=()):
        self._skills: dict[str, SkillDefinition] = {}
        for skill in skills:
            self.register(skill)

    def register(self, skill: SkillDefinition) -> None:
        if skill.skill_id in self._skills:
            raise ValueError(f"duplicate skill: {skill.skill_id}")
        self._skills[skill.skill_id] = skill

    def get(self, skill_id: str) -> SkillDefinition:
        return self._skills[skill_id]

    def list(self, *, family: str | None = None, state: str | None = None) -> tuple[SkillDefinition, ...]:
        if family is not None and family not in FAMILIES:
            raise KeyError(f"unknown family: {family}")
        rows = self._skills.values()
        if family is not None:
            rows = (row for row in rows if row.family == family)
        if state is not None:
            rows = (row for row in rows if row.implementation_state == state)
        return tuple(sorted(rows, key=lambda row: row.skill_id))

    def search(self, *, capabilities=(), domains=(), input_type: str | None = None,
               require_offline: bool = False) -> tuple[SkillDefinition, ...]:
        requested_capabilities = set(capabilities)
        requested_domains = set(domains)
        if any(domain not in BY_ID for domain in requested_domains):
            raise KeyError("unknown intelligence domain in skill request")
        rows = []
        for skill in self._skills.values():
            if requested_capabilities and not requested_capabilities.issubset(skill.required_capabilities):
                continue
            if requested_domains and not requested_domains.intersection(skill.domains):
                continue
            if input_type is not None and input_type not in skill.input_types:
                continue
            if require_offline and not skill.offline_capable:
                continue
            rows.append(skill)
        return tuple(sorted(rows, key=lambda row: (
            row.implementation_state != "qualified",
            row.network_required,
            row.max_cost_usd,
            row.skill_id,
        )))

    def describe(self) -> dict:
        return {
            "schema": "traceatlas-skill-registry/v1",
            "skills": [asdict(skill) for skill in self.list()],
            "count": len(self._skills),
            "note": (
                "Registry entries describe capabilities only. Tool/source authority, "
                "case scope, evidence capture and qualification remain external gates."
            ),
        }


def procedure_skill(skill_id: str, family: str, domains: tuple[str, ...], description: str,
                    *, input_types=("text",), output_types=("observations",),
                    required_capabilities=(), dependencies=(), next_skill_hints=(),
                    offline_capable=True, multimodal=False, risk_level="low") -> SkillDefinition:
    return SkillDefinition(
        skill_id=skill_id,
        version="1",
        family=family,
        domains=domains,
        description=description,
        input_types=tuple(input_types),
        output_types=tuple(output_types),
        required_capabilities=tuple(required_capabilities),
        dependencies=tuple(dependencies),
        next_skill_hints=tuple(next_skill_hints),
        offline_capable=offline_capable,
        multimodal=multimodal,
        risk_level=risk_level,
        implementation_state="procedure",
    )
