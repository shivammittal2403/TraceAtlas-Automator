"""traceatlas.addons.cute_v1.planning.question_decomposer - Objective -> sub-questions."""
from __future__ import annotations

from traceatlas.addons.cute_v1.core.objective_spec import ObjectiveSpec


def decompose(spec: ObjectiveSpec) -> list[str]:
    subs = []
    for r in spec.requirements:
        subs.append(f"How do we satisfy: {r}?")
    return subs
