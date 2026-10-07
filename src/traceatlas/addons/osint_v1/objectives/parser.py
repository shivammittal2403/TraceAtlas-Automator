"""Rule-based objective parser: natural-language Objective -> ObjectiveSpec.

This is deliberately deterministic and conservative. Anything it cannot parse
with confidence is flagged for human clarification rather than guessed.
"""

from __future__ import annotations

import re

from traceatlas.addons.osint_v1.core.enums import AuthorizationMode, EntityType
from traceatlas.addons.osint_v1.core.objective import Objective
from traceatlas.addons.osint_v1.core.objective_spec import Constraint, ObjectiveSpec, RequiredAnswer
from traceatlas.addons.osint_v1.core.validation import is_valid_domain, is_valid_ipv4
from traceatlas.addons.osint_v1.objectives.classifier import classify_investigation_type
from traceatlas.addons.osint_v1.objectives.entity_extractor import extract_entities
from traceatlas.addons.osint_v1.objectives.question_generator import generate_required_answers
from traceatlas.addons.osint_v1.objectives.ambiguity_detector import detect_ambiguities

_URL_RE = re.compile(r"https?://[^\s\"'<>()]+")


def parse_objective(objective: Objective) -> ObjectiveSpec:
    text = objective.text.strip()
    spec = ObjectiveSpec(objective_id=objective.id)

    spec.investigation_type = classify_investigation_type(text)
    spec.target_entities = extract_entities(text)

    urls = _URL_RE.findall(text)
    for u in urls:
        host = u.split("//", 1)[1].split("/")[0].lower()
        if is_valid_domain(host):
            spec.target_entities.append({"type": EntityType.URL.value, "value": u})

    spec.required_answers = generate_required_answers(spec.investigation_type, text)
    spec.constraints = _extract_constraints(text)
    spec.authorization_mode = _resolve_authorization(text)
    spec.ambiguities = detect_ambiguities(text, spec)
    spec.needs_human_clarification = bool(spec.ambiguities)
    return spec


def _extract_constraints(text: str) -> list[Constraint]:
    constraints: list[Constraint] = []
    lowered = text.lower()
    temporal = re.search(r"\b(since|before|after)\s+(\d{4})\b", lowered)
    if temporal:
        constraints.append(
            Constraint(kind="temporal", value=f"{temporal.group(1)} {temporal.group(2)}")
        )
    if "no social media" in lowered or "exclude social" in lowered:
        constraints.append(Constraint(kind="prohibition", value="exclude_social_platforms"))
    constraints.append(
        Constraint(kind="policy_default", value="public_sources_only", source="policy_default")
    )
    return constraints


def _resolve_authorization(text: str) -> AuthorizationMode:
    lowered = text.lower()
    if "i own" in lowered or "my company" in lowered or "authorized to investigate" in lowered:
        return AuthorizationMode.FULLY_AUTHORIZED
    if "public" in lowered:
        return AuthorizationMode.PUBLIC_ONLY
    # Default stays public-only; anything broader requires explicit authorization.
    return AuthorizationMode.PUBLIC_ONLY
