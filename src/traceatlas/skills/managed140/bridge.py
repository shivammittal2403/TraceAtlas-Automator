"""Opt-in adapter to the canonical TraceAtlas SkillResult; never overrides registry."""
from __future__ import annotations
from .registry import lookup

def to_skill_result(report):
    from traceatlas.skills.contracts import SkillResult
    return SkillResult(
        skill_id=report["skill_id"], task_id=report["task_id"], status=report["status"],
        evidence_ids=tuple(e["evidence_id"] for e in report.get("evidence", ())),
        observation_ids=tuple(o["evidence_id"] + ":" + o["field"] for o in report.get("observations", ())),
        entity_candidates=tuple(report.get("entity_candidates", ())),
        relationship_candidates=tuple(report.get("relationship_candidates", ())),
        claim_candidates=tuple(report.get("claim_candidates", ())),
        contradictions=tuple(report.get("contradictions", ())),
        uncertainties=tuple(report.get("uncertainties", ())),
        information_gaps=tuple(report.get("information_gaps", ())),
        timestamps=tuple(report.get("timestamps", ())),
        provenance={"report_sha256": report["report_sha256"], **report.get("provenance", {})},
        execution_trace=tuple(report.get("execution_trace", ())),
        cost=report.get("cost", {}),
        errors=tuple(report.get("errors", ()))
    )

def to_skill_definition(code):
    from traceatlas.skills.domains import BY_ID
    from traceatlas.skills.contracts import SkillDefinition
    domain = lookup(code)
    key = domain["code"].lower()
    if key not in BY_ID:
        return None
    native_family = BY_ID[key].family
    return SkillDefinition(
        skill_id="managed140." + key, version="0.2.0", family=native_family, domains=(key,),
        description="Offline source-labeled analysis; not a live connector.",
        input_types=("structured_json",), output_types=("evidence", "observations", "claims"),
        offline_capable=True, network_required=False,
        risk_level="high" if domain["sensitive"] else "low",
        authorization_required=("scope_approval",) if domain["sensitive"] else (),
        implementation_state="adapter")
