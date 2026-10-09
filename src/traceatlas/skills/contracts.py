"""Versioned contracts for composable TraceAtlas AI-employee skills."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SkillDefinition:
    skill_id: str
    version: str
    family: str
    domains: tuple[str, ...]
    description: str
    input_types: tuple[str, ...]
    output_types: tuple[str, ...]
    required_capabilities: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    allowed_sources: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    next_skill_hints: tuple[str, ...] = ()
    offline_capable: bool = False
    network_required: bool = False
    model_required: bool = False
    multimodal: bool = False
    risk_level: str = "low"
    authorization_required: tuple[str, ...] = ()
    timeout_seconds: int = 60
    max_tool_calls: int = 8
    max_cost_usd: float = 0.0
    evidence_required: bool = True
    implementation_state: str = "procedure"

    def __post_init__(self) -> None:
        from .domains import FAMILIES, BY_ID
        if not self.skill_id or not self.version or self.family not in FAMILIES:
            raise ValueError("invalid skill identity")
        if not self.domains or any(domain not in BY_ID for domain in self.domains):
            raise ValueError("skill references an unknown intelligence domain")
        if any(BY_ID[domain].family != self.family for domain in self.domains):
            raise ValueError("skill domains must belong to its declared family")
        if self.risk_level not in {"low", "moderate", "high", "restricted"}:
            raise ValueError("invalid risk level")
        if self.implementation_state not in {"procedure", "adapter", "qualified"}:
            raise ValueError("invalid implementation state")
        if not 1 <= self.timeout_seconds <= 3600 or not 1 <= self.max_tool_calls <= 100:
            raise ValueError("skill execution budget is out of bounds")
        if self.max_cost_usd < 0:
            raise ValueError("skill cost cannot be negative")


@dataclass(frozen=True, slots=True)
class SkillResult:
    skill_id: str
    task_id: str
    status: str
    evidence_ids: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    entity_candidates: tuple[dict, ...] = ()
    relationship_candidates: tuple[dict, ...] = ()
    timestamps: tuple[dict, ...] = ()
    claim_candidates: tuple[dict, ...] = ()
    contradictions: tuple[dict, ...] = ()
    uncertainties: tuple[dict, ...] = ()
    information_gaps: tuple[dict, ...] = ()
    next_actions: tuple[dict, ...] = ()
    provenance: dict = field(default_factory=dict)
    execution_trace: tuple[dict, ...] = ()
    cost: dict = field(default_factory=dict)
    latency_ms: int = 0
    errors: tuple[dict, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"completed", "partial", "failed", "skipped", "blocked"}:
            raise ValueError("invalid skill result status")
        if self.latency_ms < 0:
            raise ValueError("negative skill latency")
