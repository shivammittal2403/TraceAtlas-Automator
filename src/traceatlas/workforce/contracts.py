"""Strict, versioned contracts for the bounded TraceAtlas AI workforce.

These records deliberately contain references instead of credentials or raw
authorization assertions.  Authorization is resolved by the service that owns
the case and cannot be granted by a model-produced payload.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Mapping, TypeVar


SCHEMA_VERSION = "1.0"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
T = TypeVar("T", bound="StrictContract")


def _utc(value: str, name: str) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _id(value: str, name: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} has an invalid identifier")
    return value


def _text(value: str, name: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    clean = value.strip()
    if not minimum <= len(clean) <= maximum or any(ord(c) < 32 and c not in "\n\t" for c in clean):
        raise ValueError(f"{name} must be {minimum}-{maximum} safe characters")
    return clean


def _strings(values: Any, name: str, *, maximum: int = 100) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or len(values) > maximum:
        raise ValueError(f"{name} must be a bounded string array")
    result = tuple(_id(value, name) for value in values)
    if len(result) != len(set(result)):
        raise ValueError(f"{name} cannot contain duplicates")
    return result


def _finite(value: Any, name: str, minimum: float = 0, maximum: float = 1_000_000) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{name} is outside the permitted range")
    return number


class SemanticClass(str, Enum):
    FACT = "FACT"
    OBSERVATION = "OBSERVATION"
    CLAIM = "CLAIM"
    INFERENCE = "INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"
    ALLEGATION = "ALLEGATION"
    UNKNOWN = "UNKNOWN"


class VerificationStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class StrictContract:
    """Small dependency-free strict-schema helper used at trust boundaries."""

    fields: ClassVar[frozenset[str]]

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, StrictContract):
                return value.to_dict()
            if isinstance(value, tuple):
                return [convert(item) for item in value]
            if isinstance(value, dict):
                return {key: convert(item) for key, item in value.items()}
            return value
        return {key: convert(value) for key, value in asdict(self).items()}

    @classmethod
    def _strict(cls, value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ValueError(f"{cls.__name__} must be an object")
        extra, missing = set(value) - cls.fields, cls.fields - set(value)
        if extra or missing:
            raise ValueError(f"{cls.__name__} fields mismatch; missing={sorted(missing)} extra={sorted(extra)}")
        return dict(value)


@dataclass(frozen=True, slots=True)
class Budget(StrictContract):
    currency: str
    amount: float
    runtime_seconds: int
    tool_calls: int
    model_calls: int
    fields: ClassVar[frozenset[str]] = frozenset({"currency", "amount", "runtime_seconds", "tool_calls", "model_calls"})

    def __post_init__(self) -> None:
        if self.currency not in {"USD", "NONE"}:
            raise ValueError("budget currency must be USD or NONE")
        object.__setattr__(self, "amount", _finite(self.amount, "amount", 0, 100_000))
        for name, value, maximum in (("runtime_seconds", self.runtime_seconds, 86_400), ("tool_calls", self.tool_calls, 100), ("model_calls", self.model_calls, 50)):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError(f"{name} is outside the permitted range")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Budget":
        return cls(**cls._strict(value))


@dataclass(frozen=True, slots=True)
class AuthorizationContext(StrictContract):
    schema_version: str
    context_id: str
    case_id: str
    actor_id: str
    lawful_purpose: str
    scope: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    jurisdiction: str
    retention_policy: str
    issued_at: str
    expires_at: str
    policy_digest: str
    fields: ClassVar[frozenset[str]] = frozenset({
        "schema_version", "context_id", "case_id", "actor_id", "lawful_purpose", "scope",
        "allowed_actions", "allowed_tools", "jurisdiction", "retention_policy", "issued_at",
        "expires_at", "policy_digest",
    })

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported authorization schema version")
        for name in ("context_id", "case_id", "actor_id"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        object.__setattr__(self, "lawful_purpose", _text(self.lawful_purpose, "lawful_purpose", 10, 500))
        object.__setattr__(self, "scope", _strings(self.scope, "scope", maximum=20))
        object.__setattr__(self, "allowed_actions", _strings(self.allowed_actions, "allowed_actions", maximum=30))
        object.__setattr__(self, "allowed_tools", _strings(self.allowed_tools, "allowed_tools", maximum=50))
        object.__setattr__(self, "jurisdiction", _text(self.jurisdiction, "jurisdiction", 2, 80))
        object.__setattr__(self, "retention_policy", _id(self.retention_policy, "retention_policy"))
        object.__setattr__(self, "issued_at", _utc(self.issued_at, "issued_at"))
        object.__setattr__(self, "expires_at", _utc(self.expires_at, "expires_at"))
        if datetime.fromisoformat(self.expires_at) <= datetime.fromisoformat(self.issued_at):
            raise ValueError("authorization must expire after it is issued")
        if not SHA256.fullmatch(self.policy_digest):
            raise ValueError("policy_digest must be SHA-256")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuthorizationContext":
        data = cls._strict(value)
        for key in ("scope", "allowed_actions", "allowed_tools"):
            data[key] = tuple(data[key]) if isinstance(data[key], list) else data[key]
        return cls(**data)


@dataclass(frozen=True, slots=True)
class EmployeeDefinition(StrictContract):
    schema_version: str
    employee_id: str
    name: str
    version: str
    role: str
    domain: str
    objective: str
    allowed_tools: tuple[str, ...]
    allowed_sources: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    budget_limit: Budget
    escalation_policy: tuple[str, ...]
    model_policy: tuple[str, ...]
    fields: ClassVar[frozenset[str]] = frozenset({
        "schema_version", "employee_id", "name", "version", "role", "domain", "objective",
        "allowed_tools", "allowed_sources", "allowed_actions", "prohibited_actions",
        "required_capabilities", "budget_limit", "escalation_policy", "model_policy",
    })

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported employee schema version")
        for name in ("employee_id", "version", "role", "domain"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        object.__setattr__(self, "name", _text(self.name, "name", 2, 120))
        object.__setattr__(self, "objective", _text(self.objective, "objective", 10, 500))
        for name in ("allowed_tools", "allowed_sources", "allowed_actions", "prohibited_actions", "required_capabilities", "escalation_policy", "model_policy"):
            object.__setattr__(self, name, _strings(getattr(self, name), name, maximum=100))
        if set(self.allowed_actions) & set(self.prohibited_actions):
            raise ValueError("an action cannot be both allowed and prohibited")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EmployeeDefinition":
        data = cls._strict(value)
        for key in ("allowed_tools", "allowed_sources", "allowed_actions", "prohibited_actions", "required_capabilities", "escalation_policy", "model_policy"):
            data[key] = tuple(data[key]) if isinstance(data[key], list) else data[key]
        data["budget_limit"] = Budget.from_dict(data["budget_limit"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class Acquisition(StrictContract):
    acquisition_id: str
    case_id: str
    task_id: str | None
    source_id: str
    source_uri: str
    method: str
    retrieved_at: str
    trace_id: str
    fields: ClassVar[frozenset[str]] = frozenset({"acquisition_id", "case_id", "task_id", "source_id", "source_uri", "method", "retrieved_at", "trace_id"})

    def __post_init__(self) -> None:
        for name in ("acquisition_id", "case_id", "source_id", "method", "trace_id"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        if self.task_id is not None:
            object.__setattr__(self, "task_id", _id(self.task_id, "task_id"))
        object.__setattr__(self, "source_uri", _text(self.source_uri, "source_uri", 1, 2048))
        object.__setattr__(self, "retrieved_at", _utc(self.retrieved_at, "retrieved_at"))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Acquisition":
        return cls(**cls._strict(value))


@dataclass(frozen=True, slots=True)
class TaskEnvelope(StrictContract):
    schema_version: str
    task_id: str
    case_id: str
    parent_task_id: str | None
    trace_id: str
    objective: str
    scope: tuple[str, ...]
    authorization_context_id: str
    policy_digest: str
    target_entities: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    evidence_context_ids: tuple[str, ...]
    constraints: tuple[str, ...]
    budget: Budget
    deadline: str
    stop_conditions: tuple[str, ...]
    created_by: str
    created_at: str
    fields: ClassVar[frozenset[str]] = frozenset({
        "schema_version", "task_id", "case_id", "parent_task_id", "trace_id", "objective", "scope",
        "authorization_context_id", "policy_digest", "target_entities", "required_capabilities",
        "evidence_context_ids", "constraints", "budget", "deadline", "stop_conditions",
        "created_by", "created_at",
    })

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported task schema version")
        for name in ("task_id", "case_id", "trace_id", "authorization_context_id", "created_by"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        if self.parent_task_id is not None:
            object.__setattr__(self, "parent_task_id", _id(self.parent_task_id, "parent_task_id"))
        object.__setattr__(self, "objective", _text(self.objective, "objective", 10, 1000))
        for name, maximum in (("scope", 20), ("target_entities", 50), ("required_capabilities", 30), ("evidence_context_ids", 500), ("constraints", 50), ("stop_conditions", 20)):
            object.__setattr__(self, name, _strings(getattr(self, name), name, maximum=maximum))
        if not self.stop_conditions:
            raise ValueError("task requires explicit stop conditions")
        if not SHA256.fullmatch(self.policy_digest):
            raise ValueError("policy_digest must be SHA-256")
        object.__setattr__(self, "deadline", _utc(self.deadline, "deadline"))
        object.__setattr__(self, "created_at", _utc(self.created_at, "created_at"))
        if datetime.fromisoformat(self.deadline) <= datetime.fromisoformat(self.created_at):
            raise ValueError("task deadline must follow creation")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TaskEnvelope":
        data = cls._strict(value)
        for key in ("scope", "target_entities", "required_capabilities", "evidence_context_ids", "constraints", "stop_conditions"):
            data[key] = tuple(data[key]) if isinstance(data[key], list) else data[key]
        data["budget"] = Budget.from_dict(data["budget"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class EvidenceObject(StrictContract):
    schema_version: str
    evidence_id: str
    version: int
    prior_version_id: str | None
    case_id: str
    source_id: str
    source_uri: str
    acquisition_id: str
    acquisition_method: str
    retrieved_at: str
    content_hash: str
    mime_type: str
    raw_artifact_pointer: str
    parser: str
    parser_version: str
    extractor: str
    extractor_version: str
    observation_ids: tuple[str, ...]
    chain_of_custody: tuple[str, ...]
    access_policy: str
    retention_policy: str
    classification: str
    created_at: str
    fields: ClassVar[frozenset[str]] = frozenset({
        "schema_version", "evidence_id", "version", "prior_version_id", "case_id", "source_id",
        "source_uri", "acquisition_id", "acquisition_method", "retrieved_at", "content_hash",
        "mime_type", "raw_artifact_pointer", "parser", "parser_version", "extractor",
        "extractor_version", "observation_ids", "chain_of_custody", "access_policy",
        "retention_policy", "classification", "created_at",
    })

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION or not isinstance(self.version, int) or self.version < 1:
            raise ValueError("unsupported evidence version")
        for name in ("evidence_id", "case_id", "source_id", "acquisition_id", "acquisition_method", "parser", "parser_version", "extractor", "extractor_version", "access_policy", "retention_policy", "classification"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        if self.prior_version_id is not None:
            object.__setattr__(self, "prior_version_id", _id(self.prior_version_id, "prior_version_id"))
        if not SHA256.fullmatch(self.content_hash):
            raise ValueError("content_hash must be SHA-256")
        object.__setattr__(self, "retrieved_at", _utc(self.retrieved_at, "retrieved_at"))
        object.__setattr__(self, "created_at", _utc(self.created_at, "created_at"))
        object.__setattr__(self, "observation_ids", _strings(self.observation_ids, "observation_ids", maximum=1000))
        object.__setattr__(self, "chain_of_custody", _strings(self.chain_of_custody, "chain_of_custody", maximum=1000))
        for name in ("source_uri", "mime_type", "raw_artifact_pointer"):
            object.__setattr__(self, name, _text(getattr(self, name), name, 1, 2048))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceObject":
        data = cls._strict(value)
        for key in ("observation_ids", "chain_of_custody"):
            data[key] = tuple(data[key]) if isinstance(data[key], list) else data[key]
        return cls(**data)


@dataclass(frozen=True, slots=True)
class Observation(StrictContract):
    observation_id: str
    evidence_id: str
    acquisition_id: str
    statement: str
    semantic_class: SemanticClass
    observed_at: str
    fields: ClassVar[frozenset[str]] = frozenset({"observation_id", "evidence_id", "acquisition_id", "statement", "semantic_class", "observed_at"})

    def __post_init__(self) -> None:
        for name in ("observation_id", "evidence_id", "acquisition_id"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        object.__setattr__(self, "statement", _text(self.statement, "statement", 1, 4000))
        object.__setattr__(self, "semantic_class", SemanticClass(self.semantic_class))
        if self.semantic_class not in {SemanticClass.OBSERVATION, SemanticClass.ALLEGATION}:
            raise ValueError("observations must be OBSERVATION or ALLEGATION")
        object.__setattr__(self, "observed_at", _utc(self.observed_at, "observed_at"))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Observation":
        return cls(**cls._strict(value))


@dataclass(frozen=True, slots=True)
class Claim(StrictContract):
    claim_id: str
    statement: str
    semantic_class: SemanticClass
    observation_ids: tuple[str, ...]
    material: bool
    model_confidence: float | None
    fields: ClassVar[frozenset[str]] = frozenset({"claim_id", "statement", "semantic_class", "observation_ids", "material", "model_confidence"})

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _id(self.claim_id, "claim_id"))
        object.__setattr__(self, "statement", _text(self.statement, "statement", 1, 4000))
        object.__setattr__(self, "semantic_class", SemanticClass(self.semantic_class))
        if self.semantic_class not in {SemanticClass.CLAIM, SemanticClass.INFERENCE, SemanticClass.FACT}:
            raise ValueError("invalid claim semantic class")
        object.__setattr__(self, "observation_ids", _strings(self.observation_ids, "observation_ids", maximum=100))
        if not self.observation_ids:
            raise ValueError("claims require observations")
        if type(self.material) is not bool:
            raise ValueError("material must be boolean")
        if self.model_confidence is not None:
            object.__setattr__(self, "model_confidence", _finite(self.model_confidence, "model_confidence", 0, 1))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Claim":
        data = cls._strict(value)
        data["observation_ids"] = tuple(data["observation_ids"]) if isinstance(data["observation_ids"], list) else data["observation_ids"]
        return cls(**data)


@dataclass(frozen=True, slots=True)
class Hypothesis(StrictContract):
    hypothesis_id: str
    statement: str
    evidence_ids: tuple[str, ...]
    next_checks: tuple[str, ...]
    fields: ClassVar[frozenset[str]] = frozenset({"hypothesis_id", "statement", "evidence_ids", "next_checks"})

    def __post_init__(self) -> None:
        object.__setattr__(self, "hypothesis_id", _id(self.hypothesis_id, "hypothesis_id"))
        object.__setattr__(self, "statement", _text(self.statement, "statement", 1, 4000))
        object.__setattr__(self, "evidence_ids", _strings(self.evidence_ids, "evidence_ids", maximum=100))
        object.__setattr__(self, "next_checks", _strings(self.next_checks, "next_checks", maximum=30))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Hypothesis":
        data = cls._strict(value)
        data["evidence_ids"], data["next_checks"] = tuple(data["evidence_ids"]), tuple(data["next_checks"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class SourceLineage(StrictContract):
    lineage_id: str
    source_id: str
    independence_group: str
    original_source_id: str | None
    content_fingerprint: str
    ownership_group: str | None
    reasons: tuple[str, ...]
    fields: ClassVar[frozenset[str]] = frozenset({"lineage_id", "source_id", "independence_group", "original_source_id", "content_fingerprint", "ownership_group", "reasons"})

    def __post_init__(self) -> None:
        for name in ("lineage_id", "source_id", "independence_group"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        for name in ("original_source_id", "ownership_group"):
            if getattr(self, name) is not None:
                object.__setattr__(self, name, _id(getattr(self, name), name))
        if not SHA256.fullmatch(self.content_fingerprint):
            raise ValueError("content_fingerprint must be SHA-256")
        object.__setattr__(self, "reasons", _strings(self.reasons, "reasons", maximum=20))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SourceLineage":
        data = cls._strict(value)
        data["reasons"] = tuple(data["reasons"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class VerificationDecision(StrictContract):
    claim_id: str
    status: VerificationStatus
    integrity_passed: bool
    independent_groups: tuple[str, ...]
    supporting_observation_ids: tuple[str, ...]
    contradicting_observation_ids: tuple[str, ...]
    information_gaps: tuple[str, ...]
    human_review_required: bool
    decided_at: str
    fields: ClassVar[frozenset[str]] = frozenset({"claim_id", "status", "integrity_passed", "independent_groups", "supporting_observation_ids", "contradicting_observation_ids", "information_gaps", "human_review_required", "decided_at"})

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _id(self.claim_id, "claim_id"))
        object.__setattr__(self, "status", VerificationStatus(self.status))
        for name in ("integrity_passed", "human_review_required"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be boolean")
        for name in ("independent_groups", "supporting_observation_ids", "contradicting_observation_ids", "information_gaps"):
            object.__setattr__(self, name, _strings(getattr(self, name), name, maximum=200))
        object.__setattr__(self, "decided_at", _utc(self.decided_at, "decided_at"))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerificationDecision":
        data = cls._strict(value)
        for key in ("independent_groups", "supporting_observation_ids", "contradicting_observation_ids", "information_gaps"):
            data[key] = tuple(data[key])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class CostRecord(StrictContract):
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    estimated_cost: float
    actual_cost: float | None
    currency: str
    fields: ClassVar[frozenset[str]] = frozenset({"provider", "model", "input_tokens", "output_tokens", "estimated_cost", "actual_cost", "currency"})

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", _id(self.provider, "provider"))
        object.__setattr__(self, "model", _id(self.model, "model"))
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100_000_000:
                raise ValueError(f"{name} is invalid")
        object.__setattr__(self, "estimated_cost", _finite(self.estimated_cost, "estimated_cost", 0, 100_000))
        if self.actual_cost is not None:
            object.__setattr__(self, "actual_cost", _finite(self.actual_cost, "actual_cost", 0, 100_000))
        if self.currency not in {"USD", "NONE"}:
            raise ValueError("unsupported currency")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CostRecord":
        return cls(**cls._strict(value))


@dataclass(frozen=True, slots=True)
class TraceSpan(StrictContract):
    span_id: str
    trace_id: str
    parent_span_id: str | None
    operation: str
    status: str
    started_at: str
    completed_at: str
    latency_ms: int
    evidence_ids: tuple[str, ...]
    fields: ClassVar[frozenset[str]] = frozenset({"span_id", "trace_id", "parent_span_id", "operation", "status", "started_at", "completed_at", "latency_ms", "evidence_ids"})

    def __post_init__(self) -> None:
        for name in ("span_id", "trace_id", "operation", "status"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        if self.parent_span_id is not None:
            object.__setattr__(self, "parent_span_id", _id(self.parent_span_id, "parent_span_id"))
        object.__setattr__(self, "started_at", _utc(self.started_at, "started_at"))
        object.__setattr__(self, "completed_at", _utc(self.completed_at, "completed_at"))
        if isinstance(self.latency_ms, bool) or not isinstance(self.latency_ms, int) or not 0 <= self.latency_ms <= 86_400_000:
            raise ValueError("latency_ms is invalid")
        object.__setattr__(self, "evidence_ids", _strings(self.evidence_ids, "evidence_ids", maximum=1000))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TraceSpan":
        data = cls._strict(value)
        data["evidence_ids"] = tuple(data["evidence_ids"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ResultEnvelope(StrictContract):
    schema_version: str
    task_id: str
    employee_id: str
    observations: tuple[Observation, ...]
    evidence_ids: tuple[str, ...]
    entities: tuple[str, ...]
    relationships: tuple[str, ...]
    claims: tuple[Claim, ...]
    hypotheses: tuple[Hypothesis, ...]
    contradictions: tuple[str, ...]
    uncertainties: tuple[str, ...]
    confidence_basis: tuple[str, ...]
    source_independence: tuple[str, ...]
    information_gaps: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]
    cost: CostRecord
    latency_ms: int
    model_used: str
    tool_calls: tuple[str, ...]
    execution_trace: tuple[TraceSpan, ...]
    stop_reason: str
    completed_at: str
    fields: ClassVar[frozenset[str]] = frozenset({"schema_version", "task_id", "employee_id", "observations", "evidence_ids", "entities", "relationships", "claims", "hypotheses", "contradictions", "uncertainties", "confidence_basis", "source_independence", "information_gaps", "recommended_next_actions", "cost", "latency_ms", "model_used", "tool_calls", "execution_trace", "stop_reason", "completed_at"})

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported result schema version")
        for name in ("task_id", "employee_id", "model_used", "stop_reason"):
            object.__setattr__(self, name, _id(getattr(self, name), name))
        for name in ("evidence_ids", "entities", "relationships", "contradictions", "uncertainties", "confidence_basis", "source_independence", "information_gaps", "recommended_next_actions", "tool_calls"):
            object.__setattr__(self, name, _strings(getattr(self, name), name, maximum=1000))
        if len(self.observations) > 1000 or len(self.claims) > 200 or len(self.hypotheses) > 100 or len(self.execution_trace) > 1000:
            raise ValueError("result exceeds contract bounds")
        known = {item.observation_id for item in self.observations}
        if any(not set(claim.observation_ids).issubset(known) for claim in self.claims):
            raise ValueError("claim cites an unknown observation")
        if any(item.evidence_id not in self.evidence_ids for item in self.observations):
            raise ValueError("observation cites unknown evidence")
        if isinstance(self.latency_ms, bool) or not isinstance(self.latency_ms, int) or not 0 <= self.latency_ms <= 86_400_000:
            raise ValueError("latency_ms is invalid")
        object.__setattr__(self, "completed_at", _utc(self.completed_at, "completed_at"))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResultEnvelope":
        data = cls._strict(value)
        data["observations"] = tuple(Observation.from_dict(item) for item in data["observations"])
        data["claims"] = tuple(Claim.from_dict(item) for item in data["claims"])
        data["hypotheses"] = tuple(Hypothesis.from_dict(item) for item in data["hypotheses"])
        data["cost"] = CostRecord.from_dict(data["cost"])
        data["execution_trace"] = tuple(TraceSpan.from_dict(item) for item in data["execution_trace"])
        for key in ("evidence_ids", "entities", "relationships", "contradictions", "uncertainties", "confidence_basis", "source_independence", "information_gaps", "recommended_next_actions", "tool_calls"):
            data[key] = tuple(data[key])
        return cls(**data)
