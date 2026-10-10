# TRACEATLAS — KNOWINT AI EMPLOYEE
# Single-file defensive Python core for Knowledge Intelligence / Structured Graph Reasoning.
#
# PRIMARY BOUNDARY:
# KNOWLEDGE REPRESENTATION AND REASONING,
# NOT UNSOURCED FACT CREATION OR UNCONTROLLED PERSONAL PROFILING.
#
# This code does NOT:
# - invent nodes, edges, events, sources, evidence, entity identities, or causation
# - merge entities by name/embedding similarity alone
# - promote link prediction or LLM output to fact
# - infer sensitive traits from graph structure
# - expose cross-tenant/private evidence
# - send full private graph to cloud models
# - allow evidence/content to override policy

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


TOOL_VERSION = "KNOWINT-PY-0.1"
ONTOLOGY_VERSION = "KNOWINT-ONTOLOGY-1"

OFFICIAL_PRIMARY_TYPES = {
    "OFFICIAL_RECORD",
    "GOVERNMENT_SOURCE",
    "REGULATORY_SOURCE",
    "COURT_SOURCE",
    "COMPANY_FILING",
}

STRONG_IDENTIFIER_KEYS = {
    "official_registry",
    "legal_entity_id",
    "registration_number",
    "lei",
    "vat",
    "domain",
    "account_id",
    "wallet_address",
    "crypto_address",
    "certificate_serial",
    "serial_number",
    "imei",
}

CAUSAL_PREDICATES = {
    "CAUSED_BY",
    "LED_TO",
    "RESULTED_IN",
    "RESPONSIBLE_FOR",
}

CONTROL_PREDICATES = {
    "CONTROLS",
    "EFFECTIVELY_CONTROLS",
    "BENEFICIALLY_OWNS",
    "MAJORITY_CONTROL_OF",
}

SENSITIVE_TRAIT_PREDICATES = {
    "RACE",
    "ETHNICITY",
    "RELIGION",
    "SEXUAL_ORIENTATION",
    "MEDICAL_CONDITION",
    "POLITICAL_IDEOLOGY",
    "CRIMINAL_SUSPECT",
    "GUILTY_BY_ASSOCIATION",
}

BLOCK_PHRASES = [
    "invent node",
    "invent edge",
    "invent event",
    "invent source",
    "invent evidence",
    "invent entity identity",
    "invent causation",
    "merge by name",
    "merge entities by name",
    "merge on name",
    "merge on embedding",
    "embedding similarity merge",
    "promote link prediction to fact",
    "promote llm output to fact",
    "llm output to fact",
    "infer religion",
    "infer race",
    "infer ethnicity",
    "infer sexual orientation",
    "infer medical condition",
    "infer political ideology",
    "send full graph to cloud",
    "graph dump",
    "escape tenant",
    "change permissions",
    "ignore contradictions",
    "delete evidence",
    "personal profiling",
    "one-hop guilt",
    "association guilt",
]


# ======================================================================
# Enums
# ======================================================================

class Mode(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    HYBRID = "HYBRID"
    CLOUD = "CLOUD"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"
    BLOCKED_PERMISSION = "BLOCKED_PERMISSION"
    BLOCKED_PRIVACY = "BLOCKED_PRIVACY"


class ClaimState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class VerificationState(str, Enum):
    VERIFIED = "VERIFIED"
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CLAIMED = "CLAIMED"
    INFERRED = "INFERRED"
    PREDICTED = "PREDICTED"
    DISPUTED = "DISPUTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class EntityResolutionState(str, Enum):
    VERIFIED_SAME_ENTITY = "VERIFIED_SAME_ENTITY"
    PROBABLE_SAME_ENTITY = "PROBABLE_SAME_ENTITY"
    POSSIBLE_SAME_ENTITY = "POSSIBLE_SAME_ENTITY"
    UNRESOLVED = "UNRESOLVED"
    VERIFIED_DISTINCT = "VERIFIED_DISTINCT"
    PROBABLE_DISTINCT = "PROBABLE_DISTINCT"


class RelationshipState(str, Enum):
    OBSERVED = "OBSERVED"
    CLAIMED = "CLAIMED"
    INFERRED = "INFERRED"
    SUPPORTED = "SUPPORTED"
    DISPUTED = "DISPUTED"
    VERIFIED = "VERIFIED"
    HISTORICAL = "HISTORICAL"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class Staleness(str, Enum):
    FRESH = "FRESH"
    AGING = "AGING"
    STALE = "STALE"
    HISTORICAL = "HISTORICAL"
    TIMELESS = "TIMELESS"
    UNKNOWN = "UNKNOWN"


class Classification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    CASE_ONLY = "CASE_ONLY"


# ======================================================================
# Utilities
# ======================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = None
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d %b %Y", "%b %d, %Y", "%d-%m-%Y"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def sha256_12(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8", errors="ignore")).hexdigest()[:12]


def hash_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, bytes):
        data = content
    elif isinstance(content, str):
        data = content.encode("utf-8", errors="ignore")
    else:
        data = json.dumps(content, default=str, sort_keys=True).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def norm_text(text: Any) -> str:
    text = unicodedata.normalize("NFKC", str(text or ""))
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(x)))


def mean(values: list[float], default: float = 0.0) -> float:
    if not values:
        return default
    return sum(values) / len(values)


def has_limitation(limitations: list[str], token: str) -> bool:
    token = token.lower()
    return any(token in str(l).lower() for l in limitations)


def intervals_overlap(
    start_a: Optional[str],
    end_a: Optional[str],
    start_b: Optional[str],
    end_b: Optional[str],
) -> bool:
    sa = parse_dt(start_a)
    ea = parse_dt(end_a)
    sb = parse_dt(start_b)
    eb = parse_dt(end_b)

    if ea and sb and ea < sb:
        return False
    if eb and sa and eb < sa:
        return False
    return True


def is_active(valid_from: Optional[str], valid_to: Optional[str], as_of: datetime) -> bool:
    vf = parse_dt(valid_from)
    vt = parse_dt(valid_to)
    if vf and as_of < vf:
        return False
    if vt and as_of > vt:
        return False
    return True


def staleness_state(
    valid_to: Optional[str],
    last_verified: Optional[str],
    as_of: datetime,
) -> Staleness:
    vt = parse_dt(valid_to)
    if vt and as_of > vt:
        return Staleness.HISTORICAL

    lv = parse_dt(last_verified)
    if lv:
        days = (as_of - lv).days
        if days <= 90:
            return Staleness.FRESH
        if days <= 365:
            return Staleness.AGING
        return Staleness.STALE

    if not vt and not lv:
        return Staleness.UNKNOWN

    return Staleness.UNKNOWN


def accessible(obj: Any, perm: "PermissionContext") -> bool:
    tenant = getattr(obj, "tenant_id", "default")
    if perm.tenant_id != "*" and tenant != perm.tenant_id:
        return False

    case = getattr(obj, "case_id", "")
    cls = getattr(obj, "classification", Classification.PUBLIC)

    if case and perm.case_id and case != perm.case_id:
        # Public entities may be reused cross-case; private/confidential may not.
        if cls != Classification.PUBLIC:
            return False

    if cls not in perm.allowed_classifications:
        return False

    return True


# ======================================================================
# Data models
# ======================================================================

@dataclass
class PermissionContext:
    tenant_id: str = "default"
    case_id: str = ""
    classification: Classification = Classification.INTERNAL
    allowed_classifications: list[Classification] = field(
        default_factory=lambda: [Classification.PUBLIC, Classification.INTERNAL]
    )
    allowed_node_types: list[str] = field(default_factory=list)
    allowed_predicates: list[str] = field(default_factory=list)
    purpose: str = ""
    authorized: bool = False
    can_write: bool = False
    can_merge_entities: bool = False
    can_promote_facts: bool = True
    human_review_required: bool = False


@dataclass
class Source:
    source_id: str
    source_type: str = "UNKNOWN"
    publisher: str = ""
    author: str = ""
    collection_method: str = ""
    first_seen: str = ""
    last_seen: str = ""
    reliability: float = 0.5
    bias: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    upstream_source: str = ""
    independence_group: str = ""
    pedigree: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    case_id: str = ""
    classification: Classification = Classification.PUBLIC
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    evidence_id: str
    source_id: str = ""
    artifact_type: str = "DOCUMENT"
    content: Optional[str] = None
    content_hash: str = ""
    mime_type: str = ""
    locator: str = ""
    retrieved_at: str = ""
    published_at: str = ""
    observed_at: str = ""
    collector: str = ""
    parser: str = ""
    classification: Classification = Classification.PUBLIC
    tenant_id: str = "default"
    case_id: str = ""
    chain_of_custody: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Entity:
    entity_id: str
    entity_type: str = "UNKNOWN"
    display_name: str = ""
    aliases: list[str] = field(default_factory=list)
    identifiers: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    valid_from: str = ""
    valid_to: str = ""
    classification: Classification = Classification.PUBLIC
    tenant_id: str = "default"
    case_id: str = ""
    provenance: list[str] = field(default_factory=list)
    sensitivity: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Relationship:
    relationship_id: str
    subject_id: str
    predicate: str
    object_id: str
    relationship_type: str = "DIRECTED"
    state: RelationshipState = RelationshipState.CLAIMED
    valid_from: str = ""
    valid_to: str = ""
    observed_at: str = ""
    source_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    verification_state: VerificationState = VerificationState.UNKNOWN
    confidence: float = 0.5
    qualifiers: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)
    corrected_by: list[str] = field(default_factory=list)
    retracted_by: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    case_id: str = ""
    classification: Classification = Classification.PUBLIC
    provenance: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    event_id: str
    event_type: str
    participants: list[str] = field(default_factory=list)
    time_start: str = ""
    time_end: str = ""
    location: str = ""
    source_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    verification_state: VerificationState = VerificationState.UNKNOWN
    confidence: float = 0.5
    limitations: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    case_id: str = ""
    classification: Classification = Classification.PUBLIC


@dataclass
class Claim:
    claim_id: str
    statement: str = ""
    subject_id: str = ""
    predicate: str = ""
    object_id: str = ""
    claim_type: str = "FACTUAL"
    time: str = ""
    valid_from: str = ""
    valid_to: str = ""
    source_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    state: ClaimState = ClaimState.INCONCLUSIVE
    confidence: float = 0.5
    qualifiers: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    case_id: str = ""
    classification: Classification = Classification.PUBLIC


@dataclass
class Fact:
    fact_id: str
    claim_id: str
    canonical_statement: str
    supporting_evidence_ids: list[str] = field(default_factory=list)
    supporting_source_ids: list[str] = field(default_factory=list)
    independent_family_count: int = 0
    validity_from: str = ""
    validity_to: str = ""
    verification_state: VerificationState = VerificationState.SUPPORTED
    confidence: float = 0.5
    verified_at: str = field(default_factory=now_iso)
    verifier: str = "KNOWINT_PRIMARY"
    limitations: list[str] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)
    contradicted_by: list[str] = field(default_factory=list)
    tenant_id: str = "default"
    case_id: str = ""
    classification: Classification = Classification.PUBLIC


@dataclass
class Insight:
    insight_id: str
    statement: str
    supporting_fact_ids: list[str] = field(default_factory=list)
    supporting_evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: list[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    status: str = "PROPOSED"
    supporting_claim_ids: list[str] = field(default_factory=list)
    contradicting_claim_ids: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    source_dependencies: list[str] = field(default_factory=list)
    predictions: list[str] = field(default_factory=list)
    falsification_tests: list[str] = field(default_factory=list)
    confidence: float = 0.5


@dataclass
class Contradiction:
    contradiction_id: str
    object_a: str
    object_b: str
    contradiction_type: str = "DIRECT"
    materiality: str = "MATERIAL"
    temporal_context: str = ""
    explanation_candidates: list[str] = field(default_factory=list)
    status: str = "OPEN"
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Gap:
    gap_id: str
    question: str
    entity_refs: list[str] = field(default_factory=list)
    importance: str = "MEDIUM"
    reason: str = ""
    recommended_source_types: list[str] = field(default_factory=list)
    recommended_specialist: str = ""
    expected_information_value: str = "MEDIUM"
    status: str = "OPEN"


@dataclass
class EntityResolutionCandidate:
    candidate_id: str
    entity_ids: list[str]
    state: EntityResolutionState
    score: float
    matched_features: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    recommended_action: str = "REVIEW"
    requires_human_review: bool = True


@dataclass
class KnowIntRequest:
    case_id: str
    objective: str
    task_id: str = ""
    authorization: dict[str, Any] = field(default_factory=dict)
    permission: PermissionContext = field(default_factory=PermissionContext)
    questions: list[str] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    existing_facts: list[Fact] = field(default_factory=list)
    time_range: dict[str, str] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    as_of: str = ""


@dataclass
class KnowIntResult:
    case_id: str
    objective: str
    status: str
    policy_decision: str
    summary: str
    task_id: str = ""
    questions: list[str] = field(default_factory=list)
    graph_version: int = 0
    ontology_version: str = ONTOLOGY_VERSION

    source_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    claim_ids: list[str] = field(default_factory=list)
    fact_ids: list[str] = field(default_factory=list)
    insight_ids: list[str] = field(default_factory=list)
    hypothesis_ids: list[str] = field(default_factory=list)
    contradiction_ids: list[str] = field(default_factory=list)
    gap_ids: list[str] = field(default_factory=list)

    entities: list[dict[str, Any]] = field(default_factory=list)
    entity_resolution_results: list[dict[str, Any]] = field(default_factory=list)
    aliases: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    relationship_states: dict[str, str] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    claims: list[dict[str, Any]] = field(default_factory=list)
    facts: list[dict[str, Any]] = field(default_factory=list)
    insights: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    knowledge_gaps: list[dict[str, Any]] = field(default_factory=list)

    temporal_states: dict[str, Any] = field(default_factory=dict)
    current_snapshot: dict[str, Any] = field(default_factory=dict)
    historical_states: dict[str, Any] = field(default_factory=dict)

    source_reliability: dict[str, float] = field(default_factory=dict)
    source_bias: dict[str, list[str]] = field(default_factory=dict)
    source_limitations: dict[str, list[str]] = field(default_factory=dict)
    source_families: dict[str, list[str]] = field(default_factory=dict)
    source_independence: dict[str, Any] = field(default_factory=dict)

    provenance_paths: list[dict[str, Any]] = field(default_factory=list)
    evidence_paths: list[dict[str, Any]] = field(default_factory=list)
    support_paths: list[dict[str, Any]] = field(default_factory=list)
    contradiction_paths: list[dict[str, Any]] = field(default_factory=list)

    graph_clusters: list[dict[str, Any]] = field(default_factory=list)
    predicted_relationships: list[dict[str, Any]] = field(default_factory=list)
    predicted_relationships_status: str = "NONE_CREATED"

    fact_gate_results: list[dict[str, Any]] = field(default_factory=list)
    falsification_results: list[dict[str, Any]] = field(default_factory=list)
    ach_results: list[dict[str, Any]] = field(default_factory=list)
    dual_ai_results: list[dict[str, Any]] = field(default_factory=list)

    coverage: dict[str, Any] = field(default_factory=dict)
    staleness: dict[str, str] = field(default_factory=dict)
    graph_health: dict[str, Any] = field(default_factory=dict)
    permission_context: dict[str, Any] = field(default_factory=dict)

    recommended_next_actions: list[str] = field(default_factory=list)
    specialist_handoffs: list[str] = field(default_factory=list)
    human_review_items: list[str] = field(default_factory=list)
    privacy_flags: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    replay_manifest: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)


# ======================================================================
# Knowledge graph container
# ======================================================================

class KnowledgeGraph:
    def __init__(self) -> None:
        self.sources: dict[str, Source] = {}
        self.evidence: dict[str, Evidence] = {}
        self.entities: dict[str, Entity] = {}
        self.relationships: dict[str, Relationship] = {}
        self.events: dict[str, Event] = {}
        self.claims: dict[str, Claim] = {}
        self.facts: dict[str, Fact] = {}
        self.insights: dict[str, Insight] = {}
        self.hypotheses: dict[str, Hypothesis] = {}
        self.contradictions: dict[str, Contradiction] = {}
        self.gaps: dict[str, Gap] = {}
        self.entity_resolution_candidates: dict[str, EntityResolutionCandidate] = {}

        self.graph_version = 0
        self.event_log: list[dict[str, Any]] = []
        self.ontology_version = ONTOLOGY_VERSION

    def log(self, action: str, object_type: str, object_id: str, details: Optional[dict[str, Any]] = None) -> None:
        self.graph_version += 1
        self.event_log.append(
            {
                "seq": self.graph_version,
                "time": now_iso(),
                "action": action,
                "object_type": object_type,
                "object_id": object_id,
                "details": details or {},
            }
        )

    def add_source(self, source: Source) -> None:
        self.sources[source.source_id] = source
        self.log("CREATE", "Source", source.source_id)

    def add_evidence(self, evidence: Evidence) -> None:
        computed = hash_content(evidence.content)
        if evidence.content is not None:
            if not evidence.content_hash:
                evidence.content_hash = computed
            elif evidence.content_hash != computed:
                evidence.limitations.append("provided content hash does not match supplied content")

        self.evidence[evidence.evidence_id] = evidence
        self.log("CREATE", "Evidence", evidence.evidence_id, {"hash": evidence.content_hash})

    def add_entity(self, entity: Entity) -> None:
        self.entities[entity.entity_id] = entity
        self.log("CREATE", "Entity", entity.entity_id)

    def add_relationship(self, relationship: Relationship) -> None:
        self.relationships[relationship.relationship_id] = relationship
        self.log("CREATE", "Relationship", relationship.relationship_id)

    def add_event(self, event: Event) -> None:
        self.events[event.event_id] = event
        self.log("CREATE", "Event", event.event_id)

    def add_claim(self, claim: Claim) -> None:
        self.claims[claim.claim_id] = claim
        self.log("CREATE", "Claim", claim.claim_id)

    def add_fact(self, fact: Fact) -> None:
        self.facts[fact.fact_id] = fact
        self.log("CREATE", "Fact", fact.fact_id)

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self.hypotheses[hypothesis.hypothesis_id] = hypothesis
        self.log("CREATE", "Hypothesis", hypothesis.hypothesis_id)

    def add_contradiction(self, contradiction: Contradiction) -> None:
        self.contradictions[contradiction.contradiction_id] = contradiction
        self.log("CREATE", "Contradiction", contradiction.contradiction_id)

    def add_gap(self, gap: Gap) -> None:
        self.gaps[gap.gap_id] = gap
        self.log("CREATE", "Gap", gap.gap_id)


# ======================================================================
# KNOWINT agent
# ======================================================================

class KnowIntAgent:
    """
    Defensive KNOWINT core.

    Builds a temporal, provenance-aware, permission-aware knowledge graph
    from supplied evidence/entities/relationships/claims.

    It conservatively promotes claims to facts only when evidence,
    source independence, entity resolution, temporal consistency, and
    contradiction checks support the exact proposition.
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Policy / authorization
    # ------------------------------------------------------------------

    def policy_check(self, req: KnowIntRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                req.task_id,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
                json.dumps(asdict(req.permission), default=str),
            ]
        ).lower()

        if not req.permission.authorized:
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_AUTHORIZATION.value,
                "KNOWINT requires explicit authorized permission context.",
            )

        if req.authorization.get("authorized") is False:
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_AUTHORIZATION.value,
                "Authorization explicitly denied.",
            )

        if req.scope.get("send_full_graph_to_cloud"):
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_POLICY.value,
                "Full private graph export to cloud is prohibited.",
            )

        for phrase in BLOCK_PHRASES:
            if phrase in blob:
                return (
                    PolicyDecision.BLOCK,
                    Status.BLOCKED_POLICY.value,
                    f"Prohibited knowledge-intelligence action requested: {phrase}",
                )

        return PolicyDecision.ALLOW, "", ""

    def _empty_result(
        self,
        case_id: str,
        objective: str,
        status: str,
        policy_decision: str,
        summary: str,
        questions: Optional[list[str]] = None,
        limitations: Optional[list[str]] = None,
        task_id: str = "",
    ) -> KnowIntResult:
        return KnowIntResult(
            case_id=case_id,
            objective=objective,
            task_id=task_id,
            status=status,
            policy_decision=policy_decision,
            summary=summary,
            questions=questions or [],
            limitations=limitations or [],
            created_at=now_iso(),
        )

    # ------------------------------------------------------------------
    # Source families / independence
    # ------------------------------------------------------------------

    def _source_families(self, graph: KnowledgeGraph) -> dict[str, list[str]]:
        families: dict[str, list[str]] = defaultdict(list)
        for sid, source in graph.sources.items():
            key = source.upstream_source or source.independence_group or sid
            families[key].append(sid)
        return {k: sorted(v) for k, v in families.items()}

    # ------------------------------------------------------------------
    # Entity resolution
    # ------------------------------------------------------------------

    def _entity_resolution(
        self,
        graph: KnowledgeGraph,
        perm: PermissionContext,
    ) -> list[EntityResolutionCandidate]:
        candidates: list[EntityResolutionCandidate] = []
        by_type: dict[str, list[Entity]] = defaultdict(list)

        for entity in list(graph.entities.values()):
            by_type[entity.entity_type].append(entity)

        for entity_type, group in by_type.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a_id, b_id = group[i].entity_id, group[j].entity_id
                    a = graph.entities.get(a_id)
                    b = graph.entities.get(b_id)
                    if not a or not b:
                        continue

                    score = 0.0
                    matched: list[str] = []
                    conflicts: list[str] = []

                    common_keys = set(a.identifiers) & set(b.identifiers)
                    for key in common_keys:
                        av = a.identifiers.get(key)
                        bv = b.identifiers.get(key)
                        if av == bv:
                            if key in STRONG_IDENTIFIER_KEYS:
                                score = max(score, 0.96)
                                matched.append(f"exact_strong_identifier:{key}")
                            else:
                                score = max(score, 0.70)
                                matched.append(f"exact_identifier:{key}")
                        else:
                            if key in STRONG_IDENTIFIER_KEYS:
                                score = 0.0
                                conflicts.append(f"strong_identifier_mismatch:{key}")
                            else:
                                conflicts.append(f"identifier_mismatch:{key}")

                    a_names = {norm_text(a.display_name)} | {norm_text(x) for x in a.aliases}
                    b_names = {norm_text(b.display_name)} | {norm_text(x) for x in b.aliases}

                    if a_names & b_names:
                        score = max(score, 0.35)
                        matched.append("name_or_alias_overlap")

                    if any(c.startswith("strong_identifier_mismatch") for c in conflicts):
                        state = EntityResolutionState.VERIFIED_DISTINCT
                        score = 0.0
                        recommended = "keep_distinct"
                        requires_human = False
                    elif not matched:
                        continue
                    elif score >= 0.90 and not conflicts:
                        state = EntityResolutionState.VERIFIED_SAME_ENTITY
                        recommended = "merge_if_permitted"
                        requires_human = entity_type == "PersonCandidate"
                    elif score >= 0.70 and not conflicts:
                        state = EntityResolutionState.PROBABLE_SAME_ENTITY
                        recommended = "human_review_before_merge"
                        requires_human = True
                    elif score >= 0.45:
                        state = EntityResolutionState.POSSIBLE_SAME_ENTITY
                        recommended = "do_not_merge_name_only"
                        requires_human = True
                    else:
                        state = EntityResolutionState.UNRESOLVED
                        recommended = "collect_more_identifiers"
                        requires_human = True

                    candidate = EntityResolutionCandidate(
                        candidate_id=f"ER-{sha256_12(a_id + b_id)}",
                        entity_ids=[a_id, b_id],
                        state=state,
                        score=round(clamp(score), 3),
                        matched_features=sorted(set(matched)),
                        conflicts=sorted(set(conflicts)),
                        evidence_ids=sorted(set(a.provenance + b.provenance)),
                        recommended_action=recommended,
                        requires_human_review=requires_human,
                    )

                    candidates.append(candidate)
                    graph.entity_resolution_candidates[candidate.candidate_id] = candidate
                    graph.log(
                        "CREATE",
                        "EntityResolutionCandidate",
                        candidate.candidate_id,
                        {"state": state.value, "score": candidate.score},
                    )

                    # Conservative auto-merge only for non-person entities with
                    # deterministic strong identifier match and explicit permission.
                    if (
                        state == EntityResolutionState.VERIFIED_SAME_ENTITY
                        and perm.can_merge_entities
                        and not conflicts
                        and entity_type != "PersonCandidate"
                    ):
                        self._merge_entities(graph, a_id, b_id, perm)

        return candidates

    def _merge_entities(
        self,
        graph: KnowledgeGraph,
        keep_id: str,
        drop_id: str,
        perm: PermissionContext,
    ) -> None:
        keep = graph.entities.get(keep_id)
        drop = graph.entities.get(drop_id)
        if not keep or not drop or keep_id == drop_id:
            return

        existing_aliases = {norm_text(x) for x in [keep.display_name] + keep.aliases}
        for alias in [drop.display_name] + drop.aliases:
            if norm_text(alias) not in existing_aliases:
                keep.aliases.append(alias)
                existing_aliases.add(norm_text(alias))

        for k, v in drop.identifiers.items():
            keep.identifiers.setdefault(k, v)

        keep.attributes.update(drop.attributes)
        keep.provenance = sorted(set(keep.provenance + drop.provenance))

        for rel in graph.relationships.values():
            if rel.subject_id == drop_id:
                rel.subject_id = keep_id
            if rel.object_id == drop_id:
                rel.object_id = keep_id

        for claim in graph.claims.values():
            if claim.subject_id == drop_id:
                claim.subject_id = keep_id
            if claim.object_id == drop_id:
                claim.object_id = keep_id

        for event in graph.events.values():
            event.participants = [keep_id if p == drop_id else p for p in event.participants]

        del graph.entities[drop_id]
        graph.log(
            "MERGE_APPROVED",
            "Entity",
            drop_id,
            {"into": keep_id, "tenant": perm.tenant_id, "case": perm.case_id},
        )

    # ------------------------------------------------------------------
    # Claim contradiction helper
    # ------------------------------------------------------------------

    def _find_claim_contradictions(
        self,
        claim: Claim,
        graph: KnowledgeGraph,
        as_of: datetime,
    ) -> list[str]:
        contradictions: list[str] = []

        for other in graph.claims.values():
            if other.claim_id == claim.claim_id:
                continue

            same_subject = other.subject_id == claim.subject_id
            same_predicate = other.predicate.upper() == claim.predicate.upper()
            different_object = other.object_id != claim.object_id

            if not (same_subject and same_predicate and different_object):
                continue

            overlap = intervals_overlap(
                claim.valid_from or claim.time,
                claim.valid_to,
                other.valid_from or other.time,
                other.valid_to,
            )

            has_support_a = bool(claim.evidence_ids or claim.source_ids)
            has_support_b = bool(other.evidence_ids or other.source_ids)

            if overlap and has_support_a and has_support_b:
                contradictions.append(other.claim_id)

        return contradictions

    # ------------------------------------------------------------------
    # Fact gate
    # ------------------------------------------------------------------

    def _fact_gate_claim(
        self,
        claim: Claim,
        graph: KnowledgeGraph,
        perm: PermissionContext,
        as_of: datetime,
        resolution_by_entity: dict[str, list[EntityResolutionCandidate]],
    ) -> dict[str, Any]:
        limitations: list[str] = []
        privacy_flags: list[str] = []

        evidence_ids = set(claim.evidence_ids)
        source_ids = set(claim.source_ids)

        # Evidence checks.
        for eid in list(evidence_ids):
            ev = graph.evidence.get(eid)
            if not ev:
                limitations.append(f"missing evidence {eid}")
                evidence_ids.discard(eid)
                continue

            if not accessible(ev, perm):
                limitations.append(f"evidence {eid} not accessible under permission context")

            if not ev.source_id:
                limitations.append(f"evidence {eid} missing source")
            else:
                source_ids.add(ev.source_id)

            if not ev.content_hash:
                limitations.append(f"evidence {eid} missing content hash")

        # Relationship checks.
        for rid in claim.relationship_ids:
            rel = graph.relationships.get(rid)
            if not rel:
                limitations.append(f"missing relationship {rid}")
                continue

            source_ids.update(rel.source_ids)
            evidence_ids.update(rel.evidence_ids)

            if not rel.evidence_ids and not rel.source_ids:
                limitations.append(f"relationship {rid} unprovenanced")

            if not is_active(rel.valid_from, rel.valid_to, as_of):
                if claim.valid_from and rel.valid_to and parse_dt(claim.valid_from) and parse_dt(rel.valid_to):
                    if parse_dt(claim.valid_from) > parse_dt(rel.valid_to):
                        limitations.append(f"temporal conflict: relationship {rid} ended before claim period")
                    else:
                        limitations.append(f"relationship {rid} not active at as_of")
                else:
                    limitations.append(f"relationship {rid} not active at as_of")

        # Source checks.
        reliability_scores: list[float] = []
        max_rel = 0.0
        families: set[str] = set()
        official_primary = False

        for sid in list(source_ids):
            source = graph.sources.get(sid)
            if not source:
                limitations.append(f"missing source {sid}")
                source_ids.discard(sid)
                continue

            if not accessible(source, perm):
                limitations.append(f"source {sid} not accessible under permission context")

            reliability_scores.append(source.reliability)
            max_rel = max(max_rel, source.reliability)
            families.add(source.upstream_source or source.independence_group or source.source_id)

            if source.source_type.upper() in OFFICIAL_PRIMARY_TYPES and source.reliability >= 0.90:
                official_primary = True

        avg_rel = mean(reliability_scores, 0.0)
        independent_family_count = len(families)

        # Entity checks.
        for eid in [claim.subject_id, claim.object_id]:
            if not eid:
                continue
            if eid not in graph.entities:
                limitations.append(f"unresolved entity {eid}")
            else:
                cand_states = [
                    c.state
                    for c in resolution_by_entity.get(eid, [])
                    if eid in c.entity_ids
                ]
                if any(
                    s in {EntityResolutionState.POSSIBLE_SAME_ENTITY, EntityResolutionState.PROBABLE_SAME_ENTITY, EntityResolutionState.UNRESOLVED}
                    for s in cand_states
                ):
                    limitations.append(f"entity {eid} resolution unresolved")

        # Sensitive-trait restriction.
        if claim.predicate.upper() in SENSITIVE_TRAIT_PREDICATES:
            limitations.append(
                "sensitive-trait inference prohibited without explicit lawful evidence and justified purpose"
            )
            privacy_flags.append(f"Claim {claim.claim_id} attempts sensitive-trait inference.")

        # Causal restriction.
        if claim.predicate.upper() in CAUSAL_PREDICATES:
            if not (
                claim.qualifiers.get("mechanism_evidence")
                or claim.qualifiers.get("intervention_evidence")
                or claim.qualifiers.get("alternative_causes_checked")
            ):
                limitations.append(
                    "causal claim requires mechanism/intervention/alternative-cause evidence; sequence/path insufficient"
                )

        # Control / beneficial ownership restriction.
        if claim.predicate.upper() in CONTROL_PREDICATES:
            if not (
                claim.qualifiers.get("voting_rights_verified")
                or claim.qualifiers.get("control_rights_verified")
            ):
                limitations.append(
                    "control/beneficial ownership requires voting/control-rights evidence; economic ownership alone insufficient"
                )

        # Preliminary contradiction check.
        contradicting_claim_ids = self._find_claim_contradictions(claim, graph, as_of)
        if contradicting_claim_ids:
            limitations.append(f"contradicting claims: {contradicting_claim_ids}")

        severe_missing = (
            has_limitation(limitations, "missing evidence")
            or has_limitation(limitations, "missing source")
            or has_limitation(limitations, "unresolved entity")
        )

        # State decision.
        if not evidence_ids and not source_ids:
            state = ClaimState.UNSUPPORTED
        elif has_limitation(limitations, "temporal conflict"):
            state = ClaimState.UNSUPPORTED
        elif contradicting_claim_ids:
            state = ClaimState.DISPUTED
        elif (
            has_limitation(limitations, "sensitive-trait")
            or has_limitation(limitations, "causal claim requires")
            or has_limitation(limitations, "control/beneficial")
        ):
            state = ClaimState.INCONCLUSIVE
        elif (
            avg_rel >= 0.75
            and (
                independent_family_count >= 2
                or (independent_family_count == 1 and official_primary and max_rel >= 0.90)
            )
            and not severe_missing
        ):
            state = ClaimState.SUPPORTED
        elif avg_rel >= 0.55 and (independent_family_count >= 1 or official_primary) and not severe_missing:
            state = ClaimState.PARTIALLY_SUPPORTED
        else:
            state = ClaimState.INCONCLUSIVE

        confidence = clamp(
            0.20
            + 0.35 * max_rel
            + 0.15 * min(1.0, independent_family_count / 2.0)
            - 0.08 * len([l for l in limitations if "missing" in l.lower() or "conflict" in l.lower()])
        )

        return {
            "claim_id": claim.claim_id,
            "state": state.value,
            "confidence": round(confidence, 3),
            "limitations": sorted(set(limitations)),
            "privacy_flags": privacy_flags,
            "evidence_ids": sorted(evidence_ids),
            "source_ids": sorted(source_ids),
            "independent_family_count": independent_family_count,
            "source_families": sorted(families),
            "average_source_reliability": round(avg_rel, 3),
            "max_source_reliability": round(max_rel, 3),
            "official_primary": official_primary,
            "contradicting_claim_ids": contradicting_claim_ids,
        }

    # ------------------------------------------------------------------
    # Contradiction detection
    # ------------------------------------------------------------------

    def _detect_contradictions(
        self,
        graph: KnowledgeGraph,
        as_of: datetime,
    ) -> list[Contradiction]:
        contradictions: list[Contradiction] = []
        seen: set[tuple[str, str]] = set()

        for claim in graph.claims.values():
            for other_id in self._find_claim_contradictions(claim, graph, as_of):
                pair = tuple(sorted([claim.claim_id, other_id]))
                if pair in seen:
                    continue
                seen.add(pair)

                other = graph.claims.get(other_id)
                if not other:
                    continue

                materiality = "HIGH" if claim.predicate.upper() in CONTROL_PREDICATES | {"HOLDS_SHARES_OF", "OWNS"} else "MATERIAL"

                contradiction = Contradiction(
                    contradiction_id=f"CONTRA-{sha256_12(pair[0] + pair[1])}",
                    object_a=claim.claim_id,
                    object_b=other_id,
                    contradiction_type="DIRECT",
                    materiality=materiality,
                    temporal_context=f"{claim.valid_from or claim.time} / {other.valid_from or other.time}",
                    explanation_candidates=[
                        "different_time_periods",
                        "different_entity_resolution",
                        "different_scope_or_definition",
                        "source_error",
                        "version_or_update_lag",
                    ],
                    status="OPEN",
                    evidence_ids=sorted(set(claim.evidence_ids + other.evidence_ids)),
                )

                contradictions.append(contradiction)

        return contradictions

    # ------------------------------------------------------------------
    # Hypothesis generation
    # ------------------------------------------------------------------

    def _generate_hypotheses(
        self,
        graph: KnowledgeGraph,
        fact_gate_results: list[dict[str, Any]],
        contradictions: list[Contradiction],
    ) -> list[Hypothesis]:
        hypotheses: list[Hypothesis] = []
        contra_by_claim: dict[str, list[str]] = defaultdict(list)

        for c in contradictions:
            contra_by_claim[c.object_a].append(c.contradiction_id)
            contra_by_claim[c.object_b].append(c.contradiction_id)

        for fg in fact_gate_results:
            cid = fg["claim_id"]
            claim = graph.claims.get(cid)
            if not claim:
                continue

            if fg["state"] == ClaimState.SUPPORTED.value and not fg["contradicting_claim_ids"]:
                continue

            base = f"H-{cid}"

            hypotheses.append(
                Hypothesis(
                    hypothesis_id=f"{base}-TRUE",
                    statement=claim.statement or f"Claim {cid} is true as stated.",
                    status="ACTIVE" if fg["state"] in {ClaimState.SUPPORTED.value, ClaimState.PARTIALLY_SUPPORTED.value} else "CANDIDATE",
                    supporting_claim_ids=[cid],
                    assumptions=["Current evidence is sufficient for the exact proposition."],
                    unknowns=["Whether later evidence supersedes current state."],
                    falsification_tests=["Find authoritative primary record contradicting the claim."],
                    confidence=fg["confidence"],
                )
            )

            hypotheses.append(
                Hypothesis(
                    hypothesis_id=f"{base}-ERROR_OR_STALE",
                    statement="Claim reflects source error, outdated information, or extraction mistake.",
                    status="CANDIDATE",
                    contradicting_claim_ids=[cid],
                    assumptions=["Source records may be stale, copied, or misparsed."],
                    falsification_tests=["Retrieve original primary record and compare version/time."],
                    confidence=0.45,
                )
            )

            if has_limitation(fg["limitations"], "entity"):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-ENTITY_ISSUE",
                        statement="Claim may be affected by unresolved or incorrect entity resolution.",
                        status="CANDIDATE",
                        assumptions=["Subject/object identity may be merged or split incorrectly."],
                        falsification_tests=["Resolve official identifiers and time-bound entity control."],
                        confidence=0.40,
                    )
                )

            if has_limitation(fg["limitations"], "control/beneficial"):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-CONTROL_RIGHTS_MISSING",
                        statement="Economic ownership may not equal voting/control authority.",
                        status="CANDIDATE",
                        assumptions=["Share class voting rights are not independently verified."],
                        falsification_tests=["Retrieve authoritative share-class voting-rights record."],
                        confidence=0.50,
                    )
                )

            if has_limitation(fg["limitations"], "causal claim requires"):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-CAUSAL_OVERREACH",
                        statement="Observed sequence or correlation may not establish causation.",
                        status="CANDIDATE",
                        assumptions=["Alternative causes or confounders may exist."],
                        falsification_tests=["Obtain mechanism, intervention, or controlled comparison evidence."],
                        confidence=0.45,
                    )
                )

            if fg["independent_family_count"] < 2:
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-DEPENDENT_SOURCES",
                        statement="Apparent corroboration may derive from one upstream source family.",
                        status="CANDIDATE",
                        assumptions=["Multiple sources may share same original record/feed.",
                        ],
                        falsification_tests=["Identify truly independent primary evidence path."],
                        confidence=0.45,
                    )
                )

            if contra_by_claim.get(cid):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-CONTRADICTION_CONTEXT",
                        statement="Contradictory claim may reflect different time, scope, entity, or definition.",
                        status="CANDIDATE",
                        assumptions=["Conflict may not be factual contradiction."],
                        falsification_tests=["Compare temporal validity, entity resolution, and source pedigree."],
                        confidence=0.40,
                    )
                )

        return hypotheses

    # ------------------------------------------------------------------
    # Dual-AI style skeptic review
    # ------------------------------------------------------------------

    def _dual_ai_review(
        self,
        fact_gate_results: list[dict[str, Any]],
        contradictions: list[Contradiction],
        resolution_by_entity: dict[str, list[EntityResolutionCandidate]],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        contra_ids = {c.object_a for c in contradictions} | {c.object_b for c in contradictions}

        for fg in fact_gate_results:
            issues: list[str] = []
            cid = fg["claim_id"]

            if fg["state"] == ClaimState.SUPPORTED.value and fg["independent_family_count"] < 2 and not fg["official_primary"]:
                issues.append("insufficient independent corroboration")

            if has_limitation(fg["limitations"], "missing"):
                issues.append("provenance/evidence gaps")

            if has_limitation(fg["limitations"], "temporal conflict"):
                issues.append("temporal conflict")

            if has_limitation(fg["limitations"], "entity"):
                issues.append("entity resolution risk")

            if has_limitation(fg["limitations"], "causal claim requires"):
                issues.append("causal overreach risk")

            if has_limitation(fg["limitations"], "control/beneficial"):
                issues.append("control-rights evidence gap")

            if cid in contra_ids:
                issues.append("open contradiction")

            for eid in [cid]:
                # Placeholder; actual entity refs are in claim, but fact gate limitations cover risk.
                pass

            if not issues:
                outcome = "AGREE"
            elif fg["state"] == ClaimState.SUPPORTED.value:
                outcome = "DISAGREE"
            elif fg["state"] == ClaimState.INCONCLUSIVE.value:
                outcome = "INSUFFICIENT_EVIDENCE"
            else:
                outcome = "PARTIAL_AGREEMENT"

            results.append(
                {
                    "claim_id": cid,
                    "primary_state": fg["state"],
                    "skeptic_outcome": outcome,
                    "skeptic_issues": issues,
                    "note": "AI agreement is not independent source corroboration.",
                }
            )

        return results

    # ------------------------------------------------------------------
    # Gaps
    # ------------------------------------------------------------------

    def _derive_gaps(
        self,
        graph: KnowledgeGraph,
        fact_gate_results: list[dict[str, Any]],
        contradictions: list[Contradiction],
        resolution_candidates: list[EntityResolutionCandidate],
        facts: list[Fact],
        as_of: datetime,
    ) -> dict[str, Gap]:
        gaps: dict[str, Gap] = {}

        def add_gap(
            question: str,
            refs: list[str],
            importance: str,
            reason: str,
            source_types: list[str],
            specialist: str,
            value: str,
        ) -> None:
            gid = f"GAP-{sha256_12(question + ''.join(sorted(refs)))}"
            if gid in gaps:
                return
            gaps[gid] = Gap(
                gap_id=gid,
                question=question,
                entity_refs=sorted(set(refs)),
                importance=importance,
                reason=reason,
                recommended_source_types=source_types,
                recommended_specialist=specialist,
                expected_information_value=value,
                status="OPEN",
            )

        for fg in fact_gate_results:
            cid = fg["claim_id"]
            for lim in fg["limitations"]:
                low = lim.lower()

                if "missing evidence" in low:
                    add_gap(
                        f"Retrieve missing evidence for claim {cid}.",
                        [cid],
                        "HIGH",
                        lim,
                        ["native artifact", "primary record", "archive snapshot"],
                        "EVIDENCEINT/PROVENANCEINT",
                        "HIGH",
                    )
                elif "missing source" in low:
                    add_gap(
                        f"Resolve missing source for claim {cid}.",
                        [cid],
                        "HIGH",
                        lim,
                        ["publisher record", "upstream source", "source registry"],
                        "SOURCEINT",
                        "HIGH",
                    )
                elif "unresolved entity" in low:
                    add_gap(
                        f"Resolve entity identity for claim {cid}.",
                        [cid],
                        "MATERIAL",
                        lim,
                        ["official identifier", "registry record", "account identifier"],
                        "CORPINT/ENTITYRES",
                        "HIGH",
                    )
                elif "temporal conflict" in low:
                    add_gap(
                        f"Reverify current temporal state for claim {cid}.",
                        [cid],
                        "MATERIAL",
                        lim,
                        ["current primary record", "historical snapshot", "control-era evidence"],
                        "KNOWINT/TEMPORAL",
                        "HIGH",
                    )
                elif "control/beneficial" in low:
                    add_gap(
                        f"Retrieve authoritative voting/control-rights evidence for claim {cid}.",
                        [cid],
                        "HIGH",
                        lim,
                        ["share-class terms", "registry filing", "articles of association"],
                        "OWNERSHIPINT/CORPINT",
                        "HIGH",
                    )
                elif "causal claim requires" in low:
                    add_gap(
                        f"Obtain mechanism/intervention/alternative-cause evidence for claim {cid}.",
                        [cid],
                        "MATERIAL",
                        lim,
                        ["controlled comparison", "primary technical evidence", "timeline"],
                        "HYPOTHESISINT",
                        "HIGH",
                    )
                elif "sensitive-trait" in low:
                    add_gap(
                        f"Remove or lawfully justify sensitive-trait inference for claim {cid}.",
                        [cid],
                        "CRITICAL",
                        lim,
                        ["lawful explicit evidence", "purpose limitation review"],
                        "LEGALINT/HUMAN",
                        "HIGH",
                    )
                elif "unprovenanced" in low:
                    add_gap(
                        f"Add provenance to relationship referenced by claim {cid}.",
                        [cid],
                        "MATERIAL",
                        lim,
                        ["source record", "evidence hash", "collection log"],
                        "PROVENANCEINT",
                        "MEDIUM",
                    )

        for cand in resolution_candidates:
            if cand.state in {
                EntityResolutionState.POSSIBLE_SAME_ENTITY,
                EntityResolutionState.PROBABLE_SAME_ENTITY,
                EntityResolutionState.UNRESOLVED,
            }:
                add_gap(
                    f"Resolve entity merge candidate {cand.candidate_id}.",
                    cand.entity_ids,
                    "MATERIAL",
                    f"Entity resolution state: {cand.state.value}",
                    ["official identifiers", "multi-source verification", "human review"],
                    "ENTITYRES/HUMAN",
                    "HIGH",
                )

        for contra in contradictions:
            add_gap(
                f"Adjudicate contradiction {contra.contradiction_id}.",
                [contra.object_a, contra.object_b],
                contra.materiality,
                "Open contradiction must be preserved and resolved with primary independent evidence.",
                ["primary record", "independent source family", "temporal context"],
                "HYPOTHESISINT/SOURCEINT",
                "HIGH",
            )

        for fact in facts:
            st = staleness_state(fact.validity_to, fact.verified_at, as_of)
            if st in {Staleness.STALE, Staleness.AGING, Staleness.HISTORICAL}:
                add_gap(
                    f"Reverify stale or historical fact {fact.fact_id}.",
                    [fact.fact_id, fact.claim_id],
                    "MEDIUM",
                    f"Fact staleness state: {st.value}",
                    ["current primary record", "update notice", "correction/retraction"],
                    "KNOWINT/SOURCEINT",
                    "MEDIUM",
                )

        for rel in graph.relationships.values():
            if not rel.evidence_ids and not rel.source_ids:
                add_gap(
                    f"Add provenance to relationship {rel.relationship_id}.",
                    [rel.relationship_id],
                    "MATERIAL",
                    "Relationship lacks evidence/source provenance.",
                    ["primary record", "collection log", "source metadata"],
                    "PROVENANCEINT/EVIDENCEINT",
                    "HIGH",
                )

        return gaps

    # ------------------------------------------------------------------
    # Graph health
    # ------------------------------------------------------------------

    def _graph_health(
        self,
        graph: KnowledgeGraph,
        resolution_candidates: list[EntityResolutionCandidate],
        contradictions: list[Contradiction],
        facts: list[Fact],
        as_of: datetime,
    ) -> dict[str, Any]:
        connected_entities: set[str] = set()
        for rel in graph.relationships.values():
            connected_entities.add(rel.subject_id)
            connected_entities.add(rel.object_id)

        claim_entities: set[str] = set()
        for claim in graph.claims.values():
            if claim.subject_id:
                claim_entities.add(claim.subject_id)
            if claim.object_id:
                claim_entities.add(claim.object_id)

        orphan_entities = [
            eid
            for eid, ent in graph.entities.items()
            if eid not in connected_entities
            and eid not in claim_entities
            and not ent.provenance
        ]

        unprovenanced_relationships = [
            rid
            for rid, rel in graph.relationships.items()
            if not rel.evidence_ids and not rel.source_ids
        ]

        dangling_evidence = [
            eid
            for eid, ev in graph.evidence.items()
            if ev.source_id and ev.source_id not in graph.sources
        ]

        duplicate_candidates = [
            c.candidate_id
            for c in resolution_candidates
            if c.state in {
                EntityResolutionState.POSSIBLE_SAME_ENTITY,
                EntityResolutionState.PROBABLE_SAME_ENTITY,
            }
        ]

        open_contradictions = [c.contradiction_id for c in contradictions if c.status == "OPEN"]

        stale_facts = []
        for fact in facts:
            st = staleness_state(fact.validity_to, fact.verified_at, as_of)
            if st in {Staleness.STALE, Staleness.AGING, Staleness.HISTORICAL}:
                stale_facts.append(fact.fact_id)

        return {
            "orphan_entities": sorted(orphan_entities),
            "unprovenanced_relationships": sorted(unprovenanced_relationships),
            "dangling_evidence": sorted(dangling_evidence),
            "duplicate_entity_candidates": sorted(duplicate_candidates),
            "open_contradictions": sorted(open_contradictions),
            "stale_or_historical_facts": sorted(stale_facts),
            "predicted_relationships_created": 0,
            "notes": [
                "Graph health metrics are structural; they do not establish truth.",
                "Node/edge count is not intelligence quality.",
            ],
        }

    # ------------------------------------------------------------------
    # Query / snapshot / historical state
    # ------------------------------------------------------------------

    def _query_graph(
        self,
        graph: KnowledgeGraph,
        as_of: datetime,
        perm: PermissionContext,
    ) -> dict[str, Any]:
        entities = [asdict(e) for e in graph.entities.values() if accessible(e, perm)]
        entity_ids = {e["entity_id"] for e in entities}

        relationships = [
            asdict(r)
            for r in graph.relationships.values()
            if accessible(r, perm)
            and r.subject_id in entity_ids
            and r.object_id in entity_ids
            and is_active(r.valid_from, r.valid_to, as_of)
        ]

        claims = [
            asdict(c)
            for c in graph.claims.values()
            if accessible(c, perm)
            and (not c.subject_id or c.subject_id in entity_ids)
            and (not c.object_id or c.object_id in entity_ids)
        ]

        facts = [asdict(f) for f in graph.facts.values() if accessible(f, perm)]

        return {
            "as_of": as_of.isoformat(),
            "entities": entities,
            "relationships": relationships,
            "claims": claims,
            "facts": facts,
        }

    def _historical_states(
        self,
        graph: KnowledgeGraph,
        as_of: datetime,
        perm: PermissionContext,
    ) -> dict[str, Any]:
        active: list[dict[str, Any]] = []
        ended: list[dict[str, Any]] = []

        for rel in graph.relationships.values():
            if not accessible(rel, perm):
                continue
            row = asdict(rel)
            if is_active(rel.valid_from, rel.valid_to, as_of):
                active.append(row)
            else:
                ended.append(row)

        return {
            "as_of": as_of.isoformat(),
            "active_relationships": active,
            "ended_or_future_relationships": ended,
            "note": "Historical states remain queryable and are not erased.",
        }

    def _graph_clusters(
        self,
        graph: KnowledgeGraph,
        as_of: datetime,
        perm: PermissionContext,
    ) -> list[dict[str, Any]]:
        adj: dict[str, set[str]] = defaultdict(set)
        nodes: set[str] = set()

        for rel in graph.relationships.values():
            if not accessible(rel, perm):
                continue
            if not is_active(rel.valid_from, rel.valid_to, as_of):
                continue
            adj[rel.subject_id].add(rel.object_id)
            adj[rel.object_id].add(rel.subject_id)
            nodes.add(rel.subject_id)
            nodes.add(rel.object_id)

        visited: set[str] = set()
        clusters: list[dict[str, Any]] = []

        for node in sorted(nodes):
            if node in visited:
                continue
            stack = [node]
            component: list[str] = []
            visited.add(node)

            while stack:
                x = stack.pop()
                component.append(x)
                for y in adj.get(x, set()):
                    if y not in visited:
                        visited.add(y)
                        stack.append(y)

            if len(component) > 1:
                component = sorted(component)
                clusters.append(
                    {
                        "cluster_id": f"CLUSTER-{sha256_12(''.join(component))}",
                        "nodes": component,
                        "note": "Structural graph cluster. Not proof of common actor, organization, or campaign.",
                    }
                )

        return clusters

    # ------------------------------------------------------------------
    # ACH / falsification summaries
    # ------------------------------------------------------------------

    def _ach_summary(
        self,
        fact_gate_results: list[dict[str, Any]],
        hypotheses: list[Hypothesis],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []

        for fg in fact_gate_results:
            cid = fg["claim_id"]
            hyp_ids = [h.hypothesis_id for h in hypotheses if h.hypothesis_id.startswith(f"H-{cid}-")]
            out.append(
                {
                    "claim_id": cid,
                    "hypothesis_ids": hyp_ids,
                    "evidence_ids": fg["evidence_ids"],
                    "note": "Lightweight ACH index. Full competing-hypothesis adjudication belongs to HYPOTHESISINT.",
                }
            )

        return out

    def _falsification_summary(self, hypotheses: list[Hypothesis]) -> list[dict[str, Any]]:
        return [
            {
                "hypothesis_id": h.hypothesis_id,
                "tests": h.falsification_tests,
                "status": "NOT_TESTED",
                "note": "Falsification tests require evidence collection or specialist handoff.",
            }
            for h in hypotheses
        ]

    # ------------------------------------------------------------------
    # Recommendations / handoffs / human review
    # ------------------------------------------------------------------

    def _recommendations(
        self,
        gaps: dict[str, Gap],
        health: dict[str, Any],
        contradictions: list[Contradiction],
        resolution_candidates: list[EntityResolutionCandidate],
        graph: KnowledgeGraph,
        perm: PermissionContext,
    ) -> tuple[list[str], list[str], list[str]]:
        actions: set[str] = set()
        handoffs: set[str] = set()
        human: set[str] = set()

        for gap in gaps.values():
            actions.add(gap.question)
            if gap.recommended_specialist:
                for part in re.split(r"[/,]", gap.recommended_specialist):
                    part = part.strip()
                    if part:
                        handoffs.add(part)

        for contra in contradictions:
            actions.add(
                f"Adjudicate contradiction {contra.contradiction_id} using primary independent evidence and temporal context."
            )
            handoffs.update({"HYPOTHESISINT", "SOURCEINT"})

        for cand in resolution_candidates:
            if cand.requires_human_review:
                human.add(f"Human review entity merge candidate {cand.candidate_id}: {cand.recommended_action}.")

        if any(e.entity_type == "PersonCandidate" for e in graph.entities.values()):
            human.add("Real-person conclusions require strong identity resolution, multiple evidence types, and human review.")

        if health.get("unprovenanced_relationships"):
            actions.add("Add provenance to unprovenanced relationships before promoting derived claims.")
            handoffs.add("PROVENANCEINT")

        if health.get("dangling_evidence"):
            actions.add("Resolve dangling evidence source references.")
            handoffs.add("SOURCEINT")

        actions.update(
            {
                "Preserve original evidence and provenance; never overwrite historical states.",
                "Count independent evidence families, not URLs or repeated records.",
                "Do not promote predicted links or LLM output to canonical facts.",
                "Do not infer causation, guilt, control, or sensitive traits from graph proximity alone.",
                "Use minimum-necessary context for cloud routing; never dump full private graph.",
            }
        )

        handoffs.update({"SOURCEINT", "PROVENANCEINT", "EVIDENCEINT", "HYPOTHESISINT"})

        if not perm.can_merge_entities:
            actions.add("Entity merges are disabled; keep merge candidates unresolved pending authorized review.")

        return sorted(actions), sorted(handoffs), sorted(human)

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def analyze(self, req: KnowIntRequest) -> KnowIntResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self._empty_result(
                case_id=req.case_id,
                objective=req.objective,
                task_id=req.task_id,
                status=code,
                policy_decision=PolicyDecision.BLOCK.value,
                summary=f"POLICY_BLOCKED: {reason}",
                questions=req.questions,
                limitations=[reason],
            )
            self.memory.append(asdict(result))
            return result

        perm = req.permission
        as_of = parse_dt(req.as_of) or datetime.now(timezone.utc)
        graph = KnowledgeGraph()

        # Ingest sources.
        for source in req.sources:
            graph.add_source(source)

        # Ingest evidence.
        for evidence in req.evidence:
            if evidence.source_id and evidence.source_id not in graph.sources:
                evidence.limitations.append("source unresolved at ingestion")
            graph.add_evidence(evidence)

        # Ingest entities.
        for entity in req.entities:
            graph.add_entity(entity)

        # Ingest relationships only if endpoints resolve.
        for rel in req.relationships:
            if rel.subject_id not in graph.entities or rel.object_id not in graph.entities:
                rel.limitations.append("dangling endpoint; relationship not added to canonical graph")
                continue
            graph.add_relationship(rel)

        # Ingest events.
        for event in req.events:
            graph.add_event(event)

        # Ingest claims.
        for claim in req.claims:
            graph.add_claim(claim)

        # Ingest supplied hypotheses.
        for hypothesis in req.hypotheses:
            graph.add_hypothesis(hypothesis)

        # Ingest existing facts.
        for fact in req.existing_facts:
            graph.add_fact(fact)

        # Entity resolution.
        resolution_candidates = self._entity_resolution(graph, perm)
        resolution_by_entity: dict[str, list[EntityResolutionCandidate]] = defaultdict(list)
        for cand in resolution_candidates:
            for eid in cand.entity_ids:
                resolution_by_entity[eid].append(cand)

        # Source families.
        source_families = self._source_families(graph)

        # Fact gate.
        fact_gate_results: list[dict[str, Any]] = []
        facts: list[Fact] = []
        privacy_flags: set[str] = {
            "No sensitive-trait inference from graph structure.",
            "No real-person attribution from weak association or one-hop proximity.",
            "Minimum-necessary context only; no full private graph export to cloud.",
        }

        for claim in list(graph.claims.values()):
            fg = self._fact_gate_claim(claim, graph, perm, as_of, resolution_by_entity)
            claim.state = ClaimState(fg["state"])
            claim.confidence = fg["confidence"]
            claim.limitations = sorted(set(claim.limitations + fg["limitations"]))
            privacy_flags.update(fg.get("privacy_flags", []))
            fact_gate_results.append(fg)

            if fg["state"] == ClaimState.SUPPORTED.value and perm.can_promote_facts:
                fact = Fact(
                    fact_id=f"FACT-{sha256_12(claim.claim_id)}",
                    claim_id=claim.claim_id,
                    canonical_statement=claim.statement or f"{claim.subject_id} {claim.predicate} {claim.object_id}",
                    supporting_evidence_ids=fg["evidence_ids"],
                    supporting_source_ids=fg["source_ids"],
                    independent_family_count=fg["independent_family_count"],
                    validity_from=claim.valid_from or claim.time,
                    validity_to=claim.valid_to,
                    verification_state=VerificationState.SUPPORTED,
                    confidence=fg["confidence"],
                    verified_at=now_iso(),
                    verifier="KNOWINT_PRIMARY",
                    limitations=fg["limitations"],
                    tenant_id=claim.tenant_id,
                    case_id=claim.case_id,
                    classification=claim.classification,
                )
                graph.add_fact(fact)
                facts.append(fact)

        # Contradictions.
        contradictions = self._detect_contradictions(graph, as_of)
        for contra in contradictions:
            graph.add_contradiction(contra)

        # Hypotheses.
        generated_hypotheses = self._generate_hypotheses(graph, fact_gate_results, contradictions)
        for hyp in generated_hypotheses:
            graph.add_hypothesis(hyp)

        all_hypotheses = list(graph.hypotheses.values())

        # Dual-AI style review.
        dual_ai_results = self._dual_ai_review(fact_gate_results, contradictions, resolution_by_entity)

        # Gaps.
        gaps = self._derive_gaps(graph, fact_gate_results, contradictions, resolution_candidates, facts, as_of)
        for gap in gaps.values():
            graph.add_gap(gap)

        # Health / clusters / snapshots.
        health = self._graph_health(graph, resolution_candidates, contradictions, facts, as_of)
        clusters = self._graph_clusters(graph, as_of, perm)
        current_snapshot = self._query_graph(graph, as_of, perm)
        historical_states = self._historical_states(graph, as_of, perm)

        # Recommendations.
        next_actions, handoffs, human_review_items = self._recommendations(
            gaps=gaps,
            health=health,
            contradictions=contradictions,
            resolution_candidates=resolution_candidates,
            graph=graph,
            perm=perm,
        )

        # Source summaries.
        source_reliability = {sid: s.reliability for sid, s in graph.sources.items()}
        source_bias = {sid: s.bias for sid, s in graph.sources.items()}
        source_limitations = {sid: s.limitations for sid, s in graph.sources.items()}
        source_independence = {
            "unique_source_count": len(graph.sources),
            "independent_family_count": len(source_families),
            "families": source_families,
            "warning": "Multiple sources may derive from one upstream evidence family; count families, not URLs.",
        }

        # Provenance / support paths.
        provenance_paths = [
            {
                "evidence_id": eid,
                "source_id": ev.source_id,
                "content_hash": ev.content_hash,
                "locator": ev.locator,
                "retrieved_at": ev.retrieved_at,
            }
            for eid, ev in graph.evidence.items()
        ]

        evidence_paths = [
            {
                "claim_id": cid,
                "evidence_ids": fg["evidence_ids"],
                "source_ids": fg["source_ids"],
            }
            for cid, fg in ((fg["claim_id"], fg) for fg in fact_gate_results)
        ]

        support_paths = [
            {
                "fact_id": fid,
                "claim_id": f.claim_id,
                "evidence_ids": f.supporting_evidence_ids,
                "source_ids": f.supporting_source_ids,
                "independent_family_count": f.independent_family_count,
            }
            for fid, f in graph.facts.items()
        ]

        contradiction_paths = [asdict(c) for c in contradictions]

        # ACH / falsification.
        ach_results = self._ach_summary(fact_gate_results, all_hypotheses)
        falsification_results = self._falsification_summary(all_hypotheses)

        # Coverage.
        coverage = {
            "sources_supplied": len(graph.sources),
            "evidence_supplied": len(graph.evidence),
            "entities_supplied": len(graph.entities),
            "relationships_added": len(graph.relationships),
            "claims_assessed": len(fact_gate_results),
            "facts_created": len(graph.facts),
            "hypotheses_generated": len(all_hypotheses),
            "contradictions_open": len([c for c in contradictions if c.status == "OPEN"]),
            "live_collection_performed": False,
            "note": "KNOWINT consumed supplied objects only; it did not fetch live sources or invent missing graph structure.",
        }

        # Staleness.
        staleness: dict[str, str] = {}
        for fid, fact in graph.facts.items():
            staleness[fid] = staleness_state(fact.validity_to, fact.verified_at, as_of).value
        for rid, rel in graph.relationships.items():
            staleness[rid] = staleness_state(rel.valid_to, rel.observed_at, as_of).value

        # Status.
        if not fact_gate_results:
            status = Status.INCONCLUSIVE.value
        elif any(fg["state"] == ClaimState.DISPUTED.value for fg in fact_gate_results) or contradictions:
            status = Status.PARTIAL.value
        elif all(fg["state"] == ClaimState.SUPPORTED.value for fg in fact_gate_results):
            status = Status.SUCCEEDED.value
        else:
            status = Status.PARTIAL.value

        supported_count = sum(1 for fg in fact_gate_results if fg["state"] == ClaimState.SUPPORTED.value)
        partial_count = sum(1 for fg in fact_gate_results if fg["state"] == ClaimState.PARTIALLY_SUPPORTED.value)
        disputed_count = sum(1 for fg in fact_gate_results if fg["state"] == ClaimState.DISPUTED.value)
        inconclusive_count = sum(1 for fg in fact_gate_results if fg["state"] == ClaimState.INCONCLUSIVE.value)
        unsupported_count = sum(1 for fg in fact_gate_results if fg["state"] == ClaimState.UNSUPPORTED.value)

        summary = (
            f"KNOWINT defensive knowledge synthesis for case {req.case_id}. "
            f"Entities={len(graph.entities)}, relationships={len(graph.relationships)}, "
            f"claims={len(fact_gate_results)}. "
            f"Fact states: supported={supported_count}, partial={partial_count}, "
            f"disputed={disputed_count}, inconclusive={inconclusive_count}, unsupported={unsupported_count}. "
            "No unsourced facts, name-only merges, predicted-link promotions, or sensitive-trait inferences were created."
        )

        limitations = [
            "Rule-based local KNOWINT skeleton; not a production graph database or full multi-agent orchestrator.",
            "Does not fetch live sources, execute code, bypass permissions, or invent missing provenance.",
            "Fact-gate outputs are evidentiary and revisable, not legal truth determinations.",
            "Entity resolution is conservative; name/alias overlap alone never authorizes merge.",
            "Graph clusters and centralities are structural signals, not proof of control, guilt, or campaign membership.",
        ]

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "ontology_version": graph.ontology_version,
            "graph_version": graph.graph_version,
            "case_id": req.case_id,
            "task_id": req.task_id,
            "as_of": as_of.isoformat(),
            "source_ids": sorted(graph.sources),
            "evidence_hashes": {eid: ev.content_hash for eid, ev in graph.evidence.items()},
            "claim_states": {fg["claim_id"]: fg["state"] for fg in fact_gate_results},
            "fact_ids": sorted(graph.facts),
            "contradiction_ids": [c.contradiction_id for c in contradictions],
            "gap_ids": sorted(gaps),
            "entity_resolution_candidates": [c.candidate_id for c in resolution_candidates],
            "event_log_tail": graph.event_log[-50:],
        }

        result = KnowIntResult(
            case_id=req.case_id,
            task_id=req.task_id,
            objective=req.objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            summary=summary,
            questions=req.questions,
            graph_version=graph.graph_version,
            ontology_version=graph.ontology_version,
            source_ids=sorted(graph.sources),
            evidence_ids=sorted(graph.evidence),
            entity_ids=sorted(graph.entities),
            relationship_ids=sorted(graph.relationships),
            event_ids=sorted(graph.events),
            claim_ids=sorted(graph.claims),
            fact_ids=sorted(graph.facts),
            insight_ids=sorted(graph.insights),
            hypothesis_ids=sorted(graph.hypotheses),
            contradiction_ids=[c.contradiction_id for c in contradictions],
            gap_ids=sorted(gaps),
            entities=[asdict(e) for e in graph.entities.values()],
            entity_resolution_results=[asdict(c) for c in resolution_candidates],
            aliases=[
                {"entity_id": e.entity_id, "display_name": e.display_name, "aliases": e.aliases}
                for e in graph.entities.values()
            ],
            relationships=[asdict(r) for r in graph.relationships.values()],
            relationship_states={rid: r.state.value for rid, r in graph.relationships.items()},
            events=[asdict(e) for e in graph.events.values()],
            claims=[asdict(c) for c in graph.claims.values()],
            facts=[asdict(f) for f in graph.facts.values()],
            insights=[asdict(i) for i in graph.insights.values()],
            hypotheses=[asdict(h) for h in graph.hypotheses.values()],
            contradictions=[asdict(c) for c in contradictions],
            knowledge_gaps=[asdict(g) for g in gaps.values()],
            temporal_states={
                "as_of": as_of.isoformat(),
                "staleness": staleness,
            },
            current_snapshot=current_snapshot,
            historical_states=historical_states,
            source_reliability=source_reliability,
            source_bias=source_bias,
            source_limitations=source_limitations,
            source_families=source_families,
            source_independence=source_independence,
            provenance_paths=provenance_paths,
            evidence_paths=evidence_paths,
            support_paths=support_paths,
            contradiction_paths=contradiction_paths,
            graph_clusters=clusters,
            predicted_relationships=[],
            predicted_relationships_status="NONE_CREATED",
            fact_gate_results=fact_gate_results,
            falsification_results=falsification_results,
            ach_results=ach_results,
            dual_ai_results=dual_ai_results,
            coverage=coverage,
            staleness=staleness,
            graph_health=health,
            permission_context=asdict(perm),
            recommended_next_actions=next_actions,
            specialist_handoffs=handoffs,
            human_review_items=human_review_items,
            privacy_flags=sorted(privacy_flags),
            limitations=limitations,
            replay_manifest=replay_manifest,
            created_at=now_iso(),
        )

        self.memory.append(asdict(result))
        return result


# ======================================================================
# Demo
# ======================================================================

def demo() -> None:
    agent = KnowIntAgent(mode=Mode.LOCAL_ONLY)

    perm = PermissionContext(
        tenant_id="TENANT-1",
        case_id="KNOW-001",
        classification=Classification.INTERNAL,
        allowed_classifications=[Classification.PUBLIC, Classification.INTERNAL],
        purpose="defensive_knowledge_synthesis",
        authorized=True,
        can_write=True,
        can_merge_entities=False,
        can_promote_facts=True,
    )

    sources = [
        Source(
            source_id="SRC-REG",
            source_type="OFFICIAL_RECORD",
            publisher="National Corporate Registry",
            collection_method="AUTHORIZED_EXPORT",
            reliability=0.92,
            independence_group="REG-1",
            limitations=["Registry may lag corporate updates."],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Source(
            source_id="SRC-COMM",
            source_type="COMMERCIAL_PROVIDER",
            publisher="Commercial Ownership Database",
            collection_method="API",
            reliability=0.60,
            upstream_source="SRC-REG",
            independence_group="REG-1",
            limitations=["Derived from registry filing; not independent from SRC-REG for ownership fact."],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Source(
            source_id="SRC-FILING",
            source_type="COMPANY_FILING",
            publisher="Company B",
            collection_method="PUBLIC_FILING",
            reliability=0.85,
            independence_group="FILING-1",
            limitations=["Self-reporting incentive may affect framing."],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
    ]

    evidence = [
        Evidence(
            evidence_id="EV-REG",
            source_id="SRC-REG",
            artifact_type="REGISTRY_RECORD",
            content=(
                "Company A, registry id 123, holds 60% of Class X shares in "
                "Company B, registry id 456, as of 2026-01-01."
            ),
            locator="registry-record:123->456",
            retrieved_at="2026-10-08T12:00:00Z",
            published_at="2026-01-01T00:00:00Z",
            collector="KNOWINT-INGEST",
            parser="registry-parser-v1",
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Evidence(
            evidence_id="EV-COMM",
            source_id="SRC-COMM",
            artifact_type="API_RESPONSE",
            content=(
                "Commercial database reports Company A holds 60% Class X shares in Company B; "
                "source citation: National Corporate Registry."
            ),
            locator="api:ownership/A-B",
            retrieved_at="2026-10-08T12:05:00Z",
            collector="KNOWINT-INGEST",
            parser="commercial-api-parser-v1",
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Evidence(
            evidence_id="EV-FILING",
            source_id="SRC-FILING",
            artifact_type="CORPORATE_FILING",
            content=(
                "Company B filing describes Class X economic participation but does not specify "
                "voting rights attached to Class X."
            ),
            locator="filing:section-4",
            retrieved_at="2026-10-08T12:10:00Z",
            collector="KNOWINT-INGEST",
            parser="filing-parser-v1",
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
            metadata={"topic": "voting_rights"},
        ),
    ]

    entities = [
        Entity(
            entity_id="ENT-A",
            entity_type="Organization",
            display_name="Company A",
            identifiers={"official_registry": "123"},
            provenance=["EV-REG"],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Entity(
            entity_id="ENT-B",
            entity_type="Organization",
            display_name="Company B",
            identifiers={"official_registry": "456"},
            provenance=["EV-REG"],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Entity(
            entity_id="ENT-P",
            entity_type="PersonCandidate",
            display_name="Person P",
            identifiers={"employee_id": "P-99"},
            sensitivity=["PERSON"],
            provenance=["EV-REG"],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.INTERNAL,
        ),
    ]

    relationships = [
        Relationship(
            relationship_id="REL-OWN",
            subject_id="ENT-A",
            predicate="HOLDS_SHARES_OF",
            object_id="ENT-B",
            state=RelationshipState.CLAIMED,
            valid_from="2026-01-01T00:00:00Z",
            observed_at="2026-10-08T12:00:00Z",
            source_ids=["SRC-REG", "SRC-COMM"],
            evidence_ids=["EV-REG", "EV-COMM"],
            verification_state=VerificationState.CLAIMED,
            confidence=0.80,
            qualifiers={"percent": 60, "share_class": "X"},
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Relationship(
            relationship_id="REL-DIR-A",
            subject_id="ENT-P",
            predicate="DIRECTOR_OF",
            object_id="ENT-A",
            state=RelationshipState.OBSERVED,
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2026-06-01T00:00:00Z",
            observed_at="2026-10-08T12:00:00Z",
            source_ids=["SRC-REG"],
            evidence_ids=["EV-REG"],
            verification_state=VerificationState.SUPPORTED,
            confidence=0.85,
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.INTERNAL,
        ),
        Relationship(
            relationship_id="REL-DIR-B",
            subject_id="ENT-P",
            predicate="DIRECTOR_OF",
            object_id="ENT-B",
            state=RelationshipState.OBSERVED,
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2026-06-01T00:00:00Z",
            observed_at="2026-10-08T12:00:00Z",
            source_ids=["SRC-REG"],
            evidence_ids=["EV-REG"],
            verification_state=VerificationState.SUPPORTED,
            confidence=0.85,
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.INTERNAL,
        ),
    ]

    claims = [
        Claim(
            claim_id="CLM-OWN",
            statement="Company A holds 60% of Class X shares in Company B as of 2026-01-01.",
            subject_id="ENT-A",
            predicate="HOLDS_SHARES_OF",
            object_id="ENT-B",
            claim_type="FACTUAL",
            valid_from="2026-01-01T00:00:00Z",
            source_ids=["SRC-REG", "SRC-COMM"],
            evidence_ids=["EV-REG", "EV-COMM"],
            relationship_ids=["REL-OWN"],
            qualifiers={"percent": 60, "share_class": "X"},
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Claim(
            claim_id="CLM-CONTROL",
            statement="Company A controls Company B.",
            subject_id="ENT-A",
            predicate="CONTROLS",
            object_id="ENT-B",
            claim_type="FACTUAL",
            valid_from="2026-01-01T00:00:00Z",
            source_ids=["SRC-REG", "SRC-COMM"],
            evidence_ids=["EV-REG", "EV-COMM"],
            relationship_ids=["REL-OWN"],
            qualifiers={},
            limitations=["Voting/control rights not independently verified."],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.PUBLIC,
        ),
        Claim(
            claim_id="CLM-DIR-CURRENT",
            statement="Person P is currently a director of Company B as of 2026-10-09.",
            subject_id="ENT-P",
            predicate="DIRECTOR_OF",
            object_id="ENT-B",
            claim_type="FACTUAL",
            valid_from="2026-10-09T00:00:00Z",
            source_ids=["SRC-REG"],
            evidence_ids=["EV-REG"],
            relationship_ids=["REL-DIR-B"],
            tenant_id="TENANT-1",
            case_id="KNOW-001",
            classification=Classification.INTERNAL,
        ),
    ]

    req = KnowIntRequest(
        case_id="KNOW-001",
        task_id="TASK-001",
        objective=(
            "Construct a temporal, provenance-aware knowledge graph for corporate ownership/control "
            "and directorship claims, conservatively promoting facts and preserving gaps/contradictions."
        ),
        questions=[
            "Does Company A hold economic ownership in Company B?",
            "Does Company A control Company B?",
            "Is Person P currently a director of Company B?",
            "Which sources are independent?",
            "What remains unknown?",
        ],
        authorization={"authorized": True, "purpose": "defensive_knowledge_synthesis"},
        permission=perm,
        sources=sources,
        evidence=evidence,
        entities=entities,
        relationships=relationships,
        claims=claims,
        as_of="2026-10-09T00:00:00Z",
        scope={"time_range": "2025-01-01 to 2026-10-09"},
    )

    res = agent.analyze(req)

    print("=== KNOWINT SUMMARY ===")
    print(res.summary)
    print()

    print("Claim fact-gate states:")
    for fg in res.fact_gate_results:
        print(
            f"  {fg['claim_id']}: state={fg['state']}, "
            f"independent_families={fg['independent_family_count']}, "
            f"avg_rel={fg['average_source_reliability']}, "
            f"max_rel={fg['max_source_reliability']}, "
            f"official_primary={fg['official_primary']}"
        )
        if fg["limitations"]:
            print("    limitations:")
            for lim in fg["limitations"]:
                print("      -", lim)
    print()

    print("Facts created:")
    for f in res.facts:
        print(f"  {f['fact_id']}: {f['canonical_statement']}")
    print()

    print("Source independence:")
    print(f"  unique_sources={res.source_independence['unique_source_count']}")
    print(f"  independent_families={res.source_independence['independent_family_count']}")
    print(f"  families={res.source_independence['families']}")
    print()

    print("Knowledge gaps:")
    for g in res.knowledge_gaps[:8]:
        print(f"  {g['gap_id']}: {g['question']} -> {g['recommended_specialist']}")
    print()

    print("Dual-AI skeptic review:")
    for d in res.dual_ai_results:
        print(f"  {d['claim_id']}: {d['skeptic_outcome']} issues={d['skeptic_issues']}")
    print()

    print("Graph health:")
    print(f"  open_contradictions={res.graph_health['open_contradictions']}")
    print(f"  unprovenanced_relationships={res.graph_health['unprovenanced_relationships']}")
    print(f"  duplicate_entity_candidates={res.graph_health['duplicate_entity_candidates']}")
    print()

    print("Recommended next actions (first 8):")
    for action in res.recommended_next_actions[:8]:
        print("  -", action)
    print()

    print("Human review items:")
    for h in res.human_review_items:
        print("  -", h)
    print()

    # Blocked example: prohibited knowledge action.
    blocked_req = KnowIntRequest(
        case_id="KNOW-002",
        task_id="TASK-002",
        objective="Merge entities by name and infer religion from associations, then send full graph to cloud.",
        authorization={"authorized": True},
        permission=PermissionContext(authorized=True),
        sources=[],
        evidence=[],
        entities=[],
        relationships=[],
        claims=[],
    )

    blocked = agent.analyze(blocked_req)

    print("=== BLOCKED EXAMPLE ===")
    print("Status:", blocked.status)
    print("Summary:", blocked.summary)
    print("Limitations:", blocked.limitations)


if __name__ == "__main__":
    demo()