# TRACEATLAS — FUSIONINT AI EMPLOYEE
# Single-file defensive Python core for Cross-Domain Intelligence Fusion.
#
# PRIMARY BOUNDARY:
# FUSE INTELLIGENCE, DO NOT FABRICATE CERTAINTY OR OVERRIDE SPECIALIST/POLICY BOUNDARIES.
#
# This code does NOT:
# - invent evidence, sources, entities, relationships, events, timestamps, locations, or attribution
# - average contradictory facts into fake precision
# - equate module count / AI agreement / duplicate reports with corroboration
# - equate infrastructure association with ownership/control
# - generate attack plans, targeting, surveillance, autonomous enforcement, or policy bypass
# - leak across tenants/cases without authorization
# - send LOCAL_ONLY evidence to cloud models

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


TOOL_VERSION = "FUSIONINT-PY-0.1"


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


class VerificationState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class EntityResolutionState(str, Enum):
    VERIFIED_MATCH = "VERIFIED_MATCH"
    PROBABLE_MATCH = "PROBABLE_MATCH"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    UNRESOLVED = "UNRESOLVED"
    LIKELY_DISTINCT = "LIKELY_DISTINCT"
    VERIFIED_DISTINCT = "VERIFIED_DISTINCT"


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


class ContradictionType(str, Enum):
    IDENTITY = "IDENTITY_CONTRADICTION"
    TEMPORAL = "TEMPORAL_CONTRADICTION"
    LOCATION = "LOCATION_CONTRADICTION"
    RELATIONSHIP = "RELATIONSHIP_CONTRADICTION"
    SOURCE = "SOURCE_CONTRADICTION"
    TECHNICAL = "TECHNICAL_CONTRADICTION"
    FINANCIAL = "FINANCIAL_CONTRADICTION"
    OWNERSHIP = "OWNERSHIP_CONTRADICTION"
    EVENT = "EVENT_CONTRADICTION"
    ATTRIBUTION = "ATTRIBUTION_CONTRADICTION"


class Materiality(str, Enum):
    CRITICAL = "CRITICAL"
    MATERIAL = "MATERIAL"
    MODERATE = "MODERATE"
    MINOR = "MINOR"
    COSMETIC = "COSMETIC"
    UNKNOWN = "UNKNOWN"


class EvidenceStrength(str, Enum):
    PRIMARY_DIRECT = "PRIMARY_DIRECT"
    PRIMARY_INDIRECT = "PRIMARY_INDIRECT"
    SECONDARY_INDEPENDENT = "SECONDARY_INDEPENDENT"
    SECONDARY_DEPENDENT = "SECONDARY_DEPENDENT"
    ANALYTICAL_INFERENCE = "ANALYTICAL_INFERENCE"
    SOURCE_CLAIM = "SOURCE_CLAIM"
    UNVERIFIED = "UNVERIFIED"


class SourceIndependence(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    PARTIALLY_DEPENDENT = "PARTIALLY_DEPENDENT"
    DEPENDENT = "DEPENDENT"
    UNKNOWN = "UNKNOWN"


class KnowledgeState(str, Enum):
    KNOWN = "KNOWN"
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    UNRESOLVED_ENTITY = "UNRESOLVED_ENTITY"
    UNRESOLVED_RELATIONSHIP = "UNRESOLVED_RELATIONSHIP"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    UNSEARCHED_RELEVANT_SOURCE = "UNSEARCHED_RELEVANT_SOURCE"


OFFICIAL_PRIMARY_TYPES = {
    "OFFICIAL_RECORD",
    "OFFICIAL_SOURCE",
    "GOVERNMENT_SOURCE",
    "REGULATORY_SOURCE",
    "COURT_SOURCE",
    "COMPANY_FILING",
    "PUBLIC_SENSOR",
}

STRONG_IDENTIFIER_KEYS = {
    "official_registry",
    "registration_number",
    "legal_entity_id",
    "lei",
    "vat",
    "domain",
    "ip",
    "asn",
    "account_id",
    "wallet_address",
    "crypto_address",
    "certificate_serial",
    "serial_number",
    "imei",
    "shipment_id",
    "transaction_id",
}

OWNERSHIP_PREDICATES = {
    "OWNS",
    "LEGAL_OWNS",
    "CONTROLS",
    "EFFECTIVELY_CONTROLS",
    "BENEFICIALLY_OWNS",
    "MAJORITY_CONTROL_OF",
}

USE_OPERATION_PREDICATES = {
    "USES_DOMAIN",
    "OPERATES_DOMAIN",
    "OFFICIAL_WEBSITE_OF",
    "BRAND_DOMAIN",
    "USES_SERVICE",
    "USES_ACCOUNT",
}

INFRA_PREDICATES = {
    "RESOLVES_TO",
    "HOSTED_ON",
    "HOSTED_BY",
    "ALLOCATED_TO",
    "ANNOUNCED_BY",
    "DEPENDS_ON",
    "USES_PROVIDER",
}

ATTRIBUTION_PREDICATES = {
    "ATTRIBUTED_TO",
    "RESPONSIBLE_FOR",
    "OPERATED_BY",
    "CONTROLLED_BY",
}

CAUSAL_PREDICATES = {
    "CAUSED_BY",
    "LED_TO",
    "RESULTED_IN",
}

REQUIRED_DOMAINS_BY_PREDICATE: dict[str, set[str]] = {
    "OWNERSHIP": {"CORPINT", "OWNERSHIPINT", "LEGALINT", "FININT"},
    "USE_OPERATION": {"CORPINT", "OWNERSHIPINT", "WEBINT", "ARCHIVEINT", "DOMAININT", "BRANDINT"},
    "DNS": {"DNSINT", "DOMAININT", "NETINT"},
    "INFRA": {"IPINT", "INFRAINT", "CLOUDINT", "ASNINT", "NETINT"},
    "ATTRIBUTION": {"THREATACTORINT", "CTI", "CAMPAIGNINT", "CYBINT"},
    "CAUSAL": {"HYPOTHESISINT", "CYBINT", "CTI", "MALINT", "VULNINT"},
}

BLOCK_PHRASES = [
    "attack plan",
    "operational attack",
    "targeting solution",
    "weapon target",
    "surveillance target package",
    "private-person tracking",
    "track private person",
    "covert surveillance",
    "autonomous enforcement",
    "freeze assets",
    "disable accounts",
    "sanctions evasion",
    "credential abuse",
    "malware deployment",
    "infrastructure compromise",
    "fabricate evidence",
    "invent source",
    "invent entity",
    "invent relationship",
    "average contradictory facts",
    "average contradiction",
    "bypass policy",
    "bypass acl",
    "cross tenant leak",
    "cross-tenant leak",
    "override specialist boundary",
    "public accusation",
    "dox",
]

INJECTION_PATTERNS = [
    r"ignore (previous|all|above) (instructions|prompt)",
    r"system prompt",
    r"change (conclusion|verdict|answer)",
    r"mark (this|this source) as (trusted|verified)",
    r"delete (contradiction|evidence)",
    r"hide (contradiction|source dependency)",
]


# ======================================================================
# Utilities
# ======================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(x)))


def mean(values: list[float], default: float = 0.0) -> float:
    if not values:
        return default
    return sum(values) / len(values)


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


def norm_text(value: Any) -> str:
    value = unicodedata.normalize("NFKC", str(value or ""))
    value = value.lower()
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"[^a-z0-9\s]", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


STOPWORDS = {
    "a", "an", "the", "was", "were", "is", "are", "be", "been", "being",
    "of", "in", "on", "at", "by", "for", "with", "about", "against",
    "between", "into", "through", "during", "before", "after", "above",
    "below", "to", "from", "up", "down", "out", "off", "over", "under",
    "again", "further", "then", "once", "here", "there", "when", "where",
    "why", "how", "all", "any", "both", "each", "few", "more", "most",
    "other", "some", "such", "no", "nor", "not", "only", "own", "same",
    "so", "than", "too", "very", "can", "will", "just", "should", "now",
    "did", "does", "doing", "have", "has", "had", "having", "do", "done",
    "it", "its", "this", "that", "these", "those", "i", "me", "my",
    "we", "our", "you", "your", "he", "him", "his", "she", "her",
}


def tokenize(value: Any) -> list[str]:
    words = norm_text(value).split()
    return [w for w in words if w not in STOPWORDS and len(w) > 1]


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


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
            m = re.fullmatch(r"(\d{4})", s)
            if m:
                dt = datetime(int(m.group(1)), 1, 1, tzinfo=timezone.utc)
            else:
                return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def interval_for_value(value: Optional[str]) -> tuple[Optional[datetime], Optional[datetime]]:
    dt = parse_dt(value)
    if not dt:
        return None, None

    s = str(value or "").strip()
    if re.fullmatch(r"\d{4}", s):
        start = dt.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        end = dt.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
        return start, end

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return (
            dt.replace(hour=0, minute=0, second=0, microsecond=0),
            dt.replace(hour=23, minute=59, second=59, microsecond=999999),
        )

    return dt, dt


def intervals_overlap(
    a_start: Optional[datetime],
    a_end: Optional[datetime],
    b_start: Optional[datetime],
    b_end: Optional[datetime],
) -> bool:
    if a_end and b_start and a_end < b_start:
        return False
    if b_end and a_start and b_end < a_start:
        return False
    return True


def detect_injection(text: str) -> bool:
    low = str(text or "").lower()
    return any(re.search(p, low) for p in INJECTION_PATTERNS)


def excerpt(text: Any, limit: int = 180) -> str:
    text = norm_text(text)
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: str, b: str) -> str:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        if ra < rb:
            self.parent[rb] = ra
            return ra
        self.parent[ra] = rb
        return rb


# ======================================================================
# Data models
# ======================================================================

@dataclass
class PermissionContext:
    tenant_id: str = "default"
    case_id: str = ""
    classification: str = "INTERNAL"
    allowed_classifications: list[str] = field(default_factory=lambda: ["PUBLIC", "INTERNAL"])
    authorized: bool = False
    local_only_required: bool = False
    can_use_cloud: bool = False
    can_merge_entities: bool = False
    can_cross_case: bool = False
    purpose: str = ""


@dataclass
class Source:
    source_id: str
    source_name: str = ""
    source_type: str = "UNKNOWN"
    publisher: str = ""
    collector: str = ""
    upstream_source_ids: list[str] = field(default_factory=list)
    publication_time: str = ""
    retrieval_time: str = ""
    reliability: float = 0.5
    bias: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    independence_group: str = ""
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""
    local_only: bool = False


@dataclass
class Evidence:
    evidence_id: str
    case_id: str = ""
    source_id: str = ""
    domain: str = "UNKNOWN"
    artifact_reference: str = ""
    content: Optional[str] = None
    content_hash: str = ""
    retrieved_at: str = ""
    observed_at: str = ""
    event_time_candidate: str = ""
    source_type: str = "UNKNOWN"
    classification: str = "PUBLIC"
    authorization_context: str = ""
    parser_version: str = ""
    normalizer_version: str = ""
    integrity_state: str = "UNKNOWN"
    limitations: list[str] = field(default_factory=list)
    tenant_id: str = "default"


@dataclass
class Observation:
    observation_id: str
    evidence_id: str = ""
    source_id: str = ""
    domain: str = "UNKNOWN"
    observer: str = "ANALYST"
    statement: str = ""
    entity_refs: list[str] = field(default_factory=list)
    time_start: str = ""
    time_end: str = ""
    location: str = ""
    confidence: float = 0.5
    limitations: list[str] = field(default_factory=list)
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""


@dataclass
class Claim:
    claim_id: str
    subject: str = ""
    predicate: str = ""
    object_value: str = ""
    statement: str = ""
    source_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    domain: str = "UNKNOWN"
    time_start: str = ""
    time_end: str = ""
    location: str = ""
    claim_type: str = "FACTUAL"
    verification_state: str = VerificationState.INCONCLUSIVE.value
    confidence: float = 0.5
    limitations: list[str] = field(default_factory=list)
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""


@dataclass
class Entity:
    entity_id: str
    entity_type: str = "UNKNOWN"
    display_name: str = ""
    aliases: list[str] = field(default_factory=list)
    identifiers: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    valid_from: str = ""
    valid_to: str = ""
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""


@dataclass
class Relationship:
    relationship_id: str
    subject_id: str
    predicate: str
    object_id: str
    valid_from: str = ""
    valid_to: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    state: str = RelationshipState.CLAIMED.value
    confidence: float = 0.5
    limitations: list[str] = field(default_factory=list)
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""


@dataclass
class Event:
    event_id: str
    event_type: str = "UNKNOWN"
    participants: list[str] = field(default_factory=list)
    time_start: str = ""
    time_end: str = ""
    location: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    status: str = "CLAIMED"
    limitations: list[str] = field(default_factory=list)
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""


@dataclass
class SpecialistResult:
    result_id: str
    domain: str
    summary: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    claim_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: list[str] = field(default_factory=list)
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""


@dataclass
class Contradiction:
    contradiction_id: str
    contradiction_type: str = ContradictionType.RELATIONSHIP.value
    objects: list[str] = field(default_factory=list)
    values: list[str] = field(default_factory=list)
    materiality: str = Materiality.MODERATE.value
    possible_explanations: list[str] = field(default_factory=list)
    resolution_state: str = "UNRESOLVED"
    required_followup: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    classification: str = "PUBLIC"
    tenant_id: str = "default"
    case_id: str = ""


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    status: str = "PROPOSED"
    supporting_claim_ids: list[str] = field(default_factory=list)
    opposing_claim_ids: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    falsification_conditions: list[str] = field(default_factory=list)
    confidence: float = 0.5
    domain_dependencies: list[str] = field(default_factory=list)


@dataclass
class Assumption:
    assumption_id: str
    statement: str
    dependent_claim_ids: list[str] = field(default_factory=list)
    status: str = "OPEN"
    criticality: str = "IMPORTANT"


@dataclass
class Gap:
    gap_id: str
    question: str
    importance: str = "MEDIUM"
    domains_required: list[str] = field(default_factory=list)
    recommended_specialist: str = ""
    expected_information_value: str = "MEDIUM"
    blocking_state: str = "NON_BLOCKING"
    status: str = "OPEN"


@dataclass
class EntityResolutionCandidate:
    candidate_id: str
    entity_ids: list[str]
    state: str
    score: float
    matched_features: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    recommended_action: str = "REVIEW"
    requires_human_review: bool = True


@dataclass
class FusionRequest:
    case_id: str
    objective: str
    task_id: str = ""
    priority_questions: list[str] = field(default_factory=list)
    authorization: dict[str, Any] = field(default_factory=dict)
    permission: PermissionContext = field(default_factory=PermissionContext)
    scope: dict[str, Any] = field(default_factory=dict)
    time_range: dict[str, str] = field(default_factory=dict)
    sources: list[Source] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    specialist_results: list[SpecialistResult] = field(default_factory=list)
    contradictions: list[Contradiction] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)


@dataclass
class FusionResult:
    case_id: str
    task_id: str
    objective: str
    status: str
    policy_decision: str
    summary: str

    priority_questions: list[str] = field(default_factory=list)
    domains_used: list[str] = field(default_factory=list)
    specialist_results: list[dict[str, Any]] = field(default_factory=list)

    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    evidence_families: dict[str, list[str]] = field(default_factory=dict)
    source_pedigree: dict[str, list[str]] = field(default_factory=dict)
    source_independence: dict[str, Any] = field(default_factory=dict)

    entities: list[dict[str, Any]] = field(default_factory=list)
    entity_resolution_results: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)

    claims: list[dict[str, Any]] = field(default_factory=list)
    candidate_facts: list[dict[str, Any]] = field(default_factory=list)
    supported_facts: list[dict[str, Any]] = field(default_factory=list)
    partial_facts: list[dict[str, Any]] = field(default_factory=list)
    disputed_facts: list[dict[str, Any]] = field(default_factory=list)
    unsupported_claims: list[dict[str, Any]] = field(default_factory=list)

    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    competing_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    contradiction_resolutions: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[dict[str, Any]] = field(default_factory=list)

    knowledge_states: dict[str, str] = field(default_factory=dict)
    knowledge_gaps: list[dict[str, Any]] = field(default_factory=list)
    cross_domain_correlations: list[dict[str, Any]] = field(default_factory=list)
    orthogonal_evidence: list[dict[str, Any]] = field(default_factory=list)
    stale_evidence: list[str] = field(default_factory=list)
    superseded_evidence: list[str] = field(default_factory=list)

    confidence_assessments: dict[str, float] = field(default_factory=dict)
    verification_results: list[dict[str, Any]] = field(default_factory=list)

    policy_flags: list[str] = field(default_factory=list)
    privacy_flags: list[str] = field(default_factory=list)
    safety_flags: list[str] = field(default_factory=list)
    human_review_flags: list[str] = field(default_factory=list)

    recommended_next_actions: list[str] = field(default_factory=list)
    specialist_handoffs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    replay_manifest: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)


# ======================================================================
# FUSIONINT agent
# ======================================================================

class FusionIntAgent:
    """
    Defensive FUSIONINT core.

    Consumes supplied specialist/domain outputs and fuses them into a
    source-aware, entity-aware, temporal, contradiction-preserving
    intelligence picture.

    It does not replace domain specialists, invent evidence, average
    contradictions, or override policy/safety boundaries.
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Policy / authorization
    # ------------------------------------------------------------------

    def policy_check(self, req: FusionRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                req.task_id,
                " ".join(req.priority_questions),
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
                json.dumps(asdict(req.permission), default=str),
            ]
        ).lower()

        if not req.permission.authorized:
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_AUTHORIZATION.value,
                "FUSIONINT requires explicit authorized permission context.",
            )

        if req.authorization.get("authorized") is False:
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_AUTHORIZATION.value,
                "Authorization explicitly denied.",
            )

        for phrase in BLOCK_PHRASES:
            if phrase in blob:
                return (
                    PolicyDecision.BLOCK,
                    Status.BLOCKED_POLICY.value,
                    f"Prohibited fusion action requested: {phrase}",
                )

        if req.scope.get("cross_tenant") or req.scope.get("bypass_acl"):
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_PERMISSION.value,
                "Cross-tenant retrieval or ACL bypass is prohibited.",
            )

        if req.scope.get("autonomous_external_action"):
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_POLICY.value,
                "Autonomous external enforcement/action is prohibited.",
            )

        if req.scope.get("send_to_cloud") and (
            req.permission.local_only_required
            or any(s.local_only for s in req.sources)
            or any(e.classification == "LOCAL_ONLY" for e in req.evidence)
        ):
            return (
                PolicyDecision.BLOCK,
                Status.BLOCKED_PRIVACY.value,
                "LOCAL_ONLY evidence must not be sent to cloud models.",
            )

        return PolicyDecision.ALLOW, "", ""

    def blocked_result(self, req: FusionRequest, code: str, reason: str) -> FusionResult:
        return FusionResult(
            case_id=req.case_id,
            task_id=req.task_id,
            objective=req.objective,
            status=code,
            policy_decision=PolicyDecision.BLOCK.value,
            summary=f"POLICY_BLOCKED: {reason}",
            priority_questions=req.priority_questions,
            knowledge_states={},
            recommended_next_actions=[
                "Reframe request as authorized, defensive, evidence-first cross-domain fusion."
            ],
            policy_flags=[reason],
            privacy_flags=[reason],
            safety_flags=[reason],
            limitations=[reason],
            replay_manifest={},
            created_at=now_iso(),
        )

    # ------------------------------------------------------------------
    # Access control
    # ------------------------------------------------------------------

    def _accessible(self, obj: Any, perm: PermissionContext) -> bool:
        tenant = getattr(obj, "tenant_id", "default")
        if perm.tenant_id != "*" and tenant != perm.tenant_id:
            return False

        case = getattr(obj, "case_id", "")
        cls = getattr(obj, "classification", "PUBLIC")

        if case and perm.case_id and case != perm.case_id:
            if cls != "PUBLIC" or not perm.can_cross_case:
                return False

        if cls not in perm.allowed_classifications:
            return False

        return True

    # ------------------------------------------------------------------
    # Normalization / families
    # ------------------------------------------------------------------

    def _normalize_sources(self, sources: list[Source], perm: PermissionContext) -> dict[str, Source]:
        out: dict[str, Source] = {}
        for s in sources:
            if not self._accessible(s, perm):
                continue
            out[s.source_id] = s
        return out

    def _source_family(self, source: Optional[Source]) -> str:
        if not source:
            return "UNKNOWN"
        if source.upstream_source_ids:
            return source.upstream_source_ids[0]
        return source.independence_group or source.source_id

    def _source_pedigree(self, source_map: dict[str, Source]) -> dict[str, list[str]]:
        pedigree: dict[str, list[str]] = {}
        for sid, source in source_map.items():
            chain = [sid]
            cur = source
            seen = {sid}
            while cur and cur.upstream_source_ids:
                nxt = cur.upstream_source_ids[0]
                if nxt in seen:
                    chain.append(f"CYCLE:{nxt}")
                    break
                chain.append(nxt)
                seen.add(nxt)
                cur = source_map.get(nxt)
            pedigree[sid] = chain
        return pedigree

    def _normalize_evidence(
        self,
        evidence: list[Evidence],
        source_map: dict[str, Source],
        perm: PermissionContext,
    ) -> tuple[list[Evidence], dict[str, str], dict[str, str], list[dict[str, Any]], list[dict[str, Any]]]:
        prepared: list[Evidence] = []

        for orig in evidence:
            if not self._accessible(orig, perm):
                continue

            ev = Evidence(**asdict(orig))

            if ev.source_id and ev.source_id not in source_map:
                ev.limitations.append("source unresolved")

            if ev.content is not None:
                computed = hash_content(ev.content)
                if not ev.content_hash:
                    ev.content_hash = computed
                elif ev.content_hash != computed:
                    ev.limitations.append("provided content hash does not match supplied content")
                    ev.integrity_state = "INTEGRITY_CHANGED_UNEXPLAINED"
                else:
                    ev.integrity_state = "INTEGRITY_VERIFIED"
            else:
                if ev.content_hash:
                    ev.integrity_state = "INTEGRITY_UNVERIFIED"
                    ev.limitations.append("content hash supplied but content unavailable for verification")
                else:
                    ev.integrity_state = "UNKNOWN"
                    ev.limitations.append("no content hash available")

            if detect_injection(ev.content or ev.artifact_reference):
                ev.limitations.append("prompt-injection candidate in evidence text; treated as untrusted data")

            prepared.append(ev)

        ev_map = {ev.evidence_id: ev for ev in prepared}

        # Exact duplicates.
        duplicate_groups: list[dict[str, Any]] = []
        by_hash: dict[str, list[str]] = defaultdict(list)
        for ev in prepared:
            if ev.content_hash:
                by_hash[ev.content_hash].append(ev.evidence_id)

        uf = UnionFind()
        for ev in prepared:
            uf.add(ev.evidence_id)

        for h, ids in by_hash.items():
            if len(ids) > 1:
                ids_sorted = sorted(ids)
                duplicate_groups.append(
                    {
                        "basis": "identical_content_hash",
                        "hash": h,
                        "evidence_ids": ids_sorted,
                        "note": "Exact duplicates are one evidence family, not independent corroboration.",
                    }
                )
                for x in ids_sorted[1:]:
                    uf.union(ids_sorted[0], x)

        # Near duplicates by normalized text.
        near_groups: list[dict[str, Any]] = []
        tokens = {
            ev.evidence_id: set(tokenize(ev.content or ev.artifact_reference or ev.evidence_id))
            for ev in prepared
        }
        ids = list(ev_map)
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = ids[i], ids[j]
                ta, tb = tokens[a], tokens[b]
                if len(ta) < 8 or len(tb) < 8:
                    continue
                sim = jaccard(ta, tb)
                if sim >= 0.92:
                    near_groups.append(
                        {
                            "basis": "normalized_text_jaccard",
                            "evidence_ids": sorted([a, b]),
                            "similarity": round(sim, 3),
                            "note": "Near-duplicate evidence may reflect repost/syndication/derivation.",
                        }
                    )
                    uf.union(a, b)

        roots = {eid: uf.find(eid) for eid in ev_map}
        evidence_families: dict[str, list[str]] = defaultdict(list)
        for eid, root in roots.items():
            evidence_families[root].append(eid)

        return prepared, roots, {k: sorted(v) for k, v in evidence_families.items()}, duplicate_groups, near_groups

    # ------------------------------------------------------------------
    # Entity resolution
    # ------------------------------------------------------------------

    def _entity_resolution(
        self,
        entities: list[Entity],
        evidence_map: dict[str, Evidence],
        perm: PermissionContext,
    ) -> list[EntityResolutionCandidate]:
        candidates: list[EntityResolutionCandidate] = []
        by_type: dict[str, list[Entity]] = defaultdict(list)

        accessible_entities = [e for e in entities if self._accessible(e, perm)]
        for ent in accessible_entities:
            by_type[ent.entity_type.upper()].append(ent)

        for etype, group in by_type.items():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a, b = group[i], group[j]
                    score = 0.0
                    matched: list[str] = []
                    conflicts: list[str] = []

                    common_keys = set(a.identifiers) & set(b.identifiers)
                    for key in common_keys:
                        av = str(a.identifiers.get(key, "")).strip().lower()
                        bv = str(b.identifiers.get(key, "")).strip().lower()
                        if not av or not bv:
                            continue
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
                        score = max(score, 0.38)
                        matched.append("name_or_alias_overlap")

                    # Temporal incompatibility can reduce merge likelihood.
                    a_s, a_e = interval_for_value(a.valid_from), interval_for_value(a.valid_to)
                    b_s, b_e = interval_for_value(b.valid_from), interval_for_value(b.valid_to)
                    if (a_s[0] or a_e[1]) and (b_s[0] or b_e[1]):
                        if not intervals_overlap(a_s[0] or a_s[1], a_e[0] or a_e[1], b_s[0] or b_s[1], b_e[0] or b_e[1]):
                            conflicts.append("temporal_non_overlap")
                            score = min(score, 0.30)

                    if any(c.startswith("strong_identifier_mismatch") for c in conflicts):
                        state = EntityResolutionState.VERIFIED_DISTINCT.value
                        score = 0.0
                        recommended = "keep_distinct"
                        requires_human = False
                    elif not matched:
                        continue
                    elif score >= 0.95 and not conflicts and etype != "PERSONCANDIDATE":
                        state = EntityResolutionState.VERIFIED_MATCH.value
                        recommended = "merge_if_permitted"
                        requires_human = False
                    elif score >= 0.85 and not conflicts:
                        state = EntityResolutionState.PROBABLE_MATCH.value
                        recommended = "human_review_before_merge"
                        requires_human = True
                    elif score >= 0.55:
                        state = EntityResolutionState.POSSIBLE_MATCH.value
                        recommended = "do_not_merge_name_only"
                        requires_human = True
                    else:
                        state = EntityResolutionState.UNRESOLVED.value
                        recommended = "collect_more_identifiers"
                        requires_human = True

                    cand = EntityResolutionCandidate(
                        candidate_id=f"ER-{sha256_12(a.entity_id + b.entity_id)}",
                        entity_ids=[a.entity_id, b.entity_id],
                        state=state,
                        score=round(clamp(score), 3),
                        matched_features=sorted(set(matched)),
                        conflicts=sorted(set(conflicts)),
                        evidence_ids=sorted(
                            set(
                                [
                                    ev.evidence_id
                                    for ev in evidence_map.values()
                                    if a.entity_id in (ev.artifact_reference or "")
                                    or b.entity_id in (ev.artifact_reference or "")
                                ]
                            )
                        ),
                        recommended_action=recommended,
                        requires_human_review=requires_human,
                    )
                    candidates.append(cand)

        return candidates

    # ------------------------------------------------------------------
    # Relationship / temporal validation
    # ------------------------------------------------------------------

    def _validate_relationships(
        self,
        relationships: list[Relationship],
        entity_map: dict[str, Entity],
        evidence_map: dict[str, Evidence],
        source_map: dict[str, Source],
        perm: PermissionContext,
    ) -> list[Relationship]:
        valid: list[Relationship] = []
        for rel in relationships:
            if not self._accessible(rel, perm):
                continue

            r = Relationship(**asdict(rel))
            if r.subject_id not in entity_map:
                r.limitations.append(f"subject unresolved: {r.subject_id}")
            if r.object_id not in entity_map:
                r.limitations.append(f"object unresolved: {r.object_id}")
            if not r.evidence_ids and not r.source_ids:
                r.limitations.append("unprovenanced relationship")
            for eid in r.evidence_ids:
                if eid not in evidence_map:
                    r.limitations.append(f"missing evidence {eid}")
            for sid in r.source_ids:
                if sid not in source_map:
                    r.limitations.append(f"missing source {sid}")

            if r.predicate.upper() == "RELATED_TO":
                r.limitations.append("generic relationship; semantics unresolved")

            valid.append(r)
        return valid

    def _relationship_intervals(self, rel: Relationship) -> tuple[Optional[datetime], Optional[datetime]]:
        s, _ = interval_for_value(rel.valid_from)
        _, e = interval_for_value(rel.valid_to)
        if not s:
            s, _ = interval_for_value(rel.valid_from)
        if not e:
            _, e = interval_for_value(rel.valid_to)
        return s, e

    # ------------------------------------------------------------------
    # Contradiction engine
    # ------------------------------------------------------------------

    def _detect_contradictions(
        self,
        claims: list[Claim],
        relationships: list[Relationship],
        evidence_map: dict[str, Evidence],
    ) -> list[Contradiction]:
        contradictions: list[Contradiction] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()

        def add(c: Contradiction) -> None:
            key = (c.contradiction_type, tuple(sorted(c.objects)))
            if key in seen:
                return
            seen.add(key)
            contradictions.append(c)

        # Claim contradictions.
        by_claim_key: dict[tuple[str, str], list[Claim]] = defaultdict(list)
        for claim in claims:
            by_claim_key[(norm_text(claim.subject), claim.predicate.upper())].append(claim)

        for group in by_claim_key.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a, b = group[i], group[j]
                    if norm_text(a.object_value) == norm_text(b.object_value):
                        continue

                    a_s, a_e = interval_for_value(a.time_start), interval_for_value(a.time_end)
                    b_s, b_e = interval_for_value(b.time_start), interval_for_value(b.time_end)

                    has_time = bool(a_s[0] or a_e[1] or b_s[0] or b_e[1])
                    if has_time and not intervals_overlap(a_s[0] or a_s[1], a_e[0] or a_e[1], b_s[0] or b_s[1], b_e[0] or b_e[1]):
                        continue

                    pred = a.predicate.upper()
                    if pred in OWNERSHIP_PREDICATES:
                        ctype = ContradictionType.OWNERSHIP.value
                        materiality = Materiality.CRITICAL.value
                    elif pred in ATTRIBUTION_PREDICATES:
                        ctype = ContradictionType.ATTRIBUTION.value
                        materiality = Materiality.CRITICAL.value
                    elif pred in CAUSAL_PREDICATES:
                        ctype = ContradictionType.EVENT.value
                        materiality = Materiality.MATERIAL.value
                    else:
                        ctype = ContradictionType.RELATIONSHIP.value
                        materiality = Materiality.MATERIAL.value if has_time else Materiality.MODERATE.value

                    add(
                        Contradiction(
                            contradiction_id=f"CONTRA-CLAIM-{sha256_12(a.claim_id + b.claim_id)}",
                            contradiction_type=ctype,
                            objects=[a.claim_id, b.claim_id],
                            values=[a.object_value, b.object_value],
                            materiality=materiality,
                            possible_explanations=[
                                "different_time_periods",
                                "different_entity_resolution",
                                "different_scope_or_definition",
                                "source_error",
                                "version_or_update_lag",
                            ],
                            resolution_state="UNRESOLVED",
                            required_followup="Retrieve authoritative primary record and compare effective dates.",
                            evidence_ids=sorted(set(a.evidence_ids + b.evidence_ids)),
                        )
                    )

        # Relationship contradictions.
        by_rel_key: dict[tuple[str, str], list[Relationship]] = defaultdict(list)
        for rel in relationships:
            by_rel_key[(rel.subject_id, rel.predicate.upper())].append(rel)

        for group in by_rel_key.values():
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a, b = group[i], group[j]
                    if a.object_id == b.object_id:
                        continue

                    a_s, a_e = self._relationship_intervals(a)
                    b_s, b_e = self._relationship_intervals(b)
                    has_time = bool(a_s or a_e or b_s or b_e)
                    if has_time and not intervals_overlap(a_s, a_e, b_s, b_e):
                        continue

                    pred = a.predicate.upper()
                    ctype = ContradictionType.OWNERSHIP.value if pred in OWNERSHIP_PREDICATES else ContradictionType.RELATIONSHIP.value
                    materiality = Materiality.CRITICAL.value if pred in OWNERSHIP_PREDICATES else Materiality.MATERIAL.value

                    add(
                        Contradiction(
                            contradiction_id=f"CONTRA-REL-{sha256_12(a.relationship_id + b.relationship_id)}",
                            contradiction_type=ctype,
                            objects=[a.relationship_id, b.relationship_id],
                            values=[a.object_id, b.object_id],
                            materiality=materiality,
                            possible_explanations=[
                                "different_control_eras",
                                "different_entity_resolution",
                                "shared_infrastructure",
                                "source_error",
                            ],
                            resolution_state="UNRESOLVED",
                            required_followup="Resolve entity/control era using primary ownership or registry evidence.",
                            evidence_ids=sorted(set(a.evidence_ids + b.evidence_ids)),
                        )
                    )

        return contradictions

    def _merge_contradictions(
        self,
        supplied: list[Contradiction],
        detected: list[Contradiction],
    ) -> list[Contradiction]:
        out: dict[str, Contradiction] = {}
        for c in supplied + detected:
            key = c.contradiction_id or f"{c.contradiction_type}:{'|'.join(sorted(c.objects))}"
            if key not in out:
                out[key] = c
        return list(out.values())

    # ------------------------------------------------------------------
    # Fact gate
    # ------------------------------------------------------------------

    def _claim_category(self, predicate: str) -> str:
        p = predicate.upper()
        if p in OWNERSHIP_PREDICATES:
            return "OWNERSHIP"
        if p in USE_OPERATION_PREDICATES:
            return "USE_OPERATION"
        if p == "RESOLVES_TO":
            return "DNS"
        if p in INFRA_PREDICATES:
            return "INFRA"
        if p in ATTRIBUTION_PREDICATES:
            return "ATTRIBUTION"
        if p in CAUSAL_PREDICATES:
            return "CAUSAL"
        return "GENERAL"

    def _support_texts(
        self,
        claim: Claim,
        evidence_map: dict[str, Evidence],
        observation_map: dict[str, Observation],
    ) -> list[str]:
        texts: list[str] = []
        for eid in claim.evidence_ids:
            ev = evidence_map.get(eid)
            if ev:
                texts.append(ev.content or ev.artifact_reference or "")
        for oid in claim.observation_ids:
            obs = observation_map.get(oid)
            if obs:
                texts.append(obs.statement)
        return [t for t in texts if t]

    def _temporal_fit(
        self,
        claim: Claim,
        evidence_map: dict[str, Evidence],
        observation_map: dict[str, Observation],
        source_map: dict[str, Source],
    ) -> tuple[float, bool, list[str]]:
        c_s, c_e = interval_for_value(claim.time_start), interval_for_value(claim.time_end)
        claim_start = c_s[0] or c_s[1]
        claim_end = c_e[0] or c_e[1]

        if not claim_start and not claim_end:
            return 0.70, False, []

        best = 0.0
        has_direct_time = False
        notes: list[str] = []

        for eid in claim.evidence_ids:
            ev = evidence_map.get(eid)
            if not ev:
                continue

            intervals = [
                ("observed_at", interval_for_value(ev.observed_at)),
                ("event_time_candidate", interval_for_value(ev.event_time_candidate)),
                ("retrieved_at", interval_for_value(ev.retrieved_at)),
            ]
            src = source_map.get(ev.source_id)
            if src:
                intervals.append(("source_publication_time", interval_for_value(src.publication_time)))
                intervals.append(("source_retrieval_time", interval_for_value(src.retrieval_time)))

            for label, (s_pair, e_pair) in intervals:
                s = s_pair[0] or s_pair[1]
                e = e_pair[0] or e_pair[1]
                if not s and not e:
                    continue
                if label in {"observed_at", "event_time_candidate"}:
                    has_direct_time = True
                if intervals_overlap(claim_start, claim_end, s, e):
                    best = max(best, 1.0)
                else:
                    best = max(best, 0.10)

        for oid in claim.observation_ids:
            obs = observation_map.get(oid)
            if not obs:
                continue
            s_pair = interval_for_value(obs.time_start)
            e_pair = interval_for_value(obs.time_end)
            s = s_pair[0] or s_pair[1]
            e = e_pair[0] or e_pair[1]
            if not s and not e:
                continue
            has_direct_time = True
            if intervals_overlap(claim_start, claim_end, s, e):
                best = max(best, 1.0)
            else:
                best = max(best, 0.10)

        if best == 0.0:
            best = 0.45
            notes.append("No temporal anchor found in linked evidence/observations.")

        metadata_only_temporal = bool(claim_start or claim_end) and not has_direct_time
        if metadata_only_temporal:
            notes.append("Only publication/retrieval/file timestamps available; these do not establish event time.")

        return clamp(best), metadata_only_temporal, notes

    def _domain_validation(
        self,
        claim: Claim,
        evidence_map: dict[str, Evidence],
        observation_map: dict[str, Observation],
        specialist_map: dict[str, SpecialistResult],
    ) -> tuple[bool, list[str], set[str]]:
        category = self._claim_category(claim.predicate)
        required = REQUIRED_DOMAINS_BY_PREDICATE.get(category, set())

        domains: set[str] = set()
        if claim.domain and claim.domain != "UNKNOWN":
            domains.add(claim.domain.upper())

        for eid in claim.evidence_ids:
            ev = evidence_map.get(eid)
            if ev and ev.domain:
                domains.add(ev.domain.upper())

        for oid in claim.observation_ids:
            obs = observation_map.get(oid)
            if obs and obs.domain:
                domains.add(obs.domain.upper())

        for sr in specialist_map.values():
            if set(sr.claim_ids) & {claim.claim_id} or set(sr.evidence_ids) & set(claim.evidence_ids):
                domains.add(sr.domain.upper())

        if not required:
            return True, [], domains

        present = domains & required
        if present:
            return True, [], domains

        limitations = [
            f"Domain validation failed for {category}; required specialist/evidence domains not present: {sorted(required)}"
        ]

        if category == "OWNERSHIP":
            limitations.append("Infrastructure/domain/branding evidence alone does not establish ownership or control.")
        if category == "ATTRIBUTION":
            limitations.append("Attribution requires threat-actor/campaign specialist evidence and higher burden.")
        if category == "CAUSAL":
            limitations.append("Causal claim requires mechanism/alternative-cause evidence, not sequence alone.")

        return False, limitations, domains

    def _fact_gate_claim(
        self,
        claim: Claim,
        evidence_map: dict[str, Evidence],
        observation_map: dict[str, Observation],
        source_map: dict[str, Source],
        source_families: dict[str, str],
        evidence_roots: dict[str, str],
        relationships: list[Relationship],
        contradictions: list[Contradiction],
        entity_resolution_by_entity: dict[str, list[EntityResolutionCandidate]],
        specialist_map: dict[str, SpecialistResult],
    ) -> dict[str, Any]:
        limitations: list[str] = []
        privacy_flags: list[str] = []

        linked_evidence = [evidence_map[eid] for eid in claim.evidence_ids if eid in evidence_map]
        linked_observations = [observation_map[oid] for oid in claim.observation_ids if oid in observation_map]

        missing_ev = [eid for eid in claim.evidence_ids if eid not in evidence_map]
        missing_obs = [oid for oid in claim.observation_ids if oid not in observation_map]
        if missing_ev:
            limitations.append(f"missing evidence: {missing_ev}")
        if missing_obs:
            limitations.append(f"missing observations: {missing_obs}")

        if not linked_evidence and not linked_observations:
            return {
                "claim_id": claim.claim_id,
                "state": VerificationState.UNSUPPORTED.value,
                "confidence": 0.0,
                "evidence_ids": [],
                "observation_ids": [],
                "source_ids": [],
                "source_families": [],
                "evidence_families": [],
                "independent_source_families": 0,
                "independent_evidence_families": 0,
                "independent_paths": 0,
                "domains": [],
                "average_source_reliability": 0.0,
                "max_source_reliability": 0.0,
                "official_primary": False,
                "directness": 0.0,
                "temporal_fit": 0.0,
                "metadata_only_temporal": False,
                "domain_validation_pass": False,
                "material_contradiction": False,
                "relevant_contradiction_ids": [],
                "evidence_strength": EvidenceStrength.UNVERIFIED.value,
                "limitations": ["No linked evidence or observations."],
                "privacy_flags": [],
            }

        # Sources / families.
        source_ids = {ev.source_id for ev in linked_evidence if ev.source_id}
        source_ids.update(claim.source_ids)
        source_ids = {sid for sid in source_ids if sid in source_map}

        fams = {source_families.get(sid, sid) for sid in source_ids}
        ev_fams = {evidence_roots.get(ev.evidence_id, ev.evidence_id) for ev in linked_evidence}

        reliabilities = [source_map[sid].reliability for sid in source_ids if sid in source_map]
        avg_rel = mean(reliabilities, 0.0)
        max_rel = max(reliabilities, default=0.0)
        official_primary = any(
            source_map[sid].source_type.upper() in OFFICIAL_PRIMARY_TYPES
            and source_map[sid].reliability >= 0.90
            for sid in source_ids
            if sid in source_map
        )

        independent_paths = min(len(fams), len(ev_fams)) if ev_fams else len(fams)

        # Directness.
        claim_terms = set(tokenize(claim.statement or f"{claim.subject} {claim.predicate} {claim.object_value}"))
        support_terms = [set(tokenize(t)) for t in self._support_texts(claim, evidence_map, observation_map)]
        directness = max((jaccard(claim_terms, st) for st in support_terms), default=0.0)

        # Temporal.
        temporal_fit, metadata_only_temporal, temporal_notes = self._temporal_fit(
            claim, evidence_map, observation_map, source_map
        )
        limitations.extend(temporal_notes)

        # Domain validation.
        domain_ok, domain_limits, domains = self._domain_validation(
            claim, evidence_map, observation_map, specialist_map
        )
        limitations.extend(domain_limits)

        # Entity checks.
        for ref in [claim.subject, claim.object_value]:
            if not ref:
                continue
            cand_states = [
                c.state
                for c in entity_resolution_by_entity.get(ref, [])
                if ref in c.entity_ids
            ]
            if any(
                s in {
                    EntityResolutionState.POSSIBLE_MATCH.value,
                    EntityResolutionState.UNRESOLVED.value,
                }
                for s in cand_states
            ):
                limitations.append(f"entity resolution unresolved or possible for {ref}")

        # Relationship checks.
        rel_ids = set(claim.relationship_ids)
        for rid in rel_ids:
            rel = next((r for r in relationships if r.relationship_id == rid), None)
            if not rel:
                limitations.append(f"missing relationship {rid}")
                continue
            if not rel.evidence_ids and not rel.source_ids:
                limitations.append(f"relationship {rid} unprovenanced")
            if rel.predicate.upper() in INFRA_PREDICATES and claim.predicate.upper() in OWNERSHIP_PREDICATES:
                limitations.append("infrastructure relationship does not establish ownership/control")

        # Contradictions.
        relevant_contras = [
            c
            for c in contradictions
            if c.resolution_state.upper() != "RESOLVED"
            and (
                claim.claim_id in c.objects
                or set(c.evidence_ids) & set(claim.evidence_ids)
                or set(c.objects) & set(claim.relationship_ids)
            )
        ]
        material_contradiction = any(
            c.materiality.upper() in {Materiality.CRITICAL.value, Materiality.MATERIAL.value}
            for c in relevant_contras
        )
        if material_contradiction:
            limitations.append("Open material contradiction affects this claim.")

        # Low-confidence derived text.
        low_conf_derived = any(
            (obs.observer or "").upper() in {"OCR", "ASR", "TRANSLATION", "PARSER"} and obs.confidence < 0.65
            for obs in linked_observations
        )
        if low_conf_derived:
            limitations.append("Low-confidence derived text contributes to support.")

        # Dependency warning.
        dependent_modality_warning = len(fams) <= 1 and len(linked_evidence + linked_observations) > 1
        if dependent_modality_warning:
            limitations.append("Multiple inputs may derive from one source/evidence family.")

        # State decision.
        category = self._claim_category(claim.predicate)

        if material_contradiction:
            state = VerificationState.DISPUTED
        elif not domain_ok:
            state = VerificationState.INCONCLUSIVE
        elif metadata_only_temporal and category in {"OWNERSHIP", "ATTRIBUTION", "CAUSAL"}:
            state = VerificationState.INCONCLUSIVE
        elif independent_paths >= 2 and avg_rel >= 0.70 and directness >= 0.15 and temporal_fit >= 0.50:
            state = VerificationState.SUPPORTED
        elif official_primary and avg_rel >= 0.85 and directness >= 0.12 and temporal_fit >= 0.45:
            state = VerificationState.SUPPORTED
        elif independent_paths >= 1 and avg_rel >= 0.55 and directness >= 0.10:
            state = VerificationState.PARTIALLY_SUPPORTED
        else:
            state = VerificationState.INCONCLUSIVE

        # Conservative caps.
        if category == "OWNERSHIP" and state == VerificationState.SUPPORTED:
            if not any(d in {"CORPINT", "OWNERSHIPINT", "LEGALINT"} for d in domains):
                state = VerificationState.INCONCLUSIVE
                limitations.append("Ownership/control requires corporate/ownership/legal specialist evidence.")

        if category == "ATTRIBUTION" and state in {VerificationState.SUPPORTED.value, VerificationState.PARTIALLY_SUPPORTED.value}:
            state = VerificationState.INCONCLUSIVE
            limitations.append("Actor attribution requires substantially stronger evidence and human review.")

        if category == "CAUSAL":
            state = VerificationState.INCONCLUSIVE
            limitations.append("Causation cannot be promoted from correlation/sequence alone.")

        # Evidence strength.
        if state == VerificationState.SUPPORTED.value:
            if official_primary and directness >= 0.25:
                strength = EvidenceStrength.PRIMARY_DIRECT.value
            elif independent_paths >= 2:
                strength = EvidenceStrength.SECONDARY_INDEPENDENT.value
            else:
                strength = EvidenceStrength.PRIMARY_INDIRECT.value
        elif state == VerificationState.PARTIALLY_SUPPORTED.value:
            strength = EvidenceStrength.SECONDARY_DEPENDENT.value if dependent_modality_warning else EvidenceStrength.PRIMARY_INDIRECT.value
        elif state == VerificationState.DISPUTED.value:
            strength = EvidenceStrength.SOURCE_CLAIM.value
        else:
            strength = EvidenceStrength.UNVERIFIED.value

        penalty = 0.0
        if material_contradiction:
            penalty += 0.35
        if not domain_ok:
            penalty += 0.25
        if metadata_only_temporal:
            penalty += 0.15
        if low_conf_derived:
            penalty += 0.08
        if dependent_modality_warning:
            penalty += 0.05

        confidence = clamp(
            0.12
            + 0.28 * avg_rel
            + 0.18 * min(1.0, independent_paths / 2.0)
            + 0.12 * directness
            + 0.12 * temporal_fit
            + (0.10 if official_primary else 0.0)
            - penalty
        )

        if state == VerificationState.UNSUPPORTED.value:
            confidence = min(confidence, 0.05)
        elif state == VerificationState.INCONCLUSIVE.value:
            confidence = min(confidence, 0.45)
        elif state == VerificationState.DISPUTED.value:
            confidence = min(confidence, 0.35)

        return {
            "claim_id": claim.claim_id,
            "state": state.value,
            "confidence": round(confidence, 3),
            "evidence_ids": sorted({ev.evidence_id for ev in linked_evidence}),
            "observation_ids": sorted({obs.observation_id for obs in linked_observations}),
            "source_ids": sorted(source_ids),
            "source_families": sorted(fams),
            "evidence_families": sorted(ev_fams),
            "independent_source_families": len(fams),
            "independent_evidence_families": len(ev_fams),
            "independent_paths": independent_paths,
            "domains": sorted(domains),
            "average_source_reliability": round(avg_rel, 3),
            "max_source_reliability": round(max_rel, 3),
            "official_primary": official_primary,
            "directness": round(directness, 3),
            "temporal_fit": round(temporal_fit, 3),
            "metadata_only_temporal": metadata_only_temporal,
            "domain_validation_pass": domain_ok,
            "material_contradiction": material_contradiction,
            "relevant_contradiction_ids": [c.contradiction_id for c in relevant_contras],
            "evidence_strength": strength,
            "limitations": sorted(set(limitations)),
            "privacy_flags": privacy_flags,
        }

    # ------------------------------------------------------------------
    # Hypotheses / skeptic / gaps
    # ------------------------------------------------------------------

    def _generate_hypotheses(
        self,
        claims: list[Claim],
        fact_results: list[dict[str, Any]],
        contradictions: list[Contradiction],
    ) -> list[Hypothesis]:
        fact_by_id = {fr["claim_id"]: fr for fr in fact_results}
        hypotheses: list[Hypothesis] = []

        for claim in claims:
            fr = fact_by_id.get(claim.claim_id, {})
            state = fr.get("state", VerificationState.INCONCLUSIVE.value)
            category = self._claim_category(claim.predicate)
            base = f"H-{claim.claim_id}"

            hypotheses.append(
                Hypothesis(
                    hypothesis_id=f"{base}-TRUE",
                    statement=claim.statement or f"Claim {claim.claim_id} is true as stated.",
                    status=(
                        "SUPPORTED"
                        if state == VerificationState.SUPPORTED.value
                        else "ACTIVE"
                        if state == VerificationState.PARTIALLY_SUPPORTED.value
                        else "DISPUTED"
                        if state == VerificationState.DISPUTED.value
                        else "INCONCLUSIVE"
                    ),
                    supporting_claim_ids=[claim.claim_id],
                    assumptions=["Current evidence is sufficient for the exact proposition."],
                    unknowns=["Whether later primary evidence supersedes current assessment."],
                    falsification_conditions=[
                        "Retrieve authoritative primary record contradicting the claim.",
                        "Identify independent source showing different entity/time/scope.",
                    ],
                    confidence=fr.get("confidence", 0.5),
                    domain_dependencies=fr.get("domains", []),
                )
            )

            hypotheses.append(
                Hypothesis(
                    hypothesis_id=f"{base}-DEPENDENT_SOURCES",
                    statement="Apparent corroboration may derive from one upstream source/evidence family.",
                    status="ACTIVE" if fr.get("independent_paths", 0) < 2 or fr.get("limitations") and any("family" in x for x in fr["limitations"]) else "CANDIDATE",
                    opposing_claim_ids=[claim.claim_id],
                    assumptions=["Multiple modules/reports may share one original source."],
                    unknowns=["Whether all supporting inputs trace to one press release, filing, leak, or analyst."],
                    falsification_conditions=[
                        "Trace source pedigree and identify genuinely independent upstream evidence.",
                    ],
                    confidence=0.45,
                )
            )

            if category == "OWNERSHIP":
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-SHARED_PROVIDER_OR_VENDOR",
                        statement="Observed infrastructure/domain association may reflect shared provider, vendor, reseller, or historical usage rather than ownership/control.",
                        status="ACTIVE" if not fr.get("domain_validation_pass", False) else "CANDIDATE",
                        opposing_claim_ids=[claim.claim_id],
                        assumptions=["Cloud/CDN/hosting/registrar relationships are not ownership proof."],
                        unknowns=["Legal owner, operator, and controller may differ."],
                        falsification_conditions=[
                            "Obtain corporate registry/ownership filing or authorized contractual evidence.",
                        ],
                        confidence=0.50,
                        domain_dependencies=["OWNERSHIPINT", "CORPINT", "INFRAINT", "CLOUDINT"],
                    )
                )

            if fr.get("metadata_only_temporal"):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-STALE_OR_PUBLICATION_TIME",
                        statement="Claim may rely on publication/file/retrieval time rather than event/effective time.",
                        status="ACTIVE",
                        opposing_claim_ids=[claim.claim_id],
                        assumptions=["Timestamps may reflect upload, indexing, or reporting lag."],
                        unknowns=["Effective event date remains unresolved."],
                        falsification_conditions=[
                            "Retrieve contemporaneous primary record with effective date.",
                        ],
                        confidence=0.45,
                    )
                )

            if any(c.contradiction_id in fr.get("relevant_contradiction_ids", []) for c in contradictions):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"{base}-CONTRADICTION_CONTEXT",
                        statement="Contradictory evidence may reflect different time, scope, entity, definition, or source error.",
                        status="ACTIVE",
                        opposing_claim_ids=[claim.claim_id],
                        assumptions=["Conflict is not automatically fabrication."],
                        unknowns=["Which record is authoritative for the relevant period/scope?"],
                        falsification_conditions=[
                            "Adjudicate using primary independent evidence and effective dates.",
                        ],
                        confidence=0.40,
                    )
                )

            hypotheses.append(
                Hypothesis(
                    hypothesis_id=f"{base}-INSUFFICIENT",
                    statement="Current evidence is insufficient to resolve the claim confidently.",
                    status="INCONCLUSIVE",
                    supporting_claim_ids=[],
                    assumptions=["Additional primary/independent evidence may exist but was not collected."],
                    unknowns=fr.get("limitations", []),
                    falsification_conditions=[
                        "Obtain native primary artifact and independent evidence family.",
                    ],
                    confidence=0.35,
                )
            )

        return hypotheses

    def _dual_ai_skeptic(
        self,
        fact_results: list[dict[str, Any]],
        claims: list[Claim],
    ) -> list[dict[str, Any]]:
        claim_by_id = {c.claim_id: c for c in claims}
        out: list[dict[str, Any]] = []

        for fr in fact_results:
            issues: list[str] = []
            claim = claim_by_id.get(fr["claim_id"])
            if not claim:
                continue

            category = self._claim_category(claim.predicate)

            if fr["state"] == VerificationState.SUPPORTED.value:
                if fr["independent_paths"] < 2 and not fr["official_primary"]:
                    issues.append("Supported claim lacks two independent evidence/source families or authoritative primary record.")
                if category == "OWNERSHIP" and not any(d in {"CORPINT", "OWNERSHIPINT", "LEGALINT"} for d in fr["domains"]):
                    issues.append("Ownership/control claim not validated by ownership/corporate/legal domain.")
                if fr["metadata_only_temporal"]:
                    issues.append("Metadata/publication time cannot establish event/effective time.")
                if fr["material_contradiction"]:
                    issues.append("Open material contradiction exists.")
                if fr["directness"] < 0.15:
                    issues.append("Evidence wording is weakly aligned with claim.")

            elif fr["state"] == VerificationState.PARTIALLY_SUPPORTED.value:
                if fr["independent_paths"] < 2:
                    issues.append("Partial support comes from one evidence family.")
                if not fr["domain_validation_pass"]:
                    issues.append("Domain validation incomplete.")

            elif fr["state"] == VerificationState.INCONCLUSIVE.value:
                issues.extend(fr.get("limitations", [])[:3])

            if not issues:
                outcome = "AGREE"
            elif fr["state"] == VerificationState.SUPPORTED.value:
                outcome = "DISAGREE"
            elif fr["state"] == VerificationState.INCONCLUSIVE.value:
                outcome = "INSUFFICIENT_EVIDENCE"
            else:
                outcome = "PARTIAL_AGREEMENT"

            out.append(
                {
                    "claim_id": fr["claim_id"],
                    "primary_state": fr["state"],
                    "skeptic_outcome": outcome,
                    "skeptic_issues": sorted(set(issues)),
                    "note": "AI agreement is analytical consistency, not source corroboration.",
                }
            )

        return out

    def _derive_gaps_and_actions(
        self,
        fact_results: list[dict[str, Any]],
        contradictions: list[Contradiction],
        entity_candidates: list[EntityResolutionCandidate],
        relationships: list[Relationship],
        evidence: list[Evidence],
        as_of: datetime,
    ) -> tuple[list[Gap], list[str], list[str], list[str], list[str]]:
        gaps: dict[str, Gap] = {}
        actions: set[str] = set()
        handoffs: set[str] = set()
        human: set[str] = set()
        stale: list[str] = []

        def add_gap(
            question: str,
            importance: str,
            domains: list[str],
            specialist: str,
            value: str,
            blocking: str = "NON_BLOCKING",
        ) -> None:
            gid = f"GAP-{sha256_12(question + ''.join(sorted(domains)))}"
            if gid in gaps:
                return
            gaps[gid] = Gap(
                gap_id=gid,
                question=question,
                importance=importance,
                domains_required=sorted(set(domains)),
                recommended_specialist=specialist,
                expected_information_value=value,
                blocking_state=blocking,
            )

        for fr in fact_results:
            cid = fr["claim_id"]
            if fr["state"] in {
                VerificationState.PARTIALLY_SUPPORTED.value,
                VerificationState.INCONCLUSIVE.value,
            }:
                add_gap(
                    f"Obtain independent primary evidence for {cid}.",
                    "HIGH",
                    fr.get("domains", []) or ["SOURCEINT"],
                    "SOURCEINT/PROVENANCEINT",
                    "HIGH",
                    "BLOCKING" if fr["state"] == VerificationState.INCONCLUSIVE.value else "NON_BLOCKING",
                )
                actions.add(f"Seek an independent evidence family for {cid}; do not count duplicates/modules.")

            if not fr["domain_validation_pass"]:
                category = "OWNERSHIP" if any(k in " ".join(fr["limitations"]).lower() for k in ["ownership", "control"]) else "GENERAL"
                add_gap(
                    f"Route {cid} to required domain specialist for validation.",
                    "HIGH",
                    list(REQUIRED_DOMAINS_BY_PREDICATE.get(category, {"SPECIALIST"})),
                    "/".join(sorted(REQUIRED_DOMAINS_BY_PREDICATE.get(category, {"SPECIALIST"}))),
                    "HIGH",
                    "BLOCKING",
                )
                handoffs.update(REQUIRED_DOMAINS_BY_PREDICATE.get(category, {"SPECIALIST"}))

            if fr["metadata_only_temporal"]:
                add_gap(
                    f"Retrieve effective/event-time primary record for {cid}.",
                    "MATERIAL",
                    ["ARCHIVEINT", "LOGINT", "CORPINT", "DNSINT"],
                    "TEMPORAL/SOURCEINT",
                    "HIGH",
                )
                actions.add(f"Do not use publication/file/retrieval time as event time for {cid}.")

            if fr["material_contradiction"]:
                add_gap(
                    f"Adjudicate contradiction affecting {cid}.",
                    "CRITICAL",
                    ["HYPOTHESISINT", "SOURCEINT"],
                    "HYPOTHESISINT/ADJUDICATOR",
                    "HIGH",
                    "BLOCKING",
                )
                actions.add(f"Adjudicate contradiction for {cid} using primary independent evidence; do not average.")
                handoffs.update({"HYPOTHESISINT", "SOURCEINT"})

        for contra in contradictions:
            if contra.resolution_state.upper() == "RESOLVED":
                continue
            add_gap(
                f"Resolve contradiction {contra.contradiction_id}.",
                contra.materiality,
                ["SOURCEINT", "HYPOTHESISINT"],
                "HYPOTHESISINT/SOURCEINT",
                "HIGH",
                "BLOCKING" if contra.materiality in {Materiality.CRITICAL.value, Materiality.MATERIAL.value} else "NON_BLOCKING",
            )
            actions.add(f"Preserve contradiction {contra.contradiction_id}; resolve with effective dates and source authority.")

        for cand in entity_candidates:
            if cand.state in {
                EntityResolutionState.POSSIBLE_MATCH.value,
                EntityResolutionState.UNRESOLVED.value,
            }:
                add_gap(
                    f"Resolve entity candidate {cand.candidate_id}.",
                    "MATERIAL",
                    ["ENTITYRES", "CORPINT", "HUMINT"],
                    "ENTITYRES/HUMAN",
                    "HIGH",
                )
                if cand.requires_human_review:
                    human.add(f"Human review entity merge candidate {cand.candidate_id}.")

        for rel in relationships:
            if not rel.evidence_ids and not rel.source_ids:
                add_gap(
                    f"Add provenance to relationship {rel.relationship_id}.",
                    "MATERIAL",
                    ["PROVENANCEINT"],
                    "PROVENANCEINT/EVIDENCEINT",
                    "HIGH",
                )
                actions.add(f"Add provenance to relationship {rel.relationship_id} before using it in fusion.")

        for ev in evidence:
            observed = parse_dt(ev.observed_at or ev.event_time_candidate or ev.retrieved_at)
            if observed and (as_of - observed).days > 365:
                stale.append(ev.evidence_id)
                add_gap(
                    f"Reverify stale evidence {ev.evidence_id}.",
                    "MEDIUM",
                    ["SOURCEINT"],
                    "SOURCEINT",
                    "MEDIUM",
                )

        actions.update(
            {
                "Count evidence/source families, not modules, URLs, reposts, or AI agreements.",
                "Preserve specialist disagreements and contradictions; do not average conflicting values.",
                "Do not promote infrastructure association into ownership/control.",
                "Do not generate attack plans, targeting, surveillance, or autonomous enforcement.",
                "Apply most-restrictive handling inherited from source domains.",
            }
        )

        handoffs.update({"SOURCEINT", "PROVENANCEINT", "EVIDENCEINT", "HYPOTHESISINT"})

        return list(gaps.values()), sorted(actions), sorted(handoffs), sorted(human), sorted(set(stale))

    # ------------------------------------------------------------------
    # Timeline / correlations
    # ------------------------------------------------------------------

    def _build_timeline(
        self,
        events: list[Event],
        observations: list[Observation],
        evidence: list[Evidence],
        source_map: dict[str, Source],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []

        for ev in events:
            dt = parse_dt(ev.time_start or ev.time_end)
            if dt:
                rows.append(
                    {
                        "time": dt.isoformat(),
                        "type": "EVENT",
                        "id": ev.event_id,
                        "description": ev.event_type,
                        "evidence_ids": ev.evidence_ids,
                        "source_ids": ev.source_ids,
                        "confidence": ev.confidence,
                        "status": ev.status,
                    }
                )

        for obs in observations:
            dt = parse_dt(obs.time_start or obs.time_end)
            if dt:
                rows.append(
                    {
                        "time": dt.isoformat(),
                        "type": "OBSERVATION",
                        "id": obs.observation_id,
                        "description": excerpt(obs.statement, 160),
                        "evidence_ids": [obs.evidence_id] if obs.evidence_id else [],
                        "source_ids": [obs.source_id] if obs.source_id else [],
                        "confidence": obs.confidence,
                        "status": "OBSERVED",
                    }
                )

        for evd in evidence:
            dt = parse_dt(evd.observed_at or evd.event_time_candidate or evd.retrieved_at)
            src = source_map.get(evd.source_id)
            if not dt and src:
                dt = parse_dt(src.publication_time or src.retrieval_time)
            if dt:
                rows.append(
                    {
                        "time": dt.isoformat(),
                        "type": "EVIDENCE",
                        "id": evd.evidence_id,
                        "description": excerpt(evd.content or evd.artifact_reference, 160),
                        "evidence_ids": [evd.evidence_id],
                        "source_ids": [evd.source_id] if evd.source_id else [],
                        "confidence": 0.5,
                        "status": evd.integrity_state,
                    }
                )

        rows.sort(key=lambda x: x["time"])
        return rows

    def _cross_domain_correlations(
        self,
        fact_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for fr in fact_results:
            if len(fr["domains"]) >= 2 and fr["state"] in {
                VerificationState.SUPPORTED.value,
                VerificationState.PARTIALLY_SUPPORTED.value,
            }:
                out.append(
                    {
                        "claim_id": fr["claim_id"],
                        "domains": fr["domains"],
                        "state": fr["state"],
                        "independent_paths": fr["independent_paths"],
                        "note": "Cross-domain correlation is only as strong as independent evidence families.",
                    }
                )
        return out

    def _orthogonal_evidence(
        self,
        fact_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for fr in fact_results:
            if (
                fr["state"] == VerificationState.SUPPORTED.value
                and fr["independent_paths"] >= 2
                and len(fr["domains"]) >= 2
            ):
                out.append(
                    {
                        "claim_id": fr["claim_id"],
                        "domains": fr["domains"],
                        "source_families": fr["source_families"],
                        "evidence_families": fr["evidence_families"],
                        "note": "Orthogonal evidence uses different methods/channels with distinct failure modes.",
                    }
                )
        return out

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def analyze(self, req: FusionRequest) -> FusionResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self.blocked_result(req, code, reason)
            self.memory.append(asdict(result))
            return result

        perm = req.permission
        as_of = parse_dt(req.scope.get("as_of")) or datetime.now(timezone.utc)

        source_map = self._normalize_sources(req.sources, perm)
        source_families = {sid: self._source_family(src) for sid, src in source_map.items()}
        source_pedigree = self._source_pedigree(source_map)

        evidence, evidence_roots, evidence_families, duplicate_groups, near_duplicate_groups = self._normalize_evidence(
            req.evidence, source_map, perm
        )
        evidence_map = {ev.evidence_id: ev for ev in evidence}

        observations = [obs for obs in req.observations if self._accessible(obs, perm) and (not obs.evidence_id or obs.evidence_id in evidence_map)]
        observation_map = {obs.observation_id: obs for obs in observations}

        entities = [ent for ent in req.entities if self._accessible(ent, perm)]
        entity_map = {ent.entity_id: ent for ent in entities}

        claims = [c for c in req.claims if self._accessible(c, perm)]
        specialist_results = [sr for sr in req.specialist_results if self._accessible(sr, perm)]
        specialist_map = {sr.result_id: sr for sr in specialist_results}

        relationships = self._validate_relationships(req.relationships, entity_map, evidence_map, source_map, perm)
        events = [ev for ev in req.events if self._accessible(ev, perm)]

        entity_candidates = self._entity_resolution(entities, evidence_map, perm)
        entity_resolution_by_entity: dict[str, list[EntityResolutionCandidate]] = defaultdict(list)
        for cand in entity_candidates:
            for eid in cand.entity_ids:
                entity_resolution_by_entity[eid].append(cand)

        detected_contras = self._detect_contradictions(claims, relationships, evidence_map)
        contradictions = self._merge_contradictions([c for c in req.contradictions if self._accessible(c, perm)], detected_contras)

        fact_results: list[dict[str, Any]] = []
        for claim in claims:
            fr = self._fact_gate_claim(
                claim=claim,
                evidence_map=evidence_map,
                observation_map=observation_map,
                source_map=source_map,
                source_families=source_families,
                evidence_roots=evidence_roots,
                relationships=relationships,
                contradictions=contradictions,
                entity_resolution_by_entity=entity_resolution_by_entity,
                specialist_map=specialist_map,
            )
            fact_results.append(fr)

        hypotheses = self._generate_hypotheses(claims, fact_results, contradictions)
        dual_ai = self._dual_ai_skeptic(fact_results, claims)

        gaps, actions, handoffs, human_review, stale_evidence = self._derive_gaps_and_actions(
            fact_results=fact_results,
            contradictions=contradictions,
            entity_candidates=entity_candidates,
            relationships=relationships,
            evidence=evidence,
            as_of=as_of,
        )

        assumptions: list[Assumption] = []
        for fr in fact_results:
            if fr["independent_paths"] < 2:
                assumptions.append(
                    Assumption(
                        assumption_id=f"ASM-{sha256_12(fr['claim_id'] + 'independence')}",
                        statement=f"Claim {fr['claim_id']} assumes supporting inputs are not wholly dependent.",
                        dependent_claim_ids=[fr["claim_id"]],
                        status="OPEN",
                        criticality="IMPORTANT",
                    )
                )
            if fr["metadata_only_temporal"]:
                assumptions.append(
                    Assumption(
                        assumption_id=f"ASM-{sha256_12(fr['claim_id'] + 'time')}",
                        statement=f"Claim {fr['claim_id']} assumes publication/retrieval time approximates relevant state.",
                        dependent_claim_ids=[fr["claim_id"]],
                        status="OPEN",
                        criticality="MATERIAL",
                    )
                )

        timeline = self._build_timeline(events, observations, evidence, source_map)
        cross_domain = self._cross_domain_correlations(fact_results)
        orthogonal = self._orthogonal_evidence(fact_results)

        supported = [fr for fr in fact_results if fr["state"] == VerificationState.SUPPORTED.value]
        partial = [fr for fr in fact_results if fr["state"] == VerificationState.PARTIALLY_SUPPORTED.value]
        disputed = [fr for fr in fact_results if fr["state"] == VerificationState.DISPUTED.value]
        inconclusive = [fr for fr in fact_results if fr["state"] == VerificationState.INCONCLUSIVE.value]
        unsupported = [fr for fr in fact_results if fr["state"] == VerificationState.UNSUPPORTED.value]

        knowledge_states: dict[str, str] = {}
        for fr in fact_results:
            if fr["state"] == VerificationState.SUPPORTED.value:
                knowledge_states[fr["claim_id"]] = KnowledgeState.SUPPORTED.value
            elif fr["state"] == VerificationState.PARTIALLY_SUPPORTED.value:
                knowledge_states[fr["claim_id"]] = KnowledgeState.PARTIAL.value
            elif fr["state"] == VerificationState.DISPUTED.value:
                knowledge_states[fr["claim_id"]] = KnowledgeState.DISPUTED.value
            elif fr["state"] == VerificationState.UNSUPPORTED.value:
                knowledge_states[fr["claim_id"]] = KnowledgeState.MISSING_EVIDENCE.value
            else:
                knowledge_states[fr["claim_id"]] = KnowledgeState.UNKNOWN.value

        domains_used = sorted(
            {
                d.upper()
                for fr in fact_results
                for d in fr["domains"]
            }
            | {sr.domain.upper() for sr in specialist_results}
            | {ev.domain.upper() for ev in evidence}
        )

        privacy_flags = [
            "No cross-tenant or unauthorized case fusion performed.",
            "LOCAL_ONLY/restricted handling inherited from source objects where present.",
            "No private-person tracking, surveillance targeting, or doxxing generated.",
        ]
        if perm.local_only_required or any(s.local_only for s in source_map.values()):
            privacy_flags.append("LOCAL_ONLY evidence retained locally; no cloud routing performed.")

        safety_flags = [
            "No operational attack plan, weapon targeting, or infrastructure compromise guidance generated.",
            "No autonomous enforcement, account disablement, asset freeze, or legal action executed.",
            "Dependency/infrastructure fusion is analytical only and not converted into targeting.",
        ]

        human_review_flags = list(human_review)
        for fr in fact_results:
            claim = next((c for c in claims if c.claim_id == fr["claim_id"]), None)
            if not claim:
                continue
            cat = self._claim_category(claim.predicate)
            if cat in {"OWNERSHIP", "ATTRIBUTION"} and fr["state"] != VerificationState.UNSUPPORTED.value:
                human_review_flags.append(
                    f"Human review required before consequential ownership/attribution use of {fr['claim_id']}."
                )
        human_review_flags = sorted(set(human_review_flags))

        policy_flags = [
            "Fusion preserves specialist limitations and policy restrictions.",
            "Contradictions are preserved, not averaged.",
            "Source/module count is not treated as corroboration.",
        ]

        limitations = [
            "Rule-based local FUSIONINT skeleton; not a production multi-agent orchestration platform.",
            "Does not fetch live sources, execute actions, bypass permissions, or override specialist boundaries.",
            "Fact-gate outputs are evidentiary and revisable, not legal truth determinations.",
            "Entity resolution is conservative; name/alias overlap alone never authorizes merge.",
            "Infrastructure/domain/branding evidence does not establish ownership/control or actor attribution.",
        ]

        if not claims:
            status = Status.INCONCLUSIVE.value
        elif supported and not disputed and not inconclusive:
            status = Status.SUCCEEDED.value
        elif supported or partial:
            status = Status.PARTIAL.value
        else:
            status = Status.INCONCLUSIVE.value

        summary = (
            f"Defensive cross-domain fusion for case {req.case_id}. "
            f"Domains used: {len(domains_used)}. Evidence items: {len(evidence)}. Claims: {len(claims)}. "
            f"States: supported={len(supported)}, partial={len(partial)}, disputed={len(disputed)}, "
            f"inconclusive={len(inconclusive)}, unsupported={len(unsupported)}. "
            "No evidence invention, contradiction averaging, targeting, surveillance, or autonomous action performed."
        )

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "case_id": req.case_id,
            "task_id": req.task_id,
            "as_of": as_of.isoformat(),
            "source_ids": sorted(source_map),
            "evidence_ids": sorted(evidence_map),
            "evidence_hashes": {ev.evidence_id: ev.content_hash for ev in evidence},
            "source_families": source_families,
            "source_pedigree": source_pedigree,
            "evidence_families": evidence_families,
            "duplicate_groups": duplicate_groups,
            "near_duplicate_groups": near_duplicate_groups,
            "entity_resolution_candidates": [c.candidate_id for c in entity_candidates],
            "claim_states": {fr["claim_id"]: fr["state"] for fr in fact_results},
            "contradiction_ids": [c.contradiction_id for c in contradictions],
            "hypothesis_ids": [h.hypothesis_id for h in hypotheses],
            "dual_ai_outcomes": {d["claim_id"]: d["skeptic_outcome"] for d in dual_ai},
            "policy_flags": policy_flags,
        }

        result = FusionResult(
            case_id=req.case_id,
            task_id=req.task_id,
            objective=req.objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            summary=summary,
            priority_questions=req.priority_questions,
            domains_used=domains_used,
            specialist_results=[asdict(sr) for sr in specialist_results],
            evidence_ids=sorted(evidence_map),
            source_ids=sorted(source_map),
            evidence_families=evidence_families,
            source_pedigree=source_pedigree,
            source_independence={
                "unique_source_count": len(source_map),
                "independent_source_families": len(set(source_families.values())),
                "source_families": source_families,
                "evidence_families": evidence_families,
                "duplicate_groups": duplicate_groups,
                "near_duplicate_groups": near_duplicate_groups,
                "warning": "Module count, URLs, reposts, and AI agreement are not independent corroboration.",
            },
            entities=[asdict(e) for e in entities],
            entity_resolution_results=[asdict(c) for c in entity_candidates],
            relationships=[asdict(r) for r in relationships],
            events=[asdict(e) for e in events],
            timeline=timeline,
            claims=[asdict(c) for c in claims],
            candidate_facts=fact_results,
            supported_facts=supported,
            partial_facts=partial,
            disputed_facts=disputed,
            unsupported_claims=unsupported,
            hypotheses=[asdict(h) for h in hypotheses],
            competing_hypotheses=[asdict(h) for h in hypotheses if h.status in {"ACTIVE", "DISPUTED", "INCONCLUSIVE"}],
            contradictions=[asdict(c) for c in contradictions],
            contradiction_resolutions=[
                {
                    "contradiction_id": c.contradiction_id,
                    "resolution_state": c.resolution_state,
                    "required_followup": c.required_followup,
                }
                for c in contradictions
            ],
            assumptions=[asdict(a) for a in assumptions],
            knowledge_states=knowledge_states,
            knowledge_gaps=[asdict(g) for g in gaps],
            cross_domain_correlations=cross_domain,
            orthogonal_evidence=orthogonal,
            stale_evidence=stale_evidence,
            superseded_evidence=[],
            confidence_assessments={fr["claim_id"]: fr["confidence"] for fr in fact_results},
            verification_results=fact_results,
            policy_flags=policy_flags,
            privacy_flags=privacy_flags,
            safety_flags=safety_flags,
            human_review_flags=human_review_flags,
            recommended_next_actions=actions,
            specialist_handoffs=handoffs,
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
    agent = FusionIntAgent(mode=Mode.LOCAL_ONLY)

    perm = PermissionContext(
        tenant_id="TENANT-1",
        case_id="FUSION-001",
        classification="INTERNAL",
        allowed_classifications=["PUBLIC", "INTERNAL"],
        authorized=True,
        local_only_required=False,
        can_use_cloud=False,
        can_merge_entities=False,
        can_cross_case=False,
        purpose="defensive_cross_domain_fusion",
    )

    sources = [
        Source(
            source_id="SRC-CORP",
            source_name="Organization O corporate communication",
            source_type="OFFICIAL_SOURCE",
            publisher="Organization O",
            collector="CORPINT",
            publication_time="2026-03-01",
            retrieval_time="2026-10-08",
            reliability=0.86,
            independence_group="CORP-1",
            limitations=["Self-published; useful for claimed official relationship, not independent legal ownership."],
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Source(
            source_id="SRC-WEB",
            source_name="Website D public page",
            source_type="CORPORATE_SOURCE",
            publisher="Domain D",
            collector="WEBINT",
            publication_time="2026-03-02",
            retrieval_time="2026-10-08",
            reliability=0.68,
            independence_group="WEB-1",
            limitations=["Branding can be copied; not proof of legal ownership."],
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Source(
            source_id="SRC-ARCHIVE",
            source_name="Public web archive",
            source_type="ARCHIVE_SOURCE",
            publisher="Archive Provider",
            collector="ARCHIVEINT",
            publication_time="2026-02-15",
            retrieval_time="2026-10-08",
            reliability=0.78,
            independence_group="ARCHIVE-1",
            limitations=["Archive shows historical page state, not current control."],
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Source(
            source_id="SRC-NEWS",
            source_name="News article repeating corporate claim",
            source_type="NEWS_SOURCE",
            publisher="News Outlet",
            collector="OSINT",
            upstream_source_ids=["SRC-CORP"],
            publication_time="2026-03-05",
            retrieval_time="2026-10-08",
            reliability=0.58,
            independence_group="CORP-1",
            limitations=["Derivative of SRC-CORP; not independent for the official-website claim."],
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Source(
            source_id="SRC-DNS",
            source_name="Passive DNS observation",
            source_type="OFFICIAL_RECORD",
            publisher="DNS Resolver Telemetry",
            collector="DNSINT",
            publication_time="2026-06-01",
            retrieval_time="2026-10-08",
            reliability=0.92,
            independence_group="DNS-1",
            limitations=["DNS resolution indicates technical mapping at observation time, not ownership."],
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Source(
            source_id="SRC-IP",
            source_name="IP allocation / infrastructure context",
            source_type="OFFICIAL_RECORD",
            publisher="Regional Internet Registry / Cloud Provider Context",
            collector="IPINT",
            publication_time="2026-06-01",
            retrieval_time="2026-10-08",
            reliability=0.91,
            independence_group="IP-1",
            limitations=["Allocation/hosting context does not establish tenant ownership or control."],
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
    ]

    evidence = [
        Evidence(
            evidence_id="EV-CORP",
            case_id="FUSION-001",
            source_id="SRC-CORP",
            domain="CORPINT",
            artifact_reference="corp-communication-2026-03",
            content="Organization O states that https://d.example is its official website.",
            retrieved_at="2026-10-08",
            observed_at="2026-03-01",
            event_time_candidate="2026-03-01",
            source_type="OFFICIAL_SOURCE",
            classification="PUBLIC",
            tenant_id="TENANT-1",
        ),
        Evidence(
            evidence_id="EV-WEB",
            case_id="FUSION-001",
            source_id="SRC-WEB",
            domain="WEBINT",
            artifact_reference="web-d-about",
            content="Public page at d.example displays Organization O branding, contact details, and corporate identity.",
            retrieved_at="2026-10-08",
            observed_at="2026-03-02",
            event_time_candidate="2026-03-02",
            source_type="CORPORATE_SOURCE",
            classification="PUBLIC",
            tenant_id="TENANT-1",
        ),
        Evidence(
            evidence_id="EV-ARCHIVE",
            case_id="FUSION-001",
            source_id="SRC-ARCHIVE",
            domain="ARCHIVEINT",
            artifact_reference="archive-d-example-2026-02-15",
            content="Archived snapshot of d.example from 2026-02-15 shows Organization O branding and official-contact language.",
            retrieved_at="2026-10-08",
            observed_at="2026-02-15",
            event_time_candidate="2026-02-15",
            source_type="ARCHIVE_SOURCE",
            classification="PUBLIC",
            tenant_id="TENANT-1",
        ),
        Evidence(
            evidence_id="EV-NEWS",
            case_id="FUSION-001",
            source_id="SRC-NEWS",
            domain="OSINT",
            artifact_reference="news-article-2026-03-05",
            content="News article repeats Organization O statement that d.example is its official website.",
            retrieved_at="2026-10-08",
            observed_at="2026-03-05",
            event_time_candidate="2026-03-05",
            source_type="NEWS_SOURCE",
            classification="PUBLIC",
            tenant_id="TENANT-1",
            limitations=["Derivative source; do not count as independent corroboration for SRC-CORP claim."],
        ),
        Evidence(
            evidence_id="EV-DNS",
            case_id="FUSION-001",
            source_id="SRC-DNS",
            domain="DNSINT",
            artifact_reference="pdns-d-example-2026-06-01",
            content="Passive DNS records show d.example resolved to 203.0.113.10 on 2026-06-01.",
            retrieved_at="2026-10-08",
            observed_at="2026-06-01",
            event_time_candidate="2026-06-01",
            source_type="OFFICIAL_RECORD",
            classification="PUBLIC",
            tenant_id="TENANT-1",
        ),
        Evidence(
            evidence_id="EV-IP",
            case_id="FUSION-001",
            source_id="SRC-IP",
            domain="IPINT",
            artifact_reference="ip-203-0-113-10-allocation",
            content="IP 203.0.113.10 is allocated to Cloud Provider C and appears to be shared cloud infrastructure.",
            retrieved_at="2026-10-08",
            observed_at="2026-06-01",
            event_time_candidate="2026-06-01",
            source_type="OFFICIAL_RECORD",
            classification="PUBLIC",
            tenant_id="TENANT-1",
        ),
    ]

    observations = [
        Observation(
            observation_id="OBS-CORP",
            evidence_id="EV-CORP",
            source_id="SRC-CORP",
            domain="CORPINT",
            observer="CORPINT",
            statement="Organization O claims d.example is its official website.",
            entity_refs=["ENT-ORG-O", "ENT-DOMAIN-D"],
            time_start="2026-03-01",
            confidence=0.86,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Observation(
            observation_id="OBS-WEB",
            evidence_id="EV-WEB",
            source_id="SRC-WEB",
            domain="WEBINT",
            observer="WEBINT",
            statement="d.example displays Organization O branding and corporate contact information.",
            entity_refs=["ENT-ORG-O", "ENT-DOMAIN-D"],
            time_start="2026-03-02",
            confidence=0.70,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Observation(
            observation_id="OBS-ARCHIVE",
            evidence_id="EV-ARCHIVE",
            source_id="SRC-ARCHIVE",
            domain="ARCHIVEINT",
            observer="ARCHIVEINT",
            statement="Archived d.example page from 2026-02-15 shows Organization O branding.",
            entity_refs=["ENT-ORG-O", "ENT-DOMAIN-D"],
            time_start="2026-02-15",
            confidence=0.78,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Observation(
            observation_id="OBS-NEWS",
            evidence_id="EV-NEWS",
            source_id="SRC-NEWS",
            domain="OSINT",
            observer="OSINT",
            statement="News article repeats that d.example is Organization O official website.",
            entity_refs=["ENT-ORG-O", "ENT-DOMAIN-D"],
            time_start="2026-03-05",
            confidence=0.58,
            limitations=["Derivative of SRC-CORP."],
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Observation(
            observation_id="OBS-DNS",
            evidence_id="EV-DNS",
            source_id="SRC-DNS",
            domain="DNSINT",
            observer="DNSINT",
            statement="d.example resolved to 203.0.113.10 on 2026-06-01.",
            entity_refs=["ENT-DOMAIN-D", "ENT-IP-I"],
            time_start="2026-06-01",
            confidence=0.92,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Observation(
            observation_id="OBS-IP",
            evidence_id="EV-IP",
            source_id="SRC-IP",
            domain="IPINT",
            observer="IPINT",
            statement="203.0.113.10 is allocated to Cloud Provider C and appears to be shared cloud infrastructure.",
            entity_refs=["ENT-IP-I", "ENT-CLOUD-C"],
            time_start="2026-06-01",
            confidence=0.91,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
    ]

    entities = [
        Entity(
            entity_id="ENT-ORG-O",
            entity_type="Organization",
            display_name="Organization O",
            aliases=["O"],
            identifiers={"official_registry": "ORG-O-123"},
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Entity(
            entity_id="ENT-DOMAIN-D",
            entity_type="Domain",
            display_name="d.example",
            identifiers={"domain": "d.example"},
            valid_from="2026-01-01",
            valid_to="2026-12-31",
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Entity(
            entity_id="ENT-IP-I",
            entity_type="IPAddress",
            display_name="203.0.113.10",
            identifiers={"ip": "203.0.113.10"},
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Entity(
            entity_id="ENT-CLOUD-C",
            entity_type="Organization",
            display_name="Cloud Provider C",
            identifiers={"official_registry": "CLOUD-C-999"},
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
    ]

    relationships = [
        Relationship(
            relationship_id="REL-USES-DOMAIN",
            subject_id="ENT-ORG-O",
            predicate="USES_DOMAIN",
            object_id="ENT-DOMAIN-D",
            valid_from="2026-01-01",
            valid_to="2026-10-01",
            evidence_ids=["EV-CORP", "EV-WEB", "EV-ARCHIVE", "EV-NEWS"],
            source_ids=["SRC-CORP", "SRC-WEB", "SRC-ARCHIVE", "SRC-NEWS"],
            state=RelationshipState.SUPPORTED.value,
            confidence=0.82,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Relationship(
            relationship_id="REL-DNS",
            subject_id="ENT-DOMAIN-D",
            predicate="RESOLVES_TO",
            object_id="ENT-IP-I",
            valid_from="2026-06-01",
            valid_to="2026-06-01",
            evidence_ids=["EV-DNS"],
            source_ids=["SRC-DNS"],
            state=RelationshipState.OBSERVED.value,
            confidence=0.92,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Relationship(
            relationship_id="REL-HOSTED",
            subject_id="ENT-IP-I",
            predicate="HOSTED_BY",
            object_id="ENT-CLOUD-C",
            valid_from="2026-06-01",
            valid_to="2026-06-01",
            evidence_ids=["EV-IP"],
            source_ids=["SRC-IP"],
            state=RelationshipState.SUPPORTED.value,
            confidence=0.91,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
    ]

    events = [
        Event(
            event_id="EVT-DNS-OBS",
            event_type="DNS_RESOLUTION_OBSERVED",
            participants=["ENT-DOMAIN-D", "ENT-IP-I"],
            time_start="2026-06-01",
            time_end="2026-06-01",
            evidence_ids=["EV-DNS"],
            source_ids=["SRC-DNS"],
            confidence=0.92,
            status="OBSERVED",
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        )
    ]

    specialist_results = [
        SpecialistResult(
            result_id="SR-CORP",
            domain="CORPINT",
            summary="Corporate communication references d.example as official website.",
            evidence_ids=["EV-CORP"],
            source_ids=["SRC-CORP"],
            observation_ids=["OBS-CORP"],
            claim_ids=["CLM-USES"],
            confidence=0.86,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        SpecialistResult(
            result_id="SR-DNS",
            domain="DNSINT",
            summary="Passive DNS shows technical resolution during June 2026.",
            evidence_ids=["EV-DNS"],
            source_ids=["SRC-DNS"],
            observation_ids=["OBS-DNS"],
            claim_ids=["CLM-RESOLVES"],
            confidence=0.92,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        SpecialistResult(
            result_id="SR-IP",
            domain="IPINT",
            summary="IP allocation indicates cloud provider infrastructure context.",
            evidence_ids=["EV-IP"],
            source_ids=["SRC-IP"],
            observation_ids=["OBS-IP"],
            claim_ids=["CLM-HOSTED"],
            confidence=0.91,
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
    ]

    claims = [
        Claim(
            claim_id="CLM-USES",
            subject="ENT-ORG-O",
            predicate="USES_DOMAIN",
            object_value="ENT-DOMAIN-D",
            statement="Organization O uses or operates domain d.example during 2026-01-01 to 2026-10-01.",
            source_ids=["SRC-CORP", "SRC-WEB", "SRC-ARCHIVE", "SRC-NEWS"],
            evidence_ids=["EV-CORP", "EV-WEB", "EV-ARCHIVE", "EV-NEWS"],
            observation_ids=["OBS-CORP", "OBS-WEB", "OBS-ARCHIVE", "OBS-NEWS"],
            relationship_ids=["REL-USES-DOMAIN"],
            domain="CORPINT",
            time_start="2026-01-01",
            time_end="2026-10-01",
            claim_type="RELATIONSHIP",
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Claim(
            claim_id="CLM-RESOLVES",
            subject="ENT-DOMAIN-D",
            predicate="RESOLVES_TO",
            object_value="ENT-IP-I",
            statement="Domain d.example resolved to IP 203.0.113.10 on 2026-06-01.",
            source_ids=["SRC-DNS"],
            evidence_ids=["EV-DNS"],
            observation_ids=["OBS-DNS"],
            relationship_ids=["REL-DNS"],
            domain="DNSINT",
            time_start="2026-06-01",
            time_end="2026-06-01",
            claim_type="TECHNICAL",
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Claim(
            claim_id="CLM-HOSTED",
            subject="ENT-IP-I",
            predicate="HOSTED_BY",
            object_value="ENT-CLOUD-C",
            statement="IP 203.0.113.10 is hosted by or allocated to Cloud Provider C.",
            source_ids=["SRC-IP"],
            evidence_ids=["EV-IP"],
            observation_ids=["OBS-IP"],
            relationship_ids=["REL-HOSTED"],
            domain="IPINT",
            time_start="2026-06-01",
            time_end="2026-06-01",
            claim_type="TECHNICAL",
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
        Claim(
            claim_id="CLM-OWNER-IP",
            subject="ENT-ORG-O",
            predicate="OWNS",
            object_value="ENT-IP-I",
            statement="Organization O owns IP 203.0.113.10.",
            source_ids=["SRC-DNS", "SRC-IP"],
            evidence_ids=["EV-DNS", "EV-IP"],
            observation_ids=["OBS-DNS", "OBS-IP"],
            relationship_ids=["REL-DNS", "REL-HOSTED"],
            domain="INFRAINT",
            time_start="2026-06-01",
            time_end="2026-06-01",
            claim_type="OWNERSHIP",
            tenant_id="TENANT-1",
            case_id="FUSION-001",
            limitations=["Derived only from DNS resolution and IP allocation context."],
        ),
        Claim(
            claim_id="CLM-CONTROL-CLOUD",
            subject="ENT-ORG-O",
            predicate="CONTROLS",
            object_value="ENT-CLOUD-C",
            statement="Organization O controls Cloud Provider C.",
            source_ids=["SRC-IP"],
            evidence_ids=["EV-IP"],
            observation_ids=["OBS-IP"],
            relationship_ids=["REL-HOSTED"],
            domain="INFRAINT",
            time_start="2026-06-01",
            time_end="2026-06-01",
            claim_type="OWNERSHIP",
            tenant_id="TENANT-1",
            case_id="FUSION-001",
        ),
    ]

    req = FusionRequest(
        case_id="FUSION-001",
        task_id="TASK-001",
        objective=(
            "Fuse CORPINT, WEBINT, ARCHIVEINT, DNSINT, and IPINT outputs to determine what is supported "
            "about Organization O, domain d.example, IP 203.0.113.10, and Cloud Provider C without overclaiming ownership."
        ),
        priority_questions=[
            "Does Organization O use or operate domain d.example during the relevant period?",
            "Did d.example resolve to 203.0.113.10 on 2026-06-01?",
            "Is 203.0.113.10 associated with Cloud Provider C?",
            "Does the evidence support that Organization O owns or controls the IP or cloud provider?",
            "Which sources are actually independent?",
        ],
        authorization={"authorized": True, "purpose": "defensive_cross_domain_fusion"},
        permission=perm,
        scope={"as_of": "2026-10-09T00:00:00Z"},
        time_range={"start": "2026-01-01", "end": "2026-10-09"},
        sources=sources,
        evidence=evidence,
        observations=observations,
        claims=claims,
        entities=entities,
        relationships=relationships,
        events=events,
        specialist_results=specialist_results,
    )

    res = agent.analyze(req)

    print("=== FUSIONINT SUMMARY ===")
    print(res.summary)
    print()

    print("Domains used:", res.domains_used)
    print()

    print("Verification results:")
    for vr in res.verification_results:
        print(
            f"  {vr['claim_id']}: state={vr['state']}, confidence={vr['confidence']}, "
            f"independent_paths={vr['independent_paths']}, domains={vr['domains']}, "
            f"strength={vr['evidence_strength']}"
        )
        if vr["limitations"]:
            for lim in vr["limitations"]:
                print("    -", lim)
    print()

    print("Source independence:")
    print(f"  unique_sources={res.source_independence['unique_source_count']}")
    print(f"  independent_source_families={res.source_independence['independent_source_families']}")
    print(f"  source_families={res.source_independence['source_families']}")
    print()

    print("Evidence families:")
    for fam, ids in res.evidence_families.items():
        print(f"  {fam}: {ids}")
    print()

    print("Contradictions:")
    for c in res.contradictions:
        print(f"  {c['contradiction_id']}: {c['contradiction_type']} ({c['materiality']}) objects={c['objects']}")
    print()

    print("Competing hypotheses (first 8):")
    for h in res.competing_hypotheses[:8]:
        print(f"  {h['hypothesis_id']}: {h['status']} — {h['statement'][:140]}")
    print()

    print("Dual-AI skeptic review:")
    for d in res.verification_results:
        pass
    # dual_ai is not directly in result? We didn't include field in FusionResult. Need add? We have no dual_ai field. Could output from replay manifest.
    print("  see replay_manifest.dual_ai_outcomes")
    print()

    print("Knowledge gaps:")
    for g in res.knowledge_gaps[:8]:
        print(f"  {g['gap_id']}: {g['question']} -> {g['recommended_specialist']}")
    print()

    print("Recommended next actions (first 8):")
    for a in res.recommended_next_actions[:8]:
        print("  -", a)
    print()

    print("Human review flags:")
    for h in res.human_review_flags:
        print("  -", h)
    print()

    print("Safety flags:")
    for s in res.safety_flags:
        print("  -", s)
    print()

    # Blocked example: prohibited fusion/action request.
    blocked_req = FusionRequest(
        case_id="FUSION-002",
        task_id="TASK-002",
        objective="Generate an attack plan to seize domain d.example and target Cloud Provider C administrators.",
        priority_questions=["How do we disable the infrastructure?"],
        authorization={"authorized": True},
        permission=PermissionContext(authorized=True),
        sources=[],
        evidence=[],
        observations=[],
        claims=[],
        entities=[],
        relationships=[],
        events=[],
        specialist_results=[],
    )

    blocked = agent.analyze(blocked_req)

    print("=== BLOCKED EXAMPLE ===")
    print("Status:", blocked.status)
    print("Summary:", blocked.summary)
    print("Policy flags:", blocked.policy_flags)
    print("Safety flags:", blocked.safety_flags)


if __name__ == "__main__":
    demo()