#!/usr/bin/env python3
"""
TRACEATLAS / GRAPHINT — Local evidence-first graph intelligence pipeline.

IMPORTANT SAFETY / POLICY NOTES:
- This is a local demo implementation.
- It does NOT access live private records.
- It does NOT fabricate nodes or edges.
- It does NOT auto-merge entities by name.
- It does NOT perform guilt-by-association, social scoring, target selection,
  sabotage planning, biometric identification, or sensitive-trait inference.
- Sample data is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


PIPELINE_VERSION = "0.1.0-graphint-public-safe-demo"


# =====================================================================
# ENUMS
# =====================================================================

class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class SourceType(str, Enum):
    OFFICIAL_GOVERNMENT = "OFFICIAL_GOVERNMENT"
    OFFICIAL_CORPORATE_FILING = "OFFICIAL_CORPORATE_FILING"
    OFFICIAL_INSTITUTION = "OFFICIAL_INSTITUTION"
    PROFESSIONAL_REGISTRY = "PROFESSIONAL_REGISTRY"
    ACADEMIC_IDENTIFIER = "ACADEMIC_IDENTIFIER"
    COURT_OR_REGULATOR = "COURT_OR_REGULATOR"
    DNS_OBSERVATION = "DNS_OBSERVATION"
    HOSTING_OBSERVATION = "HOSTING_OBSERVATION"
    WHOIS_RECORD = "WHOIS_RECORD"
    MEDIA = "MEDIA"
    AGGREGATOR = "AGGREGATOR"
    CTI_REPORT = "CTI_REPORT"
    PERSON_SELF_REPORT = "PERSON_SELF_REPORT"
    UNKNOWN = "UNKNOWN"


class EdgeDirectness(str, Enum):
    DIRECTLY_OBSERVED = "DIRECTLY_OBSERVED"
    DIRECTLY_REPORTED = "DIRECTLY_REPORTED"
    DERIVED_DETERMINISTICALLY = "DERIVED_DETERMINISTICALLY"
    ANALYTICALLY_INFERRED = "ANALYTICALLY_INFERRED"
    SOURCE_CLAIMED = "SOURCE_CLAIMED"
    HYPOTHETICAL = "HYPOTHETICAL"
    UNKNOWN = "UNKNOWN"


class EdgeVerificationState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    RETRACTED = "RETRACTED"
    SUPERSEDED = "SUPERSEDED"


class SourceIndependenceState(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    PARTIALLY_DEPENDENT = "PARTIALLY_DEPENDENT"
    DEPENDENT = "DEPENDENT"
    SINGLE_SOURCE = "SINGLE_SOURCE"
    UNKNOWN = "UNKNOWN"


class ClaimStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    SOURCE_CLAIM_ONLY = "SOURCE_CLAIM_ONLY"
    RETRACTED = "RETRACTED"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


class GapType(str, Enum):
    MISSING_ENTITY = "MISSING_ENTITY"
    MISSING_EDGE = "MISSING_EDGE"
    UNRESOLVED_IDENTITY = "UNRESOLVED_IDENTITY"
    UNRESOLVED_RELATIONSHIP = "UNRESOLVED_RELATIONSHIP"
    TEMPORAL_GAP = "TEMPORAL_GAP"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    SOURCE_INDEPENDENCE_GAP = "SOURCE_INDEPENDENCE_GAP"
    CONTRADICTION_GAP = "CONTRADICTION_GAP"
    COVERAGE_GAP = "COVERAGE_GAP"


class PrivacyFlag(str, Enum):
    CASE_SCOPED = "CASE_SCOPED"
    NO_PRIVATE_DATA_COLLECTED = "NO_PRIVATE_DATA_COLLECTED"
    NO_BIOMETRIC_IDENTIFICATION = "NO_BIOMETRIC_IDENTIFICATION"
    NO_LIVE_LOCATION_INFERENCE = "NO_LIVE_LOCATION_INFERENCE"
    NO_SENSITIVE_TRAIT_INFERENCE = "NO_SENSITIVE_TRAIT_INFERENCE"
    NO_TARGET_SELECTION = "NO_TARGET_SELECTION"
    NO_GUILT_BY_ASSOCIATION = "NO_GUILT_BY_ASSOCIATION"


class PolicyFlag(str, Enum):
    NONE = "NONE"
    BLOCKED_REQUEST = "BLOCKED_REQUEST"
    HUMAN_REVIEW_RECOMMENDED = "HUMAN_REVIEW_RECOMMENDED"


# =====================================================================
# CONSTANTS
# =====================================================================

ENTITY_NODE_TYPES = {
    "Company",
    "Organization",
    "Provider",
    "Domain",
    "IP",
    "Hostname",
    "PersonCandidate",
    "Account",
    "UnresolvedEntity",
}

VERIFICATION_RANK = {
    EdgeVerificationState.SUPPORTED: 4,
    EdgeVerificationState.PARTIALLY_SUPPORTED: 3,
    EdgeVerificationState.INCONCLUSIVE: 2,
    EdgeVerificationState.DISPUTED: 1,
    EdgeVerificationState.UNSUPPORTED: 0,
    EdgeVerificationState.RETRACTED: -1,
    EdgeVerificationState.SUPERSEDED: -1,
}

VERIFICATION_FACTOR = {
    EdgeVerificationState.SUPPORTED: 1.0,
    EdgeVerificationState.PARTIALLY_SUPPORTED: 0.75,
    EdgeVerificationState.INCONCLUSIVE: 0.45,
    EdgeVerificationState.DISPUTED: 0.25,
    EdgeVerificationState.UNSUPPORTED: 0.10,
    EdgeVerificationState.RETRACTED: 0.0,
    EdgeVerificationState.SUPERSEDED: 0.0,
}

INDEPENDENCE_FACTOR = {
    SourceIndependenceState.INDEPENDENT: 1.0,
    SourceIndependenceState.PARTIALLY_DEPENDENT: 0.80,
    SourceIndependenceState.SINGLE_SOURCE: 0.70,
    SourceIndependenceState.DEPENDENT: 0.50,
    SourceIndependenceState.UNKNOWN: 0.60,
}

EDGE_SCHEMA: Dict[str, Dict[str, Any]] = {
    "OWNS_PERCENT": {
        "source_types": {"Company", "Organization"},
        "target_types": {"Company", "Organization"},
        "direction": "directed",
        "symmetric": False,
        "transitive": "economic_interest_only",
        "required_evidence": True,
    },
    "POTENTIAL_INDIRECT_ECONOMIC_INTEREST": {
        "source_types": {"Company", "Organization"},
        "target_types": {"Company", "Organization"},
        "direction": "directed",
        "symmetric": False,
        "transitive": "not_control",
        "required_evidence": True,
    },
    "RESOLVES_TO": {
        "source_types": {"Domain", "Hostname"},
        "target_types": {"IP", "Hostname"},
        "direction": "directed",
        "symmetric": False,
        "transitive": False,
        "required_evidence": True,
    },
    "HOSTED_BY": {
        "source_types": {"Domain", "IP", "Hostname"},
        "target_types": {"Provider", "Organization"},
        "direction": "directed",
        "symmetric": False,
        "transitive": False,
        "required_evidence": True,
    },
    "USES_PROVIDER": {
        "source_types": {"Domain", "IP", "Hostname", "Account"},
        "target_types": {"Provider", "Organization"},
        "direction": "directed",
        "symmetric": False,
        "transitive": False,
        "required_evidence": True,
    },
}


# =====================================================================
# UTILITIES
# =====================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def today_iso() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def new_id(prefix: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}{h}" if prefix else h


def jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: jsonable(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, (list, tuple, set)):
        return [jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    return obj


def parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except Exception:
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except Exception:
            return None


def normalize_label(value: str) -> str:
    s = unicodedata.normalize("NFKC", value or "")
    s = s.lower().strip()
    s = re.sub(r"[^\w\s\-'.]", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# =====================================================================
# POLICY GUARD
# =====================================================================

PROHIBITED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "AUTONOMOUS_TARGET_SELECTION",
        re.compile(
            r"\b(best\s+(?:person|server|supplier|individual|node)\s+to\s+"
            r"(?:attack|disrupt|sabotage|pressure|target)|target\s+selection)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "GUILT_BY_ASSOCIATION_OR_SOCIAL_SCORING",
        re.compile(
            r"\b(guilt\s+by\s+association|criminal\s+risk\s+score|"
            r"social\s+credit|danger\s+score|loyalty\s+score)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SENSITIVE_TRAIT_INFERENCE",
        re.compile(
            r"\b(infer|determine|score|identify)[^\n]{0,80}\b"
            r"(religion|ethnicity|sexual orientation|health|mental health|"
            r"political ideology)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "UNAUTHORIZED_ACCESS",
        re.compile(
            r"\b(hack|bypass|login|stolen)[^\n]{0,60}\b"
            r"(account|credential|private|session|cookie|authentication)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "BIOMETRIC_IDENTIFICATION",
        re.compile(
            r"\b(face|facial|voiceprint|biometric)[^\n]{0,60}\b"
            r"(identif|match|recogni)",
            re.IGNORECASE,
        ),
    ),
]


def policy_guard(text: str) -> List[Dict[str, str]]:
    violations: List[Dict[str, str]] = []
    for rule, rx in PROHIBITED_PATTERNS:
        m = rx.search(text or "")
        if m:
            violations.append({"rule": rule, "matched": m.group(0)})
    return violations


# =====================================================================
# DATACLASSES
# =====================================================================

@dataclass
class Source:
    id: str
    title: str
    url: str
    source_type: SourceType
    published_at: Optional[str] = None
    retrieved_at: Optional[str] = None
    effective_at: Optional[str] = None
    independence_group: str = "UNKNOWN"
    reliability: float = 0.5
    derived_from: Optional[str] = None
    notes: str = ""


@dataclass
class Evidence:
    id: str
    source_id: str
    artifact_type: str
    excerpt: str
    observed_at: Optional[str] = None
    content_hash: Optional[str] = None
    notes: str = ""


@dataclass
class Claim:
    id: str
    subject_node_id: str
    predicate: str
    object_node_id: str
    value: Optional[float] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    source_id: Optional[str] = None
    evidence_id: Optional[str] = None
    status: ClaimStatus = ClaimStatus.SOURCE_CLAIM_ONLY
    confidence: float = 0.5
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Node:
    id: str
    node_type: str
    canonical_label: str
    display_label: str
    aliases: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    classification: str = "UNCLASSIFIED"
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    verification_state: str = EdgeVerificationState.UNSUPPORTED.value
    access_control: str = "CASE_SCOPED"
    limitations: List[str] = field(default_factory=list)


@dataclass
class Edge:
    id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    direction: str = "DIRECTED"
    relationship_state: str = "UNKNOWN"
    directness: EdgeDirectness = EdgeDirectness.UNKNOWN
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    observed_at: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    claim_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    verification_state: EdgeVerificationState = EdgeVerificationState.INCONCLUSIVE
    independence_state: SourceIndependenceState = SourceIndependenceState.UNKNOWN
    limitations: List[str] = field(default_factory=list)
    access_control: str = "CASE_SCOPED"
    derivation_method: Optional[str] = None
    inputs: List[str] = field(default_factory=list)
    algorithm_version: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)


@dataclass
class Hypothesis:
    id: str
    statement: str
    layer: str = "HYPOTHESIS"
    supporting_edge_ids: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    predictions: List[str] = field(default_factory=list)
    falsification_conditions: List[str] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Contradiction:
    id: str
    description: str
    node_ids: List[str] = field(default_factory=list)
    edge_ids: List[str] = field(default_factory=list)
    claim_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    status: str = "OPEN"
    recommended_resolution: str = ""


@dataclass
class KnowledgeGap:
    id: str
    gap_type: GapType
    description: str
    about_node_ids: List[str] = field(default_factory=list)
    about_edge_ids: List[str] = field(default_factory=list)
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: Optional[str] = None
    expected_information_value: float = 0.0


@dataclass
class NextAction:
    id: str
    description: str
    priority: int = 1
    privacy_impact: str = "LOW"
    expected_gain: float = 0.0
    specialist: Optional[str] = None


@dataclass
class PathResult:
    path_id: str
    start_node_id: str
    target_node_id: str
    hops: int
    node_ids: List[str]
    edge_ids: List[str]
    edge_directions: List[str]
    relationship_types: List[str]
    temporal_valid: bool
    confidence: float
    components: Dict[str, float]
    explanation: List[str]
    verification_states: List[str]
    independence_state: str
    limitations: List[str]


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: ["public_records_only", "case_scoped"])
    authorization: str = "demo_authorized_public_records"
    target_entities: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    max_hops: int = 3
    sample: bool = False
    budget: Optional[str] = None
    deadline: Optional[str] = None


# =====================================================================
# GRAPH ENGINE
# =====================================================================

class GraphInt:
    def __init__(self) -> None:
        self.sources: Dict[str, Source] = {}
        self.evidences: Dict[str, Evidence] = {}
        self.claims: Dict[str, Claim] = {}
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, Edge] = {}
        self.hypotheses: Dict[str, Hypothesis] = {}
        self.contradictions: Dict[str, Contradiction] = {}
        self.entity_resolutions: List[Dict[str, Any]] = []
        self.validation_errors: List[str] = []

    # -----------------------------------------------------------------
    # Adders
    # -----------------------------------------------------------------

    def add_source(self, source: Source) -> Source:
        self.sources[source.id] = source
        return source

    def add_evidence(self, evidence: Evidence) -> Evidence:
        if not evidence.content_hash:
            evidence.content_hash = stable_hash(evidence.excerpt + evidence.source_id)
        self.evidences[evidence.id] = evidence
        return evidence

    def add_claim(self, claim: Claim) -> Claim:
        self.claims[claim.id] = claim
        return claim

    def add_node(self, node: Node) -> Node:
        if not node.created_at:
            node.created_at = now_iso()
        node.updated_at = now_iso()
        self.nodes[node.id] = node
        return node

    def add_edge(self, edge: Edge) -> Edge:
        if not edge.first_seen:
            edge.first_seen = edge.observed_at or edge.valid_from or now_iso()
        if not edge.last_seen:
            edge.last_seen = edge.observed_at or edge.valid_to or now_iso()
        edge.updated_at = now_iso()
        self.edges[edge.id] = edge
        return edge

    def add_hypothesis(self, hypothesis: Hypothesis) -> Hypothesis:
        self.hypotheses[hypothesis.id] = hypothesis
        return hypothesis

    def add_contradiction(self, contradiction: Contradiction) -> Contradiction:
        self.contradictions[contradiction.id] = contradiction
        return contradiction

    def add_entity_resolution(self, result: Dict[str, Any]) -> None:
        self.entity_resolutions.append(result)

    # -----------------------------------------------------------------
    # Provenance / independence
    # -----------------------------------------------------------------

    def get_source_family(self, source_id: str) -> Optional[str]:
        src = self.sources.get(source_id)
        if not src:
            return None
        seen: Set[str] = set()
        cur = src
        while (
            cur
            and cur.derived_from
            and cur.derived_from in self.sources
            and cur.id not in seen
        ):
            seen.add(cur.id)
            cur = self.sources[cur.derived_from]
        return cur.id if cur else source_id

    def source_families(self, source_ids: List[str]) -> Set[str]:
        families: Set[str] = set()
        for sid in source_ids:
            fam = self.get_source_family(sid)
            families.add(fam or sid)
        return families

    def independence_state_for_sources(self, source_ids: List[str]) -> SourceIndependenceState:
        if not source_ids:
            return SourceIndependenceState.UNKNOWN
        families = self.source_families(source_ids)
        if len(source_ids) == 1:
            return SourceIndependenceState.SINGLE_SOURCE
        if len(families) == 1:
            return SourceIndependenceState.DEPENDENT
        if len(families) == len(source_ids):
            return SourceIndependenceState.INDEPENDENT
        return SourceIndependenceState.PARTIALLY_DEPENDENT

    def update_edge_independence(self) -> None:
        for edge in self.edges.values():
            edge.independence_state = self.independence_state_for_sources(edge.source_ids)

    # -----------------------------------------------------------------
    # Temporal helpers
    # -----------------------------------------------------------------

    def edge_time_overlap(
        self,
        edge: Edge,
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> bool:
        qs = parse_date(start)
        qe = parse_date(end) or qs
        ef = parse_date(edge.valid_from)
        et = parse_date(edge.valid_to)

        if qs and et and et < qs:
            return False
        if qe and ef and ef > qe:
            return False
        return True

    def edge_is_temporally_explicit(self, edge: Edge) -> bool:
        return bool(edge.valid_from)

    def refresh_temporal_states(self, today: Optional[str] = None) -> None:
        td = parse_date(today or today_iso())
        for edge in self.edges.values():
            ef = parse_date(edge.valid_from)
            et = parse_date(edge.valid_to)
            if td and et and et < td:
                edge.relationship_state = "HISTORICAL"
            elif td and ef and ef <= td and (not et or et >= td):
                edge.relationship_state = "CURRENT"
            else:
                edge.relationship_state = "UNKNOWN"

    def temporal_edges(
        self,
        start: Optional[str] = None,
        end: Optional[str] = None,
        allowed_verification: Optional[EdgeVerificationState] = None,
        allowed_types: Optional[Set[str]] = None,
    ) -> List[Edge]:
        min_rank = VERIFICATION_RANK.get(allowed_verification, -99) if allowed_verification else -99
        out: List[Edge] = []
        for edge in self.edges.values():
            if allowed_types and edge.relationship_type not in allowed_types:
                continue
            if allowed_verification and VERIFICATION_RANK.get(edge.verification_state, -99) < min_rank:
                continue
            if (start or end) and not self.edge_time_overlap(edge, start, end):
                continue
            out.append(edge)
        return out

    # -----------------------------------------------------------------
    # Validation / contradictions
    # -----------------------------------------------------------------

    def validate_schema(self) -> List[str]:
        errors: List[str] = []
        for edge in self.edges.values():
            if edge.source_node_id not in self.nodes:
                errors.append(f"Edge {edge.id}: missing source node {edge.source_node_id}")
            if edge.target_node_id not in self.nodes:
                errors.append(f"Edge {edge.id}: missing target node {edge.target_node_id}")

            vf = parse_date(edge.valid_from)
            vt = parse_date(edge.valid_to)
            if vf and vt and vt < vf:
                errors.append(f"Edge {edge.id}: valid_to before valid_from")

            schema = EDGE_SCHEMA.get(edge.relationship_type)
            if schema:
                src_node = self.nodes.get(edge.source_node_id)
                tgt_node = self.nodes.get(edge.target_node_id)
                if src_node and schema.get("source_types") and src_node.node_type not in schema["source_types"]:
                    errors.append(
                        f"Edge {edge.id}: source type {src_node.node_type} invalid for "
                        f"{edge.relationship_type}"
                    )
                if tgt_node and schema.get("target_types") and tgt_node.node_type not in schema["target_types"]:
                    errors.append(
                        f"Edge {edge.id}: target type {tgt_node.node_type} invalid for "
                        f"{edge.relationship_type}"
                    )
        self.validation_errors = errors
        return errors

    def detect_contradictions(self) -> List[Contradiction]:
        found: List[Contradiction] = []
        existing_descriptions = {c.description for c in self.contradictions.values()}

        # Edge-level conflicts: same source/target/type, overlapping time, different percent.
        grouped: Dict[Tuple[str, str, str], List[Edge]] = defaultdict(list)
        for edge in self.edges.values():
            grouped[(edge.source_node_id, edge.target_node_id, edge.relationship_type)].append(edge)

        for (_, _, rtype), edges in grouped.items():
            if len(edges) < 2 or rtype != "OWNS_PERCENT":
                continue
            for i in range(len(edges)):
                for j in range(i + 1, len(edges)):
                    e1, e2 = edges[i], edges[j]
                    p1 = e1.attributes.get("percent")
                    p2 = e2.attributes.get("percent")
                    if p1 is None or p2 is None:
                        continue
                    if float(p1) == float(p2):
                        continue
                    if not (
                        self.edge_time_overlap(e1, e2.valid_from, e2.valid_to)
                        and self.edge_time_overlap(e2, e1.valid_from, e1.valid_to)
                    ):
                        continue
                    desc = (
                        f"Conflicting {rtype} edges between {e1.source_node_id} and "
                        f"{e1.target_node_id}: {p1}% vs {p2}% during overlapping period."
                    )
                    if desc in existing_descriptions:
                        continue
                    con = Contradiction(
                        id=new_id("CON-", desc),
                        description=desc,
                        node_ids=[e1.source_node_id, e1.target_node_id],
                        edge_ids=[e1.id, e2.id],
                        source_ids=sorted(set(e1.source_ids + e2.source_ids)),
                        severity="MATERIAL",
                        status="OPEN",
                        recommended_resolution=(
                            "Prefer official registry primary record; mark secondary claim disputed."
                        ),
                    )
                    found.append(con)
                    self.add_contradiction(con)
                    existing_descriptions.add(desc)

        # Claim vs edge conflicts.
        for claim in self.claims.values():
            if claim.predicate != "OWNS_PERCENT" or claim.value is None:
                continue
            for edge in self.edges.values():
                if (
                    edge.relationship_type == claim.predicate
                    and edge.source_node_id == claim.subject_node_id
                    and edge.target_node_id == claim.object_node_id
                ):
                    edge_val = edge.attributes.get("percent")
                    if edge_val is None:
                        continue
                    if float(claim.value) == float(edge_val):
                        continue
                    if not self.edge_time_overlap(edge, claim.valid_from, claim.valid_to):
                        continue
                    desc = (
                        f"Claim {claim.id} states {claim.value}% ownership, but edge "
                        f"{edge.id} is supported at {edge_val}% for the same relationship period."
                    )
                    if desc in existing_descriptions:
                        continue
                    con = Contradiction(
                        id=new_id("CON-", desc),
                        description=desc,
                        node_ids=[claim.subject_node_id, claim.object_node_id],
                        edge_ids=[edge.id],
                        claim_ids=[claim.id],
                        source_ids=sorted({s for s in [claim.source_id, edge.source_ids[0] if edge.source_ids else None] if s}),
                        severity="MATERIAL",
                        status="OPEN",
                        recommended_resolution=(
                            "Treat media/aggregator claim as dependent and disputed unless primary registry confirms."
                        ),
                    )
                    found.append(con)
                    self.add_contradiction(con)
                    existing_descriptions.add(desc)

        return found

    # -----------------------------------------------------------------
    # Path finding
    # -----------------------------------------------------------------

    def neighbors(
        self,
        node_id: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
        allowed_types: Optional[Set[str]] = None,
        allowed_verification: Optional[EdgeVerificationState] = None,
        directed: bool = True,
    ) -> List[Tuple[str, Edge, str]]:
        out: List[Tuple[str, Edge, str]] = []
        for edge in self.temporal_edges(start, end, allowed_verification, allowed_types):
            if edge.source_node_id == node_id:
                out.append((edge.target_node_id, edge, "out"))
            if not directed and edge.target_node_id == node_id:
                out.append((edge.source_node_id, edge, "in"))
        return out

    def find_paths(
        self,
        start_node_id: str,
        target_node_id: str,
        max_hops: int = 3,
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
        allowed_types: Optional[Set[str]] = None,
        directed: bool = True,
        min_verification: EdgeVerificationState = EdgeVerificationState.PARTIALLY_SUPPORTED,
        max_paths: int = 20,
    ) -> List[PathResult]:
        if start_node_id not in self.nodes or target_node_id not in self.nodes:
            return []

        results: List[PathResult] = []
        queue: deque[Tuple[str, List[str], List[str], List[str], Set[str]]] = deque()
        queue.append((start_node_id, [], [], [start_node_id], {start_node_id}))

        while queue and len(results) < max_paths:
            current, edge_ids, directions, node_ids, visited = queue.popleft()
            if len(edge_ids) >= max_hops:
                continue

            for neighbor, edge, direction in self.neighbors(
                current,
                time_start,
                time_end,
                allowed_types,
                min_verification,
                directed,
            ):
                if neighbor in visited:
                    continue

                new_edge_ids = edge_ids + [edge.id]
                new_directions = directions + [direction]
                new_node_ids = node_ids + [neighbor]
                new_visited = visited | {neighbor}

                if neighbor == target_node_id:
                    results.append(
                        self._build_path_result(
                            new_node_ids,
                            new_edge_ids,
                            new_directions,
                            time_start,
                            time_end,
                        )
                    )
                    if len(results) >= max_paths:
                        break
                else:
                    queue.append((neighbor, new_edge_ids, new_directions, new_node_ids, new_visited))

        return results

    def _build_path_result(
        self,
        node_ids: List[str],
        edge_ids: List[str],
        directions: List[str],
        time_start: Optional[str],
        time_end: Optional[str],
    ) -> PathResult:
        edges = [self.edges[eid] for eid in edge_ids]
        relationship_types = [e.relationship_type for e in edges]
        verification_states = [e.verification_state.value for e in edges]

        temporal_valid = all(
            self.edge_is_temporally_explicit(e) and self.edge_time_overlap(e, time_start, time_end)
            for e in edges
        )

        source_ids = sorted({sid for e in edges for sid in e.source_ids})
        families = self.source_families(source_ids)
        if not source_ids:
            independence_state = SourceIndependenceState.UNKNOWN
        elif len(source_ids) == 1:
            independence_state = SourceIndependenceState.SINGLE_SOURCE
        elif len(families) == 1:
            independence_state = SourceIndependenceState.DEPENDENT
        elif len(families) >= len(edges):
            independence_state = SourceIndependenceState.INDEPENDENT
        else:
            independence_state = SourceIndependenceState.PARTIALLY_DEPENDENT

        edge_scores: List[float] = []
        for e in edges:
            temporal_factor = 1.0 if temporal_valid else 0.55
            score = (
                float(e.confidence)
                * VERIFICATION_FACTOR.get(e.verification_state, 0.3)
                * INDEPENDENCE_FACTOR.get(e.independence_state, 0.5)
                * temporal_factor
            )
            edge_scores.append(score)

        bottleneck = min(edge_scores) if edge_scores else 0.0
        average = sum(edge_scores) / len(edge_scores) if edge_scores else 0.0
        confidence = round((bottleneck * 0.65) + (average * 0.35), 3)

        explanation: List[str] = []
        for i, edge in enumerate(edges):
            prev = node_ids[i]
            nxt = node_ids[i + 1]
            if directions[i] == "out":
                arrow = f"-[{edge.relationship_type}]->"
            else:
                arrow = f"<-[{edge.relationship_type}]-"
            explanation.append(
                f"{prev} {arrow} {nxt} "
                f"[edge={edge.id}; verification={edge.verification_state.value}; "
                f"confidence={edge.confidence}; evidence={','.join(edge.evidence_ids) or 'none'}]"
            )

        limitations: List[str] = []
        if not temporal_valid:
            limitations.append("Path is not fully temporally validated.")
        if independence_state != SourceIndependenceState.INDEPENDENT:
            limitations.append(f"Source independence is {independence_state.value}.")
        if len(edges) > 2:
            limitations.append("Longer path increases uncertainty.")
        if any(e.confidence < 0.7 for e in edges):
            limitations.append("At least one edge has confidence below 0.70.")
        if any(e.verification_state != EdgeVerificationState.SUPPORTED for e in edges):
            limitations.append("Not all edges are fully supported.")

        return PathResult(
            path_id=new_id("PATH-", "".join(edge_ids) + "".join(node_ids)),
            start_node_id=node_ids[0],
            target_node_id=node_ids[-1],
            hops=len(edge_ids),
            node_ids=node_ids,
            edge_ids=edge_ids,
            edge_directions=directions,
            relationship_types=relationship_types,
            temporal_valid=temporal_valid,
            confidence=confidence,
            components={
                "bottleneck_edge_score": round(bottleneck, 3),
                "average_edge_score": round(average, 3),
                "temporal_valid": 1.0 if temporal_valid else 0.0,
                "independence_factor": INDEPENDENCE_FACTOR.get(independence_state, 0.5),
            },
            explanation=explanation,
            verification_states=verification_states,
            independence_state=independence_state.value,
            limitations=limitations,
        )

    # -----------------------------------------------------------------
    # Analytics
    # -----------------------------------------------------------------

    def degree_centrality(
        self,
        allowed_verification: EdgeVerificationState = EdgeVerificationState.SUPPORTED,
    ) -> Dict[str, float]:
        deg: Dict[str, int] = defaultdict(int)
        min_rank = VERIFICATION_RANK[allowed_verification]
        for edge in self.edges.values():
            if VERIFICATION_RANK.get(edge.verification_state, -99) < min_rank:
                continue
            deg[edge.source_node_id] += 1
            deg[edge.target_node_id] += 1
        if not deg:
            return {}
        max_deg = max(deg.values())
        return {node: round(count / max_deg, 3) for node, count in deg.items()}

    def connected_components(
        self,
        allowed_verification: EdgeVerificationState = EdgeVerificationState.SUPPORTED,
    ) -> List[List[str]]:
        adj: Dict[str, Set[str]] = defaultdict(set)
        min_rank = VERIFICATION_RANK[allowed_verification]
        entity_nodes = {nid for nid, n in self.nodes.items() if n.node_type in ENTITY_NODE_TYPES}

        for edge in self.edges.values():
            if VERIFICATION_RANK.get(edge.verification_state, -99) < min_rank:
                continue
            if edge.source_node_id in entity_nodes and edge.target_node_id in entity_nodes:
                adj[edge.source_node_id].add(edge.target_node_id)
                adj[edge.target_node_id].add(edge.source_node_id)

        visited: Set[str] = set()
        components: List[List[str]] = []
        for node in sorted(entity_nodes):
            if node in visited:
                continue
            q = deque([node])
            comp: List[str] = []
            visited.add(node)
            while q:
                cur = q.popleft()
                comp.append(cur)
                for nxt in adj.get(cur, set()):
                    if nxt not in visited:
                        visited.add(nxt)
                        q.append(nxt)
            components.append(sorted(comp))
        return components

    def graph_as_of(self, timestamp: str) -> Dict[str, Any]:
        ts = parse_date(timestamp)
        nodes: Dict[str, Node] = {}
        edges: Dict[str, Edge] = {}

        for nid, node in self.nodes.items():
            nf = parse_date(node.valid_from)
            nt = parse_date(node.valid_to)
            if ts and nf and nf > ts:
                continue
            if ts and nt and nt < ts:
                continue
            nodes[nid] = node

        for eid, edge in self.edges.items():
            if edge.source_node_id not in nodes or edge.target_node_id not in nodes:
                continue
            if self.edge_time_overlap(edge, timestamp, timestamp):
                edges[eid] = edge

        return {
            "snapshot_id": new_id("SNAP-", timestamp),
            "timestamp": timestamp,
            "nodes": nodes,
            "edges": edges,
        }

    def graph_diff(
        self,
        snapshot_a: Dict[str, Any],
        snapshot_b: Dict[str, Any],
    ) -> Dict[str, Any]:
        a_nodes = set(snapshot_a.get("nodes", {}).keys())
        b_nodes = set(snapshot_b.get("nodes", {}).keys())
        a_edges = set(snapshot_a.get("edges", {}).keys())
        b_edges = set(snapshot_b.get("edges", {}).keys())

        changed_edges: List[Dict[str, Any]] = []
        for eid in sorted(a_edges & b_edges):
            ea: Edge = snapshot_a["edges"][eid]
            eb: Edge = snapshot_b["edges"][eid]
            if (
                ea.verification_state != eb.verification_state
                or abs(float(ea.confidence) - float(eb.confidence)) > 0.01
                or ea.relationship_state != eb.relationship_state
            ):
                changed_edges.append(
                    {
                        "edge_id": eid,
                        "from_verification": ea.verification_state.value,
                        "to_verification": eb.verification_state.value,
                        "from_confidence": ea.confidence,
                        "to_confidence": eb.confidence,
                        "from_state": ea.relationship_state,
                        "to_state": eb.relationship_state,
                    }
                )

        return {
            "from_snapshot": snapshot_a.get("snapshot_id"),
            "to_snapshot": snapshot_b.get("snapshot_id"),
            "nodes_added": sorted(b_nodes - a_nodes),
            "nodes_removed": sorted(a_nodes - b_nodes),
            "edges_added": sorted(b_edges - a_edges),
            "edges_removed": sorted(a_edges - b_edges),
            "edges_changed": changed_edges,
        }

    # -----------------------------------------------------------------
    # Deterministic derivation / fact gate
    # -----------------------------------------------------------------

    def derive_deterministic_edges(self) -> List[Edge]:
        derived: List[Edge] = []
        paths = self.find_paths(
            start_node_id="COMPANY-A",
            target_node_id="COMPANY-C",
            max_hops=3,
            time_start="2024-01-01",
            time_end="2024-12-31",
            allowed_types={"OWNS_PERCENT"},
            directed=True,
            min_verification=EdgeVerificationState.SUPPORTED,
            max_paths=5,
        )

        for path in paths:
            percent = 1.0
            valid_froms: List[date] = []
            valid_tos: List[date] = []
            source_ids: Set[str] = set()
            evidence_ids: Set[str] = set()

            for eid in path.edge_ids:
                edge = self.edges[eid]
                p = edge.attributes.get("percent")
                if p is None:
                    percent = 0.0
                    break
                percent *= float(p) / 100.0
                vf = parse_date(edge.valid_from)
                vt = parse_date(edge.valid_to)
                if vf:
                    valid_froms.append(vf)
                if vt:
                    valid_tos.append(vt)
                source_ids.update(edge.source_ids)
                evidence_ids.update(edge.evidence_ids)

            if percent <= 0:
                continue

            indirect_percent = round(percent * 100, 2)
            edge_id = new_id("E-DERIVED-", f"{path.start_node_id}-{path.target_node_id}-{indirect_percent}")
            if edge_id in self.edges:
                continue

            derived_edge = Edge(
                id=edge_id,
                source_node_id=path.start_node_id,
                target_node_id=path.target_node_id,
                relationship_type="POTENTIAL_INDIRECT_ECONOMIC_INTEREST",
                direction="DIRECTED",
                relationship_state="HISTORICAL",
                directness=EdgeDirectness.DERIVED_DETERMINISTICALLY,
                valid_from=max(valid_froms).isoformat() if valid_froms else None,
                valid_to=min(valid_tos).isoformat() if valid_tos else None,
                observed_at=now_iso(),
                source_ids=sorted(source_ids),
                evidence_ids=sorted(evidence_ids),
                claim_ids=[],
                confidence=round(min(path.confidence, 0.95), 3),
                verification_state=EdgeVerificationState.SUPPORTED,
                independence_state=SourceIndependenceState.UNKNOWN,
                limitations=[
                    "Deterministic arithmetic only.",
                    "Does not establish control.",
                    "Does not establish beneficial ownership.",
                    "Does not establish current status outside the valid period.",
                ],
                derivation_method="multiply_ownership_percent",
                inputs=path.edge_ids,
                algorithm_version=PIPELINE_VERSION,
                attributes={
                    "percent": indirect_percent,
                    "basis": "multiplicative indirect economic interest",
                    "control_established": False,
                },
            )
            self.add_edge(derived_edge)
            derived.append(derived_edge)

        return derived

    def prepare(self) -> None:
        self.refresh_temporal_states()
        self.update_edge_independence()
        self.validate_schema()
        self.detect_contradictions()
        self.derive_deterministic_edges()
        self.update_edge_independence()
        self.refresh_temporal_states()


# =====================================================================
# SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-GRAPHINT-001",
        task_id="TASK-GRAPHINT-001",
        objective=(
            "Determine evidence-linked relationships among Company A, Company B, Company C, "
            "Domain D1, Domain D2, IP 198.51.100.10, and Provider X; distinguish supported "
            "relationships from hypotheses and preserve temporal/provenance limits."
        ),
        questions=[
            "How is Company A related to Company C during 2024?",
            "Does the graph support an indirect economic-interest calculation?",
            "Are Domain D1 and Domain D2 operated by the same entity?",
            "Which paths are evidence-supported and which are merely structural?",
            "Which sources are dependent rather than independent?",
        ],
        target_entities=[
            "Company A",
            "Company B",
            "Company C",
            "d1.example",
            "d2.example",
            "198.51.100.10",
            "Provider X",
        ],
        time_range="2024-2026",
        max_hops=4,
        sample=True,
    )


def build_sample_graph() -> GraphInt:
    g = GraphInt()
    retrieved = now_iso()

    # Sources
    g.add_source(Source(
        id="SRC-REG-A",
        title="Corporate registry extract: Company A ownership of Company B",
        url="https://registry.example/extract/a-b",
        source_type=SourceType.OFFICIAL_CORPORATE_FILING,
        published_at="2024-03-15",
        retrieved_at=retrieved,
        effective_at="2024-03-15",
        independence_group="REG_ROOT_A",
        reliability=0.95,
        notes="Official corporate filing for 2024 ownership.",
    ))
    g.add_source(Source(
        id="SRC-REG-B",
        title="Corporate registry extract: Company B ownership of Company C",
        url="https://registry.example/extract/b-c",
        source_type=SourceType.OFFICIAL_CORPORATE_FILING,
        published_at="2024-04-02",
        retrieved_at=retrieved,
        effective_at="2024-04-02",
        independence_group="REG_ROOT_B",
        reliability=0.95,
        notes="Official corporate filing for 2024 ownership.",
    ))
    g.add_source(Source(
        id="SRC-NEWS-1",
        title="News article summarizing Company A ownership",
        url="https://news.example/company-a-ownership",
        source_type=SourceType.MEDIA,
        published_at="2024-04-10",
        retrieved_at=retrieved,
        effective_at="2024-04-10",
        independence_group="NEWS_DERIVED_REG_A",
        reliability=0.55,
        derived_from="SRC-REG-A",
        notes="Appears to paraphrase registry source; not independent for ownership percentage.",
    ))
    g.add_source(Source(
        id="SRC-AGG-2",
        title="Aggregator repost of news article",
        url="https://agg.example/company-a-ownership",
        source_type=SourceType.AGGREGATOR,
        published_at="2024-04-11",
        retrieved_at=retrieved,
        effective_at="2024-04-11",
        independence_group="AGG_DERIVED_REG_A",
        reliability=0.35,
        derived_from="SRC-NEWS-1",
        notes="Downstream copy; not new evidence.",
    ))
    g.add_source(Source(
        id="SRC-DNS",
        title="DNS observation for d1.example",
        url="https://dns.example/observations/d1",
        source_type=SourceType.DNS_OBSERVATION,
        published_at="2026-01-15",
        retrieved_at=retrieved,
        effective_at="2026-01-15",
        independence_group="DNS_ROOT",
        reliability=0.80,
        notes="Observed A record during January 2026.",
    ))
    g.add_source(Source(
        id="SRC-HOST",
        title="Hosting/provider observation for d2.example and IP",
        url="https://host.example/observations/provider-x",
        source_type=SourceType.HOSTING_OBSERVATION,
        published_at="2026-01-16",
        retrieved_at=retrieved,
        effective_at="2026-01-16",
        independence_group="HOST_ROOT",
        reliability=0.75,
        notes="Provider assignment observation; shared provider is not operator identity.",
    ))
    g.add_source(Source(
        id="SRC-WHOIS",
        title="WHOIS privacy status for d1.example and d2.example",
        url="https://whois.example/privacy/d1-d2",
        source_type=SourceType.WHOIS_RECORD,
        published_at="2026-01-17",
        retrieved_at=retrieved,
        effective_at="2026-01-17",
        independence_group="WHOIS_ROOT",
        reliability=0.60,
        notes="Registrant data privacy-preserved; does not establish common operator.",
    ))

    # Evidence
    g.add_evidence(Evidence(
        id="EV-REG-A",
        source_id="SRC-REG-A",
        artifact_type="registry_record",
        excerpt="Company A owned 60% of Company B during 2024.",
        observed_at="2024-03-15",
    ))
    g.add_evidence(Evidence(
        id="EV-REG-B",
        source_id="SRC-REG-B",
        artifact_type="registry_record",
        excerpt="Company B owned 50% of Company C during 2024.",
        observed_at="2024-04-02",
    ))
    g.add_evidence(Evidence(
        id="EV-NEWS-1",
        source_id="SRC-NEWS-1",
        artifact_type="media_article",
        excerpt="News article says Company A owns 100% of Company B.",
        observed_at="2024-04-10",
    ))
    g.add_evidence(Evidence(
        id="EV-DNS-D1",
        source_id="SRC-DNS",
        artifact_type="dns_observation",
        excerpt="d1.example resolved to 198.51.100.10 in January 2026.",
        observed_at="2026-01-15",
    ))
    g.add_evidence(Evidence(
        id="EV-HOST-D2",
        source_id="SRC-HOST",
        artifact_type="hosting_observation",
        excerpt="d2.example was hosted by Provider X in January 2026.",
        observed_at="2026-01-16",
    ))
    g.add_evidence(Evidence(
        id="EV-HOST-IP",
        source_id="SRC-HOST",
        artifact_type="hosting_observation",
        excerpt="198.51.100.10 was associated with Provider X in January 2026.",
        observed_at="2026-01-16",
    ))
    g.add_evidence(Evidence(
        id="EV-WHOIS-BOTH",
        source_id="SRC-WHOIS",
        artifact_type="whois_record",
        excerpt="Registrant information for d1.example and d2.example is privacy-preserved.",
        observed_at="2026-01-17",
    ))

    # Nodes
    g.add_node(Node(
        id="COMPANY-A",
        node_type="Company",
        canonical_label="Company A",
        display_label="Company A",
        aliases=["A Ltd"],
        attributes={"registration_id": "REG-EXAMPLE-A", "jurisdiction": "ExampleLand"},
        first_seen="2024-01-01",
        last_seen="2026-10-09",
        source_ids=["SRC-REG-A"],
        evidence_ids=["EV-REG-A"],
        confidence=0.95,
        verification_state=EdgeVerificationState.SUPPORTED.value,
    ))
    g.add_node(Node(
        id="COMPANY-B",
        node_type="Company",
        canonical_label="Company B",
        display_label="Company B",
        attributes={"registration_id": "REG-EXAMPLE-B", "jurisdiction": "ExampleLand"},
        first_seen="2024-01-01",
        last_seen="2026-10-09",
        source_ids=["SRC-REG-A", "SRC-REG-B"],
        evidence_ids=["EV-REG-A", "EV-REG-B"],
        confidence=0.95,
        verification_state=EdgeVerificationState.SUPPORTED.value,
    ))
    g.add_node(Node(
        id="COMPANY-C",
        node_type="Company",
        canonical_label="Company C",
        display_label="Company C",
        attributes={"registration_id": "REG-EXAMPLE-C", "jurisdiction": "ExampleLand"},
        first_seen="2024-01-01",
        last_seen="2026-10-09",
        source_ids=["SRC-REG-B"],
        evidence_ids=["EV-REG-B"],
        confidence=0.95,
        verification_state=EdgeVerificationState.SUPPORTED.value,
    ))
    g.add_node(Node(
        id="DOMAIN-D1",
        node_type="Domain",
        canonical_label="d1.example",
        display_label="d1.example",
        attributes={"domain": "d1.example"},
        first_seen="2026-01-15",
        last_seen="2026-10-09",
        source_ids=["SRC-DNS", "SRC-WHOIS"],
        evidence_ids=["EV-DNS-D1", "EV-WHOIS-BOTH"],
        confidence=0.80,
        verification_state=EdgeVerificationState.SUPPORTED.value,
    ))
    g.add_node(Node(
        id="DOMAIN-D2",
        node_type="Domain",
        canonical_label="d2.example",
        display_label="d2.example",
        attributes={"domain": "d2.example"},
        first_seen="2026-01-16",
        last_seen="2026-10-09",
        source_ids=["SRC-HOST", "SRC-WHOIS"],
        evidence_ids=["EV-HOST-D2", "EV-WHOIS-BOTH"],
        confidence=0.75,
        verification_state=EdgeVerificationState.SUPPORTED.value,
    ))
    g.add_node(Node(
        id="IP-198-51-100-10",
        node_type="IP",
        canonical_label="198.51.100.10",
        display_label="198.51.100.10",
        attributes={"ip": "198.51.100.10"},
        first_seen="2026-01-15",
        last_seen="2026-10-09",
        source_ids=["SRC-DNS", "SRC-HOST"],
        evidence_ids=["EV-DNS-D1", "EV-HOST-IP"],
        confidence=0.78,
        verification_state=EdgeVerificationState.SUPPORTED.value,
    ))
    g.add_node(Node(
        id="PROVIDER-X",
        node_type="Provider",
        canonical_label="Provider X",
        display_label="Provider X",
        attributes={"provider": "Example Hosting Provider X"},
        first_seen="2026-01-16",
        last_seen="2026-10-09",
        source_ids=["SRC-HOST"],
        evidence_ids=["EV-HOST-D2", "EV-HOST-IP"],
        confidence=0.75,
        verification_state=EdgeVerificationState.SUPPORTED.value,
    ))

    # Edges
    g.add_edge(Edge(
        id="E-AB",
        source_node_id="COMPANY-A",
        target_node_id="COMPANY-B",
        relationship_type="OWNS_PERCENT",
        direction="DIRECTED",
        directness=EdgeDirectness.DIRECTLY_REPORTED,
        valid_from="2024-01-01",
        valid_to="2024-12-31",
        observed_at="2024-03-15",
        source_ids=["SRC-REG-A"],
        evidence_ids=["EV-REG-A"],
        confidence=0.95,
        verification_state=EdgeVerificationState.SUPPORTED,
        attributes={"percent": 60},
        limitations=["Single primary registry source; current post-2024 status unresolved."],
    ))
    g.add_edge(Edge(
        id="E-BC",
        source_node_id="COMPANY-B",
        target_node_id="COMPANY-C",
        relationship_type="OWNS_PERCENT",
        direction="DIRECTED",
        directness=EdgeDirectness.DIRECTLY_REPORTED,
        valid_from="2024-01-01",
        valid_to="2024-12-31",
        observed_at="2024-04-02",
        source_ids=["SRC-REG-B"],
        evidence_ids=["EV-REG-B"],
        confidence=0.95,
        verification_state=EdgeVerificationState.SUPPORTED,
        attributes={"percent": 50},
        limitations=["Single primary registry source; current post-2024 status unresolved."],
    ))
    g.add_edge(Edge(
        id="E-D1-RESOLVES-IP",
        source_node_id="DOMAIN-D1",
        target_node_id="IP-198-51-100-10",
        relationship_type="RESOLVES_TO",
        direction="DIRECTED",
        directness=EdgeDirectness.DIRECTLY_OBSERVED,
        valid_from="2026-01-01",
        valid_to=None,
        observed_at="2026-01-15",
        source_ids=["SRC-DNS"],
        evidence_ids=["EV-DNS-D1"],
        confidence=0.80,
        verification_state=EdgeVerificationState.SUPPORTED,
        attributes={"record_type": "A"},
        limitations=["DNS can change; shared IP does not imply common operator."],
    ))
    g.add_edge(Edge(
        id="E-IP-HOSTED-PROVIDER",
        source_node_id="IP-198-51-100-10",
        target_node_id="PROVIDER-X",
        relationship_type="HOSTED_BY",
        direction="DIRECTED",
        directness=EdgeDirectness.DIRECTLY_OBSERVED,
        valid_from="2026-01-01",
        valid_to=None,
        observed_at="2026-01-16",
        source_ids=["SRC-HOST"],
        evidence_ids=["EV-HOST-IP"],
        confidence=0.75,
        verification_state=EdgeVerificationState.SUPPORTED,
        limitations=["Provider assignment can be multi-tenant."],
    ))
    g.add_edge(Edge(
        id="E-D2-HOSTED-PROVIDER",
        source_node_id="DOMAIN-D2",
        target_node_id="PROVIDER-X",
        relationship_type="HOSTED_BY",
        direction="DIRECTED",
        directness=EdgeDirectness.DIRECTLY_OBSERVED,
        valid_from="2026-01-01",
        valid_to=None,
        observed_at="2026-01-16",
        source_ids=["SRC-HOST"],
        evidence_ids=["EV-HOST-D2"],
        confidence=0.75,
        verification_state=EdgeVerificationState.SUPPORTED,
        limitations=["Shared hosting provider is not proof of common operator."],
    ))

    # Claim that conflicts with registry edge
    g.add_claim(Claim(
        id="CLM-NEWS-100",
        subject_node_id="COMPANY-A",
        predicate="OWNS_PERCENT",
        object_node_id="COMPANY-B",
        value=100.0,
        valid_from="2024-01-01",
        valid_to="2024-12-31",
        source_id="SRC-NEWS-1",
        evidence_id="EV-NEWS-1",
        status=ClaimStatus.SOURCE_CLAIM_ONLY,
        confidence=0.55,
        attributes={"percent": 100},
    ))

    # Hypotheses
    g.add_hypothesis(Hypothesis(
        id="H-CORP-INDIRECT",
        statement=(
            "During 2024, Company A had a potential indirect economic interest in Company C "
            "through Company B."
        ),
        supporting_edge_ids=["E-AB", "E-BC"],
        supporting_evidence_ids=["EV-REG-A", "EV-REG-B"],
        assumptions=["Multiplicative ownership percentage is a valid economic-interest proxy."],
        predictions=["A derived 30% indirect economic-interest edge should exist for 2024."],
        falsification_conditions=[
            "Registry records are wrong or superseded.",
            "Share classes/voting agreements break proportional economic interpretation.",
        ],
        status=HypothesisStatus.SUPPORTED,
        confidence=0.90,
        limitations=[
            "Does not establish control.",
            "Does not establish beneficial ownership.",
            "Historical to 2024 only.",
        ],
    ))
    g.add_hypothesis(Hypothesis(
        id="H-DOMAIN-COMMON-OPERATOR",
        statement="Domain d1.example and domain d2.example are operated by the same entity.",
        supporting_edge_ids=["E-D1-RESOLVES-IP", "E-IP-HOSTED-PROVIDER", "E-D2-HOSTED-PROVIDER"],
        supporting_evidence_ids=["EV-DNS-D1", "EV-HOST-IP", "EV-HOST-D2"],
        contradicting_evidence_ids=["EV-WHOIS-BOTH"],
        assumptions=["Shared provider/IP indicates common operator."],
        predictions=["Registrar, certificate, or payment records would show common control."],
        falsification_conditions=[
            "Provider is multi-tenant.",
            "Registrants are distinct but privacy-preserved.",
            "IP was reassigned or shared CDN/anycast.",
        ],
        status=HypothesisStatus.UNRESOLVED,
        confidence=0.35,
        limitations=[
            "Shared infrastructure is not operator identity.",
            "No strong non-biometric identity identifier links the domains to one operator.",
        ],
    ))
    g.add_hypothesis(Hypothesis(
        id="H-DOMAIN-SHARED-PROVIDER-ONLY",
        statement="Domain d1.example and domain d2.example merely use the same hosting provider.",
        supporting_edge_ids=["E-IP-HOSTED-PROVIDER", "E-D2-HOSTED-PROVIDER"],
        supporting_evidence_ids=["EV-HOST-IP", "EV-HOST-D2", "EV-WHOIS-BOTH"],
        assumptions=["Provider X is multi-tenant."],
        predictions=["No additional common-control evidence will be found."],
        falsification_conditions=[
            "Authoritative registrar or payment evidence shows common operator.",
        ],
        status=HypothesisStatus.PROBABLE,
        confidence=0.65,
        limitations=["Probable alternative explanation, not a verified fact edge."],
    ))

    # Entity resolution notes
    g.add_entity_resolution({
        "entity_ids": ["COMPANY-A", "COMPANY-B", "COMPANY-C"],
        "state": "VERIFIED_DISTINCT",
        "identifiers": ["REG-EXAMPLE-A", "REG-EXAMPLE-B", "REG-EXAMPLE-C"],
        "note": "Distinct official registration identifiers; no name-based merge performed.",
    })
    g.add_entity_resolution({
        "entity_ids": ["DOMAIN-D1", "DOMAIN-D2"],
        "state": "VERIFIED_DISTINCT",
        "identifiers": ["d1.example", "d2.example"],
        "note": "Exact domain names differ. Operator relationship remains unresolved.",
    })

    g.prepare()
    return g


# =====================================================================
# SAMPLE ARTIFACT BUILDERS
# =====================================================================

def build_sample_gaps(g: GraphInt) -> List[KnowledgeGap]:
    gaps: List[KnowledgeGap] = []

    gaps.append(KnowledgeGap(
        id="GAP-CORP-CURRENT",
        gap_type=GapType.TEMPORAL_GAP,
        description="Corporate ownership edges are supported for 2024 but current 2026 status is unresolved.",
        about_edge_ids=["E-AB", "E-BC"],
        importance="HIGH",
        recommended_source="Latest official corporate registry extracts",
        specialist="CORPINT",
        expected_information_value=0.85,
    ))
    gaps.append(KnowledgeGap(
        id="GAP-CORP-CONTROL",
        gap_type=GapType.UNRESOLVED_RELATIONSHIP,
        description="Indirect economic interest is calculable, but control/beneficial ownership is not established.",
        about_node_ids=["COMPANY-A", "COMPANY-C"],
        importance="HIGH",
        recommended_source="Share classes, voting agreements, board resolutions, beneficial ownership filings",
        specialist="OWNERSHIPINT/CORPINT",
        expected_information_value=0.80,
    ))
    gaps.append(KnowledgeGap(
        id="GAP-DOMAIN-OPERATOR",
        gap_type=GapType.UNRESOLVED_RELATIONSHIP,
        description="Whether d1.example and d2.example share an operator is unresolved.",
        about_node_ids=["DOMAIN-D1", "DOMAIN-D2"],
        about_edge_ids=["E-D1-RESOLVES-IP", "E-D2-HOSTED-PROVIDER"],
        importance="MEDIUM",
        recommended_source="Authorized registrar records, certificate transparency history, DNS history, payment/billing evidence if lawful",
        specialist="DOMAININT",
        expected_information_value=0.70,
    ))
    gaps.append(KnowledgeGap(
        id="GAP-SOURCE-INDEPENDENCE",
        gap_type=GapType.SOURCE_INDEPENDENCE_GAP,
        description="Several edges rely on single-source observations; independence is limited.",
        about_edge_ids=["E-AB", "E-BC", "E-D1-RESOLVES-IP", "E-D2-HOSTED-PROVIDER"],
        importance="MEDIUM",
        recommended_source="Independent corroborating registries/observations",
        specialist=None,
        expected_information_value=0.55,
    ))
    return gaps


def build_sample_actions(g: GraphInt) -> List[NextAction]:
    return [
        NextAction(
            id="ACT-CURRENT-REGISTRY",
            description="Retrieve latest official corporate registry extracts for Company A/B/C to refresh 2026 status.",
            priority=1,
            privacy_impact="LOW",
            expected_gain=0.85,
            specialist="CORPINT",
        ),
        NextAction(
            id="ACT-CONTROL-EVIDENCE",
            description="Collect share-class, voting, board, and beneficial-ownership evidence before any control conclusion.",
            priority=2,
            privacy_impact="LOW",
            expected_gain=0.80,
            specialist="OWNERSHIPINT",
        ),
        NextAction(
            id="ACT-DOMAIN-HISTORY",
            description="Use authorized DNS history, certificate transparency, and registrar privacy status to test domain-operator hypothesis.",
            priority=3,
            privacy_impact="LOW",
            expected_gain=0.70,
            specialist="DOMAININT",
        ),
        NextAction(
            id="ACT-HUMAN-REVIEW",
            description="Require human review before any consequential corporate-control or operator-attribution conclusion.",
            priority=4,
            privacy_impact="PROTECTIVE",
            expected_gain=0.60,
            specialist=None,
        ),
        NextAction(
            id="ACT-NO-TARGETING",
            description="Do not convert graph proximity into targeting, sabotage, social scoring, or guilt-by-association.",
            priority=99,
            privacy_impact="PROTECTIVE",
            expected_gain=0.0,
            specialist=None,
        ),
    ]


def build_sample_handoffs() -> List[Dict[str, str]]:
    return [
        {"specialist": "CORPINT", "reason": "Legal corporate filings, directorship, ownership, current registry status."},
        {"specialist": "OWNERSHIPINT", "reason": "Beneficial ownership and control analysis beyond economic percentage."},
        {"specialist": "ORGINT", "reason": "Organizational authority and role semantics if people/roles are introduced."},
        {"specialist": "DOMAININT", "reason": "Domain, DNS, certificate, registrar, and hosting-history reasoning."},
        {"specialist": "CTI", "reason": "Only if threat-actor context is separately authorized; shared IOC is not actor identity."},
    ]


def build_facts(g: GraphInt, paths: List[PathResult]) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []

    for edge in g.edges.values():
        if edge.verification_state == EdgeVerificationState.SUPPORTED:
            facts.append({
                "fact_id": f"FACT-{edge.id}",
                "statement": (
                    f"The graph contains a supported {edge.relationship_type} relationship "
                    f"from {edge.source_node_id} to {edge.target_node_id} "
                    f"for period {edge.valid_from or 'unknown'} to {edge.valid_to or 'open'}."
                ),
                "edge_id": edge.id,
                "source_ids": edge.source_ids,
                "evidence_ids": edge.evidence_ids,
                "confidence": edge.confidence,
                "verification_state": edge.verification_state.value,
                "directness": edge.directness.value,
                "limitations": edge.limitations,
            })

    for path in paths:
        if path.start_node_id == "COMPANY-A" and path.target_node_id == "COMPANY-C":
            facts.append({
                "fact_id": f"FACT-PATH-{path.path_id}",
                "statement": (
                    "During 2024, supported registry edges connect Company A to Company C "
                    "through Company B. A deterministic indirect economic-interest calculation "
                    "is possible. Control is not established."
                ),
                "path_id": path.path_id,
                "source_ids": sorted({sid for eid in path.edge_ids for sid in g.edges[eid].source_ids}),
                "evidence_ids": sorted({eid for edge_id in path.edge_ids for eid in g.edges[edge_id].evidence_ids}),
                "confidence": path.confidence,
                "verification_state": "SUPPORTED_FOR_CALCULATION_ONLY",
                "limitations": path.limitations + ["Control not established."],
            })

    return facts


def build_anomalies(g: GraphInt) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []

    historical = [e for e in g.edges.values() if e.relationship_state == "HISTORICAL"]
    if historical:
        anomalies.append({
            "anomaly_id": "ANOM-TEMPORAL-STALENESS",
            "type": "TEMPORAL_STALENESS",
            "description": "Some supported edges are historical and should not be treated as current.",
            "edge_ids": [e.id for e in historical],
            "severity": "MEDIUM",
            "interpretation": "Requires current-source refresh; not wrongdoing.",
        })

    shared_provider_edges = [
        e for e in g.edges.values()
        if e.relationship_type in {"HOSTED_BY", "USES_PROVIDER"}
    ]
    if len(shared_provider_edges) >= 2:
        anomalies.append({
            "anomaly_id": "ANOM-SHARED-PROVIDER",
            "type": "STRUCTURAL_SHARED_DEPENDENCY",
            "description": "Multiple domains/IPs depend on the same provider.",
            "edge_ids": [e.id for e in shared_provider_edges],
            "severity": "LOW",
            "interpretation": "Could be normal multi-tenant hosting; not common operator by itself.",
        })

    return anomalies


def build_motifs(g: GraphInt) -> List[Dict[str, Any]]:
    motifs: List[Dict[str, Any]] = []

    if "E-AB" in g.edges and "E-BC" in g.edges:
        motifs.append({
            "motif_id": "MOTIF-OWNERSHIP-CHAIN",
            "pattern": "Company A -> Company B -> Company C",
            "node_ids": ["COMPANY-A", "COMPANY-B", "COMPANY-C"],
            "edge_ids": ["E-AB", "E-BC"],
            "interpretation": "Two-step ownership chain. Indirect economic interest may be calculated; control is not implied.",
        })

    if "E-D1-RESOLVES-IP" in g.edges and "E-D2-HOSTED-PROVIDER" in g.edges:
        motifs.append({
            "motif_id": "MOTIF-SHARED-PROVIDER-WEDGE",
            "pattern": "Domain D1 -> IP -> Provider X <- Domain D2",
            "node_ids": ["DOMAIN-D1", "IP-198-51-100-10", "PROVIDER-X", "DOMAIN-D2"],
            "edge_ids": ["E-D1-RESOLVES-IP", "E-IP-HOSTED-PROVIDER", "E-D2-HOSTED-PROVIDER"],
            "interpretation": "Shared infrastructure wedge. Alternative explanations include multi-tenant hosting, CDN, or reassignment.",
        })

    return motifs


def build_dependency_analysis(g: GraphInt) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    dependency_chains = [
        {
            "chain_id": "DEP-CORP-2024",
            "description": "Company A depends economically on Company C through Company B during 2024.",
            "node_ids": ["COMPANY-A", "COMPANY-B", "COMPANY-C"],
            "edge_ids": ["E-AB", "E-BC"],
            "interpretation": "Economic-interest chain only; not control.",
        },
        {
            "chain_id": "DEP-INFRA-2026",
            "description": "d1.example and d2.example both have observed dependency on Provider X.",
            "node_ids": ["DOMAIN-D1", "IP-198-51-100-10", "PROVIDER-X", "DOMAIN-D2"],
            "edge_ids": ["E-D1-RESOLVES-IP", "E-IP-HOSTED-PROVIDER", "E-D2-HOSTED-PROVIDER"],
            "interpretation": "Shared provider dependency; not operator identity.",
        },
    ]

    shared_dependencies = [
        {
            "dependency_id": "SHARED-PROVIDER-X",
            "provider_node_id": "PROVIDER-X",
            "dependent_node_ids": ["DOMAIN-D1", "DOMAIN-D2", "IP-198-51-100-10"],
            "note": "Shared dependency may reflect normal multi-tenant infrastructure.",
        }
    ]

    return dependency_chains, shared_dependencies


def dual_ai_review(g: GraphInt, paths: List[PathResult]) -> Dict[str, Any]:
    issues: List[str] = []

    if g.validation_errors:
        issues.append("Graph schema validation reported errors.")

    if g.contradictions:
        issues.append(f"{len(g.contradictions)} contradiction(s) remain open.")

    for path in paths:
        if not path.temporal_valid:
            issues.append(f"Path {path.path_id} is not fully temporally valid.")
        if path.independence_state != SourceIndependenceState.INDEPENDENT.value:
            issues.append(f"Path {path.path_id} has limited source independence: {path.independence_state}.")
        if path.hops > 2:
            issues.append(f"Path {path.path_id} has {path.hops} hops; uncertainty accumulates.")

    unresolved = [h for h in g.hypotheses.values() if h.status == HypothesisStatus.UNRESOLVED]
    if unresolved:
        issues.append(f"{len(unresolved)} hypothesis(es) remain unresolved.")

    if any(e.directness == EdgeDirectness.HYPOTHETICAL for e in g.edges.values()):
        issues.append("Hypothetical edge exists in canonical graph; should be moved to candidate layer.")

    if issues:
        verdict = "PARTIAL_AGREEMENT" if len(issues) <= 4 else "INSUFFICIENT_EVIDENCE"
    else:
        verdict = "AGREE"

    return {
        "primary_graph_analyst": (
            "Corporate 2024 ownership chain supports a deterministic indirect economic-interest "
            "calculation. Infrastructure path shows shared provider dependency but not common operator."
        ),
        "independent_graph_skeptic_issues": issues,
        "verdict": verdict,
        "note": "AI agreement is not independent source evidence.",
        "adversarial_checks": [
            "Are nodes wrongly merged? No name-only merge performed.",
            "Are historical edges treated as current? No; temporal state preserved.",
            "Are copied sources counted as independent? No; source families tracked.",
            "Is shared infrastructure overinterpreted as operator identity? No; kept as hypothesis.",
            "Is centrality interpreted as leadership or target value? No.",
        ],
    }


def analyst_summary(g: GraphInt, paths: List[PathResult], dual: Dict[str, Any]) -> str:
    corp = [p for p in paths if p.start_node_id == "COMPANY-A" and p.target_node_id == "COMPANY-C"]
    infra = [p for p in paths if p.start_node_id in {"DOMAIN-D1", "DOMAIN-D2"} and p.target_node_id in {"DOMAIN-D1", "DOMAIN-D2"}]

    lines = [
        "TARGET ENTITIES: Company A/B/C and Domain D1/D2/IP/Provider X.",
        "ENTITY RESOLUTION: Companies resolved distinct by registration identifiers. Domains are distinct entities; operator relationship unresolved.",
        "VERIFIED RELATIONSHIPS: 2024 A->B 60% and B->C 50% ownership edges are supported by official registry evidence.",
        "DERIVED RELATIONSHIP: A deterministic potential indirect economic interest of 30% is supported for 2024 only.",
        "NOT ESTABLISHED: Company A control over Company C; beneficial ownership; current 2026 corporate status.",
        "INFRASTRUCTURE: D1 and D2 show a shared-provider path. This is structural evidence, not operator identity.",
        "SOURCE INDEPENDENCE: Corporate path uses two distinct registry families. Infrastructure path is partially dependent on hosting observation.",
        "CONTRADICTIONS: Media claim of 100% ownership conflicts with registry-supported 60% edge and is treated as disputed/source-only.",
        "HYPOTHESES: Common-operator hypothesis remains unresolved; shared-provider-only alternative is probable.",
        f"DUAL-AI REVIEW: {dual['verdict']}.",
        "PRIVACY/POLICY: No private data, biometrics, live location, sensitive-trait inference, target selection, or guilt-by-association scoring performed.",
        "NEXT ACTION: Refresh current registry data and collect control/beneficial-ownership evidence before any corporate-control conclusion; use authorized domain-history sources before operator attribution.",
    ]
    return "\n".join(lines)


# =====================================================================
# RESULT BUILDER
# =====================================================================

def graph_version_hash(g: GraphInt) -> str:
    seed_obj = {
        "nodes": sorted(
            (nid, n.node_type, n.verification_state, round(float(n.confidence), 3))
            for nid, n in g.nodes.items()
        ),
        "edges": sorted(
            (eid, e.source_node_id, e.target_node_id, e.relationship_type,
             e.verification_state.value, e.directness.value, round(float(e.confidence), 3))
            for eid, e in g.edges.items()
        ),
    }
    return stable_hash(json.dumps(jsonable(seed_obj), sort_keys=True))


def edge_brief(edge: Edge) -> Dict[str, Any]:
    return {
        "edge_id": edge.id,
        "source": edge.source_node_id,
        "target": edge.target_node_id,
        "relationship_type": edge.relationship_type,
        "directness": edge.directness.value,
        "verification_state": edge.verification_state.value,
        "independence_state": edge.independence_state.value,
        "relationship_state": edge.relationship_state,
        "valid_from": edge.valid_from,
        "valid_to": edge.valid_to,
        "confidence": edge.confidence,
        "evidence_ids": edge.evidence_ids,
        "source_ids": edge.source_ids,
        "limitations": edge.limitations,
        "attributes": edge.attributes,
    }


def build_source_graph(g: GraphInt) -> Dict[str, Any]:
    edges = []
    for src in g.sources.values():
        if src.derived_from:
            edges.append({
                "source": src.derived_from,
                "target": src.id,
                "relationship_type": "DERIVED_FROM",
            })
    return {
        "nodes": [s.id for s in g.sources.values()],
        "edges": edges,
    }


def build_source_dependency_graph(g: GraphInt) -> Dict[str, List[str]]:
    families: Dict[str, List[str]] = defaultdict(list)
    for sid in g.sources:
        fam = g.get_source_family(sid) or "UNKNOWN"
        families[fam].append(sid)
    return {k: sorted(v) for k, v in families.items()}


def build_evidence_graph(g: GraphInt) -> List[Dict[str, Any]]:
    used_by: Dict[str, List[str]] = defaultdict(list)
    for edge in g.edges.values():
        for evid in edge.evidence_ids:
            used_by[evid].append(edge.id)

    out = []
    for ev in g.evidences.values():
        out.append({
            "evidence_id": ev.id,
            "source_id": ev.source_id,
            "artifact_type": ev.artifact_type,
            "observed_at": ev.observed_at,
            "content_hash": ev.content_hash,
            "supports_edges": sorted(used_by.get(ev.id, [])),
            "excerpt": ev.excerpt,
        })
    return out


def build_result(
    case: Case,
    g: GraphInt,
    artifacts: Dict[str, Any],
    status: Status,
) -> Dict[str, Any]:
    paths: List[PathResult] = artifacts.get("paths", [])
    communities_raw: List[List[str]] = artifacts.get("connected_components", [])
    centrality: Dict[str, float] = artifacts.get("centrality", {})
    anomalies: List[Dict[str, Any]] = artifacts.get("anomalies", [])
    motifs: List[Dict[str, Any]] = artifacts.get("motifs", [])
    dependency_chains: List[Dict[str, Any]] = artifacts.get("dependency_chains", [])
    shared_dependencies: List[Dict[str, Any]] = artifacts.get("shared_dependencies", [])
    graph_diffs: List[Dict[str, Any]] = artifacts.get("graph_diffs", [])
    gaps: List[KnowledgeGap] = artifacts.get("gaps", [])
    actions: List[NextAction] = artifacts.get("actions", [])
    handoffs: List[Dict[str, str]] = artifacts.get("handoffs", [])
    facts: List[Dict[str, Any]] = artifacts.get("facts", [])
    observations: List[str] = artifacts.get("observations", [])
    coverage: Dict[str, Any] = artifacts.get("coverage", {})
    limitations: List[str] = artifacts.get("limitations", [])
    dual_review: Dict[str, Any] = artifacts.get("dual_review", {})
    summary: str = artifacts.get("summary", "")

    supported_edges = [e for e in g.edges.values() if e.verification_state == EdgeVerificationState.SUPPORTED]
    disputed_edges = [e for e in g.edges.values() if e.verification_state == EdgeVerificationState.DISPUTED]
    retracted_edges = [e for e in g.edges.values() if e.verification_state == EdgeVerificationState.RETRACTED]
    superseded_edges = [e for e in g.edges.values() if e.verification_state == EdgeVerificationState.SUPERSEDED]
    historical_edges = [e for e in g.edges.values() if e.relationship_state == "HISTORICAL"]
    candidate_edges = [
        e for e in g.edges.values()
        if e.directness in {EdgeDirectness.HYPOTHETICAL, EdgeDirectness.ANALYTICALLY_INFERRED}
        or e.verification_state in {EdgeVerificationState.INCONCLUSIVE, EdgeVerificationState.UNSUPPORTED}
    ]

    resolved_nodes = [n for n in g.nodes.values() if n.verification_state == EdgeVerificationState.SUPPORTED.value]
    candidate_nodes = [n for n in g.nodes.values() if n.verification_state in {
        EdgeVerificationState.UNSUPPORTED.value,
        EdgeVerificationState.INCONCLUSIVE.value,
    }]

    relevant_subgraphs = [
        {
            "subgraph_id": p.path_id,
            "purpose": "path_evidence_subgraph",
            "node_ids": p.node_ids,
            "edge_ids": p.edge_ids,
        }
        for p in paths
    ]

    communities = [
        {
            "cluster_id": f"CLUSTER_{i+1:03d}",
            "node_ids": comp,
            "interpretation": "STRUCTURAL_CLUSTER",
            "note": "Algorithmic connectivity only; not evidence of a real-world organization, conspiracy, or threat group.",
        }
        for i, comp in enumerate(communities_raw)
    ]

    privacy_flags = [
        PrivacyFlag.CASE_SCOPED.value,
        PrivacyFlag.NO_PRIVATE_DATA_COLLECTED.value,
        PrivacyFlag.NO_BIOMETRIC_IDENTIFICATION.value,
        PrivacyFlag.NO_LIVE_LOCATION_INFERENCE.value,
        PrivacyFlag.NO_SENSITIVE_TRAIT_INFERENCE.value,
        PrivacyFlag.NO_TARGET_SELECTION.value,
        PrivacyFlag.NO_GUILT_BY_ASSOCIATION.value,
    ]

    policy_flags = [PolicyFlag.NONE.value]
    if dual_review.get("verdict") in {"INSUFFICIENT_EVIDENCE", "DISAGREE"} or gaps:
        policy_flags.append(PolicyFlag.HUMAN_REVIEW_RECOMMENDED.value)

    replay_manifest = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "graph_version": graph_version_hash(g),
        "graph_write_gate": (
            "AI/raw proposal -> schema validation -> entity resolution -> evidence validation "
            "-> temporal validation -> source independence -> contradiction check -> fact gate -> canonical update"
        ),
        "source_hashes": {sid: stable_hash(s.url + s.title) for sid, s in g.sources.items()},
        "derived_edges": {
            eid: {
                "derivation_method": e.derivation_method,
                "inputs": e.inputs,
                "algorithm_version": e.algorithm_version,
            }
            for eid, e in g.edges.items()
            if e.directness == EdgeDirectness.DERIVED_DETERMINISTICALLY
        },
        "policy_exclusions": [
            "No fabricated nodes or edges.",
            "No name-only entity merge.",
            "No guilt-by-association inference.",
            "No autonomous target selection.",
            "No biometric identification.",
            "No private-account access.",
            "No sensitive-trait inference.",
        ],
    }

    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "questions": case.questions,
        "status": status.value,
        "graph_snapshot_id": artifacts.get("current_snapshot_id", new_id("SNAP-", now_iso())),
        "graph_version": graph_version_hash(g),
        "node_count": len(g.nodes),
        "edge_count": len(g.edges),
        "candidate_nodes": candidate_nodes,
        "resolved_nodes": resolved_nodes,
        "merged_nodes": [],
        "split_nodes": [],
        "candidate_edges": candidate_edges,
        "supported_edges": supported_edges,
        "disputed_edges": disputed_edges,
        "retracted_edges": retracted_edges,
        "superseded_edges": superseded_edges,
        "historical_edges": historical_edges,
        "entity_resolution_results": g.entity_resolutions,
        "relationship_resolution_results": [edge_brief(e) for e in g.edges.values()],
        "temporal_relationships": [
            {
                "edge_id": e.id,
                "relationship_type": e.relationship_type,
                "valid_from": e.valid_from,
                "valid_to": e.valid_to,
                "relationship_state": e.relationship_state,
            }
            for e in g.edges.values()
        ],
        "source_graph": build_source_graph(g),
        "source_dependency_graph": build_source_dependency_graph(g),
        "evidence_graph": build_evidence_graph(g),
        "claim_graph": list(g.claims.values()),
        "hypothesis_graph": list(g.hypotheses.values()),
        "contradiction_graph": list(g.contradictions.values()),
        "relevant_subgraphs": relevant_subgraphs,
        "paths": paths,
        "path_explanations": {p.path_id: p.explanation for p in paths},
        "communities": communities,
        "centrality_results": {
            "degree_centrality": centrality,
            "interpretation_guardrails": [
                "Centrality is not leadership.",
                "Centrality is not guilt.",
                "Centrality is not target value.",
                "High degree may reflect shared infrastructure, provider, aggregator, or directory effects.",
            ],
        },
        "graph_anomalies": anomalies,
        "motifs": motifs,
        "dependency_chains": dependency_chains,
        "shared_dependencies": shared_dependencies,
        "graph_diffs": graph_diffs,
        "coverage": coverage,
        "source_reliability": {s.id: s.reliability for s in g.sources.values()},
        "source_independence": {
            "edge_independence": {e.id: e.independence_state.value for e in g.edges.values()},
            "path_independence": {p.path_id: p.independence_state for p in paths},
            "source_families": build_source_dependency_graph(g),
        },
        "facts": facts,
        "observations": observations,
        "claims": list(g.claims.values()),
        "disputed_relationships": list(g.contradictions.values()),
        "contradictions": list(g.contradictions.values()),
        "competing_hypotheses": list(g.hypotheses.values()),
        "falsification": [
            {
                "hypothesis_id": h.id,
                "status": h.status.value,
                "falsification_conditions": h.falsification_conditions,
                "limitations": h.limitations,
            }
            for h in g.hypotheses.values()
        ],
        "knowledge_gaps": gaps,
        "next_best_actions": actions,
        "specialist_handoffs": handoffs,
        "privacy_flags": privacy_flags,
        "policy_flags": policy_flags,
        "limitations": limitations + g.validation_errors,
        "analyst_summary": summary,
        "dual_ai_review": dual_review,
        "replay_manifest": replay_manifest,
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline(case: Case) -> Dict[str, Any]:
    g = build_sample_graph()

    corp_paths = g.find_paths(
        start_node_id="COMPANY-A",
        target_node_id="COMPANY-C",
        max_hops=case.max_hops,
        time_start="2024-01-01",
        time_end="2024-12-31",
        allowed_types={"OWNS_PERCENT"},
        directed=True,
        min_verification=EdgeVerificationState.SUPPORTED,
    )

    infra_paths = g.find_paths(
        start_node_id="DOMAIN-D1",
        target_node_id="DOMAIN-D2",
        max_hops=case.max_hops + 1,
        time_start="2026-01-01",
        time_end="2026-12-31",
        allowed_types={"RESOLVES_TO", "HOSTED_BY", "USES_PROVIDER"},
        directed=False,
        min_verification=EdgeVerificationState.SUPPORTED,
    )

    all_paths = corp_paths + infra_paths

    centrality = g.degree_centrality(allowed_verification=EdgeVerificationState.SUPPORTED)
    components = g.connected_components(allowed_verification=EdgeVerificationState.SUPPORTED)
    anomalies = build_anomalies(g)
    motifs = build_motifs(g)
    dependency_chains, shared_dependencies = build_dependency_analysis(g)

    snap_2024 = g.graph_as_of("2024-06-30")
    snap_2026 = g.graph_as_of("2026-06-30")
    diff = g.graph_diff(snap_2024, snap_2026)

    gaps = build_sample_gaps(g)
    actions = build_sample_actions(g)
    handoffs = build_sample_handoffs()
    facts = build_facts(g, all_paths)
    observations = [ev.excerpt for ev in g.evidences.values()]
    dual = dual_ai_review(g, all_paths)
    summary = analyst_summary(g, all_paths, dual)

    coverage = {
        "source_families": build_source_dependency_graph(g),
        "time_coverage": {
            "corporate_ownership": "2024-01-01 to 2024-12-31",
            "infrastructure_observations": "2026-01-01 onward",
        },
        "entity_coverage": sorted(g.nodes.keys()),
        "known_gaps": [gap.description for gap in gaps],
    }

    limitations = [
        "Local synthetic demo; no live public-record retrieval.",
        "Corporate ownership is historical for 2024; current status unresolved.",
        "Shared infrastructure is not operator identity.",
        "Do not use for consequential decisions without human review and authorized primary sources.",
    ]

    artifacts = {
        "paths": all_paths,
        "centrality": centrality,
        "connected_components": components,
        "anomalies": anomalies,
        "motifs": motifs,
        "dependency_chains": dependency_chains,
        "shared_dependencies": shared_dependencies,
        "graph_diffs": [diff],
        "gaps": gaps,
        "actions": actions,
        "handoffs": handoffs,
        "facts": facts,
        "observations": observations,
        "coverage": coverage,
        "limitations": limitations,
        "dual_review": dual,
        "summary": summary,
        "current_snapshot_id": snap_2026["snapshot_id"],
    }

    return build_result(case, g, artifacts, Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    g = GraphInt()

    for label in case.target_entities:
        nid = new_id("NODE-", label)
        g.add_node(Node(
            id=nid,
            node_type="UnresolvedEntity",
            canonical_label=normalize_label(label),
            display_label=label,
            confidence=0.0,
            verification_state=EdgeVerificationState.UNSUPPORTED.value,
            limitations=["Input placeholder only; no evidence configured."],
        ))

    gaps = [KnowledgeGap(
        id="GAP-NO-SOURCES",
        gap_type=GapType.COVERAGE_GAP,
        description="No authorized public-source adapter or local evidence corpus is configured.",
        about_node_ids=list(g.nodes.keys()),
        importance="HIGH",
        recommended_source="Connect authorized public-record connectors or provide a local JSON evidence corpus.",
        specialist=None,
        expected_information_value=0.95,
    )]

    actions = [NextAction(
        id="ACT-CONFIGURE-SOURCES",
        description=(
            "Configure authorized public-source adapters or supply local evidence. "
            "Do not scrape private accounts, bypass authentication, or fabricate edges."
        ),
        priority=1,
        privacy_impact="LOW",
        expected_gain=0.95,
        specialist=None,
    )]

    dual = {
        "primary_graph_analyst": "No evidence available.",
        "independent_graph_skeptic_issues": [
            "No sources configured.",
            "No edges can be validated.",
            "No identity or relationship conclusion is possible.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "AI agreement is not independent source evidence.",
    }

    summary = (
        "GRAPH UNRESOLVED: No configured evidence corpus. "
        "No nodes or edges were fabricated beyond input placeholders. "
        "Provide authorized public sources or run sample mode."
    )

    artifacts = {
        "paths": [],
        "centrality": {},
        "connected_components": [],
        "anomalies": [],
        "motifs": [],
        "dependency_chains": [],
        "shared_dependencies": [],
        "graph_diffs": [],
        "gaps": gaps,
        "actions": actions,
        "handoffs": [],
        "facts": [],
        "observations": [],
        "coverage": {"source_families": {}, "known_gaps": [gaps[0].description]},
        "limitations": [
            "No live retrieval configured.",
            "No canonical graph write performed.",
            "No identity/relationship fabrication.",
        ],
        "dual_review": dual,
        "summary": summary,
        "current_snapshot_id": new_id("SNAP-", "empty"),
    }

    return build_result(case, g, artifacts, Status.BLOCKED_CONFIGURATION)


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited graph-intelligence request detected. "
            "GRAPHINT supports evidence-linked relationship reasoning only, "
            "not targeting, guilt-by-association, social scoring, biometric identification, "
            "private-account access, or sensitive-trait inference."
        ),
        "lawful_alternatives": [
            "Use official corporate registries for ownership/directorship context.",
            "Use authorized DNS/hosting/certificate transparency sources for infrastructure relationships.",
            "Keep hypotheses separate from verified edges.",
            "Require human review for consequential attribution or control conclusions.",
        ],
        "privacy_flags": [
            PrivacyFlag.NO_TARGET_SELECTION.value,
            PrivacyFlag.NO_GUILT_BY_ASSOCIATION.value,
            PrivacyFlag.NO_BIOMETRIC_IDENTIFICATION.value,
            PrivacyFlag.NO_SENSITIVE_TRAIT_INFERENCE.value,
        ],
        "limitations": [
            "No graph constructed.",
            "No nodes or edges fabricated.",
            "No private data accessed.",
        ],
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.questions,
            *case.target_entities,
            case.authorization or "",
        ]
    )
    violations = policy_guard(text)
    if violations:
        return blocked_policy_result(case, violations)

    if case.sample:
        return run_sample_pipeline(case)

    return run_unconfigured_pipeline(case)


# =====================================================================
# CLI
# =====================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "TRACEATLAS GRAPHINT local evidence-first graph intelligence pipeline. "
            "Sample mode uses synthetic public-record-style data."
        )
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic GRAPHINT sample.")
    parser.add_argument("--objective", help="Investigation objective.")
    parser.add_argument("--question", action="append", default=[], help="Analytic question. Repeatable.")
    parser.add_argument("--entity", action="append", default=[], help="Target entity label. Repeatable.")
    parser.add_argument("--time-range", help="Time range hint, e.g. 2024-2026.")
    parser.add_argument("--max-hops", type=int, default=3, help="Maximum path hops.")

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            questions=args.question,
            target_entities=args.entity,
            time_range=args.time_range,
            max_hops=args.max_hops,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()