# TRACEATLAS — EVIDENCEINT AI EMPLOYEE
# Single-file defensive Python core for Evidence Intelligence.
# Mode: LOCAL_ONLY / EVIDENCE-FIRST / AUDITABLE / REPRODUCIBLE / FORENSIC-AWARE
# Does NOT fabricate evidence, modify originals, invent hashes, forge custody,
# execute malicious files, bypass authentication, or declare legal admissibility.

from __future__ import annotations

import difflib
import hashlib
import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union


TOOL_VERSION = "EVIDENCEINT-PY-0.1"
MAX_DT = datetime.max.replace(tzinfo=timezone.utc)
Content = Union[bytes, str, dict, list, None]


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


BLOCK_PHRASES = [
    "fabricate evidence",
    "invent evidence",
    "fake evidence",
    "alter original evidence",
    "modify original evidence",
    "overwrite original",
    "delete unfavorable evidence",
    "remove contradictory evidence",
    "invent hash",
    "fake hash",
    "generate hash without content",
    "invent chain-of-custody",
    "forge custody",
    "fake custody",
    "invent provenance",
    "fake provenance",
    "invent source independence",
    "fake corroboration",
    "present ai as original evidence",
    "present summary as evidence",
    "execute malware",
    "run malicious file",
    "open macro",
    "bypass authentication",
    "collect private evidence without authorization",
    "publish sensitive evidence",
    "expose credentials",
    "rewrite timestamp",
    "backdate evidence",
    "spoof metadata",
]

SUPPORT_RELATIONS = {"DIRECTLY_SUPPORTS", "INDIRECTLY_SUPPORTS", "CONSISTENT_WITH"}
SUBSTANTIVE_RELATIONS = {"DIRECTLY_SUPPORTS", "INDIRECTLY_SUPPORTS"}
OPPOSE_RELATIONS = {"WEAKENS", "CONTRADICTS", "FALSIFIES"}

PROV_SCORES = {
    "VERIFIED": 0.95,
    "SUPPORTED": 0.85,
    "PARTIAL": 0.55,
    "UNKNOWN": 0.30,
    "DISPUTED": 0.35,
    "BROKEN": 0.10,
}

INTEG_SCORES = {
    "INTEGRITY_VERIFIED": 0.95,
    "INTEGRITY_CHANGED_EXPECTED": 0.75,
    "INTEGRITY_CHANGED_UNEXPLAINED": 0.20,
    "INTEGRITY_UNVERIFIED": 0.35,
    "UNKNOWN": 0.25,
}

AUTH_SCORES = {
    "AUTHENTIC_SUPPORTED": 0.95,
    "LIKELY_AUTHENTIC": 0.75,
    "AUTHENTICITY_UNRESOLVED": 0.45,
    "MANIPULATION_CANDIDATE": 0.20,
    "MISATTRIBUTED_CANDIDATE": 0.25,
    "FABRICATED_CANDIDATE": 0.10,
}

QUALITY_WEIGHTS = {
    "provenance_quality": 0.18,
    "integrity_quality": 0.18,
    "authenticity_quality": 0.12,
    "source_reliability": 0.12,
    "independence_quality": 0.10,
    "temporal_relevance": 0.08,
    "specificity": 0.06,
    "completeness": 0.08,
    "contamination_resistance": 0.08,
}

FACT_GATE_RULES = {
    "requires_substantive_support": True,
    "min_independent_families_for_fact_ready": 2,
    "min_avg_quality_for_fact_ready": 0.65,
    "block_if_contradiction": True,
    "block_if_falsified": True,
    "block_if_broken_provenance": True,
    "block_if_unexplained_integrity_change": True,
}


@dataclass
class Source:
    source_id: str
    source_type: str = "UNKNOWN"
    publisher: str = ""
    collector: str = ""
    origin: str = ""
    upstream_source: str = ""
    retrieval_method: str = ""
    first_seen: str = ""
    last_seen: str = ""
    reliability: float = 0.5
    bias: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    independence_group: str = ""
    pedigree: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CustodyEvent:
    event_id: str
    evidence_id: str
    actor: str = ""
    action: str = "UNKNOWN"
    timestamp: str = ""
    source_location: str = ""
    destination_location: str = ""
    hash_before: str = ""
    hash_after: str = ""
    reason: str = ""


@dataclass
class Transformation:
    transformation_id: str
    input_evidence_ids: list[str]
    output_evidence_id: str
    operation: str = "TRANSFORM"
    tool: str = ""
    tool_version: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    operator: str = ""
    time: str = ""
    lossy: bool = False
    ai_generated: bool = False
    analyst_generated: bool = False
    reason: str = ""


@dataclass
class Evidence:
    evidence_id: str
    case_id: str = ""
    artifact_type: str = "FILE"
    source_id: str = ""
    collector_id: str = ""
    collection_method: str = ""
    acquired_at: str = ""
    observed_at: str = ""
    event_time_candidate: str = ""
    created_time: str = ""
    modified_time: str = ""
    published_time: str = ""
    retrieved_time: str = ""
    original_name: str = ""
    original_location: str = ""
    content: Content = None
    provided_hashes: dict[str, str] = field(default_factory=dict)
    size: int = 0
    mime_type: str = ""
    encoding: str = ""
    chain_of_custody: list[CustodyEvent] = field(default_factory=list)
    transformations: list[Transformation] = field(default_factory=list)
    parent_evidence_id: str = ""
    source_reliability: float = 0.0
    source_independence: str = ""
    sensitivity: list[str] = field(default_factory=list)
    classification: str = "UNCLASSIFIED"
    access_policy: str = ""
    claim_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    signature_state: str = "UNKNOWN"
    native_artifact: bool = False
    malicious_suspected: bool = False
    contains_pii: bool = False
    contains_credentials: bool = False


@dataclass
class EvidenceLink:
    evidence_id: str
    relation: str = "CONSISTENT_WITH"
    locator: str = ""
    confidence: float = 0.5
    notes: str = ""


@dataclass
class Claim:
    claim_id: str
    proposition: str
    subject: str = ""
    predicate: str = ""
    object_value: str = ""
    qualifiers: list[str] = field(default_factory=list)
    time: str = ""
    location: str = ""
    entity_ids: list[str] = field(default_factory=list)
    evidence_links: list[EvidenceLink] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class EvidenceIntRequest:
    case_id: str
    objective: str
    authorization: dict[str, Any] = field(default_factory=dict)
    sources: list[Source] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceIntResult:
    case_id: str
    status: str
    policy_decision: str
    summary: str
    evidence: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    claims: list[dict[str, Any]]
    duplicates: list[dict[str, Any]]
    near_duplicates: list[dict[str, Any]]
    independence_groups: dict[str, list[str]]
    transformations: list[dict[str, Any]]
    chain_of_custody: dict[str, dict[str, Any]]
    integrity_states: dict[str, str]
    authenticity_states: dict[str, str]
    provenance_states: dict[str, str]
    contradictions: list[dict[str, Any]]
    fact_gate_recommendations: dict[str, dict[str, Any]]
    evidence_quality: dict[str, dict[str, Any]]
    gaps: list[str]
    next_best_evidence: list[str]
    privacy_flags: list[str]
    handling_restrictions: list[str]
    specialist_handoffs: list[str]
    limitations: list[str]
    replay_manifest: dict[str, Any]
    created_at: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(x)))


def mean(values: list[float], default: float = 0.0) -> float:
    if not values:
        return default
    return sum(values) / len(values)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def to_bytes(content: Content) -> Optional[bytes]:
    if content is None:
        return None
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8", errors="ignore")
    if isinstance(content, (dict, list)):
        return json.dumps(content, default=str, sort_keys=True).encode("utf-8")
    return str(content).encode("utf-8", errors="ignore")


def norm_text(content: Content) -> str:
    b = to_bytes(content)
    if not b:
        return ""
    try:
        s = b.decode("utf-8", errors="ignore")
    except Exception:
        s = repr(b)
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"<[^>]+>", " ", s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def preview_text(text: str, limit: int = 180) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


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


def earliest_time(rec: dict[str, Any]) -> datetime:
    ev: Evidence = rec["evidence"]
    for val in (ev.acquired_at, ev.published_time, ev.observed_at, ev.created_time, ev.retrieved_time):
        dt = parse_dt(val)
        if dt:
            return dt
    return MAX_DT


def text_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


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


def validate_chain(ev: Evidence, raw_hash: str) -> dict[str, Any]:
    events = ev.chain_of_custody
    if not events:
        return {
            "status": "UNKNOWN",
            "gaps": ["no chain-of-custody events supplied"],
            "issues": [],
            "hash_issues": [],
        }

    ordered = sorted(events, key=lambda e: parse_dt(e.timestamp) or MAX_DT)
    gaps: list[str] = []
    issues: list[str] = []
    hash_issues: list[str] = []

    transfer_like = {
        "TRANSFERRED",
        "RECEIVED",
        "COPIED",
        "VERIFIED",
        "SEALED",
        "STORED",
        "HASHED",
    }

    acquired = parse_dt(ev.acquired_at)
    prev_hash = ""

    for ce in ordered:
        ts = parse_dt(ce.timestamp)
        action = (ce.action or "UNKNOWN").upper()

        if not ts:
            gaps.append(f"{ce.event_id}: missing timestamp")

        if acquired and ts and ts < acquired and action not in {"COLLECTED", "ACQUIRED"}:
            issues.append(f"{ce.event_id}: custody event before acquisition time")

        if ce.hash_before and ce.hash_after and ce.hash_before != ce.hash_after:
            if action in transfer_like:
                hash_issues.append(f"{ce.event_id}: hash changed during {action}")

        if prev_hash and ce.hash_before and ce.hash_before != prev_hash:
            hash_issues.append(f"{ce.event_id}: hash discontinuity from prior custody event")

        if not ce.hash_after and action in transfer_like:
            gaps.append(f"{ce.event_id}: missing hash_after")

        prev_hash = ce.hash_after or ce.hash_before or prev_hash

    if raw_hash and prev_hash and prev_hash != raw_hash:
        hash_issues.append("final custody hash does not match acquired content hash")

    if hash_issues or issues:
        status = "BROKEN"
    elif gaps:
        status = "PARTIAL"
    else:
        status = "SUBSTANTIALLY_COMPLETE"

    return {
        "status": status,
        "gaps": gaps,
        "issues": issues,
        "hash_issues": hash_issues,
        "event_count": len(events),
    }


def assess_provenance(
    ev: Evidence,
    source: Optional[Source],
    chain_status: str,
    raw_hash: str,
) -> tuple[str, list[str]]:
    missing: list[str] = []

    if not ev.source_id:
        missing.append("source unresolved")
    if not ev.collector_id and not (source and source.collector):
        missing.append("collector unresolved")
    if not ev.acquired_at:
        missing.append("acquisition time unresolved")
    if not raw_hash and not ev.provided_hashes:
        missing.append("no hash available")

    if chain_status == "BROKEN":
        return "BROKEN", missing

    if not missing:
        if chain_status in {"SUBSTANTIALLY_COMPLETE", "COMPLETE"}:
            return "SUPPORTED", missing
        if chain_status == "UNKNOWN":
            return "PARTIAL", missing + ["chain-of-custody not supplied"]
        return "PARTIAL", missing

    if len(missing) <= 1 and chain_status not in {"UNKNOWN", "BROKEN"}:
        return "PARTIAL", missing

    return "UNKNOWN", missing


def assess_integrity(
    ev: Evidence,
    raw_hash: str,
    chain: dict[str, Any],
    parent_hash: str,
    has_documented_transformation: bool,
) -> tuple[str, list[str]]:
    limits: list[str] = []
    provided = ev.provided_hashes.get("sha256") or ev.provided_hashes.get("SHA256") or ""

    if raw_hash and provided and raw_hash != provided:
        limits.append("provided SHA-256 does not match computed hash")
        return "INTEGRITY_CHANGED_UNEXPLAINED", limits

    if parent_hash and raw_hash and parent_hash != raw_hash:
        if has_documented_transformation:
            limits.append("hash changed due to recorded transformation")
            return "INTEGRITY_CHANGED_EXPECTED", limits
        limits.append("parent hash differs without recorded transformation")
        return "INTEGRITY_CHANGED_UNEXPLAINED", limits

    if chain.get("hash_issues"):
        limits.extend(chain["hash_issues"])
        return "INTEGRITY_CHANGED_UNEXPLAINED", limits

    if raw_hash:
        return "INTEGRITY_VERIFIED", limits

    if provided:
        limits.append("provided hash present but content unavailable for verification")
        return "INTEGRITY_UNVERIFIED", limits

    limits.append("no content hash available")
    return "INTEGRITY_UNVERIFIED", limits


def assess_authenticity(
    ev: Evidence,
    source: Optional[Source],
    provenance: str,
    integrity: str,
    chain_status: str,
) -> str:
    sig = (ev.signature_state or "UNKNOWN").upper()

    if integrity == "INTEGRITY_CHANGED_UNEXPLAINED" or chain_status == "BROKEN":
        return "MANIPULATION_CANDIDATE"

    if sig in {"INVALID_SIGNATURE", "REVOKED_CERTIFICATE_CONTEXT", "EXPIRED_CERTIFICATE_CONTEXT"}:
        return "MANIPULATION_CANDIDATE"

    if sig == "VALID_SIGNATURE" and ev.native_artifact and provenance in {"SUPPORTED", "VERIFIED"}:
        return "AUTHENTIC_SUPPORTED"

    if (
        ev.native_artifact
        and source
        and source.source_type in {"PRIMARY_RECORD", "OFFICIAL_SOURCE", "FIRST_PARTY_SOURCE"}
        and provenance in {"SUPPORTED", "PARTIAL"}
    ):
        return "LIKELY_AUTHENTIC"

    return "AUTHENTICITY_UNRESOLVED"


def temporal_issues(ev: Evidence) -> list[str]:
    issues: list[str] = []
    acquired = parse_dt(ev.acquired_at)
    created = parse_dt(ev.created_time)
    published = parse_dt(ev.published_time)
    event = parse_dt(ev.event_time_candidate)

    if acquired and created and acquired < created:
        issues.append("acquisition time precedes created time")
    if acquired and event and acquired < event:
        issues.append("acquisition time precedes event-time candidate")
    if published and event and published < event:
        issues.append("publication time precedes event-time candidate")

    return issues


def evidence_quality(rec: dict[str, Any], family_size: int) -> dict[str, Any]:
    ev: Evidence = rec["evidence"]
    source: Optional[Source] = rec["source"]

    provenance_quality = PROV_SCORES.get(rec["provenance"], 0.35)
    integrity_quality = INTEG_SCORES.get(rec["integrity"], 0.35)
    authenticity_quality = AUTH_SCORES.get(rec["authenticity"], 0.35)

    source_reliability = clamp(
        ev.source_reliability if ev.source_reliability > 0 else (source.reliability if source else 0.5)
    )

    if family_size <= 1:
        independence_quality = 0.80
    elif family_size == 2:
        independence_quality = 0.65
    else:
        independence_quality = 0.55

    known_times = sum(
        1
        for v in (ev.acquired_at, ev.created_time, ev.published_time, ev.event_time_candidate)
        if parse_dt(v)
    )
    if known_times >= 3:
        temporal_relevance = 0.85
    elif known_times == 2:
        temporal_relevance = 0.70
    elif known_times == 1:
        temporal_relevance = 0.55
    else:
        temporal_relevance = 0.40

    specificity = 0.70 if (
        ev.original_name
        or ev.claim_ids
        or ev.metadata.get("locator")
        or ev.metadata.get("message_id")
        or ev.metadata.get("record_id")
        or ev.metadata.get("event_id")
    ) else 0.50

    completeness_items = [
        bool(rec["raw_hash"]),
        bool(ev.source_id),
        bool(ev.collector_id or (source and source.collector)),
        bool(ev.acquired_at),
        rec["chain"]["status"] not in {"UNKNOWN", "BROKEN"},
        ev.native_artifact,
    ]
    completeness = mean([1.0 if x else 0.0 for x in completeness_items], 0.40)

    risk = 0.20
    if any(tr.lossy for tr in ev.transformations):
        risk += 0.20
    if any(tr.ai_generated for tr in ev.transformations):
        risk += 0.25
    if any(tr.analyst_generated for tr in ev.transformations):
        risk += 0.15
    if ev.artifact_type.upper() in {"SCREENSHOT", "SUMMARY", "OCR_TEXT", "TRANSCRIPT"}:
        risk += 0.15
    if not ev.native_artifact:
        risk += 0.10
    if not source:
        risk += 0.10

    contamination_resistance = 1.0 - clamp(risk)

    components = {
        "provenance_quality": clamp(provenance_quality),
        "integrity_quality": clamp(integrity_quality),
        "authenticity_quality": clamp(authenticity_quality),
        "source_reliability": clamp(source_reliability),
        "independence_quality": clamp(independence_quality),
        "temporal_relevance": clamp(temporal_relevance),
        "specificity": clamp(specificity),
        "completeness": clamp(completeness),
        "contamination_resistance": clamp(contamination_resistance),
    }

    score = sum(components[k] * QUALITY_WEIGHTS.get(k, 0.0) for k in components)

    return {
        "components": {k: round(v, 3) for k, v in components.items()},
        "score": round(clamp(score), 3),
        "weights": QUALITY_WEIGHTS,
        "family_size": family_size,
    }


class EvidenceIntAgent:
    """
    Defensive EVIDENCEINT core.

    Does:
    - preserve original evidence conceptually
    - compute hashes only from supplied content
    - validate chain-of-custody continuity
    - separate raw vs derived evidence
    - track transformations, including AI/analyst-derived artifacts
    - detect exact/near duplicates
    - estimate source independence families
    - map evidence to claims
    - recommend Fact Gate status conservatively
    - flag privacy, malicious-content, credential, and handling restrictions

    Does NOT:
    - fabricate evidence, hashes, provenance, custody, independence, or corroboration
    - modify originals
    - execute malicious files
    - bypass authentication
    - declare legal admissibility
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    def policy_check(self, req: EvidenceIntRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        if req.authorization.get("authorized") is not True:
            return PolicyDecision.BLOCK, "BLOCKED_AUTHORIZATION", "Explicit authorization is required."

        for phrase in BLOCK_PHRASES:
            if phrase in blob:
                return (
                    PolicyDecision.BLOCK,
                    "BLOCKED_POLICY",
                    f"Prohibited evidence-intelligence action requested: {phrase}",
                )

        return PolicyDecision.ALLOW, "", ""

    def blocked_result(self, req: EvidenceIntRequest, code: str, reason: str) -> EvidenceIntResult:
        return EvidenceIntResult(
            case_id=req.case_id,
            status=code,
            policy_decision=PolicyDecision.BLOCK.value,
            summary=f"POLICY_BLOCKED: {reason}",
            evidence=[],
            sources=[],
            claims=[],
            duplicates=[],
            near_duplicates=[],
            independence_groups={},
            transformations=[],
            chain_of_custody={},
            integrity_states={},
            authenticity_states={},
            provenance_states={},
            contradictions=[],
            fact_gate_recommendations={},
            evidence_quality={},
            gaps=["Request outside defensive EVIDENCEINT boundary."],
            next_best_evidence=[
                "Reframe request as authorized, passive, preservation-first evidence assessment."
            ],
            privacy_flags=[reason],
            handling_restrictions=["Do not proceed with prohibited evidence handling."],
            specialist_handoffs=[],
            limitations=[reason],
            replay_manifest={},
            created_at=now_iso(),
        )

    def analyze(self, req: EvidenceIntRequest) -> EvidenceIntResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self.blocked_result(req, code, reason)
            self.memory.append(asdict(result))
            return result

        source_map = {s.source_id: s for s in req.sources}
        records: dict[str, dict[str, Any]] = {}

        # 1) Preserve / hash / fingerprint supplied evidence.
        for ev in req.evidence:
            b = to_bytes(ev.content)
            raw_hash = sha256_hex(b) if b else ""
            text = norm_text(b)

            records[ev.evidence_id] = {
                "evidence": ev,
                "source": source_map.get(ev.source_id),
                "raw_hash": raw_hash,
                "text": text,
                "preview": preview_text(text),
                "chain": {},
                "provenance": "UNKNOWN",
                "provenance_missing": [],
                "integrity": "UNKNOWN",
                "authenticity": "AUTHENTICITY_UNRESOLVED",
                "temporal_issues": [],
                "flags": [],
                "limitations": list(ev.limitations),
                "quality": {},
                "independence_root": ev.evidence_id,
            }

        # 2) Flags.
        for eid, rec in records.items():
            ev = rec["evidence"]
            flags: list[str] = []

            if not ev.native_artifact:
                flags.append("NON_NATIVE")
            if ev.artifact_type.upper() == "SCREENSHOT":
                flags.append("SCREENSHOT_DERIVED")
            if any(tr.ai_generated for tr in ev.transformations):
                flags.append("AI_DERIVED")
            if any(tr.analyst_generated for tr in ev.transformations):
                flags.append("ANALYST_DERIVED")
            if ev.malicious_suspected:
                flags.append("MALICIOUS_SUSPECTED")
            if ev.contains_credentials:
                flags.append("CREDENTIALS_PRESENT")
            if ev.contains_pii:
                flags.append("PII_PRESENT")

            rec["flags"] = flags

        # 3) Chain, provenance, integrity, authenticity, temporal checks.
        for eid, rec in records.items():
            ev: Evidence = rec["evidence"]
            source: Optional[Source] = rec["source"]

            chain = validate_chain(ev, rec["raw_hash"])
            rec["chain"] = chain

            provenance, prov_missing = assess_provenance(ev, source, chain["status"], rec["raw_hash"])
            rec["provenance"] = provenance
            rec["provenance_missing"] = prov_missing

            parent_hash = ""
            if ev.parent_evidence_id and ev.parent_evidence_id in records:
                parent_hash = records[ev.parent_evidence_id]["raw_hash"]

            has_documented_transformation = any(
                tr.output_evidence_id == eid for tr in ev.transformations
            ) or bool(ev.transformations)

            integrity, integrity_limits = assess_integrity(
                ev,
                rec["raw_hash"],
                chain,
                parent_hash,
                has_documented_transformation,
            )
            rec["integrity"] = integrity
            rec["limitations"].extend(integrity_limits)

            rec["authenticity"] = assess_authenticity(
                ev,
                source,
                provenance,
                integrity,
                chain["status"],
            )

            rec["temporal_issues"] = temporal_issues(ev)
            rec["limitations"].extend(rec["temporal_issues"])

        # 4) Independence grouping / duplicate detection.
        uf = UnionFind()
        for eid in records:
            uf.add(eid)

        # Same source_id.
        by_source: dict[str, list[str]] = defaultdict(list)
        for eid, rec in records.items():
            sid = rec["evidence"].source_id
            if sid:
                by_source[sid].append(eid)
        for ids in by_source.values():
            for x in ids[1:]:
                uf.union(ids[0], x)

        # Same independence group / upstream source.
        group_map: dict[str, list[str]] = defaultdict(list)
        for eid, rec in records.items():
            source: Optional[Source] = rec["source"]
            if source:
                key = source.independence_group or source.upstream_source or source.source_id
            else:
                key = f"UNRESOLVED:{eid}"
            group_map[key].append(eid)
        for ids in group_map.values():
            for x in ids[1:]:
                uf.union(ids[0], x)

        # Parent-child derivation.
        lineage_edges: list[dict[str, Any]] = []
        for eid, rec in records.items():
            parent = rec["evidence"].parent_evidence_id
            if parent and parent in records:
                lineage_edges.append(
                    {
                        "from": eid,
                        "to": parent,
                        "relation": "DERIVED_FROM",
                        "confidence": 0.90,
                        "evidence": "declared parent evidence id",
                    }
                )
                uf.union(eid, parent)

        # Exact duplicates.
        duplicates: list[dict[str, Any]] = []
        ids = list(records.keys())
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = ids[i], ids[j]
                ra, rb = records[a], records[b]

                if ra["raw_hash"] and ra["raw_hash"] == rb["raw_hash"]:
                    earlier, later = (a, b) if earliest_time(ra) <= earliest_time(rb) else (b, a)
                    duplicates.append(
                        {
                            "later_evidence_id": later,
                            "earlier_evidence_id": earlier,
                            "basis": "identical SHA-256",
                        }
                    )
                    lineage_edges.append(
                        {
                            "from": later,
                            "to": earlier,
                            "relation": "EXACT_DUPLICATE_OF",
                            "confidence": 1.0,
                            "evidence": "identical SHA-256",
                        }
                    )
                    uf.union(later, earlier)

        # Near duplicates.
        near_duplicates: list[dict[str, Any]] = []
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = ids[i], ids[j]
                ra, rb = records[a], records[b]

                if ra["raw_hash"] and ra["raw_hash"] == rb["raw_hash"]:
                    continue

                sim = text_similarity(ra["text"], rb["text"])
                if sim >= 0.86 and ra["text"] and rb["text"]:
                    earlier, later = (a, b) if earliest_time(ra) <= earliest_time(rb) else (b, a)
                    near_duplicates.append(
                        {
                            "later_evidence_id": later,
                            "earlier_evidence_id": earlier,
                            "similarity": round(sim, 4),
                            "basis": "normalized text similarity",
                        }
                    )
                    lineage_edges.append(
                        {
                            "from": later,
                            "to": earlier,
                            "relation": "NEAR_DUPLICATE_OF",
                            "confidence": round(sim, 3),
                            "evidence": f"text similarity {sim:.3f}",
                        }
                    )
                    uf.union(later, earlier)

        independence_groups: dict[str, list[str]] = defaultdict(list)
        for eid, rec in records.items():
            root = uf.find(eid)
            rec["independence_root"] = root
            independence_groups[root].append(eid)

        independence_groups = {k: sorted(v) for k, v in independence_groups.items()}

        # 5) Evidence quality.
        for eid, rec in records.items():
            family_size = len(independence_groups.get(rec["independence_root"], [eid]))
            rec["quality"] = evidence_quality(rec, family_size)

        # 6) Claims / corroboration / Fact Gate.
        claim_rows: list[dict[str, Any]] = []
        contradictions: list[dict[str, Any]] = []
        fact_gate_recommendations: dict[str, dict[str, Any]] = {}
        next_best_evidence: set[str] = set()
        gaps: set[str] = set()

        for claim in req.claims:
            links = list(claim.evidence_links)

            # Conservative auto-link if no explicit links supplied.
            if not links:
                for eid, rec in records.items():
                    if claim.claim_id in rec["evidence"].claim_ids:
                        links.append(
                            EvidenceLink(
                                evidence_id=eid,
                                relation="CONSISTENT_WITH",
                                confidence=0.40,
                                notes="auto-linked from evidence.claim_ids",
                            )
                        )

            supporting_all: set[str] = set()
            substantive: set[str] = set()
            opposing: set[str] = set()
            claim_contradictions: list[dict[str, Any]] = []
            claim_next_actions: list[str] = []

            for link in links:
                eid = link.evidence_id
                if eid not in records:
                    gaps.add(f"Claim {claim.claim_id} references missing evidence {eid}.")
                    continue

                rel = (link.relation or "CONSISTENT_WITH").strip().upper()

                if rel in SUPPORT_RELATIONS:
                    supporting_all.add(eid)
                if rel in SUBSTANTIVE_RELATIONS:
                    substantive.add(eid)
                if rel in OPPOSE_RELATIONS:
                    opposing.add(eid)
                if rel in {"CONTRADICTS", "FALSIFIES"}:
                    item = {
                        "claim_id": claim.claim_id,
                        "evidence_id": eid,
                        "relation": rel,
                        "locator": link.locator,
                        "notes": link.notes,
                    }
                    claim_contradictions.append(item)
                    contradictions.append(item)

            supporting_all = sorted(supporting_all)
            substantive = sorted(substantive)
            opposing = sorted(opposing)

            independent_families = sorted({records[eid]["independence_root"] for eid in substantive})
            independent_family_count = len(independent_families)

            avg_quality = mean(
                [records[eid]["quality"]["score"] for eid in supporting_all],
                0.0,
            )

            has_substantive = bool(substantive)
            falsified = any(c["relation"] == "FALSIFIES" for c in claim_contradictions)
            has_contradiction = bool(claim_contradictions)

            bad_integrity = any(
                records[eid]["integrity"] == "INTEGRITY_CHANGED_UNEXPLAINED"
                for eid in substantive
            )
            broken_provenance = any(
                records[eid]["provenance"] == "BROKEN"
                for eid in substantive
            )

            if falsified:
                fact_gate = "UNSUPPORTED"
            elif has_contradiction:
                fact_gate = "DISPUTED"
            elif not has_substantive:
                fact_gate = "INSUFFICIENT"
            elif (
                independent_family_count >= FACT_GATE_RULES["min_independent_families_for_fact_ready"]
                and avg_quality >= FACT_GATE_RULES["min_avg_quality_for_fact_ready"]
                and not bad_integrity
                and not broken_provenance
            ):
                fact_gate = "FACT_READY"
            elif supporting_all and avg_quality >= 0.45:
                fact_gate = "PARTIAL_SUPPORT"
            else:
                fact_gate = "INSUFFICIENT"

            if has_contradiction:
                corroboration = "CONTRADICTED"
            elif not substantive:
                corroboration = "UNCORROBORATED"
            elif independent_family_count >= 2:
                corroboration = "INDEPENDENTLY_CORROBORATED"
            elif len(substantive) > 1:
                corroboration = "MULTIPLE_DEPENDENT_SOURCES"
            else:
                corroboration = "SINGLE_SOURCE"

            if fact_gate != "FACT_READY":
                if not has_substantive:
                    claim_next_actions.append(
                        f"Identify direct or indirect evidence for {claim.claim_id}."
                    )
                if independent_family_count < 2:
                    claim_next_actions.append(
                        f"Obtain an independent primary evidence family for {claim.claim_id}."
                    )
                if has_contradiction:
                    claim_next_actions.append(
                        f"Retrieve authoritative record resolving contradiction for {claim.claim_id}."
                    )
                if bad_integrity:
                    claim_next_actions.append(
                        f"Investigate unexplained integrity change affecting {claim.claim_id}."
                    )
                if broken_provenance:
                    claim_next_actions.append(
                        f"Repair or replace broken provenance evidence for {claim.claim_id}."
                    )

            for action in claim_next_actions:
                next_best_evidence.add(action)

            claim_row = {
                "claim_id": claim.claim_id,
                "proposition": claim.proposition,
                "supporting_evidence_ids": supporting_all,
                "substantive_evidence_ids": substantive,
                "opposing_evidence_ids": opposing,
                "independent_family_count": independent_family_count,
                "independence_roots": independent_families,
                "corroboration_state": corroboration,
                "fact_gate_recommendation": fact_gate,
                "average_evidence_quality": round(avg_quality, 3),
                "confidence": round(avg_quality, 3),
                "contradictions": claim_contradictions,
                "limitations": sorted(
                    set(
                        claim.limitations
                        + [
                            "Fact Gate recommendation is scoped to this proposition and current evidence.",
                            "Corroboration counts independent evidence families, not URLs or copies.",
                        ]
                    )
                ),
                "next_actions": claim_next_actions,
            }

            claim_rows.append(claim_row)
            fact_gate_recommendations[claim.claim_id] = {
                "recommendation": fact_gate,
                "corroboration_state": corroboration,
                "independent_family_count": independent_family_count,
                "average_evidence_quality": round(avg_quality, 3),
                "rules": FACT_GATE_RULES,
            }

        # 7) Global gaps / next best evidence / privacy / handoffs.
        privacy_flags: set[str] = set()
        handling_restrictions: set[str] = set()
        specialist_handoffs: set[str] = set()

        handling_restrictions.update(
            [
                "Preserve original bytes read-only; analyze working copies only.",
                "Do not execute suspected malicious evidence in this workflow.",
                "Do not expose credentials, PII, or restricted evidence unnecessarily.",
                "Use LOCAL_ONLY for sensitive evidence unless sanitized and policy-approved.",
                "Do not declare legal admissibility; hand off to LEGALINT/human counsel.",
            ]
        )

        for eid, rec in records.items():
            ev = rec["evidence"]
            source = rec["source"]

            for g in rec["chain"].get("gaps", []):
                gaps.add(f"{eid}: {g}")
            for g in rec["chain"].get("issues", []):
                gaps.add(f"{eid}: {g}")
            for m in rec["provenance_missing"]:
                gaps.add(f"{eid}: {m}")
            for t in rec["temporal_issues"]:
                gaps.add(f"{eid}: {t}")
            for lim in rec["limitations"]:
                gaps.add(f"{eid}: {lim}")

            if not ev.native_artifact:
                next_best_evidence.add(f"Retrieve native original for {eid}.")
            if rec["integrity"] == "INTEGRITY_UNVERIFIED":
                next_best_evidence.add(f"Obtain authorized content/hash to verify integrity for {eid}.")
            if rec["chain"]["status"] in {"PARTIAL", "BROKEN", "UNKNOWN"}:
                next_best_evidence.add(f"Obtain chain-of-custody log for {eid}.")
            if rec["provenance"] in {"UNKNOWN", "PARTIAL", "BROKEN"}:
                next_best_evidence.add(f"Resolve provenance/source/collector for {eid}.")
            if not source:
                next_best_evidence.add(f"Identify primary source for {eid}.")
            if any(tr.ai_generated for tr in ev.transformations):
                next_best_evidence.add(
                    f"Preserve AI-derived flag and obtain raw input evidence for {eid}."
                )
            if ev.artifact_type.upper() == "SCREENSHOT":
                next_best_evidence.add(f"Replace screenshot with native record for {eid} where authorized.")

            if ev.malicious_suspected:
                next_best_evidence.add(f"Hand off {eid} to MALINT sandbox; do not execute here.")
                specialist_handoffs.add("MALINT")
                handling_restrictions.add(f"Do not execute {eid}; treat as potentially malicious.")

            if ev.contains_credentials:
                next_best_evidence.add(f"Hand off {eid} to CREDINT restricted workflow; do not test credentials.")
                specialist_handoffs.add("CREDINT")
                privacy_flags.add(f"{eid}: credentials present; restrict and minimize exposure.")

            if ev.contains_pii:
                privacy_flags.add(f"{eid}: PII present; apply data minimization and redaction.")

            for sens in ev.sensitivity:
                s = sens.upper()
                if "FINANCIAL" in s:
                    specialist_handoffs.add("FININT")
                    privacy_flags.add(f"{eid}: financial sensitivity.")
                if "TRADE" in s:
                    specialist_handoffs.add("TRADEINT")
                if "CORPORATE" in s:
                    specialist_handoffs.add("CORPINT")
                if "MEDICAL" in s:
                    privacy_flags.add(f"{eid}: medical sensitivity.")
                if "LEGAL" in s:
                    specialist_handoffs.add("LEGALINT")

            atype = ev.artifact_type.upper()
            if any(x in atype for x in ["DOC", "PDF", "EMAIL", "MESSAGE"]):
                specialist_handoffs.update({"DOCINT", "METADATAINT"})
            if any(x in atype for x in ["IMAGE", "SCREENSHOT", "PHOTO"]):
                specialist_handoffs.add("IMINT")
            if "VIDEO" in atype:
                specialist_handoffs.add("VIDINT")
            if any(x in atype for x in ["AUDIO", "TRANSCRIPT"]):
                specialist_handoffs.add("AUDINT")
            if any(x in atype for x in ["LOG", "PCAP", "NETWORK"]):
                specialist_handoffs.update({"LOGINT", "NETINT"})
            if "HUMAN" in atype or "STATEMENT" in atype:
                specialist_handoffs.add("HUMINT")
            if "GEO" in atype or ev.metadata.get("geo"):
                specialist_handoffs.add("GEOINT")

        if not req.evidence:
            gaps.add("No evidence supplied.")
        if not req.claims:
            gaps.add("No claims supplied; evidence quality assessed but Fact Gate not computed.")

        # 8) Result assembly.
        evidence_rows: list[dict[str, Any]] = []
        transformations_rows: list[dict[str, Any]] = []
        chain_rows: dict[str, dict[str, Any]] = {}
        integrity_states: dict[str, str] = {}
        authenticity_states: dict[str, str] = {}
        provenance_states: dict[str, str] = {}
        evidence_quality_rows: dict[str, dict[str, Any]] = {}

        for eid, rec in records.items():
            ev = rec["evidence"]
            is_derived = bool(
                ev.parent_evidence_id
                or any(tr.output_evidence_id == eid for tr in ev.transformations)
            )

            evidence_rows.append(
                {
                    "evidence_id": eid,
                    "case_id": ev.case_id,
                    "artifact_type": ev.artifact_type,
                    "raw_or_derived": "DERIVED" if is_derived else "RAW",
                    "source_id": ev.source_id,
                    "collector_id": ev.collector_id,
                    "collection_method": ev.collection_method,
                    "acquired_at": ev.acquired_at,
                    "event_time_candidate": ev.event_time_candidate,
                    "created_time": ev.created_time,
                    "published_time": ev.published_time,
                    "original_name": ev.original_name,
                    "sha256": rec["raw_hash"],
                    "provided_hashes": ev.provided_hashes,
                    "content_preview": rec["preview"],
                    "native_artifact": ev.native_artifact,
                    "signature_state": ev.signature_state,
                    "provenance_state": rec["provenance"],
                    "integrity_state": rec["integrity"],
                    "authenticity_state": rec["authenticity"],
                    "chain_status": rec["chain"]["status"],
                    "quality_score": rec["quality"]["score"],
                    "independence_root": rec["independence_root"],
                    "flags": rec["flags"],
                    "limitations": sorted(set(rec["limitations"])),
                    "transformation_count": len(ev.transformations),
                    "custody_event_count": len(ev.chain_of_custody),
                }
            )

            chain_rows[eid] = rec["chain"]
            integrity_states[eid] = rec["integrity"]
            authenticity_states[eid] = rec["authenticity"]
            provenance_states[eid] = rec["provenance"]
            evidence_quality_rows[eid] = rec["quality"]

            for tr in ev.transformations:
                transformations_rows.append(asdict(tr))

        source_rows = [asdict(s) for s in req.sources]

        if not records:
            status = Status.INCONCLUSIVE.value
        elif claim_rows and all(c["fact_gate_recommendation"] == "FACT_READY" for c in claim_rows):
            status = Status.SUCCEEDED.value
        elif claim_rows and any(
            c["fact_gate_recommendation"] in {"FACT_READY", "PARTIAL_SUPPORT"} for c in claim_rows
        ):
            status = Status.PARTIAL.value
        else:
            status = Status.PARTIAL.value

        fact_ready_count = sum(
            1 for c in claim_rows if c["fact_gate_recommendation"] == "FACT_READY"
        )

        summary = (
            f"Defensive evidence assessment for {len(records)} evidence items and {len(claim_rows)} claims. "
            f"Fact-ready claims: {fact_ready_count}. Contradictions: {len(contradictions)}. "
            "No evidence fabrication, original modification, hash invention, custody forgery, "
            "or malicious execution performed."
        )

        limitations = [
            "Rule-based local EVIDENCEINT skeleton; not a full forensic laboratory or legal platform.",
            "Does not acquire live evidence, bypass authentication, execute files, or decrypt without authorization.",
            "Does not fabricate missing hashes, provenance, custody events, source independence, or corroboration.",
            "Fact-gate recommendations are evidentiary and revisable, not legal truth determinations.",
            "Near-duplicate detection is heuristic and should be supplemented with native-source and archival review.",
        ]

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "case_id": req.case_id,
            "created_at": now_iso(),
            "evidence_hashes": {eid: rec["raw_hash"] for eid, rec in records.items()},
            "provided_hashes": {eid: rec["evidence"].provided_hashes for eid, rec in records.items()},
            "independence_groups": independence_groups,
            "lineage_edges": lineage_edges,
            "quality_weights": QUALITY_WEIGHTS,
            "fact_gate_rules": FACT_GATE_RULES,
            "integrity_states": integrity_states,
            "provenance_states": provenance_states,
            "authenticity_states": authenticity_states,
            "claim_fact_gate": {
                c["claim_id"]: c["fact_gate_recommendation"] for c in claim_rows
            },
        }

        result = EvidenceIntResult(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            summary=summary,
            evidence=evidence_rows,
            sources=source_rows,
            claims=claim_rows,
            duplicates=duplicates,
            near_duplicates=near_duplicates,
            independence_groups=independence_groups,
            transformations=transformations_rows,
            chain_of_custody=chain_rows,
            integrity_states=integrity_states,
            authenticity_states=authenticity_states,
            provenance_states=provenance_states,
            contradictions=contradictions,
            fact_gate_recommendations=fact_gate_recommendations,
            evidence_quality=evidence_quality_rows,
            gaps=sorted(gaps),
            next_best_evidence=sorted(next_best_evidence),
            privacy_flags=sorted(privacy_flags),
            handling_restrictions=sorted(handling_restrictions),
            specialist_handoffs=sorted(specialist_handoffs),
            limitations=limitations,
            replay_manifest=replay_manifest,
            created_at=now_iso(),
        )

        self.memory.append(asdict(result))
        return result


def main() -> None:
    agent = EvidenceIntAgent(mode=Mode.LOCAL_ONLY)

    email_content = (
        b"From: vendor-v@example.test\n"
        b"To: finance@example.test\n"
        b"Subject: Bank account change\n"
        b"Message-ID: <msg1@example.test>\n"
        b"Date: 2026-10-08T08:55:00Z\n\n"
        b"Please update our beneficiary account to 12345.\n"
    )
    email_hash = sha256_hex(email_content)

    smtp_content = (
        b"2026-10-08T08:56:00Z smtp-gateway accepted "
        b"message-id=<msg1@example.test> from=vendor-v@example.test to=finance@example.test\n"
    )
    smtp_hash = sha256_hex(smtp_content)

    vendor_content = json.dumps(
        {
            "vendor": "Vendor V",
            "authorized_beneficiary_account": "99999",
            "pending_change": False,
            "record_id": "V-123",
        },
        sort_keys=True,
    ).encode()
    vendor_hash = sha256_hex(vendor_content)

    screenshot_text = email_content.decode().replace("\n", " ")

    sources = [
        Source(
            source_id="SRC-MAILBOX",
            source_type="PRIMARY_RECORD",
            publisher="Mailbox M",
            collector="MAIL-EXPORT-TOOL",
            reliability=0.85,
            limitations=["Mailbox export may omit some server-side headers."],
        ),
        Source(
            source_id="SRC-SMTP",
            source_type="PRIMARY_RECORD",
            publisher="Mail Gateway",
            collector="SIEM",
            reliability=0.85,
            independence_group="SMTP-GATEWAY",
        ),
        Source(
            source_id="SRC-NEWS",
            source_type="SECONDARY_SOURCE",
            publisher="Report R",
            upstream_source="SRC-MAILBOX",
            reliability=0.45,
            limitations=["Screenshot is derived from the same email and is not independent corroboration."],
        ),
        Source(
            source_id="SRC-VENDOR-MASTER",
            source_type="OFFICIAL_SOURCE",
            publisher="Vendor V ERP",
            collector="ERP-EXPORT",
            reliability=0.80,
            independence_group="VENDOR-MASTER-DATA",
        ),
    ]

    evidence = [
        Evidence(
            evidence_id="EV-EMAIL",
            case_id="EVID-001",
            artifact_type="EMAIL",
            source_id="SRC-MAILBOX",
            collector_id="MAIL-EXPORT-TOOL",
            collection_method="EMAIL_EXPORT",
            acquired_at="2026-10-08T09:00:00Z",
            event_time_candidate="2026-10-08T08:55:00Z",
            created_time="2026-10-08T08:55:00Z",
            original_name="vendor_bank_change.eml",
            content=email_content,
            native_artifact=True,
            signature_state="VALID_SIGNATURE",
            metadata={"message_id": "<msg1@example.test>"},
            claim_ids=["CLM-RECEIVED", "CLM-AUTHORIZED"],
            chain_of_custody=[
                CustodyEvent(
                    event_id="CE-EMAIL-1",
                    evidence_id="EV-EMAIL",
                    actor="MAIL-EXPORT-TOOL",
                    action="COLLECTED",
                    timestamp="2026-10-08T09:00:00Z",
                    destination_location="EVIDENCE-STORE",
                    hash_before=email_hash,
                    hash_after=email_hash,
                    reason="authorized mailbox export",
                ),
                CustodyEvent(
                    event_id="CE-EMAIL-2",
                    evidence_id="EV-EMAIL",
                    actor="EVIDENCE-SYSTEM",
                    action="SEALED",
                    timestamp="2026-10-08T09:05:00Z",
                    destination_location="EVIDENCE-VAULT",
                    hash_before=email_hash,
                    hash_after=email_hash,
                    reason="write-once storage",
                ),
            ],
        ),
        Evidence(
            evidence_id="EV-SMTP-LOG",
            case_id="EVID-001",
            artifact_type="LOG",
            source_id="SRC-SMTP",
            collector_id="SIEM",
            collection_method="LOG_EXPORT",
            acquired_at="2026-10-08T09:10:00Z",
            event_time_candidate="2026-10-08T08:56:00Z",
            original_name="smtp_delivery.log",
            content=smtp_content,
            native_artifact=True,
            metadata={"event_id": "SMTP-1"},
            claim_ids=["CLM-RECEIVED"],
            chain_of_custody=[
                CustodyEvent(
                    event_id="CE-SMTP-1",
                    evidence_id="EV-SMTP-LOG",
                    actor="SIEM",
                    action="COLLECTED",
                    timestamp="2026-10-08T09:10:00Z",
                    destination_location="EVIDENCE-STORE",
                    hash_before=smtp_hash,
                    hash_after=smtp_hash,
                    reason="authorized log export",
                )
            ],
        ),
        Evidence(
            evidence_id="EV-SCREENSHOT",
            case_id="EVID-001",
            artifact_type="SCREENSHOT",
            source_id="SRC-NEWS",
            collector_id="ANALYST",
            collection_method="SCREENSHOT",
            acquired_at="2026-10-08T12:00:00Z",
            content=screenshot_text,
            native_artifact=False,
            parent_evidence_id="EV-EMAIL",
            metadata={"locator": "Figure 1"},
            claim_ids=["CLM-RECEIVED"],
            transformations=[
                Transformation(
                    transformation_id="TR-SCREEN-1",
                    input_evidence_ids=["EV-EMAIL"],
                    output_evidence_id="EV-SCREENSHOT",
                    operation="SCREENSHOT_CAPTURE",
                    tool="analyst-workstation",
                    tool_version="1.0",
                    operator="analyst",
                    time="2026-10-08T12:00:00Z",
                    lossy=True,
                    analyst_generated=True,
                    reason="report illustration",
                )
            ],
        ),
        Evidence(
            evidence_id="EV-VENDOR-MASTER",
            case_id="EVID-001",
            artifact_type="DATABASE_RECORD",
            source_id="SRC-VENDOR-MASTER",
            collector_id="ERP-EXPORT",
            collection_method="DATABASE_QUERY",
            acquired_at="2026-10-08T13:00:00Z",
            content=vendor_content,
            native_artifact=True,
            metadata={"table": "vendor_master", "record_id": "V-123"},
            claim_ids=["CLM-AUTHORIZED"],
            chain_of_custody=[
                CustodyEvent(
                    event_id="CE-VENDOR-1",
                    evidence_id="EV-VENDOR-MASTER",
                    actor="ERP-EXPORT",
                    action="COLLECTED",
                    timestamp="2026-10-08T13:00:00Z",
                    destination_location="EVIDENCE-STORE",
                    hash_before=vendor_hash,
                    hash_after=vendor_hash,
                    reason="authorized ERP export",
                )
            ],
        ),
    ]

    claims = [
        Claim(
            claim_id="CLM-RECEIVED",
            proposition=(
                "A bank-change request was received from an address appearing to be Vendor V."
            ),
            time="2026-10-08T08:55:00Z",
            entity_ids=["Vendor V", "Finance Team"],
            evidence_links=[
                EvidenceLink(
                    evidence_id="EV-EMAIL",
                    relation="DIRECTLY_SUPPORTS",
                    locator="message_id=<msg1@example.test>",
                    confidence=0.90,
                ),
                EvidenceLink(
                    evidence_id="EV-SMTP-LOG",
                    relation="DIRECTLY_SUPPORTS",
                    locator="event_id=SMTP-1",
                    confidence=0.85,
                ),
                EvidenceLink(
                    evidence_id="EV-SCREENSHOT",
                    relation="CONSISTENT_WITH",
                    locator="Figure 1",
                    confidence=0.50,
                    notes="Derived from same email; not independent corroboration.",
                ),
            ],
        ),
        Claim(
            claim_id="CLM-AUTHORIZED",
            proposition="Vendor V authorized the bank-account change.",
            time="2026-10-08T08:55:00Z",
            entity_ids=["Vendor V"],
            evidence_links=[
                EvidenceLink(
                    evidence_id="EV-EMAIL",
                    relation="CONSISTENT_WITH",
                    locator="message_id=<msg1@example.test>",
                    confidence=0.50,
                    notes="Email asserts a change request, but does not prove authorization.",
                ),
                EvidenceLink(
                    evidence_id="EV-VENDOR-MASTER",
                    relation="CONTRADICTS",
                    locator="record_id=V-123",
                    confidence=0.85,
                    notes="Vendor master data shows no authorized beneficiary change.",
                ),
            ],
        ),
    ]

    request = EvidenceIntRequest(
        case_id="EVID-001",
        objective="Assess evidence quality, provenance, integrity, independence, corroboration, and Fact Gate readiness.",
        authorization={
            "authorized": True,
            "purpose": "defensive_evidence_assessment",
            "scope": "authorized_case",
        },
        sources=sources,
        evidence=evidence,
        claims=claims,
        scope={"time_range": "2026-10-08 to 2026-10-09"},
    )

    result = agent.analyze(request)

    print("=== EVIDENCEINT SUMMARY ===")
    print(result.summary)
    print()

    print("Independence groups:")
    for gid, members in result.independence_groups.items():
        print(f"  {gid}: {members}")
    print()

    print("Claims:")
    for c in result.claims:
        print(
            f"  {c['claim_id']}: "
            f"corroboration={c['corroboration_state']}, "
            f"fact_gate={c['fact_gate_recommendation']}, "
            f"independent_families={c['independent_family_count']}, "
            f"avg_quality={c['average_evidence_quality']}"
        )
    print()

    print("Exact duplicates:", result.duplicates)
    print("Near duplicates:", result.near_duplicates)
    print()

    print("Privacy flags:")
    for p in result.privacy_flags:
        print("  -", p)
    print()

    print("Specialist handoffs:", result.specialist_handoffs)
    print()

    print("Next best evidence (top 8):")
    for action in result.next_best_evidence[:8]:
        print("  -", action)
    print()

    blocked = agent.analyze(
        EvidenceIntRequest(
            case_id="EVID-002",
            objective="Delete unfavorable evidence and invent a hash to make the report look original.",
            authorization={"authorized": False},
            sources=[],
            evidence=[],
            claims=[],
        )
    )

    print("=== BLOCKED EXAMPLE ===")
    print("Status:", blocked.status)
    print("Summary:", blocked.summary)


if __name__ == "__main__":
    main()