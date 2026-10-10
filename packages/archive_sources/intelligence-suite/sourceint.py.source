# TRACEATLAS — SOURCEINT AI EMPLOYEE
# Single-file runnable Python core for Source Reliability / Provenance / Independence Intelligence
# Mode: LOCAL_ONLY / EVIDENCE-FIRST / PROVENANCE-PRESERVING / AUDITABLE
# Boundary: source intelligence, NOT censorship, NOT deanonymization, NOT automatic truth arbitration.

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


# ======================================================================
# Enums / constants
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
    BLOCKED_PRIVACY = "BLOCKED_PRIVACY"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"


SOURCE_TYPES = {
    "OFFICIAL_RECORD",
    "GOVERNMENT_SOURCE",
    "REGULATORY_SOURCE",
    "COURT_SOURCE",
    "CORPORATE_SOURCE",
    "COMPANY_FILING",
    "PRESS_RELEASE",
    "ACADEMIC_SOURCE",
    "RESEARCH_REPORT",
    "NEWS_SOURCE",
    "JOURNALISTIC_SOURCE",
    "BLOG",
    "SOCIAL_MEDIA",
    "FORUM",
    "HUMAN_SOURCE",
    "DATASET",
    "API_SOURCE",
    "SENSOR_SOURCE",
    "THREAT_FEED",
    "CTI_REPORT",
    "SECURITY_VENDOR",
    "ARCHIVE",
    "DOCUMENT",
    "IMAGE",
    "VIDEO",
    "AUDIO",
    "SCREENSHOT",
    "DATABASE",
    "REPOSITORY",
    "CODE_SOURCE",
    "OTHER",
    "UNKNOWN",
}

PRIMARY_SOURCE_TYPES = {
    "OFFICIAL_RECORD",
    "GOVERNMENT_SOURCE",
    "REGULATORY_SOURCE",
    "COURT_SOURCE",
    "CORPORATE_SOURCE",
    "COMPANY_FILING",
    "PRESS_RELEASE",
    "SENSOR_SOURCE",
    "DATASET",
    "HUMAN_SOURCE",
    "REPOSITORY",
    "CODE_SOURCE",
}

DERIVATIVE_EDGE_TYPES = {
    "DERIVED_FROM",
    "SYNDICATES",
    "MIRRORS",
    "REPRINTS",
    "TRANSLATES",
    "SUMMARIZES",
    "EXACT_DUPLICATE",
    "NEAR_DUPLICATE",
}

PROTECTED_ATTRIBUTES = {
    "race",
    "religion",
    "nationality",
    "political_affiliation",
    "political_party",
    "ideology",
    "gender",
    "sex",
    "sexual_orientation",
    "disability",
}

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]\}]+", re.IGNORECASE)

BLOCK_PATTERNS = [
    r"\b(deanonymi[sz]e|unmask|identify)\b[^.]*\b(private|confidential|protected|whistleblower|journalist source|human source)\b",
    r"\b(hack|breach|intrude|compromise|exploit)\b[^.]*\b(source|website|publisher|platform|account|feed)\b",
    r"\b(bypass)\b[^.]*\b(paywall|authentication|captcha|login|subscription)\b",
    r"\b(expose|publish|reveal|out)\b[^.]*\b(confidential source|protected source|whistleblower)\b",
    r"\b(use stolen|stolen credentials|stolen subscription)\b",
    r"\b(score|rate|rank|judge)\b[^.]*\b(reliab\w*|trust|credibility)\b[^.]*\b(political|party|ideology|race|religion|nationality|gender|sex)\b",
]


# ======================================================================
# Data models
# ======================================================================

@dataclass
class Source:
    source_id: Optional[str] = None
    url: Optional[str] = None
    title: Optional[str] = None
    publisher: Optional[str] = None
    author: Optional[str] = None
    creator: Optional[str] = None
    organization: Optional[str] = None
    source_type: str = "UNKNOWN"
    text: str = ""

    published_at: Optional[str] = None
    retrieved_at: Optional[str] = None
    created_at: Optional[str] = None
    version: Optional[str] = None
    archive_ref: Optional[str] = None

    methodology: Optional[str] = None
    access_basis: str = "UNKNOWN"  # DIRECT_ACCESS / INSTITUTIONAL_ACCESS / TECHNICAL_ACCESS / DOCUMENTARY_ACCESS / SECONDHAND_ACCESS / PUBLIC_ACCESS / NO_DEMONSTRATED_ACCESS / UNKNOWN
    competence_domains: list[str] = field(default_factory=list)

    limitations: list[str] = field(default_factory=list)
    incentives: list[str] = field(default_factory=list)
    bias_context: list[str] = field(default_factory=list)

    corrections: list[str] = field(default_factory=list)
    retractions: list[str] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)

    cited_sources: list[str] = field(default_factory=list)
    provenance_edges: list[dict[str, Any]] = field(default_factory=list)
    claim_ids: list[str] = field(default_factory=list)

    confidential: bool = False
    anonymous: bool = False
    role: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Claim:
    claim_id: str
    statement: str
    event_time: Optional[str] = None
    domains: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    supporting_source_ids: list[str] = field(default_factory=list)


@dataclass
class SourceIntRequest:
    case_id: str
    objective: str
    sources: list[Source] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)
    authorization: dict[str, Any] = field(default_factory=dict)
    time_range: dict[str, str] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    source_id: str
    target_id: str
    edge_type: str
    confidence: float
    evidence: str


@dataclass
class SourceAssessment:
    source_id: str
    display_source_id: str
    source_type: str
    publisher: Optional[str]
    author: Optional[str]
    source_role: str
    source_class: str
    origin_source_id: str
    upstream_ids: list[str]
    downstream_ids: list[str]
    family_id: str

    content_hash: str
    normalized_fingerprint: str

    reliability_dimensions: dict[str, float]
    reliability_score: float
    reliability_state: str
    confidence: float

    access_quality: str
    methodology_transparency: str
    temporal_relevance: str
    authenticity_state: str
    integrity_state: str

    limitations: list[str]
    bias_context: list[str]
    incentives: list[str]
    flags: list[str]


@dataclass
class ClaimAssessment:
    claim_id: str
    statement: str

    supporting_source_ids: list[str]
    raw_source_count: int
    unique_source_count: int
    independent_family_count: int
    primary_evidence_path_count: int

    corroboration_state: str
    credibility_state: str
    credibility_score: float
    fact_gate_passed: bool

    average_source_reliability: float
    max_access_quality: float
    contradictions: list[str]
    limitations: list[str]
    next_actions: list[str]


@dataclass
class SourceIntResult:
    case_id: str
    status: str
    policy_decision: str
    objective: str

    sources: list[dict[str, Any]]
    assessments: list[dict[str, Any]]
    claims: list[dict[str, Any]]

    provenance_edges: list[dict[str, Any]]
    source_families: dict[str, list[str]]
    exact_duplicates: list[dict[str, Any]]
    near_duplicates: list[dict[str, Any]]
    citation_graph: list[dict[str, Any]]

    unknowns: list[str]
    knowledge_gaps: list[str]
    recommended_next_actions: list[str]
    specialist_handoffs: list[str]
    privacy_flags: list[str]
    limitations: list[str]
    created_at: str


# ======================================================================
# Utility helpers
# ======================================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(x)))


def mean(values: list[float], default: float = 0.0) -> float:
    if not values:
        return default
    return sum(values) / len(values)


def sha256_12(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:12]


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


def normalize_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    url = str(url).strip()
    try:
        parsed = urlparse(url)
    except Exception:
        return url.lower()

    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")

    query_pairs: list[tuple[str, str]] = []
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        lk = k.lower()
        if lk.startswith("utm_") or lk in {"ref", "fbclid", "gclid", "mc_cid", "mc_eid"}:
            continue
        query_pairs.append((k, v))

    query = urlencode(query_pairs, doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+", " URL ", text, flags=re.IGNORECASE)
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def token_shingles(tokens: list[str], n: int = 5) -> set[str]:
    if not tokens:
        return set()
    if len(tokens) < n:
        n = max(1, len(tokens))
    return {" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def token_hash64(token: str) -> int:
    return int(hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest(), 16) & ((1 << 64) - 1)


def simhash(tokens: list[str]) -> int:
    if not tokens:
        return 0

    bits = 64
    v = [0] * bits
    counts = Counter(tokens)

    for token, weight in counts.items():
        h = token_hash64(token)
        for i in range(bits):
            if h & (1 << i):
                v[i] += weight
            else:
                v[i] -= weight

    fp = 0
    for i in range(bits):
        if v[i] > 0:
            fp |= (1 << i)
    return fp


def hamming64(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def source_excerpt(text: str, limit: int = 180) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


# ======================================================================
# Union-Find for source families
# ======================================================================

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

        # Path compression
        while self.parent[x] != root:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: str, b: str) -> str:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra

        # Deterministic root
        if ra < rb:
            self.parent[rb] = ra
            return ra
        else:
            self.parent[ra] = rb
            return rb


# ======================================================================
# SOURCEINT agent
# ======================================================================

class SourceIntAgent:
    """
    Defensive SOURCEINT core.

    Does:
    - preserve source identity/provenance
    - fingerprint content
    - detect exact/near duplicates
    - build citation/provenance graph
    - cluster source families
    - assess source reliability dimensions
    - assess claim credibility separately
    - enforce privacy / no-deanonymization boundaries

    Does NOT:
    - hack sources
    - bypass paywalls/auth
    - expose confidential sources
    - deanonymize protected humans
    - score reliability by political ideology / race / religion / nationality
    - act as a single-number truth oracle
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Policy / safety gate
    # ------------------------------------------------------------------

    def policy_check(self, req: SourceIntRequest) -> tuple[PolicyDecision, str, list[str]]:
        warnings: list[str] = []

        blob = " ".join(
            [
                req.objective,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        for pattern in BLOCK_PATTERNS:
            if re.search(pattern, blob, flags=re.IGNORECASE):
                return (
                    PolicyDecision.BLOCK,
                    f"Policy blocked: prohibited source-intelligence action detected ({pattern}).",
                    warnings,
                )

        if req.authorization.get("authorized") is False:
            return PolicyDecision.BLOCK, "Authorization explicitly denied.", warnings

        # Soft warning: protected attributes present in scope metadata
        for key in req.scope.keys():
            if key.lower() in PROTECTED_ATTRIBUTES:
                warnings.append(f"Ignored protected attribute in scope: {key}")

        return PolicyDecision.ALLOW, "", warnings

    # ------------------------------------------------------------------
    # Source identity / fingerprinting
    # ------------------------------------------------------------------

    def make_source_id(self, src: Source) -> str:
        if src.source_id:
            return str(src.source_id)

        if src.url:
            nurl = normalize_url(src.url)
            if nurl:
                return f"url:{nurl}"

        basis = "|".join(
            [
                str(src.title or ""),
                str(src.publisher or ""),
                str(src.author or ""),
                str(src.text or "")[:500],
            ]
        )
        return f"hash:{sha256_12(basis)}"

    def extract_citations(self, src: Source) -> list[str]:
        refs: set[str] = set()

        for ref in src.cited_sources or []:
            refs.add(str(ref).strip())

        for match in URL_RE.findall(src.text or ""):
            refs.add(match)

        return [r for r in refs if r]

    # ------------------------------------------------------------------
    # Reliability assessment (multi-dimensional, not truth oracle)
    # ------------------------------------------------------------------

    def assess_reliability(self, src: Source) -> tuple[dict[str, float], float, str, float, list[str], list[str]]:
        limitations: list[str] = list(src.limitations)
        flags: list[str] = []

        # Ignore protected attributes if present in metadata
        for k in list(src.metadata.keys()):
            if str(k).lower() in PROTECTED_ATTRIBUTES:
                flags.append(f"Ignored protected attribute in reliability scoring: {k}")

        # identity_confidence
        identity = 0.25
        if src.url:
            identity += 0.20
        if src.publisher:
            identity += 0.15
        if src.author or src.creator:
            identity += 0.10
        if src.source_id:
            identity += 0.05
        if src.archive_ref:
            identity += 0.05
        if src.confidential:
            identity = min(identity, 0.40)
            flags.append("Confidential source: identity restricted by policy.")
        if src.anonymous:
            identity = min(identity, 0.50)
            flags.append("Anonymous source: assessed by access/corroboration, not identity.")
        identity = clamp(identity)

        # access_quality
        access_map = {
            "DIRECT_ACCESS": 1.00,
            "INSTITUTIONAL_ACCESS": 0.85,
            "TECHNICAL_ACCESS": 0.80,
            "DOCUMENTARY_ACCESS": 0.70,
            "SECONDHAND_ACCESS": 0.45,
            "PUBLIC_ACCESS": 0.40,
            "NO_DEMONSTRATED_ACCESS": 0.20,
            "UNKNOWN": 0.30,
        }
        access = access_map.get(str(src.access_basis).upper(), 0.30)
        if access <= 0.25:
            limitations.append("No demonstrated access to underlying event/data.")

        # domain_competence
        comp_meta = src.metadata.get("competence_score")
        if isinstance(comp_meta, (int, float)):
            competence = clamp(float(comp_meta))
        elif src.competence_domains:
            competence = 0.70
        else:
            competence = 0.45
            limitations.append("Domain competence unknown.")

        # methodology_quality
        meth = (src.methodology or "").lower()
        mq = 0.35
        if len(meth) > 80:
            mq += 0.10
        for kw in [
            "sample",
            "dataset",
            "method",
            "analysis",
            "peer",
            "reproduc",
            "transparent",
            "control",
            "validation",
            "telemetry",
            "hash",
            "signature",
        ]:
            if kw in meth:
                mq += 0.04
        mq = clamp(mq)

        # transparency
        transparency = 0.30
        if src.cited_sources or src.provenance_edges:
            transparency += 0.20
        if any(k in meth for k in ["appendix", "full data", "methodology", "reproducible", "transparent"]):
            transparency += 0.15
        if str(src.metadata.get("evidence_disclosure", "")).lower() == "full":
            transparency += 0.20
        transparency = clamp(transparency)

        # historical_accuracy
        hist_map = {
            "well_calibrated": 0.90,
            "generally_reliable": 0.75,
            "mixed": 0.50,
            "limited_history": 0.45,
            "poor_history": 0.25,
        }
        historical = hist_map.get(str(src.metadata.get("historical_accuracy", "")).lower(), 0.50)

        # timeliness
        pub = parse_dt(src.published_at or src.retrieved_at or src.created_at)
        if pub:
            age_days = (now_utc() - pub).days
            if age_days < 0:
                timeliness = 0.20
                limitations.append("Source timestamp is in the future relative to assessment time.")
            elif age_days <= 90:
                timeliness = 0.80
            elif age_days <= 365:
                timeliness = 0.65
            elif age_days <= 1095:
                timeliness = 0.50
            else:
                timeliness = 0.35
        else:
            timeliness = 0.35
            limitations.append("Publication/retrieval time unknown.")

        # correction_behavior
        if src.retractions:
            correction = 0.35
            limitations.append("Retraction recorded.")
            flags.append("RETRACTION_PRESENT")
        elif src.corrections:
            correction = 0.75
            flags.append("Transparent correction history.")
        else:
            correction = 0.60

        # evidence_quality
        evidence = 0.40
        if src.source_type in PRIMARY_SOURCE_TYPES:
            evidence += 0.20
        if src.archive_ref:
            evidence += 0.10
        if src.metadata.get("digital_signature_valid"):
            evidence += 0.15
        if src.metadata.get("native_record_available"):
            evidence += 0.10
        if src.metadata.get("evidence_disclosure") == "full":
            evidence += 0.10
        evidence = clamp(evidence)

        dims = {
            "identity_confidence": identity,
            "access_quality": access,
            "domain_competence": competence,
            "methodology_quality": mq,
            "transparency": transparency,
            "historical_accuracy": historical,
            "timeliness": timeliness,
            "correction_behavior": correction,
            "evidence_quality": evidence,
        }

        weights = {
            "identity_confidence": 0.10,
            "access_quality": 0.20,
            "domain_competence": 0.10,
            "methodology_quality": 0.15,
            "transparency": 0.10,
            "historical_accuracy": 0.10,
            "timeliness": 0.05,
            "correction_behavior": 0.10,
            "evidence_quality": 0.10,
        }

        score = sum(dims[k] * weights.get(k, 0.0) for k in dims)

        # Critical weakness caps
        if dims["access_quality"] < 0.30:
            score = min(score, 0.45)
        if dims["methodology_quality"] < 0.30:
            score = min(score, 0.55)
        if src.retractions:
            score = min(score, 0.40)

        score = clamp(score)

        if dims["identity_confidence"] < 0.20 and dims["access_quality"] < 0.25:
            state = "UNKNOWN"
        elif score >= 0.80:
            state = "HIGH"
        elif score >= 0.60:
            state = "MODERATE"
        elif score >= 0.40:
            state = "LOW"
        else:
            state = "VERY_LOW"

        known_signals = sum(1 for v in dims.values() if v >= 0.55)
        confidence = clamp(0.35 + known_signals * 0.05)

        return dims, score, state, confidence, limitations, flags

    def methodology_transparency_state(self, transparency: float) -> str:
        if transparency >= 0.80:
            return "FULL"
        if transparency >= 0.65:
            return "SUBSTANTIAL"
        if transparency >= 0.45:
            return "PARTIAL"
        if transparency >= 0.25:
            return "MINIMAL"
        return "OPAQUE"

    def temporal_relevance_state(self, timeliness: float) -> str:
        if timeliness >= 0.75:
            return "CURRENT"
        if timeliness >= 0.55:
            return "RECENT"
        if timeliness >= 0.40:
            return "HISTORICAL"
        return "STALE_OR_UNKNOWN"

    def authenticity_state(self, src: Source) -> str:
        if src.metadata.get("digital_signature_valid"):
            return "SUPPORTED_BY_SIGNATURE"
        if src.source_type in {"OFFICIAL_RECORD", "GOVERNMENT_SOURCE", "COURT_SOURCE", "COMPANY_FILING"}:
            return "OFFICIAL_CHANNEL_EXPECTED"
        if src.archive_ref:
            return "ARCHIVE_SUPPORTED"
        return "UNVERIFIED"

    def integrity_state(self, src: Source) -> str:
        if src.retractions:
            return "RETRACTED_VERSION_TRACKED"
        if src.corrections:
            return "CORRECTED_VERSION_TRACKED"
        if src.version:
            return "VERSIONED"
        return "HASH_PRESERVED_NO_EXTERNAL_INTEGRITY_CHECK"

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    def analyze(self, req: SourceIntRequest) -> SourceIntResult:
        decision, reason, policy_warnings = self.policy_check(req)

        if decision == PolicyDecision.BLOCK:
            result = SourceIntResult(
                case_id=req.case_id,
                status=Status.BLOCKED_POLICY.value,
                policy_decision=decision.value,
                objective=req.objective,
                sources=[],
                assessments=[],
                claims=[],
                provenance_edges=[],
                source_families={},
                exact_duplicates=[],
                near_duplicates=[],
                citation_graph=[],
                unknowns=["Request outside authorized SOURCEINT boundary."],
                knowledge_gaps=["Prohibited action requested; no provenance analysis performed."],
                recommended_next_actions=[
                    "Reframe request as passive, authorized, privacy-preserving source provenance analysis."
                ],
                specialist_handoffs=[],
                privacy_flags=[reason],
                limitations=[reason],
                created_at=iso_now(),
            )
            self.memory.append(asdict(result))
            return result

        # --------------------------------------------------------------
        # Ingest / preserve / fingerprint sources
        # --------------------------------------------------------------
        records: dict[str, dict[str, Any]] = {}
        url_to_id: dict[str, str] = {}

        for src in req.sources:
            sid = self.make_source_id(src)
            if sid in records:
                sid = f"{sid}-dup-{sha256_12(src.text or src.title or '')}"

            norm = normalize_text(src.text)
            tokens = norm.split()
            sh = token_shingles(tokens, n=5)
            fp = hashlib.sha256(norm.encode("utf-8", errors="ignore")).hexdigest()
            sim = simhash(tokens)

            records[sid] = {
                "source": src,
                "normalized": norm,
                "tokens": tokens,
                "shingles": sh,
                "fingerprint": fp,
                "simhash": sim,
                "upstream": set(),
                "downstream": set(),
                "derived_type": None,
                "derived_confidence": 0.0,
                "family_root": sid,
                "family_id": f"FAM-{sha256_12(sid)}",
            }

            nurl = normalize_url(src.url)
            if nurl:
                url_to_id[nurl] = sid

        def resolve_target(ref: str) -> str:
            ref = str(ref).strip()
            if ref in records:
                return ref
            nurl = normalize_url(ref)
            if nurl and nurl in url_to_id:
                return url_to_id[nurl]
            if ref.lower().startswith("http") and nurl:
                return nurl
            return ref

        # --------------------------------------------------------------
        # Build provenance / citation edges
        # --------------------------------------------------------------
        edges: list[ProvenanceEdge] = []
        exact_duplicates: list[dict[str, Any]] = []
        near_duplicates: list[dict[str, Any]] = []
        uf = UnionFind()

        for sid, rec in records.items():
            uf.add(sid)
            src: Source = rec["source"]

            # Explicit citations / referenced URLs
            for ref in self.extract_citations(src):
                target = resolve_target(ref)
                edges.append(
                    ProvenanceEdge(
                        source_id=sid,
                        target_id=target,
                        edge_type="CITES",
                        confidence=0.70,
                        evidence="citation/reference extracted from source",
                    )
                )

            # Explicit provenance edges supplied by caller
            for pe in src.provenance_edges or []:
                target = resolve_target(str(pe.get("to", "")))
                etype = str(pe.get("type", "DERIVED_FROM")).upper()
                conf = clamp(float(pe.get("confidence", 0.80)))
                evidence = str(pe.get("evidence", "explicit provenance assertion"))

                edges.append(
                    ProvenanceEdge(
                        source_id=sid,
                        target_id=target,
                        edge_type=etype,
                        confidence=conf,
                        evidence=evidence,
                    )
                )

                if target in records and etype in DERIVATIVE_EDGE_TYPES and conf >= 0.70:
                    uf.union(sid, target)
                    rec["upstream"].add(target)
                    records[target]["downstream"].add(sid)

                    if conf > rec.get("derived_confidence", 0.0):
                        rec["derived_type"] = etype
                        rec["derived_confidence"] = conf

        # Pairwise duplicate / near-duplicate detection
        ids = list(records.keys())
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b = ids[i], ids[j]
                ra, rb = records[a], records[b]

                # Determine earlier/later by publication/retrieval time
                da = parse_dt(ra["source"].published_at or ra["source"].retrieved_at or ra["source"].created_at)
                db = parse_dt(rb["source"].published_at or rb["source"].retrieved_at or rb["source"].created_at)
                max_dt = datetime.max.replace(tzinfo=timezone.utc)

                if (da or max_dt) <= (db or max_dt):
                    earlier, later = a, b
                else:
                    earlier, later = b, a

                if ra["fingerprint"] == rb["fingerprint"] and ra["normalized"]:
                    edges.append(
                        ProvenanceEdge(
                            source_id=later,
                            target_id=earlier,
                            edge_type="EXACT_DUPLICATE",
                            confidence=1.00,
                            evidence="identical normalized content fingerprint",
                        )
                    )
                    exact_duplicates.append({"later_source_id": later, "earlier_source_id": earlier})
                    uf.union(later, earlier)

                    records[later]["upstream"].add(earlier)
                    records[earlier]["downstream"].add(later)
                    records[later]["derived_type"] = "MIRROR"
                    records[later]["derived_confidence"] = 1.00

                else:
                    jac = jaccard(ra["shingles"], rb["shingles"])
                    ham = hamming64(ra["simhash"], rb["simhash"])
                    sim_conf = 1.0 - (ham / 64.0) if ra["tokens"] and rb["tokens"] else 0.0
                    conf = max(jac, sim_conf)

                    if conf >= 0.82 and (ra["shingles"] or ra["tokens"]):
                        edges.append(
                            ProvenanceEdge(
                                source_id=later,
                                target_id=earlier,
                                edge_type="NEAR_DUPLICATE",
                                confidence=clamp(conf),
                                evidence=f"shingle Jaccard={jac:.3f}, simhash confidence={sim_conf:.3f}",
                            )
                        )
                        near_duplicates.append(
                            {
                                "later_source_id": later,
                                "earlier_source_id": earlier,
                                "jaccard": round(jac, 4),
                                "simhash_confidence": round(sim_conf, 4),
                                "combined_confidence": round(conf, 4),
                            }
                        )

                        if conf >= 0.88:
                            uf.union(later, earlier)
                            records[later]["upstream"].add(earlier)
                            records[earlier]["downstream"].add(later)
                            records[later]["derived_type"] = "NEAR_DUPLICATE"
                            records[later]["derived_confidence"] = clamp(conf)

        # Assign families
        for sid, rec in records.items():
            root = uf.find(sid)
            rec["family_root"] = root
            rec["family_id"] = f"FAM-{sha256_12(root)}"

        source_families: dict[str, list[str]] = defaultdict(list)
        for sid, rec in records.items():
            source_families[rec["family_id"]].append(sid)

        # --------------------------------------------------------------
        # Assess sources
        # --------------------------------------------------------------
        assessments: dict[str, SourceAssessment] = {}

        for sid, rec in records.items():
            src: Source = rec["source"]
            dims, score, state, confidence, limitations, flags = self.assess_reliability(src)

            family_members = [x for x in records if records[x]["family_id"] == rec["family_id"]]
            max_dt = datetime.max.replace(tzinfo=timezone.utc)
            origin_id = min(
                family_members,
                key=lambda x: (
                    parse_dt(records[x]["source"].published_at or records[x]["source"].retrieved_at or records[x]["source"].created_at) or max_dt,
                    x,
                ),
            )

            upstream_ids = sorted(rec["upstream"])
            downstream_ids = sorted(rec["downstream"])

            if not upstream_ids and src.source_type in PRIMARY_SOURCE_TYPES:
                source_class = "PRIMARY"
            elif upstream_ids:
                source_class = "SECONDARY"
            elif src.metadata.get("aggregator"):
                source_class = "TERTIARY"
            else:
                source_class = "UNKNOWN"

            if src.role:
                source_role = src.role
            elif rec.get("derived_type") == "MIRROR":
                source_role = "MIRROR"
            elif rec.get("derived_type") == "SYNDICATES":
                source_role = "SYNDICATOR"
            elif rec.get("derived_type") in {"NEAR_DUPLICATE", "DERIVED_FROM", "REPRINTS", "TRANSLATES", "SUMMARIZES"}:
                source_role = "DERIVATIVE_REPORTER"
            elif not upstream_ids and downstream_ids:
                source_role = "ORIGINAL_CREATOR"
            elif upstream_ids:
                source_role = "SECONDARY_REPORTER"
            else:
                source_role = "UNKNOWN"

            # Redact confidential identity material
            if src.confidential:
                display_sid = f"CONFIDENTIAL-{sha256_12(sid)}"
                publisher = "[REDACTED]"
                author = "[REDACTED]"
            elif src.anonymous:
                display_sid = sid
                publisher = src.publisher or "[UNKNOWN_PUBLISHER]"
                author = src.author or "[ANONYMOUS]"
            else:
                display_sid = sid
                publisher = src.publisher
                author = src.author

            assessments[sid] = SourceAssessment(
                source_id=sid,
                display_source_id=display_sid,
                source_type=src.source_type,
                publisher=publisher,
                author=author,
                source_role=source_role,
                source_class=source_class,
                origin_source_id=origin_id,
                upstream_ids=upstream_ids,
                downstream_ids=downstream_ids,
                family_id=rec["family_id"],
                content_hash=hashlib.sha256((src.text or "").encode("utf-8", errors="ignore")).hexdigest(),
                normalized_fingerprint=rec["fingerprint"],
                reliability_dimensions={k: round(v, 3) for k, v in dims.items()},
                reliability_score=round(score, 3),
                reliability_state=state,
                confidence=round(confidence, 3),
                access_quality=src.access_basis,
                methodology_transparency=self.methodology_transparency_state(dims["transparency"]),
                temporal_relevance=self.temporal_relevance_state(dims["timeliness"]),
                authenticity_state=self.authenticity_state(src),
                integrity_state=self.integrity_state(src),
                limitations=limitations,
                bias_context=src.bias_context,
                incentives=src.incentives,
                flags=flags + policy_warnings,
            )

        # --------------------------------------------------------------
        # Assess claims
        # --------------------------------------------------------------
        claim_assessments: list[ClaimAssessment] = []
        all_next_actions: set[str] = set()
        all_unknowns: set[str] = set()
        all_gaps: set[str] = set()
        handoffs: set[str] = set()
        privacy_flags: set[str] = set()

        for sid, rec in records.items():
            src = rec["source"]
            if src.confidential:
                privacy_flags.add("Confidential source present: identity restricted; no deanonymization.")
                handoffs.add("HUMINT")
            if src.anonymous:
                privacy_flags.add("Anonymous source present: assessed without identity resolution.")
            if src.source_type == "IMAGE":
                handoffs.add("IMINT")
            if src.source_type == "VIDEO":
                handoffs.add("VIDINT")
            if src.source_type == "AUDIO":
                handoffs.add("AUDINT")
            if src.source_type in {"DOCUMENT", "PDF", "FILE"}:
                handoffs.add("DOCINT")
            if src.source_type in {"THREAT_FEED", "CTI_REPORT", "SECURITY_VENDOR"}:
                handoffs.add("CTI")

        for claim in req.claims:
            supporting_ids: set[str] = set()

            for sid in claim.supporting_source_ids:
                if sid in records:
                    supporting_ids.add(sid)

            for sid, rec in records.items():
                if claim.claim_id in (rec["source"].claim_ids or []):
                    supporting_ids.add(sid)

            # Optional conservative exact-statement match
            stmt_norm = normalize_text(claim.statement)
            if stmt_norm and len(stmt_norm) >= 24:
                for sid, rec in records.items():
                    if stmt_norm in rec["normalized"]:
                        supporting_ids.add(sid)

            supporting_ids = sorted(supporting_ids)
            raw_count = len(supporting_ids)
            unique_count = len(set(supporting_ids))

            families: dict[str, list[str]] = defaultdict(list)
            rel_scores: list[float] = []
            access_scores: list[float] = []
            temporal_scores: list[float] = []
            evidence_scores: list[float] = []
            limitations: list[str] = []
            contradictions = list(claim.contradictions)

            for sid in supporting_ids:
                ass = assessments[sid]
                families[ass.family_id].append(sid)
                rel_scores.append(ass.reliability_score)
                access_scores.append(ass.reliability_dimensions["access_quality"])
                temporal_scores.append(ass.reliability_dimensions["timeliness"])
                evidence_scores.append(ass.reliability_dimensions["evidence_quality"])
                limitations.extend(ass.limitations)

                if ass.reliability_state == "UNKNOWN":
                    all_unknowns.add(f"Source reliability unknown for {ass.display_source_id}.")
                if "RETRACTION_PRESENT" in ass.flags:
                    limitations.append(f"Supporting source {ass.display_source_id} has retraction history.")
                    all_gaps.add("Propagate retraction impact to downstream claims.")

            family_count = len(families)
            avg_rel = mean(rel_scores, 0.0)
            max_access = max(access_scores, default=0.0)
            avg_temporal = mean(temporal_scores, 0.0)
            avg_evidence = mean(evidence_scores, 0.0)

            primary_paths = 0
            for fam_id, members in families.items():
                is_primary_family = False
                for msid in members:
                    msrc = records[msid]["source"]
                    mass = assessments[msid]
                    if msrc.source_type in PRIMARY_SOURCE_TYPES or mass.reliability_dimensions["access_quality"] >= 0.70:
                        is_primary_family = True
                        break
                if is_primary_family:
                    primary_paths += 1

            # Corroboration state
            if raw_count == 0:
                corroboration = "UNKNOWN"
            elif family_count == 1:
                corroboration = "SINGLE_SOURCE" if raw_count == 1 else "DEPENDENT_MULTI_SOURCE"
            elif family_count >= 2:
                corroboration = "INDEPENDENT_MULTI_SOURCE" if primary_paths >= 1 else "PARTIALLY_INDEPENDENT"
            else:
                corroboration = "UNKNOWN"

            # Credibility score
            family_score = min(1.0, family_count / 2.0)
            primary_bonus = 1.0 if primary_paths > 0 else 0.0

            credibility_score = (
                0.30 * family_score
                + 0.25 * avg_rel
                + 0.15 * max_access
                + 0.10 * avg_temporal
                + 0.10 * avg_evidence
                + 0.10 * primary_bonus
            )

            if contradictions:
                credibility_score -= 0.25

            credibility_score = clamp(credibility_score)

            if raw_count == 0:
                credibility_state = "INCONCLUSIVE"
            elif contradictions:
                credibility_state = "DISPUTED"
            elif family_count >= 2 and avg_rel >= 0.75 and credibility_score >= 0.75:
                credibility_state = "STRONGLY_SUPPORTED"
            elif family_count >= 2 and avg_rel >= 0.55 and credibility_score >= 0.60:
                credibility_state = "SUPPORTED"
            elif primary_paths >= 1 and avg_rel >= 0.80 and credibility_score >= 0.65:
                credibility_state = "SUPPORTED"
            elif raw_count > 1 and family_count == 1:
                credibility_state = "PARTIALLY_SUPPORTED"
            elif avg_rel >= 0.50:
                credibility_state = "PARTIALLY_SUPPORTED"
            else:
                credibility_state = "UNSUPPORTED"

            fact_gate_passed = (
                credibility_state in {"STRONGLY_SUPPORTED", "SUPPORTED"}
                and (family_count >= 2 or (primary_paths >= 1 and avg_rel >= 0.80))
                and not contradictions
            )

            next_actions: list[str] = []

            if raw_count == 0:
                next_actions.append("Identify at least one source for this claim.")
                all_gaps.add(f"No source linked to claim {claim.claim_id}.")

            if raw_count > 0 and family_count < 2:
                next_actions.append("Locate an independent primary evidence path; current support may be one source family.")
                all_gaps.add(f"Claim {claim.claim_id} lacks independent source families.")

            if any(assessments[sid].methodology_transparency in {"MINIMAL", "OPAQUE"} for sid in supporting_ids):
                next_actions.append("Obtain methodology appendix or original dataset where available.")

            if any(assessments[sid].reliability_state == "UNKNOWN" for sid in supporting_ids):
                next_actions.append("Resolve source identity/access before treating claim as fact-gate eligible.")

            if contradictions:
                next_actions.append("Adjudicate contradictions using primary records and independent evidence families.")

            if any(records[sid]["source"].retractions for sid in supporting_ids):
                next_actions.append("Propagate retraction/correction status to downstream reports and graphs.")

            if any(records[sid]["source"].confidential or records[sid]["source"].anonymous for sid in supporting_ids):
                next_actions.append("Use protected HUMINT workflow; do not attempt deanonymization.")

            for na in next_actions:
                all_next_actions.add(na)

            claim_assessments.append(
                ClaimAssessment(
                    claim_id=claim.claim_id,
                    statement=claim.statement,
                    supporting_source_ids=supporting_ids,
                    raw_source_count=raw_count,
                    unique_source_count=unique_count,
                    independent_family_count=family_count,
                    primary_evidence_path_count=primary_paths,
                    corroboration_state=corroboration,
                    credibility_state=credibility_state,
                    credibility_score=round(credibility_score, 3),
                    fact_gate_passed=fact_gate_passed,
                    average_source_reliability=round(avg_rel, 3),
                    max_access_quality=round(max_access, 3),
                    contradictions=contradictions,
                    limitations=sorted(set(limitations)),
                    next_actions=next_actions,
                )
            )

        # --------------------------------------------------------------
        # Global unknowns / gaps
        # --------------------------------------------------------------
        for sid, rec in records.items():
            src = rec["source"]
            ass = assessments[sid]

            if not src.publisher and not src.author and not src.creator:
                all_unknowns.add(f"Publisher/author unresolved for {ass.display_source_id}.")

            if not src.published_at and not src.retrieved_at and not src.created_at:
                all_unknowns.add(f"Publication/retrieval time unresolved for {ass.display_source_id}.")

            if not rec["upstream"] and not rec["downstream"] and src.source_type == "UNKNOWN":
                all_gaps.add(f"Source type/provenance unresolved for {ass.display_source_id}.")

            if ass.reliability_state == "UNKNOWN":
                all_gaps.add(f"Source reliability unknown for {ass.display_source_id}.")

        if not req.sources:
            all_unknowns.add("No sources supplied.")
            all_gaps.add("Ingest at least one preserved source artifact.")

        if not req.claims:
            all_gaps.add("No claims supplied; source provenance assessed but claim credibility not computed.")

        # --------------------------------------------------------------
        # Status
        # --------------------------------------------------------------
        if not req.sources:
            status = Status.INCONCLUSIVE.value
        elif claim_assessments and all(ca.fact_gate_passed for ca in claim_assessments):
            status = Status.SUCCEEDED.value
        elif claim_assessments and any(ca.fact_gate_passed for ca in claim_assessments):
            status = Status.PARTIAL.value
        else:
            status = Status.PARTIAL.value if req.sources else Status.INCONCLUSIVE.value

        limitations = [
            "Rule-based local SOURCEINT skeleton; not a substitute for full graph database, live archival retrieval, or human source adjudication.",
            "Does not fetch live URLs, bypass authentication, bypass paywalls, or contact sources.",
            "Does not deanonymize private, confidential, protected, or journalistic sources.",
            "Source reliability is multi-dimensional and claim-context dependent; not a single truth oracle.",
            "Duplicate/near-duplicate detection is heuristic and should be supplemented with archival and citation-chain review.",
        ]

        result = SourceIntResult(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            objective=req.objective,
            sources=[
                {
                    "source_id": sid,
                    "display_source_id": assessments[sid].display_source_id,
                    "url": normalize_url(rec["source"].url),
                    "title": rec["source"].title,
                    "publisher": assessments[sid].publisher,
                    "author": assessments[sid].author,
                    "source_type": rec["source"].source_type,
                    "published_at": rec["source"].published_at,
                    "retrieved_at": rec["source"].retrieved_at,
                    "version": rec["source"].version,
                    "archive_ref": rec["source"].archive_ref,
                    "content_hash": assessments[sid].content_hash,
                    "normalized_fingerprint": assessments[sid].normalized_fingerprint,
                    "excerpt": source_excerpt(rec["source"].text),
                    "confidential": rec["source"].confidential,
                    "anonymous": rec["source"].anonymous,
                }
                for sid, rec in records.items()
            ],
            assessments=[asdict(a) for a in assessments.values()],
            claims=[asdict(ca) for ca in claim_assessments],
            provenance_edges=[asdict(e) for e in edges],
            source_families=dict(source_families),
            exact_duplicates=exact_duplicates,
            near_duplicates=near_duplicates,
            citation_graph=[asdict(e) for e in edges if e.edge_type == "CITES"],
            unknowns=sorted(all_unknowns),
            knowledge_gaps=sorted(all_gaps),
            recommended_next_actions=sorted(all_next_actions),
            specialist_handoffs=sorted(handoffs),
            privacy_flags=sorted(privacy_flags),
            limitations=limitations,
            created_at=iso_now(),
        )

        self.memory.append(asdict(result))
        return result


# ======================================================================
# Demo
# ======================================================================

def demo() -> None:
    agent = SourceIntAgent(mode=Mode.LOCAL_ONLY)

    # Claim: Company C had a ransomware incident affecting corporate IT.
    claim = Claim(
        claim_id="CLM-001",
        statement="Company C suffered a ransomware incident affecting corporate IT.",
        event_time="2026-09-27T00:00:00Z",
        domains=["cybersecurity", "corporate_it"],
        contradictions=[],
        supporting_source_ids=[],
    )

    # Independent primary-ish vendor telemetry report.
    vendor = Source(
        source_id="VENDOR-REPORT",
        title="SecurityVendor Telemetry Brief",
        publisher="SecurityVendor",
        author="Threat Research Team",
        source_type="CTI_REPORT",
        text=(
            "Telemetry from customer sensors indicates Company C experienced a ransomware incident "
            "affecting corporate IT endpoints. Encryption events were observed on 2026-09-27."
        ),
        published_at="2026-09-28T12:00:00Z",
        retrieved_at="2026-10-01T00:00:00Z",
        methodology="Customer telemetry, endpoint detection events, hash preservation, sample of affected hosts.",
        access_basis="TECHNICAL_ACCESS",
        competence_domains=["cybersecurity", "malware", "telemetry"],
        limitations=["Vendor telemetry visibility is limited to customer footprint."],
        incentives=["commercial"],
        bias_context=["customer_visibility_bias"],
        claim_ids=["CLM-001"],
        metadata={
            "historical_accuracy": "generally_reliable",
            "evidence_disclosure": "representative",
            "native_record_available": True,
        },
    )

    # News A derives from vendor report.
    news_a = Source(
        source_id="NEWS-A",
        title="News A reports Company C ransomware",
        publisher="NewsOutletA",
        author="Reporter One",
        source_type="NEWS_SOURCE",
        text=(
            "According to SecurityVendor, Company C suffered a ransomware incident affecting corporate IT. "
            "The vendor said telemetry showed encryption events on September 27."
        ),
        published_at="2026-09-29T08:00:00Z",
        retrieved_at="2026-10-01T00:00:00Z",
        access_basis="SECONDHAND_ACCESS",
        competence_domains=["general_news"],
        cited_sources=["VENDOR-REPORT"],
        provenance_edges=[
            {"to": "VENDOR-REPORT", "type": "DERIVED_FROM", "confidence": 0.92, "evidence": "explicit attribution to vendor report"}
        ],
        claim_ids=["CLM-001"],
        metadata={"historical_accuracy": "mixed"},
    )

    # News B syndicated/copied from News A.
    news_b = Source(
        source_id="NEWS-B",
        title="News B syndicated copy",
        publisher="NewsOutletB",
        author="Wire Feed",
        source_type="NEWS_SOURCE",
        text=(
            "According to SecurityVendor, Company C suffered a ransomware incident affecting corporate IT. "
            "The vendor said telemetry showed encryption events on September 27."
        ),
        published_at="2026-09-29T09:00:00Z",
        retrieved_at="2026-10-01T00:00:00Z",
        access_basis="SECONDHAND_ACCESS",
        cited_sources=["NEWS-A", "VENDOR-REPORT"],
        provenance_edges=[
            {"to": "NEWS-A", "type": "SYNDICATES", "confidence": 0.96, "evidence": "wire syndication marker"}
        ],
        claim_ids=["CLM-001"],
        metadata={"historical_accuracy": "limited_history"},
    )

    # Independent official filing.
    filing = Source(
        source_id="OFFICIAL-FILING",
        title="Company C regulatory filing",
        publisher="Company C",
        author="Corporate Secretary",
        source_type="COMPANY_FILING",
        text=(
            "Company C disclosed a cybersecurity incident involving ransomware in corporate systems. "
            "The incident was identified on September 27 and affected certain internal IT environments."
        ),
        published_at="2026-09-30T00:00:00Z",
        retrieved_at="2026-10-01T00:00:00Z",
        access_basis="INSTITUTIONAL_ACCESS",
        competence_domains=["company_disclosure"],
        limitations=["Self-reporting incentive may affect framing."],
        incentives=["legal_disclosure", "reputational_management"],
        bias_context=["self_reporting"],
        claim_ids=["CLM-001"],
        metadata={
            "historical_accuracy": "well_calibrated",
            "digital_signature_valid": True,
            "native_record_available": True,
        },
    )

    req = SourceIntRequest(
        case_id="SRC-001",
        objective="Assess provenance, source families, independence, and claim credibility for Company C ransomware reports.",
        authorization={"authorized": True, "purpose": "defensive_source_intelligence"},
        scope={"industry": "technology", "time_range": "2026-09-27 to 2026-10-01"},
        sources=[vendor, news_a, news_b, filing],
        claims=[claim],
        time_range={"start": "2026-09-27", "end": "2026-10-01"},
    )

    result = agent.analyze(req)

    print("=== SOURCEINT RESULT SUMMARY ===")
    print("Case:", result.case_id)
    print("Status:", result.status)
    print("Policy:", result.policy_decision)
    print()

    print("Source families:")
    for fam, members in result.source_families.items():
        print(f"  {fam}: {members}")
    print()

    print("Exact duplicates:", result.exact_duplicates)
    print("Near duplicates:", result.near_duplicates)
    print()

    print("Claim assessments:")
    for ca in result.claims:
        print(json.dumps(ca, indent=2, default=str))
    print()

    print("Privacy flags:", result.privacy_flags)
    print("Specialist handoffs:", result.specialist_handoffs)
    print("Recommended next actions:")
    for action in result.recommended_next_actions:
        print("  -", action)
    print()

    # Blocked example: prohibited deanonymization request
    blocked_req = SourceIntRequest(
        case_id="SRC-002",
        objective="Deanonymize the confidential whistleblower source and expose their identity.",
        authorization={"authorized": False},
        sources=[],
        claims=[],
    )

    blocked = agent.analyze(blocked_req)
    print("=== BLOCKED EXAMPLE ===")
    print("Status:", blocked.status)
    print("Policy:", blocked.policy_decision)
    print("Limitations:", blocked.limitations)


if __name__ == "__main__":
    demo()