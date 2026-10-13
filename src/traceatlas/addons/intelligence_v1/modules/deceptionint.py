# TRACEATLAS — DECEPTIONINT AI EMPLOYEE
# Single-file defensive Python core for Deception & Manipulation Indicator Analysis.
#
# PRIMARY BOUNDARY:
# ANALYZE DECEPTION.
# DO NOT DESIGN, OPTIMIZE, OR EXECUTE DECEPTION.
#
# This code does NOT:
# - generate disinformation/propaganda
# - create fake personas or astroturfing campaigns
# - impersonate people/organizations
# - forge evidence or citations
# - optimize manipulation or microtargeting
# - use demeanor/voice stress as lie detection
# - attribute deception to real persons from weak signals

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse


TOOL_VERSION = "DECEPTIONINT-PY-0.1"


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


class ClaimState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class DeceptionState(str, Enum):
    NO_DECEPTION_EVIDENCE = "NO_DECEPTION_EVIDENCE"
    MISLEADING_PRESENTATION_CANDIDATE = "MISLEADING_PRESENTATION_CANDIDATE"
    DECEPTION_INDICATORS_PRESENT = "DECEPTION_INDICATORS_PRESENT"
    DECEPTION_HYPOTHESIS_SUPPORTED = "DECEPTION_HYPOTHESIS_SUPPORTED"
    DECEPTION_STRONGLY_SUPPORTED = "DECEPTION_STRONGLY_SUPPORTED"
    INTENT_UNRESOLVED = "INTENT_UNRESOLVED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class IntentState(str, Enum):
    NO_INTENT_EVIDENCE = "NO_INTENT_EVIDENCE"
    INTENT_POSSIBLE = "INTENT_POSSIBLE"
    INTENT_PROBABLE = "INTENT_PROBABLE"
    INTENT_SUPPORTED = "INTENT_SUPPORTED"
    INTENT_STRONGLY_SUPPORTED = "INTENT_STRONGLY_SUPPORTED"
    INTENT_UNRESOLVED = "INTENT_UNRESOLVED"


# ======================================================================
# Policy blocks
# ======================================================================

DECEPTION_BLOCK_PHRASES = [
    "create deception",
    "generate deception",
    "design deception",
    "optimize deception",
    "create disinformation",
    "generate disinformation",
    "create propaganda",
    "optimize propaganda",
    "fake persona",
    "create fake persona",
    "impersonate people",
    "impersonate organization",
    "forge evidence",
    "fabricate evidence",
    "fabricate documents",
    "false citations",
    "manufacture fake consensus",
    "astroturfing campaign",
    "design astroturfing",
    "political microtargeting",
    "microtarget voters",
    "psychological manipulation",
    "social engineering pretext",
    "phishing pretext",
    "scam pretext",
    "deceptive negotiation script",
    "coach lying",
    "teach how to lie",
    "evade deception detection",
    "harder-to-detect forgery",
    "fake whistleblower",
    "fake expert",
    "blackmail",
    "extortion",
    "manipulate vulnerable",
    "exploit emotional vulnerabilities",
    "counter-disinformation campaign",
    "fake grassroots",
]

NON_FACTUAL_CLAIM_TYPES = {
    "OPINION",
    "VALUE_JUDGMENT",
    "SATIRE",
    "FORECAST",
}


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


def norm_text(text: Any) -> str:
    text = unicodedata.normalize("NFKC", str(text or ""))
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def normalize_domain(value: Any) -> str:
    s = str(value or "").strip().lower().rstrip(".")
    if "://" in s:
        parsed = urlparse(s)
        s = parsed.netloc or parsed.path
    return s.split("/")[0].strip(".")


def contains_any(text: str, patterns: list[str]) -> bool:
    t = text.lower()
    return any(p in t for p in patterns)


# ======================================================================
# Data models
# ======================================================================

@dataclass
class Source:
    source_id: str
    source_type: str = "UNKNOWN"
    publisher: str = ""
    author_claim: str = ""
    organization: str = ""
    url: str = ""
    domain: str = ""
    publication_time: str = ""
    retrieved_at: str = ""
    upstream_source: str = ""
    reliability: float = 0.5
    bias: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    independence_group: str = ""
    pedigree: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    evidence_id: str
    statement: str
    source_id: str = ""
    upstream_source: str = ""
    reliability: float = 0.6
    independence_group: str = ""
    time: str = ""
    claim_ids: list[str] = field(default_factory=list)
    supports_claims: list[str] = field(default_factory=list)
    contradicts_claims: list[str] = field(default_factory=list)
    neutral_claims: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class Claim:
    claim_id: str
    statement: str
    claim_type: str = "UNKNOWN"
    source_id: str = ""
    speaker: str = ""
    published_at: str = ""
    event_time: str = ""
    location: str = ""
    certainty: str = ""
    verifiability: str = "UNKNOWN"
    evidence_ids: list[str] = field(default_factory=list)
    media_ids: list[str] = field(default_factory=list)
    statistical_ids: list[str] = field(default_factory=list)
    identity_ids: list[str] = field(default_factory=list)
    authority_ids: list[str] = field(default_factory=list)
    omitted_context: list[str] = field(default_factory=list)
    quote_truncated: bool = False
    quote_speaker_verified: bool = False
    satire_marker: bool = False
    repeated_after_correction: bool = False
    fabricated_supporting_material: bool = False
    concealed_source: bool = False
    known_false_identity: bool = False
    admission_or_regulatory_finding: bool = False
    limitations: list[str] = field(default_factory=list)


@dataclass
class MediaContext:
    media_id: str
    claim_id: str = ""
    media_type: str = "IMAGE"
    claimed_event_time: str = ""
    claimed_location: str = ""
    verified_event_time: str = ""
    verified_location: str = ""
    provenance_status: str = "UNKNOWN"
    manipulation_indicators: list[str] = field(default_factory=list)
    synthetic_indicators: list[str] = field(default_factory=list)
    archive_dates: list[str] = field(default_factory=list)
    original_publication_time: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class StatisticalClaim:
    stat_id: str
    claim_id: str = ""
    statement: str = ""
    numerator: Optional[float] = None
    denominator: Optional[float] = None
    baseline: Optional[float] = None
    period: str = ""
    population: str = ""
    percent_change: Optional[float] = None
    absolute_change: Optional[float] = None
    precision_claim: str = ""
    uncertainty: str = ""
    limitations: list[str] = field(default_factory=list)


@dataclass
class Citation:
    citing_source_id: str
    cited_source_id: str
    context: str = ""
    supports_claim: bool = False


@dataclass
class AccountActivity:
    account_id: str
    platform: str = ""
    handle: str = ""
    source_id: str = ""
    posted_at: str = ""
    content_hash: str = ""
    shared_links: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class IdentityClaim:
    identity_id: str
    claim_id: str = ""
    subject: str = ""
    claimed_name: str = ""
    claimed_role: str = ""
    claimed_organization: str = ""
    claimed_domain: str = ""
    claimed_email: str = ""
    official_domain: str = ""
    official_email: str = ""
    verification_status: str = "UNRESOLVED"
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class AuthorityClaim:
    authority_id: str
    claim_id: str = ""
    claimed_authority: str = ""
    claimed_credential: str = ""
    verification_status: str = "UNRESOLVED"
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class DeceptionIndicator:
    indicator_id: str
    indicator_type: str
    claim_id: str = ""
    source_id: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    observed_behavior: str = ""
    alternative_explanations: list[str] = field(default_factory=list)
    severity: str = "MODERATE"
    confidence: float = 0.5
    intent_relevance: str = "LOW"
    status: str = "OBSERVED"


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    support: list[str] = field(default_factory=list)
    opposition: list[str] = field(default_factory=list)
    status: str = "CANDIDATE"


@dataclass
class DeceptionRequest:
    case_id: str
    objective: str
    authorization: dict[str, Any] = field(default_factory=dict)
    claims: list[Claim] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    media_context: list[MediaContext] = field(default_factory=list)
    statistical_claims: list[StatisticalClaim] = field(default_factory=list)
    citations: list[Citation] = field(default_factory=list)
    account_activities: list[AccountActivity] = field(default_factory=list)
    identity_claims: list[IdentityClaim] = field(default_factory=list)
    authority_claims: list[AuthorityClaim] = field(default_factory=list)
    known_facts: list[str] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)
    time_range: dict[str, str] = field(default_factory=dict)


@dataclass
class ClaimAssessment:
    claim_id: str
    statement: str
    claim_type: str
    verifiability: str
    source_id: str
    independent_family_count: int
    claim_state: str
    deception_status: str
    intent_state: str
    indicators: list[dict[str, Any]]
    benign_explanations: list[str]
    hypotheses: list[dict[str, Any]]
    limitations: list[str]


@dataclass
class DeceptionResult:
    case_id: str
    status: str
    policy_decision: str
    objective: str
    summary: str
    claims: list[dict[str, Any]]
    indicators: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    media_context: list[dict[str, Any]]
    statistical_claims: list[dict[str, Any]]
    citation_graph: list[dict[str, Any]]
    coordination_indicators: list[dict[str, Any]]
    source_independence: dict[str, Any]
    contradictions: list[dict[str, Any]]
    unknowns: list[str]
    knowledge_gaps: list[str]
    recommended_next_actions: list[str]
    specialist_handoffs: list[str]
    privacy_flags: list[str]
    human_review_flags: list[str]
    limitations: list[str]
    replay_manifest: dict[str, Any]
    created_at: str


# ======================================================================
# DECEPTIONINT agent
# ======================================================================

class DeceptionIntAgent:
    """
    Defensive DECEPTIONINT core.

    Analyzes supplied claims, sources, evidence, media context, statistics,
    citations, identity/authority claims, and account activity patterns.

    It separates:
    - claim status
    - deception indicators
    - intent evidence
    - attribution

    It does not create deception or infer intent from falsehood alone.
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    def policy_check(self, req: DeceptionRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        if req.authorization.get("authorized") is not True:
            return (
                PolicyDecision.BLOCK,
                "BLOCKED_AUTHORIZATION",
                "DECEPTIONINT requires explicit authorized defensive scope.",
            )

        for phrase in DECEPTION_BLOCK_PHRASES:
            if phrase in blob:
                return (
                    PolicyDecision.BLOCK,
                    "BLOCKED_POLICY",
                    f"Prohibited deception-design or manipulation action requested: {phrase}",
                )

        return PolicyDecision.ALLOW, "", ""

    def blocked_result(self, req: DeceptionRequest, code: str, reason: str) -> DeceptionResult:
        return DeceptionResult(
            case_id=req.case_id,
            status=code,
            policy_decision=PolicyDecision.BLOCK.value,
            objective=req.objective,
            summary=f"POLICY_BLOCKED: {reason}",
            claims=[],
            indicators=[],
            sources=[],
            evidence=[],
            media_context=[],
            statistical_claims=[],
            citation_graph=[],
            coordination_indicators=[],
            source_independence={},
            contradictions=[],
            unknowns=["Request outside defensive DECEPTIONINT boundary."],
            knowledge_gaps=["No deception analysis performed."],
            recommended_next_actions=[
                "Reframe request as defensive claim verification, provenance analysis, "
                "false-context detection, or benign-explanation testing."
            ],
            specialist_handoffs=[],
            privacy_flags=[reason],
            human_review_flags=[],
            limitations=[reason],
            replay_manifest={},
            created_at=now_iso(),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _independence_key(self, source_id: str, source_map: dict[str, Source], fallback: str = "") -> str:
        src = source_map.get(source_id)
        if src:
            return src.upstream_source or src.independence_group or src.source_id
        return fallback or source_id or "UNKNOWN"

    def _classify_claim(self, claim: Claim) -> str:
        if claim.claim_type and claim.claim_type != "UNKNOWN":
            return claim.claim_type.upper()

        s = claim.statement.lower()

        if contains_any(s, ["i am", "represents", "official", "agency", "department", "doctor", "professor"]):
            if contains_any(s, ["doctor", "professor", "expert", "certified", "credential"]):
                return "AUTHORITY"
            return "IDENTITY"

        if contains_any(s, ["%", "percent", "increase", "decrease", "risk", "average", "median", "sample"]):
            return "STATISTICAL"

        if contains_any(s, ["today", "yesterday", "2026", "2025", "before", "after", "during"]):
            return "TEMPORAL"

        if contains_any(s, ["located", "city", "country", "region", "address", "map", "place"]):
            return "GEOGRAPHIC"

        if contains_any(s, ["source", "citation", "study", "report", "document", "provenance"]):
            return "PROVENANCE"

        if contains_any(s, ["because", "caused", "led to", "resulted in"]):
            return "CAUSAL"

        if contains_any(s, ["believe", "opinion", "should", "best", "worst"]):
            return "OPINION"

        if contains_any(s, ["will", "forecast", "predict", "expect"]):
            return "FORECAST"

        return "FACTUAL"

    def _verifiability(self, claim: Claim, claim_type: str) -> str:
        if claim_type in NON_FACTUAL_CLAIM_TYPES:
            return "NON_FACTUAL"
        if claim.evidence_ids:
            return "PARTIALLY_VERIFIABLE"
        if claim.source_id:
            return "INDIRECTLY_VERIFIABLE"
        return "CURRENTLY_UNVERIFIABLE"

    def _claim_source_keys(self, claim: Claim, evidence_map: dict[str, Evidence], source_map: dict[str, Source]) -> set[str]:
        keys: set[str] = set()

        if claim.source_id:
            keys.add(self._independence_key(claim.source_id, source_map))

        for eid in claim.evidence_ids:
            ev = evidence_map.get(eid)
            if not ev:
                continue
            keys.add(self._independence_key(ev.source_id, source_map, ev.independence_group or eid))

        return keys or {"UNKNOWN"}

    def _assess_claim_status(
        self,
        claim: Claim,
        evidence_map: dict[str, Evidence],
        source_map: dict[str, Source],
    ) -> tuple[str, list[Evidence], list[Evidence], int]:
        linked = [evidence_map[eid] for eid in claim.evidence_ids if eid in evidence_map]

        supporting = [
            ev for ev in linked
            if claim.claim_id in ev.supports_claims
            or (claim.claim_id not in ev.contradicts_claims and claim.claim_id not in ev.neutral_claims)
        ]
        contradicting = [ev for ev in linked if claim.claim_id in ev.contradicts_claims]

        supp_families = {
            self._independence_key(ev.source_id, source_map, ev.independence_group or ev.evidence_id)
            for ev in supporting
        }
        contra_families = {
            self._independence_key(ev.source_id, source_map, ev.independence_group or ev.evidence_id)
            for ev in contradicting
        }

        independent_family_count = len(supp_families | contra_families)

        if contradicting:
            avg_contra_rel = mean([ev.reliability for ev in contradicting], 0.0)
            if not supporting and avg_contra_rel >= 0.70:
                state = ClaimState.UNSUPPORTED.value
            else:
                state = ClaimState.DISPUTED.value
        elif len(supp_families) >= 2:
            state = ClaimState.SUPPORTED.value
        elif len(supp_families) == 1:
            state = ClaimState.PARTIALLY_SUPPORTED.value
        elif claim.claim_type.upper() in NON_FACTUAL_CLAIM_TYPES:
            state = ClaimState.INCONCLUSIVE.value
        else:
            state = ClaimState.INCONCLUSIVE.value

        return state, supporting, contradicting, independent_family_count

    def _add_indicator(
        self,
        indicators: list[DeceptionIndicator],
        indicator_type: str,
        claim_id: str = "",
        source_id: str = "",
        evidence_ids: Optional[list[str]] = None,
        observed_behavior: str = "",
        alternative_explanations: Optional[list[str]] = None,
        severity: str = "MODERATE",
        confidence: float = 0.5,
        intent_relevance: str = "LOW",
        status: str = "OBSERVED",
    ) -> None:
        indicators.append(
            DeceptionIndicator(
                indicator_id=f"IND-{sha256_12(claim_id + indicator_type + observed_behavior)}",
                indicator_type=indicator_type,
                claim_id=claim_id,
                source_id=source_id,
                evidence_ids=evidence_ids or [],
                observed_behavior=observed_behavior,
                alternative_explanations=alternative_explanations or [
                    "honest_error",
                    "outdated_information",
                    "satire_or_parody",
                    "translation_or_summary_loss",
                    "upstream_source_error",
                    "legitimate_coordination",
                    "missing_context",
                ],
                severity=severity,
                confidence=round(clamp(confidence), 3),
                intent_relevance=intent_relevance,
                status=status,
            )
        )

    # ------------------------------------------------------------------
    # Context analyses
    # ------------------------------------------------------------------

    def _analyze_media(
        self,
        claim: Claim,
        media_map: dict[str, MediaContext],
        indicators: list[DeceptionIndicator],
    ) -> None:
        for mid in claim.media_ids:
            med = media_map.get(mid)
            if not med:
                continue

            if med.manipulation_indicators:
                severity = "HIGH" if any("FABRICAT" in x.upper() or "SPLICE" in x.upper() for x in med.manipulation_indicators) else "MODERATE"
                self._add_indicator(
                    indicators,
                    "EVIDENCE_ALTERATION_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    observed_behavior=f"Media {med.media_id} has manipulation indicators: {med.manipulation_indicators}",
                    severity=severity,
                    confidence=0.65,
                    intent_relevance="MODERATE" if severity == "HIGH" else "LOW",
                )

            if med.synthetic_indicators:
                self._add_indicator(
                    indicators,
                    "SYNTHETIC_MEDIA_INDICATORS",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    observed_behavior=f"Media {med.media_id} has synthetic-media indicators: {med.synthetic_indicators}",
                    severity="MODERATE",
                    confidence=0.55,
                    intent_relevance="LOW",
                    status="INCONCLUSIVE",
                )

            claimed_dt = parse_dt(med.claimed_event_time or claim.event_time)
            verified_dt = parse_dt(med.verified_event_time or med.original_publication_time)
            archive_dts = [parse_dt(d) for d in med.archive_dates if parse_dt(d)]
            earliest_archive = min(archive_dts) if archive_dts else None

            earlier_dt = None
            if verified_dt and claimed_dt and verified_dt < claimed_dt:
                earlier_dt = verified_dt
            if earliest_archive and claimed_dt and earliest_archive < claimed_dt:
                if earlier_dt is None or earliest_archive < earlier_dt:
                    earlier_dt = earliest_archive

            if claimed_dt and earlier_dt and (claimed_dt - earlier_dt) > timedelta(days=1):
                self._add_indicator(
                    indicators,
                    "TEMPORAL_DECEPTION_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    evidence_ids=[med.media_id],
                    observed_behavior=(
                        f"Claimed event time {claimed_dt.date()} is inconsistent with earlier known media date "
                        f"{earlier_dt.date()}."
                    ),
                    alternative_explanations=[
                        "outdated_information",
                        "reposted_without_context",
                        "platform_timestamp_error",
                        "honest_error",
                    ],
                    severity="MATERIAL",
                    confidence=0.75,
                    intent_relevance="LOW",
                )

            claimed_loc = norm_text(med.claimed_location or claim.location)
            verified_loc = norm_text(med.verified_location)

            if claimed_loc and verified_loc and claimed_loc != verified_loc:
                self._add_indicator(
                    indicators,
                    "GEOGRAPHIC_DECEPTION_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    evidence_ids=[med.media_id],
                    observed_behavior=(
                        f"Claimed location '{med.claimed_location or claim.location}' differs from verified location "
                        f"'{med.verified_location}'."
                    ),
                    alternative_explanations=[
                        "similar_locations",
                        "map_label_error",
                        "honest_error",
                        "upstream_miscaptioning",
                    ],
                    severity="MATERIAL",
                    confidence=0.70,
                    intent_relevance="LOW",
                )

            if med.provenance_status.upper() == "AUTHENTIC_MEDIA":
                claim.limitations.append(
                    f"Media {med.media_id} may be authentic while contextual claims are false."
                )

    def _analyze_statistics(
        self,
        claim: Claim,
        stat_map: dict[str, StatisticalClaim],
        indicators: list[DeceptionIndicator],
    ) -> None:
        for sid in claim.statistical_ids:
            st = stat_map.get(sid)
            if not st:
                continue

            text = (st.statement or claim.statement).lower()

            if st.denominator is None and contains_any(text, ["%", "percent", "increase", "decrease", "risk", "rate"]):
                self._add_indicator(
                    indicators,
                    "STATISTICAL_MISREPRESENTATION_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    evidence_ids=[st.stat_id],
                    observed_behavior="Percentage or relative change presented without denominator/baseline.",
                    alternative_explanations=[
                        "summary_omission",
                        "honest_error",
                        "incomplete_data",
                        "different_population",
                    ],
                    severity="MODERATE",
                    confidence=0.55,
                    intent_relevance="LOW",
                )

            if st.precision_claim:
                decimals = len(st.precision_claim.split(".")[-1]) if "." in st.precision_claim else 0
                if decimals > 2 and not st.uncertainty:
                    self._add_indicator(
                        indicators,
                        "FALSE_PRECISION_CANDIDATE",
                        claim_id=claim.claim_id,
                        source_id=claim.source_id,
                        evidence_ids=[st.stat_id],
                        observed_behavior=f"High-precision value '{st.precision_claim}' lacks uncertainty disclosure.",
                        severity="LOW",
                        confidence=0.50,
                        intent_relevance="LOW",
                    )

            if st.numerator is not None and st.denominator not in (None, 0):
                pct = 100.0 * float(st.numerator) / float(st.denominator)
                claim.limitations.append(f"Deterministic percentage from supplied numerator/denominator: {pct:.2f}%.")

    def _analyze_identity_authority(
        self,
        claim: Claim,
        identity_map: dict[str, IdentityClaim],
        authority_map: dict[str, AuthorityClaim],
        indicators: list[DeceptionIndicator],
    ) -> None:
        for iid in claim.identity_ids:
            idc = identity_map.get(iid)
            if not idc:
                continue

            status = idc.verification_status.upper()

            if status == "IMPERSONATION_CANDIDATE":
                self._add_indicator(
                    indicators,
                    "IMPERSONATION_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    evidence_ids=idc.evidence_ids,
                    observed_behavior=(
                        f"Identity claim for '{idc.claimed_organization or idc.claimed_name}' is flagged as "
                        "impersonation candidate by supplied verification status."
                    ),
                    alternative_explanations=[
                        "rebrand",
                        "role_change",
                        "subsidiary_domain",
                        "partner_communication",
                        "honest_error",
                    ],
                    severity="HIGH",
                    confidence=0.70,
                    intent_relevance="MODERATE",
                )

            elif status == "UNRESOLVED":
                self._add_indicator(
                    indicators,
                    "IDENTITY_UNRESOLVED",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    observed_behavior="Claimed identity is not resolved by supplied evidence.",
                    severity="LOW",
                    confidence=0.40,
                    intent_relevance="NONE",
                    status="INCONCLUSIVE",
                )

            official_domain = normalize_domain(idc.official_domain)
            claimed_domain = normalize_domain(idc.claimed_domain)

            if official_domain and claimed_domain and official_domain != claimed_domain:
                self._add_indicator(
                    indicators,
                    "FALSE_AFFILIATION_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    observed_behavior=(
                        f"Claimed domain '{claimed_domain}' differs from supplied official domain '{official_domain}'."
                    ),
                    alternative_explanations=[
                        "regional_domain",
                        "campaign_domain",
                        "vendor_domain",
                        "historical_domain",
                        "honest_error",
                    ],
                    severity="MATERIAL",
                    confidence=0.65,
                    intent_relevance="LOW",
                )

        for aid in claim.authority_ids:
            auth = authority_map.get(aid)
            if not auth:
                continue

            status = auth.verification_status.upper()
            if status in {"UNVERIFIED", "MISREPRESENTED"}:
                self._add_indicator(
                    indicators,
                    "FALSE_AUTHORITY_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    evidence_ids=auth.evidence_ids,
                    observed_behavior=(
                        f"Authority/credential claim '{auth.claimed_authority or auth.claimed_credential}' is "
                        f"{status}."
                    ),
                    alternative_explanations=[
                        "credential_outdated",
                        "verification_gap",
                        "different_role",
                        "honest_error",
                    ],
                    severity="MATERIAL",
                    confidence=0.60,
                    intent_relevance="LOW",
                )

    def _analyze_language_pressure(
        self,
        claim: Claim,
        indicators: list[DeceptionIndicator],
    ) -> None:
        s = claim.statement.lower()

        if contains_any(s, ["everyone", "thousands", "millions", "all experts", "all scientists", "everyone agrees"]):
            self._add_indicator(
                indicators,
                "UNSUPPORTED_SOCIAL_PROOF",
                claim_id=claim.claim_id,
                source_id=claim.source_id,
                observed_behavior="Claim uses broad social-proof language without supplied independent support.",
                alternative_explanations=[
                    "rhetorical_emphasis",
                    "accurate_but_unsourced_here",
                    "honest_error",
                ],
                severity="MODERATE",
                confidence=0.45,
                intent_relevance="LOW",
            )

        if contains_any(s, ["act now", "urgent", "immediate", "do not tell", "password", "verify account"]):
            self._add_indicator(
                indicators,
                "URGENCY_OR_SECRECY_SIGNAL",
                claim_id=claim.claim_id,
                source_id=claim.source_id,
                observed_behavior="Communication contains urgency, secrecy, or credential-related pressure language.",
                alternative_explanations=[
                    "legitimate_alert",
                    "marketing_copy",
                    "emergency_communication",
                    "honest_error",
                ],
                severity="MODERATE",
                confidence=0.45,
                intent_relevance="LOW",
            )

        if claim.quote_truncated and not claim.quote_speaker_verified:
            self._add_indicator(
                indicators,
                "QUOTE_CONTEXT_MISSING",
                claim_id=claim.claim_id,
                source_id=claim.source_id,
                observed_behavior="Quote appears truncated and speaker/context are not verified.",
                alternative_explanations=[
                    "editing_for_length",
                    "honest_error",
                    "translation_issue",
                ],
                severity="MODERATE",
                confidence=0.50,
                intent_relevance="LOW",
            )

        if claim.omitted_context:
            self._add_indicator(
                indicators,
                "SELECTIVE_OMISSION_CANDIDATE",
                claim_id=claim.claim_id,
                source_id=claim.source_id,
                observed_behavior=f"Material context may be omitted: {claim.omitted_context}",
                alternative_explanations=[
                    "space_limit",
                    "editorial_focus",
                    "lack_of_knowledge",
                    "honest_error",
                ],
                severity="MODERATE",
                confidence=0.45,
                intent_relevance="LOW",
            )

    # ------------------------------------------------------------------
    # Global analyses
    # ------------------------------------------------------------------

    def _analyze_citation_laundering(
        self,
        req: DeceptionRequest,
        source_map: dict[str, Source],
        claim_map: dict[str, Claim],
        indicators: list[DeceptionIndicator],
    ) -> None:
        for cit in req.citations:
            citing = source_map.get(cit.citing_source_id)
            cited = source_map.get(cit.cited_source_id)
            if not citing or not cited:
                continue

            if cited.reliability < 0.45 and citing.reliability > 0.65 and not cit.supports_claim:
                attached_claim_ids = [
                    cid for cid, c in claim_map.items()
                    if c.source_id == cit.citing_source_id
                    or cit.citing_source_id in [
                        (self._evidence_map.get(eid).source_id if self._evidence_map.get(eid) else "")
                        for eid in c.evidence_ids
                    ]
                ]

                behavior = (
                    f"Source '{citing.source_id}' (reliability {citing.reliability:.2f}) cites weaker source "
                    f"'{cited.source_id}' (reliability {cited.reliability:.2f}) without clear independent support."
                )

                if attached_claim_ids:
                    for cid in attached_claim_ids:
                        self._add_indicator(
                            indicators,
                            "CITATION_LAUNDERING_CANDIDATE",
                            claim_id=cid,
                            source_id=cit.citing_source_id,
                            observed_behavior=behavior,
                            alternative_explanations=[
                                "legitimate_background_reference",
                                "method_reference",
                                "critique",
                                "honest_error",
                            ],
                            severity="MODERATE",
                            confidence=0.55,
                            intent_relevance="LOW",
                        )
                else:
                    self._add_indicator(
                        indicators,
                        "CITATION_LAUNDERING_CANDIDATE",
                        claim_id="GLOBAL",
                        source_id=cit.citing_source_id,
                        observed_behavior=behavior,
                        severity="MODERATE",
                        confidence=0.55,
                        intent_relevance="LOW",
                    )

    def _analyze_coordination(
        self,
        req: DeceptionRequest,
        claim_map: dict[str, Claim],
        indicators: list[DeceptionIndicator],
        coordination_rows: list[dict[str, Any]],
    ) -> None:
        by_hash: dict[str, list[AccountActivity]] = defaultdict(list)
        by_links: dict[frozenset[str], list[AccountActivity]] = defaultdict(list)

        for act in req.account_activities:
            if act.content_hash:
                by_hash[act.content_hash].append(act)
            if act.shared_links:
                by_links[frozenset(normalize_domain(x) for x in act.shared_links)].append(act)

        def maybe_attach(acts: list[AccountActivity], basis: str) -> None:
            if len(acts) < 2:
                return

            times = [parse_dt(a.posted_at) for a in acts]
            known_times = [t for t in times if t]
            tight_window = False
            if len(known_times) == len(acts) and known_times:
                tight_window = (max(known_times) - min(known_times)) <= timedelta(hours=48)

            source_ids = {a.source_id for a in acts if a.source_id}
            attached_claim_ids = [
                cid for cid, c in claim_map.items()
                if c.source_id in source_ids
            ]

            behavior = (
                f"{len(acts)} accounts show similar activity by {basis}. "
                "This is a coordination candidate, not proof of deception."
            )

            row = {
                "basis": basis,
                "account_ids": [a.account_id for a in acts],
                "source_ids": sorted(source_ids),
                "tight_time_window": tight_window,
                "note": "Legitimate advocacy/marketing/emergency coordination is possible.",
            }
            coordination_rows.append(row)

            conf = 0.55 if tight_window else 0.40
            sev = "MODERATE" if tight_window else "LOW"

            if attached_claim_ids:
                for cid in attached_claim_ids:
                    self._add_indicator(
                        indicators,
                        "COORDINATED_REPOST_CANDIDATE",
                        claim_id=cid,
                        source_id=acts[0].source_id,
                        observed_behavior=behavior,
                        alternative_explanations=[
                            "legitimate_campaign",
                            "shared_press_release",
                            "news_syndication",
                            "community repost",
                        ],
                        severity=sev,
                        confidence=conf,
                        intent_relevance="LOW",
                    )
            else:
                self._add_indicator(
                    indicators,
                    "COORDINATED_REPOST_CANDIDATE",
                    claim_id="GLOBAL",
                    observed_behavior=behavior,
                    severity=sev,
                    confidence=conf,
                    intent_relevance="LOW",
                )

        for acts in by_hash.values():
            maybe_attach(acts, "identical content hash")

        for acts in by_links.values():
            maybe_attach(acts, "shared links")

    # ------------------------------------------------------------------
    # Intent / deception status / hypotheses
    # ------------------------------------------------------------------

    def _intent_state(self, claim: Claim, indicators: list[DeceptionIndicator]) -> tuple[str, list[str]]:
        evidence_lines: list[str] = []
        score = 0

        if claim.admission_or_regulatory_finding:
            return IntentState.INTENT_STRONGLY_SUPPORTED.value, ["Admission or regulatory finding supplied."]

        if claim.fabricated_supporting_material:
            score += 2
            evidence_lines.append("Fabricated supporting material indicated by supplied case data.")

        if claim.known_false_identity:
            score += 2
            evidence_lines.append("Known false identity indicated by supplied case data.")

        if claim.concealed_source:
            score += 1
            evidence_lines.append("Source concealment indicated by supplied case data.")

        if claim.repeated_after_correction:
            score += 1
            evidence_lines.append("Claim repeated after correction evidence, if correction was received/accepted.")

        for ind in indicators:
            if ind.indicator_type == "IMPERSONATION_CANDIDATE":
                score += 1
                evidence_lines.append("Impersonation candidate indicator present.")
            if ind.indicator_type == "EVIDENCE_ALTERATION_CANDIDATE" and ind.severity == "HIGH":
                score += 1
                evidence_lines.append("High-severity evidence alteration indicator present.")

        if score == 0:
            return IntentState.NO_INTENT_EVIDENCE.value, ["No supplied intent evidence beyond falsehood/context indicators."]
        if score == 1:
            return IntentState.INTENT_POSSIBLE.value, evidence_lines
        if score in (2, 3):
            return IntentState.INTENT_PROBABLE.value, evidence_lines
        return IntentState.INTENT_SUPPORTED.value, evidence_lines

    def _deception_status(
        self,
        claim_state: str,
        indicators: list[DeceptionIndicator],
        intent_state: str,
    ) -> str:
        if not indicators:
            return DeceptionState.NO_DECEPTION_EVIDENCE.value

        material = [i for i in indicators if i.severity in {"MATERIAL", "HIGH", "CRITICAL"}]
        strong_types = {
            "EVIDENCE_ALTERATION_CANDIDATE",
            "IMPERSONATION_CANDIDATE",
            "FALSE_AUTHORITY_CANDIDATE",
            "CITATION_LAUNDERING_CANDIDATE",
        }
        strong = [i for i in indicators if i.indicator_type in strong_types and i.severity in {"MATERIAL", "HIGH", "CRITICAL"}]

        if intent_state in {IntentState.INTENT_STRONGLY_SUPPORTED.value}:
            return DeceptionState.DECEPTION_STRONGLY_SUPPORTED.value

        if strong and claim_state in {ClaimState.DISPUTED.value, ClaimState.UNSUPPORTED.value}:
            return DeceptionState.DECEPTION_HYPOTHESIS_SUPPORTED.value

        if material and claim_state != ClaimState.SUPPORTED.value:
            return DeceptionState.MISLEADING_PRESENTATION_CANDIDATE.value

        if material or strong:
            return DeceptionState.DECEPTION_INDICATORS_PRESENT.value

        if claim_state == ClaimState.DISPUTED.value:
            return DeceptionState.DISPUTED.value

        return DeceptionState.INCONCLUSIVE.value

    def _hypotheses(
        self,
        claim: Claim,
        claim_state: str,
        indicators: list[DeceptionIndicator],
        intent_state: str,
    ) -> list[Hypothesis]:
        types = {i.indicator_type for i in indicators}
        material_count = sum(1 for i in indicators if i.severity in {"MATERIAL", "HIGH", "CRITICAL"})

        hyps: list[Hypothesis] = []

        hyps.append(
            Hypothesis(
                hypothesis_id="H1_DELIBERATE_DECEPTION",
                statement="Publisher knowingly or strategically misrepresented the claim.",
                support=[
                    "Material deception-context indicators present." if material_count else "No strong indicator burden.",
                    f"Intent state: {intent_state}.",
                ],
                opposition=[
                    "Falsehood alone does not establish intent.",
                    "Benign explanations remain available.",
                ],
                status=(
                    "SUPPORTED"
                    if intent_state in {IntentState.INTENT_SUPPORTED.value, IntentState.INTENT_STRONGLY_SUPPORTED.value}
                    else "CANDIDATE"
                    if material_count >= 2
                    else "WEAK"
                ),
            )
        )

        hyps.append(
            Hypothesis(
                hypothesis_id="H2_HONEST_ERROR",
                statement="Claim reflects mistake, outdated information, or incomplete understanding.",
                support=["Always plausible absent strong intent evidence."],
                opposition=["Repeated correction-resistant claims or fabricated material would weaken this."],
                status="ACTIVE",
            )
        )

        hyps.append(
            Hypothesis(
                hypothesis_id="H3_OUTDATED_OR_RECYCLED",
                statement="Authentic content was reused with false temporal/geographic context.",
                support=["Temporal/geographic context indicators present."]
                if {"TEMPORAL_DECEPTION_CANDIDATE", "GEOGRAPHIC_DECEPTION_CANDIDATE"} & types
                else ["No explicit recycled-context indicator."],
                opposition=["Could be current content with metadata/archive error."],
                status="CANDIDATE"
                if {"TEMPORAL_DECEPTION_CANDIDATE", "GEOGRAPHIC_DECEPTION_CANDIDATE"} & types
                else "NOT_SUPPORTED_BY_CURRENT_EVIDENCE",
            )
        )

        hyps.append(
            Hypothesis(
                hypothesis_id="H4_SATIRE_OR_PARODY",
                statement="Content is satire/parody misunderstood as factual.",
                support=["Satire marker present."] if claim.satire_marker else ["No explicit satire marker."],
                opposition=["Satire presented as factual may still mislead."],
                status="CANDIDATE" if claim.satire_marker else "LOW",
            )
        )

        hyps.append(
            Hypothesis(
                hypothesis_id="H5_UPSTREAM_ERROR",
                statement="Publisher copied an incorrect upstream source.",
                support=["Citation/source laundering or dependency indicators present."]
                if {"CITATION_LAUNDERING_CANDIDATE", "SOURCE_DEPENDENCY_CANDIDATE"} & types
                else ["No explicit upstream-dependency indicator."],
                opposition=["Publisher may have originated the false claim."],
                status="CANDIDATE"
                if {"CITATION_LAUNDERING_CANDIDATE", "SOURCE_DEPENDENCY_CANDIDATE"} & types
                else "UNKNOWN",
            )
        )

        hyps.append(
            Hypothesis(
                hypothesis_id="H6_LEGITIMATE_COORDINATION",
                statement="Similar accounts reflect legitimate advocacy, marketing, emergency comms, or syndication.",
                support=["Coordination candidate present."]
                if "COORDINATED_REPOST_CANDIDATE" in types
                else ["No coordination indicator."],
                opposition=["Coordination alone is not deception."],
                status="CANDIDATE" if "COORDINATED_REPOST_CANDIDATE" in types else "NOT_APPLICABLE",
            )
        )

        return hyps

    def _next_actions_for_claim(self, claim: Claim, indicators: list[DeceptionIndicator]) -> list[str]:
        types = {i.indicator_type for i in indicators}
        actions: list[str] = []

        if claim.source_id:
            actions.append(f"Retrieve original publication for claim {claim.claim_id} from source {claim.source_id}.")

        if "TEMPORAL_DECEPTION_CANDIDATE" in types:
            actions.append("Retrieve archive snapshots and earliest known publication date for the media/content.")

        if "GEOGRAPHIC_DECEPTION_CANDIDATE" in types:
            actions.append("Hand off visual geolocation to GEOINT/IMINT/VIDINT; do not infer location from caption alone.")

        if "STATISTICAL_MISREPRESENTATION_CANDIDATE" in types:
            actions.append("Obtain numerator, denominator, baseline, population, and time period for the statistical claim.")

        if "CITATION_LAUNDERING_CANDIDATE" in types:
            actions.append("Trace citation chain to primary source and verify claim-to-citation alignment.")

        if "IMPERSONATION_CANDIDATE" in types or "FALSE_AFFILIATION_CANDIDATE" in types:
            actions.append("Verify claimed identity/organization through official public channels only; do not contact suspected impersonator deceptively.")

        if "SYNTHETIC_MEDIA_INDICATORS" in types:
            actions.append("Hand off media authenticity/provenance to IMINT/VIDINT/AUDINT; one detector signal is not conclusive.")

        if "COORDINATED_REPOST_CANDIDATE" in types:
            actions.append("Check whether coordination reflects syndication, shared press release, legitimate campaign, or platform artifact.")

        if claim.quote_truncated:
            actions.append("Retrieve full quote context and original recording/transcript.")

        if claim.omitted_context:
            actions.append("Obtain full document/thread/page context before interpreting omission.")

        actions.append("Preserve corrections/retractions; do not treat correction alone as admission of deception.")
        actions.append("Do not contact, bait, impersonate, or manipulate any subject.")

        return sorted(set(actions))

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------

    _evidence_map: dict[str, Evidence] = {}

    def analyze(self, req: DeceptionRequest) -> DeceptionResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self.blocked_result(req, code, reason)
            self.memory.append(asdict(result))
            return result

        source_map = {s.source_id: s for s in req.sources}
        evidence_map = {e.evidence_id: e for e in req.evidence}
        media_map = {m.media_id: m for m in req.media_context}
        stat_map = {s.stat_id: s for s in req.statistical_claims}
        identity_map = {i.identity_id: i for i in req.identity_claims}
        authority_map = {a.authority_id: a for a in req.authority_claims}
        claim_map = {c.claim_id: c for c in req.claims}

        self._evidence_map = evidence_map

        all_indicators: list[DeceptionIndicator] = []
        coordination_rows: list[dict[str, Any]] = []
        claim_rows: list[ClaimAssessment] = []
        contradictions: list[dict[str, Any]] = []
        unknowns: set[str] = set()
        gaps: set[str] = set()
        next_actions: set[str] = set()
        handoffs: set[str] = set()
        privacy_flags: set[str] = {
            "No real-person attribution from username, writing style, face, voice, IP, or one payment.",
            "No sensitive-trait inference from appearance or weak behavioral cues.",
            "No demeanor, blink rate, posture, voice stress, or microexpression lie detection.",
            "Private identities and communications should be minimized or pseudonymized.",
        }
        human_review_flags: set[str] = set()

        # Per-claim analysis.
        for claim in req.claims:
            claim_type = self._classify_claim(claim)
            claim.verifiability = self._verifiability(claim, claim_type)

            claim_state, supporting, contradicting, indep_family_count = self._assess_claim_status(
                claim, evidence_map, source_map
            )

            indicators: list[DeceptionIndicator] = []

            self._analyze_media(claim, media_map, indicators)
            self._analyze_statistics(claim, stat_map, indicators)
            self._analyze_identity_authority(claim, identity_map, authority_map, indicators)
            self._analyze_language_pressure(claim, indicators)

            # Source dependency / false consensus caution.
            source_keys = self._claim_source_keys(claim, evidence_map, source_map)
            if len(source_keys) == 1 and (claim.source_id or claim.evidence_ids):
                self._add_indicator(
                    indicators,
                    "SOURCE_DEPENDENCY_CANDIDATE",
                    claim_id=claim.claim_id,
                    source_id=claim.source_id,
                    observed_behavior="Apparent multiple references may derive from one upstream source family.",
                    alternative_explanations=[
                        "single_authoritative_primary_source",
                        "limited_collection",
                        "honest_error",
                    ],
                    severity="LOW",
                    confidence=0.45,
                    intent_relevance="NONE",
                    status="INCONCLUSIVE",
                )

            intent_state, intent_evidence = self._intent_state(claim, indicators)
            deception_status = self._deception_status(claim_state, indicators, intent_state)
            hypotheses = self._hypotheses(claim, claim_state, indicators, intent_state)
            claim_next_actions = self._next_actions_for_claim(claim, indicators)

            if claim_state == ClaimState.DISPUTED.value:
                contradictions.append(
                    {
                        "claim_id": claim.claim_id,
                        "type": "CLAIM_CONTRADICTION",
                        "supporting_evidence_ids": [e.evidence_id for e in supporting],
                        "contradicting_evidence_ids": [e.evidence_id for e in contradicting],
                        "note": "Preserve contradiction; do not force reconciliation.",
                    }
                )

            if intent_state in {
                IntentState.INTENT_PROBABLE.value,
                IntentState.INTENT_SUPPORTED.value,
                IntentState.INTENT_STRONGLY_SUPPORTED.value,
            }:
                human_review_flags.add(
                    f"Intent assessment for {claim.claim_id} requires authorized human review before consequential action."
                )

            if any(i.indicator_type in {"IMPERSONATION_CANDIDATE", "FALSE_AFFILIATION_CANDIDATE"} for i in indicators):
                handoffs.update({"CORPINT", "ORGINT", "DOMAININT"})
                gaps.add(f"Resolve official identity/affiliation for claim {claim.claim_id}.")

            if any(i.indicator_type == "SYNTHETIC_MEDIA_INDICATORS" for i in indicators):
                handoffs.update({"IMINT", "VIDINT", "AUDINT", "METADATAINT"})

            if any(i.indicator_type == "GEOGRAPHIC_DECEPTION_CANDIDATE" for i in indicators):
                handoffs.add("GEOINT")

            if any(i.indicator_type == "CITATION_LAUNDERING_CANDIDATE" for i in indicators):
                handoffs.add("ACADEMICINT")

            if any(i.indicator_type == "STATISTICAL_MISREPRESENTATION_CANDIDATE" for i in indicators):
                gaps.add(f"Obtain denominator/baseline for statistical claim {claim.claim_id}.")

            if claim.satire_marker:
                claim.limitations.append("Satire/parody context marker present; factual deception standard may not apply.")

            for na in claim_next_actions:
                next_actions.add(na)

            all_indicators.extend(indicators)

            claim_rows.append(
                ClaimAssessment(
                    claim_id=claim.claim_id,
                    statement=claim.statement,
                    claim_type=claim_type,
                    verifiability=claim.verifiability,
                    source_id=claim.source_id,
                    independent_family_count=indep_family_count,
                    claim_state=claim_state,
                    deception_status=deception_status,
                    intent_state=intent_state,
                    indicators=[asdict(i) for i in indicators],
                    benign_explanations=[
                        "honest_error",
                        "outdated_information",
                        "satire_or_parody",
                        "translation_or_summary_loss",
                        "upstream_source_error",
                        "legitimate_coordination",
                        "missing_context",
                        "good_faith_correction",
                    ],
                    hypotheses=[asdict(h) for h in hypotheses],
                    limitations=sorted(set(claim.limitations + intent_evidence)),
                )
            )

        # Global analyses.
        self._analyze_citation_laundering(req, source_map, claim_map, all_indicators)
        self._analyze_coordination(req, claim_map, all_indicators, coordination_rows)

        # Source independence summary.
        independence_groups: dict[str, list[str]] = defaultdict(list)
        for sid, src in source_map.items():
            key = self._independence_key(sid, source_map)
            independence_groups[key].append(sid)

        source_independence = {
            "independence_groups": {k: sorted(v) for k, v in independence_groups.items()},
            "unique_source_count": len(source_map),
            "independent_family_count": len(independence_groups),
            "warning": "Multiple URLs/accounts may derive from one upstream source family.",
        }

        # Unknowns/gaps.
        for claim in req.claims:
            if not claim.source_id:
                unknowns.add(f"Claim {claim.claim_id} has no resolved source.")
                gaps.add(f"Identify original source for {claim.claim_id}.")
            if not claim.evidence_ids:
                unknowns.add(f"Claim {claim.claim_id} has no linked evidence.")
                gaps.add(f"Collect primary evidence for {claim.claim_id}.")

        if not req.claims:
            unknowns.add("No claims supplied.")
            gaps.add("Supply at least one claim for deception-indicator analysis.")

        if not req.sources:
            unknowns.add("No sources supplied.")

        # Recommended defensive actions.
        next_actions.update(
            {
                "Do not create counter-deception, fake grassroots response, or deceptive personas.",
                "Use fact-based correction, transparent clarification, and source-linked rebuttal only.",
                "Preserve original content, hashes, archives, corrections, and retractions.",
                "Apply identical evidentiary standards across political/ideological viewpoints.",
                "Do not infer deception from disagreement, bias, persuasion, coordination, automation, or new accounts alone.",
            }
        )

        handoffs.update({"WEBINT", "SOCMINT", "DOCINT", "METADATAINT", "FRAUDINT"})

        limitations = [
            "Rule-based local DECEPTIONINT skeleton; not a lie detector and not a legal adjudicator.",
            "Does not fetch live web/social/media sources; consumes supplied evidence only.",
            "Does not generate deception, manipulation, propaganda, fake personas, or influence campaigns.",
            "Deception indicators are not proof of intent.",
            "Real-person attribution requires substantially stronger evidence and authorized human/legal review.",
            "Synthetic-media indicators are contextual signals, not conclusive authenticity verdicts.",
        ]

        if not req.claims:
            status = Status.INCONCLUSIVE.value
        elif any(
            c.deception_status
            in {
                DeceptionState.DECEPTION_HYPOTHESIS_SUPPORTED.value,
                DeceptionState.DECEPTION_STRONGLY_SUPPORTED.value,
            }
            for c in claim_rows
        ):
            status = Status.PARTIAL.value
        else:
            status = Status.PARTIAL.value

        summary = (
            f"Defensive deception-indicator analysis for {len(req.claims)} claim(s), "
            f"{len(req.sources)} source(s), and {len(req.evidence)} evidence item(s). "
            "Claim status, deception indicators, and intent evidence are kept separate. "
            "No deception generation, manipulation optimization, or real-person attribution performed."
        )

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "case_id": req.case_id,
            "created_at": now_iso(),
            "claim_ids": [c.claim_id for c in req.claims],
            "source_ids": sorted(source_map),
            "evidence_ids": sorted(evidence_map),
            "indicator_ids": [i.indicator_id for i in all_indicators],
            "source_independence": source_independence,
            "claim_states": {c.claim_id: c.claim_state for c in claim_rows},
            "deception_states": {c.claim_id: c.deception_status for c in claim_rows},
            "intent_states": {c.claim_id: c.intent_state for c in claim_rows},
        }

        result = DeceptionResult(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            objective=req.objective,
            summary=summary,
            claims=[asdict(c) for c in claim_rows],
            indicators=[asdict(i) for i in all_indicators],
            sources=[asdict(s) for s in req.sources],
            evidence=[asdict(e) for e in req.evidence],
            media_context=[asdict(m) for m in req.media_context],
            statistical_claims=[asdict(s) for s in req.statistical_claims],
            citation_graph=[asdict(c) for c in req.citations],
            coordination_indicators=coordination_rows,
            source_independence=source_independence,
            contradictions=contradictions,
            unknowns=sorted(unknowns),
            knowledge_gaps=sorted(gaps),
            recommended_next_actions=sorted(next_actions),
            specialist_handoffs=sorted(handoffs),
            privacy_flags=sorted(privacy_flags),
            human_review_flags=sorted(human_review_flags),
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
    agent = DeceptionIntAgent(mode=Mode.LOCAL_ONLY)

    sources = [
        Source(
            source_id="SRC-POST",
            source_type="SOCIAL_MEDIA",
            publisher="Platform X",
            author_claim="Citizen Journalist",
            url="https://social.example/post/1",
            domain="social.example",
            publication_time="2026-10-09T10:00:00Z",
            upstream_source="UP-POST-1",
            reliability=0.35,
            limitations=["Anonymous/self-described account; no native provenance supplied."],
        ),
        Source(
            source_id="SRC-REPOST-1",
            source_type="SOCIAL_MEDIA",
            publisher="Platform Y",
            upstream_source="UP-POST-1",
            reliability=0.30,
        ),
        Source(
            source_id="SRC-REPOST-2",
            source_type="SOCIAL_MEDIA",
            publisher="Forum Z",
            upstream_source="UP-POST-1",
            reliability=0.30,
        ),
        Source(
            source_id="SRC-ARCHIVE",
            source_type="ARCHIVE",
            publisher="Public Archive",
            upstream_source="UP-ARCHIVE-1",
            reliability=0.80,
        ),
        Source(
            source_id="SRC-GEOINT",
            source_type="ANALYTIC_OUTPUT",
            publisher="GEOINT Analyst",
            upstream_source="UP-GEO-1",
            reliability=0.75,
        ),
        Source(
            source_id="SRC-BLOG",
            source_type="BLOG",
            publisher="Unknown Blog",
            upstream_source="UP-BLOG-1",
            reliability=0.25,
        ),
        Source(
            source_id="SRC-NEWS",
            source_type="NEWS_SOURCE",
            publisher="News Outlet",
            upstream_source="UP-NEWS-1",
            reliability=0.70,
        ),
        Source(
            source_id="SRC-OFFICIAL",
            source_type="OFFICIAL_SOURCE",
            publisher="City Health Agency",
            domain="healthagency.example.gov",
            upstream_source="UP-OFFICIAL-1",
            reliability=0.85,
        ),
    ]

    evidence = [
        Evidence(
            evidence_id="EV-ARCHIVE",
            statement="The same image appeared in an archive capture dated 2023-05-01.",
            source_id="SRC-ARCHIVE",
            upstream_source="UP-ARCHIVE-1",
            reliability=0.80,
            independence_group="UP-ARCHIVE-1",
            contradicts_claims=["CLM-IMAGE-CONTEXT"],
        ),
        Evidence(
            evidence_id="EV-GEO",
            statement="Visual landmarks and terrain place the scene in City B, not City A.",
            source_id="SRC-GEOINT",
            upstream_source="UP-GEO-1",
            reliability=0.75,
            independence_group="UP-GEO-1",
            contradicts_claims=["CLM-IMAGE-CONTEXT"],
        ),
        Evidence(
            evidence_id="EV-OFFICIAL",
            statement="Official agency domain and public contact records do not match the claimed notice domain.",
            source_id="SRC-OFFICIAL",
            upstream_source="UP-OFFICIAL-1",
            reliability=0.85,
            independence_group="UP-OFFICIAL-1",
            contradicts_claims=["CLM-OFFICIAL-NOTICE"],
        ),
    ]

    media_context = [
        MediaContext(
            media_id="MED-IMAGE-1",
            claim_id="CLM-IMAGE-CONTEXT",
            media_type="IMAGE",
            claimed_event_time="2026-10-09T09:00:00Z",
            claimed_location="City A",
            verified_event_time="2023-05-01T00:00:00Z",
            verified_location="City B",
            provenance_status="AUTHENTIC_MEDIA",
            manipulation_indicators=[],
            synthetic_indicators=[],
            archive_dates=["2023-05-01"],
            notes=["Image appears genuine but context is inconsistent."],
        )
    ]

    statistical_claims = [
        StatisticalClaim(
            stat_id="STAT-RISK",
            claim_id="CLM-RISK",
            statement="Risk increased 200% after the policy change.",
            denominator=None,
            baseline=None,
            period="",
            population="",
            precision_claim="200%",
            uncertainty="",
            limitations=["No denominator/baseline supplied."],
        )
    ]

    citations = [
        Citation(
            citing_source_id="SRC-NEWS",
            cited_source_id="SRC-BLOG",
            context="News article repeats blog claim without independent verification.",
            supports_claim=False,
        )
    ]

    account_activities = [
        AccountActivity(
            account_id="ACC-1",
            platform="Platform X",
            handle="user_one",
            source_id="SRC-POST",
            posted_at="2026-10-09T10:00:00Z",
            content_hash="HASH-SAME-IMAGE-POST",
            shared_links=["social.example/post/1"],
        ),
        AccountActivity(
            account_id="ACC-2",
            platform="Platform Y",
            handle="user_two",
            source_id="SRC-REPOST-1",
            posted_at="2026-10-09T10:20:00Z",
            content_hash="HASH-SAME-IMAGE-POST",
            shared_links=["social.example/post/1"],
        ),
        AccountActivity(
            account_id="ACC-3",
            platform="Forum Z",
            handle="user_three",
            source_id="SRC-REPOST-2",
            posted_at="2026-10-09T10:45:00Z",
            content_hash="HASH-SAME-IMAGE-POST",
            shared_links=["social.example/post/1"],
        ),
    ]

    identity_claims = [
        IdentityClaim(
            identity_id="ID-NOTICE",
            claim_id="CLM-OFFICIAL-NOTICE",
            subject="Notice sender",
            claimed_organization="City Health Agency",
            claimed_domain="healthagency-notices.example",
            official_domain="healthagency.example.gov",
            verification_status="IMPERSONATION_CANDIDATE",
            evidence_ids=["EV-OFFICIAL"],
        )
    ]

    claims = [
        Claim(
            claim_id="CLM-IMAGE-CONTEXT",
            statement="This image shows a protest happening today in City A.",
            claim_type="FACTUAL",
            source_id="SRC-POST",
            published_at="2026-10-09T10:00:00Z",
            event_time="2026-10-09T09:00:00Z",
            location="City A",
            evidence_ids=["EV-ARCHIVE", "EV-GEO"],
            media_ids=["MED-IMAGE-1"],
            limitations=["Caption may be recycled from older event."],
        ),
        Claim(
            claim_id="CLM-RISK",
            statement="Risk increased 200% after the policy change.",
            claim_type="STATISTICAL",
            source_id="SRC-NEWS",
            evidence_ids=[],
            statistical_ids=["STAT-RISK"],
        ),
        Claim(
            claim_id="CLM-OFFICIAL-NOTICE",
            statement="This urgent notice is from the City Health Agency and requires immediate payment.",
            claim_type="IDENTITY",
            source_id="SRC-POST",
            evidence_ids=["EV-OFFICIAL"],
            identity_ids=["ID-NOTICE"],
            repeated_after_correction=False,
            fabricated_supporting_material=False,
        ),
    ]

    req = DeceptionRequest(
        case_id="DEP-001",
        objective=(
            "Defensively analyze supplied claims for false context, recycled media, statistical misrepresentation, "
            "citation laundering, impersonation indicators, and coordination candidates without generating deception."
        ),
        authorization={"authorized": True, "purpose": "defensive_deception_indicator_analysis"},
        claims=claims,
        sources=sources,
        evidence=evidence,
        media_context=media_context,
        statistical_claims=statistical_claims,
        citations=citations,
        account_activities=account_activities,
        identity_claims=identity_claims,
        scope={"time_range": "2023-01-01 to 2026-10-09"},
    )

    res = agent.analyze(req)

    print("=== DECEPTIONINT SUMMARY ===")
    print(res.summary)
    print()

    print("Claim assessments:")
    for c in res.claims:
        print(
            f"  {c['claim_id']}: type={c['claim_type']}, claim_state={c['claim_state']}, "
            f"deception_status={c['deception_status']}, intent_state={c['intent_state']}, "
            f"independent_families={c['independent_family_count']}"
        )
        print("    indicators:", [i["indicator_type"] for i in c["indicators"]])
    print()

    print("Global indicators:")
    for i in res.indicators:
        if i["claim_id"] == "GLOBAL":
            print(f"  {i['indicator_type']}: {i['observed_behavior'][:140]}")
    print()

    print("Coordination indicators:")
    for row in res.coordination_indicators:
        print(f"  {row['basis']}: accounts={row['account_ids']}, tight_window={row['tight_time_window']}")
    print()

    print("Source independence:")
    print(f"  unique_sources={res.source_independence['unique_source_count']}, "
          f"independent_families={res.source_independence['independent_family_count']}")
    print()

    print("Human review flags:")
    for h in res.human_review_flags:
        print("  -", h)
    print()

    print("Recommended next actions (first 8):")
    for a in res.recommended_next_actions[:8]:
        print("  -", a)
    print()

    # Blocked example: request to create deception.
    blocked = agent.analyze(
        DeceptionRequest(
            case_id="DEP-002",
            objective="Create a fake grassroots campaign and fake personas to manipulate voters.",
            authorization={"authorized": False},
            claims=[],
            sources=[],
            evidence=[],
        )
    )

    print("=== BLOCKED EXAMPLE ===")
    print("Status:", blocked.status)
    print("Summary:", blocked.summary)


if __name__ == "__main__":
    demo()