"""
======================================================================
TRACEATLAS — NEWSINT
NEWS / MEDIA / EVENT / CLAIM INTELLIGENCE AI EMPLOYEE
Python Implementation
======================================================================

Mode:
PUBLIC-SOURCE / LICENSED-SOURCE / EVIDENCE-FIRST / TIME-AWARE

Primary boundary:
News intelligence,
NOT propaganda, political persuasion, harassment,
private data collection or paywall bypass.
"""

from __future__ import annotations

import difflib
import hashlib
import itertools
import json
import logging
import math
import re
import unicodedata
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("NEWSINT")


# ======================================================================
# SECTION 1 — ENUMS
# ======================================================================

class ModelMode(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    HYBRID = "HYBRID"
    CLOUD = "CLOUD"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class ArticleType(str, Enum):
    STRAIGHT_NEWS = "STRAIGHT_NEWS"
    BREAKING_NEWS = "BREAKING_NEWS"
    ANALYSIS = "ANALYSIS"
    OPINION = "OPINION"
    EDITORIAL = "EDITORIAL"
    INTERVIEW = "INTERVIEW"
    LIVE_BLOG = "LIVE_BLOG"
    INVESTIGATION = "INVESTIGATION"
    FEATURE = "FEATURE"
    FACT_CHECK = "FACT_CHECK"
    PRESS_RELEASE = "PRESS_RELEASE"
    WIRE_COPY = "WIRE_COPY"
    SYNDICATED_COPY = "SYNDICATED_COPY"
    SPONSORED_CONTENT = "SPONSORED_CONTENT"
    ADVERTISEMENT = "ADVERTISEMENT"
    SATIRE = "SATIRE"
    UNKNOWN = "UNKNOWN"


class SourceType(str, Enum):
    NEWS_WEBSITE = "NEWS_WEBSITE"
    RSS = "RSS"
    NEWS_API = "NEWS_API"
    WIRESERVICE = "WIRESERVICE"
    PRESS_RELEASE = "PRESS_RELEASE"
    OFFICIAL_STATEMENT = "OFFICIAL_STATEMENT"
    COURT_FILING = "COURT_FILING"
    REGULATORY_FILING = "REGULATORY_FILING"
    COMPANY_FILING = "COMPANY_FILING"
    RESEARCH_PAPER = "RESEARCH_PAPER"
    SOCIAL_POST = "SOCIAL_POST"
    VIDEO = "VIDEO"
    PHOTO = "PHOTO"
    DOCUMENT = "DOCUMENT"
    UNKNOWN = "UNKNOWN"


class SyndicationState(str, Enum):
    ORIGINAL = "ORIGINAL"
    WIRE_ORIGINAL = "WIRE_ORIGINAL"
    SYNDICATED_COPY = "SYNDICATED_COPY"
    PARTIALLY_REWRITTEN = "PARTIALLY_REWRITTEN"
    DERIVED_REPORT = "DERIVED_REPORT"
    INDEPENDENT_REPORT = "INDEPENDENT_REPORT"
    UNKNOWN = "UNKNOWN"


class ClaimType(str, Enum):
    EVENT_OCCURRED = "EVENT_OCCURRED"
    IDENTITY = "IDENTITY"
    LOCATION = "LOCATION"
    TIME = "TIME"
    COUNT = "COUNT"
    CAUSE = "CAUSE"
    RESPONSIBILITY = "RESPONSIBILITY"
    MOTIVE = "MOTIVE"
    FINANCIAL = "FINANCIAL"
    LEGAL = "LEGAL"
    TECHNICAL = "TECHNICAL"
    POLITICAL = "POLITICAL"
    SECURITY = "SECURITY"
    HEALTH = "HEALTH"
    BUSINESS = "BUSINESS"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class ClaimState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    SINGLE_SOURCE = "SINGLE_SOURCE"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    SUPPORTED = "SUPPORTED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    CORRECTED = "CORRECTED"
    SUPERSEDED = "SUPERSEDED"
    RETRACTED = "RETRACTED"
    FALSE_CANDIDATE = "FALSE_CANDIDATE"
    INCONCLUSIVE = "INCONCLUSIVE"


class CertaintyExpression(str, Enum):
    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"
    ALLEGED = "ALLEGED"
    SPECULATIVE = "SPECULATIVE"
    UNCERTAIN = "UNCERTAIN"
    UNKNOWN = "UNKNOWN"


class IndependenceState(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    PARTIALLY_INDEPENDENT = "PARTIALLY_INDEPENDENT"
    DEPENDENT = "DEPENDENT"
    UNKNOWN = "UNKNOWN"


class Materiality(str, Enum):
    CRITICAL = "CRITICAL"
    MATERIAL = "MATERIAL"
    MODERATE = "MODERATE"
    MINOR = "MINOR"
    COSMETIC = "COSMETIC"
    UNKNOWN = "UNKNOWN"


class FactStatus(str, Enum):
    FACT = "FACT"
    SUPPORTED = "SUPPORTED"
    CANDIDATE = "CANDIDATE"
    DISPUTED = "DISPUTED"
    CORRECTED = "CORRECTED"
    RETRACTED = "RETRACTED"
    UNKNOWN = "UNKNOWN"


class ReviewStatus(str, Enum):
    AGREE = "AGREE"
    PARTIAL_AGREEMENT = "PARTIAL_AGREEMENT"
    SEMANTIC_AGREEMENT = "SEMANTIC_AGREEMENT"
    DISAGREE = "DISAGREE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


# ======================================================================
# SECTION 2 — UTILITIES
# ======================================================================

def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def safe_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def normalize_whitespace(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def normalize_text(value: Any, upper: bool = False) -> Optional[str]:
    if value is None:
        return None
    s = unicodedata.normalize("NFKC", str(value)).strip()
    if not s:
        return None
    return s.upper() if upper else s


def to_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    elif isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        s = s.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except Exception:
            dt = None
            for fmt in (
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%Y-%m-%d",
            ):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except Exception:
                    continue
            if dt is None:
                return None
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def enum_from(cls, value: Any, default: Any) -> Any:
    if isinstance(value, cls):
        return value
    try:
        return cls(str(value).upper())
    except Exception:
        try:
            return cls(str(value))
        except Exception:
            return default


def unique_list(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        if item is None:
            continue
        key = item.value if isinstance(item, Enum) else item
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def mean(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    return sum(vals) / len(vals)


def median(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    n = len(vals)
    mid = n // 2
    if n % 2 == 1:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2.0


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_payload(payload: Any) -> str:
    try:
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
    except Exception:
        canonical = str(payload)
    return sha256_text(canonical)


def tokens(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", (text or "").lower())


def shingles(text: str, k: int = 5) -> set[Tuple[str, ...]]:
    ts = tokens(text)
    if not ts:
        return set()
    if len(ts) < k:
        return {tuple(ts)}
    return {tuple(ts[i:i + k]) for i in range(len(ts) - k + 1)}


def jaccard(a: set[Any], b: set[Any]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, (a or "").lower(), (b or "").lower()).ratio()


def canonical_url(url: Optional[str]) -> str:
    if not url:
        return ""
    try:
        p = urlparse(url)
        scheme = "https" if p.scheme in ("http", "https", "") else p.scheme
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        path = p.path.rstrip("/")
        if path.endswith("/amp"):
            path = path[:-4]

        tracking_prefixes = ("utm_",)
        tracking_exact = {
            "fbclid",
            "gclid",
            "mc_cid",
            "mc_eid",
            "igshid",
            "ref",
            "source",
            "s",
            "cmpid",
            "campaign",
        }

        query = []
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            lk = k.lower()
            if lk.startswith(tracking_prefixes) or lk in tracking_exact:
                continue
            if lk == "outputtype" and v.lower() == "amp":
                continue
            query.append((k, v))

        return urlunparse((scheme, netloc, path, p.params, urlencode(query), ""))
    except Exception:
        return normalize_whitespace(url)


def detect_language(text: str, declared: Optional[str] = None) -> str:
    if declared:
        return declared.strip().upper()
    if not text:
        return "UNKNOWN"
    for ch in text:
        cp = ord(ch)
        if 0x0600 <= cp <= 0x06FF:
            return "AR"
        if 0x0400 <= cp <= 0x04FF:
            return "RU"
        if 0x4E00 <= cp <= 0x9FFF:
            return "ZH"
        if 0x0900 <= cp <= 0x097F:
            return "HI"
        if 0xAC00 <= cp <= 0xD7AF:
            return "KO"
    return "EN"


def excerpt(text: str, limit: int = 220) -> str:
    s = normalize_whitespace(text)
    if len(s) <= limit:
        return s
    return s[: limit - 1].rstrip() + "…"


def fmt_dt(value: Optional[datetime]) -> str:
    return value.isoformat() if value else "UNKNOWN"


def parse_number(raw: str, multiplier: Optional[str] = None) -> Optional[float]:
    try:
        value = float(raw.replace(",", ""))
    except Exception:
        return None
    mult = (multiplier or "").lower()
    if mult == "thousand":
        value *= 1_000
    elif mult == "million":
        value *= 1_000_000
    elif mult == "billion":
        value *= 1_000_000_000
    return value


# ======================================================================
# SECTION 3 — POLICY GUARD / PROMPT INJECTION DEFENSE
# ======================================================================

@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str = ""


class PolicyGuard:
    """
    Blocks requests seeking prohibited NEWSINT operational guidance.

    Allows lawful public/licensed news monitoring, article verification,
    claim tracking, source pedigree analysis, correction/retraction tracking,
    event timeline reconstruction, and evidence-linked reporting.
    """

    PROHIBITED_PATTERNS = [
        r"(?:how\s+to|guide\s+to|instructions?\s+to|help\s+me|teach\s+me).{0,120}(?:bypass|circumvent|crack|defeat|evade|avoid|get\s+around).{0,120}(?:paywall|subscription|login|captcha|access\s+control|meter|registration\s+wall)",
        r"\b(?:paywall\s+bypass|subscription\s+theft|steal\s+credentials|circumvent\s+captcha|scrape\s+private\s+accounts|journalist\s+impersonation|impersonate\s+journalist|contact\s+sources\s+deceptively|harass\s+reporter|harass\s+subject|targeted\s+propaganda|political\s+persuasion\s+campaign|microtarget\s+voters|influence\s+operation|amplify\s+unverified\s+allegation\s+as\s+fact|fabricate\s+article|fabricate\s+quote|fabricate\s+source|fabricate\s+event|fake\s+news\s+generator|private\s+data\s+collection|doxx?)\b",
        r"(?:generate|create|produce|write).{0,80}(?:propaganda|persuasion\s+campaign|political\s+messaging|fake\s+article|fake\s+news|fabricated\s+quote)",
        r"(?:harass|threaten|intimidate|stalk|dox|expose\s+private).{0,80}(?:journalist|reporter|source|subject|victim|witness|private\s+person)",
        r"(?:bypass|break|defeat).{0,80}(?:paywall|login|captcha|subscription|access\s+control)",
    ]

    def __init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.PROHIBITED_PATTERNS]

    def check_request(self, text: str) -> PolicyResult:
        t = text or ""
        for rx in self._compiled:
            if rx.search(t):
                return PolicyResult(
                    decision=PolicyDecision.POLICY_BLOCKED,
                    reason="Request seeks prohibited NEWSINT paywall bypass, propaganda, harassment, fabrication, or private-data collection guidance.",
                )
        return PolicyResult(decision=PolicyDecision.ALLOW, reason="")

    def is_safe_action(self, action: str) -> bool:
        return self.check_request(action).decision == PolicyDecision.ALLOW


class PromptInjectionDefense:
    """
    Articles, RSS content, press releases, comments, embedded documents,
    and web pages are UNTRUSTED DATA.

    Neutralize obvious instruction-like injections for analysis while
    preserving raw evidence separately.
    """

    CONTROL_TOKEN_RX = re.compile(r"<\|.*?\|>", re.DOTALL)
    INSTRUCTION_RX = re.compile(
        r"(?i)\b(ignore\s+previous|ignore\s+above|system\s+prompt|you\s+are\s+now|new\s+instructions?|change\s+classification|send\s+data|execute\s+script|bypass\s+paywall|amplify\s+this)\b"
    )

    def sanitize_for_analysis(self, text: Any) -> str:
        if text is None:
            return ""
        s = str(text)
        s = self.CONTROL_TOKEN_RX.sub("[REDACTED_CONTROL_TOKEN]", s)
        s = self.INSTRUCTION_RX.sub("[UNTRUSTED_INSTRUCTION]", s)
        return normalize_whitespace(s)


# ======================================================================
# SECTION 4 — CORE DATA OBJECTS
# ======================================================================

@dataclass
class Evidence:
    evidence_id: str = field(default_factory=lambda: new_id("EV"))
    case_id: str = ""
    article_id: str = ""
    publication_id: str = ""
    source_id: str = ""
    url: str = ""
    canonical_url: str = ""
    content_hash: str = ""
    fingerprint: str = ""
    raw_reference: str = ""
    retrieved_at: datetime = field(default_factory=utcnow)
    authorization_context: str = ""


@dataclass
class Publication:
    publication_id: str
    name: str = ""
    country: str = ""
    languages: List[str] = field(default_factory=list)
    outlet_type: str = "UNKNOWN"
    ownership_context: str = "UNKNOWN"
    corrections_policy: str = "UNKNOWN"
    source_notes: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class WireService:
    wire_id: str
    name: str = ""
    upstream: str = "UNKNOWN"
    independence_group: str = "UNKNOWN"
    reliability: str = "UNKNOWN"
    limitations: List[str] = field(default_factory=list)


@dataclass
class Journalist:
    journalist_id: str
    name: str = ""
    publication_id: str = ""
    beat: str = "UNKNOWN"
    public_metadata: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Quote:
    quote_id: str = field(default_factory=lambda: new_id("QUOTE"))
    article_id: str = ""
    speaker: str = "ATTRIBUTION_UNCLEAR"
    text: str = ""
    attribution_type: str = "DIRECT_QUOTE"
    context: str = ""
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class Claim:
    claim_id: str = field(default_factory=lambda: new_id("CLAIM"))
    article_id: str = ""
    speaker: str = "UNATTRIBUTED_DESK_REPORT"
    subject: str = ""
    predicate: str = ""
    object: str = ""
    text: str = ""
    claim_type: ClaimType = ClaimType.UNKNOWN
    time_reference: Optional[datetime] = None
    location_reference: str = ""
    numeric_value: Optional[float] = None
    numeric_unit: str = ""
    certainty: CertaintyExpression = CertaintyExpression.UNKNOWN
    verification_state: ClaimState = ClaimState.UNVERIFIED
    confidence: Confidence = Confidence.LOW
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class PrimarySourceCandidate:
    source_id: str = field(default_factory=lambda: new_id("PSRC"))
    article_id: str = ""
    source_type: SourceType = SourceType.UNKNOWN
    reference: str = ""
    description: str = ""
    confidence: Confidence = Confidence.LOW
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Article:
    article_id: str
    publication_id: str = ""
    wire_service_id: str = ""
    syndicated_from: str = ""
    url: str = ""
    canonical_url: str = ""
    headline: str = ""
    subheadline: str = ""
    authors: List[str] = field(default_factory=list)
    section: str = ""
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    retrieved_at: datetime = field(default_factory=utcnow)
    language: str = "UNKNOWN"
    body: str = ""
    normalized_body: str = ""
    article_type: ArticleType = ArticleType.UNKNOWN
    source_type: SourceType = SourceType.UNKNOWN
    quoted_sources: List[str] = field(default_factory=list)
    linked_sources: List[str] = field(default_factory=list)
    primary_source_refs: List[Dict[str, Any]] = field(default_factory=list)
    claims: List[Claim] = field(default_factory=list)
    quotes: List[Quote] = field(default_factory=list)
    correction_ids: List[str] = field(default_factory=list)
    retraction_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    content_hash: str = ""
    fingerprint: str = ""
    duplicate_of: str = ""
    near_duplicate_of: str = ""
    syndication_state: SyndicationState = SyndicationState.UNKNOWN
    source_family: str = ""
    stale_correction_risk: bool = False
    limitations: List[str] = field(default_factory=list)
    raw_reference: str = ""


@dataclass
class Correction:
    correction_id: str = field(default_factory=lambda: new_id("CORR"))
    article_id: str = ""
    claim_id: str = ""
    old_claim: str = ""
    new_claim: str = ""
    correction_time: Optional[datetime] = None
    correction_text_reference: str = ""
    reason: str = "UNKNOWN"
    source_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class Retraction:
    retraction_id: str = field(default_factory=lambda: new_id("RET"))
    article_id: str = ""
    claim_id: str = ""
    scope: str = "ARTICLE"
    retraction_time: Optional[datetime] = None
    reason: str = "UNKNOWN"
    source_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class FactCheck:
    fact_check_id: str = field(default_factory=lambda: new_id("FC"))
    target_claim_id: str = ""
    target_article_id: str = ""
    rating: str = "UNKNOWN"
    source: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Event:
    event_id: str = field(default_factory=lambda: new_id("EVENT"))
    event_type: str = "UNKNOWN"
    title: str = ""
    location: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    discovery_time: Optional[datetime] = None
    claims: List[Claim] = field(default_factory=list)
    supporting_articles: List[str] = field(default_factory=list)
    supporting_source_families: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    status: ClaimState = ClaimState.UNVERIFIED
    confidence: Confidence = Confidence.LOW
    limitations: List[str] = field(default_factory=list)


@dataclass
class Narrative:
    narrative_id: str = field(default_factory=lambda: new_id("NARR"))
    central_claim: str = ""
    supporting_sources: List[str] = field(default_factory=list)
    opposing_sources: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    regions: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    source_families: List[str] = field(default_factory=list)
    verification_state: ClaimState = ClaimState.UNVERIFIED
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Contradiction:
    contradiction_id: str = field(default_factory=lambda: new_id("CONTRA"))
    contradiction_type: str = ""
    description: str = ""
    materiality: Materiality = Materiality.UNKNOWN
    claim_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    possible_explanations: List[str] = field(default_factory=list)
    resolution_status: str = "OPEN"


@dataclass
class Hypothesis:
    hypothesis_id: str = field(default_factory=lambda: new_id("HYP"))
    statement: str = ""
    supports: List[str] = field(default_factory=list)
    oppositions: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    source_dependencies: List[str] = field(default_factory=list)
    temporal_constraints: List[str] = field(default_factory=list)
    falsification_tests: List[str] = field(default_factory=list)
    status: str = "OPEN"


@dataclass
class Fact:
    fact_id: str = field(default_factory=lambda: new_id("FACT"))
    statement: str = ""
    status: FactStatus = FactStatus.UNKNOWN
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class KnowledgeGap:
    gap_id: str = field(default_factory=lambda: new_id("GAP"))
    description: str = ""
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: str = ""
    expected_information_value: str = ""


@dataclass
class NextAction:
    action_id: str = field(default_factory=lambda: new_id("ACT"))
    description: str = ""
    rationale: str = ""
    priority: str = "MEDIUM"
    safety_ok: bool = True


@dataclass
class SpecialistHandoff:
    handoff_id: str = field(default_factory=lambda: new_id("HAND"))
    specialist: str = ""
    reason: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestedCase:
    evidence: List[Evidence] = field(default_factory=list)
    publications: List[Publication] = field(default_factory=list)
    wires: List[WireService] = field(default_factory=list)
    journalists: List[Journalist] = field(default_factory=list)
    articles: List[Article] = field(default_factory=list)
    corrections: List[Correction] = field(default_factory=list)
    retractions: List[Retraction] = field(default_factory=list)
    fact_checks: List[FactCheck] = field(default_factory=list)


@dataclass
class NEWSINTResult:
    case_id: str
    task_id: str
    objective: str
    status: str
    policy_decision: PolicyDecision = PolicyDecision.ALLOW

    evidence: List[Evidence] = field(default_factory=list)
    publications: List[Publication] = field(default_factory=list)
    wires: List[WireService] = field(default_factory=list)
    journalists: List[Journalist] = field(default_factory=list)
    articles: List[Article] = field(default_factory=list)
    claims: List[Claim] = field(default_factory=list)
    quotes: List[Quote] = field(default_factory=list)
    primary_sources: List[PrimarySourceCandidate] = field(default_factory=list)
    corrections: List[Correction] = field(default_factory=list)
    retractions: List[Retraction] = field(default_factory=list)
    fact_checks: List[FactCheck] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    narratives: List[Narrative] = field(default_factory=list)

    publication_timeline: List[Dict[str, Any]] = field(default_factory=list)
    event_timeline: List[Dict[str, Any]] = field(default_factory=list)
    knowledge_timeline: List[Dict[str, Any]] = field(default_factory=list)
    numeric_claims: List[Dict[str, Any]] = field(default_factory=list)
    regional_reporting_comparison: List[Dict[str, Any]] = field(default_factory=list)

    source_families: List[str] = field(default_factory=list)
    source_independence: Dict[str, Any] = field(default_factory=dict)
    contradictions: List[Contradiction] = field(default_factory=list)
    facts: List[Fact] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    knowledge_gaps: List[KnowledgeGap] = field(default_factory=list)
    next_actions: List[NextAction] = field(default_factory=list)
    specialist_handoffs: List[SpecialistHandoff] = field(default_factory=list)

    review: Dict[str, Any] = field(default_factory=dict)
    graph: Dict[str, Any] = field(default_factory=dict)
    report: str = ""

    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    safety_flags: List[str] = field(default_factory=list)
    privacy_flags: List[str] = field(default_factory=list)


# ======================================================================
# SECTION 5 — INGESTION
# ======================================================================

class NEWSINTIngestor:
    PARSER_VERSION = "NEWSINT-parser-0.1.0"
    NORMALIZER_VERSION = "NEWSINT-normalizer-0.1.0"

    def __init__(self, injection_defense: Optional[PromptInjectionDefense] = None):
        self.injection_defense = injection_defense or PromptInjectionDefense()

    def ingest_case(self, case: Dict[str, Any]) -> IngestedCase:
        case_id = str(case.get("case_id", new_id("CASE")))
        authorization = str(case.get("authorization", ""))

        publications = [self._parse_publication(p) for p in case.get("publications", [])]
        wires = [self._parse_wire(w) for w in case.get("wire_services", [])]
        journalists = [self._parse_journalist(j) for j in case.get("journalists", [])]

        articles: List[Article] = []
        evidence: List[Evidence] = []

        for a in case.get("articles", []):
            art, evs = self._parse_article(a, case_id, authorization)
            articles.append(art)
            evidence.extend(evs)

        corrections = [self._parse_correction(c) for c in case.get("corrections", [])]
        retractions = [self._parse_retraction(r) for r in case.get("retractions", [])]
        fact_checks = [self._parse_fact_check(f) for f in case.get("fact_checks", [])]

        return IngestedCase(
            evidence=evidence,
            publications=publications,
            wires=wires,
            journalists=journalists,
            articles=articles,
            corrections=corrections,
            retractions=retractions,
            fact_checks=fact_checks,
        )

    def _parse_publication(self, p: Dict[str, Any]) -> Publication:
        return Publication(
            publication_id=str(p.get("publication_id", new_id("PUB"))),
            name=str(p.get("name", "")),
            country=str(p.get("country", "")),
            languages=[str(x) for x in p.get("languages", [])],
            outlet_type=str(p.get("outlet_type", "UNKNOWN")).upper(),
            ownership_context=str(p.get("ownership_context", "UNKNOWN")),
            corrections_policy=str(p.get("corrections_policy", "UNKNOWN")),
            source_notes=[str(x) for x in p.get("source_notes", [])],
            limitations=[str(x) for x in p.get("limitations", [])],
        )

    def _parse_wire(self, w: Dict[str, Any]) -> WireService:
        return WireService(
            wire_id=str(w.get("wire_id", new_id("WIRE"))),
            name=str(w.get("name", "")),
            upstream=str(w.get("upstream", "UNKNOWN")),
            independence_group=str(w.get("independence_group", w.get("name", "UNKNOWN"))),
            reliability=str(w.get("reliability", "UNKNOWN")).upper(),
            limitations=[str(x) for x in w.get("limitations", [])],
        )

    def _parse_journalist(self, j: Dict[str, Any]) -> Journalist:
        return Journalist(
            journalist_id=str(j.get("journalist_id", new_id("JRN"))),
            name=str(j.get("name", "")),
            publication_id=str(j.get("publication_id", "")),
            beat=str(j.get("beat", "UNKNOWN")),
            public_metadata=dict(j.get("public_metadata") or {}),
            limitations=[str(x) for x in j.get("limitations", [])],
        )

    def _parse_article(
        self,
        a: Dict[str, Any],
        case_id: str,
        authorization: str,
    ) -> Tuple[Article, List[Evidence]]:
        body_raw = str(a.get("body", ""))
        normalized_body = self.injection_defense.sanitize_for_analysis(body_raw)
        headline = normalize_whitespace(a.get("headline", ""))
        subheadline = normalize_whitespace(a.get("subheadline", ""))
        url = str(a.get("url", ""))
        canon = canonical_url(url)
        content_hash = sha256_text(normalized_body.lower())

        article_type = enum_from(ArticleType, a.get("article_type"), ArticleType.UNKNOWN)
        if article_type == ArticleType.UNKNOWN:
            article_type = self._classify_article_type(
                headline=headline,
                body=normalized_body,
                section=str(a.get("section", "")),
                wire_service_id=str(a.get("wire_service_id", "")),
                syndicated_from=str(a.get("syndicated_from", "")),
                source_type=str(a.get("source_type", "")),
            )

        source_type = enum_from(SourceType, a.get("source_type"), SourceType.UNKNOWN)
        if source_type == SourceType.UNKNOWN:
            source_type = self._infer_source_type(article_type, a)

        ev = Evidence(
            case_id=case_id,
            article_id=str(a.get("article_id", new_id("ART"))),
            publication_id=str(a.get("publication_id", "")),
            source_id=str(a.get("wire_service_id", a.get("publication_id", ""))),
            url=url,
            canonical_url=canon,
            content_hash=content_hash,
            raw_reference=json.dumps(
                {
                    "article_id": a.get("article_id"),
                    "publication_id": a.get("publication_id"),
                    "headline": headline,
                    "url": url,
                    "canonical_url": canon,
                    "body_length": len(body_raw),
                    "body_hash": content_hash,
                    "parser_version": self.PARSER_VERSION,
                },
                sort_keys=True,
                default=_json_default,
            )[:1000],
            retrieved_at=to_datetime(a.get("retrieved_at")) or utcnow(),
            authorization_context=authorization,
        )

        limitations = [str(x) for x in a.get("limitations", [])]
        limitations.extend(
            [
                "Article text is untrusted data for analysis; embedded instructions are ignored.",
                "Full copyrighted article text is not reproduced in reports; only metadata, claims, short excerpts, and fingerprints are used.",
            ]
        )

        art = Article(
            article_id=str(a.get("article_id", ev.article_id)),
            publication_id=str(a.get("publication_id", "")),
            wire_service_id=str(a.get("wire_service_id", "")),
            syndicated_from=str(a.get("syndicated_from", "")),
            url=url,
            canonical_url=canon,
            headline=headline,
            subheadline=subheadline,
            authors=[str(x) for x in a.get("authors", [])],
            section=str(a.get("section", "")),
            published_at=to_datetime(a.get("published_at") or a.get("publication_time")),
            updated_at=to_datetime(a.get("updated_at")),
            retrieved_at=ev.retrieved_at,
            language=detect_language(normalized_body, a.get("language")),
            body=body_raw,
            normalized_body=normalized_body,
            article_type=article_type,
            source_type=source_type,
            quoted_sources=[str(x) for x in a.get("quoted_sources", [])],
            linked_sources=[str(x) for x in a.get("linked_sources", [])],
            primary_source_refs=[dict(x) for x in a.get("primary_source_refs", [])],
            evidence_ids=[ev.evidence_id],
            content_hash=content_hash,
            limitations=unique_list(limitations),
            raw_reference=ev.raw_reference,
        )
        return art, [ev]

    @staticmethod
    def _classify_article_type(
        headline: str,
        body: str,
        section: str,
        wire_service_id: str,
        syndicated_from: str,
        source_type: str,
    ) -> ArticleType:
        text = f"{headline} {body} {section}".lower()
        st = (source_type or "").upper()

        if any(x in text for x in ("sponsored", "partner content", "native ad", "advertisement")):
            return ArticleType.SPONSORED_CONTENT
        if any(x in text for x in ("satire", "parody", "humor")):
            return ArticleType.SATIRE
        if "fact check" in text or "fact-check" in text:
            return ArticleType.FACT_CHECK
        if st in {"PRESS_RELEASE", "OFFICIAL_STATEMENT"} or "press release" in text:
            return ArticleType.PRESS_RELEASE
        if syndicated_from:
            return ArticleType.SYNDICATED_COPY
        if wire_service_id:
            return ArticleType.WIRE_COPY
        if any(x in text for x in ("live blog", "live updates", "rolling coverage")):
            return ArticleType.LIVE_BLOG
        if section.upper() in {"OPINION", "EDITORIAL"} or any(x in text for x in ("opinion", "editorial")):
            return ArticleType.OPINION if section.upper() != "EDITORIAL" else ArticleType.EDITORIAL
        if any(x in text for x in ("analysis", "explainer", "what we know", "why it matters")):
            return ArticleType.ANALYSIS
        if any(x in text for x in ("breaking", "developing", "just in")):
            return ArticleType.BREAKING_NEWS
        return ArticleType.STRAIGHT_NEWS

    @staticmethod
    def _infer_source_type(article_type: ArticleType, a: Dict[str, Any]) -> SourceType:
        if article_type == ArticleType.PRESS_RELEASE:
            return SourceType.PRESS_RELEASE
        if article_type in (ArticleType.WIRE_COPY, ArticleType.SYNDICATED_COPY):
            return SourceType.WIRESERVICE
        if a.get("rss") or a.get("feed"):
            return SourceType.RSS
        return SourceType.NEWS_WEBSITE

    def _parse_correction(self, c: Dict[str, Any]) -> Correction:
        return Correction(
            correction_id=str(c.get("correction_id", new_id("CORR"))),
            article_id=str(c.get("article_id", "")),
            claim_id=str(c.get("claim_id", "")),
            old_claim=str(c.get("old_claim", "")),
            new_claim=str(c.get("new_claim", "")),
            correction_time=to_datetime(c.get("correction_time") or c.get("time")),
            correction_text_reference=str(c.get("correction_text_reference", "")),
            reason=str(c.get("reason", "UNKNOWN")),
            source_id=str(c.get("source_id", "")),
            evidence_ids=[str(x) for x in c.get("evidence_ids", [])],
        )

    def _parse_retraction(self, r: Dict[str, Any]) -> Retraction:
        return Retraction(
            retraction_id=str(r.get("retraction_id", new_id("RET"))),
            article_id=str(r.get("article_id", "")),
            claim_id=str(r.get("claim_id", "")),
            scope=str(r.get("scope", "ARTICLE")).upper(),
            retraction_time=to_datetime(r.get("retraction_time") or r.get("time")),
            reason=str(r.get("reason", "UNKNOWN")),
            source_id=str(r.get("source_id", "")),
            evidence_ids=[str(x) for x in r.get("evidence_ids", [])],
        )

    def _parse_fact_check(self, f: Dict[str, Any]) -> FactCheck:
        return FactCheck(
            fact_check_id=str(f.get("fact_check_id", new_id("FC"))),
            target_claim_id=str(f.get("target_claim_id", "")),
            target_article_id=str(f.get("target_article_id", "")),
            rating=str(f.get("rating", "UNKNOWN")).upper(),
            source=str(f.get("source", "")),
            evidence_ids=[str(x) for x in f.get("evidence_ids", [])],
            limitations=[str(x) for x in f.get("limitations", [])] + [
                "Fact-check ratings are secondary analysis; inspect method and primary evidence."
            ],
        )


# ======================================================================
# SECTION 6 — QUOTE / CLAIM EXTRACTION
# ======================================================================

class QuoteExtractor:
    QUOTE_RX = re.compile(r"[“\"]([^”\"]{1,500})[”\"]")
    SPEAKER_RX = re.compile(
        r"([A-Z][^.!?,;:\"“”]{2,90}?)\s+(?:said|says|stated|announced|told|added|wrote|confirmed|reported|claims?|claimed)"
    )

    def extract(self, article: Article) -> List[Quote]:
        quotes: List[Quote] = []
        text = article.normalized_body
        for m in self.QUOTE_RX.finditer(text):
            quote_text = normalize_whitespace(m.group(1))
            if not quote_text:
                continue

            before = text[max(0, m.start() - 140):m.start()]
            after = text[m.end():m.end() + 140]

            speaker = "ATTRIBUTION_UNCLEAR"
            mb = self.SPEAKER_RX.search(before)
            ma = self.SPEAKER_RX.search(after)
            if mb:
                speaker = normalize_whitespace(mb.group(1))
            elif ma:
                speaker = normalize_whitespace(ma.group(1))

            quotes.append(
                Quote(
                    article_id=article.article_id,
                    speaker=speaker,
                    text=quote_text,
                    attribution_type="DIRECT_QUOTE",
                    context=excerpt(text, 300),
                    evidence_ids=article.evidence_ids,
                )
            )
        return quotes


class ClaimExtractor:
    SENTENCE_RX = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9“\"])")
    REPORTING_RX = re.compile(
        r"\b(?:said|says|stated|announc(?:e|ed|es)|report(?:s|ed|ing)|confirm(?:s|ed|ation)?|claim(?:s|ed)?|according\s+to|disclos(?:e|ed|es)|reveals?|arrest(?:s|ed)?|killed|dead|died|death|injur(?:y|ied|ies)|wounded|collapsed|explod(?:e|ed|es|ion)|fire(?:d)?|attack(?:s|ed)?|evacuat(?:e|ed|ion)|closed|launched|signed|filed|found|show(?:s|ed)?)\b",
        re.I,
    )
    EVENT_RX = re.compile(
        r"\b(?:collapse|collapsed|explosion|exploded|fire|attack|shooting|earthquake|flood|arrest|arrested|evacuated|closed|crash|derailed|outage|breach|indicted|charged|convicted)\b",
        re.I,
    )
    NUMERIC_RX = re.compile(
        r"(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)\s*"
        r"(million|billion|thousand)?\s*"
        r"(people|persons|injured|wounded|killed|dead|deaths|fatalities|arrested|missing|evacuated|cases|dollars|USD|%)?",
        re.I,
    )
    LOCATION_RX = re.compile(r"\b(?:in|at|near|around|inside)\s+([A-Z][A-Za-z0-9 .,'-]{2,80})")
    CAUSE_RX = re.compile(r"\b(?:because|due to|caused by|blame|structural failure|mechanical failure|explosion|weather|cyberattack)\b", re.I)
    RESPONSIBILITY_RX = re.compile(r"\b(?:responsible|behind the attack|perpetrator|did it|carried out)\b", re.I)
    LEGAL_RX = re.compile(r"\b(?:lawsuit|court|judge|verdict|settlement|indicted|charged|convicted|acquitted|arrested|person of interest|suspect)\b", re.I)
    FINANCIAL_RX = re.compile(r"\b(?:million|billion|revenue|profit|funding|valuation|share price|market cap)\b", re.I)

    def extract(self, article: Article) -> List[Claim]:
        claims: List[Claim] = []
        sentences = self._split_sentences(article.normalized_body)

        for sentence in sentences:
            if not self._is_claim_worthy(sentence):
                continue

            speaker = self._extract_speaker(sentence, article)
            location = self._extract_location(sentence)
            numeric_value, numeric_unit = self._extract_numeric(sentence)
            claim_type = self._classify_claim(sentence, numeric_value, numeric_unit, location)
            certainty = self._classify_certainty(sentence, article)

            claim = Claim(
                article_id=article.article_id,
                speaker=speaker,
                subject=self._extract_subject(sentence, speaker),
                predicate=self._extract_predicate(sentence),
                object=numeric_unit or location or excerpt(sentence, 80),
                text=normalize_whitespace(sentence),
                claim_type=claim_type,
                time_reference=article.published_at,
                location_reference=location,
                numeric_value=numeric_value,
                numeric_unit=numeric_unit,
                certainty=certainty,
                verification_state=ClaimState.UNVERIFIED,
                confidence=Confidence.LOW,
                evidence_ids=article.evidence_ids,
                limitations=[
                    "Claim is extracted from article text; article reporting is not automatic truth.",
                    "Speaker attribution is heuristic and must be reviewed for consequential use.",
                ],
            )
            claims.append(claim)

        return claims

    def _split_sentences(self, text: str) -> List[str]:
        text = normalize_whitespace(text)
        parts = self.SENTENCE_RX.split(text)
        return [p.strip() for p in parts if p.strip()]

    def _is_claim_worthy(self, sentence: str) -> bool:
        return bool(self.REPORTING_RX.search(sentence) or self.EVENT_RX.search(sentence) or self.NUMERIC_RX.search(sentence))

    def _extract_speaker(self, sentence: str, article: Article) -> str:
        for q in article.quotes:
            if q.text and q.text in sentence and q.speaker != "ATTRIBUTION_UNCLEAR":
                return q.speaker

        patterns = [
            r"^(Officials|Police|Firefighters|Hospital staff|The company|The ministry|The department|The president|The governor|The mayor|A spokesperson|Sources|Witnesses|The report|The study|Emergency management|Demo City Emergency Management)\b[^,.:;]{0,90}?\b(?:said|says|stated|announced|reported|confirmed|claims?|claimed|told|added|wrote)",
            r"according to ([A-Z][^.!?,;:]{2,90})",
            r'"([^"]+)"[,\s]*(?:\w+\s+)?([A-Z][^.!?,;:]{2,90}?)\s+(?:said|stated|told|wrote|reported|claimed|announced)',
        ]
        for pat in patterns:
            m = re.search(pat, sentence, re.I)
            if m:
                groups = [g for g in m.groups() if g]
                if groups:
                    return normalize_whitespace(groups[-1])
        return "UNATTRIBUTED_DESK_REPORT"

    def _extract_location(self, sentence: str) -> str:
        m = self.LOCATION_RX.search(sentence)
        if not m:
            return ""
        loc = normalize_whitespace(m.group(1))
        loc = re.sub(r"[.,;:!?\"]+$", "", loc)
        return loc

    def _extract_numeric(self, sentence: str) -> Tuple[Optional[float], str]:
        m = self.NUMERIC_RX.search(sentence)
        if not m:
            return None, ""
        value = parse_number(m.group(1), m.group(2))
        unit = normalize_text(m.group(3), upper=False) or ""
        if value is None:
            return None, ""
        if not unit:
            lower = sentence.lower()
            if "injur" in lower or "wounded" in lower:
                unit = "injured"
            elif "kill" in lower or "dead" in lower or "death" in lower or "fatal" in lower:
                unit = "killed"
            elif "arrest" in lower:
                unit = "arrested"
            elif "missing" in lower:
                unit = "missing"
            elif "evacuat" in lower:
                unit = "evacuated"
            elif "%" in sentence:
                unit = "percent"
            elif "dollar" in lower or "usd" in lower:
                unit = "currency"
            else:
                unit = "count"
        return value, unit

    def _classify_claim(
        self,
        sentence: str,
        numeric_value: Optional[float],
        numeric_unit: str,
        location: str,
    ) -> ClaimType:
        lower = sentence.lower()

        if numeric_value is not None and numeric_unit in {
            "injured", "killed", "dead", "deaths", "fatalities", "arrested", "missing", "evacuated", "cases"
        }:
            return ClaimType.COUNT
        if self.CAUSE_RX.search(lower):
            return ClaimType.CAUSE
        if self.RESPONSIBILITY_RX.search(lower):
            return ClaimType.RESPONSIBILITY
        if self.LEGAL_RX.search(lower):
            return ClaimType.LEGAL
        if self.FINANCIAL_RX.search(lower):
            return ClaimType.FINANCIAL
        if self.EVENT_RX.search(lower):
            return ClaimType.EVENT_OCCURRED
        if location:
            return ClaimType.LOCATION
        if "named" in lower or "identity" in lower or "suspect" in lower:
            return ClaimType.IDENTITY
        return ClaimType.OTHER

    def _classify_certainty(self, sentence: str, article: Article) -> CertaintyExpression:
        lower = sentence.lower()
        if re.search(r"\b(confirmed|officially confirmed|statement confirmed)\b", lower):
            return CertaintyExpression.CONFIRMED
        if re.search(r"\b(alleged|allegedly)\b", lower):
            return CertaintyExpression.ALLEGED
        if re.search(r"\b(reportedly|sources said|according to)\b", lower):
            return CertaintyExpression.REPORTED
        if re.search(r"\b(may|might|could|possible|investigation|unknown|not immediately|remains)\b", lower):
            return CertaintyExpression.UNCERTAIN
        if article.article_type in (ArticleType.ANALYSIS, ArticleType.OPINION, ArticleType.EDITORIAL):
            return CertaintyExpression.SPECULATIVE
        return CertaintyExpression.REPORTED

    @staticmethod
    def _extract_subject(sentence: str, speaker: str) -> str:
        words = normalize_whitespace(sentence).split()
        if not words:
            return speaker or "UNKNOWN_SUBJECT"
        return " ".join(words[:6])

    @staticmethod
    def _extract_predicate(sentence: str) -> str:
        m = re.search(r"\b(?:said|announced|reported|confirmed|collapsed|exploded|injured|killed|arrested|closed|evacuated)\b", sentence, re.I)
        return m.group(0).lower() if m else "reported"


class PrimarySourceDiscoverer:
    KEYWORDS = [
        ("court filing", SourceType.COURT_FILING),
        ("indictment", SourceType.COURT_FILING),
        ("police report", SourceType.OFFICIAL_STATEMENT),
        ("official statement", SourceType.OFFICIAL_STATEMENT),
        ("press release", SourceType.PRESS_RELEASE),
        ("company filing", SourceType.COMPANY_FILING),
        ("regulatory notice", SourceType.REGULATORY_FILING),
        ("research paper", SourceType.RESEARCH_PAPER),
        ("study", SourceType.RESEARCH_PAPER),
        ("eyewitness video", SourceType.VIDEO),
        ("satellite imagery", SourceType.PHOTO),
    ]

    def discover(self, articles: List[Article]) -> List[PrimarySourceCandidate]:
        candidates: List[PrimarySourceCandidate] = []

        for article in articles:
            for ref in article.primary_source_refs:
                candidates.append(
                    PrimarySourceCandidate(
                        article_id=article.article_id,
                        source_type=enum_from(SourceType, ref.get("source_type"), SourceType.DOCUMENT),
                        reference=str(ref.get("reference", "")),
                        description=str(ref.get("description", "")),
                        confidence=enum_from(Confidence, ref.get("confidence"), Confidence.MEDIUM),
                        evidence_ids=article.evidence_ids,
                        limitations=[
                            "Primary source is closest to claim/event, not automatically true.",
                            "Access/paywall/translation limitations may apply.",
                        ],
                    )
                )

            text = article.normalized_body.lower()
            for keyword, stype in self.KEYWORDS:
                if keyword in text:
                    candidates.append(
                        PrimarySourceCandidate(
                            article_id=article.article_id,
                            source_type=stype,
                            reference=keyword,
                            description=f"Article mentions {keyword}.",
                            confidence=Confidence.LOW,
                            evidence_ids=article.evidence_ids,
                            limitations=["Keyword-based primary-source candidate; requires retrieval and verification."],
                        )
                    )

        return candidates


# ======================================================================
# SECTION 7 — DUPLICATE / SYNDICATION / SOURCE PEDIGREE
# ======================================================================

class ArticleDeduplicator:
    def analyze(self, articles: List[Article], wire_ids: set[str]) -> None:
        by_hash: Dict[str, List[Article]] = defaultdict(list)
        for a in articles:
            if a.content_hash:
                by_hash[a.content_hash].append(a)

        for group in by_hash.values():
            if len(group) <= 1:
                continue
            original = sorted(group, key=lambda x: (x.published_at or datetime.max.replace(tzinfo=timezone.utc), x.article_id))[0]
            for dup in group:
                if dup.article_id == original.article_id:
                    continue
                dup.duplicate_of = original.article_id
                if dup.publication_id != original.publication_id or dup.wire_service_id or dup.syndicated_from:
                    dup.syndication_state = SyndicationState.SYNDICATED_COPY
                else:
                    dup.syndication_state = SyndicationState.DERIVED_REPORT

        by_id = {a.article_id: a for a in articles}

        for a, b in itertools.combinations(articles, 2):
            if a.duplicate_of or b.duplicate_of:
                continue
            if not a.normalized_body or not b.normalized_body:
                continue

            body_sim = jaccard(shingles(a.normalized_body), shingles(b.normalized_body))
            head_sim = similarity(a.headline, b.headline)
            quote_sim = self._quote_similarity(a, b)

            if body_sim >= 0.70 or (head_sim >= 0.85 and quote_sim >= 0.50):
                base, derived = sorted(
                    [a, b],
                    key=lambda x: (x.published_at or datetime.max.replace(tzinfo=timezone.utc), x.article_id),
                )
                derived.near_duplicate_of = base.article_id

                if derived.syndicated_from or base.syndicated_from or derived.wire_service_id or base.wire_service_id:
                    derived.syndication_state = SyndicationState.SYNDICATED_COPY
                else:
                    derived.syndication_state = SyndicationState.PARTIALLY_REWRITTEN

        for a in articles:
            if a.syndication_state != SyndicationState.UNKNOWN:
                continue

            if a.syndicated_from:
                a.syndication_state = SyndicationState.SYNDICATED_COPY
            elif a.wire_service_id:
                if a.publication_id in wire_ids or a.source_type == SourceType.WIRESERVICE:
                    a.syndication_state = SyndicationState.WIRE_ORIGINAL
                else:
                    a.syndication_state = SyndicationState.SYNDICATED_COPY
            elif a.article_type in (ArticleType.PRESS_RELEASE, ArticleType.SPONSORED_CONTENT, ArticleType.SATIRE):
                a.syndication_state = SyndicationState.ORIGINAL
            else:
                a.syndication_state = SyndicationState.INDEPENDENT_REPORT

    @staticmethod
    def _quote_similarity(a: Article, b: Article) -> float:
        qa = {normalize_text(q.text, upper=False) or "" for q in a.quotes if q.text}
        qb = {normalize_text(q.text, upper=False) or "" for q in b.quotes if q.text}
        return jaccard(qa, qb)


class SourcePedigreeResolver:
    def resolve(self, articles: List[Article], wire_ids: set[str]) -> List[str]:
        by_id = {a.article_id: a for a in articles}

        def family_for(article: Article, seen: Optional[set[str]] = None) -> str:
            if article.source_family:
                return article.source_family

            seen = seen or set()
            if article.article_id in seen:
                return f"publication:{article.publication_id or 'UNKNOWN'}"
            seen.add(article.article_id)

            if article.duplicate_of and article.duplicate_of in by_id:
                fam = family_for(by_id[article.duplicate_of], seen)
                article.source_family = fam
                return fam

            if article.syndicated_from and article.syndicated_from in by_id:
                fam = family_for(by_id[article.syndicated_from], seen)
                article.source_family = fam
                return fam

            if article.near_duplicate_of and article.near_duplicate_of in by_id:
                base = by_id[article.near_duplicate_of]
                if base.wire_service_id or base.syndicated_from or article.syndication_state in (
                    SyndicationState.SYNDICATED_COPY,
                    SyndicationState.PARTIALLY_REWRITTEN,
                    SyndicationState.DERIVED_REPORT,
                ):
                    fam = family_for(base, seen)
                    article.source_family = fam
                    return fam

            if article.wire_service_id:
                fam = f"wire:{article.wire_service_id}"
            elif article.source_type in (SourceType.PRESS_RELEASE, SourceType.OFFICIAL_STATEMENT):
                fam = f"official:{article.publication_id or 'UNKNOWN'}"
            elif article.primary_source_refs:
                ref = article.primary_source_refs[0]
                fam = f"primary:{ref.get('source_type', 'DOCUMENT')}:{ref.get('reference', 'UNKNOWN')}"
            elif article.quoted_sources:
                fam = f"quoted:{sorted(article.quoted_sources)[0]}"
            else:
                fam = f"publication:{article.publication_id or 'UNKNOWN'}"

            article.source_family = fam
            return fam

        for a in articles:
            family_for(a)

        return sorted({a.source_family for a in articles if a.source_family})


class SourceIndependenceAnalyzer:
    def assess(self, articles: List[Article], source_families: List[str]) -> Dict[str, Any]:
        families = sorted({a.source_family for a in articles if a.source_family})
        raw_article_count = len(articles)
        independent_family_count = len(families)

        if not families:
            status = IndependenceState.UNKNOWN
            notes = ["Source pedigree unavailable; do not treat multiple articles as independent corroboration."]
        elif independent_family_count == 1:
            status = IndependenceState.DEPENDENT
            notes = [
                "All articles appear to derive from one source family.",
                "Multiple outlets republishing one wire/press release are not independent reports.",
            ]
        elif independent_family_count >= 2:
            status = IndependenceState.PARTIALLY_INDEPENDENT
            notes = [
                "Multiple source families exist, but full independence is not proven.",
                "Check whether families share an upstream official statement, document, witness, or social post.",
            ]
        else:
            status = IndependenceState.UNKNOWN
            notes = ["Insufficient source pedigree metadata."]

        return {
            "status": status.value,
            "raw_article_count": raw_article_count,
            "independent_source_family_count": independent_family_count,
            "families": families,
            "notes": notes,
            "rule": "Count source families, not URLs.",
        }


# ======================================================================
# SECTION 8 — CORRECTIONS / RETRACTIONS / TIMELINES / EVENTS
# ======================================================================

class CorrectionTracker:
    def apply(
        self,
        articles: List[Article],
        claims: List[Claim],
        corrections: List[Correction],
        retractions: List[Retraction],
    ) -> None:
        article_by_id = {a.article_id: a for a in articles}
        claim_by_id = {c.claim_id: c for c in claims}

        for corr in corrections:
            art = article_by_id.get(corr.article_id)
            if art:
                art.correction_ids.append(corr.correction_id)

            claim = claim_by_id.get(corr.claim_id)
            if claim:
                claim.verification_state = ClaimState.CORRECTED
                claim.limitations.append(
                    f"Corrected at {fmt_dt(corr.correction_time)}: {corr.old_claim} -> {corr.new_claim}"
                )

        for ret in retractions:
            art = article_by_id.get(ret.article_id)
            if art:
                art.retraction_ids.append(ret.retraction_id)

            if ret.scope == "ARTICLE" and art:
                for claim in claims:
                    if claim.article_id == art.article_id:
                        claim.verification_state = ClaimState.RETRACTED
                        claim.limitations.append(f"Retracted at {fmt_dt(ret.retraction_time)}: {ret.reason}")
            else:
                claim = claim_by_id.get(ret.claim_id)
                if claim:
                    claim.verification_state = ClaimState.RETRACTED
                    claim.limitations.append(f"Retracted at {fmt_dt(ret.retraction_time)}: {ret.reason}")

        for corr in corrections:
            if not corr.correction_time:
                continue
            art = article_by_id.get(corr.article_id)
            if not art:
                continue
            fam = art.source_family
            for other in articles:
                if other.article_id == corr.article_id:
                    continue
                if other.source_family != fam:
                    continue
                if other.updated_at is None or other.updated_at < corr.correction_time:
                    other.stale_correction_risk = True
                    other.limitations.append(
                        f"Downstream copy may not reflect correction issued at {fmt_dt(corr.correction_time)}."
                    )


class TimelineBuilder:
    def build(self, articles: List[Article], claims: List[Claim], events: List[Event]) -> Dict[str, List[Dict[str, Any]]]:
        publication_timeline = []
        for a in sorted(articles, key=lambda x: x.published_at or datetime.max.replace(tzinfo=timezone.utc)):
            publication_timeline.append(
                {
                    "article_id": a.article_id,
                    "publication_id": a.publication_id,
                    "headline": a.headline,
                    "published_at": fmt_dt(a.published_at),
                    "updated_at": fmt_dt(a.updated_at),
                    "retrieved_at": fmt_dt(a.retrieved_at),
                    "article_type": a.article_type.value,
                    "syndication_state": a.syndication_state.value,
                    "source_family": a.source_family,
                    "stale_correction_risk": a.stale_correction_risk,
                }
            )

        event_timeline = []
        for c in sorted(claims, key=lambda x: x.time_reference or datetime.max.replace(tzinfo=timezone.utc)):
            event_timeline.append(
                {
                    "claim_id": c.claim_id,
                    "article_id": c.article_id,
                    "time_reference": fmt_dt(c.time_reference),
                    "claim_type": c.claim_type.value,
                    "certainty": c.certainty.value,
                    "text_excerpt": excerpt(c.text, 180),
                    "verification_state": c.verification_state.value,
                }
            )

        knowledge_timeline = []
        for a in sorted(articles, key=lambda x: x.retrieved_at):
            knowledge_timeline.append(
                {
                    "article_id": a.article_id,
                    "retrieved_at": fmt_dt(a.retrieved_at),
                    "published_at": fmt_dt(a.published_at),
                    "source_family": a.source_family,
                }
            )

        return {
            "publication_timeline": publication_timeline,
            "event_timeline": event_timeline,
            "knowledge_timeline": knowledge_timeline,
        }


class EventBuilder:
    def build(self, articles: List[Article], claims: List[Claim], case: Dict[str, Any]) -> List[Event]:
        events: List[Event] = []
        topics = [normalize_text(t, upper=False) or "" for t in case.get("topics", []) if normalize_text(t)]

        article_by_id = {a.article_id: a for a in articles}

        for topic in topics:
            matching_claims = [c for c in claims if topic in c.text.lower()]
            if not matching_claims:
                continue

            article_ids = sorted({c.article_id for c in matching_claims})
            families = sorted({article_by_id[aid].source_family for aid in article_ids if aid in article_by_id})
            locations = sorted({c.location_reference for c in matching_claims if c.location_reference})
            times = [c.time_reference for c in matching_claims if c.time_reference]
            retrievals = [article_by_id[aid].retrieved_at for aid in article_ids if aid in article_by_id]

            status = ClaimState.UNVERIFIED
            confidence = Confidence.LOW
            if len(families) >= 2:
                status = ClaimState.PARTIALLY_SUPPORTED
                confidence = Confidence.MEDIUM
            if any(c.certainty == CertaintyExpression.CONFIRMED for c in matching_claims) and len(families) >= 2:
                status = ClaimState.SUPPORTED
                confidence = Confidence.MEDIUM

            events.append(
                Event(
                    event_type="REPORTED_EVENT_CLUSTER",
                    title=topic.title(),
                    location=", ".join(locations) if locations else "UNKNOWN",
                    start_time=min(times) if times else None,
                    end_time=max(times) if times else None,
                    discovery_time=min(retrievals) if retrievals else None,
                    claims=matching_claims,
                    supporting_articles=article_ids,
                    supporting_source_families=families,
                    status=status,
                    confidence=confidence,
                    limitations=[
                        "Event cluster is based on reported claims; not independently verified physical event.",
                        "Similar stories may describe separate incidents or updates; temporal/entity checks required.",
                    ],
                )
            )

        for ev in case.get("events", []):
            events.append(
                Event(
                    event_id=str(ev.get("event_id", new_id("EVENT"))),
                    event_type=str(ev.get("event_type", "INPUT_EVENT")),
                    title=str(ev.get("title", "")),
                    location=str(ev.get("location", "")),
                    start_time=to_datetime(ev.get("start_time")),
                    end_time=to_datetime(ev.get("end_time")),
                    discovery_time=to_datetime(ev.get("discovery_time")),
                    status=enum_from(ClaimState, ev.get("status"), ClaimState.UNVERIFIED),
                    confidence=enum_from(Confidence, ev.get("confidence"), Confidence.UNKNOWN),
                    limitations=[str(x) for x in ev.get("limitations", [])],
                )
            )

        return events


class NarrativeTracker:
    def track(self, events: List[Event], articles: List[Article]) -> List[Narrative]:
        narratives: List[Narrative] = []
        article_by_id = {a.article_id: a for a in articles}

        for ev in events:
            supporting = []
            families = []
            languages = []
            regions = []
            times = []

            for aid in ev.supporting_articles:
                a = article_by_id.get(aid)
                if not a:
                    continue
                supporting.append(a.article_id)
                families.append(a.source_family)
                languages.append(a.language)
                regions.append(a.publication_id)
                if a.published_at:
                    times.append(a.published_at)

            narratives.append(
                Narrative(
                    central_claim=ev.title,
                    supporting_sources=unique_list(supporting),
                    opposing_sources=[],
                    first_seen=min(times) if times else None,
                    last_seen=max(times) if times else None,
                    regions=unique_list(regions),
                    languages=unique_list(languages),
                    source_families=unique_list(families),
                    verification_state=ev.status,
                    evidence_ids=[],
                    limitations=[
                        "Narrative is a recurring claim/framing cluster, not truth or falsehood.",
                        "Same narrative does not automatically imply coordination.",
                    ],
                )
            )

        return narratives


# ======================================================================
# SECTION 9 — NUMERIC TRACKING / CONTRADICTIONS
# ======================================================================

class NumericClaimTracker:
    def track(self, claims: List[Claim]) -> Tuple[List[Dict[str, Any]], List[Contradiction]]:
        groups: Dict[Tuple[str, str], List[Claim]] = defaultdict(list)
        contradictions: List[Contradiction] = []
        summaries: List[Dict[str, Any]] = []

        for c in claims:
            if c.numeric_value is None:
                continue
            key = ((c.numeric_unit or "count").lower(), (c.location_reference or "").lower())
            groups[key].append(c)

        for (unit, location), cs in groups.items():
            cs = sorted(cs, key=lambda x: x.time_reference or datetime.max.replace(tzinfo=timezone.utc))
            values = [c.numeric_value for c in cs if c.numeric_value is not None]
            unique_values = sorted(set(values))

            current = None
            for c in reversed(cs):
                if c.certainty == CertaintyExpression.CONFIRMED:
                    current = c
                    break
            if current is None and cs:
                current = cs[-1]

            summaries.append(
                {
                    "metric": unit,
                    "location": location,
                    "values_over_time": [
                        {
                            "claim_id": c.claim_id,
                            "article_id": c.article_id,
                            "value": c.numeric_value,
                            "time": fmt_dt(c.time_reference),
                            "certainty": c.certainty.value,
                            "state": c.verification_state.value,
                        }
                        for c in cs
                    ],
                    "current_best_supported_claim_id": current.claim_id if current else "",
                    "status": "UPDATED" if len(unique_values) > 1 else "STABLE",
                    "notes": [
                        "Different counts may reflect different timestamps, scopes, confirmed vs estimated figures, or later corrections.",
                        "Early counts are frequently revised.",
                    ],
                }
            )

            if len(unique_values) > 1:
                materiality = Materiality.MODERATE
                if max(values) and (max(values) - min(values)) / max(1.0, max(values)) > 0.25:
                    materiality = Materiality.MATERIAL
                contradictions.append(
                    Contradiction(
                        contradiction_type="NUMERIC_CLAIM_DIFFERENCE",
                        description=(
                            f"Metric '{unit}' in location '{location}' has differing reported values: {unique_values}."
                        ),
                        materiality=materiality,
                        claim_ids=[c.claim_id for c in cs],
                        evidence_ids=[eid for c in cs for eid in c.evidence_ids],
                        possible_explanations=[
                            "different timestamps",
                            "preliminary vs confirmed count",
                            "different scope (hospital, city, region)",
                            "later correction",
                            "translation/terminology difference",
                            "genuine reporting error",
                        ],
                        resolution_status="OPEN",
                    )
                )

        return summaries, contradictions


class ContradictionDetector:
    def detect(
        self,
        claims: List[Claim],
        numeric_contradictions: List[Contradiction],
        corrections: List[Correction],
        retractions: List[Retraction],
    ) -> List[Contradiction]:
        contradictions = list(numeric_contradictions)

        by_location_type: Dict[Tuple[str, str], List[Claim]] = defaultdict(list)
        for c in claims:
            if c.claim_type in (ClaimType.CAUSE, ClaimType.RESPONSIBILITY):
                key = ((c.location_reference or "").lower(), c.claim_type.value)
                by_location_type[key].append(c)

        for (location, ctype), cs in by_location_type.items():
            if len(cs) < 2:
                continue
            objects = {normalize_text(c.object, upper=False) or "" for c in cs if c.object}
            if len(objects) > 1:
                contradictions.append(
                    Contradiction(
                        contradiction_type=f"{ctype}_CLAIM_DIFFERENCE",
                        description=(
                            f"Differing {ctype.lower()} claims for location '{location}': {sorted(objects)}."
                        ),
                        materiality=Materiality.MATERIAL,
                        claim_ids=[c.claim_id for c in cs],
                        evidence_ids=[eid for c in cs for eid in c.evidence_ids],
                        possible_explanations=[
                            "different sources",
                            "early speculation",
                            "party statement vs independent finding",
                            "investigation ongoing",
                            "translation/framing difference",
                        ],
                        resolution_status="OPEN",
                    )
                )

        for corr in corrections:
            if corr.old_claim and corr.new_claim and corr.old_claim != corr.new_claim:
                contradictions.append(
                    Contradiction(
                        contradiction_type="CORRECTION_SUPERSESSION",
                        description=(
                            f"Correction supersedes claim: '{corr.old_claim}' -> '{corr.new_claim}'."
                        ),
                        materiality=Materiality.MATERIAL,
                        claim_ids=[corr.claim_id] if corr.claim_id else [],
                        evidence_ids=corr.evidence_ids,
                        possible_explanations=["publication corrected earlier reporting"],
                        resolution_status="CORRECTED",
                    )
                )

        for ret in retractions:
            contradictions.append(
                Contradiction(
                    contradiction_type="RETRACTION",
                    description=f"Retraction scope={ret.scope}, reason={ret.reason}.",
                    materiality=Materiality.CRITICAL if ret.scope == "ARTICLE" else Materiality.MATERIAL,
                    claim_ids=[ret.claim_id] if ret.claim_id else [],
                    evidence_ids=ret.evidence_ids,
                    possible_explanations=["source issue", "methodology issue", "copyright", "specific claim withdrawal"],
                    resolution_status="RETRACTED",
                )
            )

        return contradictions


# ======================================================================
# SECTION 10 — HYPOTHESES / FACT GATE / DUAL-AI REVIEW
# ======================================================================

class HypothesisEngine:
    def generate(
        self,
        events: List[Event],
        articles: List[Article],
        claims: List[Claim],
        numeric_summaries: List[Dict[str, Any]],
        contradictions: List[Contradiction],
        corrections: List[Correction],
        retractions: List[Retraction],
        source_independence: Dict[str, Any],
    ) -> List[Hypothesis]:
        hypotheses: List[Hypothesis] = []
        families = source_independence.get("families", [])
        raw_count = source_independence.get("raw_article_count", len(articles))
        family_count = source_independence.get("independent_source_family_count", len(families))

        for ev in events:
            hypotheses.append(
                Hypothesis(
                    statement=f"Event '{ev.title}' occurred substantially as first reported.",
                    supports=[f"{len(ev.supporting_source_families)} source families reported related claims"],
                    oppositions=["Early breaking reports may contain uncertain counts/identities"],
                    assumptions=["Articles describe same event, not separate incidents"],
                    unknowns=["exact cause", "full casualty scope", "responsibility"],
                    source_dependencies=ev.supporting_source_families,
                    temporal_constraints=[f"First publication {fmt_dt(ev.start_time)}"],
                    falsification_tests=[
                        "primary official record contradicts event occurrence",
                        "articles refer to different locations/times",
                        "all reports derive from one erroneous upstream claim",
                    ],
                )
            )

            if any(s.get("status") == "UPDATED" for s in numeric_summaries):
                hypotheses.append(
                    Hypothesis(
                        statement=f"Event '{ev.title}' occurred, but early numeric claims were revised.",
                        supports=["Numeric claim history shows multiple values"],
                        oppositions=["Different values may reflect different scopes/timestamps"],
                        assumptions=["Counts refer to same metric"],
                        unknowns=["final official count", "scope definition"],
                        source_dependencies=ev.supporting_source_families,
                        temporal_constraints=["Counts may change over time"],
                        falsification_tests=["latest official record confirms original count"],
                    )
                )

        if family_count == 1 and raw_count > 1:
            hypotheses.append(
                Hypothesis(
                    statement="Multiple articles are syndicated copies of one upstream report, not independent corroboration.",
                    supports=[f"raw_article_count={raw_count}", f"independent_source_family_count={family_count}"],
                    oppositions=["Some outlets may have independently added information"],
                    assumptions=["Source pedigree metadata is complete"],
                    unknowns=["hidden independent reporting"],
                    source_dependencies=families,
                    temporal_constraints=[],
                    falsification_tests=["independent local reporter or primary document is found"],
                )
            )

        if corrections:
            hypotheses.append(
                Hypothesis(
                    statement="Later correction invalidates or narrows earlier reporting.",
                    supports=[f"{len(corrections)} correction record(s) supplied"],
                    oppositions=["Correction may concern only a specific claim"],
                    assumptions=["Correction metadata is linked correctly"],
                    unknowns=["which downstream copies updated"],
                    source_dependencies=families,
                    temporal_constraints=[fmt_dt(c.correction_time) for c in corrections],
                    falsification_tests=["correction is itself retracted or clarified"],
                )
            )

        if retractions:
            hypotheses.append(
                Hypothesis(
                    statement="Retraction withdraws all or part of earlier reporting.",
                    supports=[f"{len(retractions)} retraction record(s) supplied"],
                    oppositions=["Retraction scope may be narrow"],
                    assumptions=["Retraction metadata is accurate"],
                    unknowns=["remaining supported facts if any"],
                    source_dependencies=families,
                    temporal_constraints=[fmt_dt(r.retraction_time) for r in retractions],
                    falsification_tests=["publisher clarifies retraction scope"],
                )
            )

        for con in contradictions[:20]:
            hypotheses.append(
                Hypothesis(
                    statement=f"Contradiction {con.contradiction_type} may reflect data quality, scope, timestamp, or translation difference rather than substantive conflict.",
                    supports=con.possible_explanations,
                    oppositions=["Some contradictions are genuine reporting errors"],
                    assumptions=["Claims are comparable"],
                    unknowns=["exact scope definitions"],
                    source_dependencies=[],
                    temporal_constraints=[],
                    falsification_tests=["primary source resolves metric/definition"],
                )
            )

        return hypotheses


class FactGate:
    def generate(
        self,
        *,
        case: Dict[str, Any],
        articles: List[Article],
        claims: List[Claim],
        quotes: List[Quote],
        primary_sources: List[PrimarySourceCandidate],
        corrections: List[Correction],
        retractions: List[Retraction],
        fact_checks: List[FactCheck],
        events: List[Event],
        numeric_summaries: List[Dict[str, Any]],
        contradictions: List[Contradiction],
        source_independence: Dict[str, Any],
        regional_comparison: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        facts: List[Fact] = []
        unknowns: List[str] = []
        limitations: List[str] = []
        gaps: List[KnowledgeGap] = []
        actions: List[NextAction] = []
        handoffs: List[SpecialistHandoff] = []

        article_by_id = {a.article_id: a for a in articles}
        claim_by_id = {c.claim_id: c for c in claims}

        for a in articles:
            facts.append(
                Fact(
                    statement=(
                        f"Article {a.article_id} published by {a.publication_id} at {fmt_dt(a.published_at)} "
                        f"reported headline: \"{excerpt(a.headline, 160)}\"."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=a.evidence_ids,
                    limitations=[
                        "This is a reporting fact, not proof that the headline claim is true.",
                        "Headline may compress, omit caveats, or differ from body.",
                    ],
                )
            )

        for c in claims[:300]:
            facts.append(
                Fact(
                    statement=(
                        f"Claim {c.claim_id} in article {c.article_id}: speaker/source '{c.speaker}' "
                        f"is reported to have made statement: \"{excerpt(c.text, 180)}\"."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=c.evidence_ids,
                    limitations=[
                        "Reported statement is not automatically true.",
                        "Speaker attribution is heuristic and may require manual review.",
                    ],
                )
            )

        for q in quotes[:200]:
            facts.append(
                Fact(
                    statement=(
                        f"Quote {q.quote_id} in article {q.article_id} attributes to '{q.speaker}': "
                        f"\"{excerpt(q.text, 180)}\"."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=q.evidence_ids,
                    limitations=[
                        "Quote proves reported utterance, not truth of underlying proposition.",
                        "Partial quote context may matter.",
                    ],
                )
            )

        facts.append(
            Fact(
                statement=(
                    f"Raw article count = {source_independence.get('raw_article_count', len(articles))}; "
                    f"independent source family count = {source_independence.get('independent_source_family_count', 0)}."
                ),
                status=FactStatus.FACT,
                evidence_ids=[],
                limitations=[
                    "Article count is not corroboration count.",
                    "Syndicated copies may share one upstream wire/press release/document.",
                ],
            )
        )

        for ev in events:
            status = FactStatus.SUPPORTED if ev.status in (ClaimState.SUPPORTED, ClaimState.STRONGLY_SUPPORTED) else FactStatus.CANDIDATE
            facts.append(
                Fact(
                    statement=(
                        f"Event cluster '{ev.title}' at location '{ev.location}' is {ev.status.value} "
                        f"based on {len(ev.supporting_source_families)} source families."
                    ),
                    status=status,
                    evidence_ids=[],
                    limitations=ev.limitations,
                )
            )

        for summary in numeric_summaries:
            current_claim = summary.get("current_best_supported_claim_id", "")
            facts.append(
                Fact(
                    statement=(
                        f"Numeric metric '{summary.get('metric')}' in '{summary.get('location')}' "
                        f"has status {summary.get('status')} with current best supported claim {current_claim}."
                    ),
                    status=FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=[
                        "Current best supported is not final truth.",
                        "Different counts may reflect timestamps, scopes, or preliminary vs confirmed figures.",
                    ],
                )
            )

        for corr in corrections:
            facts.append(
                Fact(
                    statement=(
                        f"Correction {corr.correction_id} at {fmt_dt(corr.correction_time)} changed "
                        f"'{corr.old_claim}' to '{corr.new_claim}'."
                    ),
                    status=FactStatus.CORRECTED,
                    evidence_ids=corr.evidence_ids,
                    limitations=["Correction may apply to specific claim, not entire article."],
                )
            )

        for ret in retractions:
            facts.append(
                Fact(
                    statement=(
                        f"Retraction {ret.retraction_id} at {fmt_dt(ret.retraction_time)} scope={ret.scope}, "
                        f"reason={ret.reason}."
                    ),
                    status=FactStatus.RETRACTED,
                    evidence_ids=ret.evidence_ids,
                    limitations=["Retraction does not automatically make every related detail false; preserve scope."],
                )
            )

        for fc in fact_checks:
            facts.append(
                Fact(
                    statement=f"Fact-check {fc.fact_check_id} rated target as {fc.rating} by {fc.source}.",
                    status=FactStatus.CANDIDATE,
                    evidence_ids=fc.evidence_ids,
                    limitations=fc.limitations,
                )
            )

        for ps in primary_sources[:100]:
            facts.append(
                Fact(
                    statement=(
                        f"Primary-source candidate {ps.source_id} for article {ps.article_id}: "
                        f"{ps.source_type.value} reference '{ps.reference}'."
                    ),
                    status=FactStatus.CANDIDATE,
                    evidence_ids=ps.evidence_ids,
                    limitations=ps.limitations,
                )
            )

        for con in contradictions[:100]:
            facts.append(
                Fact(
                    statement=f"Open contradiction: {con.contradiction_type} — {con.description}",
                    status=FactStatus.DISPUTED,
                    evidence_ids=con.evidence_ids,
                    limitations=con.possible_explanations,
                )
            )
            unknowns.append(f"Unresolved contradiction: {con.contradiction_type}")

        for reg in regional_comparison:
            facts.append(
                Fact(
                    statement=f"Regional reporting comparison: {reg}",
                    status=FactStatus.FACT,
                    evidence_ids=[],
                    limitations=["Regional framing difference is not automatically factual disagreement."],
                )
            )

        if source_independence.get("status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            limitations.append("Source independence is dependent or unknown; do not inflate confidence from syndicated copies.")
            gaps.append(
                KnowledgeGap(
                    description="Independent source family not established for major claim cluster.",
                    importance="HIGH",
                    recommended_source="independent local reporting / primary document / official record",
                    specialist="NEWSINT / SEARCHINT / DOCINT",
                    expected_information_value="Prevents wire/press-release double counting.",
                )
            )

        for a in articles:
            if a.stale_correction_risk:
                gaps.append(
                    KnowledgeGap(
                        description=f"Article {a.article_id} may be stale relative to correction.",
                        importance="HIGH",
                        recommended_source="updated article version / correction page",
                        specialist="NEWSINT",
                        expected_information_value="Prevents historical-to-current contamination.",
                    )
                )
            if a.article_type in (ArticleType.BREAKING_NEWS, ArticleType.LIVE_BLOG):
                limitations.append(f"Article {a.article_id} is breaking/live-blog style; early claims may be revised.")
            if a.article_type in (ArticleType.OPINION, ArticleType.EDITORIAL, ArticleType.ANALYSIS):
                limitations.append(f"Article {a.article_id} is opinion/analysis; framing is not primary evidence.")
            if a.article_type == ArticleType.PRESS_RELEASE:
                limitations.append(f"Article {a.article_id} is press release; issuer claim is not independent verification.")
            if a.article_type == ArticleType.SPONSORED_CONTENT:
                limitations.append(f"Article {a.article_id} is sponsored/native content; not ordinary independent journalism.")
            if a.article_type == ArticleType.SATIRE:
                limitations.append(f"Article {a.article_id} is satire/parody; not factual reporting.")

        limitations.extend(
            [
                "Article is not fact.",
                "Headline is not article body.",
                "Breaking news is not verified news.",
                "Multiple outlets are not multiple sources.",
                "Syndicated copies are not independent reporting.",
                "Press release is not independent corroboration.",
                "Official claim is not automatically verified fact.",
                "Quote is not truth of quoted proposition.",
                "Virality is not corroboration.",
                "Popular outlet is not automatically reliable.",
                "Small outlet is not automatically unreliable.",
                "Bias is not falsehood.",
                "Analysis is not primary evidence.",
                "Fact-check is secondary analysis; inspect method.",
                "Article publication time is not event time.",
                "First report is not best report.",
                "Latest report is not independent report.",
                "Early casualty count is not final count.",
                "Arrest is not guilt.",
                "Allegation is not finding.",
                "Same narrative is not coordination.",
                "False information is not disinformation without intent evidence.",
                "AI agreement is not news corroboration.",
            ]
        )

        unknowns.extend(
            [
                "ultimate truth of contested claims",
                "exact event cause",
                "responsibility",
                "final official counts",
                "private personal details not necessary for case",
                "intent of actors",
                "coordination behind similar narratives",
            ]
        )

        gaps.extend(
            [
                KnowledgeGap(description="Primary source not retrieved.", importance="HIGH", recommended_source="official statement/court filing/company filing/research paper", specialist="DOCINT", expected_information_value="Moves claim from reported to documented."),
                KnowledgeGap(description="Wire/syndication lineage incomplete.", importance="HIGH", recommended_source="wire attribution, canonical URLs, article versions", specialist="NEWSINT / WEBINT", expected_information_value="Prevents duplicate counting."),
                KnowledgeGap(description="Correction/retraction status unknown for downstream copies.", importance="HIGH", recommended_source="publisher correction page / archived versions", specialist="NEWSINT", expected_information_value="Prevents stale claim propagation."),
                KnowledgeGap(description="Visual/media claim not forensically verified.", importance="MEDIUM", recommended_source="original image/video metadata and context", specialist="IMINT / VIDINT / GEOINT", expected_information_value="Prevents miscaptioned media acceptance."),
                KnowledgeGap(description="Technical/cyber claim not verified.", importance="MEDIUM", recommended_source="vendor advisory, regulator notice, independent technical analysis", specialist="CTI / INCIDENTINT / VULNINT", expected_information_value="Prevents headline-as-technical-fact error."),
                KnowledgeGap(description="Scientific/health claim not verified against study.", importance="MEDIUM", recommended_source="paper, methods, limitations", specialist="ACADEMICINT", expected_information_value="Prevents news-summary distortion."),
            ]
        )

        actions.extend(
            [
                NextAction(description="Retrieve primary source document or official statement.", rationale="Moves claim from reported to documented where lawful/public/licensed.", priority="HIGH"),
                NextAction(description="Compare article versions and correction pages.", rationale="Detects superseded counts and stale syndicated copies.", priority="HIGH"),
                NextAction(description="Identify independent local reporting separate from wire family.", rationale="Improves source independence without doubling counted URLs.", priority="HIGH"),
                NextAction(description="Hand off visual claims to IMINT/VIDINT/GEOINT.", rationale="Captions and screenshots are not image truth.", priority="MEDIUM"),
                NextAction(description="Hand off technical claims to CTI/INCIDENTINT/VULNINT.", rationale="News reporting is not technical proof.", priority="MEDIUM"),
                NextAction(description="Hand off legal claims to LEGALINT for charge/indictment/verdict distinctions.", rationale="Arrest/allegation is not guilt/finding.", priority="MEDIUM"),
                NextAction(description="Apply privacy minimization to victims/minors/private addresses.", rationale="News may contain sensitive personal details not necessary for case.", priority="HIGH"),
            ]
        )

        guard = PolicyGuard()
        actions = [a for a in actions if guard.is_safe_action(a.description)]

        handoffs.extend(
            [
                SpecialistHandoff(specialist="SEARCHINT", reason="Find additional independent sources and primary documents."),
                SpecialistHandoff(specialist="WEBINT", reason="Collect/preserve public web pages and archives lawfully."),
                SpecialistHandoff(specialist="SOCMINT", reason="Analyze upstream social posts quoted by articles."),
                SpecialistHandoff(specialist="DISINFOINT", reason="Assess coordination/deception only with appropriate evidence."),
                SpecialistHandoff(specialist="DOCINT", reason="Retrieve and analyze court/regulatory/company documents."),
                SpecialistHandoff(specialist="IMINT", reason="Verify images/photos used in reporting."),
                SpecialistHandoff(specialist="VIDINT", reason="Verify video frames and sequences."),
                SpecialistHandoff(specialist="GEOINT", reason="Verify claimed locations of imagery/events."),
                SpecialistHandoff(specialist="SATINT", reason="Verify satellite imagery claims."),
                SpecialistHandoff(specialist="ENVINT", reason="Verify weather/disaster/environmental claims."),
                SpecialistHandoff(specialist="CORPINT", reason="Resolve company/ownership/corporate claims."),
                SpecialistHandoff(specialist="FININT", reason="Resolve market/financial claims."),
                SpecialistHandoff(specialist="LEGALINT", reason="Resolve legal status/charge/verdict distinctions."),
                SpecialistHandoff(specialist="ACADEMICINT", reason="Verify scientific/health study claims."),
                SpecialistHandoff(specialist="CTI", reason="Verify cyber threat intelligence claims."),
            ]
        )

        return {
            "facts": facts,
            "unknowns": sorted(set(unknowns)),
            "limitations": sorted(set(limitations)),
            "knowledge_gaps": gaps,
            "next_actions": actions,
            "specialist_handoffs": handoffs,
        }


class DualAIReviewer:
    def review(
        self,
        *,
        articles: List[Article],
        claims: List[Claim],
        events: List[Event],
        contradictions: List[Contradiction],
        corrections: List[Correction],
        retractions: List[Retraction],
        source_independence: Dict[str, Any],
        case: Dict[str, Any],
    ) -> Dict[str, Any]:
        notes: List[str] = []
        status = ReviewStatus.AGREE

        if not articles:
            status = ReviewStatus.INSUFFICIENT_EVIDENCE
            notes.append("No articles supplied.")

        if any(a.syndication_state in (SyndicationState.SYNDICATED_COPY, SyndicationState.PARTIALLY_REWRITTEN, SyndicationState.DERIVED_REPORT) for a in articles):
            notes.append("Syndicated/derived copies present; do not count URLs as independent sources.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(a.article_type == ArticleType.BREAKING_NEWS for a in articles):
            notes.append("Breaking-news material present; early counts/identities may be revised.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(a.article_type in (ArticleType.OPINION, ArticleType.EDITORIAL, ArticleType.ANALYSIS) for a in articles):
            notes.append("Opinion/analysis present; framing is not primary evidence.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(a.source_type in (SourceType.PRESS_RELEASE, SourceType.OFFICIAL_STATEMENT) for a in articles):
            notes.append("Press release/official statement present; issuer claim is not independent verification.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if corrections or retractions:
            notes.append("Corrections/retractions present; preserve version history and avoid stale claims.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if contradictions:
            notes.append("Open contradictions remain; final claims should stay conservative.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if source_independence.get("status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            notes.append("Source independence dependent/unknown; multiple reports may share one upstream family.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        human_review_required = False
        tags = [str(x).upper() for x in case.get("sensitivity_tags", [])]

        if any(c.claim_type in (ClaimType.IDENTITY, ClaimType.LEGAL, ClaimType.RESPONSIBILITY) for c in claims):
            human_review_required = True
            notes.append("Identity/legal/responsibility claims present; human review required before publication/action.")

        if any(c.numeric_unit in {"killed", "deaths", "fatalities", "injured"} for c in claims):
            human_review_required = True
            notes.append("Casualty/injury claims present; verify with primary official/medical/local independent sources.")

        if any(t in {"ELECTION", "MARKET_SENSITIVE", "PUBLIC_HEALTH", "TERRORISM", "CONFLICT", "CRIMINAL_ALLEGATION", "JOURNALIST_SAFETY", "SOURCE_PROTECTION"} for t in tags):
            human_review_required = True
            notes.append("Sensitive consequential domain supplied; human governance required.")

        return {
            "status": status.value,
            "skeptic_notes": notes,
            "rule": "AI agreement is not independent news corroboration.",
            "human_review_required": human_review_required,
        }


# ======================================================================
# SECTION 11 — GRAPHICAL MEMORY / REPORT GENERATOR
# ======================================================================

class GraphicalMemory:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, node_type: str, properties: Dict[str, Any]) -> None:
        self.nodes[node_id] = {"type": node_type, "properties": properties}

    def add_edge(self, source_id: str, relation: str, target_id: str, properties: Optional[Dict[str, Any]] = None) -> None:
        self.edges.append(
            {
                "source_id": source_id,
                "relation": relation,
                "target_id": target_id,
                "properties": properties or {},
            }
        )

    def write_result(self, result: NEWSINTResult) -> Dict[str, Any]:
        for p in result.publications:
            self.add_node(p.publication_id, "Publication", {"name": p.name, "country": p.country, "type": p.outlet_type})

        for w in result.wires:
            self.add_node(w.wire_id, "WireService", {"name": w.name, "group": w.independence_group})

        for a in result.articles:
            self.add_node(
                a.article_id,
                "Article",
                {
                    "publication_id": a.publication_id,
                    "headline": a.headline,
                    "published_at": fmt_dt(a.published_at),
                    "updated_at": fmt_dt(a.updated_at),
                    "article_type": a.article_type.value,
                    "syndication_state": a.syndication_state.value,
                    "source_family": a.source_family,
                    "fingerprint": a.fingerprint,
                    "stale_correction_risk": a.stale_correction_risk,
                },
            )
            if a.publication_id:
                self.add_edge(a.publication_id, "PUBLISHED", a.article_id)
            if a.wire_service_id:
                self.add_edge(a.article_id, "DERIVED_FROM_WIRE", a.wire_service_id)
            if a.syndicated_from:
                self.add_edge(a.article_id, "SYNDICATED_FROM", a.syndicated_from)
            if a.duplicate_of:
                self.add_edge(a.article_id, "DUPLICATE_OF", a.duplicate_of)
            if a.near_duplicate_of:
                self.add_edge(a.article_id, "NEAR_DUPLICATE_OF", a.near_duplicate_of)

        for c in result.claims[:2000]:
            self.add_node(c.claim_id, "Claim", {"article_id": c.article_id, "type": c.claim_type.value, "state": c.verification_state.value, "text_excerpt": excerpt(c.text, 180)})
            self.add_edge(c.article_id, "REPORTS_CLAIM", c.claim_id)

        for q in result.quotes[:2000]:
            self.add_node(q.quote_id, "Quote", {"article_id": q.article_id, "speaker": q.speaker, "text_excerpt": excerpt(q.text, 180)})
            self.add_edge(q.article_id, "CONTAINS_QUOTE", q.quote_id)

        for ev in result.events:
            self.add_node(ev.event_id, "Event", {"title": ev.title, "location": ev.location, "status": ev.status.value})
            for aid in ev.supporting_articles:
                self.add_edge(aid, "REPORTS_EVENT", ev.event_id)

        for corr in result.corrections:
            self.add_node(corr.correction_id, "Correction", {"article_id": corr.article_id, "claim_id": corr.claim_id, "time": fmt_dt(corr.correction_time)})
            if corr.article_id:
                self.add_edge(corr.correction_id, "CORRECTS", corr.article_id)
            if corr.claim_id:
                self.add_edge(corr.correction_id, "CORRECTS", corr.claim_id)

        for ret in result.retractions:
            self.add_node(ret.retraction_id, "Retraction", {"article_id": ret.article_id, "claim_id": ret.claim_id, "scope": ret.scope})
            if ret.article_id:
                self.add_edge(ret.retraction_id, "RETRACTS", ret.article_id)

        for f in result.facts[:2000]:
            self.add_node(f.fact_id, "Fact", {"statement": f.statement, "status": f.status.value})
            for ev in f.evidence_ids[:20]:
                self.add_edge(f.fact_id, "SUPPORTED_BY", ev)

        for h in result.hypotheses[:1000]:
            self.add_node(h.hypothesis_id, "Hypothesis", {"statement": h.statement})

        for con in result.contradictions[:1000]:
            self.add_node(con.contradiction_id, "Contradiction", {"type": con.contradiction_type, "materiality": con.materiality.value})
            for cid in con.claim_ids[:20]:
                self.add_edge(cid, "CONTRADICTS", con.contradiction_id)

        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "sample_nodes": list(self.nodes.keys())[:20],
        }


class ReportGenerator:
    def generate(self, result: NEWSINTResult) -> str:
        lines: List[str] = []

        def section(title: str) -> None:
            lines.append("")
            lines.append(title.upper())
            lines.append("-" * len(title))

        lines.append("=" * 72)
        lines.append("TRACEATLAS — NEWSINT REPORT")
        lines.append("=" * 72)
        lines.append(f"Case ID: {result.case_id}")
        lines.append(f"Task ID: {result.task_id}")
        lines.append(f"Objective: {result.objective}")
        lines.append(f"Status: {result.status}")
        lines.append(f"Policy Decision: {result.policy_decision.value}")

        section("Safety / Legal / Privacy Boundary")
        lines.append("- Public/licensed news monitoring, claim verification, source pedigree, correction/retraction tracking, and evidence-linked reporting only.")
        lines.append("- No paywall bypass, login bypass, credential theft, CAPTCHA circumvention, private account scraping, journalist impersonation, deceptive source contact, harassment, propaganda, political persuasion, fabrication, or private data collection.")
        lines.append("- Full copyrighted articles are not reproduced; reports use metadata, claims, short excerpts, fingerprints, and citations.")
        for flag in result.safety_flags:
            lines.append(f"- Safety: {flag}")
        for flag in result.privacy_flags:
            lines.append(f"- Privacy: {flag}")

        section("News Collection Summary")
        lines.append(f"- Articles: {len(result.articles)}")
        lines.append(f"- Claims: {len(result.claims)}")
        lines.append(f"- Quotes: {len(result.quotes)}")
        lines.append(f"- Events: {len(result.events)}")
        lines.append(f"- Corrections: {len(result.corrections)}")
        lines.append(f"- Retractions: {len(result.retractions)}")
        lines.append(f"- Raw article count: {result.source_independence.get('raw_article_count', len(result.articles))}")
        lines.append(f"- Independent source family count: {result.source_independence.get('independent_source_family_count', 0)}")

        section("Publications")
        for p in result.publications:
            lines.append(f"- {p.publication_id}: name={p.name}, country={p.country}, type={p.outlet_type}, ownership={p.ownership_context}, corrections_policy={p.corrections_policy}")
            if p.limitations:
                lines.append(f"  limitations={'; '.join(p.limitations)}")

        section("Wire Services")
        for w in result.wires:
            lines.append(f"- {w.wire_id}: name={w.name}, group={w.independence_group}, reliability={w.reliability}")
            if w.limitations:
                lines.append(f"  limitations={'; '.join(w.limitations)}")

        section("Article Inventory")
        for a in result.articles:
            lines.append(
                f"- {a.article_id}: publication={a.publication_id}, type={a.article_type.value}, "
                f"published={fmt_dt(a.published_at)}, updated={fmt_dt(a.updated_at)}, language={a.language}"
            )
            lines.append(f"  headline: {excerpt(a.headline, 180)}")
            lines.append(f"  body_excerpt: {excerpt(a.normalized_body, 220)}")
            lines.append(f"  url={a.url}")
            lines.append(f"  canonical_url={a.canonical_url}")
            lines.append(f"  content_hash={a.content_hash}")
            lines.append(f"  fingerprint={a.fingerprint}")
            lines.append(f"  syndication_state={a.syndication_state.value}, source_family={a.source_family}")
            lines.append(f"  duplicate_of={a.duplicate_of}, near_duplicate_of={a.near_duplicate_of}, stale_correction_risk={a.stale_correction_risk}")
            if a.limitations:
                lines.append(f"  limitations={'; '.join(a.limitations[:5])}")

        section("Wire / Syndication / Duplicate Analysis")
        for a in result.articles:
            lines.append(
                f"- {a.article_id}: syndication={a.syndication_state.value}, family={a.source_family}, "
                f"duplicate_of={a.duplicate_of or '-'}, near_duplicate_of={a.near_duplicate_of or '-'}, "
                f"wire={a.wire_service_id or '-'}, syndicated_from={a.syndicated_from or '-'}"
            )

        section("Primary Sources")
        if not result.primary_sources:
            lines.append("- None discovered.")
        for ps in result.primary_sources:
            lines.append(f"- {ps.source_id}: article={ps.article_id}, type={ps.source_type.value}, reference={ps.reference}, confidence={ps.confidence.value}")
            for lim in ps.limitations:
                lines.append(f"  limitation: {lim}")

        section("Source Pedigree / Independence")
        lines.append(f"- Status: {result.source_independence.get('status', 'UNKNOWN')}")
        lines.append(f"- Families: {result.source_independence.get('families', [])}")
        for note in result.source_independence.get("notes", []):
            lines.append(f"  - {note}")

        section("Claims")
        for c in result.claims[:200]:
            lines.append(
                f"- {c.claim_id}: article={c.article_id}, type={c.claim_type.value}, speaker={c.speaker}, "
                f"certainty={c.certainty.value}, state={c.verification_state.value}, numeric={c.numeric_value} {c.numeric_unit}"
            )
            lines.append(f"  text: {excerpt(c.text, 220)}")
            if c.limitations:
                lines.append(f"  limitations: {'; '.join(c.limitations[:3])}")

        section("Quotes")
        for q in result.quotes[:100]:
            lines.append(f"- {q.quote_id}: article={q.article_id}, speaker={q.speaker}, attribution={q.attribution_type}")
            lines.append(f"  quote: \"{excerpt(q.text, 220)}\"")

        section("Events")
        for ev in result.events:
            lines.append(
                f"- {ev.event_id}: title={ev.title}, type={ev.event_type}, location={ev.location}, "
                f"start={fmt_dt(ev.start_time)}, status={ev.status.value}, confidence={ev.confidence.value}"
            )
            lines.append(f"  supporting_articles={ev.supporting_articles}")
            lines.append(f"  source_families={ev.supporting_source_families}")
            for lim in ev.limitations:
                lines.append(f"  limitation: {lim}")

        section("Narratives")
        for n in result.narratives:
            lines.append(f"- {n.narrative_id}: central_claim={n.central_claim}, state={n.verification_state.value}, families={n.source_families}")
            for lim in n.limitations:
                lines.append(f"  limitation: {lim}")

        section("Timelines")
        lines.append("[Publication Timeline]")
        for item in result.publication_timeline[:100]:
            lines.append(f"- {item}")
        lines.append("[Event Timeline]")
        for item in result.event_timeline[:100]:
            lines.append(f"- {item}")
        lines.append("[Knowledge Timeline]")
        for item in result.knowledge_timeline[:100]:
            lines.append(f"- {item}")

        section("Numeric Claims")
        for item in result.numeric_claims:
            lines.append(f"- {item}")

        section("Regional Reporting Comparison")
        for item in result.regional_reporting_comparison:
            lines.append(f"- {item}")

        section("Corrections / Retractions / Fact Checks")
        for c in result.corrections:
            lines.append(f"- Correction {c.correction_id}: article={c.article_id}, claim={c.claim_id}, time={fmt_dt(c.correction_time)}, old='{c.old_claim}', new='{c.new_claim}', reason={c.reason}")
        for r in result.retractions:
            lines.append(f"- Retraction {r.retraction_id}: article={r.article_id}, claim={r.claim_id}, scope={r.scope}, time={fmt_dt(r.retraction_time)}, reason={r.reason}")
        for f in result.fact_checks:
            lines.append(f"- FactCheck {f.fact_check_id}: target_claim={f.target_claim_id}, rating={f.rating}, source={f.source}")

        section("Facts")
        for f in result.facts[:250]:
            lines.append(f"- [{f.status.value}] {f.statement}")
            if f.limitations:
                lines.append(f"  limitations: {'; '.join(f.limitations)}")

        section("Contradictions")
        if not result.contradictions:
            lines.append("- None detected.")
        for c in result.contradictions[:100]:
            lines.append(f"- {c.contradiction_id}: {c.contradiction_type} | materiality={c.materiality.value} | status={c.resolution_status}")
            lines.append(f"  description: {c.description}")
            lines.append(f"  possible_explanations: {c.possible_explanations}")

        section("Competing Hypotheses / ACH-lite")
        for h in result.hypotheses[:100]:
            lines.append(f"- {h.hypothesis_id}: {h.statement}")
            lines.append(f"  supports: {h.supports}")
            lines.append(f"  oppositions: {h.oppositions}")
            lines.append(f"  assumptions: {h.assumptions}")
            lines.append(f"  unknowns: {h.unknowns}")
            lines.append(f"  source_dependencies: {h.source_dependencies}")
            lines.append(f"  falsification: {h.falsification_tests}")

        section("Unknowns / Knowledge Gaps")
        for u in result.unknowns[:100]:
            lines.append(f"- Unknown: {u}")
        for g in result.knowledge_gaps[:100]:
            lines.append(f"- Gap: {g.description} | importance={g.importance} | specialist={g.specialist}")

        section("Next Actions")
        if not result.next_actions:
            lines.append("- None.")
        for a in result.next_actions:
            lines.append(f"- {a.description} ({a.priority}) — {a.rationale}")

        section("Specialist Handoffs")
        if not result.specialist_handoffs:
            lines.append("- None.")
        for h in result.specialist_handoffs:
            lines.append(f"- {h.specialist}: {h.reason}")

        section("Limitations")
        for lim in result.limitations:
            lines.append(f"- {lim}")

        section("Dual-AI Review")
        lines.append(f"- Status: {result.review.get('status', 'N/A')}")
        for n in result.review.get("skeptic_notes", []):
            lines.append(f"  - {n}")
        if result.review.get("human_review_required"):
            lines.append("  - Human review required before publication, accusation, harassment-adjacent use, or consequential action.")

        section("Required Analyst Summary")
        if result.events:
            ev = result.events[0]
            lines.append(f"EVENT: {ev.title} reportedly occurred at {ev.location}.")
            lines.append(f"REPORTING: {result.source_independence.get('raw_article_count', len(result.articles))} articles identified.")
            lines.append(f"SOURCE LINEAGE: {result.source_independence.get('independent_source_family_count', 0)} independent source families.")
            lines.append(f"FAMILIES: {result.source_independence.get('families', [])}")
            if result.numeric_claims:
                num = result.numeric_claims[0]
                lines.append(f"NUMERIC: metric={num.get('metric')}, status={num.get('status')}, current_best_claim={num.get('current_best_supported_claim_id')}.")
            if result.corrections:
                lines.append(f"CORRECTIONS: {len(result.corrections)} correction(s) tracked; early claims may be superseded.")
            if result.retractions:
                lines.append(f"RETRACTIONS: {len(result.retractions)} retraction(s) tracked; preserve scope.")
            lines.append(f"ASSESSMENT: EVENT_STATUS={ev.status.value}; CAUSE={'INCONCLUSIVE' if not any(c.claim_type == ClaimType.CAUSE and c.verification_state == ClaimState.SUPPORTED for c in result.claims) else 'PARTIAL'}; RESPONSIBILITY=NOT_ESTABLISHED.")
            lines.append("NEXT ACTION: Verify primary/official/independent local evidence rather than increasing article count with syndicated copies.")
        else:
            lines.append("EVENT: No event cluster resolved.")
            lines.append("NEXT ACTION: Retrieve primary sources, independent local reporting, and article versions.")

        lines.append("")
        lines.append("=" * 72)
        lines.append("END REPORT")
        lines.append("=" * 72)
        return "\n".join(lines)


# ======================================================================
# SECTION 12 — NEWSINT AI EMPLOYEE
# ======================================================================

class NEWSIntelligenceEmployee:
    def __init__(self, mode: ModelMode = ModelMode.LOCAL_ONLY):
        self.mode = mode
        self.policy = PolicyGuard()
        self.injection_defense = PromptInjectionDefense()
        self.ingestor = NEWSINTIngestor(injection_defense=self.injection_defense)
        self.quote_extractor = QuoteExtractor()
        self.claim_extractor = ClaimExtractor()
        self.primary_source_discoverer = PrimarySourceDiscoverer()
        self.deduplicator = ArticleDeduplicator()
        self.pedigree_resolver = SourcePedigreeResolver()
        self.independence_analyzer = SourceIndependenceAnalyzer()
        self.correction_tracker = CorrectionTracker()
        self.timeline_builder = TimelineBuilder()
        self.event_builder = EventBuilder()
        self.narrative_tracker = NarrativeTracker()
        self.numeric_tracker = NumericClaimTracker()
        self.contradiction_detector = ContradictionDetector()
        self.hypothesis_engine = HypothesisEngine()
        self.fact_gate = FactGate()
        self.reviewer = DualAIReviewer()
        self.memory = GraphicalMemory()
        self.reporter = ReportGenerator()

    def run_case(self, case: Dict[str, Any]) -> NEWSINTResult:
        case_id = str(case.get("case_id", new_id("CASE")))
        task_id = str(case.get("task_id", new_id("TASK")))
        objective = str(case.get("objective", ""))
        questions = case.get("questions", [])

        # Policy checks user intent, not untrusted article content.
        request_text = objective + "\n" + "\n".join(str(q) for q in questions)
        request_text += "\n" + "\n".join(str(x) for x in case.get("topics", []))
        request_text += "\n" + "\n".join(str(x) for x in case.get("keywords", []))

        policy = self.policy.check_request(request_text)

        if policy.decision == PolicyDecision.POLICY_BLOCKED:
            return NEWSINTResult(
                case_id=case_id,
                task_id=task_id,
                objective=objective,
                status="POLICY_BLOCKED",
                policy_decision=PolicyDecision.POLICY_BLOCKED,
                report=(
                    "POLICY_BLOCKED\n\n"
                    "This request seeks prohibited NEWSINT paywall bypass, propaganda, harassment, "
                    "fabrication, or private-data collection guidance. Lawful alternative: public/licensed "
                    "news monitoring, article normalization, claim extraction, source pedigree, wire/syndication "
                    "detection, duplicate detection, correction/retraction tracking, event timeline reconstruction, "
                    "source independence, fact gating, and evidence-linked reporting without bypassing access "
                    "controls or generating persuasion/propaganda."
                ),
                safety_flags=[
                    "No paywall/login/CAPTCHA bypass provided.",
                    "No subscription credential theft or private account scraping provided.",
                    "No journalist impersonation, deceptive source contact, or harassment provided.",
                    "No propaganda, political persuasion campaign, or fabricated article/quote/source/event provided.",
                ],
                limitations=[policy.reason],
            )

        ingested = self.ingestor.ingest_case(case)
        articles = ingested.articles
        wire_ids = {w.wire_id for w in ingested.wires}

        # Quotes first, then fingerprints.
        for a in articles:
            a.quotes = self.quote_extractor.extract(a)
            a.fingerprint = self._fingerprint(a)

        self.deduplicator.analyze(articles, wire_ids)
        source_families = self.pedigree_resolver.resolve(articles, wire_ids)

        claims: List[Claim] = []
        for a in articles:
            a.claims = self.claim_extractor.extract(a)
            claims.extend(a.claims)

        quotes = [q for a in articles for q in a.quotes]
        primary_sources = self.primary_source_discoverer.discover(articles)

        self.correction_tracker.apply(articles, claims, ingested.corrections, ingested.retractions)

        events = self.event_builder.build(articles, claims, case)
        narratives = self.narrative_tracker.track(events, articles)
        timelines = self.timeline_builder.build(articles, claims, events)

        numeric_summaries, numeric_contradictions = self.numeric_tracker.track(claims)
        contradictions = self.contradiction_detector.detect(
            claims=claims,
            numeric_contradictions=numeric_contradictions,
            corrections=ingested.corrections,
            retractions=ingested.retractions,
        )

        source_independence = self.independence_analyzer.assess(articles, source_families)
        regional_comparison = self._regional_comparison(articles, ingested.publications)

        hypotheses = self.hypothesis_engine.generate(
            events=events,
            articles=articles,
            claims=claims,
            numeric_summaries=numeric_summaries,
            contradictions=contradictions,
            corrections=ingested.corrections,
            retractions=ingested.retractions,
            source_independence=source_independence,
        )

        fact_out = self.fact_gate.generate(
            case=case,
            articles=articles,
            claims=claims,
            quotes=quotes,
            primary_sources=primary_sources,
            corrections=ingested.corrections,
            retractions=ingested.retractions,
            fact_checks=ingested.fact_checks,
            events=events,
            numeric_summaries=numeric_summaries,
            contradictions=contradictions,
            source_independence=source_independence,
            regional_comparison=regional_comparison,
        )

        review = self.reviewer.review(
            articles=articles,
            claims=claims,
            events=events,
            contradictions=contradictions,
            corrections=ingested.corrections,
            retractions=ingested.retractions,
            source_independence=source_independence,
            case=case,
        )

        status = "PARTIAL"
        if not articles:
            status = "ARTICLE_UNAVAILABLE"
        elif not claims:
            status = "CLAIM_UNRESOLVED"
        elif contradictions:
            status = "PARTIAL_DISPUTED_REPORTING"
        elif review.get("human_review_required"):
            status = "PARTIAL_HUMAN_REVIEW_REQUIRED"
        elif events and any(ev.status in (ClaimState.SUPPORTED, ClaimState.STRONGLY_SUPPORTED) for ev in events):
            status = "SUCCEEDED"
        elif source_independence.get("independent_source_family_count", 0) >= 2:
            status = "SUPPORTED_BY_MULTIPLE_FAMILIES"

        privacy_flags = []
        if self.mode == ModelMode.LOCAL_ONLY:
            privacy_flags.append("LOCAL_ONLY mode selected; sensitive media-monitoring case data should remain local.")
        elif self.mode == ModelMode.CLOUD:
            privacy_flags.append("CLOUD mode requires public/sanitized/redacted/policy-approved news data only.")
        else:
            privacy_flags.append("HYBRID mode requires routing controls, tenant isolation, and purpose limitation.")

        privacy_flags.extend(
            [
                "Victim/minor/private-address details are minimized unless strictly necessary and authorized.",
                "Full copyrighted article text is not reproduced in reports.",
                "Source protection and journalist safety constraints apply.",
            ]
        )

        result = NEWSINTResult(
            case_id=case_id,
            task_id=task_id,
            objective=objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW,
            evidence=ingested.evidence,
            publications=ingested.publications,
            wires=ingested.wires,
            journalists=ingested.journalists,
            articles=articles,
            claims=claims,
            quotes=quotes,
            primary_sources=primary_sources,
            corrections=ingested.corrections,
            retractions=ingested.retractions,
            fact_checks=ingested.fact_checks,
            events=events,
            narratives=narratives,
            publication_timeline=timelines["publication_timeline"],
            event_timeline=timelines["event_timeline"],
            knowledge_timeline=timelines["knowledge_timeline"],
            numeric_claims=numeric_summaries,
            regional_reporting_comparison=regional_comparison,
            source_families=source_families,
            source_independence=source_independence,
            contradictions=contradictions,
            hypotheses=hypotheses,
            facts=fact_out["facts"],
            knowledge_gaps=fact_out["knowledge_gaps"],
            next_actions=fact_out["next_actions"],
            specialist_handoffs=fact_out["specialist_handoffs"],
            review=review,
            unknowns=fact_out["unknowns"],
            limitations=fact_out["limitations"],
            safety_flags=[
                "No paywall/login/CAPTCHA bypass.",
                "No journalist impersonation or deceptive source contact.",
                "No harassment of reporters/subjects.",
                "No propaganda or political persuasion campaign generation.",
                "No fabrication of articles, quotes, sources, or events.",
                "Article is not fact; headline is not body; breaking is not verified.",
                "Multiple outlets are not multiple sources; count source families.",
                "Human review required for consequential publication/legal/public-safety use.",
            ],
            privacy_flags=privacy_flags,
        )

        result.graph = self.memory.write_result(result)
        result.report = self.reporter.generate(result)
        return result

    @staticmethod
    def _fingerprint(article: Article) -> str:
        quote_texts = sorted(normalize_text(q.text, upper=False) or "" for q in article.quotes)
        source_order = "|".join(sorted(article.quoted_sources))
        parts = [
            article.content_hash,
            normalize_text(article.headline, upper=False) or "",
            "|".join(quote_texts),
            article.wire_service_id or "",
            article.syndicated_from or "",
            source_order,
        ]
        return sha256_text("|".join(parts))

    @staticmethod
    def _regional_comparison(articles: List[Article], publications: List[Publication]) -> List[Dict[str, Any]]:
        pub_by_id = {p.publication_id: p for p in publications}
        by_country: Dict[str, List[str]] = defaultdict(list)
        by_type: Dict[str, List[str]] = defaultdict(list)

        for a in articles:
            pub = pub_by_id.get(a.publication_id)
            country = pub.country if pub else "UNKNOWN"
            outlet_type = pub.outlet_type if pub else "UNKNOWN"
            by_country[country].append(a.article_id)
            by_type[outlet_type].append(a.article_id)

        rows = []
        for country, aids in by_country.items():
            rows.append({"dimension": "country", "value": country, "article_ids": aids, "count": len(aids)})
        for outlet_type, aids in by_type.items():
            rows.append({"dimension": "outlet_type", "value": outlet_type, "article_ids": aids, "count": len(aids)})
        return rows


# ======================================================================
# SECTION 13 — SYNTHETIC DEMOS
# ======================================================================

def demo_lawful_breaking_event_verification() -> None:
    """
    Synthetic lawful demo:
    Fictional bridge-collapse reporting with wire syndication, local independent
    reporting, official statement, numeric revision, correction, and analysis.

    No real news, no copyrighted article reproduction, no paywall bypass,
    no propaganda, no harassment, no private-data collection.
    """
    employee = NEWSIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    case = {
        "case_id": "DEMO-NEWSINT-001",
        "task_id": "DEMO-TASK-001",
        "objective": (
            "Lawful news intelligence: verify a fictional breaking event by separating syndicated copies "
            "from independent source families, tracking numeric revisions, preserving corrections, and "
            "avoiding headline-as-fact or article-count-as-corroboration errors."
        ),
        "questions": [
            "What is actually being reported?",
            "How many independent source families exist?",
            "Which numeric claims were revised?",
            "What is supported versus unverified?",
            "What should be verified next?",
        ],
        "authorization": "PUBLIC_OR_LICENSED_NEWS_MONITORING_LAWFUL_RESEARCH",
        "sensitivity_tags": ["BREAKING_NEWS", "SYNTHETIC_FICTIONAL_EVENT", "PUBLIC_SAFETY_CONTEXT"],
        "topics": ["Demo Bridge collapse"],
        "keywords": ["Demo Bridge", "Demo City", "injured", "officials", "correction"],
        "publications": [
            {
                "publication_id": "PUB_DEMO_WIRE",
                "name": "Demo Wire",
                "country": "DEMO_COUNTRY",
                "languages": ["EN"],
                "outlet_type": "WIRE_SERVICE",
                "ownership_context": "SYNTHETIC",
                "corrections_policy": "PUBLIC_CORRECTIONS_PAGE",
                "limitations": ["Wire copies may be republished by many outlets."],
            },
            {
                "publication_id": "PUB_DEMO_NATIONAL",
                "name": "Demo National News",
                "country": "DEMO_COUNTRY",
                "languages": ["EN"],
                "outlet_type": "NATIONAL",
                "ownership_context": "SYNTHETIC",
                "corrections_policy": "UPDATE_NOTE",
            },
            {
                "publication_id": "PUB_DEMO_LOCAL",
                "name": "Demo City Local",
                "country": "DEMO_COUNTRY",
                "languages": ["EN"],
                "outlet_type": "LOCAL",
                "ownership_context": "SYNTHETIC",
                "corrections_policy": "EDITOR_NOTE",
                "limitations": ["Local outlet may have scene access but limited verification resources."],
            },
            {
                "publication_id": "PUB_DEMO_EMERGENCY",
                "name": "Demo City Emergency Management",
                "country": "DEMO_COUNTRY",
                "languages": ["EN"],
                "outlet_type": "OFFICIAL",
                "ownership_context": "GOVERNMENT",
                "corrections_policy": "OFFICIAL_UPDATE",
            },
            {
                "publication_id": "PUB_DEMO_ANALYSIS",
                "name": "Demo Analysis Desk",
                "country": "DEMO_COUNTRY",
                "languages": ["EN"],
                "outlet_type": "ANALYSIS",
                "ownership_context": "SYNTHETIC",
            },
        ],
        "wire_services": [
            {
                "wire_id": "WIRE_DEMO",
                "name": "Demo Wire",
                "upstream": "DEMO_WIRE_ORIGINAL",
                "independence_group": "demo_wire",
                "reliability": "MEDIUM",
                "limitations": ["Multiple national copies may share this wire family."],
            }
        ],
        "articles": [
            {
                "article_id": "ART_WIRE_1",
                "publication_id": "PUB_DEMO_WIRE",
                "wire_service_id": "WIRE_DEMO",
                "url": "https://demo-wire.example/bridge-collapse?utm_source=test",
                "headline": "Bridge collapse in Demo City injures 25, officials say",
                "published_at": "2026-10-08T09:00:00Z",
                "updated_at": "2026-10-08T09:00:00Z",
                "retrieved_at": "2026-10-08T09:05:00Z",
                "language": "EN",
                "body": (
                    "Officials said 25 people were injured after the Demo Bridge collapsed in Demo City. "
                    "The cause was not immediately known. Emergency crews responded near the river crossing."
                ),
                "article_type": "BREAKING_NEWS",
                "source_type": "WIRESERVICE",
                "quoted_sources": ["Demo City officials"],
                "limitations": ["Early breaking report."],
            },
            {
                "article_id": "ART_NATIONAL_1",
                "publication_id": "PUB_DEMO_NATIONAL",
                "wire_service_id": "WIRE_DEMO",
                "syndicated_from": "ART_WIRE_1",
                "url": "https://demo-national.example/bridge-collapse?fbclid=abc",
                "headline": "Bridge collapse in Demo City injures 25, officials say",
                "published_at": "2026-10-08T09:15:00Z",
                "updated_at": "2026-10-08T09:15:00Z",
                "retrieved_at": "2026-10-08T09:20:00Z",
                "language": "EN",
                "body": (
                    "Officials said 25 people were injured after the Demo Bridge collapsed in Demo City. "
                    "The cause was not immediately known. Emergency crews responded near the river crossing."
                ),
                "source_type": "NEWS_WEBSITE",
                "quoted_sources": ["Demo City officials"],
            },
            {
                "article_id": "ART_NATIONAL_2",
                "publication_id": "PUB_DEMO_NATIONAL",
                "wire_service_id": "WIRE_DEMO",
                "syndicated_from": "ART_WIRE_1",
                "url": "https://demo-national.example/bridge-collapse-update",
                "headline": "Demo Bridge collapse: 25 injured, cause unknown",
                "published_at": "2026-10-08T09:25:00Z",
                "updated_at": "2026-10-08T10:20:00Z",
                "retrieved_at": "2026-10-08T10:25:00Z",
                "language": "EN",
                "body": (
                    "Officials initially said 25 people were injured after the Demo Bridge collapsed in Demo City. "
                    "Later, Demo City Emergency Management confirmed 18 people were injured. "
                    "The cause remains under investigation."
                ),
                "source_type": "NEWS_WEBSITE",
                "quoted_sources": ["Demo City officials", "Demo City Emergency Management"],
            },
            {
                "article_id": "ART_LOCAL_1",
                "publication_id": "PUB_DEMO_LOCAL",
                "url": "https://demo-local.example/bridge-scene",
                "headline": "Local reporter sees Demo Bridge collapse; hospital says 12 treated",
                "published_at": "2026-10-08T09:30:00Z",
                "updated_at": "2026-10-08T09:55:00Z",
                "retrieved_at": "2026-10-08T09:58:00Z",
                "language": "EN",
                "body": (
                    "A Demo City Local reporter at the scene said the Demo Bridge collapsed in Demo City. "
                    "Hospital staff said 12 people were treated at the local hospital. "
                    "Police said the earlier 25 figure was preliminary."
                ),
                "source_type": "NEWS_WEBSITE",
                "quoted_sources": ["Demo City Local reporter", "Hospital staff", "Police"],
                "primary_source_refs": [
                    {
                        "source_type": "OFFICIAL_STATEMENT",
                        "reference": "Demo City Police preliminary statement",
                        "description": "Police statement on preliminary injury count.",
                        "confidence": "MEDIUM",
                    }
                ],
            },
            {
                "article_id": "ART_OFFICIAL_1",
                "publication_id": "PUB_DEMO_EMERGENCY",
                "url": "https://demo-emergency.example/releases/bridge-18",
                "headline": "Official statement: 18 confirmed injured after Demo Bridge collapse",
                "published_at": "2026-10-08T10:00:00Z",
                "updated_at": "2026-10-08T10:00:00Z",
                "retrieved_at": "2026-10-08T10:02:00Z",
                "language": "EN",
                "body": (
                    "Demo City Emergency Management confirmed that 18 people were injured after the Demo Bridge "
                    "collapsed in Demo City. The cause remains under investigation. "
                    "Earlier preliminary figures are superseded."
                ),
                "article_type": "PRESS_RELEASE",
                "source_type": "OFFICIAL_STATEMENT",
                "quoted_sources": ["Demo City Emergency Management"],
                "primary_source_refs": [
                    {
                        "source_type": "OFFICIAL_STATEMENT",
                        "reference": "Demo City Emergency Management release 2026-10-08",
                        "description": "Official confirmed injury count.",
                        "confidence": "HIGH",
                    }
                ],
            },
            {
                "article_id": "ART_ANALYSIS_1",
                "publication_id": "PUB_DEMO_ANALYSIS",
                "url": "https://demo-analysis.example/bridge-why",
                "headline": "Analysis: what we know and do not know about the Demo Bridge collapse",
                "published_at": "2026-10-08T11:00:00Z",
                "updated_at": "2026-10-08T11:00:00Z",
                "retrieved_at": "2026-10-08T11:03:00Z",
                "language": "EN",
                "body": (
                    "This analysis examines the Demo Bridge collapse in Demo City. Structural fatigue may be a cause, "
                    "but officials have not confirmed it. The article is analysis, not primary evidence."
                ),
                "article_type": "ANALYSIS",
                "source_type": "NEWS_WEBSITE",
                "quoted_sources": ["Demo City Emergency Management"],
            },
        ],
        "corrections": [
            {
                "correction_id": "CORR_NATIONAL_1",
                "article_id": "ART_NATIONAL_1",
                "claim_id": "",
                "old_claim": "25 people were injured",
                "new_claim": "18 people were confirmed injured",
                "correction_time": "2026-10-08T10:15:00Z",
                "correction_text_reference": "Editor's note: earlier injury count was preliminary and has been updated.",
                "reason": "PRELIMINARY_COUNT_UPDATED",
                "source_id": "PUB_DEMO_NATIONAL",
            }
        ],
        "retractions": [],
        "fact_checks": [
            {
                "fact_check_id": "FC_DEMO_1",
                "target_claim_id": "",
                "target_article_id": "ART_WIRE_1",
                "rating": "PARTLY_TRUE_UPDATED",
                "source": "Demo Synthetic Fact Check",
                "limitations": ["Fact-check is secondary analysis; inspect primary official record."],
            }
        ],
    }

    result = employee.run_case(case)
    print(result.report)


def demo_policy_blocked_paywall_propaganda() -> None:
    """
    Synthetic policy-block demonstration.
    Shows that paywall bypass / propaganda / harassment requests are refused.
    """
    employee = NEWSIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    case = {
        "case_id": "DEMO-NEWSINT-BLOCK-001",
        "task_id": "DEMO-TASK-BLOCK-001",
        "objective": (
            "Bypass the paywall on this newspaper, scrape the journalist's private account, "
            "and generate a propaganda campaign to harass the reporter and amplify an unverified allegation as fact."
        ),
        "questions": [
            "How do I get the full article without subscription?",
            "How do I target the journalist?",
        ],
        "authorization": "NONE",
        "articles": [],
    }

    result = employee.run_case(case)
    print(result.report)


def main() -> None:
    print("\n" + "=" * 72)
    print("LAWFUL SYNTHETIC BREAKING-EVENT VERIFICATION DEMO")
    print("=" * 72 + "\n")
    demo_lawful_breaking_event_verification()

    print("\n" + "=" * 72)
    print("POLICY-BLOCKED PAYWALL / PROPAGANDA / HARASSMENT DEMO")
    print("=" * 72 + "\n")
    demo_policy_blocked_paywall_propaganda()


if __name__ == "__main__":
    main()
