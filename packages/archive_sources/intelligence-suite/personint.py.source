#!/usr/bin/env python3
"""
PERSONINT — Public-record person research pipeline
Local, privacy-aware, evidence-first demo implementation.

IMPORTANT:
- This does NOT access live private records.
- This does NOT perform doxxing, stalking, biometric identification,
  private-account access, live location tracking, or sensitive-trait inference.
- Sample data is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

PIPELINE_VERSION = "0.1.0-personint-public-record-demo"


# =====================================================================
# ENUMS
# =====================================================================

class IdentityState(str, Enum):
    VERIFIED_PERSON = "VERIFIED_PERSON"
    STRONGLY_SUPPORTED_PERSON = "STRONGLY_SUPPORTED_PERSON"
    PROBABLE_PERSON = "PROBABLE_PERSON"
    POSSIBLE_PERSON = "POSSIBLE_PERSON"
    AMBIGUOUS_PERSON = "AMBIGUOUS_PERSON"
    DISTINCT_PERSON = "DISTINCT_PERSON"
    UNRESOLVED = "UNRESOLVED"


class ClaimState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    SOURCE_CLAIM_ONLY = "SOURCE_CLAIM_ONLY"


class RoleStatus(str, Enum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    ACTING = "ACTING"
    INTERIM = "INTERIM"
    ADVISORY = "ADVISORY"
    VOLUNTEER = "VOLUNTEER"
    CONTRACTOR = "CONTRACTOR"
    UNKNOWN = "UNKNOWN"


class SourceType(str, Enum):
    OFFICIAL_GOVERNMENT = "OFFICIAL_GOVERNMENT"
    OFFICIAL_INSTITUTION = "OFFICIAL_INSTITUTION"
    PROFESSIONAL_REGISTRY = "PROFESSIONAL_REGISTRY"
    OFFICIAL_CORPORATE_FILING = "OFFICIAL_CORPORATE_FILING"
    ACADEMIC_IDENTIFIER = "ACADEMIC_IDENTIFIER"
    COURT_OR_REGULATOR = "COURT_OR_REGULATOR"
    PERSON_SELF_REPORT = "PERSON_SELF_REPORT"
    EMPLOYER_BIO = "EMPLOYER_BIO"
    CONFERENCE_BIO = "CONFERENCE_BIO"
    MEDIA = "MEDIA"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    AGGREGATOR = "AGGREGATOR"
    ANONYMOUS_SOURCE = "ANONYMOUS_SOURCE"


class PrivacyFlag(str, Enum):
    PRIVATE_ADDRESS_REDACTED = "PRIVATE_ADDRESS_REDACTED"
    PRIVATE_PHONE_REDACTED = "PRIVATE_PHONE_REDACTED"
    PRIVATE_EMAIL_REDACTED = "PRIVATE_EMAIL_REDACTED"
    SENSITIVE_TRAIT_NOT_COLLECTED = "SENSITIVE_TRAIT_NOT_COLLECTED"
    BIOMETRIC_PROHIBITED = "BIOMETRIC_PROHIBITED"
    LIVE_LOCATION_PROHIBITED = "LIVE_LOCATION_PROHIBITED"
    MINOR_RESTRICTED = "MINOR_RESTRICTED"
    PROTECTED_SOURCE_RESTRICTED = "PROTECTED_SOURCE_RESTRICTED"


class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PERSON_UNRESOLVED = "PERSON_UNRESOLVED"
    MULTIPLE_PERSON_CANDIDATES = "MULTIPLE_PERSON_CANDIDATES"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


# =====================================================================
# CONSTANTS FOR SYNTHETIC SAMPLE
# =====================================================================

PC_ID = "PC-JORDAN-A-RIVERS-1"
ORG_NBU = "ORG-NORTHBRIDGE-UNIVERSITY"
ORG_RIVERS = "ORG-RIVERS-ANALYTICS-LTD"


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
    notes: str = ""


@dataclass
class Evidence:
    id: str
    source_id: str
    excerpt: str
    claim: str
    claim_state: ClaimState = ClaimState.SOURCE_CLAIM_ONLY
    confidence: float = 0.5
    privacy_flags: List[PrivacyFlag] = field(default_factory=list)


@dataclass
class PersonCandidate:
    person_candidate_id: str
    display_name: str
    normalized_names: List[str] = field(default_factory=list)
    aliases: List[Dict[str, str]] = field(default_factory=list)
    known_roles: List[str] = field(default_factory=list)
    known_organizations: List[str] = field(default_factory=list)
    safe_location_context: Optional[str] = None
    professional_identifiers: List[Dict[str, Any]] = field(default_factory=list)
    public_profiles: List[Dict[str, Any]] = field(default_factory=list)
    publications: List[str] = field(default_factory=list)
    public_records: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    identity_confidence: float = 0.0
    identity_state: IdentityState = IdentityState.UNRESOLVED
    limitations: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class Role:
    role_id: str
    person_candidate_id: str
    organization_id: str
    title: str
    normalized_title: str
    role_type: str
    start_date: Optional[str]
    end_date: Optional[str]
    status: RoleStatus
    source_ids: List[str]
    confidence: float


@dataclass
class Publication:
    publication_id: str
    title: str
    authors: List[str]
    venue: str
    date: str
    identifier: Optional[str]
    person_author_candidate_id: Optional[str]
    affiliation: Optional[str]
    source_ids: List[str]
    confidence: float


@dataclass
class FactGateResult:
    fact_id: str
    statement: str
    person_candidate_id: Optional[str]
    source_ids: List[str]
    evidence_ids: List[str]
    confidence: float
    status: ClaimState
    limitations: List[str]


@dataclass
class Contradiction:
    contradiction_id: str
    description: str
    person_candidate_id: Optional[str]
    source_ids: List[str]
    severity: str
    status: str
    recommended_resolution: str


@dataclass
class KnowledgeGap:
    gap_id: str
    description: str
    importance: str
    recommended_source: str
    specialist: Optional[str]
    expected_information_value: float


@dataclass
class NextAction:
    action_id: str
    description: str
    priority: int
    privacy_impact: str
    expected_gain: float
    specialist: Optional[str] = None


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: ["public_records_only"])
    authorization: str = "demo_authorized_public_records"
    person_names: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    known_roles: List[str] = field(default_factory=list)
    known_organizations: List[str] = field(default_factory=list)
    known_locations: List[str] = field(default_factory=list)
    public_profiles: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    publications: List[str] = field(default_factory=list)
    registrations: List[str] = field(default_factory=list)
    filings: List[str] = field(default_factory=list)
    professional_identifiers: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    known_facts: List[str] = field(default_factory=list)
    existing_hypotheses: List[str] = field(default_factory=list)
    existing_contradictions: List[str] = field(default_factory=list)
    budget: Optional[str] = None
    deadline: Optional[str] = None


# =====================================================================
# UTILITIES
# =====================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}{h}" if prefix else h


def jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dict__") and not isinstance(obj, type):
        return {k: jsonable(v) for k, v in vars(obj).items()}
    if isinstance(obj, (list, tuple, set)):
        return [jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    return obj


# =====================================================================
# POLICY GUARD
# =====================================================================

POLICY_RULES: List[Tuple[str, Any]] = [
    ("DOXXING", re.compile(r"\bdox(?:king|ed|ing|ers?)?\b", re.IGNORECASE)),
    ("STALKING", re.compile(r"\bstalk(?:ing|er|ers)?\b", re.IGNORECASE)),
    (
        "LIVE_LOCATION_TRACKING",
        re.compile(
            r"\b(live|real[- ]time|current)\s+(location|tracking|track|surveillance)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "BIOMETRIC_IDENTIFICATION",
        re.compile(
            r"\b(face|facial|voiceprint|voice recognition|biometric)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PRIVATE_ACCOUNT_ACCESS",
        re.compile(
            r"\b(hack|bypass|login|stolen|private)\s+(account|credential|cookie|session)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PRIVATE_CONTACT_DISCLOSURE",
        re.compile(
            r"\b(home|residential|personal)\s+(address|phone|mobile|email)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SENSITIVE_TRAIT_INFERENCE",
        re.compile(
            r"\b(infer|determine|identify).{0,40}\b"
            r"(race|ethnicity|religion|sexual orientation|health|mental health|political ideology)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CREDENTIAL_COLLECTION",
        re.compile(r"\b(password|api key|token|authentication secret)\b", re.IGNORECASE),
    ),
]


def policy_guard(text: str) -> List[Dict[str, str]]:
    violations = []
    for rule_name, rx in POLICY_RULES:
        m = rx.search(text)
        if m:
            violations.append({"rule": rule_name, "matched": m.group(0)})
    return violations


# =====================================================================
# PRIVACY REDACTION
# =====================================================================

EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RX = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[ -]?)?(?:\(\d{2,4}\)|\d{3,4})[ -]?\d{3,4}[ -]?\d{3,4}(?!\d)"
)
ADDRESS_RX = re.compile(
    r"\b(house\s*(?:no|number)?|flat|apartment|residence|home address)\b[^\n]*",
    re.IGNORECASE,
)


def redact_private_fields(text: str) -> Tuple[str, List[PrivacyFlag]]:
    flags: List[PrivacyFlag] = []
    out = text

    if EMAIL_RX.search(out):
        flags.append(PrivacyFlag.PRIVATE_EMAIL_REDACTED)
        out = EMAIL_RX.sub("PRIVATE_EMAIL_REDACTED", out)

    if PHONE_RX.search(out):
        flags.append(PrivacyFlag.PRIVATE_PHONE_REDACTED)
        out = PHONE_RX.sub("PRIVATE_PHONE_REDACTED", out)

    if ADDRESS_RX.search(out):
        flags.append(PrivacyFlag.PRIVATE_ADDRESS_REDACTED)
        out = ADDRESS_RX.sub("PRIVATE_ADDRESS_REDACTED", out)

    return out, flags


def finalize_evidence(evidence: Evidence) -> Evidence:
    evidence.excerpt, f1 = redact_private_fields(evidence.excerpt)
    evidence.claim, f2 = redact_private_fields(evidence.claim)
    evidence.privacy_flags = list(set(evidence.privacy_flags + f1 + f2))
    return evidence


# =====================================================================
# NAME NORMALIZATION
# =====================================================================

HONORIFICS = {
    "dr",
    "prof",
    "mr",
    "ms",
    "mrs",
    "miss",
    "justice",
    "colonel",
    "capt",
    "sgt",
    "rev",
}

SUFFIXES = {
    "jr",
    "sr",
    "phd",
    "md",
    "mba",
    "llb",
    "llm",
}


def normalize_name(name: str) -> Dict[str, Any]:
    original = name.strip()
    s = unicodedata.normalize("NFKC", original)
    s = re.sub(r"[^\w\s\-'.]+", " ", s, flags=re.UNICODE)
    s = s.lower()

    tokens = [t.strip(".") for t in s.split() if t.strip(".")]
    filtered = [t for t in tokens if t not in HONORIFICS and t not in SUFFIXES]

    normalized = " ".join(filtered)
    initials = ".".join(t[0] for t in filtered if t)

    variants = {original, normalized, s, initials}
    return {
        "original": original,
        "normalized": normalized,
        "tokens": filtered,
        "variants": sorted(v for v in variants if v),
    }


# =====================================================================
# FACT GATE HELPERS
# =====================================================================

def make_fact(
    fact_id: str,
    statement: str,
    person_candidate_id: Optional[str],
    source_ids: List[str],
    evidence_ids: List[str],
    confidence: float,
    status: ClaimState,
    limitations: List[str],
) -> FactGateResult:
    return FactGateResult(
        fact_id=fact_id,
        statement=statement,
        person_candidate_id=person_candidate_id,
        source_ids=source_ids,
        evidence_ids=evidence_ids,
        confidence=confidence,
        status=status,
        limitations=limitations,
    )


def evaluate_fact(
    statement: str,
    evidence_ids: List[str],
    source_map: Dict[str, Source],
    evidence_map: Dict[str, Evidence],
    person_candidate_id: Optional[str] = None,
    min_confidence: float = 0.75,
    require_independence: bool = False,
    extra_limitations: Optional[List[str]] = None,
) -> FactGateResult:
    evs = [evidence_map[eid] for eid in evidence_ids if eid in evidence_map]
    limitations = list(extra_limitations or [])
    source_ids = sorted({e.source_id for e in evs})

    if not evs:
        return FactGateResult(
            fact_id=new_id("FACT-", statement),
            statement=statement,
            person_candidate_id=person_candidate_id,
            source_ids=[],
            evidence_ids=evidence_ids,
            confidence=0.0,
            status=ClaimState.UNSUPPORTED,
            limitations=["No mapped evidence."],
        )

    max_conf = max(e.confidence for e in evs)
    avg_conf = sum(e.confidence for e in evs) / len(evs)
    groups = {
        source_map[e.source_id].independence_group
        for e in evs
        if e.source_id in source_map
    }

    if require_independence and len(groups) < 2:
        status = ClaimState.PARTIALLY_SUPPORTED
        limitations.append(
            "Evidence is not from at least two independent source families."
        )
    elif max_conf >= min_confidence:
        status = ClaimState.SUPPORTED
    elif max_conf >= 0.5:
        status = ClaimState.PARTIALLY_SUPPORTED
    else:
        status = ClaimState.INCONCLUSIVE

    confidence = round(max_conf if status == ClaimState.SUPPORTED else avg_conf, 2)

    return FactGateResult(
        fact_id=new_id("FACT-", statement + str(confidence)),
        statement=statement,
        person_candidate_id=person_candidate_id,
        source_ids=source_ids,
        evidence_ids=evidence_ids,
        confidence=confidence,
        status=status,
        limitations=limitations,
    )


# =====================================================================
# SYNTHETIC SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-PERSONINT-001",
        task_id="TASK-SAMPLE-001",
        objective=(
            "Resolve public professional identity of Jordan A. Rivers affiliated "
            "with Northbridge University and Rivers Analytics Ltd, and distinguish "
            "verified roles from self-reported claims."
        ),
        questions=[
            "Which public records refer to the same professional person?",
            "Which current roles are supported by official sources?",
            "Which founder/CEO claims remain unverified?",
            "Which namesake or profile risks remain?",
        ],
        scope=["public_records_only", "professional_context_only"],
        authorization="synthetic_demo_authorized_public_records",
        person_names=["Dr. Jordan A. Rivers", "Jordan Rivers"],
        aliases=["J. A. Rivers"],
        known_roles=["Associate Professor", "Director"],
        known_organizations=["Northbridge University", "Rivers Analytics Ltd"],
        known_locations=["Northbridge region"],
        public_profiles=["https://example.social/jordan-rivers-candidate"],
        usernames=[],
        emails=[],
        phones=[],
        publications=["DOI:10.5555/jpde.2025.123"],
        registrations=[],
        filings=["Rivers Analytics Ltd director filing"],
        professional_identifiers=["ORCID:0000-0002-1825-0097"],
        time_range="2020-2026",
        known_facts=[],
        existing_hypotheses=[],
        existing_contradictions=[],
        budget=None,
        deadline=None,
    )


def sample_sources() -> List[Source]:
    retrieved = now_iso()
    return [
        Source(
            id="SRC-NBU-FACULTY",
            title="Northbridge University faculty profile: Dr Jordan A. Rivers",
            url="https://example.edu/faculty/jordan-a-rivers",
            source_type=SourceType.OFFICIAL_INSTITUTION,
            published_at="2025-12-01",
            retrieved_at=retrieved,
            effective_at="2025-12-01",
            independence_group="NBU_OFFICIAL",
            reliability=0.95,
            notes="Official institutional page. Strong for role listing, not absolute current-status proof.",
        ),
        Source(
            id="SRC-ORCID",
            title="Public researcher identifier record: Jordan A. Rivers",
            url="https://example-orcid.org/0000-0002-1825-0097",
            source_type=SourceType.ACADEMIC_IDENTIFIER,
            published_at="2026-01-10",
            retrieved_at=retrieved,
            effective_at="2026-01-10",
            independence_group="ORCID_JR",
            reliability=0.90,
            notes="Academic identifier record. Useful for researcher disambiguation.",
        ),
        Source(
            id="SRC-CONF-BIO",
            title="Example Data Ethics Conference speaker biography",
            url="https://example-conf.org/speakers/jordan-rivers",
            source_type=SourceType.CONFERENCE_BIO,
            published_at="2025-11-20",
            retrieved_at=retrieved,
            effective_at="2025-11-20",
            independence_group="SELF_BIO_FAMILY",
            reliability=0.60,
            notes="Conference biography may be speaker-supplied and may copy official/self bio.",
        ),
        Source(
            id="SRC-LINKEDIN-CANDIDATE",
            title="Candidate public social profile: Jordan Rivers",
            url="https://example.social/jordan-rivers-candidate",
            source_type=SourceType.SOCIAL_PROFILE,
            published_at="2025-10-05",
            retrieved_at=retrieved,
            effective_at="2025-10-05",
            independence_group="SOCIAL_SELF",
            reliability=0.45,
            notes="Self-reported profile. Attribution remains candidate-only without cross-linking.",
        ),
        Source(
            id="SRC-REGISTRY",
            title="Corporate registry filing: Rivers Analytics Ltd",
            url="https://example-registry.gov/company/rivers-analytics-ltd",
            source_type=SourceType.OFFICIAL_CORPORATE_FILING,
            published_at="2026-01-02",
            retrieved_at=retrieved,
            effective_at="2026-01-02",
            independence_group="CORP_REGISTRY",
            reliability=0.92,
            notes="Official company registry. Confirms legal directorship, not ownership or founder status.",
        ),
        Source(
            id="SRC-MEDIA-QUOTE",
            title="Example Tech Review article quoting institutional role",
            url="https://example-media.test/article/data-ethics-panel",
            source_type=SourceType.MEDIA,
            published_at="2025-12-10",
            retrieved_at=retrieved,
            effective_at="2025-12-10",
            independence_group="NBU_OFFICIAL_DERIVED",
            reliability=0.70,
            notes="Media appears to quote institutional profile; not fully independent for role claim.",
        ),
    ]


def sample_evidences() -> List[Evidence]:
    items = [
        Evidence(
            id="EV-NBU-ROLE",
            source_id="SRC-NBU-FACULTY",
            excerpt="Jordan A. Rivers is listed as Associate Professor in the Department of Data Ethics.",
            claim=(
                "Northbridge University lists Jordan A. Rivers as Associate Professor, "
                "Department of Data Ethics, current as of 2025-12-01."
            ),
            confidence=0.95,
        ),
        Evidence(
            id="EV-ORCID-ID",
            source_id="SRC-ORCID",
            excerpt=(
                "Public researcher identifier 0000-0002-1825-0097 is associated with "
                "Jordan A. Rivers and Northbridge University."
            ),
            claim=(
                "ORCID-like identifier 0000-0002-1825-0097 is publicly associated "
                "with Jordan A. Rivers."
            ),
            confidence=0.90,
        ),
        Evidence(
            id="EV-ORCID-PUB",
            source_id="SRC-ORCID",
            excerpt=(
                "Work 'Ethical Auditing of Public Algorithms' "
                "(DOI:10.5555/jpde.2025.123) lists Jordan A. Rivers with "
                "Northbridge University affiliation."
            ),
            claim=(
                "Publication DOI:10.5555/jpde.2025.123 is attributed to "
                "Jordan A. Rivers in an academic identifier record."
            ),
            confidence=0.88,
        ),
        Evidence(
            id="EV-CONF-FOUNDER",
            source_id="SRC-CONF-BIO",
            excerpt=(
                "Conference biography says Jordan Rivers is Associate Professor at "
                "Northbridge University and founder of Rivers Analytics."
            ),
            claim=(
                "Conference biography publicly claims Jordan Rivers founded "
                "Rivers Analytics."
            ),
            confidence=0.60,
        ),
        Evidence(
            id="EV-LINKEDIN-CEO",
            source_id="SRC-LINKEDIN-CANDIDATE",
            excerpt=(
                "Public profile self-reports Founder & CEO at Rivers Analytics; "
                "based in Bengaluru."
            ),
            claim=(
                "Social profile self-reports Founder & CEO at Rivers Analytics."
            ),
            confidence=0.45,
        ),
        Evidence(
            id="EV-REGISTRY-DIRECTOR",
            source_id="SRC-REGISTRY",
            excerpt=(
                "Rivers Analytics Ltd filing lists Jordan Anthony Rivers as director "
                "from 2021-03-01; status current."
            ),
            claim=(
                "Official corporate filing lists Jordan Anthony Rivers as director "
                "of Rivers Analytics Ltd since 2021-03-01."
            ),
            confidence=0.92,
        ),
        Evidence(
            id="EV-MEDIA-QUOTE",
            source_id="SRC-MEDIA-QUOTE",
            excerpt="Article quotes Jordan Rivers as Associate Professor at Northbridge University.",
            claim=(
                "Media reports Jordan Rivers as Associate Professor at "
                "Northbridge University."
            ),
            confidence=0.70,
        ),
    ]
    return [finalize_evidence(e) for e in items]


def sample_roles() -> List[Role]:
    return [
        Role(
            role_id="ROLE-NBU-ASSOC-PROF",
            person_candidate_id=PC_ID,
            organization_id=ORG_NBU,
            title="Associate Professor",
            normalized_title="associate professor",
            role_type="ACADEMIC",
            start_date="2023-08-01",
            end_date=None,
            status=RoleStatus.CURRENT,
            source_ids=["SRC-NBU-FACULTY", "SRC-CONF-BIO", "SRC-MEDIA-QUOTE"],
            confidence=0.95,
        ),
        Role(
            role_id="ROLE-REGISTRY-DIRECTOR",
            person_candidate_id=PC_ID,
            organization_id=ORG_RIVERS,
            title="Director",
            normalized_title="director",
            role_type="LEGAL_DIRECTOR",
            start_date="2021-03-01",
            end_date=None,
            status=RoleStatus.CURRENT,
            source_ids=["SRC-REGISTRY"],
            confidence=0.92,
        ),
        Role(
            role_id="ROLE-SOCIAL-CEO",
            person_candidate_id=PC_ID,
            organization_id=ORG_RIVERS,
            title="CEO",
            normalized_title="ceo",
            role_type="EXECUTIVE_TITLE",
            start_date=None,
            end_date=None,
            status=RoleStatus.UNKNOWN,
            source_ids=["SRC-LINKEDIN-CANDIDATE"],
            confidence=0.45,
        ),
        Role(
            role_id="ROLE-CONF-FOUNDER",
            person_candidate_id=PC_ID,
            organization_id=ORG_RIVERS,
            title="Founder",
            normalized_title="founder",
            role_type="FOUNDER_CLAIM",
            start_date=None,
            end_date=None,
            status=RoleStatus.UNKNOWN,
            source_ids=["SRC-CONF-BIO", "SRC-LINKEDIN-CANDIDATE"],
            confidence=0.55,
        ),
    ]


def sample_publications() -> List[Publication]:
    return [
        Publication(
            publication_id="PUB-DOI-123",
            title="Ethical Auditing of Public Algorithms",
            authors=["Jordan A. Rivers"],
            venue="Journal of Public Data Ethics",
            date="2025-06-15",
            identifier="DOI:10.5555/jpde.2025.123",
            person_author_candidate_id=PC_ID,
            affiliation="Northbridge University",
            source_ids=["SRC-ORCID"],
            confidence=0.88,
        )
    ]


def sample_candidate() -> PersonCandidate:
    norm1 = normalize_name("Dr. Jordan A. Rivers")
    norm2 = normalize_name("Jordan Rivers")

    return PersonCandidate(
        person_candidate_id=PC_ID,
        display_name="Jordan A. Rivers",
        normalized_names=sorted(set(norm1["variants"] + norm2["variants"])),
        aliases=[
            {
                "type": "INITIAL_VARIANT",
                "value": "J. A. Rivers",
                "source_id": "SRC-NBU-FACULTY",
            },
            {
                "type": "PROFESSIONAL_NAME",
                "value": "Jordan Rivers",
                "source_id": "SRC-CONF-BIO",
            },
        ],
        known_roles=["Associate Professor", "Director"],
        known_organizations=["Northbridge University", "Rivers Analytics Ltd"],
        safe_location_context="Northbridge region (safe granularity; no residence inferred)",
        professional_identifiers=[
            {
                "type": "ORCID",
                "value": "0000-0002-1825-0097",
                "source_id": "SRC-ORCID",
                "confidence": 0.90,
            }
        ],
        public_profiles=[
            {
                "platform": "ExampleSocial",
                "url": "https://example.social/jordan-rivers-candidate",
                "authenticity": "CANDIDATE",
                "source_id": "SRC-LINKEDIN-CANDIDATE",
            }
        ],
        publications=["PUB-DOI-123"],
        public_records=["SRC-REGISTRY"],
        first_seen="2021-03-01",
        last_seen="2026-01-10",
        limitations=[
            "Social profile not independently attributed.",
            "Founder and CEO claims are self-reported or dependent-source claims.",
        ],
        evidence_ids=[
            "EV-NBU-ROLE",
            "EV-ORCID-ID",
            "EV-ORCID-PUB",
            "EV-CONF-FOUNDER",
            "EV-LINKEDIN-CEO",
            "EV-REGISTRY-DIRECTOR",
            "EV-MEDIA-QUOTE",
        ],
    )


def sample_contradictions() -> List[Contradiction]:
    return [
        Contradiction(
            contradiction_id="CON-FOUNDER-CEO",
            description=(
                "Founder and CEO claims appear in conference/social bios, but official "
                "registry confirms only directorship and does not establish founder "
                "status or operational authority."
            ),
            person_candidate_id=PC_ID,
            source_ids=["SRC-CONF-BIO", "SRC-LINKEDIN-CANDIDATE", "SRC-REGISTRY"],
            severity="MATERIAL",
            status="OPEN",
            recommended_resolution=(
                "Use CORPINT/official incorporation history for founder status and "
                "ORGINT/CORPINT for CEO authority. Do not infer authority from title."
            ),
        ),
        Contradiction(
            contradiction_id="CON-LOCATION",
            description=(
                "Social profile mentions Bengaluru while institutional context is "
                "Northbridge region. Not material unless objective requires location."
            ),
            person_candidate_id=PC_ID,
            source_ids=["SRC-LINKEDIN-CANDIDATE", "SRC-NBU-FACULTY"],
            severity="LOW",
            status="NOTED",
            recommended_resolution=(
                "Retain only safe city/region context if objective-relevant. "
                "Do not infer current physical location."
            ),
        ),
    ]


def sample_knowledge_gaps() -> List[KnowledgeGap]:
    return [
        KnowledgeGap(
            gap_id="GAP-FOUNDER",
            description="Founder status of Rivers Analytics is not independently verified.",
            importance="MEDIUM",
            recommended_source="Official company incorporation/history filing",
            specialist="CORPINT",
            expected_information_value=0.70,
        ),
        KnowledgeGap(
            gap_id="GAP-CEO-AUTHORITY",
            description="CEO title does not establish legal authority or current employment.",
            importance="MEDIUM",
            recommended_source="Board resolutions/company filings",
            specialist="ORGINT/CORPINT",
            expected_information_value=0.65,
        ),
        KnowledgeGap(
            gap_id="GAP-SOCIAL-ATTRIBUTION",
            description="Social profile attribution remains candidate-only.",
            importance="LOW",
            recommended_source="Self-linked official profile or consistent professional cross-links",
            specialist="SOCMINT/USERNAMEINT",
            expected_information_value=0.40,
        ),
        KnowledgeGap(
            gap_id="GAP-EDUCATION",
            description="Education/degree not verified from institutional record.",
            importance="LOW",
            recommended_source="University alumni/degree registry if public and relevant",
            specialist="ACADEMICINT",
            expected_information_value=0.30,
        ),
    ]


def sample_next_actions() -> List[NextAction]:
    return [
        NextAction(
            action_id="NA-CORPINT-FOUNDER",
            description=(
                "Query official company registry/incorporation documents for "
                "founder/director/shareholder context."
            ),
            priority=1,
            privacy_impact="LOW",
            expected_gain=0.70,
            specialist="CORPINT",
        ),
        NextAction(
            action_id="NA-ORCID-VERIFY",
            description=(
                "Re-retrieve academic identifier record to confirm publication "
                "attribution and affiliation freshness."
            ),
            priority=2,
            privacy_impact="LOW",
            expected_gain=0.60,
            specialist="ACADEMICINT",
        ),
        NextAction(
            action_id="NA-PROFILE-LINK",
            description=(
                "Look for official institutional page linking to social profile "
                "before treating it as authentic."
            ),
            priority=3,
            privacy_impact="LOW",
            expected_gain=0.40,
            specialist="SOCMINT",
        ),
        NextAction(
            action_id="NA-NO-PRIVATE-ACTION",
            description=(
                "Do not contact person, family, or private accounts; do not infer "
                "home location; do not use biometrics."
            ),
            priority=99,
            privacy_impact="PROTECTIVE",
            expected_gain=0.0,
            specialist=None,
        ),
    ]


def sample_specialist_handoffs() -> List[Dict[str, str]]:
    return [
        {
            "specialist": "CORPINT",
            "reason": "Legal directorship, founder context, corporate ownership boundaries.",
        },
        {
            "specialist": "ORGINT",
            "reason": "Meaning and authority of CEO/Director titles inside organization.",
        },
        {
            "specialist": "ACADEMICINT",
            "reason": "Researcher identity, publication attribution, identifier hygiene.",
        },
        {
            "specialist": "SOCMINT",
            "reason": "Public social profile authenticity and account-level linkage.",
        },
    ]


def sample_public_statements() -> List[Dict[str, Any]]:
    return [
        {
            "statement_id": "STMT-CONF-FOUNDER",
            "person_candidate_id": PC_ID,
            "date": "2025-11-20",
            "venue": "Example Data Ethics Conference",
            "medium": "conference_biography",
            "source_id": "SRC-CONF-BIO",
            "statement_summary": "Publicly described as founder of Rivers Analytics.",
            "exact_locator": "conference bio section",
            "context": "Speaker-submitted biography",
            "attribution_confidence": 0.60,
        },
        {
            "statement_id": "STMT-MEDIA-QUOTE",
            "person_candidate_id": PC_ID,
            "date": "2025-12-10",
            "venue": "Example Tech Review",
            "medium": "news_quote",
            "source_id": "SRC-MEDIA-QUOTE",
            "statement_summary": "Quoted as Associate Professor at Northbridge University.",
            "exact_locator": "article paragraph 3",
            "context": "Media quoting institutional role",
            "attribution_confidence": 0.70,
        },
    ]


def build_sample_facts(
    source_map: Dict[str, Source],
    evidence_map: Dict[str, Evidence],
) -> List[FactGateResult]:
    facts: List[FactGateResult] = []

    facts.append(
        evaluate_fact(
            statement=(
                "Northbridge University officially lists Jordan A. Rivers as "
                "Associate Professor, Department of Data Ethics, as of 2025-12-01."
            ),
            evidence_ids=["EV-NBU-ROLE", "EV-MEDIA-QUOTE"],
            source_map=source_map,
            evidence_map=evidence_map,
            person_candidate_id=PC_ID,
            extra_limitations=[
                "Institutional pages can lag departures; current status requires recent retrieval."
            ],
        )
    )

    facts.append(
        evaluate_fact(
            statement=(
                "ORCID-like identifier 0000-0002-1825-0097 is publicly associated "
                "with Jordan A. Rivers."
            ),
            evidence_ids=["EV-ORCID-ID"],
            source_map=source_map,
            evidence_map=evidence_map,
            person_candidate_id=PC_ID,
            extra_limitations=[
                "Researcher identifiers may be self-maintained unless platform verification is available."
            ],
        )
    )

    facts.append(
        evaluate_fact(
            statement=(
                "Official corporate filing lists Jordan Anthony Rivers as director "
                "of Rivers Analytics Ltd since 2021-03-01."
            ),
            evidence_ids=["EV-REGISTRY-DIRECTOR"],
            source_map=source_map,
            evidence_map=evidence_map,
            person_candidate_id=PC_ID,
            extra_limitations=[
                "Directorship is a legal corporate role; it does not imply ownership or day-to-day control."
            ],
        )
    )

    facts.append(
        evaluate_fact(
            statement=(
                "Publication DOI:10.5555/jpde.2025.123 is attributed to Jordan A. Rivers "
                "in an academic identifier record with Northbridge University affiliation."
            ),
            evidence_ids=["EV-ORCID-PUB"],
            source_map=source_map,
            evidence_map=evidence_map,
            person_candidate_id=PC_ID,
            extra_limitations=[
                "Author attribution relies on identifier record and affiliation consistency; common-name risk remains."
            ],
        )
    )

    facts.append(
        make_fact(
            fact_id="FACT-FOUNDER-CLAIM",
            statement=(
                "Conference and social sources publicly claim Jordan Rivers founded "
                "Rivers Analytics."
            ),
            person_candidate_id=PC_ID,
            source_ids=["SRC-CONF-BIO", "SRC-LINKEDIN-CANDIDATE"],
            evidence_ids=["EV-CONF-FOUNDER", "EV-LINKEDIN-CEO"],
            confidence=0.55,
            status=ClaimState.SOURCE_CLAIM_ONLY,
            limitations=[
                "Founder status is not independently verified.",
                "Founder != current owner.",
            ],
        )
    )

    facts.append(
        make_fact(
            fact_id="FACT-CEO-CLAIM",
            statement=(
                "A public social profile claims Jordan Rivers is CEO of Rivers Analytics."
            ),
            person_candidate_id=PC_ID,
            source_ids=["SRC-LINKEDIN-CANDIDATE"],
            evidence_ids=["EV-LINKEDIN-CEO"],
            confidence=0.45,
            status=ClaimState.SOURCE_CLAIM_ONLY,
            limitations=[
                "Job title != authority.",
                "Self-reported executive title requires corporate/org verification.",
            ],
        )
    )

    return facts


# =====================================================================
# IDENTITY RESOLUTION
# =====================================================================

def resolve_identity(
    candidate: PersonCandidate,
    roles: List[Role],
    facts: List[FactGateResult],
    contradictions: List[Contradiction],
) -> Dict[str, Any]:
    supported = [f for f in facts if f.status == ClaimState.SUPPORTED]
    score = 0.0
    reasons: List[str] = []

    if candidate.professional_identifiers:
        score += 0.30
        reasons.append("professional identifier present")

    if any(r.status == RoleStatus.CURRENT and r.confidence >= 0.85 for r in roles):
        score += 0.25
        reasons.append("current role supported by high-confidence official source")

    if len(supported) >= 3:
        score += 0.20
        reasons.append("multiple fact-gated supported statements")
    elif supported:
        score += 0.10
        reasons.append("at least one fact-gated supported statement")

    orgs = {r.organization_id for r in roles}
    if len(orgs) >= 2:
        score += 0.05
        reasons.append("cross-organization professional consistency")

    material = [c for c in contradictions if c.severity == "MATERIAL"]
    if material:
        score -= 0.05 * len(material)
        reasons.append(f"{len(material)} material contradiction(s) reduce certainty")

    score = max(0.0, min(0.99, score))

    if score >= 0.80:
        state = IdentityState.STRONGLY_SUPPORTED_PERSON
    elif score >= 0.65:
        state = IdentityState.PROBABLE_PERSON
    elif score >= 0.45:
        state = IdentityState.POSSIBLE_PERSON
    else:
        state = IdentityState.AMBIGUOUS_PERSON

    candidate.identity_confidence = round(score, 2)
    candidate.identity_state = state
    candidate.limitations.append(
        "Identity resolution drivers: " + "; ".join(reasons) + "."
    )

    return {
        "score": candidate.identity_confidence,
        "state": state.value,
        "reasons": reasons,
    }


def dual_ai_review(
    candidate: PersonCandidate,
    facts: List[FactGateResult],
    contradictions: List[Contradiction],
) -> Dict[str, Any]:
    issues: List[str] = []

    if contradictions:
        issues.append("Open contradictions exist.")

    if candidate.identity_confidence < 0.80:
        issues.append("Composite identity confidence is below strong threshold.")

    if not any(f.status == ClaimState.SUPPORTED for f in facts):
        issues.append("No fact-gated supported conclusion exists.")

    if any(f.status == ClaimState.SOURCE_CLAIM_ONLY for f in facts):
        issues.append("Some material claims remain source-only.")

    if not issues:
        verdict = "AGREE"
    elif len(issues) <= 2:
        verdict = "PARTIAL_AGREEMENT"
    else:
        verdict = "INSUFFICIENT_EVIDENCE"

    return {
        "primary_analyst": candidate.identity_state.value,
        "independent_skeptic_issues": issues,
        "verdict": verdict,
        "note": "AI agreement is not independent identity evidence.",
    }


def analyst_summary(
    candidate: PersonCandidate,
    roles: List[Role],
    facts: List[FactGateResult],
    contradictions: List[Contradiction],
) -> str:
    current = [
        f"{r.title} at {r.organization_id}"
        for r in roles
        if r.status == RoleStatus.CURRENT
    ]
    supported = [f.statement for f in facts if f.status == ClaimState.SUPPORTED]
    source_only = [f.statement for f in facts if f.status == ClaimState.SOURCE_CLAIM_ONLY]
    conflict = [c.description for c in contradictions]

    lines = [
        f"PERSON IDENTITY STATUS: {candidate.identity_state.value} "
        f"(confidence {candidate.identity_confidence:.2f}).",
        f"CANONICAL NAME: {candidate.display_name}.",
        f"CURRENT PROFESSIONAL ROLE(S): {', '.join(current) if current else 'UNKNOWN'}.",
        f"SUPPORTED FACTS: {len(supported)} fact-gated statement(s).",
        f"SOURCE-ONLY CLAIMS: {len(source_only)} claim(s) not independently verified.",
        f"CONTRADICTIONS: {len(conflict)} noted; material items require specialist handoff.",
        (
            "PRIVACY: Residential address, private phone/email, live location, "
            "biometrics, family dossier, and sensitive traits were not collected."
        ),
        (
            "NEXT ACTION: Use CORPINT/ORGINT for founder/CEO authority; use academic "
            "identifier for publication attribution."
        ),
    ]
    return "\n".join(lines)


# =====================================================================
# RESULT BUILDER
# =====================================================================

def build_result(
    case: Case,
    candidate: PersonCandidate,
    sources: List[Source],
    evidences: List[Evidence],
    roles: List[Role],
    publications: List[Publication],
    facts: List[FactGateResult],
    contradictions: List[Contradiction],
    gaps: List[KnowledgeGap],
    actions: List[NextAction],
    handoffs: List[Dict[str, str]],
    identity_info: Dict[str, Any],
    dual_review: Dict[str, Any],
    summary: str,
    status: Status,
    public_statements: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    public_statements = public_statements or []

    supported = [f for f in facts if f.status == ClaimState.SUPPORTED]
    partial = [f for f in facts if f.status == ClaimState.PARTIALLY_SUPPORTED]
    source_only = [f for f in facts if f.status == ClaimState.SOURCE_CLAIM_ONLY]
    disputed = [f for f in facts if f.status == ClaimState.DISPUTED]

    privacy_flags = sorted(
        {flag.value for e in evidences for flag in e.privacy_flags}
        | {
            PrivacyFlag.SENSITIVE_TRAIT_NOT_COLLECTED.value,
            PrivacyFlag.BIOMETRIC_PROHIBITED.value,
            PrivacyFlag.LIVE_LOCATION_PROHIBITED.value,
        }
    )

    current_roles = [r for r in roles if r.status == RoleStatus.CURRENT]
    historical_roles = [r for r in roles if r.status == RoleStatus.HISTORICAL]

    organization_affiliations = [
        {
            "organization_id": r.organization_id,
            "role": r.title,
            "status": r.status.value,
            "valid_from": r.start_date,
            "valid_to": r.end_date,
            "source_ids": r.source_ids,
            "confidence": r.confidence,
        }
        for r in roles
    ]

    directorships = [
        {
            "organization_id": r.organization_id,
            "title": r.title,
            "status": r.status.value,
            "valid_from": r.start_date,
            "valid_to": r.end_date,
            "source_ids": r.source_ids,
            "confidence": r.confidence,
            "note": "Legal directorship only if sourced from official corporate registry.",
        }
        for r in roles
        if r.role_type == "LEGAL_DIRECTOR"
    ]

    board_memberships = [
        {
            "organization_id": r.organization_id,
            "title": r.title,
            "status": r.status.value,
            "source_ids": r.source_ids,
        }
        for r in roles
        if r.role_type == "BOARD_MEMBER"
    ]

    source_independence: Dict[str, List[str]] = {}
    for s in sources:
        source_independence.setdefault(s.independence_group, []).append(s.id)

    timeline: List[Dict[str, Any]] = []
    for r in roles:
        timeline.append(
            {
                "date": r.start_date,
                "event": f"Role: {r.title} at {r.organization_id}",
                "status": r.status.value,
                "source_ids": r.source_ids,
            }
        )
    for p in publications:
        timeline.append(
            {
                "date": p.date,
                "event": f"Publication: {p.title}",
                "identifier": p.identifier,
                "source_ids": p.source_ids,
            }
        )
    timeline.sort(key=lambda x: x.get("date") or "")

    hypotheses: List[Dict[str, Any]] = []
    falsification: List[Dict[str, Any]] = []

    if candidate.person_candidate_id == PC_ID:
        hypotheses = [
            {
                "hypothesis_id": "H1",
                "statement": (
                    "Records from Northbridge University, ORCID-like identifier, "
                    "and corporate registry refer to the same professional person."
                ),
                "support": [
                    "same normalized name",
                    "same organization/role context",
                    "professional identifier",
                    "temporal consistency",
                ],
                "opposition": [
                    "founder/CEO claims are source-only",
                ],
                "unknowns": [
                    "founder status",
                    "CEO authority",
                ],
                "falsification_condition": (
                    "Registry name belongs to a different Jordan Anthony Rivers "
                    "or ORCID record is mislinked."
                ),
            },
            {
                "hypothesis_id": "H2",
                "statement": (
                    "The social profile is a namesake or unrelated account."
                ),
                "support": [
                    "different city mention",
                    "self-reported only",
                ],
                "opposition": [
                    "same name and company claim",
                ],
                "unknowns": [
                    "profile authenticity",
                ],
                "falsification_condition": (
                    "Official institutional page links to the profile or consistent "
                    "professional cross-links appear."
                ),
            },
        ]

        falsification = [
            {
                "hypothesis_id": "H1",
                "result": "NOT_FALSIFIED_ON_AVAILABLE_PUBLIC_EVIDENCE",
                "notes": (
                    "Multiple non-biometric public dimensions align; namesake risk "
                    "reduced but not eliminated."
                ),
            },
            {
                "hypothesis_id": "H2",
                "result": "UNRESOLVED",
                "notes": "Username/profile similarity alone is insufficient.",
            },
        ]

    replay = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "policy_checks": "public_record_only; privacy_minimization; no_biometrics; no_private_account_access",
        "source_ids": [s.id for s in sources],
        "evidence_ids": [e.id for e in evidences],
        "source_hashes": {
            s.id: hashlib.sha256((s.url + s.title).encode("utf-8")).hexdigest()[:12]
            for s in sources
        },
        "identity_merge_decisions": [
            "No merge performed solely on name.",
            "Sample candidate linked via official identifier, organization, role, and time consistency.",
        ],
        "privacy_exclusions": [
            "Residential address excluded",
            "Private phone/email excluded or redacted",
            "Live location not inferred",
            "Face/voice biometrics not used",
            "Sensitive traits not inferred",
        ],
    }

    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "questions": case.questions,
        "status": status.value,
        "source_ids": [s.id for s in sources],
        "evidence_ids": [e.id for e in evidences],
        "person_candidates": [candidate],
        "identity_states": {
            candidate.person_candidate_id: candidate.identity_state.value
        },
        "identity_resolution": identity_info,
        "names": candidate.normalized_names,
        "name_variants": candidate.normalized_names,
        "aliases": candidate.aliases,
        "professional_identifiers": candidate.professional_identifiers,
        "public_profiles": candidate.public_profiles,
        "public_contact_points": (
            [
                {
                    "type": "OFFICIAL_INSTITUTIONAL_PROFILE",
                    "value": "https://example.edu/faculty/jordan-a-rivers",
                    "status": "OFFICIALLY_PUBLISHED",
                }
            ]
            if candidate.person_candidate_id == PC_ID
            else []
        ),
        "safe_geographic_context": (
            [candidate.safe_location_context]
            if candidate.safe_location_context
            else []
        ),
        "current_roles": current_roles,
        "historical_roles": historical_roles,
        "organization_affiliations": organization_affiliations,
        "directorships": directorships,
        "board_memberships": board_memberships,
        "education_claims": [],
        "qualifications": [],
        "professional_licenses": [],
        "certifications": [],
        "publications": publications,
        "research_profiles": candidate.professional_identifiers,
        "patents": [],
        "conference_appearances": (
            [
                {
                    "event": "Example Data Ethics Conference",
                    "date": "2025-11-20",
                    "role": "speaker/bio subject",
                    "source_id": "SRC-CONF-BIO",
                }
            ]
            if candidate.person_candidate_id == PC_ID
            else []
        ),
        "public_statements": public_statements,
        "professional_associations": [],
        "awards": [],
        "company_context": directorships,
        "organization_context": organization_affiliations,
        "public_legal_context": [],
        "regulatory_context": [],
        "timeline_updates": timeline,
        "observations": [f.statement for f in facts],
        "candidate_facts": facts,
        "supported_facts": supported,
        "partial_facts": partial,
        "disputed_facts": disputed,
        "source_reliability": {s.id: s.reliability for s in sources},
        "source_bias": {s.id: s.notes for s in sources},
        "source_limitations": {s.id: [s.notes] if s.notes else [] for s in sources},
        "source_pedigree": {s.id: s.independence_group for s in sources},
        "source_independence": source_independence,
        "contradictions": contradictions,
        "identity_hypotheses": hypotheses,
        "falsification_results": falsification,
        "privacy_flags": privacy_flags,
        "sensitive_data_flags": [
            "No sensitive trait inference performed.",
            "No private contact disclosure performed.",
        ],
        "unknowns": [g.description for g in gaps] + candidate.limitations,
        "knowledge_gaps": gaps,
        "recommended_next_actions": actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "Local synthetic demo; no live public-record retrieval.",
            "Do not use for consequential decisions without human review.",
        ]
        + candidate.limitations,
        "analyst_summary": summary,
        "dual_ai_review": dual_review,
        "replay_manifest": replay,
    }


# =====================================================================
# BLOCKED RESULT
# =====================================================================

def blocked_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited person-intelligence request detected. "
            "This tool only supports lawful public-record research."
        ),
        "lawful_alternatives": [
            "Use official institutional/company pages for professional role verification.",
            "Use public academic identifiers for researcher disambiguation.",
            "Use official corporate registries for director/officer context.",
            "Do not collect private contact data, live location, biometrics, or sensitive traits.",
        ],
        "privacy_flags": [
            PrivacyFlag.BIOMETRIC_PROHIBITED.value,
            PrivacyFlag.LIVE_LOCATION_PROHIBITED.value,
            PrivacyFlag.SENSITIVE_TRAIT_NOT_COLLECTED.value,
        ],
        "limitations": [
            "No private-data collection performed.",
            "No live source retrieval performed.",
        ],
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline(case: Case) -> Dict[str, Any]:
    sources = sample_sources()
    evidences = sample_evidences()
    roles = sample_roles()
    publications = sample_publications()
    candidate = sample_candidate()
    contradictions = sample_contradictions()
    gaps = sample_knowledge_gaps()
    actions = sample_next_actions()
    handoffs = sample_specialist_handoffs()
    statements = sample_public_statements()

    source_map = {s.id: s for s in sources}
    evidence_map = {e.id: e for e in evidences}

    facts = build_sample_facts(source_map, evidence_map)
    identity_info = resolve_identity(candidate, roles, facts, contradictions)
    dual_review = dual_ai_review(candidate, facts, contradictions)
    summary = analyst_summary(candidate, roles, facts, contradictions)

    return build_result(
        case=case,
        candidate=candidate,
        sources=sources,
        evidences=evidences,
        roles=roles,
        publications=publications,
        facts=facts,
        contradictions=contradictions,
        gaps=gaps,
        actions=actions,
        handoffs=handoffs,
        identity_info=identity_info,
        dual_review=dual_review,
        summary=summary,
        status=Status.PARTIAL,
        public_statements=statements,
    )


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    name = case.person_names[0] if case.person_names else "Unnamed Person"
    norm = normalize_name(name)

    candidate = PersonCandidate(
        person_candidate_id=new_id("PC-", name),
        display_name=name,
        normalized_names=norm["variants"],
        known_roles=case.known_roles,
        known_organizations=case.known_organizations,
        safe_location_context=(
            "; ".join(case.known_locations) if case.known_locations else None
        ),
        limitations=[
            "No configured public-source adapter; no live lookup performed.",
            "Identity remains unresolved to avoid fabrication.",
        ],
    )

    gaps = [
        KnowledgeGap(
            gap_id="GAP-NO-SOURCES",
            description=(
                "No authorized public-record source adapter is configured in this "
                "local demo."
            ),
            importance="HIGH",
            recommended_source=(
                "Connect an authorized public-record API or provide a local source JSON corpus."
            ),
            specialist=None,
            expected_information_value=0.90,
        )
    ]

    actions = [
        NextAction(
            action_id="NA-CONFIGURE-SOURCES",
            description=(
                "Configure authorized public-source adapters or supply source JSON. "
                "Do not scrape private accounts or bypass authentication."
            ),
            priority=1,
            privacy_impact="LOW",
            expected_gain=0.90,
            specialist=None,
        )
    ]

    summary = (
        "PERSON UNRESOLVED: No configured public-source adapter. "
        "No identity was fabricated. Provide authorized public sources or run sample mode."
    )

    identity_info = {
        "score": 0.0,
        "state": IdentityState.UNRESOLVED.value,
        "reasons": ["No evidence."],
    }

    dual_review = {
        "primary_analyst": IdentityState.UNRESOLVED.value,
        "independent_skeptic_issues": [
            "No sources configured.",
            "No evidence available.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "AI agreement is not independent identity evidence.",
    }

    return build_result(
        case=case,
        candidate=candidate,
        sources=[],
        evidences=[],
        roles=[],
        publications=[],
        facts=[],
        contradictions=[],
        gaps=gaps,
        actions=actions,
        handoffs=[],
        identity_info=identity_info,
        dual_review=dual_review,
        summary=summary,
        status=Status.BLOCKED_CONFIGURATION,
        public_statements=[],
    )


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.questions,
            *case.person_names,
            *case.known_roles,
            *case.known_organizations,
        ]
    )

    violations = policy_guard(text)
    if violations:
        return blocked_result(case, violations)

    if case.case_id.startswith("SAMPLE-"):
        return run_sample_pipeline(case)

    return run_unconfigured_pipeline(case)


# =====================================================================
# CLI
# =====================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "PERSONINT public-record person research pipeline "
            "(local, privacy-aware, evidence-first demo)."
        )
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Run built-in synthetic public-record sample.",
    )
    parser.add_argument("--objective", help="Research objective.")
    parser.add_argument(
        "--name",
        action="append",
        default=[],
        help="Person name. Can be repeated.",
    )
    parser.add_argument(
        "--org",
        action="append",
        default=[],
        help="Known organization. Can be repeated.",
    )
    parser.add_argument("--role", help="Known role.")
    parser.add_argument("--time-range", help="Time range, e.g. 2020-2026.")
    parser.add_argument(
        "--question",
        action="append",
        default=[],
        help="Analytic question. Can be repeated.",
    )

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            questions=args.question,
            person_names=args.name,
            known_organizations=args.org,
            known_roles=[args.role] if args.role else [],
            time_range=args.time_range,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()