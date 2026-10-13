#!/usr/bin/env python3
"""
TRACEATLAS / RESEARCHINT — Local evidence-first research intelligence pipeline.

IMPORTANT SAFETY / POLICY NOTES:
- This is a local demo implementation.
- It does NOT access live literature databases, patent offices, standards bodies,
  code repositories, dataset archives, or paywalled publishers.
- It does NOT fabricate citations, DOIs, patent numbers, authors, datasets,
  experimental results, replications, or statistical significance.
- It does NOT bypass paywalls or use stolen academic credentials.
- It does NOT plagiarize or reproduce large copyrighted text.
- It does NOT automatically execute untrusted research code, notebooks,
  binaries, containers, or model checkpoints.
- It does NOT make final legal patentability, invalidity, infringement,
  or freedom-to-operate determinations.
- It supports authorized, evidence-first, copyright-aware research intelligence only.
- Sample data is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


PIPELINE_VERSION = "0.1.0-researchint-evidence-safe-demo"
DEFAULT_AS_OF = "2026-10-09T00:00:00Z"


# =====================================================================
# ENUMS
# =====================================================================

class Status(str, Enum):
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FULL_TEXT_UNAVAILABLE = "FULL_TEXT_UNAVAILABLE"
    METADATA_ONLY = "METADATA_ONLY"
    PAPER_VERSION_UNRESOLVED = "PAPER_VERSION_UNRESOLVED"
    PATENT_FAMILY_UNRESOLVED = "PATENT_FAMILY_UNRESOLVED"
    PRIOR_ART_DATE_UNRESOLVED = "PRIOR_ART_DATE_UNRESOLVED"
    REPLICATION_UNRESOLVED = "REPLICATION_UNRESOLVED"
    DATASET_UNAVAILABLE = "DATASET_UNAVAILABLE"
    CODE_UNAVAILABLE = "CODE_UNAVAILABLE"
    BLOCKED_COPYRIGHT = "BLOCKED_COPYRIGHT"
    BLOCKED_PERMISSION = "BLOCKED_PERMISSION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class SourceType(str, Enum):
    PEER_REVIEWED_JOURNAL = "PEER_REVIEWED_JOURNAL"
    PEER_REVIEWED_CONFERENCE = "PEER_REVIEWED_CONFERENCE"
    WORKSHOP = "WORKSHOP"
    PREPRINT = "PREPRINT"
    TECHNICAL_REPORT = "TECHNICAL_REPORT"
    THESIS = "THESIS"
    DISSERTATION = "DISSERTATION"
    BOOK = "BOOK"
    BOOK_CHAPTER = "BOOK_CHAPTER"
    STANDARD = "STANDARD"
    SPECIFICATION = "SPECIFICATION"
    PATENT_APPLICATION = "PATENT_APPLICATION"
    GRANTED_PATENT = "GRANTED_PATENT"
    PATENT_FAMILY_MEMBER = "PATENT_FAMILY_MEMBER"
    GOVERNMENT_REPORT = "GOVERNMENT_REPORT"
    INDUSTRY_WHITEPAPER = "INDUSTRY_WHITEPAPER"
    DATASET = "DATASET"
    SOFTWARE_ARTIFACT = "SOFTWARE_ARTIFACT"
    BLOG = "BLOG"
    NEWS = "NEWS"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class SearchMode(str, Enum):
    EXHAUSTIVE = "EXHAUSTIVE"
    SYSTEMATIC = "SYSTEMATIC"
    SCOPING = "SCOPING"
    RAPID = "RAPID"
    STATE_OF_ART = "STATE_OF_ART"
    PRIOR_ART = "PRIOR_ART"
    PATENT_LANDSCAPE = "PATENT_LANDSCAPE"
    VERIFICATION = "VERIFICATION"
    CUSTOM = "CUSTOM"


class ScreeningDecision(str, Enum):
    TITLE_SCREEN = "TITLE_SCREEN"
    ABSTRACT_SCREEN = "ABSTRACT_SCREEN"
    FULL_TEXT_SCREEN = "FULL_TEXT_SCREEN"
    INCLUDED = "INCLUDED"
    EXCLUDED = "EXCLUDED"


class ExclusionReason(str, Enum):
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    WRONG_POPULATION = "WRONG_POPULATION"
    WRONG_METHOD = "WRONG_METHOD"
    WRONG_TECHNOLOGY = "WRONG_TECHNOLOGY"
    WRONG_DATE = "WRONG_DATE"
    NO_RELEVANT_OUTCOME = "NO_RELEVANT_OUTCOME"
    DUPLICATE = "DUPLICATE"
    SUPERSEDED_VERSION = "SUPERSEDED_VERSION"
    LANGUAGE_LIMIT = "LANGUAGE_LIMIT"
    FULL_TEXT_UNAVAILABLE = "FULL_TEXT_UNAVAILABLE"
    OTHER = "OTHER"


class Availability(str, Enum):
    FULL_TEXT_AVAILABLE = "FULL_TEXT_AVAILABLE"
    ABSTRACT_ONLY = "ABSTRACT_ONLY"
    METADATA_ONLY = "METADATA_ONLY"
    PARTIAL_TEXT = "PARTIAL_TEXT"
    UNKNOWN = "UNKNOWN"


class ClaimType(str, Enum):
    EMPIRICAL_RESULT = "EMPIRICAL_RESULT"
    THEORETICAL_CLAIM = "THEORETICAL_CLAIM"
    METHOD_CLAIM = "METHOD_CLAIM"
    PERFORMANCE_CLAIM = "PERFORMANCE_CLAIM"
    CAUSAL_CLAIM = "CAUSAL_CLAIM"
    CORRELATIONAL_CLAIM = "CORRELATIONAL_CLAIM"
    MECHANISTIC_CLAIM = "MECHANISTIC_CLAIM"
    REVIEW_CONCLUSION = "REVIEW_CONCLUSION"
    AUTHOR_INTERPRETATION = "AUTHOR_INTERPRETATION"
    LIMITATION = "LIMITATION"
    FUTURE_WORK = "FUTURE_WORK"
    OTHER = "OTHER"


class StudyDesign(str, Enum):
    RCT = "RCT"
    COHORT = "COHORT"
    CASE_CONTROL = "CASE_CONTROL"
    CROSS_SECTIONAL = "CROSS_SECTIONAL"
    CASE_STUDY = "CASE_STUDY"
    EXPERIMENT = "EXPERIMENT"
    SIMULATION = "SIMULATION"
    BENCHMARK = "BENCHMARK"
    OBSERVATIONAL = "OBSERVATIONAL"
    QUALITATIVE = "QUALITATIVE"
    MIXED_METHODS = "MIXED_METHODS"
    SYSTEMATIC_REVIEW = "SYSTEMATIC_REVIEW"
    META_ANALYSIS = "META_ANALYSIS"
    TECHNICAL_DEMONSTRATION = "TECHNICAL_DEMONSTRATION"
    OTHER = "OTHER"


class ReplicationState(str, Enum):
    DIRECT_REPLICATION = "DIRECT_REPLICATION"
    CONCEPTUAL_REPLICATION = "CONCEPTUAL_REPLICATION"
    PARTIAL_REPLICATION = "PARTIAL_REPLICATION"
    FAILED_REPLICATION = "FAILED_REPLICATION"
    INDEPENDENT_VALIDATION = "INDEPENDENT_VALIDATION"
    AUTHOR_SELF_REPLICATION = "AUTHOR_SELF_REPLICATION"
    NO_REPLICATION_FOUND = "NO_REPLICATION_FOUND"
    UNKNOWN = "UNKNOWN"


class ReproducibilityState(str, Enum):
    REPRODUCED_INDEPENDENTLY = "REPRODUCED_INDEPENDENTLY"
    REPRODUCED_BY_AUTHORS = "REPRODUCED_BY_AUTHORS"
    ARTIFACTS_COMPLETE = "ARTIFACTS_COMPLETE"
    ARTIFACTS_PARTIAL = "ARTIFACTS_PARTIAL"
    ARTIFACTS_UNAVAILABLE = "ARTIFACTS_UNAVAILABLE"
    FAILED_REPRODUCTION_REPORTED = "FAILED_REPRODUCTION_REPORTED"
    UNKNOWN = "UNKNOWN"


class RetractionStatus(str, Enum):
    RETRACTED = "RETRACTED"
    PARTIALLY_RETRACTED = "PARTIALLY_RETRACTED"
    EXPRESSION_OF_CONCERN = "EXPRESSION_OF_CONCERN"
    CORRECTED = "CORRECTED"
    ERRATUM = "ERRATUM"
    NO_KNOWN_NOTICE = "NO_KNOWN_NOTICE"
    UNKNOWN = "UNKNOWN"


class PatentStatus(str, Enum):
    APPLICATION = "APPLICATION"
    PUBLISHED_APPLICATION = "PUBLISHED_APPLICATION"
    GRANTED = "GRANTED"
    EXPIRED = "EXPIRED"
    LAPSED = "LAPSED"
    WITHDRAWN = "WITHDRAWN"
    ABANDONED = "ABANDONED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class FamilyRelation(str, Enum):
    SAME_FAMILY = "SAME_FAMILY"
    EXTENDED_FAMILY = "EXTENDED_FAMILY"
    CONTINUATION = "CONTINUATION"
    DIVISIONAL = "DIVISIONAL"
    CONTINUATION_IN_PART = "CONTINUATION_IN_PART"
    NATIONAL_PHASE = "NATIONAL_PHASE"
    RELATED_APPLICATION = "RELATED_APPLICATION"
    UNKNOWN = "UNKNOWN"


class PriorArtRelevance(str, Enum):
    HIGHLY_RELEVANT_PRIOR_ART_CANDIDATE = "HIGHLY_RELEVANT_PRIOR_ART_CANDIDATE"
    RELEVANT_PRIOR_ART_CANDIDATE = "RELEVANT_PRIOR_ART_CANDIDATE"
    PARTIAL_OVERLAP = "PARTIAL_OVERLAP"
    BACKGROUND_ART = "BACKGROUND_ART"
    LATER_PUBLICATION = "LATER_PUBLICATION"
    NOT_RELEVANT = "NOT_RELEVANT"
    UNKNOWN = "UNKNOWN"


class ClaimElementState(str, Enum):
    EXPLICITLY_DISCLOSED = "EXPLICITLY_DISCLOSED"
    IMPLICIT_CANDIDATE = "IMPLICIT_CANDIDATE"
    PARTIAL = "PARTIAL"
    NOT_FOUND = "NOT_FOUND"
    AMBIGUOUS = "AMBIGUOUS"


class EvidenceGrade(str, Enum):
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    LIMITED = "LIMITED"
    WEAK = "WEAK"
    CONFLICTED = "CONFLICTED"
    INSUFFICIENT = "INSUFFICIENT"
    UNKNOWN = "UNKNOWN"


class VerificationState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CANDIDATE = "CANDIDATE"
    OBSERVED = "OBSERVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    DISPUTED = "DISPUTED"
    UNSUPPORTED = "UNSUPPORTED"


class FindingType(str, Enum):
    PUBLISHED_CLAIM_OBSERVED = "PUBLISHED_CLAIM_OBSERVED"
    METHOD_OBSERVED = "METHOD_OBSERVED"
    RESULT_OBSERVED = "RESULT_OBSERVED"
    REPLICATION_OBSERVED = "REPLICATION_OBSERVED"
    NON_INDEPENDENT_CITATION = "NON_INDEPENDENT_CITATION"
    CITATION_NOT_ENDORSEMENT = "CITATION_NOT_ENDORSEMENT"
    SOURCE_DEPENDENCY = "SOURCE_DEPENDENCY"
    RETRACTION_OBSERVED = "RETRACTION_OBSERVED"
    CORRECTION_OBSERVED = "CORRECTION_OBSERVED"
    BENCHMARK_INCOMPARABILITY_CANDIDATE = "BENCHMARK_INCOMPARABILITY_CANDIDATE"
    STATISTICAL_SIGNIFICANCE_NOT_PRACTICAL = "STATISTICAL_SIGNIFICANCE_NOT_PRACTICAL"
    CORRELATION_NOT_CAUSATION = "CORRELATION_NOT_CAUSATION"
    PRIOR_ART_CANDIDATE = "PRIOR_ART_CANDIDATE"
    PATENT_APPLICATION_NOT_GRANTED = "PATENT_APPLICATION_NOT_GRANTED"
    FAMILY_MEMBER_NOT_INDEPENDENT = "FAMILY_MEMBER_NOT_INDEPENDENT"
    CLAIM_ELEMENT_PARTIAL_OVERLAP = "CLAIM_ELEMENT_PARTIAL_OVERLAP"
    NOVELTY_CANDIDATE = "NOVELTY_CANDIDATE"
    RESEARCH_GAP_CANDIDATE = "RESEARCH_GAP_CANDIDATE"
    FULL_TEXT_LIMITATION = "FULL_TEXT_LIMITATION"
    COPYRIGHT_LIMITATION = "COPYRIGHT_LIMITATION"
    CODE_UNTRUSTED_NOT_EXECUTED = "CODE_UNTRUSTED_NOT_EXECUTED"
    LEGAL_REVIEW_REQUIRED = "LEGAL_REVIEW_REQUIRED"
    EVIDENCE_FAMILY = "EVIDENCE_FAMILY"
    CONTRADICTION_OBSERVED = "CONTRADICTION_OBSERVED"
    REPRODUCIBILITY_OBSERVED = "REPRODUCIBILITY_OBSERVED"
    LIMITATION_OBSERVED = "LIMITATION_OBSERVED"
    VERSION_LINK_OBSERVED = "VERSION_LINK_OBSERVED"
    DUPLICATE_PUBLICATION_CANDIDATE = "DUPLICATE_PUBLICATION_CANDIDATE"


class GapType(str, Enum):
    FULL_TEXT_UNAVAILABLE = "FULL_TEXT_UNAVAILABLE"
    METHOD_UNCLEAR = "METHOD_UNCLEAR"
    DATASET_UNAVAILABLE = "DATASET_UNAVAILABLE"
    CODE_UNAVAILABLE = "CODE_UNAVAILABLE"
    REPLICATION_ABSENT = "REPLICATION_ABSENT"
    CONFLICTING_STUDIES = "CONFLICTING_STUDIES"
    PAPER_VERSION_UNRESOLVED = "PAPER_VERSION_UNRESOLVED"
    RETRACTION_STATUS_UNRESOLVED = "RETRACTION_STATUS_UNRESOLVED"
    PRIOR_ART_DATE_UNCERTAIN = "PRIOR_ART_DATE_UNCERTAIN"
    PATENT_FAMILY_INCOMPLETE = "PATENT_FAMILY_INCOMPLETE"
    CLAIM_ELEMENT_AMBIGUOUS = "CLAIM_ELEMENT_AMBIGUOUS"
    STANDARD_VERSION_UNCLEAR = "STANDARD_VERSION_UNCLEAR"
    RESEARCH_GAP_CONFIDENCE_LOW = "RESEARCH_GAP_CONFIDENCE_LOW"
    SOURCE_INDEPENDENCE_GAP = "SOURCE_INDEPENDENCE_GAP"
    COPYRIGHT_LIMIT = "COPYRIGHT_LIMIT"
    LEGAL_REVIEW_REQUIRED = "LEGAL_REVIEW_REQUIRED"


class PrivacyFlag(str, Enum):
    CASE_SCOPED = "CASE_SCOPED"
    PROFESSIONAL_CONTEXT_ONLY = "PROFESSIONAL_CONTEXT_ONLY"
    NO_PRIVATE_PROFILING = "NO_PRIVATE_PROFILING"
    COPYRIGHT_AWARE = "COPYRIGHT_AWARE"
    NO_PAYWALL_BYPASS = "NO_PAYWALL_BYPASS"
    NO_STOLEN_CREDENTIALS = "NO_STOLEN_CREDENTIALS"
    NO_AUTO_CODE_EXECUTION = "NO_AUTO_CODE_EXECUTION"
    NO_FABRICATED_CITATIONS = "NO_FABRICATED_CITATIONS"
    LOCAL_ONLY_DEFAULT = "LOCAL_ONLY_DEFAULT"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


# =====================================================================
# CONSTANTS
# =====================================================================

SOURCE_FACTOR: Dict[SourceType, float] = {
    SourceType.PEER_REVIEWED_JOURNAL: 0.88,
    SourceType.PEER_REVIEWED_CONFERENCE: 0.86,
    SourceType.WORKSHOP: 0.76,
    SourceType.PREPRINT: 0.78,
    SourceType.TECHNICAL_REPORT: 0.80,
    SourceType.THESIS: 0.78,
    SourceType.DISSERTATION: 0.78,
    SourceType.BOOK: 0.80,
    SourceType.BOOK_CHAPTER: 0.78,
    SourceType.STANDARD: 0.88,
    SourceType.SPECIFICATION: 0.80,
    SourceType.PATENT_APPLICATION: 0.84,
    SourceType.GRANTED_PATENT: 0.88,
    SourceType.PATENT_FAMILY_MEMBER: 0.84,
    SourceType.GOVERNMENT_REPORT: 0.84,
    SourceType.INDUSTRY_WHITEPAPER: 0.68,
    SourceType.DATASET: 0.82,
    SourceType.SOFTWARE_ARTIFACT: 0.78,
    SourceType.BLOG: 0.55,
    SourceType.NEWS: 0.55,
    SourceType.OTHER: 0.65,
    SourceType.UNKNOWN: 0.50,
}

PROHIBITED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "FABRICATE_CITATIONS_OR_RESULTS",
        re.compile(
            r"\b(fabricate|invent|generate fake|make up)\s+"
            r"(citation|doi|paper|author|patent number|dataset|experimental result|statistical significance|replication)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "BYPASS_PAYWALL_OR_CREDENTIALS",
        re.compile(
            r"\b(bypass|circumvent|evade)\s+(paywall|institutional authentication|access control)\b|"
            r"\bstolen academic credential\b|\buse stolen (login|credential|token)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PLAGIARISM_OR_COPYRIGHT_OVERREPRODUCTION",
        re.compile(
            r"\b(plagiariz\w+|copy\s+entire\s+paper|reproduce\s+full\s+paper|"
            r"reproduce\s+entire\s+book|copy\s+large\s+portion\s+of\s+standard)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "AUTO_UNTRUSTED_CODE_EXECUTION",
        re.compile(
            r"\b(execute|run|install)\s+(untrusted|unknown|suspicious)\s+"
            r"(code|repository|notebook|binary|container|script)\b|"
            r"\brun research code automatically\b",
            re.IGNORECASE,
        ),
    ),
    (
        "LEGAL_PATENT_DETERMINATION",
        re.compile(
            r"\b(determine|certify|conclude|guarantee)\s+"
            r"(patent invalid|patent infringed|novelty confirmed|freedom to operate cleared|"
            r"claim not novel as a legal matter)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "FABRICATE_RESEARCH_CONDUCT",
        re.compile(
            r"\b(fabricate|invent)\s+(survey participant|lab data|interview|peer review|replication)\b",
            re.IGNORECASE,
        ),
    ),
]


# =====================================================================
# UTILITIES
# =====================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}{h}" if prefix else h


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_short(text: str) -> str:
    return stable_hash(text)[:16]


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


def normalize_text(value: str) -> str:
    s = unicodedata.normalize("NFKC", value or "")
    s = s.lower().strip()
    s = re.sub(r"[^\w\s\-'.:/@]", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def dt_or_min(value: Optional[str]) -> datetime:
    dt = parse_dt(value)
    return dt if dt else datetime.min.replace(tzinfo=timezone.utc)


def days_between(a: Optional[str], b: Optional[str]) -> Optional[int]:
    da = parse_dt(a)
    db = parse_dt(b)
    if not da or not db:
        return None
    return abs((db - da).days)


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
    independence_group: str = "UNKNOWN"
    reliability: float = 0.5
    derived_from: Optional[str] = None
    published_at: Optional[str] = None
    retrieved_at: Optional[str] = None
    notes: str = ""


@dataclass
class Evidence:
    id: str
    source_id: str
    artifact_type: str
    excerpt: str
    observed_at: Optional[str] = None
    content_hash: str = ""
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Query:
    id: str
    query_text: str
    databases: List[str] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    search_date: Optional[str] = None
    result_count: Optional[int] = None
    screened_count: Optional[int] = None
    included_count: Optional[int] = None
    excluded_count: Optional[int] = None
    version: str = "v1"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Claim:
    id: str
    source_type: str
    source_id: str
    claim_type: ClaimType
    statement: str
    subject: str = ""
    predicate: str = ""
    object: str = ""
    population: str = ""
    conditions: str = ""
    metric: str = ""
    effect: Optional[float] = None
    time: Optional[str] = None
    locator: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    verification_state: VerificationState = VerificationState.INCONCLUSIVE
    evidence_grade: EvidenceGrade = EvidenceGrade.UNKNOWN
    confidence: float = 0.0


@dataclass
class MethodRecord:
    id: str
    paper_id: str
    design: StudyDesign = StudyDesign.OTHER
    sample: str = ""
    dataset_ids: List[str] = field(default_factory=list)
    baseline: str = ""
    model: str = ""
    evaluation: str = ""
    statistical_method: str = ""
    limitations: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class ResultRecord:
    id: str
    paper_id: str
    method: str = ""
    task: str = ""
    dataset_id: str = ""
    benchmark_id: str = ""
    metric: str = ""
    value: Optional[float] = None
    baseline_metric: str = ""
    baseline_value: Optional[float] = None
    uncertainty: str = ""
    p_value: Optional[float] = None
    effect_size: str = ""
    conditions: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Paper:
    id: str
    title: str
    authors: List[str] = field(default_factory=list)
    year: Optional[int] = None
    venue: str = ""
    publication_type: SourceType = SourceType.UNKNOWN
    doi: str = ""
    arxiv_id: str = ""
    abstract: str = ""
    keywords: List[str] = field(default_factory=list)
    publication_date: Optional[str] = None
    version: str = ""
    preprint_of: Optional[str] = None
    published_as: Optional[str] = None
    extended_as: Optional[str] = None
    retraction_status: RetractionStatus = RetractionStatus.UNKNOWN
    correction_status: RetractionStatus = RetractionStatus.UNKNOWN
    availability: Availability = Availability.UNKNOWN
    funding: str = ""
    conflicts: str = ""
    code_url: str = ""
    dataset_ids: List[str] = field(default_factory=list)
    benchmark_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    claim_ids: List[str] = field(default_factory=list)
    method_ids: List[str] = field(default_factory=list)
    result_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class PatentClaim:
    id: str
    patent_id: str
    number: int
    independent: bool = True
    text_summary: str = ""
    elements: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Patent:
    id: str
    publication_number: str = ""
    application_number: str = ""
    grant_number: str = ""
    title: str = ""
    inventors: List[str] = field(default_factory=list)
    applicant: str = ""
    assignee: str = ""
    priority_date: Optional[str] = None
    filing_date: Optional[str] = None
    publication_date: Optional[str] = None
    grant_date: Optional[str] = None
    jurisdiction: str = ""
    family_id: str = ""
    family_relation: FamilyRelation = FamilyRelation.UNKNOWN
    status: PatentStatus = PatentStatus.UNKNOWN
    claim_ids: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)
    legal_status_source: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Standard:
    id: str
    number: str = ""
    title: str = ""
    version: str = ""
    status: str = ""
    publication_date: Optional[str] = None
    normative_sections: List[str] = field(default_factory=list)
    features: List[str] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Dataset:
    id: str
    name: str = ""
    version: str = ""
    source: str = ""
    size: str = ""
    license: str = ""
    collection_method: str = ""
    time_range: str = ""
    population: str = ""
    labeling_method: str = ""
    known_bias: str = ""
    accessibility: str = "UNKNOWN"
    hash: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Benchmark:
    id: str
    task: str = ""
    dataset_id: str = ""
    metric: str = ""
    protocol: str = ""
    split: str = ""
    baseline: str = ""
    version: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class TechnicalFeature:
    id: str
    name: str = ""
    normalized: str = ""
    description: str = ""
    first_seen_candidate: Optional[str] = None
    papers: List[str] = field(default_factory=list)
    patents: List[str] = field(default_factory=list)
    standards: List[str] = field(default_factory=list)
    repositories: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class ReplicationRecord:
    id: str
    original_paper_id: str
    replicating_paper_id: str
    state: ReplicationState = ReplicationState.UNKNOWN
    independence_state: str = "UNKNOWN"
    shared_dataset: bool = False
    shared_code: bool = False
    shared_authors: bool = False
    notes: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class RetractionRecord:
    id: str
    paper_id: str
    status: RetractionStatus = RetractionStatus.UNKNOWN
    reason: str = ""
    date: Optional[str] = None
    scope: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class CitationEdge:
    id: str
    citing_paper_id: str
    cited_paper_id: str
    context: str = "UNKNOWN"
    date: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class PriorArtCandidate:
    id: str
    target_patent_id: str
    reference_id: str
    reference_type: str
    reference_date: Optional[str] = None
    public_availability_date: Optional[str] = None
    relevance: PriorArtRelevance = PriorArtRelevance.UNKNOWN
    temporal_relevance: str = "UNKNOWN"
    disclosed_elements: List[str] = field(default_factory=list)
    missing_elements: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class ClaimElementMatrix:
    id: str
    target_claim_id: str
    reference_id: str
    reference_type: str
    mappings: List[Dict[str, str]] = field(default_factory=list)
    overall_relevance: PriorArtRelevance = PriorArtRelevance.UNKNOWN
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class ResearchGap:
    id: str
    gap_type: str
    description: str
    supporting_source_ids: List[str] = field(default_factory=list)
    why_existing_work_is_insufficient: str = ""
    scope: str = ""
    importance: str = "MEDIUM"
    feasibility: str = "UNKNOWN"
    evidence_quality: EvidenceGrade = EvidenceGrade.UNKNOWN
    potential_research_question: str = ""
    falsification_condition: str = ""


@dataclass
class Hypothesis:
    id: str
    statement: str
    kind: str
    supporting_finding_ids: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_finding_ids: List[str] = field(default_factory=list)
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
    contradiction_type: str
    description: str
    subject_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    status: str = "OPEN"
    recommended_resolution: str = ""


@dataclass
class KnowledgeGap:
    id: str
    gap_type: GapType
    description: str
    about_subject_ids: List[str] = field(default_factory=list)
    about_finding_ids: List[str] = field(default_factory=list)
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: Optional[str] = None
    expected_information_value: float = 0.0


@dataclass
class NextAction:
    id: str
    description: str
    priority: int = 1
    privacy_impact: str = "LOW_IF_AUTHORIZED"
    expected_gain: float = 0.0
    specialist: Optional[str] = None
    requires_human_approval: bool = False


@dataclass
class Recommendation:
    id: str
    category: str
    action: str
    target: str
    rationale: str
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    approval: str = "HUMAN_APPROVAL_REQUIRED"
    business_impact: str = "REQUIRES_REVIEW"
    reversibility: str = "REQUIRES_VALIDATION"
    limitations: List[str] = field(default_factory=list)


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    research_questions: List[str] = field(default_factory=list)
    topic: str = ""
    technical_domain: str = ""
    concepts: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    known_papers: List[str] = field(default_factory=list)
    known_patents: List[str] = field(default_factory=list)
    known_standards: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    institutions: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    jurisdictions: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=lambda: ["en"])
    publication_types: List[str] = field(default_factory=list)
    search_mode: SearchMode = SearchMode.SYSTEMATIC
    scope: List[str] = field(default_factory=lambda: ["authorized_public_or_permitted_sources", "copyright_aware", "evidence_first"])
    authorization: str = "demo_authorized_research_intelligence"
    as_of: str = DEFAULT_AS_OF
    sample: bool = False
    budget: Optional[str] = None
    deadline: Optional[str] = None


# =====================================================================
# RESEARCHINT ENGINE
# =====================================================================

class ResearchInt:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.as_of = case.as_of or DEFAULT_AS_OF

        self.sources: Dict[str, Source] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.queries: Dict[str, Query] = {}
        self.papers: Dict[str, Paper] = {}
        self.patents: Dict[str, Patent] = {}
        self.patent_claims: Dict[str, PatentClaim] = {}
        self.standards: Dict[str, Standard] = {}
        self.datasets: Dict[str, Dataset] = {}
        self.benchmarks: Dict[str, Benchmark] = {}
        self.features: Dict[str, TechnicalFeature] = {}
        self.claims: Dict[str, Claim] = {}
        self.methods: Dict[str, MethodRecord] = {}
        self.results: Dict[str, ResultRecord] = {}
        self.replications: Dict[str, ReplicationRecord] = {}
        self.retractions: Dict[str, RetractionRecord] = {}
        self.citations: Dict[str, CitationEdge] = {}
        self.prior_art: Dict[str, PriorArtCandidate] = {}
        self.matrices: Dict[str, ClaimElementMatrix] = {}
        self.research_gaps: List[ResearchGap] = []
        self.novelty_candidates: List[Dict[str, Any]] = []
        self.findings: Dict[str, Any] = {}
        self.contradictions: List[Contradiction] = []
        self.hypotheses: List[Hypothesis] = []
        self.knowledge_gaps: List[KnowledgeGap] = []
        self.actions: List[NextAction] = []
        self.recommendations: List[Recommendation] = []
        self.handoffs: List[Dict[str, str]] = []
        self.source_dependencies: Dict[str, List[str]] = defaultdict(list)
        self.evidence_families: Dict[str, List[str]] = defaultdict(list)
        self.validation_errors: List[str] = []

    # -----------------------------------------------------------------
    # Adders
    # -----------------------------------------------------------------

    def add_source(self, source: Source) -> Source:
        self.sources[source.id] = source
        return source

    def add_evidence(self, evidence: Evidence) -> Evidence:
        if not evidence.content_hash:
            evidence.content_hash = stable_hash("|".join([
                evidence.source_id,
                evidence.artifact_type,
                evidence.excerpt,
            ]))
        self.evidence[evidence.id] = evidence
        return evidence

    def add_query(self, query: Query) -> Query:
        self.queries[query.id] = query
        return query

    def add_paper(self, paper: Paper) -> Paper:
        self.papers[paper.id] = paper
        return paper

    def add_patent(self, patent: Patent) -> Patent:
        self.patents[patent.id] = patent
        return patent

    def add_patent_claim(self, claim: PatentClaim) -> PatentClaim:
        self.patent_claims[claim.id] = claim
        if claim.patent_id in self.patents:
            if claim.id not in self.patents[claim.patent_id].claim_ids:
                self.patents[claim.patent_id].claim_ids.append(claim.id)
        return claim

    def add_standard(self, standard: Standard) -> Standard:
        self.standards[standard.id] = standard
        return standard

    def add_dataset(self, dataset: Dataset) -> Dataset:
        self.datasets[dataset.id] = dataset
        return dataset

    def add_benchmark(self, benchmark: Benchmark) -> Benchmark:
        self.benchmarks[benchmark.id] = benchmark
        return benchmark

    def add_feature(self, feature: TechnicalFeature) -> TechnicalFeature:
        self.features[feature.id] = feature
        return feature

    def add_claim(self, claim: Claim) -> Claim:
        self.claims[claim.id] = claim
        if claim.source_type == "PAPER" and claim.source_id in self.papers:
            if claim.id not in self.papers[claim.source_id].claim_ids:
                self.papers[claim.source_id].claim_ids.append(claim.id)
        return claim

    def add_method(self, method: MethodRecord) -> MethodRecord:
        self.methods[method.id] = method
        if method.paper_id in self.papers:
            if method.id not in self.papers[method.paper_id].method_ids:
                self.papers[method.paper_id].method_ids.append(method.id)
        return method

    def add_result(self, result: ResultRecord) -> ResultRecord:
        self.results[result.id] = result
        if result.paper_id in self.papers:
            if result.id not in self.papers[result.paper_id].result_ids:
                self.papers[result.paper_id].result_ids.append(result.id)
        return result

    def add_replication(self, rep: ReplicationRecord) -> ReplicationRecord:
        self.replications[rep.id] = rep
        return rep

    def add_retraction(self, ret: RetractionRecord) -> RetractionRecord:
        self.retractions[ret.id] = ret
        return ret

    def add_citation(self, edge: CitationEdge) -> CitationEdge:
        self.citations[edge.id] = edge
        return edge

    def add_prior_art(self, pa: PriorArtCandidate) -> PriorArtCandidate:
        self.prior_art[pa.id] = pa
        return pa

    def add_matrix(self, matrix: ClaimElementMatrix) -> ClaimElementMatrix:
        self.matrices[matrix.id] = matrix
        return matrix

    def add_finding(self, finding: Any) -> Any:
        if finding.id in self.findings:
            return self.findings[finding.id]
        self.findings[finding.id] = finding
        return finding

    def add_contradiction(self, contradiction: Contradiction) -> Contradiction:
        if any(c.description == contradiction.description for c in self.contradictions):
            return self.contradictions[0]
        self.contradictions.append(contradiction)
        return contradiction

    # -----------------------------------------------------------------
    # Source lineage / independence
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
        if cur and cur.independence_group and cur.independence_group != "UNKNOWN":
            return cur.independence_group
        return cur.id if cur else source_id

    def source_families(self, source_ids: List[str]) -> Set[str]:
        families: Set[str] = set()
        for sid in source_ids:
            fam = self.get_source_family(sid)
            families.add(fam or sid)
        return families

    def independence_state(self, source_ids: List[str]) -> str:
        if not source_ids:
            return "UNKNOWN"
        families = self.source_families(source_ids)
        if len(source_ids) == 1:
            return "SINGLE_SOURCE"
        if len(families) == 1:
            return "DEPENDENT"
        if len(families) == len(source_ids):
            return "INDEPENDENT"
        return "PARTIALLY_DEPENDENT"

    # -----------------------------------------------------------------
    # Analysis stages
    # -----------------------------------------------------------------

    def normalize_versions_and_screening(self) -> None:
        for paper in self.papers.values():
            if paper.preprint_of and paper.preprint_of in self.papers:
                self.add_finding(FindingLite(
                    id=new_id("FIND-VER-", paper.id + paper.preprint_of),
                    finding_type=FindingType.VERSION_LINK_OBSERVED,
                    subject_id=paper.id,
                    statement=f"Paper {paper.id} is linked as a version/preprint of {paper.preprint_of}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=paper.source_ids,
                    evidence_ids=paper.evidence_ids,
                    limitations=["Preprint and published version may differ; preserve both."],
                ))

            if paper.published_as and paper.published_as in self.papers:
                self.add_finding(FindingLite(
                    id=new_id("FIND-PUBVER-", paper.id + paper.published_as),
                    finding_type=FindingType.VERSION_LINK_OBSERVED,
                    subject_id=paper.id,
                    statement=f"Paper {paper.id} has published version {paper.published_as}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=paper.source_ids,
                    evidence_ids=paper.evidence_ids,
                    limitations=["Use published version for current synthesis where appropriate; preserve preprint."],
                ))

            if paper.availability != Availability.FULL_TEXT_AVAILABLE:
                self.add_finding(FindingLite(
                    id=new_id("FIND-AVAIL-", paper.id),
                    finding_type=FindingType.FULL_TEXT_LIMITATION,
                    subject_id=paper.id,
                    statement=f"Paper {paper.id} availability is {paper.availability.value}; deep methodological conclusions are limited.",
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=paper.source_ids,
                    evidence_ids=paper.evidence_ids,
                    limitations=[
                        "Do not claim to have read unavailable full text.",
                        "Do not bypass paywalls or use stolen credentials.",
                    ],
                ))

            if paper.retraction_status in {
                RetractionStatus.RETRACTED,
                RetractionStatus.PARTIALLY_RETRACTED,
                RetractionStatus.EXPRESSION_OF_CONCERN,
            }:
                self.add_finding(FindingLite(
                    id=new_id("FIND-RET-", paper.id),
                    finding_type=FindingType.RETRACTION_OBSERVED,
                    subject_id=paper.id,
                    statement=f"Paper {paper.id} has retraction/concern status {paper.retraction_status.value}.",
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=paper.source_ids,
                    evidence_ids=paper.evidence_ids,
                    limitations=[
                        "Retraction does not automatically make every historical claim false.",
                        "Do not silently cite retracted findings as normal evidence.",
                        "Record official reason, scope, date, and source.",
                    ],
                ))

            if paper.correction_status in {
                RetractionStatus.CORRECTED,
                RetractionStatus.ERRATUM,
            }:
                self.add_finding(FindingLite(
                    id=new_id("FIND-COR-", paper.id),
                    finding_type=FindingType.CORRECTION_OBSERVED,
                    subject_id=paper.id,
                    statement=f"Paper {paper.id} has correction/erratum status {paper.correction_status.value}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=paper.source_ids,
                    evidence_ids=paper.evidence_ids,
                    limitations=["Use corrected version for current synthesis where appropriate; preserve old version."],
                ))

    def extract_claims_methods_results(self) -> None:
        for claim in self.claims.values():
            if claim.claim_type == ClaimType.PERFORMANCE_CLAIM:
                ftype = FindingType.RESULT_OBSERVED
            elif claim.claim_type == ClaimType.METHOD_CLAIM:
                ftype = FindingType.METHOD_OBSERVED
            elif claim.claim_type == ClaimType.LIMITATION:
                ftype = FindingType.LIMITATION_OBSERVED
            elif claim.claim_type == ClaimType.CAUSAL_CLAIM:
                ftype = FindingType.CORRELATION_NOT_CAUSATION
            else:
                ftype = FindingType.PUBLISHED_CLAIM_OBSERVED

            self.add_finding(FindingLite(
                id=new_id("FIND-CLAIM-", claim.id),
                finding_type=ftype,
                subject_id=claim.id,
                statement=f"Claim extracted from {claim.source_type} {claim.source_id}: {claim.statement}",
                verification_state=VerificationState.OBSERVED,
                source_ids=self._source_ids_for_claim(claim),
                evidence_ids=claim.evidence_ids,
                limitations=claim.limitations + [
                    "Author claim is not automatically research fact.",
                    "Published claim is not automatically true.",
                ],
            ))

        for method in self.methods.values():
            self.add_finding(FindingLite(
                id=new_id("FIND-METHOD-", method.id),
                finding_type=FindingType.METHOD_OBSERVED,
                subject_id=method.id,
                statement=(
                    f"Method observed in paper {method.paper_id}: design={method.design.value}, "
                    f"model={method.model}, baseline={method.baseline}, datasets={method.dataset_ids}."
                ),
                verification_state=VerificationState.OBSERVED,
                source_ids=self.papers[method.paper_id].source_ids if method.paper_id in self.papers else [],
                evidence_ids=method.evidence_ids,
                limitations=method.limitations + ["Study design alone does not determine quality."],
            ))

        for result in self.results.values():
            self.add_finding(FindingLite(
                id=new_id("FIND-RESULT-", result.id),
                finding_type=FindingType.RESULT_OBSERVED,
                subject_id=result.id,
                statement=(
                    f"Result observed in paper {result.paper_id}: method={result.method}, task={result.task}, "
                    f"metric={result.metric}, value={result.value}, baseline={result.baseline_value}, "
                    f"dataset={result.dataset_id}, conditions={result.conditions}."
                ),
                verification_state=VerificationState.OBSERVED,
                source_ids=self.papers[result.paper_id].source_ids if result.paper_id in self.papers else [],
                evidence_ids=result.evidence_ids,
                limitations=result.limitations + [
                    "Benchmark score is not real-world performance.",
                    "Statistical significance is not practical significance.",
                ],
            ))

        for bm in self.benchmarks.values():
            if bm.metric and bm.dataset_id:
                self.add_finding(FindingLite(
                    id=new_id("FIND-BM-", bm.id),
                    finding_type=FindingType.BENCHMARK_INCOMPARABILITY_CANDIDATE,
                    subject_id=bm.id,
                    statement=(
                        f"Benchmark {bm.id} uses dataset={bm.dataset_id}, metric={bm.metric}, "
                        f"split={bm.split}, protocol={bm.protocol}. Compare only under compatible conditions."
                    ),
                    verification_state=VerificationState.CANDIDATE,
                    source_ids=bm.source_ids,
                    evidence_ids=bm.evidence_ids,
                    limitations=[
                        "Do not compare random headline numbers.",
                        "Dataset version, split, metric, preprocessing, and protocol matter.",
                    ],
                ))

    def build_citation_and_source_dependency(self) -> None:
        for edge in self.citations.values():
            context_state = VerificationState.SUPPORTED
            if edge.context in {"USES_METHOD", "REPLICATES", "EXTENDS"}:
                ftype = FindingType.NON_INDEPENDENT_CITATION
            elif edge.context == "CONTRADICTS":
                ftype = FindingType.CONTRADICTION_OBSERVED
            else:
                ftype = FindingType.CITATION_NOT_ENDORSEMENT

            self.add_finding(FindingLite(
                id=new_id("FIND-CITE-", edge.id),
                finding_type=ftype,
                subject_id=edge.id,
                statement=(
                    f"Citation edge {edge.id}: {edge.citing_paper_id} cites {edge.cited_paper_id} "
                    f"in context {edge.context}."
                ),
                verification_state=context_state,
                source_ids=self._paper_source_ids(edge.citing_paper_id) + self._paper_source_ids(edge.cited_paper_id),
                evidence_ids=edge.evidence_ids,
                limitations=edge.limitations + [
                    "Citation is not automatically corroboration.",
                    "Citation may be background, criticism, method adoption, or repetition.",
                ],
            ))

        # Evidence families by shared dataset/code/authors.
        fam_key_map: Dict[str, List[str]] = defaultdict(list)
        for paper in self.papers.values():
            keys = []
            for ds in paper.dataset_ids:
                keys.append(f"DATASET:{ds}")
            if paper.code_url:
                keys.append(f"CODE:{normalize_text(paper.code_url)}")
            if paper.authors:
                keys.append(f"AUTHORS:{','.join(sorted(normalize_text(a) for a in paper.authors[:3]))}")
            for k in keys:
                fam_key_map[k].append(paper.id)

        for key, paper_ids in fam_key_map.items():
            uniq = sorted(set(paper_ids))
            if len(uniq) > 1:
                self.evidence_families[key] = uniq
                self.add_finding(FindingLite(
                    id=new_id("FIND-FAM-", key),
                    finding_type=FindingType.EVIDENCE_FAMILY,
                    subject_id=key,
                    statement=f"Papers {uniq} share evidence-family signal {key}; do not count as multiple independent confirmations.",
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=sorted({sid for pid in uniq for sid in self._paper_source_ids(pid)}),
                    evidence_ids=sorted({eid for pid in uniq for eid in self.papers[pid].evidence_ids}),
                    limitations=[
                        "Multiple papers using same dataset/code/cohort may form one evidence family.",
                        "Do not inflate evidence count.",
                    ],
                ))
                for pid in uniq:
                    self.source_dependencies[pid].append(key)

    def assess_replication_reproducibility(self) -> None:
        for rep in self.replications.values():
            self.add_finding(FindingLite(
                id=new_id("FIND-REP-", rep.id),
                finding_type=FindingType.REPLICATION_OBSERVED,
                subject_id=rep.id,
                statement=(
                    f"Replication record {rep.id}: original={rep.original_paper_id}, "
                    f"replicating={rep.replicating_paper_id}, state={rep.state.value}, "
                    f"independence={rep.independence_state}, shared_dataset={rep.shared_dataset}, "
                    f"shared_code={rep.shared_code}, notes={rep.notes}."
                ),
                verification_state=VerificationState.OBSERVED,
                source_ids=self._paper_source_ids(rep.original_paper_id) + self._paper_source_ids(rep.replicating_paper_id),
                evidence_ids=rep.evidence_ids,
                limitations=rep.limitations + [
                    "Peer review is not replication.",
                    "Same authors/data/code is not independent replication.",
                ],
            ))

            if rep.independence_state in {"DEPENDENT", "PARTIALLY_DEPENDENT"} or rep.shared_code or rep.shared_dataset:
                self.add_finding(FindingLite(
                    id=new_id("FIND-REPDEP-", rep.id),
                    finding_type=FindingType.SOURCE_DEPENDENCY,
                    subject_id=rep.id,
                    statement=f"Replication {rep.id} is not fully independent due to shared dataset/code/authors or dependent source family.",
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=self._paper_source_ids(rep.original_paper_id) + self._paper_source_ids(rep.replicating_paper_id),
                    evidence_ids=rep.evidence_ids,
                    limitations=["Do not count dependent replication as independent corroboration."],
                ))

        for paper in self.papers.values():
            state = ReproducibilityState.UNKNOWN
            reasons: List[str] = []
            if paper.code_url:
                restricted = any(
                    self.datasets.get(ds) and self.datasets[ds].accessibility in {"RESTRICTED", "REQUEST", "UNAVAILABLE"}
                    for ds in paper.dataset_ids
                )
                if restricted:
                    state = ReproducibilityState.ARTIFACTS_PARTIAL
                    reasons.append("Code URL present but dataset access is restricted/unavailable.")
                else:
                    state = ReproducibilityState.ARTIFACTS_COMPLETE
                    reasons.append("Code and dataset metadata appear available; not executed.")
            else:
                state = ReproducibilityState.ARTIFACTS_UNAVAILABLE
                reasons.append("No code URL recorded.")

            self.add_finding(FindingLite(
                id=new_id("FIND-REPRO-", paper.id),
                finding_type=FindingType.REPRODUCIBILITY_OBSERVED,
                subject_id=paper.id,
                statement=f"Reproducibility state for {paper.id}: {state.value}. Reasons: {reasons}",
                verification_state=VerificationState.OBSERVED,
                source_ids=paper.source_ids,
                evidence_ids=paper.evidence_ids,
                limitations=[
                    "Code availability is not reproducibility.",
                    "Do not automatically execute untrusted research code.",
                    "Static inspection only unless separate sandbox/authorization exists.",
                ],
            ))

    def assess_retractions_corrections(self) -> None:
        for ret in self.retractions.values():
            paper = self.papers.get(ret.paper_id)
            if paper:
                paper.retraction_status = ret.status
            self.add_finding(FindingLite(
                id=new_id("FIND-RECREC-", ret.id),
                finding_type=FindingType.RETRACTION_OBSERVED if ret.status in {
                    RetractionStatus.RETRACTED,
                    RetractionStatus.PARTIALLY_RETRACTED,
                    RetractionStatus.EXPRESSION_OF_CONCERN,
                } else FindingType.CORRECTION_OBSERVED,
                subject_id=ret.paper_id,
                statement=(
                    f"Retraction/correction record {ret.id}: paper={ret.paper_id}, status={ret.status.value}, "
                    f"reason={ret.reason}, date={ret.date}, scope={ret.scope}."
                ),
                verification_state=VerificationState.SUPPORTED,
                source_ids=ret.source_ids,
                evidence_ids=ret.evidence_ids,
                limitations=ret.limitations + [
                    "Do not ignore retractions or corrections.",
                    "Retraction reason and scope matter; do not rewrite history independently.",
                ],
            ))

    def assess_patents_and_prior_art(self) -> None:
        # Patent status and family.
        for patent in self.patents.values():
            if patent.status in {PatentStatus.APPLICATION, PatentStatus.PUBLISHED_APPLICATION}:
                self.add_finding(FindingLite(
                    id=new_id("FIND-PATSTAT-", patent.id),
                    finding_type=FindingType.PATENT_APPLICATION_NOT_GRANTED,
                    subject_id=patent.id,
                    statement=f"Patent {patent.id} status is {patent.status.value}; application publication is not granted enforceable right.",
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=patent.source_ids,
                    evidence_ids=patent.evidence_ids,
                    limitations=[
                        "Patent application is not granted patent.",
                        "Do not imply enforceable rights automatically.",
                        "Legal status may vary by jurisdiction.",
                    ],
                ))

        family_groups: Dict[str, List[str]] = defaultdict(list)
        for patent in self.patents.values():
            if patent.family_id:
                family_groups[patent.family_id].append(patent.id)
        for fam, ids in family_groups.items():
            if len(ids) > 1:
                self.add_finding(FindingLite(
                    id=new_id("FIND-FAM-", fam),
                    finding_type=FindingType.FAMILY_MEMBER_NOT_INDEPENDENT,
                    subject_id=fam,
                    statement=f"Patent family {fam} contains {ids}; family members are not independent inventions.",
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=sorted({sid for pid in ids for sid in self.patents[pid].source_ids}),
                    evidence_ids=sorted({eid for pid in ids for eid in self.patents[pid].evidence_ids}),
                    limitations=["Do not count each family member as independent invention."],
                ))

        # Prior art candidates.
        for pa in self.prior_art.values():
            target = self.patents.get(pa.target_patent_id)
            if target and target.priority_date and pa.reference_date:
                if dt_or_min(pa.reference_date) <= dt_or_min(target.priority_date):
                    pa.temporal_relevance = "PRE_PRIORITY_OR_EQUAL"
                else:
                    pa.temporal_relevance = "LATER_PUBLICATION"
                    if pa.relevance != PriorArtRelevance.LATER_PUBLICATION:
                        pa.relevance = PriorArtRelevance.LATER_PUBLICATION

            ref_paper = self.papers.get(pa.reference_id)
            if ref_paper and ref_paper.retraction_status in {
                RetractionStatus.RETRACTED,
                RetractionStatus.PARTIALLY_RETRACTED,
                RetractionStatus.EXPRESSION_OF_CONCERN,
            }:
                pa.limitations.append(
                    "Reference has retraction/concern status; technical disclosure history may still matter, but evidentiary weight is reduced."
                )

            self.add_finding(FindingLite(
                id=new_id("FIND-PA-", pa.id),
                finding_type=FindingType.PRIOR_ART_CANDIDATE,
                subject_id=pa.id,
                statement=(
                    f"Prior-art candidate {pa.id} for target {pa.target_patent_id}: reference={pa.reference_id} "
                    f"({pa.reference_type}), date={pa.reference_date}, temporal={pa.temporal_relevance}, "
                    f"relevance={pa.relevance.value}, disclosed={pa.disclosed_elements}, missing={pa.missing_elements}."
                ),
                verification_state=VerificationState.CANDIDATE,
                source_ids=pa.source_ids,
                evidence_ids=pa.evidence_ids,
                limitations=pa.limitations + [
                    "RESEARCHINT identifies candidates, not final legal validity.",
                    "Feature overlap is not automatically legal anticipation.",
                    "Do not conclude patent invalidity.",
                ],
            ))

        # Claim-element matrices.
        for matrix in self.matrices.values():
            partial_or_missing = [
                m for m in matrix.mappings
                if m.get("state") in {
                    ClaimElementState.NOT_FOUND.value,
                    ClaimElementState.PARTIAL.value,
                    ClaimElementState.IMPLICIT_CANDIDATE.value,
                    ClaimElementState.AMBIGUOUS.value,
                }
            ]
            if partial_or_missing:
                self.add_finding(FindingLite(
                    id=new_id("FIND-MATRIXPART-", matrix.id),
                    finding_type=FindingType.CLAIM_ELEMENT_PARTIAL_OVERLAP,
                    subject_id=matrix.id,
                    statement=(
                        f"Claim-element matrix {matrix.id} for claim {matrix.target_claim_id} vs reference {matrix.reference_id} "
                        f"has partial/missing/implicit elements: {partial_or_missing}."
                    ),
                    verification_state=VerificationState.CANDIDATE,
                    source_ids=matrix.source_ids,
                    evidence_ids=matrix.evidence_ids,
                    limitations=matrix.limitations + [
                        "Do not mark legally anticipated automatically.",
                        "Single-reference disclosure and multi-reference obviousness-type analysis are separate.",
                    ],
                ))

            self.add_finding(FindingLite(
                id=new_id("FIND-LEGAL-", matrix.id),
                finding_type=FindingType.LEGAL_REVIEW_REQUIRED,
                subject_id=matrix.target_claim_id,
                statement=f"Claim-element matrix {matrix.id} requires human patent/legal review before any invalidity, novelty, or infringement conclusion.",
                verification_state=VerificationState.SUPPORTED,
                source_ids=matrix.source_ids,
                evidence_ids=matrix.evidence_ids,
                limitations=[
                    "RESEARCHINT is not a patent attorney.",
                    "No final patentability, invalidity, infringement, or freedom-to-operate determination.",
                ],
            ))

    def detect_contradictions(self) -> None:
        existing = {c.description for c in self.contradictions}

        # Result contradictions by method/task/metric.
        groups: Dict[Tuple[str, str, str], List[ResultRecord]] = defaultdict(list)
        for r in self.results.values():
            if r.method and r.task and r.metric and r.value is not None:
                groups[(r.method, r.task, r.metric)].append(r)

        for key, rs in groups.items():
            if len(rs) < 2:
                continue
            vals = [float(r.value) for r in rs if r.value is not None]
            if not vals:
                continue
            if max(vals) - min(vals) <= 0.03:
                continue
            source_ids = sorted({sid for r in rs for sid in self._paper_source_ids(r.paper_id)})
            families = self.source_families(source_ids)
            if len(families) < 2:
                continue
            desc = (
                f"Conflicting results for method/task/metric {key}: "
                + "; ".join(f"{r.paper_id}={r.value} ({r.conditions})" for r in rs)
            )
            if desc in existing:
                continue
            fid = new_id("FIND-CONRES-", desc)
            self.add_finding(FindingLite(
                id=fid,
                finding_type=FindingType.CONTRADICTION_OBSERVED,
                subject_id="|".join(key),
                statement=desc,
                verification_state=VerificationState.DISPUTED,
                source_ids=source_ids,
                evidence_ids=sorted({eid for r in rs for eid in r.evidence_ids}),
                limitations=[
                    "Contradiction is not automatically error.",
                    "Differences may reflect dataset, protocol, baseline, preprocessing, sample, or metric.",
                ],
            ))
            self.add_contradiction(Contradiction(
                id=new_id("CON-", desc),
                contradiction_type="RESULT_DISAGREEMENT",
                description=desc,
                subject_ids=[r.id for r in rs],
                finding_ids=[fid],
                evidence_ids=sorted({eid for r in rs for eid in r.evidence_ids}),
                source_ids=source_ids,
                severity="MEDIUM",
                status="OPEN",
                recommended_resolution="Normalize dataset version, split, metric, preprocessing, baseline, and evaluation protocol before comparing.",
            ))
            existing.add(desc)

        # Causal claim from non-causal design.
        for claim in self.claims.values():
            if claim.claim_type != ClaimType.CAUSAL_CLAIM:
                continue
            paper = self.papers.get(claim.source_id) if claim.source_type == "PAPER" else None
            if not paper:
                continue
            method_ids = paper.method_ids
            designs = [self.methods[mid].design for mid in method_ids if mid in self.methods]
            if designs and all(d not in {StudyDesign.RCT, StudyDesign.COHORT} for d in designs):
                desc = f"Causal claim {claim.id} is not supported by study design; available designs are {[d.value for d in designs]}."
                if desc in existing:
                    continue
                fid = new_id("FIND-CAUSAL-", claim.id)
                self.add_finding(FindingLite(
                    id=fid,
                    finding_type=FindingType.CORRELATION_NOT_CAUSATION,
                    subject_id=claim.id,
                    statement=desc,
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=paper.source_ids,
                    evidence_ids=claim.evidence_ids,
                    limitations=["Correlation is not causation.", "Causal claims require appropriate design/controls/identification assumptions."],
                ))
                existing.add(desc)

    def grade_evidence(self) -> None:
        for claim in self.claims.values():
            paper = self.papers.get(claim.source_id) if claim.source_type == "PAPER" else None
            if paper and paper.retraction_status in {
                RetractionStatus.RETRACTED,
                RetractionStatus.PARTIALLY_RETRACTED,
                RetractionStatus.EXPRESSION_OF_CONCERN,
            }:
                claim.evidence_grade = EvidenceGrade.INSUFFICIENT
                claim.verification_state = VerificationState.UNSUPPORTED
                claim.limitations.append("Source paper has retraction/concern status; claim not usable as normal evidence.")
                continue

            if paper and paper.availability != Availability.FULL_TEXT_AVAILABLE:
                claim.evidence_grade = EvidenceGrade.LIMITED
                claim.limitations.append("Full-text/method access limitation reduces evidence grade.")
                continue

            # Independent replication boost.
            independent = any(
                rep.replicating_paper_id == claim.source_id or rep.original_paper_id == claim.source_id
                for rep in self.replications.values()
                if rep.state == ReplicationState.INDEPENDENT_VALIDATION
                and rep.independence_state == "INDEPENDENT"
            )
            dependent_only = any(
                rep.original_paper_id == claim.source_id
                for rep in self.replications.values()
                if rep.independence_state in {"DEPENDENT", "PARTIALLY_DEPENDENT"}
            )

            if independent:
                claim.evidence_grade = EvidenceGrade.MODERATE
            elif dependent_only:
                claim.evidence_grade = EvidenceGrade.LIMITED
            elif claim.claim_type == ClaimType.PERFORMANCE_CLAIM:
                claim.evidence_grade = EvidenceGrade.MODERATE
            else:
                claim.evidence_grade = EvidenceGrade.UNKNOWN

    def fact_gate_findings(self) -> None:
        for f in self.findings.values():
            srcs = [self.sources[sid] for sid in f.source_ids if sid in self.sources]
            if not srcs:
                f.confidence = 0.0
                if f.verification_state == VerificationState.OBSERVED:
                    f.verification_state = VerificationState.INCONCLUSIVE
                f.limitations.append("No mapped source for fact gate.")
                continue

            families = self.source_families(f.source_ids)
            max_rel = max((s.reliability for s in srcs), default=0.5)
            direct = max((SOURCE_FACTOR.get(s.source_type, 0.65) for s in srcs), default=0.65)
            base = max_rel * direct

            if len(families) >= 2:
                base = min(0.99, base * 1.05)
            elif len(families) == 1 and len(f.source_ids) > 1:
                base *= 0.90
                f.limitations.append("Multiple sources share one upstream source family.")

            ft = f.finding_type
            if ft == FindingType.PUBLISHED_CLAIM_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                base = min(base, 0.80)
                f.limitations.append("Publication establishes claim was published, not that claim is true.")

            elif ft == FindingType.RESULT_OBSERVED:
                f.verification_state = VerificationState.SUPPORTED if base >= 0.70 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.extend([
                    "Result is condition-bound to dataset, split, metric, protocol, and version.",
                    "Benchmark score is not real-world performance.",
                ])

            elif ft == FindingType.METHOD_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Study design alone does not determine quality.")

            elif ft == FindingType.REPLICATION_OBSERVED:
                f.verification_state = VerificationState.SUPPORTED if base >= 0.70 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.append("Replication classification depends on independence of group/data/analysis.")

            elif ft in {FindingType.SOURCE_DEPENDENCY, FindingType.EVIDENCE_FAMILY, FindingType.NON_INDEPENDENT_CITATION}:
                f.verification_state = VerificationState.SUPPORTED
                base = min(base, 0.85)
                f.limitations.append("Do not inflate independent evidence count.")

            elif ft == FindingType.CITATION_NOT_ENDORSEMENT:
                f.verification_state = VerificationState.SUPPORTED
                f.limitations.append("Citation is not corroboration.")

            elif ft == FindingType.RETRACTION_OBSERVED:
                f.verification_state = VerificationState.SUPPORTED
                f.limitations.append("Retracted evidence must not be silently cited as normal evidence.")

            elif ft == FindingType.CORRECTION_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Use corrected version where appropriate; preserve historical version.")

            elif ft == FindingType.BENCHMARK_INCOMPARABILITY_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.70)
                f.limitations.append("Only compare compatible dataset version, split, metric, preprocessing, and protocol.")

            elif ft == FindingType.STATISTICAL_SIGNIFICANCE_NOT_PRACTICAL:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("p-value is not practical importance.")

            elif ft == FindingType.CORRELATION_NOT_CAUSATION:
                f.verification_state = VerificationState.SUPPORTED
                f.limitations.append("Do not rewrite correlational findings as causal.")

            elif ft == FindingType.PRIOR_ART_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.72)
                f.specialist_handoff = "LEGALINT / human patent specialist"
                f.limitations.extend([
                    "Prior-art candidate is not legal invalidity.",
                    "Chronology and public availability must be verified by authoritative sources.",
                ])

            elif ft == FindingType.PATENT_APPLICATION_NOT_GRANTED:
                f.verification_state = VerificationState.SUPPORTED
                f.limitations.append("Application publication is not grant or enforceable right.")

            elif ft == FindingType.FAMILY_MEMBER_NOT_INDEPENDENT:
                f.verification_state = VerificationState.SUPPORTED
                f.limitations.append("Family members are not independent inventions.")

            elif ft == FindingType.CLAIM_ELEMENT_PARTIAL_OVERLAP:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.70)
                f.limitations.append("Feature overlap is not legal anticipation.")

            elif ft == FindingType.NOVELTY_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.60)
                f.limitations.append("Literature gap or no-search-result is not novelty confirmation.")

            elif ft == FindingType.RESEARCH_GAP_CANDIDATE:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Gap requires evidence of searched corpus and unresolved question.")

            elif ft in {
                FindingType.FULL_TEXT_LIMITATION,
                FindingType.COPYRIGHT_LIMITATION,
                FindingType.CODE_UNTRUSTED_NOT_EXECUTED,
                FindingType.LEGAL_REVIEW_REQUIRED,
            }:
                f.verification_state = VerificationState.SUPPORTED
                f.limitations.append("Boundary preserved; no unlawful access, no overreproduction, no auto-execution, no legal determination.")

            elif ft == FindingType.CONTRADICTION_OBSERVED:
                f.verification_state = VerificationState.DISPUTED
                base = min(base, 0.82)
                f.limitations.append("Preserve contradictory findings; investigate heterogeneity.")

            elif ft == FindingType.REPRODUCIBILITY_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Code availability is not reproducibility; artifacts not executed.")

            elif ft == FindingType.LIMITATION_OBSERVED:
                f.verification_state = VerificationState.OBSERVED

            elif ft == FindingType.VERSION_LINK_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Preprint and published version may differ.")

            elif ft == FindingType.DUPLICATE_PUBLICATION_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                f.limitations.append("Do not count duplicates as independent studies.")

            else:
                if base >= 0.75:
                    f.verification_state = VerificationState.SUPPORTED
                elif base >= 0.60:
                    f.verification_state = VerificationState.PARTIALLY_SUPPORTED
                elif base >= 0.40:
                    f.verification_state = VerificationState.INCONCLUSIVE
                else:
                    f.verification_state = VerificationState.UNSUPPORTED

            f.confidence = round(max(0.0, min(0.99, base)), 3)

    def build_novelty_candidates(self) -> None:
        target = self.patents.get("PAT-TARGET-US-SYN-1000001")
        if not target:
            return
        # No absolute novelty determination. Only searched-corpus candidate.
        self.novelty_candidates.append({
            "id": "NOVC-TARGET-COMBINATION",
            "target_patent_id": target.id,
            "statement": (
                "In the searched corpus, no single pre-priority reference was found that explicitly discloses all claim-1 elements "
                "E1-E4 together. This is a NOVELTY_CANDIDATE only, not novelty confirmation."
            ),
            "state": "NOVELTY_CANDIDATE",
            "multi_reference_obviousness_candidate": True,
            "limitations": [
                "No search result is not no prior art.",
                "Earliest found disclosure is not earliest ever disclosure.",
                "Legal novelty/obviousness requires qualified patent review.",
            ],
            "source_ids": sorted({sid for pa in self.prior_art.values() for sid in pa.source_ids}),
            "evidence_ids": sorted({eid for pa in self.prior_art.values() for eid in pa.evidence_ids}),
        })
        self.add_finding(FindingLite(
            id="FIND-NOVELTY-TARGET",
            finding_type=FindingType.NOVELTY_CANDIDATE,
            subject_id=target.id,
            statement="Combination of transaction streaming, rolling histogram, drift-based dynamic thresholding, and blocking appears not fully explicitly disclosed in one searched pre-priority reference; legal review required.",
            verification_state=VerificationState.CANDIDATE,
            source_ids=sorted({sid for pa in self.prior_art.values() for sid in pa.source_ids}),
            evidence_ids=sorted({eid for pa in self.prior_art.values() for eid in pa.evidence_ids}),
            limitations=[
                "Not novelty confirmed.",
                "Not patent invalidity.",
                "Not infringement.",
                "Multi-reference obviousness-type analysis requires human patent professional.",
            ],
            specialist_handoff="LEGALINT / human patent specialist",
        ))

    def build_research_gaps(self) -> None:
        gaps = [
            ResearchGap(
                id="RGAP-INDEPENDENT-DEPLOYMENT-EVAL",
                gap_type="EVIDENCE_GAP",
                description="Independent evaluation on realistic deployment datasets with matched protocols remains limited.",
                supporting_source_ids=["SRC-OPENALEX", "SRC-CROSSREF"],
                why_existing_work_is_insufficient=(
                    "P1/P2 share dataset/code family; P3 uses different metric/dataset; P4 uses different protocol. "
                    "No single independent deployment-equivalent benchmark resolves practical superiority."
                ),
                scope="fraud detection, SynthNet vs LogReg, independent datasets, matched protocol",
                importance="HIGH",
                feasibility="MEDIUM",
                evidence_quality=EvidenceGrade.LIMITED,
                potential_research_question="Does SynthNet maintain material advantage under independent, deployment-realistic data and matched evaluation protocol?",
                falsification_condition="A well-powered independent study shows no practical advantage under deployment-realistic conditions.",
            ),
            ResearchGap(
                id="RGAP-DATASET-ACCESS",
                gap_type="DATASET_GAP",
                description="Primary dataset D1 is restricted, limiting reproducibility and label-provenance audit.",
                supporting_source_ids=["SRC-ZENODO", "SRC-CROSSREF"],
                why_existing_work_is_insufficient="Code may be available, but dataset access restrictions prevent independent reproduction and label noise assessment.",
                scope="DS-D1-V1",
                importance="MEDIUM",
                feasibility="LOW_WITHOUT_AUTHORIZATION",
                evidence_quality=EvidenceGrade.LIMITED,
                potential_research_question="Can results be reproduced on an authorized mirror or synthetic equivalent with documented label provenance?",
                falsification_condition="Authorized reproduction fails materially due to dataset-specific leakage or labeling artifacts.",
            ),
            ResearchGap(
                id="RGAP-PRIOR-ART-LEGAL",
                gap_type="PRIOR_ART_UNCERTAINTY",
                description="Claim-element E3 drift-based dynamic thresholding has implicit/partial disclosures in searched pre-priority references.",
                supporting_source_ids=["SRC-PATENT-OFFICE", "SRC-ARXIV", "SRC-STANDARDS"],
                why_existing_work_is_insufficient=(
                    "References disclose related rolling-histogram and thresholding concepts, but explicitness of drift-based dynamic adjustment "
                    "is ambiguous and jurisdiction-specific legal construction is required."
                ),
                scope="Claim 1 elements E1-E4 of PAT-TARGET-US-SYN-1000001",
                importance="HIGH",
                feasibility="REQUIRES_LEGAL_REVIEW",
                evidence_quality=EvidenceGrade.CONFLICTED,
                potential_research_question="Does any pre-priority reference explicitly disclose drift-based dynamic threshold adjustment in the claimed transaction-blocking system?",
                falsification_condition="A qualified patent professional identifies explicit single-reference disclosure or confirms no anticipatory disclosure.",
            ),
        ]
        self.research_gaps = gaps
        for g in gaps:
            self.add_finding(FindingLite(
                id=new_id("FIND-RGAP-", g.id),
                finding_type=FindingType.RESEARCH_GAP_CANDIDATE,
                subject_id=g.id,
                statement=f"Research gap candidate {g.id}: {g.description}",
                verification_state=VerificationState.OBSERVED,
                source_ids=g.supporting_source_ids,
                evidence_ids=[],
                limitations=[
                    "Gap is not novelty.",
                    "Gap requires evidence of searched corpus and unresolved question.",
                    "Do not call gap 'novel because obscure'.",
                ],
            ))

    def build_hypotheses(self) -> None:
        hyps: List[Hypothesis] = []

        perf_findings = [f.id for f in self.findings.values() if f.finding_type == FindingType.RESULT_OBSERVED]
        dep_findings = [f.id for f in self.findings.values() if f.finding_type in {FindingType.SOURCE_DEPENDENCY, FindingType.EVIDENCE_FAMILY}]
        contra_findings = [f.id for f in self.findings.values() if f.finding_type == FindingType.CONTRADICTION_OBSERVED]
        bm_findings = [f.id for f in self.findings.values() if f.finding_type == FindingType.BENCHMARK_INCOMPARABILITY_CANDIDATE]

        hyps.append(Hypothesis(
            id="H-METHOD-GENUINELY-BETTER",
            statement="SynthNet genuinely materially outperforms LogReg for fraud detection across realistic conditions.",
            kind="CAPABILITY_ADVANTAGE",
            supporting_finding_ids=perf_findings,
            contradicting_finding_ids=contra_findings + dep_findings,
            assumptions=["Reported results are accurate and conditions are comparable."],
            predictions=["Independent studies with matched protocols would show consistent practical advantage."],
            falsification_conditions=[
                "Advantage disappears on independent dataset.",
                "Baseline is weak or outdated.",
                "Gain is explained by preprocessing/leakage.",
                "Only dependent replications support advantage.",
            ],
            status=HypothesisStatus.UNRESOLVED,
            confidence=0.45,
            limitations=["Benchmark score is not real-world performance.", "P2 is not independent corroboration."],
        ))

        hyps.append(Hypothesis(
            id="H-DATASET-SPECIFIC",
            statement="Reported advantage may be dataset- or benchmark-specific.",
            kind="EVAL_VALIDITY",
            supporting_finding_ids=contra_findings + bm_findings,
            assumptions=["D1/D2 and metrics differ materially."],
            predictions=["Held-out independent benchmark would reduce or eliminate advantage."],
            falsification_conditions=[
                "Multiple independent datasets with matched protocol show consistent effect size.",
                "Ablation isolates model contribution from data preprocessing.",
            ],
            status=HypothesisStatus.POSSIBLE,
            confidence=0.55,
            limitations=["Do not compare incompatible benchmarks as identical."],
        ))

        hyps.append(Hypothesis(
            id="H-WEAK-BASELINE",
            statement="Performance gain may partly result from weak or outdated baseline configuration.",
            kind="BASELINE_QUALITY",
            supporting_finding_ids=[f.id for f in self.findings.values() if f.finding_type == FindingType.METHOD_OBSERVED],
            assumptions=["Baseline tuning/preprocessing may not be equivalent."],
            predictions=["Strong tuned baseline would reduce reported delta."],
            falsification_conditions=[
                "Authors report hyperparameter search and equivalent preprocessing for baseline.",
                "Independent replication uses strong baseline and retains advantage.",
            ],
            status=HypothesisStatus.POSSIBLE,
            confidence=0.40,
            limitations=["Beating weak baseline does not necessarily represent strong advancement."],
        ))

        hyps.append(Hypothesis(
            id="H-PRIOR-ART-EXPLICIT",
            statement="A pre-priority single reference explicitly discloses all target claim elements.",
            kind="PRIOR_ART",
            supporting_finding_ids=[f.id for f in self.findings.values() if f.finding_type == FindingType.PRIOR_ART_CANDIDATE],
            contradicting_finding_ids=[f.id for f in self.findings.values() if f.finding_type == FindingType.CLAIM_ELEMENT_PARTIAL_OVERLAP],
            assumptions=["Dates and public availability are correct."],
            predictions=["Claim-element matrix would show all elements explicitly disclosed."],
            falsification_conditions=[
                "E3 is only implicit/partial.",
                "Reference is later than priority date.",
                "Reference is retracted/unclear and cannot establish enabling disclosure without legal review.",
            ],
            status=HypothesisStatus.UNRESOLVED,
            confidence=0.35,
            limitations=["No legal anticipation or invalidity determination."],
        ))

        self.hypotheses = hyps

    def build_knowledge_gaps(self) -> None:
        existing = {g.description for g in self.knowledge_gaps}

        for paper in self.papers.values():
            if paper.availability != Availability.FULL_TEXT_AVAILABLE:
                desc = f"Full text/method detail unavailable for {paper.id}."
                if desc not in existing:
                    self.knowledge_gaps.append(KnowledgeGap(
                        id=new_id("KGAP-FULL-", paper.id),
                        gap_type=GapType.FULL_TEXT_UNAVAILABLE,
                        description=desc,
                        about_subject_ids=[paper.id],
                        importance="MEDIUM",
                        recommended_source="Authorized publisher/institutional access or open version; do not bypass paywall.",
                        specialist="RESEARCHINT / DOCINT",
                        expected_information_value=0.70,
                    ))
                    existing.add(desc)

            if paper.code_url == "":
                desc = f"Code/artifact availability unknown for {paper.id}."
                if desc not in existing:
                    self.knowledge_gaps.append(KnowledgeGap(
                        id=new_id("KGAP-CODE-", paper.id),
                        gap_type=GapType.CODE_UNAVAILABLE,
                        description=desc,
                        about_subject_ids=[paper.id],
                        importance="MEDIUM",
                        recommended_source="Author repository, supplementary material, software archive metadata; static inspection only.",
                        specialist="REPOINT / RESEARCHINT",
                        expected_information_value=0.65,
                    ))
                    existing.add(desc)

        for ds in self.datasets.values():
            if ds.accessibility in {"RESTRICTED", "UNAVAILABLE", "REQUEST"}:
                desc = f"Dataset {ds.id} access is {ds.accessibility}; reproducibility and label audit limited."
                if desc not in existing:
                    self.knowledge_gaps.append(KnowledgeGap(
                        id=new_id("KGAP-DS-", ds.id),
                        gap_type=GapType.DATASET_UNAVAILABLE,
                        description=desc,
                        about_subject_ids=[ds.id],
                        importance="HIGH",
                        recommended_source="Authorized data-use agreement or public equivalent; no unlawful download.",
                        specialist="DATASETINT / RESEARCHINT",
                        expected_information_value=0.80,
                    ))
                    existing.add(desc)

        for pa in self.prior_art.values():
            if pa.temporal_relevance == "UNKNOWN" or not pa.reference_date:
                desc = f"Prior-art date/public availability uncertain for {pa.id}."
                if desc not in existing:
                    self.knowledge_gaps.append(KnowledgeGap(
                        id=new_id("KGAP-PADATE-", pa.id),
                        gap_type=GapType.PRIOR_ART_DATE_UNCERTAIN,
                        description=desc,
                        about_subject_ids=[pa.id],
                        importance="HIGH",
                        recommended_source="Official patent office/bibliographic/standards publication metadata.",
                        specialist="RESEARCHINT / LEGALINT",
                        expected_information_value=0.85,
                    ))
                    existing.add(desc)

        for matrix in self.matrices.values():
            ambiguous = [m for m in matrix.mappings if m.get("state") in {ClaimElementState.AMBIGUOUS.value, ClaimElementState.IMPLICIT_CANDIDATE.value}]
            if ambiguous:
                desc = f"Claim-element ambiguity in matrix {matrix.id}: {ambiguous}."
                if desc not in existing:
                    self.knowledge_gaps.append(KnowledgeGap(
                        id=new_id("KGAP-CLAIM-", matrix.id),
                        gap_type=GapType.CLAIM_ELEMENT_AMBIGUOUS,
                        description=desc,
                        about_subject_ids=[matrix.id, matrix.target_claim_id],
                        importance="HIGH",
                        recommended_source="Full reference text, prosecution history, legal claim construction.",
                        specialist="LEGALINT / human patent specialist",
                        expected_information_value=0.85,
                    ))
                    existing.add(desc)

        if self.contradictions:
            desc = "Conflicting studies require protocol/dataset normalization."
            if desc not in existing:
                self.knowledge_gaps.append(KnowledgeGap(
                    id="KGAP-CONTRA",
                    gap_type=GapType.CONFLICTING_STUDIES,
                    description=desc,
                    about_subject_ids=[c.id for c in self.contradictions],
                    importance="HIGH",
                    recommended_source="Independent replication with matched dataset/split/metric/preprocessing.",
                    specialist="RESEARCHINT / METHODINT",
                    expected_information_value=0.85,
                ))
                existing.add(desc)

    def build_next_actions(self) -> None:
        self.actions = [
            NextAction(
                id="ACT-RETRIEVE-PUBLISHED-VERSION",
                description="Resolve preprint-to-journal versions and use corrected versions where available; preserve historical versions.",
                priority=1,
                privacy_impact="LOW",
                expected_gain=0.80,
                specialist="RESEARCHINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-INDEPENDENT-BENCHMARK",
                description="Prioritize independent evaluation on D2 or new deployment-realistic dataset with matched protocol, baseline, and metric.",
                priority=2,
                privacy_impact="LOW",
                expected_gain=0.90,
                specialist="RESEARCHINT / DATASETINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-STATIC-CODE-INSPECTION",
                description="Perform static inspection of code repositories/manifests only; do not execute untrusted research code.",
                priority=3,
                privacy_impact="LOW",
                expected_gain=0.75,
                specialist="REPOINT / MALINT if suspicious",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-DATASET-PROVENANCE",
                description="Retrieve dataset license, collection method, labeling provenance, and split definitions through authorized channels.",
                priority=4,
                privacy_impact="MEDIUM_IF_AUTHORIZED",
                expected_gain=0.80,
                specialist="DATASETINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-RETRACTION-CHECK",
                description="Check retraction/correction notices for all cited primary sources before synthesis.",
                priority=5,
                privacy_impact="LOW",
                expected_gain=0.85,
                specialist="RESEARCHINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-PATENT-LEGAL-REVIEW",
                description="Route claim-element ambiguity, prior-art chronology, and novelty/obviousness questions to human patent specialist/LEGALINT.",
                priority=6,
                privacy_impact="LOW",
                expected_gain=0.90,
                specialist="LEGALINT",
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-SEARCH-EARLIER-TERMINOLOGY",
                description="Search earlier terminology, classification codes, theses, standards, manuals, and repositories for prior-art completeness.",
                priority=7,
                privacy_impact="LOW",
                expected_gain=0.80,
                specialist="RESEARCHINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-COPYRIGHT-SAFE",
                description="Use summaries, paraphrases, structured extraction, and short necessary quotations only; do not reproduce large copyrighted text.",
                priority=8,
                privacy_impact="PROTECTIVE",
                expected_gain=0.70,
                specialist=None,
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-NO-HARM",
                description="Do not fabricate citations, bypass paywalls, plagiarize, execute untrusted code, or make final legal patent determinations.",
                priority=99,
                privacy_impact="PROTECTIVE",
                expected_gain=0.0,
                specialist=None,
                requires_human_approval=False,
            ),
        ]

    def build_recommendations(self) -> None:
        self.recommendations = [
            Recommendation(
                id="REC-DO-NOT-CITE-RETRACTED",
                category="EVIDENCE_HYGIENE",
                action="Do not use PAPER-P5-RETRACTED as normal supporting evidence; cite only as retraction/history context if needed.",
                target="PAPER-P5-RETRACTED",
                rationale="Retraction status observed; silent citation would violate evidence hygiene.",
                finding_ids=[f.id for f in self.findings.values() if f.finding_type == FindingType.RETRACTION_OBSERVED],
                approval="AUTONOMOUS_ANALYTIC",
                limitations=["Retraction reason/scope should be preserved."],
            ),
            Recommendation(
                id="REC-USE-CORRECTED-P1",
                category="VERSION_CONTROL",
                action="Use corrected version of P1 for current synthesis while preserving preprint/erratum history.",
                target="PAPER-P1-JOURNAL",
                rationale="Correction/erratum observed; version differences must be tracked.",
                finding_ids=[f.id for f in self.findings.values() if f.finding_type == FindingType.CORRECTION_OBSERVED],
                approval="AUTONOMOUS_ANALYTIC",
                limitations=["Do not overwrite historical version."],
            ),
            Recommendation(
                id="REC-SEPARATE-P2-EVIDENCE",
                category="SOURCE_INDEPENDENCE",
                action="Treat P2 as dependent evidence family with P1, not independent replication.",
                target="PAPER-P2-EXTENSION",
                rationale="Shared dataset/code and citation context indicate non-independent corroboration.",
                finding_ids=[f.id for f in self.findings.values() if f.finding_type in {FindingType.EVIDENCE_FAMILY, FindingType.SOURCE_DEPENDENCY}],
                approval="AUTONOMOUS_ANALYTIC",
                limitations=["Do not inflate evidence count."],
            ),
            Recommendation(
                id="REC-LEGAL-PRIOR-ART",
                category="PATENT_LEGAL",
                action="Submit claim-element matrices and chronology to human patent specialist before any invalidity/novelty/infringement decision.",
                target="PAT-TARGET-US-SYN-1000001",
                rationale="Prior-art candidates and partial overlaps identified; legal construction required.",
                finding_ids=[f.id for f in self.findings.values() if f.finding_type in {FindingType.PRIOR_ART_CANDIDATE, FindingType.LEGAL_REVIEW_REQUIRED}],
                approval="HUMAN_APPROVAL_REQUIRED",
                limitations=["RESEARCHINT does not provide legal patent determinations."],
            ),
            Recommendation(
                id="REC-INDEPENDENT-EVAL",
                category="RESEARCH_DESIGN",
                action="Commission or locate independent study with matched protocol, strong baseline, and deployment-realistic dataset before claiming SOTA practical superiority.",
                target="SynthNet vs LogReg",
                rationale="Existing evidence is mixed, partially dependent, and benchmark-incomparable.",
                finding_ids=[f.id for f in self.findings.values() if f.finding_type in {FindingType.CONTRADICTION_OBSERVED, FindingType.BENCHMARK_INCOMPARABILITY_CANDIDATE}],
                approval="HUMAN_APPROVAL_REQUIRED",
                limitations=["Do not fabricate replication or results."],
            ),
        ]

    def build_handoffs(self) -> None:
        self.handoffs = [
            {"specialist": "LEGALINT / human patent specialist", "reason": "Patent validity, infringement, novelty, obviousness, freedom-to-operate, claim construction."},
            {"specialist": "DATASETINT", "reason": "Dataset provenance, licensing, bias, label quality, split leakage."},
            {"specialist": "REPOINT", "reason": "Repository history, code provenance, commit/public access chronology."},
            {"specialist": "PACKAGEINT", "reason": "Software package identity and dependency context for research artifacts."},
            {"specialist": "MALINT", "reason": "If research repository/artifact is suspected malicious; no auto-execution."},
            {"specialist": "CORPINT / OWNERSHIPINT", "reason": "Assignee/current owner/company identity for patent portfolios."},
            {"specialist": "ORGINT / ACADEMICINT", "reason": "Researcher/institution professional context only; no private profiling."},
            {"specialist": "TECHINT", "reason": "Technical system implementation and capability verification."},
            {"specialist": "DOCINT / METADATAINT", "reason": "Document parsing, metadata normalization, OCR limitations."},
            {"specialist": "VULNINT", "reason": "If research software has security vulnerability questions."},
        ]

    def dual_ai_review(self) -> Dict[str, Any]:
        issues: List[str] = []

        if any(f.finding_type == FindingType.CONTRADICTION_OBSERVED for f in self.findings.values()):
            issues.append("Contradictory results remain unresolved due to dataset/protocol heterogeneity.")

        if any(f.finding_type in {FindingType.EVIDENCE_FAMILY, FindingType.SOURCE_DEPENDENCY} for f in self.findings.values()):
            issues.append("Some citations/replications are not independent corroboration.")

        if any(f.finding_type == FindingType.RETRACTION_OBSERVED for f in self.findings.values()):
            issues.append("Retracted source present; must not be used as normal evidence.")

        if any(f.finding_type == FindingType.CORRECTION_OBSERVED for f in self.findings.values()):
            issues.append("Correction/erratum present; version control required.")

        if any(f.finding_type == FindingType.FULL_TEXT_LIMITATION for f in self.findings.values()):
            issues.append("Full-text/method access limitations constrain deep synthesis.")

        if any(f.finding_type == FindingType.BENCHMARK_INCOMPARABILITY_CANDIDATE for f in self.findings.values()):
            issues.append("Benchmark comparisons require normalization.")

        if any(f.finding_type == FindingType.PRIOR_ART_CANDIDATE for f in self.findings.values()):
            issues.append("Prior-art candidates require legal/patent specialist review.")

        if any(f.finding_type == FindingType.REPRODUCIBILITY_OBSERVED for f in self.findings.values()):
            issues.append("Reproducibility is partial or unavailable for some sources.")

        if self.research_gaps:
            issues.append(f"{len(self.research_gaps)} research-gap candidates identified.")

        if not issues:
            verdict = "AGREE"
        elif len(issues) <= 5:
            verdict = "PARTIAL_AGREEMENT"
        else:
            verdict = "INSUFFICIENT_EVIDENCE"

        return {
            "primary_research_analyst": (
                "Synthetic authorized corpus supports that SynthNet reports advantages on D1, but strongest supporting evidence includes "
                "dependent family P1/P2. Independent P3 shows smaller advantage on D2 with different metric; P4 reports null under different protocol. "
                "P5 is retracted and excluded from normal evidence. Patent prior-art candidates exist with partial/implicit E3 disclosure; legal review required."
            ),
            "independent_research_skeptic_issues": issues,
            "verdict": verdict,
            "adversarial_checks": [
                "Are we trusting prestige? No; evidence and independence assessed.",
                "Are citations independent? No; P2 flagged dependent.",
                "Are versions duplicated? Preprint/journal linked and preserved.",
                "Are incompatible benchmarks compared? Flagged; not directly compared.",
                "Is causal language stronger than design? Checked.",
                "Are negative results ignored? P4 included.",
                "Is paper retracted/corrected? P5 retracted; P1 correction tracked.",
                "Is patent application treated as granted? No.",
                "Is later art used as earlier prior art? Chronology checked.",
                "Is literature gap called novelty? No; novelty candidate only.",
            ],
            "note": "AI agreement is analytical agreement, not independent scientific replication.",
        }

    def analyst_summary(self, dual: Dict[str, Any]) -> str:
        lines = [
            "QUESTION: Does SynthNet materially outperform LogReg for fraud detection, and are there earlier technical disclosures relevant to target patent claim 1?",
            "",
            "SEARCH SCOPE: Synthetic systematic corpus across bibliographic, preprint, patent, standards, dataset, and code metadata sources.",
            "CORE PAPERS: P1 original; P2 dependent extension; P3 independent but different metric/dataset; P4 null under different protocol; P5 retracted; P6 earlier thesis.",
            "",
            "EVIDENCE:",
            "- P1/P2 report high accuracy on D1, but P2 shares dataset/code and is not independent corroboration.",
            "- P3 reports smaller advantage on D2 using F1; conditions are not directly comparable to D1 accuracy.",
            "- P4 reports no significant improvement under different protocol; negative result preserved.",
            "- P5 is retracted and excluded from normal evidence.",
            "",
            "REPLICATION / REPRODUCIBILITY:",
            "- Independent replication is partial and condition-dependent.",
            "- Code availability does not equal reproducibility; D1 access restricted.",
            "- No untrusted research code was executed.",
            "",
            "PATENT / PRIOR ART:",
            "- Target patent claim 1 elements E1-E4 mapped against pre-priority references.",
            "- Early patent application and thesis/standard references are prior-art candidates.",
            "- E3 drift-based dynamic thresholding is implicit/partial in several references; no legal anticipation/invalidity determination.",
            "",
            "NOVELTY:",
            "- No single searched pre-priority reference explicitly disclosed all elements; NOVELTY_CANDIDATE only.",
            "",
            "RESEARCH GAPS:",
            "- Independent deployment-realistic matched-protocol evaluation.",
            "- Dataset label provenance and authorized reproduction.",
            "- Human patent review for claim construction.",
            "",
            f"DUAL-AI REVIEW: {dual['verdict']}.",
            "PRIVACY/COPYRIGHT/POLICY: Evidence-first, copyright-aware, no paywall bypass, no fabricated citations, no auto-execution, no final legal patent determination.",
            "NEXT ACTION: Retrieve corrected/full versions through authorized channels, run independent matched benchmark, inspect code statically, and route prior-art matrices to legal/patent review.",
        ]
        return "\n".join(lines)

    def prepare(self) -> None:
        self.normalize_versions_and_screening()
        self.extract_claims_methods_results()
        self.build_citation_and_source_dependency()
        self.assess_replication_reproducibility()
        self.assess_retractions_corrections()
        self.assess_patents_and_prior_art()
        self.detect_contradictions()
        self.grade_evidence()
        self.fact_gate_findings()
        self.build_novelty_candidates()
        self.build_research_gaps()
        self.build_hypotheses()
        self.build_knowledge_gaps()
        self.build_next_actions()
        self.build_recommendations()
        self.build_handoffs()

    # helpers
    def _paper_source_ids(self, paper_id: str) -> List[str]:
        p = self.papers.get(paper_id)
        return p.source_ids if p else []

    def _source_ids_for_claim(self, claim: Claim) -> List[str]:
        if claim.source_type == "PAPER":
            return self._paper_source_ids(claim.source_id)
        if claim.source_type == "PATENT":
            pat = self.patents.get(claim.source_id)
            return pat.source_ids if pat else []
        if claim.source_type == "STANDARD":
            std = self.standards.get(claim.source_id)
            return std.source_ids if std else []
        return []


@dataclass
class FindingLite:
    id: str
    finding_type: FindingType
    subject_id: str
    statement: str
    verification_state: VerificationState = VerificationState.INCONCLUSIVE
    confidence: float = 0.0
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    specialist_handoff: Optional[str] = None


# =====================================================================
# SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-RESEARCHINT-001",
        task_id="TASK-RESEARCHINT-001",
        objective=(
            "Authorized evidence-first literature and prior-art intelligence for synthetic fraud-detection method SynthNet "
            "and target patent claim 1 covering rolling-histogram dynamic thresholding. Assess published claims, replication, "
            "source independence, retraction/correction, benchmark comparability, reproducibility, patent family, prior-art chronology, "
            "research gaps, and legal-review boundaries without fabricating citations or making final legal determinations."
        ),
        research_questions=[
            "Does SynthNet materially outperform LogReg under independent, comparable conditions?",
            "Which papers are primary evidence versus dependent citations/extensions?",
            "Are there retracted or corrected sources affecting synthesis?",
            "What datasets/benchmarks are used and are results comparable?",
            "What earlier technical disclosures are prior-art candidates for target claim 1?",
            "Which claim elements are explicitly disclosed, partial, implicit, or missing?",
            "What research gaps remain?",
            "What legal/patent questions require human specialist review?",
        ],
        topic="fraud detection / dynamic thresholding",
        technical_domain="machine learning / financial transaction monitoring",
        concepts=["fraud detection", "rolling histogram", "dynamic threshold", "drift detection", "transaction streaming"],
        keywords=["SynthNet", "LogReg", "fraud", "rolling histogram", "dynamic threshold"],
        known_papers=["PAPER-P1-JOURNAL", "PAPER-P3-INDEPENDENT", "PAPER-P4-NULL"],
        known_patents=["PAT-TARGET-US-SYN-1000001", "PAT-EARLY-APP-WO-SYN-2019-000123"],
        known_standards=["STD-IEEE-SYN-2020"],
        time_range="2015-01-01/2026-10-09",
        jurisdictions=["US", "WO", "EP"],
        search_mode=SearchMode.SYSTEMATIC,
        scope=["authorized_public_or_permitted_sources", "copyright_aware", "evidence_first", "no_auto_code_execution", "no_legal_patent_determination"],
        authorization="demo_authorized_research_intelligence",
        as_of=DEFAULT_AS_OF,
        sample=True,
    )


def build_sample_researchint() -> ResearchInt:
    r = ResearchInt(sample_case())
    retrieved = now_iso()

    # Sources
    r.add_source(Source(
        id="SRC-CROSSREF",
        title="Synthetic Crossref-like bibliographic metadata",
        url="https://api.example/crossref",
        source_type=SourceType.OTHER,
        independence_group="BIBLIO_ROOT",
        reliability=0.88,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Bibliographic metadata; not full text.",
    ))
    r.add_source(Source(
        id="SRC-OPENALEX",
        title="Synthetic OpenAlex-like index",
        url="https://api.example/openalex",
        source_type=SourceType.OTHER,
        independence_group="BIBLIO_ROOT",
        reliability=0.86,
        derived_from="SRC-CROSSREF",
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Aggregated index; not independent from underlying publisher metadata.",
    ))
    r.add_source(Source(
        id="SRC-ARXIV",
        title="Synthetic arXiv-like preprint repository",
        url="https://repo.example/arxiv",
        source_type=SourceType.PREPRINT,
        independence_group="PREPRINT_ROOT",
        reliability=0.78,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Preprints may differ from published versions.",
    ))
    r.add_source(Source(
        id="SRC-PUBMED",
        title="Synthetic PubMed-like database",
        url="https://api.example/pubmed",
        source_type=SourceType.OTHER,
        independence_group="BIBLIO_ROOT",
        reliability=0.86,
        derived_from="SRC-CROSSREF",
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Metadata/abstract source; full text access not assumed.",
    ))
    r.add_source(Source(
        id="SRC-PATENT-OFFICE",
        title="Synthetic patent office bibliographic/legal status data",
        url="https://patents.example",
        source_type=SourceType.PATENT_APPLICATION,
        independence_group="PATENT_ROOT",
        reliability=0.88,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Official-style metadata; legal interpretation requires specialist.",
    ))
    r.add_source(Source(
        id="SRC-STANDARDS",
        title="Synthetic standards body metadata",
        url="https://standards.example",
        source_type=SourceType.STANDARD,
        independence_group="STANDARD_ROOT",
        reliability=0.88,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Standards may be prior-art candidates; version/date matter.",
    ))
    r.add_source(Source(
        id="SRC-GITHUB",
        title="Synthetic public code repository metadata",
        url="https://code.example",
        source_type=SourceType.SOFTWARE_ARTIFACT,
        independence_group="CODE_ROOT",
        reliability=0.78,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Repository metadata only; no code executed.",
    ))
    r.add_source(Source(
        id="SRC-ZENODO",
        title="Synthetic dataset/archive metadata",
        url="https://archive.example",
        source_type=SourceType.DATASET,
        independence_group="DATASET_ROOT",
        reliability=0.82,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Dataset metadata; access restrictions preserved.",
    ))
    r.add_source(Source(
        id="SRC-RETRACTION-WATCH",
        title="Synthetic retraction/correction notice index",
        url="https://retraction.example",
        source_type=SourceType.OTHER,
        independence_group="RETRACTION_ROOT",
        reliability=0.84,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Retraction/correction tracking; reason/scope matter.",
    ))

    # Evidence
    r.add_evidence(Evidence(
        id="EV-P1-ABSTRACT",
        source_id="SRC-CROSSREF",
        artifact_type="abstract",
        excerpt="P1 journal abstract reports SynthNet achieves 95% accuracy on Fraud-D1 test split versus 91% LogReg baseline.",
        observed_at="2022-03-01T00:00:00Z",
        parsed_fields={"metric": "accuracy", "value": 0.95, "baseline": 0.91},
        limitations=["Abstract may omit limitations and subgroup findings."],
    ))
    r.add_evidence(Evidence(
        id="EV-P1-METHOD",
        source_id="SRC-CROSSREF",
        artifact_type="method_excerpt",
        excerpt="P1 method uses rolling histogram features and threshold adjustment; industry-funded pilot dataset.",
        observed_at="2022-03-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-P1-CORRECTION",
        source_id="SRC-RETRACTION-WATCH",
        artifact_type="erratum",
        excerpt="P1 erratum 2022-08 corrects Table 2 secondary metric values; primary accuracy claim unchanged according to notice.",
        observed_at="2022-08-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-P2-CITATION",
        source_id="SRC-OPENALEX",
        artifact_type="citation_context",
        excerpt="P2 cites P1 as method source and reuses same public code repository and Fraud-D1 split.",
        observed_at="2022-09-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-P3-RESULT",
        source_id="SRC-PUBMED",
        artifact_type="abstract",
        excerpt="P3 independent group evaluates SynthNet on Fraud-D2 and reports F1 0.88 versus LogReg 0.84.",
        observed_at="2023-04-01T00:00:00Z",
        parsed_fields={"metric": "F1", "value": 0.88, "baseline": 0.84},
    ))
    r.add_evidence(Evidence(
        id="EV-P4-NULL",
        source_id="SRC-ARXIV",
        artifact_type="workshop_abstract",
        excerpt="P4 reports no significant SynthNet advantage under alternative preprocessing and stronger tuned LogReg baseline; accuracy delta 0.001, p=0.42.",
        observed_at="2023-07-01T00:00:00Z",
        parsed_fields={"metric": "accuracy_delta", "value": 0.001, "p_value": 0.42},
    ))
    r.add_evidence(Evidence(
        id="EV-P5-RETRACTION",
        source_id="SRC-RETRACTION-WATCH",
        artifact_type="retraction_notice",
        excerpt="P5 retracted 2024-02-15 due to image duplication and unverifiable experimental figures; all primary results withdrawn.",
        observed_at="2024-02-15T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-P6-THESIS",
        source_id="SRC-CROSSREF",
        artifact_type="thesis_abstract",
        excerpt="P6 2020 thesis discloses rolling-histogram anomaly scoring for transaction streams and static threshold blocking.",
        observed_at="2020-10-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-PAT-TARGET",
        source_id="SRC-PATENT-OFFICE",
        artifact_type="patent_bibliographic",
        excerpt="Target patent US-SYN-1,000,001 granted; priority 2022-01-01; claim 1 covers transaction stream, rolling histogram, drift-based dynamic threshold, blocking.",
        observed_at="2024-06-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-PAT-EARLY",
        source_id="SRC-PATENT-OFFICE",
        artifact_type="patent_application",
        excerpt="Early WO application published 2021-06-01, priority 2019-12-01, describes rolling histogram and adaptive threshold based on distribution drift.",
        observed_at="2021-06-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-STD-2020",
        source_id="SRC-STANDARDS",
        artifact_type="standard_excerpt",
        excerpt="STD-IEEE-SYN-2020 specifies rolling-histogram scoring and threshold-based blocking for transaction monitoring; drift-based dynamic threshold not normatively required.",
        observed_at="2020-05-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-CODE-P1",
        source_id="SRC-GITHUB",
        artifact_type="repository_metadata",
        excerpt="Repository synthnet-official contains README, requirements, and training script metadata; not executed.",
        observed_at="2022-03-15T00:00:00Z",
        limitations=["Remote code risk; static inspection only."],
    ))
    r.add_evidence(Evidence(
        id="EV-DS-D1",
        source_id="SRC-ZENODO",
        artifact_type="dataset_metadata",
        excerpt="Fraud-D1 v1 restricted access, proprietary license, labels partially automated, known class imbalance.",
        observed_at="2021-12-01T00:00:00Z",
    ))
    r.add_evidence(Evidence(
        id="EV-DS-D2",
        source_id="SRC-ZENODO",
        artifact_type="dataset_metadata",
        excerpt="Fraud-D2 v2 public CC-BY, independent collection, manual adjudication subset, documented split.",
        observed_at="2023-01-01T00:00:00Z",
    ))

    # Queries
    r.add_query(Query(
        id="QUERY-LIT-001",
        query_text='("fraud detection" AND ("SynthNet" OR "rolling histogram" OR "dynamic threshold" OR "drift detection"))',
        databases=["Crossref-like", "OpenAlex-like", "arXiv-like", "PubMed-like"],
        filters={"date": "2015-01-01/2026-10-09", "languages": ["en"], "types": ["journal", "conference", "preprint", "thesis"]},
        search_date="2026-10-08T00:00:00Z",
        result_count=120,
        screened_count=35,
        included_count=8,
        excluded_count=27,
        source_ids=["SRC-CROSSREF", "SRC-OPENALEX", "SRC-ARXIV", "SRC-PUBMED"],
        evidence_ids=["EV-P1-ABSTRACT", "EV-P3-RESULT", "EV-P4-NULL"],
        limitations=["Database coverage is not exhaustive.", "Absence from one database is not no research."],
    ))
    r.add_query(Query(
        id="QUERY-PAT-001",
        query_text='(CPC:G06Q20/40 OR IPC:G06Q20/40) AND ("rolling histogram" OR "adaptive threshold" OR "drift") AND priority date < 2022-01-01',
        databases=["Espacenet-like", "USPTO-like", "WIPO-like"],
        filters={"jurisdictions": ["US", "WO", "EP"], "status": ["application", "granted"]},
        search_date="2026-10-08T00:00:00Z",
        result_count=45,
        screened_count=12,
        included_count=3,
        excluded_count=9,
        source_ids=["SRC-PATENT-OFFICE"],
        evidence_ids=["EV-PAT-TARGET", "EV-PAT-EARLY"],
        limitations=["Classification is not exact technology match.", "Legal status varies by jurisdiction."],
    ))
    r.add_query(Query(
        id="QUERY-STD-001",
        query_text='transaction monitoring AND ("rolling histogram" OR "threshold")',
        databases=["Standards-body-like"],
        filters={"date": "2015-01-01/2026-10-09", "status": ["published", "draft"]},
        search_date="2026-10-08T00:00:00Z",
        result_count=12,
        screened_count=4,
        included_count=1,
        excluded_count=3,
        source_ids=["SRC-STANDARDS"],
        evidence_ids=["EV-STD-2020"],
        limitations=["Draft vs final standard status must be preserved."],
    ))

    # Datasets / benchmarks
    r.add_dataset(Dataset(
        id="DS-D1-V1",
        name="Fraud-D1",
        version="v1",
        source="Industry pilot synthetic",
        size="1.2M transactions",
        license="Restricted proprietary",
        collection_method="Proprietary production sample",
        time_range="2019-2021",
        population="Payment transactions",
        labeling_method="Partially automated + rules",
        known_bias="Class imbalance; label noise possible",
        accessibility="RESTRICTED",
        hash="sha256:d1v1-placeholder",
        source_ids=["SRC-ZENODO"],
        evidence_ids=["EV-DS-D1"],
        limitations=["Dataset is not ground truth.", "Restricted access limits reproduction."],
    ))
    r.add_dataset(Dataset(
        id="DS-D2-V2",
        name="Fraud-D2",
        version="v2",
        source="Independent research archive",
        size="800K transactions",
        license="CC-BY-4.0",
        collection_method="Independent collection",
        time_range="2020-2022",
        population="Payment transactions",
        labeling_method="Manual adjudication subset + rules",
        known_bias="Geographic skew possible",
        accessibility="PUBLIC",
        hash="sha256:d2v2-placeholder",
        source_ids=["SRC-ZENODO"],
        evidence_ids=["EV-DS-D2"],
        limitations=["Public does not mean unbiased or deployment-equivalent."],
    ))
    r.add_benchmark(Benchmark(
        id="BM-D1-ACCURACY",
        task="fraud detection",
        dataset_id="DS-D1-V1",
        metric="accuracy",
        protocol="test split v1, threshold at operating point A",
        split="test-v1",
        baseline="LogReg default",
        version="v1",
        source_ids=["SRC-CROSSREF"],
        evidence_ids=["EV-P1-ABSTRACT"],
        limitations=["Accuracy can be misleading under class imbalance."],
    ))
    r.add_benchmark(Benchmark(
        id="BM-D2-F1",
        task="fraud detection",
        dataset_id="DS-D2-V2",
        metric="F1",
        protocol="test split v2, PR-curve integration",
        split="test-v2",
        baseline="LogReg tuned",
        version="v1",
        source_ids=["SRC-PUBMED"],
        evidence_ids=["EV-P3-RESULT"],
        limitations=["F1 and accuracy are not directly comparable."],
    ))

    # Features
    r.add_feature(TechnicalFeature(
        id="FEAT-ROLLING-HISTOGRAM",
        name="rolling histogram",
        normalized="rolling histogram",
        description="Maintain histogram of transaction feature distribution over sliding window.",
        first_seen_candidate="2020-05-01",
        papers=["PAPER-P6-THESIS", "PAPER-P1-JOURNAL"],
        patents=["PAT-EARLY-APP-WO-SYN-2019-000123", "PAT-TARGET-US-SYN-1000001"],
        standards=["STD-IEEE-SYN-2020"],
        evidence_ids=["EV-P6-THESIS", "EV-STD-2020", "EV-PAT-EARLY"],
        confidence=0.88,
        limitations=["First found is not first ever."],
    ))
    r.add_feature(TechnicalFeature(
        id="FEAT-DYNAMIC-THRESHOLD",
        name="dynamic threshold",
        normalized="dynamic threshold",
        description="Adjust blocking threshold based on distribution or score dynamics.",
        first_seen_candidate="2019-12-01",
        papers=["PAPER-P1-JOURNAL"],
        patents=["PAT-EARLY-APP-WO-SYN-2019-000123", "PAT-TARGET-US-SYN-1000001"],
        standards=[],
        evidence_ids=["EV-PAT-EARLY", "EV-P1-METHOD"],
        confidence=0.72,
        limitations=["Explicitness varies by reference; legal claim construction required."],
    ))
    r.add_feature(TechnicalFeature(
        id="FEAT-DRIFT-DETECTION",
        name="drift detection",
        normalized="drift detection",
        description="Detect distribution drift and trigger threshold adaptation.",
        first_seen_candidate="2019-12-01",
        papers=[],
        patents=["PAT-EARLY-APP-WO-SYN-2019-000123", "PAT-TARGET-US-SYN-1000001"],
        standards=[],
        evidence_ids=["EV-PAT-EARLY"],
        confidence=0.60,
        limitations=["Implicit candidate only in some references; ambiguity preserved."],
    ))

    # Papers
    r.add_paper(Paper(
        id="PAPER-P1-PREPRINT",
        title="SynthNet: Rolling-Histogram Dynamic Thresholding for Fraud Detection",
        authors=["A. Researcher", "B. Engineer"],
        year=2021,
        venue="arXiv-like",
        publication_type=SourceType.PREPRINT,
        arxiv_id="2105.0001",
        abstract="Preprint reports 95% accuracy on Fraud-D1.",
        keywords=["fraud", "SynthNet", "rolling histogram"],
        publication_date="2021-05-20T00:00:00Z",
        version="v1",
        published_as="PAPER-P1-JOURNAL",
        availability=Availability.FULL_TEXT_AVAILABLE,
        funding="Industry pilot grant",
        conflicts="One author employed by data provider",
        code_url="https://code.example/synthnet-official",
        dataset_ids=["DS-D1-V1"],
        benchmark_ids=["BM-D1-ACCURACY"],
        references=["PAPER-P6-THESIS"],
        source_ids=["SRC-ARXIV", "SRC-GITHUB"],
        evidence_ids=["EV-P1-ABSTRACT", "EV-CODE-P1"],
        confidence=0.78,
        limitations=["Preprint may differ from published version."],
    ))
    r.add_paper(Paper(
        id="PAPER-P1-JOURNAL",
        title="SynthNet: Rolling-Histogram Dynamic Thresholding for Fraud Detection",
        authors=["A. Researcher", "B. Engineer", "C. Scientist"],
        year=2022,
        venue="Journal of Synthetic Financial ML",
        publication_type=SourceType.PEER_REVIEWED_JOURNAL,
        doi="10.5555/synth.2022.001",
        arxiv_id="2105.0001",
        abstract="Journal version reports 95% accuracy on Fraud-D1 test split versus 91% LogReg.",
        keywords=["fraud", "SynthNet", "rolling histogram", "dynamic threshold"],
        publication_date="2022-03-01T00:00:00Z",
        version="v2-corrected",
        preprint_of="PAPER-P1-PREPRINT",
        retraction_status=RetractionStatus.NO_KNOWN_NOTICE,
        correction_status=RetractionStatus.ERRATUM,
        availability=Availability.FULL_TEXT_AVAILABLE,
        funding="Industry pilot grant",
        conflicts="One author employed by data provider",
        code_url="https://code.example/synthnet-official",
        dataset_ids=["DS-D1-V1"],
        benchmark_ids=["BM-D1-ACCURACY"],
        references=["PAPER-P6-THESIS"],
        source_ids=["SRC-CROSSREF", "SRC-OPENALEX", "SRC-GITHUB", "SRC-RETRACTION-WATCH"],
        evidence_ids=["EV-P1-ABSTRACT", "EV-P1-METHOD", "EV-P1-CORRECTION", "EV-CODE-P1"],
        confidence=0.86,
        limitations=[
            "Peer review is not replication.",
            "Erratum affects secondary table values; primary result tracked separately.",
            "Industry funding and conflict declared; not automatic invalidation.",
        ],
    ))
    r.add_paper(Paper(
        id="PAPER-P2-EXTENSION",
        title="Extending SynthNet for Transaction Monitoring",
        authors=["B. Engineer", "D. Student"],
        year=2022,
        venue="Workshop on Synthetic FinML",
        publication_type=SourceType.WORKSHOP,
        doi="10.5555/synth.ws.2022.014",
        abstract="Reports 96% accuracy using same code and Fraud-D1 split.",
        keywords=["SynthNet", "extension"],
        publication_date="2022-09-01T00:00:00Z",
        availability=Availability.ABSTRACT_ONLY,
        code_url="https://code.example/synthnet-official",
        dataset_ids=["DS-D1-V1"],
        benchmark_ids=["BM-D1-ACCURACY"],
        references=["PAPER-P1-JOURNAL"],
        source_ids=["SRC-OPENALEX", "SRC-CROSSREF"],
        evidence_ids=["EV-P2-CITATION"],
        confidence=0.70,
        limitations=["Abstract-only; shares code/dataset with P1; not independent replication."],
    ))
    r.add_paper(Paper(
        id="PAPER-P3-INDEPENDENT",
        title="Independent Evaluation of SynthNet on Public Fraud Data",
        authors=["E. Independent", "F. Analyst"],
        year=2023,
        venue="Journal of Reproducible FinML",
        publication_type=SourceType.PEER_REVIEWED_JOURNAL,
        doi="10.5555/synth.2023.101",
        abstract="Independent group reports SynthNet F1 0.88 versus tuned LogReg 0.84 on Fraud-D2.",
        keywords=["replication", "SynthNet", "Fraud-D2"],
        publication_date="2023-04-01T00:00:00Z",
        availability=Availability.FULL_TEXT_AVAILABLE,
        funding="Public research grant",
        conflicts="None declared",
        code_url="https://code.example/independent-eval",
        dataset_ids=["DS-D2-V2"],
        benchmark_ids=["BM-D2-F1"],
        references=["PAPER-P1-JOURNAL"],
        source_ids=["SRC-PUBMED", "SRC-CROSSREF"],
        evidence_ids=["EV-P3-RESULT"],
        confidence=0.84,
        limitations=["Different dataset/metric; not directly comparable to D1 accuracy."],
    ))
    r.add_paper(Paper(
        id="PAPER-P4-NULL",
        title="Null Results for SynthNet Under Alternative Preprocessing",
        authors=["G. Skeptic", "H. Reviewer"],
        year=2023,
        venue="Workshop on Negative Results",
        publication_type=SourceType.WORKSHOP,
        arxiv_id="2307.0042",
        abstract="No significant advantage under alternative preprocessing and stronger baseline; accuracy delta 0.001, p=0.42.",
        keywords=["null result", "SynthNet", "baseline"],
        publication_date="2023-07-01T00:00:00Z",
        availability=Availability.FULL_TEXT_AVAILABLE,
        code_url="",
        dataset_ids=["DS-D1-V1"],
        benchmark_ids=["BM-D1-ACCURACY"],
        references=["PAPER-P1-JOURNAL"],
        source_ids=["SRC-ARXIV"],
        evidence_ids=["EV-P4-NULL"],
        confidence=0.76,
        limitations=["Different preprocessing/baseline; preserve as negative evidence, not suppress."],
    ))
    r.add_paper(Paper(
        id="PAPER-P5-RETRACTED",
        title="Superior Fraud Detection with Advanced SynthNet Variants",
        authors=["I. Former", "J. Coauthor"],
        year=2021,
        venue="Predatory-like journal placeholder",
        publication_type=SourceType.PEER_REVIEWED_JOURNAL,
        doi="10.5555/synth.bad.2021",
        abstract="Claimed 99% accuracy; later retracted.",
        keywords=["fraud", "SynthNet"],
        publication_date="2021-11-01T00:00:00Z",
        retraction_status=RetractionStatus.RETRACTED,
        availability=Availability.METADATA_ONLY,
        dataset_ids=["DS-D1-V1"],
        source_ids=["SRC-RETRACTION-WATCH", "SRC-CROSSREF"],
        evidence_ids=["EV-P5-RETRACTION"],
        confidence=0.20,
        limitations=["Retracted; do not use as normal evidence."],
    ))
    r.add_paper(Paper(
        id="PAPER-P6-THESIS",
        title="Rolling-Histogram Anomaly Scoring for Transaction Streams",
        authors=["K. Thesis Author"],
        year=2020,
        venue="University Synthetic Repository",
        publication_type=SourceType.THESIS,
        doi="10.5555/thesis.2020.777",
        abstract="Thesis discloses rolling-histogram scoring and static threshold blocking for transaction streams.",
        keywords=["rolling histogram", "transaction stream", "threshold"],
        publication_date="2020-10-01T00:00:00Z",
        availability=Availability.FULL_TEXT_AVAILABLE,
        dataset_ids=[],
        source_ids=["SRC-CROSSREF"],
        evidence_ids=["EV-P6-THESIS"],
        confidence=0.80,
        limitations=["Thesis may contain earlier technical disclosure; public accessibility date must be verified."],
    ))

    # Claims
    r.add_claim(Claim(
        id="CLM-P1-PERF",
        source_type="PAPER",
        source_id="PAPER-P1-JOURNAL",
        claim_type=ClaimType.PERFORMANCE_CLAIM,
        statement="SynthNet achieves 95% accuracy on Fraud-D1 test split versus 91% for LogReg.",
        subject="SynthNet",
        predicate="achieves",
        object="95% accuracy",
        population="Fraud-D1 test split v1",
        conditions="protocol A, operating point A",
        metric="accuracy",
        effect=0.95,
        time="2022-03-01",
        locator="Abstract / Table 1",
        evidence_ids=["EV-P1-ABSTRACT"],
        limitations=["Condition-bound result; not general performance."],
    ))
    r.add_claim(Claim(
        id="CLM-P1-METHOD",
        source_type="PAPER",
        source_id="PAPER-P1-JOURNAL",
        claim_type=ClaimType.METHOD_CLAIM,
        statement="SynthNet uses rolling-histogram features and threshold adjustment for fraud detection.",
        subject="SynthNet",
        predicate="uses",
        object="rolling histogram and threshold adjustment",
        evidence_ids=["EV-P1-METHOD"],
    ))
    r.add_claim(Claim(
        id="CLM-P2-PERF",
        source_type="PAPER",
        source_id="PAPER-P2-EXTENSION",
        claim_type=ClaimType.PERFORMANCE_CLAIM,
        statement="Extended SynthNet achieves 96% accuracy on Fraud-D1 using same code/split.",
        subject="SynthNet extension",
        metric="accuracy",
        effect=0.96,
        evidence_ids=["EV-P2-CITATION"],
        limitations=["Dependent evidence family; abstract-only."],
    ))
    r.add_claim(Claim(
        id="CLM-P3-PERF",
        source_type="PAPER",
        source_id="PAPER-P3-INDEPENDENT",
        claim_type=ClaimType.PERFORMANCE_CLAIM,
        statement="SynthNet achieves F1 0.88 versus tuned LogReg 0.84 on Fraud-D2.",
        subject="SynthNet",
        metric="F1",
        effect=0.88,
        evidence_ids=["EV-P3-RESULT"],
        limitations=["Different dataset/metric; not directly comparable to accuracy."],
    ))
    r.add_claim(Claim(
        id="CLM-P4-NULL",
        source_type="PAPER",
        source_id="PAPER-P4-NULL",
        claim_type=ClaimType.EMPIRICAL_RESULT,
        statement="No significant SynthNet advantage under alternative preprocessing and stronger baseline.",
        subject="SynthNet",
        metric="accuracy_delta",
        effect=0.001,
        evidence_ids=["EV-P4-NULL"],
        limitations=["Negative result preserved; protocol differs."],
    ))
    r.add_claim(Claim(
        id="CLM-P5-PERF",
        source_type="PAPER",
        source_id="PAPER-P5-RETRACTED",
        claim_type=ClaimType.PERFORMANCE_CLAIM,
        statement="Advanced SynthNet variant achieves 99% accuracy.",
        subject="SynthNet variant",
        metric="accuracy",
        effect=0.99,
        evidence_ids=["EV-P5-RETRACTION"],
        limitations=["Source retracted; not usable as normal evidence."],
    ))
    r.add_claim(Claim(
        id="CLM-P6-METHOD",
        source_type="PAPER",
        source_id="PAPER-P6-THESIS",
        claim_type=ClaimType.METHOD_CLAIM,
        statement="Rolling-histogram anomaly scoring with static threshold blocking for transaction streams.",
        subject="Rolling-histogram anomaly scoring",
        evidence_ids=["EV-P6-THESIS"],
    ))

    # Methods
    r.add_method(MethodRecord(
        id="METH-P1",
        paper_id="PAPER-P1-JOURNAL",
        design=StudyDesign.EXPERIMENT,
        sample="1.2M transactions, restricted proprietary sample",
        dataset_ids=["DS-D1-V1"],
        baseline="LogReg default",
        model="SynthNet",
        evaluation="accuracy on test split v1",
        statistical_method="paired comparison not fully reported",
        limitations=["Single restricted dataset; baseline tuning unclear; industry conflict declared."],
        evidence_ids=["EV-P1-METHOD"],
    ))
    r.add_method(MethodRecord(
        id="METH-P3",
        paper_id="PAPER-P3-INDEPENDENT",
        design=StudyDesign.EXPERIMENT,
        sample="800K independent transactions",
        dataset_ids=["DS-D2-V2"],
        baseline="tuned LogReg",
        model="SynthNet",
        evaluation="F1 on test split v2",
        statistical_method="bootstrap CI reported",
        limitations=["Different metric/dataset; deployment realism uncertain."],
        evidence_ids=["EV-P3-RESULT"],
    ))
    r.add_method(MethodRecord(
        id="METH-P4",
        paper_id="PAPER-P4-NULL",
        design=StudyDesign.BENCHMARK,
        sample="Fraud-D1 subset with alternative preprocessing",
        dataset_ids=["DS-D1-V1"],
        baseline="stronger tuned LogReg",
        model="SynthNet",
        evaluation="accuracy delta, paired test",
        statistical_method="paired permutation test",
        limitations=["Preprocessing/baseline differences may explain null."],
        evidence_ids=["EV-P4-NULL"],
    ))

    # Results
    r.add_result(ResultRecord(
        id="RES-P1",
        paper_id="PAPER-P1-JOURNAL",
        method="SynthNet",
        task="fraud detection",
        dataset_id="DS-D1-V1",
        benchmark_id="BM-D1-ACCURACY",
        metric="accuracy",
        value=0.95,
        baseline_metric="accuracy",
        baseline_value=0.91,
        uncertainty="not reported",
        conditions="protocol A, operating point A",
        evidence_ids=["EV-P1-ABSTRACT"],
    ))
    r.add_result(ResultRecord(
        id="RES-P2",
        paper_id="PAPER-P2-EXTENSION",
        method="SynthNet extension",
        task="fraud detection",
        dataset_id="DS-D1-V1",
        benchmark_id="BM-D1-ACCURACY",
        metric="accuracy",
        value=0.96,
        baseline_metric="accuracy",
        baseline_value=0.91,
        conditions="same code/split",
        evidence_ids=["EV-P2-CITATION"],
        limitations=["Dependent family."],
    ))
    r.add_result(ResultRecord(
        id="RES-P3",
        paper_id="PAPER-P3-INDEPENDENT",
        method="SynthNet",
        task="fraud detection",
        dataset_id="DS-D2-V2",
        benchmark_id="BM-D2-F1",
        metric="F1",
        value=0.88,
        baseline_metric="F1",
        baseline_value=0.84,
        uncertainty="bootstrap CI reported",
        conditions="independent dataset, tuned baseline",
        evidence_ids=["EV-P3-RESULT"],
    ))
    r.add_result(ResultRecord(
        id="RES-P4",
        paper_id="PAPER-P4-NULL",
        method="SynthNet",
        task="fraud detection",
        dataset_id="DS-D1-V1",
        benchmark_id="BM-D1-ACCURACY",
        metric="accuracy",
        value=0.911,
        baseline_metric="accuracy",
        baseline_value=0.910,
        p_value=0.42,
        effect_size="negligible",
        conditions="alternative preprocessing, stronger baseline",
        evidence_ids=["EV-P4-NULL"],
    ))
    r.add_result(ResultRecord(
        id="RES-P5",
        paper_id="PAPER-P5-RETRACTED",
        method="SynthNet variant",
        task="fraud detection",
        dataset_id="DS-D1-V1",
        benchmark_id="BM-D1-ACCURACY",
        metric="accuracy",
        value=0.99,
        conditions="retracted source",
        evidence_ids=["EV-P5-RETRACTION"],
        limitations=["Retracted; exclude from normal synthesis."],
    ))

    # Replications
    r.add_replication(ReplicationRecord(
        id="REP-P2",
        original_paper_id="PAPER-P1-JOURNAL",
        replicating_paper_id="PAPER-P2-EXTENSION",
        state=ReplicationState.PARTIAL_REPLICATION,
        independence_state="DEPENDENT",
        shared_dataset=True,
        shared_code=True,
        shared_authors=True,
        notes="Same code/dataset and overlapping author; not independent replication.",
        evidence_ids=["EV-P2-CITATION"],
    ))
    r.add_replication(ReplicationRecord(
        id="REP-P3",
        original_paper_id="PAPER-P1-JOURNAL",
        replicating_paper_id="PAPER-P3-INDEPENDENT",
        state=ReplicationState.INDEPENDENT_VALIDATION,
        independence_state="INDEPENDENT",
        shared_dataset=False,
        shared_code=False,
        shared_authors=False,
        notes="Independent group, independent dataset, different metric; partial conceptual validation.",
        evidence_ids=["EV-P3-RESULT"],
    ))
    r.add_replication(ReplicationRecord(
        id="REP-P4",
        original_paper_id="PAPER-P1-JOURNAL",
        replicating_paper_id="PAPER-P4-NULL",
        state=ReplicationState.FAILED_REPLICATION,
        independence_state="PARTIALLY_DEPENDENT",
        shared_dataset=True,
        shared_code=False,
        shared_authors=False,
        notes="Same dataset but different preprocessing/baseline; null result under altered protocol.",
        evidence_ids=["EV-P4-NULL"],
    ))

    # Retractions
    r.add_retraction(RetractionRecord(
        id="RET-P5",
        paper_id="PAPER-P5-RETRACTED",
        status=RetractionStatus.RETRACTED,
        reason="Image duplication and unverifiable experimental figures.",
        date="2024-02-15T00:00:00Z",
        scope="All primary results withdrawn.",
        source_ids=["SRC-RETRACTION-WATCH"],
        evidence_ids=["EV-P5-RETRACTION"],
    ))
    r.add_retraction(RetractionRecord(
        id="CORR-P1",
        paper_id="PAPER-P1-JOURNAL",
        status=RetractionStatus.ERRATUM,
        reason="Publisher erratum correcting secondary Table 2 values.",
        date="2022-08-01T00:00:00Z",
        scope="Secondary metrics corrected; primary accuracy claim unchanged according to notice.",
        source_ids=["SRC-RETRACTION-WATCH"],
        evidence_ids=["EV-P1-CORRECTION"],
    ))

    # Citations
    r.add_citation(CitationEdge(
        id="CITE-P2-P1",
        citing_paper_id="PAPER-P2-EXTENSION",
        cited_paper_id="PAPER-P1-JOURNAL",
        context="USES_METHOD",
        date="2022-09-01",
        evidence_ids=["EV-P2-CITATION"],
    ))
    r.add_citation(CitationEdge(
        id="CITE-P3-P1",
        citing_paper_id="PAPER-P3-INDEPENDENT",
        cited_paper_id="PAPER-P1-JOURNAL",
        context="BACKGROUND",
        date="2023-04-01",
        evidence_ids=["EV-P3-RESULT"],
    ))
    r.add_citation(CitationEdge(
        id="CITE-P4-P1",
        citing_paper_id="PAPER-P4-NULL",
        cited_paper_id="PAPER-P1-JOURNAL",
        context="CONTRADICTS",
        date="2023-07-01",
        evidence_ids=["EV-P4-NULL"],
    ))
    r.add_citation(CitationEdge(
        id="CITE-P1-P6",
        citing_paper_id="PAPER-P1-JOURNAL",
        cited_paper_id="PAPER-P6-THESIS",
        context="BACKGROUND",
        date="2022-03-01",
        evidence_ids=["EV-P6-THESIS"],
    ))

    # Patents and claims
    r.add_patent(Patent(
        id="PAT-TARGET-US-SYN-1000001",
        publication_number="US-SYN-1,000,001-B2",
        application_number="US-SYN-17/000,001",
        grant_number="US-SYN-1,000,001",
        title="Dynamic fraud thresholding using rolling histograms",
        inventors=["L. Inventor", "M. Co-inventor"],
        applicant="Synthetic Payments Corp",
        assignee="Synthetic Payments Corp",
        priority_date="2022-01-01T00:00:00Z",
        filing_date="2022-03-01T00:00:00Z",
        publication_date="2023-01-01T00:00:00Z",
        grant_date="2024-06-01T00:00:00Z",
        jurisdiction="US",
        family_id="FAM-DYNAMIC-THRESHOLD",
        family_relation=FamilyRelation.SAME_FAMILY,
        status=PatentStatus.GRANTED,
        classifications=["G06Q20/40", "G06N20/00"],
        citations=["PAT-EARLY-APP-WO-SYN-2019-000123", "PAPER-P1-JOURNAL"],
        legal_status_source="Synthetic patent office metadata",
        source_ids=["SRC-PATENT-OFFICE"],
        evidence_ids=["EV-PAT-TARGET"],
        confidence=0.88,
        limitations=["Grant does not prove working technology or legal enforceability in all jurisdictions."],
    ))
    r.add_patent_claim(PatentClaim(
        id="CLAIM-TARGET-1",
        patent_id="PAT-TARGET-US-SYN-1000001",
        number=1,
        independent=True,
        text_summary="System for dynamic fraud thresholding using rolling histograms and drift-based adjustment.",
        elements=[
            "E1 receiving transaction stream",
            "E2 computing rolling histogram",
            "E3 adjusting threshold dynamically based on drift",
            "E4 blocking transaction if score exceeds threshold",
        ],
        evidence_ids=["EV-PAT-TARGET"],
        limitations=["Legal claim construction required."],
    ))
    r.add_patent(Patent(
        id="PAT-EARLY-APP-WO-SYN-2019-000123",
        publication_number="WO-SYN-2019/000123-A1",
        application_number="PCT/SYN2019/000123",
        title="Adaptive transaction scoring",
        inventors=["N. Earlier"],
        applicant="Synthetic Research Ltd",
        assignee="Synthetic Research Ltd",
        priority_date="2019-12-01T00:00:00Z",
        filing_date="2020-12-01T00:00:00Z",
        publication_date="2021-06-01T00:00:00Z",
        jurisdiction="WO",
        family_id="FAM-DYNAMIC-THRESHOLD",
        family_relation=FamilyRelation.RELATED_APPLICATION,
        status=PatentStatus.PUBLISHED_APPLICATION,
        classifications=["G06Q20/40"],
        source_ids=["SRC-PATENT-OFFICE"],
        evidence_ids=["EV-PAT-EARLY"],
        confidence=0.84,
        limitations=["Published application is not granted patent.", "Legal status may vary by national phase."],
    ))
    r.add_patent(Patent(
        id="PAT-FAMILY-EP-SYN-2022-000456",
        publication_number="EP-SYN-2022-000456-A1",
        application_number="EP-SYN-221000456",
        title="Dynamic fraud thresholding",
        inventors=["L. Inventor"],
        applicant="Synthetic Payments Corp",
        assignee="Synthetic Payments Corp",
        priority_date="2022-01-01T00:00:00Z",
        filing_date="2022-12-01T00:00:00Z",
        publication_date="2023-06-01T00:00:00Z",
        jurisdiction="EP",
        family_id="FAM-DYNAMIC-THRESHOLD",
        family_relation=FamilyRelation.NATIONAL_PHASE,
        status=PatentStatus.PUBLISHED_APPLICATION,
        source_ids=["SRC-PATENT-OFFICE"],
        evidence_ids=["EV-PAT-TARGET"],
        limitations=["Family member; not independent invention."],
    ))

    # Standard
    r.add_standard(Standard(
        id="STD-IEEE-SYN-2020",
        number="IEEE-SYN-2020",
        title="Transaction Monitoring Reference Architecture",
        version="2020",
        status="PUBLISHED",
        publication_date="2020-05-01T00:00:00Z",
        normative_sections=["Section 5.2 rolling histogram scoring", "Section 5.4 threshold blocking"],
        features=["FEAT-ROLLING-HISTOGRAM", "FEAT-DYNAMIC-THRESHOLD"],
        source_ids=["SRC-STANDARDS"],
        evidence_ids=["EV-STD-2020"],
        limitations=["Standard does not prove implementation supports it.", "Draft/final status and date matter for prior art."],
    ))

    # Prior art candidates
    r.add_prior_art(PriorArtCandidate(
        id="PA-PAT-EARLY",
        target_patent_id="PAT-TARGET-US-SYN-1000001",
        reference_id="PAT-EARLY-APP-WO-SYN-2019-000123",
        reference_type="PATENT_APPLICATION",
        reference_date="2019-12-01T00:00:00Z",
        public_availability_date="2021-06-01T00:00:00Z",
        relevance=PriorArtRelevance.HIGHLY_RELEVANT_PRIOR_ART_CANDIDATE,
        temporal_relevance="PRE_PRIORITY_OR_EQUAL",
        disclosed_elements=["E1", "E2", "E4"],
        missing_elements=["E3 explicit; implicit candidate only"],
        source_ids=["SRC-PATENT-OFFICE"],
        evidence_ids=["EV-PAT-EARLY"],
        confidence=0.72,
        limitations=["Application not granted.", "E3 explicitness ambiguous.", "Legal review required."],
    ))
    r.add_prior_art(PriorArtCandidate(
        id="PA-P6-THESIS",
        target_patent_id="PAT-TARGET-US-SYN-1000001",
        reference_id="PAPER-P6-THESIS",
        reference_type="THESIS",
        reference_date="2020-10-01T00:00:00Z",
        public_availability_date="2020-10-01T00:00:00Z",
        relevance=PriorArtRelevance.RELEVANT_PRIOR_ART_CANDIDATE,
        temporal_relevance="PRE_PRIORITY_OR_EQUAL",
        disclosed_elements=["E1", "E2", "E4 partial"],
        missing_elements=["E3"],
        source_ids=["SRC-CROSSREF"],
        evidence_ids=["EV-P6-THESIS"],
        confidence=0.68,
        limitations=["Thesis public accessibility date should be verified.", "Not legal anticipation."],
    ))
    r.add_prior_art(PriorArtCandidate(
        id="PA-STD-2020",
        target_patent_id="PAT-TARGET-US-SYN-1000001",
        reference_id="STD-IEEE-SYN-2020",
        reference_type="STANDARD",
        reference_date="2020-05-01T00:00:00Z",
        public_availability_date="2020-05-01T00:00:00Z",
        relevance=PriorArtRelevance.PARTIAL_OVERLAP,
        temporal_relevance="PRE_PRIORITY_OR_EQUAL",
        disclosed_elements=["E1", "E2", "E4"],
        missing_elements=["E3"],
        source_ids=["SRC-STANDARDS"],
        evidence_ids=["EV-STD-2020"],
        confidence=0.70,
        limitations=["Standard version/date matters.", "Not legal anticipation."],
    ))
    r.add_prior_art(PriorArtCandidate(
        id="PA-P1-JOURNAL",
        target_patent_id="PAT-TARGET-US-SYN-1000001",
        reference_id="PAPER-P1-JOURNAL",
        reference_type="PAPER",
        reference_date="2021-05-20T00:00:00Z",
        public_availability_date="2021-05-20T00:00:00Z",
        relevance=PriorArtRelevance.RELEVANT_PRIOR_ART_CANDIDATE,
        temporal_relevance="PRE_PRIORITY_OR_EQUAL",
        disclosed_elements=["E1", "E2", "E4", "E3 partial"],
        missing_elements=["E3 explicit drift-based adjustment unclear"],
        source_ids=["SRC-ARXIV", "SRC-CROSSREF"],
        evidence_ids=["EV-P1-ABSTRACT", "EV-P1-METHOD"],
        confidence=0.66,
        limitations=["Preprint public date considered; published version later.", "Legal review required."],
    ))
    r.add_prior_art(PriorArtCandidate(
        id="PA-P4-LATER",
        target_patent_id="PAT-TARGET-US-SYN-1000001",
        reference_id="PAPER-P4-NULL",
        reference_type="PAPER",
        reference_date="2023-07-01T00:00:00Z",
        public_availability_date="2023-07-01T00:00:00Z",
        relevance=PriorArtRelevance.LATER_PUBLICATION,
        temporal_relevance="LATER_PUBLICATION",
        disclosed_elements=["E1", "E2", "E3", "E4"],
        missing_elements=[],
        source_ids=["SRC-ARXIV"],
        evidence_ids=["EV-P4-NULL"],
        confidence=0.60,
        limitations=["Later than target priority date; technically relevant but not pre-priority prior art candidate."],
    ))

    # Claim-element matrices
    r.add_matrix(ClaimElementMatrix(
        id="MAT-PAT-EARLY",
        target_claim_id="CLAIM-TARGET-1",
        reference_id="PAT-EARLY-APP-WO-SYN-2019-000123",
        reference_type="PATENT_APPLICATION",
        mappings=[
            {"element": "E1 receiving transaction stream", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
            {"element": "E2 computing rolling histogram", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
            {"element": "E3 adjusting threshold dynamically based on drift", "state": ClaimElementState.IMPLICIT_CANDIDATE.value, "notes": "Adaptive threshold described; drift linkage ambiguous."},
            {"element": "E4 blocking transaction if score exceeds threshold", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
        ],
        overall_relevance=PriorArtRelevance.HIGHLY_RELEVANT_PRIOR_ART_CANDIDATE,
        source_ids=["SRC-PATENT-OFFICE"],
        evidence_ids=["EV-PAT-EARLY"],
        limitations=["Not legal anticipation.", "E3 requires claim construction."],
    ))
    r.add_matrix(ClaimElementMatrix(
        id="MAT-P6-THESIS",
        target_claim_id="CLAIM-TARGET-1",
        reference_id="PAPER-P6-THESIS",
        reference_type="THESIS",
        mappings=[
            {"element": "E1 receiving transaction stream", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
            {"element": "E2 computing rolling histogram", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
            {"element": "E3 adjusting threshold dynamically based on drift", "state": ClaimElementState.NOT_FOUND.value, "notes": "Static threshold only."},
            {"element": "E4 blocking transaction if score exceeds threshold", "state": ClaimElementState.PARTIAL.value, "notes": "Alert/block concept present but not identical."},
        ],
        overall_relevance=PriorArtRelevance.RELEVANT_PRIOR_ART_CANDIDATE,
        source_ids=["SRC-CROSSREF"],
        evidence_ids=["EV-P6-THESIS"],
    ))
    r.add_matrix(ClaimElementMatrix(
        id="MAT-STD-2020",
        target_claim_id="CLAIM-TARGET-1",
        reference_id="STD-IEEE-SYN-2020",
        reference_type="STANDARD",
        mappings=[
            {"element": "E1 receiving transaction stream", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Normative."},
            {"element": "E2 computing rolling histogram", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Normative."},
            {"element": "E3 adjusting threshold dynamically based on drift", "state": ClaimElementState.NOT_FOUND.value, "notes": "Not normatively required."},
            {"element": "E4 blocking transaction if score exceeds threshold", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Normative."},
        ],
        overall_relevance=PriorArtRelevance.PARTIAL_OVERLAP,
        source_ids=["SRC-STANDARDS"],
        evidence_ids=["EV-STD-2020"],
    ))
    r.add_matrix(ClaimElementMatrix(
        id="MAT-P1-JOURNAL",
        target_claim_id="CLAIM-TARGET-1",
        reference_id="PAPER-P1-JOURNAL",
        reference_type="PAPER",
        mappings=[
            {"element": "E1 receiving transaction stream", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
            {"element": "E2 computing rolling histogram", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
            {"element": "E3 adjusting threshold dynamically based on drift", "state": ClaimElementState.PARTIAL.value, "notes": "Threshold adjustment described; drift basis ambiguous."},
            {"element": "E4 blocking transaction if score exceeds threshold", "state": ClaimElementState.EXPLICITLY_DISCLOSED.value, "notes": "Explicit."},
        ],
        overall_relevance=PriorArtRelevance.RELEVANT_PRIOR_ART_CANDIDATE,
        source_ids=["SRC-ARXIV", "SRC-CROSSREF"],
        evidence_ids=["EV-P1-ABSTRACT", "EV-P1-METHOD"],
    ))

    r.prepare()
    return r


# =====================================================================
# RESULT BUILDER
# =====================================================================

def graph_version_hash(r: ResearchInt) -> str:
    seed_obj = {
        "papers": sorted((pid, p.title, p.year or 0, p.publication_type.value, p.retraction_status.value, p.availability.value) for pid, p in r.papers.items()),
        "patents": sorted((pid, pt.publication_number, pt.status.value, pt.priority_date or "", pt.family_id) for pid, pt in r.patents.items()),
        "claims": sorted((cid, c.source_id, c.claim_type.value, c.evidence_grade.value, round(float(c.confidence), 3)) for cid, c in r.claims.items()),
        "results": sorted((rid, x.paper_id, x.method, x.metric, float(x.value or 0.0)) for rid, x in r.results.items()),
        "prior_art": sorted((pid, pa.target_patent_id, pa.reference_id, pa.relevance.value, pa.temporal_relevance) for pid, pa in r.prior_art.items()),
        "findings": sorted((fid, f.finding_type.value, f.subject_id, f.verification_state.value, round(float(f.confidence), 3)) for fid, f in r.findings.items()),
    }
    return sha256_short(json.dumps(jsonable(seed_obj), sort_keys=True))


def build_source_graph(r: ResearchInt) -> Dict[str, Any]:
    edges = []
    for src in r.sources.values():
        if src.derived_from:
            edges.append({"source": src.derived_from, "target": src.id, "relationship_type": "DERIVED_FROM"})
    return {"nodes": [s.id for s in r.sources.values()], "edges": edges}


def build_source_dependency_graph(r: ResearchInt) -> Dict[str, List[str]]:
    families: Dict[str, List[str]] = defaultdict(list)
    for sid in r.sources:
        fam = r.get_source_family(sid) or "UNKNOWN"
        families[fam].append(sid)
    return {k: sorted(v) for k, v in families.items()}


def build_citation_network(r: ResearchInt) -> Dict[str, Any]:
    nodes = sorted(r.papers.keys())
    edges = []
    for edge in r.citations.values():
        edges.append({
            "id": edge.id,
            "citing": edge.citing_paper_id,
            "cited": edge.cited_paper_id,
            "context": edge.context,
            "date": edge.date,
            "evidence_ids": edge.evidence_ids,
            "limitations": edge.limitations,
        })
    return {
        "nodes": nodes,
        "edges": edges,
        "guardrails": [
            "CITES is not automatically SUPPORTS.",
            "Citation context preserved.",
            "Forward/backward citation analysis used for discovery, not truth voting.",
        ],
    }


def build_research_graph(r: ResearchInt) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for q in r.queries.values():
        nodes.append({"id": q.id, "type": "Query", "text": q.query_text, "databases": q.databases})
    for p in r.papers.values():
        nodes.append({
            "id": p.id,
            "type": "Paper",
            "title": p.title,
            "publication_type": p.publication_type.value,
            "availability": p.availability.value,
            "retraction_status": p.retraction_status.value,
            "correction_status": p.correction_status.value,
        })
    for pt in r.patents.values():
        nodes.append({
            "id": pt.id,
            "type": "Patent",
            "status": pt.status.value,
            "priority_date": pt.priority_date,
            "family_id": pt.family_id,
        })
    for pc in r.patent_claims.values():
        nodes.append({"id": pc.id, "type": "PatentClaim", "patent_id": pc.patent_id, "number": pc.number, "elements": pc.elements})
        edges.append({"source": pc.patent_id, "target": pc.id, "relationship_type": "HAS_CLAIM"})
    for s in r.standards.values():
        nodes.append({"id": s.id, "type": "Standard", "number": s.number, "publication_date": s.publication_date})
    for d in r.datasets.values():
        nodes.append({"id": d.id, "type": "Dataset", "name": d.name, "accessibility": d.accessibility, "license": d.license})
    for b in r.benchmarks.values():
        nodes.append({"id": b.id, "type": "Benchmark", "task": b.task, "metric": b.metric, "dataset_id": b.dataset_id})
        edges.append({"source": b.id, "target": b.dataset_id, "relationship_type": "USES_DATASET"})
    for c in r.claims.values():
        nodes.append({"id": c.id, "type": "Claim", "source_id": c.source_id, "claim_type": c.claim_type.value, "evidence_grade": c.evidence_grade.value})
        edges.append({"source": c.source_id, "target": c.id, "relationship_type": "CLAIMS"})
    for res in r.results.values():
        nodes.append({"id": res.id, "type": "Result", "paper_id": res.paper_id, "metric": res.metric, "value": res.value})
        edges.append({"source": res.paper_id, "target": res.id, "relationship_type": "REPORTS_RESULT"})
        if res.dataset_id:
            edges.append({"source": res.id, "target": res.dataset_id, "relationship_type": "MEASURED_ON_DATASET"})
    for rep in r.replications.values():
        edges.append({"source": rep.replicating_paper_id, "target": rep.original_paper_id, "relationship_type": rep.state.value, "independence": rep.independence_state})
    for cite in r.citations.values():
        edges.append({"source": cite.citing_paper_id, "target": cite.cited_paper_id, "relationship_type": "CITES", "context": cite.context})
    for pa in r.prior_art.values():
        edges.append({"source": pa.reference_id, "target": pa.target_patent_id, "relationship_type": "POTENTIAL_PRIOR_ART_FOR", "relevance": pa.relevance.value})
    for feat in r.features.values():
        nodes.append({"id": feat.id, "type": "TechnicalFeature", "name": feat.name, "first_seen_candidate": feat.first_seen_candidate})
        for pid in feat.papers:
            edges.append({"source": pid, "target": feat.id, "relationship_type": "DISCLOSES_FEATURE"})
        for pid in feat.patents:
            edges.append({"source": pid, "target": feat.id, "relationship_type": "DISCLOSES_FEATURE"})
        for sid in feat.standards:
            edges.append({"source": sid, "target": feat.id, "relationship_type": "DISCLOSES_FEATURE"})

    return {
        "nodes": nodes,
        "edges": edges,
        "guardrails": [
            "Temporal edges preserve publication/priority dates.",
            "Citation and support graphs are separate.",
            "Prior-art edges are candidates, not legal determinations.",
        ],
    }


def build_timeline(r: ResearchInt) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for q in r.queries.values():
        if q.search_date:
            events.append({
                "time": q.search_date,
                "type": "SEARCH_QUERY",
                "subject_id": q.id,
                "description": f"Query {q.id} executed across {q.databases}; included {q.included_count}.",
                "source_ids": q.source_ids,
                "evidence_ids": q.evidence_ids,
            })

    for p in r.papers.values():
        if p.publication_date:
            events.append({
                "time": p.publication_date,
                "type": "PAPER_PUBLICATION",
                "subject_id": p.id,
                "description": f"{p.publication_type.value} published: {p.title}",
                "source_ids": p.source_ids,
                "evidence_ids": p.evidence_ids,
            })

    for ret in r.retractions.values():
        if ret.date:
            events.append({
                "time": ret.date,
                "type": "RETRACTION_OR_CORRECTION",
                "subject_id": ret.id,
                "description": f"{ret.status.value} for {ret.paper_id}: {ret.reason}",
                "source_ids": ret.source_ids,
                "evidence_ids": ret.evidence_ids,
            })

    for pt in r.patents.values():
        for label, date in [
            ("PRIORITY_DATE", pt.priority_date),
            ("FILING_DATE", pt.filing_date),
            ("PUBLICATION_DATE", pt.publication_date),
            ("GRANT_DATE", pt.grant_date),
        ]:
            if date:
                events.append({
                    "time": date,
                    "type": f"PATENT_{label}",
                    "subject_id": pt.id,
                    "description": f"Patent {pt.id} {label}: {date}; status={pt.status.value}.",
                    "source_ids": pt.source_ids,
                    "evidence_ids": pt.evidence_ids,
                })

    for s in r.standards.values():
        if s.publication_date:
            events.append({
                "time": s.publication_date,
                "type": "STANDARD_PUBLICATION",
                "subject_id": s.id,
                "description": f"Standard {s.number} version {s.version} published.",
                "source_ids": s.source_ids,
                "evidence_ids": s.evidence_ids,
            })

    return sorted(events, key=lambda e: dt_or_min(e.get("time")))


def build_facts_by_state(r: ResearchInt) -> Dict[str, List[Any]]:
    out: Dict[str, List[Any]] = defaultdict(list)
    for f in r.findings.values():
        out[f.verification_state.value].append(f)
    return {k: v for k, v in out.items()}


def build_result(r: ResearchInt, status: Status) -> Dict[str, Any]:
    dual = r.dual_ai_review()
    summary = r.analyst_summary(dual)
    source_families = build_source_dependency_graph(r)
    facts_by_state = build_facts_by_state(r)

    finding_independence = {
        fid: r.independence_state(f.source_ids)
        for fid, f in r.findings.items()
    }

    supported_facts = facts_by_state.get(VerificationState.SUPPORTED.value, [])
    partial_facts = facts_by_state.get(VerificationState.PARTIALLY_SUPPORTED.value, [])
    candidate_facts = facts_by_state.get(VerificationState.CANDIDATE.value, [])
    disputed_facts = facts_by_state.get(VerificationState.DISPUTED.value, [])
    observed_facts = facts_by_state.get(VerificationState.OBSERVED.value, [])
    unsupported_facts = facts_by_state.get(VerificationState.UNSUPPORTED.value, [])

    unsupported_claims = [
        c for c in r.claims.values()
        if c.verification_state == VerificationState.UNSUPPORTED
        or c.evidence_grade == EvidenceGrade.INSUFFICIENT
    ]

    databases = sorted({db for q in r.queries.values() for db in q.databases})
    search_dates = sorted({q.search_date for q in r.queries.values() if q.search_date})

    preprints = [
        p for p in r.papers.values()
        if p.publication_type == SourceType.PREPRINT
    ]

    reviews = [
        p for p in r.papers.values()
        if any(
            r.methods[mid].design in {
                StudyDesign.SYSTEMATIC_REVIEW,
                StudyDesign.META_ANALYSIS,
            }
            for mid in p.method_ids
            if mid in r.methods
        )
    ]

    meta_analyses = [
        p for p in r.papers.values()
        if any(
            r.methods[mid].design == StudyDesign.META_ANALYSIS
            for mid in p.method_ids
            if mid in r.methods
        )
    ]

    technical_reports = [
        p for p in r.papers.values()
        if p.publication_type == SourceType.TECHNICAL_REPORT
    ]

    theses = [
        p for p in r.papers.values()
        if p.publication_type in {
            SourceType.THESIS,
            SourceType.DISSERTATION,
        }
    ]

    specifications = []

    patent_applications = [
        p for p in r.patents.values()
        if p.status in {
            PatentStatus.APPLICATION,
            PatentStatus.PUBLISHED_APPLICATION,
        }
    ]

    family_map: Dict[str, List[str]] = defaultdict(list)
    for p in r.patents.values():
        if p.family_id:
            family_map[p.family_id].append(p.id)

    patent_families = [
        {
            "family_id": fam,
            "member_ids": sorted(ids),
            "note": "Patent family members are related filings, not independent inventions.",
        }
        for fam, ids in sorted(family_map.items())
        if len(ids) > 1
    ]

    authors = sorted({a for p in r.papers.values() for a in p.authors})
    inventors = sorted({i for p in r.patents.values() for i in p.inventors})
    applicants = sorted({p.applicant for p in r.patents.values() if p.applicant})
    assignees = sorted({p.assignee for p in r.patents.values() if p.assignee})

    institutions = []
    institution_note = (
        "Professional researcher/institution context is not separately modeled in this demo. "
        "No private-person profiling is performed."
    )

    models = sorted(
        {m.model for m in r.methods.values() if m.model}
        | {res.method for res in r.results.values() if res.method}
    )

    algorithms = []
    algorithm_note = (
        "Algorithm-level identity is not separately modeled in this demo. "
        "Do not infer exact algorithm from paper title or method name alone."
    )

    metrics = sorted(
        {res.metric for res in r.results.values() if res.metric}
        | {bm.metric for bm in r.benchmarks.values() if bm.metric}
    )

    experimental_setups = [
        {
            "method_id": m.id,
            "paper_id": m.paper_id,
            "design": m.design.value,
            "sample": m.sample,
            "dataset_ids": m.dataset_ids,
            "baseline": m.baseline,
            "model": m.model,
            "evaluation": m.evaluation,
            "statistical_method": m.statistical_method,
            "limitations": m.limitations,
            "evidence_ids": m.evidence_ids,
        }
        for m in r.methods.values()
    ]

    effect_sizes = [
        {
            "result_id": res.id,
            "paper_id": res.paper_id,
            "metric": res.metric,
            "value": res.value,
            "baseline_value": res.baseline_value,
            "effect_size": res.effect_size,
            "p_value": res.p_value,
            "uncertainty": res.uncertainty,
            "conditions": res.conditions,
        }
        for res in r.results.values()
        if res.effect_size or res.p_value is not None or res.uncertainty
    ]

    statistical_context = [
        {
            "result_id": res.id,
            "paper_id": res.paper_id,
            "metric": res.metric,
            "value": res.value,
            "baseline_value": res.baseline_value,
            "p_value": res.p_value,
            "uncertainty": res.uncertainty,
            "effect_size": res.effect_size,
            "conditions": res.conditions,
            "guardrails": [
                "Statistical significance is not practical significance.",
                "p-values do not establish replication or truth.",
            ],
        }
        for res in r.results.values()
    ]

    source_level_limitations = sorted(
        {
            lim
            for p in r.papers.values()
            for lim in p.limitations
        }
        | {
            lim
            for pt in r.patents.values()
            for lim in pt.limitations
        }
        | {
            lim
            for s in r.standards.values()
            for lim in s.limitations
        }
        | {
            lim
            for d in r.datasets.values()
            for lim in d.limitations
        }
    )

    funding_context = [
        {
            "paper_id": p.id,
            "funding": p.funding,
            "note": "Funding is context, not automatic invalidation.",
        }
        for p in r.papers.values()
        if p.funding
    ]

    conflicts_of_interest = [
        {
            "paper_id": p.id,
            "conflicts": p.conflicts,
            "note": "Declared COI is contextual evidence, not proof of false research.",
        }
        for p in r.papers.values()
        if p.conflicts
    ]

    code_artifacts = [
        {
            "paper_id": p.id,
            "code_url": p.code_url,
            "availability_note": "Repository metadata only; no code was executed.",
            "limitations": [
                "Code availability does not equal reproducibility.",
                "Remote code risk; static inspection only unless separate sandbox/authorization exists.",
            ],
        }
        for p in r.papers.values()
        if p.code_url
    ]

    data_artifacts = list(r.datasets.values())

    reproducibility_states = [
        {
            "paper_id": p.id,
            "state": next(
                (
                    f.statement
                    for f in r.findings.values()
                    if f.finding_type == FindingType.REPRODUCIBILITY_OBSERVED
                    and f.subject_id == p.id
                ),
                "UNKNOWN",
            ),
            "code_url": p.code_url,
            "dataset_ids": p.dataset_ids,
            "limitations": [
                "Code availability is not reproducibility.",
                "No untrusted research code was executed.",
            ],
        }
        for p in r.papers.values()
    ]

    retraction_statuses = {
        RetractionStatus.RETRACTED,
        RetractionStatus.PARTIALLY_RETRACTED,
        RetractionStatus.EXPRESSION_OF_CONCERN,
    }

    retractions = [
        ret for ret in r.retractions.values()
        if ret.status in retraction_statuses
    ]

    corrections = [
        ret for ret in r.retractions.values()
        if ret.status in {
            RetractionStatus.CORRECTED,
            RetractionStatus.ERRATUM,
        }
    ]

    citation_network = build_citation_network(r)

    research_landscape = {
        "topic": r.case.topic,
        "technical_domain": r.case.technical_domain,
        "counts": {
            "papers": len(r.papers),
            "preprints": len(preprints),
            "theses": len(theses),
            "patents": len(r.patents),
            "patent_families": len(patent_families),
            "standards": len(r.standards),
            "datasets": len(r.datasets),
            "benchmarks": len(r.benchmarks),
            "claims": len(r.claims),
            "results": len(r.results),
            "replications": len(r.replications),
            "prior_art_candidates": len(r.prior_art),
            "research_gaps": len(r.research_gaps),
        },
        "major_methods_or_models": models,
        "datasets": sorted(r.datasets.keys()),
        "benchmarks": sorted(r.benchmarks.keys()),
        "standards": sorted(r.standards.keys()),
        "patent_families": [f["family_id"] for f in patent_families],
        "technical_features": sorted(r.features.keys()),
        "open_problems_or_gaps": [g.description for g in r.research_gaps],
        "guardrails": [
            "Landscape is bounded by searched synthetic corpus.",
            "Absence from searched corpus is not absence of all literature or prior art.",
            "Patent count is not innovation quality.",
            "Benchmark leadership is not real-world superiority.",
        ],
    }

    state_of_art = []
    for res in r.results.values():
        paper = r.papers.get(res.paper_id)
        bm = r.benchmarks.get(res.benchmark_id)
        state_of_art.append({
            "task": res.task,
            "method": res.method,
            "paper_id": res.paper_id,
            "paper_date": paper.publication_date if paper else None,
            "dataset_id": res.dataset_id,
            "benchmark_id": res.benchmark_id,
            "benchmark_version": bm.version if bm else None,
            "metric": res.metric,
            "value": res.value,
            "baseline_value": res.baseline_value,
            "conditions": res.conditions,
            "uncertainty": res.uncertainty,
            "note": "Condition-bound result; not universal state-of-the-art.",
            "guardrails": [
                "Benchmark score is not real-world performance.",
                "Do not compare incompatible dataset/split/metric/protocol results.",
                "SOTA claim requires independent, matched, reproducible evaluation.",
            ],
        })

    prior_art_candidates = list(r.prior_art.values())
    claim_element_matrices = list(r.matrices.values())
    novelty_candidates = list(r.novelty_candidates)
    research_gaps = list(r.research_gaps)
    timeline_updates = build_timeline(r)
    observations = list(r.evidence.values())

    source_reliability = {sid: src.reliability for sid, src in r.sources.items()}
    source_bias = {sid: src.notes for sid, src in r.sources.items()}
    source_limitations = {
        sid: [src.notes]
        for sid, src in r.sources.items()
        if src.notes
    }
    source_pedigree = {
        sid: r.get_source_family(sid)
        for sid in r.sources
    }
    source_independence = {
        "source_families": source_families,
        "finding_independence": finding_independence,
        "evidence_families": dict(r.evidence_families),
        "source_dependencies": dict(r.source_dependencies),
    }

    falsification_results = [
        {
            "hypothesis_id": h.id,
            "statement": h.statement,
            "kind": h.kind,
            "status": h.status.value,
            "confidence": h.confidence,
            "supporting_finding_ids": h.supporting_finding_ids,
            "contradicting_finding_ids": h.contradicting_finding_ids,
            "assumptions": h.assumptions,
            "predictions": h.predictions,
            "falsification_conditions": h.falsification_conditions,
            "limitations": h.limitations,
        }
        for h in r.hypotheses
    ]

    unknowns = sorted(set(
        [g.description for g in r.knowledge_gaps]
        + [g.description for g in r.research_gaps]
        + [
            h.statement
            for h in r.hypotheses
            if h.status in {
                HypothesisStatus.UNRESOLVED,
                HypothesisStatus.DISPUTED,
            }
        ]
    ))

    privacy_flags = [
        PrivacyFlag.CASE_SCOPED.value,
        PrivacyFlag.PROFESSIONAL_CONTEXT_ONLY.value,
        PrivacyFlag.NO_PRIVATE_PROFILING.value,
        PrivacyFlag.COPYRIGHT_AWARE.value,
        PrivacyFlag.NO_PAYWALL_BYPASS.value,
        PrivacyFlag.NO_STOLEN_CREDENTIALS.value,
        PrivacyFlag.NO_AUTO_CODE_EXECUTION.value,
        PrivacyFlag.NO_FABRICATED_CITATIONS.value,
        PrivacyFlag.LOCAL_ONLY_DEFAULT.value,
    ]

    legal_flags = [
        "RESEARCHINT does not make final patent validity, infringement, novelty, obviousness, or freedom-to-operate determinations.",
        "Prior-art candidates and claim-element matrices require human patent specialist / LEGALINT review.",
        "Copyright-sensitive reproduction requires permission or lawful exception analysis.",
        "Research misconduct allegations require human review and authoritative evidence.",
    ]

    limitations = [
        "Local synthetic demo; no live literature, patent, standards, code, or dataset access.",
        "Evidence-first, copyright-aware, legal-boundary-aware research intelligence only.",
        "No citations, DOIs, patent numbers, authors, datasets, results, replications, or statistics were fabricated.",
        "No paywall bypass or stolen academic credentials were used.",
        "No large copyrighted text was reproduced; summaries and short necessary excerpts only.",
        "No untrusted research code, notebooks, binaries, containers, or checkpoints were executed.",
        "No final legal patentability, invalidity, infringement, novelty, obviousness, or freedom-to-operate determination was made.",
        "Published does not mean true.",
        "Peer review does not mean replication.",
        "Citation does not mean corroboration.",
        "Preprint and published version may differ.",
        "Retracted sources are excluded from normal evidence.",
        "Database absence is not absence of all research.",
        "Earliest found disclosure is not earliest ever disclosure.",
        "Literature gap is not novelty.",
        "Prior-art candidate is not legal anticipation or invalidity.",
        institution_note,
        algorithm_note,
    ] + r.validation_errors + source_level_limitations

    replay_manifest = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "graph_version": graph_version_hash(r),
        "core_principle": (
            "QUESTION -> SEARCH PLAN -> SOURCE DISCOVERY -> SOURCE PRESERVATION -> SOURCE CLASSIFICATION -> "
            "CLAIM EXTRACTION -> METHODOLOGY EXTRACTION -> EVIDENCE ASSESSMENT -> CITATION / PRIOR-ART GRAPH -> "
            "TEMPORAL ANALYSIS -> SOURCE INDEPENDENCE -> CONTRADICTION ANALYSIS -> REPLICATION CHECK -> "
            "FACT GATE -> SYNTHESIS -> GAP ANALYSIS -> NEXT BEST RESEARCH ACTION"
        ),
        "as_of": r.as_of,
        "search_rule": "Queries, databases, filters, dates, inclusion/exclusion counts, and limitations are preserved for replay.",
        "version_rule": "Preprint, published, corrected, retracted, and erratum versions are linked but not overwritten.",
        "evidence_rule": "Published claim is not automatically true; peer review is not replication; citation is not corroboration.",
        "independence_rule": "Shared dataset, code, authors, cohort, or upstream report may form one evidence family.",
        "patent_rule": "Patent application is not granted patent; family members are not independent inventions; prior-art candidate is not legal invalidity.",
        "copyright_rule": "Only summaries, paraphrases, structured extraction, and short necessary quotations are used.",
        "code_rule": "Research code/artifacts are inspected as untrusted metadata only; no automatic execution.",
        "legal_rule": "Final patent/legal determinations require qualified human review.",
        "policy_exclusions": [
            "No fabricated citations.",
            "No invented DOIs, patent numbers, authors, datasets, results, or replications.",
            "No paywall bypass.",
            "No stolen academic credentials.",
            "No plagiarism or large copyrighted reproduction.",
            "No automatic execution of untrusted research code.",
            "No false patentability or invalidity assurance.",
            "No hiding of contradictory, null, retracted, or corrected research.",
        ],
        "queries": [
            {
                "query_id": q.id,
                "query_text": q.query_text,
                "databases": q.databases,
                "filters": q.filters,
                "search_date": q.search_date,
                "result_count": q.result_count,
                "screened_count": q.screened_count,
                "included_count": q.included_count,
                "excluded_count": q.excluded_count,
                "limitations": q.limitations,
            }
            for q in r.queries.values()
        ],
        "source_lineage": source_families,
        "finding_independence": finding_independence,
        "evidence_families": dict(r.evidence_families),
        "source_dependencies": dict(r.source_dependencies),
    }

    return {
        "case_id": r.case.case_id,
        "task_id": r.case.task_id,
        "objective": r.case.objective,
        "research_questions": r.case.research_questions,
        "topic": r.case.topic,
        "technical_domain": r.case.technical_domain,
        "concepts": r.case.concepts,
        "keywords": r.case.keywords,
        "search_mode": r.case.search_mode.value,
        "scope": r.case.scope,
        "authorization": r.case.authorization,
        "status": status.value,
        "as_of": r.as_of,

        "queries": list(r.queries.values()),
        "databases": databases,
        "search_dates": search_dates,

        "source_ids": sorted(r.sources.keys()),
        "evidence_ids": sorted(r.evidence.keys()),

        "papers": list(r.papers.values()),
        "preprints": preprints,
        "reviews": reviews,
        "meta_analyses": meta_analyses,
        "technical_reports": technical_reports,
        "theses": theses,

        "standards": list(r.standards.values()),
        "specifications": specifications,

        "patents": list(r.patents.values()),
        "patent_applications": patent_applications,
        "patent_families": patent_families,
        "patent_claims": list(r.patent_claims.values()),

        "authors": authors,
        "inventors": inventors,
        "institutions": institutions,
        "applicants": applicants,
        "assignees": assignees,

        "technical_features": list(r.features.values()),
        "methods": list(r.methods.values()),
        "algorithms": algorithms,
        "models": models,

        "datasets": list(r.datasets.values()),
        "benchmarks": list(r.benchmarks.values()),
        "metrics": metrics,
        "experimental_setups": experimental_setups,

        "results": list(r.results.values()),
        "effect_sizes": effect_sizes,
        "statistical_context": statistical_context,

        "limitations_by_source": source_level_limitations,
        "funding_context": funding_context,
        "conflicts_of_interest": conflicts_of_interest,

        "code_artifacts": code_artifacts,
        "data_artifacts": data_artifacts,

        "replication_records": list(r.replications.values()),
        "reproducibility_states": reproducibility_states,

        "retractions": retractions,
        "corrections": corrections,

        "citation_network": citation_network,
        "source_dependencies": dict(r.source_dependencies),
        "evidence_families": dict(r.evidence_families),

        "research_landscape": research_landscape,
        "state_of_art": state_of_art,

        "prior_art_candidates": prior_art_candidates,
        "claim_element_matrices": claim_element_matrices,
        "novelty_candidates": novelty_candidates,
        "research_gaps": research_gaps,

        "timeline_updates": timeline_updates,

        "observations": observations,
        "claims": list(r.claims.values()),
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "observed_facts": observed_facts,
        "unsupported_facts": unsupported_facts,
        "unsupported_claims": unsupported_claims,

        "source_reliability": source_reliability,
        "source_bias": source_bias,
        "source_limitations": source_limitations,
        "source_pedigree": source_pedigree,
        "source_independence": source_independence,

        "contradictions": r.contradictions,
        "hypotheses": r.hypotheses,
        "falsification_results": falsification_results,

        "privacy_flags": privacy_flags,
        "legal_flags": legal_flags,

        "unknowns": unknowns,
        "knowledge_gaps": r.knowledge_gaps,
        "recommended_next_actions": r.actions,
        "recommendations": r.recommendations,
        "specialist_handoffs": r.handoffs,

        "limitations": limitations,
        "analyst_summary": summary,
        "dual_ai_review": dual,
        "research_graph": build_research_graph(r),
        "source_graph": build_source_graph(r),
        "source_dependency_graph": source_families,
        "replay_manifest": replay_manifest,
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline() -> Dict[str, Any]:
    r = build_sample_researchint()
    return build_result(r, Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    r = ResearchInt(case)

    r.knowledge_gaps.append(KnowledgeGap(
        id="KGAP-NO-CORPUS",
        gap_type=GapType.FULL_TEXT_UNAVAILABLE,
        description=(
            "No configured public/authorized research corpus is available. "
            "No papers, patents, standards, datasets, code artifacts, citations, replications, "
            "retractions, prior-art candidates, or research gaps can be resolved."
        ),
        importance="HIGH",
        recommended_source=(
            "Provide authorized bibliographic metadata, open-access papers, patent office records, "
            "standards metadata, dataset/archive metadata, repository metadata, retraction notices, "
            "or a sanitized local RESEARCHINT evidence corpus."
        ),
        specialist="RESEARCHINT / DOCINT / LEGALINT / DATASETINT / REPOINT",
        expected_information_value=0.95,
    ))

    r.actions = [
        NextAction(
            id="ACT-CONFIGURE-RESEARCH-EVIDENCE",
            description=(
                "Configure lawful public/authorized research evidence or supply sanitized local corpus. "
                "Do not fabricate citations, bypass paywalls, use stolen credentials, reproduce large "
                "copyrighted text, execute untrusted research code, or make final legal patent determinations."
            ),
            priority=1,
            privacy_impact="LOW",
            expected_gain=0.95,
            specialist=None,
            requires_human_approval=False,
        )
    ]

    r.handoffs = []
    r.recommendations = []
    r.hypotheses = []
    r.research_gaps = []
    r.novelty_candidates = []

    dual = {
        "primary_research_analyst": "No evidence available.",
        "independent_research_skeptic_issues": [
            "No research corpus configured.",
            "No papers or patents resolved.",
            "No claims, methods, results, replications, or prior-art candidates can be assessed.",
            "No citations, DOIs, patent numbers, authors, datasets, or results can be fabricated.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "AI agreement is not independent scientific replication.",
    }

    summary = (
        "RESEARCHINT UNRESOLVED: No configured public/authorized research corpus. "
        "No papers, patents, citations, DOIs, authors, datasets, results, replications, prior art, "
        "novelty, invalidity, infringement, or research gaps were fabricated. "
        "Provide authorized evidence or run sample mode."
    )

    result = build_result(r, Status.BLOCKED_CONFIGURATION)
    result["analyst_summary"] = summary
    result["dual_ai_review"] = dual
    return result


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "research_questions": case.research_questions,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited research-intelligence request detected. RESEARCHINT supports authorized, "
            "evidence-first, copyright-aware, legal-boundary-aware research intelligence only. "
            "It does not fabricate citations, DOIs, patent numbers, authors, datasets, results, or replications; "
            "does not bypass paywalls or use stolen academic credentials; does not plagiarize or reproduce large "
            "copyrighted text; does not execute untrusted research code; and does not make final legal patent "
            "validity, infringement, novelty, obviousness, or freedom-to-operate determinations."
        ),
        "lawful_alternatives": [
            "Search configured/public/authorized bibliographic, patent, standards, dataset, and repository metadata.",
            "Resolve paper versions, preprints, corrections, retractions, and duplicate publications.",
            "Extract claims, methods, datasets, benchmarks, results, limitations, funding, and COI context.",
            "Assess citation context, source independence, evidence families, replication, and reproducibility.",
            "Identify prior-art candidates and claim-element overlaps without legal conclusions.",
            "Route patent/legal questions to LEGALINT or a qualified human patent specialist.",
            "Use summaries, paraphrases, structured extraction, and short necessary quotations only.",
            "Perform static inspection of research code/artifacts; do not execute untrusted code.",
        ],
        "privacy_flags": [
            PrivacyFlag.COPYRIGHT_AWARE.value,
            PrivacyFlag.NO_PAYWALL_BYPASS.value,
            PrivacyFlag.NO_STOLEN_CREDENTIALS.value,
            PrivacyFlag.NO_AUTO_CODE_EXECUTION.value,
            PrivacyFlag.NO_FABRICATED_CITATIONS.value,
            PrivacyFlag.PROFESSIONAL_CONTEXT_ONLY.value,
            PrivacyFlag.NO_PRIVATE_PROFILING.value,
        ],
        "legal_flags": [
            "No final patent validity determination.",
            "No final infringement determination.",
            "No final novelty or obviousness determination.",
            "No final freedom-to-operate determination.",
            "Copyright-sensitive reproduction requires lawful permission or exception analysis.",
        ],
        "limitations": [
            "No research-intelligence analysis performed.",
            "No citations, papers, patents, authors, datasets, results, replications, or prior art fabricated.",
            "No paywall bypass, credential misuse, plagiarism, code execution, or legal determination performed.",
        ],
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.research_questions,
            case.topic,
            case.technical_domain,
            *case.concepts,
            *case.keywords,
            *case.known_papers,
            *case.known_patents,
            *case.known_standards,
            *case.authors,
            *case.institutions,
            case.authorization or "",
            " ".join(case.scope),
        ]
    )

    violations = policy_guard(text)
    if violations:
        return blocked_policy_result(case, violations)

    if case.sample:
        return run_sample_pipeline()

    return run_unconfigured_pipeline(case)


# =====================================================================
# CLI
# =====================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "TRACEATLAS RESEARCHINT local evidence-first research intelligence pipeline. "
            "Sample mode uses synthetic authorized literature/patent/standard/dataset/code metadata."
        )
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic RESEARCHINT sample.")
    parser.add_argument("--objective", help="Authorized research-intelligence objective.")
    parser.add_argument("--question", action="append", default=[], help="Research question. Repeatable.")
    parser.add_argument("--topic", default="", help="Research topic.")
    parser.add_argument("--domain", default="", help="Technical domain.")
    parser.add_argument("--concept", action="append", default=[], help="Concept. Repeatable.")
    parser.add_argument("--keyword", action="append", default=[], help="Keyword. Repeatable.")
    parser.add_argument("--paper", action="append", default=[], help="Known paper ID/DOI/title hint. Repeatable.")
    parser.add_argument("--patent", action="append", default=[], help="Known patent ID/number. Repeatable.")
    parser.add_argument("--standard", action="append", default=[], help="Known standard ID. Repeatable.")
    parser.add_argument("--author", action="append", default=[], help="Author name. Repeatable.")
    parser.add_argument("--institution", action="append", default=[], help="Institution name. Repeatable.")
    parser.add_argument("--time-range", help="Time range hint.")
    parser.add_argument("--jurisdiction", action="append", default=[], help="Patent jurisdiction. Repeatable.")
    parser.add_argument("--language", action="append", default=["en"], help="Language filter. Repeatable.")
    parser.add_argument("--publication-type", action="append", default=[], help="Publication type filter. Repeatable.")
    parser.add_argument(
        "--search-mode",
        choices=[m.value for m in SearchMode],
        default=None,
        help="Search mode.",
    )
    parser.add_argument("--as-of", default=DEFAULT_AS_OF, help="Analysis as-of timestamp.")

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        try:
            search_mode = SearchMode(args.search_mode) if args.search_mode else SearchMode.SYSTEMATIC
        except ValueError:
            search_mode = SearchMode.CUSTOM

        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            research_questions=args.question,
            topic=args.topic,
            technical_domain=args.domain,
            concepts=args.concept,
            keywords=args.keyword,
            known_papers=args.paper,
            known_patents=args.patent,
            known_standards=args.standard,
            authors=args.author,
            institutions=args.institution,
            time_range=args.time_range,
            jurisdictions=args.jurisdiction,
            languages=args.language,
            publication_types=args.publication_type,
            search_mode=search_mode,
            as_of=args.as_of,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
    
