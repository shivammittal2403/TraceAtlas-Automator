#!/usr/bin/env python3
"""
TRACEATLAS / REPUTATIONINT — Local lawful public-source reputation intelligence pipeline.

SAFETY / POLICY BOUNDARIES:
- Local synthetic demo only.
- Does NOT access live social platforms, private groups, private accounts, closed channels,
  restricted databases, stolen accounts, or non-public sources.
- Does NOT harass critics, dox users, expose private contact details, identify anonymous
  critics unnecessarily, infiltrate private groups, use stolen accounts, impersonate users,
  create/buy fake reviews or endorsements, deploy bots, astroturf, brigade, mass-report
  legitimate criticism, threaten/blackmail critics, generate propaganda, manipulate political
  opinion/voters, or autonomously publish accusations.
- Separates perception from fact.
- Treats allegations as allegations until independently verified.
- Hands off breach/fraud/coordination/legal questions to appropriate specialists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


PIPELINE_VERSION = "0.1.0-reputationint-lawful-public-source-demo"
DEFAULT_AS_OF = "2026-10-09T00:00:00Z"


class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ENTITY_UNRESOLVED = "ENTITY_UNRESOLVED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_DEPENDENCY_UNRESOLVED = "SOURCE_DEPENDENCY_UNRESOLVED"
    NARRATIVE_UNRESOLVED = "NARRATIVE_UNRESOLVED"
    SENTIMENT_LOW_CONFIDENCE = "SENTIMENT_LOW_CONFIDENCE"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_PERMISSION = "BLOCKED_PERMISSION"
    BLOCKED_PRIVACY = "BLOCKED_PRIVACY"
    BLOCKED_LEGAL = "BLOCKED_LEGAL"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class ContentType(str, Enum):
    FACTUAL_REPORT = "FACTUAL_REPORT"
    ALLEGATION = "ALLEGATION"
    OPINION = "OPINION"
    COMMENTARY = "COMMENTARY"
    EDITORIAL = "EDITORIAL"
    REVIEW = "REVIEW"
    COMPLAINT = "COMPLAINT"
    TESTIMONY = "TESTIMONY"
    PRESS_RELEASE = "PRESS_RELEASE"
    OFFICIAL_STATEMENT = "OFFICIAL_STATEMENT"
    ADVERTISEMENT = "ADVERTISEMENT"
    SATIRE = "SATIRE"
    PARODY = "PARODY"
    RUMOR = "RUMOR"
    MISINFORMATION_CANDIDATE = "MISINFORMATION_CANDIDATE"
    FACT_CHECK = "FACT_CHECK"
    CORRECTION = "CORRECTION"
    UNKNOWN = "UNKNOWN"


class ClaimState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    SUPPORTED = "SUPPORTED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    REFUTED_BY_AVAILABLE_EVIDENCE = "REFUTED_BY_AVAILABLE_EVIDENCE"
    LEGAL_FINDING_EXISTS = "LEGAL_FINDING_EXISTS"
    INCONCLUSIVE = "INCONCLUSIVE"
    OFFICIAL_RESPONSE = "OFFICIAL_RESPONSE"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


PROHIBITED_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    (
        "HARASSMENT_DOXXING_THREATS",
        re.compile(
            r"\b(harass|dox|doxx|expose (private|home|address|phone)|identify anonymous critic|"
            r"threaten reviewer|blackmail critic|target critic)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "FAKE_REVIEWS_OR_ENDORSEMENTS",
        re.compile(
            r"\b(create|buy|generate|plant|incentivize)\s+(fake\s+)?(review|endorsement|testimonial)|"
            r"review manipulation\b|\bfake criticism\b",
            re.IGNORECASE,
        ),
    ),
    (
        "BOTS_ASTROTURF_BRIGADING_MASS_REPORTING",
        re.compile(
            r"\b(deploy bots?|bot network|astroturf|fake engagement|fake amplification|"
            r"coordinate brigading|mass[- ]report|report critics)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PRIVATE_INFILTRATION_OR_STOLEN_ACCOUNTS",
        re.compile(
            r"\b(infiltrate private (group|channel|account)|use stolen account|impersonate user|"
            r"access private (dm|message|account|group))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PROPAGANDA_PERSUASION_VOTER_MANIPULATION",
        re.compile(
            r"\b(propaganda|psychological manipulation|political persuasion|voter manipulation|"
            r"microtarget(?:ing|ed) influence|deceptive narrative|reputation laundering)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "AUTONOMOUS_DEFAMATION_OR_ACCUSATION",
        re.compile(
            r"\b(autonomously publish accusation|defame|declare guilty|"
            r"publish unverified (criminal|fraud|misconduct) allegation)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PRIVATE_PERSON_SURVEILLANCE_OR_SENSITIVE_INFERENCE",
        re.compile(
            r"\b(private person surveillance|profile minor|comprehensive reputation score for private person|"
            r"infer (race|religion|health|sexual orientation|political belief) from public content)\b",
            re.IGNORECASE,
        ),
    ),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}{h}"


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {f: jsonable(getattr(obj, f)) for f in obj.__dataclass_fields__}
    if isinstance(obj, (list, tuple, set)):
        return [jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    return obj


def policy_guard(text: str) -> List[Dict[str, str]]:
    violations: List[Dict[str, str]] = []
    for rule, rx in PROHIBITED_PATTERNS:
        m = rx.search(text or "")
        if m:
            violations.append({"rule": rule, "matched": m.group(0)})
    return violations


@dataclass
class Source:
    id: str
    title: str
    url: str
    source_type: str
    independence_group: str = "UNKNOWN"
    reliability: float = 0.5
    derived_from: Optional[str] = None
    published_at: Optional[str] = None
    notes: str = ""


@dataclass
class Mention:
    id: str
    entity: str
    source_id: str
    author_or_publisher: str
    published_at: str
    content_type: ContentType
    text: str
    language: str = "en"
    stance: str = "UNCLEAR"
    sentiment: str = "UNCLEAR"
    aspects: Dict[str, str] = field(default_factory=dict)
    claim_ids: List[str] = field(default_factory=list)
    count: int = 1
    family_count: int = 1
    source_family: str = ""
    origin_group: str = ""
    engagement: Dict[str, int] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Claim:
    id: str
    subject: str
    predicate: str
    object: str
    claim_type: str
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    state: ClaimState = ClaimState.INCONCLUSIVE
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Narrative:
    id: str
    entity: str
    topic: str
    summary: str
    first_seen: str
    last_seen: str
    source_families: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    supporting_claims: List[str] = field(default_factory=list)
    contradicting_claims: List[str] = field(default_factory=list)
    sentiment: str = "MIXED"
    reach: str = "UNKNOWN"
    persistence: str = "UNKNOWN"
    state: str = "OBSERVED"
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class OfficialResponse:
    id: str
    entity: str
    published_at: str
    response_type: str
    summary: str
    source_id: str
    limitations: List[str] = field(default_factory=list)


@dataclass
class Correction:
    id: str
    source_id: str
    original_claim_id: str
    corrected_claim_id: str
    published_at: str
    summary: str
    original_reach: int
    correction_reach: int
    limitations: List[str] = field(default_factory=list)


@dataclass
class FactCheck:
    id: str
    claim_id: str
    source_id: str
    published_at: str
    verdict: str
    summary: str
    limitations: List[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    id: str
    statement: str
    kind: str
    supporting_claim_ids: List[str] = field(default_factory=list)
    contradicting_claim_ids: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
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
    severity: str = "MEDIUM"
    status: str = "OPEN"
    recommended_resolution: str = ""


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: [
        "lawful_public_source_monitoring",
        "evidence_first",
        "privacy_aware",
        "no_manipulation",
        "no_harassment",
        "no_doxxing",
        "perception_fact_separation",
    ])
    authorization: str = "demo_authorized_public_source_reputation_intelligence"
    organizations: List[str] = field(default_factory=list)
    brands: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    public_roles: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    events: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    as_of: str = DEFAULT_AS_OF
    sample: bool = False


class ReputationInt:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.as_of = case.as_of or DEFAULT_AS_OF

        self.sources: Dict[str, Source] = {}
        self.mentions: List[Mention] = []
        self.claims: Dict[str, Claim] = {}
        self.narratives: List[Narrative] = []
        self.official_responses: List[OfficialResponse] = []
        self.corrections: List[Correction] = []
        self.fact_checks: List[FactCheck] = []

        self.raw_mention_count = 0
        self.deduplicated_content_origins = 0
        self.independent_source_families = 0
        self.top_source_families: List[Dict[str, Any]] = []
        self.syndication_groups: List[Dict[str, Any]] = []
        self.aspect_sentiment: Dict[str, Dict[str, float]] = {}
        self.overall_sentiment: Dict[str, float] = {}
        self.misinformation_candidates: List[str] = []
        self.coordination_candidates: List[Dict[str, str]] = []
        self.reputation_risk: Dict[str, Any] = {}
        self.reputation_opportunities: List[str] = []
        self.stakeholder_groups: List[str] = []
        self.representativeness = ""
        self.timeline: List[Dict[str, Any]] = []
        self.hypotheses: List[Hypothesis] = []
        self.contradictions: List[Contradiction] = []
        self.gaps: List[Dict[str, Any]] = []
        self.actions: List[Dict[str, Any]] = []
        self.recommendations: List[Dict[str, Any]] = []
        self.handoffs: List[Dict[str, str]] = []
        self.privacy_flags: List[str] = []
        self.legal_flags: List[str] = []
        self.limitations: List[str] = []
        self.dual: Dict[str, Any] = {}
        self.summary = ""

    def add_source(self, source: Source) -> Source:
        self.sources[source.id] = source
        return source

    def add_mention(self, mention: Mention) -> Mention:
        self.mentions.append(mention)
        return mention

    def add_claim(self, claim: Claim) -> Claim:
        self.claims[claim.id] = claim
        return claim

    def add_narrative(self, narrative: Narrative) -> Narrative:
        self.narratives.append(narrative)
        return narrative

    def add_official_response(self, response: OfficialResponse) -> OfficialResponse:
        self.official_responses.append(response)
        return response

    def add_correction(self, correction: Correction) -> Correction:
        self.corrections.append(correction)
        return correction

    def add_fact_check(self, fact_check: FactCheck) -> FactCheck:
        self.fact_checks.append(fact_check)
        return fact_check

    def get_source_family(self, source_id: str) -> Optional[str]:
        src = self.sources.get(source_id)
        if not src:
            return None
        seen: Set[str] = set()
        cur = src
        while cur and cur.derived_from and cur.derived_from in self.sources and cur.id not in seen:
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

    def compute_metrics(self) -> None:
        if not self.mentions:
            self.raw_mention_count = 0
            self.deduplicated_content_origins = 0
            self.independent_source_families = 0
            self.top_source_families = []
            self.syndication_groups = []
            return

        family_volume: Dict[str, int] = defaultdict(int)
        family_count: Dict[str, int] = {}
        origin_volume: Dict[str, int] = defaultdict(int)
        origin_families: Dict[str, Set[str]] = defaultdict(set)

        for m in self.mentions:
            family_volume[m.source_family] += m.count
            family_count[m.source_family] = max(family_count.get(m.source_family, 0), m.family_count)
            origin_volume[m.origin_group] += m.count
            origin_families[m.origin_group].add(m.source_family)

        self.raw_mention_count = sum(m.count for m in self.mentions)
        self.independent_source_families = sum(family_count.values())
        self.deduplicated_content_origins = len(origin_volume)
        self.top_source_families = [
            {"rank": i + 1, "source_family": k, "mention_count": v}
            for i, (k, v) in enumerate(sorted(family_volume.items(), key=lambda x: x[1], reverse=True)[:9])
        ]
        self.syndication_groups = [
            {
                "origin_group": k,
                "mention_count": v,
                "source_families": sorted(origin_families[k]),
                "note": "Mentions in one origin group are distribution events, not independent corroboration.",
            }
            for k, v in sorted(origin_volume.items(), key=lambda x: x[1], reverse=True)
        ]

    def fact_gate_claims(self) -> None:
        for c in self.claims.values():
            families = self.source_families(c.source_ids)
            rels = [self.sources[sid].reliability for sid in c.source_ids if sid in self.sources]
            base = max(rels, default=0.5)

            if len(families) >= 2:
                base = min(0.99, base * 1.05)
            elif len(families) == 1 and len(c.source_ids) > 1:
                base *= 0.90
                c.limitations.append("Multiple cited sources share one upstream source family.")

            if c.claim_type == "PERCEPTION_FACT":
                c.state = ClaimState.SUPPORTED
                base = max(base, 0.90)
                c.limitations.append("Perception fact: describes public discourse, not underlying truth.")
            elif c.claim_type == "SUBSTANTIVE_ALLEGATION":
                c.state = ClaimState.UNVERIFIED
                base = min(base, 0.45)
                c.limitations.append("Allegation not adjudicated by REPUTATIONINT; requires independent primary evidence.")
            elif c.claim_type == "REGULATORY_ACTION":
                c.state = ClaimState.SUPPORTED if base >= 0.70 else ClaimState.PARTIALLY_SUPPORTED
                c.limitations.append("Regulatory action is precise public record, not generalized misconduct conclusion.")
            elif c.claim_type == "CLAIM_INFLATION":
                c.state = ClaimState.DISPUTED
                base = min(base, 0.35)
                c.limitations.append("Downstream severity/scope/certainty inflation detected or disputed.")
            elif c.claim_type == "OFFICIAL_STATEMENT":
                c.state = ClaimState.OFFICIAL_RESPONSE
                base = min(base, 0.75)
                c.limitations.append("Official statement is one source, not final truth; denial does not refute allegation.")
            elif c.claim_type == "CUSTOMER_EXPERIENCE":
                c.state = ClaimState.PARTIALLY_SUPPORTED
                base = min(base, 0.65)
                c.limitations.append("Review/complaint is self-reported and not automatically verified experience.")
            else:
                if base >= 0.75:
                    c.state = ClaimState.SUPPORTED
                elif base >= 0.60:
                    c.state = ClaimState.PARTIALLY_SUPPORTED
                elif base >= 0.40:
                    c.state = ClaimState.INCONCLUSIVE
                else:
                    c.state = ClaimState.UNVERIFIED

            c.confidence = round(max(0.0, min(0.99, base)), 3)

    def aggregate_sentiment(self) -> None:
        aspect_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        aspect_totals: Dict[str, int] = defaultdict(int)
        overall_counts: Dict[str, int] = defaultdict(int)

        for m in self.mentions:
            overall_counts[m.sentiment] += m.count
            for aspect, label in m.aspects.items():
                aspect_counts[aspect][label] += m.count
                aspect_totals[aspect] += m.count

        self.aspect_sentiment = {
            aspect: {
                label: round((cnt / aspect_totals[aspect]) * 100.0, 1)
                for label, cnt in labels.items()
            }
            for aspect, labels in aspect_counts.items()
            if aspect_totals[aspect]
        }

        total = sum(overall_counts.values())
        self.overall_sentiment = {
            label: round((cnt / total) * 100.0, 1)
            for label, cnt in overall_counts.items()
        } if total else {}

    def detect_candidates(self) -> None:
        self.misinformation_candidates = [
            c.id for c in self.claims.values()
            if c.claim_type in {"CLAIM_INFLATION", "RUMOR"}
            and c.state in {ClaimState.DISPUTED, ClaimState.UNVERIFIED, ClaimState.REFUTED_BY_AVAILABLE_EVIDENCE}
        ]

        if self.raw_mention_count and self.top_source_families:
            top_share = sum(x["mention_count"] for x in self.top_source_families) / self.raw_mention_count
        else:
            top_share = 0.0

        if top_share >= 0.70:
            self.coordination_candidates = [{
                "id": "COORD-CAND-1",
                "state": "LOW_CONFIDENCE_CANDIDATE",
                "reason": "Amplification is concentrated in a small number of source families/origin groups.",
                "handoff": "DISINFOINT",
                "limitations": [
                    "Concentration is not proof of malicious coordination.",
                    "Organic virality, syndication, and platform effects remain possible.",
                    "Do not infer intent without evidence.",
                ],
            }]
        else:
            self.coordination_candidates = []

    def build_risk_and_opportunities(self) -> None:
        if not self.mentions:
            self.reputation_risk = {"state": "UNKNOWN", "reason": "No public-source corpus configured."}
            self.reputation_opportunities = []
            return

        negative = sum(m.count for m in self.mentions if m.sentiment in {"NEGATIVE", "STRONGLY_NEGATIVE"})
        negative_share = negative / max(1, self.raw_mention_count)

        severe_unverified = any(
            c.claim_type == "SUBSTANTIVE_ALLEGATION" and c.state == ClaimState.UNVERIFIED
            for c in self.claims.values()
        )
        regulated = any(c.claim_type == "REGULATORY_ACTION" for c in self.claims.values())
        corrected = bool(self.corrections)

        self.reputation_risk = {
            "public_impact": "HIGH" if negative_share >= 0.50 else "MEDIUM" if negative_share >= 0.20 else "LOW",
            "claim_severity": "HIGH" if severe_unverified else "MEDIUM",
            "claim_verification": "LOW_FOR_SUBSTANTIVE_ALLEGATION" if severe_unverified else "MIXED",
            "source_independence": "LOW_FOR_CORE_ALLEGATION" if self.independent_source_families <= 10 else "PARTIAL",
            "reach_concentration": round(negative_share * 100.0, 1),
            "persistence": "HIGH" if self.narratives and any(n.persistence == "HIGH" for n in self.narratives) else "MEDIUM",
            "stakeholder_relevance": "HIGH" if regulated else "MEDIUM",
            "response_effect": "MIXED" if self.official_responses and corrected else "UNKNOWN",
            "factual_misconduct_status": "UNRESOLVED",
            "guardrails": [
                "Reputation risk is not proof of wrongdoing.",
                "A false allegation can still create severe reputational risk.",
                "Substantive breach/fraud/criminal claims require specialist adjudication.",
            ],
        }

        self.reputation_opportunities = [
            "Transparent correction propagation can reduce persistent misinformation.",
            "Verified service remediation may improve customer-service aspect sentiment.",
            "Clear regulator-aligned public communication may reduce speculation.",
            "Independent fact-check adoption can improve trust signals if accurately cited.",
        ]

    def build_timeline(self) -> None:
        events: List[Dict[str, Any]] = []

        for src in self.sources.values():
            if src.published_at:
                events.append({
                    "time": src.published_at,
                    "type": "SOURCE_PUBLICATION",
                    "subject_id": src.id,
                    "description": f"{src.source_type} source published: {src.title}",
                    "source_ids": [src.id],
                })

        for resp in self.official_responses:
            events.append({
                "time": resp.published_at,
                "type": "OFFICIAL_RESPONSE",
                "subject_id": resp.id,
                "description": resp.summary,
                "source_ids": [resp.source_id],
            })

        for corr in self.corrections:
            events.append({
                "time": corr.published_at,
                "type": "CORRECTION",
                "subject_id": corr.id,
                "description": corr.summary,
                "source_ids": [corr.source_id],
            })

        for fc in self.fact_checks:
            events.append({
                "time": fc.published_at,
                "type": "FACT_CHECK",
                "subject_id": fc.id,
                "description": fc.summary,
                "source_ids": [fc.source_id],
            })

        self.timeline = sorted(events, key=lambda e: e.get("time") or "")

    def build_outputs(self) -> None:
        self.privacy_flags = [
            "PUBLIC_SOURCE_ONLY",
            "NO_DOXXING",
            "NO_HARASSMENT",
            "NO_PRIVATE_GROUP_INFILTRATION",
            "NO_STOLEN_ACCOUNTS",
            "NO_FAKE_REVIEWS",
            "NO_FAKE_ENDORSEMENTS",
            "NO_BOT_AMPLIFICATION",
            "NO_ASTROTURF",
            "NO_BRIGADING",
            "NO_MASS_REPORTING_LEGITIMATE_CRITICISM",
            "NO_PROPAGANDA",
            "NO_POLITICAL_PERSUASION",
            "NO_PRIVATE_PERSON_SURVEILLANCE",
            "NO_MINOR_REPUTATION_PROFILING",
            "SENSITIVE_TRAITS_EXCLUDED_BY_DEFAULT",
        ]

        self.legal_flags = [
            "ALLEGATION_LANGUAGE_REQUIRED_FOR_SERIOUS_CLAIMS",
            "DEFAMATION_REVIEW_REQUIRED_BEFORE_PUBLIC_ACCUSATION",
            "LEGAL_REVIEW_REQUIRED_FOR_CRIMINAL_FRAUD_MISCONDUCT_ALLEGATIONS",
            "HUMAN_REVIEW_REQUIRED_FOR_CRISIS_RESPONSE_OR_CONTENT_REMOVAL",
        ]

        self.limitations = [
            "Local synthetic demo; no live platform access.",
            "Public-source reputation monitoring only.",
            "Perception is separated from evidence/fact.",
            "Mention volume is not truth, trust, or misconduct.",
            "Syndicated/reposted content is not independent corroboration.",
            "Allegations remain allegations until independently verified.",
            "Sentiment is not fact and may be affected by sarcasm/language/platform bias.",
            "No harassment, doxxing, fake reviews, bots, astroturf, brigading, propaganda, or manipulation.",
        ]

        if not self.claims:
            self.gaps = [{
                "id": "GAP-NO-CORPUS",
                "description": "No configured public-source reputation corpus is available.",
                "importance": "HIGH",
                "recommended_source": "Lawful public/authorized media, review, complaint, official statement, and fact-check metadata.",
                "specialist": "REPUTATIONINT",
                "expected_information_value": 0.95,
            }]
            self.actions = [{
                "id": "ACT-CONFIGURE-PUBLIC-SOURCES",
                "description": "Configure lawful public/authorized sources only. Do not harass, dox, fake reviews, deploy bots, infiltrate private groups, or manipulate narratives.",
                "priority": 1,
                "privacy_impact": "LOW",
                "expected_gain": 0.95,
                "requires_human_approval": False,
            }]
            self.recommendations = []
            self.handoffs = []
            self.stakeholder_groups = []
            self.representativeness = "UNKNOWN"
            self.hypotheses = []
            self.contradictions = []
            return

        self.stakeholder_groups = [
            "customers",
            "public_reviewers",
            "regulators",
            "media_outlets",
            "social_platform_users",
            "company_spokesperson",
            "fact_checkers",
        ]
        self.representativeness = (
            "PLATFORM_SAMPLE / SELF_SELECTED_SAMPLE. Public social/review content is not scientific population polling."
        )

        self.gaps = [
            {
                "id": "GAP-BREACH-TRUTH",
                "description": "Underlying data-exposure/breach claim is not technically adjudicated.",
                "importance": "HIGH",
                "recommended_source": "BREACHINT / INCIDENTINT technical evidence, regulator filing, court record.",
                "specialist": "BREACHINT",
                "expected_information_value": 0.90,
            },
            {
                "id": "GAP-SOURCE-ORIGIN",
                "description": "Original technical source for 'millions exposed' claim is unresolved.",
                "importance": "HIGH",
                "recommended_source": "Primary document, regulator notice, company incident disclosure.",
                "specialist": "REPUTATIONINT / DOCINT",
                "expected_information_value": 0.85,
            },
            {
                "id": "GAP-COORDINATION",
                "description": "Amplification concentration may indicate coordination candidate but intent is unresolved.",
                "importance": "MEDIUM",
                "recommended_source": "DISINFOINT coordinated-behavior analysis.",
                "specialist": "DISINFOINT",
                "expected_information_value": 0.75,
            },
            {
                "id": "GAP-REVIEW-AUTHENTICITY",
                "description": "Review authenticity and verified-experience status are unclear.",
                "importance": "MEDIUM",
                "recommended_source": "Review-platform verification metadata, complaint deduplication.",
                "specialist": "COMPLAINTINT / REPUTATIONINT",
                "expected_information_value": 0.65,
            },
            {
                "id": "GAP-LEGAL",
                "description": "Serious allegation wording may require legal/defamation review.",
                "importance": "HIGH",
                "recommended_source": "LEGALINT / human counsel review.",
                "specialist": "LEGALINT",
                "expected_information_value": 0.80,
            },
        ]

        self.actions = [
            {
                "id": "ACT-RETRIEVE-ORIGINAL-SOURCE",
                "description": "Retrieve the original primary source for the breach allegation and any regulator/court record.",
                "priority": 1,
                "privacy_impact": "LOW",
                "expected_gain": 0.90,
                "requires_human_approval": False,
            },
            {
                "id": "ACT-COLLAPSE-SYNDICATION",
                "description": "Collapse syndicated articles and reposts into source families before measuring corroboration.",
                "priority": 2,
                "privacy_impact": "LOW",
                "expected_gain": 0.85,
                "requires_human_approval": False,
            },
            {
                "id": "ACT-VERIFY-OFFICIAL-RESPONSE",
                "description": "Compare official statements against primary regulatory/legal evidence without treating denial as refutation.",
                "priority": 3,
                "privacy_impact": "LOW",
                "expected_gain": 0.80,
                "requires_human_approval": False,
            },
            {
                "id": "ACT-HANDOFF-BREACH",
                "description": "Hand underlying breach/data-exposure truth adjudication to BREACHINT / INCIDENTINT.",
                "priority": 4,
                "privacy_impact": "LOW",
                "expected_gain": 0.90,
                "requires_human_approval": False,
            },
            {
                "id": "ACT-HANDOFF-DISINFO",
                "description": "Hand coordination/misinformation intent analysis to DISINFOINT.",
                "priority": 5,
                "privacy_impact": "LOW",
                "expected_gain": 0.75,
                "requires_human_approval": False,
            },
            {
                "id": "ACT-HUMAN-LEGAL-REVIEW",
                "description": "Route serious allegation wording, possible defamation, and public-response strategy to human legal/comms review.",
                "priority": 6,
                "privacy_impact": "PROTECTIVE",
                "expected_gain": 0.85,
                "requires_human_approval": True,
            },
            {
                "id": "ACT-NO-HARM",
                "description": "Do not attack critics, remove reviews deceptively, mass-report posts, create counter-propaganda, impersonate customers, or manipulate public opinion.",
                "priority": 99,
                "privacy_impact": "PROTECTIVE",
                "expected_gain": 0.0,
                "requires_human_approval": False,
            },
        ]

        self.recommendations = [
            {
                "id": "REC-KEEP-ALLEGATION-LANGUAGE",
                "category": "COMMUNICATION",
                "action": "Use source-attributed allegation language: 'reports allege', 'regulator opened investigation', not 'company committed fraud'.",
                "target": "Public briefing",
                "rationale": "Prevents promotion of unverified misconduct and reduces defamation risk.",
                "approval": "HUMAN_REVIEW",
            },
            {
                "id": "REC-PRESERVE-CORRECTIONS",
                "category": "MISINFORMATION",
                "action": "Track correction propagation and avoid deleting historical narrative state.",
                "target": "Narrative memory",
                "rationale": "Original false/inflated claims often travel farther than corrections.",
                "approval": "AUTONOMOUS_ANALYTIC",
            },
            {
                "id": "REC-NO-CRITIC-TARGETING",
                "category": "ETHICS",
                "action": "Do not identify, harass, report, or retaliate against critics based on public negative mentions.",
                "target": "Operators",
                "rationale": "Legitimate criticism must not be silenced through surveillance or manipulation.",
                "approval": "HUMAN_APPROVAL_REQUIRED",
            },
            {
                "id": "REC-SEPARATE-SERVICE-ISSUES",
                "category": "REMEDIATION",
                "action": "Address verified customer-service issues separately from unverified breach allegations.",
                "target": "Customer operations",
                "rationale": "Improves genuine reputation drivers without conceding unverified facts.",
                "approval": "HUMAN_REVIEW",
            },
        ]

        self.handoffs = [
            {"specialist": "BREACHINT", "reason": "Adjudicate underlying data-exposure/breach technical truth."},
            {"specialist": "INCIDENTINT", "reason": "Incident timeline and operational impact if breach confirmed."},
            {"specialist": "FRAUDINT", "reason": "If fraud allegation requires evidentiary adjudication."},
            {"specialist": "DISINFOINT", "reason": "Coordination, intent, amplification network analysis."},
            {"specialist": "LEGALINT", "reason": "Defamation, serious allegation wording, legal review."},
            {"specialist": "CORPINT", "reason": "Corporate entity/subsidiary/brand resolution."},
            {"specialist": "NEWSINT", "reason": "News archive and media-source deep analysis."},
            {"specialist": "SOCMINT", "reason": "Public social-content collection and network context."},
            {"specialist": "COMPLAINTINT", "reason": "Complaint deduplication and resolution tracking."},
        ]

        self.hypotheses = [
            Hypothesis(
                id="H-REAL-BREACH",
                statement="A genuine data-exposure/breach event occurred.",
                kind="SUBSTANTIVE_TRUTH",
                supporting_claim_ids=["C1", "C3"],
                contradicting_claim_ids=["C4", "C5"],
                assumptions=["Public allegation and regulator action reflect underlying incident."],
                falsification_conditions=[
                    "Independent technical evidence shows no unauthorized access/exposure.",
                    "Regulator action relates to policy review, not confirmed breach.",
                    "Original source is satire, parody, or fabricated.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.35,
                limitations=["REPUTATIONINT does not adjudicate breach truth."],
            ),
            Hypothesis(
                id="H-SYNDICATION-INFLATION",
                statement="Mention volume is inflated by syndication and reposts rather than independent corroboration.",
                kind="AMPLIFICATION",
                supporting_claim_ids=["C2"],
                contradicting_claim_ids=[],
                assumptions=["Many mentions derive from one origin report."],
                falsification_conditions=[
                    "Multiple independent primary documents from unrelated origins appear.",
                    "Source-family collapse shows broad independent reporting.",
                ],
                status=HypothesisStatus.PROBABLE,
                confidence=0.75,
                limitations=["High raw mention count is not high corroboration."],
            ),
            Hypothesis(
                id="H-COORDINATED-CAMPAIGN",
                statement="A coordinated campaign is amplifying the allegation.",
                kind="COORDINATION",
                supporting_claim_ids=[],
                contradicting_claim_ids=[],
                assumptions=["Temporal synchronization and account behavior indicate direction."],
                falsification_conditions=[
                    "Spread is explainable by organic news cycle and platform algorithms.",
                    "No evidence of intent, funding, or central direction.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.25,
                limitations=["Do not infer malicious coordination from concentration alone."],
            ),
            Hypothesis(
                id="H-SERVICE-Deterioration",
                statement="Negative review/complaint trend reflects genuine customer-service deterioration.",
                kind="OPERATIONAL",
                supporting_claim_ids=["C6"],
                contradicting_claim_ids=[],
                assumptions=["Reviews are not duplicated or manipulated."],
                falsification_conditions=[
                    "Complaint deduplication reveals one incident copied across platforms.",
                    "Review burst aligns with unrelated controversy or organized campaign.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.55,
                limitations=["Self-selected review samples are not population sentiment."],
            ),
        ]

        self.contradictions = [
            Contradiction(
                id="CON-MILLIONS",
                contradiction_type="CLAIM_INFLATION_VS_FACT_CHECK",
                description="Social amplification alleges 'millions exposed'; fact-check/correction find that scope unsupported.",
                subject_ids=["C4"],
                severity="HIGH",
                status="OPEN",
                recommended_resolution="Preserve original and corrected claims; do not amplify unsupported scope; route truth to BREACHINT.",
            ),
            Contradiction(
                id="CON-DENIAL-VS-INVESTIGATION",
                contradiction_type="OFFICIAL_RESPONSE_VS_REGULATORY_ACTION",
                description="Company disputes record-count claim while regulator has opened investigation into data-handling practices.",
                subject_ids=["C3", "C5"],
                severity="MEDIUM",
                status="OPEN",
                recommended_resolution="Treat as distinct claims: regulatory action exists; company response exists; underlying breach remains unresolved.",
            ),
        ]

    def dual_ai_review(self) -> Dict[str, Any]:
        issues: List[str] = []

        if any(c.claim_type == "SUBSTANTIVE_ALLEGATION" and c.state == ClaimState.UNVERIFIED for c in self.claims.values()):
            issues.append("Core substantive allegation remains unverified.")

        if self.misinformation_candidates:
            issues.append("Claim inflation/misinformation candidate detected; correction propagation matters.")

        if self.coordination_candidates:
            issues.append("Amplification concentration raises coordination candidate, but intent is unresolved.")

        if self.corrections:
            issues.append("Correction exists; original inflated claim may persist wider than correction.")

        if self.official_responses:
            issues.append("Official response is source-dependent and not final truth.")

        if self.contradictions:
            issues.append(f"{len(self.contradictions)} contradiction(s) preserved.")

        if not issues:
            verdict = "AGREE"
        elif len(issues) <= 5:
            verdict = "PARTIAL_AGREEMENT"
        else:
            verdict = "INSUFFICIENT_EVIDENCE"

        return {
            "primary_reputation_analyst": (
                "Public discourse around Company C intensified after a data-exposure allegation. "
                "Raw mention volume is high, but source-family collapse shows heavy dependence on one origin report "
                "and downstream syndication/social reposting. The allegation's circulation is a supported perception fact. "
                "The underlying breach is not adjudicated. A 'millions exposed' scope claim is disputed/inflated. "
                "Regulator action and official denial are distinct public records."
            ),
            "independent_reputation_skeptic_issues": issues,
            "verdict": verdict,
            "adversarial_checks": [
                "Are copied articles counted repeatedly? No; source families collapsed.",
                "Are viral posts mistaken for public consensus? No; representativeness flagged.",
                "Are allegations converted into facts? No; substantive claims remain unverified.",
                "Are reviews treated as verified experience? No; self-selected sample flagged.",
                "Is competitor/PR bias accounted for? Source reliability and bias preserved.",
                "Is entity correctly resolved? Synthetic Company C only; real entity resolution required in production.",
                "Are historical events presented as current? Timeline preserves publication dates.",
                "Is manipulation/harassment suggested? No; prohibited actions blocked.",
            ],
            "note": "AI agreement is analytical agreement, not public corroboration or truth.",
        }

    def analyst_summary(self) -> str:
        if not self.mentions:
            return (
                "REPUTATIONINT UNRESOLVED: No lawful public-source corpus configured. "
                "No mentions, reviews, complaints, narratives, claims, sentiment, campaigns, or misconduct were fabricated. "
                "Provide authorized public/authorized sources or run sample mode."
            )

        top = self.top_source_families[0] if self.top_source_families else {"source_family": "UNKNOWN", "mention_count": 0}
        neg_share = self.reputation_risk.get("reach_concentration", 0)

        return "\n".join([
            f"ENTITY: {', '.join(self.case.organizations) or 'Company C'}",
            f"AS_OF: {self.as_of}",
            f"MONITORING WINDOW: {self.case.time_range or 'synthetic event window'}",
            "OVERALL PUBLIC NARRATIVE: Negative data-exposure allegation amplified across news/social sources; underlying breach unresolved.",
            f"RAW MENTIONS: {self.raw_mention_count}",
            f"INDEPENDENT SOURCE FAMILIES: {self.independent_source_families}",
            f"TOP SOURCE FAMILY: {top['source_family']} with {top['mention_count']} mentions",
            "KEY NEGATIVE NARRATIVES: data exposure, security negligence, inflated 'millions exposed' claim, customer-service frustration.",
            "KEY MIXED/NEUTRAL NARRATIVES: regulator investigation, company denial/clarification, correction of inflated scope.",
            "MATERIAL CLAIMS: C1 breach allegation unverified; C2 allegation circulation supported; C3 regulator action supported; C4 millions-exposed disputed; C5 official response recorded; C6 service frustration partially supported.",
            "FACT STATUS: Perception facts separated from substantive truth. Breach truth outside REPUTATIONINT.",
            "OFFICIAL RESPONSE: Company disputes record count; denial is not refutation.",
            "CORRECTIONS: One correction reduced unsupported 'millions' scope; correction reach lower than original amplification.",
            f"REPUTATION RISK: public_impact={self.reputation_risk.get('public_impact')}, claim_verification={self.reputation_risk.get('claim_verification')}, factual_misconduct_status={self.reputation_risk.get('factual_misconduct_status')}.",
            f"NEGATIVE SHARE: {neg_share}%",
            "NEXT ACTION: Verify original primary evidence, collapse syndication, hand breach truth to BREACHINT, coordination to DISINFOINT, legal wording to LEGALINT. Do not harass critics, fake reviews, bot amplify, or manipulate narrative.",
        ])

    def analyze(self) -> None:
        self.compute_metrics()
        self.fact_gate_claims()
        self.aggregate_sentiment()
        self.detect_candidates()
        self.build_risk_and_opportunities()
        self.build_timeline()
        self.build_outputs()
        self.dual = self.dual_ai_review()
        self.summary = self.analyst_summary()

    def count_content_type(self, ct: ContentType) -> int:
        return sum(m.count for m in self.mentions if m.content_type == ct)

    def result(self, status: Status) -> Dict[str, Any]:
        content_types = sorted({m.content_type.value for m in self.mentions})
        claim_states = {cid: c.state.value for cid, c in self.claims.items()}
        source_reliability = {sid: s.reliability for sid, s in self.sources.items()}
        source_bias = {sid: s.notes for sid, s in self.sources.items()}
        source_pedigree = {sid: self.get_source_family(sid) for sid in self.sources}
        source_independence = {
            "claim_independence": {cid: self.independence_state(c.source_ids) for cid, c in self.claims.items()},
            "syndication_groups": self.syndication_groups,
        }

        engagement_totals: Dict[str, int] = defaultdict(int)
        for m in self.mentions:
            for k, v in m.engagement.items():
                engagement_totals[k] += v

        top_share = 0.0
        if self.raw_mention_count and self.top_source_families:
            top_share = round(sum(x["mention_count"] for x in self.top_source_families) / self.raw_mention_count * 100.0, 1)

        return {
            "case_id": self.case.case_id,
            "task_id": self.case.task_id,
            "objective": self.case.objective,
            "questions": self.case.questions,
            "scope": self.case.scope,
            "authorization": self.case.authorization,
            "status": status.value,
            "as_of": self.as_of,

            "source_ids": sorted(self.sources.keys()),
            "evidence_ids": [m.id for m in self.mentions],

            "entities": self.case.organizations + self.case.brands + self.case.products + self.case.public_roles,
            "brands": self.case.brands,
            "products": self.case.products,
            "services": self.case.services,
            "public_roles": self.case.public_roles,
            "issues": self.case.issues,
            "events": self.case.events,

            "mentions": self.mentions,
            "raw_mention_count": self.raw_mention_count,
            "deduplicated_mentions": self.deduplicated_content_origins,
            "independent_source_families": self.independent_source_families,
            "top_source_families": self.top_source_families,
            "syndication_groups": self.syndication_groups,

            "claims": list(self.claims.values()),
            "claim_states": claim_states,
            "content_types": content_types,

            "narratives": self.narratives,
            "narrative_clusters": self.narratives,
            "narrative_evolution": [
                {
                    "narrative_id": n.id,
                    "topic": n.topic,
                    "first_seen": n.first_seen,
                    "last_seen": n.last_seen,
                    "state": n.state,
                    "limitations": n.limitations,
                }
                for n in self.narratives
            ],

            "sentiment": self.overall_sentiment,
            "aspect_sentiment": self.aspect_sentiment,
            "stance": sorted({m.stance for m in self.mentions}),
            "topics": sorted({n.topic for n in self.narratives}),

            "stakeholder_groups": self.stakeholder_groups,
            "representativeness": self.representativeness,

            "complaints": self.count_content_type(ContentType.COMPLAINT),
            "reviews": self.count_content_type(ContentType.REVIEW),
            "media_coverage": self.count_content_type(ContentType.FACTUAL_REPORT) + self.count_content_type(ContentType.ALLEGATION),
            "social_coverage": self.count_content_type(ContentType.RUMOR) + self.count_content_type(ContentType.COMMENTARY),
            "official_responses": self.official_responses,
            "corrections": self.corrections,
            "fact_checks": self.fact_checks,

            "reach": {
                "state": "ESTIMATED_FROM_SYNTHETIC_MENTION_COUNTS_ONLY",
                "raw_mention_count": self.raw_mention_count,
                "note": "Follower count and engagement are not treated as actual audience or influence.",
            },
            "engagement": dict(engagement_totals),
            "amplification": {
                "top_9_source_family_share_percent": top_share,
                "concentration_note": "High concentration may indicate syndication, platform effects, or coordination candidate; not proof.",
            },

            "source_pedigree": source_pedigree,
            "source_reliability": source_reliability,
            "source_bias": source_bias,
            "source_limitations": {sid: [s.notes] for sid, s in self.sources.items() if s.notes},
            "source_independence": source_independence,

            "coordination_candidates": self.coordination_candidates,
            "misinformation_candidates": self.misinformation_candidates,

            "reputation_events": self.case.events,
            "reputation_dimensions": {
                "trust": "UNDER_MINED_BY_UNVERIFIED_ALLEGATION",
                "security": "NEGATIVE_PERCEPTION",
                "privacy": "NEGATIVE_PERCEPTION",
                "customer_service": "MIXED_NEGATIVE",
                "governance": "MIXED",
                "leadership": "MIXED",
            },
            "reputation_risk": self.reputation_risk,
            "reputation_opportunities": self.reputation_opportunities,

            "baseline": {
                "state": "SYNTHETIC_EVENT_BASELINE",
                "note": "Production requires prior 7/30/90-day mention, sentiment, complaint, and review baselines.",
            },
            "trend": {
                "direction": "NEGATIVE_SPIKE_AFTER_EVENT",
                "level": "ELEVATED",
                "note": "Direction and level stored separately; trend does not prove misconduct.",
            },

            "timeline_updates": self.timeline,
            "observations": self.mentions,

            "candidate_facts": [c for c in self.claims.values() if c.state in {ClaimState.PARTIALLY_SUPPORTED, ClaimState.UNVERIFIED}],
            "supported_facts": [c for c in self.claims.values() if c.state in {ClaimState.SUPPORTED, ClaimState.STRONGLY_SUPPORTED}],
            "partial_facts": [c for c in self.claims.values() if c.state == ClaimState.PARTIALLY_SUPPORTED],
            "disputed_facts": [c for c in self.claims.values() if c.state in {ClaimState.DISPUTED, ClaimState.REFUTED_BY_AVAILABLE_EVIDENCE}],

            "contradictions": self.contradictions,
            "hypotheses": self.hypotheses,
            "falsification_results": [
                {
                    "hypothesis_id": h.id,
                    "statement": h.statement,
                    "status": h.status.value,
                    "confidence": h.confidence,
                    "falsification_conditions": h.falsification_conditions,
                    "limitations": h.limitations,
                }
                for h in self.hypotheses
            ],

            "privacy_flags": self.privacy_flags,
            "legal_flags": self.legal_flags,

            "unknowns": sorted(set(
                [g["description"] for g in self.gaps]
                + [h.statement for h in self.hypotheses if h.status in {HypothesisStatus.UNRESOLVED, HypothesisStatus.DISPUTED}]
            )),
            "knowledge_gaps": self.gaps,
            "recommended_next_actions": self.actions,
            "specialist_handoffs": self.handoffs,
            "limitations": self.limitations,

            "analyst_summary": self.summary,
            "dual_ai_review": self.dual,

            "replay_manifest": {
                "generated_at": now_iso(),
                "pipeline_version": PIPELINE_VERSION,
                "core_principle": (
                    "PUBLIC MENTION -> SOURCE PRESERVATION -> ENTITY RESOLUTION -> CONTENT CLASSIFICATION -> "
                    "CLAIM EXTRACTION -> OPINION/FACT SEPARATION -> SOURCE RELIABILITY -> SOURCE PEDIGREE -> "
                    "SOURCE INDEPENDENCE -> TEMPORAL ANALYSIS -> AMPLIFICATION ANALYSIS -> EXTERNAL VERIFICATION -> "
                    "FACT GATE -> NARRATIVE ASSESSMENT -> REPUTATION ASSESSMENT"
                ),
                "as_of": self.as_of,
                "perception_rule": "Reputation measures perception; it does not determine objective truth.",
                "allegation_rule": "Allegations remain allegations until supported by appropriate independent evidence.",
                "syndication_rule": "Reposts/syndicated copies are distribution events, not independent corroboration.",
                "sentiment_rule": "Sentiment is one signal, not fact, not truth, and not representative without sampling controls.",
                "manipulation_rule": "No fake reviews, bots, astroturf, brigading, mass-reporting, propaganda, or persuasion optimization.",
                "privacy_rule": "Public-source only; no doxxing, harassment, private-group infiltration, or private-person surveillance.",
                "legal_rule": "Serious allegations require precise source-attributed wording and human/legal review.",
                "policy_exclusions": [
                    "No harassment or threats against critics.",
                    "No doxxing or private-contact exposure.",
                    "No fake reviews/endorsements/criticism.",
                    "No bot amplification or astroturfing.",
                    "No brigading or mass-reporting legitimate criticism.",
                    "No infiltration of private groups or stolen accounts.",
                    "No deceptive propaganda or political persuasion.",
                    "No autonomous defamation or unverified public accusation.",
                ],
            },
        }


def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-REPUTATIONINT-001",
        task_id="TASK-REPUTATIONINT-001",
        objective=(
            "Authorized lawful public-source reputation monitoring for synthetic Company C after a data-exposure allegation. "
            "Separate perception from fact, collapse syndication, identify claim inflation, preserve official responses and corrections, "
            "and recommend specialist handoffs without harassment, doxxing, fake reviews, bots, astroturf, or manipulation."
        ),
        questions=[
            "What is being said about Company C?",
            "Which claims are factual public-discourse facts versus substantive allegations?",
            "How many raw mentions collapse into independent source families?",
            "Is the 'millions exposed' claim supported?",
            "What did the company publicly say?",
            "What corrections/retractions/fact-checks exist?",
            "What reputational risk is supported without asserting misconduct?",
            "What specialist handoffs are required?",
        ],
        organizations=["Company C"],
        brands=["Company C"],
        products=["C-Cloud"],
        issues=["data exposure allegation", "customer service frustration"],
        events=["public breach allegation", "regulator investigation notice", "company denial", "media correction"],
        domains=["news.example", "social.example", "reviews.example", "regulator.example"],
        keywords=["Company C", "data exposure", "breach allegation", "customer service"],
        time_range="2026-10-01/2026-10-09",
        as_of=DEFAULT_AS_OF,
        sample=True,
    )


def build_sample_reputationint() -> ReputationInt:
    r = ReputationInt(sample_case())

    # Sources
    r.add_source(Source(
        id="SRC-ORIG",
        title="Initial specialist report alleging Company C customer-data exposure",
        url="https://news.example/company-c-data-exposure",
        source_type="SPECIALIST_MEDIA",
        independence_group="ORIG_ROOT",
        reliability=0.72,
        published_at="2026-10-01T09:00:00Z",
        notes="Origin of allegation; later syndicated and socially amplified.",
    ))
    r.add_source(Source(
        id="SRC-SYND-A",
        title="Syndicated report repeating initial allegation",
        url="https://news.example/synd-a",
        source_type="NEWSWIRE",
        independence_group="ORIG_ROOT",
        reliability=0.60,
        derived_from="SRC-ORIG",
        published_at="2026-10-01T12:00:00Z",
        notes="Syndicated copy; not independent corroboration.",
    ))
    r.add_source(Source(
        id="SRC-SYND-B",
        title="Aggregated article repeating initial allegation",
        url="https://news.example/synd-b",
        source_type="AGGREGATOR",
        independence_group="ORIG_ROOT",
        reliability=0.58,
        derived_from="SRC-ORIG",
        published_at="2026-10-01T14:00:00Z",
        notes="Aggregated copy; not independent corroboration.",
    ))
    r.add_source(Source(
        id="SRC-SOCIAL-1",
        title="High-volume social hub reposting allegation with inflated scope",
        url="https://social.example/hub-1",
        source_type="SOCIAL_PLATFORM",
        independence_group="ORIG_ROOT",
        reliability=0.45,
        derived_from="SRC-SYND-B",
        published_at="2026-10-02T08:00:00Z",
        notes="Social amplification; scope inflation candidate.",
    ))
    r.add_source(Source(
        id="SRC-SOCIAL-2",
        title="Second social hub reposting allegation",
        url="https://social.example/hub-2",
        source_type="SOCIAL_PLATFORM",
        independence_group="ORIG_ROOT",
        reliability=0.43,
        derived_from="SRC-SYND-B",
        published_at="2026-10-02T10:00:00Z",
        notes="Social amplification; not independent verification.",
    ))
    r.add_source(Source(
        id="SRC-SOCIAL-3",
        title="Third social hub reposting allegation",
        url="https://social.example/hub-3",
        source_type="SOCIAL_PLATFORM",
        independence_group="ORIG_ROOT",
        reliability=0.40,
        derived_from="SRC-SOCIAL-1",
        published_at="2026-10-02T12:00:00Z",
        notes="Downstream social repost.",
    ))
    r.add_source(Source(
        id="SRC-REVIEW",
        title="Public review aggregate reporting post-outage support delays",
        url="https://reviews.example/company-c",
        source_type="REVIEW_PLATFORM",
        independence_group="CUSTOMER_REVIEW",
        reliability=0.55,
        published_at="2026-10-03T00:00:00Z",
        notes="Self-selected customer reviews; not verified population sample.",
    ))
    r.add_source(Source(
        id="SRC-REG",
        title="Public regulator notice: investigation opened into data-handling practices",
        url="https://regulator.example/notice-company-c",
        source_type="REGULATORY_PUBLICATION",
        independence_group="REGULATOR",
        reliability=0.88,
        published_at="2026-10-04T00:00:00Z",
        notes="Precise regulatory action; not a finding of breach or fraud.",
    ))
    r.add_source(Source(
        id="SRC-FC",
        title="Independent fact-check on 'millions exposed' claim",
        url="https://factcheck.example/company-c-millions",
        source_type="FACT_CHECKING_ORGANIZATION",
        independence_group="FACTCHECK",
        reliability=0.80,
        published_at="2026-10-05T00:00:00Z",
        notes="Finds 'millions exposed' scope unsupported by public evidence.",
    ))
    r.add_source(Source(
        id="SRC-COMPANY",
        title="Company C official statement disputing record-count claim",
        url="https://company.example/statements/data-exposure",
        source_type="OFFICIAL_STATEMENT",
        independence_group="COMPANY",
        reliability=0.70,
        published_at="2026-10-05T12:00:00Z",
        notes="Company source; denial is not independent refutation.",
    ))
    r.add_source(Source(
        id="SRC-CORR",
        title="Original outlet correction: number exposed not established as millions",
        url="https://news.example/company-c-correction",
        source_type="SPECIALIST_MEDIA",
        independence_group="ORIG_ROOT",
        reliability=0.72,
        derived_from="SRC-ORIG",
        published_at="2026-10-06T09:00:00Z",
        notes="Correction reduces inflated scope.",
    ))
    r.add_source(Source(
        id="SRC-MINOR",
        title="Aggregate of 135 low-volume public sources repeating allegation",
        url="https://social.example/minor-aggregate",
        source_type="MIXED_PUBLIC_SOURCES",
        independence_group="MIXED_MINOR",
        reliability=0.45,
        published_at="2026-10-03T00:00:00Z",
        notes="Aggregate low-volume sources; origin diversity unresolved.",
    ))

    # Mentions / public-source evidence samples
    r.add_mention(Mention(
        id="MEN-ORIG",
        entity="Company C",
        source_id="SRC-ORIG",
        author_or_publisher="Specialist Reporter A",
        published_at="2026-10-01T09:00:00Z",
        content_type=ContentType.ALLEGATION,
        text="Report alleges Company C exposed customer data; source claims unauthorized access to some records.",
        stance="OPPOSED",
        sentiment="NEGATIVE",
        aspects={"privacy": "NEGATIVE", "security": "NEGATIVE"},
        claim_ids=["C1", "C2"],
        count=1,
        family_count=1,
        source_family="FAM-ORIG-REPORT",
        origin_group="ORIG-REPORT",
        engagement={"shares": 120, "comments": 40},
        limitations=["Allegation; no technical adjudication."],
    ))
    r.add_mention(Mention(
        id="MEN-SYND-A",
        entity="Company C",
        source_id="SRC-SYND-A",
        author_or_publisher="Newswire Desk",
        published_at="2026-10-01T12:00:00Z",
        content_type=ContentType.FACTUAL_REPORT,
        text="Syndicated article repeats initial report that Company C may have exposed customer data.",
        stance="NEUTRAL",
        sentiment="NEGATIVE",
        aspects={"privacy": "NEGATIVE", "security": "NEGATIVE"},
        claim_ids=["C1", "C2"],
        count=800,
        family_count=1,
        source_family="FAM-SYND-A",
        origin_group="ORIG-REPORT",
        engagement={"shares": 3000, "comments": 700},
        limitations=["Derived from origin report; not independent corroboration."],
    ))
    r.add_mention(Mention(
        id="MEN-SYND-B",
        entity="Company C",
        source_id="SRC-SYND-B",
        author_or_publisher="Aggregator B",
        published_at="2026-10-01T14:00:00Z",
        content_type=ContentType.FACTUAL_REPORT,
        text="Aggregated coverage repeats data-exposure allegation against Company C.",
        stance="NEUTRAL",
        sentiment="NEGATIVE",
        aspects={"privacy": "NEGATIVE", "security": "NEGATIVE"},
        claim_ids=["C1", "C2"],
        count=3200,
        family_count=1,
        source_family="FAM-SYND-B",
        origin_group="ORIG-REPORT",
        engagement={"shares": 9000, "comments": 1800},
        limitations=["Aggregated copy; source family dependent on origin."],
    ))
    r.add_mention(Mention(
        id="MEN-SOCIAL-1",
        entity="Company C",
        source_id="SRC-SOCIAL-1",
        author_or_publisher="Social Hub 1",
        published_at="2026-10-02T08:00:00Z",
        content_type=ContentType.RUMOR,
        text="Viral posts claim Company C leaked millions of customer records.",
        stance="OPPOSED",
        sentiment="STRONGLY_NEGATIVE",
        aspects={"privacy": "STRONGLY_NEGATIVE", "security": "STRONGLY_NEGATIVE", "trust": "NEGATIVE"},
        claim_ids=["C1", "C2", "C4"],
        count=3000,
        family_count=1,
        source_family="FAM-SOCIAL-1",
        origin_group="SOCIAL-HUB-1",
        engagement={"shares": 22000, "comments": 5400},
        limitations=["Scope inflation candidate; not verified."],
    ))
    r.add_mention(Mention(
        id="MEN-SOCIAL-2",
        entity="Company C",
        source_id="SRC-SOCIAL-2",
        author_or_publisher="Social Hub 2",
        published_at="2026-10-02T10:00:00Z",
        content_type=ContentType.RUMOR,
        text="Posts repeat alleged breach and call for boycott.",
        stance="OPPOSED",
        sentiment="STRONGLY_NEGATIVE",
        aspects={"trust": "NEGATIVE", "security": "NEGATIVE"},
        claim_ids=["C1", "C2"],
        count=2500,
        family_count=1,
        source_family="FAM-SOCIAL-2",
        origin_group="SOCIAL-HUB-2",
        engagement={"shares": 14000, "comments": 3200},
        limitations=["Public opinion/activism; not evidence of misconduct."],
    ))
    r.add_mention(Mention(
        id="MEN-SOCIAL-3",
        entity="Company C",
        source_id="SRC-SOCIAL-3",
        author_or_publisher="Social Hub 3",
        published_at="2026-10-02T12:00:00Z",
        content_type=ContentType.COMMENTARY,
        text="Commentary argues Company C security culture is negligent.",
        stance="OPPOSED",
        sentiment="NEGATIVE",
        aspects={"governance": "NEGATIVE", "security": "NEGATIVE"},
        claim_ids=["C1", "C2"],
        count=1800,
        family_count=1,
        source_family="FAM-SOCIAL-3",
        origin_group="SOCIAL-HUB-3",
        engagement={"shares": 7000, "comments": 2100},
        limitations=["Opinion/commentary; not factual verification."],
    ))
    r.add_mention(Mention(
        id="MEN-REVIEW",
        entity="Company C",
        source_id="SRC-REVIEW",
        author_or_publisher="Public reviewers",
        published_at="2026-10-03T00:00:00Z",
        content_type=ContentType.REVIEW,
        text="Reviews report slow support after outage and billing confusion.",
        stance="MIXED",
        sentiment="NEGATIVE",
        aspects={"customer_service": "NEGATIVE", "reliability": "MIXED", "value": "MIXED"},
        claim_ids=["C6"],
        count=120,
        family_count=1,
        source_family="FAM-REVIEW",
        origin_group="REVIEW-THREAD",
        engagement={"helpful_votes": 340},
        limitations=["Self-selected reviews; authenticity not verified."],
    ))
    r.add_mention(Mention(
        id="MEN-REG",
        entity="Company C",
        source_id="SRC-REG",
        author_or_publisher="Regulator",
        published_at="2026-10-04T00:00:00Z",
        content_type=ContentType.FACTUAL_REPORT,
        text="Regulator notice states an investigation into Company C data-handling practices has been opened.",
        stance="NEUTRAL",
        sentiment="MIXED",
        aspects={"governance": "MIXED", "privacy": "MIXED"},
        claim_ids=["C3"],
        count=1,
        family_count=1,
        source_family="FAM-REG",
        origin_group="REG-NOTICE",
        engagement={"downloads": 900},
        limitations=["Investigation opened is not a finding of violation or breach."],
    ))
    r.add_mention(Mention(
        id="MEN-FC",
        entity="Company C",
        source_id="SRC-FC",
        author_or_publisher="Fact-checker",
        published_at="2026-10-05T00:00:00Z",
        content_type=ContentType.FACT_CHECK,
        text="Fact-check finds no public evidence supporting 'millions exposed' scope.",
        stance="NEUTRAL",
        sentiment="MIXED",
        aspects={"privacy": "MIXED", "trust": "MIXED"},
        claim_ids=["C4"],
        count=1,
        family_count=1,
        source_family="FAM-FACTCHECK",
        origin_group="FACTCHECK",
        engagement={"shares": 450},
        limitations=["Fact-check contributes verification but does not adjudicate underlying breach."],
    ))
    r.add_mention(Mention(
        id="MEN-COMPANY",
        entity="Company C",
        source_id="SRC-COMPANY",
        author_or_publisher="Company C Communications",
        published_at="2026-10-05T12:00:00Z",
        content_type=ContentType.OFFICIAL_STATEMENT,
        text="Company says it is reviewing reports, disputes the 'millions' figure, and states no confirmed exfiltration has been established publicly.",
        stance="NEUTRAL",
        sentiment="MIXED",
        aspects={"leadership": "MIXED", "trust": "MIXED"},
        claim_ids=["C5"],
        count=1,
        family_count=1,
        source_family="FAM-COMPANY",
        origin_group="COMPANY-STMT",
        engagement={"shares": 220},
        limitations=["Official statement is one source; denial is not independent refutation."],
    ))
    r.add_mention(Mention(
        id="MEN-CORR",
        entity="Company C",
        source_id="SRC-CORR",
        author_or_publisher="Specialist Reporter A",
        published_at="2026-10-06T09:00:00Z",
        content_type=ContentType.CORRECTION,
        text="Correction: earlier report should not have stated millions exposed; number exposed remains undetermined in public evidence.",
        stance="NEUTRAL",
        sentiment="MIXED",
        aspects={"privacy": "MIXED", "trust": "MIXED"},
        claim_ids=["C4"],
        count=1,
        family_count=1,
        source_family="FAM-CORRECTION",
        origin_group="CORRECTION",
        engagement={"shares": 80},
        limitations=["Correction reach is lower than original inflated claim."],
    ))
    r.add_mention(Mention(
        id="MEN-MINOR",
        entity="Company C",
        source_id="SRC-MINOR",
        author_or_publisher="Mixed low-volume public sources",
        published_at="2026-10-03T00:00:00Z",
        content_type=ContentType.UNKNOWN,
        text="Aggregate low-volume posts repeat data-exposure allegation; some add unsupported severity.",
        stance="UNCLEAR",
        sentiment="NEGATIVE",
        aspects={"privacy": "NEGATIVE", "security": "NEGATIVE"},
        claim_ids=["C1", "C2", "C4"],
        count=1055,
        family_count=135,
        source_family="FAM-MINOR-AGGREGATE",
        origin_group="MIXED-MINOR-ORIGINS",
        engagement={"shares": 2600},
        limitations=["Aggregate representation of 135 low-volume source families; origin diversity unresolved."],
    ))

    # Claims
    r.add_claim(Claim(
        id="C1",
        subject="Company C",
        predicate="may have experienced",
        object="customer-data exposure/breach",
        claim_type="SUBSTANTIVE_ALLEGATION",
        source_ids=["SRC-ORIG", "SRC-SYND-A", "SRC-SYND-B", "SRC-SOCIAL-1", "SRC-SOCIAL-2", "SRC-SOCIAL-3", "SRC-MINOR"],
        evidence_ids=["MEN-ORIG", "MEN-SYND-A", "MEN-SYND-B", "MEN-SOCIAL-1", "MEN-SOCIAL-2", "MEN-SOCIAL-3", "MEN-MINOR"],
        limitations=["Requires BREACHINT/technical adjudication."],
    ))
    r.add_claim(Claim(
        id="C2",
        subject="Public discourse",
        predicate="contains widespread allegation that",
        object="Company C exposed customer data",
        claim_type="PERCEPTION_FACT",
        source_ids=["SRC-ORIG", "SRC-SYND-A", "SRC-SYND-B", "SRC-SOCIAL-1", "SRC-SOCIAL-2", "SRC-SOCIAL-3", "SRC-MINOR"],
        evidence_ids=["MEN-ORIG", "MEN-SYND-A", "MEN-SYND-B", "MEN-SOCIAL-1", "MEN-SOCIAL-2", "MEN-SOCIAL-3", "MEN-MINOR"],
        limitations=["Describes circulation, not truth."],
    ))
    r.add_claim(Claim(
        id="C3",
        subject="Regulator",
        predicate="opened",
        object="investigation into Company C data-handling practices",
        claim_type="REGULATORY_ACTION",
        source_ids=["SRC-REG"],
        evidence_ids=["MEN-REG"],
        limitations=["Investigation is not a finding of breach, fraud, or violation."],
    ))
    r.add_claim(Claim(
        id="C4",
        subject="Social posts",
        predicate="claim",
        object="millions of Company C records were exposed",
        claim_type="CLAIM_INFLATION",
        source_ids=["SRC-SOCIAL-1", "SRC-SOCIAL-2", "SRC-SOCIAL-3", "SRC-MINOR", "SRC-FC", "SRC-CORR"],
        evidence_ids=["MEN-SOCIAL-1", "MEN-SOCIAL-2", "MEN-SOCIAL-3", "MEN-MINOR", "MEN-FC", "MEN-CORR"],
        limitations=["Unsupported scope; corrected/disputed by fact-check and correction."],
    ))
    r.add_claim(Claim(
        id="C5",
        subject="Company C",
        predicate="publicly disputes",
        object="the 'millions exposed' record-count claim and states no confirmed public exfiltration",
        claim_type="OFFICIAL_STATEMENT",
        source_ids=["SRC-COMPANY"],
        evidence_ids=["MEN-COMPANY"],
        limitations=["Company statement is not independent verification; denial does not refute allegation."],
    ))
    r.add_claim(Claim(
        id="C6",
        subject="Customers",
        predicate="report",
        object="slow support and billing confusion after outage",
        claim_type="CUSTOMER_EXPERIENCE",
        source_ids=["SRC-REVIEW"],
        evidence_ids=["MEN-REVIEW"],
        limitations=["Self-selected reviews; not verified population sample."],
    ))

    # Narratives
    r.add_narrative(Narrative(
        id="NAR-BREACH-ALLEGATION",
        entity="Company C",
        topic="data exposure allegation",
        summary="Allegation that Company C exposed customer data spread from one specialist report into syndication and social amplification.",
        first_seen="2026-10-01T09:00:00Z",
        last_seen="2026-10-06T09:00:00Z",
        source_families=["FAM-ORIG-REPORT", "FAM-SYND-A", "FAM-SYND-B", "FAM-SOCIAL-1", "FAM-SOCIAL-2", "FAM-SOCIAL-3", "FAM-MINOR-AGGREGATE"],
        platforms=["news", "social", "aggregators"],
        supporting_claims=["C2", "C3"],
        contradicting_claims=["C4", "C5"],
        sentiment="NEGATIVE",
        reach="HIGH",
        persistence="HIGH",
        state="CLAIM_INFLATION_CANDIDATE",
        confidence=0.82,
        limitations=["Underlying breach unresolved.", "Raw volume not independent corroboration."],
    ))
    r.add_narrative(Narrative(
        id="NAR-SECURITY-NEGLIGENCE",
        entity="Company C",
        topic="security negligence",
        summary="Framing evolves from service outage to cyberattack to data breach to millions exposed without equivalent evidence at each step.",
        first_seen="2026-10-02T08:00:00Z",
        last_seen="2026-10-05T00:00:00Z",
        source_families=["FAM-SOCIAL-1", "FAM-SOCIAL-3", "FAM-MINOR-AGGREGATE"],
        platforms=["social", "commentary"],
        supporting_claims=["C1"],
        contradicting_claims=["C4", "C5"],
        sentiment="STRONGLY_NEGATIVE",
        reach="HIGH",
        persistence="MEDIUM",
        state="NARRATIVE_MUTATION_OBSERVED",
        confidence=0.70,
        limitations=["Narrative mutation tracked; not proof of coordination."],
    ))
    r.add_narrative(Narrative(
        id="NAR-CUSTOMER-SERVICE",
        entity="Company C",
        topic="customer service frustration",
        summary="Reviews report support delays and billing confusion after outage.",
        first_seen="2026-10-03T00:00:00Z",
        last_seen="2026-10-03T00:00:00Z",
        source_families=["FAM-REVIEW"],
        platforms=["review_platform"],
        supporting_claims=["C6"],
        contradicting_claims=[],
        sentiment="NEGATIVE",
        reach="MEDIUM",
        persistence="MEDIUM",
        state="PARTIALLY_SUPPORTED",
        confidence=0.60,
        limitations=["Self-selected sample; review authenticity unresolved."],
    ))
    r.add_narrative(Narrative(
        id="NAR-REGULATORY-SCRUTINY",
        entity="Company C",
        topic="regulator investigation",
        summary="Regulator opened investigation into data-handling practices.",
        first_seen="2026-10-04T00:00:00Z",
        last_seen="2026-10-04T00:00:00Z",
        source_families=["FAM-REG"],
        platforms=["official_regulator"],
        supporting_claims=["C3"],
        contradicting_claims=[],
        sentiment="MIXED",
        reach="MEDIUM",
        persistence="MEDIUM",
        state="SUPPORTED_PUBLIC_RECORD",
        confidence=0.85,
        limitations=["Investigation is not finding of wrongdoing."],
    ))
    r.add_narrative(Narrative(
        id="NAR-CORRECTION-REMEDIATION",
        entity="Company C",
        topic="correction and official response",
        summary="Original outlet corrected inflated scope; company disputed record count; fact-check found millions claim unsupported.",
        first_seen="2026-10-05T00:00:00Z",
        last_seen="2026-10-06T09:00:00Z",
        source_families=["FAM-FACTCHECK", "FAM-COMPANY", "FAM-CORRECTION"],
        platforms=["fact_check", "official_statement", "news_correction"],
        supporting_claims=["C4", "C5"],
        contradicting_claims=[],
        sentiment="MIXED",
        reach="LOW_TO_MEDIUM",
        persistence="MEDIUM",
        state="CORRECTION_PROPAGATION_GAP",
        confidence=0.78,
        limitations=["Correction reach lower than original inflated claim."],
    ))

    # Official responses, corrections, fact-checks
    r.add_official_response(OfficialResponse(
        id="RESP-COMPANY-1",
        entity="Company C",
        published_at="2026-10-05T12:00:00Z",
        response_type="DENIAL_CLARIFICATION",
        summary="Company disputes 'millions exposed' figure and says no confirmed public exfiltration has been established.",
        source_id="SRC-COMPANY",
        limitations=["Company source; not independent verification.", "Denial is not refutation."],
    ))
    r.add_correction(Correction(
        id="CORR-ORIGINAL-1",
        source_id="SRC-CORR",
        original_claim_id="C4",
        corrected_claim_id="C4",
        published_at="2026-10-06T09:00:00Z",
        summary="Outlet corrected that number exposed was not established as millions.",
        original_reach=9055,
        correction_reach=80,
        limitations=["Correction propagation gap observed."],
    ))
    r.add_fact_check(FactCheck(
        id="FC-MILLIONS-1",
        claim_id="C4",
        source_id="SRC-FC",
        published_at="2026-10-05T00:00:00Z",
        verdict="UNSUPPORTED_SCOPE",
        summary="Fact-check finds no public evidence for 'millions exposed'.",
        limitations=["Does not adjudicate whether some exposure occurred."],
    ))

    r.analyze()
    return r


def run_sample_pipeline() -> Dict[str, Any]:
    r = build_sample_reputationint()
    return r.result(Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    r = ReputationInt(case)
    r.analyze()
    return r.result(Status.BLOCKED_CONFIGURATION)


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "questions": case.questions,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited reputation-intelligence request detected. REPUTATIONINT supports lawful, public-source, "
            "authorized, evidence-first, privacy-aware reputation intelligence only. It does not harass critics, "
            "dox users, expose private contact details, infiltrate private groups, use stolen accounts, impersonate users, "
            "create/buy fake reviews or endorsements, deploy bots, astroturf, brigade, mass-report legitimate criticism, "
            "threaten/blackmail critics, generate propaganda, manipulate political opinion/voters, or autonomously publish accusations."
        ),
        "lawful_alternatives": [
            "Monitor lawful public/authorized sources.",
            "Collapse syndication and reposts into source families.",
            "Separate perception facts from substantive allegations.",
            "Extract claims and classify fact/opinion/allegation/satire/rumor.",
            "Track official responses, corrections, retractions, and fact-checks.",
            "Hand breach/fraud truth to BREACHINT/FRAUDINT.",
            "Hand coordination/intent to DISINFOINT.",
            "Route serious allegation wording and public-response strategy to LEGALINT/human review.",
        ],
        "privacy_flags": [
            "NO_HARASSMENT",
            "NO_DOXXING",
            "NO_FAKE_REVIEWS",
            "NO_BOT_AMPLIFICATION",
            "NO_ASTROTURF",
            "NO_BRIGADING",
            "NO_MASS_REPORTING_LEGITIMATE_CRITICISM",
            "NO_PRIVATE_GROUP_INFILTRATION",
            "NO_STOLEN_ACCOUNTS",
            "NO_PROPAGANDA",
            "NO_POLITICAL_PERSUASION",
        ],
        "legal_flags": [
            "DEFAMATION_REVIEW_REQUIRED",
            "HUMAN_REVIEW_REQUIRED_FOR_SERIOUS_ALLEGATIONS",
        ],
        "limitations": [
            "No reputation analysis performed.",
            "No mentions, reviews, complaints, narratives, claims, sentiment, campaigns, or misconduct fabricated.",
            "No harassment, doxxing, manipulation, fake engagement, or private-source access performed.",
        ],
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join([
        case.objective,
        *case.questions,
        *case.organizations,
        *case.brands,
        *case.products,
        *case.issues,
        *case.events,
        *case.keywords,
        case.authorization or "",
        " ".join(case.scope),
    ])

    violations = policy_guard(text)
    if violations:
        return blocked_policy_result(case, violations)

    if case.sample:
        return run_sample_pipeline()

    return run_unconfigured_pipeline(case)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TRACEATLAS REPUTATIONINT local lawful public-source reputation intelligence pipeline."
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic REPUTATIONINT sample.")
    parser.add_argument("--objective", help="Lawful public-source reputation objective.")
    parser.add_argument("--question", action="append", default=[], help="Analytic question. Repeatable.")
    parser.add_argument("--organization", action="append", default=[], help="Organization name. Repeatable.")
    parser.add_argument("--brand", action="append", default=[], help="Brand name. Repeatable.")
    parser.add_argument("--product", action="append", default=[], help="Product name. Repeatable.")
    parser.add_argument("--service", action="append", default=[], help="Service name. Repeatable.")
    parser.add_argument("--public-role", action="append", default=[], help="Public role name. Repeatable.")
    parser.add_argument("--issue", action="append", default=[], help="Issue/topic. Repeatable.")
    parser.add_argument("--event", action="append", default=[], help="Reputation event. Repeatable.")
    parser.add_argument("--domain", action="append", default=[], help="Domain/source scope hint. Repeatable.")
    parser.add_argument("--keyword", action="append", default=[], help="Keyword. Repeatable.")
    parser.add_argument("--alias", action="append", default=[], help="Entity alias. Repeatable.")
    parser.add_argument("--time-range", help="Time range hint.")
    parser.add_argument("--as-of", default=DEFAULT_AS_OF, help="Analysis as-of timestamp.")

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            questions=args.question,
            organizations=args.organization,
            brands=args.brand,
            products=args.product,
            services=args.service,
            public_roles=args.public_role,
            issues=args.issue,
            events=args.event,
            domains=args.domain,
            keywords=args.keyword,
            aliases=args.alias,
            time_range=args.time_range,
            as_of=args.as_of,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
