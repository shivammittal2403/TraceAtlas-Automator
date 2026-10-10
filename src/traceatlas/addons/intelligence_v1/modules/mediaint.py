#!/usr/bin/env python3
"""
TRACEATLAS MEDIAINT main.py
===========================

Lawful, public-source / authorized, evidence-first media intelligence scaffold.

This module:
- Does NOT fetch live media, scrape sites, bypass paywalls, or access private
  newsroom systems.
- Does NOT invent articles, publishers, authors, quotes, claims, corrections,
  retractions, source families, syndication relationships, events, or multimedia
  provenance.
- Does NOT generate propaganda, influence operations, persuasive campaigns,
  fake news, fake quotes, fake interviews, fake leaks, or forged media.
- Does NOT target, harass, threaten, dox, pressure, or deanonymize journalists
  or confidential sources.
- Does NOT hack media organizations or use stolen credentials.
- Does NOT manipulate search/news rankings or conduct unauthorized takedowns.
- Does NOT declare image/video/audio authentic or synthetic without specialist
  technical validation.
- Does NOT equate publication with truth, headline with body, article count
  with corroboration, syndication with independence, or framing with intent.

It consumes deterministic media records supplied by lawful/public/authorized
sources:
- media items: articles, wire reports, broadcasts, podcasts, press releases,
  interviews, transcripts, public videos/audio, fact-checks
- publishers, outlets, authors, source pedigree metadata
- claims, quotes, citations, primary-source references
- article versions, corrections, retractions
- syndication / duplicate / near-duplicate metadata
- multimedia asset context: image/video/audio captions, credits, reuse markers
- events, entities, topics, narratives, frames, languages, regions
- source reliability / bias / independence metadata

It produces an evidence-linked MEDIAINTResult with:
- publisher/outlet/author resolution status
- media-type preservation
- headline vs body separation
- claim extraction from supplied records only
- quote attribution and context checks from supplied records only
- primary-source tracing from supplied citations only
- source pedigree and source-family grouping
- syndication / duplicate / near-duplicate detection from supplied hashes/text
- independent-information-family counting
- article version, correction, and retraction tracking
- multimedia context without authenticity adjudication
- coverage volume / velocity / language / region metrics
- narrative/frame aggregation from supplied labels only
- contradiction preservation
- competing hypotheses and falsification conditions
- dual-AI style skeptic review
- privacy / journalist-protection / safety flags
- graphical memory scaffold
- analyst summary and report-ready result object
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

VERSION = "0.1.0"

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

MEDIA_TYPES = {
    "NEWS_ARTICLE",
    "WIRE_REPORT",
    "EDITORIAL",
    "OPINION",
    "ANALYSIS",
    "PRESS_RELEASE",
    "GOVERNMENT_RELEASE",
    "CORPORATE_RELEASE",
    "INTERVIEW",
    "PRESS_CONFERENCE",
    "TV_BROADCAST",
    "RADIO_BROADCAST",
    "PODCAST",
    "NEWSLETTER",
    "BLOG",
    "DOCUMENTARY",
    "PUBLIC_VIDEO",
    "PUBLIC_AUDIO",
    "TRANSCRIPT",
    "FACT_CHECK",
    "OTHER",
    "UNKNOWN",
}

CLAIM_TYPES = {
    "FACTUAL_CLAIM",
    "SOURCE_REPORTED_CLAIM",
    "OPINION",
    "PREDICTION",
    "ANALYSIS",
    "ALLEGATION",
    "DENIAL",
    "ADMISSION",
    "ESTIMATE",
    "RUMOR",
    "UNATTRIBUTED_ASSERTION",
    "UNKNOWN",
}

CLAIM_SCOPES = {
    "HEADLINE",
    "BODY",
    "OTHER",
    "UNKNOWN",
}

QUOTE_MODES = {
    "DIRECT_QUOTE",
    "PARAPHRASE",
    "REPORTED_SPEECH",
    "SUMMARY",
    "TRANSLATION",
    "UNKNOWN",
}

CORRECTION_STATES = {
    "ORIGINAL",
    "UPDATED",
    "CORRECTED",
    "RETRACTED",
    "ARCHIVED",
    "UNKNOWN",
}

DUPLICATE_STATES = {
    "EXACT_DUPLICATE",
    "SYNDICATED_COPY",
    "LIGHT_REWRITE",
    "PARTIAL_OVERLAP",
    "COMMON_UPSTREAM_SOURCE",
    "DISTINCT",
    "UNKNOWN",
}

INDEPENDENCE_STATES = {
    "INDEPENDENT",
    "PARTIALLY_DEPENDENT",
    "DEPENDENT",
    "SINGLE_SOURCE",
    "UNKNOWN",
}

CLAIM_STATUS = {
    "SOURCE_REPORTED",
    "UNCORROBORATED",
    "PARTIALLY_SUPPORTED",
    "SUPPORTED",
    "STRONGLY_SUPPORTED",
    "DISPUTED",
    "RETRACTED",
    "UNSUPPORTED",
    "INCONCLUSIVE",
    "OPINION",
    "PREDICTION",
    "ANALYSIS",
    "ALLEGATION",
    "UNKNOWN",
}

CITATION_TYPES = {
    "PRIMARY_SOURCE",
    "SECONDARY_REPORTING",
    "TERTIARY_AGGREGATION",
    "OFFICIAL_RELEASE",
    "WIRE",
    "SOCIAL_EMBED",
    "DATASET",
    "COURT_FILING",
    "REGULATORY_FILING",
    "RESEARCH_REPORT",
    "IMAGE",
    "VIDEO",
    "AUDIO",
    "DOCUMENT",
    "UNKNOWN",
}

ASSET_TYPES = {
    "IMAGE",
    "VIDEO",
    "AUDIO",
    "DOCUMENT",
    "OTHER",
    "UNKNOWN",
}

EXTERNAL_CORROBORATION_TYPES = {
    "OFFICIAL_DOCUMENT_CORROBORATED",
    "INDEPENDENT_MEDIA_CORROBORATED",
    "TECHNICALLY_CORROBORATED",
    "MULTI_SOURCE_DEPENDENT",
    "SINGLE_SOURCE",
    "CONTRADICTED",
    "INCONCLUSIVE",
}

SEVERE_QUALITY_FLAGS = {
    "missing_publication_time",
    "missing_publisher",
    "missing_outlet",
    "source_unknown",
    "paywall_no_archive",
    "article_version_unavailable",
    "correction_status_unknown",
    "retracted",
    "upstream_retraction_affects",
    "headline_body_mismatch",
    "quote_context_missing",
    "translation_uncertain",
    "primary_source_unresolved",
    "source_family_unresolved",
    "source_independence_unknown",
    "multimedia_provenance_unknown",
    "numeric_contradiction",
    "quote_speaker_conflict",
    "multimedia_reuse_candidate",
    "privacy_journalist_source_redacted",
}

PRIVATE_TAGS = {
    "private_journalist_location",
    "journalist_home",
    "personal_contact",
    "private_source_identity",
    "confidential_source_deanonymization",
    "stalking_target",
    "private_person",
}

SENSITIVE_TAGS = {
    "confidential_source",
    "anonymous_source",
    "journalist_safety",
    "whistleblower",
    "protected_source",
    "vulnerable_population",
    "political_persuasion",
    "microtargeting",
}

BLOCK_PHRASES = [
    # unlawful access / newsroom compromise
    "hack newsroom",
    "hack media organization",
    "bypass paywall",
    "paywall bypass",
    "circumvent paywall",
    "stolen newsroom credentials",
    "stolen media credentials",
    "unauthorized access to article",
    "access embargoed reporting unlawfully",
    "private reporting unlawfully",

    # journalist / source harm
    "dox journalist",
    "doxx journalist",
    "harass journalist",
    "target journalist",
    "threaten journalist",
    "pressure journalist",
    "deanonymize confidential source",
    "deanonymise confidential source",
    "identify confidential source",
    "unmask source",
    "find journalist home",
    "journalist home location",
    "private journalist location",

    # fabrication / manipulation
    "create fake news article",
    "fabricate article",
    "fabricate quote",
    "fabricate interview",
    "fabricate press release",
    "fake leak",
    "deceptive leak",
    "forge screenshot",
    "forged screenshot",
    "forge press release",
    "run propaganda",
    "propaganda generation",
    "influence operation",
    "covert influence campaign",
    "inauthentic amplification",
    "coordinate inauthentic amplification",
    "microtarget political persuasion",
    "automate political persuasion",
    "reputational smear",
    "smear campaign",
    "manipulate search ranking",
    "manipulate news ranking",
    "mass-report lawful media",
    "unauthorized takedown",
]

SOURCE_TYPE_RELIABILITY = {
    "OFFICIAL_GOVERNMENT_RELEASE": "HIGH",
    "OFFICIAL_COURT_FILING": "HIGH",
    "OFFICIAL_REGULATORY_FILING": "HIGH",
    "LICENSED_MEDIA_DATABASE": "HIGH",
    "AUTHORIZED_MEDIA_MONITORING": "HIGH",
    "PUBLIC_BROADCASTER_ARCHIVE": "HIGH",
    "NATIONAL_NEWS_AGENCY": "HIGH",
    "WIRE_SERVICE": "HIGH",
    "ESTABLISHED_NEWS_OUTLET": "MODERATE",
    "LOCAL_NEWS_OUTLET": "MODERATE",
    "FACT_CHECKER": "MODERATE",
    "CORPORATE_PRESS_ROOM": "MODERATE",
    "PUBLIC_PODCAST": "MODERATE",
    "PUBLIC_VIDEO_PLATFORM": "LOW",
    "SOCIAL_POST": "LOW",
    "BLOG": "LOW",
    "AGGREGATOR": "LOW",
    "UNKNOWN": "UNKNOWN",
}

FACTUAL_CLAIM_TYPES = {
    "FACTUAL_CLAIM",
    "SOURCE_REPORTED_CLAIM",
    "ALLEGATION",
    "DENIAL",
    "ADMISSION",
    "ESTIMATE",
    "RUMOR",
    "UNATTRIBUTED_ASSERTION",
}

SOFTER_CLAIM_TYPES = {
    "ALLEGATION",
    "DENIAL",
    "ESTIMATE",
    "RUMOR",
    "UNATTRIBUTED_ASSERTION",
    "UNKNOWN",
}

NON_FACT_CLAIM_TYPES = {
    "OPINION",
    "PREDICTION",
    "ANALYSIS",
}


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def to_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        f = float(value)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except Exception:
        return None


def public_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if not str(k).startswith("_")}


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def iso_or_none(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def dt_sort_key(dt: Optional[datetime]) -> float:
    return dt.timestamp() if isinstance(dt, datetime) else 0.0


def add_flag(obj: Dict[str, Any], flag: str) -> None:
    flags = obj.setdefault("_quality_flags", [])
    f = str(flag).strip().lower()
    if f and f not in flags:
        flags.append(f)


def safe_std(values: List[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return None
    try:
        return statistics.stdev(vals)
    except Exception:
        return None


def numeric_summary(values: List[Any]) -> Dict[str, Any]:
    arr: List[float] = []
    for v in values:
        f = to_float(v)
        if f is not None:
            arr.append(f)
    if not arr:
        return {"count": 0, "min": None, "max": None, "median": None, "mean": None, "std": None}
    return {
        "count": len(arr),
        "min": min(arr),
        "max": max(arr),
        "median": statistics.median(arr),
        "mean": statistics.fmean(arr),
        "std": safe_std(arr),
    }


def normalize_choice(value: Any, allowed: Iterable[str], default: str = "UNKNOWN") -> str:
    s = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    return s if s in set(allowed) else default


def normalize_name(value: Any) -> Optional[str]:
    s = unicodedata.normalize("NFKC", str(value or "")).lower().strip()
    s = re.sub(r"\s+", " ", s)
    return s or None


def normalize_language(value: Any) -> Optional[str]:
    s = str(value or "").strip().lower()
    return s or None


def normalize_region(value: Any) -> Optional[str]:
    s = str(value or "").strip().upper().replace(" ", "_")
    return s or None


def short_text(value: Any, limit: int = 180) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if len(s) <= limit:
        return s
    return s[:limit].rstrip() + "..."


def get_tags(obj: Dict[str, Any]) -> Set[str]:
    return {str(x).strip().lower() for x in ensure_list(obj.get("tags") or obj.get("sensitive_tags")) if x}


def get_records(case: Dict[str, Any], *keys: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for k in keys:
        v = case.get(k)
        if isinstance(v, list):
            out.extend([x for x in v if isinstance(x, dict)])
        elif isinstance(v, dict):
            out.append(v)
    return out


def normalize_external_corroboration(value: Any) -> List[str]:
    arr = [str(x).strip().upper() for x in ensure_list(value) if x]
    allowed = set(EXTERNAL_CORROBORATION_TYPES)
    return [x for x in arr if x in allowed] or arr


def sha256_text(text: Any) -> Optional[str]:
    if text is None:
        return None
    s = str(text)
    if not s.strip():
        return None
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def normalize_text(text: Any) -> str:
    if text is None:
        return ""
    s = unicodedata.normalize("NFKC", str(text)).lower()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^\w\s]", "", s)
    return s.strip()


def normalized_hash(text: Any) -> Optional[str]:
    nt = normalize_text(text)
    if not nt:
        return None
    return hashlib.sha256(nt.encode("utf-8")).hexdigest()


def token_shingles(text: Any, n: int = 3) -> Set[str]:
    toks = normalize_text(text).split()
    if not toks:
        return set()
    if len(toks) < n:
        return {" ".join(toks)}
    return {" ".join(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def normalize_url(value: Any) -> Tuple[Optional[str], Optional[str], List[str]]:
    if value is None:
        return None, None, ["url_missing"]
    raw = str(value).strip()
    if not raw:
        return raw or None, None, ["url_missing"]
    try:
        p = urlparse(raw)
    except Exception:
        return raw, None, ["url_unparseable"]

    flags: List[str] = []
    if not p.scheme:
        flags.append("url_scheme_missing")
    if not p.netloc:
        flags.append("url_host_missing")

    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    path = re.sub(r"/+", "/", p.path)
    if path.endswith("/") and path != "/":
        path = path[:-1]

    keep: List[Tuple[str, str]] = []
    tracking_prefixes = ("utm_",)
    tracking_exact = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source", "spm"}

    for k, v in parse_qsl(p.query, keep_blank_values=True):
        lk = k.lower()
        if lk.startswith(tracking_prefixes) or lk in tracking_exact:
            continue
        keep.append((k, v))

    query = urlencode(keep, doseq=True)
    normalized = urlunparse((scheme, netloc, path, "", query, ""))
    return raw, normalized, flags


class DSU:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def semantic_claim_key(claim: Dict[str, Any]) -> str:
    subj = normalize_name(claim.get("_subject")) or ""
    pred = normalize_name(claim.get("_predicate")) or ""
    obj = normalize_name(claim.get("_object")) or ""
    if subj or pred or obj:
        return f"{subj}|{pred}|{obj}"
    return normalize_name(claim.get("_claim_summary")) or str(claim.get("claim_id") or "")


def verification_rank(state: Any) -> int:
    return {
        "STRONGLY_SUPPORTED": 6,
        "SUPPORTED": 5,
        "PARTIALLY_SUPPORTED": 4,
        "SOURCE_REPORTED": 3,
        "UNCORROBORATED": 2,
        "INCONCLUSIVE": 1,
        "DISPUTED": -1,
        "RETRACTED": -2,
        "UNSUPPORTED": -3,
    }.get(str(state or "").upper(), 0)


# -----------------------------------------------------------------------------
# Policy gate
# -----------------------------------------------------------------------------

def policy_block_reasons(case: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []

    scanned_parts: List[str] = []
    for key in ("objective", "questions", "scope", "authorization", "requested_outputs", "tags", "next_action_requests"):
        val = case.get(key)
        if val is not None:
            scanned_parts.append(json.dumps(val, ensure_ascii=False, default=str))

    text = " ".join(scanned_parts).lower()

    for phrase in BLOCK_PHRASES:
        if phrase in text:
            reasons.append(f"Forbidden MEDIAINT action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    requested = case.get("requested_outputs") if isinstance(case.get("requested_outputs"), dict) else {}

    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    if scope.get("public_or_authorized_sources_only") is False:
        reasons.append("scope.public_or_authorized_sources_only must not be false")

    if scope.get("lawful_only") is False:
        reasons.append("scope.lawful_only must not be false")

    prohibited_scope_flags = [
        "propaganda_generation",
        "influence_operation",
        "political_persuasion",
        "journalist_targeting",
        "journalist_harassment",
        "source_deanonymization",
        "paywall_bypass",
        "newsroom_intrusion",
        "fake_article_generation",
        "fake_quote_generation",
        "media_manipulation",
        "ranking_manipulation",
        "unauthorized_takedown",
        "private_person_tracking",
    ]

    for flag in prohibited_scope_flags:
        if scope.get(flag) is True:
            reasons.append(f"scope.{flag} is prohibited")

    prohibited_requested = [
        "propaganda",
        "influence_campaign",
        "deanonymize_source",
        "dox_journalist",
        "bypass_paywall",
        "fake_article",
        "fake_quote",
        "fake_interview",
        "fake_leak",
        "forge_screenshot",
        "manipulate_rankings",
        "unauthorized_takedown",
        "private_journalist_location",
    ]

    for flag in prohibited_requested:
        if requested.get(flag) is True:
            reasons.append(f"requested_outputs.{flag} is prohibited")

    if not auth.get("lawful_basis"):
        reasons.append("authorization.lawful_basis is missing")

    if not auth.get("purpose"):
        reasons.append("authorization.purpose is missing")

    return reasons


def blocked_result(
    case: Dict[str, Any],
    reasons: List[str],
    started: str,
    input_path: Optional[str],
    input_hash: Optional[str],
) -> Dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "status": "POLICY_BLOCKED",
        "policy_block_reasons": reasons,
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "safety_flags": [
            "NO_PROPAGANDA_GENERATION",
            "NO_INFLUENCE_OPERATIONS",
            "NO_POLITICAL_PERSUASION_AUTOMATION",
            "NO_JOURNALIST_TARGETING",
            "NO_JOURNALIST_HARASSMENT",
            "NO_SOURCE_DEANONYMIZATION",
            "NO_NEWSROOM_INTRUSION",
            "NO_PAYWALL_BYPASS",
            "NO_FAKE_ARTICLES",
            "NO_FAKE_QUOTES",
            "NO_FAKE_INTERVIEWS",
            "NO_MEDIA_MANIPULATION",
            "NO_RANKING_MANIPULATION",
            "NO_UNAUTHORIZED_TAKEDOWNS",
        ],
        "privacy_flags": [
            "NO_PRIVATE_JOURNALIST_LOCATION_EXPOSURE",
            "NO_CONFIDENTIAL_SOURCE_IDENTIFICATION",
            "PUBLIC_MEDIA_EVIDENCE_ONLY",
            "MINIMUM_NECESSARY_PERSONAL_DATA",
        ],
        "recommended_next_actions": [
            "Restate objective as lawful media analysis, verification, archival context, or defensive narrative assessment",
            "Use public/authorized/licensed media records only",
            "Preserve headline/body, claim/fact, publication/truth, and source-family distinctions",
            "Handoff image/video/audio technical validation to IMINT/VIDINT/AUDINT",
            "Handoff disinformation hypotheses to DISINFOINT with evidence, not labels",
        ],
        "limitations": [
            "Requested or detected use crosses MEDIAINT lawful/ethical boundary.",
            "No propaganda, influence operations, journalist targeting, source deanonymization, paywall bypass, fabrication, or media manipulation support is provided.",
        ],
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
        },
    }


# -----------------------------------------------------------------------------
# Source / publisher / outlet / author validation
# -----------------------------------------------------------------------------

def source_reliability_label(source: Dict[str, Any]) -> str:
    rel = str(source.get("reliability") or source.get("_reliability") or "").strip().upper()
    if rel in {"HIGH", "MODERATE", "LOW", "UNKNOWN"}:
        return rel
    stype = str(source.get("source_type") or source.get("_source_type") or "UNKNOWN").strip().upper()
    return SOURCE_TYPE_RELIABILITY.get(stype, "UNKNOWN")


def validate_sources(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    sources: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(get_records(case, "sources", "media_sources")):
        sid = str(s.get("source_id") or s.get("id") or f"SRC-{idx + 1}").strip()
        s["source_id"] = sid

        stype = str(s.get("source_type", "UNKNOWN")).strip().upper()
        s["_source_type"] = stype
        s["_reliability"] = source_reliability_label(s)
        s["_publisher_id"] = str(s.get("publisher_id") or "").strip() or None
        s["_outlet_id"] = str(s.get("outlet_id") or "").strip() or None
        s["_upstream_source_id"] = str(s.get("upstream_source_id") or "").strip() or None
        s["_independence_group"] = str(
            s.get("independence_group")
            or s.get("upstream_source_id")
            or s.get("publisher_id")
            or s.get("outlet_id")
            or sid
        ).strip().upper()

        s["_paywalled"] = bool(s.get("paywalled"))
        s["_archive_reference"] = s.get("archive_reference")
        s["_license"] = s.get("license")
        s["_limitations"] = ensure_list(s.get("limitations"))

        if s["_paywalled"] and not s["_archive_reference"]:
            add_flag(s, "paywall_no_archive")
            warnings.append(f"source {sid} is paywalled and no archive reference was supplied")

        sources[sid] = s

    if not sources:
        issues.append("No media sources supplied")

    return sources, issues, warnings


def validate_publishers(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    publishers: Dict[str, Dict[str, Any]] = {}

    for idx, p in enumerate(get_records(case, "publishers", "media_companies")):
        pid = str(p.get("publisher_id") or p.get("media_company_id") or p.get("id") or f"PUB-{idx + 1}").strip()
        p["publisher_id"] = pid
        p["_name"] = p.get("name") or p.get("publisher_name")
        p["_legal_owner"] = p.get("legal_owner") or p.get("owner")
        p["_ownership_context"] = p.get("ownership_context")
        p["_countries"] = [str(x).strip().upper() for x in ensure_list(p.get("countries") or p.get("country")) if x]
        p["_official_domains"] = [str(x).strip().lower() for x in ensure_list(p.get("official_domains")) if x]
        p["_state_owned"] = bool(p.get("state_owned"))
        p["_commercial"] = bool(p.get("commercial"))
        p["_nonprofit"] = bool(p.get("nonprofit"))
        publishers[pid] = p

    return publishers, issues


def validate_outlets(
    case: Dict[str, Any],
    publishers: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    outlets: Dict[str, Dict[str, Any]] = {}

    for idx, o in enumerate(get_records(case, "outlets", "news_outlets")):
        oid = str(o.get("outlet_id") or o.get("id") or f"OUT-{idx + 1}").strip()
        o["outlet_id"] = oid
        o["_name"] = o.get("name") or o.get("outlet_name")
        o["_publisher_id"] = str(o.get("publisher_id") or "").strip() or None
        if o["_publisher_id"] and o["_publisher_id"] not in publishers:
            warnings.append(f"outlet {oid} references unknown publisher_id={o['_publisher_id']}")
        o["_country"] = str(o.get("country") or "").strip().upper() or None
        o["_languages"] = [normalize_language(x) for x in ensure_list(o.get("languages")) if x]
        o["_media_type"] = normalize_choice(o.get("media_type"), MEDIA_TYPES, "UNKNOWN")
        o["_ownership_context"] = o.get("ownership_context")
        o["_official_domains"] = [str(x).strip().lower() for x in ensure_list(o.get("official_domains")) if x]
        o["_valid_from"] = parse_dt(o.get("valid_from"))
        o["_valid_to"] = parse_dt(o.get("valid_to"))
        if o["_valid_from"] and o["_valid_to"] and o["_valid_to"] < o["_valid_from"]:
            add_flag(o, "timing_conflict")
        outlets[oid] = o

    return outlets, issues, warnings


def validate_authors(case: Dict[str, Any], outlets: Dict[str, Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    authors: Dict[str, Dict[str, Any]] = {}

    for idx, a in enumerate(get_records(case, "authors", "reporters", "speakers")):
        aid = str(a.get("author_id") or a.get("speaker_id") or a.get("id") or f"AUTH-{idx + 1}").strip()
        a["author_id"] = aid
        a["_published_name"] = a.get("published_name") or a.get("name")
        a["_outlet_id"] = str(a.get("outlet_id") or "").strip() or None
        if a["_outlet_id"] and a["_outlet_id"] not in outlets:
            warnings.append(f"author {aid} references unknown outlet_id={a['_outlet_id']}")
        a["_role"] = str(a.get("role") or "UNKNOWN").strip().upper()
        a["_public_profile_ref"] = a.get("public_profile_ref") or a.get("profile_url")

        tags = get_tags(a)
        a["_tags"] = tags
        if tags & PRIVATE_TAGS:
            add_flag(a, "privacy_journalist_source_redacted")
            for k in list(a.keys()):
                lk = str(k).lower()
                if any(x in lk for x in ("home", "private", "personal", "contact", "address", "phone", "family")):
                    a[k] = "REDACTED"
            warnings.append(f"author {aid} contained private/personal fields; redacted by privacy boundary")

        authors[aid] = a

    return authors, issues, warnings


# -----------------------------------------------------------------------------
# Media item validation
# -----------------------------------------------------------------------------

def validate_media_items(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    publishers: Dict[str, Dict[str, Any]],
    outlets: Dict[str, Dict[str, Any]],
    authors: Dict[str, Dict[str, Any]],
    settings: Dict[str, Any],
    now: datetime,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    items: List[Dict[str, Any]] = []
    items_by_id: Dict[str, Dict[str, Any]] = {}

    raw_items = get_records(
        case,
        "media_items",
        "articles",
        "wire_reports",
        "broadcasts",
        "podcasts",
        "press_releases",
        "interviews",
        "transcripts",
        "fact_checks",
        "public_videos",
        "public_audio",
    )

    versions_by_item: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for idx, v in enumerate(get_records(case, "article_versions", "media_versions")):
        vid = str(v.get("version_id") or v.get("id") or f"VER-{idx + 1}").strip()
        v["version_id"] = vid
        mid = str(v.get("media_item_id") or v.get("article_id") or "").strip()
        v["_media_item_id"] = mid
        v["_published_at"] = parse_dt(v.get("published_at") or v.get("publication_time"))
        v["_updated_at"] = parse_dt(v.get("updated_at"))
        v["_correction_state"] = normalize_choice(v.get("correction_state"), CORRECTION_STATES, "UNKNOWN")
        v["_title"] = v.get("title")
        v["_content_hash"] = v.get("content_hash")
        v["_normalized_hash"] = v.get("normalized_hash") or normalized_hash(v.get("body_text") or v.get("text") or v.get("content_text"))
        if mid:
            versions_by_item[mid].append(v)

    for idx, m in enumerate(raw_items):
        mid = str(m.get("media_item_id") or m.get("article_id") or m.get("id") or f"MEDIA-{idx + 1}").strip()
        m["media_item_id"] = mid

        m["_media_type"] = normalize_choice(m.get("media_type") or m.get("type"), MEDIA_TYPES, "UNKNOWN")

        m["_publisher_id"] = str(m.get("publisher_id") or "").strip() or None
        m["_outlet_id"] = str(m.get("outlet_id") or "").strip() or None
        m["_author_id"] = str(m.get("author_id") or m.get("reporter_id") or "").strip() or None
        m["_source_id"] = str(m.get("source_id") or "").strip() or None

        if m["_outlet_id"] and not m["_publisher_id"]:
            m["_publisher_id"] = outlets.get(m["_outlet_id"], {}).get("_publisher_id")

        if m["_publisher_id"] and m["_publisher_id"] not in publishers:
            warnings.append(f"media item {mid} references unknown publisher_id={m['_publisher_id']}")
            add_flag(m, "missing_publisher")
        if not m["_publisher_id"]:
            add_flag(m, "missing_publisher")

        if m["_outlet_id"] and m["_outlet_id"] not in outlets:
            warnings.append(f"media item {mid} references unknown outlet_id={m['_outlet_id']}")
            add_flag(m, "missing_outlet")

        if m["_author_id"] and m["_author_id"] not in authors:
            warnings.append(f"media item {mid} references unknown author_id={m['_author_id']}")

        if m["_source_id"] and m["_source_id"] not in sources:
            warnings.append(f"media item {mid} references unknown source_id={m['_source_id']}")
            add_flag(m, "source_unknown")

        pub_raw, pub_norm, pub_flags = normalize_url(m.get("publication_url") or m.get("url"))
        canon_raw, canon_norm, canon_flags = normalize_url(m.get("canonical_url") or pub_norm or pub_raw)
        m["_publication_url_original"] = pub_raw
        m["_publication_url_normalized"] = pub_norm
        m["_canonical_url_original"] = canon_raw
        m["_canonical_url_normalized"] = canon_norm
        for f in pub_flags + canon_flags:
            add_flag(m, f)

        m["_published_at"] = parse_dt(m.get("published_at") or m.get("publication_time") or m.get("first_published_at"))
        m["_updated_at"] = parse_dt(m.get("updated_at") or m.get("modification_time"))
        m["_retrieved_at"] = parse_dt(m.get("retrieved_at"))
        m["_event_time"] = parse_dt(m.get("event_time"))

        if not m["_published_at"]:
            add_flag(m, "missing_publication_time")
            issues.append(f"media item {mid} missing published_at")

        if m["_updated_at"] and m["_published_at"] and m["_updated_at"] < m["_published_at"]:
            add_flag(m, "timing_conflict")

        m["_language"] = normalize_language(m.get("language"))
        m["_region"] = normalize_region(m.get("region") or m.get("country"))

        m["_title"] = m.get("title")
        m["_subtitle"] = m.get("subtitle")
        m["_normalized_title_hash"] = normalized_hash(m["_title"])

        body = m.get("body_text") or m.get("text") or m.get("content_text")
        m["_body_present"] = bool(body)
        m["_normalized_text_hash"] = m.get("normalized_hash") or normalized_hash(body)
        m["_content_hash"] = m.get("content_hash") or sha256_text(body)
        m["_shingles"] = token_shingles(body, int(settings.get("shingle_size", 3))) if body else set()

        m["_archive_reference"] = m.get("archive_reference") or (sources.get(m["_source_id"] or "", {}).get("_archive_reference"))
        m["_content_locator"] = m.get("content_locator")

        if sources.get(m["_source_id"] or "", {}).get("_paywalled") and not m["_archive_reference"]:
            add_flag(m, "paywall_no_archive")

        m["_correction_state"] = normalize_choice(m.get("correction_state") or m.get("status"), CORRECTION_STATES, "UNKNOWN")
        m["_retracted"] = m["_correction_state"] == "RETRACTED" or bool(m.get("retracted"))
        if m["_retracted"]:
            add_flag(m, "retracted")

        m["_corrects_media_item_id"] = str(m.get("corrects_media_item_id") or m.get("correction_of") or "").strip() or None
        m["_syndicated_from"] = str(m.get("syndicated_from") or "").strip() or None
        m["_upstream_media_item_id"] = str(m.get("upstream_media_item_id") or m.get("derived_from") or "").strip() or None
        m["_wire_service_id"] = str(m.get("wire_service_id") or m.get("upstream_wire_source") or "").strip() or None
        m["_source_family_id"] = str(m.get("source_family_id") or "").strip() or None
        m["_primary_source_id"] = str(m.get("primary_source_id") or "").strip() or None

        m["_headline_body_mismatch_supplied"] = bool(m.get("headline_body_mismatch"))
        m["_external_corroboration"] = normalize_external_corroboration(m.get("external_corroboration"))

        m["_event_ids"] = [str(x).strip() for x in ensure_list(m.get("event_ids") or m.get("events")) if x]
        m["_entity_ids"] = [str(x).strip() for x in ensure_list(m.get("entity_ids") or m.get("entities")) if x]
        m["_topic_ids"] = [str(x).strip() for x in ensure_list(m.get("topic_ids") or m.get("topics")) if x]
        m["_narrative_ids"] = [str(x).strip() for x in ensure_list(m.get("narrative_ids") or m.get("narratives")) if x]
        m["_frame_labels"] = [str(x).strip().upper() for x in ensure_list(m.get("frame_labels") or m.get("frames")) if x]

        m["_source_ids"] = [str(x).strip() for x in ensure_list(m.get("source_ids") or m.get("source_id")) if x]
        m["_evidence_ids"] = [str(x).strip() for x in ensure_list(m.get("evidence_ids") or m.get("evidence_id")) if x]

        tags = get_tags(m)
        m["_tags"] = tags
        if tags & PRIVATE_TAGS:
            add_flag(m, "privacy_journalist_source_redacted")
            m["_author_id"] = "REDACTED"
            m["_published_name"] = "REDACTED"

        versions = sorted(
            versions_by_item.get(mid, []),
            key=lambda x: dt_sort_key(x.get("_published_at") or x.get("_updated_at")),
        )
        m["_versions"] = versions

        if m["_updated_at"] and not versions:
            add_flag(m, "article_version_unavailable")

        if m["_correction_state"] == "UNKNOWN" and m["_updated_at"]:
            add_flag(m, "correction_status_unknown")

        items.append(m)
        items_by_id[mid] = m

    if not items:
        issues.append("No media items supplied")

    return items, items_by_id, issues, warnings


# -----------------------------------------------------------------------------
# Claim / quote / citation / asset validation
# -----------------------------------------------------------------------------

def validate_claims(
    case: Dict[str, Any],
    items_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    claims: List[Dict[str, Any]] = []
    raw: List[Dict[str, Any]] = []

    for mid, m in items_by_id.items():
        for c in ensure_list(m.get("claims")):
            if isinstance(c, dict):
                cc = dict(c)
                cc.setdefault("media_item_id", mid)
                raw.append(cc)
        for c in ensure_list(m.get("headline_claims")):
            if isinstance(c, dict):
                cc = dict(c)
                cc.setdefault("media_item_id", mid)
                cc.setdefault("claim_scope", "HEADLINE")
                raw.append(cc)
        for c in ensure_list(m.get("body_claims")):
            if isinstance(c, dict):
                cc = dict(c)
                cc.setdefault("media_item_id", mid)
                cc.setdefault("claim_scope", "BODY")
                raw.append(cc)

    for c in get_records(case, "claims"):
        raw.append(dict(c))

    for idx, c in enumerate(raw):
        cid = str(c.get("claim_id") or c.get("id") or f"CLAIM-{idx + 1}").strip()
        c["claim_id"] = cid

        mid = str(c.get("media_item_id") or c.get("article_id") or "").strip()
        c["_media_item_id"] = mid
        if mid not in items_by_id:
            issues.append(f"claim {cid} references unknown media_item_id={mid}")

        item = items_by_id.get(mid, {})
        c["_claim_scope"] = normalize_choice(c.get("claim_scope") or c.get("scope"), CLAIM_SCOPES, "UNKNOWN")
        c["_claim_type"] = normalize_choice(c.get("claim_type") or c.get("type"), CLAIM_TYPES, "UNKNOWN")
        c["_subject"] = normalize_name(c.get("subject"))
        c["_predicate"] = normalize_name(c.get("predicate"))
        c["_object"] = normalize_name(c.get("object"))
        c["_time_reference"] = str(c.get("time_reference") or c.get("time") or "").strip() or None
        c["_location_reference"] = normalize_region(c.get("location_reference") or c.get("location"))
        c["_claim_summary"] = short_text(
            c.get("claim_text_summary") or c.get("claim_text") or c.get("text") or c.get("summary"),
            240,
        )
        c["_source_attribution"] = c.get("source_attribution") or c.get("attribution")
        c["_basis"] = c.get("basis")
        c["_numeric_value"] = to_float(c.get("numeric_value") or c.get("value"))
        c["_numeric_unit"] = str(c.get("numeric_unit") or c.get("unit") or "").strip() or None
        c["_verification_state"] = normalize_choice(c.get("verification_state") or c.get("status"), CLAIM_STATUS, "UNKNOWN")
        c["_confidence"] = str(c.get("confidence") or "UNKNOWN").upper()
        c["_external_corroboration"] = normalize_external_corroboration(c.get("external_corroboration") or item.get("_external_corroboration"))
        c["_primary_source_ids"] = [
            str(x).strip()
            for x in ensure_list(c.get("primary_source_ids") or c.get("primary_source_id") or (c.get("basis") or {}).get("primary_source_id") if isinstance(c.get("basis"), dict) else c.get("primary_source_id"))
            if x
        ]
        c["_source_ids"] = [str(x).strip() for x in ensure_list(c.get("source_ids") or c.get("source_id")) if x]
        c["_evidence_ids"] = [str(x).strip() for x in ensure_list(c.get("evidence_ids") or c.get("evidence_id")) if x]

        if not c["_claim_summary"] and not (c["_subject"] and c["_predicate"]):
            warnings.append(f"claim {cid} has no usable summary or subject/predicate")

        if item.get("_retracted"):
            add_flag(c, "retracted")

        claims.append(c)

    return claims, issues, warnings


def validate_quotes(
    case: Dict[str, Any],
    items_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    quotes: List[Dict[str, Any]] = []
    raw: List[Dict[str, Any]] = []

    for mid, m in items_by_id.items():
        for q in ensure_list(m.get("quotes")):
            if isinstance(q, dict):
                qq = dict(q)
                qq.setdefault("media_item_id", mid)
                raw.append(qq)

    for q in get_records(case, "quotes"):
        raw.append(dict(q))

    for idx, q in enumerate(raw):
        qid = str(q.get("quote_id") or q.get("id") or f"QUOTE-{idx + 1}").strip()
        q["quote_id"] = qid

        mid = str(q.get("media_item_id") or q.get("article_id") or "").strip()
        q["_media_item_id"] = mid
        if mid not in items_by_id:
            issues.append(f"quote {qid} references unknown media_item_id={mid}")

        item = items_by_id.get(mid, {})
        q["_speaker"] = q.get("speaker") or q.get("speaker_name")
        q["_speaker_role"] = str(q.get("speaker_role") or "UNKNOWN").upper()
        q["_source_attribution"] = q.get("source_attribution") or q.get("attribution")
        q["_mode"] = normalize_choice(q.get("direct_or_indirect") or q.get("quote_mode"), QUOTE_MODES, "UNKNOWN")
        q["_quote_locator"] = q.get("quote_locator") or q.get("locator")
        q["_original_language"] = normalize_language(q.get("original_language"))
        q["_quote_language"] = normalize_language(q.get("quote_language") or item.get("_language"))
        q["_context_window"] = q.get("context_window")
        q["_context_available"] = bool(q.get("context_window") or q.get("context_available"))
        q["_verification_state"] = normalize_choice(q.get("verification_state"), CLAIM_STATUS, "UNKNOWN")
        q["_quote_summary"] = short_text(q.get("quote_text_summary") or q.get("quote_text") or q.get("text"), 200)
        q["_quote_text_hash"] = normalized_hash(q.get("quote_text") or q.get("quote_text_summary") or q.get("text"))
        q["_is_translation"] = bool(q.get("translation")) or q["_mode"] == "TRANSLATION"

        if q["_mode"] == "DIRECT_QUOTE" and not q["_context_available"]:
            add_flag(q, "quote_context_missing")

        if q["_is_translation"] and not q["_original_language"]:
            add_flag(q, "translation_uncertain")

        if item.get("_retracted"):
            add_flag(q, "retracted")

        q["_source_ids"] = [str(x).strip() for x in ensure_list(q.get("source_ids") or q.get("source_id")) if x]
        q["_evidence_ids"] = [str(x).strip() for x in ensure_list(q.get("evidence_ids") or q.get("evidence_id")) if x]

        quotes.append(q)

    return quotes, issues, warnings


def validate_citations(
    case: Dict[str, Any],
    items_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    citations: List[Dict[str, Any]] = []
    raw: List[Dict[str, Any]] = []

    for mid, m in items_by_id.items():
        for cit in ensure_list(m.get("citations")):
            if isinstance(cit, dict):
                cc = dict(cit)
                cc.setdefault("media_item_id", mid)
                raw.append(cc)

    for cit in get_records(case, "citations", "citation_network"):
        raw.append(dict(cit))

    for idx, c in enumerate(raw):
        cid = str(c.get("citation_id") or c.get("id") or f"CIT-{idx + 1}").strip()
        c["citation_id"] = cid

        mid = str(c.get("media_item_id") or c.get("article_id") or "").strip()
        c["_media_item_id"] = mid
        if mid not in items_by_id:
            issues.append(f"citation {cid} references unknown media_item_id={mid}")

        c["_cited_media_item_id"] = str(c.get("cited_media_item_id") or c.get("cited_article_id") or "").strip() or None
        if c["_cited_media_item_id"] and c["_cited_media_item_id"] not in items_by_id:
            warnings.append(f"citation {cid} references unknown cited_media_item_id={c['_cited_media_item_id']}")

        c["_cited_source_id"] = str(c.get("cited_source_id") or c.get("source_id") or "").strip() or None
        c["_cited_document_id"] = str(c.get("cited_document_id") or c.get("document_id") or "").strip() or None

        url_raw, url_norm, url_flags = normalize_url(c.get("cited_url") or c.get("url"))
        c["_cited_url_original"] = url_raw
        c["_cited_url_normalized"] = url_norm
        for f in url_flags:
            add_flag(c, f)

        c["_citation_type"] = normalize_choice(c.get("citation_type") or c.get("type"), CITATION_TYPES, "UNKNOWN")
        c["_locator"] = c.get("locator") or c.get("content_locator")
        c["_is_primary_source"] = bool(c.get("primary_source")) or c["_citation_type"] == "PRIMARY_SOURCE"
        c["_source_ids"] = [str(x).strip() for x in ensure_list(c.get("source_ids") or c.get("source_id")) if x]
        c["_evidence_ids"] = [str(x).strip() for x in ensure_list(c.get("evidence_ids") or c.get("evidence_id")) if x]

        citations.append(c)

    return citations, issues, warnings


def validate_multimedia_assets(
    case: Dict[str, Any],
    items_by_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    assets: List[Dict[str, Any]] = []
    raw: List[Dict[str, Any]] = []

    for mid, m in items_by_id.items():
        for a in ensure_list(m.get("media_assets") or m.get("assets")):
            if isinstance(a, dict):
                aa = dict(a)
                aa.setdefault("media_item_id", mid)
                raw.append(aa)

    for a in get_records(case, "multimedia_assets", "image_context", "video_context", "audio_context"):
        raw.append(dict(a))

    for idx, a in enumerate(raw):
        aid = str(a.get("asset_id") or a.get("id") or f"ASSET-{idx + 1}").strip()
        a["asset_id"] = aid

        mid = str(a.get("media_item_id") or a.get("article_id") or "").strip()
        a["_media_item_id"] = mid
        if mid not in items_by_id:
            issues.append(f"asset {aid} references unknown media_item_id={mid}")

        item = items_by_id.get(mid, {})
        a["_asset_type"] = normalize_choice(a.get("asset_type") or a.get("type"), ASSET_TYPES, "UNKNOWN")
        a["_caption"] = short_text(a.get("caption"), 220)
        a["_credit"] = a.get("credit")
        a["_url_original"], a["_url_normalized"], url_flags = normalize_url(a.get("url") or a.get("asset_url"))
        for f in url_flags:
            add_flag(a, f)
        a["_first_seen"] = parse_dt(a.get("first_seen") or a.get("published_at"))
        a["_original_event_time"] = parse_dt(a.get("original_event_time"))
        a["_reuse_of_asset_id"] = str(a.get("reuse_of_asset_id") or a.get("reuse_of") or "").strip() or None
        a["_stock_file_label"] = str(a.get("stock_file_label") or a.get("image_label") or "").strip().upper() or None
        a["_manipulation_candidate"] = bool(a.get("manipulation_candidate"))
        a["_synthetic_candidate"] = bool(a.get("synthetic_candidate"))
        a["_detector_output"] = a.get("detector_output")

        if not a["_caption"]:
            add_flag(a, "multimedia_provenance_unknown")

        if a["_reuse_of_asset_id"] or a["_original_event_time"]:
            if not a["_stock_file_label"]:
                add_flag(a, "multimedia_reuse_candidate")

        if item.get("_retracted"):
            add_flag(a, "retracted")

        a["_source_ids"] = [str(x).strip() for x in ensure_list(a.get("source_ids") or a.get("source_id")) if x]
        a["_evidence_ids"] = [str(x).strip() for x in ensure_list(a.get("evidence_ids") or a.get("evidence_id")) if x]

        assets.append(a)

    return assets, issues, warnings


# -----------------------------------------------------------------------------
# Relationship / family / duplicate / cluster analysis
# -----------------------------------------------------------------------------

def attach_primary_sources(
    items_by_id: Dict[str, Dict[str, Any]],
    citations: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
) -> None:
    for m in items_by_id.values():
        m["_cited_primary_source_ids"] = set()
        if m.get("_primary_source_id"):
            m["_cited_primary_source_ids"].add(str(m["_primary_source_id"]))

    for c in citations:
        mid = c.get("_media_item_id")
        if mid in items_by_id and c.get("_is_primary_source"):
            pid = c.get("_cited_source_id") or c.get("_cited_document_id") or c.get("_cited_url_normalized") or c.get("_cited_media_item_id")
            if pid:
                items_by_id[mid]["_cited_primary_source_ids"].add(str(pid))

    for cl in claims:
        mid = cl.get("_media_item_id")
        if mid in items_by_id:
            for pid in cl.get("_primary_source_ids") or []:
                items_by_id[mid]["_cited_primary_source_ids"].add(str(pid))

    for m in items_by_id.values():
        m["_primary_source_ids"] = sorted(m.pop("_cited_primary_source_ids", set()))
        if not m["_primary_source_ids"]:
            add_flag(m, "primary_source_unresolved")


def build_lineage_families(
    items: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
) -> Dict[str, List[str]]:
    dsu = DSU()
    for m in items:
        dsu.find(m["media_item_id"])

    by_hash: Dict[str, List[str]] = defaultdict(list)
    by_url: Dict[str, List[str]] = defaultdict(list)
    by_family: Dict[str, List[str]] = defaultdict(list)
    by_wire: Dict[str, List[str]] = defaultdict(list)

    for m in items:
        mid = m["media_item_id"]
        for rel in [m.get("_syndicated_from"), m.get("_upstream_media_item_id")]:
            if rel and rel in items_by_id:
                dsu.union(mid, rel)
        if m.get("_normalized_text_hash"):
            by_hash[m["_normalized_text_hash"]].append(mid)
        if m.get("_canonical_url_normalized"):
            by_url[m["_canonical_url_normalized"]].append(mid)
        if m.get("_source_family_id"):
            by_family[str(m["_source_family_id"])].append(mid)
        if m.get("_wire_service_id"):
            by_wire[str(m["_wire_service_id"])].append(mid)

    for groups in (by_hash, by_url, by_family, by_wire):
        for ids in groups.values():
            for a, b in zip(ids, ids[1:]):
                dsu.union(a, b)

    families: Dict[str, List[str]] = defaultdict(list)
    for m in items:
        root = dsu.find(m["media_item_id"])
        families[root].append(m["media_item_id"])

    out: Dict[str, List[str]] = {}
    for i, (root, ids) in enumerate(sorted(families.items(), key=lambda x: x[0]), 1):
        fid = f"FAM-{i:04d}"
        out[fid] = sorted(ids)
        for mid in ids:
            items_by_id[mid]["_lineage_family_id"] = fid
            items_by_id[mid]["_lineage_family_members"] = sorted(ids)

    return out


def detect_duplicates(
    items: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
    settings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    relationships: List[Dict[str, Any]] = []

    for m in items:
        m["_duplicate_state"] = "UNKNOWN"
        m["_duplicate_similarity"] = None

    by_hash: Dict[str, List[str]] = defaultdict(list)
    for m in items:
        if m.get("_normalized_text_hash"):
            by_hash[m["_normalized_text_hash"]].append(m["media_item_id"])

    for h, ids in by_hash.items():
        if len(ids) > 1:
            for mid in ids:
                items_by_id[mid]["_duplicate_state"] = "EXACT_DUPLICATE"
            relationships.append(
                {
                    "type": "exact_duplicate",
                    "normalized_text_hash": h,
                    "media_item_ids": sorted(ids),
                }
            )

    max_pairs = int(settings.get("max_near_duplicate_pairs", 5000))
    light = float(settings.get("near_duplicate_light_threshold", 0.75))
    partial = float(settings.get("near_duplicate_partial_threshold", 0.45))

    comparable = [m for m in items if m.get("_shingles")]
    pairs = 0
    for i in range(len(comparable)):
        if pairs >= max_pairs:
            break
        a = comparable[i]
        for j in range(i + 1, len(comparable)):
            if pairs >= max_pairs:
                break
            b = comparable[j]
            if a.get("_duplicate_state") == "EXACT_DUPLICATE" or b.get("_duplicate_state") == "EXACT_DUPLICATE":
                continue
            if a.get("_language") and b.get("_language") and a["_language"] != b["_language"]:
                continue
            sim = jaccard(a["_shingles"], b["_shingles"])
            pairs += 1
            if sim >= light:
                state = "LIGHT_REWRITE"
            elif sim >= partial:
                state = "PARTIAL_OVERLAP"
            else:
                state = "DISTINCT"

            if state != "DISTINCT":
                for m in (a, b):
                    if m["_duplicate_state"] in {"UNKNOWN", "DISTINCT"}:
                        m["_duplicate_state"] = state
                    m["_duplicate_similarity"] = max(m.get("_duplicate_similarity") or 0.0, sim)
                relationships.append(
                    {
                        "type": "near_duplicate",
                        "media_item_ids": [a["media_item_id"], b["media_item_id"]],
                        "similarity": sim,
                        "state": state,
                    }
                )
            else:
                for m in (a, b):
                    if m["_duplicate_state"] == "UNKNOWN":
                        m["_duplicate_state"] = "DISTINCT"

    for m in items:
        if m.get("_syndicated_from") or m.get("_upstream_media_item_id") or m.get("_wire_service_id"):
            if m["_duplicate_state"] in {"UNKNOWN", "DISTINCT"}:
                m["_duplicate_state"] = "SYNDICATED_COPY"

    return relationships


def assign_story_clusters(items: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    clusters: Dict[str, List[str]] = defaultdict(list)
    for m in items:
        key = (
            m.get("story_cluster_id")
            or (m.get("_event_ids") or [None])[0]
            or (m.get("_topic_ids") or [None])[0]
            or m.get("_normalized_title_hash")
            or m["media_item_id"]
        )
        key = str(key)
        cid = "CLU-" + (sha256_text(key) or key)[:12]
        m["_story_cluster_id"] = cid
        m["_story_cluster_key"] = key
        clusters[cid].append(m["media_item_id"])
    return {k: sorted(v) for k, v in clusters.items()}


# -----------------------------------------------------------------------------
# Coverage / timeline / headline-body / quote / correction analysis
# -----------------------------------------------------------------------------

def coverage_metrics(
    items: List[Dict[str, Any]],
    families: Dict[str, List[str]],
    publishers: Dict[str, Dict[str, Any]],
    outlets: Dict[str, Dict[str, Any]],
    authors: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    publishers_used = {m.get("_publisher_id") for m in items if m.get("_publisher_id")}
    outlets_used = {m.get("_outlet_id") for m in items if m.get("_outlet_id")}
    authors_used = {m.get("_author_id") for m in items if m.get("_author_id") and m.get("_author_id") != "REDACTED"}
    languages = {m.get("_language") for m in items if m.get("_language")}
    regions = {m.get("_region") for m in items if m.get("_region")}
    media_types = {m.get("_media_type") for m in items if m.get("_media_type")}
    primary_sources = {pid for m in items for pid in (m.get("_primary_source_ids") or []) if pid}

    return {
        "raw_media_items": len(items),
        "unique_publishers": len(publishers_used),
        "unique_outlets": len(outlets_used),
        "unique_authors_or_speakers": len(authors_used),
        "independent_lineage_families": len(families),
        "distinct_primary_source_references": len(primary_sources),
        "languages": sorted(languages),
        "regions": sorted(regions),
        "media_types": sorted(media_types),
        "limitations": [
            "Raw article/item count is not corroboration.",
            "Unique publisher count is not source independence if syndication or shared upstream sources exist.",
            "Primary-source reference count is only as good as supplied citation metadata.",
        ],
    }


def coverage_velocity(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    hourly: Counter = Counter()
    daily: Counter = Counter()
    first_by_family: Dict[str, str] = {}

    for m in sorted(items, key=lambda x: dt_sort_key(x.get("_published_at"))):
        dt = m.get("_published_at")
        if not dt:
            continue
        hourly[dt.strftime("%Y-%m-%dT%H:00Z")] += 1
        daily[dt.date().isoformat()] += 1
        fam = m.get("_lineage_family_id")
        if fam and fam not in first_by_family:
            first_by_family[fam] = iso_or_none(dt) or ""

    return {
        "hourly_counts": dict(hourly),
        "daily_counts": dict(daily),
        "first_publication_by_family": first_by_family,
        "limitation": "Velocity measures propagation speed, not truth or importance.",
    }


def headline_body_analysis(
    items_by_id: Dict[str, Dict[str, Any]],
    claims: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    mismatches: List[Dict[str, Any]] = []
    contradictions: List[Dict[str, Any]] = []

    by_item: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: {"HEADLINE": [], "BODY": [], "OTHER": []})
    for c in claims:
        scope = c.get("_claim_scope") or "UNKNOWN"
        if scope not in by_item[c.get("_media_item_id", "")]:
            scope = "OTHER"
        by_item[c.get("_media_item_id", "")][scope].append(c)

    for mid, buckets in by_item.items():
        item = items_by_id.get(mid, {})
        heads = buckets.get("HEADLINE", [])
        bodies = buckets.get("BODY", [])

        if item.get("_headline_body_mismatch_supplied"):
            mismatches.append({"media_item_id": mid, "source": "supplied_flag"})
            add_flag(item, "headline_body_mismatch")

        for h in heads:
            for b in bodies:
                if semantic_claim_key(h) != semantic_claim_key(b):
                    continue

                reason: Optional[str] = None
                if h.get("_claim_type") in {"FACTUAL_CLAIM"} and b.get("_claim_type") in SOFTER_CLAIM_TYPES:
                    reason = "headline_asserts_fact_while_body_reports_softer_claim"
                elif verification_rank(h.get("_verification_state")) > verification_rank(b.get("_verification_state")) + 1:
                    reason = "headline_verification_state_exceeds_body"

                if reason:
                    mismatches.append(
                        {
                            "media_item_id": mid,
                            "headline_claim_id": h.get("claim_id"),
                            "body_claim_id": b.get("claim_id"),
                            "reason": reason,
                        }
                    )
                    add_flag(h, "headline_body_mismatch")
                    add_flag(b, "headline_body_mismatch")
                    add_flag(item, "headline_body_mismatch")
                    contradictions.append(
                        {
                            "type": "headline_body_mismatch",
                            "media_item_id": mid,
                            "headline_claim_id": h.get("claim_id"),
                            "body_claim_id": b.get("claim_id"),
                            "reason": reason,
                            "note": "Headline may overstate or compress body-supported claim.",
                        }
                    )

    return mismatches, contradictions


def quote_context_analysis(quotes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    contradictions: List[Dict[str, Any]] = []
    by_hash: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for q in quotes:
        if q.get("_quote_text_hash"):
            by_hash[q["_quote_text_hash"]].append(q)

    for h, qs in by_hash.items():
        if len(qs) < 2:
            continue
        speakers = {normalize_name(q.get("_speaker")) for q in qs if q.get("_speaker")}
        if len(speakers) > 1:
            for q in qs:
                add_flag(q, "quote_speaker_conflict")
            contradictions.append(
                {
                    "type": "quote_speaker_conflict",
                    "quote_text_hash": h,
                    "quote_ids": [q.get("quote_id") for q in qs],
                    "speakers": sorted(s for s in speakers if s),
                    "note": "Same quoted text attributed to different speakers in supplied records.",
                }
            )

    return contradictions


def correction_retraction_analysis(
    items: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
    claims: List[Dict[str, Any]],
    quotes: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    corrections: List[Dict[str, Any]] = []
    retractions: List[Dict[str, Any]] = []
    contradictions: List[Dict[str, Any]] = []

    for m in items:
        if m.get("_correction_state") == "CORRECTED":
            corrections.append(
                {
                    "media_item_id": m.get("media_item_id"),
                    "corrects_media_item_id": m.get("_corrects_media_item_id"),
                    "correction_note": m.get("correction_note"),
                    "updated_at": iso_or_none(m.get("_updated_at")),
                }
            )
            target = items_by_id.get(m.get("_corrects_media_item_id") or "")
            if target:
                target.setdefault("_corrected_by", []).append(m.get("media_item_id"))

        if m.get("_retracted"):
            retractions.append(
                {
                    "media_item_id": m.get("media_item_id"),
                    "retraction_notice": m.get("retraction_notice"),
                    "retracted_at": iso_or_none(m.get("_updated_at") or m.get("_published_at")),
                    "reason": m.get("retraction_reason"),
                }
            )
            for other in items:
                if other.get("_lineage_family_id") == m.get("_lineage_family_id") and other is not m:
                    add_flag(other, "upstream_retraction_affects")

    for c in claims:
        item = items_by_id.get(c.get("_media_item_id") or "", {})
        if item.get("_retracted") or "upstream_retraction_affects" in (item.get("_quality_flags") or []):
            add_flag(c, "retracted")
            c["_verification_state"] = "RETRACTED"
        if item.get("_corrected_by"):
            c.setdefault("_upstream_correction_affects", True)

    for q in quotes:
        item = items_by_id.get(q.get("_media_item_id") or "", {})
        if item.get("_retracted") or "upstream_retraction_affects" in (item.get("_quality_flags") or []):
            add_flag(q, "retracted")

    return corrections, retractions, contradictions


def numeric_contradictions(
    claims: List[Dict[str, Any]],
    settings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    contradictions: List[Dict[str, Any]] = []
    tol = float(settings.get("numeric_relative_tolerance", 0.05))
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)

    for c in claims:
        if c.get("_numeric_value") is None:
            continue
        key = (
            c.get("_subject"),
            c.get("_predicate"),
            c.get("_object"),
            c.get("_time_reference"),
            c.get("_location_reference"),
            c.get("_numeric_unit"),
        )
        groups[key].append(c)

    for key, cs in groups.items():
        if len(cs) < 2:
            continue
        vals = [float(x["_numeric_value"]) for x in cs if x.get("_numeric_value") is not None]
        if not vals:
            continue
        lo, hi = min(vals), max(vals)
        scale = max(abs(lo), abs(hi), 1e-9)
        if (hi - lo) / scale > tol:
            for c in cs:
                add_flag(c, "numeric_contradiction")
            contradictions.append(
                {
                    "type": "numeric_claim_conflict",
                    "subject": key[0],
                    "predicate": key[1],
                    "object": key[2],
                    "time_reference": key[3],
                    "location_reference": key[4],
                    "unit": key[5],
                    "claim_ids": [c.get("claim_id") for c in cs],
                    "values": vals,
                    "note": "Numeric claims conflict; preserve versions and definitions rather than averaging.",
                }
            )

    return contradictions


def source_independence_analysis(
    items: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
    clusters: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for cid, ids in clusters.items():
        its = [items_by_id[i] for i in ids if i in items_by_id]
        if not its:
            continue

        families = {m.get("_lineage_family_id") for m in its if m.get("_lineage_family_id")}
        primary = {pid for m in its for pid in (m.get("_primary_source_ids") or []) if pid}
        publishers = {m.get("_publisher_id") for m in its if m.get("_publisher_id")}
        outlets = {m.get("_outlet_id") for m in its if m.get("_outlet_id")}
        languages = {m.get("_language") for m in its if m.get("_language")}

        if len(its) <= 1:
            state = "SINGLE_SOURCE"
        elif len(families) <= 1:
            state = "DEPENDENT"
        elif len(primary) == 1 and primary:
            state = "PARTIALLY_DEPENDENT"
        elif len(families) > 1 and len(publishers) > 1 and len(outlets) > 1:
            state = "INDEPENDENT"
        else:
            state = "UNKNOWN"

        for m in its:
            m["_cluster_independence_state"] = state
            if state == "UNKNOWN":
                add_flag(m, "source_independence_unknown")
            elif state == "DEPENDENT":
                add_flag(m, "source_family_unresolved")

        results.append(
            {
                "story_cluster_id": cid,
                "media_item_count": len(its),
                "lineage_family_count": len(families),
                "primary_source_reference_count": len(primary),
                "publisher_count": len(publishers),
                "outlet_count": len(outlets),
                "language_count": len(languages),
                "independence_state": state,
                "limitations": [
                    "Independence is assessed from supplied pedigree/citation metadata only.",
                    "Same publisher does not automatically mean same reporting team, but may reduce independence confidence.",
                    "Shared primary source means multiple reports may not be independent evidence for the underlying fact.",
                ],
            }
        )

    return results


def claim_corroboration_analysis(
    claims: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
) -> None:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in claims:
        groups[semantic_claim_key(c)].append(c)

    for key, cs in groups.items():
        item_ids = {c.get("_media_item_id") for c in cs if c.get("_media_item_id")}
        its = [items_by_id[i] for i in item_ids if i in items_by_id]
        families = {m.get("_lineage_family_id") for m in its if m.get("_lineage_family_id")}
        primary = {pid for c in cs for pid in (c.get("_primary_source_ids") or []) if pid}
        primary |= {pid for m in its for pid in (m.get("_primary_source_ids") or []) if pid}
        publishers = {m.get("_publisher_id") for m in its if m.get("_publisher_id")}
        retracted = any(m.get("_retracted") or "upstream_retraction_affects" in (m.get("_quality_flags") or []) for m in its)
        contradicted = any("numeric_contradiction" in (c.get("_quality_flags") or []) for c in cs)
        external = {x for c in cs for x in (c.get("_external_corroboration") or []) if x}

        for c in cs:
            c["_corroborating_media_item_ids"] = sorted(item_ids)
            c["_corroborating_lineage_family_count"] = len(families)
            c["_corroborating_primary_source_count"] = len(primary)
            c["_corroborating_publisher_count"] = len(publishers)

            ctype = c.get("_claim_type")
            if ctype in NON_FACT_CLAIM_TYPES:
                c["_corroboration_state"] = ctype
                continue

            if retracted or "retracted" in (c.get("_quality_flags") or []):
                c["_corroboration_state"] = "RETRACTED"
            elif contradicted:
                c["_corroboration_state"] = "DISPUTED"
            elif external & {"OFFICIAL_DOCUMENT_CORROBORATED", "TECHNICALLY_CORROBORATED"}:
                c["_corroboration_state"] = "STRONGLY_SUPPORTED" if len(families) >= 2 and len(primary) >= 2 else "SUPPORTED"
            elif len(families) >= 2 and len(primary) >= 2:
                c["_corroboration_state"] = "SUPPORTED"
            elif len(families) >= 2 and len(primary) == 1:
                c["_corroboration_state"] = "PARTIALLY_SUPPORTED"
            elif len(families) == 1:
                c["_corroboration_state"] = "SOURCE_REPORTED"
            else:
                c["_corroboration_state"] = "UNCORROBORATED"

            if c["_corroboration_state"] in {"SOURCE_REPORTED", "UNCORROBORATED"} and not primary:
                add_flag(c, "primary_source_unresolved")


# -----------------------------------------------------------------------------
# Additional contradictions / facts / hypotheses / dual review
# -----------------------------------------------------------------------------

def detect_additional_contradictions(
    items: List[Dict[str, Any]],
    clusters: Dict[str, List[str]],
    independence_results: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    items_by_id: Dict[str, Dict[str, Any]],
    quote_contradictions: List[Dict[str, Any]],
    numeric_contradiction_list: List[Dict[str, Any]],
    headline_contradictions: List[Dict[str, Any]],
    initial_contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    contradictions = list(initial_contradictions)
    contradictions.extend(quote_contradictions)
    contradictions.extend(numeric_contradiction_list)
    contradictions.extend(headline_contradictions)

    indep_by_cluster = {x.get("story_cluster_id"): x for x in independence_results}

    for cid, ids in clusters.items():
        ind = indep_by_cluster.get(cid, {})
        if len(ids) > 3 and ind.get("independence_state") == "DEPENDENT":
            contradictions.append(
                {
                    "type": "coverage_volume_not_independence",
                    "story_cluster_id": cid,
                    "media_item_count": len(ids),
                    "lineage_family_count": ind.get("lineage_family_count"),
                    "note": "High item count may reflect syndication or common upstream source, not independent corroboration.",
                }
            )

    for a in assets:
        item = items_by_id.get(a.get("_media_item_id") or "", {})
        if a.get("_original_event_time") and item.get("_event_time"):
            if a["_original_event_time"] < item["_event_time"] and not a.get("_stock_file_label"):
                contradictions.append(
                    {
                        "type": "multimedia_reuse_candidate",
                        "asset_id": a.get("asset_id"),
                        "media_item_id": a.get("_media_item_id"),
                        "asset_original_event_time": iso_or_none(a.get("_original_event_time")),
                        "item_event_time": iso_or_none(item.get("_event_time")),
                        "note": "Asset may predate associated event; handoff to IMINT/VIDINT/AUDINT for technical provenance.",
                    }
                )

    return contradictions


def item_source_reliability(
    item: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    publishers: Dict[str, Dict[str, Any]],
) -> str:
    rels: List[str] = []
    for sid in item.get("_source_ids") or []:
        rels.append(source_reliability_label(sources.get(sid, {})))
    pub = publishers.get(item.get("_publisher_id") or "", {})
    if pub.get("state_owned") is True:
        rels.append("MODERATE")
    if pub.get("commercial") is True:
        rels.append("MODERATE")
    if "HIGH" in rels:
        return "HIGH"
    if "MODERATE" in rels:
        return "MODERATE"
    if rels:
        return "LOW"
    return "UNKNOWN"


def build_facts(
    items: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    quotes: List[Dict[str, Any]],
    citations: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    corrections: List[Dict[str, Any]],
    retractions: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    publishers: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "Publication is not truth.",
        "Headline is not article body.",
        "Article claim is not verified fact.",
        "Press release is not independent reporting.",
        "Primary source is not automatically true.",
        "Article count is not corroboration.",
        "Unique outlet count is not source independence.",
        "Syndication is not independent reporting.",
        "Multiple translations are not multiple sources.",
        "Wire copies are not independent confirmations.",
        "Opinion is not news reporting.",
        "Allegation is not finding.",
        "Denial is not disproof.",
        "Public claim of responsibility is not verified responsibility.",
        "Media ownership is not direct editorial control.",
        "State ownership is not automatic falsehood.",
        "Commercial ownership is not automatic bias.",
        "Negative sentiment is not false reporting.",
        "Framing is not manipulation.",
        "Synchronized reporting is not covert coordination.",
        "Coordination signals are not disinformation.",
        "Old image is not current event evidence.",
        "Caption is not verified image content.",
        "Video clip is not complete event.",
        "AI detector output is not deepfake proof.",
        "Correction is not outlet unreliability.",
        "Article deletion is not censorship or falsehood.",
        "Media silence is not event nonexistence.",
        "Media attention is not intelligence importance.",
        "AI agreement is not source corroboration.",
        "No journalist or confidential source is targeted, doxxed, harassed, or deanonymized.",
        "No paywall bypass, newsroom intrusion, fake media, propaganda, or influence operation is supported.",
    ]

    for m in items:
        rel = item_source_reliability(m, sources, publishers)
        severe = bool(set(m.get("_quality_flags") or []) & SEVERE_QUALITY_FLAGS)
        conf = "LOW" if severe else rel
        stmt = (
            f"Publisher {m.get('_publisher_id') or 'UNKNOWN'} / outlet {m.get('_outlet_id') or 'UNKNOWN'} "
            f"published {m.get('_media_type')} '{short_text(m.get('_title'), 120)}' "
            f"at {iso_or_none(m.get('_published_at'))}; canonical URL {m.get('_canonical_url_normalized')}; "
            f"normalized text hash {m.get('_normalized_text_hash')}; correction state {m.get('_correction_state')}."
        )
        fact = {
            "fact_id": f"FCT-MEDIA-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": stmt,
            "media_item_id": m.get("media_item_id"),
            "confidence": conf,
            "quality_flags": m.get("_quality_flags"),
            "limitation": "This is a publication fact, not verification of the article's substantive claims.",
        }
        if conf == "HIGH":
            supported.append(fact)
        elif conf == "MODERATE":
            candidates.append(fact)
        else:
            partial.append(fact)

    for c in claims:
        state = c.get("_corroboration_state") or c.get("_verification_state") or "UNKNOWN"
        stmt = (
            f"Claim {c.get('claim_id')} in media item {c.get('_media_item_id')} is classified {state}: "
            f"{short_text(c.get('_claim_summary'), 180)}"
        )
        fact = {
            "fact_id": f"FCT-CLAIM-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": stmt,
            "claim_id": c.get("claim_id"),
            "media_item_id": c.get("_media_item_id"),
            "confidence": "MODERATE" if state in {"SUPPORTED", "STRONGLY_SUPPORTED"} else "LOW",
            "corroboration_state": state,
            "limitation": "Claim status describes evidence state, not automatic truth.",
        }
        if state in {"STRONGLY_SUPPORTED", "SUPPORTED"}:
            candidates.append(fact)
        elif state in {"DISPUTED", "RETRACTED", "UNSUPPORTED"}:
            disputed.append(fact)
        else:
            partial.append(fact)

    for q in quotes:
        partial.append(
            {
                "fact_id": f"FCT-QUOTE-{len(partial) + 1}",
                "statement": (
                    f"Quote {q.get('quote_id')} attributes text to {q.get('_speaker') or 'UNKNOWN'} "
                    f"in mode {q.get('_mode')} with locator {q.get('_quote_locator')}."
                ),
                "quote_id": q.get("quote_id"),
                "confidence": "LOW",
                "limitation": "Quote attribution requires transcript/recording/context verification.",
            }
        )

    for cit in citations:
        candidates.append(
            {
                "fact_id": f"FCT-CIT-{len(candidates) + 1}",
                "statement": (
                    f"Citation {cit.get('citation_id')} links media item {cit.get('_media_item_id')} "
                    f"to {cit.get('_cited_source_id') or cit.get('_cited_url_normalized') or cit.get('_cited_document_id')} "
                    f"as {cit.get('_citation_type')}."
                ),
                "citation_id": cit.get("citation_id"),
                "confidence": "MODERATE" if cit.get("_is_primary_source") else "LOW",
                "limitation": "Citation metadata does not prove cited source supports the claim without inspection.",
            }
        )

    for a in assets:
        partial.append(
            {
                "fact_id": f"FCT-ASSET-{len(partial) + 1}",
                "statement": (
                    f"Asset {a.get('asset_id')} of type {a.get('_asset_type')} was used in media item "
                    f"{a.get('_media_item_id')} with caption '{short_text(a.get('_caption'), 120)}' and credit {a.get('_credit')}."
                ),
                "asset_id": a.get("asset_id"),
                "confidence": "LOW",
                "limitation": "Media asset context is not technical authentication; handoff IMINT/VIDINT/AUDINT.",
            }
        )

    for corr in corrections:
        candidates.append(
            {
                "fact_id": f"FCT-CORR-{len(candidates) + 1}",
                "statement": f"Correction record: {corr}.",
                "confidence": "MODERATE",
                "limitation": "Correction changes specific claim state; it is not automatic proof of general unreliability.",
            }
        )

    for ret in retractions:
        disputed.append(
            {
                "fact_id": f"FCT-RET-{len(disputed) + 1}",
                "statement": f"Retraction record: {ret}.",
                "confidence": "HIGH" if ret.get("retraction_notice") else "MODERATE",
                "limitation": "Retracted content must not be cited as current fact.",
            }
        )

    for c in contradictions:
        disputed.append(
            {
                "disputed_id": f"DIS-{len(disputed) + 1}",
                "type": c.get("type"),
                "statement": "Material media contradiction present; do not silently resolve.",
                "details": c,
            }
        )

    return supported, candidates, partial, disputed, not_facts


def build_hypotheses(
    items: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    clusters: Dict[str, List[str]],
    independence_results: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    corrections: List[Dict[str, Any]],
    retractions: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []
    claims_by_item: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in claims:
        claims_by_item[c.get("_media_item_id", "")].append(c)

    indep_by_cluster = {x.get("story_cluster_id"): x for x in independence_results}

    for idx, (cid, ids) in enumerate(clusters.items(), 1):
        cluster_claims = [c for mid in ids for c in claims_by_item.get(mid, [])]
        ind = indep_by_cluster.get(cid, {})
        base = {
            "hypothesis_set_id": f"HSET-CLU-{idx}",
            "story_cluster_id": cid,
            "media_item_count": len(ids),
            "independence_state": ind.get("independence_state", "UNKNOWN"),
        }

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-EVENT_AS_REPORTED",
                "statement": "The underlying event or claim may be substantially as reported.",
                "support": [
                    f"{len(cluster_claims)} supplied claims in cluster.",
                    f"Independence state: {ind.get('independence_state', 'UNKNOWN')}.",
                ],
                "opposition": ["Contradictions present." if contradictions else "No contradictions recorded."],
                "unknowns": ["primary evidence", "independent corroboration", "multimedia provenance"],
                "falsification_conditions": [
                    "Primary source contradicts claim.",
                    "Independent local evidence excludes event.",
                    "Correction/retraction invalidates key claim.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-SINGLE_UPSTREAM_PROPAGATION",
                "statement": "Multiple items may derive from one upstream source, wire copy, press release, or social post.",
                "support": [
                    f"Lineage family count: {ind.get('lineage_family_count', 'UNKNOWN')}.",
                    f"Primary source reference count: {ind.get('primary_source_reference_count', 'UNKNOWN')}.",
                ],
                "opposition": ["Multiple independent families and primary sources supplied." if ind.get("independence_state") == "INDEPENDENT" else "Independence not confirmed."],
                "unknowns": ["upstream pedigree", "citation completeness"],
                "falsification_conditions": ["Source pedigree shows truly independent reporting."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-HEADLINE_OVERSTATEMENT",
                "statement": "Headlines may overstate or compress body-supported claims.",
                "support": ["Headline/body mismatch flags present." if any("headline_body_mismatch" in (c.get("_quality_flags") or []) for c in cluster_claims) else "No mismatch flags recorded."],
                "opposition": ["Headline and body claim states align."],
                "unknowns": ["editorial intent", "later title changes"],
                "falsification_conditions": ["Archived headline and body text show equivalent claim strength."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-MULTIMEDIA_REUSE",
                "statement": "Images/video/audio attached to coverage may be old, stock, file, cropped, or from another event.",
                "support": ["Asset reuse flags present." if any("multimedia_reuse_candidate" in (a.get("_quality_flags") or []) for a in assets) else "No reuse flags recorded."],
                "opposition": ["Assets have verified original event provenance."],
                "unknowns": ["technical provenance", "caption accuracy"],
                "falsification_conditions": ["IMINT/VIDINT/AUDINT confirms asset originates from reported event."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-TRANSLATION_DUPLICATE",
                "statement": "Cross-language items may be translations of the same source rather than independent coverage.",
                "support": ["Multiple languages in cluster." if len({m.get('_language') for m in items if m.get('media_item_id') in ids and m.get('_language')}) > 1 else "Single/unknown language."],
                "opposition": ["Independent local reporting in each language."],
                "unknowns": ["translation lineage", "machine translation quality"],
                "falsification_conditions": ["Original-language source and independent local source both exist."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-CORRECTION_PENDING",
                "statement": "Coverage may be evolving; corrections or retractions may not yet be reflected in downstream items.",
                "support": [f"Corrections: {len(corrections)}.", f"Retractions: {len(retractions)}."],
                "opposition": ["No correction/retraction records supplied." if not corrections and not retractions else "Correction/retraction records supplied."],
                "unknowns": ["downstream propagation", "current canonical state"],
                "falsification_conditions": ["All dependent items updated or marked with correction/retraction status."],
            }
        )

    if issues:
        hypotheses.append(
            {
                "hypothesis_set_id": "HSET-GLOBAL",
                "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
                "statement": "Validation issues materially weaken all media interpretations.",
                "support": issues[:10],
                "opposition": ["No independent clean source supplied yet."],
                "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
            }
        )

    return hypotheses


def dual_ai_review(
    items: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    independence_results: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary MEDIAINT Analyst",
        "assessment": (
            "Media items, claims, quotes, citations, and/or source metadata exist."
            if items or claims
            else "No usable media records were supplied."
        ),
        "classification": "Publication facts, claim states, source independence, and narrative framing remain conservative and evidence-bounded.",
    }

    if not items and not claims:
        skeptic = {
            "role": "Independent Media Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No deterministic media records were supplied. Do not infer articles, quotes, claims, or source relationships from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Media Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Media Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions must be preserved; do not silently resolve headline/body, quote, numeric, or source-family conflicts.",
        }
    elif any(x.get("independence_state") == "DEPENDENT" for x in independence_results):
        skeptic = {
            "role": "Independent Media Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Coverage volume may reflect syndication or common upstream sources, not independent corroboration.",
        }
    elif items and any(item_source_reliability_label := "HIGH" for _ in [0]):
        skeptic = {
            "role": "Independent Media Skeptic",
            "verdict": "AGREE_ON_PUBLICATION_CONTEXT_ONLY",
            "reason": "Media records may support publication/claim-context assessment only, not truth, intent, responsibility, or disinformation adjudication.",
        }
    else:
        skeptic = {
            "role": "Independent Media Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Single-source or incomplete metadata supports candidate media context only.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not source corroboration. Humans govern consequential public media conclusions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    sources: Dict[str, Dict[str, Any]],
    publishers: Dict[str, Dict[str, Any]],
    outlets: Dict[str, Dict[str, Any]],
    authors: Dict[str, Dict[str, Any]],
    items: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    quotes: List[Dict[str, Any]],
    citations: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    families: Dict[str, List[str]],
    clusters: Dict[str, List[str]],
    corrections: List[Dict[str, Any]],
    retractions: List[Dict[str, Any]],
    facts: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def add_node(node_id: str, node_type: str, props: Dict[str, Any]) -> None:
        if not node_id:
            return
        if any(n.get("id") == node_id for n in nodes):
            return
        nodes.append({"id": node_id, "type": node_type, "properties": props})

    def add_edge(src: str, dst: str, rel: str, props: Dict[str, Any]) -> None:
        if not src or not dst:
            return
        edges.append({"from": src, "to": dst, "type": rel, "properties": props})

    for sid, s in sources.items():
        add_node(sid, "Source", public_dict(s))

    for pid, p in publishers.items():
        add_node(pid, "Publisher", public_dict(p))

    for oid, o in outlets.items():
        add_node(oid, "MediaOutlet", public_dict(o))
        if o.get("_publisher_id"):
            add_edge(oid, o["_publisher_id"], "PUBLISHED_BY", {"outlet_id": oid})

    for aid, a in authors.items():
        add_node(aid, "Author", public_dict(a))
        if a.get("_outlet_id"):
            add_edge(aid, a["_outlet_id"], "AUTHORED_FOR", {"author_id": aid})

    for m in items:
        mid = m.get("media_item_id")
        add_node(
            mid,
            "MediaItem",
            {
                "media_type": m.get("_media_type"),
                "title": short_text(m.get("_title"), 160),
                "publisher_id": m.get("_publisher_id"),
                "outlet_id": m.get("_outlet_id"),
                "author_id": m.get("_author_id"),
                "published_at": iso_or_none(m.get("_published_at")),
                "updated_at": iso_or_none(m.get("_updated_at")),
                "canonical_url": m.get("_canonical_url_normalized"),
                "language": m.get("_language"),
                "region": m.get("_region"),
                "correction_state": m.get("_correction_state"),
                "lineage_family_id": m.get("_lineage_family_id"),
                "story_cluster_id": m.get("_story_cluster_id"),
                "duplicate_state": m.get("_duplicate_state"),
                "quality_flags": m.get("_quality_flags"),
            },
        )
        if m.get("_publisher_id"):
            add_edge(mid, m["_publisher_id"], "PUBLISHED_BY", {"media_item_id": mid})
        if m.get("_outlet_id"):
            add_edge(mid, m["_outlet_id"], "PUBLISHED_BY", {"media_item_id": mid})
        if m.get("_author_id") and m["_author_id"] != "REDACTED":
            add_edge(mid, m["_author_id"], "AUTHORED_BY", {"media_item_id": mid})
        for sid in m.get("_source_ids") or []:
            add_edge(mid, sid, "SUPPORTED_BY", {"media_item_id": mid})
        if m.get("_lineage_family_id"):
            add_edge(mid, m["_lineage_family_id"], "BELONGS_TO_SOURCE_FAMILY", {"media_item_id": mid})
        if m.get("_story_cluster_id"):
            add_edge(mid, m["_story_cluster_id"], "BELONGS_TO_STORY_CLUSTER", {"media_item_id": mid})
        if m.get("_syndicated_from"):
            add_edge(mid, m["_syndicated_from"], "SYNDICATED_FROM", {"media_item_id": mid})
        if m.get("_upstream_media_item_id"):
            add_edge(mid, m["_upstream_media_item_id"], "DERIVED_FROM", {"media_item_id": mid})
        if m.get("_corrects_media_item_id"):
            add_edge(mid, m["_corrects_media_item_id"], "CORRECTS", {"media_item_id": mid})
        if m.get("_retracted"):
            add_node(f"RETRACT-{mid}", "Retraction", {"media_item_id": mid})
            add_edge(f"RETRACT-{mid}", mid, "RETRACTS", {"media_item_id": mid})

    for fid, ids in families.items():
        add_node(fid, "SourceFamily", {"media_item_ids": ids})
        for mid in ids:
            add_edge(mid, fid, "BELONGS_TO_SOURCE_FAMILY", {"family_id": fid})

    for cid, ids in clusters.items():
        add_node(cid, "StoryCluster", {"media_item_ids": ids})
        for mid in ids:
            add_edge(mid, cid, "BELONGS_TO_STORY_CLUSTER", {"cluster_id": cid})

    for c in claims:
        cid = c.get("claim_id")
        add_node(
            cid,
            "Claim",
            {
                "media_item_id": c.get("_media_item_id"),
                "scope": c.get("_claim_scope"),
                "claim_type": c.get("_claim_type"),
                "summary": c.get("_claim_summary"),
                "corroboration_state": c.get("_corroboration_state"),
                "quality_flags": c.get("_quality_flags"),
            },
        )
        if c.get("_media_item_id"):
            add_edge(cid, c["_media_item_id"], "CLAIMED_BY", {"claim_id": cid})
        for pid in c.get("_primary_source_ids") or []:
            add_edge(cid, pid, "SUPPORTS_CANDIDATE", {"claim_id": cid})

    for q in quotes:
        qid = q.get("quote_id")
        add_node(
            qid,
            "Quote",
            {
                "media_item_id": q.get("_media_item_id"),
                "speaker": q.get("_speaker"),
                "mode": q.get("_mode"),
                "locator": q.get("_quote_locator"),
                "quality_flags": q.get("_quality_flags"),
            },
        )
        if q.get("_media_item_id"):
            add_edge(qid, q["_media_item_id"], "QUOTES", {"quote_id": qid})

    for cit in citations:
        cid = cit.get("citation_id")
        add_node(
            cid,
            "Citation",
            {
                "media_item_id": cit.get("_media_item_id"),
                "cited_source_id": cit.get("_cited_source_id"),
                "cited_url": cit.get("_cited_url_normalized"),
                "citation_type": cit.get("_citation_type"),
                "is_primary_source": cit.get("_is_primary_source"),
            },
        )
        if cit.get("_media_item_id"):
            add_edge(cid, cit["_media_item_id"], "CITES", {"citation_id": cid})
        for target in [cit.get("_cited_source_id"), cit.get("_cited_media_item_id"), cit.get("_cited_document_id")]:
            if target:
                add_edge(cid, target, "CITES", {"citation_id": cid})

    for a in assets:
        aid = a.get("asset_id")
        add_node(
            aid,
            "MultimediaAsset",
            {
                "media_item_id": a.get("_media_item_id"),
                "asset_type": a.get("_asset_type"),
                "caption": a.get("_caption"),
                "credit": a.get("_credit"),
                "url": a.get("_url_normalized"),
                "first_seen": iso_or_none(a.get("_first_seen")),
                "reuse_of_asset_id": a.get("_reuse_of_asset_id"),
                "quality_flags": a.get("_quality_flags"),
            },
        )
        if a.get("_media_item_id"):
            rel = {
                "IMAGE": "USES_IMAGE",
                "VIDEO": "USES_VIDEO",
                "AUDIO": "USES_AUDIO",
                "DOCUMENT": "USES_DOCUMENT",
            }.get(a.get("_asset_type"), "USES_ASSET")
            add_edge(a.get("_media_item_id"), aid, rel, {"asset_id": aid})

    for i, corr in enumerate(corrections, 1):
        cid = f"CORR-{i}"
        add_node(cid, "Correction", corr)
        if corr.get("media_item_id") and corr.get("corrects_media_item_id"):
            add_edge(cid, corr["corrects_media_item_id"], "CORRECTS", {"correction_id": cid})

    for i, ret in enumerate(retractions, 1):
        rid = f"RET-{i}"
        add_node(rid, "Retraction", ret)
        if ret.get("media_item_id"):
            add_edge(rid, ret["media_item_id"], "RETRACTS", {"retraction_id": rid})

    for fac in facts:
        fid = fac.get("fact_id") or fac.get("disputed_id")
        add_node(fid, "Fact" if fac.get("fact_id") else "ContradictionFact", fac)
        for key in ("media_item_id", "claim_id", "quote_id", "citation_id", "asset_id"):
            if fac.get(key):
                add_edge(fid, fac[key], "SUPPORTED_BY", {"fact_id": fid})

    for h in hypotheses:
        add_node(h.get("hypothesis_id"), "Hypothesis", h)

    for i, c in enumerate(contradictions, 1):
        cid = f"CONTRA-{i}"
        add_node(cid, "Contradiction", c)

    for g in gaps:
        gid = g.get("gap_id") or f"GAP-{len(gaps)}"
        add_node(gid, "Gap", g)

    return {"nodes": nodes, "edges": edges, "version": VERSION}


# -----------------------------------------------------------------------------
# Gaps / actions / handoffs / summary
# -----------------------------------------------------------------------------

def build_knowledge_gaps(
    items: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    quotes: List[Dict[str, Any]],
    citations: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    independence_results: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
    sources: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not items:
        gaps.append(
            {
                "gap_id": "GAP-NO-MEDIA-ITEMS",
                "gap": "No media items supplied",
                "importance": "HIGH",
                "recommended_source": "Public/authorized/licensed media archive or RSS/API export",
                "expected_information_value": "Establishes media evidence base",
            }
        )

    if any("primary_source_unresolved" in (c.get("_quality_flags") or []) for c in claims):
        gaps.append(
            {
                "gap_id": "GAP-PRIMARY-SOURCE-UNRESOLVED",
                "gap": "One or more claims lack supplied primary-source citation",
                "importance": "HIGH",
                "recommended_source": "Official document, court filing, press release, direct interview, dataset, or original media",
                "expected_information_value": "Separates reporting from primary evidence",
            }
        )

    if any(x.get("independence_state") == "UNKNOWN" for x in independence_results):
        gaps.append(
            {
                "gap_id": "GAP-SOURCE-INDEPENDENCE-UNKNOWN",
                "gap": "Source independence unresolved for one or more story clusters",
                "importance": "HIGH",
                "recommended_source": "Wire/syndication metadata, upstream article IDs, publisher pedigree, citation network",
                "expected_information_value": "Prevents counting dependent copies as corroboration",
            }
        )

    if any("quote_context_missing" in (q.get("_quality_flags") or []) for q in quotes):
        gaps.append(
            {
                "gap_id": "GAP-QUOTE-CONTEXT-MISSING",
                "gap": "Direct quotes lack supplied context window or locator",
                "importance": "MODERATE",
                "recommended_source": "Full transcript, recording, video timestamp, or article paragraph context",
                "expected_information_value": "Reduces misquotation/out-of-context risk",
            }
        )

    if any("article_version_unavailable" in (m.get("_quality_flags") or []) for m in items):
        gaps.append(
            {
                "gap_id": "GAP-ARTICLE-VERSION-UNAVAILABLE",
                "gap": "Updated articles lack supplied version history",
                "importance": "MODERATE",
                "recommended_source": "Web archive, publisher version API, CMS revision log where authorized",
                "expected_information_value": "Preserves headline/claim evolution",
            }
        )

    if any("translation_uncertain" in (q.get("_quality_flags") or []) for q in quotes):
        gaps.append(
            {
                "gap_id": "GAP-TRANSLATION-UNCERTAIN",
                "gap": "Translated quotes lack original-language reference",
                "importance": "MODERATE",
                "recommended_source": "Original-language article/transcript/audio",
                "expected_information_value": "Prevents translation drift being treated as independent source",
            }
        )

    if any("multimedia_provenance_unknown" in (a.get("_quality_flags") or []) for a in assets):
        gaps.append(
            {
                "gap_id": "GAP-MULTIMEDIA-PROVENANCE-UNKNOWN",
                "gap": "Image/video/audio assets lack caption/credit/first-seen provenance",
                "importance": "HIGH",
                "recommended_source": "IMINT/VIDINT/AUDINT technical provenance, original publisher asset metadata",
                "expected_information_value": "Prevents old/stock/miscaptioned media being treated as event evidence",
            }
        )

    if any("paywall_no_archive" in (m.get("_quality_flags") or []) for m in items):
        gaps.append(
            {
                "gap_id": "GAP-PAYWALL-ACCESS-BOUNDARY",
                "gap": "Paywalled item lacks lawful archive/reference",
                "importance": "MODERATE",
                "recommended_source": "Licensed database, public summary, author interview, or lawful archive",
                "expected_information_value": "Avoids access-control bypass while preserving uncertainty",
            }
        )

    if contradictions:
        gaps.append(
            {
                "gap_id": "GAP-CONTRADICTIONS",
                "gap": "Material media contradictions present",
                "importance": "HIGH",
                "recommended_source": "Raw article versions, primary sources, transcripts, archives, source pedigree",
                "expected_information_value": "Prevents silent false resolution",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Input validation issues present",
                "importance": "HIGH",
                "recommended_source": "Corrected publisher/outlet/time/hash/citation metadata",
                "expected_information_value": "Improves media evidence trust",
            }
        )

    if any(get_tags(m) & {"confidential_source", "anonymous_source", "protected_source"} for m in items):
        gaps.append(
            {
                "gap_id": "GAP-CONFIDENTIAL-SOURCE-BOUNDARY",
                "gap": "Anonymous/confidential source material present",
                "importance": "PRIVACY_BOUNDARY",
                "recommended_source": "No deanonymization source recommended; analyze publication wording only",
                "expected_information_value": "Protects journalists and sources",
            }
        )

    return gaps


def build_next_actions(
    items: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    quotes: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not items:
        actions.append("Supply deterministic public/authorized/licensed media records with publisher, time, URL/canonical URL, hashes, and source pedigree")

    if any(g["gap_id"] == "GAP-PRIMARY-SOURCE-UNRESOLVED" for g in gaps):
        actions.append("Retrieve or cite the original primary source before treating media claim as fact")

    if any(g["gap_id"] == "GAP-SOURCE-INDEPENDENCE-UNKNOWN" for g in gaps):
        actions.append("Trace wire/syndication/upstream relationships and count information families, not URLs")

    if any(g["gap_id"] == "GAP-QUOTE-CONTEXT-MISSING" for g in gaps):
        actions.append("Obtain transcript/recording/full paragraph context before assessing quotation accuracy")

    if any(g["gap_id"] == "GAP-ARTICLE-VERSION-UNAVAILABLE" for g in gaps):
        actions.append("Check lawful archive/version history for headline, body, correction, and retraction evolution")

    if any(g["gap_id"] == "GAP-MULTIMEDIA-PROVENANCE-UNKNOWN" for g in gaps):
        actions.append("Handoff image/video/audio technical provenance to IMINT/VIDINT/AUDINT; do not adjudicate authenticity from media context alone")

    if any(g["gap_id"] == "GAP-PAYWALL-ACCESS-BOUNDARY" for g in gaps):
        actions.append("Use licensed/archive/public summary routes only; do not bypass paywalls or access controls")

    if contradictions:
        actions.append("Preserve contradictions and compare raw versions, primary sources, and source pedigree before resolution")

    if any(get_tags(m) & {"confidential_source", "anonymous_source", "protected_source"} for m in items):
        actions.append("Maintain confidential-source boundary; analyze only what publication reveals and do not attempt deanonymization")

    actions.append("Maintain safety boundary: no propaganda, influence operations, journalist targeting, harassment, fake media, or media manipulation")

    return actions


def build_specialist_handoffs(
    items: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if any(a.get("_asset_type") == "IMAGE" for a in assets):
        handoffs.append(
            {
                "to": "IMINT",
                "reason": "Image provenance, manipulation, geolocation clues, and reuse require technical imagery analysis",
                "restrictions": ["MEDIAINT does not declare image real/fake from context alone"],
            }
        )

    if any(a.get("_asset_type") == "VIDEO" for a in assets):
        handoffs.append(
            {
                "to": "VIDINT",
                "reason": "Video frames, cuts, metadata, sequence, and provenance require technical video analysis",
                "restrictions": ["Clip context is not complete event proof"],
            }
        )

    if any(a.get("_asset_type") == "AUDIO" for a in assets):
        handoffs.append(
            {
                "to": "AUDINT",
                "reason": "ASR, speaker segmentation, edit indicators, and audio events require technical audio analysis",
                "restrictions": ["Transcript context is not speaker/authentication proof"],
            }
        )

    if any(a.get("_asset_type") == "DOCUMENT" for a in assets) or any("document" in str(c.get("_citation_type", "")).lower() for c in claims):
        handoffs.append(
            {
                "to": "DOCINT / METADATAINT",
                "reason": "Document parsing, file provenance, and metadata require document intelligence",
                "restrictions": ["Do not execute untrusted documents"],
            }
        )

    if contradictions or any("coordination" in str(m.get("_tag", "")).lower() for m in items):
        handoffs.append(
            {
                "to": "DISINFOINT",
                "reason": "Information-manipulation hypotheses require dedicated disinformation analysis and evidence",
                "restrictions": ["MEDIAINT does not label disinformation without evidence of falsity/manipulation"],
            }
        )

    if any(c.get("_claim_type") in {"ALLEGATION", "ADMISSION", "DENIAL"} for c in claims):
        handoffs.append(
            {
                "to": "LEGALINT / HUMINT / investigative specialist as appropriate",
                "reason": "Allegations, admissions, denials, and legal status exceed media publication context",
                "restrictions": ["Allegation is not finding", "Denial is not disproof"],
            }
        )

    if any("cyber" in str(c.get("_claim_summary", "")).lower() or "hack" in str(c.get("_claim_summary", "")).lower() for c in claims):
        handoffs.append(
            {
                "to": "CTI / CYBINT",
                "reason": "Cyber incident attribution and technical claims require cyber intelligence",
                "restrictions": ["Media attribution is not verified actor attribution"],
            }
        )

    if any("financial" in str(c.get("_claim_summary", "")).lower() or "revenue" in str(c.get("_claim_summary", "")).lower() for c in claims):
        handoffs.append(
            {
                "to": "FININT / CORPINT",
                "reason": "Financial and corporate claims require financial/corporate intelligence validation",
                "restrictions": ["Press release is not independent financial verification"],
            }
        )

    return handoffs


def analyst_summary(r: Dict[str, Any]) -> str:
    def fmt_list(lst: Any) -> str:
        if not lst:
            return "NONE"
        if isinstance(lst, list):
            return ", ".join(str(x) for x in lst)
        return str(lst)

    items = r.get("media_items") or []
    claims = r.get("claims") or []
    quotes = r.get("quotes") or []
    citations = r.get("citations") or []
    assets = r.get("multimedia_assets") or []
    coverage = r.get("coverage_volume") or {}
    velocity = r.get("coverage_velocity") or {}
    indep = r.get("source_independence_analysis") or []
    contradictions = r.get("contradictions") or []
    corrections = r.get("corrections") or []
    retractions = r.get("retractions") or []

    lines = [
        "MEDIA EVENT / TOPIC: " + fmt_list(r.get("topics") or r.get("events")),
        "KEY OUTLETS: " + fmt_list(sorted({m.get("outlet_id") for m in items if m.get("outlet_id")})[:20]),
        "PRIMARY SOURCES: " + fmt_list(sorted({pid for m in items for pid in (m.get("primary_source_ids") or [])})[:20]),
        "SOURCE FAMILIES: " + str(coverage.get("independent_lineage_families", 0)),
        "ARTICLE COUNT: " + str(coverage.get("raw_media_items", 0)),
        "INDEPENDENT SOURCE COUNT: families=" + str(coverage.get("independent_lineage_families", 0)) + " primary_refs=" + str(coverage.get("distinct_primary_source_references", 0)),
        "FIRST REPORT: " + fmt_list(list((velocity.get("first_publication_by_family") or {}).items())[:10]),
        "KEY CLAIMS: " + fmt_list([f"{c.get('claim_id')}:{c.get('corroboration_state')}" for c in claims[:10]]),
        "HEADLINE VS BODY DIFFERENCES: " + fmt_list([m.get("media_item_id") for m in (r.get("headline_body_mismatches") or [])][:10]),
        "QUOTES / ATTRIBUTION: quotes=" + str(len(quotes)) + " conflicts=" + str(sum(1 for c in contradictions if c.get("type") == "quote_speaker_conflict")),
        "CORRECTIONS: " + str(len(corrections)),
        "RETRACTIONS: " + str(len(retractions)),
        "SYNDICATION / DUPLICATES: " + fmt_list([d.get("type") + ":" + str(len(d.get("media_item_ids") or [])) for d in (r.get("duplicate_relationships") or [])][:10]),
        "MULTIMEDIA CONTEXT: assets=" + str(len(assets)),
        "NARRATIVES / FRAMES: " + fmt_list(r.get("narratives") or r.get("frames")),
        "REGIONAL / LANGUAGE DIFFERENCES: languages=" + fmt_list(coverage.get("languages")) + " regions=" + fmt_list(coverage.get("regions")),
        "SOURCE RELIABILITY: " + fmt_list([f"{s.get('source_id')}={s.get('reliability')}" for s in (r.get("source_reliability") or [])][:10]),
        "SOURCE INDEPENDENCE: " + fmt_list([f"{x.get('story_cluster_id')}={x.get('independence_state')}" for x in indep[:10]]),
        "CONTRADICTIONS: " + str(len(contradictions)),
        "SUPPORTED FACTS: " + str(len(r.get("supported_facts") or [])),
        "DISPUTED CLAIMS: " + str(len(r.get("disputed_facts") or [])),
        "UNKNOWN: " + fmt_list(r.get("unknowns")),
        "NEXT ACTION: " + ((r.get("recommended_next_actions") or ["NONE"])[0]),
    ]

    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Main analysis
# -----------------------------------------------------------------------------

def analyze(case: Dict[str, Any], input_path: Optional[str] = None, input_hash: Optional[str] = None) -> Dict[str, Any]:
    started = utcnow_iso()

    block_reasons = policy_block_reasons(case)
    if block_reasons:
        return blocked_result(case, block_reasons, started, input_path, input_hash)

    settings_raw = case.get("analysis_settings") or {}
    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    def setting_int(name: str, default: int) -> int:
        try:
            return int(settings_raw.get(name, default))
        except Exception:
            return default

    settings: Dict[str, Any] = {
        "shingle_size": setting_int("shingle_size", 3),
        "max_near_duplicate_pairs": setting_int("max_near_duplicate_pairs", 5000),
        "near_duplicate_light_threshold": setting_float("near_duplicate_light_threshold", 0.75),
        "near_duplicate_partial_threshold": setting_float("near_duplicate_partial_threshold", 0.45),
        "numeric_relative_tolerance": setting_float("numeric_relative_tolerance", 0.05),
        "journalist_privacy_strict": scope.get("journalist_privacy_strict", True) is not False,
    }

    now = parse_dt(case.get("knowledge_time")) or datetime.now(timezone.utc)

    sources, src_issues, src_warnings = validate_sources(case)
    publishers, pub_issues = validate_publishers(case)
    outlets, out_issues, out_warnings = validate_outlets(case, publishers)
    authors, auth_issues, auth_warnings = validate_authors(case, outlets)
    items, items_by_id, item_issues, item_warnings = validate_media_items(case, sources, publishers, outlets, authors, settings, now)
    claims, claim_issues, claim_warnings = validate_claims(case, items_by_id)
    quotes, quote_issues, quote_warnings = validate_quotes(case, items_by_id)
    citations, cit_issues, cit_warnings = validate_citations(case, items_by_id)
    assets, asset_issues, asset_warnings = validate_multimedia_assets(case, items_by_id)

    issues = src_issues + pub_issues + out_issues + auth_issues + item_issues + claim_issues + quote_issues + cit_issues + asset_issues
    warnings = src_warnings + out_warnings + auth_warnings + item_warnings + claim_warnings + quote_warnings + cit_warnings + asset_warnings

    attach_primary_sources(items_by_id, citations, claims)
    families = build_lineage_families(items, items_by_id)
    duplicate_relationships = detect_duplicates(items, items_by_id, settings)
    clusters = assign_story_clusters(items)

    coverage = coverage_metrics(items, families, publishers, outlets, authors)
    velocity = coverage_velocity(items)

    headline_mismatches, headline_contradictions = headline_body_analysis(items_by_id, claims)
    quote_contradictions = quote_context_analysis(quotes)
    corrections, retractions, correction_contradictions = correction_retraction_analysis(items, items_by_id, claims, quotes)
    numeric_contradiction_list = numeric_contradictions(claims, settings)
    independence_results = source_independence_analysis(items, items_by_id, clusters)
    claim_corroboration_analysis(claims, items_by_id)

    contradictions = detect_additional_contradictions(
        items,
        clusters,
        independence_results,
        assets,
        items_by_id,
        quote_contradictions,
        numeric_contradiction_list,
        headline_contradictions,
        list(case.get("existing_contradictions") or []) + correction_contradictions,
    )

    supported_facts, candidate_facts, partial_facts, disputed_facts, not_facts = build_facts(
        items,
        claims,
        quotes,
        citations,
        assets,
        corrections,
        retractions,
        contradictions,
        sources,
        publishers,
    )

    hypotheses = build_hypotheses(
        items,
        claims,
        clusters,
        independence_results,
        contradictions,
        corrections,
        retractions,
        assets,
        issues,
    )

    dual = dual_ai_review(items, claims, contradictions, independence_results, issues)

    gaps = build_knowledge_gaps(
        items,
        claims,
        quotes,
        citations,
        assets,
        independence_results,
        contradictions,
        issues,
        sources,
    )

    next_actions = build_next_actions(items, claims, quotes, assets, gaps, contradictions)
    handoffs = build_specialist_handoffs(items, claims, assets, contradictions)

    graph = build_graph(
        sources,
        publishers,
        outlets,
        authors,
        items,
        claims,
        quotes,
        citations,
        assets,
        families,
        clusters,
        corrections,
        retractions,
        supported_facts + candidate_facts + partial_facts,
        hypotheses,
        contradictions,
        gaps,
    )

    # Public objects
    media_item_public = []
    for m in items:
        media_item_public.append(
            {
                "media_item_id": m.get("media_item_id"),
                "media_type": m.get("_media_type"),
                "publisher_id": m.get("_publisher_id"),
                "outlet_id": m.get("_outlet_id"),
                "author_id": m.get("_author_id"),
                "title": short_text(m.get("_title"), 200),
                "subtitle": short_text(m.get("_subtitle"), 200),
                "publication_url": m.get("_publication_url_original"),
                "canonical_url": m.get("_canonical_url_normalized"),
                "published_at": iso_or_none(m.get("_published_at")),
                "updated_at": iso_or_none(m.get("_updated_at")),
                "retrieved_at": iso_or_none(m.get("_retrieved_at")),
                "event_time": iso_or_none(m.get("_event_time")),
                "language": m.get("_language"),
                "region": m.get("_region"),
                "content_hash": m.get("_content_hash"),
                "normalized_hash": m.get("_normalized_text_hash"),
                "archive_reference": m.get("_archive_reference"),
                "content_locator": m.get("_content_locator"),
                "correction_state": m.get("_correction_state"),
                "retracted": bool(m.get("_retracted")),
                "corrects_media_item_id": m.get("_corrects_media_item_id"),
                "syndicated_from": m.get("_syndicated_from"),
                "upstream_media_item_id": m.get("_upstream_media_item_id"),
                "wire_service_id": m.get("_wire_service_id"),
                "lineage_family_id": m.get("_lineage_family_id"),
                "story_cluster_id": m.get("_story_cluster_id"),
                "duplicate_state": m.get("_duplicate_state"),
                "primary_source_ids": m.get("_primary_source_ids"),
                "event_ids": m.get("_event_ids"),
                "entity_ids": m.get("_entity_ids"),
                "topic_ids": m.get("_topic_ids"),
                "narrative_ids": m.get("_narrative_ids"),
                "frame_labels": m.get("_frame_labels"),
                "source_ids": m.get("_source_ids"),
                "evidence_ids": m.get("_evidence_ids"),
                "quality_flags": m.get("_quality_flags"),
                "confidence": item_source_reliability(m, sources, publishers),
                "short_excerpt": short_text(m.get("excerpt") or m.get("body_text"), 180),
                "versions": [
                    {
                        "version_id": v.get("version_id"),
                        "title": short_text(v.get("_title"), 160),
                        "published_at": iso_or_none(v.get("_published_at")),
                        "updated_at": iso_or_none(v.get("_updated_at")),
                        "correction_state": v.get("_correction_state"),
                        "normalized_hash": v.get("_normalized_hash"),
                    }
                    for v in m.get("_versions") or []
                ],
                "limitations": [
                    "Publication is not truth.",
                    "Headline is not article body.",
                    "Article claim is not verified fact.",
                    "Metadata and hashes do not replace primary-source inspection.",
                ],
            }
        )

    claim_public = [
        {
            "claim_id": c.get("claim_id"),
            "media_item_id": c.get("_media_item_id"),
            "claim_scope": c.get("_claim_scope"),
            "claim_type": c.get("_claim_type"),
            "claim_summary": c.get("_claim_summary"),
            "subject": c.get("_subject"),
            "predicate": c.get("_predicate"),
            "object": c.get("_object"),
            "time_reference": c.get("_time_reference"),
            "location_reference": c.get("_location_reference"),
            "source_attribution": c.get("_source_attribution"),
            "basis": c.get("_basis"),
            "numeric_value": c.get("_numeric_value"),
            "numeric_unit": c.get("_numeric_unit"),
            "verification_state": c.get("_verification_state"),
            "corroboration_state": c.get("_corroboration_state"),
            "primary_source_ids": c.get("_primary_source_ids"),
            "external_corroboration": c.get("_external_corroboration"),
            "corroborating_lineage_family_count": c.get("_corroborating_lineage_family_count"),
            "corroborating_primary_source_count": c.get("_corroborating_primary_source_count"),
            "corroborating_publisher_count": c.get("_corroborating_publisher_count"),
            "quality_flags": c.get("_quality_flags"),
            "confidence": c.get("_confidence"),
            "source_ids": c.get("_source_ids"),
            "evidence_ids": c.get("_evidence_ids"),
            "limitations": [
                "Claim status describes evidence state, not automatic truth.",
                "Allegation is not finding.",
                "Denial is not disproof.",
            ],
        }
        for c in claims
    ]

    quote_public = [
        {
            "quote_id": q.get("quote_id"),
            "media_item_id": q.get("_media_item_id"),
            "speaker": q.get("_speaker"),
            "speaker_role": q.get("_speaker_role"),
            "source_attribution": q.get("_source_attribution"),
            "mode": q.get("_mode"),
            "quote_summary": q.get("_quote_summary"),
            "quote_locator": q.get("_quote_locator"),
            "original_language": q.get("_original_language"),
            "quote_language": q.get("_quote_language"),
            "context_available": q.get("_context_available"),
            "is_translation": q.get("_is_translation"),
            "verification_state": q.get("_verification_state"),
            "quality_flags": q.get("_quality_flags"),
            "source_ids": q.get("_source_ids"),
            "evidence_ids": q.get("_evidence_ids"),
            "limitations": [
                "Quote attribution requires transcript/recording/context verification.",
                "Paraphrase is not direct quotation.",
                "Translation is not original quote.",
            ],
        }
        for q in quotes
    ]

    citation_public = [
        {
            "citation_id": c.get("citation_id"),
            "media_item_id": c.get("_media_item_id"),
            "cited_media_item_id": c.get("_cited_media_item_id"),
            "cited_source_id": c.get("_cited_source_id"),
            "cited_document_id": c.get("_cited_document_id"),
            "cited_url": c.get("_cited_url_normalized"),
            "citation_type": c.get("_citation_type"),
            "is_primary_source": c.get("_is_primary_source"),
            "locator": c.get("_locator"),
            "quality_flags": c.get("_quality_flags"),
            "source_ids": c.get("_source_ids"),
            "evidence_ids": c.get("_evidence_ids"),
            "limitations": [
                "Citation metadata does not prove cited source supports the claim without inspection.",
                "Secondary reporting is not primary evidence.",
            ],
        }
        for c in citations
    ]

    asset_public = [
        {
            "asset_id": a.get("asset_id"),
            "media_item_id": a.get("_media_item_id"),
            "asset_type": a.get("_asset_type"),
            "caption": a.get("_caption"),
            "credit": a.get("_credit"),
            "url": a.get("_url_normalized"),
            "first_seen": iso_or_none(a.get("_first_seen")),
            "original_event_time": iso_or_none(a.get("_original_event_time")),
            "reuse_of_asset_id": a.get("_reuse_of_asset_id"),
            "stock_file_label": a.get("_stock_file_label"),
            "manipulation_candidate": a.get("_manipulation_candidate"),
            "synthetic_candidate": a.get("_synthetic_candidate"),
            "detector_output": a.get("_detector_output"),
            "quality_flags": a.get("_quality_flags"),
            "source_ids": a.get("_source_ids"),
            "evidence_ids": a.get("_evidence_ids"),
            "limitations": [
                "MEDIAINT does not declare media authentic or synthetic without specialist validation.",
                "Caption is not verified asset content.",
                "Detector output is one signal, not proof.",
            ],
        }
        for a in assets
    ]

    source_reliability = [
        {
            "source_id": s.get("source_id"),
            "source_type": s.get("_source_type"),
            "publisher_id": s.get("_publisher_id"),
            "outlet_id": s.get("_outlet_id"),
            "reliability": s.get("_reliability"),
            "independence_group": s.get("_independence_group"),
            "upstream_source_id": s.get("_upstream_source_id"),
            "paywalled": s.get("_paywalled"),
            "archive_reference": s.get("_archive_reference"),
            "license": s.get("_license"),
            "limitations": s.get("_limitations"),
        }
        for s in sources.values()
    ]

    all_source_ids = sorted(
        {
            sid
            for obj in items + claims + quotes + citations + assets
            for sid in (obj.get("_source_ids") or [])
            if sid
        }
    )

    narratives = sorted({nid for m in items for nid in (m.get("_narrative_ids") or []) if nid})
    frames = sorted({f for m in items for f in (m.get("_frame_labels") or []) if f})
    topics = sorted({t for m in items for t in (m.get("_topic_ids") or []) if t})
    events = sorted({e for m in items for e in (m.get("_event_ids") or []) if e})

    unknowns: List[str] = []
    if not items:
        unknowns.append("Media evidence base unresolved")
    if any("primary_source_unresolved" in (c.get("_quality_flags") or []) for c in claims):
        unknowns.append("Primary-source support unresolved for some claims")
    if any(x.get("independence_state") == "UNKNOWN" for x in independence_results):
        unknowns.append("Source independence unresolved")
    if contradictions:
        unknowns.append("Media contradictions unresolved")
    if assets:
        unknowns.append("Multimedia technical provenance unresolved without IMINT/VIDINT/AUDINT")
    unknowns.append("Intent, coordination, disinformation adjudication, journalist identity, and confidential source identity unresolved by design")

    if contradictions:
        status = "SOURCE_CONFLICT"
    elif issues:
        status = "PARTIAL"
    elif not items and not claims:
        status = "INCONCLUSIVE"
    elif supported_facts:
        status = "SUCCEEDED"
    else:
        status = "PARTIAL"

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "source_ids": sorted(sources.keys()),
        "evidence_ids": sorted(
            {
                eid
                for obj in items + claims + quotes + citations + assets
                for eid in (obj.get("_evidence_ids") or [])
                if eid
            }
        ),
        "outlets": {oid: public_dict(o) for oid, o in outlets.items()},
        "publishers": {pid: public_dict(p) for pid, p in publishers.items()},
        "authors": {
            aid: {
                "author_id": aid,
                "published_name": a.get("_published_name"),
                "outlet_id": a.get("_outlet_id"),
                "role": a.get("_role"),
                "public_profile_ref": a.get("_public_profile_ref"),
                "quality_flags": a.get("_quality_flags"),
                "limitations": ["No private journalist location, contact, family, or source-identification data is exposed."],
            }
            for aid, a in authors.items()
        },
        "media_items": media_item_public,
        "articles": [m for m in media_item_public if m.get("media_type") in {"NEWS_ARTICLE", "WIRE_REPORT", "BLOG", "NEWSLETTER"}],
        "wire_reports": [m for m in media_item_public if m.get("media_type") == "WIRE_REPORT"],
        "broadcasts": [m for m in media_item_public if m.get("media_type") in {"TV_BROADCAST", "RADIO_BROADCAST"}],
        "podcasts": [m for m in media_item_public if m.get("media_type") == "PODCAST"],
        "press_releases": [m for m in media_item_public if m.get("media_type") in {"PRESS_RELEASE", "GOVERNMENT_RELEASE", "CORPORATE_RELEASE"}],
        "interviews": [m for m in media_item_public if m.get("media_type") in {"INTERVIEW", "PRESS_CONFERENCE", "TRANSCRIPT"}],
        "quotes": quote_public,
        "claims": claim_public,
        "headline_claims": [c for c in claim_public if c.get("claim_scope") == "HEADLINE"],
        "body_claims": [c for c in claim_public if c.get("claim_scope") == "BODY"],
        "primary_sources": sorted({pid for m in media_item_public for pid in (m.get("primary_source_ids") or []) if pid}),
        "source_families": families,
        "citation_network": citation_public,
        "syndication_relationships": [
            {
                "media_item_id": m.get("media_item_id"),
                "syndicated_from": m.get("syndicated_from"),
                "upstream_media_item_id": m.get("upstream_media_item_id"),
                "wire_service_id": m.get("wire_service_id"),
            }
            for m in media_item_public
            if m.get("syndicated_from") or m.get("upstream_media_item_id") or m.get("wire_service_id")
        ],
        "duplicate_stories": duplicate_relationships,
        "story_clusters": clusters,
        "events": events,
        "narratives": narratives,
        "frames": frames,
        "topics": topics,
        "languages": coverage.get("languages"),
        "regions": coverage.get("regions"),
        "coverage_volume": coverage,
        "coverage_velocity": velocity,
        "independent_source_count": {
            "lineage_families": coverage.get("independent_lineage_families"),
            "primary_source_references": coverage.get("distinct_primary_source_references"),
            "note": "Count information families and primary-source references, not URLs.",
        },
        "article_versions": {m.get("media_item_id"): m.get("versions") for m in media_item_public},
        "headline_versions": {
            m.get("media_item_id"): [
                {
                    "version_id": v.get("version_id"),
                    "title": v.get("title"),
                    "published_at": v.get("published_at"),
                    "updated_at": v.get("updated_at"),
                }
                for v in (m.get("versions") or [])
                if v.get("title")
            ]
            for m in media_item_public
        },
        "headline_body_mismatches": headline_mismatches,
        "corrections": corrections,
        "retractions": retractions,
        "multimedia_assets": asset_public,
        "image_context": [a for a in asset_public if a.get("asset_type") == "IMAGE"],
        "video_context": [a for a in asset_public if a.get("asset_type") == "VIDEO"],
        "audio_context": [a for a in asset_public if a.get("asset_type") == "AUDIO"],
        "media_ownership_context": {
            "publishers": {pid: public_dict(p) for pid, p in publishers.items()},
            "outlets": {oid: public_dict(o) for oid, o in outlets.items()},
            "limitations": [
                "Ownership relationship is not direct editorial control.",
                "State ownership is not automatic falsehood.",
                "Commercial ownership is not automatic bias.",
            ],
        },
        "source_independence_analysis": independence_results,
        "timeline_updates": sorted(
            [
                {
                    "kind": "media_item",
                    "id": m.get("media_item_id"),
                    "time": m.get("published_at"),
                    "updated_at": m.get("updated_at"),
                    "publisher_id": m.get("publisher_id"),
                    "media_type": m.get("media_type"),
                }
                for m in media_item_public
            ]
            + [
                {
                    "kind": "correction",
                    "id": f"CORR-{i}",
                    "time": c.get("updated_at"),
                    "media_item_id": c.get("media_item_id"),
                    "corrects_media_item_id": c.get("corrects_media_item_id"),
                }
                for i, c in enumerate(corrections, 1)
            ]
            + [
                {
                    "kind": "retraction",
                    "id": f"RET-{i}",
                    "time": r.get("retracted_at"),
                    "media_item_id": r.get("media_item_id"),
                }
                for i, r in enumerate(retractions, 1)
            ],
            key=lambda x: x.get("time") or "",
        ),
        "observations": media_item_public + claim_public + quote_public + citation_public + asset_public,
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "source_reliability": source_reliability,
        "source_bias": case.get("source_bias") or [
            "Commercial incentives may affect topic selection and framing.",
            "State ownership may affect governance and permitted narratives.",
            "Access journalism may increase source dependence.",
            "Deadline pressure may increase early-reporting error risk.",
            "Aggregators may generalize or compress claims.",
            "Crowdsourced/social material may lack editorial verification.",
        ],
        "source_limitations": case.get("source_limitations") or [
            "Publication is not truth.",
            "Headline is not body.",
            "Press release is not independent reporting.",
            "Primary source is not automatically true.",
            "Article count is not corroboration.",
            "Syndication is not independence.",
            "Multimedia context is not technical authentication.",
        ],
        "source_pedigree": case.get("source_pedigree") or [
            {
                "source_id": s.get("source_id"),
                "source_type": s.get("_source_type"),
                "publisher_id": s.get("_publisher_id"),
                "outlet_id": s.get("_outlet_id"),
                "upstream_source_id": s.get("_upstream_source_id"),
                "independence_group": s.get("_independence_group"),
            }
            for s in sources.values()
        ],
        "source_independence": {
            "cluster_results": independence_results,
            "global_note": "Use lineage families and primary-source references, not raw item counts, to assess independence.",
        },
        "contradictions": contradictions,
        "hypotheses": hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.get("hypothesis_id"),
                "status": "WEAKENED_BY_CONTRADICTIONS" if contradictions else "NOT_FALSIFIED_WITH_CURRENT_EVIDENCE",
                "required_additional_evidence": [
                    "Original primary source",
                    "Archived article version",
                    "Full transcript/recording",
                    "Independent local outlet",
                    "Official document/court/regulator record",
                    "IMINT/VIDINT/AUDINT asset provenance",
                    "Source pedigree / wire metadata",
                ],
            }
            for h in hypotheses
        ],
        "privacy_flags": [
            "NO_PRIVATE_JOURNALIST_LOCATION_EXPOSURE",
            "NO_CONFIDENTIAL_SOURCE_IDENTIFICATION",
            "NO_DOXXING",
            "NO_HARASSMENT",
            "PUBLIC_MEDIA_EVIDENCE_ONLY",
            "MINIMUM_NECESSARY_PERSONAL_DATA",
        ],
        "safety_flags": [
            "NO_PROPAGANDA_GENERATION",
            "NO_INFLUENCE_OPERATIONS",
            "NO_POLITICAL_PERSUASION_AUTOMATION",
            "NO_JOURNALIST_TARGETING",
            "NO_NEWSROOM_INTRUSION",
            "NO_PAYWALL_BYPASS",
            "NO_FAKE_ARTICLES",
            "NO_FAKE_QUOTES",
            "NO_FAKE_INTERVIEWS",
            "NO_MEDIA_MANIPULATION",
            "NO_RANKING_MANIPULATION",
            "NO_UNAUTHORIZED_TAKEDOWNS",
            "NO_DISINFORMATION_ADJUDICATION_WITHOUT_SPECIALIST_EVIDENCE",
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not fetch live media or bypass access controls.",
            "It consumes deterministic media records only.",
            "It does not invent articles, quotes, claims, corrections, retractions, or source relationships.",
            "It separates publication, headline, body, claim, fact, primary source, syndication, and independence.",
            "It does not declare multimedia authentic or synthetic without IMINT/VIDINT/AUDINT.",
            "It does not label disinformation, coordination, intent, or responsibility without evidence and specialist review.",
            "It protects journalists and confidential sources and redacts private/personal fields when detected.",
        ],
        "dual_ai_review": dual,
        "not_facts": not_facts,
        "graphical_memory": graph,
        "validation_issues": issues,
        "validation_warnings": warnings,
        "analysis_settings": settings,
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
            "deterministic_operations": [
                "URL/canonical URL normalization",
                "timestamp parsing",
                "language/region normalization",
                "title/body normalized hashing",
                "token shingle generation",
                "Jaccard near-duplicate scoring",
                "lineage family union-find",
                "story cluster assignment",
                "coverage counts and velocity bucketing",
                "headline/body claim comparison",
                "quote context and speaker-conflict checks",
                "correction/retraction propagation",
                "numeric claim conflict detection",
                "source independence grouping",
                "claim corroboration state assignment",
                "fact gate",
            ],
            "note": (
                "Replay requires original media snapshots, canonical URLs, publication/update times, "
                "publisher/outlet/author metadata, source pedigree, citation network, article versions, "
                "correction/retraction notices, multimedia captions/credits/first-seen data, hashes, "
                "language/region metadata, and model/parser versions."
            ),
        },
    }

    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": (
            "Placeholders only. Replace with deterministic public/authorized/licensed media records. "
            "Do not treat this template as real article, quote, claim, correction, or source evidence."
        ),
        "case_id": "CASE-MEDIAINT-EXAMPLE",
        "task_id": "TASK-MEDIAINT-EXAMPLE",
        "objective": (
            "Authorized lawful media analysis of a public incident report to trace primary sources, "
            "count independent information families, separate headline from body, and identify unresolved claims. "
            "Not propaganda, influence operations, journalist targeting, source deanonymization, or paywall bypass."
        ),
        "questions": [
            "Which outlets published what?",
            "Which claims derive from the same wire/press release?",
            "What primary sources are cited?",
            "Do headlines overstate body-supported claims?",
            "What corrections or retractions exist?",
            "What multimedia requires specialist provenance review?",
            "What remains unknown?",
        ],
        "scope": {
            "authorized_only": True,
            "public_or_authorized_sources_only": True,
            "lawful_only": True,
            "no_propaganda_generation": True,
            "no_influence_operations": True,
            "no_journalist_targeting": True,
            "no_source_deanonymization": True,
            "no_paywall_bypass": True,
            "no_fake_media_generation": True,
            "no_media_manipulation": True,
            "journalist_privacy_strict": True,
        },
        "authorization": {
            "lawful_basis": "PUBLIC_OR_LICENSED_MEDIA_ANALYSIS",
            "purpose": "MEDIA_EVIDENCE_VERIFICATION_AND_SOURCE_PEDIGREE_ANALYSIS",
            "approval_reference": "AUTH-MEDIAINT-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "knowledge_time": "2026-10-08T12:00:00Z",
        "analysis_settings": {
            "shingle_size": 3,
            "max_near_duplicate_pairs": 5000,
            "near_duplicate_light_threshold": 0.75,
            "near_duplicate_partial_threshold": 0.45,
            "numeric_relative_tolerance": 0.05,
        },
        "sources": [
            {
                "source_id": "SRC-WIRE",
                "source_type": "WIRE_SERVICE",
                "publisher_id": "PUB-WIRE",
                "reliability": "HIGH",
                "independence_group": "WIRE_A",
                "limitations": ["Wire copy may be syndicated by many outlets."],
            },
            {
                "source_id": "SRC-OUTLET-A",
                "source_type": "ESTABLISHED_NEWS_OUTLET",
                "publisher_id": "PUB-A",
                "outlet_id": "OUT-A",
                "reliability": "MODERATE",
                "independence_group": "OUTLET_A",
                "limitations": ["Downstream article may derive from wire."],
            },
            {
                "source_id": "SRC-GOV",
                "source_type": "OFFICIAL_GOVERNMENT_RELEASE",
                "publisher_id": "PUB-GOV",
                "reliability": "HIGH",
                "independence_group": "GOV_A",
                "limitations": ["Official release states government claim, not independently verified fact."],
            },
        ],
        "publishers": [
            {
                "publisher_id": "PUB-WIRE",
                "name": "Example Wire Service",
                "commercial": True,
                "official_domains": ["wire.example"],
            },
            {
                "publisher_id": "PUB-A",
                "name": "Example News Publisher",
                "commercial": True,
                "official_domains": ["news.example"],
            },
                        {
                "publisher_id": "PUB-GOV",
                "name": "Example Government Publisher",
                "state_owned": True,
                "official_domains": ["gov.example"],
            },
        ],
        "outlets": [
            {
                "outlet_id": "OUT-WIRE",
                "name": "Example Wire Service",
                "publisher_id": "PUB-WIRE",
                "country": "US",
                "languages": ["en"],
                "media_type": "WIRE_REPORT",
                "official_domains": ["wire.example"],
                "valid_from": "2020-01-01T00:00:00Z",
            },
            {
                "outlet_id": "OUT-A",
                "name": "Example News Outlet",
                "publisher_id": "PUB-A",
                "country": "US",
                "languages": ["en"],
                "media_type": "NEWS_ARTICLE",
                "official_domains": ["news.example"],
                "valid_from": "2020-01-01T00:00:00Z",
            },
            {
                "outlet_id": "OUT-GOV",
                "name": "Example Agency Newsroom",
                "publisher_id": "PUB-GOV",
                "country": "US",
                "languages": ["en"],
                "media_type": "GOVERNMENT_RELEASE",
                "official_domains": ["gov.example"],
                "valid_from": "2020-01-01T00:00:00Z",
            },
        ],
        "authors": [
            {
                "author_id": "AUTH-REPORTER-A",
                "published_name": "A. Reporter",
                "outlet_id": "OUT-A",
                "role": "REPORTER",
                "public_profile_ref": "https://news.example/authors/a-reporter",
            },
            {
                "author_id": "AUTH-SPOKESPERSON",
                "published_name": "Example Agency Spokesperson",
                "outlet_id": "OUT-GOV",
                "role": "SPOKESPERSON",
            },
        ],
        "media_items": [
            {
                "media_item_id": "MEDIA-GOV-1",
                "media_type": "GOVERNMENT_RELEASE",
                "publisher_id": "PUB-GOV",
                "outlet_id": "OUT-GOV",
                "author_id": "AUTH-SPOKESPERSON",
                "source_id": "SRC-GOV",
                "title": "Statement on facility incident",
                "publication_url": "https://gov.example/statements/incident-1?utm_source=rss",
                "canonical_url": "https://gov.example/statements/incident-1",
                "published_at": "2026-10-08T08:30:00Z",
                "language": "en",
                "region": "US",
                "body_text": (
                    "The agency is aware of an incident at a facility. "
                    "An investigation is ongoing. No cause has been confirmed."
                ),
                "event_ids": ["EVT-INCIDENT-1"],
                "topic_ids": ["TOPIC-FACILITY-INCIDENT"],
                "source_ids": ["SRC-GOV"],
                "evidence_ids": ["EVD-MEDIA-GOV-1"],
                "correction_state": "ORIGINAL",
            },
            {
                "media_item_id": "MEDIA-WIRE-1",
                "media_type": "WIRE_REPORT",
                "publisher_id": "PUB-WIRE",
                "outlet_id": "OUT-WIRE",
                "source_id": "SRC-WIRE",
                "title": "Officials say facility incident under investigation",
                "publication_url": "https://wire.example/incident-1",
                "canonical_url": "https://wire.example/incident-1",
                "published_at": "2026-10-08T09:00:00Z",
                "language": "en",
                "region": "US",
                "body_text": (
                    "Officials said an incident occurred at a facility and that the cause is under investigation. "
                    "The statement did not confirm sabotage."
                ),
                "event_ids": ["EVT-INCIDENT-1"],
                "topic_ids": ["TOPIC-FACILITY-INCIDENT"],
                "primary_source_id": "SRC-GOV",
                "headline_claims": [
                    {
                        "claim_id": "CLAIM-WIRE-HEADLINE",
                        "claim_scope": "HEADLINE",
                        "claim_type": "FACTUAL_CLAIM",
                        "subject": "officials",
                        "predicate": "say",
                        "object": "incident under investigation",
                        "claim_text_summary": "Officials say facility incident is under investigation.",
                    }
                ],
                "body_claims": [
                    {
                        "claim_id": "CLAIM-WIRE-BODY",
                        "claim_scope": "BODY",
                        "claim_type": "SOURCE_REPORTED_CLAIM",
                        "subject": "wire report",
                        "predicate": "reports",
                        "object": "officials say cause under investigation",
                        "claim_text_summary": (
                            "The wire report says officials described the cause as under investigation "
                            "and did not confirm sabotage."
                        ),
                        "primary_source_ids": ["SRC-GOV"],
                    }
                ],
                "citations": [
                    {
                        "citation_id": "CIT-WIRE-GOV",
                        "cited_source_id": "SRC-GOV",
                        "citation_type": "OFFICIAL_RELEASE",
                        "primary_source": True,
                        "locator": "agency statement 2026-10-08T08:30:00Z",
                    }
                ],
                "source_ids": ["SRC-WIRE"],
                "evidence_ids": ["EVD-MEDIA-WIRE-1"],
                "correction_state": "ORIGINAL",
            },
            {
                "media_item_id": "MEDIA-OUTLET-A-1",
                "media_type": "NEWS_ARTICLE",
                "publisher_id": "PUB-A",
                "outlet_id": "OUT-A",
                "author_id": "AUTH-REPORTER-A",
                "source_id": "SRC-OUTLET-A",
                "title": "Confirmed sabotage at facility, reports say",
                "publication_url": "https://news.example/incident-1?fbclid=abc123",
                "canonical_url": "https://news.example/incident-1",
                "published_at": "2026-10-08T09:20:00Z",
                "updated_at": "2026-10-08T10:00:00Z",
                "language": "en",
                "region": "US",
                "body_text": (
                    "According to a wire report citing an agency statement, officials said the cause "
                    "of the incident is under investigation."
                ),
                "syndicated_from": "MEDIA-WIRE-1",
                "headline_body_mismatch": True,
                "event_ids": ["EVT-INCIDENT-1"],
                "topic_ids": ["TOPIC-FACILITY-INCIDENT"],
                "headline_claims": [
                    {
                        "claim_id": "CLAIM-OUTLET-HEADLINE",
                        "claim_scope": "HEADLINE",
                        "claim_type": "FACTUAL_CLAIM",
                        "subject": "sabotage",
                        "predicate": "confirmed at",
                        "object": "facility",
                        "claim_text_summary": "Sabotage was confirmed at the facility.",
                    }
                ],
                "body_claims": [
                    {
                        "claim_id": "CLAIM-OUTLET-BODY",
                        "claim_scope": "BODY",
                        "claim_type": "SOURCE_REPORTED_CLAIM",
                        "subject": "news outlet",
                        "predicate": "reports",
                        "object": "wire says cause under investigation",
                        "claim_text_summary": (
                            "The outlet reports that a wire story said the cause is under investigation."
                        ),
                        "primary_source_ids": ["SRC-GOV"],
                    }
                ],
                "citations": [
                    {
                        "citation_id": "CIT-OUTLET-WIRE",
                        "cited_media_item_id": "MEDIA-WIRE-1",
                        "citation_type": "SECONDARY_REPORTING",
                        "primary_source": False,
                        "locator": "wire report",
                    }
                ],
                "media_assets": [
                    {
                        "asset_id": "ASSET-IMG-FILE",
                        "asset_type": "IMAGE",
                        "caption": "File photo of a similar facility",
                        "credit": "Example Stock",
                        "url": "https://images.example/file-photo.jpg",
                        "first_seen": "2025-01-01T00:00:00Z",
                        "original_event_time": "2025-01-01T00:00:00Z",
                        "stock_file_label": "FILE PHOTO",
                        "source_ids": ["SRC-OUTLET-A"],
                        "evidence_ids": ["EVD-ASSET-IMG-FILE"],
                    }
                ],
                "source_ids": ["SRC-OUTLET-A"],
                "evidence_ids": ["EVD-MEDIA-OUTLET-A-1"],
                "correction_state": "UPDATED",
            },
            {
                "media_item_id": "MEDIA-OUTLET-A-CORR",
                "media_type": "NEWS_ARTICLE",
                "publisher_id": "PUB-A",
                "outlet_id": "OUT-A",
                "author_id": "AUTH-REPORTER-A",
                "source_id": "SRC-OUTLET-A",
                "title": "Correction: incident cause under investigation, not confirmed",
                "publication_url": "https://news.example/incident-1-correction",
                "canonical_url": "https://news.example/incident-1-correction",
                "published_at": "2026-10-08T10:10:00Z",
                "language": "en",
                "region": "US",
                "body_text": (
                    "An earlier headline overstated the agency statement. "
                    "Officials said the cause is under investigation, not confirmed."
                ),
                "corrects_media_item_id": "MEDIA-OUTLET-A-1",
                "correction_state": "CORRECTED",
                "correction_note": "Headline corrected after review of agency statement.",
                "event_ids": ["EVT-INCIDENT-1"],
                "topic_ids": ["TOPIC-FACILITY-INCIDENT"],
                "source_ids": ["SRC-OUTLET-A"],
                "evidence_ids": ["EVD-MEDIA-OUTLET-A-CORR"],
            },
        ],
        "article_versions": [
            {
                "version_id": "VER-OUTLET-A-1-V1",
                "media_item_id": "MEDIA-OUTLET-A-1",
                "title": "Confirmed sabotage at facility, reports say",
                "published_at": "2026-10-08T09:20:00Z",
                "correction_state": "ORIGINAL",
            },
            {
                "version_id": "VER-OUTLET-A-1-V2",
                "media_item_id": "MEDIA-OUTLET-A-1",
                "title": "Sabotage under investigation, officials say",
                "published_at": "2026-10-08T09:20:00Z",
                "updated_at": "2026-10-08T10:00:00Z",
                "correction_state": "UPDATED",
            },
        ],
        "quotes": [
            {
                "quote_id": "QUOTE-SPOKESPERSON-1",
                "media_item_id": "MEDIA-WIRE-1",
                "speaker": "Example Agency Spokesperson",
                "speaker_role": "SPOKESPERSON",
                "quote_mode": "DIRECT_QUOTE",
                "quote_text": "We are investigating the cause.",
                "quote_locator": "paragraph 2",
                "context_window": (
                    "Question: Has sabotage been ruled out? "
                    "Answer: We are investigating the cause."
                ),
                "original_language": "en",
                "source_ids": ["SRC-WIRE"],
                "evidence_ids": ["EVD-QUOTE-SPOKESPERSON-1"],
            },
            {
                "quote_id": "QUOTE-PARAPHRASE-1",
                "media_item_id": "MEDIA-OUTLET-A-1",
                "speaker": "Example Agency Spokesperson",
                "speaker_role": "SPOKESPERSON",
                "quote_mode": "PARAPHRASE",
                "quote_text_summary": "The spokesperson said the cause was under investigation.",
                "context_available": False,
                "source_ids": ["SRC-OUTLET-A"],
                "evidence_ids": ["EVD-QUOTE-PARAPHRASE-1"],
            },
        ],
        "claims": [
            {
                "claim_id": "CLAIM-NUM-1",
                "media_item_id": "MEDIA-WIRE-1",
                "claim_scope": "BODY",
                "claim_type": "ESTIMATE",
                "subject": "agency",
                "predicate": "estimated",
                "object": "response units",
                "time_reference": "2026-10-08T09:00:00Z",
                "location_reference": "US",
                "numeric_value": 12,
                "numeric_unit": "units",
                "claim_text_summary": "Agency estimated 12 response units.",
                "primary_source_ids": ["SRC-GOV"],
                "source_ids": ["SRC-WIRE"],
                "evidence_ids": ["EVD-CLAIM-NUM-1"],
            },
            {
                "claim_id": "CLAIM-NUM-2",
                "media_item_id": "MEDIA-OUTLET-A-1",
                "claim_scope": "BODY",
                "claim_type": "ESTIMATE",
                "subject": "agency",
                "predicate": "estimated",
                "object": "response units",
                "time_reference": "2026-10-08T09:00:00Z",
                "location_reference": "US",
                "numeric_value": 20,
                "numeric_unit": "units",
                "claim_text_summary": "Outlet reported agency estimated 20 response units.",
                "primary_source_ids": ["SRC-GOV"],
                "source_ids": ["SRC-OUTLET-A"],
                "evidence_ids": ["EVD-CLAIM-NUM-2"],
            },
        ],
        "citations": [
            {
                "citation_id": "CIT-OUTLET-GOV",
                "media_item_id": "MEDIA-OUTLET-A-1",
                "cited_source_id": "SRC-GOV",
                "citation_type": "OFFICIAL_RELEASE",
                "primary_source": True,
                "locator": "agency statement",
                "source_ids": ["SRC-OUTLET-A"],
                "evidence_ids": ["EVD-CIT-OUTLET-GOV"],
            }
        ],
        "multimedia_assets": [],
        "existing_facts": [],
        "existing_hypotheses": [],
        "existing_contradictions": [],
        "budget": "EXAMPLE",
        "deadline": "EXAMPLE",
    }


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "TRACEATLAS MEDIAINT lawful public-source / authorized evidence-first media intelligence scaffold. "
            "Consumes deterministic media records; does not fetch live media, bypass paywalls, hack newsrooms, "
            "target journalists, deanonymize sources, generate propaganda/fake media, or manipulate rankings."
        )
    )
    parser.add_argument("--input", "-i", help="Path to MEDIAINT input JSON")
    parser.add_argument("--output", "-o", default="mediaint_result.json", help="Output MEDIAINTResult JSON path")
    parser.add_argument("--write-template", action="store_true", help="Print a safe input template and exit")
    args = parser.parse_args()

    if args.write_template:
        print(json.dumps(template_case(), indent=2, default=str))
        return

    if not args.input:
        parser.error("--input is required unless --write-template is used")

    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Input file not found: {path}")

    raw = path.read_bytes()
    input_hash = sha256_bytes(raw)

    try:
        case = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"Failed to parse input JSON: {exc}")

    if not isinstance(case, dict):
        raise SystemExit("Input JSON must be an object")

    result = analyze(case, str(path), input_hash)

    out = Path(args.output)
    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")

    print(
        json.dumps(
            {
                "status": result.get("status"),
                "output": str(out),
                "summary": result.get("required_analyst_summary"),
            },
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    main()