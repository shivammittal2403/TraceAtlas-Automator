#!/usr/bin/env python3
"""
TRACEATLAS RELATIONSHIPINT — Safe Python Starter Implementation

Purpose:
  Evidence-first relationship/network intelligence pipeline.

Hard boundaries enforced in code:
  - Does NOT fabricate relationships.
  - Does NOT use guilt-by-association.
  - Does NOT stalk, track, dox, or surveil private persons.
  - Does NOT perform face/voice/biometric identification.
  - Does NOT generate attack paths, target lists, sabotage plans, or manipulation plans.
  - Does NOT infer romantic/sexual/religious/ethnic/political/medical/criminal status from weak association.
  - Keeps fact graph separate from analytical graph.
  - Treats shared attributes/co-occurrence as candidates, not facts.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VERSION = "0.1.0-relationshipint-safe-starter"
FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)

# --------------------------------------------------------------------
# Policy / authorization constants
# --------------------------------------------------------------------

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_case_evidence",
    "lawful_corporate_records",
    "provided_records_only",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bguilt\s*by\s*association\b"), "GUILT_BY_ASSOCIATION"),
    (re.compile(r"(?i)\b(stalk|surveil|track)\s+(person|individual|someone|user|target)"), "PRIVATE_TRACKING_OR_SURVEILLANCE"),
    (re.compile(r"(?i)\b(dox|doxx|expose\s+private\s+address|home\s+address)\b"), "DOXXING_OR_PRIVATE_ADDRESS_EXPOSURE"),
    (re.compile(r"(?i)\b(face\s+recognition|facial\s+match|voiceprint|biometric\s+identif)"), "BIOMETRIC_IDENTIFICATION_REQUEST"),
    (re.compile(r"(?i)\b(target\s+list|attack\s+path|sabotage|assassination|violence\s+targeting|map\s+vulnerabilit)"), "ATTACK_OR_SABOTAGE_PLANNING"),
    (re.compile(r"(?i)\b(infer|determine|detect|classify)\s+(romantic|sexual|intimate|religion|religious|ethnicity|race|political\s+belief|medical|health|criminality)"), "SENSITIVE_TRAIT_OR_STATUS_INFERENCE"),
    (re.compile(r"(?i)\b(contact|message|call)\s+(target|person|subject)\b"), "UNAUTHORIZED_CONTACT_REQUEST"),
    (re.compile(r"(?i)\b(social\s+engineering|impersonat|manipulat(e|ion)\s+(target|person))"), "MANIPULATION_OR_IMPERSONATION"),
]

SENSITIVE_RELATIONSHIP_TYPES = {
    "ROMANTIC_PARTNER",
    "SEXUAL_PARTNER",
    "INTIMATE_PARTNER",
    "RELIGIOUS_AFFILIATION",
    "ETHNIC_ASSOCIATION",
    "RACIAL_ASSOCIATION",
    "POLITICAL_AFFILIATION",
    "MEDICAL_SUPPORT_NETWORK",
    "CRIMINAL_ASSOCIATION",
}

SOURCE_RELIABILITY: Dict[str, float] = {
    "official_registry": 0.95,
    "corporate_filing": 0.92,
    "court_record": 0.90,
    "regulatory_filing": 0.90,
    "authorized_transaction": 0.90,
    "authorized_communication_metadata": 0.85,
    "authorized_internal_directory": 0.82,
    "official_org_page": 0.80,
    "public_procurement": 0.78,
    "trade_record": 0.75,
    "authorized_incident_telemetry": 0.75,
    "public_event_record": 0.65,
    "public_website": 0.55,
    "reputable_media": 0.52,
    "public_profile": 0.45,
    "aggregator": 0.35,
    "commercial_database": 0.35,
    "anonymous": 0.15,
    "inference": 0.20,
    "unknown": 0.30,
}

HIGH_AUTHORITY_SOURCE_TYPES = {
    "official_registry",
    "corporate_filing",
    "court_record",
    "regulatory_filing",
    "authorized_transaction",
    "authorized_communication_metadata",
    "authorized_internal_directory",
    "official_org_page",
}

RELATIONSHIP_SYNONYMS: Dict[str, str] = {
    "EMPLOYMENT": "EMPLOYED_BY",
    "WORKS_FOR": "EMPLOYED_BY",
    "FORMER_EMPLOYMENT": "FORMERLY_EMPLOYED_BY",
    "DIRECTOR": "DIRECTOR_OF",
    "DIRECTORSHIP": "DIRECTOR_OF",
    "OFFICER": "OFFICER_OF",
    "SHAREHOLDER": "SHAREHOLDER_OF",
    "OWNER": "OWNS",
    "OWNERSHIP": "OWNS",
    "BENEFICIAL_OWNER": "BENEFICIALLY_OWNS_CANDIDATE",
    "CONTROL": "CONTROLS_CANDIDATE",
    "PARENT_SUBSIDIARY": "PARENT_OF",
    "SUBSIDIARY": "SUBSIDIARY_OF",
    "VENDOR": "VENDOR_TO",
    "SUPPLIER": "SUPPLIER_TO",
    "CUSTOMER": "CUSTOMER_OF",
    "CONTRACTOR": "CONTRACTOR_TO",
    "SUBCONTRACTOR": "SUBCONTRACTOR_TO",
    "ADVISOR": "ADVISOR_TO",
    "COMMUNICATION": "COMMUNICATED_WITH",
    "EMAIL": "EMAILED",
    "PHONE": "CALLED",
    "SOCIAL": "SOCIAL_CONNECTION",
    "FOLLOWS_ON_SOCIAL": "FOLLOWS",
    "CO_ATTENDANCE": "EVENT_COATTENDANCE",
    "CO_LOCATION": "CO_LOCATED_WITH",
    "ADDRESS": "ADDRESS_ASSOCIATION",
    "DOMAIN": "DOMAIN_ASSOCIATION",
    "INFRASTRUCTURE": "INFRASTRUCTURE_ASSOCIATION",
    "TECHNICAL": "TECHNICAL_DEPENDENCY",
    "SUPPLY_CHAIN": "SUPPLY_CHAIN_DEPENDENCY",
    "TRADE": "TRADE_RELATIONSHIP",
    "PROCUREMENT": "PROCUREMENT_RELATIONSHIP",
    "CAMPAIGN": "CAMPAIGN_RELATIONSHIP",
    "INCIDENT": "INCIDENT_RELATIONSHIP",
    "RELATED": "RELATED_TO",
    "ASSOCIATED": "RELATED_TO",
}

DIRECTED_TYPES = {
    "EMPLOYED_BY", "FORMERLY_EMPLOYED_BY", "CONTRACTOR_TO", "SUBCONTRACTOR_TO",
    "DIRECTOR_OF", "OFFICER_OF", "SHAREHOLDER_OF", "OWNS",
    "BENEFICIALLY_OWNS_CANDIDATE", "CONTROLS_CANDIDATE",
    "PARENT_OF", "SUBSIDIARY_OF", "VENDOR_TO", "SUPPLIER_TO", "CUSTOMER_OF",
    "ADVISOR_TO", "AUDITOR_OF", "LEGAL_REPRESENTATION",
    "FINANCIAL_TRANSACTION", "TRANSFERRED_TO", "PAID", "RECEIVED_FROM",
    "LENT_TO", "BORROWED_FROM", "INVESTED_IN",
    "SHIPPED_TO", "IMPORTS_FROM", "EXPORTS_TO", "SUPPLIES",
    "BID_FOR", "AWARDED_TO", "CONTRACTED_WITH", "PROCURES_FROM",
    "DEPENDS_ON", "HOSTED_BY", "RESOLVES_TO", "USES_CERTIFICATE",
    "USES_NAMESERVER", "USES_PROVIDER", "USES_DOMAIN", "USES_ACCOUNT",
    "USES_PHONE", "USES_EMAIL", "AUTHORED", "SIGNED", "REFERENCED_IN",
    "MENTIONED_IN", "FILED_BY", "ISSUED_BY", "RECEIVED_BY",
    "ATTENDED", "ORGANIZED", "SPONSORED", "SPOKE_AT", "HOSTED", "INVITED_TO",
}

UNDIRECTED_TYPES = {
    "PARTNERSHIP", "JOINT_VENTURE", "CO_LOCATED_WITH", "ADDRESS_ASSOCIATION",
    "DOCUMENT_ASSOCIATION", "DOMAIN_ASSOCIATION", "INFRASTRUCTURE_ASSOCIATION",
    "TECHNICAL_DEPENDENCY", "SUPPLY_CHAIN_DEPENDENCY", "TRADE_RELATIONSHIP",
    "PROCUREMENT_RELATIONSHIP", "CAMPAIGN_RELATIONSHIP", "INCIDENT_RELATIONSHIP",
    "EVENT_COATTENDANCE", "SOCIAL_CONNECTION", "COMMUNICATED_WITH",
    "RELATED_TO", "SHARED_ATTRIBUTE_CANDIDATE", "CO_OCCURRENCE", "UNKNOWN",
}

TECHNICAL_SHARED_TYPES = {
    "DOMAIN_ASSOCIATION", "INFRASTRUCTURE_ASSOCIATION", "TECHNICAL_DEPENDENCY",
    "USES_CERTIFICATE", "USES_NAMESERVER", "USES_PROVIDER", "RESOLVES_TO", "HOSTED_BY",
}

CONTROL_OR_COORDINATION_TYPES = {
    "CONTROLS_CANDIDATE", "BENEFICIALLY_OWNS_CANDIDATE", "CAMPAIGN_RELATIONSHIP",
    "COORDINATION_CANDIDATE",
}

NEGATIVE_RELATIONSHIP_TYPES = {
    "LEGAL_DISPUTE", "COMPETES_WITH", "SANCTIONED_AGAINST", "PUBLICLY_OPPOSES",
}

DIRECTNESS_RANK = {
    "DIRECTLY_OBSERVED": 5,
    "DOCUMENTED": 4,
    "SOURCE_REPORTED": 3,
    "DERIVED": 2,
    "INFERRED": 1,
    "HYPOTHETICAL": 0,
    "UNKNOWN": 0,
}

DIRECTNESS_SCORE = {
    "DIRECTLY_OBSERVED": 0.95,
    "DOCUMENTED": 0.85,
    "SOURCE_REPORTED": 0.65,
    "DERIVED": 0.45,
    "INFERRED": 0.30,
    "HYPOTHETICAL": 0.15,
    "UNKNOWN": 0.25,
}

VERIFICATION_RANK = {
    "VERIFIED": 5,
    "SUPPORTED": 4,
    "PARTIALLY_SUPPORTED": 3,
    "HISTORICAL": 3,
    "CANDIDATE": 2,
    "UNKNOWN": 1,
    "DISPUTED": 0,
    "REFUTED": -1,
}

FACT_GRAPH_STATES = {"VERIFIED", "SUPPORTED", "PARTIALLY_SUPPORTED", "HISTORICAL"}

# --------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(json_safe(p)) for p in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    s = unicodedata.normalize("NFKC", str(value))
    s = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", s)
    return s.strip()


def collapse_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    s = normalize_text(value)
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y-%m",
        "%Y",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None


def time_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def mask_value(value: Any, keep: int = 2) -> str:
    s = normalize_text(value)
    if not s:
        return ""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


def unique_preserve(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = json_safe(item)
        if isinstance(key, (dict, list)):
            key = json.dumps(key, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


# --------------------------------------------------------------------
# Policy / authorization
# --------------------------------------------------------------------

def collect_manifest_text(manifest: Dict[str, Any]) -> str:
    parts = [
        normalize_text(manifest.get("objective", "")),
        " ".join(normalize_text(q) for q in manifest.get("questions", []) or []),
    ]
    for rel in manifest.get("relationships", []) or []:
        parts.append(normalize_text(rel.get("relationship_type", "")))
        parts.append(normalize_text(rel.get("context", "")))
    return " ".join(parts)


def policy_screen(manifest: Dict[str, Any]) -> List[str]:
    blob = collect_manifest_text(manifest)
    blocked = []
    for pat, label in PROHIBITED_PATTERNS:
        if pat.search(blob):
            blocked.append(label)

    rel_types = {
        normalize_text(rel.get("relationship_type", "")).upper().replace("-", "_").replace(" ", "_")
        for rel in manifest.get("relationships", []) or []
    }
    for t in rel_types:
        if t in SENSITIVE_RELATIONSHIP_TYPES:
            blocked.append(f"SENSITIVE_RELATIONSHIP_TYPE:{t}")

    return list(dict.fromkeys(blocked))


def authorization_check(manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
    auth = manifest.get("authorization") or {}
    reasons: List[str] = []

    if not auth.get("approved"):
        reasons.append("AUTHORIZATION_MISSING_OR_NOT_APPROVED")

    scope = auth.get("scope", "provided_records_only")
    if scope not in ALLOWED_SCOPES:
        reasons.append("UNSUPPORTED_SCOPE")

    model_mode = auth.get("model_mode", "LOCAL_ONLY")
    if model_mode == "CLOUD" and not auth.get("cloud_approved"):
        reasons.append("CLOUD_PROCESSING_NOT_APPROVED")

    if model_mode not in {"LOCAL_ONLY", "HYBRID", "CLOUD"}:
        reasons.append("UNKNOWN_MODEL_MODE")

    return (len(reasons) == 0), reasons


# --------------------------------------------------------------------
# Normalization helpers
# --------------------------------------------------------------------

def normalize_entity_type(value: Any) -> str:
    t = normalize_text(value).upper().replace("-", "_").replace(" ", "_")
    return t or "UNKNOWN"


def normalize_relationship_type(value: Any) -> str:
    t = normalize_text(value).upper().replace("-", "_").replace(" ", "_")
    return RELATIONSHIP_SYNONYMS.get(t, t or "UNKNOWN")


def normalize_direction(value: Any, rel_type: str) -> str:
    d = normalize_text(value).upper()
    if d in {"DIRECTED", "UNDIRECTED", "BIDIRECTIONAL", "UNKNOWN"}:
        return d
    if rel_type in DIRECTED_TYPES:
        return "DIRECTED"
    if rel_type in UNDIRECTED_TYPES:
        return "UNDIRECTED"
    return "UNKNOWN"


def normalize_directness(value: Any, has_source: bool, has_evidence: bool) -> str:
    d = normalize_text(value).upper()
    if d in DIRECTNESS_RANK:
        return d
    if has_evidence:
        return "DOCUMENTED"
    if has_source:
        return "SOURCE_REPORTED"
    return "INFERRED"


def normalize_verification_state(value: Any) -> str:
    s = normalize_text(value).upper()
    if s in VERIFICATION_RANK:
        return s
    return "UNKNOWN"


def normalize_confidence(value: Any) -> Tuple[Optional[float], str]:
    if value is None:
        return None, "UNKNOWN"
    if isinstance(value, (int, float)):
        score = clamp(float(value))
        if score >= 0.85:
            return score, "HIGH"
        if score >= 0.65:
            return score, "MODERATE"
        if score >= 0.35:
            return score, "LOW"
        return score, "VERY_LOW"
    s = normalize_text(value).upper()
    mapping = {
        "HIGH": 0.85,
        "HIGH_CONFIDENCE": 0.85,
        "STRONG": 0.80,
        "MODERATE": 0.60,
        "MEDIUM": 0.60,
        "PROBABLE": 0.65,
        "POSSIBLE": 0.40,
        "WEAK": 0.30,
        "LOW": 0.25,
        "UNKNOWN": 0.0,
    }
    score = mapping.get(s)
    return score, s or "UNKNOWN"


# --------------------------------------------------------------------
# Source handling
# --------------------------------------------------------------------

def ingest_sources(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    sources: Dict[str, Dict[str, Any]] = {}
    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if not sid:
            continue
        stype = normalize_text(s.get("source_type", "unknown")).lower()
        rel = s.get("reliability")
        if rel is None:
            rel = SOURCE_RELIABILITY.get(stype, SOURCE_RELIABILITY["unknown"])
        sources[sid] = {
            "source_id": sid,
            "source_type": stype,
            "upstream_source_id": normalize_text(s.get("upstream_source_id")) or None,
            "reliability": clamp(float(rel)),
            "observed_at": parse_time(s.get("observed_at")),
            "url": s.get("url"),
            "limitations": list(s.get("limitations", []) or []),
        }
    return sources


def resolve_source_root(sid: str, sources: Dict[str, Dict[str, Any]], memo: Dict[str, str], visiting: Set[str]) -> str:
    if sid in memo:
        return memo[sid]
    if sid in visiting:
        return sid
    visiting.add(sid)
    src = sources.get(sid)
    if not src or not src.get("upstream_source_id"):
        memo[sid] = sid
        visiting.discard(sid)
        return sid
    root = resolve_source_root(src["upstream_source_id"], sources, memo, visiting)
    memo[sid] = root
    visiting.discard(sid)
    return root


def build_source_roots(sources: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    memo: Dict[str, str] = {}
    for sid in sources:
        resolve_source_root(sid, sources, memo, set())
    return memo


def source_family_ids(source_ids: List[str], source_roots: Dict[str, str]) -> List[str]:
    roots = []
    for sid in source_ids:
        roots.append(source_roots.get(sid, sid))
    return list(dict.fromkeys(roots))


def source_quality(source_ids: List[str], sources: Dict[str, Dict[str, Any]]) -> Tuple[float, float]:
    vals = []
    for sid in source_ids:
        vals.append(float(sources.get(sid, {}).get("reliability", SOURCE_RELIABILITY["unknown"])))
    if not vals:
        return SOURCE_RELIABILITY["unknown"], SOURCE_RELIABILITY["unknown"]
    return max(vals), sum(vals) / len(vals)


def independence_state(families: List[str], sources: Dict[str, Dict[str, Any]], source_ids: List[str]) -> str:
    if not source_ids:
        return "UNKNOWN"
    if len(families) <= 1:
        return "DEPENDENT"
    types = {sources.get(sid, {}).get("source_type", "unknown") for sid in source_ids}
    rels = [sources.get(sid, {}).get("reliability", 0.3) for sid in source_ids]
    if len(types) == 1 and max(rels) < 0.70:
        return "PARTIALLY_DEPENDENT"
    if max(rels) >= 0.70:
        return "INDEPENDENT"
    return "PARTIALLY_DEPENDENT"


# --------------------------------------------------------------------
# Entity handling
# --------------------------------------------------------------------

def ensure_entity(entities: Dict[str, Dict[str, Any]], entity_id: str, reason: str) -> Dict[str, Any]:
    eid = normalize_text(entity_id)
    if eid in entities:
        return entities[eid]
    placeholder = {
        "entity_id": eid,
        "entity_type": "UNKNOWN",
        "canonical_name": eid,
        "aliases": [],
        "identifiers": {},
        "valid_from": None,
        "valid_to": None,
        "source_ids": [],
        "resolution_state": "UNRESOLVED",
        "confidence_score": 0.25,
        "confidence_label": "LOW",
        "limitations": [f"Placeholder entity created because {reason}."],
    }
    entities[eid] = placeholder
    return placeholder


def ingest_entities(manifest: Dict[str, Any], sources: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    entities: Dict[str, Dict[str, Any]] = {}
    for idx, ent in enumerate(manifest.get("entities", []) or []):
        eid = normalize_text(ent.get("entity_id") or f"ENT-{idx}")
        conf_score, conf_label = normalize_confidence(ent.get("confidence"))
        source_ids = list(dict.fromkeys([normalize_text(x) for x in ent.get("source_ids", []) or [] if normalize_text(x)]))
        for sid in source_ids:
            if sid not in sources:
                sources[sid] = {
                    "source_id": sid,
                    "source_type": "unknown",
                    "upstream_source_id": None,
                    "reliability": SOURCE_RELIABILITY["unknown"],
                    "observed_at": None,
                    "url": None,
                    "limitations": ["Source referenced but not defined in manifest."],
                }

        identifiers = {}
        for k, v in (ent.get("identifiers") or {}).items():
            nk = normalize_text(k).lower()
            if isinstance(v, list):
                identifiers[nk] = [normalize_text(x) for x in v if normalize_text(x)]
            elif normalize_text(v):
                identifiers[nk] = [normalize_text(v)]

        entities[eid] = {
            "entity_id": eid,
            "entity_type": normalize_entity_type(ent.get("entity_type")),
            "canonical_name": normalize_text(ent.get("canonical_name") or eid),
            "aliases": [normalize_text(a) for a in ent.get("aliases", []) or [] if normalize_text(a)],
            "identifiers": identifiers,
            "valid_from": parse_time(ent.get("valid_from")),
            "valid_to": parse_time(ent.get("valid_to")),
            "source_ids": source_ids,
            "resolution_state": normalize_text(ent.get("resolution_state", "UNRESOLVED")).upper() or "UNRESOLVED",
            "confidence_score": conf_score if conf_score is not None else 0.50,
            "confidence_label": conf_label,
            "limitations": list(ent.get("limitations", []) or []) + [
                "Entity reference is not automatically a verified real-world identity.",
                "Account/persona/organization/legal person layers must remain separate.",
            ],
        }
    return entities


# --------------------------------------------------------------------
# Evidence handling
# --------------------------------------------------------------------

def ingest_evidence(manifest: Dict[str, Any], sources: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    evidence: Dict[str, Dict[str, Any]] = {}
    for idx, ev in enumerate(manifest.get("evidence", []) or []):
        evid = normalize_text(ev.get("evidence_id") or f"EV-{idx}")
        sid = normalize_text(ev.get("source_id"))
        if sid and sid not in sources:
            sources[sid] = {
                "source_id": sid,
                "source_type": "unknown",
                "upstream_source_id": None,
                "reliability": SOURCE_RELIABILITY["unknown"],
                "observed_at": None,
                "url": None,
                "limitations": ["Evidence source referenced but not defined in manifest."],
            }
        evidence[evid] = {
            "evidence_id": evid,
            "source_id": sid or None,
            "entity_ids": [normalize_text(x) for x in ev.get("entity_ids", []) or [] if normalize_text(x)],
            "locator": normalize_text(ev.get("locator")),
            "text": normalize_text(ev.get("text")),
            "observed_at": parse_time(ev.get("observed_at")),
            "limitations": list(ev.get("limitations", []) or []),
        }
    return evidence


# --------------------------------------------------------------------
# Relationship ingestion and merging
# --------------------------------------------------------------------

def edge_interval(edge: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime]]:
    start = edge.get("valid_from") or edge.get("first_seen")
    end = edge.get("valid_to") or edge.get("last_seen")
    return start, end


def intervals_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    a_start, a_end = edge_interval(a)
    b_start, b_end = edge_interval(b)
    if a_start and b_end and a_start > b_end:
        return False
    if b_start and a_end and b_start > a_end:
        return False
    return True


def min_dt(values: Iterable[Optional[datetime]]) -> Optional[datetime]:
    vals = [v for v in values if v is not None]
    return min(vals) if vals else None


def max_dt(values: Iterable[Optional[datetime]]) -> Optional[datetime]:
    vals = [v for v in values if v is not None]
    return max(vals) if vals else None


def ingest_relationships(
    manifest: Dict[str, Any],
    entities: Dict[str, Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    evidence: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    raw_edges: List[Dict[str, Any]] = []

    for idx, rel in enumerate(manifest.get("relationships", []) or []):
        src_id = normalize_text(rel.get("source_entity") or rel.get("from") or rel.get("source"))
        tgt_id = normalize_text(rel.get("target_entity") or rel.get("to") or rel.get("target"))
        if not src_id or not tgt_id:
            continue

        ensure_entity(entities, src_id, "relationship referenced missing source entity")
        ensure_entity(entities, tgt_id, "relationship referenced missing target entity")

        rel_type = normalize_relationship_type(rel.get("relationship_type") or rel.get("type"))
        direction = normalize_direction(rel.get("direction"), rel_type)
        source_ids = [normalize_text(x) for x in rel.get("source_ids", []) or [] if normalize_text(x)]
        evidence_ids = [normalize_text(x) for x in rel.get("evidence_ids", []) or [] if normalize_text(x)]

        for evid in evidence_ids:
            ev = evidence.get(evid)
            if ev and ev.get("source_id") and ev["source_id"] not in source_ids:
                source_ids.append(ev["source_id"])

        source_ids = list(dict.fromkeys(source_ids))
        for sid in source_ids:
            if sid not in sources:
                sources[sid] = {
                    "source_id": sid,
                    "source_type": "unknown",
                    "upstream_source_id": None,
                    "reliability": SOURCE_RELIABILITY["unknown"],
                    "observed_at": None,
                    "url": None,
                    "limitations": ["Relationship source referenced but not defined in manifest."],
                }

        directness = normalize_directness(rel.get("directness"), bool(source_ids), bool(evidence_ids))
        verification = normalize_verification_state(rel.get("verification_state") or rel.get("state"))
        if verification == "UNKNOWN":
            if evidence_ids and directness in {"DIRECTLY_OBSERVED", "DOCUMENTED"}:
                verification = "PARTIALLY_SUPPORTED"
            elif source_ids:
                verification = "CANDIDATE"
            else:
                verification = "UNKNOWN"

        conf_score, conf_label = normalize_confidence(rel.get("confidence"))

        edge = {
            "relationship_id": normalize_text(rel.get("relationship_id")) or stable_id("REL", idx, src_id, tgt_id, rel_type),
            "source_entity": src_id,
            "target_entity": tgt_id,
            "relationship_type": rel_type,
            "direction": direction,
            "directness": directness,
            "verification_state": verification,
            "valid_from": parse_time(rel.get("valid_from")),
            "valid_to": parse_time(rel.get("valid_to")),
            "first_seen": parse_time(rel.get("first_seen")),
            "last_seen": parse_time(rel.get("last_seen")),
            "source_ids": source_ids,
            "evidence_ids": evidence_ids,
            "context": normalize_text(rel.get("context")),
            "input_confidence_score": conf_score,
            "input_confidence_label": conf_label,
            "limitations": list(rel.get("limitations", []) or []),
            "origin": "PROVIDED_RELATIONSHIP",
        }
        raw_edges.append(edge)

    return raw_edges


def merge_state(states: List[str]) -> str:
    states = [s for s in states if s in VERIFICATION_RANK]
    if not states:
        return "UNKNOWN"
    if "REFUTED" in states and any(s in {"VERIFIED", "SUPPORTED", "PARTIALLY_SUPPORTED"} for s in states):
        return "DISPUTED"
    if "DISPUTED" in states:
        return "DISPUTED"
    ranked = sorted(states, key=lambda s: VERIFICATION_RANK.get(s, 0), reverse=True)
    top = ranked[0]
    distinct = set(ranked)
    if len(distinct) > 1 and VERIFICATION_RANK.get(top, 0) - min(VERIFICATION_RANK.get(s, 0) for s in distinct) > 1:
        return "PARTIALLY_SUPPORTED"
    return top


def merge_directness(states: List[str]) -> str:
    states = [s for s in states if s in DIRECTNESS_RANK]
    if not states:
        return "UNKNOWN"
    return sorted(states, key=lambda s: DIRECTNESS_RANK.get(s, 0), reverse=True)[0]


def merge_edges(raw_edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for e in raw_edges:
        key = (e["source_entity"], e["target_entity"], e["relationship_type"], e["direction"])
        buckets[key].append(e)

    merged: List[Dict[str, Any]] = []

    for key, lst in buckets.items():
        lst.sort(key=lambda x: edge_interval(x)[0] or datetime.min.replace(tzinfo=timezone.utc))
        current: Optional[Dict[str, Any]] = None

        for item in lst:
            if current is None:
                current = dict(item)
                current["merged_relationship_ids"] = [item["relationship_id"]]
                continue

            if intervals_overlap(current, item):
                current["source_ids"] = list(dict.fromkeys(current.get("source_ids", []) + item.get("source_ids", [])))
                current["evidence_ids"] = list(dict.fromkeys(current.get("evidence_ids", []) + item.get("evidence_ids", [])))
                current["limitations"] = list(dict.fromkeys(current.get("limitations", []) + item.get("limitations", [])))
                current["merged_relationship_ids"] = list(dict.fromkeys(current.get("merged_relationship_ids", []) + [item["relationship_id"]]))
                current["valid_from"] = min_dt([current.get("valid_from"), item.get("valid_from")])
                current["valid_to"] = max_dt([current.get("valid_to"), item.get("valid_to")])
                current["first_seen"] = min_dt([current.get("first_seen"), item.get("first_seen")])
                current["last_seen"] = max_dt([current.get("last_seen"), item.get("last_seen")])
                current["verification_state"] = merge_state([current.get("verification_state", "UNKNOWN"), item.get("verification_state", "UNKNOWN")])
                current["directness"] = merge_directness([current.get("directness", "UNKNOWN"), item.get("directness", "UNKNOWN")])
                if item.get("context"):
                    current["context"] = collapse_ws((current.get("context") or "") + " | " + item["context"])
            else:
                merged.append(current)
                current = dict(item)
                current["merged_relationship_ids"] = [item["relationship_id"]]

        if current is not None:
            merged.append(current)

    for e in merged:
        e["edge_id"] = stable_id(
            "EDGE",
            e["source_entity"],
            e["target_entity"],
            e["relationship_type"],
            e["direction"],
            time_iso(e.get("valid_from")),
            time_iso(e.get("valid_to")),
            time_iso(e.get("first_seen")),
            time_iso(e.get("last_seen")),
        )

    return merged


# --------------------------------------------------------------------
# Candidate links from shared attributes / co-occurrence
# --------------------------------------------------------------------

SHARED_ATTRIBUTE_PRIORITY = {
    "account_id": 0.55,
    "official_id": 0.60,
    "registration_number": 0.60,
    "email": 0.45,
    "phone": 0.40,
    "domain": 0.35,
    "ip": 0.20,
    "asn": 0.10,
    "nameserver": 0.15,
    "registrar": 0.10,
    "certificate": 0.30,
    "address": 0.25,
    "document_id": 0.35,
    "event_id": 0.25,
    "wallet_address": 0.30,
    "payment_account_id": 0.35,
}

SENSITIVE_IDENTIFIER_KEYS = {"home_address", "private_address", "national_id", "passport", "dob", "date_of_birth"}


def mask_identifier_value(key: str, value: str) -> str:
    if key in {"email", "phone", "address", "home_address", "private_address", "national_id", "passport", "dob", "date_of_birth", "wallet_address", "payment_account_id", "account_id", "official_id", "registration_number"}:
        return mask_value(value)
    return value


def generate_candidate_edges(
    entities: Dict[str, Dict[str, Any]],
    evidence: Dict[str, Dict[str, Any]],
    existing_edges: List[Dict[str, Any]],
    max_candidates: int = 500,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    existing_pairs = set()
    for e in existing_edges:
        existing_pairs.add((e["source_entity"], e["target_entity"], e["relationship_type"]))
        existing_pairs.add((e["target_entity"], e["source_entity"], e["relationship_type"]))

    entity_ids = sorted(entities.keys())

    # Shared identifiers
    for i in range(len(entity_ids)):
        for j in range(i + 1, len(entity_ids)):
            a = entities[entity_ids[i]]
            b = entities[entity_ids[j]]
            shared = []
            for key, priority in SHARED_ATTRIBUTE_PRIORITY.items():
                if key in SENSITIVE_IDENTIFIER_KEYS:
                    continue
                av = set(a.get("identifiers", {}).get(key, []) or [])
                bv = set(b.get("identifiers", {}).get(key, []) or [])
                inter = av & bv
                if inter:
                    val = sorted(inter)[0]
                    shared.append({
                        "attribute": key,
                        "value_masked": mask_identifier_value(key, val),
                        "priority": priority,
                    })
            if shared:
                best = max(shared, key=lambda x: x["priority"])
                candidates.append({
                    "edge_id": stable_id("CAND", a["entity_id"], b["entity_id"], "SHARED_ATTRIBUTE_CANDIDATE", best["attribute"]),
                    "source_entity": a["entity_id"],
                    "target_entity": b["entity_id"],
                    "relationship_type": "SHARED_ATTRIBUTE_CANDIDATE",
                    "direction": "UNDIRECTED",
                    "directness": "INFERRED",
                    "verification_state": "CANDIDATE",
                    "valid_from": None,
                    "valid_to": None,
                    "first_seen": None,
                    "last_seen": None,
                    "source_ids": [],
                    "evidence_ids": [],
                    "context": "Generated from shared identifier attribute.",
                    "shared_attributes": shared,
                    "limitations": [
                        "Shared attribute is a relationship candidate only.",
                        "Do not infer personal relationship, ownership, control, coordination, or criminality from this candidate.",
                    ],
                    "origin": "SHARED_ATTRIBUTE_CANDIDATE",
                    "in_fact_graph": False,
                })

    # Evidence co-occurrence
    for ev in evidence.values():
        eids = [x for x in ev.get("entity_ids", []) if x in entities]
        eids = list(dict.fromkeys(eids))
        if len(eids) < 2:
            continue
        for i in range(len(eids)):
            for j in range(i + 1, len(eids)):
                a, b = eids[i], eids[j]
                if (a, b, "CO_OCCURRENCE") in existing_pairs or (b, a, "CO_OCCURRENCE") in existing_pairs:
                    continue
                candidates.append({
                    "edge_id": stable_id("CAND", a, b, "CO_OCCURRENCE", ev["evidence_id"]),
                    "source_entity": a,
                    "target_entity": b,
                    "relationship_type": "CO_OCCURRENCE",
                    "direction": "UNDIRECTED",
                    "directness": "DERIVED",
                    "verification_state": "CANDIDATE",
                    "valid_from": ev.get("observed_at"),
                    "valid_to": ev.get("observed_at"),
                    "first_seen": ev.get("observed_at"),
                    "last_seen": ev.get("observed_at"),
                    "source_ids": [ev["source_id"]] if ev.get("source_id") else [],
                    "evidence_ids": [ev["evidence_id"]],
                    "context": f"Entities co-occur in evidence {ev['evidence_id']}.",
                    "limitations": [
                        "Co-occurrence does not prove association, communication, coordination, control, or relationship.",
                    ],
                    "origin": "EVIDENCE_CO_OCCURRENCE",
                    "in_fact_graph": False,
                })

    return candidates[:max_candidates]


# --------------------------------------------------------------------
# Temporal / alternative explanation / confidence
# --------------------------------------------------------------------

def classify_temporal(edge: Dict[str, Any], as_of: datetime) -> str:
    start, end = edge_interval(edge)
    if start is None and end is None:
        return "UNKNOWN"
    if end and end < as_of:
        days = (as_of - end).days
        return "STALE" if days > 730 else "HISTORICAL"
    if start and start > as_of:
        return "FUTURE_CANDIDATE"
    if start and end and start <= as_of <= end:
        return "CURRENT"
    if start and start <= as_of:
        return "CURRENT_OR_RECENT"
    return "UNKNOWN"


def detect_alternative_explanations(
    edge: Dict[str, Any],
    entities: Dict[str, Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    independent_families: List[str],
) -> List[str]:
    alts: List[str] = []
    rt = edge.get("relationship_type", "")
    direct = edge.get("directness", "")
    ctx = normalize_text(edge.get("context", "")).lower()
    lims = " ".join(normalize_text(x).lower() for x in edge.get("limitations", []) or [])
    blob = ctx + " " + lims

    if rt in TECHNICAL_SHARED_TYPES and len(independent_families) <= 1:
        alts.append("Technical link may be explained by shared hosting, CDN, DNS provider, certificate automation, cloud platform, or NAT.")

    if rt in {"ADDRESS_ASSOCIATION", "CO_LOCATED_WITH"}:
        alts.append("Shared address may reflect office building, coworking space, registered agent, virtual office, university, hospital, or large facility.")

    if rt in {"EVENT_COATTENDANCE", "CO_OCCURRENCE"}:
        alts.append("Co-attendance/co-occurrence may be coincidental, public-event artifact, platform artifact, or third-party aggregation.")

    if rt in {"SOCIAL_CONNECTION", "FOLLOWS", "MENTIONED"}:
        alts.append("Social follow/mention/reaction is platform engagement, not proof of friendship, agreement, coordination, or control.")

    if rt in {"COMMUNICATED_WITH", "EMAILED", "CALLED"}:
        alts.append("Communication metadata may reflect automation, support traffic, mailing list, call center, forwarding, or one-way contact.")

    if rt in CONTROL_OR_COORDINATION_TYPES:
        alts.append("Control/coordination requires stronger independent evidence than association, shared resource, or communication frequency.")

    if direct in {"INFERRED", "HYPOTHETICAL", "DERIVED"}:
        alts.append("Edge is analytical/candidate and must not be treated as observed relationship.")

    if any(k in blob for k in ["ip", "asn", "hosting", "cdn", "nameserver", "registrar", "certificate"]):
        alts.append("Shared network/infrastructure attribute may have benign provider explanation.")

    if any(k in blob for k in ["address", "office", "registered agent", "virtual"]):
        alts.append("Address linkage may be institutional rather than personal.")

    return list(dict.fromkeys(alts))


def preliminary_enrich_edges(
    edges: List[Dict[str, Any]],
    entities: Dict[str, Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    source_roots: Dict[str, str],
    as_of: datetime,
) -> None:
    for e in edges:
        src_ent = entities.get(e["source_entity"], {})
        tgt_ent = entities.get(e["target_entity"], {})
        e["entity_resolution_confidence"] = min(
            float(src_ent.get("confidence_score", 0.5)),
            float(tgt_ent.get("confidence_score", 0.5)),
        )
        e["entity_resolution_states"] = {
            "source": src_ent.get("resolution_state", "UNKNOWN"),
            "target": tgt_ent.get("resolution_state", "UNKNOWN"),
        }

        families = source_family_ids(e.get("source_ids", []), source_roots)
        e["raw_source_count"] = len(e.get("source_ids", []))
        e["independent_source_family_count"] = len(families)
        e["source_family_ids"] = families
        e["source_independence_state"] = independence_state(families, sources, e.get("source_ids", []))
        e["source_max_reliability"], e["source_avg_reliability"] = source_quality(e.get("source_ids", []), sources)
        e["temporal_state"] = classify_temporal(e, as_of)
        e["alternative_explanations"] = detect_alternative_explanations(e, entities, sources, families)
        e["contradiction_penalty"] = 1.0
        e["contradictions"] = []


def apply_fact_gate(edges: List[Dict[str, Any]], known_facts: List[Any]) -> None:
    for kf in known_facts or []:
        if isinstance(kf, dict):
            eids = {normalize_text(x) for x in kf.get("entity_ids", []) or [] if normalize_text(x)}
            rel_type = normalize_relationship_type(kf.get("relationship_type")) if kf.get("relationship_type") else None
            state = normalize_text(kf.get("state", "SUPPORTED")).upper()
            note = normalize_text(kf.get("text", "Provided known fact."))
            for e in edges:
                pair = {e["source_entity"], e["target_entity"]}
                if eids and not eids.issubset(pair):
                    continue
                if rel_type and rel_type != "UNKNOWN" and e["relationship_type"] != rel_type:
                    continue
                if state in {"SUPPORTED", "VERIFIED"}:
                    e["verification_state"] = "SUPPORTED" if state == "SUPPORTED" else "VERIFIED"
                    e["fact_gate_note"] = note
                elif state == "REFUTED":
                    e["verification_state"] = "REFUTED"
                    e["fact_gate_note"] = note
                elif state == "DISPUTED":
                    e["verification_state"] = "DISPUTED"
                    e["fact_gate_note"] = note
        else:
            text = normalize_text(kf).lower()
            if not text:
                continue
            for e in edges:
                labels = [
                    normalize_text(entities_cache.get(e["source_entity"], {}).get("canonical_name", e["source_entity"])).lower(),
                    normalize_text(entities_cache.get(e["target_entity"], {}).get("canonical_name", e["target_entity"])).lower(),
                ]
                if all(lbl and lbl in text for lbl in labels):
                    e["verification_state"] = "SUPPORTED"
                    e["fact_gate_note"] = "Matched provided textual known fact."


def detect_contradictions(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    contradictions: List[Dict[str, Any]] = []
    by_pair_type: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    by_pair: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

    for e in edges:
        key_pt = (e["source_entity"], e["target_entity"], e["relationship_type"])
        by_pair_type[key_pt].append(e)
        pair = tuple(sorted([e["source_entity"], e["target_entity"]]))
        by_pair[pair].append(e)

    # Refuted vs supported same pair/type
    for key, lst in by_pair_type.items():
        states = {e["verification_state"] for e in lst}
        if "REFUTED" in states and states & {"VERIFIED", "SUPPORTED", "PARTIALLY_SUPPORTED"}:
            for e in lst:
                e["contradiction_penalty"] = min(e["contradiction_penalty"], 0.35)
                e["contradictions"].append("REFUTED_VS_SUPPORTED_SAME_RELATIONSHIP")
            contradictions.append({
                "contradiction_id": stable_id("CTR", "refuted_supported", *key),
                "type": "REFUTED_VS_SUPPORTED_RELATIONSHIP",
                "severity": "HARD",
                "entities": [key[0], key[1]],
                "relationship_type": key[2],
                "edges": [e["edge_id"] for e in lst],
                "detail": "Same relationship is both refuted and supported by provided facts/evidence.",
            })

    # Incompatible overlapping directed relationship types
    incompatible_same_direction = {
        ("EMPLOYED_BY", "FORMERLY_EMPLOYED_BY"),
        ("PARENT_OF", "SUBSIDIARY_OF"),
        ("OWNS", "CONTROLS_CANDIDATE"),  # conservative: control candidate should not override ownership without evidence
    }

    for pair, lst in by_pair.items():
        for i in range(len(lst)):
            for j in range(i + 1, len(lst)):
                a, b = lst[i], lst[j]
                if a["source_entity"] != b["source_entity"] or a["target_entity"] != b["target_entity"]:
                    continue
                if not intervals_overlap(a, b):
                    continue
                types = {a["relationship_type"], b["relationship_type"]}
                for x, y in incompatible_same_direction:
                    if types == {x, y}:
                        severity = "STRONG"
                        penalty = 0.60
                        if x == "PARENT_OF" and y == "SUBSIDIARY_OF":
                            severity = "HARD"
                            penalty = 0.35
                        for e in (a, b):
                            e["contradiction_penalty"] = min(e["contradiction_penalty"], penalty)
                            e["contradictions"].append(f"INCOMPATIBLE_OVERLAPPING_TYPE:{x}/{y}")
                        contradictions.append({
                            "contradiction_id": stable_id("CTR", "incompatible", a["edge_id"], b["edge_id"]),
                            "type": "INCOMPATIBLE_OVERLAPPING_RELATIONSHIP_TYPES",
                            "severity": severity,
                            "entities": [a["source_entity"], a["target_entity"]],
                            "relationship_types": [a["relationship_type"], b["relationship_type"]],
                            "edges": [a["edge_id"], b["edge_id"]],
                            "detail": "Overlapping records assert incompatible relationship types for the same directed pair.",
                        })

    return contradictions


def finalize_edge_scores(edges: List[Dict[str, Any]]) -> None:
    for e in edges:
        direct_score = DIRECTNESS_SCORE.get(e.get("directness", "UNKNOWN"), 0.25)
        source_quality_score = 0.70 * float(e.get("source_max_reliability", 0.30)) + 0.30 * float(e.get("source_avg_reliability", 0.30))
        fam_count = int(e.get("independent_source_family_count", 0))
        if fam_count >= 2:
            indep_score = 1.00
        elif fam_count == 1:
            indep_score = 0.55
        else:
            indep_score = 0.35

        temporal_state = e.get("temporal_state", "UNKNOWN")
        temporal_mult = {
            "CURRENT": 1.00,
            "CURRENT_OR_RECENT": 0.95,
            "HISTORICAL": 0.90,
            "STALE": 0.65,
            "FUTURE_CANDIDATE": 0.55,
            "UNKNOWN": 0.75,
        }.get(temporal_state, 0.75)

        entity_conf = float(e.get("entity_resolution_confidence", 0.5))
        entity_mult = 0.55 + 0.45 * entity_conf

        alt_penalty = 1.0
        if e.get("alternative_explanations"):
            if fam_count <= 1 and e.get("directness") not in {"DIRECTLY_OBSERVED", "DOCUMENTED"}:
                alt_penalty = 0.55
            else:
                alt_penalty = 0.80

        contradiction_penalty = float(e.get("contradiction_penalty", 1.0))

        base = 0.45 * direct_score + 0.35 * source_quality_score + 0.20 * indep_score
        score = base * temporal_mult * entity_mult * alt_penalty * contradiction_penalty

        bonus = min(0.08, 0.02 * max(0, fam_count - 1) + 0.005 * len(e.get("evidence_ids", [])))
        score = clamp(score + bonus)

        # Caps
        if e.get("directness") in {"INFERRED", "HYPOTHETICAL"}:
            score = min(score, 0.45)
        if e.get("verification_state") == "CANDIDATE":
            score = min(score, 0.65)
        if fam_count <= 1:
            score = min(score, 0.70)
        if entity_conf < 0.50:
            score = min(score, 0.60)
        if contradiction_penalty <= 0.35:
            score = min(score, 0.35)

        e["confidence_score"] = round(score, 4)
        if score >= 0.80:
            e["confidence_label"] = "HIGH"
            e["relationship_strength"] = "STRONG"
        elif score >= 0.60:
            e["confidence_label"] = "MODERATE"
            e["relationship_strength"] = "MODERATE"
        elif score >= 0.35:
            e["confidence_label"] = "LOW"
            e["relationship_strength"] = "WEAK"
        else:
            e["confidence_label"] = "VERY_LOW"
            e["relationship_strength"] = "UNKNOWN"

        e["in_fact_graph"] = (
            e.get("verification_state") in FACT_GRAPH_STATES
            and e.get("confidence_score", 0) >= 0.55
            and e.get("directness") not in {"HYPOTHETICAL"}
            and contradiction_penalty > 0.35
        )

        e.setdefault("limitations", []).extend([
            "Relationship strength is evidence-weighted, not proof of control, coordination, intent, or criminality.",
            "Historical relationships must not be automatically treated as current.",
        ])


# --------------------------------------------------------------------
# Network analysis
# --------------------------------------------------------------------

def build_adjacency(edges: List[Dict[str, Any]], directed: bool = True) -> Dict[str, List[Tuple[str, str]]]:
    adj: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    nodes = set()
    for e in edges:
        s, t = e["source_entity"], e["target_entity"]
        nodes.add(s)
        nodes.add(t)
        eid = e["edge_id"]
        adj[s].append((t, eid))
        if not directed or e.get("direction") in {"UNDIRECTED", "BIDIRECTIONAL"}:
            adj[t].append((s, eid))
    for n in nodes:
        adj.setdefault(n, [])
    return dict(adj)


def unique_neighbors(adj: Dict[str, List[Tuple[str, str]]]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for n, lst in adj.items():
        out[n] = sorted({m for m, _ in lst})
    return out


def connected_components(adj_unique: Dict[str, List[str]]) -> List[List[str]]:
    seen = set()
    comps = []
    for start in sorted(adj_unique):
        if start in seen:
            continue
        q = deque([start])
        comp = []
        seen.add(start)
        while q:
            n = q.popleft()
            comp.append(n)
            for m in adj_unique.get(n, []):
                if m not in seen:
                    seen.add(m)
                    q.append(m)
        comps.append(sorted(comp))
    return [c for c in comps if len(c) > 1] or comps


def degree_metrics(edges: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    nodes = set()
    outdeg: Counter = Counter()
    indeg: Counter = Counter()
    total: Counter = Counter()
    for e in edges:
        s, t = e["source_entity"], e["target_entity"]
        nodes.update([s, t])
        outdeg[s] += 1
        indeg[t] += 1
        total[s] += 1
        total[t] += 1
    return {
        n: {
            "out_degree": outdeg[n],
            "in_degree": indeg[n],
            "total_degree": total[n],
        }
        for n in sorted(nodes)
    }


def betweenness_centrality(adj_unique: Dict[str, List[str]]) -> Dict[str, float]:
    nodes = sorted(adj_unique)
    cb = dict.fromkeys(nodes, 0.0)
    for s in nodes:
        stack = []
        pred: Dict[str, List[str]] = {w: [] for w in nodes}
        sigma = dict.fromkeys(nodes, 0)
        sigma[s] = 1
        dist = dict.fromkeys(nodes, -1)
        dist[s] = 0
        q = deque([s])
        while q:
            v = q.popleft()
            stack.append(v)
            for w in adj_unique.get(v, []):
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    q.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        delta = dict.fromkeys(nodes, 0.0)
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                cb[w] += delta[w]

    n = len(nodes)
    norm = (n - 1) * (n - 2) if n > 2 else 0
    if norm:
        for k in cb:
            cb[k] = cb[k] / norm
    return {k: round(v, 6) for k, v in cb.items()}


def bridges_and_articulation(adj_unique: Dict[str, List[str]]) -> Dict[str, Any]:
    nodes = sorted(adj_unique)
    disc: Dict[str, int] = {}
    low: Dict[str, int] = {}
    parent: Dict[str, Optional[str]] = {}
    ap: Set[str] = set()
    bridges: List[Tuple[str, str]] = []
    timer = [0]

    def dfs(u: str) -> None:
        children = 0
        disc[u] = low[u] = timer[0]
        timer[0] += 1
        for v in adj_unique.get(u, []):
            if v not in disc:
                children += 1
                parent[v] = u
                dfs(v)
                low[u] = min(low[u], low[v])
                if parent[u] is None and children > 1:
                    ap.add(u)
                if parent[u] is not None and low[v] >= disc[u]:
                    ap.add(u)
                if low[v] > disc[u]:
                    bridges.append(tuple(sorted([u, v])))
            elif v != parent[u]:
                low[u] = min(low[u], disc[v])

    parent.update({n: None for n in nodes})
    for n in nodes:
        if n not in disc:
            dfs(n)

    return {
        "articulation_points": sorted(ap),
        "bridges": sorted(set(bridges)),
        "interpretation_limitation": "Structural resilience signal only. Do not convert to attack targeting or sabotage planning.",
    }


def label_prop_communities(adj_unique: Dict[str, List[str]], max_iter: int = 20) -> List[List[str]]:
    nodes = sorted(adj_unique)
    if not nodes:
        return []
    labels = {n: n for n in nodes}
    for _ in range(max_iter):
        changed = False
        for n in nodes:
            neigh = adj_unique.get(n, [])
            if not neigh:
                continue
            counts = Counter(labels[m] for m in neigh)
            if not counts:
                continue
            mx = max(counts.values())
            candidates = sorted([lab for lab, c in counts.items() if c == mx])
            new_label = candidates[0]
            if new_label != labels[n]:
                labels[n] = new_label
                changed = True
        if not changed:
            break
    groups: Dict[str, List[str]] = defaultdict(list)
    for n in nodes:
        groups[labels[n]].append(n)
    return [sorted(v) for v in groups.values() if len(v) > 1]


def bfs_shortest_path(start: str, target: str, adj_unique: Dict[str, List[str]]) -> Optional[List[str]]:
    if start == target:
        return [start]
    if start not in adj_unique or target not in adj_unique:
        return None
    q = deque([start])
    prev: Dict[str, Optional[str]] = {start: None}
    while q:
        n = q.popleft()
        for m in adj_unique.get(n, []):
            if m not in prev:
                prev[m] = n
                if m == target:
                    path = []
                    cur: Optional[str] = m
                    while cur is not None:
                        path.append(cur)
                        cur = prev[cur]
                    return list(reversed(path))
                q.append(m)
    return None


def build_weighted_adj(edges: List[Dict[str, Any]]) -> Dict[str, List[Tuple[str, str, float]]]:
    adj: Dict[str, List[Tuple[str, str, float]]] = defaultdict(list)
    best: Dict[Tuple[str, str], Tuple[str, float]] = {}
    for e in edges:
        s, t = e["source_entity"], e["target_entity"]
        conf = float(e.get("confidence_score", 0.0))
        for a, b in ((s, t), (t, s)):
            key = (a, b)
            old = best.get(key)
            if old is None or conf > old[1]:
                best[key] = (e["edge_id"], conf)
    for (a, b), (eid, conf) in best.items():
        adj[a].append((b, eid, conf))
    return dict(adj)


def strongest_path(start: str, target: str, weighted_adj: Dict[str, List[Tuple[str, str, float]]]) -> Optional[Dict[str, Any]]:
    if start == target:
        return {"nodes": [start], "edges": [], "min_confidence": 1.0}
    if start not in weighted_adj or target not in weighted_adj:
        return None

    # Maximize minimum edge confidence.
    best = {n: -1.0 for n in weighted_adj}
    best[start] = 1.0
    prev: Dict[str, Tuple[Optional[str], Optional[str]]] = {start: (None, None)}
    heap = [(-1.0, start)]  # min-heap on negative confidence

    while heap:
        neg_conf, u = heapq.heappop(heap)
        conf_u = -neg_conf
        if conf_u < best[u]:
            continue
        if u == target:
            break
        for v, eid, edge_conf in weighted_adj.get(u, []):
            new_conf = min(conf_u, edge_conf)
            if new_conf > best.get(v, -1.0):
                best[v] = new_conf
                prev[v] = (u, eid)
                heapq.heappush(heap, (-new_conf, v))

    if best.get(target, -1.0) < 0:
        return None

    nodes = []
    edges = []
    cur = target
    while cur is not None:
        nodes.append(cur)
        p, eid = prev[cur]
        if eid:
            edges.append(eid)
        cur = p
    nodes.reverse()
    edges.reverse()
    return {
        "nodes": nodes,
        "edges": edges,
        "min_confidence": round(best[target], 4),
        "hop_count": len(edges),
    }


def edge_valid_at(edge: Dict[str, Any], t: datetime) -> bool:
    start, end = edge_interval(edge)
    if start and t < start:
        return False
    if end and t > end:
        return False
    return True


def temporal_path_assessment(path_edges: List[Dict[str, Any]], as_of: datetime) -> Dict[str, Any]:
    if not path_edges:
        return {"state": "EMPTY_PATH", "common_interval": None}

    starts = [edge_interval(e)[0] for e in path_edges]
    ends = [edge_interval(e)[1] for e in path_edges]
    valid_starts = [s for s in starts if s is not None]
    valid_ends = [e for e in ends if e is not None]

    common_start = max(valid_starts) if valid_starts else None
    common_end = min(valid_ends) if valid_ends else None

    if common_start and common_end and common_start > common_end:
        return {"state": "NOT_SIMULTANEOUS", "common_interval": None}

    all_valid_at_as_of = all(edge_valid_at(e, as_of) for e in path_edges)
    if all_valid_at_as_of:
        return {
            "state": "VALID_AT_AS_OF",
            "common_interval": {"from": time_iso(common_start), "to": time_iso(common_end)},
        }

    if common_start is None and common_end is None:
        return {"state": "TEMPORAL_UNKNOWN", "common_interval": None}

    return {
        "state": "TEMPORALLY_COMPATIBLE_BUT_NOT_ALL_VALID_AT_AS_OF",
        "common_interval": {"from": time_iso(common_start), "to": time_iso(common_end)},
    }


def analyze_network(fact_edges: List[Dict[str, Any]], target_pairs: List[List[str]], as_of: datetime) -> Dict[str, Any]:
    adj_dir = build_adjacency(fact_edges, directed=True)
    adj_und = build_adjacency(fact_edges, directed=False)
    adj_und_unique = unique_neighbors(adj_und)
    weighted_adj = build_weighted_adj(fact_edges)
    edge_by_id = {e["edge_id"]: e for e in fact_edges}

    components = connected_components(adj_und_unique)
    degrees = degree_metrics(fact_edges)
    betweenness = betweenness_centrality(adj_und_unique)
    structural = bridges_and_articulation(adj_und_unique)
    communities = label_prop_communities(adj_und_unique)

    paths = []
    for pair in target_pairs or []:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        a, b = normalize_text(pair[0]), normalize_text(pair[1])
        sp = bfs_shortest_path(a, b, adj_und_unique)
        st = strongest_path(a, b, weighted_adj)
        path_obj = {
            "source": a,
            "target": b,
            "shortest_path_nodes": sp,
            "shortest_hop_count": len(sp) - 1 if sp else None,
            "strongest_supported_path": st,
        }
        if st and st.get("edges"):
            p_edges = [edge_by_id[eid] for eid in st["edges"] if eid in edge_by_id]
            path_obj["temporal_path_assessment"] = temporal_path_assessment(p_edges, as_of)
            path_obj["path_edge_types"] = [e["relationship_type"] for e in p_edges]
            path_obj["path_limitations"] = [
                "A graph path is a sequence of relationships, not a single direct relationship.",
                "Path confidence is bounded by weakest material edge.",
                "Do not interpret path as control, coordination, conspiracy, or criminality.",
            ]
        paths.append(path_obj)

    return {
        "node_count": len(adj_und_unique),
        "fact_edge_count": len(fact_edges),
        "connected_components": components[:100],
        "degree_metrics": {k: v for k, v in list(degrees.items())[:500]},
        "betweenness_centrality": {k: v for k, v in sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:200]},
        "structural_resilience": structural,
        "communities": communities[:100],
        "paths": paths[:100],
        "interpretation_limits": [
            "Centrality is structure, not power, authority, leadership, or criminality.",
            "Communities are network candidates, not organizations, families, campaigns, or conspiracies.",
            "Bridges/articulation points are structural dependencies, not attack targets.",
            "Paths are evidence sequences, not direct relationships.",
        ],
    }


# --------------------------------------------------------------------
# Hypotheses / dual-AI / graph memory / outputs
# --------------------------------------------------------------------

def generate_hypotheses(edges: List[Dict[str, Any]], candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hyp = []
    for e in edges + candidates:
        rt = e.get("relationship_type", "UNKNOWN")
        pair = [e.get("source_entity"), e.get("target_entity")]
        state = e.get("verification_state", "UNKNOWN")
        direct = e.get("directness", "UNKNOWN")

        hyp.append({
            "hypothesis_id": stable_id("HYP", e.get("edge_id", e.get("relationship_id", "x")), "exists"),
            "edge_id": e.get("edge_id"),
            "entities": pair,
            "statement": f"A {rt} relationship exists between {pair[0]} and {pair[1]}.",
            "support": [
                f"verification_state={state}",
                f"directness={direct}",
                f"independent_source_families={e.get('independent_source_family_count', 0)}",
            ],
            "opposition": e.get("contradictions", []) + e.get("alternative_explanations", [])[:5],
            "unknowns": [
                "Whether relationship is current or historical.",
                "Whether sources are truly independent.",
                "Whether entity resolution is correct.",
            ],
            "falsification_conditions": [
                "Authoritative record refutes relationship.",
                "Temporal windows are incompatible.",
                "Link is fully explained by shared provider/virtual office/event coincidence.",
                "Entity merge was incorrect.",
            ],
            "status": state,
        })

        if rt in CONTROL_OR_COORDINATION_TYPES or any("control" in str(x).lower() or "coordination" in str(x).lower() for x in e.get("alternative_explanations", [])):
            hyp.append({
                "hypothesis_id": stable_id("HYP", e.get("edge_id", "x"), "alt_shared_resource"),
                "edge_id": e.get("edge_id"),
                "entities": pair,
                "statement": "Apparent link may be explained by shared resource, provider, platform, event, or institutional address rather than direct relationship.",
                "support": e.get("alternative_explanations", [])[:5],
                "opposition": [f"directness={direct}", f"sources={e.get('raw_source_count', 0)}"],
                "unknowns": ["Upstream provider/resource ownership", "Independent corroborating evidence"],
                "falsification_conditions": [
                    "Independent authoritative records show direct relationship.",
                    "Shared-resource explanation is technically impossible.",
                ],
                "status": "CANDIDATE",
            })

    return hyp[:500]


def dual_ai_review_stub(edges: List[Dict[str, Any]], candidates: List[Dict[str, Any]], network: Dict[str, Any]) -> Dict[str, Any]:
    review = {
        "status": "INSUFFICIENT_EVIDENCE",
        "primary_conclusions": [],
        "skeptic_challenges": [],
        "comparison": "NO_SECOND_MODEL_CONFIGURED",
        "notes": [
            "This starter does not call an independent second model.",
            "AI agreement is not independent relationship evidence.",
            "Human review is required for consequential association/control/coordination claims.",
        ],
    }
    for e in edges[:100]:
        if e.get("in_fact_graph"):
            review["primary_conclusions"].append(f"{e.get('edge_id')}: fact-graph candidate edge.")
            review["skeptic_challenges"].append("Check source independence, temporal validity, entity resolution, and alternative shared-resource explanations.")
        if e.get("relationship_type") in CONTROL_OR_COORDINATION_TYPES:
            review["primary_conclusions"].append(f"{e.get('edge_id')}: control/coordination-type edge present.")
            review["skeptic_challenges"].append("Control/coordination requires stronger evidence than association or communication frequency.")
    for c in candidates[:50]:
        review["primary_conclusions"].append(f"{c.get('edge_id')}: analytical candidate link.")
        review["skeptic_challenges"].append("Candidate link must not be promoted to fact graph without independent evidence.")
    if network.get("communities"):
        review["primary_conclusions"].append("Network communities detected.")
        review["skeptic_challenges"].append("Communities are structural candidates, not organizations, campaigns, families, or conspiracies.")
    if review["primary_conclusions"]:
        review["status"] = "PARTIAL_AGREEMENT"
    return review


class GraphMemory:
    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self._node_ids: Set[str] = set()

    def add_node(self, node_type: str, node_id: str, properties: Optional[Dict[str, Any]] = None) -> None:
        if node_id in self._node_ids:
            return
        self._node_ids.add(node_id)
        self.nodes.append({"type": node_type, "id": node_id, "properties": properties or {}})

    def add_edge(self, from_id: str, to_id: str, edge_type: str, properties: Optional[Dict[str, Any]] = None) -> None:
        self.edges.append({
            "from": from_id,
            "to": to_id,
            "type": edge_type,
            "properties": properties or {},
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes[:2000],
            "edges": self.edges[:4000],
            "note": "Fact graph and analytical graph are separated by edge properties. No edge exists without provenance fields where available.",
        }


def build_graph_memory(
    entities: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> GraphMemory:
    g = GraphMemory()

    for ent in entities.values():
        g.add_node("Entity", ent["entity_id"], {
            "entity_type": ent.get("entity_type"),
            "canonical_name": ent.get("canonical_name"),
            "resolution_state": ent.get("resolution_state"),
            "confidence_score": ent.get("confidence_score"),
        })

    for e in edges:
        g.add_edge(e["source_entity"], e["target_entity"], e["relationship_type"], {
            "edge_id": e["edge_id"],
            "graph_layer": "FACT_GRAPH" if e.get("in_fact_graph") else "ANALYTICAL_GRAPH",
            "direction": e.get("direction"),
            "directness": e.get("directness"),
            "verification_state": e.get("verification_state"),
            "temporal_state": e.get("temporal_state"),
            "confidence_score": e.get("confidence_score"),
            "raw_source_count": e.get("raw_source_count"),
            "independent_source_family_count": e.get("independent_source_family_count"),
            "source_independence_state": e.get("source_independence_state"),
            "limitations": e.get("limitations", [])[:5],
        })

    for c in candidates:
        g.add_edge(c["source_entity"], c["target_entity"], c["relationship_type"], {
            "edge_id": c["edge_id"],
            "graph_layer": "ANALYTICAL_GRAPH",
            "verification_state": "CANDIDATE",
            "directness": c.get("directness"),
            "limitations": c.get("limitations", [])[:5],
        })

    for h in hypotheses[:500]:
        g.add_node("Hypothesis", h["hypothesis_id"], {
            "statement": h["statement"],
            "status": h["status"],
            "edge_id": h.get("edge_id"),
        })

    for c in contradictions[:500]:
        g.add_node("Contradiction", c["contradiction_id"], {
            "type": c["type"],
            "severity": c["severity"],
            "entities": c.get("entities"),
        })

    for gap in gaps[:500]:
        g.add_node("Gap", gap["gap_id"], {
            "type": gap["type"],
            "importance": gap["importance"],
        })

    return g


def build_observations(entities: Dict[str, Any], edges: List[Dict[str, Any]], candidates: List[Dict[str, Any]], network: Dict[str, Any]) -> List[str]:
    obs = []
    obs.append(f"Entities ingested: {len(entities)}.")
    obs.append(f"Provided/merged relationship edges: {len(edges)}.")
    obs.append(f"Fact-graph edges: {sum(1 for e in edges if e.get('in_fact_graph'))}.")
    obs.append(f"Analytical candidate edges: {len(candidates)}.")
    if any(e.get("source_independence_state") == "DEPENDENT" for e in edges):
        obs.append("Some edges rely on dependent sources; multiple copied reports are not independent corroboration.")
    if any(e.get("temporal_state") in {"HISTORICAL", "STALE"} for e in edges):
        obs.append("Historical/stale relationships detected; do not automatically treat as current.")
    if any(e.get("alternative_explanations") for e in edges):
        obs.append("Alternative benign explanations detected for some edges, including shared infrastructure/address/event/platform effects.")
    if network.get("communities"):
        obs.append("Network communities detected as structural candidates only.")
    obs.append("No guilt-by-association, private tracking, biometric identification, attack targeting, or sensitive-status inference was performed.")
    return obs


def build_unknowns(edges: List[Dict[str, Any]], candidates: List[Dict[str, Any]], contradictions: List[Dict[str, Any]]) -> List[str]:
    unknowns = []
    for e in edges:
        if e.get("verification_state") in {"UNKNOWN", "CANDIDATE", "DISPUTED"}:
            unknowns.append(f"Edge {e['edge_id']} verification state unresolved: {e.get('verification_state')}.")
        if e.get("temporal_state") == "UNKNOWN":
            unknowns.append(f"Edge {e['edge_id']} temporal state unknown.")
        if e.get("direction") == "UNKNOWN":
            unknowns.append(f"Edge {e['edge_id']} direction unresolved.")
    for c in candidates[:100]:
        unknowns.append(f"Candidate link {c['edge_id']} requires verification before any relationship claim.")
    for ctr in contradictions[:100]:
        unknowns.append(f"Contradiction {ctr['contradiction_id']} unresolved: {ctr['type']}.")
    return list(dict.fromkeys(unknowns))[:500]


def build_gaps(entities: Dict[str, Any], edges: List[Dict[str, Any]], candidates: List[Dict[str, Any]], contradictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    gaps = []
    for ent in entities.values():
        if ent.get("resolution_state") in {"UNRESOLVED", "DISPUTED"} or float(ent.get("confidence_score", 0)) < 0.55:
            gaps.append({
                "gap_id": stable_id("GAP", "entity", ent["entity_id"]),
                "type": "ENTITY_RESOLUTION_INCOMPLETE",
                "importance": "HIGH",
                "entity_id": ent["entity_id"],
                "recommended_source": "Authoritative registry, official organization record, authorized identity directory, or independent primary source.",
                "specialist": "IDENTITYINT / CORPINT / ORGINT",
                "expected_information_value": "Prevent false node merges and uncertain downstream edges.",
            })

    for e in edges:
        if e.get("source_independence_state") in {"DEPENDENT", "UNKNOWN"} and e.get("confidence_score", 0) >= 0.45:
            gaps.append({
                "gap_id": stable_id("GAP", "indep", e["edge_id"]),
                "type": "SOURCE_INDEPENDENCE_UNRESOLVED",
                "importance": "HIGH",
                "edge_id": e["edge_id"],
                "recommended_source": "Upstream source lineage, independent official record, or original primary evidence.",
                "specialist": "RELATIONSHIPINT / DOCINT / WEBINT",
                "expected_information_value": "Prevent copied sources from inflating relationship confidence.",
            })
        if e.get("temporal_state") in {"UNKNOWN", "STALE", "HISTORICAL"}:
            gaps.append({
                "gap_id": stable_id("GAP", "temporal", e["edge_id"]),
                "type": "TEMPORAL_RELATIONSHIP_UNCLEAR",
                "importance": "MEDIUM" if e.get("temporal_state") != "UNKNOWN" else "HIGH",
                "edge_id": e["edge_id"],
                "recommended_source": "Effective dates, filing history, contract term, employment period, or observation timeline.",
                "specialist": "RELATIONSHIPINT / CORPINT / FININT",
                "expected_information_value": "Distinguish current, historical, stale, or future-candidate relationships.",
            })
        if e.get("relationship_type") in {"UNKNOWN", "RELATED_TO"}:
            gaps.append({
                "gap_id": stable_id("GAP", "type", e["edge_id"]),
                "type": "RELATIONSHIP_TYPE_UNRESOLVED",
                "importance": "MEDIUM",
                "edge_id": e["edge_id"],
                "recommended_source": "Primary document, filing, transaction record, communication metadata, or organizational chart.",
                "specialist": "RELATIONSHIPINT / DOCINT / COMINT",
                "expected_information_value": "Replace generic RELATED_TO with precise typed edge.",
            })
        if e.get("relationship_type") in CONTROL_OR_COORDINATION_TYPES:
            gaps.append({
                "gap_id": stable_id("GAP", "control", e["edge_id"]),
                "type": "CONTROL_OR_COORDINATION_INSUFFICIENT_EVIDENCE",
                "importance": "HIGH",
                "edge_id": e["edge_id"],
                "recommended_source": "Ownership filings, control agreements, board records, command infrastructure, synchronized independent evidence.",
                "specialist": "OWNERSHIPINT / CORPINT / CAMPAIGNINT / FRAUDINT",
                "expected_information_value": "Prevent association from being mistaken for control or coordination.",
            })

    for c in candidates[:200]:
        gaps.append({
            "gap_id": stable_id("GAP", "candidate", c["edge_id"]),
            "type": "CANDIDATE_LINK_UNVERIFIED",
            "importance": "MEDIUM",
            "edge_id": c["edge_id"],
            "recommended_source": "Independent primary evidence, authoritative record, or explicit documented relationship.",
            "specialist": "RELATIONSHIPINT",
            "expected_information_value": "Determine whether shared attribute/co-occurrence reflects real relationship.",
        })

    for ctr in contradictions[:200]:
        gaps.append({
            "gap_id": stable_id("GAP", "contradiction", ctr["contradiction_id"]),
            "type": "RELATIONSHIP_CONTRADICTION_UNRESOLVED",
            "importance": "HIGH",
            "contradiction_id": ctr["contradiction_id"],
            "recommended_source": "Authoritative original record, edit history, effective dates, or entity resolution review.",
            "specialist": "RELATIONSHIPINT / IDENTITYINT / HUMAN_REVIEW",
            "expected_information_value": "Resolve conflicting relationship assertions.",
        })

    return gaps[:500]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    priority_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for g in gaps:
        if g["type"] == "ENTITY_RESOLUTION_INCOMPLETE":
            action = "Resolve entity/node identity through authoritative records before relying on downstream edges."
        elif g["type"] == "SOURCE_INDEPENDENCE_UNRESOLVED":
            action = "Trace source pedigree and obtain at least one independent primary source."
        elif g["type"] == "TEMPORAL_RELATIONSHIP_UNCLEAR":
            action = "Retrieve effective/start/end dates and distinguish current vs historical relationship."
        elif g["type"] == "RELATIONSHIP_TYPE_UNRESOLVED":
            action = "Replace generic RELATED_TO with precise typed edge from primary evidence."
        elif g["type"] == "CONTROL_OR_COORDINATION_INSUFFICIENT_EVIDENCE":
            action = "Seek ownership/control/coordination-specific evidence; do not infer control from association."
        elif g["type"] == "CANDIDATE_LINK_UNVERIFIED":
            action = "Verify candidate shared-attribute/co-occurrence link with independent evidence before promotion."
        elif g["type"] == "RELATIONSHIP_CONTRADICTION_UNRESOLVED":
            action = "Resolve contradiction using authoritative original records and temporal context."
        else:
            action = "Gather additional authorized evidence."

        actions.append({
            "action": action,
            "gap_id": g["gap_id"],
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not contact target deceptively.",
                "Do not hack accounts or bypass privacy.",
                "Do not track private persons.",
                "Do not generate attack paths or target lists.",
                "Do not infer guilt, control, coordination, romance, religion, ethnicity, politics, health, or criminality from association alone.",
            ],
        })
    actions.sort(key=lambda x: priority_map.get(x.get("priority", "LOW"), 9))
    return actions[:200]


def build_handoffs(manifest: Dict[str, Any], edges: List[Dict[str, Any]], candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    blob = collect_manifest_text(manifest).lower()
    hands = []
    types = {e.get("relationship_type") for e in edges + candidates}

    def add(spec: str, reason: str) -> None:
        hands.append({
            "specialist": spec,
            "reason": reason,
            "payload": ["entity_ids", "edge_ids", "question", "time_range", "evidence_ids", "known_facts", "unknowns", "contradictions", "limitations"],
        })

    if types & {"DIRECTOR_OF", "OFFICER_OF", "SHAREHOLDER_OF", "PARENT_OF", "SUBSIDIARY_OF", "OWNS", "BENEFICIALLY_OWNS_CANDIDATE"} or "corporate" in blob:
        add("CORPINT / OWNERSHIPINT", "Corporate ownership/directorship/shareholder resolution required.")
    if types & {"EMPLOYED_BY", "FORMERLY_EMPLOYED_BY", "CONTRACTOR_TO", "ADVISOR_TO"} or "employment" in blob:
        add("ORGINT / HR authorized records", "Employment/role relationship verification required.")
    if types & {"TRANSFERRED_TO", "PAID", "RECEIVED_FROM", "INVESTED_IN", "FINANCIAL_TRANSACTION"} or "financial" in blob:
        add("FININT", "Financial transaction/payment relationship analysis required.")
    if types & {"SUPPLIER_TO", "VENDOR_TO", "CUSTOMER_OF", "SHIPPED_TO", "TRADE_RELATIONSHIP", "PROCUREMENT_RELATIONSHIP"} or "supply" in blob or "trade" in blob:
        add("TRADEINT / SUPPLYCHAININT / PROCUREMENTINT", "Trade, procurement, or supply-chain relationship analysis required.")
    if types & TECHNICAL_SHARED_TYPES or "infrastructure" in blob or "domain" in blob:
        add("INFRAINT / DOMAININT / NETINT / CERTINT", "Technical/infrastructure relationship verification required.")
    if types & {"COMMUNICATED_WITH", "EMAILED", "CALLED"} or "communication" in blob:
        add("COMINT / MESSENGERINT where authorized", "Communication relationship metadata/content analysis requires separate authorization.")
    if types & {"SOCIAL_CONNECTION", "FOLLOWS", "MENTIONED"} or "social" in blob:
        add("SOCMINT", "Public social connection context requires platform-aware analysis.")
    if types & CONTROL_OR_COORDINATION_TYPES or "campaign" in blob or "coordination" in blob:
        add("CAMPAIGNINT / NARRATIVEINT / FRAUDINT", "Coordination/campaign/control hypotheses require specialist evidence.")
    if any(e.get("relationship_type") == "INCIDENT_RELATIONSHIP" for e in edges) or "incident" in blob:
        add("INCIDENTINT / LOGINT", "Incident relationship telemetry review required.")
    return hands


# --------------------------------------------------------------------
# Result assembly
# --------------------------------------------------------------------

def empty_result(manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": manifest.get("case_id", "CASE-UNKNOWN"),
        "task_id": manifest.get("task_id", "TASK-UNKNOWN"),
        "objective": manifest.get("objective", ""),
        "questions": manifest.get("questions", []) or [],
        "generated_at": utc_now(),
        "version": VERSION,
        "source_ids": [],
        "evidence_ids": [],
        "entities": [],
        "entity_resolution_states": [],
        "relationships": [],
        "fact_graph_edges": [],
        "analytical_graph_edges": [],
        "candidate_relationships": [],
        "relationship_types": [],
        "relationship_directions": [],
        "relationship_states": [],
        "relationship_directness": [],
        "relationship_strength": [],
        "valid_from": [],
        "valid_to": [],
        "first_seen": [],
        "last_seen": [],
        "current_relationships": [],
        "historical_relationships": [],
        "shared_attributes": [],
        "co_occurrences": [],
        "communication_relationships": [],
        "organizational_relationships": [],
        "corporate_relationships": [],
        "ownership_context": [],
        "financial_relationships": [],
        "trade_relationships": [],
        "procurement_relationships": [],
        "supplier_relationships": [],
        "technical_relationships": [],
        "infrastructure_relationships": [],
        "event_relationships": [],
        "document_relationships": [],
        "account_relationships": [],
        "campaign_relationships": [],
        "source_pedigree": [],
        "source_independence": [],
        "edge_evidence_counts": [],
        "independent_source_counts": [],
        "network_analysis": {},
        "network_components": [],
        "communities": [],
        "bridges": [],
        "centrality_metrics": {},
        "strongest_paths": [],
        "temporal_paths": [],
        "predicted_relationships": [],
        "graph_diffs": [],
        "observations": [],
        "candidate_facts": [],
        "supported_facts": [],
        "partial_facts": [],
        "disputed_facts": [],
        "contradictions": [],
        "hypotheses": [],
        "falsification_results": [],
        "privacy_flags": [],
        "unknowns": [],
        "knowledge_gaps": [],
        "recommended_next_actions": [],
        "specialist_handoffs": [],
        "limitations": [],
        "dual_ai_review": {},
        "graph_memory": {},
        "status": "PARTIAL",
    }


def summarize_edge(e: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(e)
    # Do not expose raw evidence text in summary if sensitive; keep IDs/locators.
    out.pop("context", None)
    return out


def finalize_status(result: Dict[str, Any], entities: Dict[str, Any], edges: List[Dict[str, Any]], auth_ok: bool, policy_blocked: List[str]) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not entities:
        return "INSUFFICIENT_INPUT"
    if result.get("contradictions"):
        return "PARTIAL"
    if any(e.get("verification_state") in {"UNKNOWN", "CANDIDATE", "DISPUTED"} for e in edges):
        return "PARTIAL"
    if result.get("knowledge_gaps"):
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_relationship_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["privacy_flags"] = [{"type": label, "action": "PROHIBITED_REQUEST_NOT_PERFORMED"} for label in policy_blocked]
        result["limitations"] = [
            "RELATIONSHIPINT does not fabricate relationships, use guilt-by-association, stalk/track/dox, perform biometric identification, generate attack/targeting plans, or infer sensitive statuses from weak association."
        ]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    as_of = parse_time(manifest.get("as_of")) or datetime.now(timezone.utc)
    sources = ingest_sources(manifest)
    source_roots = build_source_roots(sources)
    entities = ingest_entities(manifest, sources)
    evidence = ingest_evidence(manifest, sources)

    raw_edges = ingest_relationships(manifest, entities, sources, evidence)
    edges = merge_edges(raw_edges)
    candidates = generate_candidate_edges(entities, evidence, edges)

    preliminary_enrich_edges(edges, entities, sources, source_roots, as_of)

    # Temporary global cache for textual fact gate.
    global entities_cache
    entities_cache = entities

    apply_fact_gate(edges, manifest.get("known_facts", []) or [])
    contradictions = detect_contradictions(edges)
    finalize_edge_scores(edges)

    fact_edges = [e for e in edges if e.get("in_fact_graph")]
    analytical_edges = [e for e in edges if not e.get("in_fact_graph")]
    network = analyze_network(fact_edges, manifest.get("target_pairs", []) or [], as_of)

    hypotheses = generate_hypotheses(edges, candidates)
    gaps = build_gaps(entities, edges, candidates, contradictions)
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(manifest, edges, candidates)
    dual_review = dual_ai_review_stub(edges, candidates, network)
    graph = build_graph_memory(entities, edges, candidates, hypotheses, contradictions, gaps)

    result["entities"] = list(entities.values())
    result["relationships"] = [summarize_edge(e) for e in edges]
    result["fact_graph_edges"] = [summarize_edge(e) for e in fact_edges]
    result["analytical_graph_edges"] = [summarize_edge(e) for e in analytical_edges]
    result["candidate_relationships"] = candidates
    result["predicted_relationships"] = [c for c in candidates if c.get("relationship_type") in {"SHARED_ATTRIBUTE_CANDIDATE", "CO_OCCURRENCE"}]
    result["contradictions"] = contradictions
    result["hypotheses"] = hypotheses
    result["falsification_results"] = [
        {
            "hypothesis_id": h["hypothesis_id"],
            "opposition": h.get("opposition"),
            "falsification_conditions": h.get("falsification_conditions"),
        }
        for h in hypotheses
    ]
    result["network_analysis"] = network
    result["network_components"] = network.get("connected_components", [])
    result["communities"] = network.get("communities", [])
    result["bridges"] = network.get("structural_resilience", {}).get("bridges", [])
    result["centrality_metrics"] = {
        "degree": network.get("degree_metrics", {}),
        "betweenness": network.get("betweenness_centrality", {}),
    }
    result["strongest_paths"] = [p.get("strongest_supported_path") for p in network.get("paths", []) if p.get("strongest_supported_path")]
    result["temporal_paths"] = [
        {
            "source": p.get("source"),
            "target": p.get("target"),
            "assessment": p.get("temporal_path_assessment"),
        }
        for p in network.get("paths", [])
        if p.get("temporal_path_assessment")
    ]
    result["observations"] = build_observations(entities, edges, candidates, network)
    result["unknowns"] = build_unknowns(edges, candidates, contradictions)
    result["knowledge_gaps"] = gaps
    result["recommended_next_actions"] = actions
    result["specialist_handoffs"] = handoffs
    result["dual_ai_review"] = dual_review
    result["graph_memory"] = graph.to_dict()

    for sid, src in sources.items():
        result["source_ids"].append(sid)
        result["source_pedigree"].append({
            "source_id": sid,
            "source_type": src.get("source_type"),
            "upstream_source_id": src.get("upstream_source_id"),
            "root_source_id": source_roots.get(sid, sid),
            "reliability": src.get("reliability"),
        })

    for evid in evidence.keys():
        result["evidence_ids"].append(evid)

    for ent in entities.values():
        result["entity_resolution_states"].append({
            "entity_id": ent["entity_id"],
            "entity_type": ent["entity_type"],
            "resolution_state": ent["resolution_state"],
            "confidence_score": ent["confidence_score"],
        })

    for e in edges:
        result["relationship_types"].append({"edge_id": e["edge_id"], "type": e["relationship_type"]})
        result["relationship_directions"].append({"edge_id": e["edge_id"], "direction": e["direction"]})
        result["relationship_states"].append({"edge_id": e["edge_id"], "verification_state": e["verification_state"], "temporal_state": e["temporal_state"]})
        result["relationship_directness"].append({"edge_id": e["edge_id"], "directness": e["directness"]})
        result["relationship_strength"].append({"edge_id": e["edge_id"], "strength": e.get("relationship_strength"), "confidence_score": e.get("confidence_score")})
        result["valid_from"].append({"edge_id": e["edge_id"], "valid_from": time_iso(e.get("valid_from"))})
        result["valid_to"].append({"edge_id": e["edge_id"], "valid_to": time_iso(e.get("valid_to"))})
        result["first_seen"].append({"edge_id": e["edge_id"], "first_seen": time_iso(e.get("first_seen"))})
        result["last_seen"].append({"edge_id": e["edge_id"], "last_seen": time_iso(e.get("last_seen"))})
        result["edge_evidence_counts"].append({"edge_id": e["edge_id"], "raw_source_count": e.get("raw_source_count"), "evidence_count": len(e.get("evidence_ids", []))})
        result["independent_source_counts"].append({"edge_id": e["edge_id"], "independent_source_family_count": e.get("independent_source_family_count"), "state": e.get("source_independence_state")})
        result["source_independence"].append({"edge_id": e["edge_id"], "state": e.get("source_independence_state")})

        if e.get("temporal_state") in {"CURRENT", "CURRENT_OR_RECENT"}:
            result["current_relationships"].append(e["edge_id"])
        if e.get("temporal_state") in {"HISTORICAL", "STALE"}:
            result["historical_relationships"].append(e["edge_id"])

        rt = e.get("relationship_type")
        if rt in {"COMMUNICATED_WITH", "EMAILED", "CALLED"}:
            result["communication_relationships"].append(e["edge_id"])
        if rt in {"EMPLOYED_BY", "FORMERLY_EMPLOYED_BY", "CONTRACTOR_TO", "ADVISOR_TO", "MEMBER_OF", "HOLDS_ROLE"}:
            result["organizational_relationships"].append(e["edge_id"])
        if rt in {"DIRECTOR_OF", "OFFICER_OF", "SHAREHOLDER_OF", "OWNS", "PARENT_OF", "SUBSIDIARY_OF", "PARTNERSHIP", "JOINT_VENTURE"}:
            result["corporate_relationships"].append(e["edge_id"])
        if rt in {"OWNS", "BENEFICIALLY_OWNS_CANDIDATE", "CONTROLS_CANDIDATE", "SHAREHOLDER_OF"}:
            result["ownership_context"].append(e["edge_id"])
        if rt in {"FINANCIAL_TRANSACTION", "TRANSFERRED_TO", "PAID", "RECEIVED_FROM", "LENT_TO", "BORROWED_FROM", "INVESTED_IN"}:
            result["financial_relationships"].append(e["edge_id"])
        if rt in {"TRADE_RELATIONSHIP", "SHIPPED_TO", "IMPORTS_FROM", "EXPORTS_TO", "SUPPLIES"}:
            result["trade_relationships"].append(e["edge_id"])
        if rt in {"PROCUREMENT_RELATIONSHIP", "BID_FOR", "AWARDED_TO", "CONTRACTED_WITH", "PROCURES_FROM"}:
            result["procurement_relationships"].append(e["edge_id"])
        if rt in {"VENDOR_TO", "SUPPLIER_TO", "CUSTOMER_OF", "SUBCONTRACTOR_TO", "SUPPLY_CHAIN_DEPENDENCY"}:
            result["supplier_relationships"].append(e["edge_id"])
        if rt in TECHNICAL_SHARED_TYPES:
            result["technical_relationships"].append(e["edge_id"])
            result["infrastructure_relationships"].append(e["edge_id"])
        if rt in {"ATTENDED", "ORGANIZED", "SPONSORED", "SPOKE_AT", "HOSTED", "INVITED_TO", "EVENT_COATTENDANCE"}:
            result["event_relationships"].append(e["edge_id"])
        if rt in {"AUTHORED", "SIGNED", "REFERENCED_IN", "MENTIONED_IN", "FILED_BY", "ISSUED_BY", "RECEIVED_BY", "DOCUMENT_ASSOCIATION"}:
            result["document_relationships"].append(e["edge_id"])
        if rt in {"USES_ACCOUNT", "ACCOUNT_ASSOCIATION"}:
            result["account_relationships"].append(e["edge_id"])
        if rt == "CAMPAIGN_RELATIONSHIP":
            result["campaign_relationships"].append(e["edge_id"])

        if e.get("verification_state") in {"VERIFIED", "SUPPORTED"}:
            result["supported_facts"].append({"edge_id": e["edge_id"], "statement": f"{e['source_entity']} {e['relationship_type']} {e['target_entity']}"})
        elif e.get("verification_state") == "PARTIALLY_SUPPORTED":
            result["partial_facts"].append({"edge_id": e["edge_id"], "statement": f"{e['source_entity']} {e['relationship_type']} {e['target_entity']}"})
        elif e.get("verification_state") == "DISPUTED":
            result["disputed_facts"].append({"edge_id": e["edge_id"], "statement": f"{e['source_entity']} {e['relationship_type']} {e['target_entity']}"})
        else:
            result["candidate_facts"].append({"edge_id": e["edge_id"], "statement": f"{e['source_entity']} {e['relationship_type']} {e['target_entity']}"})

    for c in candidates:
        if c.get("relationship_type") == "SHARED_ATTRIBUTE_CANDIDATE":
            result["shared_attributes"].append(c)
        if c.get("relationship_type") == "CO_OCCURRENCE":
            result["co_occurrences"].append(c)

    base_limits = [
        "RELATIONSHIPINT starter uses only provided/local authorized records; no external network lookup was performed.",
        "Shared attributes and co-occurrences are analytical candidates, not established relationships.",
        "Connection is not association, association is not coordination, coordination is not control, and relationship is not criminality.",
        "Centrality, communities, bridges, and paths are structural signals, not proof of power, conspiracy, targeting priority, or intent.",
        "Historical relationships must not be automatically treated as current.",
        "Dependent/copied sources are not independent corroboration.",
        "Entity-resolution uncertainty propagates into relationship confidence.",
        "No guilt-by-association, private tracking, doxxing, biometric identification, attack planning, or sensitive-status inference was performed.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

    result["status"] = finalize_status(result, entities, edges, auth_ok, policy_blocked)
    return result


# --------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------

def generate_report(result: Dict[str, Any]) -> str:
    lines = []
    lines.append("# RELATIONSHIPINT Evidence-Linked Report")
    lines.append("")
    lines.append(f"- Case ID: `{result.get('case_id')}`")
    lines.append(f"- Task ID: `{result.get('task_id')}`")
    lines.append(f"- Generated: `{result.get('generated_at')}`")
    lines.append(f"- Version: `{result.get('version')}`")
    lines.append(f"- Status: `{result.get('status')}`")
    lines.append("")

    if result.get("status") == "POLICY_BLOCKED":
        lines.append("## POLICY BLOCKED")
        lines.append("The request violated RELATIONSHIPINT hard restrictions:")
        for v in result.get("violations", []):
            lines.append(f"- `{v}`")
        lines.append("")
        lines.append("No relationship graph was constructed.")
        return "\n".join(lines)

    lines.append("## Objective")
    lines.append(str(result.get("objective", "")))
    lines.append("")

    lines.append("## Required Analyst Summary")
    entities = result.get("entities", [])
    edges = result.get("relationships", [])
    fact_edges = result.get("fact_graph_edges", [])
    candidates = result.get("candidate_relationships", [])
    network = result.get("network_analysis", {})
    lines.append(f"- ENTITIES: {len(entities)}")
    lines.append(f"- PROVIDED/MERGED EDGES: {len(edges)}")
    lines.append(f"- FACT-GRAPH EDGES: {len(fact_edges)}")
    lines.append(f"- ANALYTICAL CANDIDATE EDGES: {len(candidates)}")
    lines.append(f"- CONTRADICTIONS: {len(result.get('contradictions', []))}")
    lines.append(f"- NETWORK COMPONENTS: {len(network.get('connected_components', []))}")
    lines.append(f"- COMMUNITY CANDIDATES: {len(network.get('communities', []))}")
    lines.append(f"- BRIDGES: {len(network.get('structural_resilience', {}).get('bridges', []))}")
    lines.append(f"- ARTICULATION POINTS: {len(network.get('structural_resilience', {}).get('articulation_points', []))}")
    lines.append(f"- UNKNOWN ITEMS: {len(result.get('unknowns', []))}")
    lines.append("- NEXT ACTION: " + (result.get("recommended_next_actions", [{}])[0].get("action", "None") if result.get("recommended_next_actions") else "None"))
    lines.append("")

    lines.append("## Privacy / Relationship Boundaries")
    lines.append("- Connection ≠ association ≠ coordination ≠ control ≠ criminality.")
    lines.append("- Shared IP/ASN/hosting/nameserver/registrar/certificate/address/event are candidate links only.")
    lines.append("- Centrality is structure, not power or authority.")
    lines.append("- Communities are structural candidates, not conspiracies, organizations, families, or threat groups.")
    lines.append("- Paths are evidence sequences, not direct relationships or attack paths.")
    lines.append("- No stalking, tracking, doxxing, biometric identification, target listing, sabotage planning, or sensitive-status inference was performed.")
    lines.append("")

    lines.append("## Entity Inventory")
    for ent in entities[:200]:
        lines.append(f"### `{ent.get('entity_id')}` — {ent.get('canonical_name')}")
        lines.append(f"- Type: `{ent.get('entity_type')}`")
        lines.append(f"- Resolution state: `{ent.get('resolution_state')}` confidence=`{ent.get('confidence_score')}`")
        lines.append(f"- Aliases: {', '.join(ent.get('aliases', [])[:10]) or 'None'}")
        if ent.get("identifiers"):
            masked = {k: [mask_value(v) for v in vals[:5]] for k, vals in ent["identifiers"].items()}
            lines.append(f"- Identifiers masked: `{json.dumps(masked, ensure_ascii=False)}`"[:700])
        lines.append("")

    lines.append("## Fact Graph Edges")
    for e in fact_edges[:200]:
        lines.append(f"### `{e.get('edge_id')}`")
        lines.append(f"- {e.get('source_entity')} --`{e.get('relationship_type')}`--> {e.get('target_entity')}")
        lines.append(f"- Direction: `{e.get('direction')}` | Directness: `{e.get('directness')}` | Verification: `{e.get('verification_state')}`")
        lines.append(f"- Temporal: `{e.get('temporal_state')}` valid_from=`{e.get('valid_from')}` valid_to=`{e.get('valid_to')}`")
        lines.append(f"- Strength: `{e.get('relationship_strength')}` confidence=`{e.get('confidence_score')}`")
        lines.append(f"- Sources: raw=`{e.get('raw_source_count')}` independent_families=`{e.get('independent_source_family_count')}` independence=`{e.get('source_independence_state')}`")
        if e.get("alternative_explanations"):
            lines.append("- Alternative explanations:")
            for alt in e["alternative_explanations"][:5]:
                lines.append(f"  - {alt}")
        if e.get("contradictions"):
            lines.append(f"- Contradiction flags: {', '.join(e['contradictions'][:5])}")
        lines.append("")

    lines.append("## Analytical / Candidate Edges")
    for e in (result.get("analytical_graph_edges", []) + candidates)[:300]:
        lines.append(f"- `{e.get('edge_id')}`: {e.get('source_entity')} ↔ {e.get('target_entity')} type=`{e.get('relationship_type')}` state=`{e.get('verification_state')}` directness=`{e.get('directness')}`")
        if e.get("shared_attributes"):
            lines.append(f"  - shared attributes: {json.dumps(e['shared_attributes'][:5], ensure_ascii=False)}"[:500])
        if e.get("limitations"):
            lines.append(f"  - limitation: {e['limitations'][0]}")
    lines.append("")

    lines.append("## Network Analysis")
    lines.append(f"- Node count: `{network.get('node_count')}`")
    lines.append(f"- Fact-edge count: `{network.get('fact_edge_count')}`")
    lines.append("")
    lines.append("### Connected Components")
    for comp in network.get("connected_components", [])[:50]:
        lines.append(f"- {', '.join(comp[:50])}")
    lines.append("")
    lines.append("### Community Candidates")
    for comm in network.get("communities", [])[:50]:
        lines.append(f"- {', '.join(comm[:50])}")
    lines.append("")
    lines.append("### Degree Metrics (top 50)")
    deg = network.get("degree_metrics", {})
    for n, d in sorted(deg.items(), key=lambda x: x[1].get("total_degree", 0), reverse=True)[:50]:
        lines.append(f"- `{n}`: in={d.get('in_degree')} out={d.get('out_degree')} total={d.get('total_degree')}")
    lines.append("")
    lines.append("### Betweenness Centrality (top 50)")
    bet = network.get("betweenness_centrality", {})
    for n, v in sorted(bet.items(), key=lambda x: x[1], reverse=True)[:50]:
        lines.append(f"- `{n}`: {v}")
    lines.append("")
    lines.append("### Structural Resilience")
    sr = network.get("structural_resilience", {})
    lines.append(f"- Articulation points: {', '.join(sr.get('articulation_points', [])[:100]) or 'None'}")
    lines.append(f"- Bridges: {json.dumps(sr.get('bridges', [])[:100], ensure_ascii=False)}")
    lines.append(f"- Limitation: {sr.get('interpretation_limitation')}")
    lines.append("")
    lines.append("### Paths")
    for p in network.get("paths", [])[:50]:
        lines.append(f"- {p.get('source')} → {p.get('target')}")
        lines.append(f"  - shortest_path_nodes: {p.get('shortest_path_nodes')}")
        lines.append(f"  - strongest_supported_path: {json.dumps(p.get('strongest_supported_path'), ensure_ascii=False)}"[:700])
        lines.append(f"  - temporal_path_assessment: {json.dumps(p.get('temporal_path_assessment'), ensure_ascii=False)}")
    lines.append("")

    lines.append("## Contradictions")
    for c in result.get("contradictions", [])[:200]:
        lines.append(f"- `{c.get('contradiction_id')}` [{c.get('severity')}] {c.get('type')}: entities={c.get('entities')} edges={c.get('edges')}")
        lines.append(f"  - {c.get('detail')}")
    lines.append("")

    lines.append("## Hypotheses")
    for h in result.get("hypotheses", [])[:200]:
        lines.append(f"- `{h.get('hypothesis_id')}` [{h.get('status')}]: {h.get('statement')}")
        if h.get("support"):
            lines.append(f"  - support: {'; '.join(map(str, h['support'][:5]))}")
        if h.get("opposition"):
            lines.append(f"  - opposition: {'; '.join(map(str, h['opposition'][:5]))}")
        if h.get("falsification_conditions"):
            lines.append(f"  - falsify if: {'; '.join(map(str, h['falsification_conditions'][:5]))}")
    lines.append("")

    lines.append("## Knowledge Gaps")
    for g in result.get("knowledge_gaps", [])[:200]:
        lines.append(f"- `{g.get('gap_id')}` [{g.get('importance')}] {g.get('type')}: {g.get('recommended_source')}")
    lines.append("")

    lines.append("## Recommended Next Actions")
    for a in result.get("recommended_next_actions", [])[:200]:
        lines.append(f"- [{a.get('priority')}] {a.get('action')}")
    lines.append("")

    lines.append("## Specialist Handoffs")
    for h in result.get("specialist_handoffs", []):
        lines.append(f"- {h.get('specialist')}: {h.get('reason')}")
    lines.append("")

    lines.append("## Dual-AI Review Stub")
    dr = result.get("dual_ai_review", {})
    lines.append(f"- Status: `{dr.get('status')}`")
    lines.append(f"- Comparison: `{dr.get('comparison')}`")
    for n in dr.get("notes", []):
        lines.append(f"- {n}")
    for c in dr.get("primary_conclusions", [])[:50]:
        lines.append(f"- Primary: {c}")
    for c in dr.get("skeptic_challenges", [])[:50]:
        lines.append(f"- Skeptic: {c}")
    lines.append("")

    lines.append("## Limitations")
    for lim in result.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    lines.append("## Non-Negotiable Boundary")
    lines.append("- Resolve nodes first.")
    lines.append("- Type every edge.")
    lines.append("- Direction matters.")
    lines.append("- Time-bound every edge.")
    lines.append("- Trace source and count independent source families, not URLs.")
    lines.append("- Keep fact graph separate from analytical graph.")
    lines.append("- Centrality is structure, not power.")
    lines.append("- Clusters are leads, not conspiracies.")
    lines.append("- Attribute control last, and only with strong independent evidence.")

    return "\n".join(lines)


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEATLAS RELATIONSHIPINT safe starter")
    parser.add_argument("--manifest", required=True, help="Path to RELATIONSHIPINT manifest JSON")
    parser.add_argument("--output", default="relationshipint_result.json", help="Output JSON path")
    parser.add_argument("--report", default="relationshipint_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR reading manifest: {exc}", file=sys.stderr)
        return 2

    result = analyze_relationship_manifest(manifest)

    Path(args.output).write_text(
        json.dumps(json_safe(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    Path(args.report).write_text(generate_report(result), encoding="utf-8")

    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



{
  "case_id": "REL-CASE-001",
  "task_id": "REL-TASK-001",
  "objective": "Analyze authorized corporate and communication relationships among provided entities, distinguish direct evidence from candidates, and assess network structure without guilt-by-association or private tracking.",
  "questions": [
    "Which relationships are directly evidenced?",
    "Which links are only shared-attribute candidates?",
    "Are any relationships historical rather than current?",
    "What network communities or bridges exist structurally?",
    "What contradictions or source-dependency issues exist?"
  ],
  "authorization": {
    "approved": True,
    "scope": "public_and_authorized_records",
    "model_mode": "LOCAL_ONLY",
    "cloud_approved": False
  },
  "as_of": "2026-10-09T00:00:00Z",
  "sources": [
    {
      "source_id": "S1",
      "source_type": "official_registry",
      "reliability": 0.95,
      "observed_at": "2025-07-01T00:00:00Z"
    },
    {
      "source_id": "S2",
      "source_type": "public_profile",
      "reliability": 0.45,
      "observed_at": "2026-01-10T00:00:00Z"
    },
    {
      "source_id": "S3",
      "source_type": "aggregator",
      "upstream_source_id": "S2",
      "reliability": 0.35,
      "observed_at": "2026-02-01T00:00:00Z"
    },
    {
      "source_id": "S4",
      "source_type": "authorized_communication_metadata",
      "reliability": 0.85,
      "observed_at": "2026-03-01T00:00:00Z"
    }
  ],
  "entities": [
    {
      "entity_id": "P1",
      "entity_type": "PERSON_CANDIDATE",
      "canonical_name": "Alex Kumar",
      "aliases": ["A. Kumar"],
      "identifiers": {
        "email": ["alex.kumar@example-org.com"],
        "domain": ["example-org.com"]
      },
      "resolution_state": "PROBABLE_SAME_ENTITY",
      "confidence": 0.70,
      "source_ids": ["S1"]
    },
    {
      "entity_id": "O1",
      "entity_type": "ORGANIZATION",
      "canonical_name": "Example Org",
      "identifiers": {
        "registration_number": ["REG-12345"],
        "domain": ["example-org.com"]
      },
      "resolution_state": "VERIFIED_SAME_ENTITY",
      "confidence": 0.90,
      "source_ids": ["S1"]
    },
    {
      "entity_id": "P2",
      "entity_type": "PERSON_CANDIDATE",
      "canonical_name": "Sam Patel",
      "identifiers": {
        "email": ["sam.patel@othercorp.example"],
        "address": ["100 Corporate Park Way, Suite 500"]
      },
      "resolution_state": "UNRESOLVED",
      "confidence": 0.45,
      "source_ids": ["S2"]
    },
    {
      "entity_id": "O2",
      "entity_type": "ORGANIZATION",
      "canonical_name": "OtherCorp",
      "identifiers": {
        "address": ["100 Corporate Park Way, Suite 500"],
        "domain": ["othercorp.example"]
      },
      "resolution_state": "PROBABLE_SAME_ENTITY",
      "confidence": 0.65,
      "source_ids": ["S2"]
    }
  ],
  "evidence": [
    {
      "evidence_id": "EV1",
      "source_id": "S1",
      "entity_ids": ["P1", "O1"],
      "locator": "registry/filing/2023-001/page-2",
      "text": "Official filing lists Alex Kumar as director of Example Org from 2023-02-01 to 2025-06-30."
    },
    {
      "evidence_id": "EV2",
      "source_id": "S4",
      "entity_ids": ["P1", "P2"],
      "locator": "authorized-email-metadata/thread-88",
      "text": "Authorized metadata shows bidirectional email traffic between P1 and P2 during 2026-01."
    }
  ],
  "relationships": [
    {
      "relationship_id": "R1",
      "source_entity": "P1",
      "target_entity": "O1",
      "relationship_type": "DIRECTOR_OF",
      "direction": "DIRECTED",
      "directness": "DOCUMENTED",
      "verification_state": "SUPPORTED",
      "valid_from": "2023-02-01T00:00:00Z",
      "valid_to": "2025-06-30T00:00:00Z",
      "source_ids": ["S1"],
      "evidence_ids": ["EV1"],
      "context": "Official corporate filing."
    },
    {
      "relationship_id": "R2",
      "source_entity": "P1",
      "target_entity": "P2",
      "relationship_type": "COMMUNICATED_WITH",
      "direction": "BIDIRECTIONAL",
      "directness": "SOURCE_REPORTED",
      "verification_state": "CANDIDATE",
      "valid_from": "2026-01-01T00:00:00Z",
      "valid_to": "2026-01-31T00:00:00Z",
      "source_ids": ["S4"],
      "evidence_ids": ["EV2"],
      "context": "Authorized communication metadata only; content not analyzed."
    },
    {
      "relationship_id": "R3",
      "source_entity": "P2",
      "target_entity": "O2",
      "relationship_type": "EMPLOYED_BY",
      "direction": "DIRECTED",
      "directness": "SOURCE_REPORTED",
      "verification_state": "CANDIDATE",
      "source_ids": ["S2", "S3"],
      "context": "Public profile and aggregator; aggregator derives from public profile."
    }
  ],
  "known_facts": [
    {
      "entity_ids": ["P1", "O1"],
      "relationship_type": "DIRECTOR_OF",
      "state": "SUPPORTED",
      "text": "Official registry confirms directorship period 2023-2025."
    }
  ],
  "target_pairs": [
    ["P1", "O2"],
    ["P1", "P2"]
  ]
}
