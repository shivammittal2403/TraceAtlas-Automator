#!/usr/bin/env python3
"""
TRACEATLAS IDENTITYINT — Safe Python Starter Implementation

Purpose:
  Evidence-first identity/entity resolution pipeline.

Hard boundaries enforced in code:
  - Does NOT perform doxxing or private-person tracking.
  - Does NOT perform face recognition, voiceprint matching, gait/iris/fingerprint identification.
  - Does NOT infer race, ethnicity, religion, sexual orientation, health, political belief, union membership, or sex life.
  - Does NOT access private accounts, credentials, or carrier/social platforms.
  - Does NOT make network requests.
  - Treats identifiers as pointers, not identities.
  - Treats account holder, account operator, persona, and legal person as separate layers.
  - Uses soft links before hard merges.
  - Preserves merge/split history and provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

VERSION = "0.1.0-identityint-safe-starter"

FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)

# --------------------------------------------------------------------
# Policy / privacy constants
# --------------------------------------------------------------------

SENSITIVE_KEYS = {
    "race",
    "ethnicity",
    "religion",
    "faith",
    "sexual_orientation",
    "sex_life",
    "health",
    "medical_condition",
    "disability",
    "political_belief",
    "political_affiliation",
    "union_membership",
    "biometric",
    "face",
    "facial",
    "voiceprint",
    "gait",
    "fingerprint",
    "iris",
    "dna",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(doxx|dox|expose\s+private\s+address|home\s+address)\b"), "DOXXING_OR_PRIVATE_ADDRESS_EXPOSURE"),
    (re.compile(r"(?i)\b(face\s+recognition|facial\s+match|face\s+search|biometric\s+identif)"), "BIOMETRIC_IDENTIFICATION_REQUEST"),
    (re.compile(r"(?i)\b(voiceprint|voice\s+identif|gait|iris|fingerprint)"), "BIOMETRIC_IDENTIFICATION_REQUEST"),
    (re.compile(r"(?i)\b(track|locate|stalk|surveil)\s+(person|individual|someone|user|target)"), "PRIVATE_TRACKING_REQUEST"),
    (re.compile(r"(?i)\b(infer|determine|detect|classify)\s+(religion|ethnicity|race|political\s+belief|sexual\s+orientation|health|medical\s+condition)"), "SENSITIVE_TRAIT_INFERENCE_REQUEST"),
    (re.compile(r"(?i)\b(credential\s+test|password\s+spray|social\s+engineering|contact\s+(target|person)|message\s+(target|person))\b"), "UNAUTHORIZED_CONTACT_OR_SOCIAL_ENGINEERING"),
]

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_identity_directory",
    "lawful_case_records",
    "provided_records_only",
}

SOURCE_RELIABILITY: Dict[str, float] = {
    "official_registry": 0.95,
    "authorized_identity_provider": 0.93,
    "government_record": 0.90,
    "authorized_hr_directory": 0.88,
    "court_record": 0.85,
    "official_org_page": 0.82,
    "official_filing": 0.80,
    "platform_verified": 0.70,
    "academic_publication": 0.60,
    "reputable_media": 0.55,
    "self_reported": 0.35,
    "public_profile": 0.35,
    "commercial_data_broker": 0.25,
    "forum": 0.20,
    "anonymous": 0.10,
    "unknown": 0.25,
}

HIGH_AUTHORITY_SOURCE_TYPES = {
    "official_registry",
    "authorized_identity_provider",
    "government_record",
    "authorized_hr_directory",
    "court_record",
    "official_org_page",
    "official_filing",
}

PERSON_LIKE = {"PERSON_CANDIDATE", "LEGAL_PERSON", "PERSONA", "UNKNOWN"}
ACCOUNT_LIKE = {"ACCOUNT", "PERSONA", "UNKNOWN"}
ORG_LIKE = {"ORGANIZATION", "LEGAL_ENTITY", "BRAND", "UNKNOWN"}
ROLE_LIKE = {"ROLE", "UNKNOWN"}

ROLE_BASED_EMAIL_LOCALS = {
    "admin", "support", "sales", "security", "info", "contact",
    "help", "noreply", "no-reply", "postmaster", "webmaster",
    "abuse", "hr", "billing", "accounts", "service", "team",
}

NAME_PREFIX_HONORIFICS = {
    "mr", "mrs", "ms", "miss", "dr", "prof", "professor",
    "sir", "madam", "capt", "col", "gen", "lt", "rev", "fr",
}

NAME_SUFFIXES = {
    "jr", "sr", "ii", "iii", "iv", "v",
    "phd", "md", "jd", "esq", "mba", "bsc", "msc", "ma", "ba",
}

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


def normalize_unicode(value: Any) -> str:
    if value is None:
        return ""
    s = unicodedata.normalize("NFKC", str(value))
    s = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", s)
    return s.strip()


def strip_accents(value: str) -> str:
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", value)
        if not unicodedata.combining(ch)
    )


def collapse_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip()
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
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None


def mask_email(email: Optional[str]) -> str:
    if not email or "@" not in email:
        return "[REDACTED_EMAIL]"
    local, domain = email.rsplit("@", 1)
    first = local[:1] if local else "*"
    return f"{first}***@{domain}"


def mask_phone(phone: Optional[str]) -> str:
    if not phone:
        return "[REDACTED_PHONE]"
    digits = re.sub(r"\D", "", phone)
    plus = "+" if phone.strip().startswith("+") else ""
    if len(digits) <= 5:
        return plus + "*" * len(digits)
    return plus + digits[:3] + "*" * (len(digits) - 5) + digits[-2:]


def mask_secret(value: Optional[str]) -> str:
    if not value:
        return "[EMPTY]"
    value = str(value)
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def display_identifier(kind: str, value: Optional[str]) -> str:
    if not value:
        return "[MISSING]"
    if kind == "email":
        return mask_email(value)
    if kind == "phone":
        return mask_phone(value)
    if kind in {"official_id", "registration_number", "account_id", "device_id", "session_id", "wallet_address", "payment_account_id"}:
        return mask_secret(value)
    return str(value)


# --------------------------------------------------------------------
# Policy / authorization
# --------------------------------------------------------------------

def policy_screen(manifest: Dict[str, Any]) -> List[str]:
    blob = " ".join([
        str(manifest.get("objective", "")),
        " ".join(str(q) for q in manifest.get("questions", []) or []),
    ])
    blocked = []
    for pat, label in PROHIBITED_PATTERNS:
        if pat.search(blob):
            blocked.append(label)
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
# Normalizers
# --------------------------------------------------------------------

def normalize_name(value: Any) -> Dict[str, Any]:
    raw = normalize_unicode(value)
    lowered = strip_accents(raw).lower()
    cleaned = re.sub(r"[^a-z0-9\s-]", " ", lowered)
    tokens = [t for t in cleaned.split() if t]

    while tokens and tokens[0] in NAME_PREFIX_HONORIFICS:
        tokens.pop(0)
    while tokens and tokens[-1] in NAME_SUFFIXES:
        tokens.pop()

    normalized = " ".join(tokens) if tokens else collapse_ws(lowered)
    sorted_tokens = " ".join(sorted(tokens)) if tokens else normalized
    initials = ".".join(t[0] for t in tokens) if tokens else ""

    return {
        "raw": raw,
        "normalized": normalized,
        "tokens": tokens,
        "sorted_tokens": sorted_tokens,
        "initials": initials,
        "limitations": [
            "Name normalization is heuristic and does not model all cultural name orders or transliterations.",
            "Same normalized name does not prove same person.",
        ],
    }


def normalize_email(value: Any) -> Dict[str, Any]:
    raw = normalize_unicode(value).strip().strip("<>")
    if raw.lower().startswith("mailto:"):
        raw = raw[7:]

    if "@" not in raw:
        return {
            "raw": str(value),
            "normalized": None,
            "local": None,
            "domain": None,
            "base_local": None,
            "role_based": False,
            "valid": False,
            "limitations": ["Invalid email format."],
        }

    local, domain = raw.rsplit("@", 1)
    domain = domain.lower().strip(".")
    local_casefold = local.casefold()
    base_local = local_casefold.split("+", 1)[0]
    normalized = f"{base_local}@{domain}"
    role_based = base_local in ROLE_BASED_EMAIL_LOCALS

    return {
        "raw": str(value),
        "normalized": normalized,
        "local": local_casefold,
        "base_local": base_local,
        "domain": domain,
        "role_based": role_based,
        "valid": bool(domain and "." in domain),
        "limitations": [
            "Email local-part case sensitivity and provider aliasing are not fully modeled.",
            "Role-based/shared mailboxes may have multiple operators.",
            "Email aliasing may indicate same mailbox but not same human identity.",
        ],
    }


def normalize_phone(value: Any, country_hint: Optional[str] = None) -> Dict[str, Any]:
    raw = normalize_unicode(value)
    has_plus = raw.startswith("+")
    digits = re.sub(r"\D", "", raw)

    if raw.startswith("00"):
        normalized_e164 = "+" + digits[2:]
    elif has_plus:
        normalized_e164 = "+" + digits
    elif country_hint:
        cc = str(country_hint).lstrip("+")
        normalized_e164 = f"+{cc}{digits}"
    else:
        normalized_e164 = None

    ambiguous = normalized_e164 is None

    return {
        "raw": raw,
        "normalized_e164": normalized_e164,
        "normalized_digits": digits,
        "ambiguous_without_country": ambiguous,
        "country_hint": country_hint,
        "limitations": [
            "Phone number is not permanent identity proof.",
            "Numbers can be reassigned, shared, VoIP, business-owned, forwarded, or spoofed.",
            "Without country context, normalization may be ambiguous.",
        ],
    }


def normalize_username(value: Any) -> Dict[str, Any]:
    raw = normalize_unicode(value)
    cleaned = raw.lstrip("@").strip()
    normalized = strip_accents(cleaned).casefold()
    return {
        "raw": raw,
        "normalized": normalized,
        "limitations": [
            "Username reuse can occur across platforms, people, bots, brands, or recycled accounts.",
            "Same username alone is weak identity evidence.",
        ],
    }


def normalize_domain(value: Any) -> Dict[str, Any]:
    raw = normalize_unicode(value)
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.netloc or parsed.path
    host = host.split("/")[0].lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return {
        "raw": raw,
        "normalized": host,
        "limitations": [
            "Domain ownership/control changes over time.",
            "Domain may belong to company, brand, agency, privacy proxy, reseller, or hosting customer.",
        ],
    }


def normalize_identifier(value: Any) -> Dict[str, Any]:
    raw = normalize_unicode(value)
    normalized = raw.strip()
    return {
        "raw": raw,
        "normalized": normalized,
        "limitations": [
            "Identifier format may be platform-, organization-, or jurisdiction-specific.",
            "Identifier match supports candidate linkage, not automatic human identity.",
        ],
    }


def normalize_attributes(attrs_raw: Dict[str, Any], country_hint: Optional[str] = None) -> Tuple[Dict[str, Any], List[str]]:
    attrs: Dict[str, Any] = {}
    privacy_flags: List[str] = []

    for key, value in attrs_raw.items():
        lk = str(key).lower()
        if lk in SENSITIVE_KEYS:
            privacy_flags.append(f"SENSITIVE_ATTRIBUTE_REMOVED:{lk}")
            continue

        if value is None or str(value).strip() == "":
            continue

        if lk == "name":
            attrs["name"] = normalize_name(value)
        elif lk == "username":
            attrs["username"] = normalize_username(value)
        elif lk == "email":
            attrs["email"] = normalize_email(value)
        elif lk == "phone":
            attrs["phone"] = normalize_phone(value, country_hint)
        elif lk == "domain":
            attrs["domain"] = normalize_domain(value)
        elif lk == "organization":
            attrs["organization"] = normalize_name(value)
        elif lk == "role":
            attrs["role"] = normalize_name(value)
        elif lk in {
            "account_id", "official_id", "registration_number",
            "device_id", "session_id", "wallet_address", "payment_account_id",
        }:
            attrs[lk] = normalize_identifier(value)
        else:
            attrs[lk] = {"raw": normalize_unicode(value), "normalized": normalize_unicode(value)}

    return attrs, privacy_flags


# --------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------

def ingest_reference(ref: Dict[str, Any], idx: int, default_country: Optional[str] = None) -> Dict[str, Any]:
    reference_id = str(ref.get("reference_id") or f"REF-{idx}")
    entity_type = str(ref.get("entity_type") or "UNKNOWN").upper()
    attrs_raw = dict(ref.get("attributes") or {})
    source = dict(ref.get("source") or {})

    country_hint = ref.get("country_hint") or source.get("country_hint") or default_country
    attrs, privacy_flags = normalize_attributes(attrs_raw, country_hint)

    source_id = str(source.get("source_id") or f"SRC-{reference_id}")
    source_type = str(source.get("source_type") or "unknown").lower()
    upstream_source_id = source.get("upstream_source_id")

    reliability = source.get("reliability")
    if reliability is None:
        reliability = SOURCE_RELIABILITY.get(source_type, SOURCE_RELIABILITY["unknown"])
    reliability = max(0.0, min(1.0, float(reliability)))

    observed_at = parse_time(source.get("observed_at") or ref.get("observed_at"))
    valid_from = parse_time(source.get("valid_from") or ref.get("valid_from"))
    valid_to = parse_time(source.get("valid_to") or ref.get("valid_to"))

    raw_label = (
        ref.get("canonical_label")
        or attrs_raw.get("name")
        or attrs_raw.get("username")
        or attrs_raw.get("email")
        or attrs_raw.get("account_id")
        or attrs_raw.get("organization")
        or reference_id
    )

    record_id = stable_id("REC", reference_id, entity_type, json_safe(attrs_raw), source_id)

    return {
        "record_id": record_id,
        "reference_id": reference_id,
        "entity_type": entity_type,
        "raw_label": normalize_unicode(raw_label),
        "attributes": attrs,
        "source": {
            "source_id": source_id,
            "source_type": source_type,
            "upstream_source_id": upstream_source_id,
            "url": source.get("url"),
            "reliability": round(reliability, 3),
        },
        "observed_at": observed_at,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "privacy_flags": privacy_flags,
        "limitations": [
            "No external lookup or network request performed.",
            "Source record is evidence, not canonical truth.",
            "Account holder, operator, persona, and legal person are separate layers.",
        ],
    }


def compute_frequency_maps(records: List[Dict[str, Any]]) -> Tuple[Counter, Counter]:
    name_counts: Counter = Counter()
    username_counts: Counter = Counter()

    for r in records:
        name = r["attributes"].get("name", {}).get("normalized")
        if name:
            name_counts[name] += 1
        username = r["attributes"].get("username", {}).get("normalized")
        if username:
            username_counts[username] += 1

    return name_counts, username_counts


# --------------------------------------------------------------------
# Temporal / source helpers
# --------------------------------------------------------------------

def temporal_interval(rec: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime]]:
    start = rec.get("valid_from") or rec.get("observed_at")
    if rec.get("valid_to"):
        end = rec["valid_to"]
    elif rec.get("valid_from"):
        end = FAR_FUTURE
    else:
        end = start
    return start, end


def time_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[float, str]:
    a_start, a_end = temporal_interval(a)
    b_start, b_end = temporal_interval(b)

    if a_start is None or b_start is None:
        return 0.75, "UNKNOWN"

    if a_end is None:
        a_end = a_start
    if b_end is None:
        b_end = b_start

    if a_start <= b_end and b_start <= a_end:
        return 1.0, "OVERLAPPING"
    return 0.35, "DISJOINT"


def source_independence(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[str, float]:
    sa = a["source"]
    sb = b["source"]

    if sa["source_id"] == sb["source_id"]:
        return "DEPENDENT", 0.45

    if sa.get("upstream_source_id") and sa["upstream_source_id"] == sb.get("upstream_source_id"):
        return "DEPENDENT", 0.55

    if sa["source_type"] in HIGH_AUTHORITY_SOURCE_TYPES and sb["source_type"] in HIGH_AUTHORITY_SOURCE_TYPES:
        return "INDEPENDENT", 1.0

    if sa["source_type"] in {"self_reported", "public_profile"} and sb["source_type"] in {"self_reported", "public_profile"}:
        return "PARTIALLY_DEPENDENT", 0.75

    return "UNKNOWN", 0.85


def types_compatible(t1: str, t2: str) -> bool:
    if t1 == t2:
        return True
    if t1 in PERSON_LIKE and t2 in PERSON_LIKE:
        return True
    if t1 in ACCOUNT_LIKE and t2 in ACCOUNT_LIKE:
        return True
    if t1 in ORG_LIKE and t2 in ORG_LIKE:
        return True
    if t1 in ROLE_LIKE and t2 in ROLE_LIKE:
        return True
    if "PERSONA" in {t1, t2} and t1 in (PERSON_LIKE | ACCOUNT_LIKE) and t2 in (PERSON_LIKE | ACCOUNT_LIKE):
        return True
    return False


# --------------------------------------------------------------------
# Feature comparison
# --------------------------------------------------------------------

def add_feature(
    features: List[Dict[str, Any]],
    kind: str,
    base_strength: float,
    diagnosticity: float,
    stability: float,
    spoofability: float,
    reassignment_risk: float,
    notes: List[str],
) -> None:
    features.append({
        "kind": kind,
        "base_strength": round(base_strength, 3),
        "diagnosticity": round(diagnosticity, 3),
        "stability": round(stability, 3),
        "spoofability": round(spoofability, 3),
        "reassignment_risk": round(reassignment_risk, 3),
        "notes": notes,
    })


def add_contradiction(
    contradictions: List[Dict[str, Any]],
    ctype: str,
    severity: str,
    detail: str,
) -> None:
    contradictions.append({
        "type": ctype,
        "severity": severity,
        "detail": detail,
        "interpretation": "Contradiction candidate; may result from reassignment, shared accounts, stale data, impersonation, or data error.",
    })


def compare_records(
    a: Dict[str, Any],
    b: Dict[str, Any],
    name_counts: Counter,
    username_counts: Counter,
) -> Dict[str, Any]:
    pair_id = stable_id("PAIR", *sorted([a["record_id"], b["record_id"]]))
    compat = types_compatible(a["entity_type"], b["entity_type"])
    temporal_factor, temporal_state = time_overlap(a, b)
    indep_state, indep_factor = source_independence(a, b)

    features: List[Dict[str, Any]] = []
    contradictions: List[Dict[str, Any]] = []

    aa = a["attributes"]
    bb = b["attributes"]

    # Official ID / registration number
    for kind in ("official_id", "registration_number"):
        av = aa.get(kind, {}).get("normalized")
        bv = bb.get(kind, {}).get("normalized")
        if av and bv:
            if av == bv:
                add_feature(
                    features, kind, 0.95, 1.0, 0.90, 0.20, 0.10,
                    ["Exact official/registration identifier match."],
                )
            else:
                add_contradiction(
                    contradictions, f"{kind.upper()}_CONFLICT", "HARD",
                    "Two records contain different official/registration identifiers.",
                )

    # Account ID
    av = aa.get("account_id", {}).get("normalized")
    bv = bb.get("account_id", {}).get("normalized")
    if av and bv and av == bv:
        add_feature(
            features, "account_id", 0.75, 0.80, 0.70, 0.40, 0.30,
            ["Same account identifier. Account may be shared, transferred, or compromised."],
        )

    # Email
    ea = aa.get("email", {})
    eb = bb.get("email", {})
    if ea.get("normalized") and eb.get("normalized") and ea["normalized"] == eb["normalized"]:
        role_based = bool(ea.get("role_based") or eb.get("role_based"))
        base = 0.35 if role_based else 0.65
        diag = 0.40 if role_based else 0.70
        add_feature(
            features, "email", base, diag, 0.50, 0.50, 0.50,
            ["Same normalized email. Role/shared/forwarded email may not identify one person."],
        )

    # Phone
    pa = aa.get("phone", {})
    pb = bb.get("phone", {})
    phone_a = pa.get("normalized_e164") or pa.get("normalized_digits")
    phone_b = pb.get("normalized_e164") or pb.get("normalized_digits")
    if phone_a and phone_b and phone_a == phone_b:
        e164 = bool(pa.get("normalized_e164") and pb.get("normalized_e164"))
        base = 0.55 if e164 else 0.35
        diag = 0.60 if e164 else 0.35
        add_feature(
            features, "phone", base, diag, 0.40, 0.60, 0.70,
            ["Same phone value. Phone reassignment, VoIP, business PBX, forwarding, or spoofing possible."],
        )

    # Username
    ua = aa.get("username", {}).get("normalized")
    ub = bb.get("username", {}).get("normalized")
    if ua and ub and ua == ub:
        freq = username_counts.get(ua, 1)
        if freq <= 1:
            base, diag = 0.55, 0.80
        elif freq <= 3:
            base, diag = 0.35, 0.50
        else:
            base, diag = 0.15, 0.20
        add_feature(
            features, "username", base, diag, 0.40, 0.50, 0.60,
            [f"Same username; dataset frequency={freq}. Username reuse/recycling possible."],
        )

    # Name
    na = aa.get("name", {})
    nb = bb.get("name", {})
    if na.get("normalized") and nb.get("normalized"):
        if na["normalized"] == nb["normalized"]:
            freq = name_counts.get(na["normalized"], 1)
            if freq <= 1:
                base, diag = 0.35, 0.40
            elif freq <= 5:
                base, diag = 0.25, 0.30
            else:
                base, diag = 0.12, 0.15
            add_feature(
                features, "name", base, diag, 0.30, 0.70, 0.20,
                [f"Same normalized name; dataset frequency={freq}. Name collision possible."],
            )
        elif na.get("sorted_tokens") and na["sorted_tokens"] == nb.get("sorted_tokens"):
            add_feature(
                features, "name_sorted_variant", 0.20, 0.25, 0.30, 0.70, 0.20,
                ["Name token set matches but order differs."],
            )
        elif na.get("initials") and na["initials"] == nb.get("initials") and len(na.get("tokens", [])) == len(nb.get("tokens", [])):
            add_feature(
                features, "name_initials", 0.08, 0.10, 0.20, 0.80, 0.20,
                ["Initials match; very weak evidence."],
            )

    # Organization
    oa = aa.get("organization", {}).get("normalized")
    ob = bb.get("organization", {}).get("normalized")
    if oa and ob and oa == ob:
        both_org = a["entity_type"] in ORG_LIKE and b["entity_type"] in ORG_LIKE
        base, diag = (0.50, 0.70) if both_org else (0.20, 0.30)
        add_feature(
            features, "organization", base, diag, 0.50, 0.50, 0.30,
            ["Same organization reference. Organization membership is not automatically employment."],
        )

    # Domain
    da = aa.get("domain", {}).get("normalized")
    db = bb.get("domain", {}).get("normalized")
    if da and db and da == db:
        both_org = a["entity_type"] in ORG_LIKE and b["entity_type"] in ORG_LIKE
        base, diag = (0.40, 0.55) if both_org else (0.15, 0.25)
        add_feature(
            features, "domain", base, diag, 0.40, 0.60, 0.70,
            ["Same domain. Domain control changes over time."],
        )

    # Role
    ra = aa.get("role", {}).get("normalized")
    rb = bb.get("role", {}).get("normalized")
    if ra and rb and ra == rb:
        add_feature(
            features, "role", 0.20, 0.25, 0.40, 0.60, 0.40,
            ["Same role label. Roles must be time-bound and organization-bound."],
        )

    # Device/session
    for kind in ("device_id", "session_id"):
        av = aa.get(kind, {}).get("normalized")
        bv = bb.get(kind, {}).get("normalized")
        if av and bv and av == bv:
            add_feature(
                features, kind, 0.15, 0.25, 0.30, 0.70, 0.70,
                ["Same device/session identifier. Devices/sessions may be shared, virtual, or compromised."],
            )

    if not compat:
        add_contradiction(
            contradictions, "ENTITY_TYPE_INCOMPATIBILITY", "STRONG",
            f"Entity types {a['entity_type']} and {b['entity_type']} are not directly compatible for same-entity merge.",
        )

    if temporal_state == "DISJOINT":
        add_contradiction(
            contradictions, "TEMPORAL_DISJOINT", "SOFT",
            "Record validity/observation periods do not overlap.",
        )

    # Effective scores
    rel_avg = (a["source"]["reliability"] + b["source"]["reliability"]) / 2.0
    for f in features:
        penalty = 1.0 - (0.12 * f["spoofability"]) - (0.12 * f["reassignment_risk"])
        eff = f["base_strength"] * f["diagnosticity"] * rel_avg * temporal_factor * indep_factor * penalty
        f["source_reliability_avg"] = round(rel_avg, 3)
        f["temporal_factor"] = round(temporal_factor, 3)
        f["independence_state"] = indep_state
        f["independence_factor"] = round(indep_factor, 3)
        f["effective_score"] = round(max(0.0, min(0.99, eff)), 4)

    features.sort(key=lambda x: x["effective_score"], reverse=True)

    if features:
        max_f = features[0]["effective_score"]
        rest = sum(f["effective_score"] for f in features[1:])
        score = min(0.99, max_f + 0.30 * rest)
    else:
        score = 0.0

    kinds = {f["kind"] for f in features}
    hard = any(c["severity"] == "HARD" for c in contradictions)
    strong = any(c["severity"] == "STRONG" for c in contradictions)
    independent_diagnostic = sum(
        1 for f in features
        if f["effective_score"] >= 0.35 and indep_state != "DEPENDENT"
    )

    # Caps
    if not compat:
        score = min(score, 0.25)
    if hard:
        score = min(score, 0.15)
    if kinds == {"name"}:
        score = min(score, 0.35)
    if kinds == {"username"}:
        uname = aa.get("username", {}).get("normalized") or bb.get("username", {}).get("normalized")
        if username_counts.get(uname, 99) > 3:
            score = min(score, 0.25)
    if kinds and kinds <= {"email", "phone"} and rel_avg < 0.50:
        score = min(score, 0.50)
    if temporal_state == "DISJOINT":
        score = min(score, 0.45)
    if independent_diagnostic < 2 and score > 0.75:
        score = min(score, 0.70)

    # Resolution state
    canonical_merge = False
    if hard:
        state = "PROBABLE_DIFFERENT_ENTITY"
    elif score >= 0.80 and independent_diagnostic >= 2 and compat and temporal_state != "DISJOINT":
        state = "STRONGLY_SUPPORTED_SAME_ENTITY"
        canonical_merge = True
    elif score >= 0.70 and len(features) >= 2 and compat:
        state = "PROBABLE_SAME_ENTITY"
    elif score >= 0.55 and compat:
        state = "POSSIBLE_SAME_ENTITY"
    elif score >= 0.35:
        state = "UNRESOLVED"
    else:
        state = "UNRESOLVED"

    # Relationship candidates
    relationships: List[Dict[str, Any]] = []
    if score >= 0.35:
        if (a["entity_type"] == "ACCOUNT" and b["entity_type"] in PERSON_LIKE) or (b["entity_type"] == "ACCOUNT" and a["entity_type"] in PERSON_LIKE):
            relationships.append({
                "relationship_id": stable_id("REL", pair_id, "operates_account"),
                "type": "OPERATES_ACCOUNT_CANDIDATE",
                "source_record": a["record_id"] if a["entity_type"] in PERSON_LIKE else b["record_id"],
                "target_record": b["record_id"] if a["entity_type"] in PERSON_LIKE else a["record_id"],
                "confidence": state,
                "score": round(score, 4),
                "limitations": [
                    "Account operator is not automatically account registrant.",
                    "Account may be shared, automated, transferred, or compromised.",
                ],
            })

        if (a["entity_type"] in PERSON_LIKE and b["entity_type"] in ORG_LIKE) or (b["entity_type"] in PERSON_LIKE and a["entity_type"] in ORG_LIKE):
            person_rec = a if a["entity_type"] in PERSON_LIKE else b
            org_rec = b if a["entity_type"] in PERSON_LIKE else a
            if person_rec["attributes"].get("role") or org_rec["attributes"].get("organization") or "organization" in kinds or "domain" in kinds:
                relationships.append({
                    "relationship_id": stable_id("REL", pair_id, "employment_or_role"),
                    "type": "EMPLOYEE_OR_ROLE_HOLDER_CANDIDATE",
                    "person_record": person_rec["record_id"],
                    "organization_record": org_rec["record_id"],
                    "confidence": state,
                    "score": round(score, 4),
                    "limitations": [
                        "Organization membership is not automatically employment.",
                        "Role relationships must be time-bound.",
                    ],
                })

    return {
        "pair_id": pair_id,
        "record_a": a["record_id"],
        "record_b": b["record_id"],
        "label_a": a["raw_label"],
        "label_b": b["raw_label"],
        "entity_type_a": a["entity_type"],
        "entity_type_b": b["entity_type"],
        "types_compatible": compat,
        "temporal_state": temporal_state,
        "temporal_factor": round(temporal_factor, 3),
        "source_independence_state": indep_state,
        "source_independence_factor": round(indep_factor, 3),
        "features": features,
        "contradictions": contradictions,
        "match_score": round(score, 4),
        "independent_diagnostic_feature_count": independent_diagnostic,
        "same_entity_state": state,
        "canonical_merge_recommended": canonical_merge,
        "relationship_candidates": relationships,
        "verification_state": "SOURCE_REPORTED",
        "limitations": [
            "Match score is transparent heuristic, not verified identity.",
            "Soft links preserve uncertainty and must not be treated as canonical merges.",
        ],
    }


# --------------------------------------------------------------------
# Fact gate / hypotheses / dual-AI
# --------------------------------------------------------------------

def apply_fact_gate(pairs: List[Dict[str, Any]], known_facts: List[Any]) -> None:
    for p in pairs:
        states = []
        for kf in known_facts:
            if isinstance(kf, dict):
                if kf.get("pair_id") == p["pair_id"]:
                    states.append(kf.get("state", "SUPPORTED"))
                record_ids = set(kf.get("record_ids", []) or [])
                if record_ids == {p["record_a"], p["record_b"]}:
                    states.append(kf.get("state", "SUPPORTED"))
                text = normalize_unicode(kf.get("text", "")).lower()
            else:
                text = normalize_unicode(kf).lower()

            if text:
                la = normalize_unicode(p["label_a"]).lower()
                lb = normalize_unicode(p["label_b"]).lower()
                if la and lb and la in text and lb in text:
                    states.append("SUPPORTED")

        if "REFUTED" in states:
            p["verification_state"] = "REFUTED"
        elif "DISPUTED" in states:
            p["verification_state"] = "DISPUTED"
        elif "SUPPORTED" in states:
            p["verification_state"] = "SUPPORTED"
        else:
            p["verification_state"] = "SOURCE_REPORTED"


def generate_hypotheses(pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hyp = []
    for p in pairs:
        feature_kinds = [f["kind"] for f in p["features"]]
        contradiction_types = [c["type"] for c in p["contradictions"]]

        hyp.append({
            "hypothesis_id": stable_id("HYP", p["pair_id"], "same_entity"),
            "pair_id": p["pair_id"],
            "statement": f"{p['label_a']} and {p['label_b']} refer to the same entity.",
            "support": feature_kinds[:8],
            "opposition": contradiction_types[:8],
            "unknowns": [
                "Whether identifiers were active during the same period.",
                "Whether account/persona was shared, transferred, or compromised.",
                "Whether sources are truly independent.",
            ],
            "falsification_conditions": [
                "Authoritative records show different official identifiers.",
                "Temporal windows are incompatible.",
                "Shared attribute is common/reused/recycled.",
                "Source lineage reveals copied profile/data broker origin.",
            ],
            "status": p["same_entity_state"],
        })

        hyp.append({
            "hypothesis_id": stable_id("HYP", p["pair_id"], "different_entities"),
            "pair_id": p["pair_id"],
            "statement": f"{p['label_a']} and {p['label_b']} refer to different entities.",
            "support": contradiction_types[:8],
            "opposition": feature_kinds[:8],
            "unknowns": [
                "Whether apparent differences are due to stale data or aliasing.",
            ],
            "falsification_conditions": [
                "Multiple independent diagnostic identifiers match.",
                "Authoritative source explicitly links the references.",
            ],
            "status": "PROBABLE_DIFFERENT_ENTITY" if p["same_entity_state"] in {"PROBABLE_DIFFERENT_ENTITY", "VERIFIED_DIFFERENT_ENTITY"} else "UNRESOLVED",
        })

        if any(r["type"] in {"OPERATES_ACCOUNT_CANDIDATE", "EMPLOYEE_OR_ROLE_HOLDER_CANDIDATE"} for r in p["relationship_candidates"]):
            hyp.append({
                "hypothesis_id": stable_id("HYP", p["pair_id"], "control_or_role"),
                "pair_id": p["pair_id"],
                "statement": "One reference may control/use the other account/organization role context.",
                "support": [r["type"] for r in p["relationship_candidates"]],
                "opposition": [
                    "Account may be shared, automated, compromised, or institutionally managed.",
                    "Role may be historical or self-reported.",
                ],
                "unknowns": ["Current operator vs registrant", "Valid role period"],
                "falsification_conditions": [
                    "Authorized directory shows different operator.",
                    "Role period does not overlap event time.",
                    "Account compromise indicator exists.",
                ],
                "status": "CANDIDATE",
            })

    return hyp


def dual_ai_review_stub(pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    review = {
        "status": "INSUFFICIENT_EVIDENCE",
        "primary_conclusions": [],
        "skeptic_challenges": [],
        "comparison": "NO_SECOND_MODEL_CONFIGURED",
        "notes": [
            "This starter does not call an independent second model.",
            "AI agreement is not identity verification.",
            "Human review is required for consequential real-person attribution.",
        ],
    }

    for p in pairs:
        if p["canonical_merge_recommended"]:
            review["primary_conclusions"].append(f"{p['pair_id']}: canonical merge candidate.")
            review["skeptic_challenges"].append(
                "Check for shared devices, family accounts, role mailboxes, data broker copies, and account compromise."
            )
        if p["same_entity_state"] in {"POSSIBLE_SAME_ENTITY", "UNRESOLVED"} and p["match_score"] >= 0.35:
            review["primary_conclusions"].append(f"{p['pair_id']}: soft link candidate.")
            review["skeptic_challenges"].append(
                "Do not hard merge on common name, reused username, reassigned phone/email, or single dependent source."
            )
        if p["contradictions"]:
            review["primary_conclusions"].append(f"{p['pair_id']}: contradiction present.")
            review["skeptic_challenges"].append(
                "Contradiction may be benign: stale profile, alias, reassignment, shared account, or impersonation."
            )

    if review["primary_conclusions"]:
        review["status"] = "PARTIAL_AGREEMENT"
    return review


# --------------------------------------------------------------------
# Merge / split / canonicalization
# --------------------------------------------------------------------

class UnionFind:
    def __init__(self, items: Iterable[str]):
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def build_canonical_entities(
    records: List[Dict[str, Any]],
    pairs: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str], List[Dict[str, Any]]]:
    record_by_id = {r["record_id"]: r for r in records}
    pair_lookup = {frozenset((p["record_a"], p["record_b"])): p for p in pairs}
    uf = UnionFind(record_by_id.keys())

    merge_decisions: List[Dict[str, Any]] = []
    split_proposals: List[Dict[str, Any]] = []

    merge_pairs = sorted(
        [p for p in pairs if p["canonical_merge_recommended"]],
        key=lambda x: x["match_score"],
        reverse=True,
    )

    def sets_have_hard_contradiction(set_a: Set[str], set_b: Set[str]) -> bool:
        for x in set_a:
            for y in set_b:
                p = pair_lookup.get(frozenset((x, y)))
                if p and any(c["severity"] == "HARD" for c in p["contradictions"]):
                    return True
        return False

    for p in merge_pairs:
        ra = uf.find(p["record_a"])
        rb = uf.find(p["record_b"])
        if ra == rb:
            continue

        set_a = {rid for rid in record_by_id if uf.find(rid) == ra}
        set_b = {rid for rid in record_by_id if uf.find(rid) == rb}

        if sets_have_hard_contradiction(set_a, set_b):
            split_proposals.append({
                "proposal_id": stable_id("SPLIT", p["pair_id"]),
                "type": "MERGE_BLOCKED_BY_HARD_CONTRADICTION",
                "pair_id": p["pair_id"],
                "records": [p["record_a"], p["record_b"]],
                "reason": "Hard contradiction prevents reversible canonical merge.",
                "confidence": "PROBABLE_DIFFERENT_ENTITY",
            })
            continue

        uf.union(p["record_a"], p["record_b"])
        merge_decisions.append({
            "decision_id": stable_id("MERGE", p["pair_id"]),
            "pair_id": p["pair_id"],
            "records": [p["record_a"], p["record_b"]],
            "score": p["match_score"],
            "state": p["same_entity_state"],
            "reversible": True,
            "preserves_source_records": True,
        })

    clusters: Dict[str, List[str]] = defaultdict(list)
    for rid in record_by_id:
        clusters[uf.find(rid)].append(rid)

    canonical_entities: List[Dict[str, Any]] = []
    record_to_canonical: Dict[str, str] = {}

    for root, rids in clusters.items():
        rids = sorted(rids)
        cluster_records = [record_by_id[rid] for rid in rids]
        canonical_id = stable_id("CANON", *rids)

        entity_types = Counter(r["entity_type"] for r in cluster_records)
        canonical_type = entity_types.most_common(1)[0][0]

        aliases = list(dict.fromkeys(r["raw_label"] for r in cluster_records))
        identifiers: Dict[str, List[str]] = defaultdict(list)
        source_ids = set()
        privacy_flags = []

        for r in cluster_records:
            source_ids.add(r["source"]["source_id"])
            privacy_flags.extend(r.get("privacy_flags", []))
            for kind in (
                "name", "username", "email", "phone", "domain", "organization", "role",
                "account_id", "official_id", "registration_number", "device_id",
                "session_id", "wallet_address", "payment_account_id",
            ):
                val = r["attributes"].get(kind, {}).get("normalized")
                if val:
                    identifiers[kind].append(val)

        # Determine cluster status
        cluster_pairs = []
        for i in range(len(rids)):
            for j in range(i + 1, len(rids)):
                p = pair_lookup.get(frozenset((rids[i], rids[j])))
                if p:
                    cluster_pairs.append(p)

        has_hard = any(any(c["severity"] == "HARD" for c in p["contradictions"]) for p in cluster_pairs)
        all_strong = bool(cluster_pairs) and all(p["same_entity_state"] == "STRONGLY_SUPPORTED_SAME_ENTITY" for p in cluster_pairs)

        if len(rids) == 1:
            resolution_status = "SINGLE_SOURCE_RECORD"
        elif has_hard:
            resolution_status = "DISPUTED"
            split_proposals.append({
                "proposal_id": stable_id("SPLIT", canonical_id),
                "type": "POST_CLUSTER_HARD_CONTRADICTION",
                "canonical_id": canonical_id,
                "records": rids,
                "reason": "Cluster contains hard contradiction after transitive grouping.",
                "confidence": "DISPUTED",
            })
        elif all_strong:
            resolution_status = "STRONGLY_SUPPORTED_SAME_ENTITY"
        else:
            resolution_status = "PROBABLE_SAME_ENTITY"

        canonical = {
            "canonical_id": canonical_id,
            "entity_type": canonical_type,
            "display_label": aliases[0] if aliases else canonical_id,
            "aliases": aliases,
            "source_record_ids": rids,
            "source_ids": sorted(source_ids),
            "identifiers": {k: list(dict.fromkeys(v)) for k, v in identifiers.items()},
            "resolution_status": resolution_status,
            "merge_history": [m for m in merge_decisions if set(m["records"]).issubset(set(rids))],
            "privacy_flags": list(dict.fromkeys(privacy_flags)),
            "limitations": [
                "Canonical entity is derived from evidence and remains reversible.",
                "Canonicalization does not prove legal identity or real-person identity.",
            ],
        }
        canonical_entities.append(canonical)
        for rid in rids:
            record_to_canonical[rid] = canonical_id

    return canonical_entities, split_proposals, record_to_canonical, merge_decisions


# --------------------------------------------------------------------
# Identity eras / account control
# --------------------------------------------------------------------

def build_identity_eras(
    records: List[Dict[str, Any]],
    record_to_canonical: Dict[str, str],
) -> List[Dict[str, Any]]:
    eras = []
    identifier_kinds = (
        "email", "phone", "username", "domain", "account_id",
        "official_id", "registration_number", "device_id", "session_id",
        "wallet_address", "payment_account_id",
    )

    for r in records:
        canonical_id = record_to_canonical.get(r["record_id"], r["record_id"])
        for kind in identifier_kinds:
            value = r["attributes"].get(kind, {}).get("normalized")
            if not value:
                continue
            eras.append({
                "era_id": stable_id("ERA", r["record_id"], kind, value),
                "identifier_type": kind,
                "identifier_hash": hashlib.sha256(value.encode("utf-8")).hexdigest()[:16],
                "identifier_display": display_identifier(kind, value),
                "source_record_id": r["record_id"],
                "canonical_entity_id": canonical_id,
                "valid_from": r.get("valid_from"),
                "valid_to": r.get("valid_to"),
                "observed_at": r.get("observed_at"),
                "source_id": r["source"]["source_id"],
                "confidence": "POSSIBLE" if r["source"]["reliability"] < 0.60 else "PROBABLE",
                "limitations": [
                    "Identifier usage is time-bounded.",
                    "Reassignment, recycling, forwarding, sharing, or compromise may change operator.",
                ],
            })
    return eras


def build_account_control_assessments(
    records: List[Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    record_to_canonical: Dict[str, str],
) -> List[Dict[str, Any]]:
    account_records = [r for r in records if r["entity_type"] == "ACCOUNT"]
    assessments = []

    linked_operators: Dict[str, Set[str]] = defaultdict(set)
    compromised_candidates: Set[str] = set()

    for p in pairs:
        for rel in p["relationship_candidates"]:
            if rel["type"] == "OPERATES_ACCOUNT_CANDIDATE":
                account_rid = rel["target_record"]
                person_rid = rel["source_record"]
                linked_operators[account_rid].add(person_rid)

    for r in records:
        if r["entity_type"] == "ACCOUNT":
            raw_state = str(r["attributes"].get("account_status", {}).get("normalized", "")).lower()
            if "compromis" in raw_state or "takeover" in raw_state or "hijack" in raw_state:
                compromised_candidates.add(r["record_id"])

    for r in account_records:
        ops = linked_operators.get(r["record_id"], set())
        if r["record_id"] in compromised_candidates:
            state = "COMPROMISED_ACCOUNT_CANDIDATE"
        elif len(ops) > 1:
            state = "SHARED_OR_MULTIPLE_OPERATOR_CANDIDATE"
        elif len(ops) == 1:
            state = "SINGLE_OPERATOR_CANDIDATE"
        else:
            state = "OPERATOR_UNRESOLVED"

        assessments.append({
            "assessment_id": stable_id("ACCTCTL", r["record_id"]),
            "account_record_id": r["record_id"],
            "canonical_entity_id": record_to_canonical.get(r["record_id"]),
            "state": state,
            "linked_operator_records": sorted(ops),
            "limitations": [
                "Registrant, operator, beneficiary, and actor may differ.",
                "Shared, automated, transferred, sold, or compromised accounts are possible.",
            ],
        })

    return assessments


# --------------------------------------------------------------------
# Graph memory
# --------------------------------------------------------------------

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
            "note": "Graph is evidence-linked memory, not proof. Edges retain confidence/state where available.",
        }


def build_graph(
    records: List[Dict[str, Any]],
    canonical_entities: List[Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    record_to_canonical: Dict[str, str],
) -> GraphMemory:
    g = GraphMemory()

    for r in records:
        g.add_node("SourceRecord", r["record_id"], {
            "entity_type": r["entity_type"],
            "display_label": r["raw_label"],
            "source_id": r["source"]["source_id"],
            "source_type": r["source"]["source_type"],
            "reliability": r["source"]["reliability"],
        })

    for c in canonical_entities:
        g.add_node("CanonicalEntity", c["canonical_id"], {
            "entity_type": c["entity_type"],
            "display_label": c["display_label"],
            "resolution_status": c["resolution_status"],
            "aliases": c["aliases"][:10],
        })

    for r in records:
        canon = record_to_canonical.get(r["record_id"])
        if canon:
            g.add_edge(r["record_id"], canon, "REPRESENTED_BY", {
                "method": "identity_resolution",
                "confidence": "DERIVED",
            })

    for c in canonical_entities:
        for kind, values in c.get("identifiers", {}).items():
            for val in values[:20]:
                ident_id = stable_id("IDENT", kind, val)
                g.add_node("Identifier", ident_id, {
                    "identifier_type": kind,
                    "display": display_identifier(kind, val),
                    "hash": hashlib.sha256(str(val).encode("utf-8")).hexdigest()[:16],
                })
                g.add_edge(c["canonical_id"], ident_id, "HAS_IDENTIFIER", {
                    "method": "normalization",
                    "confidence": "POSSIBLE",
                })

    for p in pairs:
        ca = record_to_canonical.get(p["record_a"], p["record_a"])
        cb = record_to_canonical.get(p["record_b"], p["record_b"])
        if p["canonical_merge_recommended"]:
            edge_type = "SAME_ENTITY_AS"
        elif p["match_score"] >= 0.35:
            edge_type = "POSSIBLY_SAME_ENTITY_AS"
        else:
            edge_type = "WEAKLY_RELATED_CANDIDATE"

        g.add_edge(ca, cb, edge_type, {
            "pair_id": p["pair_id"],
            "score": p["match_score"],
            "state": p["same_entity_state"],
            "verification_state": p["verification_state"],
            "source_independence": p["source_independence_state"],
            "temporal_state": p["temporal_state"],
        })

        for rel in p["relationship_candidates"]:
            g.add_edge(rel["source_record"] if "source_record" in rel else rel.get("person_record", ca),
                       rel["target_record"] if "target_record" in rel else rel.get("organization_record", cb),
                       rel["type"], {
                           "relationship_id": rel["relationship_id"],
                           "confidence": rel["confidence"],
                           "score": rel["score"],
                       })

    for h in hypotheses[:200]:
        g.add_node("Hypothesis", h["hypothesis_id"], {
            "statement": h["statement"],
            "status": h["status"],
            "pair_id": h.get("pair_id"),
        })
        if h.get("pair_id"):
            g.add_edge(h["hypothesis_id"], h["pair_id"], "ABOUT_PAIR", {"method": "hypothesis_engine"})

    for c in contradictions[:200]:
        g.add_node("Contradiction", c["contradiction_id"], {
            "type": c["type"],
            "severity": c["severity"],
            "pair_id": c.get("pair_id"),
        })
        if c.get("pair_id"):
            g.add_edge(c["contradiction_id"], c["pair_id"], "CONTRADICTS_PAIR", {"severity": c["severity"]})

    for gap in gaps[:200]:
        g.add_node("Gap", gap["gap_id"], {
            "type": gap["type"],
            "importance": gap["importance"],
        })

    return g


# --------------------------------------------------------------------
# Gaps / actions / handoffs / observations
# --------------------------------------------------------------------

def collect_contradictions(pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for p in pairs:
        for c in p["contradictions"]:
            out.append({
                "contradiction_id": stable_id("CTR", p["pair_id"], c["type"]),
                "pair_id": p["pair_id"],
                "records": [p["record_a"], p["record_b"]],
                **c,
            })
    return out


def build_observations(
    records: List[Dict[str, Any]],
    canonical_entities: List[Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    privacy_flags: List[Dict[str, Any]],
) -> List[str]:
    obs = []
    obs.append(f"Source records ingested: {len(records)}.")
    obs.append(f"Canonical entities derived: {len(canonical_entities)}.")
    merges = [p for p in pairs if p["canonical_merge_recommended"]]
    soft = [p for p in pairs if not p["canonical_merge_recommended"] and p["match_score"] >= 0.35]
    obs.append(f"Canonical merge candidates: {len(merges)}. Soft-link candidates: {len(soft)}.")
    if any(p["source_independence_state"] == "DEPENDENT" for p in pairs):
        obs.append("Some candidate links derive from dependent sources; do not treat as independent corroboration.")
    if any(p["temporal_state"] == "DISJOINT" for p in pairs):
        obs.append("Temporal disjointness detected in some pairs; historical identifiers must not be propagated to current identity.")
    if privacy_flags:
        obs.append("Sensitive attributes were removed and not used as identity-resolution features.")
    obs.append("No biometric, face, voice, gait, private tracking, account access, or network lookup was performed.")
    return obs


def build_unknowns(
    pairs: List[Dict[str, Any]],
    account_assessments: List[Dict[str, Any]],
) -> List[str]:
    unknowns = []
    for p in pairs:
        if p["same_entity_state"] in {"UNRESOLVED", "POSSIBLE_SAME_ENTITY", "DISPUTED"}:
            unknowns.append(f"Pair {p['pair_id']} identity state unresolved: {p['same_entity_state']}.")
    for a in account_assessments:
        if a["state"] in {"OPERATOR_UNRESOLVED", "SHARED_OR_MULTIPLE_OPERATOR_CANDIDATE", "COMPROMISED_ACCOUNT_CANDIDATE"}:
            unknowns.append(f"Account {a['account_record_id']} operator/control state: {a['state']}.")
    return list(dict.fromkeys(unknowns))


def build_gaps(
    records: List[Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    account_assessments: List[Dict[str, Any]],
    privacy_flags: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps = []

    for p in pairs:
        if p["match_score"] >= 0.35 and p["same_entity_state"] in {"UNRESOLVED", "POSSIBLE_SAME_ENTITY", "PROBABLE_SAME_ENTITY"}:
            gaps.append({
                "gap_id": stable_id("GAP", "identity", p["pair_id"]),
                "type": "ENTITY_RESOLUTION_INCOMPLETE",
                "importance": "HIGH" if p["match_score"] >= 0.55 else "MEDIUM",
                "pair_id": p["pair_id"],
                "recommended_source": "Authoritative identity directory, official organization page, explicit cross-link, or authorized account-control record.",
                "specialist": "IDENTITYINT / HUMAN_REVIEW",
                "expected_information_value": "Distinguish same entity, shared account, alias, impersonation, or reassignment.",
            })

        if p["source_independence_state"] in {"DEPENDENT", "UNKNOWN"} and p["match_score"] >= 0.35:
            gaps.append({
                "gap_id": stable_id("GAP", "indep", p["pair_id"]),
                "type": "SOURCE_INDEPENDENCE_UNRESOLVED",
                "importance": "HIGH",
                "pair_id": p["pair_id"],
                "recommended_source": "Upstream source lineage, independent official record, or original publication.",
                "specialist": "IDENTITYINT / WEBINT / DOCINT",
                "expected_information_value": "Prevent copied profiles/data brokers from inflating confidence.",
            })

        if p["temporal_state"] in {"DISJOINT", "UNKNOWN"} and p["match_score"] >= 0.35:
            gaps.append({
                "gap_id": stable_id("GAP", "temporal", p["pair_id"]),
                "type": "TEMPORAL_IDENTITY_UNCLEAR",
                "importance": "MEDIUM",
                "pair_id": p["pair_id"],
                "recommended_source": "Creation/update history, role validity period, identifier assignment era.",
                "specialist": "IDENTITYINT",
                "expected_information_value": "Avoid historical-to-current identity contamination.",
            })

    for a in account_assessments:
        if a["state"] != "SINGLE_OPERATOR_CANDIDATE":
            gaps.append({
                "gap_id": stable_id("GAP", "acct", a["account_record_id"]),
                "type": "ACCOUNT_OPERATOR_UNRESOLVED",
                "importance": "HIGH",
                "account_record_id": a["account_record_id"],
                "recommended_source": "Authorized account-control log, platform verified ownership, incident record, or HR/directory evidence.",
                "specialist": "IDENTITYINT / INCIDENTINT / FRAUDINT",
                "expected_information_value": "Separate registrant, operator, shared use, compromise, and automation.",
            })

    for pf in privacy_flags:
        gaps.append({
            "gap_id": stable_id("GAP", "privacy", pf.get("record_id", "global"), pf.get("type")),
            "type": "SENSITIVE_ATTRIBUTE_EXCLUDED",
            "importance": "HIGH",
            "record_id": pf.get("record_id"),
            "recommended_source": "Do not seek sensitive trait data unless exceptional lawful necessity and explicit policy permission.",
            "specialist": "PRIVACY / HUMAN_REVIEW",
            "expected_information_value": "Maintain sensitive-trait firewall.",
        })

    return gaps[:200]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    priority_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    for g in gaps:
        if g["type"] == "ENTITY_RESOLUTION_INCOMPLETE":
            action = "Retrieve authoritative identity record or explicit cross-platform link before merging."
        elif g["type"] == "SOURCE_INDEPENDENCE_UNRESOLVED":
            action = "Trace source pedigree and obtain independent official/original source."
        elif g["type"] == "TEMPORAL_IDENTITY_UNCLEAR":
            action = "Resolve identifier/role usage eras with creation, update, and validity timestamps."
        elif g["type"] == "ACCOUNT_OPERATOR_UNRESOLVED":
            action = "Review authorized account-control evidence; distinguish registrant, operator, shared use, and compromise."
        elif g["type"] == "SENSITIVE_ATTRIBUTE_EXCLUDED":
            action = "Maintain privacy boundary; do not pursue sensitive-trait inference."
        else:
            action = "Gather additional authorized evidence."

        actions.append({
            "action": action,
            "gap_id": g["gap_id"],
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not perform face search or biometric identification.",
                "Do not track private persons or infer precise private location.",
                "Do not access private accounts or use stolen credentials.",
                "Do not contact subjects deceptively or perform social engineering.",
                "Do not infer race, ethnicity, religion, politics, health, or sexual orientation.",
            ],
        })

    actions.sort(key=lambda x: priority_map.get(x.get("priority", "LOW"), 9))
    return actions[:80]


def build_handoffs(manifest: Dict[str, Any], records: List[Dict[str, Any]], pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    blob = " ".join([str(manifest.get("objective", ""))] + [str(q) for q in manifest.get("questions", []) or []]).lower()
    hands = []

    def add(spec: str, reason: str) -> None:
        hands.append({
            "specialist": spec,
            "reason": reason,
            "payload": ["record_ids", "canonical_ids", "identifiers_masked", "time_range", "evidence_ids", "known_facts", "unknowns", "limitations"],
        })

    if any(r["entity_type"] == "ACCOUNT" for r in records) or "account" in blob:
        add("SOCMINT / MESSENGERINT", "Public account/profile context may require platform-specific lawful analysis.")
    if any(r["attributes"].get("phone") for r in records) or "phone" in blob:
        add("PHONEINT", "Phone assignment era, portability, and caller-ID context.")
    if any(r["attributes"].get("email") for r in records) or "email" in blob:
        add("CREDINT / BREACHINT", "Email exposure/breach context only if authorized; do not use credentials.")
    if any(r["entity_type"] in ORG_LIKE for r in records) or "company" in blob or "organization" in blob:
        add("CORPINT / ORGINT", "Corporate/legal entity resolution.")
    if any(r["attributes"].get("domain") for r in records) or "domain" in blob:
        add("DOMAININT / WEBINT", "Domain control era and website lineage.")
    if any("impersonat" in str(p).lower() for p in pairs) or "fraud" in blob:
        add("FRAUDINT / INCIDENTINT", "Impersonation, synthetic identity, or account takeover context.")
    if any(r["attributes"].get("official_id") or r["attributes"].get("registration_number") for r in records):
        add("DOCINT / METADATAINT", "Documented identity evidence and provenance.")

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
        "entity_types": [],
        "canonical_entities": [],
        "person_candidates": [],
        "legal_persons": [],
        "personas": [],
        "accounts": [],
        "organizations": [],
        "legal_entities": [],
        "brands": [],
        "roles": [],
        "identifiers": [],
        "names": [],
        "aliases": [],
        "usernames": [],
        "emails": [],
        "phones": [],
        "domains": [],
        "devices": [],
        "sessions": [],
        "wallets": [],
        "payment_accounts": [],
        "normalized_identifiers": [],
        "identity_candidates": [],
        "match_features": [],
        "contradicting_features": [],
        "resolution_states": [],
        "verification_states": [],
        "match_confidence": [],
        "source_confidence": [],
        "temporal_confidence": [],
        "identity_eras": [],
        "account_control_eras": [],
        "phone_assignment_eras": [],
        "email_usage_eras": [],
        "domain_control_eras": [],
        "role_holding_eras": [],
        "entity_merge_proposals": [],
        "entity_split_proposals": [],
        "merge_history": [],
        "split_history": [],
        "source_pedigree": [],
        "source_reliability": [],
        "source_bias": [],
        "source_limitations": [],
        "source_independence": [],
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
        "records": [],
        "pairs": [],
        "status": "PARTIAL",
    }


def summarize_record_for_output(r: Dict[str, Any]) -> Dict[str, Any]:
    attrs = r["attributes"]
    return {
        "record_id": r["record_id"],
        "reference_id": r["reference_id"],
        "entity_type": r["entity_type"],
        "display_label": r["raw_label"],
        "source_id": r["source"]["source_id"],
        "source_type": r["source"]["source_type"],
        "source_reliability": r["source"]["reliability"],
        "observed_at": r.get("observed_at"),
        "valid_from": r.get("valid_from"),
        "valid_to": r.get("valid_to"),
        "identifiers_masked": {
            "name": attrs.get("name", {}).get("normalized"),
            "username": attrs.get("username", {}).get("normalized"),
            "email": mask_email(attrs.get("email", {}).get("normalized")),
            "phone": mask_phone(attrs.get("phone", {}).get("normalized_e164") or attrs.get("phone", {}).get("normalized_digits")),
            "domain": attrs.get("domain", {}).get("normalized"),
            "organization": attrs.get("organization", {}).get("normalized"),
            "role": attrs.get("role", {}).get("normalized"),
            "account_id": mask_secret(attrs.get("account_id", {}).get("normalized")),
            "official_id": mask_secret(attrs.get("official_id", {}).get("normalized")),
        },
        "privacy_flags": r.get("privacy_flags", []),
        "limitations": r.get("limitations", []),
    }


def summarize_pair_for_output(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pair_id": p["pair_id"],
        "record_a": p["record_a"],
        "record_b": p["record_b"],
        "label_a": p["label_a"],
        "label_b": p["label_b"],
        "entity_type_a": p["entity_type_a"],
        "entity_type_b": p["entity_type_b"],
        "same_entity_state": p["same_entity_state"],
        "match_score": p["match_score"],
        "canonical_merge_recommended": p["canonical_merge_recommended"],
        "verification_state": p["verification_state"],
        "temporal_state": p["temporal_state"],
        "source_independence_state": p["source_independence_state"],
        "feature_kinds": [f["kind"] for f in p["features"]],
        "top_features": p["features"][:5],
        "contradictions": p["contradictions"],
        "relationship_candidates": p["relationship_candidates"],
        "limitations": p["limitations"],
    }


def finalize_status(
    result: Dict[str, Any],
    records: List[Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    auth_ok: bool,
    policy_blocked: List[str],
) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not records:
        return "INSUFFICIENT_INPUT"
    if any(p["same_entity_state"] == "DISPUTED" for p in pairs):
        return "PARTIAL"
    if any(p["same_entity_state"] in {"UNRESOLVED", "POSSIBLE_SAME_ENTITY"} for p in pairs):
        return "PARTIAL"
    if result.get("knowledge_gaps"):
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_identity_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["limitations"] = [
            "IDENTITYINT does not perform doxxing, biometric identification, private tracking, sensitive-trait inference, credential testing, or deceptive contact."
        ]
        result["privacy_flags"] = [{"type": label, "action": "PROHIBITED_REQUEST_NOT_PERFORMED"} for label in policy_blocked]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    refs = manifest.get("entity_references") or manifest.get("references") or []
    if not refs:
        result["status"] = "INSUFFICIENT_INPUT"
        result["limitations"].append("No entity_references provided.")
        return result

    default_country = manifest.get("default_country_code") or manifest.get("country_hint")
    records = [ingest_reference(ref, i, default_country) for i, ref in enumerate(refs)]
    name_counts, username_counts = compute_frequency_maps(records)

    pairs = []
    for i in range(len(records)):
        for j in range(i + 1, len(records)):
            pairs.append(compare_records(records[i], records[j], name_counts, username_counts))

    apply_fact_gate(pairs, manifest.get("known_facts", []) or [])
    hypotheses = generate_hypotheses(pairs)
    contradictions = collect_contradictions(pairs)

    canonical_entities, split_proposals, record_to_canonical, merge_decisions = build_canonical_entities(records, pairs)
    identity_eras = build_identity_eras(records, record_to_canonical)
    account_assessments = build_account_control_assessments(records, pairs, record_to_canonical)

    privacy_flags = []
    for r in records:
        for pf in r.get("privacy_flags", []):
            privacy_flags.append({
                "record_id": r["record_id"],
                "type": pf,
                "action": "SENSITIVE_ATTRIBUTE_REMOVED_NOT_USED",
            })

    observations = build_observations(records, canonical_entities, pairs, privacy_flags)
    unknowns = build_unknowns(pairs, account_assessments)
    gaps = build_gaps(records, pairs, account_assessments, privacy_flags)
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(manifest, records, pairs)
    dual_review = dual_ai_review_stub(pairs)
    graph = build_graph(records, canonical_entities, pairs, hypotheses, contradictions, gaps, record_to_canonical)

    # Populate result fields
    result["records"] = [summarize_record_for_output(r) for r in records]
    result["pairs"] = [summarize_pair_for_output(p) for p in pairs]
    result["canonical_entities"] = canonical_entities
    result["identity_eras"] = identity_eras
    result["account_control_eras"] = account_assessments
    result["entity_merge_proposals"] = [p for p in pairs if p["canonical_merge_recommended"]]
    result["entity_split_proposals"] = split_proposals
    result["merge_history"] = merge_decisions
    result["split_history"] = split_proposals
    result["contradictions"] = contradictions
    result["hypotheses"] = hypotheses
    result["falsification_results"] = [
        {
            "hypothesis_id": h["hypothesis_id"],
            "opposition": h["opposition"],
            "falsification_conditions": h["falsification_conditions"],
        }
        for h in hypotheses
    ]
    result["dual_ai_review"] = dual_review
    result["graph_memory"] = graph.to_dict()
    result["observations"] = observations
    result["unknowns"] = unknowns
    result["knowledge_gaps"] = gaps
    result["recommended_next_actions"] = actions
    result["specialist_handoffs"] = handoffs
    result["privacy_flags"] = privacy_flags

    for r in records:
        result["source_ids"].append(r["source"]["source_id"])
        result["evidence_ids"].append(stable_id("EV", r["record_id"]))
        result["entity_types"].append({"record_id": r["record_id"], "entity_type": r["entity_type"]})
        result["source_reliability"].append({
            "record_id": r["record_id"],
            "source_id": r["source"]["source_id"],
            "source_type": r["source"]["source_type"],
            "reliability": r["source"]["reliability"],
        })
        result["source_pedigree"].append({
            "record_id": r["record_id"],
            "source_id": r["source"]["source_id"],
            "upstream_source_id": r["source"].get("upstream_source_id"),
            "source_type": r["source"]["source_type"],
        })

        attrs = r["attributes"]
        if attrs.get("name"):
            result["names"].append({"record_id": r["record_id"], "normalized": attrs["name"].get("normalized")})
        if attrs.get("username"):
            result["usernames"].append({"record_id": r["record_id"], "normalized": attrs["username"].get("normalized")})
        if attrs.get("email"):
            result["emails"].append({"record_id": r["record_id"], "masked": mask_email(attrs["email"].get("normalized"))})
        if attrs.get("phone"):
            result["phones"].append({"record_id": r["record_id"], "masked": mask_phone(attrs["phone"].get("normalized_e164") or attrs["phone"].get("normalized_digits"))})
        if attrs.get("domain"):
            result["domains"].append({"record_id": r["record_id"], "normalized": attrs["domain"].get("normalized")})
        if attrs.get("account_id"):
            result["accounts"].append({"record_id": r["record_id"], "masked": mask_secret(attrs["account_id"].get("normalized"))})
        if attrs.get("official_id"):
            result["normalized_identifiers"].append({"record_id": r["record_id"], "type": "official_id", "masked": mask_secret(attrs["official_id"].get("normalized"))})

        if r["entity_type"] in PERSON_LIKE:
            result["person_candidates"].append({"record_id": r["record_id"], "label": r["raw_label"]})
        if r["entity_type"] in ORG_LIKE:
            result["organizations"].append({"record_id": r["record_id"], "label": r["raw_label"]})
        if r["entity_type"] == "ROLE":
            result["roles"].append({"record_id": r["record_id"], "label": r["raw_label"]})

    for p in pairs:
        result["identity_candidates"].append({
            "pair_id": p["pair_id"],
            "records": [p["record_a"], p["record_b"]],
            "state": p["same_entity_state"],
            "score": p["match_score"],
        })
        result["match_features"].extend([dict(f, pair_id=p["pair_id"]) for f in p["features"][:10]])
        result["contradicting_features"].extend([dict(c, pair_id=p["pair_id"]) for c in p["contradictions"]])
        result["resolution_states"].append({"pair_id": p["pair_id"], "state": p["same_entity_state"]})
        result["verification_states"].append({"pair_id": p["pair_id"], "state": p["verification_state"]})
        result["match_confidence"].append({"pair_id": p["pair_id"], "score": p["match_score"]})
        result["source_confidence"].append({"pair_id": p["pair_id"], "independence": p["source_independence_state"]})
        result["temporal_confidence"].append({"pair_id": p["pair_id"], "state": p["temporal_state"]})
        result["source_independence"].append({"pair_id": p["pair_id"], "state": p["source_independence_state"]})

        if p["verification_state"] == "SUPPORTED":
            result["supported_facts"].append({"pair_id": p["pair_id"], "statement": f"{p['label_a']} and {p['label_b']} supported by provided known fact."})
        elif p["verification_state"] == "DISPUTED":
            result["disputed_facts"].append({"pair_id": p["pair_id"], "statement": f"{p['label_a']} and {p['label_b']} disputed."})
        else:
            result["candidate_facts"].append({"pair_id": p["pair_id"], "statement": f"{p['label_a']} and {p['label_b']} candidate same-entity link."})

    base_limits = [
        "IDENTITYINT starter performs local deterministic/heuristic resolution only; no external lookup or network request was made.",
        "No face recognition, voiceprint matching, biometric identification, private tracking, or doxxing was performed.",
        "Sensitive traits were not inferred and sensitive input attributes were removed from scoring.",
        "Identifier match is candidate evidence, not verified human identity.",
        "Account registrant, operator, persona, legal person, and organization are separate layers.",
        "Soft links preserve uncertainty and must not be treated as canonical merges.",
        "Identifier reassignment, shared accounts, account compromise, impersonation, and stale profiles are explicitly considered.",
        "Consequential real-person attribution requires human review and authoritative evidence.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

    result["status"] = finalize_status(result, records, pairs, auth_ok, policy_blocked)
    return result


# --------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------

def generate_report(result: Dict[str, Any]) -> str:
    lines = []
    lines.append("# IDENTITYINT Evidence-Linked Report")
    lines.append("")
    lines.append(f"- Case ID: `{result.get('case_id')}`")
    lines.append(f"- Task ID: `{result.get('task_id')}`")
    lines.append(f"- Generated: `{result.get('generated_at')}`")
    lines.append(f"- Version: `{result.get('version')}`")
    lines.append(f"- Status: `{result.get('status')}`")
    lines.append("")

    if result.get("status") == "POLICY_BLOCKED":
        lines.append("## POLICY BLOCKED")
        lines.append("The request violated IDENTITYINT hard restrictions:")
        for v in result.get("violations", []):
            lines.append(f"- `{v}`")
        lines.append("")
        lines.append("No identity resolution was performed.")
        return "\n".join(lines)

    lines.append("## Objective")
    lines.append(str(result.get("objective", "")))
    lines.append("")

    lines.append("## Required Analyst Summary")
    records = result.get("records", [])
    pairs = result.get("pairs", [])
    canonical = result.get("canonical_entities", [])
    lines.append(f"- SOURCE RECORDS: {len(records)}")
    lines.append(f"- CANONICAL ENTITIES: {len(canonical)}")
    lines.append(f"- CANDIDATE PAIRS: {len(pairs)}")
    lines.append(f"- CANONICAL MERGE CANDIDATES: {sum(1 for p in pairs if p.get('canonical_merge_recommended'))}")
    lines.append(f"- SOFT LINK CANDIDATES: {sum(1 for p in pairs if not p.get('canonical_merge_recommended') and p.get('match_score', 0) >= 0.35)}")
    lines.append(f"- CONTRADICTIONS: {len(result.get('contradictions', []))}")
    lines.append(f"- ACCOUNT CONTROL ASSESSMENTS: {len(result.get('account_control_eras', []))}")
    lines.append(f"- PRIVACY FLAGS: {len(result.get('privacy_flags', []))}")
    lines.append(f"- UNKNOWN ITEMS: {len(result.get('unknowns', []))}")
    lines.append("- NEXT ACTION: " + (result.get("recommended_next_actions", [{}])[0].get("action", "None") if result.get("recommended_next_actions") else "None"))
    lines.append("")

    lines.append("## Privacy / Identity Boundaries")
    lines.append("- No doxxing, private tracking, face recognition, voiceprint matching, or biometric identification.")
    lines.append("- No inference of race, ethnicity, religion, sexual orientation, health, political belief, union membership, or sex life.")
    lines.append("- No account access, credential testing, social engineering, or deceptive contact.")
    lines.append("- Identifiers are masked in human-facing output where sensitive.")
    lines.append("- Soft links are not canonical identity merges.")
    lines.append("")

    lines.append("## Entity Inventory")
    for r in records[:100]:
        lines.append(f"### `{r.get('record_id')}` — {r.get('display_label')}")
        lines.append(f"- Entity type: `{r.get('entity_type')}`")
        lines.append(f"- Source: `{r.get('source_id')}` / `{r.get('source_type')}` / reliability=`{r.get('source_reliability')}`")
        lines.append(f"- Temporal: observed=`{r.get('observed_at')}` valid=`{r.get('valid_from')}` to `{r.get('valid_to')}`")
        lines.append(f"- Identifiers: `{json.dumps(r.get('identifiers_masked', {}), ensure_ascii=False)}`"[:700])
        if r.get("privacy_flags"):
            lines.append(f"- Privacy flags: {', '.join(r.get('privacy_flags', []))}")
        lines.append("")

    lines.append("## Canonical Entities")
    for c in canonical[:100]:
        lines.append(f"### `{c.get('canonical_id')}` — {c.get('display_label')}")
        lines.append(f"- Type: `{c.get('entity_type')}`")
        lines.append(f"- Resolution status: `{c.get('resolution_status')}`")
        lines.append(f"- Source records: {', '.join(c.get('source_record_ids', []))}")
        lines.append(f"- Aliases: {', '.join(c.get('aliases', [])[:10])}")
        lines.append(f"- Merge history entries: {len(c.get('merge_history', []))}")
        lines.append("")

    lines.append("## Pairwise Identity Candidates")
    for p in pairs[:100]:
        lines.append(f"### `{p.get('pair_id')}`")
        lines.append(f"- Records: `{p.get('record_a')}` ↔ `{p.get('record_b')}`")
        lines.append(f"- Labels: {p.get('label_a')} ↔ {p.get('label_b')}")
        lines.append(f"- Same-entity state: `{p.get('same_entity_state')}`")
        lines.append(f"- Match score: `{p.get('match_score')}`")
        lines.append(f"- Canonical merge recommended: `{p.get('canonical_merge_recommended')}`")
        lines.append(f"- Verification state: `{p.get('verification_state')}`")
        lines.append(f"- Temporal state: `{p.get('temporal_state')}`")
        lines.append(f"- Source independence: `{p.get('source_independence_state')}`")
        if p.get("feature_kinds"):
            lines.append(f"- Feature kinds: {', '.join(p.get('feature_kinds', []))}")
        if p.get("contradictions"):
            lines.append("- Contradictions:")
            for c in p.get("contradictions", [])[:10]:
                lines.append(f"  - `{c.get('type')}` [{c.get('severity')}]: {c.get('detail')}")
        if p.get("relationship_candidates"):
            lines.append("- Relationship candidates:")
            for rel in p.get("relationship_candidates", [])[:10]:
                lines.append(f"  - `{rel.get('type')}` confidence=`{rel.get('confidence')}` score=`{rel.get('score')}`")
        lines.append("")

    lines.append("## Account Control Assessments")
    for a in result.get("account_control_eras", [])[:100]:
        lines.append(f"- `{a.get('account_record_id')}`: `{a.get('state')}` linked_operators={a.get('linked_operator_records')}")
    lines.append("")

    lines.append("## Identity Eras")
    for e in result.get("identity_eras", [])[:100]:
        lines.append(
            f"- `{e.get('era_id')}` type=`{e.get('identifier_type')}` display=`{e.get('identifier_display')}` "
            f"canonical=`{e.get('canonical_entity_id')}` valid=`{e.get('valid_from')}` to `{e.get('valid_to')}`"
        )
    lines.append("")

    lines.append("## Hypotheses")
    for h in result.get("hypotheses", [])[:100]:
        lines.append(f"- `{h.get('hypothesis_id')}` [{h.get('status')}]: {h.get('statement')}")
        if h.get("support"):
            lines.append(f"  - support: {', '.join(map(str, h['support'][:8]))}")
        if h.get("opposition"):
            lines.append(f"  - opposition: {', '.join(map(str, h['opposition'][:8]))}")
        if h.get("falsification_conditions"):
            lines.append(f"  - falsify if: {'; '.join(map(str, h['falsification_conditions'][:5]))}")
    lines.append("")

    lines.append("## Dual-AI Review Stub")
    dr = result.get("dual_ai_review", {})
    lines.append(f"- Status: `{dr.get('status')}`")
    lines.append(f"- Comparison: `{dr.get('comparison')}`")
    for n in dr.get("notes", []):
        lines.append(f"- {n}")
    for c in dr.get("primary_conclusions", [])[:20]:
        lines.append(f"- Primary: {c}")
    for c in dr.get("skeptic_challenges", [])[:20]:
        lines.append(f"- Skeptic: {c}")
    lines.append("")

    lines.append("## Knowledge Gaps")
    for g in result.get("knowledge_gaps", [])[:100]:
        lines.append(f"- `{g.get('gap_id')}` [{g.get('importance')}] {g.get('type')}: {g.get('recommended_source')}")
    lines.append("")

    lines.append("## Recommended Next Actions")
    for a in result.get("recommended_next_actions", [])[:100]:
        lines.append(f"- [{a.get('priority')}] {a.get('action')}")
    lines.append("")

    lines.append("## Specialist Handoffs")
    for h in result.get("specialist_handoffs", []):
        lines.append(f"- {h.get('specialist')}: {h.get('reason')}")
    lines.append("")

    lines.append("## Limitations")
    for lim in result.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    lines.append("## Non-Negotiable Boundary")
    lines.append("- Resolve entity type first.")
    lines.append("- Normalize identifiers deterministically.")
    lines.append("- Check time, reassignment, account compromise, and source independence.")
    lines.append("- Soft-link before hard-merge.")
    lines.append("- Attribute a real person last, and only with authoritative evidence plus human review.")

    return "\n".join(lines)


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEATLAS IDENTITYINT safe starter")
    parser.add_argument("--manifest", required=True, help="Path to IDENTITYINT manifest JSON")
    parser.add_argument("--output", default="identityint_result.json", help="Output JSON path")
    parser.add_argument("--report", default="identityint_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR reading manifest: {exc}", file=sys.stderr)
        return 2

    result = analyze_identity_manifest(manifest)

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
  "case_id": "ID-CASE-001",
  "task_id": "ID-TASK-001",
  "objective": "Resolve whether provided authorized/public identity references refer to the same entity, different entities, or uncertain account/persona relationships, without biometric identification or private tracking.",
  "questions": [
    "Which references may refer to the same person candidate?",
    "Which account/persona relationships are only candidates?",
    "What contradictions prevent merge?",
    "What additional authoritative evidence is needed?"
  ],
  "authorization": {
    "approved": True,
    "scope": "public_and_authorized_records",
    "model_mode": "LOCAL_ONLY",
    "cloud_approved": False
  },
  "default_country_code": "1",
  "known_facts": [],
  "entity_references": [
    {
      "reference_id": "R1",
      "entity_type": "PERSON_CANDIDATE",
      "canonical_label": "Alex Kumar",
      "attributes": {
        "name": "Dr. Alex Kumar Jr.",
        "email": "alex.kumar@example-org.com",
        "username": "alexkumar-sec",
        "organization": "Example Org",
        "role": "Security Lead"
      },
      "source": {
        "source_id": "S1",
        "source_type": "official_org_page",
        "observed_at": "2026-09-01T00:00:00Z",
        "valid_from": "2026-01-01T00:00:00Z"
      }
    },
    {
      "reference_id": "R2",
      "entity_type": "ACCOUNT",
      "canonical_label": "github:alexkumar-sec",
      "attributes": {
        "username": "alexkumar-sec",
        "account_id": "gh-889911",
        "domain": "github.com"
      },
      "source": {
        "source_id": "S2",
        "source_type": "platform_verified",
        "observed_at": "2026-09-02T00:00:00Z"
      }
    },
    {
      "reference_id": "R3",
      "entity_type": "PERSON_CANDIDATE",
      "canonical_label": "Alex Kumar",
      "attributes": {
        "name": "Alex Kumar",
        "email": "alex@example.com",
        "phone": "+1 555 0100"
      },
      "source": {
        "source_id": "S3",
        "source_type": "self_reported",
        "observed_at": "2020-01-01T00:00:00Z",
        "valid_to": "2021-01-01T00:00:00Z"
      }
    }
  ]
}
