#!/usr/bin/env python3
"""
TRACEATLAS TIMELINEINT — Safe Python Starter Implementation

Purpose:
  Evidence-first timeline / temporal reconstruction pipeline.

Hard boundaries enforced in code:
  - Does NOT track private persons in real time.
  - Does NOT construct stalking/targeting timelines.
  - Does NOT fabricate, alter, or forge timestamps.
  - Does NOT silently correct clocks.
  - Does NOT equate record/publication/ingestion time with event time.
  - Does NOT infer causality from temporal sequence alone.
  - Does NOT create false precision from approximate/relative time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import unicodedata
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

VERSION = "0.1.0-timelineint-safe-starter"
FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)

try:
    from zoneinfo import ZoneInfo  # type: ignore
    HAS_ZONEINFO = True
except Exception:
    HAS_ZONEINFO = False


# --------------------------------------------------------------------
# Policy / authorization constants
# --------------------------------------------------------------------

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_case_evidence",
    "authorized_logs_and_incidents",
    "provided_records_only",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(track|locate|surveil|stalk)\s+(person|individual|someone|user|target|suspect)"), "PRIVATE_TRACKING_OR_SURVEILLANCE"),
    (re.compile(r"(?i)\b(real[- ]time tracking|live tracking)"), "REAL_TIME_TRACKING"),
    (re.compile(r"(?i)\b(daily routine|home arrival|departure pattern|movement schedule|predict.*schedule)"), "PRIVATE_ROUTINE_OR_PREDICTIVE_TARGETING"),
    (re.compile(r"(?i)\b(attack timing|targeting window|surveillance avoidance|evade detection|blind spot)"), "TARGETING_OR_EVASION_PLANNING"),
    (re.compile(r"(?i)\b(fabricat|alter|forge|change|rewrite)\s+(timestamp|clock|time|log)"), "TIMESTAMP_FABRICATION_OR_ALTERATION"),
    (re.compile(r"(?i)\b(prove|establish)\s+causation\s+from\s+(timeline|sequence|order)"), "CAUSALITY_OVERCLAIM_REQUEST"),
]

SOURCE_RELIABILITY: Dict[str, float] = {
    "signed_system_log": 0.92,
    "ntp_synced_server": 0.90,
    "database_record": 0.86,
    "payment_processor": 0.86,
    "authorized_transaction_record": 0.88,
    "authorized_communication_metadata": 0.84,
    "siem_export": 0.80,
    "edr_xdr_log": 0.80,
    "network_sensor": 0.76,
    "official_filing": 0.88,
    "official_notice": 0.84,
    "court_record": 0.88,
    "media_container_metadata": 0.62,
    "exif_metadata": 0.55,
    "public_post": 0.45,
    "news_article": 0.52,
    "web_archive_capture": 0.58,
    "human_statement": 0.35,
    "anonymous_source": 0.15,
    "unknown": 0.30,
}

HIGH_AUTHORITY_SOURCE_TYPES = {
    "signed_system_log",
    "ntp_synced_server",
    "database_record",
    "payment_processor",
    "authorized_transaction_record",
    "authorized_communication_metadata",
    "siem_export",
    "edr_xdr_log",
    "official_filing",
    "official_notice",
    "court_record",
}

TIMESTAMP_TYPE_PRIORITY = {
    "EVENT_TIME": 0,
    "OBSERVED_TIME": 1,
    "RECORDED_TIME": 2,
    "PROCESSED_TIME": 3,
    "REPORTED_TIME": 4,
    "COMPLETED_TIME": 5,
    "SETTLED_TIME": 6,
    "PUBLISHED_TIME": 7,
    "INGESTION_TIME": 8,
    "DISCOVERY_TIME": 9,
    "KNOWLEDGE_TIME": 10,
    "CREATION_TIME": 11,
    "MODIFICATION_TIME": 12,
    "ACCESS_TIME": 13,
    "RETRIEVAL_TIME": 14,
    "REPORT_TIME": 15,
    "UNKNOWN": 99,
}

EXPECTED_TIMESTAMP_ORDER = [
    "EVENT_TIME",
    "OBSERVED_TIME",
    "RECORDED_TIME",
    "PROCESSED_TIME",
    "REPORTED_TIME",
    "PUBLISHED_TIME",
    "INGESTION_TIME",
]

PRECISION_RANK = {
    "NANOSECOND": 0,
    "MICROSECOND": 1,
    "MILLISECOND": 2,
    "SECOND": 3,
    "MINUTE": 4,
    "HOUR": 5,
    "DAY": 6,
    "WEEK": 7,
    "MONTH": 8,
    "YEAR": 9,
    "INTERVAL_ONLY": 10,
    "SEQUENCE_ONLY": 11,
    "UNKNOWN": 12,
}

PRECISION_DELTA_SECONDS = {
    "NANOSECOND": 1e-9,
    "MICROSECOND": 1e-6,
    "MILLISECOND": 1e-3,
    "SECOND": 1.0,
    "MINUTE": 60.0,
    "HOUR": 3600.0,
    "DAY": 86400.0,
    "WEEK": 604800.0,
    "MONTH": 2592000.0,
    "YEAR": 31536000.0,
}

CLOCK_QUALITY_FACTOR = {
    "SYNCHRONIZED": 1.0,
    "LIKELY_SYNCHRONIZED": 1.5,
    "KNOWN_SKEW": 2.0,
    "UNKNOWN": 3.0,
    "UNRELIABLE": 10.0,
}

TEMPORAL_RELATIONS = {
    "BEFORE",
    "AFTER",
    "EQUAL",
    "DURING",
    "CONTAINS",
    "STARTS",
    "STARTED_BY",
    "FINISHES",
    "FINISHED_BY",
    "OVERLAPS",
    "OVERLAPPED_BY",
    "MEETS",
    "MET_BY",
    "POSSIBLY_SIMULTANEOUS",
    "UNKNOWN",
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
    if isinstance(obj, timedelta):
        return obj.total_seconds()
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


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


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


# --------------------------------------------------------------------
# Policy / authorization
# --------------------------------------------------------------------

def collect_user_intent_text(manifest: Dict[str, Any]) -> str:
    parts = [
        normalize_text(manifest.get("objective", "")),
        " ".join(normalize_text(q) for q in manifest.get("questions", []) or []),
    ]
    return " ".join(parts)


def policy_screen(manifest: Dict[str, Any]) -> List[str]:
    blob = collect_user_intent_text(manifest)
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
# Timezone / timestamp parsing
# --------------------------------------------------------------------

def parse_tz_offset(value: Any) -> Optional[timezone]:
    if value is None:
        return None
    s = normalize_text(value)
    if not s:
        return None
    if s.upper() == "Z":
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", s)
    if not m:
        return None
    sign = 1 if m.group(1) == "+" else -1
    hours = int(m.group(2))
    minutes = int(m.group(3))
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def localize_naive_datetime(
    dt: datetime,
    timezone_hint: Optional[str],
    timezone_state_hint: Optional[str] = None,
) -> Tuple[datetime, str, List[str]]:
    limitations: List[str] = []

    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc), "EXPLICIT", limitations

    hint = normalize_text(timezone_hint) if timezone_hint else None
    if not hint:
        return dt.replace(tzinfo=timezone.utc), "UNKNOWN", [
            "Timezone unknown; UTC assumed only for deterministic comparison. This is an assumption, not evidence."
        ]

    offset = parse_tz_offset(hint)
    if offset is not None:
        return dt.replace(tzinfo=offset).astimezone(timezone.utc), "EXPLICIT", limitations

    if HAS_ZONEINFO:
        try:
            tz = ZoneInfo(hint)
            aware = dt.replace(tzinfo=tz)
            state = timezone_state_hint or "SOURCE_CONFIGURED"
            limitations.append(
                "Named timezone used. DST fold/gap ambiguity is only partially modeled in this starter."
            )
            return aware.astimezone(timezone.utc), state, limitations
        except Exception as exc:
            limitations.append(f"ZoneInfo unavailable/error for '{hint}': {exc}")

    limitations.append(f"Timezone '{hint}' could not be resolved; UTC assumed for comparison only.")
    return dt.replace(tzinfo=timezone.utc), "UNKNOWN", limitations


def detect_precision_from_raw(raw: str) -> str:
    s = normalize_text(raw)
    if not s:
        return "UNKNOWN"

    m = re.search(r"[T ]\d{2}:\d{2}:\d{2}\.(\d+)", s)
    if m:
        frac_len = len(m.group(1))
        if frac_len >= 9:
            return "NANOSECOND"
        if frac_len >= 6:
            return "MICROSECOND"
        if frac_len >= 3:
            return "MILLISECOND"
        return "SECOND"

    if re.search(r"[T ]\d{2}:\d{2}:\d{2}", s):
        return "SECOND"
    if re.search(r"[T ]\d{2}:\d{2}(?!:\d)", s):
        return "MINUTE"
    if re.search(r"[T ]\d{2}(?![:\d])", s):
        return "HOUR"
    if re.search(r"\d{4}-\d{2}-\d{2}", s):
        return "DAY"
    if re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", s):
        return "DAY"
    if re.search(r"\d{4}-\d{2}(?!-\d)", s):
        return "MONTH"
    if re.search(r"\b\d{4}\b(?![-/\d])", s):
        return "YEAR"
    return "UNKNOWN"


def precision_from_format(fmt: str) -> str:
    if "%f" in fmt:
        return "MICROSECOND"
    if "%S" in fmt:
        return "SECOND"
    if "%M" in fmt:
        return "MINUTE"
    if "%H" in fmt:
        return "HOUR"
    if "%d" in fmt or "%j" in fmt:
        return "DAY"
    if "%m" in fmt:
        return "MONTH"
    if "%Y" in fmt or "%y" in fmt:
        return "YEAR"
    return "UNKNOWN"


def date_format_ambiguity(raw: str, locale_hint: Optional[str]) -> bool:
    s = normalize_text(raw)
    m = re.fullmatch(r"(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})(?:\s+.*)?", s)
    if not m:
        return False
    a = int(m.group(1))
    b = int(m.group(2))
    if a <= 12 and b <= 12 and a != b:
        return not bool(locale_hint)
    return False


def parse_datetime_string(
    raw: str,
    locale_hint: Optional[str] = None,
) -> Tuple[Optional[datetime], Optional[str], str, bool, List[str]]:
    s = normalize_text(raw)
    limitations: List[str] = []

    if not s:
        return None, None, "UNKNOWN", False, ["Empty timestamp."]

    # ISO first
    iso_candidate = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        precision = detect_precision_from_raw(s)
        tz_explicit = dt.tzinfo is not None
        if date_format_ambiguity(s, locale_hint):
            limitations.append("Numeric date format may be ambiguous (DD/MM vs MM/DD).")
        return dt, "ISO8601", precision, tz_explicit, limitations
    except Exception:
        pass

    dayfirst_locales = {"en-gb", "en-in", "dd/mm/yyyy", "dayfirst", "ddmm"}
    dayfirst = normalize_text(locale_hint or "").lower() in dayfirst_locales

    common_formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H",
        "%Y-%m-%d %H",
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d %B %Y",
        "%d %b %Y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%B %d %Y",
        "%b %d %Y",
        "%Y-%m",
        "%Y",
    ]

    ambiguous_numeric = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y",
        "%m-%d-%Y %H:%M:%S",
        "%m-%d-%Y",
    ]

    if dayfirst:
        ordered = ambiguous_numeric[:3] + common_formats + ambiguous_numeric[3:]
    else:
        ordered = ambiguous_numeric[3:6] + common_formats + ambiguous_numeric[:3]

    for fmt in ordered:
        try:
            dt = datetime.strptime(s, fmt)
            precision = precision_from_format(fmt)
            tz_explicit = "%z" in fmt
            if date_format_ambiguity(s, locale_hint):
                limitations.append(
                    "Numeric date format may be ambiguous (DD/MM vs MM/DD). Locale hint was not sufficient to resolve confidently."
                )
            return dt, fmt, precision, tz_explicit, limitations
        except Exception:
            continue

    return None, None, "UNKNOWN", False, ["Unrecognized timestamp format."]


def detect_epoch_unit(value: float, hint: Optional[str] = None) -> str:
    if hint:
        h = normalize_text(hint).upper()
        if h in {"SECONDS", "SEC", "S"}:
            return "SECONDS"
        if h in {"MILLISECONDS", "MS"}:
            return "MILLISECONDS"
        if h in {"MICROSECONDS", "US", "MCS"}:
            return "MICROSECONDS"
        if h in {"NANOSECONDS", "NS"}:
            return "NANOSECONDS"

    av = abs(value)
    # Rough plausible range: 1970-01-01 to 2100-01-01.
    max_seconds = 4102444800.0
    if av <= max_seconds:
        return "SECONDS"
    if av <= max_seconds * 1e3:
        return "MILLISECONDS"
    if av <= max_seconds * 1e6:
        return "MICROSECONDS"
    if av <= max_seconds * 1e9:
        return "NANOSECONDS"
    return "UNKNOWN"


def parse_epoch_value(
    raw: Any,
    epoch_unit_hint: Optional[str] = None,
) -> Tuple[Optional[datetime], Optional[str], str, bool, List[str]]:
    limitations: List[str] = []
    try:
        value = float(raw)
    except Exception:
        return None, None, "UNKNOWN", False, ["Epoch value not numeric."]

    unit = detect_epoch_unit(value, epoch_unit_hint)
    if unit == "UNKNOWN":
        return None, None, "UNKNOWN", False, ["Epoch unit could not be determined."]

    if unit == "SECONDS":
        seconds = value
        precision = "SECOND" if value == int(value) else "MICROSECOND"
    elif unit == "MILLISECONDS":
        seconds = value / 1e3
        precision = "MILLISECOND"
    elif unit == "MICROSECONDS":
        seconds = value / 1e6
        precision = "MICROSECOND"
    else:
        seconds = value / 1e9
        precision = "NANOSECOND"

    try:
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except Exception as exc:
        return None, None, "UNKNOWN", False, [f"Epoch conversion failed: {exc}"]

    limitations.append(f"Epoch unit inferred/declared as {unit}. Unit detection can be ambiguous without field documentation.")
    return dt, f"EPOCH_{unit}", precision, True, limitations


def precision_delta_seconds(precision: str) -> Optional[float]:
    return PRECISION_DELTA_SECONDS.get(precision)


def default_uncertainty_seconds(precision: str) -> Optional[float]:
    delta = precision_delta_seconds(precision)
    if delta is None:
        return None
    return delta / 2.0


def parse_timestamp_value(
    raw: Any,
    timezone_hint: Optional[str] = None,
    locale_hint: Optional[str] = None,
    precision_hint: Optional[str] = None,
    uncertainty_seconds: Optional[float] = None,
    timestamp_type: Optional[str] = None,
    epoch_unit_hint: Optional[str] = None,
) -> Dict[str, Any]:
    limitations: List[str] = []
    raw_text = normalize_text(raw) if raw is not None else ""

    base = {
        "raw_timestamp": raw_text,
        "normalized_start_utc": None,
        "normalized_end_utc": None,
        "representative_utc": None,
        "precision": normalize_text(precision_hint).upper() or "UNKNOWN",
        "timezone_state": "UNKNOWN",
        "timezone_hint": timezone_hint,
        "format_detected": None,
        "uncertainty_seconds": uncertainty_seconds,
        "sequence_only": False,
        "limitations": limitations,
    }

    tt = normalize_text(timestamp_type).upper()
    if tt == "SEQUENCE_ONLY" or (not raw_text and tt == "SEQUENCE_ONLY"):
        base["sequence_only"] = True
        base["precision"] = "SEQUENCE_ONLY"
        base["limitations"].append("Sequence-only evidence; no absolute timestamp supplied.")
        return base

    dt: Optional[datetime] = None
    fmt: Optional[str] = None
    precision = normalize_text(precision_hint).upper() or None
    tz_explicit = False

    if isinstance(raw, datetime):
        dt = raw
        precision = precision or detect_precision_from_raw(raw.isoformat())
        tz_explicit = raw.tzinfo is not None
        fmt = "PYTHON_DATETIME"
    elif raw is not None and re.fullmatch(r"-?\d+(?:\.\d+)?", normalize_text(raw)):
        dt, fmt, parsed_precision, tz_explicit, epoch_lim = parse_epoch_value(raw, epoch_unit_hint)
        precision = precision or parsed_precision
        limitations.extend(epoch_lim)
    else:
        dt, fmt, parsed_precision, tz_explicit, parse_lim = parse_datetime_string(raw_text, locale_hint)
        precision = precision or parsed_precision
        limitations.extend(parse_lim)

    if dt is None:
        base["limitations"].append("Timestamp could not be parsed.")
        base["precision"] = precision or "UNKNOWN"
        return base

    if tz_explicit:
        normalized = dt.astimezone(timezone.utc)
        tz_state = "EXPLICIT"
    else:
        normalized, tz_state, tz_lim = localize_naive_datetime(dt, timezone_hint)
        limitations.extend(tz_lim)

    precision = precision or detect_precision_from_raw(raw_text) or "UNKNOWN"
    base["format_detected"] = fmt
    base["precision"] = precision
    base["timezone_state"] = tz_state

    delta = precision_delta_seconds(precision)
    if delta is not None:
        start = normalized
        end = normalized + timedelta(seconds=delta)
        rep = start + timedelta(seconds=delta / 2.0)
    else:
        start = end = rep = normalized

    if base["uncertainty_seconds"] is None:
        base["uncertainty_seconds"] = default_uncertainty_seconds(precision)

    base["normalized_start_utc"] = start
    base["normalized_end_utc"] = end
    base["representative_utc"] = rep

    if precision in {"INTERVAL_ONLY", "UNKNOWN"}:
        base["limitations"].append("Precision uncertain; interval representation is conservative.")

    return base


# --------------------------------------------------------------------
# Sources / clocks
# --------------------------------------------------------------------

def collect_referenced_source_ids(manifest: Dict[str, Any]) -> Set[str]:
    ids = set()
    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if sid:
            ids.add(sid)
    for ev in manifest.get("temporal_evidence", []) or []:
        sid = normalize_text(ev.get("source_id"))
        if sid:
            ids.add(sid)
    for event in manifest.get("events", []) or []:
        for ts in event.get("timestamps", []) or []:
            sid = normalize_text(ts.get("source_id"))
            if sid:
                ids.add(sid)
    for cov in manifest.get("source_coverage", []) or []:
        sid = normalize_text(cov.get("source_id"))
        if sid:
            ids.add(sid)
    for claim in manifest.get("temporal_claims", []) or []:
        sid = normalize_text(claim.get("source_id"))
        if sid:
            ids.add(sid)
    return ids


def ingest_sources(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    sources: Dict[str, Dict[str, Any]] = {}

    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if not sid:
            continue
        stype = normalize_text(s.get("source_type", "unknown")).lower()
        reliability = s.get("reliability")
        if reliability is None:
            reliability = SOURCE_RELIABILITY.get(stype, SOURCE_RELIABILITY["unknown"])
        sources[sid] = {
            "source_id": sid,
            "source_type": stype,
            "upstream_source_id": normalize_text(s.get("upstream_source_id")) or None,
            "reliability": clamp(float(reliability)),
            "observed_at": normalize_text(s.get("observed_at")) or None,
            "url": s.get("url"),
            "limitations": list(s.get("limitations", []) or []),
        }

    for sid in collect_referenced_source_ids(manifest):
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


def ingest_clocks(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    clocks: Dict[str, Dict[str, Any]] = {}
    for c in manifest.get("clocks", []) or []:
        cid = normalize_text(c.get("clock_id"))
        if not cid:
            continue
        anchor = None
        anchor_raw = c.get("offset_anchor_time") or c.get("offset_valid_from") or c.get("last_sync")
        if anchor_raw:
            parsed = parse_timestamp_value(anchor_raw, precision_hint="SECOND")
            anchor = parsed.get("representative_utc")

        clocks[cid] = {
            "clock_id": cid,
            "source_system": normalize_text(c.get("source_system")),
            "timezone": normalize_text(c.get("timezone")),
            "sync_method": normalize_text(c.get("sync_method")),
            "last_sync": normalize_text(c.get("last_sync")),
            "quality": normalize_text(c.get("quality", "UNKNOWN")).upper(),
            "offset_seconds": float(c.get("offset_seconds", 0.0) or 0.0),
            "drift_seconds_per_day": float(c.get("drift_seconds_per_day", 0.0) or 0.0),
            "offset_valid_from": parse_timestamp_value(c.get("offset_valid_from"), precision_hint="SECOND").get("representative_utc") if c.get("offset_valid_from") else None,
            "offset_valid_to": parse_timestamp_value(c.get("offset_valid_to"), precision_hint="SECOND").get("representative_utc") if c.get("offset_valid_to") else None,
            "anchor_time": anchor,
            "limitations": list(c.get("limitations", []) or []),
        }
    return clocks


def clock_offset_at(clock: Dict[str, Any], t: Optional[datetime]) -> Tuple[Optional[float], str]:
    if not clock:
        return None, "NO_CLOCK"
    if t is None:
        return float(clock.get("offset_seconds", 0.0)), "UNKNOWN_TIME"

    valid_from = clock.get("offset_valid_from")
    valid_to = clock.get("offset_valid_to")
    if valid_from and t < valid_from:
        return None, "OUTSIDE_VALIDITY"
    if valid_to and t > valid_to:
        return None, "OUTSIDE_VALIDITY"

    offset = float(clock.get("offset_seconds", 0.0))
    drift = float(clock.get("drift_seconds_per_day", 0.0))
    anchor = clock.get("anchor_time") or valid_from
    if drift and anchor:
        days = (t - anchor).total_seconds() / 86400.0
        offset += drift * days

    return offset, "WITHIN_VALIDITY"


def apply_clock_correction(ts: Dict[str, Any], clock: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out = dict(ts)
    out["clock_id"] = clock.get("clock_id") if clock else None
    out["clock_quality"] = clock.get("quality", "UNKNOWN") if clock else "UNKNOWN"
    out["clock_offset_seconds"] = None
    out["correction_state"] = "NO_CORRECTION"
    out["corrected_start_utc"] = out.get("normalized_start_utc")
    out["corrected_end_utc"] = out.get("normalized_end_utc")
    out["corrected_representative_utc"] = out.get("representative_utc")

    if out.get("sequence_only") or not clock:
        out["limitations"].append("No clock correction applied." if not clock else "Sequence-only evidence; no clock correction applied.")
        return out

    rep = out.get("representative_utc")
    offset, state = clock_offset_at(clock, rep)
    out["clock_offset_seconds"] = offset

    if state != "WITHIN_VALIDITY" or offset is None:
        out["correction_state"] = state
        out["limitations"].append(f"Clock correction not applied: {state}.")
        return out

    delta = timedelta(seconds=offset)
    start = out.get("normalized_start_utc")
    end = out.get("normalized_end_utc")
    out["corrected_start_utc"] = start - delta if start else None
    out["corrected_end_utc"] = end - delta if end else None
    out["corrected_representative_utc"] = rep - delta if rep else None
    out["correction_state"] = "APPLIED"
    out["limitations"].append(
        "Clock correction is a candidate adjustment based on declared offset/drift. Raw time remains preserved."
    )

    quality = normalize_text(clock.get("quality", "UNKNOWN")).upper()
    factor = CLOCK_QUALITY_FACTOR.get(quality, 3.0)
    if out.get("uncertainty_seconds") is not None:
        out["uncertainty_seconds"] = float(out["uncertainty_seconds"]) * factor
    else:
        out["uncertainty_seconds"] = 60.0 * factor

    return out


# --------------------------------------------------------------------
# Evidence ingestion
# --------------------------------------------------------------------

def normalize_timestamp_type(value: Any) -> str:
    t = normalize_text(value).upper().replace("-", "_").replace(" ", "_")
    if t in TIMESTAMP_TYPE_PRIORITY:
        return t
    if t in {"EVENT", "OCCURRED_AT", "TIME_OF_EVENT"}:
        return "EVENT_TIME"
    if t in {"RECORD", "LOG_TIME", "SERVER_TIME"}:
        return "RECORDED_TIME"
    if t in {"PUBLISH", "PUBLICATION_TIME"}:
        return "PUBLISHED_TIME"
    if t in {"INGEST", "INDEX_TIME", "COLLECTOR_TIME"}:
        return "INGESTION_TIME"
    return "UNKNOWN"


def ingest_temporal_evidence(
    manifest: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    clocks: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    raw_items: List[Dict[str, Any]] = []

    for item in manifest.get("temporal_evidence", []) or []:
        raw_items.append(dict(item))

    for event in manifest.get("events", []) or []:
        for ts in event.get("timestamps", []) or []:
            item = dict(ts)
            item.setdefault("event_id", event.get("event_id"))
            item.setdefault("event_candidate_id", event.get("event_candidate_id"))
            item.setdefault("event_family_id", event.get("event_family_id"))
            item.setdefault("event_type", event.get("event_type"))
            item.setdefault("phase", event.get("phase"))
            item.setdefault("entities", event.get("entities", []))
            item.setdefault("identifiers", event.get("identifiers", {}))
            item.setdefault("location", event.get("location"))
            raw_items.append(item)

    for idx, item in enumerate(raw_items):
        evid_id = normalize_text(item.get("evidence_id")) or f"EV-{idx}"
        source_id = normalize_text(item.get("source_id")) or None
        clock_id = normalize_text(item.get("clock_id")) or None
        timestamp_type = normalize_timestamp_type(item.get("timestamp_type") or item.get("type"))
        phase = normalize_text(item.get("phase")).upper() or None

        ts = parse_timestamp_value(
            item.get("timestamp") if "timestamp" in item else item.get("raw_timestamp"),
            timezone_hint=item.get("timezone") or item.get("timezone_hint"),
            locale_hint=item.get("locale") or item.get("locale_hint"),
            precision_hint=item.get("precision"),
            uncertainty_seconds=float(item["uncertainty_seconds"]) if item.get("uncertainty_seconds") is not None else None,
            timestamp_type=timestamp_type,
            epoch_unit_hint=item.get("epoch_unit"),
        )

        clock = clocks.get(clock_id) if clock_id else None
        ts = apply_clock_correction(ts, clock)

        src = sources.get(source_id, {}) if source_id else {}
        ts["source_reliability"] = float(src.get("reliability", SOURCE_RELIABILITY["unknown"]))
        ts["source_type"] = src.get("source_type", "unknown")
        ts["evidence_id"] = evid_id
        ts["source_id"] = source_id
        ts["clock_id"] = clock_id
        ts["timestamp_type"] = timestamp_type
        ts["phase"] = phase
        ts["event_id"] = normalize_text(item.get("event_id")) or None
        ts["event_candidate_id"] = normalize_text(item.get("event_candidate_id")) or None
        ts["event_family_id"] = normalize_text(item.get("event_family_id")) or None
        ts["event_type"] = normalize_text(item.get("event_type")) or None
        ts["entities"] = [normalize_text(x) for x in item.get("entities", []) or [] if normalize_text(x)]
        ts["identifiers"] = {
            normalize_text(k).lower(): [normalize_text(v)] if not isinstance(v, list) else [normalize_text(x) for x in v]
            for k, v in (item.get("identifiers") or {}).items()
        }
        ts["location"] = normalize_text(item.get("location")) or None
        ts["text"] = normalize_text(item.get("text")) or None
        ts["limitations"] = list(dict.fromkeys(ts.get("limitations", []) + list(item.get("limitations", []) or [])))

        evidence.append(ts)

    return evidence


# --------------------------------------------------------------------
# Event construction
# --------------------------------------------------------------------

def timestamp_interval(ev: Dict[str, Any], use_corrected: bool = True) -> Tuple[Optional[datetime], Optional[datetime], Optional[datetime]]:
    if ev.get("sequence_only"):
        return None, None, None
    if use_corrected and ev.get("correction_state") == "APPLIED":
        return (
            ev.get("corrected_start_utc"),
            ev.get("corrected_end_utc"),
            ev.get("corrected_representative_utc"),
        )
    return (
        ev.get("normalized_start_utc"),
        ev.get("normalized_end_utc"),
        ev.get("representative_utc"),
    )


def choose_primary_timestamp(evs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    candidates = [e for e in evs if not e.get("sequence_only")]
    if not candidates:
        return None

    def sort_key(e: Dict[str, Any]) -> Tuple[int, float, int, str]:
        tt = TIMESTAMP_TYPE_PRIORITY.get(e.get("timestamp_type", "UNKNOWN"), 99)
        rel = -float(e.get("source_reliability", 0.3))
        prec = PRECISION_RANK.get(e.get("precision", "UNKNOWN"), 99)
        return (tt, rel, prec, e.get("evidence_id", ""))

    return sorted(candidates, key=sort_key)[0]


def build_events(
    evidence: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    source_roots: Dict[str, str],
) -> List[Dict[str, Any]]:
    by_event: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for ev in evidence:
        eid = ev.get("event_id") or ev.get("event_candidate_id") or ev["evidence_id"]
        by_event[eid].append(ev)

    events: List[Dict[str, Any]] = []

    for eid, evs in by_event.items():
        event_types = [e.get("event_type") for e in evs if e.get("event_type")]
        event_type = Counter(event_types).most_common(1)[0][0] if event_types else "UNKNOWN"

        entities = sorted({x for e in evs for x in e.get("entities", [])})
        identifiers: Dict[str, List[str]] = defaultdict(list)
        for e in evs:
            for k, vals in (e.get("identifiers") or {}).items():
                identifiers[k].extend(vals)
        identifiers = {k: list(dict.fromkeys(v)) for k, v in identifiers.items()}

        locations = sorted({e.get("location") for e in evs if e.get("location")})
        phases = sorted({e.get("phase") for e in evs if e.get("phase")})
        timestamp_types = sorted({e.get("timestamp_type") for e in evs if e.get("timestamp_type")})
        source_ids = sorted({e.get("source_id") for e in evs if e.get("source_id")})
        evidence_ids = sorted({e["evidence_id"] for e in evs})
        families = sorted({e.get("event_family_id") for e in evs if e.get("event_family_id")})

        primary = choose_primary_timestamp(evs)
        raw_start = raw_end = raw_rep = None
        start = end = rep = None
        precision = "UNKNOWN"
        uncertainty = None
        correction_state = "NO_CORRECTION"
        clock_id = None

        if primary:
            raw_start, raw_end, raw_rep = timestamp_interval(primary, use_corrected=False)
            start, end, rep = timestamp_interval(primary, use_corrected=True)
            precision = primary.get("precision", "UNKNOWN")
            uncertainty = primary.get("uncertainty_seconds")
            correction_state = primary.get("correction_state", "NO_CORRECTION")
            clock_id = primary.get("clock_id")

        sequence_only = all(e.get("sequence_only") for e in evs)

        families_ids = source_family_ids(source_ids, source_roots)
        max_rel, avg_rel = source_quality(source_ids, sources)
        indep_state = independence_state(families_ids, sources, source_ids)

        # Confidence heuristic
        confidence = 0.35
        if primary:
            confidence += 0.25 * max_rel
            if indep_state == "INDEPENDENT":
                confidence += 0.10
            elif indep_state == "PARTIALLY_DEPENDENT":
                confidence += 0.05
            if correction_state == "APPLIED":
                confidence += 0.05
            if precision in {"SECOND", "MILLISECOND", "MICROSECOND", "NANOSECOND"}:
                confidence += 0.05
            if len(families_ids) >= 2:
                confidence += 0.05
        confidence = clamp(confidence)

        limitations = [
            "Event time is represented with uncertainty; normalized/corrected times are not claimed as exact truth.",
            "Record/publication/ingestion timestamps are not automatically event timestamps.",
            "Event identity is based on provided event_id/event_candidate_id; absent explicit IDs, records remain provisional.",
        ]
        if sequence_only:
            limitations.append("Only sequence/relative evidence available for this event.")
        if correction_state == "APPLIED":
            limitations.append("Clock-corrected candidate time is stored separately from raw time.")
        if indep_state == "DEPENDENT":
            limitations.append("Sources for this event are not independent; do not treat multiple copied timestamps as corroboration.")

        events.append({
            "event_id": eid,
            "event_type": event_type,
            "event_family_id": families[0] if families else None,
            "phase": phases[0] if phases else None,
            "entities": entities,
            "identifiers": identifiers,
            "location": locations[0] if locations else None,
            "locations": locations,
            "timestamp_types": timestamp_types,
            "source_ids": source_ids,
            "evidence_ids": evidence_ids,
            "independent_source_family_count": len(families_ids),
            "source_independence_state": indep_state,
            "source_max_reliability": round(max_rel, 4),
            "source_avg_reliability": round(avg_rel, 4),
            "sequence_only": sequence_only,
            "raw_start_utc": raw_start,
            "raw_end_utc": raw_end,
            "raw_representative_utc": raw_rep,
            "start_utc": start,
            "end_utc": end,
            "representative_utc": rep,
            "time_precision": precision,
            "time_uncertainty_seconds": uncertainty,
            "clock_id": clock_id,
            "clock_correction_state": correction_state,
            "confidence_score": round(confidence, 4),
            "verification_state": "SOURCE_REPORTED",
            "limitations": list(dict.fromkeys(limitations)),
            "timestamps": evs,
        })

    events.sort(key=lambda e: (e.get("representative_utc") or FAR_FUTURE, e["event_id"]))
    return events


# --------------------------------------------------------------------
# Temporal claims / constraints / partial order
# --------------------------------------------------------------------

def normalize_relation(value: Any) -> str:
    r = normalize_text(value).upper().replace("-", "_").replace(" ", "_")
    if r in {"BEFORE", "PRIOR_TO", "PRECEDES"}:
        return "BEFORE"
    if r in {"AFTER", "SINCE", "FOLLOWS"}:
        return "AFTER"
    if r in {"EQUAL", "SAME_TIME", "SIMULTANEOUS"}:
        return "EQUAL"
    if r in {"DURING", "WITHIN"}:
        return "DURING"
    if r in {"CONTAINS", "INCLUDES"}:
        return "CONTAINS"
    if r in {"OVERLAPS", "OVERLAP"}:
        return "OVERLAPS"
    if r in {"MEETS"}:
        return "MEETS"
    return "UNKNOWN"


def ingest_temporal_claims(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    claims = []
    for idx, c in enumerate(manifest.get("temporal_claims", []) or []):
        claim_id = normalize_text(c.get("temporal_claim_id") or c.get("claim_id") or f"TCLM-{idx}")
        relation = normalize_relation(c.get("relation") or c.get("type"))
        claims.append({
            "temporal_claim_id": claim_id,
            "event_a": normalize_text(c.get("event_a") or c.get("source_event")),
            "event_b": normalize_text(c.get("event_b") or c.get("target_event")),
            "relation": relation,
            "source_id": normalize_text(c.get("source_id")) or None,
            "evidence_ids": [normalize_text(x) for x in c.get("evidence_ids", []) or [] if normalize_text(x)],
            "confidence": normalize_text(c.get("confidence", "UNKNOWN")).upper(),
            "verification_state": normalize_text(c.get("verification_state", "SOURCE_REPORTED")).upper(),
            "limitations": list(c.get("limitations", []) or []),
        })
    return claims


def add_constraint(
    constraints: List[Dict[str, Any]],
    seen: Set[Tuple[str, str]],
    a: str,
    b: str,
    origin: str,
    confidence: str = "UNKNOWN",
    source_ids: Optional[List[str]] = None,
    evidence_ids: Optional[List[str]] = None,
) -> None:
    if not a or not b or a == b:
        return
    key = (a, b)
    if key in seen:
        return
    seen.add(key)
    constraints.append({
        "constraint_id": stable_id("CON", a, b, origin),
        "source_event": a,
        "target_event": b,
        "relation": "BEFORE",
        "origin": origin,
        "confidence": confidence,
        "source_ids": source_ids or [],
        "evidence_ids": evidence_ids or [],
    })


def build_constraints(
    events: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    constraints: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()

    event_by_id = {e["event_id"]: e for e in events}

    for c in claims:
        a = c["event_a"]
        b = c["event_b"]
        if c["relation"] == "BEFORE":
            add_constraint(constraints, seen, a, b, "EXPLICIT_CLAIM", c.get("confidence", "UNKNOWN"), [c.get("source_id")] if c.get("source_id") else [], c.get("evidence_ids"))
        elif c["relation"] == "AFTER":
            add_constraint(constraints, seen, b, a, "EXPLICIT_CLAIM", c.get("confidence", "UNKNOWN"), [c.get("source_id")] if c.get("source_id") else [], c.get("evidence_ids"))

    # Derived from non-overlapping primary intervals
    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            a = events[i]
            b = events[j]
            if a.get("sequence_only") or b.get("sequence_only"):
                continue
            a_start, a_end, _ = timestamp_interval(a, use_corrected=True) if a.get("clock_correction_state") == "APPLIED" else (a.get("start_utc"), a.get("end_utc"), a.get("representative_utc"))
            b_start, b_end, _ = timestamp_interval(b, use_corrected=True) if b.get("clock_correction_state") == "APPLIED" else (b.get("start_utc"), b.get("end_utc"), b.get("representative_utc"))

            # Use event stored intervals already selected
            a_start, a_end = a.get("start_utc"), a.get("end_utc")
            b_start, b_end = b.get("start_utc"), b.get("end_utc")
            if not (a_start and a_end and b_start and b_end):
                continue

            if a_end < b_start:
                add_constraint(constraints, seen, a["event_id"], b["event_id"], "DERIVED_INTERVAL", "SUPPORTED", a.get("source_ids", []), a.get("evidence_ids", []))
            elif b_end < a_start:
                add_constraint(constraints, seen, b["event_id"], a["event_id"], "DERIVED_INTERVAL", "SUPPORTED", b.get("source_ids", []), b.get("evidence_ids", []))

    return constraints


def compute_reachable(nodes: List[str], adj: Dict[str, List[str]]) -> Dict[str, Set[str]]:
    reach: Dict[str, Set[str]] = {}
    for s in nodes:
        seen = set()
        q = deque([s])
        while q:
            n = q.popleft()
            for m in adj.get(n, []):
                if m not in seen:
                    seen.add(m)
                    q.append(m)
        reach[s] = seen
    return reach


def analyze_partial_order(
    events: List[Dict[str, Any]],
    constraints: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes = [e["event_id"] for e in events]
    adj: Dict[str, List[str]] = defaultdict(list)
    indeg: Dict[str, int] = {n: 0 for n in nodes}

    for c in constraints:
        a, b = c["source_event"], c["target_event"]
        if a in indeg and b in indeg:
            adj[a].append(b)
            indeg[b] += 1

    q = deque(sorted([n for n in nodes if indeg[n] == 0]))
    order: List[str] = []
    indeg_work = dict(indeg)

    while q:
        n = q.popleft()
        order.append(n)
        for m in sorted(adj.get(n, [])):
            indeg_work[m] -= 1
            if indeg_work[m] == 0:
                q.append(m)

    cycle_nodes = sorted([n for n in nodes if n not in order])
    cycle_edges = []
    if cycle_nodes:
        cycle_set = set(cycle_nodes)
        for c in constraints:
            if c["source_event"] in cycle_set and c["target_event"] in cycle_set:
                cycle_edges.append(c["constraint_id"])

    reach = compute_reachable(nodes, adj)
    pair_order: Dict[Tuple[str, str], str] = {}
    for i in range(len(nodes)):
        for j in range(len(nodes)):
            if i == j:
                continue
            a, b = nodes[i], nodes[j]
            a_to_b = b in reach.get(a, set())
            b_to_a = a in reach.get(b, set())
            if a_to_b and b_to_a:
                pair_order[(a, b)] = "DISPUTED_CYCLE"
            elif a_to_b:
                pair_order[(a, b)] = "BEFORE"
            elif b_to_a:
                pair_order[(a, b)] = "AFTER"
            else:
                pair_order[(a, b)] = "AMBIGUOUS"

    return {
        "valid_sequence": order if not cycle_nodes else None,
        "cycle_nodes": cycle_nodes,
        "cycle_edges": cycle_edges,
        "reachable": {k: sorted(v) for k, v in reach.items()},
        "pair_order": {f"{a}|{b}": v for (a, b), v in pair_order.items()},
        "constraint_count": len(constraints),
    }


# --------------------------------------------------------------------
# Allen interval relations
# --------------------------------------------------------------------

def seconds_between(a: datetime, b: datetime) -> float:
    return (b - a).total_seconds()


def allen_relation(
    a_start: Optional[datetime],
    a_end: Optional[datetime],
    b_start: Optional[datetime],
    b_end: Optional[datetime],
    tolerance_seconds: float = 0.0,
) -> str:
    if not (a_start and a_end and b_start and b_end):
        return "UNKNOWN"

    if seconds_between(a_end, b_start) > tolerance_seconds:
        return "BEFORE"
    if seconds_between(b_end, a_start) > tolerance_seconds:
        return "AFTER"
    if abs(seconds_between(a_start, b_start)) <= tolerance_seconds and abs(seconds_between(a_end, b_end)) <= tolerance_seconds:
        return "EQUAL"
    if abs(seconds_between(a_end, b_start)) <= tolerance_seconds:
        return "MEETS"
    if abs(seconds_between(b_end, a_start)) <= tolerance_seconds:
        return "MET_BY"
    if a_start <= b_start and b_end <= a_end:
        return "CONTAINS"
    if b_start <= a_start and a_end <= b_end:
        return "DURING"
    if a_start <= b_start <= a_end <= b_end:
        return "OVERLAPS"
    if b_start <= a_start <= b_end <= a_end:
        return "OVERLAPPED_BY"
    return "POSSIBLY_SIMULTANEOUS"


def compute_event_relations(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rels = []
    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            a = events[i]
            b = events[j]
            rel = allen_relation(a.get("start_utc"), a.get("end_utc"), b.get("start_utc"), b.get("end_utc"))
            raw_rel = allen_relation(a.get("raw_start_utc"), a.get("raw_end_utc"), b.get("raw_start_utc"), b.get("raw_end_utc"))
            rels.append({
                "relation_id": stable_id("TREL", a["event_id"], b["event_id"]),
                "event_a": a["event_id"],
                "event_b": b["event_id"],
                "relation": rel,
                "raw_relation": raw_rel,
                "confidence": "SUPPORTED" if rel not in {"UNKNOWN", "POSSIBLY_SIMULTANEOUS"} else "AMBIGUOUS",
                "limitations": [
                    "Allen relation is computed from selected primary event-time interval, not from all timestamp stages.",
                    "Overlap does not imply causality, coordination, or same event.",
                ],
            })
    return rels


# --------------------------------------------------------------------
# Contradictions / coverage / duplicates
# --------------------------------------------------------------------

def detect_expected_order_contradictions(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    contradictions = []
    order_index = {t: i for i, t in enumerate(EXPECTED_TIMESTAMP_ORDER)}

    for ev in events:
        by_type: Dict[str, Dict[str, Any]] = {}
        for ts in ev.get("timestamps", []):
            tt = ts.get("timestamp_type")
            if tt in order_index and tt not in by_type:
                by_type[tt] = ts

        types = sorted(by_type.keys(), key=lambda t: order_index[t])
        for i in range(len(types)):
            for j in range(i + 1, len(types)):
                earlier_type = types[i]
                later_type = types[j]
                e_ts = by_type[earlier_type]
                l_ts = by_type[later_type]
                e_start, e_end, _ = timestamp_interval(e_ts, use_corrected=True)
                l_start, l_end, _ = timestamp_interval(l_ts, use_corrected=True)
                if not (e_start and e_end and l_start and l_end):
                    continue
                if l_end < e_start:
                    contradictions.append({
                        "contradiction_id": stable_id("CTR", "expected_order", ev["event_id"], earlier_type, later_type),
                        "type": "TIMESTAMP_SEMANTIC_ORDER_CONTRADICTION",
                        "severity": "MATERIAL",
                        "event_id": ev["event_id"],
                        "detail": f"{later_type} is strictly earlier than {earlier_type} for the same event after selected clock correction.",
                        "possible_causes": [
                            "timestamp type mislabelled",
                            "clock skew/drift",
                            "timezone error",
                            "different underlying event",
                            "batch/ingestion delay",
                            "source error",
                        ],
                        "limitations": ["Semantic order expectation is heuristic; not all systems obey this ordering."],
                    })
    return contradictions


def ingest_source_coverage(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    coverage = []
    for idx, c in enumerate(manifest.get("source_coverage", []) or []):
        sid = normalize_text(c.get("source_id"))
        start = parse_timestamp_value(c.get("coverage_start"), precision_hint="SECOND").get("representative_utc")
        end = parse_timestamp_value(c.get("coverage_end"), precision_hint="SECOND").get("representative_utc")
        coverage.append({
            "coverage_id": normalize_text(c.get("coverage_id") or f"COV-{idx}"),
            "source_id": sid,
            "coverage_start_utc": start,
            "coverage_end_utc": end,
            "operational": bool(c.get("operational", True)),
            "retention_gap": bool(c.get("retention_gap", False)),
            "limitations": list(c.get("limitations", []) or []),
        })
    return coverage


def detect_coverage_contradictions(
    evidence: List[Dict[str, Any]],
    coverage: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    contradictions = []
    cov_by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in coverage:
        if c.get("source_id"):
            cov_by_source[c["source_id"]].append(c)

    for ev in evidence:
        rep = ev.get("corrected_representative_utc") or ev.get("representative_utc")
        sid = ev.get("source_id")
        if not rep or not sid:
            continue
        for c in cov_by_source.get(sid, []):
            start = c.get("coverage_start_utc")
            end = c.get("coverage_end_utc")
            if (start and rep < start) or (end and rep > end):
                contradictions.append({
                    "contradiction_id": stable_id("CTR", "coverage", ev["evidence_id"], c["coverage_id"]),
                    "type": "COVERAGE_CONTRADICTION",
                    "severity": "MATERIAL",
                    "evidence_id": ev["evidence_id"],
                    "source_id": sid,
                    "coverage_id": c["coverage_id"],
                    "detail": "Timestamp falls outside declared source coverage window.",
                    "possible_causes": [
                        "wrong source coverage window",
                        "timezone error",
                        "clock skew",
                        "replayed/backdated record",
                        "data entry error",
                    ],
                })
    return contradictions


def detect_sequence_contradictions(
    events: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    topo: Dict[str, Any],
) -> List[Dict[str, Any]]:
    contradictions = []

    if topo.get("cycle_nodes"):
        contradictions.append({
            "contradiction_id": stable_id("CTR", "cycle", *topo["cycle_nodes"]),
            "type": "TEMPORAL_CYCLE_CONTRADICTION",
            "severity": "HARD",
            "events": topo["cycle_nodes"],
            "constraints": topo.get("cycle_edges", []),
            "detail": "Partial-order constraints imply a temporal cycle.",
            "possible_causes": [
                "clock skew/drift",
                "timestamp type confusion",
                "event identity error",
                "timezone error",
                "fabricated/altered timestamp (requires evidence, not assumed)",
            ],
        })

    pair_order = topo.get("pair_order", {})
    for c in claims:
        a, b = c["event_a"], c["event_b"]
        rel = c["relation"]
        key = f"{a}|{b}"
        observed = pair_order.get(key, "AMBIGUOUS")
        if rel == "BEFORE" and observed == "AFTER":
            contradictions.append({
                "contradiction_id": stable_id("CTR", "claim_order", c["temporal_claim_id"]),
                "type": "EXPLICIT_ORDER_CONTRADICTION",
                "severity": "MATERIAL",
                "claim_id": c["temporal_claim_id"],
                "events": [a, b],
                "detail": f"Explicit claim says {a} BEFORE {b}, but derived partial order says {b} BEFORE {a}.",
            })
        if rel == "AFTER" and observed == "BEFORE":
            contradictions.append({
                "contradiction_id": stable_id("CTR", "claim_order", c["temporal_claim_id"]),
                "type": "EXPLICIT_ORDER_CONTRADICTION",
                "severity": "MATERIAL",
                "claim_id": c["temporal_claim_id"],
                "events": [a, b],
                "detail": f"Explicit claim says {a} AFTER {b}, but derived partial order says {a} BEFORE {b}.",
            })

    return contradictions


def detect_duplicate_event_candidates(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates = []
    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            a = events[i]
            b = events[j]
            if a.get("event_id") == b.get("event_id"):
                continue
            same_type = a.get("event_type") == b.get("event_type") and a.get("event_type") != "UNKNOWN"
            same_entities = set(a.get("entities", [])) == set(b.get("entities", [])) and bool(a.get("entities"))
            same_ids = a.get("identifiers") == b.get("identifiers") and bool(a.get("identifiers"))
            rel = allen_relation(a.get("start_utc"), a.get("end_utc"), b.get("start_utc"), b.get("end_utc"))
            time_close = rel in {"EQUAL", "OVERLAPS", "OVERLAPPED_BY", "DURING", "CONTAINS", "MEETS", "MET_BY", "POSSIBLY_SIMULTANEOUS"}

            if (same_type and (same_entities or same_ids)) and time_close:
                candidates.append({
                    "candidate_id": stable_id("DUP", a["event_id"], b["event_id"]),
                    "event_a": a["event_id"],
                    "event_b": b["event_id"],
                    "state": "SAME_EVENT_DIFFERENT_SOURCE_CANDIDATE",
                    "confidence": "POSSIBLE",
                    "basis": {
                        "same_event_type": same_type,
                        "same_entities": same_entities,
                        "same_identifiers": same_ids,
                        "temporal_relation": rel,
                    },
                    "limitations": [
                        "Do not merge solely on time similarity.",
                        "Same timestamp does not prove same event.",
                        "Different event stages may legitimately share entities and time windows.",
                    ],
                })
    return candidates


def analyze_source_coverage_gaps(
    events: List[Dict[str, Any]],
    coverage: List[Dict[str, Any]],
    gap_threshold_seconds: float = 86400.0,
) -> Dict[str, Any]:
    times = [e.get("representative_utc") for e in events if e.get("representative_utc")]
    times = sorted([t for t in times if t is not None])

    gaps = []
    for i in range(len(times) - 1):
        delta = (times[i + 1] - times[i]).total_seconds()
        if delta > gap_threshold_seconds:
            gaps.append({
                "gap_id": stable_id("GAP", "time", iso(times[i]), iso(times[i + 1])),
                "type": "TEMPORAL_DATA_GAP",
                "from_utc": times[i],
                "to_utc": times[i + 1],
                "duration_seconds": delta,
                "interpretation": "No event evidence in this interval within provided dataset.",
                "limitations": [
                    "Absence of record is not absence of event.",
                    "Gap may reflect retention, collection outage, timezone issue, or irrelevant period.",
                ],
            })

    dataset_window = None
    if times:
        dataset_window = {"start_utc": times[0], "end_utc": times[-1]}

    return {
        "coverage_records": coverage,
        "dataset_window": dataset_window,
        "temporal_gaps": gaps,
        "limitations": [
            "Coverage is only as good as declared source coverage.",
            "Non-detection does not prove non-occurrence.",
        ],
    }


# --------------------------------------------------------------------
# Fact gate / hypotheses / gaps / actions
# --------------------------------------------------------------------

def apply_fact_gate(
    events: List[Dict[str, Any]],
    constraints: List[Dict[str, Any]],
    topo: Dict[str, Any],
    known_facts: List[Any],
) -> List[Dict[str, Any]]:
    contradictions = []
    event_by_id = {e["event_id"]: e for e in events}

    for idx, fact in enumerate(known_facts or []):
        if isinstance(fact, dict):
            state = normalize_text(fact.get("state", "SUPPORTED")).upper()
            fact_id = normalize_text(fact.get("fact_id") or f"KF-{idx}")

            for eid in fact.get("event_ids", []) or []:
                ev = event_by_id.get(normalize_text(eid))
                if not ev:
                    continue
                if state in {"SUPPORTED", "VERIFIED"}:
                    ev["verification_state"] = "SUPPORTED" if state == "SUPPORTED" else "VERIFIED"
                elif state == "REFUTED":
                    ev["verification_state"] = "REFUTED"
                elif state == "DISPUTED":
                    ev["verification_state"] = "DISPUTED"

            a = normalize_text(fact.get("event_a"))
            b = normalize_text(fact.get("event_b"))
            rel = normalize_relation(fact.get("relation"))
            if a and b and rel in {"BEFORE", "AFTER"}:
                key = f"{a}|{b}"
                observed = topo.get("pair_order", {}).get(key, "AMBIGUOUS")
                expected = "BEFORE" if rel == "BEFORE" else "AFTER"
                if state == "REFUTED" and observed == expected:
                    contradictions.append({
                        "contradiction_id": stable_id("CTR", "fact_gate", fact_id),
                        "type": "FACT_GATE_REFUTED_ORDER",
                        "severity": "HARD",
                        "events": [a, b],
                        "detail": f"Known fact refutes derived order {a} {expected} {b}.",
                    })
                elif state in {"SUPPORTED", "VERIFIED"} and observed == "AMBIGUOUS":
                    # Do not silently add constraint after topo in starter; record as supported claim.
                    pass
        else:
            text = normalize_text(fact).lower()
            if not text:
                continue
            for ev in events:
                label = normalize_text(ev.get("event_type") or ev["event_id"]).lower()
                if label and label in text:
                    ev["verification_state"] = "SUPPORTED"

    return contradictions


def detect_raw_corrected_reversals(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    reversals = []
    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            a = events[i]
            b = events[j]
            raw_rel = allen_relation(a.get("raw_start_utc"), a.get("raw_end_utc"), b.get("raw_start_utc"), b.get("raw_end_utc"))
            corr_rel = allen_relation(a.get("start_utc"), a.get("end_utc"), b.get("start_utc"), b.get("end_utc"))
            if raw_rel == "BEFORE" and corr_rel == "AFTER":
                reversals.append({"event_a": a["event_id"], "event_b": b["event_id"], "raw_relation": raw_rel, "corrected_relation": corr_rel})
            elif raw_rel == "AFTER" and corr_rel == "BEFORE":
                reversals.append({"event_a": a["event_id"], "event_b": b["event_id"], "raw_relation": raw_rel, "corrected_relation": corr_rel})
    return reversals


def generate_hypotheses(
    events: List[Dict[str, Any]],
    constraints: List[Dict[str, Any]],
    topo: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    duplicate_candidates: List[Dict[str, Any]],
    reversals: List[Dict[str, Any]],
    coverage_analysis: Dict[str, Any],
) -> List[Dict[str, Any]]:
    hyp = []
    event_by_id = {e["event_id"]: e for e in events}

    for ctr in contradictions:
        if ctr["type"] == "TEMPORAL_CYCLE_CONTRADICTION":
            evs = ctr.get("events", [])
            hyp.append({
                "hypothesis_id": stable_id("HYP", ctr["contradiction_id"], "clock_skew"),
                "statement": "Temporal cycle may be caused by clock skew/drift or timezone misnormalization.",
                "support": ["Cycle detected in partial order.", "Clock corrections are candidate-only."],
                "opposition": ["Cycle may reflect event identity error or mislabelled timestamp type."],
                "unknowns": ["Reference clock anchors", "NTP/sync logs", "original source timezone"],
                "falsification_conditions": [
                    "Independent synchronized source shows consistent order.",
                    "Clock offset evidence cannot explain reversal.",
                    "Event identity resolution shows distinct events.",
                ],
                "status": "CANDIDATE",
                "events": evs,
            })
            hyp.append({
                "hypothesis_id": stable_id("HYP", ctr["contradiction_id"], "event_identity"),
                "statement": "Records may refer to different events or different event stages.",
                "support": ["Cycle/contradiction present."],
                "opposition": ["Explicit event IDs may assert same event."],
                "unknowns": ["Event fingerprint", "transaction/session/message IDs"],
                "falsification_conditions": [
                    "Stable identifiers confirm same underlying event.",
                    "Timestamp types are verified and consistent.",
                ],
                "status": "CANDIDATE",
                "events": evs,
            })

    for rev in reversals:
        hyp.append({
            "hypothesis_id": stable_id("HYP", rev["event_a"], rev["event_b"], "raw_corrected_reversal"),
            "statement": f"Apparent order reversal between {rev['event_a']} and {rev['event_b']} may be explained by clock correction.",
            "support": [f"raw_relation={rev['raw_relation']}", f"corrected_relation={rev['corrected_relation']}"],
            "opposition": ["Clock offset may be wrong, stale, or drift non-linear.", "Timezone error may mimic skew."],
            "unknowns": ["Clock anchor quality", "offset validity window", "drift model"],
            "falsification_conditions": [
                "Independent reference clock shows raw order was correct.",
                "Declared offset applies outside validity window.",
                "Timezone normalization error explains reversal.",
            ],
            "status": "CANDIDATE",
            "events": [rev["event_a"], rev["event_b"]],
        })

    for dup in duplicate_candidates:
        hyp.append({
            "hypothesis_id": stable_id("HYP", dup["candidate_id"], "same_event"),
            "statement": f"{dup['event_a']} and {dup['event_b']} may be the same underlying event observed by different sources/stages.",
            "support": [f"temporal_relation={dup['basis']['temporal_relation']}", "shared entities/identifiers/event type"],
            "opposition": ["Same time does not prove same event.", "Different event stages can overlap."],
            "unknowns": ["Stable event ID", "payload hash", "session/transaction/message ID"],
            "falsification_conditions": [
                "Distinct stable identifiers prove separate events.",
                "Timestamp types correspond to different stages of one process but not same atomic event.",
            ],
            "status": "CANDIDATE",
            "events": [dup["event_a"], dup["event_b"]],
        })

    for gap in coverage_analysis.get("temporal_gaps", [])[:50]:
        hyp.append({
            "hypothesis_id": stable_id("HYP", gap["gap_id"], "missing_data"),
            "statement": "Temporal gap may reflect missing collection/retention rather than absence of events.",
            "support": [f"gap_duration_seconds={gap['duration_seconds']}"],
            "opposition": ["Period may genuinely contain no relevant events."],
            "unknowns": ["Sensor operational status", "retention policy", "collection coverage"],
            "falsification_conditions": [
                "Source coverage confirms operational continuous logging in gap.",
                "Independent sources show no activity in interval.",
            ],
            "status": "CANDIDATE",
            "gap_id": gap["gap_id"],
        })

    # Ambiguous order hypotheses for top few pairs
    pair_order = topo.get("pair_order", {})
    ambiguous = [(k, v) for k, v in pair_order.items() if v == "AMBIGUOUS"]
    for key, _ in ambiguous[:50]:
        a, b = key.split("|", 1)
        if a not in event_by_id or b not in event_by_id:
            continue
        hyp.append({
            "hypothesis_id": stable_id("HYP", a, b, "order_ambiguous"),
            "statement": f"Order between {a} and {b} is ambiguous under current evidence.",
            "support": ["No non-overlapping interval or constraint establishes order."],
            "opposition": ["Additional synchronized source or stable identifier may resolve order."],
            "unknowns": ["event-time vs record-time", "clock quality", "timezone"],
            "falsification_conditions": [
                "Independent high-quality event-time evidence orders the events.",
                "Clock/timezone correction resolves non-overlap.",
            ],
            "status": "ORDER_AMBIGUOUS",
            "events": [a, b],
        })

    return hyp[:500]


def build_unknowns(
    events: List[Dict[str, Any]],
    topo: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    coverage_analysis: Dict[str, Any],
) -> List[str]:
    unknowns = []
    for ev in events:
        if ev.get("sequence_only"):
            unknowns.append(f"Event {ev['event_id']} has sequence-only evidence; absolute time unresolved.")
        if ev.get("timezone_state") == "UNKNOWN" if isinstance(ev, dict) else False:
            pass
        for ts in ev.get("timestamps", []):
            if ts.get("timezone_state") == "UNKNOWN":
                unknowns.append(f"Evidence {ts['evidence_id']} timezone unresolved.")
            if ts.get("correction_state") in {"NO_CLOCK", "OUTSIDE_VALIDITY", "UNKNOWN_TIME"}:
                unknowns.append(f"Evidence {ts['evidence_id']} clock correction unresolved: {ts.get('correction_state')}.")
    if topo.get("cycle_nodes"):
        unknowns.append(f"Temporal cycle unresolved among events: {', '.join(topo['cycle_nodes'])}.")
    for gap in coverage_analysis.get("temporal_gaps", [])[:50]:
        unknowns.append(f"Temporal data gap between {iso(gap['from_utc'])} and {iso(gap['to_utc'])}.")
    return list(dict.fromkeys(unknowns))[:500]


def build_gaps(
    events: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    coverage_analysis: Dict[str, Any],
    duplicate_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps = []

    for ev in evidence:
        if ev.get("timezone_state") == "UNKNOWN":
            gaps.append({
                "gap_id": stable_id("GAP", "tz", ev["evidence_id"]),
                "type": "TIMEZONE_UNRESOLVED",
                "importance": "HIGH",
                "evidence_id": ev["evidence_id"],
                "recommended_source": "Original log schema, system timezone config, NTP/source documentation, or independent anchored timestamp.",
                "specialist": "TIMELINEINT / LOGINT / METADATAINT",
                "expected_information_value": "Reduce false ordering caused by timezone assumptions.",
            })
        if ev.get("correction_state") in {"NO_CLOCK", "OUTSIDE_VALIDITY", "UNKNOWN_TIME"}:
            gaps.append({
                "gap_id": stable_id("GAP", "clock", ev["evidence_id"]),
                "type": "CLOCK_UNRESOLVED",
                "importance": "HIGH",
                "evidence_id": ev["evidence_id"],
                "recommended_source": "NTP logs, signed timestamps, common anchor event, or device sync metadata.",
                "specialist": "TIMELINEINT / LOGINT",
                "expected_information_value": "Distinguish true event order from clock artifacts.",
            })
        if ev.get("precision") in {"UNKNOWN", "DAY", "MONTH", "YEAR"}:
            gaps.append({
                "gap_id": stable_id("GAP", "precision", ev["evidence_id"]),
                "type": "TIME_PRECISION_LOW",
                "importance": "MEDIUM",
                "evidence_id": ev["evidence_id"],
                "recommended_source": "Original system log, transaction record, media container metadata, or higher-resolution sensor.",
                "specialist": "TIMELINEINT / DOCINT / IMINT / VIDINT",
                "expected_information_value": "Reduce false precision and improve interval reasoning.",
            })

    for ctr in contradictions[:100]:
        gaps.append({
            "gap_id": stable_id("GAP", "contradiction", ctr["contradiction_id"]),
            "type": "TEMPORAL_CONTRADICTION_UNRESOLVED",
            "importance": "HIGH",
            "contradiction_id": ctr["contradiction_id"],
            "recommended_source": "Independent synchronized source, original raw log, clock anchor, or event identity evidence.",
            "specialist": "TIMELINEINT / LOGINT / INCIDENTINT",
            "expected_information_value": "Resolve whether conflict is benign temporal artifact or substantive inconsistency.",
        })

    for dup in duplicate_candidates[:100]:
        gaps.append({
            "gap_id": stable_id("GAP", "event_identity", dup["candidate_id"]),
            "type": "EVENT_IDENTITY_AMBIGUOUS",
            "importance": "MEDIUM",
            "candidate_id": dup["candidate_id"],
            "recommended_source": "Stable event ID, transaction ID, session ID, message ID, payload hash, or original source schema.",
            "specialist": "TIMELINEINT / LOGINT / EVENTINT",
            "expected_information_value": "Prevent false event merge or false duplicate chronology.",
        })

    for gap in coverage_analysis.get("temporal_gaps", [])[:100]:
        gaps.append({
            "gap_id": gap["gap_id"],
            "type": "SOURCE_COVERAGE_INCOMPLETE",
            "importance": "MEDIUM",
            "from_utc": gap["from_utc"],
            "to_utc": gap["to_utc"],
            "recommended_source": "Retention policy, sensor operational log, alternate independent source, or archive capture.",
            "specialist": "TIMELINEINT / LOGINT / ARCHIVEINT",
            "expected_information_value": "Distinguish missing data from non-occurrence.",
        })

    return gaps[:500]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    priority_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for g in gaps:
        if g["type"] == "TIMEZONE_UNRESOLVED":
            action = "Retrieve original timezone/source schema or independent anchored timestamp; do not silently assume timezone."
        elif g["type"] == "CLOCK_UNRESOLVED":
            action = "Obtain NTP/sync evidence or common anchor event; preserve raw and corrected candidate times."
        elif g["type"] == "TIME_PRECISION_LOW":
            action = "Request higher-resolution original record; represent approximate times as intervals."
        elif g["type"] == "TEMPORAL_CONTRADICTION_UNRESOLVED":
            action = "Compare independent synchronized sources and test clock/timezone/event-identity explanations before accepting order."
        elif g["type"] == "EVENT_IDENTITY_AMBIGUOUS":
            action = "Resolve stable event identifiers before merging or deduplicating events."
        elif g["type"] == "SOURCE_COVERAGE_INCOMPLETE":
            action = "Check source operational/retention coverage; absence of record is not absence of event."
        else:
            action = "Gather additional authorized temporal evidence."

        actions.append({
            "action": action,
            "gap_id": g.get("gap_id"),
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not fabricate or alter timestamps.",
                "Do not track private persons in real time.",
                "Do not infer causality from sequence alone.",
                "Do not create false precision from approximate time.",
            ],
        })
    actions.sort(key=lambda x: priority_map.get(x.get("priority", "LOW"), 9))
    return actions[:200]


def build_handoffs(manifest: Dict[str, Any], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    blob = collect_user_intent_text(manifest).lower()
    types = {e.get("event_type", "").lower() for e in events}
    hands = []

    def add(spec: str, reason: str) -> None:
        hands.append({
            "specialist": spec,
            "reason": reason,
            "payload": ["event_ids", "raw_timestamps", "normalized_timestamps", "timezone_assumptions", "precision", "uncertainty", "known_facts", "contradictions", "evidence_ids"],
        })

    if any("log" in t or "siem" in t or "edr" in t for t in types) or "log" in blob:
        add("LOGINT", "Log schema/timestamp semantics require log specialist analysis.")
    if any("incident" in t for t in types) or "incident" in blob:
        add("INCIDENTINT", "Incident meaning/root cause requires incident specialist; TIMELINEINT only orders evidence.")
    if any("network" in t or "dns" in t or "flow" in t for t in types) or "network" in blob:
        add("NETINT / DNSINT", "Network/DNS timing semantics require specialist correlation.")
    if any("media" in t or "video" in t or "image" in t or "exif" in t for t in types) or "media" in blob:
        add("IMINT / VIDINT / AUDINT", "Media capture/publication time requires media specialist metadata analysis.")
    if any("financial" in t or "payment" in t or "settlement" in t for t in types) or "financial" in blob:
        add("FININT / PAYMENTINT", "Authorization/posting/settlement semantics require financial specialist.")
    if any("trade" in t or "shipment" in t for t in types) or "trade" in blob:
        add("TRADEINT", "Shipment/customs/delivery timing requires trade specialist.")
    if any("corporate" in t or "filing" in t for t in types) or "corporate" in blob:
        add("CORPINT", "Corporate effective dates/filing chronology requires corporate specialist.")
    if any("human" in t or "witness" in t for t in types) or "humint" in blob:
        add("HUMINT", "Human approximate memory timelines require source-handling care.")
    return hands


def dual_ai_review_stub(events: List[Dict[str, Any]], topo: Dict[str, Any], contradictions: List[Dict[str, Any]]) -> Dict[str, Any]:
    review = {
        "status": "INSUFFICIENT_EVIDENCE",
        "primary_conclusions": [],
        "skeptic_challenges": [],
        "comparison": "NO_SECOND_MODEL_CONFIGURED",
        "notes": [
            "This starter does not call an independent second model.",
            "AI agreement is not temporal corroboration.",
            "Human review is required for consequential event-order or causality claims.",
        ],
    }
    if topo.get("valid_sequence"):
        review["primary_conclusions"].append("A partial-order sequence was reconstructed from non-contradictory constraints.")
        review["skeptic_challenges"].append("Check timestamp semantics, clock skew, timezone assumptions, and event identity before accepting sequence.")
    if contradictions:
        review["primary_conclusions"].append(f"{len(contradictions)} temporal contradiction candidate(s) detected.")
        review["skeptic_challenges"].append("Contradictions may be benign: ingestion delay, batch processing, DST, clock drift, metadata error, or different event stages.")
    if any(e.get("clock_correction_state") == "APPLIED" for e in events):
        review["primary_conclusions"].append("Clock-corrected candidate times influenced ordering.")
        review["skeptic_challenges"].append("Clock correction must remain candidate-only; raw times preserved and offset validity checked.")
    if review["primary_conclusions"]:
        review["status"] = "PARTIAL_AGREEMENT"
    return review


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
            "note": "Temporal graph preserves raw/normalized/corrected states and uncertainty. It is not proof of causality.",
        }


def build_graph_memory(
    events: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    constraints: List[Dict[str, Any]],
    relations: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> GraphMemory:
    g = GraphMemory()

    for ev in evidence:
        g.add_node("Timestamp", ev["evidence_id"], {
            "raw": ev.get("raw_timestamp"),
            "type": ev.get("timestamp_type"),
            "normalized_start": iso(ev.get("normalized_start_utc")),
            "normalized_end": iso(ev.get("normalized_end_utc")),
            "corrected_start": iso(ev.get("corrected_start_utc")),
            "corrected_end": iso(ev.get("corrected_end_utc")),
            "precision": ev.get("precision"),
            "uncertainty_seconds": ev.get("uncertainty_seconds"),
            "timezone_state": ev.get("timezone_state"),
            "correction_state": ev.get("correction_state"),
        })

    for e in events:
        g.add_node("Event", e["event_id"], {
            "event_type": e.get("event_type"),
            "start": iso(e.get("start_utc")),
            "end": iso(e.get("end_utc")),
            "precision": e.get("time_precision"),
            "verification_state": e.get("verification_state"),
        })
        for evid in e.get("evidence_ids", []):
            g.add_edge(e["event_id"], evid, "HAS_TIMESTAMP_EVIDENCE", {"method": "event_construction"})

    for c in constraints:
        g.add_edge(c["source_event"], c["target_event"], "OCCURRED_BEFORE", {
            "constraint_id": c["constraint_id"],
            "origin": c["origin"],
            "confidence": c["confidence"],
        })

    for r in relations:
        if r["relation"] not in {"UNKNOWN"}:
            g.add_edge(r["event_a"], r["event_b"], f"TEMPORAL_{r['relation']}", {
                "relation_id": r["relation_id"],
                "confidence": r["confidence"],
            })

    for ctr in contradictions[:500]:
        g.add_node("Contradiction", ctr["contradiction_id"], {
            "type": ctr["type"],
            "severity": ctr["severity"],
            "detail": ctr.get("detail"),
        })
        for eid in ctr.get("events", [])[:10]:
            g.add_edge(ctr["contradiction_id"], eid, "CONTRADICTS_EVENT_ORDER", {"severity": ctr["severity"]})

    for h in hypotheses[:500]:
        g.add_node("Hypothesis", h["hypothesis_id"], {
            "statement": h["statement"],
            "status": h["status"],
        })

    for gap in gaps[:500]:
        g.add_node("Gap", gap["gap_id"], {
            "type": gap["type"],
            "importance": gap["importance"],
        })

    return g


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
        "events": [],
        "event_families": [],
        "raw_timestamps": [],
        "normalized_timestamps": [],
        "timestamp_types": [],
        "timezones": [],
        "timezone_resolution_states": [],
        "clock_objects": [],
        "clock_offsets": [],
        "clock_drift": [],
        "clock_quality": [],
        "precision": [],
        "uncertainty_intervals": [],
        "event_start_times": [],
        "event_end_times": [],
        "event_durations": [],
        "temporal_relations": [],
        "partial_order_graph": {},
        "event_sequences": [],
        "simultaneous_event_groups": [],
        "duplicate_events": [],
        "state_changes": [],
        "timeline_versions": [],
        "timeline_diffs": [],
        "source_coverage": {},
        "source_reliability": [],
        "source_bias": [],
        "source_limitations": [],
        "source_pedigree": [],
        "source_independence": [],
        "observations": [],
        "candidate_facts": [],
        "supported_facts": [],
        "partial_facts": [],
        "disputed_facts": [],
        "temporal_contradictions": [],
        "hypotheses": [],
        "falsification_results": [],
        "causal_claim_states": {},
        "missing_event_gaps": [],
        "knowledge_gaps": [],
        "privacy_flags": [],
        "recommended_next_actions": [],
        "specialist_handoffs": [],
        "limitations": [],
        "dual_ai_review": {},
        "graph_memory": {},
        "status": "PARTIAL",
    }


def summarize_event(e: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(e)
    # Keep timestamps list but trim heavy fields in output.
    out["timestamps"] = [
        {
            "evidence_id": ts.get("evidence_id"),
            "source_id": ts.get("source_id"),
            "timestamp_type": ts.get("timestamp_type"),
            "raw_timestamp": ts.get("raw_timestamp"),
            "normalized_start_utc": iso(ts.get("normalized_start_utc")),
            "normalized_end_utc": iso(ts.get("normalized_end_utc")),
            "corrected_start_utc": iso(ts.get("corrected_start_utc")),
            "corrected_end_utc": iso(ts.get("corrected_end_utc")),
            "precision": ts.get("precision"),
            "uncertainty_seconds": ts.get("uncertainty_seconds"),
            "timezone_state": ts.get("timezone_state"),
            "clock_id": ts.get("clock_id"),
            "clock_offset_seconds": ts.get("clock_offset_seconds"),
            "correction_state": ts.get("correction_state"),
            "limitations": ts.get("limitations", [])[:5],
        }
        for ts in e.get("timestamps", [])[:50]
    ]
    for k in ("start_utc", "end_utc", "representative_utc", "raw_start_utc", "raw_end_utc", "raw_representative_utc"):
        if k in out:
            out[k] = iso(out[k])
    return out


def finalize_status(
    result: Dict[str, Any],
    events: List[Dict[str, Any]],
    auth_ok: bool,
    policy_blocked: List[str],
) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not events:
        return "INSUFFICIENT_INPUT"
    if result.get("temporal_contradictions"):
        return "PARTIAL"
    if any(e.get("sequence_only") for e in events):
        return "PARTIAL"
    if result.get("knowledge_gaps"):
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_timeline_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["privacy_flags"] = [{"type": label, "action": "PROHIBITED_REQUEST_NOT_PERFORMED"} for label in policy_blocked]
        result["limitations"] = [
            "TIMELINEINT does not track private persons, construct targeting timelines, fabricate/alter timestamps, or infer causality from sequence alone."
        ]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    sources = ingest_sources(manifest)
    source_roots = build_source_roots(sources)
    clocks = ingest_clocks(manifest)
    evidence = ingest_temporal_evidence(manifest, sources, clocks)
    events = build_events(evidence, sources, source_roots)
    claims = ingest_temporal_claims(manifest)
    constraints = build_constraints(events, claims)
    topo = analyze_partial_order(events, constraints)
    relations = compute_event_relations(events)
    coverage = ingest_source_coverage(manifest)
    coverage_analysis = analyze_source_coverage_gaps(events, coverage)

    contradictions = []
    contradictions.extend(detect_sequence_contradictions(events, claims, topo))
    contradictions.extend(detect_expected_order_contradictions(events))
    contradictions.extend(detect_coverage_contradictions(evidence, coverage))

    duplicate_candidates = detect_duplicate_event_candidates(events)
    reversals = detect_raw_corrected_reversals(events)

    fact_gate_contradictions = apply_fact_gate(events, constraints, topo, manifest.get("known_facts", []) or [])
    contradictions.extend(fact_gate_contradictions)

    hypotheses = generate_hypotheses(events, constraints, topo, contradictions, duplicate_candidates, reversals, coverage_analysis)
    gaps = build_gaps(events, evidence, contradictions, coverage_analysis, duplicate_candidates)
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(manifest, events)
    dual_review = dual_ai_review_stub(events, topo, contradictions)
    graph = build_graph_memory(events, evidence, constraints, relations, contradictions, hypotheses, gaps)

    # Causality boundary
    intent = collect_user_intent_text(manifest).lower()
    causal_requested = bool(re.search(r"(cause|why|root cause|consequence)", intent))
    result["causal_claim_states"] = {
        "requested": causal_requested,
        "state": "CAUSALITY_UNRESOLVED" if causal_requested else "TEMPORAL_ONLY",
        "limitations": [
            "Temporal order alone does not establish causality.",
            "Causal claims require mechanism, independent evidence, and domain-specialist support.",
        ],
    }

    # Populate result
    result["events"] = [summarize_event(e) for e in events]
    result["temporal_relations"] = relations
    result["partial_order_graph"] = {
        "valid_sequence": topo.get("valid_sequence"),
        "cycle_nodes": topo.get("cycle_nodes"),
        "cycle_edges": topo.get("cycle_edges"),
        "constraint_count": topo.get("constraint_count"),
        "pair_order_sample": dict(list(topo.get("pair_order", {}).items())[:500]),
    }
    result["event_sequences"] = [topo.get("valid_sequence")] if topo.get("valid_sequence") else []
    result["duplicate_events"] = duplicate_candidates
    result["temporal_contradictions"] = contradictions
    result["hypotheses"] = hypotheses
    result["falsification_results"] = [
        {
            "hypothesis_id": h["hypothesis_id"],
            "opposition": h.get("opposition"),
            "falsification_conditions": h.get("falsification_conditions"),
        }
        for h in hypotheses
    ]
    result["source_coverage"] = json_safe(coverage_analysis)
    result["knowledge_gaps"] = gaps
    result["recommended_next_actions"] = actions
    result["specialist_handoffs"] = handoffs
    result["dual_ai_review"] = dual_review
    result["graph_memory"] = graph.to_dict()
    result["unknowns"] = build_unknowns(events, topo, contradictions, coverage_analysis)

    for sid, src in sources.items():
        result["source_ids"].append(sid)
        result["source_reliability"].append({
            "source_id": sid,
            "source_type": src.get("source_type"),
            "reliability": src.get("reliability"),
        })
        result["source_pedigree"].append({
            "source_id": sid,
            "upstream_source_id": src.get("upstream_source_id"),
            "root_source_id": source_roots.get(sid, sid),
        })

    for cid, clock in clocks.items():
        result["clock_objects"].append({
            "clock_id": cid,
            "source_system": clock.get("source_system"),
            "timezone": clock.get("timezone"),
            "sync_method": clock.get("sync_method"),
            "quality": clock.get("quality"),
            "offset_seconds": clock.get("offset_seconds"),
            "drift_seconds_per_day": clock.get("drift_seconds_per_day"),
            "offset_valid_from": iso(clock.get("offset_valid_from")),
            "offset_valid_to": iso(clock.get("offset_valid_to")),
        })

    for ev in evidence:
        result["evidence_ids"].append(ev["evidence_id"])
        result["raw_timestamps"].append({
            "evidence_id": ev["evidence_id"],
            "raw_timestamp": ev.get("raw_timestamp"),
            "timestamp_type": ev.get("timestamp_type"),
            "source_id": ev.get("source_id"),
        })
        result["normalized_timestamps"].append({
            "evidence_id": ev["evidence_id"],
            "normalized_start_utc": iso(ev.get("normalized_start_utc")),
            "normalized_end_utc": iso(ev.get("normalized_end_utc")),
            "corrected_start_utc": iso(ev.get("corrected_start_utc")),
            "corrected_end_utc": iso(ev.get("corrected_end_utc")),
            "precision": ev.get("precision"),
            "uncertainty_seconds": ev.get("uncertainty_seconds"),
            "correction_state": ev.get("correction_state"),
        })
        result["timestamp_types"].append({"evidence_id": ev["evidence_id"], "type": ev.get("timestamp_type")})
        result["timezones"].append({"evidence_id": ev["evidence_id"], "timezone_state": ev.get("timezone_state"), "hint": ev.get("timezone_hint")})
        result["timezone_resolution_states"].append({"evidence_id": ev["evidence_id"], "state": ev.get("timezone_state")})
        result["precision"].append({"evidence_id": ev["evidence_id"], "precision": ev.get("precision")})
        result["uncertainty_intervals"].append({
            "evidence_id": ev["evidence_id"],
            "uncertainty_seconds": ev.get("uncertainty_seconds"),
            "start": iso(ev.get("corrected_start_utc") or ev.get("normalized_start_utc")),
            "end": iso(ev.get("corrected_end_utc") or ev.get("normalized_end_utc")),
        })
        if ev.get("clock_offset_seconds") is not None:
            result["clock_offsets"].append({"evidence_id": ev["evidence_id"], "clock_id": ev.get("clock_id"), "offset_seconds": ev.get("clock_offset_seconds")})
        if ev.get("clock_quality"):
            result["clock_quality"].append({"evidence_id": ev["evidence_id"], "clock_id": ev.get("clock_id"), "quality": ev.get("clock_quality")})

    for e in events:
        result["event_start_times"].append({"event_id": e["event_id"], "start_utc": iso(e.get("start_utc")), "raw_start_utc": iso(e.get("raw_start_utc"))})
        result["event_end_times"].append({"event_id": e["event_id"], "end_utc": iso(e.get("end_utc")), "raw_end_utc": iso(e.get("raw_end_utc"))})
        if e.get("start_utc") and e.get("end_utc"):
            duration = (e["end_utc"] - e["start_utc"]).total_seconds()
            result["event_durations"].append({"event_id": e["event_id"], "duration_seconds": duration, "basis": "selected primary interval"})
        if e.get("verification_state") in {"SUPPORTED", "VERIFIED"}:
            result["supported_facts"].append({"event_id": e["event_id"], "statement": f"Event {e['event_id']} supported by provided facts/evidence."})
        elif e.get("verification_state") == "DISPUTED":
            result["disputed_facts"].append({"event_id": e["event_id"], "statement": f"Event {e['event_id']} disputed."})
        else:
            result["candidate_facts"].append({"event_id": e["event_id"], "statement": f"Event {e['event_id']} source-reported candidate."})

    # Observations
    obs = []
    obs.append(f"Events constructed: {len(events)}.")
    obs.append(f"Temporal evidence items: {len(evidence)}.")
    obs.append(f"Partial-order constraints: {len(constraints)}.")
    if topo.get("valid_sequence"):
        obs.append("A non-contradictory partial-order sequence was reconstructed.")
    if topo.get("cycle_nodes"):
        obs.append("Temporal cycle detected; event order is disputed until clock/timezone/event-identity explanations are tested.")
    if reversals:
        obs.append("Raw vs clock-corrected order reversal candidates detected; raw times preserved and corrections remain candidate-only.")
    if duplicate_candidates:
        obs.append("Duplicate/same-event candidates detected; not merged automatically.")
    if coverage_analysis.get("temporal_gaps"):
        obs.append("Temporal data gaps detected; absence of record is not absence of event.")
    obs.append("No causality was inferred from sequence alone.")
    obs.append("No private-person real-time tracking, targeting timeline, or timestamp fabrication was performed.")
    result["observations"] = obs

    base_limits = [
        "TIMELINEINT starter uses only provided/local authorized records; no external network lookup was performed.",
        "Raw timestamps are preserved; normalized and clock-corrected times are separate derived representations.",
        "Timestamp precision is not timestamp accuracy.",
        "Record/publication/ingestion/discovery time are not automatically event time.",
        "Clock corrections are candidate adjustments based on declared offsets/drift.",
        "Temporal order does not establish causality.",
        "Absence of evidence in a coverage gap is not evidence of absence.",
        "Dependent/copied timestamps are not independent corroboration.",
        "No real-time private-person tracking, stalking, targeting, or timestamp alteration was performed.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

    result["status"] = finalize_status(result, events, auth_ok, policy_blocked)
    return result


# --------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------

def generate_report(result: Dict[str, Any]) -> str:
    lines = []
    lines.append("# TIMELINEINT Evidence-Linked Report")
    lines.append("")
    lines.append(f"- Case ID: `{result.get('case_id')}`")
    lines.append(f"- Task ID: `{result.get('task_id')}`")
    lines.append(f"- Generated: `{result.get('generated_at')}`")
    lines.append(f"- Version: `{result.get('version')}`")
    lines.append(f"- Status: `{result.get('status')}`")
    lines.append("")

    if result.get("status") == "POLICY_BLOCKED":
        lines.append("## POLICY BLOCKED")
        lines.append("The request violated TIMELINEINT hard restrictions:")
        for v in result.get("violations", []):
            lines.append(f"- `{v}`")
        lines.append("")
        lines.append("No timeline reconstruction was performed.")
        return "\n".join(lines)

    lines.append("## Objective")
    lines.append(str(result.get("objective", "")))
    lines.append("")

    lines.append("## Required Analyst Summary")
    events = result.get("events", [])
    topo = result.get("partial_order_graph", {})
    lines.append(f"- EVENTS: {len(events)}")
    lines.append(f"- EVIDENCE ITEMS: {len(result.get('raw_timestamps', []))}")
    lines.append(f"- CONSTRAINTS: {topo.get('constraint_count', 0)}")
    lines.append(f"- VALID SEQUENCE: `{topo.get('valid_sequence')}`")
    lines.append(f"- CYCLE NODES: `{topo.get('cycle_nodes')}`")
    lines.append(f"- TEMPORAL CONTRADICTIONS: {len(result.get('temporal_contradictions', []))}")
    lines.append(f"- DUPLICATE/SAME-EVENT CANDIDATES: {len(result.get('duplicate_events', []))}")
    lines.append(f"- TEMPORAL DATA GAPS: {len(result.get('source_coverage', {}).get('temporal_gaps', []))}")
    lines.append(f"- KNOWLEDGE GAPS: {len(result.get('knowledge_gaps', []))}")
    lines.append("- CAUSALITY BOUNDARY: " + str(result.get("causal_claim_states", {}).get("state", "TEMPORAL_ONLY")))
    lines.append("- NEXT ACTION: " + (result.get("recommended_next_actions", [{}])[0].get("action", "None") if result.get("recommended_next_actions") else "None"))
    lines.append("")

    lines.append("## Privacy / Temporal Boundaries")
    lines.append("- No real-time private-person tracking or stalking timeline.")
    lines.append("- No targeting, attack-timing, surveillance-avoidance, or predictive-schedule output.")
    lines.append("- No fabricated, altered, or overwritten timestamps.")
    lines.append("- Raw time preserved separately from normalized/corrected candidate time.")
    lines.append("- Sequence is not causality.")
    lines.append("- Absence of record is not absence of event.")
    lines.append("")

    lines.append("## Clock Inventory")
    for c in result.get("clock_objects", [])[:100]:
        lines.append(f"- `{c.get('clock_id')}` system=`{c.get('source_system')}` quality=`{c.get('quality')}` offset=`{c.get('offset_seconds')}s` drift=`{c.get('drift_seconds_per_day')}s/day`")
    lines.append("")

    lines.append("## Event Timeline")
    for e in events[:300]:
        lines.append(f"### `{e.get('event_id')}` — {e.get('event_type')}")
        lines.append(f"- Selected interval: `{e.get('start_utc')}` to `{e.get('end_utc')}`")
        lines.append(f"- Raw interval: `{e.get('raw_start_utc')}` to `{e.get('raw_end_utc')}`")
        lines.append(f"- Precision: `{e.get('time_precision')}` uncertainty=`{e.get('time_uncertainty_seconds')}s`")
        lines.append(f"- Clock correction: `{e.get('clock_correction_state')}` clock=`{e.get('clock_id')}`")
        lines.append(f"- Verification: `{e.get('verification_state')}` confidence=`{e.get('confidence_score')}`")
        lines.append(f"- Source independence: `{e.get('source_independence_state')}` independent_families=`{e.get('independent_source_family_count')}`")
        if e.get("timestamps"):
            lines.append("- Timestamps:")
            for ts in e["timestamps"][:20]:
                lines.append(
                    f"  - `{ts.get('evidence_id')}` type=`{ts.get('timestamp_type')}` raw=`{ts.get('raw_timestamp')}` "
                    f"norm=`{ts.get('normalized_start_utc')}` corr=`{ts.get('corrected_start_utc')}` "
                    f"tz=`{ts.get('timezone_state')}` corr_state=`{ts.get('correction_state')}`"
                )
        if e.get("limitations"):
            lines.append("- Limitations:")
            for lim in e["limitations"][:5]:
                lines.append(f"  - {lim}")
        lines.append("")

    lines.append("## Temporal Relations")
    for r in result.get("temporal_relations", [])[:200]:
        lines.append(f"- `{r.get('event_a')}` ↔ `{r.get('event_b')}`: relation=`{r.get('relation')}` raw=`{r.get('raw_relation')}` confidence=`{r.get('confidence')}`")
    lines.append("")

    lines.append("## Contradictions")
    for c in result.get("temporal_contradictions", [])[:200]:
        lines.append(f"- `{c.get('contradiction_id')}` [{c.get('severity')}] {c.get('type')}: {c.get('detail')}")
        if c.get("events"):
            lines.append(f"  - events: {', '.join(c['events'])}")
        if c.get("possible_causes"):
            lines.append(f"  - possible causes: {'; '.join(c['possible_causes'])}")
    lines.append("")

    lines.append("## Duplicate / Same-Event Candidates")
    for d in result.get("duplicate_events", [])[:100]:
        lines.append(f"- `{d.get('candidate_id')}`: `{d.get('event_a')}` ↔ `{d.get('event_b')}` state=`{d.get('state')}` basis={json.dumps(d.get('basis'), ensure_ascii=False)}")
    lines.append("")

    lines.append("## Source Coverage / Gaps")
    sc = result.get("source_coverage", {})
    lines.append(f"- Dataset window: `{sc.get('dataset_window')}`")
    for g in sc.get("temporal_gaps", [])[:100]:
        lines.append(f"- Gap `{g.get('gap_id')}`: `{g.get('from_utc')}` to `{g.get('to_utc')}` duration=`{g.get('duration_seconds')}s`")
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
    lines.append("- Preserve raw time.")
    lines.append("- Identify what the timestamp means.")
    lines.append("- Resolve timezone explicitly or label assumption.")
    lines.append("- Check clock quality before correcting.")
    lines.append("- Represent uncertainty.")
    lines.append("- Build partial order before inventing exact order.")
    lines.append("- Separate sequence from causality.")
    lines.append("- Time-bound everything.")

    return "\n".join(lines)


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEATLAS TIMELINEINT safe starter")
    parser.add_argument("--manifest", required=True, help="Path to TIMELINEINT manifest JSON")
    parser.add_argument("--output", default="timelineint_result.json", help="Output JSON path")
    parser.add_argument("--report", default="timelineint_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR reading manifest: {exc}", file=sys.stderr)
        return 2

    result = analyze_timeline_manifest(manifest)

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
  "case_id": "TL-CASE-001",
  "task_id": "TL-TASK-001",
  "objective": "Reconstruct authorized incident chronology from provided logs, distinguish event time from record/ingestion time, assess clock skew, and identify temporal contradictions without inferring causality.",
  "questions": [
    "What is the best-supported event order?",
    "Do raw timestamps conflict with clock-corrected timestamps?",
    "Which timestamps are event time vs record time?",
    "What temporal gaps or contradictions remain unresolved?"
  ],
  "authorization": {
    "approved": True,
    "scope": "authorized_logs_and_incidents",
    "model_mode": "LOCAL_ONLY",
    "cloud_approved": False
  },
  "sources": [
    {
      "source_id": "S1",
      "source_type": "siem_export",
      "reliability": 0.82
    },
    {
      "source_id": "S2",
      "source_type": "edr_xdr_log",
      "reliability": 0.78
    },
    {
      "source_id": "S3",
      "source_type": "network_sensor",
      "reliability": 0.72
    }
  ],
  "source_coverage": [
    {
      "coverage_id": "COV1",
      "source_id": "S1",
      "coverage_start": "2026-10-08T09:00:00Z",
      "coverage_end": "2026-10-08T12:00:00Z",
      "operational": True
    },
    {
      "coverage_id": "COV2",
      "source_id": "S2",
      "coverage_start": "2026-10-08T09:00:00Z",
      "coverage_end": "2026-10-08T12:00:00Z",
      "operational": True
    }
  ],
  "clocks": [
    {
      "clock_id": "APP1",
      "source_system": "application-server-01",
      "timezone": "UTC",
      "sync_method": "NTP",
      "quality": "LIKELY_SYNCHRONIZED",
      "offset_seconds": 135.0,
      "drift_seconds_per_day": 0.0,
      "offset_valid_from": "2026-10-08T00:00:00Z",
      "offset_valid_to": "2026-10-09T00:00:00Z"
    }
  ],
  "events": [
    {
      "event_id": "E1",
      "event_type": "authentication",
      "entities": ["account:A", "system:identity"],
      "timestamps": [
        {
          "evidence_id": "EV1",
          "source_id": "S1",
          "timestamp": "2026-10-08T10:02:13Z",
          "timestamp_type": "EVENT_TIME",
          "precision": "SECOND",
          "uncertainty_seconds": 1.0
        }
      ]
    },
    {
      "event_id": "E2",
      "event_type": "privileged_action",
      "entities": ["account:A", "system:app"],
      "timestamps": [
        {
          "evidence_id": "EV2",
          "source_id": "S2",
          "clock_id": "APP1",
          "timestamp": "2026-10-08T10:03:00",
          "timestamp_type": "EVENT_TIME",
          "precision": "SECOND",
          "uncertainty_seconds": 2.0,
          "timezone_hint": "UTC"
        },
        {
          "evidence_id": "EV2B",
          "source_id": "S2",
          "timestamp": "2026-10-08T10:03:18Z",
          "timestamp_type": "RECORDED_TIME",
          "precision": "SECOND"
        }
      ]
    },
    {
      "event_id": "E3",
      "event_type": "network_session",
      "entities": ["account:A", "system:edge"],
      "timestamps": [
        {
          "evidence_id": "EV3",
          "source_id": "S3",
          "timestamp": "2026-10-08T10:01:40Z",
          "timestamp_type": "OBSERVED_TIME",
          "precision": "SECOND",
          "uncertainty_seconds": 3.0
        },
        {
          "evidence_id": "EV3B",
          "source_id": "S3",
          "timestamp": "2026-10-08T10:05:00Z",
          "timestamp_type": "INGESTION_TIME",
          "precision": "SECOND"
        }
      ]
    }
  ],
  "temporal_claims": [
    {
      "temporal_claim_id": "TC1",
      "event_a": "E1",
      "event_b": "E2",
      "relation": "BEFORE",
      "source_id": "S1",
      "confidence": "SOURCE_REPORTED"
    }
  ],
  "known_facts": []
}
