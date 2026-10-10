#!/usr/bin/env python3
"""
TRACEATLAS / EVENTINT — Local evidence-first event intelligence pipeline.

IMPORTANT SAFETY / POLICY NOTES:
- This is a local demo implementation.
- It does NOT access live systems or private records.
- It does NOT fabricate events, timestamps, participants, locations, or causes.
- It does NOT equate correlation with causation.
- It does NOT equate account activity with real-person action.
- It does NOT perform stalking, live tracking, operational targeting,
  sabotage timing, weapon-target scheduling, or critical-infrastructure attack planning.
- Sample data is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


PIPELINE_VERSION = "0.1.0-eventint-temporal-safe-demo"


# =====================================================================
# ENUMS
# =====================================================================

class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    EVENT_UNRESOLVED = "EVENT_UNRESOLVED"
    TIME_UNRESOLVED = "TIME_UNRESOLVED"
    SEQUENCE_UNRESOLVED = "SEQUENCE_UNRESOLVED"
    CAUSALITY_UNRESOLVED = "CAUSALITY_UNRESOLVED"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class SourceType(str, Enum):
    SYSTEM_LOG = "SYSTEM_LOG"
    APPLICATION_LOG = "APPLICATION_LOG"
    NETWORK_TELEMETRY = "NETWORK_TELEMETRY"
    IDENTITY_LOG = "IDENTITY_LOG"
    OFFICIAL_RECORD = "OFFICIAL_RECORD"
    CORPORATE_FILING = "CORPORATE_FILING"
    TRANSACTION_RECORD = "TRANSACTION_RECORD"
    TRADE_RECORD = "TRADE_RECORD"
    TRANSPORT_RECORD = "TRANSPORT_RECORD"
    AIS_RECORD = "AIS_RECORD"
    SATELLITE_OBSERVATION = "SATELLITE_OBSERVATION"
    SEISMIC_RECORD = "SEISMIC_RECORD"
    ENVIRONMENTAL_OBSERVATION = "ENVIRONMENTAL_OBSERVATION"
    DOCUMENT = "DOCUMENT"
    MEDIA = "MEDIA"
    AGGREGATOR = "AGGREGATOR"
    SOCIAL_POST = "SOCIAL_POST"
    HUMAN_SOURCE = "HUMAN_SOURCE"
    PERSON_SELF_REPORT = "PERSON_SELF_REPORT"
    CTI_REPORT = "CTI_REPORT"
    OTHER = "OTHER"


class VerificationState(str, Enum):
    REPORTED = "REPORTED"
    OBSERVED = "OBSERVED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    SUPPORTED = "SUPPORTED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    RETRACTED = "RETRACTED"
    FALSE_REPORT_CANDIDATE = "FALSE_REPORT_CANDIDATE"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"


class TemporalPrecision(str, Enum):
    EXACT = "EXACT"
    SECOND = "SECOND"
    MINUTE = "MINUTE"
    HOUR = "HOUR"
    DAY = "DAY"
    DATE_RANGE = "DATE_RANGE"
    APPROXIMATE = "APPROXIMATE"
    RELATIVE = "RELATIVE"
    SEQUENCE_ONLY = "SEQUENCE_ONLY"
    INTERVAL_BOUNDED = "INTERVAL_BOUNDED"
    UNKNOWN = "UNKNOWN"


class IntervalRelation(str, Enum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    MEETS = "MEETS"
    OVERLAPS = "OVERLAPS"
    STARTS = "STARTS"
    FINISHES = "FINISHES"
    DURING = "DURING"
    CONTAINS = "CONTAINS"
    EQUALS = "EQUALS"
    POSSIBLY_OVERLAPS = "POSSIBLY_OVERLAPS"
    UNKNOWN = "UNKNOWN"


class EventIdentityState(str, Enum):
    SAME_EVENT = "SAME_EVENT"
    PROBABLE_SAME_EVENT = "PROBABLE_SAME_EVENT"
    POSSIBLY_SAME_EVENT = "POSSIBLY_SAME_EVENT"
    RELATED_DISTINCT_EVENTS = "RELATED_DISTINCT_EVENTS"
    DISTINCT_EVENTS = "DISTINCT_EVENTS"
    UNKNOWN = "UNKNOWN"


class DuplicateState(str, Enum):
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    NEAR_DUPLICATE = "NEAR_DUPLICATE"
    SAME_UPSTREAM_EVENT = "SAME_UPSTREAM_EVENT"
    UPDATED_RECORD = "UPDATED_RECORD"
    CORRECTED_RECORD = "CORRECTED_RECORD"
    RELATED_EVENT = "RELATED_EVENT"
    DISTINCT = "DISTINCT"
    UNKNOWN = "UNKNOWN"


class ParticipantRole(str, Enum):
    PARTICIPANT = "PARTICIPANT"
    SUBJECT = "SUBJECT"
    OBJECT = "OBJECT"
    SOURCE = "SOURCE"
    REPORTER = "REPORTER"
    OWNER = "OWNER"
    OPERATOR_CANDIDATE = "OPERATOR_CANDIDATE"
    AFFECTED_ENTITY = "AFFECTED_ENTITY"
    RESPONDER = "RESPONDER"
    OBSERVING_SENSOR = "OBSERVING_SENSOR"
    UNKNOWN = "UNKNOWN"


class LocationPrecision(str, Enum):
    EXACT_COORDINATE = "EXACT_COORDINATE"
    SITE = "SITE"
    NEIGHBORHOOD = "NEIGHBORHOOD"
    CITY = "CITY"
    REGION = "REGION"
    COUNTRY = "COUNTRY"
    NETWORK_VIRTUAL = "NETWORK_VIRTUAL"
    APPROXIMATE = "APPROXIMATE"
    UNKNOWN = "UNKNOWN"


class CorrelationLevel(str, Enum):
    NONE = "NONE"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    DIRECTLY_LINKED = "DIRECTLY_LINKED"
    UNKNOWN = "UNKNOWN"


class CausalState(str, Enum):
    NO_CAUSAL_CLAIM = "NO_CAUSAL_CLAIM"
    CAUSAL_HYPOTHESIS = "CAUSAL_HYPOTHESIS"
    CAUSAL_SUPPORT_PARTIAL = "CAUSAL_SUPPORT_PARTIAL"
    CAUSAL_SUPPORT_STRONG = "CAUSAL_SUPPORT_STRONG"
    CAUSAL_LINK_VERIFIED = "CAUSAL_LINK_VERIFIED"
    CAUSAL_LINK_DISPUTED = "CAUSAL_LINK_DISPUTED"
    UNKNOWN = "UNKNOWN"


class SequenceMembership(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


class GapType(str, Enum):
    MISSING_ENTITY = "MISSING_ENTITY"
    MISSING_EVENT = "MISSING_EVENT"
    EXPECTED_EVENT_NOT_OBSERVED = "EXPECTED_EVENT_NOT_OBSERVED"
    SOURCE_GAP = "SOURCE_GAP"
    COVERAGE_GAP = "COVERAGE_GAP"
    TEMPORAL_GAP = "TEMPORAL_GAP"
    TIMEZONE_GAP = "TIMEZONE_GAP"
    CLOCK_SKEW_GAP = "CLOCK_SKEW_GAP"
    EVENT_IDENTITY_GAP = "EVENT_IDENTITY_GAP"
    PARTICIPANT_GAP = "PARTICIPANT_GAP"
    LOCATION_GAP = "LOCATION_GAP"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    CAUSAL_GAP = "CAUSAL_GAP"
    SOURCE_INDEPENDENCE_GAP = "SOURCE_INDEPENDENCE_GAP"


class PrivacyFlag(str, Enum):
    CASE_SCOPED = "CASE_SCOPED"
    NO_PRIVATE_DATA_COLLECTED = "NO_PRIVATE_DATA_COLLECTED"
    NO_LIVE_LOCATION_TRACKING = "NO_LIVE_LOCATION_TRACKING"
    NO_STALKING = "NO_STALKING"
    NO_OPERATIONAL_TARGETING = "NO_OPERATIONAL_TARGETING"
    NO_BIOMETRIC_IDENTIFICATION = "NO_BIOMETRIC_IDENTIFICATION"
    NO_SENSITIVE_TRAIT_INFERENCE = "NO_SENSITIVE_TRAIT_INFERENCE"
    NO_REAL_PERSON_ATTRIBUTION_FROM_ACCOUNT = "NO_REAL_PERSON_ATTRIBUTION_FROM_ACCOUNT"


class PolicyFlag(str, Enum):
    NONE = "NONE"
    BLOCKED_REQUEST = "BLOCKED_REQUEST"
    HUMAN_REVIEW_RECOMMENDED = "HUMAN_REVIEW_RECOMMENDED"
    CAUSALITY_UNSAFE = "CAUSALITY_UNSAFE"


# =====================================================================
# CONSTANTS
# =====================================================================

PRIMARY_DIRECT_SOURCE_TYPES = {
    SourceType.SYSTEM_LOG,
    SourceType.APPLICATION_LOG,
    SourceType.NETWORK_TELEMETRY,
    SourceType.IDENTITY_LOG,
    SourceType.OFFICIAL_RECORD,
    SourceType.TRANSACTION_RECORD,
    SourceType.TRADE_RECORD,
    SourceType.TRANSPORT_RECORD,
    SourceType.AIS_RECORD,
    SourceType.SATELLITE_OBSERVATION,
    SourceType.SEISMIC_RECORD,
    SourceType.ENVIRONMENTAL_OBSERVATION,
}

CLAIM_LIKE_SOURCE_TYPES = {
    SourceType.MEDIA,
    SourceType.AGGREGATOR,
    SourceType.SOCIAL_POST,
    SourceType.HUMAN_SOURCE,
    SourceType.PERSON_SELF_REPORT,
}

DIRECT_FACTOR = {
    SourceType.SYSTEM_LOG: 1.00,
    SourceType.APPLICATION_LOG: 1.00,
    SourceType.NETWORK_TELEMETRY: 1.00,
    SourceType.IDENTITY_LOG: 1.00,
    SourceType.OFFICIAL_RECORD: 0.95,
    SourceType.CORPORATE_FILING: 0.95,
    SourceType.TRANSACTION_RECORD: 0.95,
    SourceType.TRADE_RECORD: 0.92,
    SourceType.TRANSPORT_RECORD: 0.92,
    SourceType.AIS_RECORD: 0.90,
    SourceType.SATELLITE_OBSERVATION: 0.88,
    SourceType.SEISMIC_RECORD: 0.90,
    SourceType.ENVIRONMENTAL_OBSERVATION: 0.88,
    SourceType.DOCUMENT: 0.90,
    SourceType.CTI_REPORT: 0.80,
    SourceType.MEDIA: 0.75,
    SourceType.AGGREGATOR: 0.50,
    SourceType.SOCIAL_POST: 0.55,
    SourceType.HUMAN_SOURCE: 0.65,
    SourceType.PERSON_SELF_REPORT: 0.60,
    SourceType.OTHER: 0.70,
}

TEMPORAL_FACTOR = {
    TemporalPrecision.EXACT: 1.00,
    TemporalPrecision.SECOND: 1.00,
    TemporalPrecision.MINUTE: 0.98,
    TemporalPrecision.HOUR: 0.90,
    TemporalPrecision.INTERVAL_BOUNDED: 0.92,
    TemporalPrecision.DAY: 0.75,
    TemporalPrecision.DATE_RANGE: 0.70,
    TemporalPrecision.APPROXIMATE: 0.65,
    TemporalPrecision.RELATIVE: 0.50,
    TemporalPrecision.SEQUENCE_ONLY: 0.40,
    TemporalPrecision.UNKNOWN: 0.20,
}

PRECISION_RANK = {
    TemporalPrecision.EXACT: 11,
    TemporalPrecision.SECOND: 10,
    TemporalPrecision.MINUTE: 9,
    TemporalPrecision.INTERVAL_BOUNDED: 8,
    TemporalPrecision.HOUR: 7,
    TemporalPrecision.DAY: 6,
    TemporalPrecision.DATE_RANGE: 5,
    TemporalPrecision.APPROXIMATE: 4,
    TemporalPrecision.RELATIVE: 3,
    TemporalPrecision.SEQUENCE_ONLY: 2,
    TemporalPrecision.UNKNOWN: 0,
}

CONCURRENCY_RELATIONS = {
    IntervalRelation.OVERLAPS,
    IntervalRelation.STARTS,
    IntervalRelation.FINISHES,
    IntervalRelation.DURING,
    IntervalRelation.CONTAINS,
    IntervalRelation.EQUALS,
    IntervalRelation.POSSIBLY_OVERLAPS,
}

PROHIBITED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "OPERATIONAL_TARGETING",
        re.compile(
            r"\b(best\s+(?:person|server|supplier|node|facility)\s+to\s+"
            r"(?:attack|strike|disrupt|sabotage|pressure)|weapon[- ]target scheduling|"
            r"attack timing|sabotage timing)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CRITICAL_INFRASTRUCTURE_ATTACK",
        re.compile(
            r"\b(enable|plan|coordinate|schedule)[^\n]{0,80}\b"
            r"(attack|disruption|sabotage)[^\n]{0,80}\b"
            r"(critical infrastructure|power grid|water treatment|transport network)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "STALKING_OR_LIVE_TRACKING",
        re.compile(
            r"\b(stalk|live track|real[- ]time track|current location|precise movements|"
            r"predict[^\n]{0,40}movements)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "GUILT_BY_TEMPORAL_PROXIMITY",
        re.compile(
            r"\b(prove[^\n]{0,40}guilt|criminal intent|conspiracy|responsibility)\b[^\n]{0,80}"
            r"\b(from|based on|only because)[^\n]{0,40}(timing|proximity|sequence)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "UNAUTHORIZED_ACCESS",
        re.compile(
            r"\b(hack|bypass|login|stolen)[^\n]{0,60}\b"
            r"(account|credential|private|session|cookie|authentication|log)\b",
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
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


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


def coerce_precision(value: Any) -> Optional[TemporalPrecision]:
    if value is None:
        return None
    if isinstance(value, TemporalPrecision):
        return value
    try:
        return TemporalPrecision(str(value).upper())
    except Exception:
        return TemporalPrecision.UNKNOWN


def parse_offset(tz_str: Optional[str]) -> Optional[timezone]:
    if not tz_str:
        return None
    s = tz_str.strip()
    if s.upper() in {"UTC", "Z", "+00:00", "-00:00"}:
        return timezone.utc
    m = re.match(r"^([+-])(\d{2}):(\d{2})$", s)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        hours = int(m.group(2))
        minutes = int(m.group(3))
        return timezone(sign * timedelta(hours=hours, minutes=minutes))
    try:
        from zoneinfo import ZoneInfo  # type: ignore
        return ZoneInfo(s)  # type: ignore[return-value]
    except Exception:
        return None


def format_offset(dt: datetime) -> Optional[str]:
    off = dt.utcoffset()
    if off is None:
        return None
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    hours, rem = divmod(total, 3600)
    minutes = rem // 60
    return f"{sign}{hours:02d}:{minutes:02d}"


def parse_single_datetime(
    value: str,
    default_tz: Optional[str] = None,
) -> Tuple[Optional[datetime], TemporalPrecision, Optional[str], bool, bool]:
    """
    Returns:
        datetime_or_none, precision, timezone_string, timezone_inferred, approximate
    """
    if not value:
        return None, TemporalPrecision.UNKNOWN, None, False, False

    original = str(value).strip()
    s = original
    approximate = False

    if re.match(r"^(around|approx(?:imately)?|circa|~)\s+", s, re.IGNORECASE):
        approximate = True
        s = re.sub(r"^(around|approx(?:imately)?|circa|~)\s+", "", s, flags=re.IGNORECASE).strip()

    tzinfo = parse_offset(default_tz)
    dt: Optional[datetime] = None

    iso = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
    except Exception:
        formats = [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M",
            "%Y/%m/%d",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except Exception:
                continue

    if dt is None:
        return None, TemporalPrecision.UNKNOWN, None, False, approximate

    inferred = False
    if dt.tzinfo is None:
        if tzinfo is not None:
            dt = dt.replace(tzinfo=tzinfo)
            inferred = True
    tz_str = format_offset(dt) if dt.tzinfo else default_tz

    if approximate:
        precision = TemporalPrecision.APPROXIMATE
    elif re.search(r"\d{2}:\d{2}:\d{2}", original):
        precision = TemporalPrecision.SECOND
    elif re.search(r"\d{2}:\d{2}", original):
        precision = TemporalPrecision.MINUTE
    elif re.search(r"T\d{2}\b", original):
        precision = TemporalPrecision.HOUR
    elif re.match(r"^\d{4}-\d{2}-\d{2}$", original) or re.match(r"^\d{4}/\d{2}/\d{2}$", original):
        precision = TemporalPrecision.DAY
    else:
        precision = TemporalPrecision.UNKNOWN

    return dt, precision, tz_str, inferred, approximate


@dataclass
class TimeValue:
    original: str = ""
    start_original: Optional[str] = None
    end_original: Optional[str] = None
    normalized_start_utc: Optional[str] = None
    normalized_end_utc: Optional[str] = None
    local_start: Optional[str] = None
    local_end: Optional[str] = None
    timezone: Optional[str] = None
    precision: TemporalPrecision = TemporalPrecision.UNKNOWN
    basis: str = "SOURCE_TIMESTAMP"
    inferred_timezone: bool = False
    clock_offset_seconds: Optional[int] = None
    notes: str = ""


def parse_time_value(
    raw: Any,
    precision: Any = None,
    tz_hint: Optional[str] = None,
    basis: str = "SOURCE_TIMESTAMP",
    notes: str = "",
) -> TimeValue:
    if isinstance(raw, TimeValue):
        tv = raw
        p = coerce_precision(precision)
        if p:
            tv.precision = p
        if tz_hint and not tv.timezone:
            tv.timezone = tz_hint
        if basis:
            tv.basis = basis
        if notes:
            tv.notes = (tv.notes + " " + notes).strip()
        return tv

    if isinstance(raw, dict):
        start_raw = str(raw.get("start", "") or "")
        end_raw = str(raw.get("end", "") or "")
        tz_hint = raw.get("timezone", tz_hint)
        precision = raw.get("precision", precision)
        basis = raw.get("basis", basis)
        notes = raw.get("notes", notes)
        original = raw.get("original") or (f"{start_raw}/{end_raw}" if end_raw else start_raw)
    else:
        start_raw = str(raw or "").strip()
        end_raw = ""
        original = start_raw

        # ISO-8601 style interval: start/end. Avoid splitting ordinary dated paths like 2026/10/08.
        if "/" in start_raw and ("T" in start_raw or ":" in start_raw):
            parts = start_raw.split("/", 1)
            if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                start_raw, end_raw = parts[0].strip(), parts[1].strip()

    start_dt, start_prec, start_tz, start_inferred, start_approx = parse_single_datetime(start_raw, tz_hint)
    end_dt, end_prec, end_tz, end_inferred, end_approx = parse_single_datetime(end_raw, tz_hint or start_tz)

    p = coerce_precision(precision)
    if p:
        final_precision = p
    elif start_approx or end_approx:
        final_precision = TemporalPrecision.APPROXIMATE
    elif end_dt is not None:
        if start_dt and start_dt.time() == datetime.min.time() and end_dt.time() == datetime.min.time():
            final_precision = TemporalPrecision.DATE_RANGE
        else:
            final_precision = TemporalPrecision.INTERVAL_BOUNDED
    else:
        final_precision = start_prec

    normalized_start_utc = start_dt.astimezone(timezone.utc).isoformat() if start_dt and start_dt.tzinfo else None
    normalized_end_utc = end_dt.astimezone(timezone.utc).isoformat() if end_dt and end_dt.tzinfo else None
    local_start = start_dt.isoformat() if start_dt else None
    local_end = end_dt.isoformat() if end_dt else None
    timezone_string = start_tz or end_tz or tz_hint

    return TimeValue(
        original=str(original),
        start_original=start_raw or None,
        end_original=end_raw or None,
        normalized_start_utc=normalized_start_utc,
        normalized_end_utc=normalized_end_utc,
        local_start=local_start,
        local_end=local_end,
        timezone=timezone_string,
        precision=final_precision,
        basis=basis,
        inferred_timezone=bool(start_inferred or end_inferred),
        notes=notes,
    )


def make_time(raw: Any, precision: Any = None, tz_hint: Optional[str] = None, basis: str = "SOURCE_TIMESTAMP", notes: str = "") -> TimeValue:
    return parse_time_value(raw, precision=precision, tz_hint=tz_hint, basis=basis, notes=notes)


def timevalue_interval(tv: Optional[TimeValue]) -> Optional[Tuple[datetime, datetime]]:
    if not tv:
        return None

    def parse_utc(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return None
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    start = parse_utc(tv.normalized_start_utc)
    end = parse_utc(tv.normalized_end_utc)

    if start is None:
        return None

    if end is None:
        if tv.precision == TemporalPrecision.SECOND:
            end = start + timedelta(seconds=1) - timedelta(microseconds=1)
        elif tv.precision == TemporalPrecision.MINUTE:
            end = start + timedelta(minutes=1) - timedelta(microseconds=1)
        elif tv.precision == TemporalPrecision.HOUR:
            end = start + timedelta(hours=1) - timedelta(microseconds=1)
        elif tv.precision == TemporalPrecision.DAY:
            end = start + timedelta(days=1) - timedelta(microseconds=1)
        elif tv.precision in {TemporalPrecision.EXACT, TemporalPrecision.APPROXIMATE, TemporalPrecision.UNKNOWN}:
            # Do not invent bounds for approximate/unknown unless explicit end exists.
            return None
        else:
            end = start

    if end < start:
        start, end = end, start

    return start, end


def interval_relation(a: Optional[Tuple[datetime, datetime]], b: Optional[Tuple[datetime, datetime]]) -> IntervalRelation:
    if not a or not b:
        return IntervalRelation.UNKNOWN

    a_start, a_end = a
    b_start, b_end = b

    if a_end < b_start:
        return IntervalRelation.BEFORE
    if b_end < a_start:
        return IntervalRelation.AFTER
    if a_end == b_start:
        return IntervalRelation.MEETS
    if a_start == b_start and a_end == b_end:
        return IntervalRelation.EQUALS
    if a_start == b_start:
        return IntervalRelation.STARTS if a_end < b_end else IntervalRelation.FINISHES
    if a_end == b_end:
        return IntervalRelation.FINISHES if a_start > b_start else IntervalRelation.STARTS
    if b_start <= a_start and a_end <= b_end:
        return IntervalRelation.DURING
    if a_start <= b_start and b_end <= a_end:
        return IntervalRelation.CONTAINS
    if a_start < b_start < a_end < b_end:
        return IntervalRelation.OVERLAPS
    if b_start < a_start < b_end < a_end:
        return IntervalRelation.OVERLAPS

    return IntervalRelation.POSSIBLY_OVERLAPS


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
    published_at: Optional[str] = None
    retrieved_at: Optional[str] = None
    effective_at: Optional[str] = None
    independence_group: str = "UNKNOWN"
    reliability: float = 0.5
    derived_from: Optional[str] = None
    notes: str = ""


@dataclass
class Evidence:
    id: str
    source_id: str
    artifact_type: str
    excerpt: str
    observed_at: Optional[TimeValue] = None
    stable_ids: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""
    notes: str = ""


@dataclass
class Observation:
    id: str
    source_id: str
    evidence_id: str
    observed_at: Optional[TimeValue] = None
    statement: str = ""
    entity_refs: List[str] = field(default_factory=list)
    location_ref: Optional[str] = None
    event_type_candidate: Optional[str] = None
    notes: str = ""


@dataclass
class Claim:
    id: str
    claimant: str
    statement: str
    asserted_at: Optional[TimeValue] = None
    source_id: Optional[str] = None
    evidence_id: Optional[str] = None
    status: str = "SOURCE_CLAIM_ONLY"
    confidence: float = 0.5


@dataclass
class Location:
    id: str
    display_name: str
    precision: LocationPrecision = LocationPrecision.UNKNOWN
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    site: Optional[str] = None
    coordinates: Optional[str] = None
    network_virtual: Optional[str] = None
    notes: str = ""


@dataclass
class Participant:
    entity_id: str
    role: ParticipantRole = ParticipantRole.UNKNOWN
    confidence: float = 0.5
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)


@dataclass
class EventCandidate:
    id: str
    event_type: str
    subtype: Optional[str] = None
    title: str = ""
    description: str = ""
    time: TimeValue = field(default_factory=TimeValue)
    location_id: Optional[str] = None
    participants: List[Participant] = field(default_factory=list)
    objects: List[str] = field(default_factory=list)
    organizations: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    observation_ids: List[str] = field(default_factory=list)
    claim_ids: List[str] = field(default_factory=list)
    stable_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    verification_state: VerificationState = VerificationState.REPORTED
    fingerprint: str = ""
    limitations: List[str] = field(default_factory=list)
    parent_candidate_id: Optional[str] = None
    supersedes_candidate_id: Optional[str] = None
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)


@dataclass
class Event:
    id: str
    case_id: str
    event_type: str
    subtype: Optional[str] = None
    title: str = ""
    description: str = ""
    verification_state: VerificationState = VerificationState.REPORTED
    confidence: float = 0.0
    time: TimeValue = field(default_factory=TimeValue)
    locations: List[Location] = field(default_factory=list)
    participants: List[Participant] = field(default_factory=list)
    objects: List[str] = field(default_factory=list)
    organizations: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    observation_ids: List[str] = field(default_factory=list)
    claim_ids: List[str] = field(default_factory=list)
    stable_ids: List[str] = field(default_factory=list)
    causal_status: CausalState = CausalState.NO_CAUSAL_CLAIM
    sequence_ids: List[str] = field(default_factory=list)
    parent_event_id: Optional[str] = None
    supersedes_event_id: Optional[str] = None
    identity_state: EventIdentityState = EventIdentityState.UNKNOWN
    merged_from: List[str] = field(default_factory=list)
    duplicate_reports: List[Dict[str, str]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)


@dataclass
class TemporalConstraint:
    id: str
    left_event_id: str
    relation: IntervalRelation
    right_event_id: str
    directness: str = "DIRECT_INTERVAL_ANALYSIS"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    notes: str = ""


@dataclass
class Sequence:
    id: str
    name: str
    sequence_type: str
    event_ids: List[str]
    membership_state: SequenceMembership
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Cluster:
    id: str
    event_ids: List[str]
    method: str
    interpretation: str
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    id: str
    statement: str
    kind: str
    supporting_event_ids: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
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
    event_ids: List[str] = field(default_factory=list)
    candidate_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    status: str = "OPEN"
    recommended_resolution: str = ""


@dataclass
class KnowledgeGap:
    id: str
    gap_type: GapType
    description: str
    about_event_ids: List[str] = field(default_factory=list)
    about_candidate_ids: List[str] = field(default_factory=list)
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: Optional[str] = None
    expected_information_value: float = 0.0


@dataclass
class NextAction:
    id: str
    description: str
    priority: int = 1
    privacy_impact: str = "LOW"
    expected_gain: float = 0.0
    specialist: Optional[str] = None


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: ["authorized_records_only", "case_scoped"])
    authorization: str = "demo_authorized_event_records"
    target_entities: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    sample: bool = False
    budget: Optional[str] = None
    deadline: Optional[str] = None


# =====================================================================
# EVENTINT ENGINE
# =====================================================================

class EventInt:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.sources: Dict[str, Source] = {}
        self.evidences: Dict[str, Evidence] = {}
        self.observations: Dict[str, Observation] = {}
        self.claims: Dict[str, Claim] = {}
        self.locations: Dict[str, Location] = {}
        self.candidates: Dict[str, EventCandidate] = {}
        self.events: Dict[str, Event] = {}
        self.constraints: List[TemporalConstraint] = []
        self.sequences: List[Sequence] = []
        self.clusters: List[Cluster] = []
        self.hypotheses: List[Hypothesis] = []
        self.contradictions: List[Contradiction] = []
        self.gaps: List[KnowledgeGap] = []
        self.actions: List[NextAction] = []
        self.handoffs: List[Dict[str, str]] = []
        self.identity_clusters: List[Dict[str, Any]] = []
        self.precedences: List[Dict[str, Any]] = []
        self.concurrencies: List[Dict[str, Any]] = []
        self.correlations: List[Dict[str, Any]] = []
        self.causal_hypotheses: List[Hypothesis] = []
        self.expected_events: List[Dict[str, Any]] = []
        self.missing_events: List[KnowledgeGap] = []
        self.validation_errors: List[str] = []

    # -----------------------------------------------------------------
    # Adders
    # -----------------------------------------------------------------

    def add_source(self, source: Source) -> Source:
        self.sources[source.id] = source
        return source

    def add_evidence(self, evidence: Evidence) -> Evidence:
        if not evidence.content_hash:
            seed = evidence.excerpt + evidence.source_id
            if evidence.observed_at:
                seed += evidence.observed_at.original
            evidence.content_hash = stable_hash(seed)
        self.evidences[evidence.id] = evidence
        return evidence

    def add_location(self, location: Location) -> Location:
        self.locations[location.id] = location
        return location

    def add_candidate(self, candidate: EventCandidate) -> EventCandidate:
        if not candidate.fingerprint:
            candidate.fingerprint = self.event_fingerprint(candidate)
        candidate.updated_at = now_iso()
        self.candidates[candidate.id] = candidate
        return candidate

    def add_event(self, event: Event) -> Event:
        self.events[event.id] = event
        return event

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
        return cur.id if cur else source_id

    def source_families(self, source_ids: List[str]) -> Set[str]:
        families: Set[str] = set()
        for sid in source_ids:
            fam = self.get_source_family(sid)
            families.add(fam or sid)
        return families

    def independence_state_for_sources(self, source_ids: List[str]) -> str:
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
    # Derived observations / claims
    # -----------------------------------------------------------------

    def derive_observations(self) -> None:
        for ev in self.evidences.values():
            obs_id = f"OBS-{ev.id}"
            if obs_id in self.observations:
                continue
            attrs = ev.attributes or {}
            self.observations[obs_id] = Observation(
                id=obs_id,
                source_id=ev.source_id,
                evidence_id=ev.id,
                observed_at=ev.observed_at,
                statement=ev.excerpt,
                entity_refs=list(attrs.get("entity_refs", [])),
                location_ref=attrs.get("location_ref"),
                event_type_candidate=attrs.get("event_type_candidate"),
                notes=ev.notes,
            )

    def derive_claims(self) -> None:
        for ev in self.evidences.values():
            src = self.sources.get(ev.source_id)
            if not src or src.source_type not in CLAIM_LIKE_SOURCE_TYPES:
                continue
            claim_id = f"CLM-{ev.id}"
            if claim_id in self.claims:
                continue
            self.claims[claim_id] = Claim(
                id=claim_id,
                claimant=src.title,
                statement=ev.excerpt,
                asserted_at=ev.observed_at,
                source_id=src.id,
                evidence_id=ev.id,
                status="SOURCE_CLAIM_ONLY",
                confidence=round(src.reliability * 0.8, 3),
            )

    def update_candidate_refs(self) -> None:
        for cand in self.candidates.values():
            cand.observation_ids = [
                oid for oid, obs in self.observations.items()
                if obs.evidence_id in cand.evidence_ids
            ]
            cand.claim_ids = [
                cid for cid, clm in self.claims.items()
                if clm.evidence_id in cand.evidence_ids
            ]

    # -----------------------------------------------------------------
    # Fingerprints / stable IDs
    # -----------------------------------------------------------------

    def stable_ids_for_candidate(self, cand: EventCandidate) -> Set[str]:
        ids = set(cand.stable_ids)
        for eid in cand.evidence_ids:
            ev = self.evidences.get(eid)
            if ev:
                ids.update(ev.stable_ids)
        return ids

    def event_fingerprint(self, cand: EventCandidate) -> str:
        stable = sorted(self.stable_ids_for_candidate(cand))
        participants = sorted(p.entity_id for p in cand.participants)
        time_key = ""
        iv = timevalue_interval(cand.time)
        if iv:
            time_key = f"{iv[0].date().isoformat()}|{iv[1].date().isoformat()}"
        else:
            time_key = normalize_text(cand.time.original or "")
        components = [
            normalize_text(cand.event_type),
            normalize_text(cand.subtype or ""),
            ",".join(participants),
            time_key,
            cand.location_id or "",
            ",".join(stable),
        ]
        return stable_hash("|".join(components))

    # -----------------------------------------------------------------
    # Event identity resolution
    # -----------------------------------------------------------------

    def participant_ids(self, cand: EventCandidate) -> Set[str]:
        return {p.entity_id for p in cand.participants}

    def time_overlap(self, c1: EventCandidate, c2: EventCandidate) -> bool:
        rel = interval_relation(timevalue_interval(c1.time), timevalue_interval(c2.time))
        return rel not in {IntervalRelation.BEFORE, IntervalRelation.AFTER, IntervalRelation.UNKNOWN}

    def location_conflict(self, c1: EventCandidate, c2: EventCandidate) -> bool:
        if not c1.location_id or not c2.location_id or c1.location_id == c2.location_id:
            return False
        l1 = self.locations.get(c1.location_id)
        l2 = self.locations.get(c2.location_id)
        if not l1 or not l2:
            return False
        precise = {
            LocationPrecision.EXACT_COORDINATE,
            LocationPrecision.SITE,
            LocationPrecision.NEIGHBORHOOD,
            LocationPrecision.CITY,
        }
        return l1.precision in precise and l2.precision in precise

    def compare_candidates(self, c1: EventCandidate, c2: EventCandidate) -> Dict[str, Any]:
        stable1 = self.stable_ids_for_candidate(c1)
        stable2 = self.stable_ids_for_candidate(c2)
        stable_common = stable1 & stable2

        reasons: List[str] = []
        opposition: List[str] = []

        if stable_common:
            return {
                "state": EventIdentityState.SAME_EVENT,
                "reasons": [f"stable identifier match: {sorted(stable_common)}"],
                "opposition": [],
                "score": 10,
            }

        if c1.event_type == c2.event_type:
            reasons.append("same_event_type")
        else:
            opposition.append("event_type_conflict")

        if c1.subtype and c2.subtype and c1.subtype == c2.subtype:
            reasons.append("same_subtype")

        p1 = self.participant_ids(c1)
        p2 = self.participant_ids(c2)
        if p1 & p2:
            reasons.append("participant_overlap")
        else:
            opposition.append("no_participant_overlap")

        if self.time_overlap(c1, c2):
            reasons.append("time_overlap")
        else:
            opposition.append("temporal_separation_or_unknown")

        if c1.location_id and c1.location_id == c2.location_id:
            reasons.append("same_location")
        elif self.location_conflict(c1, c2):
            opposition.append("location_conflict")

        fam1 = self.source_families(c1.source_ids)
        fam2 = self.source_families(c2.source_ids)
        if fam1 & fam2:
            reasons.append("same_upstream_source_family")

        if c1.fingerprint == c2.fingerprint:
            reasons.append("fingerprint_match")

        score = len(reasons)

        if "event_type_conflict" in opposition or "location_conflict" in opposition:
            state = EventIdentityState.DISTINCT_EVENTS
        elif score >= 4 and "participant_overlap" in reasons and "time_overlap" in reasons and "same_event_type" in reasons:
            state = EventIdentityState.PROBABLE_SAME_EVENT
        elif score >= 2 and not any(x in opposition for x in ["event_type_conflict", "location_conflict"]):
            state = EventIdentityState.POSSIBLY_SAME_EVENT
        else:
            state = EventIdentityState.UNKNOWN

        return {
            "state": state,
            "reasons": reasons,
            "opposition": opposition,
            "score": score,
        }

    def resolve_event_identity(self) -> None:
        cand_ids = list(self.candidates.keys())
        if not cand_ids:
            return

        parent = {cid: cid for cid in cand_ids}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        pair_results: List[Dict[str, Any]] = []

        for i in range(len(cand_ids)):
            for j in range(i + 1, len(cand_ids)):
                c1 = self.candidates[cand_ids[i]]
                c2 = self.candidates[cand_ids[j]]
                res = self.compare_candidates(c1, c2)
                res.update({
                    "candidate_ids": [c1.id, c2.id],
                })
                pair_results.append(res)

                if res["state"] == EventIdentityState.SAME_EVENT:
                    union(c1.id, c2.id)
                elif res["state"] in {EventIdentityState.PROBABLE_SAME_EVENT, EventIdentityState.POSSIBLY_SAME_EVENT}:
                    self.identity_clusters.append({
                        "cluster_id": new_id("EIC-", c1.id + c2.id),
                        "candidate_ids": [c1.id, c2.id],
                        "state": res["state"].value,
                        "reasons": res["reasons"],
                        "opposition": res["opposition"],
                        "merged": False,
                        "limitation": "Probable/possible identity is not automatically merged; human or stronger evidence required.",
                    })

        groups: Dict[str, List[str]] = defaultdict(list)
        for cid in cand_ids:
            groups[find(cid)].append(cid)

        for root, members in groups.items():
            event = self.build_event_from_candidates(members, root)
            self.add_event(event)

        self.identity_clusters.extend(pair_results)

    def build_event_from_candidates(self, member_ids: List[str], root: str) -> Event:
        members = [self.candidates[mid] for mid in member_ids]
        rep = max(
            members,
            key=lambda c: (
                c.confidence,
                PRECISION_RANK.get(c.time.precision, 0),
                len(c.evidence_ids),
                c.id,
            ),
        )

        participants_by_entity: Dict[str, Participant] = {}
        for c in members:
            for p in c.participants:
                old = participants_by_entity.get(p.entity_id)
                if not old or p.confidence > old.confidence:
                    participants_by_entity[p.entity_id] = p

        locations: List[Location] = []
        seen_loc: Set[str] = set()
        for c in members:
            if c.location_id and c.location_id not in seen_loc:
                loc = self.locations.get(c.location_id)
                if loc:
                    locations.append(loc)
                    seen_loc.add(loc.id)

        objects = sorted({o for c in members for o in c.objects})
        organizations = sorted({o for c in members for o in c.organizations})
        source_ids = sorted({s for c in members for s in c.source_ids})
        evidence_ids = sorted({e for c in members for e in c.evidence_ids})
        observation_ids = sorted({o for c in members for o in c.observation_ids})
        claim_ids = sorted({cl for c in members for cl in c.claim_ids})
        stable_ids = sorted({s for c in members for s in self.stable_ids_for_candidate(c)})

        limitations = list(rep.limitations)
        duplicate_reports: List[Dict[str, str]] = []

        if len(members) > 1:
            fams = self.source_families(source_ids)
            dup_state = DuplicateState.SAME_UPSTREAM_EVENT if len(fams) == 1 else DuplicateState.NEAR_DUPLICATE
            for c in members:
                if c.id == rep.id:
                    continue
                duplicate_reports.append({
                    "candidate_id": c.id,
                    "duplicate_state": dup_state.value,
                    "original_time": c.time.original,
                    "source_ids": ",".join(c.source_ids),
                })
            limitations.append(
                "Merged duplicate reports by stable identifier/event fingerprint. Alternate time representations are preserved in duplicate_reports and evidence."
            )
            identity_state = EventIdentityState.SAME_EVENT
        else:
            identity_state = EventIdentityState.UNKNOWN

        return Event(
            id=new_id("EVT-", root + rep.id),
            case_id=self.case.case_id,
            event_type=rep.event_type,
            subtype=rep.subtype,
            title=rep.title,
            description=rep.description,
            verification_state=VerificationState.REPORTED,
            confidence=rep.confidence,
            time=rep.time,
            locations=locations,
            participants=list(participants_by_entity.values()),
            objects=objects,
            organizations=organizations,
            source_ids=source_ids,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            claim_ids=claim_ids,
            stable_ids=stable_ids,
            causal_status=CausalState.NO_CAUSAL_CLAIM,
            sequence_ids=[],
            identity_state=identity_state,
            merged_from=sorted(member_ids),
            duplicate_reports=duplicate_reports,
            limitations=limitations,
        )

    # -----------------------------------------------------------------
    # Contradictions
    # -----------------------------------------------------------------

    def detect_contradictions(self) -> None:
        event_ids = list(self.events.keys())

        for i in range(len(event_ids)):
            for j in range(i + 1, len(event_ids)):
                e1 = self.events[event_ids[i]]
                e2 = self.events[event_ids[j]]

                same_type = e1.event_type == e2.event_type and e1.subtype == e2.subtype
                p1 = {p.entity_id for p in e1.participants}
                p2 = {p.entity_id for p in e2.participants}
                participant_overlap = bool(p1 & p2)

                iv1 = timevalue_interval(e1.time)
                iv2 = timevalue_interval(e2.time)
                close_time = False
                delta_seconds = None
                if iv1 and iv2:
                    delta_seconds = abs((iv1[0] - iv2[0]).total_seconds())
                    close_time = delta_seconds <= 3600

                if same_type and participant_overlap and close_time and not (set(e1.stable_ids) & set(e2.stable_ids)):
                    desc = (
                        f"Two {e1.subtype or e1.event_type} events involving overlapping entities occur within "
                        f"{int(delta_seconds or 0)} seconds but are not resolved as the same event. "
                        "This may indicate duplicate reporting, distinct consecutive actions, imprecise timing, "
                        "timezone/clock issues, or entity-resolution uncertainty."
                    )
                    self.contradictions.append(Contradiction(
                        id=new_id("CON-", desc),
                        contradiction_type="TEMPORAL_IDENTITY",
                        description=desc,
                        event_ids=[e1.id, e2.id],
                        source_ids=sorted(set(e1.source_ids + e2.source_ids)),
                        severity="LOW",
                        status="OPEN",
                        recommended_resolution=(
                            "Retrieve primary stable identifiers, endpoint/session telemetry, or independent timestamped records "
                            "before deciding same-event versus distinct-event."
                        ),
                    ))

    # -----------------------------------------------------------------
    # Fact gate
    # -----------------------------------------------------------------

    def fact_gate_events(self) -> None:
        for event in self.events.values():
            source_objs = [self.sources[sid] for sid in event.source_ids if sid in self.sources]
            families = self.source_families(event.source_ids)
            max_rel = max((s.reliability for s in source_objs), default=0.5)
            temporal_factor = TEMPORAL_FACTOR.get(event.time.precision, 0.35)
            direct_factor = max((DIRECT_FACTOR.get(s.source_type, 0.7) for s in source_objs), default=0.7)
            has_primary = any(s.source_type in PRIMARY_DIRECT_SOURCE_TYPES for s in source_objs)

            confidence = round(max_rel * temporal_factor * direct_factor, 3)
            if len(families) >= 2:
                confidence = round(min(0.99, confidence * 1.05), 3)

            material_contradiction = any(
                event.id in c.event_ids and c.severity in {"MATERIAL", "HIGH"}
                for c in self.contradictions
            )

            if material_contradiction:
                state = VerificationState.DISPUTED
            elif len(families) >= 2 and confidence >= 0.75:
                state = VerificationState.STRONGLY_SUPPORTED
            elif has_primary and confidence >= 0.70:
                state = VerificationState.SUPPORTED
            elif confidence >= 0.50:
                state = VerificationState.PARTIALLY_SUPPORTED
            elif event.evidence_ids or event.claim_ids or event.observation_ids:
                state = VerificationState.REPORTED
            else:
                state = VerificationState.UNSUPPORTED

            event.confidence = confidence
            event.verification_state = state
            event.limitations.append(
                f"Source independence state: {self.independence_state_for_sources(event.source_ids)}."
            )

    # -----------------------------------------------------------------
    # Temporal constraints / partial order
    # -----------------------------------------------------------------

    def build_temporal_constraints(self) -> None:
        event_ids = list(self.events.keys())
        seen: Set[Tuple[str, str, str]] = set()

        for i in range(len(event_ids)):
            for j in range(len(event_ids)):
                if i == j:
                    continue
                e1 = self.events[event_ids[i]]
                e2 = self.events[event_ids[j]]
                rel = interval_relation(timevalue_interval(e1.time), timevalue_interval(e2.time))
                if rel == IntervalRelation.UNKNOWN:
                    continue

                left, right, normalized_rel = e1.id, e2.id, rel
                if normalized_rel == IntervalRelation.AFTER:
                    left, right = e2.id, e1.id
                    normalized_rel = IntervalRelation.BEFORE

                key = (left, normalized_rel.value, right)
                if key in seen:
                    continue
                seen.add(key)

                conf = round((e1.confidence + e2.confidence) / 2, 3)
                constraint = TemporalConstraint(
                    id=new_id("TC-", f"{left}{normalized_rel.value}{right}"),
                    left_event_id=left,
                    relation=normalized_rel,
                    right_event_id=right,
                    source_ids=sorted(set(e1.source_ids + e2.source_ids)),
                    evidence_ids=sorted(set(e1.evidence_ids + e2.evidence_ids)),
                    confidence=conf,
                    notes="Derived from normalized UTC intervals. Approximate/unknown times are not forced into exact order.",
                )
                self.constraints.append(constraint)

                if normalized_rel == IntervalRelation.BEFORE:
                    self.precedences.append({
                        "left_event_id": left,
                        "relation": "BEFORE",
                        "right_event_id": right,
                        "derivation": "DIRECT",
                        "confidence": conf,
                        "evidence_ids": constraint.evidence_ids,
                    })
                elif normalized_rel in CONCURRENCY_RELATIONS:
                    self.concurrencies.append({
                        "left_event_id": left,
                        "relation": normalized_rel.value,
                        "right_event_id": right,
                        "confidence": conf,
                        "evidence_ids": constraint.evidence_ids,
                    })

        self.apply_transitive_before()

    def apply_transitive_before(self) -> None:
        graph: Dict[str, Set[str]] = defaultdict(set)
        direct_pairs = {(p["left_event_id"], p["right_event_id"]) for p in self.precedences if p["derivation"] == "DIRECT"}
        for a, b in direct_pairs:
            graph[a].add(b)

        inferred: Set[Tuple[str, str]] = set()
        cycle_found = False

        for start in list(graph.keys()):
            stack = [(start, [start])]
            while stack:
                node, path = stack.pop()
                for nxt in graph.get(node, set()):
                    if nxt in path:
                        cycle_found = True
                        continue
                    if nxt != start:
                        inferred.add((start, nxt))
                    stack.append((nxt, path + [nxt]))

        for a, b in sorted(inferred):
            if (a, b) in direct_pairs:
                continue
            self.precedences.append({
                "left_event_id": a,
                "relation": "BEFORE",
                "right_event_id": b,
                "derivation": "TRANSITIVE",
                "confidence": 0.0,
                "evidence_ids": [],
                "note": "Deterministic partial-order inference from direct BEFORE constraints.",
            })

        if cycle_found:
            self.contradictions.append(Contradiction(
                id=new_id("CON-", "temporal-cycle"),
                contradiction_type="TEMPORAL_CYCLE",
                description="Direct BEFORE constraints produce an impossible temporal cycle.",
                event_ids=[],
                severity="HIGH",
                status="OPEN",
                recommended_resolution="Do not silently resolve. Re-check timezone normalization, clock skew, event identity, and source timestamps.",
            ))

    # -----------------------------------------------------------------
    # Sequences / clusters / correlations / hypotheses
    # -----------------------------------------------------------------

    def build_sequences(self) -> None:
        incident_groups: Dict[str, List[str]] = defaultdict(list)
        for event in self.events.values():
            for obj in event.objects:
                if obj.upper().startswith("INCIDENT-"):
                    incident_groups[obj].append(event.id)

        for incident_id, event_ids in incident_groups.items():
            if len(event_ids) < 2:
                continue
            ordered = sorted(
                event_ids,
                key=lambda eid: (
                    timevalue_interval(self.events[eid].time)[0] if timevalue_interval(self.events[eid].time) else datetime.max.replace(tzinfo=timezone.utc),
                    eid,
                ),
            )
            seq_id = new_id("SEQ-", incident_id + "".join(ordered))
            seq = Sequence(
                id=seq_id,
                name=f"Candidate incident sequence {incident_id}",
                sequence_type="INCIDENT_SEQUENCE",
                event_ids=ordered,
                membership_state=SequenceMembership.SUPPORTED,
                evidence_ids=sorted({eid for ev_id in ordered for eid in self.events[ev_id].evidence_ids}),
                source_ids=sorted({sid for ev_id in ordered for sid in self.events[ev_id].source_ids}),
                limitations=[
                    "Sequence membership is based on shared incident identifier and temporal ordering.",
                    "This does not establish causality.",
                    "Incident-level interpretation belongs to INCIDENTINT / domain specialists.",
                ],
            )
            self.sequences.append(seq)
            for eid in ordered:
                self.events[eid].sequence_ids.append(seq_id)

    def build_clusters(self) -> None:
        events = [e for e in self.events.values() if timevalue_interval(e.time)]
        events.sort(key=lambda e: timevalue_interval(e.time)[0])  # type: ignore[index]

        used: Set[str] = set()
        for i, e1 in enumerate(events):
            if e1.id in used:
                continue
            cluster_ids = [e1.id]
            iv1 = timevalue_interval(e1.time)
            if not iv1:
                continue
            for e2 in events[i + 1:]:
                iv2 = timevalue_interval(e2.time)
                if not iv2:
                    continue
                if abs((iv2[0] - iv1[0]).total_seconds()) <= 900:
                    p1 = {p.entity_id for p in e1.participants}
                    p2 = {p.entity_id for p in e2.participants}
                    if p1 & p2:
                        cluster_ids.append(e2.id)
                        used.add(e2.id)
            if len(cluster_ids) >= 2:
                self.clusters.append(Cluster(
                    id=new_id("CLU-", "".join(cluster_ids)),
                    event_ids=cluster_ids,
                    method="TEMPORAL_PROXIMITY_15_MIN_SHARED_PARTICIPANT",
                    interpretation="EVENT_CLUSTER_CANDIDATE",
                    confidence=0.5,
                    limitations=[
                        "Temporal cluster is analytical only.",
                        "Cluster does not establish incident, campaign, coordination, or causation.",
                    ],
                ))
                used.add(e1.id)

    def build_correlations(self) -> None:
        event_ids = list(self.events.keys())
        for i in range(len(event_ids)):
            for j in range(i + 1, len(event_ids)):
                e1 = self.events[event_ids[i]]
                e2 = self.events[event_ids[j]]
                shared_objects = set(e1.objects) & set(e2.objects)
                shared_participants = {p.entity_id for p in e1.participants} & {p.entity_id for p in e2.participants}
                iv1 = timevalue_interval(e1.time)
                iv2 = timevalue_interval(e2.time)
                close_time = False
                if iv1 and iv2:
                    close_time = abs((iv1[0] - iv2[0]).total_seconds()) <= 3600

                if any(o.upper().startswith("INCIDENT-") for o in shared_objects):
                    level = CorrelationLevel.DIRECTLY_LINKED
                    basis = ["shared incident identifier"]
                elif e1.subtype == e2.subtype and shared_participants and close_time:
                    level = CorrelationLevel.STRONG
                    basis = ["same event subtype", "participant overlap", "time proximity"]
                elif shared_participants and close_time:
                    level = CorrelationLevel.MODERATE
                    basis = ["participant overlap", "time proximity"]
                elif self.source_families(e1.source_ids) & self.source_families(e2.source_ids):
                    level = CorrelationLevel.WEAK
                    basis = ["shared upstream source family"]
                else:
                    level = CorrelationLevel.NONE
                    basis = []

                self.correlations.append({
                    "left_event_id": e1.id,
                    "right_event_id": e2.id,
                    "correlation_level": level.value,
                    "basis": basis,
                    "causal_state": CausalState.NO_CAUSAL_CLAIM.value,
                    "limitation": "Correlation is not causation.",
                })

    def build_hypotheses(self) -> None:
        # Causal hypotheses for adjacent sequence events.
        for seq in self.sequences:
            for a, b in zip(seq.event_ids, seq.event_ids[1:]):
                hyp = Hypothesis(
                    id=new_id("HYP-CAUSAL-", a + b),
                    statement=(
                        f"Event {a} may be procedurally or technically connected to Event {b}; "
                        "temporal precedence alone does not establish causation."
                    ),
                    kind="CAUSAL",
                    supporting_event_ids=[a, b],
                    supporting_evidence_ids=sorted(set(self.events[a].evidence_ids + self.events[b].evidence_ids)),
                    assumptions=["The two events are part of the same operational process."],
                    predictions=["Session/device/process identifiers would link the events."],
                    falsification_conditions=[
                        "Different session/device/process context.",
                        "Timestamp normalization error.",
                        "Duplicate or misattributed log record.",
                        "Independent coincidental activity.",
                    ],
                    status=HypothesisStatus.UNRESOLVED,
                    confidence=0.35,
                    limitations=[
                        "Causal hypothesis only.",
                        "Do not promote to verified causal edge without mechanism and independent evidence.",
                    ],
                )
                self.hypotheses.append(hyp)
                self.causal_hypotheses.append(hyp)

        # Identity hypotheses for strong correlated but unmerged events.
        for corr in self.correlations:
            if corr["correlation_level"] not in {CorrelationLevel.STRONG.value, CorrelationLevel.DIRECTLY_LINKED.value}:
                continue
            a = corr["left_event_id"]
            b = corr["right_event_id"]
            if set(self.events[a].stable_ids) & set(self.events[b].stable_ids):
                continue
            hyp = Hypothesis(
                id=new_id("HYP-IDENT-", a + b),
                statement=(
                    f"Events {a} and {b} may be duplicate reports of one event, distinct consecutive events, "
                    "or consequences of a common underlying action."
                ),
                kind="EVENT_IDENTITY",
                supporting_event_ids=[a, b],
                supporting_evidence_ids=sorted(set(self.events[a].evidence_ids + self.events[b].evidence_ids)),
                assumptions=["Temporal proximity and participant overlap are diagnostically useful but not conclusive."],
                predictions=["Stable transaction/session/flow identifiers or primary telemetry would resolve identity."],
                falsification_conditions=[
                    "Distinct stable identifiers.",
                    "Incompatible locations or participants.",
                    "Source lineage shows independent events.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.40,
                limitations=["Event identity remains unresolved; no automatic merge."],
            )
            self.hypotheses.append(hyp)

    def build_expected_missing_events(self) -> None:
        subtypes = {e.subtype for e in self.events.values() if e.subtype}

        if "DOCUMENT_ACCESS" in subtypes and "EXTERNAL_UPLOAD" in subtypes:
            expected_types = {"ENDPOINT_PROCESS_TELEMETRY", "DLP_ALERT", "NOTIFICATION"}
            if not (subtypes & expected_types):
                gap = KnowledgeGap(
                    id=new_id("GAP-EXP-", "document-upload-followup"),
                    gap_type=GapType.EXPECTED_EVENT_NOT_OBSERVED,
                    description=(
                        "Document access followed by external upload is observed, but endpoint process telemetry, "
                        "DLP alert, or notification event is not present in the authorized corpus. "
                        "This is not evidence that such events did not occur."
                    ),
                    about_event_ids=[e.id for e in self.events.values() if e.subtype in {"DOCUMENT_ACCESS", "EXTERNAL_UPLOAD"}],
                    importance="HIGH",
                    recommended_source="Authorized endpoint telemetry, DLP logs, or notification records",
                    specialist="LOGINT / CYBINT / INCIDENTINT",
                    expected_information_value=0.85,
                )
                self.gaps.append(gap)
                self.missing_events.append(gap)
                self.expected_events.append({
                    "expected_event_types": sorted(expected_types),
                    "trigger_sequence": ["DOCUMENT_ACCESS", "EXTERNAL_UPLOAD"],
                    "status": "EXPECTED_EVENT_NOT_OBSERVED",
                })

        human_upload = [e for e in self.events.values() if e.subtype == "EXTERNAL_UPLOAD" and SourceType.HUMAN_SOURCE in {self.sources[s].source_type for s in e.source_ids if s in self.sources}]
        telemetry_upload = [e for e in self.events.values() if e.subtype == "EXTERNAL_UPLOAD" and SourceType.NETWORK_TELEMETRY in {self.sources[s].source_type for s in e.source_ids if s in self.sources}]
        if human_upload and telemetry_upload:
            gap = KnowledgeGap(
                id=new_id("GAP-TZ-", "human-telemetry-time"),
                gap_type=GapType.TIMEZONE_GAP,
                description=(
                    "Human-reported upload time and telemetry interval are close but not identical. "
                    "Timezone, clock skew, memory imprecision, or distinct consecutive actions remain possible."
                ),
                about_event_ids=[e.id for e in human_upload + telemetry_upload],
                importance="MEDIUM",
                recommended_source="Original witness statement metadata, device clock offset, primary telemetry session ID",
                specialist="HUMINT / LOGINT",
                expected_information_value=0.60,
            )
            self.gaps.append(gap)

    # -----------------------------------------------------------------
    # Actions / handoffs / review / summary
    # -----------------------------------------------------------------

    def build_next_actions(self) -> None:
        self.actions = [
            NextAction(
                id="ACT-ENDPOINT-TELEMETRY",
                description="Retrieve authorized endpoint process telemetry or DLP logs to test procedural linkage without asserting causation.",
                priority=1,
                privacy_impact="LOW_IF_AUTHORIZED",
                expected_gain=0.85,
                specialist="LOGINT / CYBINT",
            ),
            NextAction(
                id="ACT-STABLE-IDS",
                description="Obtain stable session/device/flow/transaction identifiers to resolve event identity and avoid duplicate-event inflation.",
                priority=2,
                privacy_impact="LOW",
                expected_gain=0.80,
                specialist="EVENTINT / LOGINT",
            ),
            NextAction(
                id="ACT-TIMEZONE-CLOCK",
                description="Verify timezone, clock offset, and sensor latency for human-reported and telemetry timestamps.",
                priority=3,
                privacy_impact="LOW",
                expected_gain=0.65,
                specialist="EVENTINT / HUMINT",
            ),
            NextAction(
                id="ACT-INDEPENDENT-SOURCE",
                description="Seek an independent source family for material events; do not count copied media as corroboration.",
                priority=4,
                privacy_impact="LOW",
                expected_gain=0.60,
                specialist=None,
            ),
            NextAction(
                id="ACT-HUMAN-REVIEW",
                description="Require human review before incident classification, responsibility attribution, or causal conclusion.",
                priority=5,
                privacy_impact="PROTECTIVE",
                expected_gain=0.70,
                specialist=None,
            ),
            NextAction(
                id="ACT-NO-TARGETING",
                description="Do not use this chronology for stalking, live tracking, operational targeting, sabotage timing, or harm coordination.",
                priority=99,
                privacy_impact="PROTECTIVE",
                expected_gain=0.0,
                specialist=None,
            ),
        ]

    def build_handoffs(self) -> None:
        self.handoffs = [
            {"specialist": "INCIDENTINT", "reason": "Incident-level interpretation and response context."},
            {"specialist": "CYBINT / CTI", "reason": "Cyber event semantics, actor/tool context, and defensive analysis."},
            {"specialist": "LOGINT", "reason": "Primary log integrity, clock skew, session/device correlation."},
            {"specialist": "HUMINT", "reason": "Witness basis-of-knowledge, reliability, and source protection."},
            {"specialist": "GEOINT / IMINT", "reason": "Location verification if physical event location is material and authorized."},
            {"specialist": "PERSONINT", "reason": "Real-person attribution only with authorized identity evidence; account activity is not person activity."},
        ]

    def dual_ai_review(self) -> Dict[str, Any]:
        issues: List[str] = []

        if self.contradictions:
            issues.append(f"{len(self.contradictions)} temporal/identity contradiction(s) remain open.")

        unresolved_identity = [h for h in self.hypotheses if h.kind == "EVENT_IDENTITY" and h.status == HypothesisStatus.UNRESOLVED]
        if unresolved_identity:
            issues.append(f"{len(unresolved_identity)} event-identity hypothesis(es) unresolved.")

        dependent_events = [
            e for e in self.events.values()
            if self.independence_state_for_sources(e.source_ids) in {"DEPENDENT", "SINGLE_SOURCE"}
        ]
        if dependent_events:
            issues.append("Some events rely on single-source or dependent source families.")

        if self.causal_hypotheses:
            issues.append("Causal links remain hypotheses; temporal precedence is not causation.")

        if self.missing_events:
            issues.append("Expected follow-up events are not observed; this may be a coverage gap, not non-occurrence.")

        if any(e.time.inferred_timezone for e in self.events.values()):
            issues.append("Some timestamps use inferred timezone; verify before exact ordering.")

        if not issues:
            verdict = "AGREE"
        elif len(issues) <= 4:
            verdict = "PARTIAL_AGREEMENT"
        else:
            verdict = "INSUFFICIENT_EVIDENCE"

        return {
            "primary_event_analyst": (
                "Supported chronology shows authentication, document access, and external upload in sequence. "
                "Duplicate media reports are collapsed to one upload event via stable flow identifier. "
                "A human-reported upload time remains a separate reported event pending identity resolution."
            ),
            "independent_temporal_skeptic_issues": issues,
            "verdict": verdict,
            "adversarial_checks": [
                "Are publication/observation times confused with event times? No; separate fields preserved.",
                "Are copied sources counted as independent? No; source families tracked.",
                "Is sequence treated as causal chain? No; causal edges remain hypotheses.",
                "Is account activity treated as real-person action? No; person attribution withheld.",
                "Are approximate times forced to exact? No; precision preserved.",
                "Is missing telemetry treated as non-occurrence? No; marked expected-but-not-observed.",
            ],
            "note": "AI agreement is analytical agreement, not independent source corroboration.",
        }

    def analyst_summary(self, dual: Dict[str, Any]) -> str:
        event_lines = []
        for event in sorted(
            self.events.values(),
            key=lambda e: timevalue_interval(e.time)[0] if timevalue_interval(e.time) else datetime.max.replace(tzinfo=timezone.utc),
        ):
            iv = timevalue_interval(event.time)
            time_repr = iv[0].isoformat() if iv else event.time.original
            event_lines.append(
                f"{event.id}: {event.subtype or event.event_type} at {time_repr} "
                f"[precision={event.time.precision.value}; verification={event.verification_state.value}; confidence={event.confidence}]"
            )

        seq_lines = []
        for seq in self.sequences:
            seq_lines.append(f"{seq.id}: {' -> '.join(seq.event_ids)} [{seq.membership_state.value}]")

        return "\n".join([
            "EVENTS:",
            *event_lines,
            "",
            "SEQUENCES:",
            *(seq_lines or ["None supported."]),
            "",
            "NOT ESTABLISHED:",
            "- Causation between sequential events.",
            "- Real-world person behind account/device activity.",
            "- Intent, guilt, or criminal responsibility.",
            "- Incident classification without INCIDENTINT/domain review.",
            "",
            f"DUAL-AI REVIEW: {dual['verdict']}.",
            "PRIVACY/POLICY: No stalking, live tracking, operational targeting, biometric identification, or sensitive-trait inference performed.",
            "NEXT ACTION: Retrieve authorized endpoint/session/flow identifiers and verify timezone/clock before causal or incident conclusions.",
        ])

    # -----------------------------------------------------------------
    # Prepare full pipeline
    # -----------------------------------------------------------------

    def prepare(self) -> None:
        self.derive_observations()
        self.derive_claims()
        self.update_candidate_refs()
        self.resolve_event_identity()
        self.detect_contradictions()
        self.fact_gate_events()
        self.build_temporal_constraints()
        self.build_sequences()
        self.build_clusters()
        self.build_correlations()
        self.build_hypotheses()
        self.build_expected_missing_events()
        self.build_next_actions()
        self.build_handoffs()


# =====================================================================
# SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-EVENTINT-001",
        task_id="TASK-EVENTINT-001",
        objective=(
            "Reconstruct authorized incident chronology for Account ACC-1 and Document DOC-123, "
            "distinguish event time from observation/publication time, deduplicate media reports, "
            "and keep causal links as hypotheses."
        ),
        questions=[
            "What events are supported?",
            "What is the earliest and latest supported event?",
            "Which timestamps are exact, bounded, or approximate?",
            "Which records are duplicate reports of the same event?",
            "Which sequence relationships are factual?",
            "Which causal relationships are only hypotheses?",
            "What expected events are missing from coverage?",
        ],
        target_entities=["ACC-1", "DEV-1", "DOC-123", "EXT-1"],
        time_range="2026-10-08",
        sample=True,
    )


def build_sample_eventint() -> EventInt:
    e = EventInt(sample_case())
    retrieved = now_iso()

    # Locations
    e.add_location(Location(
        id="LOC-NETWORK",
        display_name="Corporate network / virtual location",
        precision=LocationPrecision.NETWORK_VIRTUAL,
        network_virtual="enterprise-network",
        notes="Network/virtual context only; not a physical private location.",
    ))
    e.add_location(Location(
        id="LOC-FACILITY-A",
        display_name="Facility A",
        precision=LocationPrecision.SITE,
        city="Example City",
        region="Example Region",
        country="ExampleLand",
        notes="Public/authorized facility context; no residential tracking.",
    ))

    # Sources
    e.add_source(Source(
        id="SRC-IDP-LOG",
        title="Authorized identity provider log",
        url="https://logs.example/idp/ACC-1",
        source_type=SourceType.IDENTITY_LOG,
        published_at="2026-10-08T14:03:05Z",
        retrieved_at=retrieved,
        effective_at="2026-10-08T14:03:00Z",
        independence_group="IDP_ROOT",
        reliability=0.95,
        notes="Primary system log. Event time represented by log timestamp; publication/retrieval separate.",
    ))
    e.add_source(Source(
        id="SRC-DOC-LOG",
        title="Authorized document platform log",
        url="https://logs.example/documents/DOC-123",
        source_type=SourceType.APPLICATION_LOG,
        published_at="2026-10-08T14:09:03Z",
        retrieved_at=retrieved,
        effective_at="2026-10-08T14:09:00Z",
        independence_group="DOC_ROOT",
        reliability=0.95,
        notes="Primary application log.",
    ))
    e.add_source(Source(
        id="SRC-NET-TELEMETRY",
        title="Authorized network telemetry flow record",
        url="https://telemetry.example/flows/FLOW-777",
        source_type=SourceType.NETWORK_TELEMETRY,
        published_at="2026-10-08T14:17:10Z",
        retrieved_at=retrieved,
        effective_at="2026-10-08T14:12:00Z/2026-10-08T14:17:00Z",
        independence_group="NET_ROOT",
        reliability=0.88,
        notes="Bounded interval observation; sensor latency possible.",
    ))
    e.add_source(Source(
        id="SRC-MEDIA-1",
        title="Media article referencing flow FLOW-777",
        url="https://media.example/upload-report",
        source_type=SourceType.MEDIA,
        published_at="2026-10-08T15:00:00Z",
        retrieved_at=retrieved,
        effective_at="2026-10-08T14:15:00Z",
        independence_group="MEDIA_DERIVED_NET",
        reliability=0.55,
        derived_from="SRC-NET-TELEMETRY",
        notes="Appears to reference primary telemetry; not independent for upload existence.",
    ))
    e.add_source(Source(
        id="SRC-AGG-1",
        title="Aggregator repost of media article",
        url="https://agg.example/upload-report",
        source_type=SourceType.AGGREGATOR,
        published_at="2026-10-08T15:20:00Z",
        retrieved_at=retrieved,
        effective_at="2026-10-08T14:15:00Z",
        independence_group="AGG_DERIVED_MEDIA",
        reliability=0.35,
        derived_from="SRC-MEDIA-1",
        notes="Downstream copy; does not add independent evidence.",
    ))
    e.add_source(Source(
        id="SRC-HUMINT-1",
        title="Authorized human source statement",
        url="https://humint.example/statement/W-17",
        source_type=SourceType.HUMAN_SOURCE,
        published_at="2026-10-08T18:00:00Z",
        retrieved_at=retrieved,
        effective_at="2026-10-08T19:40:00+05:30",
        independence_group="HUMINT_ROOT",
        reliability=0.50,
        notes="Human memory and local timezone may introduce uncertainty.",
    ))

    # Evidence
    e.add_evidence(Evidence(
        id="EV-IDP",
        source_id="SRC-IDP-LOG",
        artifact_type="identity_log_record",
        excerpt="Account ACC-1 authenticated from device DEV-1 at 2026-10-08T14:03:00Z.",
        observed_at=make_time("2026-10-08T14:03:00Z", basis="LOG_TIMESTAMP"),
        stable_ids=["SESSION-777"],
        attributes={
            "entity_refs": ["ACC-1", "DEV-1"],
            "location_ref": "LOC-NETWORK",
            "event_type_candidate": "CYBER_EVENT/AUTHENTICATION",
        },
    ))
    e.add_evidence(Evidence(
        id="EV-DOC",
        source_id="SRC-DOC-LOG",
        artifact_type="application_log_record",
        excerpt="Account ACC-1 downloaded document DOC-123 at 2026-10-08T14:09:00Z.",
        observed_at=make_time("2026-10-08T14:09:00Z", basis="LOG_TIMESTAMP"),
        stable_ids=["DOWNLOAD-777"],
        attributes={
            "entity_refs": ["ACC-1", "DOC-123"],
            "location_ref": "LOC-NETWORK",
            "event_type_candidate": "CYBER_EVENT/DOCUMENT_ACCESS",
        },
    ))
    e.add_evidence(Evidence(
        id="EV-NET",
        source_id="SRC-NET-TELEMETRY",
        artifact_type="network_flow_record",
        excerpt="External upload of DOC-123 from DEV-1 to EXT-1 observed between 2026-10-08T14:12:00Z and 2026-10-08T14:17:00Z.",
        observed_at=make_time({
            "start": "2026-10-08T14:12:00Z",
            "end": "2026-10-08T14:17:00Z",
            "precision": "INTERVAL_BOUNDED",
            "basis": "TELEMETRY_INTERVAL",
        }),
        stable_ids=["FLOW-777"],
        attributes={
            "entity_refs": ["DEV-1", "DOC-123", "EXT-1"],
            "location_ref": "LOC-NETWORK",
            "event_type_candidate": "CYBER_EVENT/EXTERNAL_UPLOAD",
        },
    ))
    e.add_evidence(Evidence(
        id="EV-MEDIA-1",
        source_id="SRC-MEDIA-1",
        artifact_type="media_article",
        excerpt="Article reports external upload of DOC-123 around 14:15 UTC and references flow FLOW-777.",
        observed_at=make_time("around 2026-10-08T14:15:00Z", basis="PUBLISHED_CLAIM"),
        stable_ids=["FLOW-777"],
        attributes={
            "entity_refs": ["DOC-123", "EXT-1"],
            "event_type_candidate": "CYBER_EVENT/EXTERNAL_UPLOAD",
        },
    ))
    e.add_evidence(Evidence(
        id="EV-AGG-1",
        source_id="SRC-AGG-1",
        artifact_type="aggregator_repost",
        excerpt="Aggregator repeats article claim of external upload around 14:15 UTC, referencing FLOW-777.",
        observed_at=make_time("around 2026-10-08T14:15:00Z", basis="DOWNSTREAM_CLAIM"),
        stable_ids=["FLOW-777"],
        attributes={
            "entity_refs": ["DOC-123", "EXT-1"],
            "event_type_candidate": "CYBER_EVENT/EXTERNAL_UPLOAD",
        },
    ))
    e.add_evidence(Evidence(
        id="EV-HUMINT-1",
        source_id="SRC-HUMINT-1",
        artifact_type="human_statement",
        excerpt="Witness reports seeing upload activity at Facility A at 2026-10-08T19:40:00+05:30.",
        observed_at=make_time("2026-10-08T19:40:00+05:30", basis="HUMAN_LOCAL_TIME"),
        stable_ids=[],
        attributes={
            "entity_refs": ["ACC-1", "DOC-123"],
            "location_ref": "LOC-FACILITY-A",
            "event_type_candidate": "CYBER_EVENT/EXTERNAL_UPLOAD",
        },
        notes="Local timezone preserved; normalized UTC computed without overwriting original.",
    ))

    # Event candidates
    e.add_candidate(EventCandidate(
        id="CAND-AUTH",
        event_type="CYBER_EVENT",
        subtype="AUTHENTICATION",
        title="Account authentication",
        description="Authenticated session start for ACC-1 from DEV-1.",
        time=e.evidences["EV-IDP"].observed_at or TimeValue(),
        location_id="LOC-NETWORK",
        participants=[
            Participant(entity_id="ACC-1", role=ParticipantRole.PARTICIPANT, confidence=0.95, evidence_ids=["EV-IDP"], source_ids=["SRC-IDP-LOG"]),
            Participant(entity_id="DEV-1", role=ParticipantRole.OBJECT, confidence=0.90, evidence_ids=["EV-IDP"], source_ids=["SRC-IDP-LOG"]),
        ],
        objects=["SESSION-777", "INCIDENT-777"],
        source_ids=["SRC-IDP-LOG"],
        evidence_ids=["EV-IDP"],
        stable_ids=["SESSION-777"],
        confidence=0.95,
        limitations=["Account/device activity only; no real-person attribution."],
    ))
    e.add_candidate(EventCandidate(
        id="CAND-DOWNLOAD",
        event_type="CYBER_EVENT",
        subtype="DOCUMENT_ACCESS",
        title="Document download",
        description="Document DOC-123 accessed/downloaded by ACC-1.",
        time=e.evidences["EV-DOC"].observed_at or TimeValue(),
        location_id="LOC-NETWORK",
        participants=[
            Participant(entity_id="ACC-1", role=ParticipantRole.PARTICIPANT, confidence=0.95, evidence_ids=["EV-DOC"], source_ids=["SRC-DOC-LOG"]),
            Participant(entity_id="DOC-123", role=ParticipantRole.OBJECT, confidence=0.95, evidence_ids=["EV-DOC"], source_ids=["SRC-DOC-LOG"]),
        ],
        objects=["DOWNLOAD-777", "INCIDENT-777"],
        source_ids=["SRC-DOC-LOG"],
        evidence_ids=["EV-DOC"],
        stable_ids=["DOWNLOAD-777"],
        confidence=0.95,
        limitations=["Application log supports account action; intent/exfiltration not established."],
    ))
    e.add_candidate(EventCandidate(
        id="CAND-UPLOAD-TELEMETRY",
        event_type="CYBER_EVENT",
        subtype="EXTERNAL_UPLOAD",
        title="External upload observed by telemetry",
        description="Bounded network telemetry interval showing upload from DEV-1 to EXT-1.",
        time=e.evidences["EV-NET"].observed_at or TimeValue(),
        location_id="LOC-NETWORK",
        participants=[
            Participant(entity_id="DEV-1", role=ParticipantRole.PARTICIPANT, confidence=0.88, evidence_ids=["EV-NET"], source_ids=["SRC-NET-TELEMETRY"]),
            Participant(entity_id="DOC-123", role=ParticipantRole.OBJECT, confidence=0.85, evidence_ids=["EV-NET"], source_ids=["SRC-NET-TELEMETRY"]),
            Participant(entity_id="EXT-1", role=ParticipantRole.AFFECTED_ENTITY, confidence=0.80, evidence_ids=["EV-NET"], source_ids=["SRC-NET-TELEMETRY"]),
        ],
        objects=["FLOW-777", "INCIDENT-777"],
        source_ids=["SRC-NET-TELEMETRY"],
        evidence_ids=["EV-NET"],
        stable_ids=["FLOW-777"],
        confidence=0.88,
        limitations=["Telemetry interval; sensor latency possible. Upload intent/exfiltration not established."],
    ))
    e.add_candidate(EventCandidate(
        id="CAND-UPLOAD-MEDIA",
        event_type="CYBER_EVENT",
        subtype="EXTERNAL_UPLOAD",
        title="Media report of external upload",
        description="Media article reports upload around 14:15 UTC referencing FLOW-777.",
        time=e.evidences["EV-MEDIA-1"].observed_at or TimeValue(),
        participants=[
            Participant(entity_id="DOC-123", role=ParticipantRole.OBJECT, confidence=0.55, evidence_ids=["EV-MEDIA-1"], source_ids=["SRC-MEDIA-1"]),
        ],
        objects=["FLOW-777", "INCIDENT-777"],
        source_ids=["SRC-MEDIA-1"],
        evidence_ids=["EV-MEDIA-1"],
        stable_ids=["FLOW-777"],
        confidence=0.55,
        limitations=["Dependent media report; not independent confirmation."],
    ))
    e.add_candidate(EventCandidate(
        id="CAND-UPLOAD-AGG",
        event_type="CYBER_EVENT",
        subtype="EXTERNAL_UPLOAD",
        title="Aggregator repost of upload report",
        description="Aggregator repeats media claim referencing FLOW-777.",
        time=e.evidences["EV-AGG-1"].observed_at or TimeValue(),
        participants=[
            Participant(entity_id="DOC-123", role=ParticipantRole.OBJECT, confidence=0.35, evidence_ids=["EV-AGG-1"], source_ids=["SRC-AGG-1"]),
        ],
        objects=["FLOW-777"],
        source_ids=["SRC-AGG-1"],
        evidence_ids=["EV-AGG-1"],
        stable_ids=["FLOW-777"],
        confidence=0.35,
        limitations=["Downstream copy; no new evidence."],
    ))
    e.add_candidate(EventCandidate(
        id="CAND-UPLOAD-HUMINT",
        event_type="CYBER_EVENT",
        subtype="EXTERNAL_UPLOAD",
        title="Human-reported upload activity",
        description="Witness reports upload activity at Facility A in local time.",
        time=e.evidences["EV-HUMINT-1"].observed_at or TimeValue(),
        location_id="LOC-FACILITY-A",
        participants=[
            Participant(entity_id="ACC-1", role=ParticipantRole.PARTICIPANT, confidence=0.50, evidence_ids=["EV-HUMINT-1"], source_ids=["SRC-HUMINT-1"]),
            Participant(entity_id="DOC-123", role=ParticipantRole.OBJECT, confidence=0.45, evidence_ids=["EV-HUMINT-1"], source_ids=["SRC-HUMINT-1"]),
        ],
        objects=[],
        source_ids=["SRC-HUMINT-1"],
        evidence_ids=["EV-HUMINT-1"],
        stable_ids=[],
        confidence=0.50,
        limitations=[
            "Human source; memory/timezone/clock uncertainty possible.",
            "Not merged with telemetry upload due absent stable identifier.",
        ],
    ))

    e.prepare()
    return e


# =====================================================================
# RESULT BUILDER
# =====================================================================

def graph_version_hash(e: EventInt) -> str:
    seed_obj = {
        "events": sorted(
            (ev.id, ev.event_type, ev.subtype or "", ev.verification_state.value, round(float(ev.confidence), 3))
            for ev in e.events.values()
        ),
        "constraints": sorted(
            (c.left_event_id, c.relation.value, c.right_event_id)
            for c in e.constraints
        ),
    }
    return stable_hash(json.dumps(jsonable(seed_obj), sort_keys=True))


def build_timeline_version(e: EventInt, version: int = 1) -> Dict[str, Any]:
    ordered_events = sorted(
        e.events.values(),
        key=lambda ev: timevalue_interval(ev.time)[0] if timevalue_interval(ev.time) else datetime.max.replace(tzinfo=timezone.utc),
    )
    payload = {
        "timeline_id": f"TIMELINE_V{version}",
        "case_id": e.case.case_id,
        "as_of": now_iso(),
        "event_ids": [ev.id for ev in ordered_events],
        "ordering_constraints": [
            {
                "left": c.left_event_id,
                "relation": c.relation.value,
                "right": c.right_event_id,
            }
            for c in e.constraints
        ],
        "contradictions": [c.id for c in e.contradictions],
        "gaps": [g.id for g in e.gaps],
    }
    payload["version_hash"] = stable_hash(json.dumps(jsonable(payload), sort_keys=True))
    return payload


def build_graph_updates(e: EventInt) -> Dict[str, Any]:
    nodes = []
    for ev in e.events.values():
        nodes.append({
            "node_id": ev.id,
            "node_type": "Event",
            "label": ev.title or ev.subtype or ev.event_type,
            "verification_state": ev.verification_state.value,
            "confidence": ev.confidence,
        })
    edges = []
    for p in e.precedences:
        edges.append({
            "source": p["left_event_id"],
            "target": p["right_event_id"],
            "relationship_type": "PRECEDES",
            "derivation": p.get("derivation", "DIRECT"),
            "causal": False,
        })
    for c in e.contradictions:
        for ev_id in c.event_ids:
            edges.append({
                "source": c.id,
                "target": ev_id,
                "relationship_type": "CONTRADICTS",
            })
    return {"nodes": nodes, "edges": edges}


def build_result(e: EventInt, status: Status) -> Dict[str, Any]:
    dual = e.dual_ai_review()
    summary = e.analyst_summary(dual)
    timeline = build_timeline_version(e, version=1)

    event_timezones = {ev.id: ev.time.timezone for ev in e.events.values()}
    event_precision = {ev.id: ev.time.precision.value for ev in e.events.values()}
    time_bounds = {
        ev.id: {
            "original": ev.time.original,
            "normalized_start_utc": ev.time.normalized_start_utc,
            "normalized_end_utc": ev.time.normalized_end_utc,
            "precision": ev.time.precision.value,
            "timezone": ev.time.timezone,
            "inferred_timezone": ev.time.inferred_timezone,
        }
        for ev in e.events.values()
    }

    source_families = {sid: e.get_source_family(sid) for sid in e.sources}
    event_independence = {
        ev.id: e.independence_state_for_sources(ev.source_ids)
        for ev in e.events.values()
    }

    temporal_contradictions = [c for c in e.contradictions if c.contradiction_type.startswith("TEMPORAL")]
    location_contradictions = [c for c in e.contradictions if c.contradiction_type == "LOCATION"]
    entity_contradictions = [c for c in e.contradictions if c.contradiction_type in {"ENTITY", "TEMPORAL_IDENTITY"}]

    coverage = {
        "source_ids": sorted(e.sources.keys()),
        "source_families": source_families,
        "event_time_coverage": {
            ev.id: {
                "start": ev.time.normalized_start_utc,
                "end": ev.time.normalized_end_utc,
            }
            for ev in e.events.values()
        },
        "known_gaps": [g.description for g in e.gaps],
    }

    limitations = [
        "Local synthetic demo; no live system retrieval.",
        "Temporal ordering is partial where precision is approximate/unknown.",
        "Causal relationships remain hypotheses.",
        "Account/device activity is not real-person attribution.",
        "Do not use for operational targeting, stalking, or harm coordination.",
    ] + e.validation_errors

    replay_manifest = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "graph_version": graph_version_hash(e),
        "golden_rule": "RAW OBSERVATION -> EVENT CANDIDATE -> NORMALIZATION -> IDENTITY RESOLUTION -> FACT GATE -> TEMPORAL RELATIONSHIPS -> SEQUENCE -> CORRELATION -> CAUSAL HYPOTHESIS -> FALSIFICATION -> VERIFIED TIMELINE",
        "original_timestamps": {
            ev.id: {
                "original": ev.time.original,
                "start_original": ev.time.start_original,
                "end_original": ev.time.end_original,
                "timezone": ev.time.timezone,
                "inferred_timezone": ev.time.inferred_timezone,
            }
            for ev in e.events.values()
        },
        "event_merge_decisions": [
            {
                "event_id": ev.id,
                "merged_from": ev.merged_from,
                "duplicate_reports": ev.duplicate_reports,
                "identity_state": ev.identity_state.value,
            }
            for ev in e.events.values()
            if ev.merged_from
        ],
        "source_lineage": source_families,
        "causal_hypothesis_history": [
            {
                "hypothesis_id": h.id,
                "statement": h.statement,
                "status": h.status.value,
                "falsification_conditions": h.falsification_conditions,
            }
            for h in e.causal_hypotheses
        ],
        "policy_exclusions": [
            "No fabricated events/timestamps/participants/locations/causes.",
            "No publication time treated as event time.",
            "No correlation treated as causation.",
            "No account activity treated as real-person action.",
            "No stalking/live tracking/operational targeting.",
        ],
    }

    return {
        "case_id": e.case.case_id,
        "task_id": e.case.task_id,
        "objective": e.case.objective,
        "questions": e.case.questions,
        "status": status.value,
        "source_ids": sorted(e.sources.keys()),
        "evidence_ids": sorted(e.evidences.keys()),
        "observations": list(e.observations.values()),
        "claims": list(e.claims.values()),
        "event_candidates": list(e.candidates.values()),
        "events": list(e.events.values()),
        "event_types": sorted({ev.event_type for ev in e.events.values()}),
        "event_subtypes": sorted({ev.subtype for ev in e.events.values() if ev.subtype}),
        "verification_states": {ev.id: ev.verification_state.value for ev in e.events.values()},
        "event_start_times": {ev.id: ev.time.normalized_start_utc for ev in e.events.values()},
        "event_end_times": {ev.id: ev.time.normalized_end_utc for ev in e.events.values()},
        "temporal_precision": event_precision,
        "timezones": event_timezones,
        "time_bounds": time_bounds,
        "locations": list(e.locations.values()),
        "location_precision": {loc.id: loc.precision.value for loc in e.locations.values()},
        "participants": {
            ev.id: [jsonable(p) for p in ev.participants]
            for ev in e.events.values()
        },
        "participant_roles": {
            ev.id: {p.entity_id: p.role.value for p in ev.participants}
            for ev in e.events.values()
        },
        "event_identity_clusters": e.identity_clusters,
        "duplicates": [
            {
                "event_id": ev.id,
                "duplicate_reports": ev.duplicate_reports,
            }
            for ev in e.events.values()
            if ev.duplicate_reports
        ],
        "merged_events": [ev.id for ev in e.events.values() if len(ev.merged_from) > 1],
        "split_events": [],
        "superseded_events": [],
        "event_sequences": e.sequences,
        "ordering_constraints": e.constraints,
        "precedence_relationships": e.precedences,
        "concurrency_relationships": e.concurrencies,
        "interval_relationships": [
            {
                "left": c.left_event_id,
                "relation": c.relation.value,
                "right": c.right_event_id,
            }
            for c in e.constraints
        ],
        "event_clusters": e.clusters,
        "incident_membership": [
            {
                "sequence_id": s.id,
                "event_ids": s.event_ids,
                "membership_state": s.membership_state.value,
                "limitations": s.limitations,
            }
            for s in e.sequences
            if s.sequence_type == "INCIDENT_SEQUENCE"
        ],
        "campaign_membership_candidates": [
            {
                "sequence_id": s.id,
                "event_ids": s.event_ids,
                "membership_state": s.membership_state.value,
            }
            for s in e.sequences
            if s.sequence_type == "CAMPAIGN_SEQUENCE"
        ],
        "state_transitions": [],
        "correlations": e.correlations,
        "correlation_strength": {
            f"{c['left_event_id']}|{c['right_event_id']}": c["correlation_level"]
            for c in e.correlations
        },
        "causal_hypotheses": e.causal_hypotheses,
        "causal_states": {
            ev.id: ev.causal_status.value
            for ev in e.events.values()
        },
        "source_reliability": {sid: s.reliability for sid, s in e.sources.items()},
        "source_bias": {sid: s.notes for sid, s in e.sources.items()},
        "source_limitations": {sid: [s.notes] for sid, s in e.sources.items() if s.notes},
        "source_pedigree": source_families,
        "source_independence": {
            "event_independence": event_independence,
            "source_families": source_families,
        },
        "facts": [
            {
                "fact_id": f"FACT-{ev.id}",
                "statement": (
                    f"Event {ev.id} ({ev.subtype or ev.event_type}) is {ev.verification_state.value} "
                    f"for time representation {ev.time.original} with confidence {ev.confidence}."
                ),
                "event_id": ev.id,
                "source_ids": ev.source_ids,
                "evidence_ids": ev.evidence_ids,
                "confidence": ev.confidence,
                "verification_state": ev.verification_state.value,
                "limitations": ev.limitations,
            }
            for ev in e.events.values()
            if ev.verification_state in {
                VerificationState.SUPPORTED,
                VerificationState.STRONGLY_SUPPORTED,
                VerificationState.PARTIALLY_SUPPORTED,
            }
        ],
        "contradictions": e.contradictions,
        "temporal_contradictions": temporal_contradictions,
        "location_contradictions": location_contradictions,
        "entity_contradictions": entity_contradictions,
        "hypotheses": e.hypotheses,
        "ach_matrix": [
            {
                "hypothesis_id": h.id,
                "evidence_ids": h.supporting_evidence_ids,
                "assessment": "CONSISTENT_BUT_NOT_DIAGNOSTIC_ENOUGH",
                "note": "Simplified ACH placeholder; full ACH requires evidence-by-hypothesis diagnostic scoring.",
            }
            for h in e.hypotheses
        ],
        "falsification_results": [
            {
                "hypothesis_id": h.id,
                "status": h.status.value,
                "falsification_conditions": h.falsification_conditions,
                "limitations": h.limitations,
            }
            for h in e.hypotheses
        ],
        "expected_events": e.expected_events,
        "missing_events": e.missing_events,
        "coverage_gaps": [g for g in e.gaps if g.gap_type in {GapType.COVERAGE_GAP, GapType.SOURCE_GAP, GapType.EXPECTED_EVENT_NOT_OBSERVED}],
        "unknowns": [g.description for g in e.gaps] + [h.statement for h in e.hypotheses if h.status == HypothesisStatus.UNRESOLVED],
        "knowledge_gaps": e.gaps,
        "recommended_next_actions": e.actions,
        "specialist_handoffs": e.handoffs,
        "timeline_versions": [timeline],
        "graph_updates": build_graph_updates(e),
        "limitations": limitations,
        "privacy_flags": [
            PrivacyFlag.CASE_SCOPED.value,
            PrivacyFlag.NO_PRIVATE_DATA_COLLECTED.value,
            PrivacyFlag.NO_LIVE_LOCATION_TRACKING.value,
            PrivacyFlag.NO_STALKING.value,
            PrivacyFlag.NO_OPERATIONAL_TARGETING.value,
            PrivacyFlag.NO_BIOMETRIC_IDENTIFICATION.value,
            PrivacyFlag.NO_SENSITIVE_TRAIT_INFERENCE.value,
            PrivacyFlag.NO_REAL_PERSON_ATTRIBUTION_FROM_ACCOUNT.value,
        ],
        "policy_flags": [
            PolicyFlag.NONE.value,
            PolicyFlag.HUMAN_REVIEW_RECOMMENDED.value if e.contradictions or e.causal_hypotheses else PolicyFlag.NONE.value,
        ],
        "analyst_summary": summary,
        "dual_ai_review": dual,
        "replay_manifest": replay_manifest,
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline() -> Dict[str, Any]:
    e = build_sample_eventint()
    return build_result(e, Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    e = EventInt(case)

    gap = KnowledgeGap(
        id="GAP-NO-SOURCES",
        gap_type=GapType.COVERAGE_GAP,
        description="No authorized event-source adapter or local evidence corpus is configured.",
        importance="HIGH",
        recommended_source="Connect authorized log/telemetry/document/media sources or provide local JSON evidence corpus.",
        specialist=None,
        expected_information_value=0.95,
    )
    e.gaps.append(gap)
    e.actions = [NextAction(
        id="ACT-CONFIGURE-SOURCES",
        description=(
            "Configure authorized event sources or supply local evidence. "
            "Do not fabricate timestamps, probe unauthorized systems, stalk persons, or create targeting timelines."
        ),
        priority=1,
        privacy_impact="LOW",
        expected_gain=0.95,
    )]
    e.handoffs = []
    e.validation_errors = []

    dual = {
        "primary_event_analyst": "No evidence available.",
        "independent_temporal_skeptic_issues": [
            "No sources configured.",
            "No events can be validated.",
            "No timestamps can be normalized from evidence.",
            "No sequence or causality conclusion is possible.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "AI agreement is not independent source corroboration.",
    }

    summary = (
        "EVENT UNRESOLVED: No configured evidence corpus. "
        "No events, timestamps, participants, locations, or causes were fabricated. "
        "Provide authorized sources or run sample mode."
    )

    result = build_result(e, Status.BLOCKED_CONFIGURATION)
    result["analyst_summary"] = summary
    result["dual_ai_review"] = dual
    return result


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited event-intelligence request detected. EVENTINT supports lawful, authorized, "
            "evidence-first chronology only, not stalking, live tracking, operational targeting, "
            "sabotage timing, guilt-by-timing, or unauthorized access."
        ),
        "lawful_alternatives": [
            "Use authorized logs/telemetry/documents for historical chronology.",
            "Preserve original timestamps and timezone uncertainty.",
            "Keep sequence separate from causation.",
            "Require human review for incident/responsibility conclusions.",
        ],
        "privacy_flags": [
            PrivacyFlag.NO_STALKING.value,
            PrivacyFlag.NO_LIVE_LOCATION_TRACKING.value,
            PrivacyFlag.NO_OPERATIONAL_TARGETING.value,
        ],
        "limitations": [
            "No events constructed.",
            "No timestamps fabricated.",
            "No private data accessed.",
        ],
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.questions,
            *case.target_entities,
            case.authorization or "",
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
            "TRACEATLAS EVENTINT local evidence-first event intelligence pipeline. "
            "Sample mode uses synthetic authorized-record-style data."
        )
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic EVENTINT sample.")
    parser.add_argument("--objective", help="Investigation objective.")
    parser.add_argument("--question", action="append", default=[], help="Analytic question. Repeatable.")
    parser.add_argument("--entity", action="append", default=[], help="Target entity label. Repeatable.")
    parser.add_argument("--time-range", help="Time range hint, e.g. 2026-10-08.")

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            questions=args.question,
            target_entities=args.entity,
            time_range=args.time_range,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()