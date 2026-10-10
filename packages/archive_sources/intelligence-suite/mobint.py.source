"""
======================================================================
TRACEATLAS — MOBINT
MOBILITY & MOVEMENT-PATTERN INTELLIGENCE AI EMPLOYEE
Python Implementation
======================================================================

Mode:
LAWFUL / AUTHORIZED / PRIVACY-PRESERVING / EVIDENCE-FIRST

Primary boundary:
Mobility intelligence and movement-pattern analysis,
NOT private-person tracking, stalking or targeting.
"""

from __future__ import annotations

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("MOBINT")


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


class EntityType(str, Enum):
    ASSET = "ASSET"
    VEHICLE = "VEHICLE"
    FLEET = "FLEET"
    DEVICE = "DEVICE"
    PUBLIC_TRANSPORT = "PUBLIC_TRANSPORT"
    VESSEL = "VESSEL"
    AIRCRAFT = "AIRCRAFT"
    AGGREGATE = "AGGREGATE"
    PERSON = "PERSON"
    UNKNOWN = "UNKNOWN"


class MovementEventType(str, Enum):
    OBSERVED_AT = "OBSERVED_AT"
    DEPARTED = "DEPARTED"
    ARRIVED = "ARRIVED"
    IN_TRANSIT = "IN_TRANSIT"
    STOPPED = "STOPPED"
    DWELLING = "DWELLING"
    ROUTE_SEGMENT = "ROUTE_SEGMENT"
    ZONE_ENTERED = "ZONE_ENTERED"
    ZONE_EXITED = "ZONE_EXITED"
    TRANSFER = "TRANSFER"
    BOARDING_REPORTED = "BOARDING_REPORTED"
    ALIGHTING_REPORTED = "ALIGHTING_REPORTED"
    UNKNOWN = "UNKNOWN"


class PrecisionLevel(str, Enum):
    EXACT_SENSOR = "EXACT_SENSOR"
    HIGH_PRECISION = "HIGH_PRECISION"
    STREET_LEVEL = "STREET_LEVEL"
    NEIGHBORHOOD = "NEIGHBORHOOD"
    CITY = "CITY"
    REGION = "REGION"
    COUNTRY = "COUNTRY"
    UNKNOWN = "UNKNOWN"


class MovementMode(str, Enum):
    WALKING_CANDIDATE = "WALKING_CANDIDATE"
    CYCLING_CANDIDATE = "CYCLING_CANDIDATE"
    ROAD_VEHICLE_CANDIDATE = "ROAD_VEHICLE_CANDIDATE"
    RAIL_CANDIDATE = "RAIL_CANDIDATE"
    MARITIME_CANDIDATE = "MARITIME_CANDIDATE"
    AIR_CANDIDATE = "AIR_CANDIDATE"
    STATIONARY = "STATIONARY"
    UNKNOWN = "UNKNOWN"


class StopType(str, Enum):
    TRANSIENT_STOP = "TRANSIENT_STOP"
    DWELL_STOP = "DWELL_STOP"
    TRANSFER_STOP = "TRANSFER_STOP"
    OPERATIONAL_STOP = "OPERATIONAL_STOP"
    UNKNOWN = "UNKNOWN"


class AnomalyState(str, Enum):
    EXPECTED = "EXPECTED"
    MINOR_VARIATION = "MINOR_VARIATION"
    UNUSUAL = "UNUSUAL"
    MATERIALLY_UNUSUAL = "MATERIALLY_UNUSUAL"
    UNEXPLAINED = "UNEXPLAINED"
    UNKNOWN = "UNKNOWN"


class DeviationState(str, Enum):
    NORMAL_VARIATION = "NORMAL_VARIATION"
    MINOR_DEVIATION = "MINOR_DEVIATION"
    MATERIAL_DEVIATION = "MATERIAL_DEVIATION"
    UNEXPLAINED_DEVIATION = "UNEXPLAINED_DEVIATION"
    UNKNOWN = "UNKNOWN"


class ColocationState(str, Enum):
    SUPPORTED_COLOCATION = "SUPPORTED_COLOCATION"
    POSSIBLE_COLOCATION = "POSSIBLE_COLOCATION"
    COLOCATION_NOT_SUPPORTED = "COLOCATION_NOT_SUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ComovementState(str, Enum):
    COMOVED_CANDIDATE = "COMOVED_CANDIDATE"
    POSSIBLE_COMOVEMENT = "POSSIBLE_COMOVEMENT"
    COMOVEMENT_NOT_SUPPORTED = "COMOVEMENT_NOT_SUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class IndependenceState(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    PARTIALLY_DEPENDENT = "PARTIALLY_DEPENDENT"
    DEPENDENT = "DEPENDENT"
    UNKNOWN = "UNKNOWN"


class FactStatus(str, Enum):
    FACT = "FACT"
    SUPPORTED = "SUPPORTED"
    CANDIDATE = "CANDIDATE"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"


class ReviewStatus(str, Enum):
    AGREE = "AGREE"
    PARTIAL_AGREEMENT = "PARTIAL_AGREEMENT"
    DISAGREE = "DISAGREE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class PrivacyClassification(str, Enum):
    PUBLIC = "PUBLIC"
    BUSINESS = "BUSINESS"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    HIGHLY_SENSITIVE = "HIGHLY_SENSITIVE"


class ZoneType(str, Enum):
    CITY = "CITY"
    REGION = "REGION"
    PORT = "PORT"
    AIRPORT = "AIRPORT"
    WAREHOUSE = "WAREHOUSE"
    FACILITY = "FACILITY"
    ROAD_CORRIDOR = "ROAD_CORRIDOR"
    TRANSIT_ZONE = "TRANSIT_ZONE"
    EVENT_ZONE = "EVENT_ZONE"
    AUTHORIZED_OPERATIONAL_ZONE = "AUTHORIZED_OPERATIONAL_ZONE"
    MEDICAL = "MEDICAL"
    RELIGIOUS = "RELIGIOUS"
    SHELTER = "SHELTER"
    POLITICAL = "POLITICAL"
    RESIDENCE = "RESIDENCE"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


SENSITIVE_ZONE_TYPES = {
    ZoneType.MEDICAL,
    ZoneType.RELIGIOUS,
    ZoneType.SHELTER,
    ZoneType.POLITICAL,
    ZoneType.RESIDENCE,
}


# ======================================================================
# SECTION 2 — UTILITIES
# ======================================================================

EARTH_RADIUS_M = 6371000.0


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


def std(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return 0.0
    m = sum(vals) / len(vals)
    var = sum((x - m) ** 2 for x in vals) / (len(vals) - 1)
    return math.sqrt(var)


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def haversine_m(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
) -> Optional[float]:
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return None
    try:
        p1 = math.radians(float(lat1))
        p2 = math.radians(float(lat2))
        dp = math.radians(float(lat2) - float(lat1))
        dl = math.radians(float(lon2) - float(lon1))
        a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return EARTH_RADIUS_M * c
    except Exception:
        return None


def bearing_deg(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
) -> Optional[float]:
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return None
    try:
        p1 = math.radians(float(lat1))
        p2 = math.radians(float(lat2))
        dl = math.radians(float(lon2) - float(lon1))
        y = math.sin(dl) * math.cos(p2)
        x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
        return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0
    except Exception:
        return None


def angle_diff_deg(a: Optional[float], b: Optional[float]) -> Optional[float]:
    if a is None or b is None:
        return None
    return abs((a - b + 180.0) % 360.0 - 180.0)


def hash_payload(payload: Any) -> str:
    try:
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
    except Exception:
        canonical = str(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def round_coord(value: Optional[float], digits: int = 5) -> Optional[float]:
    if value is None:
        return None
    return round(float(value), digits)


def token_set(text: Optional[str]) -> set[str]:
    if not text:
        return set()
    return {t for t in re.split(r"\W+", text.lower()) if t}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


VELOCITY_UNIT_TO_MS = {
    "m/s": 1.0,
    "mps": 1.0,
    "km/h": 1.0 / 3.6,
    "kph": 1.0 / 3.6,
    "kn": 0.514444,
    "knot": 0.514444,
    "knots": 0.514444,
    "mph": 0.44704,
}


def to_m_s(value: Optional[float], unit: Optional[str]) -> Tuple[Optional[float], Optional[str]]:
    if value is None:
        return None, None
    u = (unit or "m/s").strip().lower()
    factor = VELOCITY_UNIT_TO_MS.get(u)
    if factor is None:
        return None, "UNIT_UNKNOWN"
    return value * factor, u


# ======================================================================
# SECTION 3 — POLICY GUARD / PROMPT INJECTION DEFENSE
# ======================================================================

@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str = ""


class PolicyGuard:
    """
    Blocks requests seeking prohibited MOBINT private-person tracking,
    targeting, interception, evasion, or exploitation guidance.

    Allows lawful authorized asset/fleet/public-transport/aggregate
    historical mobility analysis and defensive resilience assessment.
    """

    PROHIBITED_PATTERNS = [
        r"(?:track|follow|locate|find|monitor|surveil|stalk|pursue|intercept|ambush|approach|wait for).{0,80}(?:private person|individual|person|woman|man|child|minor|victim|witness|source|journalist|activist|employee|home|residence|house|apartment|workplace|work address|office)",
        r"\b(?:live|real.time|current).{0,40}(?:tracking|location|pursuit|surveillance|monitoring).{0,40}(?:person|individual|home|victim|witness|source|child)",
        r"\b(?:stolen|unauthorized|leaked|private|personal).{0,40}(?:gps|telematics|telemetry|cellular|telecom|cctv|camera|device|account|credentials|spyware|wifi|wi.fi|bluetooth|license plate|plate reader)",
        r"\b(?:interception|ambush|choke.point|targeting coordinates|attack route|evasion route|avoid cameras|avoid gps|defeat monitoring|bypass geofence|conceal movement|evade law enforcement)\b",
        r"(?:infer|determine|find|discover).{0,40}(?:home|residence|workplace|work address).{0,40}(?:person|individual|employee|someone|him|her)",
        r"(?:activate|turn on|enable).{0,40}(?:sensor|microphone|camera|gps|tracking).{0,40}(?:device|phone|person|vehicle)",
    ]

    def __init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.PROHIBITED_PATTERNS]

    def check_request(self, text: str) -> PolicyResult:
        t = text or ""
        for rx in self._compiled:
            if rx.search(t):
                return PolicyResult(
                    decision=PolicyDecision.POLICY_BLOCKED,
                    reason="Request seeks prohibited MOBINT private-person tracking, targeting, interception, evasion, or exploitation guidance.",
                )
        return PolicyResult(decision=PolicyDecision.ALLOW, reason="")

    def is_safe_action(self, action: str) -> bool:
        return self.check_request(action).decision == PolicyDecision.ALLOW


class PromptInjectionDefense:
    """
    Telemetry comments, dispatch notes, transport records, map metadata,
    and external feeds are untrusted data. Neutralize obvious instruction-like
    injections while preserving original evidence separately.
    """

    CONTROL_TOKEN_RX = re.compile(r"<\|.*?\|>", re.DOTALL)
    INSTRUCTION_RX = re.compile(
        r"(?i)\b(ignore\s+previous|ignore\s+above|system\s+prompt|you\s+are\s+now|new\s+instructions?|change\s+classification|reveal\s+private|disable\s+privacy|track\s+person)\b"
    )

    def sanitize(self, text: Any, max_len: int = 500) -> Optional[str]:
        if text is None:
            return None
        s = str(text)
        s = self.CONTROL_TOKEN_RX.sub("[REDACTED_CONTROL_TOKEN]", s)
        s = self.INSTRUCTION_RX.sub("[UNTRUSTED_INSTRUCTION]", s)
        return s[:max_len]


# ======================================================================
# SECTION 4 — CORE DATA OBJECTS
# ======================================================================

@dataclass
class Evidence:
    evidence_id: str = field(default_factory=lambda: new_id("EV"))
    case_id: str = ""
    source_id: str = ""
    source_type: str = "UNKNOWN"
    entity_id: str = ""
    asset_id: str = ""
    timestamp: Optional[datetime] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    coordinate_precision: str = "UNKNOWN"
    source_precision: str = "UNKNOWN"
    location_uncertainty_m: Optional[float] = None
    speed_m_s: Optional[float] = None
    heading_deg: Optional[float] = None
    raw_reference: str = ""
    content_hash: str = ""
    parser_version: str = "MOBINT-parser-0.1.0"
    normalizer_version: str = "MOBINT-normalizer-0.1.0"
    authorization_context: str = ""


@dataclass
class Source:
    source_id: str
    provider: str = "UNKNOWN"
    upstream_feed: str = "UNKNOWN"
    independence_group: str = "UNKNOWN"
    reliability: str = "UNKNOWN"
    source_type: str = "UNKNOWN"
    data_freshness: str = "UNKNOWN"
    limitations: List[str] = field(default_factory=list)


@dataclass
class Entity:
    entity_id: str
    entity_type: EntityType = EntityType.UNKNOWN
    asset_id: str = ""
    display_label: str = ""
    privacy: PrivacyClassification = PrivacyClassification.PUBLIC
    pseudonymized: bool = False
    source_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class TrackPoint:
    point_id: str = field(default_factory=lambda: new_id("PT"))
    entity_id: str = ""
    asset_id: str = ""
    timestamp: datetime = field(default_factory=utcnow)
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    accuracy_radius_m: Optional[float] = None
    speed_m_s: Optional[float] = None
    heading_deg: Optional[float] = None
    event_type: MovementEventType = MovementEventType.OBSERVED_AT
    precision_level: PrecisionLevel = PrecisionLevel.UNKNOWN
    source_id: str = ""
    evidence_id: str = ""
    quality_flags: List[str] = field(default_factory=list)


@dataclass
class Stop:
    stop_id: str = field(default_factory=lambda: new_id("STOP"))
    entity_id: str = ""
    asset_id: str = ""
    start_time: datetime = field(default_factory=utcnow)
    end_time: datetime = field(default_factory=utcnow)
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_m: Optional[float] = None
    duration_s: Optional[float] = None
    stop_type: StopType = StopType.UNKNOWN
    confidence: Confidence = Confidence.LOW
    point_ids: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class RouteSegment:
    segment_id: str = field(default_factory=lambda: new_id("SEG"))
    from_point_id: str = ""
    to_point_id: str = ""
    method: str = "RAW_GEODESIC"
    distance_m: Optional[float] = None
    duration_s: Optional[float] = None
    average_speed_m_s: Optional[float] = None
    matched_road_id: Optional[str] = None
    matched_road_name: Optional[str] = None
    confidence: Confidence = Confidence.LOW
    inferred: bool = True
    notes: List[str] = field(default_factory=list)


@dataclass
class Trip:
    trip_id: str = field(default_factory=lambda: new_id("TRIP"))
    entity_id: str = ""
    asset_id: str = ""
    start_time: datetime = field(default_factory=utcnow)
    end_time: datetime = field(default_factory=utcnow)
    points: List[TrackPoint] = field(default_factory=list)
    stops: List[Stop] = field(default_factory=list)
    route_segments: List[RouteSegment] = field(default_factory=list)
    route_signature: Tuple[Any, ...] = field(default_factory=tuple)
    distance_m: Optional[float] = None
    duration_s: Optional[float] = None
    average_speed_m_s: Optional[float] = None
    max_speed_m_s: Optional[float] = None
    movement_mode: MovementMode = MovementMode.UNKNOWN
    origin_state: str = "OBSERVED_ORIGIN"
    destination_state: str = "OBSERVED_DESTINATION"
    segmentation_confidence: Confidence = Confidence.LOW
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Zone:
    zone_id: str
    name: str = ""
    zone_type: ZoneType = ZoneType.UNKNOWN
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_m: Optional[float] = None
    privacy: PrivacyClassification = PrivacyClassification.PUBLIC
    min_count: int = 1
    limitations: List[str] = field(default_factory=list)


@dataclass
class GeofenceEvent:
    event_id: str = field(default_factory=lambda: new_id("GEOF"))
    entity_id: str = ""
    asset_id: str = ""
    zone_id: str = ""
    zone_name: str = ""
    event_type: MovementEventType = MovementEventType.UNKNOWN
    timestamp: datetime = field(default_factory=utcnow)
    confidence: Confidence = Confidence.LOW
    notes: List[str] = field(default_factory=list)


@dataclass
class Colocation:
    colocation_id: str = field(default_factory=lambda: new_id("COLOC"))
    entity_a: str = ""
    entity_b: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_m: Optional[float] = None
    matched_points: int = 0
    average_distance_m: Optional[float] = None
    state: ColocationState = ColocationState.INCONCLUSIVE
    confidence: Confidence = Confidence.LOW
    notes: List[str] = field(default_factory=list)


@dataclass
class Comovement:
    comovement_id: str = field(default_factory=lambda: new_id("COMOV"))
    entity_a: str = ""
    entity_b: str = ""
    overlapping_trip_ids: List[str] = field(default_factory=list)
    duration_s: Optional[float] = None
    average_distance_m: Optional[float] = None
    state: ComovementState = ComovementState.INCONCLUSIVE
    confidence: Confidence = Confidence.LOW
    notes: List[str] = field(default_factory=list)


@dataclass
class MovementAnomaly:
    anomaly_id: str = field(default_factory=lambda: new_id("ANOM"))
    entity_id: str = ""
    asset_id: str = ""
    trip_id: str = ""
    anomaly_type: str = "UNKNOWN"
    state: AnomalyState = AnomalyState.UNKNOWN
    description: str = ""
    baseline_id: str = ""
    z_score: Optional[float] = None
    confidence: Confidence = Confidence.LOW
    notes: List[str] = field(default_factory=list)


@dataclass
class RouteDeviation:
    deviation_id: str = field(default_factory=lambda: new_id("DEV"))
    entity_id: str = ""
    asset_id: str = ""
    trip_id: str = ""
    baseline_route_signature: Tuple[Any, ...] = field(default_factory=tuple)
    observed_route_signature: Tuple[Any, ...] = field(default_factory=tuple)
    state: DeviationState = DeviationState.UNKNOWN
    segment_difference_count: int = 0
    explanation_context: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    notes: List[str] = field(default_factory=list)


@dataclass
class Contradiction:
    contradiction_id: str = field(default_factory=lambda: new_id("CONTRA"))
    contradiction_type: str = ""
    description: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    candidate_resolutions: List[str] = field(default_factory=list)
    status: str = "OPEN"


@dataclass
class Hypothesis:
    hypothesis_id: str = field(default_factory=lambda: new_id("HYP"))
    statement: str = ""
    supports: List[str] = field(default_factory=list)
    oppositions: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
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
class MOBINTResult:
    case_id: str
    task_id: str
    objective: str
    status: str
    policy_decision: PolicyDecision = PolicyDecision.ALLOW

    evidence: List[Evidence] = field(default_factory=list)
    sources: List[Source] = field(default_factory=list)
    entities: List[Entity] = field(default_factory=list)
    tracks: List[TrackPoint] = field(default_factory=list)
    trips: List[Trip] = field(default_factory=list)
    stops: List[Stop] = field(default_factory=list)
    zones: List[Zone] = field(default_factory=list)
    geofence_events: List[GeofenceEvent] = field(default_factory=list)
    colocations: List[Colocation] = field(default_factory=list)
    comovements: List[Comovement] = field(default_factory=list)
    anomalies: List[MovementAnomaly] = field(default_factory=list)
    deviations: List[RouteDeviation] = field(default_factory=list)
    od_matrix: List[Dict[str, Any]] = field(default_factory=list)
    corridor_summary: List[Dict[str, Any]] = field(default_factory=list)
    recurring_routes: List[Dict[str, Any]] = field(default_factory=list)

    contradictions: List[Contradiction] = field(default_factory=list)
    facts: List[Fact] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    knowledge_gaps: List[KnowledgeGap] = field(default_factory=list)
    next_actions: List[NextAction] = field(default_factory=list)
    specialist_handoffs: List[SpecialistHandoff] = field(default_factory=list)

    source_independence: Dict[str, Any] = field(default_factory=dict)
    review: Dict[str, Any] = field(default_factory=dict)
    graph: Dict[str, Any] = field(default_factory=dict)
    report: str = ""

    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    safety_flags: List[str] = field(default_factory=list)
    privacy_flags: List[str] = field(default_factory=list)
    sensitive_location_flags: List[str] = field(default_factory=list)


# ======================================================================
# SECTION 5 — INGESTION
# ======================================================================

class MOBINTIngestor:
    PARSER_VERSION = "MOBINT-parser-0.1.0"
    NORMALIZER_VERSION = "MOBINT-normalizer-0.1.0"

    def __init__(self, injection_defense: Optional[PromptInjectionDefense] = None):
        self.injection_defense = injection_defense or PromptInjectionDefense()

    def ingest_case(
        self, case: Dict[str, Any]
    ) -> Tuple[
        List[Evidence],
        List[Source],
        List[Entity],
        List[TrackPoint],
        List[Zone],
        Dict[str, List[Dict[str, Any]]],
    ]:
        case_id = str(case.get("case_id", new_id("CASE")))
        authorization = str(case.get("authorization", ""))
        privacy_mode = str(case.get("privacy_mode", "ASSET_LEVEL")).upper()

        sources = [self._parse_source(s) for s in case.get("sources", [])]
        source_map = {s.source_id: s for s in sources}

        entities = [self._parse_entity(e, privacy_mode) for e in case.get("entities", [])]
        entity_map = {e.entity_id: e for e in entities}

        zones = [self._parse_zone(z) for z in case.get("zones", [])]

        tracks: List[TrackPoint] = []
        evidence: List[Evidence] = []

        for track in case.get("tracks", []):
            entity_id = str(track.get("entity_id", ""))
            asset_id = str(track.get("asset_id", entity_map.get(entity_id).asset_id if entity_id in entity_map else ""))
            source_id = str(track.get("source_id", ""))
            precision = enum_from(PrecisionLevel, track.get("precision_level"), PrecisionLevel.UNKNOWN)

            for point in track.get("points", []):
                ev, tp = self._parse_point(
                    point=point,
                    case_id=case_id,
                    authorization=authorization,
                    entity_id=entity_id,
                    asset_id=asset_id,
                    source_id=source_id,
                    source_map=source_map,
                    default_precision=precision,
                )
                evidence.append(ev)
                tracks.append(tp)

        context = {
            "road_network": [dict(x) for x in case.get("road_network", [])],
            "traffic_context": [dict(x) for x in case.get("traffic_context", [])],
            "weather_context": [dict(x) for x in case.get("weather_context", [])],
            "logistics_records": [dict(x) for x in case.get("logistics_records", [])],
            "public_transport_records": [dict(x) for x in case.get("public_transport_records", [])],
            "transport_dependencies": [dict(x) for x in case.get("transport_dependencies", [])],
        }

        return evidence, sources, entities, tracks, zones, context

    def _parse_source(self, s: Dict[str, Any]) -> Source:
        return Source(
            source_id=str(s.get("source_id", new_id("SRC"))),
            provider=str(s.get("provider", "UNKNOWN")),
            upstream_feed=str(s.get("upstream_feed", "UNKNOWN")),
            independence_group=str(s.get("independence_group", s.get("provider", "UNKNOWN"))),
            reliability=str(s.get("reliability", "UNKNOWN")).upper(),
            source_type=str(s.get("source_type", "UNKNOWN")),
            data_freshness=str(s.get("data_freshness", "UNKNOWN")).upper(),
            limitations=[str(x) for x in s.get("limitations", [])],
        )

    def _parse_entity(self, e: Dict[str, Any], privacy_mode: str) -> Entity:
        entity_type = enum_from(EntityType, e.get("entity_type"), EntityType.UNKNOWN)
        privacy = enum_from(PrivacyClassification, e.get("privacy"), PrivacyClassification.PUBLIC)

        if entity_type == EntityType.PERSON:
            privacy = PrivacyClassification.HIGHLY_SENSITIVE
        if privacy_mode == "AGGREGATE":
            privacy = PrivacyClassification.SENSITIVE

        pseudonymized = bool(e.get("pseudonymized", privacy != PrivacyClassification.PUBLIC or privacy_mode == "AGGREGATE"))
        label = str(e.get("display_label", e.get("asset_id", e.get("entity_id", ""))))
        if pseudonymized:
            label = str(e.get("pseudonym", f"PSEUDO_{normalize_text(e.get('entity_id', new_id('ENT')), upper=True)}"))

        return Entity(
            entity_id=str(e.get("entity_id", new_id("ENT"))),
            entity_type=entity_type,
            asset_id=str(e.get("asset_id", "")),
            display_label=label,
            privacy=privacy,
            pseudonymized=pseudonymized,
            source_ids=[str(x) for x in e.get("source_ids", [])],
            limitations=[str(x) for x in e.get("limitations", [])],
        )

    def _parse_zone(self, z: Dict[str, Any]) -> Zone:
        zone_type = enum_from(ZoneType, z.get("zone_type"), ZoneType.UNKNOWN)
        privacy = enum_from(PrivacyClassification, z.get("privacy"), PrivacyClassification.PUBLIC)
        if zone_type in SENSITIVE_ZONE_TYPES:
            privacy = PrivacyClassification.HIGHLY_SENSITIVE

        return Zone(
            zone_id=str(z.get("zone_id", new_id("ZONE"))),
            name=str(z.get("name", "")),
            zone_type=zone_type,
            center_lat=safe_float(z.get("center_lat", z.get("lat"))),
            center_lon=safe_float(z.get("center_lon", z.get("lon"))),
            radius_m=safe_float(z.get("radius_m")),
            privacy=privacy,
            min_count=int(safe_float(z.get("min_count")) or 1),
            limitations=[str(x) for x in z.get("limitations", [])],
        )

    def _parse_point(
        self,
        point: Dict[str, Any],
        case_id: str,
        authorization: str,
        entity_id: str,
        asset_id: str,
        source_id: str,
        source_map: Dict[str, Source],
        default_precision: PrecisionLevel,
    ) -> Tuple[Evidence, TrackPoint]:
        flags: List[str] = []

        timestamp = to_datetime(point.get("timestamp") or point.get("time"))
        if timestamp is None:
            timestamp = utcnow()
            flags.append("MISSING_TIMESTAMP_USING_INGEST_TIME")

        lat = safe_float(point.get("latitude", point.get("lat")))
        lon = safe_float(point.get("longitude", point.get("lon")))
        if lat is None or lon is None:
            flags.append("MISSING_COORDINATE")
        elif not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            flags.append("INVALID_COORDINATE")

        accuracy = safe_float(point.get("accuracy_m", point.get("accuracy_radius_m")))
        if accuracy is None:
            flags.append("ACCURACY_UNKNOWN")
        elif accuracy < 0:
            flags.append("NEGATIVE_ACCURACY")
            accuracy = None

        speed_raw = safe_float(point.get("speed"))
        speed_unit = point.get("speed_unit", point.get("unit"))
        speed_m_s, normalized_speed_unit = to_m_s(speed_raw, speed_unit)
        if speed_raw is not None and speed_m_s is None:
            flags.append("SPEED_UNIT_UNKNOWN")
        if speed_m_s is not None and speed_m_s < 0:
            flags.append("NEGATIVE_SPEED")
            speed_m_s = None

        heading = safe_float(point.get("heading"))
        if heading is not None:
            heading = (heading + 360.0) % 360.0

        event_type = enum_from(MovementEventType, point.get("event_type"), MovementEventType.OBSERVED_AT)
        precision = enum_from(PrecisionLevel, point.get("precision_level"), default_precision)
        source = source_map.get(source_id)

        if source is None:
            flags.append("SOURCE_UNRESOLVED")
        else:
            if source.data_freshness in {"LIVE", "LIVE_AUTHORIZED", "NEAR_REAL_TIME"}:
                flags.append("NEAR_REAL_TIME_OR_LIVE_SOURCE")
            if source.reliability == "LOW":
                flags.append("LOW_RELIABILITY_SOURCE")

        raw_payload = dict(point)
        for key in ("notes", "comment", "metadata", "annotation"):
            if key in raw_payload:
                raw_payload[f"_sanitized_{key}"] = self.injection_defense.sanitize(raw_payload.get(key))

        content_hash = hash_payload(raw_payload)
        ev = Evidence(
            case_id=case_id,
            source_id=source_id,
            source_type=source.source_type if source else "UNKNOWN",
            entity_id=entity_id,
            asset_id=asset_id,
            timestamp=timestamp,
            latitude=lat,
            longitude=lon,
            altitude_m=safe_float(point.get("altitude_m", point.get("altitude"))),
            coordinate_precision=precision.value,
            source_precision=source.source_type if source else "UNKNOWN",
            location_uncertainty_m=accuracy,
            speed_m_s=speed_m_s,
            heading_deg=heading,
            raw_reference=json.dumps(raw_payload, sort_keys=True, default=_json_default)[:1000],
            content_hash=content_hash,
            parser_version=self.PARSER_VERSION,
            normalizer_version=self.NORMALIZER_VERSION,
            authorization_context=authorization,
        )

        tp = TrackPoint(
            point_id=str(point.get("point_id", new_id("PT"))),
            entity_id=entity_id,
            asset_id=asset_id,
            timestamp=timestamp,
            latitude=lat,
            longitude=lon,
            altitude_m=safe_float(point.get("altitude_m", point.get("altitude"))),
            accuracy_radius_m=accuracy,
            speed_m_s=speed_m_s,
            heading_deg=heading,
            event_type=event_type,
            precision_level=precision,
            source_id=source_id,
            evidence_id=ev.evidence_id,
            quality_flags=unique_list(flags),
        )
        return ev, tp


# ======================================================================
# SECTION 6 — MAP MATCHING / TRIP SEGMENTATION / ROUTE RECONSTRUCTION
# ======================================================================

def point_to_segment_distance_m(
    lat: float,
    lon: float,
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
) -> float:
    mid_lat = (lat1 + lat2) / 2.0
    m_per_deg_lat = 111320.0
    m_per_deg_lon = 111320.0 * max(0.01, math.cos(math.radians(mid_lat)))

    px = (lon - lon1) * m_per_deg_lon
    py = (lat - lat1) * m_per_deg_lat
    sx = (lon2 - lon1) * m_per_deg_lon
    sy = (lat2 - lat1) * m_per_deg_lat

    len2 = sx * sx + sy * sy
    if len2 <= 1e-9:
        return math.hypot(px, py)

    t = clamp((px * sx + py * sy) / len2, 0.0, 1.0)
    projx = t * sx
    projy = t * sy
    return math.hypot(px - projx, py - projy)


class MapMatcher:
    def __init__(self, road_network: List[Dict[str, Any]], threshold_m: float = 200.0):
        self.road_network = road_network
        self.threshold_m = threshold_m

    def match_segment(
        self,
        p1: TrackPoint,
        p2: TrackPoint,
    ) -> Optional[Dict[str, Any]]:
        if p1.latitude is None or p1.longitude is None or p2.latitude is None or p2.longitude is None:
            return None

        mid_lat = (p1.latitude + p2.latitude) / 2.0
        mid_lon = (p1.longitude + p2.longitude) / 2.0
        seg_bearing = bearing_deg(p1.latitude, p1.longitude, p2.latitude, p2.longitude)
        acc1 = p1.accuracy_radius_m or 100.0
        acc2 = p2.accuracy_radius_m or 100.0
        threshold = self.threshold_m + max(acc1, acc2)

        best = None
        best_score = math.inf

        for road in self.road_network:
            r_lat1 = safe_float(road.get("start_lat", road.get("lat1")))
            r_lon1 = safe_float(road.get("start_lon", road.get("lon1")))
            r_lat2 = safe_float(road.get("end_lat", road.get("lat2")))
            r_lon2 = safe_float(road.get("end_lon", road.get("lon2")))

            if None in (r_lat1, r_lon1, r_lat2, r_lon2):
                continue

            dist = point_to_segment_distance_m(mid_lat, mid_lon, r_lat1, r_lon1, r_lat2, r_lon2)
            road_bearing = bearing_deg(r_lat1, r_lon1, r_lat2, r_lon2)
            diff = angle_diff_deg(seg_bearing, road_bearing) or 180.0

            if dist <= threshold and diff <= 60.0:
                score = dist + diff
                if score < best_score:
                    best_score = score
                    best = road

        return best


def route_signature(trip: Trip) -> Tuple[Any, ...]:
    roads = [seg.matched_road_id for seg in trip.route_segments if seg.matched_road_id]
    if roads:
        return tuple(roads)

    cells = []
    for p in trip.points:
        if p.latitude is not None and p.longitude is not None:
            cells.append((round(p.latitude, 3), round(p.longitude, 3)))
    return tuple(cells)


class TripSegmenter:
    def __init__(
        self,
        max_time_gap_s: float = 1800.0,
        min_stop_duration_s: float = 180.0,
        stop_radius_m: float = 150.0,
        max_stop_duration_s: float = 14400.0,
    ):
        self.max_time_gap_s = max_time_gap_s
        self.min_stop_duration_s = min_stop_duration_s
        self.stop_radius_m = stop_radius_m
        self.max_stop_duration_s = max_stop_duration_s

    def analyze(
        self,
        points: List[TrackPoint],
        entities: List[Entity],
        road_network: List[Dict[str, Any]],
        case: Dict[str, Any],
    ) -> Tuple[List[Trip], List[Stop]]:
        by_entity: Dict[str, List[TrackPoint]] = defaultdict(list)
        for p in points:
            if p.latitude is not None and p.longitude is not None:
                by_entity[p.entity_id].append(p)

        entity_map = {e.entity_id: e for e in entities}
        matcher = MapMatcher(
            road_network=road_network,
            threshold_m=float(case.get("map_match_threshold_m", 200.0)),
        )

        trips: List[Trip] = []
        all_stops: List[Stop] = []

        for entity_id, pts in by_entity.items():
            pts = sorted(pts, key=lambda x: x.timestamp)
            entity = entity_map.get(entity_id)
            chunks = self._split_chunks(pts)

            for chunk in chunks:
                if not chunk:
                    continue

                stops = self._detect_stops(chunk, entity_id)
                all_stops.extend(stops)

                segments = self._build_route_segments(chunk, matcher)
                distance = sum(s.distance_m or 0.0 for s in segments)
                duration = (chunk[-1].timestamp - chunk[0].timestamp).total_seconds() if len(chunk) > 1 else 0.0
                avg_speed = distance / duration if duration > 0 else None
                max_speed = max(
                    [p.speed_m_s for p in chunk if p.speed_m_s is not None]
                    + [s.average_speed_m_s for s in segments if s.average_speed_m_s is not None]
                    + [0.0]
                )

                mode = self._classify_mode(
                    avg_speed=avg_speed,
                    entity=entity,
                    stops=stops,
                )

                sig = tuple(seg.matched_road_id for seg in segments if seg.matched_road_id)
                if not sig:
                    sig = tuple((round(p.latitude, 3), round(p.longitude, 3)) for p in chunk if p.latitude is not None and p.longitude is not None)

                confidence = Confidence.LOW
                if len(chunk) >= 5 and duration > 0:
                    confidence = Confidence.MEDIUM
                if len(chunk) >= 10 and all(p.accuracy_radius_m is not None and p.accuracy_radius_m <= 50 for p in chunk):
                    confidence = Confidence.HIGH

                limitations = [
                    "Trip is segmented from observed points; unobserved segments remain inferred.",
                    "Map-matched route is analytical inference, not direct observation.",
                    "Stop/dwell does not establish activity, meeting, residence, workplace, or intent.",
                ]
                if entity and entity.privacy == PrivacyClassification.HIGHLY_SENSITIVE:
                    limitations.append("Highly sensitive entity: exact coordinates must be suppressed/coarsened in downstream use.")

                trip = Trip(
                    entity_id=entity_id,
                    asset_id=chunk[0].asset_id,
                    start_time=chunk[0].timestamp,
                    end_time=chunk[-1].timestamp,
                    points=chunk,
                    stops=stops,
                    route_segments=segments,
                    route_signature=sig,
                    distance_m=distance if distance > 0 else None,
                    duration_s=duration if duration > 0 else None,
                    average_speed_m_s=avg_speed,
                    max_speed_m_s=max_speed if max_speed > 0 else None,
                    movement_mode=mode,
                    origin_state="OBSERVED_ORIGIN",
                    destination_state="OBSERVED_DESTINATION",
                    segmentation_confidence=confidence,
                    source_ids=sorted({p.source_id for p in chunk if p.source_id}),
                    evidence_ids=[p.evidence_id for p in chunk],
                    limitations=limitations,
                )
                trips.append(trip)

        return trips, all_stops

    def _split_chunks(self, pts: List[TrackPoint]) -> List[List[TrackPoint]]:
        chunks: List[List[TrackPoint]] = []
        cur: List[TrackPoint] = []
        prev: Optional[TrackPoint] = None

        for p in pts:
            if prev is not None:
                dt = (p.timestamp - prev.timestamp).total_seconds()
                if dt > self.max_time_gap_s:
                    if cur:
                        chunks.append(cur)
                    cur = []
            cur.append(p)
            prev = p

        if cur:
            chunks.append(cur)
        return chunks

    def _detect_stops(self, pts: List[TrackPoint], entity_id: str) -> List[Stop]:
        stops: List[Stop] = []
        n = len(pts)
        i = 0

        while i < n:
            j = i + 1
            while j <= n:
                cand = pts[i:j]
                if not cand:
                    break
                duration = (cand[-1].timestamp - cand[0].timestamp).total_seconds()
                if duration > self.max_stop_duration_s:
                    break

                center_lat = mean([p.latitude for p in cand])
                center_lon = mean([p.longitude for p in cand])
                if center_lat is None or center_lon is None:
                    break

                max_dist = 0.0
                for p in cand:
                    acc = p.accuracy_radius_m or 100.0
                    d = haversine_m(center_lat, center_lon, p.latitude, p.longitude)
                    if d is None:
                        max_dist = math.inf
                        break
                    max_dist = max(max_dist, d + 0.5 * acc)

                if max_dist <= self.stop_radius_m:
                    j += 1
                else:
                    break

            stop_pts = pts[i:max(i + 1, j - 1)]
            if len(stop_pts) >= 2:
                duration = (stop_pts[-1].timestamp - stop_pts[0].timestamp).total_seconds()
                if duration >= self.min_stop_duration_s:
                    center_lat = mean([p.latitude for p in stop_pts])
                    center_lon = mean([p.longitude for p in stop_pts])
                    radius = self.stop_radius_m
                    stop_type = StopType.DWELL_STOP if duration >= 600 else StopType.TRANSIENT_STOP
                    confidence = Confidence.MEDIUM if len(stop_pts) >= 3 else Confidence.LOW

                    stops.append(
                        Stop(
                            entity_id=entity_id,
                            asset_id=stop_pts[0].asset_id,
                            start_time=stop_pts[0].timestamp,
                            end_time=stop_pts[-1].timestamp,
                            center_lat=center_lat,
                            center_lon=center_lon,
                            radius_m=radius,
                            duration_s=duration,
                            stop_type=stop_type,
                            confidence=confidence,
                            point_ids=[p.point_id for p in stop_pts],
                            notes=[
                                "Stop/dwell is a spatial-temporal observation.",
                                "It does not establish meeting, delivery, residence, workplace, activity, or intent.",
                            ],
                        )
                    )
                    i = j - 1 if j > i + 1 else i + 1
                    continue

            i += 1

        return stops

    def _build_route_segments(
        self,
        pts: List[TrackPoint],
        matcher: MapMatcher,
    ) -> List[RouteSegment]:
        segments: List[RouteSegment] = []
        for p1, p2 in zip(pts, pts[1:]):
            dist = haversine_m(p1.latitude, p1.longitude, p2.latitude, p2.longitude)
            dt = (p2.timestamp - p1.timestamp).total_seconds()
            avg = dist / dt if dist is not None and dt > 0 else None

            road = matcher.match_segment(p1, p2)
            matched_id = str(road.get("road_id", road.get("id", ""))) if road else None
            matched_name = str(road.get("name", "")) if road else None

            confidence = Confidence.LOW
            notes = ["Route segment is reconstructed between observed points; not continuously observed."]
            if matched_id:
                confidence = Confidence.MEDIUM
                notes.append("Map-matched to road network; matched route is inference, not direct observation.")
            if dt > 1800:
                notes.append("Long temporal gap; unobserved segment possible.")
                confidence = Confidence.LOW

            segments.append(
                RouteSegment(
                    from_point_id=p1.point_id,
                    to_point_id=p2.point_id,
                    method="MAP_MATCHED" if matched_id else "RAW_GEODESIC",
                    distance_m=dist,
                    duration_s=dt if dt > 0 else None,
                    average_speed_m_s=avg,
                    matched_road_id=matched_id,
                    matched_road_name=matched_name,
                    confidence=confidence,
                    inferred=True,
                    notes=notes,
                )
            )
        return segments

    @staticmethod
    def _classify_mode(
        avg_speed: Optional[float],
        entity: Optional[Entity],
        stops: List[Stop],
    ) -> MovementMode:
        if avg_speed is None:
            if stops:
                return MovementMode.STATIONARY
            return MovementMode.UNKNOWN

        if avg_speed <= 0.2:
            return MovementMode.STATIONARY

        etype = entity.entity_type if entity else EntityType.UNKNOWN

        if etype == EntityType.AIRCRAFT and avg_speed > 50:
            return MovementMode.AIR_CANDIDATE
        if etype == EntityType.VESSEL and avg_speed <= 15:
            return MovementMode.MARITIME_CANDIDATE
        if etype in (EntityType.VEHICLE, EntityType.FLEET, EntityType.PUBLIC_TRANSPORT):
            if avg_speed <= 40:
                return MovementMode.ROAD_VEHICLE_CANDIDATE
            if avg_speed <= 90:
                return MovementMode.RAIL_CANDIDATE

        if avg_speed <= 1.5:
            return MovementMode.WALKING_CANDIDATE
        if avg_speed <= 6:
            return MovementMode.CYCLING_CANDIDATE
        if avg_speed <= 40:
            return MovementMode.ROAD_VEHICLE_CANDIDATE
        if avg_speed <= 90:
            return MovementMode.RAIL_CANDIDATE
        if avg_speed <= 15:
            return MovementMode.MARITIME_CANDIDATE
        return MovementMode.UNKNOWN


# ======================================================================
# SECTION 7 — GEOFENCE / PATTERNS / CO-LOCATION / CONTRADICTIONS
# ======================================================================

class GeofenceAnalyzer:
    def analyze(self, trips: List[Trip], zones: List[Zone]) -> List[GeofenceEvent]:
        events: List[GeofenceEvent] = []
        points_by_entity: Dict[str, List[TrackPoint]] = defaultdict(list)
        for trip in trips:
            points_by_entity[trip.entity_id].extend(trip.points)

        for entity_id, pts in points_by_entity.items():
            pts = sorted(pts, key=lambda x: x.timestamp)
            for zone in zones:
                if zone.center_lat is None or zone.center_lon is None or zone.radius_m is None:
                    continue
                inside = False
                for p in pts:
                    dist = haversine_m(zone.center_lat, zone.center_lon, p.latitude, p.longitude)
                    acc = p.accuracy_radius_m or 100.0
                    if dist is None:
                        continue
                    currently_inside = dist <= zone.radius_m + 0.5 * acc
                    ambiguous = acc > zone.radius_m * 0.5

                    if not inside and currently_inside:
                        events.append(
                            GeofenceEvent(
                                entity_id=entity_id,
                                asset_id=p.asset_id,
                                zone_id=zone.zone_id,
                                zone_name=zone.name,
                                event_type=MovementEventType.ZONE_ENTERED,
                                timestamp=p.timestamp,
                                confidence=Confidence.LOW if ambiguous else Confidence.MEDIUM,
                                notes=[
                                    "Zone entry is spatial observation, not activity or purpose.",
                                    "Sensitive-zone visits must not be used to infer religion, politics, health, or private status.",
                                ]
                                if zone.zone_type in SENSITIVE_ZONE_TYPES
                                else ["Zone entry is spatial observation, not activity or purpose."],
                            )
                        )
                    elif inside and not currently_inside:
                        events.append(
                            GeofenceEvent(
                                entity_id=entity_id,
                                asset_id=p.asset_id,
                                zone_id=zone.zone_id,
                                zone_name=zone.name,
                                event_type=MovementEventType.ZONE_EXITED,
                                timestamp=p.timestamp,
                                confidence=Confidence.LOW if ambiguous else Confidence.MEDIUM,
                                notes=["Zone exit is spatial observation, not activity or purpose."],
                            )
                        )
                    inside = currently_inside

        return events


class PatternAnalyzer:
    def analyze(
        self,
        trips: List[Trip],
        traffic_context: List[Dict[str, Any]],
        case: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], List[RouteDeviation], List[MovementAnomaly], List[Dict[str, Any]]]:
        recurring: List[Dict[str, Any]] = []
        deviations: List[RouteDeviation] = []
        anomalies: List[MovementAnomaly] = []
        corridors: List[Dict[str, Any]] = []

        by_entity: Dict[str, List[Trip]] = defaultdict(list)
        for t in trips:
            by_entity[t.entity_id].append(t)

        # Corridor frequency from matched roads.
        road_counts: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "entities": set(), "name": ""})
        for t in trips:
            for seg in t.route_segments:
                if seg.matched_road_id:
                    item = road_counts[seg.matched_road_id]
                    item["count"] += 1
                    item["entities"].add(t.entity_id)
                    item["name"] = seg.matched_road_name or item["name"]

        for road_id, info in road_counts.items():
            corridors.append(
                {
                    "road_id": road_id,
                    "road_name": info["name"],
                    "segment_occurrences": info["count"],
                    "distinct_entities": len(info["entities"]),
                    "notes": [
                        "Corridor frequency is movement-context analysis, not attack planning.",
                        "Chokepoint language is restricted to resilience/capacity risk only.",
                    ],
                }
            )
        corridors.sort(key=lambda x: x["segment_occurrences"], reverse=True)

        # Recurring routes and baselines.
        baseline_durations: Dict[Tuple[Any, ...], List[float]] = defaultdict(list)
        common_signature_by_entity: Dict[str, Tuple[Any, ...]] = {}

        for entity_id, ts in by_entity.items():
            sig_counts: Dict[Tuple[Any, ...], Dict[str, Any]] = defaultdict(lambda: {"count": 0, "days": set(), "trip_ids": []})
            for t in ts:
                sig = t.route_signature
                if not sig:
                    continue
                item = sig_counts[sig]
                item["count"] += 1
                item["days"].add(t.start_time.date().isoformat())
                item["trip_ids"].append(t.trip_id)
                if t.duration_s is not None:
                    baseline_durations[sig].append(t.duration_s)

            best_sig = None
            best_count = 0
            for sig, info in sig_counts.items():
                state = "INSUFFICIENT_HISTORY"
                if info["count"] >= 3 and len(info["days"]) >= 2:
                    state = "RECURRING_SUPPORTED"
                elif info["count"] >= 2:
                    state = "RECURRING_CANDIDATE"

                recurring.append(
                    {
                        "entity_id": entity_id,
                        "route_signature": list(sig),
                        "count": info["count"],
                        "distinct_days": len(info["days"]),
                        "state": state,
                        "trip_ids": info["trip_ids"],
                        "notes": [
                            "Recurring route does not prove routine, intent, home, workplace, or predict future movement.",
                        ],
                    }
                )

                if info["count"] > best_count:
                    best_count = info["count"]
                    best_sig = sig

            if best_sig is not None and best_count >= 2:
                common_signature_by_entity[entity_id] = best_sig

        # Route deviations.
        for entity_id, ts in by_entity.items():
            common = common_signature_by_entity.get(entity_id)
            if common is None:
                continue
            common_set = set(common)

            for t in ts:
                if not t.route_signature or t.route_signature == common:
                    continue
                obs_set = set(t.route_signature)
                diff_count = len(obs_set.symmetric_difference(common_set))

                explanation = []
                state = DeviationState.MINOR_DEVIATION if diff_count <= 2 else DeviationState.MATERIAL_DEVIATION

                for ctx in traffic_context:
                    road_id = str(ctx.get("road_id", ""))
                    ctype = str(ctx.get("type", "")).upper()
                    start = to_datetime(ctx.get("start_time"))
                    end = to_datetime(ctx.get("end_time"))
                    if road_id in common_set and ctype in {"CLOSURE", "CONGESTION", "INCIDENT", "DETOUR"}:
                        if start and end and t.start_time <= end and t.end_time >= start:
                            explanation.append(f"Traffic context indicates {ctype} on {road_id} during trip window.")
                            state = DeviationState.NORMAL_VARIATION

                if not explanation and diff_count > 4:
                    state = DeviationState.UNEXPLAINED_DEVIATION

                deviations.append(
                    RouteDeviation(
                        entity_id=entity_id,
                        asset_id=t.asset_id,
                        trip_id=t.trip_id,
                        baseline_route_signature=common,
                        observed_route_signature=t.route_signature,
                        state=state,
                        segment_difference_count=diff_count,
                        explanation_context=explanation,
                        confidence=Confidence.MEDIUM if explanation else Confidence.LOW,
                        notes=[
                            "Route deviation is not suspicious without independent case evidence.",
                            "Possible benign causes include traffic, closure, weather, delivery, detour, optimization, or emergency.",
                        ],
                    )
                )

        # Travel-time anomalies.
        for t in trips:
            sig = t.route_signature
            if not sig or t.duration_s is None:
                continue
            vals = baseline_durations.get(sig, [])
            if len(vals) < 3:
                continue
            med = median(vals)
            sd = std(vals)
            if med is None or sd is None or sd <= 0:
                continue
            z = (t.duration_s - med) / sd
            if z >= 3:
                state = AnomalyState.MATERIALLY_UNUSUAL
            elif z >= 2:
                state = AnomalyState.UNUSUAL
            elif z >= 1:
                state = AnomalyState.MINOR_VARIATION
            else:
                state = AnomalyState.EXPECTED

            if state in (AnomalyState.UNUSUAL, AnomalyState.MATERIALLY_UNUSUAL):
                anomalies.append(
                    MovementAnomaly(
                        entity_id=t.entity_id,
                        asset_id=t.asset_id,
                        trip_id=t.trip_id,
                        anomaly_type="TRAVEL_TIME",
                        state=state,
                        description=f"Travel time z-score {z:.2f} relative to same-route baseline.",
                        baseline_id="ROUTE_DURATION_BASELINE",
                        z_score=z,
                        confidence=Confidence.MEDIUM if len(vals) >= 5 else Confidence.LOW,
                        notes=[
                            "Anomaly is statistical departure, not intent.",
                            "Congestion, stops, sensor gaps, rerouting, weather, or operational reasons may explain it.",
                        ],
                    )
                )

        return recurring, deviations, anomalies, corridors


class CoLocationAnalyzer:
    def __init__(self, distance_gate_m: float = 200.0, time_gate_s: float = 300.0):
        self.distance_gate_m = distance_gate_m
        self.time_gate_s = time_gate_s

    def analyze(
        self,
        points: List[TrackPoint],
        entities: List[Entity],
        zones: List[Zone],
    ) -> Tuple[List[Colocation], List[Comovement]]:
        by_entity: Dict[str, List[TrackPoint]] = defaultdict(list)
        for p in points:
            if p.latitude is not None and p.longitude is not None:
                by_entity[p.entity_id].append(p)

        entity_map = {e.entity_id: e for e in entities}
        colocations: List[Colocation] = []
        comovements: List[Comovement] = []

        for a, b in itertools.combinations(sorted(by_entity.keys()), 2):
            matched = []
            distances = []
            times = []

            for pa in by_entity[a]:
                for pb in by_entity[b]:
                    dt = abs((pa.timestamp - pb.timestamp).total_seconds())
                    if dt > self.time_gate_s:
                        continue
                    dist = haversine_m(pa.latitude, pa.longitude, pb.latitude, pb.longitude)
                    if dist is None or dist > self.distance_gate_m:
                        continue
                    matched.append((pa, pb))
                    distances.append(dist)
                    times.extend([pa.timestamp, pb.timestamp])

            if not matched:
                colocations.append(
                    Colocation(
                        entity_a=a,
                        entity_b=b,
                        state=ColocationState.COLOCATION_NOT_SUPPORTED,
                        confidence=Confidence.LOW,
                        notes=["No spatial-temporal overlap beyond thresholds."],
                    )
                )
                continue

            center_lat = mean([p.latitude for pair in matched for p in pair])
            center_lon = mean([p.longitude for pair in matched for p in pair])
            avg_dist = mean(distances)
            start = min(times)
            end = max(times)

            sensitive = False
            for z in zones:
                if z.zone_type in SENSITIVE_ZONE_TYPES and z.center_lat is not None and z.center_lon is not None and z.radius_m is not None:
                    d = haversine_m(z.center_lat, z.center_lon, center_lat, center_lon)
                    if d is not None and d <= z.radius_m + 500:
                        sensitive = True

            if len(matched) >= 2 and avg_dist is not None and avg_dist <= self.distance_gate_m * 0.5:
                state = ColocationState.SUPPORTED_COLOCATION
                confidence = Confidence.MEDIUM
            else:
                state = ColocationState.POSSIBLE_COLOCATION
                confidence = Confidence.LOW

            notes = [
                "Co-location is spatial-temporal observation only.",
                "It does not establish meeting, interaction, relationship, coordination, family, romance, collusion, or intent.",
                "Shared roads, stations, events, traffic, fleets, or public transport can create coincidental co-location.",
            ]
            if sensitive:
                notes.append("Sensitive-zone proximity detected; do not infer health, religion, political belief, shelter status, or private residence.")
            if entity_map.get(a) and entity_map[a].privacy == PrivacyClassification.HIGHLY_SENSITIVE:
                notes.append("Highly sensitive entity involved; exact coordinates must be suppressed/coarsened.")
            if entity_map.get(b) and entity_map[b].privacy == PrivacyClassification.HIGHLY_SENSITIVE:
                notes.append("Highly sensitive entity involved; exact coordinates must be suppressed/coarsened.")

            coloc = Colocation(
                entity_a=a,
                entity_b=b,
                start_time=start,
                end_time=end,
                center_lat=center_lat,
                center_lon=center_lon,
                radius_m=self.distance_gate_m,
                matched_points=len(matched),
                average_distance_m=avg_dist,
                state=state,
                confidence=confidence,
                notes=notes,
            )
            colocations.append(coloc)

            duration = (end - start).total_seconds() if start and end else None
            if state == ColocationState.SUPPORTED_COLOCATION and len(matched) >= 3 and duration is not None and duration >= 300:
                comovements.append(
                    Comovement(
                        entity_a=a,
                        entity_b=b,
                        duration_s=duration,
                        average_distance_m=avg_dist,
                        state=ComovementState.COMOVED_CANDIDATE,
                        confidence=Confidence.LOW,
                        notes=[
                            "Co-movement candidate only.",
                            "It does not establish relationship, coordination, convoy, or intent.",
                            "Public corridors, scheduled fleets, and event traffic can produce co-movement.",
                        ],
                    )
                )
            else:
                comovements.append(
                    Comovement(
                        entity_a=a,
                        entity_b=b,
                        duration_s=duration,
                        average_distance_m=avg_dist,
                        state=ComovementState.POSSIBLE_COMOVEMENT if state != ColocationState.COLOCATION_NOT_SUPPORTED else ComovementState.COMOVEMENT_NOT_SUPPORTED,
                        confidence=Confidence.LOW,
                        notes=["Co-movement not sufficiently supported."],
                    )
                )

        return colocations, comovements


class ContradictionDetector:
    def __init__(self, max_plausible_speed_m_s: float = 250.0):
        self.max_plausible_speed_m_s = max_plausible_speed_m_s

    def detect(self, points: List[TrackPoint]) -> List[Contradiction]:
        contradictions: List[Contradiction] = []
        by_entity: Dict[str, List[TrackPoint]] = defaultdict(list)
        for p in points:
            if p.latitude is not None and p.longitude is not None:
                by_entity[p.entity_id].append(p)

        for entity_id, pts in by_entity.items():
            pts = sorted(pts, key=lambda x: x.timestamp)

            for p1, p2 in zip(pts, pts[1:]):
                dt = (p2.timestamp - p1.timestamp).total_seconds()
                dist = haversine_m(p1.latitude, p1.longitude, p2.latitude, p2.longitude)
                if dt > 0 and dist is not None:
                    speed = dist / dt
                    if speed > self.max_plausible_speed_m_s:
                        contradictions.append(
                            Contradiction(
                                contradiction_type="IMPOSSIBLE_TRAVEL_CANDIDATE",
                                description=(
                                    f"Entity {entity_id} implied speed {speed:.1f} m/s between "
                                    f"{p1.timestamp.isoformat()} and {p2.timestamp.isoformat()}."
                                ),
                                evidence_ids=[p1.evidence_id, p2.evidence_id],
                                candidate_resolutions=[
                                    "clock error",
                                    "timezone error",
                                    "device/asset identity mismatch",
                                    "GPS multipath/spurious point",
                                    "duplicate identity",
                                    "data corruption",
                                    "air travel if mode supports it",
                                ],
                            )
                        )

            # Sensor disagreement for close-time different-source points.
            for p1, p2 in itertools.combinations(pts, 2):
                if p1.source_id == p2.source_id:
                    continue
                dt = abs((p1.timestamp - p2.timestamp).total_seconds())
                if dt > 120:
                    continue
                dist = haversine_m(p1.latitude, p1.longitude, p2.latitude, p2.longitude)
                acc1 = p1.accuracy_radius_m or 100.0
                acc2 = p2.accuracy_radius_m or 100.0
                tol = max(3.0 * acc1, 3.0 * acc2, 1000.0)
                if dist is not None and dist > tol:
                    contradictions.append(
                        Contradiction(
                            contradiction_type="SENSOR_DISAGREEMENT",
                            description=(
                                f"Entity {entity_id} sources {p1.source_id} and {p2.source_id} differ by "
                                f"{dist/1000:.2f} km within {dt:.0f}s."
                            ),
                            evidence_ids=[p1.evidence_id, p2.evidence_id],
                            candidate_resolutions=[
                                "different sensor precision/calibration",
                                "multipath/urban canyon error",
                                "clock offset",
                                "map/provider interpolation",
                                "asset identity mismatch",
                            ],
                        )
                    )

        return contradictions


# ======================================================================
# SECTION 8 — HYPOTHESES / FACT GATE / DUAL-AI REVIEW
# ======================================================================

class HypothesisEngine:
    def generate(
        self,
        trips: List[Trip],
        deviations: List[RouteDeviation],
        anomalies: List[MovementAnomaly],
        colocations: List[Colocation],
        contradictions: List[Contradiction],
    ) -> List[Hypothesis]:
        hypotheses: List[Hypothesis] = []

        for dev in deviations[:50]:
            hypotheses.extend(
                [
                    Hypothesis(
                        statement=f"Trip {dev.trip_id} deviation reflects normal operational detour or route optimization.",
                        supports=dev.explanation_context,
                        oppositions=["No independent dispatch/traffic evidence" if not dev.explanation_context else ""],
                        unknowns=["dispatch instruction", "driver/vehicle assignment", "purpose"],
                        falsification_tests=["dispatch record shows no detour authorization", "traffic/closure data contradicts route change"],
                    ),
                    Hypothesis(
                        statement=f"Trip {dev.trip_id} deviation is caused by traffic/closure/weather context.",
                        supports=dev.explanation_context,
                        oppositions=[],
                        unknowns=["real-time traffic source completeness"],
                        falsification_tests=["closure period does not overlap trip", "alternate route remained available"],
                    ),
                    Hypothesis(
                        statement=f"Trip {dev.trip_id} deviation is sensor/map-matching artifact.",
                        supports=["Map-matched route is inference" if dev.observed_route_signature else ""],
                        oppositions=["Multiple consistent points weaken artifact hypothesis"],
                        unknowns=["raw GPS quality", "road network version"],
                        falsification_tests=["raw track inspection shows actual road alignment", "independent telemetry confirms route"],
                    ),
                ]
            )

        for anom in anomalies[:50]:
            hypotheses.extend(
                [
                    Hypothesis(
                        statement=f"Anomaly {anom.anomaly_id} reflects congestion, stop, weather, or operational delay.",
                        supports=["Travel-time baseline departure"],
                        oppositions=["No traffic/weather context supplied"],
                        unknowns=["stop purpose", "road conditions"],
                        falsification_tests=["traffic/weather records show normal conditions", "stop detection explains duration"],
                    ),
                    Hypothesis(
                        statement=f"Anomaly {anom.anomaly_id} reflects sensor gap or clock error.",
                        supports=[],
                        oppositions=["Continuous high-quality points weaken gap hypothesis"],
                        unknowns=["device health", "timestamp sync"],
                        falsification_tests=["device logs show continuous valid fixes", "clock sync verified"],
                    ),
                ]
            )

        for coloc in colocations[:50]:
            if coloc.state in (ColocationState.SUPPORTED_COLOCATION, ColocationState.POSSIBLE_COLOCATION):
                hypotheses.extend(
                    [
                        Hypothesis(
                            statement=f"Co-location {coloc.colocation_id} is coincidental shared corridor/event/fleet infrastructure.",
                            supports=["Spatial-temporal overlap only"],
                            oppositions=["No interaction evidence"],
                            unknowns=["entities involved", "activity", "relationship"],
                            falsification_tests=["independent records show no interaction", "overlap explained by scheduled public route"],
                        ),
                        Hypothesis(
                            statement=f"Co-location {coloc.colocation_id} may reflect authorized fleet convoy or coordinated operation.",
                            supports=["Sustained proximity candidate" if coloc.matched_points >= 3 else "Single overlap"],
                            oppositions=["Co-location alone does not prove coordination"],
                            unknowns=["dispatch orders", "operator", "purpose"],
                            falsification_tests=["dispatch records show independent tasks", "routes diverge outside shared corridor"],
                        ),
                    ]
                )

        for con in contradictions[:50]:
            hypotheses.append(
                Hypothesis(
                    statement=f"Contradiction {con.contradiction_type} may reflect data quality/identity issue rather than real movement.",
                    supports=con.candidate_resolutions,
                    oppositions=[],
                    unknowns=["true asset identity", "sensor health", "clock sync"],
                    falsification_tests=["independent authorized telemetry resolves conflict", "device audit confirms identity"],
                )
            )

        for h in hypotheses:
            h.supports = [s for s in h.supports if s]
            h.oppositions = [o for o in h.oppositions if o]

        return hypotheses


class FactGate:
    def generate(
        self,
        *,
        case: Dict[str, Any],
        sources: List[Source],
        entities: List[Entity],
        trips: List[Trip],
        stops: List[Stop],
        geofence_events: List[GeofenceEvent],
        colocations: List[Colocation],
        comovements: List[Comovement],
        deviations: List[RouteDeviation],
        anomalies: List[MovementAnomaly],
        recurring: List[Dict[str, Any]],
        contradictions: List[Contradiction],
        source_independence: Dict[str, Any],
    ) -> Dict[str, Any]:
        facts: List[Fact] = []
        unknowns: List[str] = []
        limitations: List[str] = []
        gaps: List[KnowledgeGap] = []
        actions: List[NextAction] = []
        handoffs: List[SpecialistHandoff] = []
        sensitive_flags: List[str] = []

        entity_map = {e.entity_id: e for e in entities}
        source_map = {s.source_id: s for s in sources}

        for trip in trips[:100]:
            entity = entity_map.get(trip.entity_id)
            label = entity.display_label if entity else trip.entity_id
            facts.append(
                Fact(
                    statement=(
                        f"Authorized movement sources observed {label} between "
                        f"{trip.start_time.isoformat()} and {trip.end_time.isoformat()} "
                        f"with {len(trip.points)} track points."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=trip.evidence_ids[:50],
                    limitations=[
                        "This is telemetry observation, not proof of driver, passenger, person presence, activity, or intent.",
                        "Location precision and source independence limit interpretation.",
                    ],
                )
            )

            if trip.distance_m is not None and trip.duration_s:
                facts.append(
                    Fact(
                        statement=(
                            f"Trip {trip.trip_id} has reconstructed straight-line/map-matched distance "
                            f"{trip.distance_m/1000:.2f} km over {trip.duration_s/60:.1f} minutes."
                        ),
                        status=FactStatus.CANDIDATE,
                        evidence_ids=trip.evidence_ids[:50],
                        limitations=[
                            "Distance is reconstructed from observed points; unobserved segments may exist.",
                            "Straight-line/geodesic distance is not necessarily travel distance.",
                        ],
                    )
                )

        for stop in stops[:100]:
            entity = entity_map.get(stop.entity_id)
            label = entity.display_label if entity else stop.entity_id
            facts.append(
                Fact(
                    statement=(
                        f"A {stop.stop_type.value} of {int((stop.duration_s or 0)/60)} minutes was detected "
                        f"for {label} near ({round_coord(stop.center_lat, 4)}, {round_coord(stop.center_lon, 4)})."
                    ),
                    status=FactStatus.SUPPORTED if stop.confidence != Confidence.LOW else FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=[
                        "Stop/dwell does not establish meeting, delivery, residence, workplace, activity, or intent.",
                        "Traffic lights, congestion, loading, waiting, breaks, maintenance, or sensor gaps can produce stops.",
                    ],
                )
            )

        for ev in geofence_events[:100]:
            zone = next((z for z in case.get("zones", []) if z.get("zone_id") == ev.zone_id), {})
            facts.append(
                Fact(
                    statement=f"Geofence event {ev.event_type.value} for entity {ev.entity_id} in zone {ev.zone_name or ev.zone_id}.",
                    status=FactStatus.SUPPORTED if ev.confidence != Confidence.LOW else FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=[
                        "Zone entry/exit is spatial observation, not activity or purpose.",
                        "Do not infer private residence, workplace, health, religion, politics, or shelter status.",
                    ],
                )
            )
            if enum_from(ZoneType, zone.get("zone_type"), ZoneType.UNKNOWN) in SENSITIVE_ZONE_TYPES:
                sensitive_flags.append(f"Sensitive zone {ev.zone_name or ev.zone_id} involved; trait inference prohibited.")

        for coloc in colocations[:100]:
            facts.append(
                Fact(
                    statement=(
                        f"Co-location state {coloc.state.value} between {coloc.entity_a} and {coloc.entity_b} "
                        f"with {coloc.matched_points} matched point pairs."
                    ),
                    status=FactStatus.SUPPORTED if coloc.state == ColocationState.SUPPORTED_COLOCATION else FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=coloc.notes,
                )
            )

        for com in comovements[:100]:
            facts.append(
                Fact(
                    statement=f"Co-movement state {com.state.value} between {com.entity_a} and {com.entity_b}.",
                    status=FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=com.notes,
                )
            )

        for dev in deviations[:100]:
            facts.append(
                Fact(
                    statement=f"Route deviation state {dev.state.value} for trip {dev.trip_id}.",
                    status=FactStatus.SUPPORTED if dev.state != DeviationState.UNKNOWN else FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=dev.notes + dev.explanation_context,
                )
            )

        for anom in anomalies[:100]:
            facts.append(
                Fact(
                    statement=f"Movement anomaly state {anom.state.value}: {anom.description}",
                    status=FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=anom.notes,
                )
            )

        for rec in recurring[:100]:
            facts.append(
                Fact(
                    statement=f"Recurring route state {rec['state']} for entity {rec['entity_id']} count {rec['count']}.",
                    status=FactStatus.SUPPORTED if rec["state"] == "RECURRING_SUPPORTED" else FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=[
                        "Recurring route does not prove routine, intent, home, workplace, or predictable future movement.",
                    ],
                )
            )

        for con in contradictions[:100]:
            facts.append(
                Fact(
                    statement=f"Open contradiction: {con.contradiction_type} — {con.description}",
                    status=FactStatus.DISPUTED,
                    evidence_ids=con.evidence_ids,
                    limitations=con.candidate_resolutions,
                )
            )
            unknowns.append(f"Unresolved contradiction: {con.contradiction_type}")

        if source_independence.get("overall_status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            limitations.append("Source independence is dependent or unknown; multiple points/providers may share one upstream feed.")
            gaps.append(
                KnowledgeGap(
                    description="Independent movement source pedigree not established.",
                    importance="HIGH",
                    recommended_source="independent telematics/dispatch/transport operator record",
                    specialist="MOBINT source evaluation",
                    expected_information_value="Prevents false corroboration from one device/provider family.",
                )
            )

        for e in entities:
            if e.privacy == PrivacyClassification.HIGHLY_SENSITIVE:
                sensitive_flags.append(f"Entity {e.display_label} is highly sensitive; exact coordinates suppressed/coarsened.")
            if e.entity_type == EntityType.PERSON:
                sensitive_flags.append("Person-level movement detected; no real-time private tracking, no home/work inference, human review required.")

        limitations.extend(
            [
                "Track point is not movement; movement requires temporally ordered observations or supporting transport evidence.",
                "Device is not person.",
                "Vehicle is not driver.",
                "Account is not traveler.",
                "Location is not activity.",
                "Co-location is not meeting.",
                "Co-movement is not relationship.",
                "Common route is not association.",
                "Route deviation is not suspicious activity.",
                "Stop is not meeting.",
                "Dwell is not purpose.",
                "Frequent origin is not home.",
                "Frequent destination is not workplace.",
                "Booking is not travel.",
                "Schedule is not actual movement.",
                "IP geolocation is not exact location.",
                "GPS point is not perfect location.",
                "Map-matched route is not direct observation.",
                "Non-detection is not absence.",
                "Anomaly is not intent.",
                "Movement is not guilt.",
                "Multiple points from one sensor are not independent sources.",
                "AI agreement is not mobility corroboration.",
            ]
        )

        unknowns.extend(
            [
                "driver identity",
                "passenger identity",
                "person presence",
                "purpose of movement",
                "activity at stop/destination",
                "employer/employment status",
                "residence",
                "relationship between co-located entities",
                "intent",
            ]
        )

        gaps.extend(
            [
                KnowledgeGap(description="Asset identity resolution uncertain.", importance="HIGH", recommended_source="authorized asset register/dispatch record", specialist="MOBINT / TRANSPORTINT", expected_information_value="Prevents device/vehicle/person conflation."),
                KnowledgeGap(description="Route segment unobserved or map-match uncertain.", importance="MEDIUM", recommended_source="higher-rate telemetry / independent road sensor", specialist="MOBINT / GEOINT", expected_information_value="Distinguishes observed route from inferred route."),
                KnowledgeGap(description="Stop purpose unknown.", importance="MEDIUM", recommended_source="authorized delivery/logistics/facility record", specialist="MOBINT / SUPPLYCHAININT", expected_information_value="Prevents activity/intent inference."),
                KnowledgeGap(description="Sensor precision unknown.", importance="HIGH", recommended_source="device health/calibration metadata", specialist="MOBINT sensor QC", expected_information_value="Reduces false anomaly and false co-location."),
                KnowledgeGap(description="Co-location significance unclear.", importance="MEDIUM", recommended_source="independent event/transport/fleet context", specialist="MOBINT / TRANSPORTINT", expected_information_value="Distinguishes coincidence from coordinated movement."),
            ]
        )

        actions.extend(
            [
                NextAction(description="Retrieve independent authorized telemetry or dispatch record.", rationale="Tests asset identity and route corroboration without private tracking.", priority="HIGH"),
                NextAction(description="Validate GPS accuracy, clock sync, and sensor health.", rationale="Precision errors create false stops/deviations.", priority="HIGH"),
                NextAction(description="Compare road closure/traffic/weather context before interpreting deviation.", rationale="Benign transport context often explains route changes.", priority="HIGH"),
                NextAction(description="Aggregate OD and corridor analysis when person-level detail is unnecessary.", rationale="Privacy-preserving mobility insight.", priority="MEDIUM"),
                NextAction(description="Handoff location verification to GEOINT and transport asset questions to TRANSPORTINT.", rationale="MOBINT focuses on movement patterns, not all geospatial/transport specialization.", priority="MEDIUM"),
                NextAction(description="Require human review before any person-level, employment, law-enforcement, or sensitive-location conclusion.", rationale="Consequential person-level inference requires governance.", priority="HIGH"),
            ]
        )

        guard = PolicyGuard()
        actions = [a for a in actions if guard.is_safe_action(a.description)]

        handoffs.extend(
            [
                SpecialistHandoff(specialist="GEOINT", reason="Location verification, terrain, map features, visual geolocation."),
                SpecialistHandoff(specialist="TRANSPORTINT", reason="Transport asset/system/route-specific interpretation."),
                SpecialistHandoff(specialist="AISINT", reason="Maritime AIS-specific movement."),
                SpecialistHandoff(specialist="SATINT", reason="Satellite-derived movement/change observations."),
                SpecialistHandoff(specialist="ENVINT", reason="Weather/environmental context affecting movement."),
                SpecialistHandoff(specialist="TRADEINT", reason="Commercial shipment meaning."),
                SpecialistHandoff(specialist="SUPPLYCHAININT", reason="Supply-chain dependency and delivery context."),
                SpecialistHandoff(specialist="ORGINT", reason="Organizational/unit relationships if workplace inference arises."),
                SpecialistHandoff(specialist="INCIDENTINT", reason="Authorized incident timeline correlation."),
                SpecialistHandoff(specialist="IMINT", reason="Image/video movement context, no face-based tracking."),
                SpecialistHandoff(specialist="VIDINT", reason="Video route/scene context, no private-person tracking."),
                SpecialistHandoff(specialist="HUMINT", reason="Witness/source claims require separate reliability handling."),
            ]
        )

        return {
            "facts": facts,
            "unknowns": sorted(set(unknowns)),
            "limitations": sorted(set(limitations)),
            "knowledge_gaps": gaps,
            "next_actions": actions,
            "specialist_handoffs": handoffs,
            "sensitive_location_flags": sorted(set(sensitive_flags)),
        }


class DualAIReviewer:
    def review(
        self,
        *,
        entities: List[Entity],
        trips: List[Trip],
        colocations: List[Colocation],
        deviations: List[RouteDeviation],
        anomalies: List[MovementAnomaly],
        contradictions: List[Contradiction],
        source_independence: Dict[str, Any],
        case: Dict[str, Any],
    ) -> Dict[str, Any]:
        notes: List[str] = []
        status = ReviewStatus.AGREE

        if not trips:
            status = ReviewStatus.INSUFFICIENT_EVIDENCE
            notes.append("No trips reconstructed from supplied movement points.")

        if any(seg.inferred for trip in trips for seg in trip.route_segments):
            notes.append("Map-matched/reconstructed segments are inference, not direct observation.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if colocations:
            notes.append("Co-location does not establish meeting, relationship, coordination, or intent.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if deviations or anomalies:
            notes.append("Deviation/anomaly requires benign-context testing before any case-relevant interpretation.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if contradictions:
            notes.append("Open movement contradictions remain; do not promote to person-level conclusion.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if source_independence.get("overall_status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            notes.append("Source independence dependent/unknown; multiple points may share one device/provider family.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        human_review_required = False
        tags = [str(x).upper() for x in case.get("sensitivity_tags", [])]

        for e in entities:
            if e.entity_type == EntityType.PERSON or e.privacy == PrivacyClassification.HIGHLY_SENSITIVE:
                human_review_required = True
                notes.append("Person-level/highly sensitive entity movement present; exact location suppression and human governance required.")

        if any(t in {"LAW_ENFORCEMENT", "EMPLOYMENT_CONSEQUENCE", "SENSITIVE_LOCATION", "PROTECTED_PERSON", "VICTIM_WITNESS_SOURCE"} for t in tags):
            human_review_required = True
            notes.append("Sensitive legal/employment/protected-person context supplied; human review required.")

        if any(c.state in (ColocationState.SUPPORTED_COLOCATION, ColocationState.POSSIBLE_COLOCATION) for c in colocations):
            human_review_required = True
            notes.append("Co-location output may be misread as relationship; human review required before case use.")

        return {
            "status": status.value,
            "skeptic_notes": notes,
            "rule": "AI agreement is not independent mobility corroboration.",
            "human_review_required": human_review_required,
        }


# ======================================================================
# SECTION 9 — SOURCE INDEPENDENCE / OD AGGREGATION
# ======================================================================

class SourceIndependenceAnalyzer:
    def assess(self, sources: List[Source], points: List[TrackPoint]) -> Dict[str, Any]:
        used_source_ids = {p.source_id for p in points if p.source_id}
        groups = set()
        for sid in used_source_ids:
            src = next((s for s in sources if s.source_id == sid), None)
            if src and src.independence_group and src.independence_group != "UNKNOWN":
                groups.add(src.independence_group)

        if not groups:
            status = IndependenceState.UNKNOWN
            notes = ["Source independence group unavailable; do not treat multiple points as independent sources."]
        elif len(groups) == 1:
            status = IndependenceState.DEPENDENT
            notes = [
                "All used movement sources appear to share one independence group/upstream feed.",
                "100 GPS points from one tracker are one source family, not 100 corroborators.",
            ]
        else:
            status = IndependenceState.PARTIALLY_DEPENDENT
            notes = [
                "Multiple source groups exist, but full pedigree/independence is not proven.",
                "Verify sensor, platform, aggregator, and API lineage.",
            ]

        return {
            "overall_status": status.value,
            "groups": sorted(groups),
            "used_source_ids": sorted(used_source_ids),
            "notes": notes,
        }


class ODAggregator:
    def __init__(self, min_count: int = 1):
        self.min_count = min_count

    def aggregate(self, trips: List[Trip], zones: List[Zone], privacy_mode: str) -> List[Dict[str, Any]]:
        counts: Dict[Tuple[str, str], int] = defaultdict(int)

        for trip in trips:
            if not trip.points:
                continue
            origin = self._zone_or_cell(trip.points[0], zones, privacy_mode)
            dest = self._zone_or_cell(trip.points[-1], zones, privacy_mode)
            counts[(origin, dest)] += 1

        rows = []
        for (origin, dest), count in counts.items():
            if count >= self.min_count:
                rows.append({"origin": origin, "destination": dest, "count": count})
            else:
                rows.append({"origin": origin, "destination": dest, "count": count, "suppressed": True, "reason": "below minimum cohort threshold"})

        rows.sort(key=lambda x: x.get("count", 0), reverse=True)
        return rows

    @staticmethod
    def _zone_or_cell(point: TrackPoint, zones: List[Zone], privacy_mode: str) -> str:
        for z in zones:
            if z.center_lat is None or z.center_lon is None or z.radius_m is None:
                continue
            dist = haversine_m(z.center_lat, z.center_lon, point.latitude, point.longitude)
            acc = point.accuracy_radius_m or 100.0
            if dist is not None and dist <= z.radius_m + 0.5 * acc:
                return z.name or z.zone_id
        if privacy_mode == "AGGREGATE" and point.latitude is not None and point.longitude is not None:
            return f"CELL_{round(point.latitude, 1)}_{round(point.longitude, 1)}"
        return "UNZONED"


# ======================================================================
# SECTION 10 — GRAPHICAL MEMORY / REPORT GENERATOR
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

    def write_result(self, result: MOBINTResult) -> Dict[str, Any]:
        entity_map = {e.entity_id: e for e in result.entities}

        for s in result.sources:
            self.add_node(s.source_id, "Source", {"provider": s.provider, "group": s.independence_group, "freshness": s.data_freshness})

        for e in result.entities:
            self.add_node(e.entity_id, "Entity", {"type": e.entity_type.value, "label": e.display_label, "privacy": e.privacy.value, "pseudonymized": e.pseudonymized})

        for p in result.tracks[:2000]:
            self.add_node(
                p.point_id,
                "TrackPoint",
                {
                    "entity_id": p.entity_id,
                    "timestamp": p.timestamp.isoformat(),
                    "latitude": p.latitude,
                    "longitude": p.longitude,
                    "accuracy_m": p.accuracy_radius_m,
                    "source_id": p.source_id,
                },
            )
            self.add_edge(p.point_id, "OBSERVED_AT", p.entity_id, {"evidence_id": p.evidence_id, "source_id": p.source_id})

        for t in result.trips:
            self.add_node(
                t.trip_id,
                "Trip",
                {
                    "entity_id": t.entity_id,
                    "start_time": t.start_time.isoformat(),
                    "end_time": t.end_time.isoformat(),
                    "mode": t.movement_mode.value,
                    "distance_m": t.distance_m,
                    "duration_s": t.duration_s,
                },
            )
            for p in t.points[:200]:
                self.add_edge(p.point_id, "PART_OF_TRIP", t.trip_id)

        for stop in result.stops:
            self.add_node(stop.stop_id, "Stop", {"entity_id": stop.entity_id, "duration_s": stop.duration_s, "type": stop.stop_type.value})
            self.add_edge(stop.stop_id, "DWELLED_AT", stop.entity_id)

        for coloc in result.colocations:
            self.add_node(coloc.colocation_id, "Colocation", {"state": coloc.state.value, "matched_points": coloc.matched_points})
            self.add_edge(coloc.entity_a, "COLOCATED_WITH_CANDIDATE", coloc.entity_b, {"colocation_id": coloc.colocation_id})

        for f in result.facts[:1000]:
            self.add_node(f.fact_id, "Fact", {"statement": f.statement, "status": f.status.value})
            for ev in f.evidence_ids[:20]:
                self.add_edge(f.fact_id, "SUPPORTED_BY", ev)

        for h in result.hypotheses[:1000]:
            self.add_node(h.hypothesis_id, "Hypothesis", {"statement": h.statement})

        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "sample_nodes": list(self.nodes.keys())[:20],
            "entity_map_size": len(entity_map),
        }


class ReportGenerator:
    def __init__(self):
        self.entity_map: Dict[str, Entity] = {}

    def generate(self, result: MOBINTResult) -> str:
        self.entity_map = {e.entity_id: e for e in result.entities}
        lines: List[str] = []

        def section(title: str) -> None:
            lines.append("")
            lines.append(title.upper())
            lines.append("-" * len(title))

        lines.append("=" * 72)
        lines.append("TRACEATLAS — MOBINT REPORT")
        lines.append("=" * 72)
        lines.append(f"Case ID: {result.case_id}")
        lines.append(f"Task ID: {result.task_id}")
        lines.append(f"Objective: {result.objective}")
        lines.append(f"Status: {result.status}")
        lines.append(f"Policy Decision: {result.policy_decision.value}")

        section("Safety / Privacy Boundary")
        lines.append("- Lawful authorized asset/fleet/public-transport/logistics/aggregate mobility analysis only.")
        lines.append("- No private-person real-time tracking, stalking, home/work inference, interception, ambush, targeting, hostile surveillance, or evasion guidance.")
        for flag in result.safety_flags:
            lines.append(f"- Safety: {flag}")
        for flag in result.privacy_flags:
            lines.append(f"- Privacy: {flag}")
        for flag in result.sensitive_location_flags:
            lines.append(f"- Sensitive location: {flag}")

        section("Source Inventory")
        if not result.sources:
            lines.append("- No sources supplied.")
        for s in result.sources:
            lines.append(f"- {s.source_id}: provider={s.provider}, group={s.independence_group}, reliability={s.reliability}, freshness={s.data_freshness}, type={s.source_type}")
            if s.limitations:
                lines.append(f"  limitations={'; '.join(s.limitations)}")

        section("Entity / Asset Resolution")
        if not result.entities:
            lines.append("- No entities supplied.")
        for e in result.entities:
            lines.append(f"- {e.entity_id}: type={e.entity_type.value}, label={e.display_label}, privacy={e.privacy.value}, pseudonymized={e.pseudonymized}")
            lines.append("  caution: device != person, vehicle != driver, account != traveler, asset != assigned person.")

        section("Track Inventory / Precision")
        lines.append(f"- Track points: {len(result.tracks)}")
        for p in result.tracks[:50]:
            ent = self.entity_map.get(p.entity_id)
            label = ent.display_label if ent else p.entity_id
            lines.append(
                f"- {p.point_id}: entity={label}, time={p.timestamp.isoformat()}, "
                f"coord={self._fmt_coord(p.latitude, p.longitude, ent)}, accuracy_m={p.accuracy_radius_m}, "
                f"speed_m_s={p.speed_m_s}, precision={p.precision_level.value}, flags={p.quality_flags}"
            )

        section("Trips")
        if not result.trips:
            lines.append("- No trips reconstructed.")
        for t in result.trips:
            ent = self.entity_map.get(t.entity_id)
            label = ent.display_label if ent else t.entity_id
            lines.append(f"- Trip {t.trip_id}: entity={label}, start={t.start_time.isoformat()}, end={t.end_time.isoformat()}")
            lines.append(f"  points={len(t.points)}, distance_m={t.distance_m}, duration_s={t.duration_s}, avg_speed_m_s={t.average_speed_m_s}, mode={t.movement_mode.value}")
            lines.append(f"  origin={t.origin_state}, destination={t.destination_state}, segmentation_confidence={t.segmentation_confidence.value}")
            lines.append(f"  route_signature={list(t.route_signature)}")
            if t.limitations:
                lines.append(f"  limitations={'; '.join(t.limitations)}")

        section("Stops / Dwell")
        if not result.stops:
            lines.append("- No stops detected.")
        for s in result.stops:
            ent = self.entity_map.get(s.entity_id)
            label = ent.display_label if ent else s.entity_id
            lines.append(
                f"- Stop {s.stop_id}: entity={label}, start={s.start_time.isoformat()}, end={s.end_time.isoformat()}, "
                f"duration_s={s.duration_s}, type={s.stop_type.value}, center={self._fmt_coord(s.center_lat, s.center_lon, ent)}"
            )
            lines.append("  caution: stop/dwell does not establish meeting, delivery, residence, workplace, activity, or intent.")

        section("Route Segments / Map Matching")
        for t in result.trips[:20]:
            lines.append(f"Trip {t.trip_id}:")
            for seg in t.route_segments[:20]:
                lines.append(
                    f"- {seg.segment_id}: {seg.from_point_id} -> {seg.to_point_id}, method={seg.method}, "
                    f"distance_m={seg.distance_m}, duration_s={seg.duration_s}, road={seg.matched_road_id}, "
                    f"inferred={seg.inferred}, confidence={seg.confidence.value}"
                )
                for n in seg.notes:
                    lines.append(f"  note: {n}")

        section("Geofence Events")
        if not result.geofence_events:
            lines.append("- None.")
        for ev in result.geofence_events:
            lines.append(f"- {ev.event_id}: entity={ev.entity_id}, zone={ev.zone_name or ev.zone_id}, type={ev.event_type.value}, time={ev.timestamp.isoformat()}, confidence={ev.confidence.value}")
            for n in ev.notes:
                lines.append(f"  note: {n}")

        section("Recurring Routes / Corridors")
        for r in result.recurring_routes[:50]:
            lines.append(f"- Recurring: entity={r['entity_id']}, state={r['state']}, count={r['count']}, days={r['distinct_days']}, signature={r['route_signature']}")
        for c in result.corridor_summary[:50]:
            lines.append(f"- Corridor: {c}")

        section("Route Deviations / Movement Anomalies")
        for d in result.deviations[:50]:
            lines.append(f"- Deviation {d.deviation_id}: entity={d.entity_id}, trip={d.trip_id}, state={d.state.value}, diff={d.segment_difference_count}")
            lines.append(f"  baseline={list(d.baseline_route_signature)}")
            lines.append(f"  observed={list(d.observed_route_signature)}")
            lines.append(f"  explanation_context={d.explanation_context}")
            lines.append("  caution: deviation is not suspicious without independent case evidence.")
        for a in result.anomalies[:50]:
            lines.append(f"- Anomaly {a.anomaly_id}: entity={a.entity_id}, trip={a.trip_id}, type={a.anomaly_type}, state={a.state.value}, z={a.z_score}")
            lines.append(f"  description={a.description}")
            lines.append("  caution: anomaly is statistical departure, not intent.")

        section("Co-location / Co-movement")
        if not result.colocations:
            lines.append("- None.")
        for c in result.colocations:
            lines.append(
                f"- Co-location {c.colocation_id}: {c.entity_a} <-> {c.entity_b}, state={c.state.value}, "
                f"matched={c.matched_points}, avg_dist_m={c.average_distance_m}, center={self._fmt_coord(c.center_lat, c.center_lon, None)}"
            )
            for n in c.notes:
                lines.append(f"  note: {n}")
        for m in result.comovements:
            lines.append(f"- Co-movement {m.comovement_id}: {m.entity_a} <-> {m.entity_b}, state={m.state.value}, duration_s={m.duration_s}")
            for n in m.notes:
                lines.append(f"  note: {n}")

        section("OD Matrix / Aggregate Mobility")
        for row in result.od_matrix[:100]:
            lines.append(f"- {row}")
        lines.append("- OD aggregation is movement volume context, not individual trajectory reconstruction.")

        section("Source Independence")
        lines.append(f"- Overall: {result.source_independence.get('overall_status', 'UNKNOWN')}")
        lines.append(f"- Groups: {result.source_independence.get('groups', [])}")
        for note in result.source_independence.get("notes", []):
            lines.append(f"  - {note}")

        section("Facts")
        for f in result.facts[:200]:
            lines.append(f"- [{f.status.value}] {f.statement}")
            if f.limitations:
                lines.append(f"  limitations: {'; '.join(f.limitations)}")

        section("Contradictions")
        if not result.contradictions:
            lines.append("- None detected.")
        for c in result.contradictions[:100]:
            lines.append(f"- {c.contradiction_type}: {c.description}")
            lines.append(f"  resolutions: {c.candidate_resolutions}")

        section("Competing Hypotheses")
        for h in result.hypotheses[:100]:
            lines.append(f"- {h.hypothesis_id}: {h.statement}")
            lines.append(f"  supports: {h.supports}")
            lines.append(f"  oppositions: {h.oppositions}")
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
            lines.append("  - Human review required before person-level, employment, law-enforcement, sensitive-location, or public accusation use.")

        section("Required Analyst Summary")
        if result.trips:
            t = result.trips[0]
            ent = self.entity_map.get(t.entity_id)
            label = ent.display_label if ent else t.entity_id
            lines.append(f"ASSET: {label}.")
            lines.append(f"OBSERVATION: Authorized movement sources place the asset along reconstructed route between {t.start_time.isoformat()} and {t.end_time.isoformat()}.")
            lines.append(f"ROUTE: Map-matching/reconstruction confidence {t.segmentation_confidence.value}; unobserved segments remain inferred.")
            if result.stops:
                s = result.stops[0]
                lines.append(f"STOP: A {int((s.duration_s or 0)/60)}-minute stationary period was detected.")
                lines.append("CAUTION: Stop does not establish driver identity, passenger identity, meeting, delivery, activity, residence, workplace, or intent.")
            if result.deviations:
                d = result.deviations[0]
                lines.append(f"DEVIATION: {d.state.value}; context={d.explanation_context}.")
                lines.append("ASSESSMENT: ROUTE_DEVIATION = SUPPORTED/CANDIDATE. SUSPICIOUS_MOVEMENT = NOT ESTABLISHED.")
            if result.colocations:
                c = result.colocations[0]
                lines.append(f"CO-LOCATION: {c.state.value}. It is not meeting/relationship/coordination without independent evidence.")
            lines.append("NEXT ACTION: Correlate with authorized dispatch/transport/traffic records and independent telemetry rather than inferring purpose from location alone.")
        else:
            lines.append("ASSET: No trip reconstructed.")
            lines.append("NEXT ACTION: Verify source coverage, timestamps, coordinates, and asset identity.")

        lines.append("")
        lines.append("=" * 72)
        lines.append("END REPORT")
        lines.append("=" * 72)
        return "\n".join(lines)

    def _fmt_coord(
        self,
        lat: Optional[float],
        lon: Optional[float],
        entity: Optional[Entity],
    ) -> str:
        if lat is None or lon is None:
            return "UNKNOWN"
        if entity is not None and entity.privacy == PrivacyClassification.HIGHLY_SENSITIVE:
            return "SUPPRESSED_PRIVATE_LOCATION"
        if entity is not None and entity.privacy == PrivacyClassification.SENSITIVE:
            return f"COARSE({round(lat, 2)}, {round(lon, 2)})"
        return f"({round(lat, 5)}, {round(lon, 5)})"


# ======================================================================
# SECTION 11 — MOBINT AI EMPLOYEE
# ======================================================================

class MOBIntelligenceEmployee:
    def __init__(self, mode: ModelMode = ModelMode.LOCAL_ONLY):
        self.mode = mode
        self.policy = PolicyGuard()
        self.injection_defense = PromptInjectionDefense()
        self.ingestor = MOBINTIngestor(injection_defense=self.injection_defense)
        self.segmenter = TripSegmenter()
        self.geofence = GeofenceAnalyzer()
        self.patterns = PatternAnalyzer()
        self.colocation = CoLocationAnalyzer()
        self.contradictions = ContradictionDetector()
        self.hypotheses = HypothesisEngine()
        self.independence = SourceIndependenceAnalyzer()
        self.od = ODAggregator()
        self.fact_gate = FactGate()
        self.reviewer = DualAIReviewer()
        self.memory = GraphicalMemory()
        self.reporter = ReportGenerator()

    def run_case(self, case: Dict[str, Any]) -> MOBINTResult:
        case_id = str(case.get("case_id", new_id("CASE")))
        task_id = str(case.get("task_id", new_id("TASK")))
        objective = str(case.get("objective", ""))
        questions = case.get("questions", [])

        request_text = objective + "\n" + "\n".join(str(q) for q in questions)
        for e in case.get("entities", []):
            request_text += "\n" + " ".join(str(e.get(k, "")) for k in ("display_label", "asset_id", "notes"))

        policy = self.policy.check_request(request_text)

        if policy.decision == PolicyDecision.POLICY_BLOCKED:
            return MOBINTResult(
                case_id=case_id,
                task_id=task_id,
                objective=objective,
                status="POLICY_BLOCKED",
                policy_decision=PolicyDecision.POLICY_BLOCKED,
                report=(
                    "POLICY_BLOCKED\n\n"
                    "This request seeks prohibited MOBINT private-person tracking, targeting, interception, evasion, "
                    "or exploitation guidance. Lawful alternative: authorized asset/fleet/public-transport/logistics "
                    "movement analysis, historical trip reconstruction, stop/dwell uncertainty, route-deviation context, "
                    "aggregate mobility, source independence, and defensive resilience assessment without live private "
                    "tracking, home/work inference, stalking, interception, or evasion guidance."
                ),
                safety_flags=[
                    "No private-person real-time tracking or stalking provided.",
                    "No home/work/residence inference provided.",
                    "No interception/ambush/targeting coordinates provided.",
                    "No camera/GPS/AIS/geofence evasion guidance provided.",
                ],
                limitations=[policy.reason],
            )

        evidence, sources, entities, tracks, zones, context = self.ingestor.ingest_case(case)
        source_map = {s.source_id: s for s in sources}
        entity_map = {e.entity_id: e for e in entities}

        # Hard privacy boundary: no live private-person tracking.
        for e in entities:
            if e.entity_type == EntityType.PERSON:
                live_sources = [
                    source_map[p.source_id].data_freshness
                    for p in tracks
                    if p.entity_id == e.entity_id and p.source_id in source_map
                ]
                if any(f in {"LIVE", "LIVE_AUTHORIZED", "NEAR_REAL_TIME"} for f in live_sources):
                    return MOBINTResult(
                        case_id=case_id,
                        task_id=task_id,
                        objective=objective,
                        status="POLICY_BLOCKED",
                        policy_decision=PolicyDecision.POLICY_BLOCKED,
                        report=(
                            "POLICY_BLOCKED\n\n"
                            "Live or near-real-time movement data for a person-level entity is not accepted. "
                            "MOBINT may analyze authorized asset/fleet/public-transport/aggregate historical movement, "
                            "but must not function as a private-person real-time tracker."
                        ),
                        safety_flags=["No live private-person tracking provided."],
                        limitations=["Person-level live/near-real-time mobility boundary enforced."],
                    )

        trips, stops = self.segmenter.analyze(
            points=tracks,
            entities=entities,
            road_network=context.get("road_network", []),
            case=case,
        )

        geofence_events = self.geofence.analyze(trips, zones)

        recurring, deviations, anomalies, corridors = self.patterns.analyze(
            trips=trips,
            traffic_context=context.get("traffic_context", []),
            case=case,
        )

        colocations, comovements = self.colocation.analyze(tracks, entities, zones)
        contradictions = self.contradictions.detect(tracks)
        hypotheses = self.hypotheses.generate(trips, deviations, anomalies, colocations, contradictions)

        privacy_mode = str(case.get("privacy_mode", "ASSET_LEVEL")).upper()
        min_count = int(case.get("od_min_count", 5 if privacy_mode == "AGGREGATE" else 1))
        self.od = ODAggregator(min_count=min_count)
        od_matrix = self.od.aggregate(trips, zones, privacy_mode)

        source_independence = self.independence.assess(sources, tracks)

        fact_out = self.fact_gate.generate(
            case=case,
            sources=sources,
            entities=entities,
            trips=trips,
            stops=stops,
            geofence_events=geofence_events,
            colocations=colocations,
            comovements=comovements,
            deviations=deviations,
            anomalies=anomalies,
            recurring=recurring,
            contradictions=contradictions,
            source_independence=source_independence,
        )

        review = self.reviewer.review(
            entities=entities,
            trips=trips,
            colocations=colocations,
            deviations=deviations,
            anomalies=anomalies,
            contradictions=contradictions,
            source_independence=source_independence,
            case=case,
        )

        status = "PARTIAL"
        if not tracks:
            status = "INSUFFICIENT_DATA"
        elif not trips:
            status = "TRIP_UNRESOLVED"
        elif contradictions:
            status = "PARTIAL_DISPUTED_MOVEMENT"
        elif review.get("human_review_required"):
            status = "PARTIAL_HUMAN_REVIEW_REQUIRED"
        elif trips and any(t.segmentation_confidence in (Confidence.MEDIUM, Confidence.HIGH) for t in trips):
            status = "SUCCEEDED"

        privacy_flags = []
        if self.mode == ModelMode.LOCAL_ONLY:
            privacy_flags.append("LOCAL_ONLY mode selected; sensitive asset/device telemetry should remain local.")
        elif self.mode == ModelMode.CLOUD:
            privacy_flags.append("CLOUD mode requires sanitized/aggregated/policy-approved movement metadata only.")
        else:
            privacy_flags.append("HYBRID mode requires routing controls, tenant isolation, and purpose limitation.")

        privacy_flags.append("Device is not person; vehicle is not driver; account is not traveler.")
        privacy_flags.append("Private residence/workplace inference is prohibited.")
        privacy_flags.append("Sensitive-zone visits must not be used to infer health, religion, politics, shelter status, or private identity.")

        result = MOBINTResult(
            case_id=case_id,
            task_id=task_id,
            objective=objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW,
            evidence=evidence,
            sources=sources,
            entities=entities,
            tracks=tracks,
            trips=trips,
            stops=stops,
            zones=zones,
            geofence_events=geofence_events,
            colocations=colocations,
            comovements=comovements,
            anomalies=anomalies,
            deviations=deviations,
            od_matrix=od_matrix,
            corridor_summary=corridors,
            recurring_routes=recurring,
            contradictions=contradictions,
            hypotheses=hypotheses,
            facts=fact_out["facts"],
            knowledge_gaps=fact_out["knowledge_gaps"],
            next_actions=fact_out["next_actions"],
            specialist_handoffs=fact_out["specialist_handoffs"],
            source_independence=source_independence,
            review=review,
            unknowns=fact_out["unknowns"],
            limitations=fact_out["limitations"],
            safety_flags=[
                "No private-person real-time tracking or stalking.",
                "No home/work/residence inference.",
                "No interception/ambush/targeting coordinates.",
                "No camera/GPS/AIS/geofence evasion guidance.",
                "Asset movement is not person presence.",
                "Co-location is not meeting.",
                "Route deviation is not suspicious activity.",
                "Human review required for person-level or consequential use.",
            ],
            privacy_flags=privacy_flags,
            sensitive_location_flags=fact_out["sensitive_location_flags"],
        )

        result.graph = self.memory.write_result(result)
        result.report = self.reporter.generate(result)
        return result


# ======================================================================
# SECTION 12 — SYNTHETIC DEMOS
# ======================================================================

def demo_lawful_fleet_mobility() -> None:
    """
    Synthetic lawful demo:
    Authorized fleet telematics, logistics corridor, road closure context,
    stop/dwell uncertainty, co-location at depot, and privacy-preserving reporting.
    No private-person tracking.
    """
    employee = MOBIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    def pt(ts: str, lat: float, lon: float, acc: float = 25.0, speed: Optional[float] = None, source: str = "SRC_FLEET") -> Dict[str, Any]:
        return {
            "timestamp": ts,
            "latitude": lat,
            "longitude": lon,
            "accuracy_m": acc,
            "speed": speed,
            "speed_unit": "m/s" if speed is not None else None,
            "source_id": source,
        }

    case = {
        "case_id": "DEMO-MOBINT-001",
        "task_id": "DEMO-TASK-001",
        "objective": (
            "Lawful authorized fleet mobility analysis: reconstruct delivery vehicle movement, "
            "identify stops/dwell uncertainty, test route deviation against traffic closure context, "
            "assess depot co-location without inferring meetings, and preserve privacy/precision limits."
        ),
        "questions": [
            "What movement is evidenced by authorized telemetry?",
            "Which stops are supported and what do they not prove?",
            "Is route deviation explained by traffic/closure context?",
            "Is co-location at depot meeting/relationship evidence?",
            "What remains unknown?",
        ],
        "authorization": "AUTHORIZED_FLEET_TELEMETRICS_LOGISTICS_SAFETY_RESEARCH",
        "privacy_mode": "ASSET_LEVEL",
        "sensitivity_tags": ["FLEET_AUTHORIZED", "LOGISTICS", "SYNTHETIC_DEMO"],
        "map_match_threshold_m": 250.0,
        "od_min_count": 1,
        "sources": [
            {
                "source_id": "SRC_FLEET",
                "provider": "Demo Fleet Telematics",
                "upstream_feed": "fleet_api",
                "independence_group": "fleet_provider",
                "reliability": "HIGH",
                "source_type": "FLEET_TELEMETRICS",
                "data_freshness": "HISTORICAL",
                "limitations": ["One device family; multiple points are not independent sources."],
            },
            {
                "source_id": "SRC_DISPATCH",
                "provider": "Demo Dispatch System",
                "upstream_feed": "dispatch_db",
                "independence_group": "operations",
                "reliability": "MEDIUM",
                "source_type": "LOGISTICS_RECORD",
                "data_freshness": "HISTORICAL",
                "limitations": ["Self-reported operational record."],
            },
            {
                "source_id": "SRC_TRAFFIC",
                "provider": "Demo Traffic Feed",
                "upstream_feed": "traffic_api",
                "independence_group": "traffic",
                "reliability": "MEDIUM",
                "source_type": "TRAFFIC_CONTEXT",
                "data_freshness": "HISTORICAL",
                "limitations": ["Coverage and latency limitations."],
            },
        ],
        "entities": [
            {
                "entity_id": "ENT_V42",
                "entity_type": "VEHICLE",
                "asset_id": "V-42",
                "display_label": "Fleet Vehicle V-42",
                "privacy": "BUSINESS",
                "source_ids": ["SRC_FLEET", "SRC_DISPATCH"],
                "limitations": ["Vehicle movement does not identify driver or passengers."],
            },
            {
                "entity_id": "ENT_V17",
                "entity_type": "VEHICLE",
                "asset_id": "V-17",
                "display_label": "Fleet Vehicle V-17",
                "privacy": "BUSINESS",
                "source_ids": ["SRC_FLEET"],
                "limitations": ["Vehicle movement does not identify driver or passengers."],
            },
        ],
        "zones": [
            {
                "zone_id": "ZONE_DEPOT",
                "name": "Demo Depot",
                "zone_type": "WAREHOUSE",
                "center_lat": 40.0000,
                "center_lon": -74.0000,
                "radius_m": 250.0,
                "privacy": "BUSINESS",
                "min_count": 1,
            },
            {
                "zone_id": "ZONE_FACILITY",
                "name": "Demo Delivery Facility",
                "zone_type": "FACILITY",
                "center_lat": 40.0200,
                "center_lon": -74.0000,
                "radius_m": 300.0,
                "privacy": "BUSINESS",
                "min_count": 1,
            },
        ],
        "road_network": [
            {
                "road_id": "R1_MAIN",
                "name": "Main Corridor",
                "start_lat": 40.0050,
                "start_lon": -74.0000,
                "end_lat": 40.0150,
                "end_lon": -74.0000,
            },
            {
                "road_id": "R2_ALT",
                "name": "Alternate Corridor",
                "start_lat": 40.0050,
                "start_lon": -73.9900,
                "end_lat": 40.0150,
                "end_lon": -73.9900,
            },
        ],
        "traffic_context": [
            {
                "road_id": "R1_MAIN",
                "type": "CLOSURE",
                "start_time": "2026-10-08T08:00:00Z",
                "end_time": "2026-10-08T09:00:00Z",
                "source_id": "SRC_TRAFFIC",
                "notes": ["Synthetic closure explains alternate route."],
            }
        ],
        "tracks": [
            {
                "track_id": "TRK_V42_DAY1",
                "entity_id": "ENT_V42",
                "asset_id": "V-42",
                "source_id": "SRC_FLEET",
                "precision_level": "HIGH_PRECISION",
                "points": [
                    pt("2026-10-07T08:00:00Z", 40.0000, -74.0000, 20, 0.0),
                    pt("2026-10-07T08:10:00Z", 40.0100, -74.0000, 25, 12.0),
                    pt("2026-10-07T08:20:00Z", 40.0200, -74.0000, 30, 0.0),
                    pt("2026-10-07T08:45:00Z", 40.0200, -74.0000, 30, 0.0),
                    pt("2026-10-07T08:55:00Z", 40.0100, -74.0000, 25, 12.0),
                    pt("2026-10-07T09:05:00Z", 40.0000, -74.0000, 20, 0.0),
                ],
            },
            {
                "track_id": "TRK_V42_DAY2",
                "entity_id": "ENT_V42",
                "asset_id": "V-42",
                "source_id": "SRC_FLEET",
                "precision_level": "HIGH_PRECISION",
                "points": [
                    pt("2026-10-08T08:00:00Z", 40.0000, -74.0000, 20, 0.0),
                    pt("2026-10-08T08:12:00Z", 40.0100, -73.9900, 25, 11.0),
                    pt("2026-10-08T08:25:00Z", 40.0200, -74.0000, 30, 0.0),
                    pt("2026-10-08T09:00:00Z", 40.0200, -74.0000, 30, 0.0),
                    pt("2026-10-08T09:10:00Z", 40.0100, -73.9900, 25, 11.0),
                    pt("2026-10-08T09:20:00Z", 40.0000, -74.0000, 20, 0.0),
                ],
            },
            {
                "track_id": "TRK_V17_DAY2",
                "entity_id": "ENT_V17",
                "asset_id": "V-17",
                "source_id": "SRC_FLEET",
                "precision_level": "HIGH_PRECISION",
                "points": [
                    pt("2026-10-08T07:58:00Z", 40.0001, -74.0001, 25, 0.0),
                    pt("2026-10-08T08:05:00Z", 40.0001, -74.0001, 25, 0.0),
                    pt("2026-10-08T08:20:00Z", 40.0001, -74.0001, 25, 0.0),
                ],
            },
        ],
        "logistics_records": [
            {
                "record_id": "DISPATCH_V42_D2",
                "asset_id": "V-42",
                "timestamp": "2026-10-08T07:45:00Z",
                "instruction": "Use alternate corridor due to announced closure.",
                "source_id": "SRC_DISPATCH",
            }
        ],
    }

    result = employee.run_case(case)
    print(result.report)


def demo_policy_blocked_private_tracking() -> None:
    """
    Synthetic policy-block demonstration.
    Shows that private-person live tracking/home-location requests are refused.
    """
    employee = MOBIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    case = {
        "case_id": "DEMO-MOBINT-BLOCK-001",
        "task_id": "DEMO-TASK-BLOCK-001",
        "objective": "Track Jane Doe's personal phone in real time and find her home address so I can wait for her.",
        "questions": [
            "Where is she right now?",
            "What is her home address?",
        ],
        "authorization": "NONE",
        "entities": [
            {
                "entity_id": "ENT_JANE",
                "entity_type": "PERSON",
                "display_label": "Jane Doe",
                "privacy": "HIGHLY_SENSITIVE",
            }
        ],
        "sources": [
            {
                "source_id": "SRC_PRIVATE_PHONE",
                "provider": "Unknown",
                "independence_group": "private_device",
                "reliability": "UNKNOWN",
                "source_type": "PRIVATE_DEVICE_TELEMETRY",
                "data_freshness": "LIVE",
            }
        ],
        "tracks": [
            {
                "track_id": "TRK_JANE",
                "entity_id": "ENT_JANE",
                "source_id": "SRC_PRIVATE_PHONE",
                "points": [
                    {"timestamp": "2026-10-08T12:00:00Z", "latitude": 40.0, "longitude": -74.0}
                ],
            }
        ],
    }

    result = employee.run_case(case)
    print(result.report)


def main() -> None:
    print("\n" + "=" * 72)
    print("LAWFUL AUTHORIZED FLEET MOBILITY DEMO")
    print("=" * 72 + "\n")
    demo_lawful_fleet_mobility()

    print("\n" + "=" * 72)
    print("POLICY-BLOCKED PRIVATE-TRACKING DEMO")
    print("=" * 72 + "\n")
    demo_policy_blocked_private_tracking()


if __name__ == "__main__":
    main()