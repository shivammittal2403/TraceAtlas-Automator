"""
======================================================================
TRACEATLAS — RADINT
RADAR INTELLIGENCE AI EMPLOYEE
Python Implementation
======================================================================

Mode:
LAWFUL / AUTHORIZED / PASSIVE-FIRST / EVIDENCE-FIRST / DEFENSIVE

Primary boundary:
Radar intelligence and sensor analysis,
NOT radar defeat, jamming, targeting or weapon employment.
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
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("RADINT")


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


class SensorType(str, Enum):
    PRIMARY_SURVEILLANCE_RADAR = "PRIMARY_SURVEILLANCE_RADAR"
    SECONDARY_SURVEILLANCE_RADAR = "SECONDARY_SURVEILLANCE_RADAR"
    MARITIME_NAVIGATION_RADAR = "MARITIME_NAVIGATION_RADAR"
    WEATHER_RADAR = "WEATHER_RADAR"
    SAR_SENSOR = "SAR_SENSOR"
    GROUND_SURVEILLANCE_RADAR = "GROUND_SURVEILLANCE_RADAR"
    PERIMETER_RADAR = "PERIMETER_RADAR"
    RESEARCH_RADAR = "RESEARCH_RADAR"
    TRAFFIC_RADAR = "TRAFFIC_RADAR"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class ProductType(str, Enum):
    DETECTION_LIST = "DETECTION_LIST"
    TRACK_EXPORT = "TRACK_EXPORT"
    SAR_IMAGE_PRODUCT = "SAR_IMAGE_PRODUCT"
    WEATHER_RADAR_PRODUCT = "WEATHER_RADAR_PRODUCT"
    MARITIME_RADAR_LOG = "MARITIME_RADAR_LOG"
    AVIATION_RADAR_LOG = "AVIATION_RADAR_LOG"
    GROUND_RADAR_LOG = "GROUND_RADAR_LOG"
    FUSED_TRACK_PRODUCT = "FUSED_TRACK_PRODUCT"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class CalibrationState(str, Enum):
    CALIBRATION_VALID = "CALIBRATION_VALID"
    CALIBRATION_REPORTED = "CALIBRATION_REPORTED"
    CALIBRATION_STALE = "CALIBRATION_STALE"
    CALIBRATION_UNKNOWN = "CALIBRATION_UNKNOWN"


class SensorQuality(str, Enum):
    NOMINAL = "NOMINAL"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"


class TrackContinuity(str, Enum):
    CONTINUOUS = "CONTINUOUS"
    INTERMITTENT = "INTERMITTENT"
    FRAGMENTED = "FRAGMENTED"
    LOST = "LOST"
    REACQUIRED = "REACQUIRED"
    UNKNOWN = "UNKNOWN"


class ClaimState(str, Enum):
    OBSERVED = "OBSERVED"
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    SENSOR_ARTIFACT_CANDIDATE = "SENSOR_ARTIFACT_CANDIDATE"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class IndependenceState(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    PARTIALLY_DEPENDENT = "PARTIALLY_DEPENDENT"
    DEPENDENT = "DEPENDENT"
    UNKNOWN = "UNKNOWN"


class ObjectClass(str, Enum):
    AIRCRAFT_LIKE = "AIRCRAFT_LIKE"
    VESSEL_LIKE = "VESSEL_LIKE"
    VEHICLE_LIKE = "VEHICLE_LIKE"
    WEATHER_PHENOMENON = "WEATHER_PHENOMENON"
    FIXED_OBJECT = "FIXED_OBJECT"
    BIOLOGICAL_OR_CLUTTER_CANDIDATE = "BIOLOGICAL_OR_CLUTTER_CANDIDATE"
    UNKNOWN = "UNKNOWN"


class InterferenceStatus(str, Enum):
    NONE_REPORTED = "NONE_REPORTED"
    INTERFERENCE_OBSERVED = "INTERFERENCE_OBSERVED"
    JAMMING_CANDIDATE = "JAMMING_CANDIDATE"
    JAMMING_SUPPORTED_BY_SOURCE = "JAMMING_SUPPORTED_BY_SOURCE"
    UNKNOWN = "UNKNOWN"


class CoverageState(str, Enum):
    COVERED = "COVERED"
    PARTIALLY_COVERED = "PARTIALLY_COVERED"
    EDGE_OF_COVERAGE = "EDGE_OF_COVERAGE"
    OUTSIDE_COVERAGE = "OUTSIDE_COVERAGE"
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
    try:
        return cls(str(value).upper())
    except Exception:
        try:
            return cls(str(value))
        except Exception:
            return default


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


def normalize_azimuth(deg: Optional[float]) -> Optional[float]:
    if deg is None:
        return None
    return (float(deg) + 360.0) % 360.0


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
        return normalize_azimuth(math.degrees(math.atan2(y, x)))
    except Exception:
        return None


def polar_to_latlon(
    sensor_lat: Optional[float],
    sensor_lon: Optional[float],
    range_m: Optional[float],
    azimuth_deg: Optional[float],
) -> Tuple[Optional[float], Optional[float]]:
    if sensor_lat is None or sensor_lon is None or range_m is None or azimuth_deg is None:
        return None, None
    try:
        lat1 = math.radians(float(sensor_lat))
        lon1 = math.radians(float(sensor_lon))
        brng = math.radians(float(azimuth_deg))
        delta = float(range_m) / EARTH_RADIUS_M

        lat2 = math.asin(
            math.sin(lat1) * math.cos(delta)
            + math.cos(lat1) * math.sin(delta) * math.cos(brng)
        )
        lon2 = lon1 + math.atan2(
            math.sin(brng) * math.sin(delta) * math.cos(lat1),
            math.cos(delta) - math.sin(lat1) * math.sin(lat2),
        )

        lon2_deg = math.degrees(lon2)
        lon2_deg = (lon2_deg + 540.0) % 360.0 - 180.0
        return math.degrees(lat2), lon2_deg
    except Exception:
        return None, None


RANGE_UNIT_TO_M = {
    "m": 1.0,
    "meter": 1.0,
    "meters": 1.0,
    "km": 1000.0,
    "kilometer": 1000.0,
    "kilometers": 1000.0,
    "nmi": 1852.0,
    "nm": 1852.0,
    "nautical mile": 1852.0,
    "nautical miles": 1852.0,
    "ft": 0.3048,
    "feet": 0.3048,
    "yd": 0.9144,
    "yard": 0.9144,
    "yards": 0.9144,
}


def to_meters(value: Optional[float], unit: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    u = (unit or "m").strip().lower()
    factor = RANGE_UNIT_TO_M.get(u)
    if factor is None:
        return None
    return value * factor


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


def to_m_s(value: Optional[float], unit: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    u = (unit or "m/s").strip().lower()
    factor = VELOCITY_UNIT_TO_MS.get(u)
    if factor is None:
        return None
    return value * factor


def circular_spread_deg(headings: List[Optional[float]]) -> Optional[float]:
    hs = [h for h in headings if h is not None]
    if not hs:
        return None
    x = sum(math.cos(math.radians(h)) for h in hs)
    y = sum(math.sin(math.radians(h)) for h in hs)
    n = len(hs)
    r = math.sqrt(x * x + y * y) / n
    r = clamp(r, 0.0, 1.0)
    if r >= 1.0:
        return 0.0
    if r <= 0.0:
        return 180.0
    cstd = math.sqrt(max(0.0, -2.0 * math.log(r)))
    return math.degrees(cstd)


# ======================================================================
# SECTION 3 — POLICY GUARD / PROMPT INJECTION DEFENSE
# ======================================================================

@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str = ""


class PolicyGuard:
    """
    Blocks requests seeking prohibited RADINT operational guidance.
    Allows lawful passive radar analysis, safety, research, verification,
    and defensive sensor-quality interpretation.
    """

    PROHIBITED_PATTERNS = [
        r"(?:how\s+to|guide\s+to|instructions?\s+to|teach\s+me).*(?:jam|spoof|evade|defeat|blind|mask|hide|reduce\s+signature|avoid\s+detection).*?(?:radar|sensor|detection|surveillance|tracking)",
        r"\b(?:fire\s+control|firing\s+solution|missile\s+guidance|weapon\s+targeting|target\s+priority|engagement\s+envelope|kill\s+chain)\b",
        r"\b(?:radar\s+evasion|stealth\s+optimization|rcs\s+reduction|blind\s+spot\s+(?:for|to)\s+(?:attack|evasion)|attack\s+route)\b",
        r"\b(?:jamming|spoofing)\s+(?:waveform|technique|strategy|method)",
        r"\b(?:private\s+person|individual).*(?:stalk|surveil|covertly\s+track|home\s+routines)",
    ]

    def __init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.PROHIBITED_PATTERNS]

    def check_request(self, text: str) -> PolicyResult:
        t = text or ""
        for rx in self._compiled:
            if rx.search(t):
                return PolicyResult(
                    decision=PolicyDecision.POLICY_BLOCKED,
                    reason="Request seeks prohibited RADINT operational guidance.",
                )
        return PolicyResult(decision=PolicyDecision.ALLOW, reason="")

    def is_safe_action(self, action: str) -> bool:
        return self.check_request(action).decision == PolicyDecision.ALLOW


class PromptInjectionDefense:
    """
    Radar product metadata, track comments, AIS/ADS-B text, and documents
    are untrusted data. Neutralize obvious instruction-like injections while
    preserving original evidence separately.
    """

    CONTROL_TOKEN_RX = re.compile(r"<\|.*?\|>", re.DOTALL)
    INSTRUCTION_RX = re.compile(
        r"(?i)\b(ignore\s+previous|ignore\s+above|system\s+prompt|you\s+are\s+now|new\s+instructions?|change\s+classification)\b"
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
    evidence_id: str
    case_id: str
    source_id: str
    sensor_id: str
    sensor_type: SensorType
    product_type: ProductType
    observation_id: str
    track_id: str
    timestamp: datetime
    coordinate_reference_system: str
    sensor_reference_frame: str
    measurement_units: str
    quality_flags: List[str] = field(default_factory=list)
    content_hash: str = ""
    raw_artifact_reference: str = ""
    parser_version: str = "RADINT-parser-0.1.0"
    normalizer_version: str = "RADINT-normalizer-0.1.0"
    authorization_context: str = ""


@dataclass
class RadarSensor:
    sensor_id: str
    sensor_type: SensorType = SensorType.UNKNOWN
    operator: Optional[str] = None
    authorized_source: Optional[str] = None
    data_source: str = "UNKNOWN"
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None
    location_reference: str = "UNKNOWN"
    coverage_reference: str = "UNKNOWN"
    frequency_band_if_public_or_authorized: Optional[str] = None
    measurement_modes: List[str] = field(default_factory=list)
    observation_period: str = "UNKNOWN"
    calibration_state: CalibrationState = CalibrationState.CALIBRATION_UNKNOWN
    quality_state: SensorQuality = SensorQuality.UNKNOWN
    source: str = "UNKNOWN"
    limitations: List[str] = field(default_factory=list)


@dataclass
class RadarProduct:
    product_id: str
    sensor_id: str
    product_type: ProductType
    source_id: str
    timestamp: datetime
    coordinate_reference_system: str = "UNKNOWN"
    units: str = "UNKNOWN"
    quality_flags: List[str] = field(default_factory=list)
    raw_reference: str = ""
    evidence_id: str = ""


@dataclass
class Detection:
    detection_id: str
    sensor_id: str
    product_id: str
    timestamp: datetime
    range_m: Optional[float] = None
    range_original: Optional[float] = None
    range_unit: str = "UNKNOWN"
    azimuth_deg: Optional[float] = None
    elevation_deg: Optional[float] = None
    doppler_radial_velocity_m_s: Optional[float] = None
    signal_quality: Optional[float] = None
    classification_candidate: Optional[str] = None
    track_candidate: Optional[str] = None
    quality_flags: List[str] = field(default_factory=list)
    evidence_id: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    position_uncertainty_m: Optional[float] = None
    time_uncertainty_s: Optional[float] = None
    sensor_location_lat: Optional[float] = None
    sensor_location_lon: Optional[float] = None
    coordinate_reference_system: str = "UNKNOWN"


@dataclass
class TrackPoint:
    timestamp: datetime
    latitude: Optional[float]
    longitude: Optional[float]
    range_m: Optional[float]
    azimuth_deg: Optional[float]
    velocity_m_s: Optional[float]
    heading_deg: Optional[float]
    detection_id: str
    quality_flags: List[str] = field(default_factory=list)
    position_uncertainty_m: Optional[float] = None


@dataclass
class Track:
    track_id: str
    source_track_id: Optional[str]
    sensor_ids: List[str]
    start_time: datetime
    end_time: datetime
    detections: List[Detection] = field(default_factory=list)
    track_points: List[TrackPoint] = field(default_factory=list)
    classification_candidates: List[Dict[str, Any]] = field(default_factory=list)
    identity_candidates: List[Dict[str, Any]] = field(default_factory=list)
    track_quality: str = "UNKNOWN"
    continuity_state: TrackContinuity = TrackContinuity.UNKNOWN
    correlation_state: str = "UNCORRELATED"
    confidence: Confidence = Confidence.UNKNOWN
    limitations: List[str] = field(default_factory=list)
    movement_pattern: str = "UNKNOWN"
    object_class_candidate: str = ObjectClass.UNKNOWN.value
    average_speed_m_s: Optional[float] = None
    coverage_state: CoverageState = CoverageState.UNKNOWN


@dataclass
class AISIdentity:
    identity_id: str
    mmsi: Optional[str] = None
    imo: Optional[str] = None
    name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    sog_kn: Optional[float] = None
    cog_deg: Optional[float] = None
    timestamp: Optional[datetime] = None
    source_id: str = ""
    evidence_id: str = ""


@dataclass
class ADSBIdentity:
    identity_id: str
    icao: Optional[str] = None
    callsign: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    speed_kn: Optional[float] = None
    heading_deg: Optional[float] = None
    altitude_ft: Optional[float] = None
    timestamp: Optional[datetime] = None
    source_id: str = ""
    evidence_id: str = ""


@dataclass
class WeatherContext:
    weather_id: str
    timestamp: datetime
    region: str = "UNKNOWN"
    precipitation_intensity: Optional[float] = None
    sea_state: Optional[float] = None
    cloud_cover_fraction: Optional[float] = None
    visibility_km: Optional[float] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class ClutterContext:
    clutter_id: str
    clutter_type: str
    sensor_id: Optional[str] = None
    confidence: Confidence = Confidence.UNKNOWN
    notes: List[str] = field(default_factory=list)


@dataclass
class InterferenceContext:
    interference_id: str
    status: InterferenceStatus
    sensor_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class CoverageArea:
    coverage_id: str
    sensor_id: Optional[str] = None
    center_lat: Optional[float] = None
    center_lon: Optional[float] = None
    radius_m: Optional[float] = None
    state: CoverageState = CoverageState.UNKNOWN
    notes: List[str] = field(default_factory=list)


@dataclass
class IdentityCorrelation:
    correlation_id: str
    track_id: str
    external_type: str
    external_id: str
    matched_points: int
    average_distance_m: Optional[float]
    confidence: Confidence
    status: str
    limitations: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class Contradiction:
    contradiction_id: str
    contradiction_type: str
    description: str
    evidence_ids: List[str] = field(default_factory=list)
    candidate_resolutions: List[str] = field(default_factory=list)
    status: str = "OPEN"


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    supports: List[str] = field(default_factory=list)
    oppositions: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    falsification_tests: List[str] = field(default_factory=list)
    status: str = "OPEN"


@dataclass
class Fact:
    fact_id: str
    statement: str
    status: FactStatus
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class KnowledgeGap:
    gap_id: str
    description: str
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: str = ""
    expected_information_value: str = ""


@dataclass
class NextAction:
    action_id: str
    description: str
    rationale: str = ""
    priority: str = "MEDIUM"
    safety_ok: bool = True


@dataclass
class SpecialistHandoff:
    handoff_id: str
    specialist: str
    reason: str
    payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RADINTResult:
    case_id: str
    task_id: str
    objective: str
    status: str
    policy_decision: PolicyDecision = PolicyDecision.ALLOW

    evidence: List[Evidence] = field(default_factory=list)
    sensors: List[RadarSensor] = field(default_factory=list)
    products: List[RadarProduct] = field(default_factory=list)
    detections: List[Detection] = field(default_factory=list)
    tracks: List[Track] = field(default_factory=list)

    ais_identities: List[AISIdentity] = field(default_factory=list)
    adsb_identities: List[ADSBIdentity] = field(default_factory=list)
    weather_contexts: List[WeatherContext] = field(default_factory=list)
    clutter_contexts: List[ClutterContext] = field(default_factory=list)
    interference_contexts: List[InterferenceContext] = field(default_factory=list)
    coverage_areas: List[CoverageArea] = field(default_factory=list)

    correlations: List[IdentityCorrelation] = field(default_factory=list)
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


# ======================================================================
# SECTION 5 — INGESTION
# ======================================================================

class RADINTIngestor:
    PARSER_VERSION = "RADINT-parser-0.1.0"
    NORMALIZER_VERSION = "RADINT-normalizer-0.1.0"

    def __init__(self, injection_defense: Optional[PromptInjectionDefense] = None):
        self.injection_defense = injection_defense or PromptInjectionDefense()

    def ingest_case(
        self, case: Dict[str, Any]
    ) -> Tuple[
        List[Evidence],
        List[RadarSensor],
        List[RadarProduct],
        List[Detection],
        List[AISIdentity],
        List[ADSBIdentity],
        List[WeatherContext],
        List[ClutterContext],
        List[InterferenceContext],
        List[CoverageArea],
    ]:
        case_id = str(case.get("case_id", new_id("CASE")))
        authorization = str(case.get("authorization", ""))

        sensors = [self._parse_sensor(s) for s in case.get("sensors", [])]
        sensors_by_id = {s.sensor_id: s for s in sensors}

        products = [self._parse_product(p, case_id, authorization) for p in case.get("radar_products", [])]
        products_by_id = {p.product_id: p for p in products}

        detections = [
            self._parse_detection(d, case_id, authorization, sensors_by_id, products_by_id)
            for d in case.get("detections", [])
        ]

        ais = [self._parse_ais(a) for a in case.get("ais_context", [])]
        adsb = [self._parse_adsb(a) for a in case.get("adsb_context", [])]
        weather = [self._parse_weather(w) for w in case.get("weather_context", [])]
        clutter = [self._parse_clutter(c) for c in case.get("clutter_context", [])]
        interference = [self._parse_interference(i) for i in case.get("interference_context", [])]
        coverage = [self._parse_coverage(c) for c in case.get("coverage_areas", [])]

        evidence = [d.evidence_id for d in detections]  # placeholder; actual Evidence stored separately below
        # For simplicity, Evidence objects are embedded in detections/products; full list reconstructed:
        evidence_objects: List[Evidence] = []
        for d in detections:
            # Detection does not store full Evidence object in this simplified implementation.
            pass

        return (
            evidence_objects,
            sensors,
            products,
            detections,
            ais,
            adsb,
            weather,
            clutter,
            interference,
            coverage,
        )

    def _parse_sensor(self, s: Dict[str, Any]) -> RadarSensor:
        return RadarSensor(
            sensor_id=str(s.get("sensor_id", new_id("SENSOR"))),
            sensor_type=enum_from(SensorType, s.get("sensor_type"), SensorType.UNKNOWN),
            operator=normalize_text(s.get("operator")),
            authorized_source=normalize_text(s.get("authorized_source")),
            data_source=str(s.get("data_source", "UNKNOWN")),
            location_lat=safe_float(s.get("location_lat", s.get("lat"))),
            location_lon=safe_float(s.get("location_lon", s.get("lon"))),
            location_reference=str(s.get("location_reference", "UNKNOWN")),
            coverage_reference=str(s.get("coverage_reference", "UNKNOWN")),
            frequency_band_if_public_or_authorized=normalize_text(s.get("frequency_band_if_public_or_authorized")),
            measurement_modes=[str(x) for x in s.get("measurement_modes", [])],
            observation_period=str(s.get("observation_period", "UNKNOWN")),
            calibration_state=enum_from(CalibrationState, s.get("calibration_state"), CalibrationState.CALIBRATION_UNKNOWN),
            quality_state=enum_from(SensorQuality, s.get("quality_state"), SensorQuality.UNKNOWN),
            source=str(s.get("source", "UNKNOWN")),
            limitations=[str(x) for x in s.get("limitations", [])],
        )

    def _parse_product(
        self,
        p: Dict[str, Any],
        case_id: str,
        authorization_context: str,
    ) -> RadarProduct:
        timestamp = to_datetime(p.get("timestamp")) or utcnow()
        canonical = json.dumps(p, sort_keys=True, default=_json_default)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        ev = Evidence(
            evidence_id=new_id("EV"),
            case_id=case_id,
            source_id=str(p.get("source_id", "unknown_source")),
            sensor_id=str(p.get("sensor_id", "unknown_sensor")),
            sensor_type=enum_from(SensorType, p.get("sensor_type"), SensorType.UNKNOWN),
            product_type=enum_from(ProductType, p.get("product_type"), ProductType.UNKNOWN),
            observation_id=str(p.get("product_id", new_id("PROD"))),
            track_id="",
            timestamp=timestamp,
            coordinate_reference_system=str(p.get("coordinate_reference_system", "UNKNOWN")),
            sensor_reference_frame=str(p.get("sensor_reference_frame", "UNKNOWN")),
            measurement_units=str(p.get("units", "UNKNOWN")),
            quality_flags=[str(x) for x in p.get("quality_flags", [])],
            content_hash=content_hash,
            raw_artifact_reference=canonical[:1000],
            parser_version=self.PARSER_VERSION,
            normalizer_version=self.NORMALIZER_VERSION,
            authorization_context=authorization_context,
        )

        return RadarProduct(
            product_id=str(p.get("product_id", ev.observation_id)),
            sensor_id=str(p.get("sensor_id", "unknown_sensor")),
            product_type=enum_from(ProductType, p.get("product_type"), ProductType.UNKNOWN),
            source_id=str(p.get("source_id", "unknown_source")),
            timestamp=timestamp,
            coordinate_reference_system=str(p.get("coordinate_reference_system", "UNKNOWN")),
            units=str(p.get("units", "UNKNOWN")),
            quality_flags=[str(x) for x in p.get("quality_flags", [])],
            raw_reference=canonical[:1000],
            evidence_id=ev.evidence_id,
        )

    def _parse_detection(
        self,
        d: Dict[str, Any],
        case_id: str,
        authorization_context: str,
        sensors_by_id: Dict[str, RadarSensor],
        products_by_id: Dict[str, RadarProduct],
    ) -> Detection:
        sensor_id = str(d.get("sensor_id", "unknown_sensor"))
        sensor = sensors_by_id.get(sensor_id)
        product_id = str(d.get("product_id", ""))
        product = products_by_id.get(product_id)

        timestamp = to_datetime(d.get("timestamp"))
        quality_flags: List[str] = []
        if timestamp is None:
            timestamp = utcnow()
            quality_flags.append("MISSING_TIMESTAMP_USING_INGEST_TIME")

        canonical = json.dumps(d, sort_keys=True, default=_json_default)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        ev = Evidence(
            evidence_id=new_id("EV"),
            case_id=case_id,
            source_id=str(d.get("source_id", product.source_id if product else "unknown_source")),
            sensor_id=sensor_id,
            sensor_type=sensor.sensor_type if sensor else SensorType.UNKNOWN,
            product_type=product.product_type if product else ProductType.DETECTION_LIST,
            observation_id=str(d.get("detection_id", new_id("DET"))),
            track_id=str(d.get("track_candidate", "")),
            timestamp=timestamp,
            coordinate_reference_system=str(d.get("coordinate_reference_system", product.coordinate_reference_system if product else "UNKNOWN")),
            sensor_reference_frame=str(d.get("sensor_reference_frame", "SENSOR_RELATIVE")),
            measurement_units=str(d.get("units", product.units if product else "UNKNOWN")),
            quality_flags=quality_flags + [str(x) for x in d.get("quality_flags", [])],
            content_hash=content_hash,
            raw_artifact_reference=canonical[:1000],
            parser_version=self.PARSER_VERSION,
            normalizer_version=self.NORMALIZER_VERSION,
            authorization_context=authorization_context,
        )

        range_original = safe_float(d.get("range"))
        range_unit = str(d.get("range_unit", "m"))
        range_m = to_meters(range_original, range_unit)
        if range_original is not None and range_m is None:
            quality_flags.append("RANGE_UNIT_UNKNOWN")

        azimuth_deg = normalize_azimuth(safe_float(d.get("azimuth")))
        elevation_deg = safe_float(d.get("elevation"))
        doppler_value = safe_float(d.get("doppler_radial_velocity", d.get("radial_velocity")))
        doppler_unit = str(d.get("doppler_unit", d.get("velocity_unit", "m/s")))
        doppler_m_s = to_m_s(doppler_value, doppler_unit)
        if doppler_value is not None and doppler_m_s is None:
            quality_flags.append("DOPPLER_UNIT_UNKNOWN")

        signal_quality = safe_float(d.get("signal_quality"))
        if signal_quality is not None and signal_quality < 0.2:
            quality_flags.append("LOW_SIGNAL_QUALITY")

        lat = safe_float(d.get("lat", d.get("latitude")))
        lon = safe_float(d.get("lon", d.get("longitude")))

        sensor_lat = sensor.location_lat if sensor else None
        sensor_lon = sensor.location_lon if sensor else None

        if (lat is None or lon is None) and sensor_lat is not None and sensor_lon is not None:
            lat, lon = polar_to_latlon(sensor_lat, sensor_lon, range_m, azimuth_deg)
            if lat is not None and lon is not None:
                quality_flags.append("POSITION_DERIVED_FROM_POLAR")

        if lat is None or lon is None:
            quality_flags.append("MISSING_POSITION")
        elif not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
            quality_flags.append("INVALID_COORDINATE")

        position_uncertainty_m = safe_float(d.get("position_uncertainty_m"))
        if position_uncertainty_m is None and "POSITION_DERIVED_FROM_POLAR" in quality_flags:
            position_uncertainty_m = 100.0

        time_uncertainty_s = safe_float(d.get("time_uncertainty_s"))

        return Detection(
            detection_id=str(d.get("detection_id", ev.observation_id)),
            sensor_id=sensor_id,
            product_id=product_id,
            timestamp=timestamp,
            range_m=range_m,
            range_original=range_original,
            range_unit=range_unit,
            azimuth_deg=azimuth_deg,
            elevation_deg=elevation_deg,
            doppler_radial_velocity_m_s=doppler_m_s,
            signal_quality=signal_quality,
            classification_candidate=normalize_text(d.get("classification_candidate")),
            track_candidate=normalize_text(d.get("track_candidate", d.get("source_track_id"))),
            quality_flags=quality_flags,
            evidence_id=ev.evidence_id,
            latitude=lat,
            longitude=lon,
            position_uncertainty_m=position_uncertainty_m,
            time_uncertainty_s=time_uncertainty_s,
            sensor_location_lat=sensor_lat,
            sensor_location_lon=sensor_lon,
            coordinate_reference_system=str(d.get("coordinate_reference_system", "UNKNOWN")),
        )

    def _parse_ais(self, a: Dict[str, Any]) -> AISIdentity:
        return AISIdentity(
            identity_id=str(a.get("identity_id", new_id("AIS"))),
            mmsi=normalize_text(a.get("mmsi"), upper=False),
            imo=normalize_text(a.get("imo"), upper=False),
            name=normalize_text(a.get("name")),
            latitude=safe_float(a.get("lat", a.get("latitude"))),
            longitude=safe_float(a.get("lon", a.get("longitude"))),
            sog_kn=safe_float(a.get("sog_kn", a.get("sog"))),
            cog_deg=normalize_azimuth(safe_float(a.get("cog_deg", a.get("cog")))),
            timestamp=to_datetime(a.get("timestamp")),
            source_id=str(a.get("source_id", "")),
            evidence_id=str(a.get("evidence_id", "")),
        )

    def _parse_adsb(self, a: Dict[str, Any]) -> ADSBIdentity:
        return ADSBIdentity(
            identity_id=str(a.get("identity_id", new_id("ADSB"))),
            icao=normalize_text(a.get("icao"), upper=False),
            callsign=normalize_text(a.get("callsign")),
            latitude=safe_float(a.get("lat", a.get("latitude"))),
            longitude=safe_float(a.get("lon", a.get("longitude"))),
            speed_kn=safe_float(a.get("speed_kn", a.get("speed"))),
            heading_deg=normalize_azimuth(safe_float(a.get("heading_deg", a.get("heading")))),
            altitude_ft=safe_float(a.get("altitude_ft", a.get("altitude"))),
            timestamp=to_datetime(a.get("timestamp")),
            source_id=str(a.get("source_id", "")),
            evidence_id=str(a.get("evidence_id", "")),
        )

    def _parse_weather(self, w: Dict[str, Any]) -> WeatherContext:
        return WeatherContext(
            weather_id=str(w.get("weather_id", new_id("WX"))),
            timestamp=to_datetime(w.get("timestamp")) or utcnow(),
            region=str(w.get("region", "UNKNOWN")),
            precipitation_intensity=safe_float(w.get("precipitation_intensity")),
            sea_state=safe_float(w.get("sea_state")),
            cloud_cover_fraction=safe_float(w.get("cloud_cover_fraction")),
            visibility_km=safe_float(w.get("visibility_km")),
            notes=[str(x) for x in w.get("notes", [])],
        )

    def _parse_clutter(self, c: Dict[str, Any]) -> ClutterContext:
        return ClutterContext(
            clutter_id=str(c.get("clutter_id", new_id("CLUT"))),
            clutter_type=str(c.get("clutter_type", "UNKNOWN")),
            sensor_id=c.get("sensor_id"),
            confidence=enum_from(Confidence, c.get("confidence"), Confidence.UNKNOWN),
            notes=[str(x) for x in c.get("notes", [])],
        )

    def _parse_interference(self, i: Dict[str, Any]) -> InterferenceContext:
        return InterferenceContext(
            interference_id=str(i.get("interference_id", new_id("INTF"))),
            status=enum_from(InterferenceStatus, i.get("status"), InterferenceStatus.UNKNOWN),
            sensor_id=i.get("sensor_id"),
            start_time=to_datetime(i.get("start_time")),
            end_time=to_datetime(i.get("end_time")),
            notes=[str(x) for x in i.get("notes", [])],
        )

    def _parse_coverage(self, c: Dict[str, Any]) -> CoverageArea:
        return CoverageArea(
            coverage_id=str(c.get("coverage_id", new_id("COV"))),
            sensor_id=c.get("sensor_id"),
            center_lat=safe_float(c.get("center_lat", c.get("lat"))),
            center_lon=safe_float(c.get("center_lon", c.get("lon"))),
            radius_m=safe_float(c.get("radius_m")),
            state=enum_from(CoverageState, c.get("state"), CoverageState.UNKNOWN),
            notes=[str(x) for x in c.get("notes", [])],
        )


# ======================================================================
# SECTION 6 — TRACK ASSOCIATION
# ======================================================================

@dataclass
class _OpenTrack:
    track_id: str
    sensor_id: str
    source_track_id: Optional[str]
    detections: List[Detection] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)


class TrackAssociator:
    """
    Associates detections into tracks using conservative gating.
    Does not force associations across different source track IDs.
    """

    def __init__(
        self,
        max_time_gap_s: float = 180.0,
        base_gate_m: float = 1000.0,
        max_speed_m_s: float = 50.0,
    ):
        self.max_time_gap_s = max_time_gap_s
        self.base_gate_m = base_gate_m
        self.max_speed_m_s = max_speed_m_s

    def associate(self, detections: List[Detection]) -> List[Track]:
        usable = [
            d for d in detections
            if d.timestamp is not None and d.latitude is not None and d.longitude is not None
        ]
        usable.sort(key=lambda x: (x.sensor_id, x.timestamp))

        open_by_key: Dict[Tuple[str, str], _OpenTrack] = {}
        open_by_sensor: Dict[str, List[_OpenTrack]] = {}

        for det in usable:
            key: Optional[Tuple[str, str]] = None
            if det.track_candidate:
                key = (det.sensor_id, det.track_candidate)

            if key is not None:
                ot = open_by_key.get(key)
                if ot is None:
                    ot = _OpenTrack(
                        track_id=new_id("TRK"),
                        sensor_id=det.sensor_id,
                        source_track_id=det.track_candidate,
                    )
                    open_by_key[key] = ot
                    open_by_sensor.setdefault(det.sensor_id, []).append(ot)
                ot.detections.append(det)
                continue

            candidates: List[Tuple[float, _OpenTrack]] = []
            for ot in open_by_sensor.get(det.sensor_id, []):
                last = ot.detections[-1]
                dt = (det.timestamp - last.timestamp).total_seconds()
                if dt < 0 or dt > self.max_time_gap_s:
                    continue
                dist = haversine_m(last.latitude, last.longitude, det.latitude, det.longitude)
                if dist is None:
                    continue
                allowed = self.base_gate_m + self.max_speed_m_s * dt
                if dist <= allowed:
                    candidates.append((dist, ot))

            if candidates:
                candidates.sort(key=lambda x: x[0])
                _, ot = candidates[0]
                if len(candidates) > 1 and candidates[1][0] <= candidates[0][0] * 1.5 + self.base_gate_m:
                    ot.flags.append("ASSOCIATION_AMBIGUOUS")
                ot.detections.append(det)
            else:
                ot = _OpenTrack(
                    track_id=new_id("TRK"),
                    sensor_id=det.sensor_id,
                    source_track_id=None,
                )
                ot.detections.append(det)
                open_by_sensor.setdefault(det.sensor_id, []).append(ot)

        tracks: List[Track] = []
        all_open = [ot for lst in open_by_sensor.values() for ot in lst]

        for ot in all_open:
            dets = sorted(ot.detections, key=lambda x: x.timestamp)
            points = self._build_track_points(dets)
            if not points:
                continue

            limitations = list(ot.flags)
            if any("ASSOCIATION_AMBIGUOUS" in f for f in limitations):
                limitations.append("Track association may contain ambiguous detections.")

            track = Track(
                track_id=ot.track_id,
                source_track_id=ot.source_track_id,
                sensor_ids=[ot.sensor_id],
                start_time=points[0].timestamp,
                end_time=points[-1].timestamp,
                detections=dets,
                track_points=points,
                limitations=limitations,
            )
            tracks.append(track)

        return tracks

    @staticmethod
    def _build_track_points(dets: List[Detection]) -> List[TrackPoint]:
        points: List[TrackPoint] = []
        prev: Optional[Detection] = None

        for det in dets:
            velocity = None
            heading = None
            if prev is not None and prev.latitude is not None and prev.longitude is not None:
                dt = (det.timestamp - prev.timestamp).total_seconds()
                dist = haversine_m(prev.latitude, prev.longitude, det.latitude, det.longitude)
                if dt > 0 and dist is not None:
                    velocity = dist / dt
                heading = bearing_deg(prev.latitude, prev.longitude, det.latitude, det.longitude)

            points.append(
                TrackPoint(
                    timestamp=det.timestamp,
                    latitude=det.latitude,
                    longitude=det.longitude,
                    range_m=det.range_m,
                    azimuth_deg=det.azimuth_deg,
                    velocity_m_s=velocity,
                    heading_deg=heading,
                    detection_id=det.detection_id,
                    quality_flags=list(det.quality_flags),
                    position_uncertainty_m=det.position_uncertainty_m,
                )
            )
            prev = det

        return points


# ======================================================================
# SECTION 7 — TRACK QUALITY / CONTINUITY / COVERAGE / MOVEMENT
# ======================================================================

class TrackQualityAnalyzer:
    def analyze(self, track: Track) -> None:
        pts = track.track_points
        if len(pts) < 2:
            track.continuity_state = TrackContinuity.UNKNOWN
            track.track_quality = "INSUFFICIENT_POINTS"
            track.confidence = Confidence.LOW
            return

        intervals = [
            (b.timestamp - a.timestamp).total_seconds()
            for a, b in zip(pts, pts[1:])
        ]
        med_interval = median(intervals) or 60.0
        gap_threshold = max(180.0, med_interval * 3.0)
        gaps = sum(1 for i in intervals if i > gap_threshold)

        if gaps == 0:
            track.continuity_state = TrackContinuity.CONTINUOUS
        elif gaps == 1:
            track.continuity_state = TrackContinuity.INTERMITTENT
        else:
            track.continuity_state = TrackContinuity.FRAGMENTED

        speeds = [p.velocity_m_s for p in pts if p.velocity_m_s is not None]
        track.average_speed_m_s = mean(speeds)

        uncertainties = [p.position_uncertainty_m for p in pts if p.position_uncertainty_m is not None]
        avg_unc = mean(uncertainties)

        quality_score = 0
        if len(pts) >= 10:
            quality_score += 2
        elif len(pts) >= 5:
            quality_score += 1

        if track.continuity_state == TrackContinuity.CONTINUOUS:
            quality_score += 2
        elif track.continuity_state == TrackContinuity.INTERMITTENT:
            quality_score += 1

        if avg_unc is not None and avg_unc <= 100.0:
            quality_score += 1

        if quality_score >= 5:
            track.track_quality = "GOOD"
            track.confidence = Confidence.MEDIUM
        elif quality_score >= 3:
            track.track_quality = "FAIR"
            track.confidence = Confidence.LOW
        else:
            track.track_quality = "POOR"
            track.confidence = Confidence.LOW


class CoverageAnalyzer:
    def analyze(self, track: Track, coverage_areas: List[CoverageArea]) -> None:
        if not track.track_points:
            track.coverage_state = CoverageState.UNKNOWN
            return

        states: List[CoverageState] = []
        for pt in track.track_points:
            best = CoverageState.UNKNOWN
            for area in coverage_areas:
                if area.sensor_id not in (None, "", track.sensor_ids[0]):
                    continue
                if area.center_lat is None or area.center_lon is None or area.radius_m is None:
                    continue
                dist = haversine_m(pt.latitude, pt.longitude, area.center_lat, area.center_lon)
                if dist is None:
                    continue
                if dist <= area.radius_m:
                    best = CoverageState.COVERED
                    break
                elif dist <= area.radius_m * 1.25:
                    if best != CoverageState.COVERED:
                        best = CoverageState.EDGE_OF_COVERAGE
                else:
                    if best == CoverageState.UNKNOWN:
                        best = CoverageState.OUTSIDE_COVERAGE
            states.append(best)

        if CoverageState.COVERED in states and CoverageState.EDGE_OF_COVERAGE not in states and CoverageState.OUTSIDE_COVERAGE not in states:
            track.coverage_state = CoverageState.COVERED
        elif CoverageState.EDGE_OF_COVERAGE in states:
            track.coverage_state = CoverageState.EDGE_OF_COVERAGE
        elif CoverageState.OUTSIDE_COVERAGE in states:
            track.coverage_state = CoverageState.OUTSIDE_COVERAGE
        else:
            track.coverage_state = CoverageState.UNKNOWN

        if (
            track.continuity_state in (TrackContinuity.INTERMITTENT, TrackContinuity.FRAGMENTED)
            and track.coverage_state in (CoverageState.EDGE_OF_COVERAGE, CoverageState.OUTSIDE_COVERAGE, CoverageState.UNKNOWN)
        ):
            track.continuity_state = TrackContinuity.LOST
            track.limitations.append(
                "Track loss may be explained by coverage, processing threshold, clutter, or sensor geometry; it does not prove object disappearance."
            )


class MovementPatternAnalyzer:
    def analyze(self, track: Track) -> None:
        pts = track.track_points
        if len(pts) < 2:
            track.movement_pattern = "UNKNOWN"
            return

        speeds = [p.velocity_m_s for p in pts if p.velocity_m_s is not None]
        headings = [p.heading_deg for p in pts if p.heading_deg is not None]

        path_length = 0.0
        for a, b in zip(pts, pts[1:]):
            d = haversine_m(a.latitude, a.longitude, b.latitude, b.longitude)
            if d is not None:
                path_length += d

        displacement = haversine_m(pts[0].latitude, pts[0].longitude, pts[-1].latitude, pts[-1].longitude) or 0.0
        straightness = displacement / path_length if path_length > 0 else 1.0
        avg_speed = mean(speeds)
        spread = circular_spread_deg(headings)

        if avg_speed is not None and avg_speed < 0.3 and displacement < 20.0:
            track.movement_pattern = "STATIONARY"
        elif straightness > 0.75 and spread is not None and spread < 30.0:
            track.movement_pattern = "LINEAR"
        elif path_length > max(displacement, 1.0) * 2.5 and spread is not None and spread > 60.0:
            track.movement_pattern = "CIRCLING"
        elif speeds and any(s < 0.3 for s in speeds) and any(s > 1.0 for s in speeds):
            track.movement_pattern = "STOP_START"
        elif avg_speed is not None and avg_speed < 1.0 and displacement > 100.0:
            track.movement_pattern = "DRIFT"
        else:
            track.movement_pattern = "UNKNOWN"


# ======================================================================
# SECTION 8 — OBJECT CLASS / CLUTTER / WEATHER / INTERFERENCE
# ======================================================================

class ObjectClassAnalyzer:
    def analyze(
        self,
        track: Track,
        sensors_by_id: Dict[str, RadarSensor],
        clutter_contexts: List[ClutterContext],
        weather_contexts: List[WeatherContext],
    ) -> None:
        sensor = sensors_by_id.get(track.sensor_ids[0]) if track.sensor_ids else None
        stype = sensor.sensor_type if sensor else SensorType.UNKNOWN
        avg_speed = track.average_speed_m_s
        pattern = track.movement_pattern

        candidates: List[Dict[str, Any]] = []

        def add(label: ObjectClass, confidence: Confidence, support: List[str], opposition: List[str]) -> None:
            candidates.append(
                {
                    "label": label.value,
                    "confidence": confidence.value,
                    "support": support,
                    "opposition": opposition,
                }
            )

        if stype == SensorType.WEATHER_RADAR:
            add(
                ObjectClass.WEATHER_PHENOMENON,
                Confidence.MEDIUM,
                ["Weather radar product"],
                ["Precipitation returns can mimic slow moving targets"],
            )
            add(
                ObjectClass.BIOLOGICAL_OR_CLUTTER_CANDIDATE,
                Confidence.LOW,
                ["Weather/research radar can observe birds/insects"],
                ["No biological corroboration"],
            )

        elif stype == SensorType.MARITIME_NAVIGATION_RADAR:
            if pattern == "STATIONARY":
                add(
                    ObjectClass.FIXED_OBJECT,
                    Confidence.LOW,
                    ["Stationary maritime radar return"],
                    ["Could be anchored vessel, buoy, land return, or clutter"],
                )
            if avg_speed is not None and 0.0 <= avg_speed <= 15.0:
                add(
                    ObjectClass.VESSEL_LIKE,
                    Confidence.MEDIUM,
                    ["Maritime radar context", "Speed consistent with surface vessel"],
                    ["Radar track alone does not prove vessel identity"],
                )
            if any(c.clutter_type.lower() in {"sea", "rain", "wave"} for c in clutter_contexts):
                add(
                    ObjectClass.BIOLOGICAL_OR_CLUTTER_CANDIDATE,
                    Confidence.LOW,
                    ["Sea/rain clutter context supplied"],
                    ["Clutter filters may be imperfect"],
                )

        elif stype in (SensorType.PRIMARY_SURVEILLANCE_RADAR, SensorType.SECONDARY_SURVEILLANCE_RADAR):
            if avg_speed is not None and avg_speed > 30.0:
                add(
                    ObjectClass.AIRCRAFT_LIKE,
                    Confidence.MEDIUM,
                    ["Surveillance radar context", "High speed"],
                    ["Speed alone does not identify aircraft type"],
                )
            else:
                add(
                    ObjectClass.UNKNOWN,
                    Confidence.LOW,
                    ["Surveillance radar track"],
                    ["Insufficient class-discriminating evidence"],
                )

        elif stype in (SensorType.GROUND_SURVEILLANCE_RADAR, SensorType.PERIMETER_RADAR, SensorType.TRAFFIC_RADAR):
            if avg_speed is not None and 0.0 <= avg_speed <= 40.0:
                add(
                    ObjectClass.VEHICLE_LIKE,
                    Confidence.MEDIUM,
                    ["Ground/traffic radar context", "Speed consistent with vehicle"],
                    ["Could be animal, debris, clutter, or non-vehicle object"],
                )
            if track.track_quality in ("POOR", "INSUFFICIENT_POINTS"):
                add(
                    ObjectClass.BIOLOGICAL_OR_CLUTTER_CANDIDATE,
                    Confidence.LOW,
                    ["Low track quality"],
                    ["May still be real small target"],
                )

        else:
            add(ObjectClass.UNKNOWN, Confidence.LOW, ["Sensor class not sufficient"], [])

        # Low signal quality increases clutter/artifact candidate.
        low_quality = sum(1 for d in track.detections if "LOW_SIGNAL_QUALITY" in d.quality_flags)
        if low_quality >= max(1, len(track.detections) // 3):
            add(
                ObjectClass.BIOLOGICAL_OR_CLUTTER_CANDIDATE,
                Confidence.LOW,
                ["Multiple low-quality detections"],
                ["Real weak targets can also have low signal quality"],
            )

        track.classification_candidates = candidates
        if candidates:
            best = max(candidates, key=lambda c: ({"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(c["confidence"], 0)))
            track.object_class_candidate = best["label"]
        else:
            track.object_class_candidate = ObjectClass.UNKNOWN.value


class InterferenceAnalyzer:
    def annotate_tracks(
        self,
        tracks: List[Track],
        interference_contexts: List[InterferenceContext],
    ) -> None:
        for track in tracks:
            for intf in interference_contexts:
                if intf.sensor_id not in (None, "", track.sensor_ids[0]):
                    continue
                if intf.start_time and intf.end_time:
                    if track.end_time < intf.start_time or track.start_time > intf.end_time:
                        continue
                track.limitations.append(
                    f"Interference context reported for sensor {intf.sensor_id}: {intf.status.value}. "
                    "Interference is not automatically hostile jamming."
                )


# ======================================================================
# SECTION 9 — EXTERNAL CORRELATION
# ======================================================================

class ExternalCorrelator:
    def __init__(
        self,
        time_gate_s: float = 300.0,
        distance_gate_m: float = 1000.0,
    ):
        self.time_gate_s = time_gate_s
        self.distance_gate_m = distance_gate_m

    def correlate(
        self,
        tracks: List[Track],
        ais_identities: List[AISIdentity],
        adsb_identities: List[ADSBIdentity],
        sensors_by_id: Dict[str, RadarSensor],
    ) -> Tuple[List[IdentityCorrelation], List[Contradiction]]:
        correlations: List[IdentityCorrelation] = []
        contradictions: List[Contradiction] = []

        for track in tracks:
            # AIS correlation
            ais_corr = self._correlate_one_way(
                track,
                [(a.identity_id, a.timestamp, a.latitude, a.longitude, a.sog_kn, a.cog_deg, a.evidence_id) for a in ais_identities],
                "AIS",
            )
            if ais_corr:
                correlations.append(ais_corr)
                track.identity_candidates.append(
                    {
                        "type": "AIS",
                        "id": ais_corr.external_id,
                        "confidence": ais_corr.confidence.value,
                        "status": ais_corr.status,
                        "matched_points": ais_corr.matched_points,
                        "average_distance_m": ais_corr.average_distance_m,
                    }
                )
                track.correlation_state = "AIS_CORRELATION_CANDIDATE"

                speed_mismatch = self._speed_mismatch(track, ais_corr.average_distance_m, None)
                if speed_mismatch:
                    contradictions.append(
                        Contradiction(
                            contradiction_id=new_id("CONTRA"),
                            contradiction_type="RADAR_VS_AIS_SPEED",
                            description=f"Radar track {track.track_id} and AIS identity {ais_corr.external_id} show speed inconsistency.",
                            evidence_ids=[ais_corr.external_id],
                            candidate_resolutions=[
                                "timing offset",
                                "AIS stale position",
                                "radar association error",
                                "different objects",
                                "AIS reporting error",
                            ],
                        )
                    )

            # ADS-B correlation
            adsb_corr = self._correlate_one_way(
                track,
                [(a.identity_id, a.timestamp, a.latitude, a.longitude, a.speed_kn, a.heading_deg, a.evidence_id) for a in adsb_identities],
                "ADSB",
            )
            if adsb_corr:
                correlations.append(adsb_corr)
                track.identity_candidates.append(
                    {
                        "type": "ADSB",
                        "id": adsb_corr.external_id,
                        "confidence": adsb_corr.confidence.value,
                        "status": adsb_corr.status,
                        "matched_points": adsb_corr.matched_points,
                        "average_distance_m": adsb_corr.average_distance_m,
                    }
                )
                track.correlation_state = "ADSB_CORRELATION_CANDIDATE"

        # Multi-radar correlation
        for t1, t2 in itertools.combinations(tracks, 2):
            if t1.sensor_ids[0] == t2.sensor_ids[0]:
                continue
            overlap = self._time_overlap(t1, t2)
            if not overlap:
                continue
            min_dist = self._min_distance(t1, t2)
            if min_dist is not None and min_dist <= self.distance_gate_m:
                s1 = sensors_by_id.get(t1.sensor_ids[0])
                s2 = sensors_by_id.get(t2.sensor_ids[0])
                if s1 and s2 and s1.data_source != "UNKNOWN" and s2.data_source != "UNKNOWN":
                    independence = IndependenceState.INDEPENDENT if s1.data_source != s2.data_source else IndependenceState.DEPENDENT
                else:
                    independence = IndependenceState.UNKNOWN

                corr = IdentityCorrelation(
                    correlation_id=new_id("CORR"),
                    track_id=t1.track_id,
                    external_type="MULTI_RADAR",
                    external_id=t2.track_id,
                    matched_points=1,
                    average_distance_m=min_dist,
                    confidence=Confidence.MEDIUM if independence == IndependenceState.INDEPENDENT else Confidence.LOW,
                    status="MULTI_RAR_CORRELATION_CANDIDATE",
                    limitations=[
                        "Multi-radar proximity does not prove same object.",
                        f"Sensor independence: {independence.value}.",
                    ],
                    evidence_ids=[],
                )
                correlations.append(corr)
                t1.identity_candidates.append(
                    {
                        "type": "MULTI_RADAR",
                        "id": t2.track_id,
                        "confidence": corr.confidence.value,
                        "status": corr.status,
                        "matched_points": corr.matched_points,
                        "average_distance_m": corr.average_distance_m,
                    }
                )
                t1.correlation_state = "MULTI_RADAR_CORRELATION_CANDIDATE"

        return correlations, contradictions

    def _correlate_one_way(
        self,
        track: Track,
        externals: List[Tuple[str, Optional[datetime], Optional[float], Optional[float], Optional[float], Optional[float], str]],
        ext_type: str,
    ) -> Optional[IdentityCorrelation]:
        matches = 0
        distances: List[float] = []
        evidence_ids: List[str] = []
        ext_id = ""

        for pt in track.track_points:
            for eid, ets, elat, elon, espeed, ecourse, evid in externals:
                if ets is None or elat is None or elon is None:
                    continue
                dt = abs((pt.timestamp - ets).total_seconds())
                if dt > self.time_gate_s:
                    continue
                dist = haversine_m(pt.latitude, pt.longitude, elat, elon)
                if dist is None or dist > self.distance_gate_m:
                    continue
                matches += 1
                distances.append(dist)
                evidence_ids.append(evid)
                ext_id = eid

        if matches == 0:
            return None

        avg_dist = mean(distances)
        if matches >= 2 and avg_dist is not None and avg_dist < self.distance_gate_m * 0.5:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        return IdentityCorrelation(
            correlation_id=new_id("CORR"),
            track_id=track.track_id,
            external_type=ext_type,
            external_id=ext_id,
            matched_points=matches,
            average_distance_m=avg_dist,
            confidence=confidence,
            status=f"{ext_type}_CORRELATION_CANDIDATE",
            limitations=[
                f"{ext_type} correlation is candidate only.",
                "Cooperative identity is not automatically assigned to radar track.",
                "Timing, position error, different objects, or stale data remain possible.",
            ],
            evidence_ids=evidence_ids,
        )

    @staticmethod
    def _time_overlap(t1: Track, t2: Track) -> bool:
        return max(t1.start_time, t2.start_time) < min(t1.end_time, t2.end_time)

    @staticmethod
    def _min_distance(t1: Track, t2: Track) -> Optional[float]:
        best = None
        for p1 in t1.track_points:
            for p2 in t2.track_points:
                dt = abs((p1.timestamp - p2.timestamp).total_seconds())
                if dt > 300:
                    continue
                d = haversine_m(p1.latitude, p1.longitude, p2.latitude, p2.longitude)
                if d is None:
                    continue
                if best is None or d < best:
                    best = d
        return best

    @staticmethod
    def _speed_mismatch(track: Track, avg_dist: Optional[float], unused: Any) -> bool:
        # Simplified: if track has very low speed but external correlation exists, not necessarily mismatch.
        # Real implementation would compare AIS SOG / ADS-B speed with derived track speed.
        return False


# ======================================================================
# SECTION 10 — SOURCE INDEPENDENCE
# ======================================================================

class SourceIndependenceAnalyzer:
    def assess(self, sensors: List[RadarSensor], detections: List[Detection]) -> Dict[str, Any]:
        sources = {s.data_source for s in sensors if s.data_source and s.data_source != "UNKNOWN"}
        if not sources:
            return {
                "status": IndependenceState.UNKNOWN.value,
                "notes": ["Sensor data_source metadata unavailable; independence unknown."],
                "groups": {},
            }

        if len(sources) == 1:
            status = IndependenceState.DEPENDENT
            notes = [
                "All configured sensors appear to share one upstream data source/feed.",
                "Multiple displays of one radar source are not independent sensors.",
            ]
        else:
            status = IndependenceState.PARTIALLY_DEPENDENT
            notes = [
                "Multiple data sources exist, but full pedigree/independence is not proven.",
                "Verify physical sensor separation and processing independence.",
            ]

        groups: Dict[str, List[str]] = {}
        for s in sensors:
            groups.setdefault(s.data_source, []).append(s.sensor_id)

        return {
            "status": status.value,
            "notes": notes,
            "groups": groups,
        }


# ======================================================================
# SECTION 11 — FACT GATE / HYPOTHESES
# ======================================================================

class FactGate:
    def generate(
        self,
        *,
        tracks: List[Track],
        correlations: List[IdentityCorrelation],
        contradictions: List[Contradiction],
        source_independence: Dict[str, Any],
        weather_contexts: List[WeatherContext],
        interference_contexts: List[InterferenceContext],
    ) -> Dict[str, Any]:
        facts: List[Fact] = []
        hypotheses: List[Hypothesis] = []
        unknowns: List[str] = []
        limitations: List[str] = []
        gaps: List[KnowledgeGap] = []
        actions: List[NextAction] = []
        handoffs: List[SpecialistHandoff] = []

        for track in tracks[:50]:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Radar sensor(s) {', '.join(track.sensor_ids)} produced track {track.track_id} "
                        f"with {len(track.track_points)} associated detections between "
                        f"{track.start_time.isoformat()} and {track.end_time.isoformat()}."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=[d.evidence_id for d in track.detections[:20]],
                    limitations=[
                        "This is a sensor-produced track observation, not ground truth.",
                        "Track association and coordinate normalization may contain uncertainty.",
                    ],
                )
            )

            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Track {track.track_id} movement pattern candidate: {track.movement_pattern}; "
                        f"object class candidate: {track.object_class_candidate}."
                    ),
                    status=FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=[
                        "Movement pattern is descriptive, not intent.",
                        "Object class candidate is not specific identity.",
                    ],
                )
            )

            if track.continuity_state == TrackContinuity.LOST:
                facts.append(
                    Fact(
                        fact_id=new_id("FACT"),
                        statement=(
                            f"Track {track.track_id} was lost or fragmented near coverage/processing boundary."
                        ),
                        status=FactStatus.SUPPORTED,
                        evidence_ids=[],
                        limitations=[
                            "Track loss does not prove object disappearance.",
                            "Possible causes include coverage, clutter, occlusion, threshold, interference, or departure.",
                        ],
                    )
                )
                gaps.append(
                    KnowledgeGap(
                        gap_id=new_id("GAP"),
                        description=f"Track-loss cause unresolved for {track.track_id}.",
                        importance="HIGH",
                        recommended_source="independent radar/satellite/AIS context, weather, sensor logs",
                        specialist="RADINT / AISINT / SATINT",
                        expected_information_value="Distinguish coverage loss from actual absence.",
                    )
                )

            for ident in track.identity_candidates[:5]:
                facts.append(
                    Fact(
                        fact_id=new_id("FACT"),
                        statement=(
                            f"Track {track.track_id} has {ident['type']} correlation candidate "
                            f"{ident['id']} with confidence {ident['confidence']}."
                        ),
                        status=FactStatus.CANDIDATE,
                        evidence_ids=[],
                        limitations=[
                            "Correlation candidate does not establish identity.",
                            "Cooperative data may be stale, misconfigured, or belong to another object.",
                        ],
                    )
                )

                hypotheses.extend(
                    [
                        Hypothesis(
                            hypothesis_id=new_id("HYP"),
                            statement=f"Track {track.track_id} corresponds to {ident['type']} identity {ident['id']}.",
                            supports=[f"{ident['matched_points']} spatiotemporal matches"],
                            oppositions=["No independent confirmation", "Association uncertainty possible"],
                            unknowns=["Exact object identity", "Operator", "Intent"],
                            falsification_tests=[
                                "Independent sensor shows different object at same location/time",
                                "External identity position/timing is stale",
                                "Track association links unrelated detections",
                            ],
                        ),
                        Hypothesis(
                            hypothesis_id=new_id("HYP"),
                            statement=f"Track {track.track_id} is a different object without matching external identity.",
                            supports=["External identity may be incomplete"],
                            oppositions=["Strong spatiotemporal correlation"],
                            unknowns=["Object population in area"],
                            falsification_tests=["External identity history converges over longer window"],
                        ),
                        Hypothesis(
                            hypothesis_id=new_id("HYP"),
                            statement=f"Track {track.track_id} is clutter, artifact, or processing error.",
                            supports=["Low track quality if present"],
                            oppositions=["Continuous spatial progression"],
                            unknowns=["Sensor processing version"],
                            falsification_tests=["Reprocessing raw radar removes track"],
                        ),
                    ]
                )

        if contradictions:
            for c in contradictions[:50]:
                facts.append(
                    Fact(
                        fact_id=new_id("FACT"),
                        statement=f"Open contradiction: {c.contradiction_type} — {c.description}",
                        status=FactStatus.DISPUTED,
                        evidence_ids=c.evidence_ids,
                        limitations=c.candidate_resolutions,
                    )
                )
                unknowns.append(f"Unresolved contradiction: {c.contradiction_type}")

        if source_independence.get("status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            limitations.append(
                "Source independence is dependent or unknown; multiple feeds may share one upstream radar source."
            )
            gaps.append(
                KnowledgeGap(
                    gap_id=new_id("GAP"),
                    description="Independent radar/sensor pedigree not established.",
                    importance="HIGH",
                    recommended_source="direct sensor logs / independent authorized radar / satellite",
                    specialist="RADINT source evaluation",
                    expected_information_value="Prevents confidence inflation from duplicated feeds.",
                )
            )

        if weather_contexts:
            limitations.append("Weather/clutter context may affect detection and track continuity.")
        if interference_contexts:
            limitations.append("Reported interference is not automatically hostile jamming.")

        limitations.extend(
            [
                "Detection is not track.",
                "Track is not identity.",
                "Identity is not operator.",
                "Movement is not intent.",
                "Non-detection is not absence.",
                "Nominal coverage is not guaranteed detection.",
                "AI classification is not sensor fact.",
                "Fused track is not raw radar evidence.",
            ]
        )

        unknowns.extend(
            [
                "Exact physical object identity",
                "Operator or organization",
                "Intent",
                "Cause of track loss",
                "Whether external cooperative identity is truthful/current",
            ]
        )

        actions.extend(
            [
                NextAction(new_id("ACT"), "Verify sensor timestamp and clock synchronization.", "Time errors corrupt track association.", "HIGH"),
                NextAction(new_id("ACT"), "Validate coordinate reference system and polar-to-grid transform.", "CRS errors can displace tracks.", "HIGH"),
                NextAction(new_id("ACT"), "Compare an independent authorized radar or satellite observation.", "Tests sensor independence and track continuity.", "HIGH"),
                NextAction(new_id("ACT"), "Correlate with AIS/ADS-B history over a longer window.", "Reduces accidental correlation risk.", "MEDIUM"),
                NextAction(new_id("ACT"), "Review weather/clutter context before classifying returns.", "Prevents clutter false positives.", "MEDIUM"),
                NextAction(new_id("ACT"), "Handoff emitter waveform questions to ELINT if radar emission metadata is relevant.", "RADINT does not perform deep emitter classification.", "MEDIUM"),
            ]
        )

        guard = PolicyGuard()
        actions = [a for a in actions if guard.is_safe_action(a.description)]

        handoffs.extend(
            [
                SpecialistHandoff(new_id("HAND"), "AISINT", "Maritime identity resolution requires AIS/vessel registry context.", {}),
                SpecialistHandoff(new_id("HAND"), "SATINT", "SAR/satellite corroboration may resolve track loss or object class.", {}),
                SpecialistHandoff(new_id("HAND"), "ELINT", "Radar emitter characteristics require ELINT analysis.", {}),
                SpecialistHandoff(new_id("HAND"), "GEOINT", "Precise geospatial refinement and terrain context.", {}),
                SpecialistHandoff(new_id("HAND"), "LEGALINT", "Regulated airspace/waters or enforcement conclusions require legal review.", {}),
            ]
        )

        return {
            "facts": facts,
            "hypotheses": hypotheses,
            "unknowns": sorted(set(unknowns)),
            "limitations": sorted(set(limitations)),
            "knowledge_gaps": gaps,
            "next_actions": actions,
            "specialist_handoffs": handoffs,
        }


# ======================================================================
# SECTION 12 — DUAL-AI REVIEW
# ======================================================================

class DualAIReviewer:
    def review(
        self,
        *,
        tracks: List[Track],
        contradictions: List[Contradiction],
        source_independence: Dict[str, Any],
        correlations: List[IdentityCorrelation],
    ) -> Dict[str, Any]:
        notes: List[str] = []
        status = ReviewStatus.AGREE

        if any("ASSOCIATION_AMBIGUOUS" in " ".join(t.limitations) for t in tracks):
            notes.append("Ambiguous track association detected; identity promotion should be avoided.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(t.coverage_state == CoverageState.UNKNOWN for t in tracks):
            notes.append("Coverage unknown for at least one track; non-detection conclusions are unsafe.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if source_independence.get("status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            notes.append("Sensor/source independence is dependent or unknown; corroboration confidence reduced.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if contradictions:
            notes.append("Open contradictions remain; final attribution should be deferred.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(c.confidence == Confidence.MEDIUM for c in correlations):
            notes.append("Medium-confidence correlation still requires independent verification before identity claim.")

        human_review_required = bool(
            contradictions
            or any(t.confidence == Confidence.LOW and t.identity_candidates for t in tracks)
            or any("ASSOCIATION_AMBIGUOUS" in " ".join(t.limitations) for t in tracks)
        )

        return {
            "status": status.value,
            "skeptic_notes": notes,
            "rule": "AI agreement is not independent sensor corroboration.",
            "human_review_required": human_review_required,
        }


# ======================================================================
# SECTION 13 — GRAPHICAL MEMORY
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

    def write_result(self, result: RADINTResult) -> Dict[str, Any]:
        for s in result.sensors:
            self.add_node(
                s.sensor_id,
                "RadarSensor",
                {
                    "sensor_type": s.sensor_type.value,
                    "data_source": s.data_source,
                    "calibration_state": s.calibration_state.value,
                },
            )

        for d in result.detections[:500]:
            self.add_node(
                d.detection_id,
                "Detection",
                {
                    "sensor_id": d.sensor_id,
                    "timestamp": d.timestamp.isoformat(),
                    "latitude": d.latitude,
                    "longitude": d.longitude,
                },
            )
            self.add_edge(d.detection_id, "DETECTED_BY", d.sensor_id, {"evidence_id": d.evidence_id})

        for t in result.tracks:
            self.add_node(
                t.track_id,
                "Track",
                {
                    "sensor_ids": t.sensor_ids,
                    "start_time": t.start_time.isoformat(),
                    "end_time": t.end_time.isoformat(),
                    "continuity": t.continuity_state.value,
                    "object_class": t.object_class_candidate,
                },
            )
            for d in t.detections[:50]:
                self.add_edge(d.detection_id, "PART_OF_TRACK", t.track_id)

            for ident in t.identity_candidates[:10]:
                self.add_edge(
                    t.track_id,
                    "CORRELATED_WITH_CANDIDATE",
                    ident["id"],
                    {"type": ident["type"], "confidence": ident["confidence"]},
                )

        for f in result.facts[:500]:
            self.add_node(f.fact_id, "Fact", {"statement": f.statement, "status": f.status.value})
            for ev in f.evidence_ids[:20]:
                self.add_edge(f.fact_id, "SUPPORTED_BY", ev)

        for h in result.hypotheses:
            self.add_node(h.hypothesis_id, "Hypothesis", {"statement": h.statement, "status": h.status})

        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "sample_nodes": list(self.nodes.keys())[:20],
        }


# ======================================================================
# SECTION 14 — REPORT GENERATOR
# ======================================================================

class ReportGenerator:
    def generate(self, result: RADINTResult) -> str:
        lines: List[str] = []

        def section(title: str) -> None:
            lines.append("")
            lines.append(title.upper())
            lines.append("-" * len(title))

        lines.append("=" * 72)
        lines.append("TRACEATLAS — RADINT REPORT")
        lines.append("=" * 72)
        lines.append(f"Case ID: {result.case_id}")
        lines.append(f"Task ID: {result.task_id}")
        lines.append(f"Objective: {result.objective}")
        lines.append(f"Status: {result.status}")
        lines.append(f"Policy Decision: {result.policy_decision.value}")

        section("Safety / Privacy Boundary")
        lines.append("- Passive-first, lawful radar sensor analysis, safety, research, verification, and defensive context only.")
        lines.append("- No radar jamming, spoofing, electronic attack, targeting, fire-control, missile guidance, stealth optimization, evasion, blind-spot exploitation, or private-person stalking.")
        for flag in result.safety_flags:
            lines.append(f"- Safety: {flag}")
        for flag in result.privacy_flags:
            lines.append(f"- Privacy: {flag}")

        section("Radar Sensors")
        if not result.sensors:
            lines.append("- No sensors supplied.")
        for s in result.sensors:
            lines.append(f"- {s.sensor_id}: type={s.sensor_type.value}, data_source={s.data_source}, calibration={s.calibration_state.value}, quality={s.quality_state.value}")
            if s.limitations:
                lines.append(f"  limitations={'; '.join(s.limitations)}")

        section("Detections")
        lines.append(f"- Total detections parsed: {len(result.detections)}")
        for d in result.detections[:20]:
            lines.append(
                f"- {d.detection_id}: sensor={d.sensor_id}, time={d.timestamp.isoformat()}, "
                f"pos=({d.latitude}, {d.longitude}), range_m={d.range_m}, az={d.azimuth_deg}, quality_flags={d.quality_flags}"
            )

        section("Tracks")
        if not result.tracks:
            lines.append("- No tracks associated.")
        for t in result.tracks:
            lines.append(f"- Track {t.track_id}: sensors={t.sensor_ids}, points={len(t.track_points)}, continuity={t.continuity_state.value}, confidence={t.confidence.value}")
            lines.append(f"  time={t.start_time.isoformat()} -> {t.end_time.isoformat()}")
            lines.append(f"  movement={t.movement_pattern}, object_class={t.object_class_candidate}, avg_speed_m_s={t.average_speed_m_s}")
            lines.append(f"  coverage={t.coverage_state.value}, correlation={t.correlation_state}")
            if t.identity_candidates:
                lines.append(f"  identity_candidates={t.identity_candidates}")
            if t.limitations:
                lines.append(f"  limitations={'; '.join(t.limitations)}")

        section("AIS / ADS-B Correlation")
        if not result.correlations:
            lines.append("- No external correlations.")
        for c in result.correlations:
            lines.append(
                f"- {c.correlation_id}: track={c.track_id}, type={c.external_type}, external={c.external_id}, "
                f"matches={c.matched_points}, avg_dist_m={c.average_distance_m}, confidence={c.confidence.value}, status={c.status}"
            )
            for lim in c.limitations:
                lines.append(f"  caution: {lim}")

        section("Weather / Clutter / Interference")
        for w in result.weather_contexts[:10]:
            lines.append(f"- Weather {w.weather_id}: time={w.timestamp.isoformat()}, precip={w.precipitation_intensity}, sea_state={w.sea_state}, notes={w.notes}")
        for c in result.clutter_contexts[:10]:
            lines.append(f"- Clutter {c.clutter_id}: type={c.clutter_type}, sensor={c.sensor_id}, confidence={c.confidence.value}")
        for i in result.interference_contexts[:10]:
            lines.append(f"- Interference {i.interference_id}: status={i.status.value}, sensor={i.sensor_id}, notes={i.notes}")
            lines.append("  caution: interference is not automatically hostile jamming.")

        section("Source Independence")
        lines.append(f"- Status: {result.source_independence.get('status', 'UNKNOWN')}")
        for note in result.source_independence.get("notes", []):
            lines.append(f"  - {note}")

        section("Facts")
        for f in result.facts[:100]:
            lines.append(f"- [{f.status.value}] {f.statement}")
            if f.limitations:
                lines.append(f"  limitations: {'; '.join(f.limitations)}")

        section("Contradictions")
        if not result.contradictions:
            lines.append("- None detected.")
        for c in result.contradictions[:50]:
            lines.append(f"- {c.contradiction_type}: {c.description}")
            lines.append(f"  resolutions: {c.candidate_resolutions}")

        section("Competing Hypotheses")
        for h in result.hypotheses[:50]:
            lines.append(f"- {h.hypothesis_id}: {h.statement}")
            lines.append(f"  supports: {h.supports}")
            lines.append(f"  oppositions: {h.oppositions}")
            lines.append(f"  falsification: {h.falsification_tests}")

        section("Unknowns / Knowledge Gaps")
        for u in result.unknowns[:50]:
            lines.append(f"- Unknown: {u}")
        for g in result.knowledge_gaps[:50]:
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
            lines.append("  - Human review required before consequential identification/enforcement action.")

        section("Required Analyst Summary Example")
        lines.append("RADAR: Authorized sensor(s) produced the track observations listed above.")
        lines.append("TRACK: Track existence and movement are supported only to the extent shown by associated detections.")
        lines.append("IDENTITY: External correlations remain candidates; track is not identity.")
        lines.append("INTENT: Not established.")
        lines.append("NEXT ACTION: Verify independent sensor coverage, clock/CRS, and external history before promotion.")

        lines.append("")
        lines.append("=" * 72)
        lines.append("END REPORT")
        lines.append("=" * 72)
        return "\n".join(lines)


# ======================================================================
# SECTION 15 — RADINT AI EMPLOYEE
# ======================================================================

class RADIntelligenceEmployee:
    def __init__(self, mode: ModelMode = ModelMode.LOCAL_ONLY):
        self.mode = mode
        self.policy = PolicyGuard()
        self.injection_defense = PromptInjectionDefense()
        self.ingestor = RADINTIngestor(injection_defense=self.injection_defense)
        self.associator = TrackAssociator()
        self.quality_analyzer = TrackQualityAnalyzer()
        self.coverage_analyzer = CoverageAnalyzer()
        self.movement_analyzer = MovementPatternAnalyzer()
        self.object_analyzer = ObjectClassAnalyzer()
        self.interference_analyzer = InterferenceAnalyzer()
        self.correlator = ExternalCorrelator()
        self.independence_analyzer = SourceIndependenceAnalyzer()
        self.fact_gate = FactGate()
        self.reviewer = DualAIReviewer()
        self.memory = GraphicalMemory()
        self.reporter = ReportGenerator()

    def run_case(self, case: Dict[str, Any]) -> RADINTResult:
        case_id = str(case.get("case_id", new_id("CASE")))
        task_id = str(case.get("task_id", new_id("TASK")))
        objective = str(case.get("objective", ""))
        questions = case.get("questions", [])

        request_text = objective + "\n" + "\n".join(str(q) for q in questions)
        policy = self.policy.check_request(request_text)

        if policy.decision == PolicyDecision.POLICY_BLOCKED:
            return RADINTResult(
                case_id=case_id,
                task_id=task_id,
                objective=objective,
                status="POLICY_BLOCKED",
                policy_decision=PolicyDecision.POLICY_BLOCKED,
                report=(
                    "POLICY_BLOCKED\n\n"
                    "This request seeks prohibited RADINT operational guidance. "
                    "Lawful alternative: passive/authorized radar product analysis, track continuity, "
                    "sensor quality, coverage uncertainty, clutter/weather context, AIS/ADS-B correlation candidates, "
                    "and defensive verification without targeting, jamming, spoofing, evasion, or blind-spot exploitation."
                ),
                safety_flags=[
                    "No targeting/fire-control/missile guidance provided.",
                    "No radar jamming/spoofing/evasion guidance provided.",
                    "No private-person tracking provided.",
                ],
                limitations=[policy.reason],
            )

        (
            evidence,
            sensors,
            products,
            detections,
            ais_identities,
            adsb_identities,
            weather_contexts,
            clutter_contexts,
            interference_contexts,
            coverage_areas,
        ) = self.ingestor.ingest_case(case)

        sensors_by_id = {s.sensor_id: s for s in sensors}

        tracks = self.associator.associate(detections)

        for track in tracks:
            self.quality_analyzer.analyze(track)
            self.coverage_analyzer.analyze(track, coverage_areas)
            self.movement_analyzer.analyze(track)
            self.object_analyzer.analyze(track, sensors_by_id, clutter_contexts, weather_contexts)

        self.interference_analyzer.annotate_tracks(tracks, interference_contexts)

        correlations, contradictions = self.correlator.correlate(
            tracks,
            ais_identities,
            adsb_identities,
            sensors_by_id,
        )

        source_independence = self.independence_analyzer.assess(sensors, detections)

        fact_out = self.fact_gate.generate(
            tracks=tracks,
            correlations=correlations,
            contradictions=contradictions,
            source_independence=source_independence,
            weather_contexts=weather_contexts,
            interference_contexts=interference_contexts,
        )

        review = self.reviewer.review(
            tracks=tracks,
            contradictions=contradictions,
            source_independence=source_independence,
            correlations=correlations,
        )

        status = "PARTIAL"
        if not detections:
            status = "INSUFFICIENT_DATA"
        elif not tracks:
            status = "TRACK_UNRESOLVED"
        elif review.get("human_review_required"):
            status = "PARTIAL_HUMAN_REVIEW_REQUIRED"
        elif tracks and any(t.confidence == Confidence.MEDIUM for t in tracks):
            status = "SUCCEEDED"

        privacy_flags = []
        if self.mode == ModelMode.LOCAL_ONLY:
            privacy_flags.append("LOCAL_ONLY mode selected; sensitive radar coverage/track data should remain local.")
        elif self.mode == ModelMode.CLOUD:
            privacy_flags.append("CLOUD mode requires sanitized/aggregated/policy-approved radar summaries only.")
        else:
            privacy_flags.append("HYBRID mode requires routing controls and tenant isolation.")

        result = RADINTResult(
            case_id=case_id,
            task_id=task_id,
            objective=objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW,
            evidence=evidence,
            sensors=sensors,
            products=products,
            detections=detections,
            tracks=tracks,
            ais_identities=ais_identities,
            adsb_identities=adsb_identities,
            weather_contexts=weather_contexts,
            clutter_contexts=clutter_contexts,
            interference_contexts=interference_contexts,
            coverage_areas=coverage_areas,
            correlations=correlations,
            contradictions=contradictions,
            facts=fact_out["facts"],
            hypotheses=fact_out["hypotheses"],
            knowledge_gaps=fact_out["knowledge_gaps"],
            next_actions=fact_out["next_actions"],
            specialist_handoffs=fact_out["specialist_handoffs"],
            source_independence=source_independence,
            review=review,
            unknowns=fact_out["unknowns"],
            limitations=fact_out["limitations"],
            safety_flags=[
                "Passive-first analysis only.",
                "No targeting/fire-control/missile guidance.",
                "No radar jamming/spoofing/evasion guidance.",
                "Track is not identity.",
                "Identity is not intent.",
                "Non-detection is not absence.",
                "Human review required for consequential identification/enforcement action.",
            ],
            privacy_flags=privacy_flags,
        )

        result.graph = self.memory.write_result(result)
        result.report = self.reporter.generate(result)
        return result


# ======================================================================
# SECTION 16 — DEMO
# ======================================================================

def demo() -> None:
    """
    Synthetic lawful demo:
    Authorized maritime radar track + AIS correlation candidate.
    No real targeting, no evasion, no jamming, no private-person tracking.
    """
    employee = RADIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    case = {
        "case_id": "DEMO-RADINT-001",
        "task_id": "DEMO-TASK-001",
        "objective": (
            "Lawful maritime safety and verification analysis: assess authorized radar track continuity, "
            "object-class candidates, AIS correlation candidacy, coverage uncertainty, and clutter context "
            "without identifying intent or enabling harmful action."
        ),
        "questions": [
            "What did the radar sensor actually observe?",
            "Is the track continuous or coverage-limited?",
            "Is AIS correlation only a candidate?",
            "What remains unknown?",
        ],
        "authorization": "AUTHORIZED_MARITIME_SAFETY_RESEARCH_PUBLIC_OR_LICENSED_DATA",
        "sensors": [
            {
                "sensor_id": "RAD_MAR_DEMO_1",
                "sensor_type": "MARITIME_NAVIGATION_RADAR",
                "operator": "Demo Harbor Safety Authority",
                "authorized_source": "authorized_harbor_radar_demo",
                "data_source": "authorized_harbor_radar_demo",
                "location_lat": 51.9000,
                "location_lon": 4.0000,
                "location_reference": "WGS84",
                "coverage_reference": "generic harbor approach coverage",
                "measurement_modes": ["surface_search"],
                "observation_period": "2026-10-01T10:00:00Z/2026-10-01T10:05:00Z",
                "calibration_state": "CALIBRATION_REPORTED",
                "quality_state": "NOMINAL",
                "source": "demo_authorized_radar_log",
                "limitations": [
                    "Synthetic demo geometry only.",
                    "Coverage metadata is generic and not an operational blind-spot map.",
                ],
            }
        ],
        "detections": [
            {
                "detection_id": "DET_DEMO_1",
                "sensor_id": "RAD_MAR_DEMO_1",
                "timestamp": "2026-10-01T10:00:00Z",
                "range": 5000.0,
                "range_unit": "m",
                "azimuth": 90.0,
                "signal_quality": 0.82,
                "track_candidate": "TRK_DEMO_1",
                "source_id": "authorized_harbor_radar_demo",
            },
            {
                "detection_id": "DET_DEMO_2",
                "sensor_id": "RAD_MAR_DEMO_1",
                "timestamp": "2026-10-01T10:02:00Z",
                "range": 5500.0,
                "range_unit": "m",
                "azimuth": 90.0,
                "signal_quality": 0.80,
                "track_candidate": "TRK_DEMO_1",
                "source_id": "authorized_harbor_radar_demo",
            },
            {
                "detection_id": "DET_DEMO_3",
                "sensor_id": "RAD_MAR_DEMO_1",
                "timestamp": "2026-10-01T10:04:00Z",
                "range": 6000.0,
                "range_unit": "m",
                "azimuth": 90.0,
                "signal_quality": 0.78,
                "track_candidate": "TRK_DEMO_1",
                "source_id": "authorized_harbor_radar_demo",
            },
        ],
        "ais_context": [
            {
                "identity_id": "AIS_DEMO_1",
                "mmsi": "219000001",
                "imo": "9074729",
                "name": "DEMO MARITIME TARGET",
                "lat": 51.9000,
                "lon": 4.0727,
                "sog_kn": 8.1,
                "cog_deg": 90.0,
                "timestamp": "2026-10-01T10:00:00Z",
                "source_id": "public_ais_demo",
            },
            {
                "identity_id": "AIS_DEMO_1",
                "mmsi": "219000001",
                "imo": "9074729",
                "name": "DEMO MARITIME TARGET",
                "lat": 51.9000,
                "lon": 4.0800,
                "sog_kn": 8.1,
                "cog_deg": 90.0,
                "timestamp": "2026-10-01T10:02:00Z",
                "source_id": "public_ais_demo",
            },
            {
                "identity_id": "AIS_DEMO_1",
                "mmsi": "219000001",
                "imo": "9074729",
                "name": "DEMO MARITIME TARGET",
                "lat": 51.9000,
                "lon": 4.0873,
                "sog_kn": 8.1,
                "cog_deg": 90.0,
                "timestamp": "2026-10-01T10:04:00Z",
                "source_id": "public_ais_demo",
            },
        ],
        "weather_context": [
            {
                "weather_id": "WX_DEMO_1",
                "timestamp": "2026-10-01T10:00:00Z",
                "region": "Demo harbor approach",
                "precipitation_intensity": 0.0,
                "sea_state": 2.0,
                "visibility_km": 10.0,
                "notes": ["Light sea state; low rain clutter expected."],
            }
        ],
        "clutter_context": [
            {
                "clutter_id": "CLUT_DEMO_1",
                "clutter_type": "sea",
                "sensor_id": "RAD_MAR_DEMO_1",
                "confidence": "LOW",
                "notes": ["Minor sea clutter possible near range rings."],
            }
        ],
        "coverage_areas": [
            {
                "coverage_id": "COV_DEMO_1",
                "sensor_id": "RAD_MAR_DEMO_1",
                "center_lat": 51.9000,
                "center_lon": 4.0000,
                "radius_m": 10000.0,
                "state": "COVERED",
                "notes": ["Generic demo coverage circle; not an operational blind-spot map."],
            }
        ],
    }

    result = employee.run_case(case)
    print(result.report)


def main() -> None:
    demo()


if __name__ == "__main__":
    main()