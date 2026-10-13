"""
======================================================================
TRACEATLAS — METINT
MEASUREMENT & SIGNATURE INTELLIGENCE AI EMPLOYEE
Python Implementation
======================================================================

Mode:
LAWFUL / AUTHORIZED / EVIDENCE-FIRST / SCIENTIFICALLY DEFENSIBLE

Architecture:
MULTI-AGENT + FACT GATE + DUAL-AI + GRAPHICAL MEMORY + JARVIS

Primary boundary:
Measurement and signature analysis,
NOT weapon targeting, CBRN optimization, sensor defeat, or evasion.
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
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("METINT")


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
    OPTICAL = "OPTICAL"
    INFRARED = "INFRARED"
    THERMAL = "THERMAL"
    MULTISPECTRAL = "MULTISPECTRAL"
    HYPERSPECTRAL = "HYPERSPECTRAL"
    ACOUSTIC = "ACOUSTIC"
    VIBRATION = "VIBRATION"
    SEISMIC = "SEISMIC"
    RADAR_DERIVED = "RADAR_DERIVED"
    RF_MEASUREMENT = "RF_MEASUREMENT"
    ELECTROMAGNETIC = "ELECTROMAGNETIC"
    MAGNETIC = "MAGNETIC"
    RADIOMETRIC = "RADIOMETRIC"
    CHEMICAL = "CHEMICAL"
    RADIOLOGICAL = "RADIOLOGICAL"
    BIOLOGICAL = "BIOLOGICAL"
    METEOROLOGICAL = "METEOROLOGICAL"
    GEOPHYSICAL = "GEOPHYSICAL"
    INDUSTRIAL = "INDUSTRIAL"
    MECHANICAL = "MECHANICAL"
    ELECTRICAL = "ELECTRICAL"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class CalibrationState(str, Enum):
    CALIBRATED = "CALIBRATED"
    CALIBRATION_REPORTED = "CALIBRATION_REPORTED"
    CALIBRATION_EXPIRED = "CALIBRATION_EXPIRED"
    CALIBRATION_UNKNOWN = "CALIBRATION_UNKNOWN"
    CALIBRATION_SUSPECT = "CALIBRATION_SUSPECT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SensorHealth(str, Enum):
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    SATURATED = "SATURATED"
    CLIPPED = "CLIPPED"
    OFFLINE = "OFFLINE"
    INTERMITTENT = "INTERMITTENT"
    CLOCK_UNCERTAIN = "CLOCK_UNCERTAIN"
    NOISY = "NOISY"
    UNKNOWN = "UNKNOWN"


class UnitFamily(str, Enum):
    TEMPERATURE = "TEMPERATURE"
    LENGTH = "LENGTH"
    VELOCITY = "VELOCITY"
    FREQUENCY = "FREQUENCY"
    POWER = "POWER"
    PRESSURE = "PRESSURE"
    MASS = "MASS"
    ENERGY = "ENERGY"
    TIME = "TIME"
    RADIANCE = "RADIANCE"
    COUNT = "COUNT"
    DIMENSIONLESS = "DIMENSIONLESS"
    UNKNOWN = "UNKNOWN"


class BaselineQuality(str, Enum):
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    INSUFFICIENT = "INSUFFICIENT"
    UNKNOWN = "UNKNOWN"


class AnomalySignificance(str, Enum):
    NONE = "NONE"
    MINOR = "MINOR"
    MODERATE = "MODERATE"
    STATISTICALLY_SIGNIFICANT = "STATISTICALLY_SIGNIFICANT"
    UNKNOWN = "UNKNOWN"


class MatchQuality(str, Enum):
    STRONG_MATCH = "STRONG_MATCH"
    MODERATE_MATCH = "MODERATE_MATCH"
    WEAK_MATCH = "WEAK_MATCH"
    PARTIAL_MATCH = "PARTIAL_MATCH"
    NO_MATCH = "NO_MATCH"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ClassificationLevel(str, Enum):
    PHENOMENON_CLASS = "PHENOMENON_CLASS"
    OBJECT_CLASS = "OBJECT_CLASS"
    SYSTEM_CLASS = "SYSTEM_CLASS"
    MODEL_FAMILY_CANDIDATE = "MODEL_FAMILY_CANDIDATE"
    SPECIFIC_INSTANCE_CANDIDATE = "SPECIFIC_INSTANCE_CANDIDATE"
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
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class IndependenceState(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    PARTIALLY_DEPENDENT = "PARTIALLY_DEPENDENT"
    DEPENDENT = "DEPENDENT"
    UNKNOWN = "UNKNOWN"


class ACHRelation(str, Enum):
    CONSISTENT = "CONSISTENT"
    INCONSISTENT = "INCONSISTENT"
    NEUTRAL = "NEUTRAL"
    UNKNOWN = "UNKNOWN"


# ======================================================================
# SECTION 2 — UTILITIES
# ======================================================================

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
        r = 6371000.0
        p1 = math.radians(float(lat1))
        p2 = math.radians(float(lat2))
        dp = math.radians(float(lat2) - float(lat1))
        dl = math.radians(float(lon2) - float(lon1))
        a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return r * c
    except Exception:
        return None


def coordinate_valid(lat: Optional[float], lon: Optional[float]) -> bool:
    if lat is None or lon is None:
        return False
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0


def enum_from(cls, value: Any, default: Any) -> Any:
    try:
        return cls(str(value).upper())
    except Exception:
        return default


# ======================================================================
# SECTION 3 — UNIT NORMALIZATION
# ======================================================================

@dataclass
class NormalizedQuantity:
    original_value: Optional[float]
    original_unit: Optional[str]
    normalized_value: Optional[float]
    normalized_unit: str
    unit_family: UnitFamily
    conversion_formula: str


TEMPERATURE_UNITS = {"c", "celsius", "deg c", "degree c", "f", "fahrenheit", "deg f", "k", "kelvin"}
LENGTH_UNITS = {"m", "meter", "meters", "km", "kilometer", "kilometers", "ft", "feet", "nmi", "nm", "nautical mile", "nautical miles"}
VELOCITY_UNITS = {"m/s", "mps", "km/h", "kph", "kn", "knot", "knots", "mph"}
FREQUENCY_UNITS = {"hz", "khz", "mhz", "ghz"}
POWER_UNITS = {"w", "kw", "mw", "dbm"}
PRESSURE_UNITS = {"pa", "kpa", "hpa", "mbar", "bar", "psi"}
MASS_UNITS = {"kg", "g", "lb", "lbs", "pound", "pounds"}
ENERGY_UNITS = {"j", "kj", "mj"}
TIME_UNITS = {"s", "sec", "second", "seconds", "ms", "millisecond", "milliseconds", "min", "minute", "minutes", "h", "hr", "hour", "hours"}
RADIANCE_UNITS = {"w/m^2", "w/m2", "w/m^2/sr", "w/m2/sr", "radiance", "irradiance"}
COUNT_UNITS = {"count", "counts", "pixel", "pixels", "adc", "dn", "digital number", "digital numbers"}
DIMENSIONLESS_UNITS = {"", "-", "ratio", "fraction", "dimensionless", "unitless"}


def detect_family(unit: Optional[str]) -> UnitFamily:
    u = (unit or "").strip().lower()
    if u in TEMPERATURE_UNITS:
        return UnitFamily.TEMPERATURE
    if u in LENGTH_UNITS:
        return UnitFamily.LENGTH
    if u in VELOCITY_UNITS:
        return UnitFamily.VELOCITY
    if u in FREQUENCY_UNITS:
        return UnitFamily.FREQUENCY
    if u in POWER_UNITS:
        return UnitFamily.POWER
    if u in PRESSURE_UNITS:
        return UnitFamily.PRESSURE
    if u in MASS_UNITS:
        return UnitFamily.MASS
    if u in ENERGY_UNITS:
        return UnitFamily.ENERGY
    if u in TIME_UNITS:
        return UnitFamily.TIME
    if u in RADIANCE_UNITS or "w/m" in u:
        return UnitFamily.RADIANCE
    if u in COUNT_UNITS:
        return UnitFamily.COUNT
    if u in DIMENSIONLESS_UNITS:
        return UnitFamily.DIMENSIONLESS
    return UnitFamily.UNKNOWN


def normalize_quantity(value: Optional[float], unit: Optional[str]) -> NormalizedQuantity:
    original_unit = unit
    u = (unit or "").strip().lower()
    family = detect_family(u)

    if value is None:
        return NormalizedQuantity(
            original_value=None,
            original_unit=original_unit,
            normalized_value=None,
            normalized_unit="UNIT_UNKNOWN",
            unit_family=family,
            conversion_formula="no_value",
        )

    if family == UnitFamily.TEMPERATURE:
        if u in {"c", "celsius", "deg c", "degree c"}:
            return NormalizedQuantity(value, original_unit, value + 273.15, "K", family, "K = C + 273.15")
        if u in {"f", "fahrenheit", "deg f"}:
            return NormalizedQuantity(value, original_unit, (value - 32.0) * 5.0 / 9.0 + 273.15, "K", family, "K = (F - 32) * 5/9 + 273.15")
        if u in {"k", "kelvin"}:
            return NormalizedQuantity(value, original_unit, value, "K", family, "identity")

    if family == UnitFamily.LENGTH:
        if u in {"m", "meter", "meters"}:
            return NormalizedQuantity(value, original_unit, value, "m", family, "identity")
        if u in {"km", "kilometer", "kilometers"}:
            return NormalizedQuantity(value, original_unit, value * 1000.0, "m", family, "m = km * 1000")
        if u in {"ft", "feet"}:
            return NormalizedQuantity(value, original_unit, value * 0.3048, "m", family, "m = ft * 0.3048")
        if u in {"nmi", "nm", "nautical mile", "nautical miles"}:
            return NormalizedQuantity(value, original_unit, value * 1852.0, "m", family, "m = nmi * 1852")

    if family == UnitFamily.VELOCITY:
        if u in {"m/s", "mps"}:
            return NormalizedQuantity(value, original_unit, value, "m/s", family, "identity")
        if u in {"km/h", "kph"}:
            return NormalizedQuantity(value, original_unit, value / 3.6, "m/s", family, "m/s = km/h / 3.6")
        if u in {"kn", "knot", "knots"}:
            return NormalizedQuantity(value, original_unit, value * 0.514444, "m/s", family, "m/s = kn * 0.514444")
        if u == "mph":
            return NormalizedQuantity(value, original_unit, value * 0.44704, "m/s", family, "m/s = mph * 0.44704")

    if family == UnitFamily.FREQUENCY:
        if u == "hz":
            return NormalizedQuantity(value, original_unit, value, "Hz", family, "identity")
        if u == "khz":
            return NormalizedQuantity(value, original_unit, value * 1e3, "Hz", family, "Hz = kHz * 1000")
        if u == "mhz":
            return NormalizedQuantity(value, original_unit, value * 1e6, "Hz", family, "Hz = MHz * 1e6")
        if u == "ghz":
            return NormalizedQuantity(value, original_unit, value * 1e9, "Hz", family, "Hz = GHz * 1e9")

    if family == UnitFamily.POWER:
        if u == "w":
            return NormalizedQuantity(value, original_unit, value, "W", family, "identity")
        if u == "kw":
            return NormalizedQuantity(value, original_unit, value * 1e3, "W", family, "W = kW * 1000")
        if u == "mw":
            return NormalizedQuantity(value, original_unit, value * 1e6, "W", family, "W = MW * 1e6")
        if u == "dbm":
            watts = (10.0 ** (value / 10.0)) * 0.001
            return NormalizedQuantity(value, original_unit, watts, "W", family, "W = 10^(dBm/10) * 0.001")

    if family == UnitFamily.PRESSURE:
        if u == "pa":
            return NormalizedQuantity(value, original_unit, value, "Pa", family, "identity")
        if u == "kpa":
            return NormalizedQuantity(value, original_unit, value * 1e3, "Pa", family, "Pa = kPa * 1000")
        if u == "hpa":
            return NormalizedQuantity(value, original_unit, value * 100.0, "Pa", family, "Pa = hPa * 100")
        if u == "mbar":
            return NormalizedQuantity(value, original_unit, value * 100.0, "Pa", family, "Pa = mbar * 100")
        if u == "bar":
            return NormalizedQuantity(value, original_unit, value * 1e5, "Pa", family, "Pa = bar * 100000")
        if u == "psi":
            return NormalizedQuantity(value, original_unit, value * 6894.76, "Pa", family, "Pa = psi * 6894.76")

    if family == UnitFamily.MASS:
        if u == "kg":
            return NormalizedQuantity(value, original_unit, value, "kg", family, "identity")
        if u == "g":
            return NormalizedQuantity(value, original_unit, value / 1000.0, "kg", family, "kg = g / 1000")
        if u in {"lb", "lbs", "pound", "pounds"}:
            return NormalizedQuantity(value, original_unit, value * 0.453592, "kg", family, "kg = lb * 0.453592")

    if family == UnitFamily.ENERGY:
        if u == "j":
            return NormalizedQuantity(value, original_unit, value, "J", family, "identity")
        if u == "kj":
            return NormalizedQuantity(value, original_unit, value * 1e3, "J", family, "J = kJ * 1000")
        if u == "mj":
            return NormalizedQuantity(value, original_unit, value * 1e6, "J", family, "J = MJ * 1e6")

    if family == UnitFamily.TIME:
        if u in {"s", "sec", "second", "seconds"}:
            return NormalizedQuantity(value, original_unit, value, "s", family, "identity")
        if u in {"ms", "millisecond", "milliseconds"}:
            return NormalizedQuantity(value, original_unit, value / 1000.0, "s", family, "s = ms / 1000")
        if u in {"min", "minute", "minutes"}:
            return NormalizedQuantity(value, original_unit, value * 60.0, "s", family, "s = min * 60")
        if u in {"h", "hr", "hour", "hours"}:
            return NormalizedQuantity(value, original_unit, value * 3600.0, "s", family, "s = h * 3600")

    if family == UnitFamily.RADIANCE:
        if "sr" in u:
            return NormalizedQuantity(value, original_unit, value, "W/m^2/sr", family, "identity")
        return NormalizedQuantity(value, original_unit, value, "W/m^2", family, "identity")

    if family == UnitFamily.COUNT:
        return NormalizedQuantity(value, original_unit, value, "count", family, "identity")

    if family == UnitFamily.DIMENSIONLESS:
        if u == "percent" or u == "%":
            return NormalizedQuantity(value, original_unit, value / 100.0, "fraction", family, "fraction = percent / 100")
        return NormalizedQuantity(value, original_unit, value, "dimensionless", family, "identity")

    return NormalizedQuantity(
        original_value=value,
        original_unit=original_unit,
        normalized_value=value,
        normalized_unit="UNIT_UNKNOWN",
        unit_family=UnitFamily.UNKNOWN,
        conversion_formula="no_known_conversion",
    )


def normalize_series(values: List[Optional[float]], unit: Optional[str]) -> Tuple[List[float], UnitFamily, str]:
    normalized: List[float] = []
    families: set[UnitFamily] = set()
    formulas: set[str] = set()

    for v in values:
        q = normalize_quantity(v, unit)
        families.add(q.unit_family)
        formulas.add(q.conversion_formula)
        if q.normalized_value is not None:
            normalized.append(q.normalized_value)

    if len(families) == 1:
        family = families.pop()
    else:
        family = UnitFamily.UNKNOWN

    return normalized, family, "; ".join(sorted(formulas))


# ======================================================================
# SECTION 4 — POLICY GUARD / PROMPT INJECTION DEFENSE
# ======================================================================

@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str = ""


class PolicyGuard:
    """
    Blocks requests seeking prohibited METINT operational guidance.
    Allows lawful scientific, safety, environmental, verification, and defensive analysis.
    """

    PROHIBITED_PATTERNS = [
        r"(?:how\s+to|guide\s+to|instructions?\s+to|teach\s+me).*(?:jam|spoof|evade|defeat|blind|overload|mask|hide|reduce\s+signature).*?(?:sensor|radar|thermal|acoustic|rf|detection)",
        r"\b(?:weapon|strike|targeting|firing\s+solution|aim\s+point|engagement\s+recommendation)\b",
        r"\b(?:CBRN|chemical|biological|radiological|nuclear).*(?:synthesis|production|weaponization|dispersal\s+optimization|evasion)\b",
        r"\b(?:explosive|blast).*(?:design|optimization|formulation|initiation|placement)\b",
        r"\b(?:stealth|radar\s+evasion|thermal\s+evasion|acoustic\s+evasion|sensor\s+defeat)\b",
        r"\b(?:sabotage|bypass\s+safety\s+controls|attack\s+sensor\s+infrastructure)\b",
        r"\b(?:private\s+person|individual).*(?:stalk|track|locate|surveil)\b",
        r"\b(?:generate|calculate).*(?:strike\s+coordinates|target\s+coordinates)\b",
    ]

    def __init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.PROHIBITED_PATTERNS]

    def check_request(self, text: str) -> PolicyResult:
        t = text or ""
        for rx in self._compiled:
            if rx.search(t):
                return PolicyResult(
                    decision=PolicyDecision.POLICY_BLOCKED,
                    reason="Request seeks prohibited METINT operational guidance.",
                )
        return PolicyResult(decision=PolicyDecision.ALLOW, reason="")

    def is_safe_action(self, action: str) -> bool:
        return self.check_request(action).decision == PolicyDecision.ALLOW


class PromptInjectionDefense:
    """
    Sensor metadata, reports, annotations, files, and documents are untrusted data.
    Neutralize obvious instruction-like injections while preserving original evidence.
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
# SECTION 5 — CORE DATA OBJECTS
# ======================================================================

@dataclass
class Evidence:
    evidence_id: str
    case_id: str
    source_id: str
    sensor_id: str
    measurement_type: str
    raw_payload_reference: str
    decoded_payload: Dict[str, Any]
    received_at: datetime
    transmitted_at: Optional[datetime] = None
    retrieved_at: Optional[datetime] = None
    content_hash: str = ""
    parser_version: str = "METINT-parser-0.1.0"
    normalizer_version: str = "METINT-normalizer-0.1.0"
    authorization_context: str = ""


@dataclass
class Sensor:
    sensor_id: str
    sensor_type: SensorType = SensorType.UNKNOWN
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    measurement_domain: Optional[str] = None
    location_latitude: Optional[float] = None
    location_longitude: Optional[float] = None
    orientation: Optional[str] = None
    sampling_rate_hz: Optional[float] = None
    resolution: Optional[float] = None
    sensitivity: Optional[float] = None
    dynamic_range_min: Optional[float] = None
    dynamic_range_max: Optional[float] = None
    calibration_state: CalibrationState = CalibrationState.CALIBRATION_UNKNOWN
    health_state: SensorHealth = SensorHealth.UNKNOWN
    clock_source: str = "UNKNOWN"
    data_source: str = "UNKNOWN"
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    limitations: List[str] = field(default_factory=list)


@dataclass
class CalibrationRecord:
    calibration_id: str
    sensor_id: str
    calibrated_at: datetime
    valid_until: Optional[datetime] = None
    method: Optional[str] = None
    standard: Optional[str] = None
    uncertainty: Optional[float] = None
    uncertainty_unit: Optional[str] = None
    source_id: str = ""


@dataclass
class EnvironmentalContext:
    env_id: str
    timestamp: datetime
    location_latitude: Optional[float] = None
    location_longitude: Optional[float] = None
    air_temperature_K: Optional[float] = None
    humidity_fraction: Optional[float] = None
    wind_speed_m_s: Optional[float] = None
    pressure_Pa: Optional[float] = None
    cloud_cover_fraction: Optional[float] = None
    solar_irradiance_W_m2: Optional[float] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class Measurement:
    measurement_id: str
    case_id: str
    sensor_id: str
    measurement_type: str
    timestamp: datetime
    raw_value: Optional[float] = None
    normalized_value: Optional[float] = None
    unit: str = "UNIT_UNKNOWN"
    normalized_unit: str = "UNIT_UNKNOWN"
    unit_family: UnitFamily = UnitFamily.UNKNOWN
    raw_values: Optional[List[float]] = None
    normalized_values: Optional[List[float]] = None
    sample_interval_s: Optional[float] = None
    reference_frame: str = "UNKNOWN"
    location_latitude: Optional[float] = None
    location_longitude: Optional[float] = None
    spatial_uncertainty_m: Optional[float] = None
    measurement_uncertainty: Optional[float] = None
    uncertainty_components: Dict[str, float] = field(default_factory=dict)
    quality_flags: List[str] = field(default_factory=list)
    calibration_reference: Optional[str] = None
    environmental_context_id: Optional[str] = None
    source_id: str = ""
    evidence_id: str = ""
    raw_payload: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Baseline:
    baseline_id: str
    sensor_id: str
    measurement_type: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    mean: Optional[float] = None
    std: Optional[float] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    sample_count: int = 0
    unit: str = "UNIT_UNKNOWN"
    quality: BaselineQuality = BaselineQuality.UNKNOWN
    version: str = "baseline-v0"
    source_id: str = ""


@dataclass
class FeatureVector:
    feature_id: str
    measurement_id: str
    domain: str
    features: Dict[str, float] = field(default_factory=dict)
    feature_units: Dict[str, str] = field(default_factory=dict)
    extraction_method: str = ""
    limitations: List[str] = field(default_factory=list)


@dataclass
class Signature:
    signature_id: str
    measurement_id: str
    domain: str
    feature_vector_id: str
    features: Dict[str, float] = field(default_factory=dict)
    feature_units: Dict[str, str] = field(default_factory=dict)
    source: str = ""
    confidence: str = "LOW"
    limitations: List[str] = field(default_factory=list)


@dataclass
class SignatureLibraryEntry:
    entry_id: str
    library_version: str
    domain: str
    reference_class: str
    features: Dict[str, float] = field(default_factory=dict)
    feature_units: Dict[str, str] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    source: str = ""
    uncertainty: Optional[float] = None
    limitations: List[str] = field(default_factory=list)


@dataclass
class MatchResult:
    match_id: str
    signature_id: str
    entry_id: str
    reference_class: str
    quality: MatchQuality
    similarity: Optional[float]
    method: str
    features_compared: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class ClassificationResult:
    classification_id: str
    level: ClassificationLevel
    label: str
    confidence: str
    status: FactStatus
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class CalibrationAssessment:
    sensor_id: str
    measurement_id: str
    state: CalibrationState
    record_id: Optional[str] = None
    uncertainty: Optional[float] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class HealthAssessment:
    sensor_id: str
    measurement_id: str
    state: SensorHealth
    flags: List[str] = field(default_factory=list)


@dataclass
class UncertaintyEstimate:
    measurement_id: str
    combined: Optional[float]
    components: Dict[str, float] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


@dataclass
class Anomaly:
    anomaly_id: str
    measurement_id: str
    anomaly_type: str
    z_score: Optional[float]
    statistical_significance: AnomalySignificance
    operational_significance: str
    notes: List[str] = field(default_factory=list)


@dataclass
class FusionAssessment:
    independence: IndependenceState
    common_mode_errors: List[str] = field(default_factory=list)
    corroborations: List[Dict[str, Any]] = field(default_factory=list)
    contradictions: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


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
class ACHCell:
    evidence_id: str
    hypothesis_id: str
    relation: ACHRelation
    rationale: str = ""


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
class METINTResult:
    case_id: str
    task_id: str
    objective: str
    status: str
    policy_decision: PolicyDecision = PolicyDecision.ALLOW

    evidence: List[Evidence] = field(default_factory=list)
    sensors: List[Sensor] = field(default_factory=list)
    calibration_records: List[CalibrationRecord] = field(default_factory=list)
    environmental_contexts: List[EnvironmentalContext] = field(default_factory=list)
    measurements: List[Measurement] = field(default_factory=list)
    baselines: List[Baseline] = field(default_factory=list)

    calibration_assessments: List[CalibrationAssessment] = field(default_factory=list)
    health_assessments: List[HealthAssessment] = field(default_factory=list)
    uncertainty_estimates: List[UncertaintyEstimate] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    feature_vectors: List[FeatureVector] = field(default_factory=list)
    signatures: List[Signature] = field(default_factory=list)
    signature_library: List[SignatureLibraryEntry] = field(default_factory=list)
    matches: List[MatchResult] = field(default_factory=list)
    classifications: List[ClassificationResult] = field(default_factory=list)

    fusion_assessments: List[FusionAssessment] = field(default_factory=list)
    contradictions: List[Contradiction] = field(default_factory=list)
    facts: List[Fact] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    ach_matrix: List[ACHCell] = field(default_factory=list)

    knowledge_gaps: List[KnowledgeGap] = field(default_factory=list)
    next_actions: List[NextAction] = field(default_factory=list)
    specialist_handoffs: List[SpecialistHandoff] = field(default_factory=list)

    review: Dict[str, Any] = field(default_factory=dict)
    graph: Dict[str, Any] = field(default_factory=dict)
    report: str = ""

    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    safety_flags: List[str] = field(default_factory=list)
    privacy_flags: List[str] = field(default_factory=list)


# ======================================================================
# SECTION 6 — INGESTION
# ======================================================================

class METINTIngestor:
    PARSER_VERSION = "METINT-parser-0.1.0"
    NORMALIZER_VERSION = "METINT-normalizer-0.1.0"

    def __init__(self, injection_defense: Optional[PromptInjectionDefense] = None):
        self.injection_defense = injection_defense or PromptInjectionDefense()

    def ingest_case(
        self, case: Dict[str, Any]
    ) -> Tuple[
        List[Evidence],
        List[Measurement],
        List[Sensor],
        List[CalibrationRecord],
        List[EnvironmentalContext],
        List[Baseline],
        List[SignatureLibraryEntry],
    ]:
        case_id = str(case.get("case_id", new_id("CASE")))
        authorization = str(case.get("authorization", ""))

        sensors = [self._parse_sensor(s) for s in case.get("sensors", [])]
        calibration_records = [self._parse_calibration(c) for c in case.get("calibration_records", [])]
        environments = [self._parse_environment(e) for e in case.get("environmental_contexts", [])]
        baselines = [self._parse_baseline(b) for b in case.get("baselines", [])]
        library = [self._parse_library_entry(x) for x in case.get("signature_library", [])]

        evidence_list: List[Evidence] = []
        measurements: List[Measurement] = []

        for m in case.get("measurements", []):
            ev, meas = self._parse_measurement(case_id, authorization, m)
            evidence_list.append(ev)
            if meas is not None:
                measurements.append(meas)

        return evidence_list, measurements, sensors, calibration_records, environments, baselines, library

    def _parse_sensor(self, s: Dict[str, Any]) -> Sensor:
        lat = safe_float(s.get("location_latitude", s.get("lat")))
        lon = safe_float(s.get("location_longitude", s.get("lon")))
        return Sensor(
            sensor_id=str(s.get("sensor_id", new_id("SENSOR"))),
            sensor_type=enum_from(SensorType, s.get("sensor_type"), SensorType.UNKNOWN),
            manufacturer=normalize_text(s.get("manufacturer")),
            model=normalize_text(s.get("model")),
            measurement_domain=normalize_text(s.get("measurement_domain")),
            location_latitude=lat,
            location_longitude=lon,
            orientation=normalize_text(s.get("orientation")),
            sampling_rate_hz=safe_float(s.get("sampling_rate_hz")),
            resolution=safe_float(s.get("resolution")),
            sensitivity=safe_float(s.get("sensitivity")),
            dynamic_range_min=safe_float(s.get("dynamic_range_min")),
            dynamic_range_max=safe_float(s.get("dynamic_range_max")),
            calibration_state=enum_from(CalibrationState, s.get("calibration_state"), CalibrationState.CALIBRATION_UNKNOWN),
            health_state=enum_from(SensorHealth, s.get("health_state"), SensorHealth.UNKNOWN),
            clock_source=str(s.get("clock_source", "UNKNOWN")),
            data_source=str(s.get("data_source", "UNKNOWN")),
            valid_from=to_datetime(s.get("valid_from")),
            valid_to=to_datetime(s.get("valid_to")),
            limitations=[str(x) for x in s.get("limitations", [])],
        )

    def _parse_calibration(self, c: Dict[str, Any]) -> CalibrationRecord:
        return CalibrationRecord(
            calibration_id=str(c.get("calibration_id", new_id("CAL"))),
            sensor_id=str(c.get("sensor_id", "")),
            calibrated_at=to_datetime(c.get("calibrated_at")) or utcnow(),
            valid_until=to_datetime(c.get("valid_until")),
            method=normalize_text(c.get("method")),
            standard=normalize_text(c.get("standard")),
            uncertainty=safe_float(c.get("uncertainty")),
            uncertainty_unit=normalize_text(c.get("uncertainty_unit")),
            source_id=str(c.get("source_id", "")),
        )

    def _parse_environment(self, e: Dict[str, Any]) -> EnvironmentalContext:
        air_t = normalize_quantity(safe_float(e.get("air_temperature", e.get("air_temp"))), e.get("air_temperature_unit", "C"))
        hum = normalize_quantity(safe_float(e.get("humidity")), e.get("humidity_unit", "percent"))
        wind = normalize_quantity(safe_float(e.get("wind_speed")), e.get("wind_speed_unit", "m/s"))
        pres = normalize_quantity(safe_float(e.get("pressure")), e.get("pressure_unit", "Pa"))
        cloud = normalize_quantity(safe_float(e.get("cloud_cover")), e.get("cloud_cover_unit", "percent"))
        solar = normalize_quantity(safe_float(e.get("solar_irradiance")), e.get("solar_irradiance_unit", "W/m^2"))

        return EnvironmentalContext(
            env_id=str(e.get("env_id", new_id("ENV"))),
            timestamp=to_datetime(e.get("timestamp")) or utcnow(),
            location_latitude=safe_float(e.get("location_latitude", e.get("lat"))),
            location_longitude=safe_float(e.get("location_longitude", e.get("lon"))),
            air_temperature_K=air_t.normalized_value,
            humidity_fraction=hum.normalized_value,
            wind_speed_m_s=wind.normalized_value,
            pressure_Pa=pres.normalized_value,
            cloud_cover_fraction=cloud.normalized_value,
            solar_irradiance_W_m2=solar.normalized_value,
            notes=[str(x) for x in e.get("notes", [])],
        )

    def _parse_baseline(self, b: Dict[str, Any]) -> Baseline:
        values = [safe_float(x) for x in b.get("values", [])]
        values = [v for v in values if v is not None]
        unit = b.get("unit", "UNIT_UNKNOWN")
        norm_values, family, _ = normalize_series(values, unit)

        normalized_unit = "K" if family == UnitFamily.TEMPERATURE else (norm_values and "normalized" or "UNIT_UNKNOWN")
        if family == UnitFamily.TEMPERATURE:
            normalized_unit = "K"
        elif family == UnitFamily.DIMENSIONLESS:
            normalized_unit = "dimensionless"
        else:
            normalized_unit = str(unit)

        m = mean(norm_values)
        s = std(norm_values)
        count = len(norm_values)

        if count >= 30:
            quality = BaselineQuality.STRONG
        elif count >= 10:
            quality = BaselineQuality.MODERATE
        elif count > 0:
            quality = BaselineQuality.WEAK
        else:
            quality = BaselineQuality.INSUFFICIENT

        return Baseline(
            baseline_id=str(b.get("baseline_id", new_id("BASE"))),
            sensor_id=str(b.get("sensor_id", "")),
            measurement_type=str(b.get("measurement_type", "")),
            start_time=to_datetime(b.get("start_time")),
            end_time=to_datetime(b.get("end_time")),
            mean=m,
            std=s,
            min_value=min(norm_values) if norm_values else None,
            max_value=max(norm_values) if norm_values else None,
            sample_count=count,
            unit=normalized_unit,
            quality=quality,
            version=str(b.get("version", "baseline-v0")),
            source_id=str(b.get("source_id", "")),
        )

    def _parse_library_entry(self, x: Dict[str, Any]) -> SignatureLibraryEntry:
        features = {}
        feature_units = {}
        for k, v in (x.get("features") or {}).items():
            fv = safe_float(v)
            if fv is not None:
                features[str(k)] = fv
        for k, u in (x.get("feature_units") or {}).items():
            feature_units[str(k)] = str(u)

        return SignatureLibraryEntry(
            entry_id=str(x.get("entry_id", new_id("LIB"))),
            library_version=str(x.get("library_version", "library-v0")),
            domain=str(x.get("domain", "UNKNOWN")),
            reference_class=str(x.get("reference_class", "UNKNOWN")),
            features=features,
            feature_units=feature_units,
            created_at=to_datetime(x.get("created_at")),
            updated_at=to_datetime(x.get("updated_at")),
            source=str(x.get("source", "")),
            uncertainty=safe_float(x.get("uncertainty")),
            limitations=[str(i) for i in x.get("limitations", [])],
        )

    def _parse_measurement(
        self,
        case_id: str,
        authorization_context: str,
        m: Dict[str, Any],
    ) -> Tuple[Evidence, Optional[Measurement]]:
        payload = dict(m)
        for key in ("notes", "annotation", "metadata"):
            if key in payload:
                payload[f"_sanitized_{key}"] = self.injection_defense.sanitize(payload.get(key))

        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        timestamp = to_datetime(m.get("timestamp")) or utcnow()
        evidence = Evidence(
            evidence_id=new_id("EV"),
            case_id=case_id,
            source_id=str(m.get("source_id", "unknown_source")),
            sensor_id=str(m.get("sensor_id", "unknown_sensor")),
            measurement_type=str(m.get("measurement_type", "unknown_measurement")),
            raw_payload_reference=canonical[:1000],
            decoded_payload=payload,
            received_at=utcnow(),
            transmitted_at=timestamp,
            retrieved_at=utcnow(),
            content_hash=content_hash,
            parser_version=self.PARSER_VERSION,
            normalizer_version=self.NORMALIZER_VERSION,
            authorization_context=authorization_context,
        )

        raw_value = safe_float(m.get("value"))
        raw_values = [safe_float(x) for x in m.get("values", [])]
        raw_values = [v for v in raw_values if v is not None]
        unit = str(m.get("unit", "UNIT_UNKNOWN"))
        sample_interval_s = safe_float(m.get("sample_interval_s"))

        q = normalize_quantity(raw_value, unit)
        norm_values, series_family, series_formula = normalize_series(raw_values, unit)

        if raw_values:
            unit_family = series_family
            normalized_unit = "K" if unit_family == UnitFamily.TEMPERATURE else (q.normalized_unit if q.normalized_unit != "UNIT_UNKNOWN" else "normalized")
            conversion_formula = series_formula
            normalized_value = mean(norm_values)
        else:
            unit_family = q.unit_family
            normalized_unit = q.normalized_unit
            conversion_formula = q.conversion_formula
            normalized_value = q.normalized_value

        quality_flags: List[str] = []
        if unit == "UNIT_UNKNOWN" or unit_family == UnitFamily.UNKNOWN:
            quality_flags.append("UNIT_UNKNOWN")
        if raw_value is None and not raw_values:
            quality_flags.append("NO_VALUE")
        lat = safe_float(m.get("location_latitude", m.get("lat")))
        lon = safe_float(m.get("location_longitude", m.get("lon")))
        if (lat is not None or lon is not None) and not coordinate_valid(lat, lon):
            quality_flags.append("INVALID_COORDINATE")
        if normalized_value is not None and math.isnan(normalized_value):
            quality_flags.append("NaN_VALUE")
        if normalized_value is not None and math.isinf(normalized_value):
            quality_flags.append("Inf_VALUE")

        measurement = Measurement(
            measurement_id=str(m.get("measurement_id", new_id("MEAS"))),
            case_id=case_id,
            sensor_id=str(m.get("sensor_id", "unknown_sensor")),
            measurement_type=str(m.get("measurement_type", "unknown_measurement")),
            timestamp=timestamp,
            raw_value=raw_value,
            normalized_value=normalized_value,
            unit=unit,
            normalized_unit=normalized_unit,
            unit_family=unit_family,
            raw_values=raw_values if raw_values else None,
            normalized_values=norm_values if norm_values else None,
            sample_interval_s=sample_interval_s,
            reference_frame=str(m.get("reference_frame", "UNKNOWN")),
            location_latitude=lat,
            location_longitude=lon,
            spatial_uncertainty_m=safe_float(m.get("spatial_uncertainty_m")),
            measurement_uncertainty=safe_float(m.get("measurement_uncertainty")),
            uncertainty_components={str(k): float(v) for k, v in (m.get("uncertainty_components") or {}).items() if safe_float(v) is not None},
            quality_flags=quality_flags,
            calibration_reference=m.get("calibration_reference"),
            environmental_context_id=m.get("environmental_context_id"),
            source_id=str(m.get("source_id", "")),
            evidence_id=evidence.evidence_id,
            raw_payload=payload,
        )

        return evidence, measurement


# ======================================================================
# SECTION 7 — CALIBRATION / HEALTH / UNCERTAINTY
# ======================================================================

class CalibrationAnalyzer:
    def assess(
        self,
        measurement: Measurement,
        sensor: Sensor,
        records: List[CalibrationRecord],
    ) -> CalibrationAssessment:
        relevant = [r for r in records if r.sensor_id == sensor.sensor_id]
        chosen: Optional[CalibrationRecord] = None

        for r in relevant:
            if r.calibrated_at <= measurement.timestamp:
                if r.valid_until is None or measurement.timestamp < r.valid_until:
                    chosen = r
                    break

        notes: List[str] = []
        uncertainty = None

        if chosen is not None:
            uncertainty = chosen.uncertainty
            if uncertainty is not None:
                state = CalibrationState.CALIBRATED
                notes.append("Valid calibration record found with stated uncertainty.")
            else:
                state = CalibrationState.CALIBRATION_REPORTED
                notes.append("Valid calibration record found, but uncertainty not stated.")
        elif sensor.calibration_state in (CalibrationState.CALIBRATED, CalibrationState.CALIBRATION_REPORTED):
            state = CalibrationState.CALIBRATION_REPORTED
            notes.append("Sensor metadata reports calibration, but no matching record was supplied.")
        elif any(r.sensor_id == sensor.sensor_id and r.valid_until and r.valid_until < measurement.timestamp for r in relevant):
            state = CalibrationState.CALIBRATION_EXPIRED
            notes.append("Calibration record appears expired for measurement time.")
        else:
            state = CalibrationState.CALIBRATION_UNKNOWN
            notes.append("No calibration record available for measurement time.")

        return CalibrationAssessment(
            sensor_id=sensor.sensor_id,
            measurement_id=measurement.measurement_id,
            state=state,
            record_id=chosen.calibration_id if chosen else None,
            uncertainty=uncertainty,
            notes=notes,
        )


class SensorHealthAnalyzer:
    def assess(self, sensor: Sensor, measurement: Measurement) -> HealthAssessment:
        flags: List[str] = []
        state = sensor.health_state

        values = measurement.normalized_values or ([measurement.normalized_value] if measurement.normalized_value is not None else [])
        raw_values = measurement.raw_values or ([measurement.raw_value] if measurement.raw_value is not None else [])

        if not values and not raw_values:
            flags.append("NO_DATA")
            state = SensorHealth.UNKNOWN

        if sensor.dynamic_range_max is not None:
            for v in raw_values:
                if v is not None and v >= sensor.dynamic_range_max:
                    flags.append("SATURATED")
                    state = SensorHealth.SATURATED
                    break

        if sensor.dynamic_range_min is not None:
            for v in raw_values:
                if v is not None and v <= sensor.dynamic_range_min:
                    flags.append("CLIPPED_LOW")
                    if state not in (SensorHealth.SATURATED,):
                        state = SensorHealth.CLIPPED
                    break

        if sensor.clock_source.upper() == "UNKNOWN":
            flags.append("CLOCK_SOURCE_UNKNOWN")
            if state == SensorHealth.UNKNOWN:
                state = SensorHealth.CLOCK_UNCERTAIN

        if measurement.unit_family == UnitFamily.UNKNOWN:
            flags.append("UNIT_UNKNOWN")

        if len(values) >= 5:
            s = std(values)
            m = mean(values)
            if m not in (None, 0.0) and s is not None and abs(s / m) > 0.5:
                flags.append("HIGH_RELATIVE_VARIABILITY")
                if state == SensorHealth.ONLINE:
                    state = SensorHealth.NOISY

        return HealthAssessment(
            sensor_id=sensor.sensor_id,
            measurement_id=measurement.measurement_id,
            state=state,
            flags=flags,
        )


class UncertaintyModel:
    def estimate(
        self,
        measurement: Measurement,
        sensor: Sensor,
        calibration: CalibrationAssessment,
        health: HealthAssessment,
    ) -> UncertaintyEstimate:
        components: Dict[str, float] = {}
        notes: List[str] = []

        if measurement.measurement_uncertainty is not None:
            components["provided_instrumental"] = measurement.measurement_uncertainty

        for k, v in measurement.uncertainty_components.items():
            components[k] = v

        if sensor.resolution is not None and "provided_instrumental" not in components:
            components["sensor_resolution"] = sensor.resolution

        if calibration.uncertainty is not None:
            components["calibration"] = calibration.uncertainty

        if measurement.normalized_values and len(measurement.normalized_values) > 1:
            s = std(measurement.normalized_values)
            if s is not None:
                components["series_dispersion"] = s

        if "CLOCK_SOURCE_UNKNOWN" in health.flags:
            components.setdefault("temporal_reference", 0.0)
            notes.append("Clock source unknown; temporal uncertainty not quantified.")

        if not components:
            return UncertaintyEstimate(
                measurement_id=measurement.measurement_id,
                combined=None,
                components={},
                notes=["No uncertainty basis supplied; uncertainty remains UNKNOWN."],
            )

        combined = math.sqrt(sum(v * v for v in components.values() if v is not None))
        notes.append("Combined uncertainty estimated by root-sum-square of available components.")
        notes.append("Uncertainty is not a claim of accuracy; it represents supported error budget.")

        return UncertaintyEstimate(
            measurement_id=measurement.measurement_id,
            combined=combined,
            components=components,
            notes=notes,
        )


# ======================================================================
# SECTION 8 — BASELINE / ANOMALY
# ======================================================================

class BaselineSelector:
    def choose(self, measurement: Measurement, baselines: List[Baseline]) -> Optional[Baseline]:
        candidates = [
            b for b in baselines
            if b.sensor_id == measurement.sensor_id
            and (
                b.measurement_type == measurement.measurement_type
                or measurement.measurement_type.startswith(b.measurement_type)
                or b.measurement_type.startswith(measurement.measurement_type)
            )
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda b: (b.sample_count, b.end_time or datetime.min.replace(tzinfo=timezone.utc)))


class AnomalyDetector:
    def detect(
        self,
        measurement: Measurement,
        baseline: Optional[Baseline],
        uncertainty: Optional[float],
    ) -> Optional[Anomaly]:
        if baseline is None or baseline.mean is None:
            return None

        value = measurement.normalized_value
        if value is None and measurement.normalized_values:
            value = mean(measurement.normalized_values)
        if value is None:
            return None

        sigma = baseline.std or 0.0
        unc = uncertainty or 0.0
        denom = math.sqrt(sigma * sigma + unc * unc)

        notes = [
            "Anomaly means departure from defined baseline.",
            "Anomaly is not automatically malfunction, hazard, attack, or intentional activity.",
        ]

        if denom <= 0:
            z = None
            significance = AnomalySignificance.UNKNOWN
            notes.append("Baseline std and uncertainty are zero/unknown; z-score not computable.")
        else:
            z = (value - baseline.mean) / denom
            az = abs(z)
            if az >= 3:
                significance = AnomalySignificance.STATISTICALLY_SIGNIFICANT
            elif az >= 2:
                significance = AnomalySignificance.MODERATE
            elif az >= 1:
                significance = AnomalySignificance.MINOR
            else:
                significance = AnomalySignificance.NONE

        return Anomaly(
            anomaly_id=new_id("ANOM"),
            measurement_id=measurement.measurement_id,
            anomaly_type="AMPLITUDE",
            z_score=z,
            statistical_significance=significance,
            operational_significance="UNKNOWN",
            notes=notes,
        )


# ======================================================================
# SECTION 9 — FEATURE EXTRACTION / SIGNATURES
# ======================================================================

class FeatureExtractor:
    def extract(self, measurement: Measurement, sensor: Sensor) -> FeatureVector:
        features: Dict[str, float] = {}
        units: Dict[str, str] = {}
        method_parts: List[str] = ["deterministic_summary_statistics"]
        limitations: List[str] = [
            "Features are derived measurements, not raw sensor evidence.",
            "Feature extraction does not establish identity or cause.",
        ]

        vals = measurement.normalized_values or ([measurement.normalized_value] if measurement.normalized_value is not None else [])
        vals = [v for v in vals if v is not None]

        if vals:
            m = mean(vals)
            s = std(vals)
            features["mean"] = m if m is not None else 0.0
            features["std"] = s if s is not None else 0.0
            features["min"] = min(vals)
            features["max"] = max(vals)
            features["range"] = max(vals) - min(vals)
            units.update({
                "mean": measurement.normalized_unit,
                "std": measurement.normalized_unit,
                "min": measurement.normalized_unit,
                "max": measurement.normalized_unit,
                "range": measurement.normalized_unit,
            })

            slope = self._linear_slope(vals, measurement.sample_interval_s)
            if slope is not None:
                features["trend_slope_per_s"] = slope
                units["trend_slope_per_s"] = f"{measurement.normalized_unit}/s"
                method_parts.append("linear_trend")

            if measurement.sample_interval_s and len(vals) >= 8:
                freq, mag = self._dominant_frequency(vals, measurement.sample_interval_s)
                if freq is not None and mag is not None:
                    features["dominant_frequency_hz"] = freq
                    features["dominant_magnitude"] = mag
                    units["dominant_frequency_hz"] = "Hz"
                    units["dominant_magnitude"] = measurement.normalized_unit
                    method_parts.append("naive_dft_peak")

        st = sensor.sensor_type.value.lower()
        mt = measurement.measurement_type.lower()

        if "thermal" in st or "thermal" in mt or "temperature" in mt:
            if "mean" in features:
                features["thermal_mean"] = features["mean"]
                units["thermal_mean"] = measurement.normalized_unit
            if "max" in features:
                features["thermal_max"] = features["max"]
                units["thermal_max"] = measurement.normalized_unit
            if "range" in features:
                features["thermal_contrast"] = features["range"]
                units["thermal_contrast"] = measurement.normalized_unit
            method_parts.append("thermal_context_features")

        if "optical" in st or "reflectance" in mt or "radiance" in mt:
            if "mean" in features:
                features["optical_mean"] = features["mean"]
                units["optical_mean"] = measurement.normalized_unit
            if "range" in features:
                features["optical_range"] = features["range"]
                units["optical_range"] = measurement.normalized_unit
            method_parts.append("optical_context_features")

        if "acoustic" in st or "audio" in mt:
            if vals:
                rms = math.sqrt(sum(v * v for v in vals) / len(vals))
                features["acoustic_rms"] = rms
                units["acoustic_rms"] = measurement.normalized_unit
                method_parts.append("acoustic_rms")

        return FeatureVector(
            feature_id=new_id("FEAT"),
            measurement_id=measurement.measurement_id,
            domain=f"{sensor.sensor_type.value}:{measurement.measurement_type}",
            features=features,
            feature_units=units,
            extraction_method="+".join(method_parts),
            limitations=limitations,
        )

    @staticmethod
    def _linear_slope(vals: List[float], sample_interval_s: Optional[float]) -> Optional[float]:
        n = len(vals)
        if n < 2:
            return None
        xmean = (n - 1) / 2.0
        ymean = sum(vals) / n
        cov = sum((i - xmean) * (v - ymean) for i, v in enumerate(vals))
        var = sum((i - xmean) ** 2 for i in range(n))
        if var == 0:
            return None
        slope_per_sample = cov / var
        if sample_interval_s and sample_interval_s > 0:
            return slope_per_sample / sample_interval_s
        return slope_per_sample

    @staticmethod
    def _dominant_frequency(vals: List[float], dt: float) -> Tuple[Optional[float], Optional[float]]:
        n = len(vals)
        if n < 4 or dt <= 0:
            return None, None
        m = sum(vals) / n
        x = [v - m for v in vals]
        max_k = min(n // 2, 64)
        best_k = 0
        best_mag = 0.0

        for k in range(1, max_k + 1):
            re = 0.0
            im = 0.0
            omega = 2.0 * math.pi * k / n
            for i, xi in enumerate(x):
                re += xi * math.cos(omega * i)
                im -= xi * math.sin(omega * i)
            mag = math.sqrt(re * re + im * im) / n
            if mag > best_mag:
                best_mag = mag
                best_k = k

        if best_k == 0:
            return None, None
        freq = best_k / (n * dt)
        return freq, best_mag


class SignatureBuilder:
    def build(self, measurement: Measurement, feature_vector: FeatureVector, sensor: Sensor) -> Signature:
        return Signature(
            signature_id=new_id("SIG"),
            measurement_id=measurement.measurement_id,
            domain=feature_vector.domain,
            feature_vector_id=feature_vector.feature_id,
            features=dict(feature_vector.features),
            feature_units=dict(feature_vector.feature_units),
            source=f"{sensor.sensor_id}:{measurement.source_id}",
            confidence="LOW",
            limitations=[
                "Signature is a feature representation, not identity.",
                "Environmental and calibration context must be considered before matching.",
            ],
        )


# ======================================================================
# SECTION 10 — SIGNATURE MATCHING / CLASSIFICATION
# ======================================================================

class SignatureMatcher:
    def match(self, signature: Signature, library: List[SignatureLibraryEntry]) -> List[MatchResult]:
        matches: List[MatchResult] = []
        method = "relative_absolute_feature_distance"

        for entry in library:
            common = sorted(set(signature.features.keys()) & set(entry.features.keys()))
            if len(common) < 2:
                matches.append(
                    MatchResult(
                        match_id=new_id("MATCH"),
                        signature_id=signature.signature_id,
                        entry_id=entry.entry_id,
                        reference_class=entry.reference_class,
                        quality=MatchQuality.INSUFFICIENT_DATA,
                        similarity=None,
                        method=method,
                        features_compared=common,
                        limitations=["Fewer than two common features; match not meaningful."],
                    )
                )
                continue

            diffs = []
            for k in common:
                a = signature.features[k]
                b = entry.features[k]
                denom = max(1e-9, abs(a) + abs(b))
                diffs.append(abs(a - b) / denom)

            similarity = clamp(1.0 - (sum(diffs) / len(diffs)), 0.0, 1.0)

            if similarity >= 0.90:
                quality = MatchQuality.STRONG_MATCH
            elif similarity >= 0.75:
                quality = MatchQuality.MODERATE_MATCH
            elif similarity >= 0.50:
                quality = MatchQuality.WEAK_MATCH
            elif similarity > 0.20:
                quality = MatchQuality.PARTIAL_MATCH
            else:
                quality = MatchQuality.NO_MATCH

            matches.append(
                MatchResult(
                    match_id=new_id("MATCH"),
                    signature_id=signature.signature_id,
                    entry_id=entry.entry_id,
                    reference_class=entry.reference_class,
                    quality=quality,
                    similarity=round(similarity, 4),
                    method=method,
                    features_compared=common,
                    limitations=[
                        "Match means observed features are consistent with reference class.",
                        "Match does not prove exact object identity, operator, or intent.",
                        "Similarity depends on feature selection, units, and library version.",
                    ],
                )
            )

        return matches


class ClassificationEngine:
    def classify(
        self,
        signature: Signature,
        matches: List[MatchResult],
        fusion: Optional[FusionAssessment],
    ) -> ClassificationResult:
        usable = [m for m in matches if m.quality not in (MatchQuality.INSUFFICIENT_DATA, MatchQuality.NO_MATCH)]
        if not usable:
            return ClassificationResult(
                classification_id=new_id("CLASS"),
                level=ClassificationLevel.UNKNOWN,
                label="UNKNOWN",
                confidence="LOW",
                status=FactStatus.UNKNOWN,
                supporting_evidence_ids=[],
                contradicting_evidence_ids=[],
                alternatives=[],
                limitations=["No usable signature match."],
            )

        best = max(usable, key=lambda m: (m.similarity or 0.0))
        alternatives = sorted({m.reference_class for m in usable if m.reference_class != best.reference_class})

        corroborated = False
        if fusion:
            corroborated = any(
                c.get("independence") == IndependenceState.INDEPENDENT.value
                for c in fusion.corroborations
            )

        if best.quality == MatchQuality.STRONG_MATCH and corroborated:
            confidence = "HIGH"
            status = FactStatus.SUPPORTED
            level = ClassificationLevel.OBJECT_CLASS
        elif best.quality == MatchQuality.STRONG_MATCH:
            confidence = "MEDIUM"
            status = FactStatus.CANDIDATE
            level = ClassificationLevel.OBJECT_CLASS
        elif best.quality == MatchQuality.MODERATE_MATCH:
            confidence = "MEDIUM"
            status = FactStatus.CANDIDATE
            level = ClassificationLevel.OBJECT_CLASS
        elif best.quality == MatchQuality.WEAK_MATCH:
            confidence = "LOW"
            status = FactStatus.CANDIDATE
            level = ClassificationLevel.PHENOMENON_CLASS
        else:
            confidence = "LOW"
            status = FactStatus.CANDIDATE
            level = ClassificationLevel.PHENOMENON_CLASS

        limitations = [
            "Classification is conservative and evidence-linked.",
            "Specific-instance identity is not asserted.",
            "Attribution to operator, organization, or intent is not established.",
        ]

        return ClassificationResult(
            classification_id=new_id("CLASS"),
            level=level,
            label=best.reference_class,
            confidence=confidence,
            status=status,
            supporting_evidence_ids=[best.match_id],
            contradicting_evidence_ids=[],
            alternatives=alternatives,
            limitations=limitations,
        )


# ======================================================================
# SECTION 11 — MULTI-SENSOR FUSION
# ======================================================================

class MultiSensorFusion:
    def assess(
        self,
        measurements: List[Measurement],
        sensors_by_id: Dict[str, Sensor],
        anomalies_by_measurement: Dict[str, Anomaly],
    ) -> FusionAssessment:
        notes: List[str] = []
        common_mode: List[str] = []
        corroborations: List[Dict[str, Any]] = []
        contradictions: List[Dict[str, Any]] = []

        if len(measurements) < 2:
            return FusionAssessment(
                independence=IndependenceState.UNKNOWN,
                common_mode_errors=[],
                corroborations=[],
                contradictions=[],
                notes=["Fewer than two measurements; multi-sensor fusion not possible."],
            )

        independence_votes: List[IndependenceState] = []

        for m1, m2 in itertools.combinations(measurements, 2):
            s1 = sensors_by_id.get(m1.sensor_id)
            s2 = sensors_by_id.get(m2.sensor_id)
            if s1 is None or s2 is None:
                independence_votes.append(IndependenceState.UNKNOWN)
                continue

            if s1.sensor_id == s2.sensor_id:
                ind = IndependenceState.DEPENDENT
            elif s1.data_source == s2.data_source:
                ind = IndependenceState.DEPENDENT
                common_mode.append(f"Shared data_source: {s1.data_source}")
            elif s1.clock_source == s2.clock_source and s1.clock_source != "UNKNOWN":
                ind = IndependenceState.PARTIALLY_DEPENDENT
                common_mode.append(f"Shared clock_source: {s1.clock_source}")
            elif s1.sensor_type != s2.sensor_type:
                ind = IndependenceState.INDEPENDENT
            else:
                ind = IndependenceState.UNKNOWN

            independence_votes.append(ind)

            a1 = anomalies_by_measurement.get(m1.measurement_id)
            a2 = anomalies_by_measurement.get(m2.measurement_id)

            time_diff_h = abs((m1.timestamp - m2.timestamp).total_seconds()) / 3600.0
            loc_dist_m = haversine_m(m1.location_latitude, m1.location_longitude, m2.location_latitude, m2.location_longitude)

            same_context = time_diff_h <= 2.0 and (loc_dist_m is None or loc_dist_m <= 5000.0)

            if ind == IndependenceState.INDEPENDENT and same_context:
                if a1 and a2 and a1.statistical_significance in (AnomalySignificance.MODERATE, AnomalySignificance.STATISTICALLY_SIGNIFICANT) and a2.statistical_significance in (AnomalySignificance.MODERATE, AnomalySignificance.STATISTICALLY_SIGNIFICANT):
                    corroborations.append(
                        {
                            "measurement_a": m1.measurement_id,
                            "measurement_b": m2.measurement_id,
                            "sensor_a": m1.sensor_id,
                            "sensor_b": m2.sensor_id,
                            "independence": ind.value,
                            "time_difference_hours": round(time_diff_h, 3),
                            "location_distance_m": loc_dist_m,
                            "interpretation": "Independent sensors show consistent anomalies in same general context.",
                        }
                    )
                elif (a1 and not a2) or (a2 and not a1):
                    contradictions.append(
                        {
                            "measurement_a": m1.measurement_id,
                            "measurement_b": m2.measurement_id,
                            "type": "SENSOR_DISAGREEMENT",
                            "description": "One independent sensor shows anomaly while another does not in same context.",
                            "candidate_resolutions": [
                                "different physical quantity",
                                "different viewing geometry",
                                "sensor-specific artifact",
                                "phenomenon affects one modality only",
                            ],
                        }
                    )

        if not independence_votes:
            overall = IndependenceState.UNKNOWN
        elif all(v == IndependenceState.INDEPENDENT for v in independence_votes):
            overall = IndependenceState.INDEPENDENT
        elif any(v == IndependenceState.DEPENDENT for v in independence_votes):
            overall = IndependenceState.DEPENDENT
        elif any(v == IndependenceState.PARTIALLY_DEPENDENT for v in independence_votes):
            overall = IndependenceState.PARTIALLY_DEPENDENT
        else:
            overall = IndependenceState.UNKNOWN

        notes.append("Sensor fusion does not vote-count poor correlated sensors over one high-quality independent sensor.")
        notes.append("Common-mode errors may arise from weather, clock, calibration, processing, or platform.")

        return FusionAssessment(
            independence=overall,
            common_mode_errors=sorted(set(common_mode)),
            corroborations=corroborations,
            contradictions=contradictions,
            notes=notes,
        )


# ======================================================================
# SECTION 12 — FACT GATE / HYPOTHESES / ACH
# ======================================================================

class FactGate:
    def generate(
        self,
        *,
        case: Dict[str, Any],
        measurements: List[Measurement],
        sensors: List[Sensor],
        calibrations: List[CalibrationAssessment],
        healths: List[HealthAssessment],
        uncertainties: List[UncertaintyEstimate],
        baselines: List[Baseline],
        anomalies: List[Anomaly],
        features: List[FeatureVector],
        signatures: List[Signature],
        matches: List[MatchResult],
        classifications: List[ClassificationResult],
        fusion: Optional[FusionAssessment],
        environments: List[EnvironmentalContext],
    ) -> Dict[str, Any]:
        facts: List[Fact] = []
        hypotheses: List[Hypothesis] = []
        ach: List[ACHCell] = []
        contradictions: List[Contradiction] = []
        unknowns: List[str] = []
        limitations: List[str] = []
        gaps: List[KnowledgeGap] = []
        actions: List[NextAction] = []
        handoffs: List[SpecialistHandoff] = []

        sensors_by_id = {s.sensor_id: s for s in sensors}
        cal_by_meas = {c.measurement_id: c for c in calibrations}
        unc_by_meas = {u.measurement_id: u for u in uncertainties}
        anom_by_meas = {a.measurement_id: a for a in anomalies}

        # Measurement facts
        for m in measurements[:100]:
            sensor = sensors_by_id.get(m.sensor_id)
            sensor_desc = f"{sensor.sensor_type.value}" if sensor else "UNKNOWN_SENSOR"
            val = m.normalized_value
            unc = unc_by_meas.get(m.measurement_id)
            unc_txt = f"±{unc.combined:.3f}" if unc and unc.combined is not None else "±UNKNOWN"
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Sensor {m.sensor_id} ({sensor_desc}) recorded {m.measurement_type} "
                        f"normalized value {val if val is not None else 'NA'} {m.normalized_unit} "
                        f"{unc_txt} at {m.timestamp.isoformat()}."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=[m.evidence_id],
                    limitations=[
                        "This is a recorded measurement, not independent ground truth.",
                        "Interpretation requires calibration, environment, baseline, and uncertainty context.",
                    ],
                )
            )

        # Calibration facts
        for c in calibrations[:100]:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=f"Calibration state for measurement {c.measurement_id} is {c.state.value}.",
                    status=FactStatus.FACT if c.state != CalibrationState.CALIBRATION_UNKNOWN else FactStatus.UNKNOWN,
                    evidence_ids=[c.record_id] if c.record_id else [],
                    limitations=c.notes,
                )
            )
            if c.state in (CalibrationState.CALIBRATION_UNKNOWN, CalibrationState.CALIBRATION_EXPIRED, CalibrationState.CALIBRATION_SUSPECT):
                gaps.append(
                    KnowledgeGap(
                        gap_id=new_id("GAP"),
                        description=f"Calibration uncertain/expired for measurement {c.measurement_id}.",
                        importance="HIGH",
                        recommended_source="calibration certificate / instrument log",
                        specialist="METINT calibration verification",
                        expected_information_value="Reduces measurement uncertainty and false anomaly risk.",
                    )
                )
                actions.append(
                    NextAction(
                        action_id=new_id("ACT"),
                        description="Obtain calibration record for the sensor and measurement period.",
                        rationale="Calibration state materially affects measurement interpretation.",
                        priority="HIGH",
                    )
                )

        # Anomaly facts
        for a in anomalies[:100]:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Measurement {a.measurement_id} departs from baseline with z-score "
                        f"{a.z_score if a.z_score is not None else 'UNKNOWN'} "
                        f"({a.statistical_significance.value})."
                    ),
                    status=FactStatus.SUPPORTED if a.statistical_significance != AnomalySignificance.UNKNOWN else FactStatus.UNKNOWN,
                    evidence_ids=[],
                    limitations=[
                        "Anomaly is a baseline departure, not automatically threat, malfunction, or cause.",
                        "Operational significance remains UNKNOWN without context.",
                    ],
                )
            )

        # Match facts
        for mt in matches[:200]:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Signature {mt.signature_id} vs library {mt.entry_id} "
                        f"({mt.reference_class}): {mt.quality.value}, similarity={mt.similarity}."
                    ),
                    status=FactStatus.CANDIDATE if mt.quality not in (MatchQuality.NO_MATCH, MatchQuality.INSUFFICIENT_DATA) else FactStatus.UNKNOWN,
                    evidence_ids=[mt.match_id],
                    limitations=mt.limitations,
                )
            )

        # Classification facts
        for cl in classifications:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=f"Conservative classification candidate: {cl.label} at level {cl.level.value}, confidence {cl.confidence}.",
                    status=cl.status,
                    evidence_ids=cl.supporting_evidence_ids,
                    limitations=cl.limitations,
                )
            )
            handoffs.append(
                SpecialistHandoff(
                    handoff_id=new_id("HAND"),
                    specialist="TECHINT / IMINT / SATINT as authorized",
                    reason="Specific identity or platform attribution requires independent technical/imagery evidence.",
                    payload={"classification": cl.label, "confidence": cl.confidence},
                )
            )

        # Fusion facts
        if fusion:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=f"Sensor independence assessment: {fusion.independence.value}.",
                    status=FactStatus.SUPPORTED if fusion.independence != IndependenceState.UNKNOWN else FactStatus.UNKNOWN,
                    evidence_ids=[],
                    limitations=fusion.notes,
                )
            )
            for corr in fusion.corroborations:
                facts.append(
                    Fact(
                        fact_id=new_id("FACT"),
                        statement=(
                            f"Independent corroboration between {corr['sensor_a']} and {corr['sensor_b']} "
                            f"in same general time/location context."
                        ),
                        status=FactStatus.SUPPORTED,
                        evidence_ids=[corr["measurement_a"], corr["measurement_b"]],
                        limitations=["Corroboration strengthens observation, not attribution."],
                    )
                )
            for contra in fusion.contradictions:
                contradictions.append(
                    Contradiction(
                        contradiction_id=new_id("CONTRA"),
                        contradiction_type=contra["type"],
                        description=contra["description"],
                        evidence_ids=[contra["measurement_a"], contra["measurement_b"]],
                        candidate_resolutions=contra["candidate_resolutions"],
                        status="OPEN",
                    )
                )

        # Environmental context facts
        for e in environments[:50]:
            facts.append(
                Fact(
                    fact_id=new_id("FACT"),
                    statement=(
                        f"Environmental context at {e.timestamp.isoformat()}: "
                        f"air_T={e.air_temperature_K} K, humidity={e.humidity_fraction}, "
                        f"wind={e.wind_speed_m_s} m/s, solar={e.solar_irradiance_W_m2} W/m^2."
                    ),
                    status=FactStatus.FACT,
                    evidence_ids=[e.env_id],
                    limitations=["Environmental data may be sparse or representative of sensor site, not target region."],
                )
            )

        # Hypotheses for thermal/optical industrial-like anomaly
        hyp_active = Hypothesis(
            hypothesis_id=new_id("HYP"),
            statement="Observed signature is consistent with active industrial equipment.",
            supports=["Thermal anomaly", "Optical change candidate", "Daytime/operational context if supplied"],
            oppositions=["No direct operational record supplied", "Specific equipment identity unresolved"],
            unknowns=["Equipment state", "Operator", "Purpose"],
            falsification_tests=["Nighttime/low-solar observation removes anomaly", "Authorized operational records show no activity"],
        )
        hyp_solar = Hypothesis(
            hypothesis_id=new_id("HYP"),
            statement="Observed thermal signature is caused by solar heating or surface material response.",
            supports=["High solar irradiance context", "Optical reflectance change", "Diurnal pattern possible"],
            oppositions=["Independent optical anomaly may indicate non-solar process"],
            unknowns=["Surface material", "Viewing geometry", "Shading history"],
            falsification_tests=["Nighttime observation persists", "Thermal pattern inconsistent with insolation"],
        )
        hyp_drift = Hypothesis(
            hypothesis_id=new_id("HYP"),
            statement="Observation is caused by sensor drift, calibration error, or instrument artifact.",
            supports=["Calibration unknown/expired if present", "Single-modality anomaly"],
            oppositions=["Valid calibration record", "Independent sensor corroboration"],
            unknowns=["Sensor health history", "Maintenance logs"],
            falsification_tests=["Recalibration removes anomaly", "Peer sensors remain normal"],
        )
        hyp_atmo = Hypothesis(
            hypothesis_id=new_id("HYP"),
            statement="Atmospheric conditions or propagation effects altered the measurement.",
            supports=["Weather context available", "Remote sensing geometry"],
            oppositions=["Contact/industrial sensor unaffected by atmosphere"],
            unknowns=["Atmospheric profile", "Path geometry"],
            falsification_tests=["Different viewing geometry removes effect", "In-situ measurement confirms physical change"],
        )
        hyp_artifact = Hypothesis(
            hypothesis_id=new_id("HYP"),
            statement="Observation is a processing artifact, compression effect, clipping, or aliasing.",
            supports=["Sensor health flags", "Low sampling rate", "Saturation/clipping"],
            oppositions=["Raw data preserved and quality flags clean"],
            unknowns=["Processing pipeline version", "Original raw file integrity"],
            falsification_tests=["Reprocess raw data", "Compare independent raw feed"],
        )
        hypotheses.extend([hyp_active, hyp_solar, hyp_drift, hyp_atmo, hyp_artifact])

        # Simple ACH matrix
        evidence_items = {
            "E1_thermal_anomaly": any(a.measurement_id in [m.measurement_id for m in measurements if "thermal" in m.measurement_type.lower()] for a in anomalies),
            "E2_optical_change": any("optical" in m.measurement_type.lower() or "reflectance" in m.measurement_type.lower() for m in measurements),
            "E3_high_solar": any((e.solar_irradiance_W_m2 or 0) > 400 for e in environments),
            "E4_valid_calibration": any(c.state in (CalibrationState.CALIBRATED, CalibrationState.CALIBRATION_REPORTED) for c in calibrations),
            "E5_independent_corroboration": bool(fusion and fusion.corroborations),
        }

        for ev_id, present in evidence_items.items():
            if not present:
                continue
            if ev_id == "E1_thermal_anomaly":
                for hyp in [hyp_active, hyp_solar, hyp_drift, hyp_atmo, hyp_artifact]:
                    ach.append(ACHCell(ev_id, hyp.hypothesis_id, ACHRelation.CONSISTENT, "Thermal anomaly can be produced by multiple mechanisms."))
            if ev_id == "E2_optical_change":
                ach.append(ACHCell(ev_id, hyp_active.hypothesis_id, ACHRelation.CONSISTENT, "Active processes may alter optical signature."))
                ach.append(ACHCell(ev_id, hyp_solar.hypothesis_id, ACHRelation.CONSISTENT, "Solar illumination/material response may alter optical signature."))
                ach.append(ACHCell(ev_id, hyp_drift.hypothesis_id, ACHRelation.NEUTRAL, "Depends whether optical sensor is affected."))
            if ev_id == "E3_high_solar":
                ach.append(ACHCell(ev_id, hyp_solar.hypothesis_id, ACHRelation.CONSISTENT, "High solar irradiance supports heating hypothesis."))
                ach.append(ACHCell(ev_id, hyp_active.hypothesis_id, ACHRelation.NEUTRAL, "Solar context does not exclude machinery."))
            if ev_id == "E4_valid_calibration":
                ach.append(ACHCell(ev_id, hyp_drift.hypothesis_id, ACHRelation.INCONSISTENT, "Valid calibration weakens simple drift explanation."))
                ach.append(ACHCell(ev_id, hyp_artifact.hypothesis_id, ACHRelation.NEUTRAL, "Calibration does not rule out processing artifacts."))
            if ev_id == "E5_independent_corroboration":
                ach.append(ACHCell(ev_id, hyp_active.hypothesis_id, ACHRelation.CONSISTENT, "Independent modalities observing change supports physical phenomenon."))
                ach.append(ACHCell(ev_id, hyp_solar.hypothesis_id, ACHRelation.CONSISTENT, "Independent modalities can also corroborate environmental heating."))
                ach.append(ACHCell(ev_id, hyp_drift.hypothesis_id, ACHRelation.INCONSISTENT, "Independent corroboration weakens single-sensor drift."))

        # Generic limitations / unknowns
        limitations.extend(
            [
                "Measurement is not interpretation.",
                "Signature match is not identification.",
                "Detection is not attribution.",
                "Non-detection is not absence.",
                "Anomaly is not automatically threat.",
                "AI classifier output is not physical sensor evidence.",
                "Interpolation or generated detail is not original measurement.",
                "Calibration is not zero error.",
                "High precision is not high accuracy.",
            ]
        )
        unknowns.extend(
            [
                "Exact physical source of signature",
                "Operator or organization",
                "Intent or cause",
                "Specific equipment identity",
                "Whether change is operational, environmental, or artifact",
            ]
        )

        # Generic gaps/actions
        if not baselines:
            gaps.append(
                KnowledgeGap(
                    gap_id=new_id("GAP"),
                    description="No baseline supplied; anomaly significance weak.",
                    importance="HIGH",
                    recommended_source="historical sensor data / control site",
                    specialist="METINT baseline analysis",
                    expected_information_value="Distinguishes normal variation from departure.",
                )
            )
        if not environments:
            gaps.append(
                KnowledgeGap(
                    gap_id=new_id("GAP"),
                    description="Environmental confounders not supplied.",
                    importance="MEDIUM",
                    recommended_source="weather station / atmospheric model",
                    specialist="environmental context",
                    expected_information_value="Tests solar/weather/atmospheric explanations.",
                )
            )
        if not library_has_matches(matches):
            gaps.append(
                KnowledgeGap(
                    gap_id=new_id("GAP"),
                    description="Signature library produced no usable match.",
                    importance="MEDIUM",
                    recommended_source="validated reference signatures",
                    specialist="signature library curation",
                    expected_information_value="Improves classification coverage.",
                )
            )

        actions.extend(
            [
                NextAction(new_id("ACT"), "Retrieve calibration certificate for relevant sensor era.", "Reduces calibration uncertainty.", "HIGH"),
                NextAction(new_id("ACT"), "Compare with nighttime or low-solar-angle observations.", "Tests solar heating hypothesis.", "HIGH"),
                NextAction(new_id("ACT"), "Retrieve independent sensor modality if authorized.", "Tests common-mode sensor error.", "HIGH"),
                NextAction(new_id("ACT"), "Verify signature library version and collection conditions.", "Prevents stale or mismatched references.", "MEDIUM"),
                NextAction(new_id("ACT"), "Handoff geospatial refinement to GEOINT if location uncertainty matters.", "METINT resolves measurement, not precise where.", "MEDIUM"),
            ]
        )

        # Safety filter
        guard = PolicyGuard()
        actions = [a for a in actions if guard.is_safe_action(a.description)]

        return {
            "facts": facts,
            "hypotheses": hypotheses,
            "ach_matrix": ach,
            "contradictions": contradictions,
            "unknowns": sorted(set(unknowns)),
            "limitations": sorted(set(limitations)),
            "knowledge_gaps": gaps,
            "next_actions": actions,
            "specialist_handoffs": handoffs,
        }


def library_has_matches(matches: List[MatchResult]) -> bool:
    return any(m.quality not in (MatchQuality.NO_MATCH, MatchQuality.INSUFFICIENT_DATA) for m in matches)


# ======================================================================
# SECTION 13 — DUAL-AI REVIEW
# ======================================================================

class DualAIReviewer:
    def review(
        self,
        *,
        facts: List[Fact],
        calibrations: List[CalibrationAssessment],
        anomalies: List[Anomaly],
        matches: List[MatchResult],
        classifications: List[ClassificationResult],
        fusion: Optional[FusionAssessment],
        contradictions: List[Contradiction],
    ) -> Dict[str, Any]:
        notes: List[str] = []
        status = ReviewStatus.AGREE

        if any(c.state in (CalibrationState.CALIBRATION_UNKNOWN, CalibrationState.CALIBRATION_EXPIRED) for c in calibrations):
            notes.append("Calibration uncertain/expired; do not overtrust measurement magnitude.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(a.statistical_significance == AnomalySignificance.UNKNOWN for a in anomalies):
            notes.append("Anomaly significance unknown due weak baseline or uncertainty.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(m.quality == MatchQuality.STRONG_MATCH for m in matches):
            notes.append("Strong signature match still does not establish specific-instance identity.")

        if fusion and fusion.independence in (IndependenceState.DEPENDENT, IndependenceState.UNKNOWN):
            notes.append("Sensor independence is dependent/unknown; corroboration confidence reduced.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if contradictions:
            notes.append("Open contradictions remain; final classification should stay conservative.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if not facts:
            status = ReviewStatus.INSUFFICIENT_DATA
            notes.append("No facts generated.")

        human_review_required = bool(
            contradictions
            or any(cl.confidence in ("LOW", "MEDIUM") and cl.status == FactStatus.CANDIDATE for cl in classifications)
            or any(c.state == CalibrationState.CALIBRATION_UNKNOWN for c in calibrations)
        )

        return {
            "status": status.value,
            "skeptic_notes": notes,
            "rule": "AI agreement is not physical corroboration.",
            "human_review_required": human_review_required,
        }


# ======================================================================
# SECTION 14 — GRAPHICAL MEMORY
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

    def write_result(self, result: METINTResult) -> Dict[str, Any]:
        for s in result.sensors:
            self.add_node(
                s.sensor_id,
                "Sensor",
                {
                    "sensor_type": s.sensor_type.value,
                    "data_source": s.data_source,
                    "clock_source": s.clock_source,
                },
            )

        for m in result.measurements[:500]:
            self.add_node(
                m.measurement_id,
                "Measurement",
                {
                    "sensor_id": m.sensor_id,
                    "measurement_type": m.measurement_type,
                    "timestamp": m.timestamp.isoformat(),
                    "normalized_value": m.normalized_value,
                    "normalized_unit": m.normalized_unit,
                },
            )
            self.add_edge(m.measurement_id, "MEASURED_BY", m.sensor_id, {"evidence_id": m.evidence_id})

        for sig in result.signatures[:500]:
            self.add_node(sig.signature_id, "Signature", {"domain": sig.domain, "measurement_id": sig.measurement_id})
            self.add_edge(sig.measurement_id, "HAS_SIGNATURE", sig.signature_id)

        for mt in result.matches[:500]:
            self.add_node(mt.match_id, "SignatureMatch", {"quality": mt.quality.value, "similarity": mt.similarity})
            self.add_edge(mt.signature_id, "MATCHES_SIGNATURE_CANDIDATE", mt.match_id, {"entry_id": mt.entry_id})

        for cl in result.classifications:
            self.add_node(cl.classification_id, "Classification", {"label": cl.label, "level": cl.level.value, "confidence": cl.confidence})
            for ev in cl.supporting_evidence_ids:
                self.add_edge(cl.classification_id, "SUPPORTED_BY", ev)

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
# SECTION 15 — REPORT GENERATOR
# ======================================================================

class ReportGenerator:
    def generate(self, result: METINTResult) -> str:
        lines: List[str] = []

        def section(title: str) -> None:
            lines.append("")
            lines.append(title.upper())
            lines.append("-" * len(title))

        lines.append("=" * 72)
        lines.append("TRACEATLAS — METINT REPORT")
        lines.append("=" * 72)
        lines.append(f"Case ID: {result.case_id}")
        lines.append(f"Task ID: {result.task_id}")
        lines.append(f"Objective: {result.objective}")
        lines.append(f"Status: {result.status}")
        lines.append(f"Policy Decision: {result.policy_decision.value}")

        section("Safety / Privacy Boundary")
        lines.append("- Lawful measurement, signature, safety, environmental, and verification analysis only.")
        lines.append("- No weapon targeting, firing solution, strike coordinates, CBRN optimization, sensor defeat, jamming, spoofing, stealth/evasion, sabotage, or private-person stalking.")
        for flag in result.safety_flags:
            lines.append(f"- Safety: {flag}")
        for flag in result.privacy_flags:
            lines.append(f"- Privacy: {flag}")

        section("Sensor Inventory")
        if not result.sensors:
            lines.append("- No sensors supplied.")
        for s in result.sensors:
            lines.append(f"- {s.sensor_id}: type={s.sensor_type.value}, domain={s.measurement_domain or 'NA'}, data_source={s.data_source}, clock={s.clock_source}")
            lines.append(f"  calibration_state={s.calibration_state.value}, health_state={s.health_state.value}")
            if s.limitations:
                lines.append(f"  limitations={'; '.join(s.limitations)}")

        section("Calibration Assessments")
        if not result.calibration_assessments:
            lines.append("- None.")
        for c in result.calibration_assessments[:50]:
            lines.append(f"- Measurement {c.measurement_id}: {c.state.value}, record={c.record_id or 'NONE'}, uncertainty={c.uncertainty}")
            for n in c.notes:
                lines.append(f"  note: {n}")

        section("Sensor Health Assessments")
        if not result.health_assessments:
            lines.append("- None.")
        for h in result.health_assessments[:50]:
            lines.append(f"- Measurement {h.measurement_id}: {h.state.value}, flags={h.flags}")

        section("Measurements / Units / Uncertainty")
        if not result.measurements:
            lines.append("- No measurements.")
        unc_by_meas = {u.measurement_id: u for u in result.uncertainty_estimates}
        for m in result.measurements[:50]:
            u = unc_by_meas.get(m.measurement_id)
            unc = f"{u.combined:.4f}" if u and u.combined is not None else "UNKNOWN"
            lines.append(f"- {m.measurement_id}: sensor={m.sensor_id}, type={m.measurement_type}, time={m.timestamp.isoformat()}")
            lines.append(f"  raw_value={m.raw_value}, raw_values_count={len(m.raw_values) if m.raw_values else 0}")
            lines.append(f"  normalized_value={m.normalized_value}, unit={m.normalized_unit}, family={m.unit_family.value}")
            lines.append(f"  measurement_uncertainty={unc}, components={u.components if u else {}}")
            lines.append(f"  location=({m.location_latitude}, {m.location_longitude}), spatial_uncertainty_m={m.spatial_uncertainty_m}")
            if m.quality_flags:
                lines.append(f"  quality_flags={m.quality_flags}")

        section("Environmental Context")
        if not result.environmental_contexts:
            lines.append("- None supplied.")
        for e in result.environmental_contexts[:20]:
            lines.append(f"- {e.env_id}: time={e.timestamp.isoformat()}, air_T_K={e.air_temperature_K}, humidity={e.humidity_fraction}, wind_m_s={e.wind_speed_m_s}, solar_W_m2={e.solar_irradiance_W_m2}")

        section("Baselines / Anomalies")
        if not result.baselines:
            lines.append("- No baselines supplied.")
        for b in result.baselines[:20]:
            lines.append(f"- {b.baseline_id}: sensor={b.sensor_id}, type={b.measurement_type}, mean={b.mean}, std={b.std}, count={b.sample_count}, quality={b.quality.value}")
        if not result.anomalies:
            lines.append("- No anomalies computed.")
        for a in result.anomalies[:50]:
            lines.append(f"- {a.anomaly_id}: measurement={a.measurement_id}, z={a.z_score}, significance={a.statistical_significance.value}, operational={a.operational_significance}")

        section("Features / Signatures / Matches")
        for f in result.feature_vectors[:50]:
            lines.append(f"- Feature {f.feature_id}: measurement={f.measurement_id}, domain={f.domain}")
            lines.append(f"  features={ {k: round(v, 4) for k, v in f.features.items()} }")
        for s in result.signatures[:50]:
            lines.append(f"- Signature {s.signature_id}: domain={s.domain}, measurement={s.measurement_id}")
        for mt in result.matches[:100]:
            lines.append(f"- Match {mt.match_id}: signature={mt.signature_id}, class={mt.reference_class}, quality={mt.quality.value}, similarity={mt.similarity}")
            lines.append(f"  compared_features={mt.features_compared}")

        section("Classification")
        if not result.classifications:
            lines.append("- None.")
        for cl in result.classifications:
            lines.append(f"- {cl.classification_id}: label={cl.label}, level={cl.level.value}, confidence={cl.confidence}, status={cl.status.value}")
            lines.append(f"  alternatives={cl.alternatives}")
            lines.append(f"  limitations={cl.limitations}")

        section("Multi-Sensor Fusion")
        if not result.fusion_assessments:
            lines.append("- None.")
        for fu in result.fusion_assessments:
            lines.append(f"- Independence: {fu.independence.value}")
            lines.append(f"- Common-mode errors: {fu.common_mode_errors}")
            lines.append(f"- Corroborations: {len(fu.corroborations)}")
            for c in fu.corroborations[:10]:
                lines.append(f"  * {c}")
            lines.append(f"- Contradictions: {len(fu.contradictions)}")
            for c in fu.contradictions[:10]:
                lines.append(f"  * {c}")
            for n in fu.notes:
                lines.append(f"  note: {n}")

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

        section("Competing Hypotheses / ACH")
        for h in result.hypotheses:
            lines.append(f"- {h.hypothesis_id}: {h.statement}")
            lines.append(f"  supports: {h.supports}")
            lines.append(f"  oppositions: {h.oppositions}")
            lines.append(f"  falsification: {h.falsification_tests}")
        if result.ach_matrix:
            lines.append("ACH summary:")
            for cell in result.ach_matrix[:100]:
                lines.append(f"- {cell.evidence_id} vs {cell.hypothesis_id}: {cell.relation.value} — {cell.rationale}")

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
            lines.append("  - Human review required before consequential action.")

        lines.append("")
        lines.append("=" * 72)
        lines.append("END REPORT")
        lines.append("=" * 72)
        return "\n".join(lines)


# ======================================================================
# SECTION 16 — METINT AI EMPLOYEE
# ======================================================================

class METIntelligenceEmployee:
    def __init__(self, mode: ModelMode = ModelMode.LOCAL_ONLY):
        self.mode = mode
        self.policy = PolicyGuard()
        self.injection_defense = PromptInjectionDefense()
        self.ingestor = METINTIngestor(injection_defense=self.injection_defense)
        self.calibration_analyzer = CalibrationAnalyzer()
        self.health_analyzer = SensorHealthAnalyzer()
        self.uncertainty_model = UncertaintyModel()
        self.baseline_selector = BaselineSelector()
        self.anomaly_detector = AnomalyDetector()
        self.feature_extractor = FeatureExtractor()
        self.signature_builder = SignatureBuilder()
        self.signature_matcher = SignatureMatcher()
        self.classification_engine = ClassificationEngine()
        self.fusion = MultiSensorFusion()
        self.fact_gate = FactGate()
        self.reviewer = DualAIReviewer()
        self.memory = GraphicalMemory()
        self.reporter = ReportGenerator()

    def run_case(self, case: Dict[str, Any]) -> METINTResult:
        case_id = str(case.get("case_id", new_id("CASE")))
        task_id = str(case.get("task_id", new_id("TASK")))
        objective = str(case.get("objective", ""))
        questions = case.get("questions", [])

        request_text = objective + "\n" + "\n".join(str(q) for q in questions)
        policy = self.policy.check_request(request_text)

        if policy.decision == PolicyDecision.POLICY_BLOCKED:
            return METINTResult(
                case_id=case_id,
                task_id=task_id,
                objective=objective,
                status="POLICY_BLOCKED",
                policy_decision=PolicyDecision.POLICY_BLOCKED,
                report=(
                    "POLICY_BLOCKED\n\n"
                    "This request seeks prohibited METINT operational guidance. "
                    "Lawful alternative: authorized measurement validation, calibration review, "
                    "uncertainty analysis, baseline/anomaly assessment, signature candidate matching, "
                    "multi-sensor corroboration, safety/environmental interpretation, and evidence-linked reporting "
                    "without targeting, CBRN optimization, sensor defeat, jamming, spoofing, evasion, or sabotage."
                ),
                safety_flags=[
                    "No targeting/firing/strike guidance provided.",
                    "No sensor-defeat/evasion guidance provided.",
                    "No CBRN/explosive optimization provided.",
                ],
                limitations=[policy.reason],
            )

        (
            evidence,
            measurements,
            sensors,
            calibration_records,
            environments,
            baselines,
            library,
        ) = self.ingestor.ingest_case(case)

        sensors_by_id = {s.sensor_id: s for s in sensors}
        cal_assessments: List[CalibrationAssessment] = []
        health_assessments: List[HealthAssessment] = []
        uncertainty_estimates: List[UncertaintyEstimate] = []
        anomalies: List[Anomaly] = []
        feature_vectors: List[FeatureVector] = []
        signatures: List[Signature] = []
        matches: List[MatchResult] = []
        classifications: List[ClassificationResult] = []

        anomalies_by_measurement: Dict[str, Anomaly] = {}

        for m in measurements:
            sensor = sensors_by_id.get(m.sensor_id)
            if sensor is None:
                sensor = Sensor(sensor_id=m.sensor_id, sensor_type=SensorType.UNKNOWN, data_source="UNRESOLVED")
                sensors_by_id[m.sensor_id] = sensor
                sensors.append(sensor)
                m.quality_flags.append("SENSOR_UNRESOLVED")

            cal = self.calibration_analyzer.assess(m, sensor, calibration_records)
            cal_assessments.append(cal)

            health = self.health_analyzer.assess(sensor, m)
            health_assessments.append(health)

            unc = self.uncertainty_model.estimate(m, sensor, cal, health)
            uncertainty_estimates.append(unc)
            if unc.combined is not None:
                m.measurement_uncertainty = unc.combined
                m.uncertainty_components.update(unc.components)

            baseline = self.baseline_selector.choose(m, baselines)
            anomaly = self.anomaly_detector.detect(m, baseline, unc.combined)
            if anomaly:
                anomalies.append(anomaly)
                anomalies_by_measurement[m.measurement_id] = anomaly

            feat = self.feature_extractor.extract(m, sensor)
            feature_vectors.append(feat)

            sig = self.signature_builder.build(m, feat, sensor)
            signatures.append(sig)

            sig_matches = self.signature_matcher.match(sig, library)
            matches.extend(sig_matches)

        # Initial fusion for classification support
        fusion_assessment = self.fusion.assess(measurements, sensors_by_id, anomalies_by_measurement)

        for sig in signatures:
            sig_matches = [m for m in matches if m.signature_id == sig.signature_id]
            cl = self.classification_engine.classify(sig, sig_matches, fusion_assessment)
            classifications.append(cl)

        fact_out = self.fact_gate.generate(
            case=case,
            measurements=measurements,
            sensors=sensors,
            calibrations=cal_assessments,
            healths=health_assessments,
            uncertainties=uncertainty_estimates,
            baselines=baselines,
            anomalies=anomalies,
            features=feature_vectors,
            signatures=signatures,
            matches=matches,
            classifications=classifications,
            fusion=fusion_assessment,
            environments=environments,
        )

        review = self.reviewer.review(
            facts=fact_out["facts"],
            calibrations=cal_assessments,
            anomalies=anomalies,
            matches=matches,
            classifications=classifications,
            fusion=fusion_assessment,
            contradictions=fact_out["contradictions"],
        )

        status = "PARTIAL"
        if not measurements:
            status = "INSUFFICIENT_DATA"
        elif review.get("human_review_required"):
            status = "PARTIAL_HUMAN_REVIEW_REQUIRED"
        elif classifications and any(c.status == FactStatus.SUPPORTED for c in classifications):
            status = "SUCCEEDED"

        privacy_flags = []
        if self.mode == ModelMode.LOCAL_ONLY:
            privacy_flags.append("LOCAL_ONLY mode selected; sensitive measurement data should remain local.")
        elif self.mode == ModelMode.CLOUD:
            privacy_flags.append("CLOUD mode requires sanitized/aggregated/policy-approved data only.")
        else:
            privacy_flags.append("HYBRID mode requires routing controls and tenant isolation.")

        result = METINTResult(
            case_id=case_id,
            task_id=task_id,
            objective=objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW,
            evidence=evidence,
            sensors=sensors,
            calibration_records=calibration_records,
            environmental_contexts=environments,
            measurements=measurements,
            baselines=baselines,
            calibration_assessments=cal_assessments,
            health_assessments=health_assessments,
            uncertainty_estimates=uncertainty_estimates,
            anomalies=anomalies,
            feature_vectors=feature_vectors,
            signatures=signatures,
            signature_library=library,
            matches=matches,
            classifications=classifications,
            fusion_assessments=[fusion_assessment],
            contradictions=fact_out["contradictions"],
            facts=fact_out["facts"],
            hypotheses=fact_out["hypotheses"],
            ach_matrix=fact_out["ach_matrix"],
            knowledge_gaps=fact_out["knowledge_gaps"],
            next_actions=fact_out["next_actions"],
            specialist_handoffs=fact_out["specialist_handoffs"],
            review=review,
            unknowns=fact_out["unknowns"],
            limitations=fact_out["limitations"],
            safety_flags=[
                "No targeting/firing/strike guidance.",
                "No sensor-defeat/jamming/spoofing/evasion guidance.",
                "No CBRN/explosive optimization.",
                "Anomaly is not automatically threat.",
                "Signature match is not identity.",
                "Human review required for consequential action.",
            ],
            privacy_flags=privacy_flags,
        )

        result.graph = self.memory.write_result(result)
        result.report = self.reporter.generate(result)
        return result


# ======================================================================
# SECTION 17 — DEMO
# ======================================================================

def demo() -> None:
    """
    Synthetic lawful demo:
    Authorized industrial thermal/optical measurement verification.
    No real vessel/person targeting. No evasion/sensor-defeat content.
    """
    employee = METIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    case = {
        "case_id": "DEMO-METINT-001",
        "task_id": "DEMO-TASK-001",
        "objective": (
            "Lawful scientific verification: assess whether authorized thermal and optical measurements "
            "show a baseline anomaly consistent with industrial activity, while testing solar heating, "
            "sensor drift, and artifact alternatives."
        ),
        "questions": [
            "What was actually measured?",
            "Was the sensor calibrated during the observation period?",
            "Is the thermal observation anomalous relative to baseline?",
            "Does an independent optical measurement corroborate change?",
            "What classification level is safely supported?",
            "What remains unknown?",
        ],
        "authorization": "AUTHORIZED_SITE_TELEMETRY_LAWFUL_SAFETY_RESEARCH",
        "sensors": [
            {
                "sensor_id": "SENS_TH_001",
                "sensor_type": "THERMAL",
                "manufacturer": "DemoCorp",
                "model": "TCAM-100",
                "measurement_domain": "thermal_surface_temperature",
                "location_latitude": 40.7128,
                "location_longitude": -74.0060,
                "sampling_rate_hz": 0.001666,
                "resolution": 0.5,
                "sensitivity": 0.2,
                "dynamic_range_min": -20.0,
                "dynamic_range_max": 120.0,
                "calibration_state": "CALIBRATION_REPORTED",
                "health_state": "ONLINE",
                "clock_source": "GPS",
                "data_source": "authorized_site_thermal_feed",
                "limitations": ["Region-level footprint; not exact object-level thermometry."],
            },
            {
                "sensor_id": "SENS_OPT_002",
                "sensor_type": "OPTICAL",
                "manufacturer": "DemoCorp",
                "model": "OCAM-200",
                "measurement_domain": "optical_reflectance",
                "location_latitude": 40.7129,
                "location_longitude": -74.0059,
                "sampling_rate_hz": 0.001666,
                "resolution": 0.01,
                "dynamic_range_min": 0.0,
                "dynamic_range_max": 1.0,
                "calibration_state": "CALIBRATION_REPORTED",
                "health_state": "ONLINE",
                "clock_source": "GPS",
                "data_source": "authorized_site_optical_feed",
                "limitations": ["Reflectance proxy; illumination geometry affects values."],
            },
            {
                "sensor_id": "SENS_MET_003",
                "sensor_type": "METEOROLOGICAL",
                "manufacturer": "DemoWeather",
                "model": "WS-10",
                "measurement_domain": "environment",
                "location_latitude": 40.7130,
                "location_longitude": -74.0058,
                "clock_source": "NTP",
                "data_source": "authorized_weather_station",
            },
        ],
        "calibration_records": [
            {
                "calibration_id": "CAL_TH_2026_09",
                "sensor_id": "SENS_TH_001",
                "calibrated_at": "2026-09-01T00:00:00Z",
                "valid_until": "2026-10-01T00:00:00Z",
                "method": "blackbody_reference",
                "standard": "NIST-traceable demo standard",
                "uncertainty": 0.8,
                "uncertainty_unit": "K",
                "source_id": "site_calibration_log",
            },
            {
                "calibration_id": "CAL_OPT_2026_09",
                "sensor_id": "SENS_OPT_002",
                "calibrated_at": "2026-09-05T00:00:00Z",
                "valid_until": "2026-10-05T00:00:00Z",
                "method": "reflectance_panel",
                "standard": "demo certified panel",
                "uncertainty": 0.02,
                "uncertainty_unit": "dimensionless",
                "source_id": "site_calibration_log",
            },
        ],
        "environmental_contexts": [
            {
                "env_id": "ENV_2026_09_15_NOON",
                "timestamp": "2026-09-15T12:00:00Z",
                "location_latitude": 40.7130,
                "location_longitude": -74.0058,
                "air_temperature": 29.0,
                "air_temperature_unit": "C",
                "humidity": 45.0,
                "humidity_unit": "percent",
                "wind_speed": 3.2,
                "wind_speed_unit": "m/s",
                "pressure": 1013.0,
                "pressure_unit": "hPa",
                "cloud_cover": 10.0,
                "cloud_cover_unit": "percent",
                "solar_irradiance": 720.0,
                "solar_irradiance_unit": "W/m^2",
                "notes": ["Authorized site weather station."],
            }
        ],
        "baselines": [
            {
                "baseline_id": "BASE_TH_30D",
                "sensor_id": "SENS_TH_001",
                "measurement_type": "thermal_surface_temperature",
                "start_time": "2026-08-15T00:00:00Z",
                "end_time": "2026-09-14T00:00:00Z",
                "unit": "C",
                "values": [24.0, 25.0, 24.5, 26.0, 25.2, 24.8, 25.5, 26.1, 25.0, 24.7, 25.3, 26.2],
                "version": "baseline-30d-v1",
                "source_id": "historical_site_thermal",
            },
            {
                "baseline_id": "BASE_OPT_30D",
                "sensor_id": "SENS_OPT_002",
                "measurement_type": "optical_reflectance",
                "start_time": "2026-08-15T00:00:00Z",
                "end_time": "2026-09-14T00:00:00Z",
                "unit": "dimensionless",
                "values": [0.17, 0.18, 0.17, 0.19, 0.18, 0.175, 0.185, 0.178, 0.182, 0.176],
                "version": "baseline-30d-v1",
                "source_id": "historical_site_optical",
            },
        ],
        "measurements": [
            {
                "measurement_id": "MEAS_TH_DEMO_1",
                "sensor_id": "SENS_TH_001",
                "measurement_type": "thermal_surface_temperature",
                "timestamp": "2026-09-15T12:00:00Z",
                "unit": "C",
                "sample_interval_s": 600.0,
                "values": [28.1, 29.4, 35.2, 48.9, 52.3, 49.1, 38.2, 30.1],
                "location_latitude": 40.7128,
                "location_longitude": -74.0060,
                "spatial_uncertainty_m": 50.0,
                "measurement_uncertainty": 1.0,
                "source_id": "authorized_site_thermal_feed",
                "reference_frame": "site_local",
            },
            {
                "measurement_id": "MEAS_OPT_DEMO_1",
                "sensor_id": "SENS_OPT_002",
                "measurement_type": "optical_reflectance",
                "timestamp": "2026-09-15T12:00:00Z",
                "unit": "dimensionless",
                "sample_interval_s": 600.0,
                "values": [0.18, 0.19, 0.22, 0.31, 0.34, 0.30, 0.24, 0.20],
                "location_latitude": 40.7129,
                "location_longitude": -74.0059,
                "spatial_uncertainty_m": 50.0,
                "measurement_uncertainty": 0.02,
                "source_id": "authorized_site_optical_feed",
                "reference_frame": "site_local",
            },
            {
                "measurement_id": "MEAS_MET_DEMO_1",
                "sensor_id": "SENS_MET_003",
                "measurement_type": "air_temperature",
                "timestamp": "2026-09-15T12:00:00Z",
                "unit": "C",
                "value": 29.0,
                "location_latitude": 40.7130,
                "location_longitude": -74.0058,
                "measurement_uncertainty": 0.3,
                "source_id": "authorized_weather_station",
            },
        ],
        "signature_library": [
            {
                "entry_id": "LIB_INDUSTRIAL_ACTIVE",
                "library_version": "site-signature-lib-v1",
                "domain": "THERMAL:OPTICAL",
                "reference_class": "industrial_equipment_active",
                "features": {
                    "mean": 316.0,
                    "max": 326.0,
                    "range": 22.0,
                    "thermal_mean": 316.0,
                    "thermal_max": 326.0,
                    "thermal_contrast": 22.0,
                    "optical_range": 0.16,
                },
                "feature_units": {
                    "mean": "K",
                    "max": "K",
                    "range": "K",
                    "thermal_mean": "K",
                    "thermal_max": "K",
                    "thermal_contrast": "K",
                    "optical_range": "dimensionless",
                },
                "source": "authorized_reference_test",
                "uncertainty": 5.0,
                "limitations": ["Reference conditions may differ from current weather/load."],
            },
            {
                "entry_id": "LIB_SOLAR_HEATED",
                "library_version": "site-signature-lib-v1",
                "domain": "THERMAL:OPTICAL",
                "reference_class": "solar_heated_surface",
                "features": {
                    "mean": 312.0,
                    "max": 320.0,
                    "range": 15.0,
                    "thermal_mean": 312.0,
                    "thermal_max": 320.0,
                    "thermal_contrast": 15.0,
                    "optical_range": 0.10,
                },
                "feature_units": {
                    "mean": "K",
                    "max": "K",
                    "range": "K",
                    "thermal_mean": "K",
                    "thermal_max": "K",
                    "thermal_contrast": "K",
                    "optical_range": "dimensionless",
                },
                "source": "authorized_reference_test",
                "uncertainty": 4.0,
                "limitations": ["Strongly dependent on sun angle, material, and wind."],
            },
            {
                "entry_id": "LIB_SENSOR_DRIFT",
                "library_version": "site-signature-lib-v1",
                "domain": "THERMAL",
                "reference_class": "sensor_drift_or_calibration_error",
                "features": {
                    "mean": 303.0,
                    "max": 305.0,
                    "range": 3.0,
                    "thermal_mean": 303.0,
                    "thermal_max": 305.0,
                    "thermal_contrast": 3.0,
                },
                "feature_units": {
                    "mean": "K",
                    "max": "K",
                    "range": "K",
                    "thermal_mean": "K",
                    "thermal_max": "K",
                    "thermal_contrast": "K",
                },
                "source": "instrument_health_reference",
                "uncertainty": 1.0,
                "limitations": ["Drift patterns vary by instrument and environment."],
            },
        ],
    }

    result = employee.run_case(case)
    print(result.report)


def main() -> None:
    demo()


if __name__ == "__main__":
    main()