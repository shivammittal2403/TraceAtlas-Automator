"""
======================================================================
TRACEATLAS — SEISINT
SEISMIC / GEOPHYSICAL EVENT INTELLIGENCE AI EMPLOYEE
Python Implementation
======================================================================

Mode:
SCIENTIFIC / DEFENSIVE / AUTHORIZED / EVIDENCE-FIRST

Primary boundary:
Seismic event detection, characterization, correlation and assessment,
NOT explosion design, test-evasion or targeting.
"""

from __future__ import annotations

import hashlib
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
logger = logging.getLogger("SEISINT")


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


class StationHealth(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    NOISY = "NOISY"
    CLIPPED = "CLIPPED"
    TIMING_UNCERTAIN = "TIMING_UNCERTAIN"
    OFFLINE = "OFFLINE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class TimingQuality(str, Enum):
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"
    BAD = "BAD"
    UNKNOWN = "UNKNOWN"


class PhaseType(str, Enum):
    P_CANDIDATE = "P_CANDIDATE"
    P_SUPPORTED = "P_SUPPORTED"
    S_CANDIDATE = "S_CANDIDATE"
    S_SUPPORTED = "S_SUPPORTED"
    SURFACE_CANDIDATE = "SURFACE_CANDIDATE"
    UNKNOWN_PHASE = "UNKNOWN_PHASE"


class PhaseConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    AMBIGUOUS = "AMBIGUOUS"


class EventType(str, Enum):
    VERIFIED_EARTHQUAKE = "VERIFIED_EARTHQUAKE"
    EARTHQUAKE_SUPPORTED = "EARTHQUAKE_SUPPORTED"
    EARTHQUAKE_CANDIDATE = "EARTHQUAKE_CANDIDATE"
    ANTHROPOGENIC_EVENT_SUPPORTED = "ANTHROPOGENIC_EVENT_SUPPORTED"
    EXPLOSION_CANDIDATE = "EXPLOSION_CANDIDATE"
    QUARRY_BLAST_CANDIDATE = "QUARRY_BLAST_CANDIDATE"
    QUARRY_BLAST_SUPPORTED = "QUARRY_BLAST_SUPPORTED"
    MINING_EVENT_CANDIDATE = "MINING_EVENT_CANDIDATE"
    VOLCANIC_EVENT_CANDIDATE = "VOLCANIC_EVENT_CANDIDATE"
    COLLAPSE_CANDIDATE = "COLLAPSE_CANDIDATE"
    INDUCED_POSSIBLE = "INDUCED_POSSIBLE"
    INDUCED_SUPPORTED = "INDUCED_SUPPORTED"
    NOISE_ARTIFACT_CANDIDATE = "NOISE_ARTIFACT_CANDIDATE"
    UNKNOWN = "UNKNOWN"


class MagnitudeType(str, Enum):
    MW = "Mw"
    ML = "ML"
    MB = "mb"
    MS = "Ms"
    MD = "Md"
    MWP = "Mwp"
    ML_APPROX = "ML_APPROX"
    AMP_INDEX = "AMP_INDEX"
    CATALOG_REPORTED = "CATALOG_REPORTED"
    UNKNOWN = "UNKNOWN"


class CatalogMatchState(str, Enum):
    SAME_EVENT_SUPPORTED = "SAME_EVENT_SUPPORTED"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    DISTINCT = "DISTINCT"
    UNRESOLVED = "UNRESOLVED"


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


# ======================================================================
# SECTION 2 — UTILITIES
# ======================================================================

EARTH_RADIUS_KM = 6371.0


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
    if isinstance(value, cls):
        return value
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


def std(values: Iterable[Optional[float]]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return 0.0
    m = sum(vals) / len(vals)
    var = sum((x - m) ** 2 for x in vals) / (len(vals) - 1)
    return math.sqrt(var)


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def haversine_km(
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
        return EARTH_RADIUS_KM * c
    except Exception:
        return None


def hypocentral_distance_km(
    event_lat: Optional[float],
    event_lon: Optional[float],
    event_depth_km: Optional[float],
    station_lat: Optional[float],
    station_lon: Optional[float],
) -> Optional[float]:
    horiz = haversine_km(event_lat, event_lon, station_lat, station_lon)
    if horiz is None or event_depth_km is None:
        return None
    return math.sqrt(horiz * horiz + float(event_depth_km) * float(event_depth_km))


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


def hash_payload(payload: Any) -> str:
    try:
        canonical = json.dumps(payload, sort_keys=True, default=_json_default)
    except Exception:
        canonical = str(payload)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ======================================================================
# SECTION 3 — POLICY GUARD / PROMPT INJECTION DEFENSE
# ======================================================================

@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str = ""


class PolicyGuard:
    """
    Blocks requests seeking prohibited SEISINT operational guidance.
    Allows lawful scientific monitoring, verification, emergency-response,
    hazard assessment, and defensive seismic analysis.
    """

    PROHIBITED_PATTERNS = [
        r"(?:how\s+to|guide\s+to|instructions?\s+to|teach\s+me).*(?:design|optimize|conceal|hide|evade|reduce\s+detectability|disable|tamper|spoof|jam).*?(?:explosive|underground\s+test|nuclear\s+test|seismic\s+monitoring|sensor|station|waveform)",
        r"\b(?:explosive|bomb|warhead|energetic\s+material).*(?:design|synthesis|construction|optimization|formulation)",
        r"\b(?:underground|nuclear).*(?:test|explosion).*(?:conceal|hide|evade|maximize\s+yield|optimize|decoupl|cavity)",
        r"\b(?:seismic|station|sensor|network).*(?:disable|tamper|spoof|jam|evade\s+monitoring|reduce\s+detectability|blind)",
        r"\b(?:sabotage|attack|target).*(?:dam|mine|tunnel|fault|infrastructure|seismic\s+network|geophysical\s+sensor)",
        r"\b(?:targeting|strike|weapon).*(?:seismic|geophysical|fault|infrastructure|dam|mine|tunnel)",
        r"\b(?:destructive\s+geophysical|geophysical\s+weapon|earthquake\s+induction|fault\s+activation)",
    ]

    def __init__(self) -> None:
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.PROHIBITED_PATTERNS]

    def check_request(self, text: str) -> PolicyResult:
        t = text or ""
        for rx in self._compiled:
            if rx.search(t):
                return PolicyResult(
                    decision=PolicyDecision.POLICY_BLOCKED,
                    reason="Request seeks prohibited SEISINT operational guidance.",
                )
        return PolicyResult(decision=PolicyDecision.ALLOW, reason="")

    def is_safe_action(self, action: str) -> bool:
        return self.check_request(action).decision == PolicyDecision.ALLOW


class PromptInjectionDefense:
    """
    Catalog metadata, station notes, reports, documents, and external feeds
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
    evidence_id: str = field(default_factory=lambda: new_id("EV"))
    case_id: str = ""
    station_id: str = ""
    channel: str = ""
    network: str = ""
    location_code: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    sampling_rate: Optional[float] = None
    units: str = "UNKNOWN"
    waveform_hash: str = ""
    instrument_response_reference: str = ""
    data_quality_flags: List[str] = field(default_factory=list)
    clock_quality: str = "UNKNOWN"
    source_id: str = ""
    retrieved_at: Optional[datetime] = None
    processing_history: List[str] = field(default_factory=list)
    authorization_context: str = ""


@dataclass
class Station:
    station_id: str
    network_code: str = ""
    station_code: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    elevation_m: Optional[float] = None
    sensor_type: str = "UNKNOWN"
    channels: List[str] = field(default_factory=list)
    sampling_rate_hz: Optional[float] = None
    timing_source: str = "UNKNOWN"
    timing_quality: TimingQuality = TimingQuality.UNKNOWN
    health_status: StationHealth = StationHealth.UNKNOWN
    sensitivity_counts_per_physical: Optional[float] = None
    physical_unit: str = "UNKNOWN"
    local_magnitude_type: str = "ML_APPROX"
    clip_level: Optional[float] = None
    operational_period: str = "UNKNOWN"
    source: str = "UNKNOWN"
    limitations: List[str] = field(default_factory=list)


@dataclass
class Waveform:
    waveform_id: str = field(default_factory=lambda: new_id("WF"))
    station_id: str = ""
    channel: str = ""
    network: str = ""
    start_time: datetime = field(default_factory=utcnow)
    sampling_rate_hz: float = 50.0
    samples: List[float] = field(default_factory=list)
    units: str = "COUNTS"
    quality_flags: List[str] = field(default_factory=list)
    evidence_id: str = ""
    instrument_response_reference: str = ""
    clock_quality: str = "UNKNOWN"
    data_quality_flags: List[str] = field(default_factory=list)


@dataclass
class PreprocessingStep:
    step_id: str = field(default_factory=lambda: new_id("PRE"))
    waveform_id: str = ""
    operation: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    input_hash: str = ""
    output_hash: str = ""
    implemented_by: str = "SEISINT-deterministic"
    timestamp: datetime = field(default_factory=utcnow)


@dataclass
class SignalDetection:
    detection_id: str = field(default_factory=lambda: new_id("DET"))
    waveform_id: str = ""
    station_id: str = ""
    channel: str = ""
    onset_time: datetime = field(default_factory=utcnow)
    peak_time: datetime = field(default_factory=utcnow)
    sta_lta_ratio: Optional[float] = None
    threshold: Optional[float] = None
    method: str = "STA_LTA"
    peak_amplitude_counts: Optional[float] = None
    snr: Optional[float] = None
    confidence: PhaseConfidence = PhaseConfidence.LOW
    evidence_id: str = ""


@dataclass
class PhasePick:
    pick_id: str = field(default_factory=lambda: new_id("PICK"))
    station_id: str = ""
    channel: str = ""
    phase_type: PhaseType = PhaseType.UNKNOWN_PHASE
    pick_time: datetime = field(default_factory=utcnow)
    uncertainty_s: Optional[float] = None
    method: str = "AUTO"
    amplitude_counts: Optional[float] = None
    signal_to_noise: Optional[float] = None
    confidence: PhaseConfidence = PhaseConfidence.LOW
    analyst_or_model: str = "SEISINT-auto"
    evidence_id: str = ""
    waveform_id: str = ""


@dataclass
class VelocityModel:
    model_id: str = field(default_factory=lambda: new_id("VM"))
    name: str = "DEFAULT_1D"
    version: str = "v0"
    region: str = "GLOBAL_APPROX"
    vp_km_s: float = 6.0
    vs_km_s: float = 3.5
    max_depth_km: float = 30.0
    assumptions: List[str] = field(default_factory=lambda: ["constant velocity approximation"])
    source: str = "SEISINT-default"


@dataclass
class MagnitudeEstimate:
    magnitude_id: str = field(default_factory=lambda: new_id("MAG"))
    event_id: str = ""
    magnitude_type: str = MagnitudeType.UNKNOWN.value
    value: Optional[float] = None
    uncertainty: Optional[float] = None
    method: str = ""
    station_id: str = ""
    amplitude_counts: Optional[float] = None
    amplitude_physical: Optional[float] = None
    physical_unit: str = "UNKNOWN"
    distance_km: Optional[float] = None
    source: str = ""
    limitations: List[str] = field(default_factory=list)


@dataclass
class MomentTensor:
    mt_id: str = field(default_factory=lambda: new_id("MT"))
    event_id: str = ""
    mrr: Optional[float] = None
    mtt: Optional[float] = None
    mpp: Optional[float] = None
    mrt: Optional[float] = None
    mrp: Optional[float] = None
    mtp: Optional[float] = None
    isotropic_component_percent: Optional[float] = None
    double_couple_percent: Optional[float] = None
    clvd_percent: Optional[float] = None
    source: str = ""
    uncertainty: Optional[str] = None
    limitations: List[str] = field(default_factory=list)


@dataclass
class FocalMechanism:
    fm_id: str = field(default_factory=lambda: new_id("FM"))
    event_id: str = ""
    strike: Optional[float] = None
    dip: Optional[float] = None
    rake: Optional[float] = None
    mechanism_type: str = "UNKNOWN"
    source: str = ""
    uncertainty: Optional[str] = None
    limitations: List[str] = field(default_factory=list)


@dataclass
class SourceClassification:
    classification_id: str = field(default_factory=lambda: new_id("SRC"))
    event_id: str = ""
    primary_label: str = EventType.UNKNOWN.value
    status: str = "UNKNOWN"
    confidence: Confidence = Confidence.UNKNOWN
    supporting_features: List[str] = field(default_factory=list)
    opposing_features: List[str] = field(default_factory=list)
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    scores: Dict[str, float] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)


@dataclass
class SeismicEvent:
    event_id: str = field(default_factory=lambda: new_id("EVT"))
    origin_time: Optional[datetime] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    depth_km: Optional[float] = None
    horizontal_uncertainty_km: Optional[float] = None
    depth_uncertainty_km: Optional[float] = None
    station_count: int = 0
    phase_count: int = 0
    rms_residual_s: Optional[float] = None
    azimuthal_gap_deg: Optional[float] = None
    magnitude_estimates: List[MagnitudeEstimate] = field(default_factory=list)
    preferred_magnitude: Optional[MagnitudeEstimate] = None
    moment_tensor: Optional[MomentTensor] = None
    focal_mechanism: Optional[FocalMechanism] = None
    event_type: str = EventType.UNKNOWN.value
    source_classification: Optional[SourceClassification] = None
    velocity_model_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    pick_ids: List[str] = field(default_factory=list)
    status: str = "UNKNOWN"
    confidence: Confidence = Confidence.UNKNOWN
    limitations: List[str] = field(default_factory=list)


@dataclass
class CatalogEntry:
    catalog_event_id: str = field(default_factory=lambda: new_id("CAT"))
    agency: str = ""
    source_id: str = ""
    origin_time: Optional[datetime] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    depth_km: Optional[float] = None
    magnitude: Optional[float] = None
    magnitude_type: str = MagnitudeType.UNKNOWN.value
    event_type: str = "UNKNOWN"
    quality: str = "UNKNOWN"
    evidence_id: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CatalogMatch:
    match_id: str = field(default_factory=lambda: new_id("MATCH"))
    event_id: str = ""
    catalog_event_id: str = ""
    agency: str = ""
    match_state: CatalogMatchState = CatalogMatchState.UNRESOLVED
    time_diff_s: Optional[float] = None
    distance_km: Optional[float] = None
    depth_diff_km: Optional[float] = None
    magnitude_diff: Optional[float] = None
    limitations: List[str] = field(default_factory=list)


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
class SEISINTResult:
    case_id: str
    task_id: str
    objective: str
    status: str
    policy_decision: PolicyDecision = PolicyDecision.ALLOW

    evidence: List[Evidence] = field(default_factory=list)
    stations: List[Station] = field(default_factory=list)
    waveforms: List[Waveform] = field(default_factory=list)
    preprocessing_steps: List[PreprocessingStep] = field(default_factory=list)
    detections: List[SignalDetection] = field(default_factory=list)
    phase_picks: List[PhasePick] = field(default_factory=list)
    events: List[SeismicEvent] = field(default_factory=list)
    catalogs: List[CatalogEntry] = field(default_factory=list)
    catalog_matches: List[CatalogMatch] = field(default_factory=list)
    contradictions: List[Contradiction] = field(default_factory=list)
    facts: List[Fact] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    knowledge_gaps: List[KnowledgeGap] = field(default_factory=list)
    next_actions: List[NextAction] = field(default_factory=list)
    specialist_handoffs: List[SpecialistHandoff] = field(default_factory=list)

    velocity_models: List[VelocityModel] = field(default_factory=list)
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

class SEISINTIngestor:
    PARSER_VERSION = "SEISINT-parser-0.1.0"
    NORMALIZER_VERSION = "SEISINT-normalizer-0.1.0"

    def __init__(self, injection_defense: Optional[PromptInjectionDefense] = None):
        self.injection_defense = injection_defense or PromptInjectionDefense()

    def ingest_case(
        self, case: Dict[str, Any]
    ) -> Tuple[
        List[Evidence],
        List[Station],
        List[Waveform],
        List[CatalogEntry],
        List[VelocityModel],
        List[PhasePick],
    ]:
        case_id = str(case.get("case_id", new_id("CASE")))
        authorization = str(case.get("authorization", ""))

        stations = [self._parse_station(s, case_id, authorization) for s in case.get("stations", [])]
        station_map = {s.station_id: s for s in stations}

        waveforms: List[Waveform] = []
        evidence: List[Evidence] = []
        for w in case.get("waveforms", []):
            ev, wf = self._parse_waveform(w, case_id, authorization, station_map)
            evidence.append(ev)
            if wf is not None:
                waveforms.append(wf)

        catalogs = [self._parse_catalog(c, case_id, authorization) for c in case.get("catalogs", [])]
        velocity_models = [self._parse_velocity_model(v) for v in case.get("velocity_models", [])]
        if not velocity_models:
            velocity_models.append(VelocityModel())

        manual_picks = [self._parse_manual_pick(p) for p in case.get("phase_picks", [])]

        return evidence, stations, waveforms, catalogs, velocity_models, manual_picks

    def _parse_station(self, s: Dict[str, Any], case_id: str, authorization: str) -> Station:
        channels = [str(x) for x in s.get("channels", [])]
        return Station(
            station_id=str(s.get("station_id", new_id("STA"))),
            network_code=str(s.get("network_code", "")),
            station_code=str(s.get("station_code", "")),
            latitude=safe_float(s.get("latitude", s.get("lat"))),
            longitude=safe_float(s.get("longitude", s.get("lon"))),
            elevation_m=safe_float(s.get("elevation_m", s.get("elevation"))),
            sensor_type=str(s.get("sensor_type", "UNKNOWN")),
            channels=channels,
            sampling_rate_hz=safe_float(s.get("sampling_rate_hz")),
            timing_source=str(s.get("timing_source", "UNKNOWN")),
            timing_quality=enum_from(TimingQuality, s.get("timing_quality"), TimingQuality.UNKNOWN),
            health_status=enum_from(StationHealth, s.get("health_status"), StationHealth.UNKNOWN),
            sensitivity_counts_per_physical=safe_float(s.get("sensitivity_counts_per_physical")),
            physical_unit=str(s.get("physical_unit", "UNKNOWN")),
            local_magnitude_type=str(s.get("local_magnitude_type", "ML_APPROX")),
            clip_level=safe_float(s.get("clip_level")),
            operational_period=str(s.get("operational_period", "UNKNOWN")),
            source=str(s.get("source", "UNKNOWN")),
            limitations=[str(x) for x in s.get("limitations", [])],
        )

    def _parse_waveform(
        self,
        w: Dict[str, Any],
        case_id: str,
        authorization: str,
        station_map: Dict[str, Station],
    ) -> Tuple[Evidence, Optional[Waveform]]:
        station_id = str(w.get("station_id", "unknown_station"))
        station = station_map.get(station_id)
        channel = str(w.get("channel", (station.channels[0] if station and station.channels else "HHZ")))
        start_time = to_datetime(w.get("start_time")) or utcnow()
        fs = safe_float(w.get("sampling_rate_hz")) or (station.sampling_rate_hz if station else 50.0) or 50.0
        samples = [safe_float(x) for x in w.get("samples", [])]
        samples = [s for s in samples if s is not None]

        quality_flags: List[str] = []
        if not samples:
            quality_flags.append("EMPTY_WAVEFORM")
        if fs is None or fs <= 0:
            quality_flags.append("INVALID_SAMPLING_RATE")
            fs = 50.0

        clip_level = safe_float(w.get("clip_level")) or (station.clip_level if station else None)
        if clip_level is not None and any(abs(s) >= clip_level * 0.98 for s in samples):
            quality_flags.append("CLIPPED")

        if station and station.timing_quality == TimingQuality.BAD:
            quality_flags.append("STATION_TIMING_BAD")

        raw_payload = dict(w)
        for key in ("notes", "metadata", "comment"):
            if key in raw_payload:
                raw_payload[f"_sanitized_{key}"] = self.injection_defense.sanitize(raw_payload.get(key))

        wf_hash = hash_payload(samples)
        ev = Evidence(
            case_id=case_id,
            station_id=station_id,
            channel=channel,
            network=str(w.get("network", station.network_code if station else "")),
            location_code=str(w.get("location_code", "")),
            start_time=start_time,
            end_time=start_time + timedelta(seconds=len(samples) / fs) if samples and fs else None,
            sampling_rate=fs,
            units=str(w.get("units", "COUNTS")),
            waveform_hash=wf_hash,
            instrument_response_reference=str(w.get("instrument_response_reference", "")),
            data_quality_flags=quality_flags,
            clock_quality=str(w.get("clock_quality", station.timing_quality.value if station else "UNKNOWN")),
            source_id=str(w.get("source_id", station.source if station else "UNKNOWN")),
            retrieved_at=utcnow(),
            processing_history=[f"parser={self.PARSER_VERSION}", f"normalizer={self.NORMALIZER_VERSION}"],
            authorization_context=authorization,
        )

        wf = Waveform(
            station_id=station_id,
            channel=channel,
            network=ev.network,
            start_time=start_time,
            sampling_rate_hz=fs,
            samples=samples,
            units=ev.units,
            quality_flags=quality_flags,
            evidence_id=ev.evidence_id,
            instrument_response_reference=ev.instrument_response_reference,
            clock_quality=ev.clock_quality,
            data_quality_flags=quality_flags,
        )
        return ev, wf

    def _parse_catalog(self, c: Dict[str, Any], case_id: str, authorization: str) -> CatalogEntry:
        raw = dict(c)
        for key in ("notes", "comment", "description"):
            if key in raw:
                raw[f"_sanitized_{key}"] = self.injection_defense.sanitize(raw.get(key))
        ev = Evidence(
            case_id=case_id,
            source_id=str(c.get("source_id", c.get("agency", "catalog"))),
            authorization_context=authorization,
            waveform_hash=hash_payload(raw),
            data_quality_flags=[str(x) for x in c.get("quality_flags", [])],
        )
        return CatalogEntry(
            catalog_event_id=str(c.get("catalog_event_id", ev.evidence_id)),
            agency=str(c.get("agency", "UNKNOWN")),
            source_id=str(c.get("source_id", c.get("agency", "UNKNOWN"))),
            origin_time=to_datetime(c.get("origin_time", c.get("time"))),
            latitude=safe_float(c.get("latitude", c.get("lat"))),
            longitude=safe_float(c.get("longitude", c.get("lon"))),
            depth_km=safe_float(c.get("depth_km", c.get("depth"))),
            magnitude=safe_float(c.get("magnitude", c.get("mag"))),
            magnitude_type=str(c.get("magnitude_type", MagnitudeType.CATALOG_REPORTED.value)),
            event_type=str(c.get("event_type", "UNKNOWN")),
            quality=str(c.get("quality", "UNKNOWN")),
            evidence_id=ev.evidence_id,
            raw=raw,
        )

    def _parse_velocity_model(self, v: Dict[str, Any]) -> VelocityModel:
        return VelocityModel(
            model_id=str(v.get("model_id", new_id("VM"))),
            name=str(v.get("name", "CUSTOM")),
            version=str(v.get("version", "v0")),
            region=str(v.get("region", "UNKNOWN")),
            vp_km_s=safe_float(v.get("vp_km_s")) or 6.0,
            vs_km_s=safe_float(v.get("vs_km_s")) or 3.5,
            max_depth_km=safe_float(v.get("max_depth_km")) or 30.0,
            assumptions=[str(x) for x in v.get("assumptions", [])],
            source=str(v.get("source", "case_supplied")),
        )

    def _parse_manual_pick(self, p: Dict[str, Any]) -> PhasePick:
        phase = enum_from(PhaseType, p.get("phase_type", p.get("phase")), PhaseType.UNKNOWN_PHASE)
        return PhasePick(
            station_id=str(p.get("station_id", "")),
            channel=str(p.get("channel", "")),
            phase_type=phase,
            pick_time=to_datetime(p.get("pick_time", p.get("time"))) or utcnow(),
            uncertainty_s=safe_float(p.get("uncertainty_s")),
            method="MANUAL",
            amplitude_counts=safe_float(p.get("amplitude_counts")),
            signal_to_noise=safe_float(p.get("snr")),
            confidence=enum_from(PhaseConfidence, p.get("confidence"), PhaseConfidence.MEDIUM),
            analyst_or_model=str(p.get("analyst", "human_manual")),
            evidence_id=str(p.get("evidence_id", "")),
            waveform_id=str(p.get("waveform_id", "")),
        )


# ======================================================================
# SECTION 6 — PREPROCESSING / DETECTION / PHASE PICKING
# ======================================================================

class WaveformPreprocessor:
    def demean_detrend(self, wf: Waveform) -> Tuple[List[float], PreprocessingStep]:
        samples = list(wf.samples)
        n = len(samples)
        if n == 0:
            out: List[float] = []
        elif n == 1:
            out = [0.0]
        else:
            mean_val = sum(samples) / n
            x_mean = (n - 1) / 2.0
            y_mean = mean_val
            cov = sum((i - x_mean) * (samples[i] - y_mean) for i in range(n))
            var = sum((i - x_mean) ** 2 for i in range(n))
            slope = cov / var if var != 0 else 0.0
            intercept = y_mean - slope * x_mean
            out = [samples[i] - (intercept + slope * i) for i in range(n)]

        step = PreprocessingStep(
            waveform_id=wf.waveform_id,
            operation="DEMEAN_DETREND",
            parameters={"n": n},
            input_hash=hash_payload(wf.samples),
            output_hash=hash_payload(out),
        )
        return out, step


class SignalDetector:
    def __init__(
        self,
        short_window_s: float = 1.0,
        long_window_s: float = 10.0,
        threshold: float = 3.0,
        min_separation_s: float = 0.5,
    ):
        self.short_window_s = short_window_s
        self.long_window_s = long_window_s
        self.threshold = threshold
        self.min_separation_s = min_separation_s

    def detect(self, wf: Waveform, samples: List[float]) -> List[SignalDetection]:
        n = len(samples)
        fs = wf.sampling_rate_hz
        if n == 0 or fs <= 0:
            return []

        short_win = max(1, int(fs * self.short_window_s))
        long_win = max(short_win + 1, int(fs * self.long_window_s))
        if n < long_win + short_win:
            return []

        abs_s = [abs(x) for x in samples]
        prefix = [0.0] * (n + 1)
        for i, v in enumerate(abs_s):
            prefix[i + 1] = prefix[i] + v

        detections: List[SignalDetection] = []
        armed = True
        eps = 1e-12

        for i in range(long_win, n - short_win + 1):
            sta = (prefix[i] - prefix[i - short_win]) / short_win
            lta = (prefix[i] - prefix[i - long_win]) / long_win
            ratio = sta / (lta + eps)

            if armed and ratio > self.threshold:
                window_end = min(n, i + int(fs * 2.0))
                if window_end <= i:
                    window_end = i + 1
                peak_idx = max(range(i, window_end), key=lambda j: abs_s[j])
                peak_amp = abs_s[peak_idx]
                onset_time = wf.start_time + timedelta(seconds=i / fs)
                peak_time = wf.start_time + timedelta(seconds=peak_idx / fs)

                detections.append(
                    SignalDetection(
                        waveform_id=wf.waveform_id,
                        station_id=wf.station_id,
                        channel=wf.channel,
                        onset_time=onset_time,
                        peak_time=peak_time,
                        sta_lta_ratio=ratio,
                        threshold=self.threshold,
                        method="STA_LTA",
                        peak_amplitude_counts=peak_amp,
                        snr=ratio,
                        confidence=PhaseConfidence.MEDIUM if ratio > 10 else PhaseConfidence.LOW,
                        evidence_id=wf.evidence_id,
                    )
                )
                armed = False

            if not armed and ratio < self.threshold * 0.5:
                armed = True

        return detections


class PhasePicker:
    def pick(
        self,
        waveforms: List[Waveform],
        detections_by_waveform: Dict[str, List[SignalDetection]],
        station_map: Dict[str, Station],
        manual_picks: List[PhasePick],
    ) -> List[PhasePick]:
        picks: List[PhasePick] = list(manual_picks)

        for wf in waveforms:
            dets = sorted(detections_by_waveform.get(wf.waveform_id, []), key=lambda d: d.onset_time)
            if not dets:
                continue

            station = station_map.get(wf.station_id)
            last_time: Optional[datetime] = None
            last_phase: Optional[PhaseType] = None

            for det in dets:
                if last_time is None:
                    phase = PhaseType.P_CANDIDATE
                else:
                    dt = (det.onset_time - last_time).total_seconds()
                    if dt < 0.25:
                        continue
                    if last_phase in (PhaseType.P_CANDIDATE, PhaseType.P_SUPPORTED) and 0.25 <= dt < 30.0:
                        phase = PhaseType.S_CANDIDATE
                    elif dt >= 30.0:
                        phase = PhaseType.SURFACE_CANDIDATE
                    else:
                        phase = PhaseType.UNKNOWN_PHASE

                confidence = PhaseConfidence.LOW
                if station and station.health_status == StationHealth.HEALTHY and station.timing_quality == TimingQuality.GOOD:
                    if det.snr is not None and det.snr > 10:
                        confidence = PhaseConfidence.HIGH
                    elif det.snr is not None and det.snr > 4:
                        confidence = PhaseConfidence.MEDIUM

                uncertainty = max(1.0 / wf.sampling_rate_hz, 0.05)
                if confidence == PhaseConfidence.LOW:
                    uncertainty += 0.10

                picks.append(
                    PhasePick(
                        station_id=wf.station_id,
                        channel=wf.channel,
                        phase_type=phase,
                        pick_time=det.onset_time,
                        uncertainty_s=uncertainty,
                        method="STA_LTA_AUTO",
                        amplitude_counts=det.peak_amplitude_counts,
                        signal_to_noise=det.snr,
                        confidence=confidence,
                        analyst_or_model="SEISINT-auto",
                        evidence_id=wf.evidence_id,
                        waveform_id=wf.waveform_id,
                    )
                )
                last_time = det.onset_time
                last_phase = phase

        return picks


# ======================================================================
# SECTION 7 — EVENT ASSOCIATION / LOCATION
# ======================================================================

class GridLocator:
    def locate(
        self,
        picks: List[PhasePick],
        station_map: Dict[str, Station],
        vm: VelocityModel,
    ) -> Optional[SeismicEvent]:
        usable = []
        for p in picks:
            st = station_map.get(p.station_id)
            if st is None or st.latitude is None or st.longitude is None:
                continue
            if st.timing_quality == TimingQuality.BAD:
                continue
            usable.append((p, st))

        if len(usable) < 2:
            return None

        lats = [st.latitude for _, st in usable]
        lons = [st.longitude for _, st in usable]
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)

        lat_span = max(0.05, max_lat - min_lat)
        lon_span = max(0.05, max_lon - min_lon)
        margin = max(0.08, 0.25 * max(lat_span, lon_span))

        lat_start = min_lat - margin
        lat_end = max_lat + margin
        lon_start = min_lon - margin
        lon_end = max_lon + margin

        n_grid = 17
        depth_step = 2.0
        max_depth = vm.max_depth_km

        lat_step = (lat_end - lat_start) / max(1, n_grid - 1)
        lon_step = (lon_end - lon_start) / max(1, n_grid - 1)
        depth_points = max(3, int(max_depth / depth_step) + 1)

        # Reduce grid if too large.
        while n_grid * n_grid * depth_points > 8000 and n_grid > 7:
            n_grid -= 2
            lat_step = (lat_end - lat_start) / max(1, n_grid - 1)
            lon_step = (lon_end - lon_start) / max(1, n_grid - 1)

        best: Optional[Dict[str, Any]] = None

        for il in range(n_grid):
            lat = lat_start + il * lat_step
            for ino in range(n_grid):
                lon = lon_start + ino * lon_step
                for idp in range(depth_points):
                    depth = idp * depth_step
                    origin_vals: List[float] = []
                    residuals: List[float] = []

                    for p, st in usable:
                        dist = hypocentral_distance_km(lat, lon, depth, st.latitude, st.longitude)
                        if dist is None:
                            continue
                        vel = vm.vp_km_s
                        if p.phase_type in (PhaseType.S_CANDIDATE, PhaseType.S_SUPPORTED):
                            vel = vm.vs_km_s
                        if vel <= 0:
                            continue
                        tt = dist / vel
                        epoch = p.pick_time.timestamp()
                        origin_vals.append(epoch - tt)

                    if not origin_vals:
                        continue

                    origin = median(origin_vals)
                    if origin is None:
                        continue

                    for p, st in usable:
                        dist = hypocentral_distance_km(lat, lon, depth, st.latitude, st.longitude)
                        if dist is None:
                            continue
                        vel = vm.vp_km_s
                        if p.phase_type in (PhaseType.S_CANDIDATE, PhaseType.S_SUPPORTED):
                            vel = vm.vs_km_s
                        if vel <= 0:
                            continue
                        predicted = origin + dist / vel
                        residuals.append(p.pick_time.timestamp() - predicted)

                    if not residuals:
                        continue

                    rms = math.sqrt(sum(r * r for r in residuals) / len(residuals))

                    if best is None or rms < best["rms"]:
                        best = {
                            "lat": lat,
                            "lon": lon,
                            "depth": depth,
                            "origin": origin,
                            "rms": rms,
                            "station_count": len({p.station_id for p, _ in usable}),
                            "phase_count": len(usable),
                            "usable": usable,
                        }

        if best is None:
            return None

        bearings = []
        for _, st in best["usable"]:
            b = bearing_deg(best["lat"], best["lon"], st.latitude, st.longitude)
            if b is not None:
                bearings.append(b)

        azimuthal_gap = None
        if bearings:
            bearings.sort()
            gaps = [(bearings[(i + 1) % len(bearings)] - bearings[i]) % 360.0 for i in range(len(bearings))]
            azimuthal_gap = max(gaps) if gaps else 360.0

        approx_grid_km = max(
            0.5,
            lat_step * 111.0,
            lon_step * 111.0 * max(0.2, math.cos(math.radians(best["lat"]))),
        )

        horizontal_unc = max(1.0, best["rms"] * vm.vp_km_s * 2.0 + approx_grid_km)
        depth_unc = max(1.0, best["rms"] * vm.vp_km_s * 2.0 + depth_step)

        if best["station_count"] < 3:
            horizontal_unc *= 2.0
            depth_unc *= 2.0

        confidence = Confidence.LOW
        status = "LOCATION_CANDIDATE"
        if best["station_count"] >= 4 and best["rms"] < 0.75 and (azimuthal_gap is None or azimuthal_gap < 180):
            confidence = Confidence.MEDIUM
            status = "LOCATION_SUPPORTED"
        elif best["station_count"] >= 3 and best["rms"] < 1.5:
            confidence = Confidence.LOW
            status = "LOCATION_CANDIDATE"
        else:
            status = "LOCATION_UNRESOLVED"

        return SeismicEvent(
            origin_time=datetime.fromtimestamp(best["origin"], tz=timezone.utc),
            latitude=best["lat"],
            longitude=best["lon"],
            depth_km=best["depth"],
            horizontal_uncertainty_km=horizontal_unc,
            depth_uncertainty_km=depth_unc,
            station_count=best["station_count"],
            phase_count=best["phase_count"],
            rms_residual_s=best["rms"],
            azimuthal_gap_deg=azimuthal_gap,
            velocity_model_id=vm.model_id,
            status=status,
            confidence=confidence,
            limitations=[
                "Location uses a simplified constant-velocity grid search.",
                "Depth and epicenter are model-dependent.",
                "Uncertainty includes grid spacing and residual RMS approximation.",
            ],
            pick_ids=[p.pick_id for p, _ in best["usable"]],
        )


class EventAssociator:
    def __init__(self, association_window_s: float = 20.0):
        self.association_window_s = association_window_s

    def associate(
        self,
        picks: List[PhasePick],
        station_map: Dict[str, Station],
        vm: VelocityModel,
    ) -> List[SeismicEvent]:
        usable = [
            p for p in picks
            if p.station_id in station_map
            and station_map[p.station_id].latitude is not None
            and station_map[p.station_id].longitude is not None
            and station_map[p.station_id].timing_quality != TimingQuality.BAD
        ]
        usable.sort(key=lambda x: x.pick_time)

        clusters: List[List[PhasePick]] = []
        current: List[PhasePick] = []

        for p in usable:
            if not current:
                current = [p]
                continue
            if (p.pick_time - current[0].pick_time).total_seconds() <= self.association_window_s:
                current.append(p)
            else:
                clusters.append(current)
                current = [p]
        if current:
            clusters.append(current)

        events: List[SeismicEvent] = []
        locator = GridLocator()

        for cluster in clusters:
            best_by_station: Dict[str, PhasePick] = {}
            for p in cluster:
                old = best_by_station.get(p.station_id)
                if old is None or self._better(p, old):
                    best_by_station[p.station_id] = p

            picks_for_location = [p for p in best_by_station.values() if p.phase_type in (PhaseType.P_CANDIDATE, PhaseType.P_SUPPORTED)]
            if len(picks_for_location) < 2:
                picks_for_location = list(best_by_station.values())

            if len(picks_for_location) < 2:
                continue

            ev = locator.locate(picks_for_location, station_map, vm)
            if ev is None:
                continue

            ev.evidence_ids = sorted({p.evidence_id for p in picks_for_location if p.evidence_id})
            ev.pick_ids = [p.pick_id for p in picks_for_location]
            events.append(ev)

        return events

    @staticmethod
    def _better(a: PhasePick, b: PhasePick) -> bool:
        rank = {
            PhaseType.P_SUPPORTED: 6,
            PhaseType.P_CANDIDATE: 5,
            PhaseType.S_SUPPORTED: 4,
            PhaseType.S_CANDIDATE: 3,
            PhaseType.SURFACE_CANDIDATE: 2,
            PhaseType.UNKNOWN_PHASE: 1,
        }
        conf = {
            PhaseConfidence.HIGH: 3,
            PhaseConfidence.MEDIUM: 2,
            PhaseConfidence.LOW: 1,
            PhaseConfidence.AMBIGUOUS: 0,
        }
        return (rank.get(a.phase_type, 0), conf.get(a.confidence, 0), a.signal_to_noise or 0.0) > (
            rank.get(b.phase_type, 0), conf.get(b.confidence, 0), b.signal_to_noise or 0.0
        )


# ======================================================================
# SECTION 8 — MAGNITUDE / CATALOG / SOURCE DISCRIMINATION
# ======================================================================

class MagnitudeEstimator:
    def __init__(self, alpha: float = 1.1, beta: float = -1.0):
        self.alpha = alpha
        self.beta = beta

    def estimate(
        self,
        event: SeismicEvent,
        picks: List[PhasePick],
        waveforms: List[Waveform],
        station_map: Dict[str, Station],
    ) -> List[MagnitudeEstimate]:
        wf_by_key: Dict[Tuple[str, str], Waveform] = {}
        for wf in waveforms:
            wf_by_key[(wf.station_id, wf.channel)] = wf
            if wf.station_id not in {k[0] for k in wf_by_key}:
                wf_by_key[(wf.station_id, "")] = wf

        estimates: List[MagnitudeEstimate] = []

        for p in picks:
            if p.phase_type not in (PhaseType.P_CANDIDATE, PhaseType.P_SUPPORTED):
                continue
            st = station_map.get(p.station_id)
            if st is None:
                continue
            wf = wf_by_key.get((p.station_id, p.channel)) or wf_by_key.get((p.station_id, ""))
            if wf is None or not wf.samples:
                continue

            idx = int((p.pick_time - wf.start_time).total_seconds() * wf.sampling_rate_hz)
            window = max(1, int(wf.sampling_rate_hz * 2.0))
            start = max(0, idx - window)
            end = min(len(wf.samples), idx + window)
            if start >= end:
                continue

            amp_counts = max(abs(x) for x in wf.samples[start:end])
            dist = hypocentral_distance_km(
                event.latitude,
                event.longitude,
                event.depth_km,
                st.latitude,
                st.longitude,
            )
            if dist is None or dist <= 0:
                continue

            physical_amp = None
            if st.sensitivity_counts_per_physical and st.sensitivity_counts_per_physical > 0:
                physical_amp = amp_counts / st.sensitivity_counts_per_physical

            value = None
            mag_type = MagnitudeType.AMP_INDEX.value
            limitations = ["Amplitude-derived magnitude is approximate and requires calibration."]

            if physical_amp is not None and physical_amp > 0:
                value = math.log10(max(physical_amp, 1e-9)) + self.alpha * math.log10(max(dist, 1.0)) + self.beta
                mag_type = st.local_magnitude_type or MagnitudeType.ML_APPROX.value
                limitations.append("Uses simplified local-magnitude approximation; not an authoritative agency value.")
            else:
                value = math.log10(max(amp_counts, 1e-9))
                limitations.append("Physical unit conversion unavailable; amplitude index only.")

            estimates.append(
                MagnitudeEstimate(
                    event_id=event.event_id,
                    magnitude_type=mag_type,
                    value=value,
                    uncertainty=0.3 + min(1.0, event.rms_residual_s or 0.0),
                    method="AMPLITUDE_DISTANCE_APPROX",
                    station_id=p.station_id,
                    amplitude_counts=amp_counts,
                    amplitude_physical=physical_amp,
                    physical_unit=st.physical_unit,
                    distance_km=dist,
                    source=st.source,
                    limitations=limitations,
                )
            )

        return estimates

    @staticmethod
    def choose_preferred(event: SeismicEvent, estimates: List[MagnitudeEstimate]) -> Optional[MagnitudeEstimate]:
        if not estimates:
            return None
        vals = [e.value for e in estimates if e.value is not None]
        if not vals:
            return None
        med = median(vals)
        best = min(estimates, key=lambda e: abs((e.value or 0.0) - (med or 0.0)))
        best_copy = MagnitudeEstimate(
            magnitude_id=best.magnitude_id,
            event_id=event.event_id,
            magnitude_type=best.magnitude_type,
            value=med,
            uncertainty=best.uncertainty,
            method="MEDIAN_OF_STATION_ESTIMATES",
            station_id="MULTI",
            amplitude_counts=best.amplitude_counts,
            amplitude_physical=best.amplitude_physical,
            physical_unit=best.physical_unit,
            distance_km=best.distance_km,
            source=best.source,
            limitations=best.limitations + ["Median across stations; still approximate."],
        )
        return best_copy


class CatalogReconciler:
    def reconcile(
        self,
        event: SeismicEvent,
        catalogs: List[CatalogEntry],
    ) -> Tuple[List[CatalogMatch], List[Contradiction], List[MagnitudeEstimate]]:
        matches: List[CatalogMatch] = []
        contradictions: List[Contradiction] = []
        mag_estimates: List[MagnitudeEstimate] = []

        for cat in catalogs:
            if cat.origin_time is None or event.origin_time is None:
                continue
            time_diff = abs((cat.origin_time - event.origin_time).total_seconds())
            dist = haversine_km(event.latitude, event.longitude, cat.latitude, cat.longitude)
            depth_diff = abs((cat.depth_km or 0.0) - (event.depth_km or 0.0)) if cat.depth_km is not None and event.depth_km is not None else None
            mag_diff = abs((cat.magnitude or 0.0) - (event.preferred_magnitude.value or 0.0)) if cat.magnitude is not None and event.preferred_magnitude and event.preferred_magnitude.value is not None else None

            horiz_tol = max(50.0, (event.horizontal_uncertainty_km or 10.0) * 3.0)
            depth_tol = max(10.0, (event.depth_uncertainty_km or 5.0) * 2.0)

            if time_diff <= 60 and dist is not None and dist <= horiz_tol and (mag_diff is None or mag_diff <= 0.5) and (depth_diff is None or depth_diff <= depth_tol):
                state = CatalogMatchState.SAME_EVENT_SUPPORTED
            elif time_diff <= 180 and dist is not None and dist <= 100.0:
                state = CatalogMatchState.POSSIBLE_MATCH
            elif time_diff <= 600 and dist is not None and dist <= 300.0:
                state = CatalogMatchState.UNRESOLVED
            else:
                state = CatalogMatchState.DISTINCT

            match = CatalogMatch(
                event_id=event.event_id,
                catalog_event_id=cat.catalog_event_id,
                agency=cat.agency,
                match_state=state,
                time_diff_s=time_diff,
                distance_km=dist,
                depth_diff_km=depth_diff,
                magnitude_diff=mag_diff,
                limitations=[
                    "Catalog agreement does not prove source independence.",
                    "Different catalogs may use different velocity models and phase picks.",
                ],
            )
            matches.append(match)

            if cat.magnitude is not None:
                mag_estimates.append(
                    MagnitudeEstimate(
                        event_id=event.event_id,
                        magnitude_type=cat.magnitude_type or MagnitudeType.CATALOG_REPORTED.value,
                        value=cat.magnitude,
                        uncertainty=0.2 if cat.quality in ("REVIEWED", "FINAL") else 0.4,
                        method="CATALOG_REPORTED",
                        source=cat.agency,
                        limitations=["Catalog magnitude may use different scale/method."],
                    )
                )

            if state in (CatalogMatchState.SAME_EVENT_SUPPORTED, CatalogMatchState.POSSIBLE_MATCH):
                if dist is not None and event.horizontal_uncertainty_km is not None and dist > event.horizontal_uncertainty_km * 3.0:
                    contradictions.append(
                        Contradiction(
                            contradiction_type="LOCATION_CONFLICT",
                            description=f"Computed event and catalog {cat.catalog_event_id} differ by {dist:.1f} km.",
                            evidence_ids=[cat.evidence_id],
                            candidate_resolutions=[
                                "different velocity model",
                                "different phase picks",
                                "different station set",
                                "catalog revision",
                                "location instability",
                            ],
                        )
                    )
                if mag_diff is not None and mag_diff > 0.8:
                    contradictions.append(
                        Contradiction(
                            contradiction_type="MAGNITUDE_CONFLICT",
                            description=f"Magnitude difference {mag_diff:.2f} between computed and catalog {cat.catalog_event_id}.",
                            evidence_ids=[cat.evidence_id],
                            candidate_resolutions=[
                                "different magnitude scale",
                                "different amplitude measurement",
                                "saturation/clipping",
                                "site effect",
                            ],
                        )
                    )
                if depth_diff is not None and event.depth_uncertainty_km is not None and depth_diff > event.depth_uncertainty_km * 3.0:
                    contradictions.append(
                        Contradiction(
                            contradiction_type="DEPTH_CONFLICT",
                            description=f"Depth difference {depth_diff:.1f} km vs catalog {cat.catalog_event_id}.",
                            evidence_ids=[cat.evidence_id],
                            candidate_resolutions=[
                                "fixed depth assumption",
                                "poor depth constraint",
                                "different velocity model",
                            ],
                        )
                    )

        return matches, contradictions, mag_estimates


class SourceDiscriminator:
    def classify(
        self,
        event: SeismicEvent,
        picks: List[PhasePick],
        waveforms: List[Waveform],
        station_map: Dict[str, Station],
        catalogs: List[CatalogEntry],
        matches: List[CatalogMatch],
        case_context: Dict[str, Any],
    ) -> SourceClassification:
        scores: Dict[str, float] = {
            "TECTONIC": 0.0,
            "QUARRY_BLAST": 0.0,
            "MINING": 0.0,
            "EXPLOSION": 0.0,
            "COLLAPSE": 0.0,
            "VOLCANIC": 0.0,
            "INDUCED": 0.0,
            "NOISE_ARTIFACT": 0.0,
        }
        supports: Dict[str, List[str]] = {k: [] for k in scores}
        oppositions: Dict[str, List[str]] = {k: [] for k in scores}

        depth = event.depth_km
        station_count = event.station_count
        rms = event.rms_residual_s or 0.0

        ps_ratio = self._ps_ratio(picks, waveforms)

        quarries = case_context.get("quarries", [])
        mines = case_context.get("mines", [])
        volcanoes = case_context.get("volcanoes", [])
        industrial = case_context.get("industrial_sites", [])
        historical = case_context.get("historical_events", [])
        external_reports = case_context.get("external_reports", [])

        near_quarry = self._near_any(event, quarries)
        near_mine = self._near_any(event, mines)
        near_volcano = self._near_any(event, volcanoes)
        near_industrial = self._near_any(event, industrial)

        hour_utc = event.origin_time.hour if event.origin_time else None
        working_hours = self._working_hours(quarries, hour_utc)
        recurrence = self._recurrence(event, historical)

        catalog_types = " ".join(
            c.event_type.upper()
            for c in catalogs
            for m in matches
            if m.catalog_event_id == c.catalog_event_id and m.match_state in (CatalogMatchState.SAME_EVENT_SUPPORTED, CatalogMatchState.POSSIBLE_MATCH)
        )

        # Noise/artifact
        if station_count < 3:
            scores["NOISE_ARTIFACT"] += 2
            supports["NOISE_ARTIFACT"].append("fewer than 3 usable stations")
        if any(p.confidence in (PhaseConfidence.LOW, PhaseConfidence.AMBIGUOUS) for p in picks):
            scores["NOISE_ARTIFACT"] += 1
            supports["NOISE_ARTIFACT"].append("low-confidence phase picks")
        if rms > 1.5:
            scores["NOISE_ARTIFACT"] += 2
            supports["NOISE_ARTIFACT"].append("high location residual")
        if any(station_map.get(p.station_id) and station_map[p.station_id].timing_quality in (TimingQuality.POOR, TimingQuality.UNKNOWN) for p in picks):
            scores["NOISE_ARTIFACT"] += 1
            supports["NOISE_ARTIFACT"].append("station timing quality uncertain")

        # Tectonic
        if depth is not None and 3 <= depth <= 70:
            scores["TECTONIC"] += 2
            supports["TECTONIC"].append("depth consistent with crustal seismicity")
        if not near_quarry and not near_mine and not near_industrial:
            scores["TECTONIC"] += 1
            supports["TECTONIC"].append("no nearby industrial source context supplied")
        if "EARTHQUAKE" in catalog_types:
            scores["TECTONIC"] += 2
            supports["TECTONIC"].append("catalog event type earthquake")
        if event.focal_mechanism and event.focal_mechanism.mechanism_type in ("NORMAL", "REVERSE", "STRIKE_SLIP", "OBLIQUE"):
            scores["TECTONIC"] += 2
            supports["TECTONIC"].append("focal mechanism consistent with shear faulting")

        # Quarry
        if depth is not None and depth < 5:
            scores["QUARRY_BLAST"] += 2
            supports["QUARRY_BLAST"].append("shallow source")
        if ps_ratio is not None and ps_ratio < 0.4:
            scores["QUARRY_BLAST"] += 2
            supports["QUARRY_BLAST"].append("low S/P amplitude ratio candidate")
        if near_quarry:
            scores["QUARRY_BLAST"] += 3
            supports["QUARRY_BLAST"].append("within supplied quarry radius")
        if working_hours:
            scores["QUARRY_BLAST"] += 1
            supports["QUARRY_BLAST"].append("occurred during supplied working-hours window (UTC approximation)")
        if recurrence >= 3:
            scores["QUARRY_BLAST"] += 1
            supports["QUARRY_BLAST"].append("recurrent nearby events")
        if "QUARRY" in catalog_types or "BLAST" in catalog_types:
            scores["QUARRY_BLAST"] += 2
            supports["QUARRY_BLAST"].append("catalog blast/quarry context")

        # Mining
        if depth is not None and depth < 5:
            scores["MINING"] += 2
            supports["MINING"].append("shallow source")
        if near_mine:
            scores["MINING"] += 3
            supports["MINING"].append("within supplied mine radius")
        if ps_ratio is not None and ps_ratio < 0.5:
            scores["MINING"] += 1
            supports["MINING"].append("low S/P ratio candidate")
        if "MINE" in catalog_types or "MINING" in catalog_types:
            scores["MINING"] += 2
            supports["MINING"].append("catalog mining context")

        # Explosion candidate (high-level only)
        if depth is not None and depth < 5:
            scores["EXPLOSION"] += 2
            supports["EXPLOSION"].append("shallow source")
        if ps_ratio is not None and ps_ratio < 0.3:
            scores["EXPLOSION"] += 2
            supports["EXPLOSION"].append("strong P relative to S candidate")
        if any("EXPLOSION" in str(r.get("description", "")).upper() or "BLAST" in str(r.get("description", "")).upper() for r in external_reports):
            scores["EXPLOSION"] += 3
            supports["EXPLOSION"].append("external report mentions explosion/blast")
        if "EXPLOSION" in catalog_types:
            scores["EXPLOSION"] += 2
            supports["EXPLOSION"].append("catalog explosion context")

        # Collapse
        if near_mine or near_quarry:
            scores["COLLAPSE"] += 2
            supports["COLLAPSE"].append("near mine/quarry context")
        if depth is not None and depth < 3:
            scores["COLLAPSE"] += 1
            supports["COLLAPSE"].append("very shallow source")
        if any("COLLAPSE" in str(r.get("description", "")).upper() for r in external_reports):
            scores["COLLAPSE"] += 2
            supports["COLLAPSE"].append("external report mentions collapse")

        # Volcanic
        if near_volcano:
            scores["VOLCANIC"] += 3
            supports["VOLCANIC"].append("within supplied volcano radius")
        if "VOLCAN" in catalog_types:
            scores["VOLCANIC"] += 2
            supports["VOLCANIC"].append("catalog volcanic context")
        if case_context.get("tremor_context") or case_context.get("swarm_context"):
            scores["VOLCANIC"] += 2
            supports["VOLCANIC"].append("tremor/swarm context supplied")

        # Induced
        if case_context.get("injection_context") or case_context.get("reservoir_context"):
            scores["INDUCED"] += 3
            supports["INDUCED"].append("fluid injection/reservoir context supplied")
        if near_industrial:
            scores["INDUCED"] += 2
            supports["INDUCED"].append("near industrial operation context")
        if recurrence >= 5:
            scores["INDUCED"] += 1
            supports["INDUCED"].append("elevated recurrence")

        # Oppositions
        if near_quarry or near_mine:
            oppositions["TECTONIC"].append("nearby industrial source context exists")
        if depth is not None and depth > 10:
            oppositions["QUARRY_BLAST"].append("depth less consistent with shallow blast")
            oppositions["EXPLOSION"].append("depth less consistent with shallow explosion")
        if ps_ratio is not None and ps_ratio > 0.6:
            oppositions["QUARRY_BLAST"].append("S/P ratio not strongly blast-like")
            oppositions["EXPLOSION"].append("S/P ratio not strongly explosion-like")

        primary, top_score = max(scores.items(), key=lambda kv: kv[1])
        alternatives = sorted(
            [{"label": k, "score": v, "supports": supports[k], "oppositions": oppositions[k]} for k, v in scores.items() if k != primary],
            key=lambda x: x["score"],
            reverse=True,
        )[:5]

        confidence = Confidence.LOW
        status = EventType.UNKNOWN.value

        if top_score < 3:
            primary_label = EventType.UNKNOWN.value
            status = "INCONCLUSIVE"
        elif primary == "NOISE_ARTIFACT" and top_score >= max(scores["TECTONIC"], scores["QUARRY_BLAST"], scores["EXPLOSION"]) + 2:
            primary_label = EventType.NOISE_ARTIFACT_CANDIDATE.value
            status = "NOISE_ARTIFACT_CANDIDATE"
        elif primary == "TECTONIC":
            if top_score >= 5 and station_count >= 3 and not near_quarry and not near_mine:
                primary_label = EventType.EARTHQUAKE_SUPPORTED.value
                status = "EARTHQUAKE_SUPPORTED"
                confidence = Confidence.MEDIUM
            else:
                primary_label = EventType.EARTHQUAKE_CANDIDATE.value
                status = "EARTHQUAKE_CANDIDATE"
        elif primary == "QUARRY_BLAST":
            if top_score >= 8 and near_quarry and (ps_ratio is not None and ps_ratio < 0.4):
                primary_label = EventType.QUARRY_BLAST_SUPPORTED.value
                status = "QUARRY_BLAST_SUPPORTED"
                confidence = Confidence.MEDIUM
            else:
                primary_label = EventType.QUARRY_BLAST_CANDIDATE.value
                status = "QUARRY_BLAST_CANDIDATE"
        elif primary == "MINING":
            primary_label = EventType.MINING_EVENT_CANDIDATE.value
            status = "MINING_EVENT_CANDIDATE"
        elif primary == "EXPLOSION":
            primary_label = EventType.EXPLOSION_CANDIDATE.value
            status = "EXPLOSION_CANDIDATE"
            confidence = Confidence.LOW
        elif primary == "COLLAPSE":
            primary_label = EventType.COLLAPSE_CANDIDATE.value
            status = "COLLAPSE_CANDIDATE"
        elif primary == "VOLCANIC":
            primary_label = EventType.VOLCANIC_EVENT_CANDIDATE.value
            status = "VOLCANIC_EVENT_CANDIDATE"
        elif primary == "INDUCED":
            primary_label = EventType.INDUCED_POSSIBLE.value
            status = "INDUCED_POSSIBLE"
        else:
            primary_label = EventType.UNKNOWN.value
            status = "UNKNOWN"

        limitations = [
            "Source classification is conservative and evidence-linked.",
            "One feature such as shallow depth, daytime timing, or P/S ratio is not proof.",
            "Actor attribution is not assessed from seismic data alone.",
            "Explosion candidate does not imply weapon test or responsible party.",
        ]

        return SourceClassification(
            event_id=event.event_id,
            primary_label=primary_label,
            status=status,
            confidence=confidence,
            supporting_features=supports.get(primary, []),
            opposing_features=oppositions.get(primary, []),
            alternatives=alternatives,
            scores=scores,
            limitations=limitations,
        )

    @staticmethod
    def _ps_ratio(picks: List[PhasePick], waveforms: List[Waveform]) -> Optional[float]:
        by_station: Dict[str, Dict[str, Optional[float]]] = {}
        for p in picks:
            d = by_station.setdefault(p.station_id, {})
            if p.phase_type in (PhaseType.P_CANDIDATE, PhaseType.P_SUPPORTED):
                d["P"] = p.amplitude_counts
            elif p.phase_type in (PhaseType.S_CANDIDATE, PhaseType.S_SUPPORTED):
                d["S"] = p.amplitude_counts

        ratios = []
        for d in by_station.values():
            p = d.get("P")
            s = d.get("S")
            if p and s and p > 0:
                ratios.append(s / p)
        return median(ratios)

    @staticmethod
    def _near_any(event: SeismicEvent, entities: List[Dict[str, Any]]) -> bool:
        for e in entities:
            lat = safe_float(e.get("latitude", e.get("lat")))
            lon = safe_float(e.get("longitude", e.get("lon")))
            radius = safe_float(e.get("radius_km")) or 10.0
            d = haversine_km(event.latitude, event.longitude, lat, lon)
            if d is not None and d <= radius:
                return True
        return False

    @staticmethod
    def _working_hours(quarries: List[Dict[str, Any]], hour_utc: Optional[int]) -> bool:
        if hour_utc is None:
            return False
        for q in quarries:
            wh = q.get("working_hours_utc")
            if isinstance(wh, list) and len(wh) == 2:
                try:
                    start = int(wh[0])
                    end = int(wh[1])
                    if start <= end:
                        if start <= hour_utc < end:
                            return True
                    else:
                        if hour_utc >= start or hour_utc < end:
                            return True
                except Exception:
                    continue
        return False

    @staticmethod
    def _recurrence(event: SeismicEvent, historical: List[Dict[str, Any]]) -> int:
        if event.origin_time is None:
            return 0
        count = 0
        for h in historical:
            t = to_datetime(h.get("time", h.get("origin_time")))
            lat = safe_float(h.get("latitude", h.get("lat")))
            lon = safe_float(h.get("longitude", h.get("lon")))
            if t is None or lat is None or lon is None:
                continue
            dt_days = abs((t - event.origin_time).total_seconds()) / 86400.0
            dist = haversine_km(event.latitude, event.longitude, lat, lon)
            if dt_days <= 30 and dist is not None and dist <= 20.0:
                count += 1
        return count


class SequenceAnalyzer:
    def analyze(self, event: SeismicEvent, case_context: Dict[str, Any]) -> List[str]:
        notes: List[str] = []
        historical = case_context.get("historical_events", [])
        if event.origin_time is None:
            return ["Sequence context unavailable."]

        for h in historical:
            t = to_datetime(h.get("time", h.get("origin_time")))
            lat = safe_float(h.get("latitude", h.get("lat")))
            lon = safe_float(h.get("longitude", h.get("lon")))
            mag = safe_float(h.get("magnitude"))
            if t is None or lat is None or lon is None:
                continue
            dist = haversine_km(event.latitude, event.longitude, lat, lon)
            dt_days = (event.origin_time - t).total_seconds() / 86400.0
            if dist is not None and dist <= 50.0 and 0 < dt_days <= 7 and mag is not None and event.preferred_magnitude and event.preferred_magnitude.value is not None and mag > event.preferred_magnitude.value + 0.5:
                notes.append("AFTERSHOCK_CANDIDATE: larger nearby event occurred within previous 7 days.")
                break

        future_larger = False
        for h in historical:
            t = to_datetime(h.get("time", h.get("origin_time")))
            lat = safe_float(h.get("latitude", h.get("lat")))
            lon = safe_float(h.get("longitude", h.get("lon")))
            mag = safe_float(h.get("magnitude"))
            if t is None or lat is None or lon is None:
                continue
            dist = haversine_km(event.latitude, event.longitude, lat, lon)
            dt_days = (t - event.origin_time).total_seconds() / 86400.0
            if dist is not None and dist <= 50.0 and 0 < dt_days <= 7 and mag is not None and event.preferred_magnitude and event.preferred_magnitude.value is not None and mag > event.preferred_magnitude.value + 0.5:
                future_larger = True
                break
        if future_larger:
            notes.append("FORESHOCK_RETROSPECTIVE_CANDIDATE: larger nearby event occurred later in supplied data.")

        nearby_24h = 0
        for h in historical:
            t = to_datetime(h.get("time", h.get("origin_time")))
            lat = safe_float(h.get("latitude", h.get("lat")))
            lon = safe_float(h.get("longitude", h.get("lon")))
            if t is None or lat is None or lon is None:
                continue
            dist = haversine_km(event.latitude, event.longitude, lat, lon)
            dt_hours = abs((t - event.origin_time).total_seconds()) / 3600.0
            if dist is not None and dist <= 20.0 and dt_hours <= 24:
                nearby_24h += 1
        if nearby_24h >= 5:
            notes.append("SWARM_MEMBER_CANDIDATE: multiple nearby events within 24 hours.")

        if not notes:
            notes.append("INDEPENDENT_EVENT_CANDIDATE or UNKNOWN sequence relationship.")
        return notes


# ======================================================================
# SECTION 9 — SOURCE INDEPENDENCE / FACT GATE / REVIEW
# ======================================================================

class SourceIndependenceAnalyzer:
    def assess(self, stations: List[Station], catalogs: List[CatalogEntry], case_context: Dict[str, Any]) -> Dict[str, Any]:
        sources = set()
        for s in stations:
            if s.source and s.source != "UNKNOWN":
                sources.add(s.source)
            if s.network_code:
                sources.add(f"network:{s.network_code}")
        for c in catalogs:
            if c.source_id:
                sources.add(c.source_id)
            if c.agency:
                sources.add(f"agency:{c.agency}")
        for r in case_context.get("external_reports", []):
            src = r.get("source")
            if src:
                sources.add(str(src))

        if not sources:
            return {"status": IndependenceState.UNKNOWN.value, "notes": ["No source metadata supplied."], "sources": []}

        if len(sources) == 1:
            status = IndependenceState.DEPENDENT
            notes = [
                "All available measurement/catalog/report sources appear to derive from one source family.",
                "Do not count multiple articles or dashboards consuming one bulletin as independent confirmations.",
            ]
        else:
            status = IndependenceState.PARTIALLY_DEPENDENT
            notes = [
                "Multiple source identifiers exist, but full pedigree/independence is not proven.",
                "Verify whether catalogs/reports derive from the same seismic network.",
            ]

        return {"status": status.value, "notes": notes, "sources": sorted(sources)}


class FactGate:
    def generate(
        self,
        *,
        case: Dict[str, Any],
        stations: List[Station],
        waveforms: List[Waveform],
        detections: List[SignalDetection],
        picks: List[PhasePick],
        events: List[SeismicEvent],
        catalogs: List[CatalogEntry],
        matches: List[CatalogMatch],
        contradictions: List[Contradiction],
        source_independence: Dict[str, Any],
    ) -> Dict[str, Any]:
        facts: List[Fact] = []
        hypotheses: List[Hypothesis] = []
        unknowns: List[str] = []
        limitations: List[str] = []
        gaps: List[KnowledgeGap] = []
        actions: List[NextAction] = []
        handoffs: List[SpecialistHandoff] = []

        for wf in waveforms[:100]:
            facts.append(
                Fact(
                    statement=f"Station {wf.station_id} channel {wf.channel} provided waveform starting {wf.start_time.isoformat()} with hash {wf.evidence_id}.",
                    status=FactStatus.FACT,
                    evidence_ids=[wf.evidence_id],
                    limitations=["Raw waveform preservation; interpretation requires station health, timing, and response context."],
                )
            )

        for p in picks[:200]:
            facts.append(
                Fact(
                    statement=f"Phase pick {p.phase_type.value} at station {p.station_id} time {p.pick_time.isoformat()} method {p.method} confidence {p.confidence.value}.",
                    status=FactStatus.FACT if p.confidence in (PhaseConfidence.HIGH, PhaseConfidence.MEDIUM) else FactStatus.CANDIDATE,
                    evidence_ids=[p.evidence_id],
                    limitations=["Phase picks can be ambiguous; misidentification possible."],
                )
            )

        for ev in events:
            facts.append(
                Fact(
                    statement=(
                        f"Multi-station association supports seismic event near ({ev.latitude}, {ev.longitude}) "
                        f"depth {ev.depth_km} km at {ev.origin_time.isoformat() if ev.origin_time else 'UNKNOWN'} "
                        f"using {ev.station_count} stations."
                    ),
                    status=FactStatus.SUPPORTED if ev.station_count >= 3 and (ev.rms_residual_s or 99) < 1.5 else FactStatus.CANDIDATE,
                    evidence_ids=ev.evidence_ids,
                    limitations=[
                        "Location is model-dependent.",
                        "Depth may be poorly constrained.",
                        "Uncertainty must accompany any quantitative claim.",
                    ],
                )
            )

            if ev.preferred_magnitude and ev.preferred_magnitude.value is not None:
                facts.append(
                    Fact(
                        statement=(
                            f"Preferred magnitude estimate {ev.preferred_magnitude.value:.2f} "
                            f"{ev.preferred_magnitude.magnitude_type} with uncertainty {ev.preferred_magnitude.uncertainty}."
                        ),
                        status=FactStatus.CANDIDATE,
                        evidence_ids=ev.evidence_ids,
                        limitations=[
                            "Magnitude scale must be preserved.",
                            "Approximate magnitude is not an authoritative agency value unless sourced.",
                        ],
                    )
                )

            if ev.source_classification:
                sc = ev.source_classification
                facts.append(
                    Fact(
                        statement=f"Source classification candidate: {sc.primary_label} status={sc.status} confidence={sc.confidence.value}.",
                        status=FactStatus.CANDIDATE if sc.confidence != Confidence.HIGH else FactStatus.SUPPORTED,
                        evidence_ids=ev.evidence_ids,
                        limitations=sc.limitations,
                    )
                )

                for label, score in sorted(sc.scores.items(), key=lambda x: x[1], reverse=True)[:5]:
                    hypotheses.append(
                        Hypothesis(
                            statement=f"{label} source hypothesis (score={score:.1f}).",
                            supports=sc.supporting_features if label == sc.primary_label else [],
                            oppositions=sc.oppositions_features if label == sc.primary_label else [],
                            unknowns=[
                                "exact source mechanism",
                                "operator/actor",
                                "industrial schedule verification",
                                "independent external event report",
                            ],
                            falsification_tests=[
                                "independent stations show noise/artifact",
                                "velocity/model revision removes shallow source",
                                "external records contradict industrial context",
                                "waveform spectral features inconsistent with hypothesis",
                            ],
                        )
                    )

        for m in matches[:100]:
            facts.append(
                Fact(
                    statement=f"Catalog reconciliation: event {m.event_id} vs {m.agency} {m.catalog_event_id} = {m.match_state.value}.",
                    status=FactStatus.SUPPORTED if m.match_state == CatalogMatchState.SAME_EVENT_SUPPORTED else FactStatus.CANDIDATE,
                    evidence_ids=[],
                    limitations=m.limitations,
                )
            )

        for c in contradictions[:100]:
            facts.append(
                Fact(
                    statement=f"Open contradiction: {c.contradiction_type} — {c.description}",
                    status=FactStatus.DISPUTED,
                    evidence_ids=c.evidence_ids,
                    limitations=c.candidate_resolutions,
                )
            )
            unknowns.append(f"Unresolved contradiction: {c.contradiction_type}")

        if source_independence.get("status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            limitations.append("Source independence is dependent or unknown; do not inflate confidence from duplicated bulletins.")
            gaps.append(
                KnowledgeGap(
                    description="Independent seismic source pedigree not established.",
                    importance="HIGH",
                    recommended_source="independent network/catalog/observatory source",
                    specialist="SEISINT source evaluation",
                    expected_information_value="Prevents false corroboration from one upstream network.",
                )
            )

        for ev in events:
            if ev.station_count < 3:
                gaps.append(KnowledgeGap(description=f"Event {ev.event_id} has fewer than 3 usable stations.", importance="HIGH", recommended_source="additional stations", specialist="SEISINT", expected_information_value="Improves location and detection confidence."))
            if ev.depth_uncertainty_km is not None and ev.depth_uncertainty_km > 10:
                gaps.append(KnowledgeGap(description=f"Depth poorly constrained for event {ev.event_id}.", importance="HIGH", recommended_source="better station geometry / regional model", specialist="SEISINT", expected_information_value="Reduces source-type ambiguity."))
            if ev.source_classification and ev.source_classification.status in ("UNKNOWN", "INCONCLUSIVE"):
                gaps.append(KnowledgeGap(description=f"Source type unresolved for event {ev.event_id}.", importance="MEDIUM", recommended_source="spectral analysis, moment tensor, industrial context", specialist="SEISINT / GEOINT / EVENTINT", expected_information_value="Improves classification."))

        limitations.extend(
            [
                "Single-station trigger is not a verified seismic event.",
                "Shallow event is not automatically explosion.",
                "Low S-wave energy is not absolute explosion proof.",
                "Daytime timing is not quarry-blast proof.",
                "Magnitude is not intensity, damage, or explosive yield.",
                "Catalog agreement is not source independence.",
                "AI classification is not seismic measurement.",
            ]
        )

        unknowns.extend(
            [
                "exact source mechanism",
                "operator or responsible actor",
                "whether event is natural, industrial, volcanic, or artifact",
                "true depth if poorly constrained",
                "authoritative magnitude scale equivalence",
            ]
        )

        actions.extend(
            [
                NextAction(description="Retrieve additional independent stations or reviewed catalog solution.", rationale="Improves location, depth, and source confidence.", priority="HIGH"),
                NextAction(description="Validate station clock and timing quality before final association.", rationale="Timing errors corrupt phase picks and hypocenter.", priority="HIGH"),
                NextAction(description="Compare regional velocity model and fixed-depth assumptions.", rationale="Location/depth are model-dependent.", priority="HIGH"),
                NextAction(description="Request moment tensor or focal mechanism if available from authoritative source.", rationale="Helps distinguish shear vs explosive/collapse sources.", priority="MEDIUM"),
                NextAction(description="Correlate with authorized industrial/quarry/mining schedule at high level.", rationale="Tests anthropogenic source hypotheses without operational targeting.", priority="MEDIUM"),
                NextAction(description="Handoff surface deformation/damage context to SATINT/GEOINT/IMINT.", rationale="Seismic waveform alone does not establish surface effects or cause.", priority="MEDIUM"),
            ]
        )

        guard = PolicyGuard()
        actions = [a for a in actions if guard.is_safe_action(a.description)]

        handoffs.extend(
            [
                SpecialistHandoff(specialist="SATINT", reason="Surface deformation / InSAR / crater / landslide context.", payload={}),
                SpecialistHandoff(specialist="GEOINT", reason="Fault geography, terrain, infrastructure, population context.", payload={}),
                SpecialistHandoff(specialist="IMINT", reason="Ground damage / facility imagery, no facial identification.", payload={}),
                SpecialistHandoff(specialist="EVENTINT", reason="Broader event reconstruction and external correlation.", payload={}),
                SpecialistHandoff(specialist="INFRAINT", reason="Critical infrastructure safety/resilience context only.", payload={}),
                SpecialistHandoff(specialist="LEGALINT", reason="Regulatory/emergency/public-warning conclusions require legal review.", payload={}),
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


class DualAIReviewer:
    def review(
        self,
        *,
        events: List[SeismicEvent],
        picks: List[PhasePick],
        contradictions: List[Contradiction],
        source_independence: Dict[str, Any],
        case: Dict[str, Any],
    ) -> Dict[str, Any]:
        notes: List[str] = []
        status = ReviewStatus.AGREE

        if not events:
            status = ReviewStatus.INSUFFICIENT_EVIDENCE
            notes.append("No associated seismic event.")

        if any(ev.station_count < 3 for ev in events):
            notes.append("Fewer than 3 usable stations for at least one event; location/source claims should remain candidate.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(ev.depth_uncertainty_km is not None and ev.depth_uncertainty_km > 10 for ev in events):
            notes.append("Depth uncertainty high; avoid shallow/deep source certainty.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if any(p.confidence in (PhaseConfidence.LOW, PhaseConfidence.AMBIGUOUS) for p in picks):
            notes.append("Low-confidence phase picks present; phase misidentification possible.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if source_independence.get("status") in (IndependenceState.DEPENDENT.value, IndependenceState.UNKNOWN.value):
            notes.append("Source independence dependent/unknown; multiple reports may share one network.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        if contradictions:
            notes.append("Open contradictions remain; final classification should stay conservative.")
            status = ReviewStatus.PARTIAL_AGREEMENT

        human_review_required = False
        for ev in events:
            if ev.source_classification and ev.source_classification.primary_label in (
                EventType.EXPLOSION_CANDIDATE.value,
                EventType.QUARRY_BLAST_SUPPORTED.value,
                EventType.ANTHROPOGENIC_EVENT_SUPPORTED.value,
            ):
                human_review_required = True
                notes.append("Explosion/anthropogenic classification requires human review before consequential claims.")

        tags = [str(x).upper() for x in case.get("sensitivity_tags", [])]
        if any(t in ("NUCLEAR", "MILITARY", "CRITICAL_INFRASTRUCTURE", "PUBLIC_EMERGENCY") for t in tags):
            human_review_required = True
            notes.append("Sensitive context supplied; human review required.")

        return {
            "status": status.value,
            "skeptic_notes": notes,
            "rule": "AI agreement is not seismic corroboration.",
            "human_review_required": human_review_required,
        }


# ======================================================================
# SECTION 10 — GRAPHICAL MEMORY / REPORT
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

    def write_result(self, result: SEISINTResult) -> Dict[str, Any]:
        for st in result.stations:
            self.add_node(st.station_id, "Station", {"network": st.network_code, "health": st.health_status.value, "timing": st.timing_quality.value})

        for wf in result.waveforms[:500]:
            self.add_node(wf.waveform_id, "Waveform", {"station_id": wf.station_id, "channel": wf.channel, "start_time": wf.start_time.isoformat()})
            self.add_edge(wf.waveform_id, "OBSERVED_BY", wf.station_id, {"evidence_id": wf.evidence_id})

        for p in result.phase_picks[:1000]:
            self.add_node(p.pick_id, "PhasePick", {"station": p.station_id, "phase": p.phase_type.value, "time": p.pick_time.isoformat()})
            self.add_edge(p.pick_id, "HAS_PHASE", p.station_id)

        for ev in result.events:
            self.add_node(
                ev.event_id,
                "SeismicEvent",
                {
                    "origin_time": ev.origin_time.isoformat() if ev.origin_time else None,
                    "latitude": ev.latitude,
                    "longitude": ev.longitude,
                    "depth_km": ev.depth_km,
                    "status": ev.status,
                },
            )
            for pid in ev.pick_ids[:100]:
                self.add_edge(pid, "ASSOCIATED_WITH_EVENT", ev.event_id)
            if ev.source_classification:
                self.add_node(ev.source_classification.classification_id, "SourceClassification", {"label": ev.source_classification.primary_label, "status": ev.source_classification.status})
                self.add_edge(ev.event_id, "CLASSIFIED_AS", ev.source_classification.classification_id)

        for m in result.catalog_matches[:500]:
            self.add_node(m.match_id, "CatalogMatch", {"state": m.match_state.value, "agency": m.agency})
            self.add_edge(m.event_id, "MATCHES_CATALOG", m.match_id)

        for f in result.facts[:1000]:
            self.add_node(f.fact_id, "Fact", {"statement": f.statement, "status": f.status.value})
            for ev in f.evidence_ids[:20]:
                self.add_edge(f.fact_id, "SUPPORTED_BY", ev)

        for h in result.hypotheses:
            self.add_node(h.hypothesis_id, "Hypothesis", {"statement": h.statement})

        return {"node_count": len(self.nodes), "edge_count": len(self.edges), "sample_nodes": list(self.nodes.keys())[:20]}


class ReportGenerator:
    def generate(self, result: SEISINTResult) -> str:
        lines: List[str] = []

        def section(title: str) -> None:
            lines.append("")
            lines.append(title.upper())
            lines.append("-" * len(title))

        lines.append("=" * 72)
        lines.append("TRACEATLAS — SEISINT REPORT")
        lines.append("=" * 72)
        lines.append(f"Case ID: {result.case_id}")
        lines.append(f"Task ID: {result.task_id}")
        lines.append(f"Objective: {result.objective}")
        lines.append(f"Status: {result.status}")
        lines.append(f"Policy Decision: {result.policy_decision.value}")

        section("Safety / Boundary")
        lines.append("- Scientific, defensive, authorized seismic monitoring and verification analysis only.")
        lines.append("- No explosive design, underground-test optimization, concealment, monitoring evasion, sensor tampering, sabotage, or infrastructure targeting.")
        for flag in result.safety_flags:
            lines.append(f"- Safety: {flag}")
        for flag in result.privacy_flags:
            lines.append(f"- Privacy: {flag}")

        section("Station Inventory")
        if not result.stations:
            lines.append("- No stations supplied.")
        for s in result.stations:
            lines.append(f"- {s.station_id}: network={s.network_code}, health={s.health_status.value}, timing={s.timing_quality.value}, lat={s.latitude}, lon={s.longitude}")
            if s.limitations:
                lines.append(f"  limitations={'; '.join(s.limitations)}")

        section("Waveforms / Preprocessing")
        lines.append(f"- Waveforms: {len(result.waveforms)}")
        lines.append(f"- Preprocessing steps: {len(result.preprocessing_steps)}")
        for step in result.preprocessing_steps[:20]:
            lines.append(f"- {step.operation} on {step.waveform_id}: input_hash={step.input_hash[:12]} output_hash={step.output_hash[:12]}")

        section("Signal Detections")
        if not result.detections:
            lines.append("- No STA/LTA detections.")
        for d in result.detections[:50]:
            lines.append(f"- {d.detection_id}: station={d.station_id}, channel={d.channel}, onset={d.onset_time.isoformat()}, ratio={d.sta_lta_ratio}, amp={d.peak_amplitude_counts}")

        section("Phase Picks")
        if not result.phase_picks:
            lines.append("- No phase picks.")
        for p in result.phase_picks[:100]:
            lines.append(f"- {p.pick_id}: {p.station_id}/{p.channel} {p.phase_type.value} at {p.pick_time.isoformat()} conf={p.confidence.value} method={p.method}")

        section("Events / Location / Magnitude")
        if not result.events:
            lines.append("- No associated seismic event.")
        for ev in result.events:
            lines.append(f"- Event {ev.event_id}: origin={ev.origin_time.isoformat() if ev.origin_time else 'UNKNOWN'}")
            lines.append(f"  hypocenter=({ev.latitude}, {ev.longitude}, depth={ev.depth_km} km)")
            lines.append(f"  uncertainty=horiz {ev.horizontal_uncertainty_km} km, depth {ev.depth_uncertainty_km} km")
            lines.append(f"  stations={ev.station_count}, phases={ev.phase_count}, rms_s={ev.rms_residual_s}, azimuth_gap={ev.azimuthal_gap_deg}")
            lines.append(f"  status={ev.status}, confidence={ev.confidence.value}, velocity_model={ev.velocity_model_id}")
            if ev.preferred_magnitude:
                lines.append(f"  preferred_magnitude={ev.preferred_magnitude.value} {ev.preferred_magnitude.magnitude_type} ± {ev.preferred_magnitude.uncertainty}")
            for me in ev.magnitude_estimates[:10]:
                lines.append(f"  magnitude_estimate: {me.value} {me.magnitude_type} source={me.source} method={me.method}")
            if ev.source_classification:
                sc = ev.source_classification
                lines.append(f"  source_classification={sc.primary_label} status={sc.status} confidence={sc.confidence.value}")
                lines.append(f"  supporting_features={sc.supporting_features}")
                lines.append(f"  opposing_features={sc.opposing_features}")
                lines.append(f"  scores={sc.scores}")
                lines.append(f"  limitations={sc.limitations}")
            if ev.limitations:
                lines.append(f"  event_limitations={ev.limitations}")

        section("Catalog Reconciliation")
        if not result.catalog_matches:
            lines.append("- No catalog matches.")
        for m in result.catalog_matches:
            lines.append(f"- {m.match_id}: event={m.event_id}, catalog={m.catalog_event_id}, agency={m.agency}, state={m.match_state.value}, time_diff_s={m.time_diff_s}, dist_km={m.distance_km}")

        section("Source Independence")
        lines.append(f"- Status: {result.source_independence.get('status', 'UNKNOWN')}")
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
            lines.append("  - Human review required before consequential explosion/anthropogenic/public-safety claims.")

        section("Required Analyst Summary")
        if result.events:
            ev = result.events[0]
            lines.append(f"EVENT: {'Supported' if ev.station_count >= 3 else 'Candidate'} multi-station seismic event near ({ev.latitude}, {ev.longitude}) at {ev.origin_time}.")
            lines.append(f"LOCATION: Horizontal uncertainty ~{ev.horizontal_uncertainty_km} km, depth uncertainty ~{ev.depth_uncertainty_km} km.")
            lines.append(f"MAGNITUDE: Preferred {ev.preferred_magnitude.value if ev.preferred_magnitude else 'UNKNOWN'} {ev.preferred_magnitude.magnitude_type if ev.preferred_magnitude else ''}.")
            lines.append(f"SOURCE: {ev.source_classification.primary_label if ev.source_classification else 'UNKNOWN'} — candidate/conservative, not actor attribution.")
            lines.append("NEXT ACTION: Obtain independent stations/reviewed catalog and validate velocity model/timing before strengthening classification.")
        else:
            lines.append("EVENT: No associated seismic event from supplied data.")
            lines.append("NEXT ACTION: Verify station health, timing, waveform availability, and detection thresholds.")

        lines.append("")
        lines.append("=" * 72)
        lines.append("END REPORT")
        lines.append("=" * 72)
        return "\n".join(lines)


# ======================================================================
# SECTION 11 — SEISINT AI EMPLOYEE
# ======================================================================

class SEISIntelligenceEmployee:
    def __init__(self, mode: ModelMode = ModelMode.LOCAL_ONLY):
        self.mode = mode
        self.policy = PolicyGuard()
        self.injection_defense = PromptInjectionDefense()
        self.ingestor = SEISINTIngestor(injection_defense=self.injection_defense)
        self.preprocessor = WaveformPreprocessor()
        self.detector = SignalDetector()
        self.picker = PhasePicker()
        self.associator = EventAssociator()
        self.magnitude_estimator = MagnitudeEstimator()
        self.catalog_reconciler = CatalogReconciler()
        self.source_discriminator = SourceDiscriminator()
        self.sequence_analyzer = SequenceAnalyzer()
        self.independence_analyzer = SourceIndependenceAnalyzer()
        self.fact_gate = FactGate()
        self.reviewer = DualAIReviewer()
        self.memory = GraphicalMemory()
        self.reporter = ReportGenerator()

    def run_case(self, case: Dict[str, Any]) -> SEISINTResult:
        case_id = str(case.get("case_id", new_id("CASE")))
        task_id = str(case.get("task_id", new_id("TASK")))
        objective = str(case.get("objective", ""))
        questions = case.get("questions", [])

        request_text = objective + "\n" + "\n".join(str(q) for q in questions)
        policy = self.policy.check_request(request_text)

        if policy.decision == PolicyDecision.POLICY_BLOCKED:
            return SEISINTResult(
                case_id=case_id,
                task_id=task_id,
                objective=objective,
                status="POLICY_BLOCKED",
                policy_decision=PolicyDecision.POLICY_BLOCKED,
                report=(
                    "POLICY_BLOCKED\n\n"
                    "This request seeks prohibited SEISINT operational guidance. "
                    "Lawful alternative: authorized seismic monitoring, event detection, "
                    "phase-pick quality assessment, hypocenter uncertainty, magnitude reconciliation, "
                    "source-classification candidates, catalog verification, emergency-response context, "
                    "and scientific reporting without explosive design, test concealment, monitoring evasion, "
                    "sensor tampering, sabotage, or targeting."
                ),
                safety_flags=[
                    "No explosive/test/concealment guidance provided.",
                    "No sensor tampering/evasion guidance provided.",
                    "No infrastructure targeting provided.",
                ],
                limitations=[policy.reason],
            )

        evidence, stations, waveforms, catalogs, velocity_models, manual_picks = self.ingestor.ingest_case(case)
        station_map = {s.station_id: s for s in stations}
        vm = velocity_models[0] if velocity_models else VelocityModel()

        preprocessing_steps: List[PreprocessingStep] = []
        processed_samples: Dict[str, List[float]] = {}
        for wf in waveforms:
            samples, step = self.preprocessor.demean_detrend(wf)
            processed_samples[wf.waveform_id] = samples
            preprocessing_steps.append(step)

        detections: List[SignalDetection] = []
        detections_by_waveform: Dict[str, List[SignalDetection]] = {}
        for wf in waveforms:
            dets = self.detector.detect(wf, processed_samples.get(wf.waveform_id, wf.samples))
            detections_by_waveform[wf.waveform_id] = dets
            detections.extend(dets)

        picks = self.picker.pick(waveforms, detections_by_waveform, station_map, manual_picks)
        events = self.associator.associate(picks, station_map, vm)

        all_matches: List[CatalogMatch] = []
        all_contradictions: List[Contradiction] = []

        for ev in events:
            ev.station_count = len({p.station_id for p in picks if p.pick_id in ev.pick_ids}) or ev.station_count
            mag_est = self.magnitude_estimator.estimate(ev, picks, waveforms, station_map)
            ev.magnitude_estimates.extend(mag_est)
            ev.preferred_magnitude = self.magnitude_estimator.choose_preferred(ev, mag_est)

            matches, contradictions, catalog_mags = self.catalog_reconciler.reconcile(ev, catalogs)
            all_matches.extend(matches)
            all_contradictions.extend(contradictions)
            ev.magnitude_estimates.extend(catalog_mags)

            # Prefer catalog magnitude if same-event supported.
            supported_cat = [m for m in matches if m.match_state == CatalogMatchState.SAME_EVENT_SUPPORTED]
            if supported_cat and catalog_mags:
                ev.preferred_magnitude = catalog_mags[0]
                ev.preferred_magnitude.magnitude_id = new_id("MAG")
                ev.preferred_magnitude.limitations.append("Preferred from matched catalog; preserve scale/method.")

            sc = self.source_discriminator.classify(ev, picks, waveforms, station_map, catalogs, matches, case)
            ev.source_classification = sc
            ev.event_type = sc.primary_label

            seq_notes = self.sequence_analyzer.analyze(ev, case)
            ev.limitations.extend(seq_notes)

        source_independence = self.independence_analyzer.assess(stations, catalogs, case)

        fact_out = self.fact_gate.generate(
            case=case,
            stations=stations,
            waveforms=waveforms,
            detections=detections,
            picks=picks,
            events=events,
            catalogs=catalogs,
            matches=all_matches,
            contradictions=all_contradictions,
            source_independence=source_independence,
        )

        review = self.reviewer.review(
            events=events,
            picks=picks,
            contradictions=all_contradictions,
            source_independence=source_independence,
            case=case,
        )

        status = "PARTIAL"
        if not waveforms:
            status = "FAILED"
        elif not detections:
            status = "NO_SIGNAL"
        elif not picks:
            status = "PHASE_UNRESOLVED"
        elif not events:
            status = "EVENT_UNRESOLVED"
        elif any(ev.status == "LOCATION_UNRESOLVED" for ev in events):
            status = "LOCATION_UNRESOLVED"
        elif any(ev.source_classification and ev.source_classification.status in ("UNKNOWN", "INCONCLUSIVE") for ev in events):
            status = "SOURCE_TYPE_UNRESOLVED"
        elif review.get("human_review_required"):
            status = "PARTIAL_HUMAN_REVIEW_REQUIRED"
        else:
            status = "SUCCEEDED"

        privacy_flags = []
        if self.mode == ModelMode.LOCAL_ONLY:
            privacy_flags.append("LOCAL_ONLY mode selected; sensitive station layout/waveforms should remain local.")
        elif self.mode == ModelMode.CLOUD:
            privacy_flags.append("CLOUD mode requires sanitized/public/aggregated seismic metadata only.")
        else:
            privacy_flags.append("HYBRID mode requires routing controls and tenant isolation.")

        result = SEISINTResult(
            case_id=case_id,
            task_id=task_id,
            objective=objective,
            status=status,
            policy_decision=PolicyDecision.ALLOW,
            evidence=evidence,
            stations=stations,
            waveforms=waveforms,
            preprocessing_steps=preprocessing_steps,
            detections=detections,
            phase_picks=picks,
            events=events,
            catalogs=catalogs,
            catalog_matches=all_matches,
            contradictions=all_contradictions,
            facts=fact_out["facts"],
            hypotheses=fact_out["hypotheses"],
            knowledge_gaps=fact_out["knowledge_gaps"],
            next_actions=fact_out["next_actions"],
            specialist_handoffs=fact_out["specialist_handoffs"],
            velocity_models=velocity_models,
            source_independence=source_independence,
            review=review,
            unknowns=fact_out["unknowns"],
            limitations=fact_out["limitations"],
            safety_flags=[
                "No explosive design/test optimization/concealment guidance.",
                "No seismic-monitoring evasion or sensor tampering guidance.",
                "No infrastructure targeting or sabotage guidance.",
                "Explosion candidate is not actor attribution.",
                "Human review required for consequential anthropogenic/public-safety claims.",
            ],
            privacy_flags=privacy_flags,
        )

        result.graph = self.memory.write_result(result)
        result.report = self.reporter.generate(result)
        return result


# ======================================================================
# SECTION 12 — SYNTHETIC DEMO
# ======================================================================

def _synthetic_waveform_samples(
    start: datetime,
    fs: float,
    duration_s: float,
    p_delay_s: float,
    s_delay_s: float,
    p_amp: float,
    s_amp: float,
) -> List[float]:
    n = int(duration_s * fs)
    samples: List[float] = []
    for i in range(n):
        t = i / fs
        noise = 20.0 * math.sin(2.0 * math.pi * 0.2 * t) + 10.0 * math.sin(2.0 * math.pi * 1.3 * t + 0.7)
        val = noise

        if 0 <= t - p_delay_s <= 2.0:
            dt = t - p_delay_s
            val += p_amp * math.sin(2.0 * math.pi * 5.0 * dt) * math.exp(-(dt * dt) / 0.25)

        if 0 <= t - s_delay_s <= 2.5:
            dt = t - s_delay_s
            val += s_amp * math.sin(2.0 * math.pi * 3.0 * dt) * math.exp(-(dt * dt) / 0.45)

        samples.append(val)
    return samples


def demo() -> None:
    """
    Synthetic lawful demo:
    Authorized regional seismic network event characterization.
    No real station layout, no targeting, no test evasion, no explosive design.
    """
    employee = SEISIntelligenceEmployee(mode=ModelMode.LOCAL_ONLY)

    start = datetime(2026, 10, 8, 10, 0, 0, tzinfo=timezone.utc)
    fs = 50.0
    duration = 30.0

    # True synthetic source: origin 10:00:10, lat 40.000, lon -116.000, depth 5 km.
    vp = 6.0
    vs = 3.5
    origin_offset = 10.0

    stations = [
        {"station_id": "ST_A", "network_code": "DEMO", "latitude": 40.050, "longitude": -116.000, "elevation_m": 1200},
        {"station_id": "ST_B", "network_code": "DEMO", "latitude": 39.950, "longitude": -116.000, "elevation_m": 1200},
        {"station_id": "ST_C", "network_code": "DEMO", "latitude": 40.000, "longitude": -115.950, "elevation_m": 1200},
        {"station_id": "ST_D", "network_code": "DEMO", "latitude": 40.000, "longitude": -116.060, "elevation_m": 1200},
    ]

    waveforms = []
    for st in stations:
        horiz = haversine_km(40.0, -116.0, st["latitude"], st["longitude"]) or 1.0
        hypo = math.sqrt(horiz * horiz + 5.0 * 5.0)
        p_delay = origin_offset + hypo / vp
        s_delay = origin_offset + hypo / vs
        samples = _synthetic_waveform_samples(start, fs, duration, p_delay, s_delay, p_amp=120000.0, s_amp=75000.0)
        waveforms.append(
            {
                "station_id": st["station_id"],
                "channel": "BHZ",
                "network": "DEMO",
                "start_time": start.isoformat(),
                "sampling_rate_hz": fs,
                "units": "COUNTS",
                "samples": samples,
                "source_id": "demo_authorized_regional_network",
                "clock_quality": "GOOD",
            }
        )

    station_records = []
    for st in stations:
        station_records.append(
            {
                "station_id": st["station_id"],
                "network_code": "DEMO",
                "station_code": st["station_id"][-1],
                "latitude": st["latitude"],
                "longitude": st["longitude"],
                "elevation_m": st["elevation_m"],
                "sensor_type": "BROADBAND",
                "channels": ["BHZ"],
                "sampling_rate_hz": fs,
                "timing_source": "GPS",
                "timing_quality": "GOOD",
                "health_status": "HEALTHY",
                "sensitivity_counts_per_physical": 1000.0,
                "physical_unit": "um",
                "local_magnitude_type": "ML_APPROX",
                "source": "demo_authorized_regional_network",
                "limitations": ["Synthetic demo station; not operational sensor metadata."],
            }
        )

    case = {
        "case_id": "DEMO-SEISINT-001",
        "task_id": "DEMO-TASK-001",
        "objective": (
            "Lawful scientific seismic verification: characterize an authorized regional-network event, "
            "estimate hypocenter with uncertainty, reconcile magnitude, and conservatively assess source-class candidates."
        ),
        "questions": [
            "Is there a multi-station seismic event?",
            "What location and depth are supported, with uncertainty?",
            "What magnitude estimates exist and how should scales be preserved?",
            "Is the source consistent with natural tectonic activity, or is an anthropogenic candidate plausible?",
            "What remains unknown?",
        ],
        "authorization": "AUTHORIZED_SCIENTIFIC_SEISMIC_MONITORING_SYNTHETIC_DEMO",
        "sensitivity_tags": ["SCIENTIFIC", "SYNTHETIC_DEMO"],
        "stations": station_records,
        "waveforms": waveforms,
        "velocity_models": [
            {
                "model_id": "VM_DEMO_1D",
                "name": "DEMO_1D",
                "version": "v0",
                "region": "synthetic_regional",
                "vp_km_s": 6.0,
                "vs_km_s": 3.5,
                "max_depth_km": 20.0,
                "assumptions": ["constant velocity", "demo only"],
                "source": "synthetic_reference",
            }
        ],
        "catalogs": [
            {
                "catalog_event_id": "CAT_DEMO_001",
                "agency": "DEMO_SEISMIC_AGENCY",
                "source_id": "demo_seismic_agency",
                "origin_time": "2026-10-08T10:00:10Z",
                "latitude": 40.001,
                "longitude": -116.001,
                "depth_km": 5.0,
                "magnitude": 2.4,
                "magnitude_type": "ML",
                "event_type": "EARTHQUAKE",
                "quality": "REVIEWED",
            }
        ],
        "phase_picks": [],
        "quarries": [],
        "mines": [],
        "volcanoes": [],
        "industrial_sites": [],
        "historical_events": [],
        "external_reports": [],
    }

    result = employee.run_case(case)
    print(result.report)


def main() -> None:
    demo()


if __name__ == "__main__":
    main()