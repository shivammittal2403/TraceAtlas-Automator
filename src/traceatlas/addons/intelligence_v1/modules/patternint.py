from __future__ import annotations

import hashlib
import json
import logging
import math
import statistics
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from itertools import combinations
from typing import Any, Dict, List, Optional, Tuple

# ==============================================================================
# TRACEATLAS — PATTERNINT
# PATTERN INTELLIGENCE AI EMPLOYEE
# MODE: EVIDENCE-FIRST / MULTI-DOMAIN / TEMPORAL / PRIVACY-AWARE
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("TRACEATLAS.PATTERNINT")


# ==============================================================================
# SECTION 12: HARD RESTRICTIONS / POLICY ENGINE
# ==============================================================================

class PolicyViolation(Exception):
    pass


PROHIBITED_SCOPE_FLAGS = (
    "allow_private_individual_tracking",
    "create_private_person_movement_profiles",
    "predict_criminality_from_personal_characteristics",
    "infer_guilt_from_recurrence",
    "infer_intent_from_routine_behaviour",
    "infer_protected_traits",
    "infer_medical_or_mental_health_conditions",
    "infer_sexual_behaviour",
    "infer_religion",
    "infer_political_beliefs_of_private_persons",
    "perform_predictive_policing_on_individuals",
    "generate_target_lists_for_harm",
    "optimize_attack_timing",
    "identify_vulnerabilities_for_sabotage",
    "recommend_exploitation_windows",
    "identify_critical_choke_points_for_offensive_targeting",
    "recommend_evasion_of_monitoring",
    "help_adversaries_alter_behaviour_to_defeat_detection",
    "perform_autonomous_legal_employment_financial_decisions",
)

PROHIBITED_OBJECTIVE_KEYWORDS = (
    "dox",
    "stalk",
    "private individual tracking",
    "movement profile",
    "predict criminality",
    "infer guilt",
    "infer intent from routine",
    "predictive policing",
    "target list",
    "attack optimization",
    "attack timing",
    "sabotage target",
    "exploitation window",
    "offensive targeting",
    "evasion of monitoring",
    "adversary behavior modification",
    "autonomous legal decision",
    "autonomous employment decision",
    "autonomous financial decision",
)


def enforce_policy(objective: str, scope: Dict[str, Any]) -> None:
    """
    Enforces PATTERNINT hard restrictions.
    Defensive, aggregate/system-level, evidence-first analysis only.
    """
    if not isinstance(scope, dict):
        raise PolicyViolation("POLICY_BLOCKED: scope must be a dictionary.")

    for flag in PROHIBITED_SCOPE_FLAGS:
        if scope.get(flag, False):
            raise PolicyViolation(f"POLICY_BLOCKED: prohibited scope flag '{flag}'.")

    objective_lower = (objective or "").lower()
    for keyword in PROHIBITED_OBJECTIVE_KEYWORDS:
        if keyword in objective_lower:
            raise PolicyViolation(
                f"POLICY_BLOCKED: objective contains prohibited concept '{keyword}'."
            )


# ==============================================================================
# ENUMS / STATES
# ==============================================================================

class PatternType(Enum):
    TEMPORAL = auto()
    PERIODIC = auto()
    SEASONAL = auto()
    SEQUENTIAL = auto()
    RELATIONAL = auto()
    STRUCTURAL = auto()
    GRAPH_MOTIF = auto()
    SPATIAL = auto()
    SPATIOTEMPORAL = auto()
    TRANSACTIONAL = auto()
    FINANCIAL = auto()
    CYBER = auto()
    TTP = auto()
    IOC = auto()
    FRAUD = auto()
    TRADE = auto()
    LOGISTICS = auto()
    SUPPLY_CHAIN = auto()
    ORGANIZATIONAL = auto()
    NARRATIVE = auto()
    INFLUENCE = auto()
    ENVIRONMENTAL = auto()
    SENSOR = auto()
    MULTI_DOMAIN = auto()
    OTHER = auto()


class PatternState(Enum):
    CANDIDATE = auto()
    WEAK = auto()
    EMERGING = auto()
    SUPPORTED = auto()
    STRONGLY_SUPPORTED = auto()
    STABLE = auto()
    DRIFTING = auto()
    DECAYING = auto()
    HISTORICAL = auto()
    DISPUTED = auto()
    FALSIFIED = auto()
    INCONCLUSIVE = auto()


class PeriodicityState(Enum):
    STRONG_PERIODICITY = auto()
    MODERATE_PERIODICITY = auto()
    WEAK_PERIODICITY = auto()
    NO_PERIODICITY = auto()
    INSUFFICIENT_DATA = auto()


class SeasonalityState(Enum):
    SEASONALITY_EXPLAINS = auto()
    PARTIAL_SEASONALITY = auto()
    NO_SEASONALITY = auto()
    INSUFFICIENT_DATA = auto()


class TrendDirection(Enum):
    INCREASING = auto()
    DECREASING = auto()
    STABLE = auto()
    VOLATILE = auto()
    UNKNOWN = auto()


class ChangePointState(Enum):
    CHANGE_DETECTED = auto()
    NO_CHANGE = auto()
    INSUFFICIENT_DATA = auto()


class SourceIndependenceState(Enum):
    INDEPENDENT = auto()
    PARTIALLY_DEPENDENT = auto()
    DEPENDENT = auto()
    UNKNOWN = auto()


class PatternEvidenceState(Enum):
    OBSERVED_RECURRENCE = auto()
    STATISTICALLY_SUPPORTED = auto()
    STRUCTURALLY_SUPPORTED = auto()
    CROSS_SOURCE_SUPPORTED = auto()
    CROSS_DOMAIN_SUPPORTED = auto()
    DISPUTED = auto()
    FALSIFIED = auto()
    INCONCLUSIVE = auto()


class HypothesisStatus(Enum):
    ACTIVE = auto()
    REJECTED = auto()
    CONFIRMED = auto()
    CANDIDATE = auto()
    INCONCLUSIVE = auto()


# ==============================================================================
# DATA OBJECTS
# ==============================================================================

@dataclass
class ObservationObject:
    obs_id: str
    case_id: str
    source_id: str
    upstream_source_id: str
    domain: str
    entity_ids: List[str]
    event_ids: List[str]
    timestamp_utc: datetime
    event_time_precision: str
    location_scope: Optional[str]
    features: Dict[str, Any]
    raw_payload: Dict[str, Any]
    ingest_time: Optional[datetime]
    publication_time: Optional[datetime]
    reliability: float
    limitations: List[str] = field(default_factory=list)


@dataclass
class PatternObject:
    pattern_id: str
    pattern_type: PatternType
    pattern_name: str
    description: str
    domain: str
    entity_ids: List[str]
    event_ids: List[str]
    observation_ids: List[str]
    time_window: Dict[str, Any]
    baseline_window: Dict[str, Any]
    frequency: Dict[str, Any]
    support_count: int
    independent_support_count: int
    recurrence_interval: Dict[str, Any]
    spatial_scope: Optional[str]
    sequence: List[Any]
    features: Dict[str, Any]
    confidence: Dict[str, float]
    stability: str
    drift: str
    lifecycle: str
    source_ids: List[str]
    evidence_ids: List[str]
    alternative_explanations: List[str]
    falsification_tests: Dict[str, Any]
    status: PatternState
    limitations: List[str]

    tags: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    seasonality: Dict[str, Any] = field(default_factory=dict)
    out_of_seasonality_count: int = 0
    duplicate_count: int = 0
    raw_count: int = 0
    upstream_source_ids: List[str] = field(default_factory=list)
    method: Dict[str, Any] = field(default_factory=dict)
    baseline: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Hypothesis:
    id: str
    description: str
    support_evidence: List[str]
    opposition_evidence: List[str]
    unknowns: List[str]
    falsification_criteria: str
    status: HypothesisStatus


@dataclass
class GraphNode:
    node_id: str
    type: str
    attributes: Dict[str, Any]


@dataclass
class GraphEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    relation: str
    confidence: float
    evidence_ids: List[str]


# ==============================================================================
# CONSTANTS
# ==============================================================================

SOURCE_RELIABILITY = {
    "siem_event": 0.90,
    "network_telemetry": 0.88,
    "transaction_record": 0.86,
    "financial_record": 0.85,
    "trade_record": 0.82,
    "shipment_record": 0.82,
    "incident_record": 0.84,
    "cti_feed": 0.70,
    "ioc_sighting": 0.65,
    "sensor_record": 0.75,
    "satellite_derived_observation": 0.72,
    "ais_derived_observation": 0.70,
    "radar_derived_observation": 0.68,
    "seismic_record": 0.72,
    "public_web_data": 0.55,
    "authorized_social_data": 0.55,
    "repository_metadata": 0.70,
    "package_metadata": 0.68,
    "sbom_data": 0.66,
    "cloud_metadata": 0.72,
    "search_result_snippet": 0.35,
    "third_party_aggregator": 0.30,
    "unknown": 0.20,
}

BUSINESS_LIKE_DOMAINS = {
    "transactional",
    "financial",
    "organizational",
    "cyber",
    "logistics",
    "trade",
    "supply_chain",
    "fraud",
}

DEFAULT_SEASONALITY_FEATURE_KEYS = [
    "maintenance_window",
    "business_hours",
    "holiday",
    "scheduled",
    "reporting_cycle",
    "billing_cycle",
    "payroll_cycle",
    "patch_cycle",
]


# ==============================================================================
# HELPERS
# ==============================================================================

def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def json_serial(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.name
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    text = str(value).strip()
    if not text:
        return None

    text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def feature_signature(features: Dict[str, Any], keys: Optional[List[str]] = None) -> str:
    """
    Deterministic feature signature for grouping.
    Avoids including unnecessary PII or volatile timestamps.
    """
    if keys:
        selected = {k: features.get(k) for k in keys if k in features}
    else:
        selected = {
            k: v
            for k, v in features.items()
            if not isinstance(v, (dict, list))
            and k not in {"timestamp", "ingest_time", "publication_time"}
        }

    return json.dumps(selected, sort_keys=True, default=json_serial)


def observation_from_dict(d: Dict[str, Any], case_id: str, now: datetime) -> ObservationObject:
    ts = parse_dt(
        d.get("timestamp_utc")
        or d.get("timestamp")
        or d.get("event_time")
        or d.get("observed_at")
    )

    precision = str(d.get("event_time_precision", "EXACT" if ts else "UNKNOWN")).upper()
    if ts is None:
        ts = parse_dt(d.get("ingest_time")) or now
        precision = "UNKNOWN"

    source_type = str(d.get("source_type", "unknown"))
    reliability = float(d.get("reliability", SOURCE_RELIABILITY.get(source_type, 0.20)))

    return ObservationObject(
        obs_id=str(d.get("obs_id") or new_id("OBS")),
        case_id=case_id,
        source_id=str(d.get("source_id") or "UNKNOWN_SOURCE"),
        upstream_source_id=str(d.get("upstream_source_id") or d.get("source_id") or "UNKNOWN_UPSTREAM"),
        domain=str(d.get("domain", "other")),
        entity_ids=[str(x) for x in d.get("entity_ids", [])],
        event_ids=[str(x) for x in d.get("event_ids", [])],
        timestamp_utc=ts,
        event_time_precision=precision,
        location_scope=d.get("location_scope"),
        features=dict(d.get("features", {}) or {}),
        raw_payload=dict(d),
        ingest_time=parse_dt(d.get("ingest_time")),
        publication_time=parse_dt(d.get("publication_time")),
        reliability=reliability,
        limitations=list(d.get("limitations", [])),
    )


def coverage_days(observations: List[ObservationObject], time_range: Tuple[datetime, datetime]) -> float:
    if not observations:
        start, end = time_range
        return max(1.0, (end - start).total_seconds() / 86400.0)

    start = min(o.timestamp_utc for o in observations)
    end = max(o.timestamp_utc for o in observations)
    return max(1.0, (end - start).total_seconds() / 86400.0)


def parse_time_range(scope: Dict[str, Any], observations: List[ObservationObject], now: datetime) -> Tuple[datetime, datetime]:
    tr = scope.get("time_range") or {}
    start = parse_dt(tr.get("start"))
    end = parse_dt(tr.get("end"))

    if observations:
        obs_start = min(o.timestamp_utc for o in observations)
        obs_end = max(o.timestamp_utc for o in observations)
        start = start or obs_start
        end = end or obs_end
    else:
        start = start or (now - __import__("datetime").timedelta(days=30))
        end = end or now

    if end < start:
        start, end = end, start

    return start, end


def deduplicate_observations(
    observations: List[ObservationObject],
    scope: Dict[str, Any],
) -> Tuple[List[ObservationObject], List[Dict[str, Any]]]:
    """
    Removes duplicate representations of the same underlying event/observation.
    Duplicate source syndication must not inflate recurrence.
    """
    time_window = int(scope.get("dedupe_time_window_seconds", 3600))
    pattern_feature_keys = scope.get("pattern_feature_keys")

    groups: Dict[Tuple[Any, ...], List[ObservationObject]] = defaultdict(list)

    for o in observations:
        bucket = int(o.timestamp_utc.timestamp() // max(1, time_window))
        sig = feature_signature(o.features, pattern_feature_keys)
        key = (
            o.domain,
            tuple(sorted(o.event_ids)),
            tuple(sorted(o.entity_ids)),
            bucket,
            sig,
        )
        groups[key].append(o)

    unique: List[ObservationObject] = []
    duplicate_groups: List[Dict[str, Any]] = []

    for key, items in groups.items():
        best = max(items, key=lambda x: (x.reliability, x.obs_id))
        unique.append(best)

        if len(items) > 1:
            duplicate_groups.append(
                {
                    "representative_id": best.obs_id,
                    "duplicate_ids": [o.obs_id for o in items if o.obs_id != best.obs_id],
                    "domain": best.domain,
                    "feature_signature": key[4],
                    "time_bucket": key[3],
                    "duplicate_count": len(items) - 1,
                }
            )

    return unique, duplicate_groups


def analyze_source_independence(observations: List[ObservationObject]) -> Dict[str, Any]:
    upstream_groups: Dict[str, List[str]] = defaultdict(list)
    source_groups: Dict[str, List[str]] = defaultdict(list)

    for o in observations:
        upstream_groups[o.upstream_source_id].append(o.obs_id)
        source_groups[o.source_id].append(o.obs_id)

    dependent_roots = {root for root, ids in upstream_groups.items() if len(ids) > 1}

    if not upstream_groups:
        state = SourceIndependenceState.UNKNOWN
    elif len(dependent_roots) == 0:
        state = SourceIndependenceState.INDEPENDENT
    elif len(dependent_roots) < len(upstream_groups):
        state = SourceIndependenceState.PARTIALLY_DEPENDENT
    else:
        state = SourceIndependenceState.DEPENDENT

    return {
        "state": state.name,
        "total_observations": len(observations),
        "unique_sources": len(source_groups),
        "unique_upstream_families": len(upstream_groups),
        "dependent_upstream_families": sorted(dependent_roots),
        "upstream_groups": {root: sorted(ids) for root, ids in upstream_groups.items()},
    }


def compute_interval_stats(observations: List[ObservationObject]) -> Dict[str, Any]:
    if len(observations) < 2:
        return {
            "interval_count": 0,
            "median_seconds": None,
            "mean_seconds": None,
            "coefficient_of_variation": None,
            "intervals_seconds": [],
        }

    sorted_obs = sorted(observations, key=lambda x: x.timestamp_utc)
    intervals = [
        (sorted_obs[i + 1].timestamp_utc - sorted_obs[i].timestamp_utc).total_seconds()
        for i in range(len(sorted_obs) - 1)
    ]

    mean = sum(intervals) / len(intervals)
    median = statistics.median(intervals)

    if len(intervals) >= 2 and mean > 0:
        cv = statistics.pstdev(intervals) / mean
    else:
        cv = None

    return {
        "interval_count": len(intervals),
        "median_seconds": median,
        "mean_seconds": mean,
        "coefficient_of_variation": cv,
        "intervals_seconds": intervals,
    }


def periodicity_state(count: int, interval_stats: Dict[str, Any]) -> PeriodicityState:
    if count < 3:
        return PeriodicityState.INSUFFICIENT_DATA

    cv = interval_stats.get("coefficient_of_variation")
    if cv is None:
        return PeriodicityState.INSUFFICIENT_DATA

    if cv <= 0.25:
        return PeriodicityState.STRONG_PERIODICITY
    if cv <= 0.50:
        return PeriodicityState.MODERATE_PERIODICITY
    if cv <= 0.80:
        return PeriodicityState.WEAK_PERIODICITY
    return PeriodicityState.NO_PERIODICITY


def seasonality_analysis(
    observations: List[ObservationObject],
    scope: Dict[str, Any],
    existing_facts: Dict[str, Any],
) -> Dict[str, Any]:
    controls = scope.get("seasonality_feature_keys", DEFAULT_SEASONALITY_FEATURE_KEYS)
    control_count = 0
    control_dates: List[str] = []
    verified_control_count = 0

    for o in observations:
        if any(bool(o.features.get(c)) for c in controls):
            control_count += 1
            date = o.timestamp_utc.date().isoformat()
            control_dates.append(date)
            if existing_facts.get(f"maintenance_window:{date}") or existing_facts.get(f"seasonality_verified:{date}"):
                verified_control_count += 1

    total = max(1, len(observations))
    ratio = control_count / total
    out_count = len(observations) - control_count

    weekday_count = sum(1 for o in observations if o.timestamp_utc.weekday() < 5)
    weekday_ratio = weekday_count / total

    domain = observations[0].domain if observations else "other"

    if ratio >= 0.70:
        state = SeasonalityState.SEASONALITY_EXPLAINS
    elif ratio >= 0.40 or (domain in BUSINESS_LIKE_DOMAINS and weekday_ratio >= 0.70):
        state = SeasonalityState.PARTIAL_SEASONALITY
    else:
        state = SeasonalityState.NO_SEASONALITY

    if control_count == 0:
        verification = "NO_CONTROL_FEATURES"
    elif verified_control_count == control_count:
        verification = "INDEPENDENTLY_VERIFIED"
    elif verified_control_count > 0:
        verification = "PARTIALLY_VERIFIED"
    else:
        verification = "FEATURE_CLAIM_ONLY"

    return {
        "state": state.name,
        "control_feature_keys": controls,
        "control_count": control_count,
        "out_of_control_count": out_count,
        "control_ratio": round(ratio, 4),
        "weekday_ratio": round(weekday_ratio, 4),
        "verified_control_count": verified_control_count,
        "verification": verification,
    }


def compute_baseline(
    observations: List[ObservationObject],
    all_unique: List[ObservationObject],
    scope: Dict[str, Any],
    time_range: Tuple[datetime, datetime],
) -> Dict[str, Any]:
    coverage = coverage_days(observations, time_range)
    observed = len(observations)

    baseline_rate = scope.get("baseline_rate_per_day")
    baseline_quality = "SCOPE_PROVIDED"

    if baseline_rate is None:
        domain = observations[0].domain if observations else "other"
        domain_obs = [o for o in all_unique if o.domain == domain]
        domain_coverage = coverage_days(domain_obs or observations, time_range)
        baseline_rate = (len(domain_obs) / domain_coverage) if domain_coverage > 0 else 0.0
        baseline_quality = "IN_SAMPLE_DOMAIN_APPROXIMATE"

    expected = float(baseline_rate) * coverage

    if expected > 0:
        z = (observed - expected) / math.sqrt(expected)
    else:
        z = 0.0 if observed == 0 else 3.0

    return {
        "baseline_rate_per_day": round(float(baseline_rate), 6),
        "expected_count_in_window": round(expected, 4),
        "observed_count": observed,
        "poisson_approx_z": round(z, 4),
        "baseline_quality": baseline_quality,
        "coverage_days": round(coverage, 4),
    }


def linear_regression_slope(xs: List[float], ys: List[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0

    mean_x = sum(xs) / n
    mean_y = sum(ys) / n

    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom == 0:
        return 0.0

    numer = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    return numer / denom


def trend_and_change_point(
    observations: List[ObservationObject],
    time_range: Tuple[datetime, datetime],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    start, end = time_range
    total_days = max(1, int((end - start).total_seconds() // 86400) + 1)

    counts = [0] * total_days
    for o in observations:
        day_index = max(0, min(total_days - 1, int((o.timestamp_utc - start).total_seconds() // 86400)))
        counts[day_index] += 1

    xs = [float(i) for i in range(total_days)]
    ys = [float(c) for c in counts]

    slope = linear_regression_slope(xs, ys)
    mean = sum(ys) / len(ys) if ys else 0.0
    stdev = statistics.pstdev(ys) if len(ys) > 1 else 0.0

    if mean > 0 and stdev / mean > 1.5:
        direction = TrendDirection.VOLATILE
    elif slope > 0.02:
        direction = TrendDirection.INCREASING
    elif slope < -0.02:
        direction = TrendDirection.DECREASING
    else:
        direction = TrendDirection.STABLE

    change_state = ChangePointState.INSUFFICIENT_DATA
    if len(counts) >= 4:
        mid = len(counts) // 2
        first = counts[:mid]
        second = counts[mid:]
        mean_first = sum(first) / len(first)
        mean_second = sum(second) / len(second)
        pooled = math.sqrt((statistics.pstdev(first) ** 2 + statistics.pstdev(second) ** 2) / 2.0)
        threshold = max(0.5, pooled * 1.5)

        if abs(mean_second - mean_first) > threshold:
            change_state = ChangePointState.CHANGE_DETECTED
        else:
            change_state = ChangePointState.NO_CHANGE

    trend = {
        "direction": direction.name,
        "slope_per_day": round(slope, 6),
        "mean_daily_count": round(mean, 6),
        "stdev_daily_count": round(stdev, 6),
        "daily_counts_sample": counts[:31],
    }

    change = {
        "state": change_state.name,
        "first_half_mean": round(sum(counts[: len(counts) // 2]) / max(1, len(counts) // 2), 6) if counts else 0.0,
        "second_half_mean": round(sum(counts[len(counts) // 2 :]) / max(1, len(counts) - len(counts) // 2), 6) if counts else 0.0,
    }

    return trend, change


def build_pattern_from_group(
    group: List[ObservationObject],
    scope: Dict[str, Any],
    all_unique: List[ObservationObject],
    duplicate_groups: List[Dict[str, Any]],
    existing_facts: Dict[str, Any],
    time_range: Tuple[datetime, datetime],
    now: datetime,
    pattern_type_override: Optional[PatternType] = None,
    sequence: Optional[List[Any]] = None,
    spatial_scope: Optional[str] = None,
    signature: Optional[str] = None,
    name: Optional[str] = None,
    min_count: Optional[int] = None,
) -> PatternObject:
    sorted_obs = sorted(group, key=lambda x: x.timestamp_utc)
    obs_ids = [o.obs_id for o in sorted_obs]
    obs_id_set = set(obs_ids)

    entity_ids = sorted({eid for o in sorted_obs for eid in o.entity_ids})
    event_ids = sorted({eid for o in sorted_obs for eid in o.event_ids})
    source_ids = sorted({o.source_id for o in sorted_obs})
    upstream_ids = sorted({o.upstream_source_id for o in sorted_obs})

    total = len(sorted_obs)
    independent = len(upstream_ids)
    min_count = int(min_count or scope.get("min_recurrence", 3))

    duplicate_count = sum(
        len(d.get("duplicate_ids", []))
        for d in duplicate_groups
        if d.get("representative_id") in obs_id_set
    )
    raw_count = total + duplicate_count

    coverage = coverage_days(sorted_obs, time_range)
    interval_stats = compute_interval_stats(sorted_obs)
    periodic = periodicity_state(total, interval_stats)
    seasonality = seasonality_analysis(sorted_obs, scope, existing_facts)
    baseline = compute_baseline(sorted_obs, all_unique, scope, time_range)
    trend, change = trend_and_change_point(sorted_obs, time_range)

    if signature is None:
        sig_features = feature_signature(sorted_obs[0].features, scope.get("pattern_feature_keys"))
        signature = f"{sorted_obs[0].domain}|{','.join(sorted_obs[0].entity_ids)}|{sig_features}"

    if name is None:
        event_type = sorted_obs[0].features.get("event_type") or sorted_obs[0].domain
        short_entities = ", ".join(entity_ids[:3]) if entity_ids else "unspecified entities"
        name = f"Recurring {event_type} involving {short_entities}"

    recurrence_strength = clamp(independent / max(min_count, 2))
    source_diversity = clamp(independent / max(1, total))
    cv = interval_stats.get("coefficient_of_variation")
    temporal_stability = clamp(1.0 - float(cv)) if cv is not None else 0.5
    baseline_significance = clamp(abs(float(baseline.get("poisson_approx_z", 0.0))) / 3.0)
    coverage_confidence = clamp(coverage / max(1.0, (time_range[1] - time_range[0]).total_seconds() / 86400.0)) * clamp(
        independent / 3.0
    )

    confidence_weights = {
        "recurrence_strength": 0.35,
        "source_diversity": 0.20,
        "temporal_stability": 0.20,
        "baseline_significance": 0.15,
        "coverage_confidence": 0.10,
    }

    composite = (
        confidence_weights["recurrence_strength"] * recurrence_strength
        + confidence_weights["source_diversity"] * source_diversity
        + confidence_weights["temporal_stability"] * temporal_stability
        + confidence_weights["baseline_significance"] * baseline_significance
        + confidence_weights["coverage_confidence"] * coverage_confidence
    )

    confidence = {
        "recurrence_strength": round(recurrence_strength, 4),
        "source_diversity": round(source_diversity, 4),
        "temporal_stability": round(temporal_stability, 4),
        "baseline_significance": round(baseline_significance, 4),
        "coverage_confidence": round(coverage_confidence, 4),
        "composite_transparent_ranking_score": round(composite, 4),
    }

    if total < 2:
        status = PatternState.INCONCLUSIVE
    elif independent <= 1:
        status = PatternState.WEAK
    elif total >= min_count:
        if (
            seasonality["state"] == SeasonalityState.SEASONALITY_EXPLAINS.name
            and seasonality["out_of_control_count"] < min_count
        ):
            status = PatternState.SUPPORTED
        elif baseline_significance >= 0.60 and independent >= 3:
            status = PatternState.STRONGLY_SUPPORTED
        elif independent >= 3 and temporal_stability >= 0.60:
            status = PatternState.STRONGLY_SUPPORTED
        else:
            status = PatternState.SUPPORTED
    else:
        status = PatternState.CANDIDATE

    duplicate_ratio = duplicate_count / raw_count if raw_count else 0.0
    if duplicate_ratio > 0.50 and independent < 3 and status in (PatternState.SUPPORTED, PatternState.STRONGLY_SUPPORTED):
        status = PatternState.WEAK

    if pattern_type_override:
        ptype = pattern_type_override
    elif periodic in (PeriodicityState.STRONG_PERIODICITY, PeriodicityState.MODERATE_PERIODICITY):
        ptype = PatternType.PERIODIC
    elif seasonality["state"] == SeasonalityState.SEASONALITY_EXPLAINS.name:
        ptype = PatternType.SEASONAL
    else:
        ptype = PatternType.TEMPORAL

    stability = "STABLE"
    if cv is None:
        stability = "UNKNOWN"
    elif cv <= 0.50:
        stability = "STABLE"
    elif cv <= 0.80:
        stability = "MODERATE"
    else:
        stability = "UNSTABLE"

    drift = "NO_MATERIAL_DRIFT"
    if cv is not None and cv > 0.80:
        drift = "TIMING_DRIFT_CANDIDATE"

    last_seen = sorted_obs[-1].timestamp_utc
    days_since_last = (now - last_seen).total_seconds() / 86400.0
    if days_since_last <= 30:
        lifecycle = "ACTIVE"
    elif days_since_last <= 120:
        lifecycle = "DECAYING"
    else:
        lifecycle = "HISTORICAL"

    alternative_explanations = [
        "coincidence",
        "data artifact",
        "shared upstream provider",
        "scheduled automation",
        "business process",
        "reporting-cycle effect",
        "unknown",
    ]

    if seasonality["state"] == SeasonalityState.SEASONALITY_EXPLAINS.name:
        alternative_explanations.extend(["seasonality", "maintenance cycle", "scheduled batch process"])

    if duplicate_count > 0:
        alternative_explanations.append("duplicate source inflation before deduplication")

    limitations = [
        "Pattern recurrence does not establish causation.",
        "Pattern recurrence does not establish intent, guilt, coordination, or actor attribution.",
        "Baseline is approximate unless independently supplied.",
        "Entity resolution is limited to supplied identifiers.",
    ]

    if seasonality["verification"] == "FEATURE_CLAIM_ONLY":
        limitations.append("Seasonality control is based on profile/record feature claims and is not independently verified.")

    method = {
        "algorithm": "deterministic_recurrence_grouping",
        "version": "1.0",
        "parameters": {
            "min_count": min_count,
            "dedupe_time_window_seconds": scope.get("dedupe_time_window_seconds", 3600),
            "pattern_feature_keys": scope.get("pattern_feature_keys"),
            "seasonality_feature_keys": scope.get("seasonality_feature_keys", DEFAULT_SEASONALITY_FEATURE_KEYS),
        },
        "confidence_weights": confidence_weights,
        "baseline_quality": baseline.get("baseline_quality"),
        "deterministic_first": True,
    }

    description = (
        f"{ptype.name} pattern: {name}. "
        f"{total} unique observations after deduplication, {independent} independent upstream source families, "
        f"{duplicate_count} duplicate representations removed. "
        f"Seasonality state: {seasonality['state']}. "
        f"Baseline quality: {baseline['baseline_quality']}. "
        f"This is a recurrence/structure assessment only, not causation or intent."
    )

    return PatternObject(
        pattern_id=new_id("PAT"),
        pattern_type=ptype,
        pattern_name=name,
        description=description,
        domain=sorted_obs[0].domain,
        entity_ids=entity_ids,
        event_ids=event_ids,
        observation_ids=obs_ids,
        time_window={
            "start": sorted_obs[0].timestamp_utc.isoformat(),
            "end": sorted_obs[-1].timestamp_utc.isoformat(),
            "coverage_days": round(coverage, 4),
        },
        baseline_window={
            "mode": baseline.get("baseline_quality"),
            "rate_per_day": baseline.get("baseline_rate_per_day"),
            "expected_count": baseline.get("expected_count_in_window"),
        },
        frequency={
            "absolute_count": total,
            "raw_count": raw_count,
            "independent_support_count": independent,
            "rate_per_day": round(total / coverage, 6) if coverage else 0.0,
            "population_denominator": scope.get("population_denominator", 1),
            "observation_coverage_days": round(coverage, 4),
        },
        support_count=total,
        independent_support_count=independent,
        recurrence_interval=interval_stats,
        spatial_scope=spatial_scope,
        sequence=sequence or [],
        features={
            "pattern_signature": signature,
            "interval_stats": interval_stats,
            "trend": trend,
            "change_point": change,
        },
        confidence=confidence,
        stability=stability,
        drift=drift,
        lifecycle=lifecycle,
        source_ids=source_ids,
        evidence_ids=obs_ids,
        alternative_explanations=sorted(set(alternative_explanations)),
        falsification_tests={},
        status=status,
        limitations=limitations,
        tags=[],
        contradictions=[],
        seasonality=seasonality,
        out_of_seasonality_count=seasonality["out_of_control_count"],
        duplicate_count=duplicate_count,
        raw_count=raw_count,
        upstream_source_ids=upstream_ids,
        method=method,
        baseline=baseline,
    )


def group_temporal_patterns(
    unique_obs: List[ObservationObject],
    scope: Dict[str, Any],
) -> Dict[str, List[ObservationObject]]:
    pattern_feature_keys = scope.get("pattern_feature_keys")
    groups: Dict[str, List[ObservationObject]] = defaultdict(list)

    for o in unique_obs:
        sig = feature_signature(o.features, pattern_feature_keys)
        key = f"{o.domain}|{','.join(sorted(o.entity_ids))}|{sig}"
        groups[key].append(o)

    return groups


def detect_sequence_patterns(
    unique_obs: List[ObservationObject],
    scope: Dict[str, Any],
    duplicate_groups: List[Dict[str, Any]],
    existing_facts: Dict[str, Any],
    time_range: Tuple[datetime, datetime],
    now: datetime,
) -> Tuple[List[PatternObject], List[Dict[str, Any]]]:
    key = scope.get("sequence_feature_key", "state")
    min_count = int(scope.get("min_sequence_count", 2))

    transition_obs: Dict[Tuple[str, str], List[ObservationObject]] = defaultdict(list)
    transition_upstreams: Dict[Tuple[str, str], set] = defaultdict(set)

    prev: Optional[ObservationObject] = None
    for o in sorted(unique_obs, key=lambda x: x.timestamp_utc):
        state = o.features.get(key)
        if state is None:
            continue

        if prev is not None and (set(prev.entity_ids) & set(o.entity_ids)):
            prev_state = prev.features.get(key)
            if prev_state is not None:
                pair = (str(prev_state), str(state))
                transition_obs[pair].append(o)
                transition_upstreams[pair].add(o.upstream_source_id)

        prev = o

    patterns: List[PatternObject] = []
    transitions: List[Dict[str, Any]] = []

    for pair, items in transition_obs.items():
        unique_items = list({o.obs_id: o for o in items}.values())
        count = len(unique_items)
        independent = len({o.upstream_source_id for o in unique_items})

        transitions.append(
            {
                "from": pair[0],
                "to": pair[1],
                "count": count,
                "independent_support_count": independent,
                "observation_ids": [o.obs_id for o in unique_items],
            }
        )

        if count >= min_count and independent >= 2:
            p = build_pattern_from_group(
                group=unique_items,
                scope=scope,
                all_unique=unique_obs,
                duplicate_groups=duplicate_groups,
                existing_facts=existing_facts,
                time_range=time_range,
                now=now,
                pattern_type_override=PatternType.SEQUENTIAL,
                sequence=[{"from": pair[0], "to": pair[1], "count": count}],
                signature=f"sequence:{pair[0]}->{pair[1]}",
                name=f"Recurring sequence {pair[0]} -> {pair[1]}",
                min_count=min_count,
            )
            patterns.append(p)

    return patterns, transitions


def detect_spatial_patterns(
    unique_obs: List[ObservationObject],
    scope: Dict[str, Any],
    duplicate_groups: List[Dict[str, Any]],
    existing_facts: Dict[str, Any],
    time_range: Tuple[datetime, datetime],
    now: datetime,
) -> Tuple[List[PatternObject], List[Dict[str, Any]]]:
    min_count = int(scope.get("min_recurrence", 3))
    pattern_feature_keys = scope.get("pattern_feature_keys")

    groups: Dict[Tuple[str, str], List[ObservationObject]] = defaultdict(list)

    for o in unique_obs:
        if not o.location_scope:
            continue
        sig = feature_signature(o.features, pattern_feature_keys)
        groups[(o.location_scope, sig)].append(o)

    patterns: List[PatternObject] = []
    spatial: List[Dict[str, Any]] = []

    for (loc, sig), items in groups.items():
        independent = len({o.upstream_source_id for o in items})
        spatial.append(
            {
                "location_scope": loc,
                "signature": sig,
                "count": len(items),
                "independent_support_count": independent,
                "observation_ids": [o.obs_id for o in items],
            }
        )

        if len(items) >= min_count and independent >= 2:
            p = build_pattern_from_group(
                group=items,
                scope=scope,
                all_unique=unique_obs,
                duplicate_groups=duplicate_groups,
                existing_facts=existing_facts,
                time_range=time_range,
                now=now,
                pattern_type_override=PatternType.SPATIAL,
                spatial_scope=loc,
                signature=f"spatial:{loc}|{sig}",
                name=f"Recurring activity in {loc}",
                min_count=min_count,
            )
            patterns.append(p)

    return patterns, spatial


def detect_graph_motifs(
    unique_obs: List[ObservationObject],
    scope: Dict[str, Any],
) -> List[Dict[str, Any]]:
    min_count = int(scope.get("min_recurrence", 3))

    pair_obs: Dict[Tuple[str, str], List[ObservationObject]] = defaultdict(list)
    pair_up: Dict[Tuple[str, str], set] = defaultdict(set)

    triad_obs: Dict[Tuple[str, str, str], List[ObservationObject]] = defaultdict(list)
    triad_up: Dict[Tuple[str, str, str], set] = defaultdict(set)

    for o in unique_obs:
        ents = sorted(set(o.entity_ids))

        for a, b in combinations(ents, 2):
            pair_obs[(a, b)].append(o)
            pair_up[(a, b)].add(o.upstream_source_id)

        if len(ents) >= 3:
            for tri in combinations(ents, 3):
                triad_obs[tri].append(o)
                triad_up[tri].add(o.upstream_source_id)

    motifs: List[Dict[str, Any]] = []

    for pair, items in pair_obs.items():
        if len(items) >= 2:
            motifs.append(
                {
                    "motif_type": "EDGE_RECURRENCE",
                    "entities": list(pair),
                    "count": len(items),
                    "independent_support_count": len(pair_up[pair]),
                    "meets_min_recurrence": len(items) >= min_count,
                    "observation_ids": [o.obs_id for o in items],
                }
            )

    for tri, items in triad_obs.items():
        if len(items) >= 2:
            motifs.append(
                {
                    "motif_type": "TRIAD_RECURRENCE",
                    "entities": list(tri),
                    "count": len(items),
                    "independent_support_count": len(triad_up[tri]),
                    "meets_min_recurrence": len(items) >= min_count,
                    "observation_ids": [o.obs_id for o in items],
                }
            )

    return motifs


def deduplicate_patterns(patterns: List[PatternObject]) -> Tuple[List[PatternObject], List[Dict[str, Any]]]:
    kept: List[PatternObject] = []
    log: List[Dict[str, Any]] = []

    ordered = sorted(
        patterns,
        key=lambda p: (p.support_count, p.confidence.get("composite_transparent_ranking_score", 0.0)),
        reverse=True,
    )

    for p in ordered:
        pset = set(p.observation_ids)
        duplicate = False

        for k in kept:
            kset = set(k.observation_ids)

            if pset == kset:
                log.append(
                    {
                        "pattern_id": p.pattern_id,
                        "relation": "EXACT_SAME_PATTERN",
                        "retained_pattern_id": k.pattern_id,
                    }
                )
                duplicate = True
                break

            if pset <= kset and p.pattern_type in (PatternType.RELATIONAL, PatternType.GRAPH_MOTIF, PatternType.SPATIAL):
                log.append(
                    {
                        "pattern_id": p.pattern_id,
                        "relation": "OVERLAPPING_PATTERN",
                        "retained_pattern_id": k.pattern_id,
                    }
                )
                duplicate = True
                break

        if not duplicate:
            kept.append(p)

    return kept, log


def run_fact_gate(
    pattern: PatternObject,
    obs_by_id: Dict[str, ObservationObject],
    scope: Dict[str, Any],
    existing_facts: Dict[str, Any],
) -> Dict[str, Any]:
    min_count = int(scope.get("min_recurrence", 3))
    group_obs = [obs_by_id[oid] for oid in pattern.observation_ids if oid in obs_by_id]
    sorted_obs = sorted(group_obs, key=lambda x: x.timestamp_utc)

    contradictions: List[str] = []
    alternatives: List[str] = []

    if pattern.support_count < min_count:
        contradictions.append("Sample size below configured minimum recurrence threshold.")
        alternatives.append("insufficient data")

    if pattern.independent_support_count <= 1:
        contradictions.append("All unique observations appear to derive from one upstream source family.")
        alternatives.append("syndicated or duplicated source reporting")
        if pattern.status in (PatternState.SUPPORTED, PatternState.STRONGLY_SUPPORTED):
            pattern.status = PatternState.WEAK

    duplicate_ratio = pattern.duplicate_count / pattern.raw_count if pattern.raw_count else 0.0
    if duplicate_ratio > 0.40:
        contradictions.append("High duplicate inflation was present before deduplication.")
        alternatives.append("data artifact from repeated ingestion")

    if pattern.seasonality.get("state") == SeasonalityState.SEASONALITY_EXPLAINS.name:
        alternatives.extend(
            [
                "scheduled automation",
                "business process",
                "maintenance cycle",
                "reporting-cycle effect",
            ]
        )
        if pattern.seasonality.get("verification") == "FEATURE_CLAIM_ONLY":
            contradictions.append("Seasonality explanation relies on unverified feature claims.")

    if len(sorted_obs) >= 3:
        split = max(1, int(math.floor(len(sorted_obs) * 0.7)))
        holdout = sorted_obs[split:]
        holdout_count = len(holdout)
        holdout_independent = len({o.upstream_source_id for o in holdout})
    else:
        holdout_count = 0
        holdout_independent = 0

    tests = {
        "survives_deduplication": pattern.support_count >= min_count,
        "survives_source_independence": pattern.independent_support_count >= 2,
        "survives_seasonality_control_for_general_recurrence": True,
        "survives_seasonality_control_for_anomaly": pattern.out_of_seasonality_count >= min_count,
        "reproduces_in_holdout": holdout_count >= 1 and holdout_independent >= 1,
        "sustained_in_holdout": holdout_count >= min_count,
        "holdout_count": holdout_count,
        "holdout_independent_support_count": holdout_independent,
    }

    if not tests["survives_deduplication"]:
        pattern.status = PatternState.INCONCLUSIVE

    if not tests["survives_source_independence"]:
        pattern.tags.append("SOURCE_DEPENDENCY_RISK")

    if not tests["survives_seasonality_control_for_anomaly"]:
        pattern.tags.append("ANOMALY_NOT_SUPPORTED_BY_CURRENT_EVIDENCE")

    if tests["reproduces_in_holdout"]:
        pattern.tags.append("HOLDOUT_REPRODUCIBLE")
    else:
        pattern.tags.append("HOLDOUT_NOT_REPRODUCED")

    pattern.falsification_tests = tests
    pattern.alternative_explanations = sorted(set(pattern.alternative_explanations + alternatives))
    pattern.contradictions = sorted(set(pattern.contradictions + contradictions))

    return tests


def independent_skeptic_review(
    pattern: PatternObject,
    tests: Dict[str, Any],
    scope: Dict[str, Any],
) -> Dict[str, Any]:
    min_count = int(scope.get("min_recurrence", 3))

    flags: List[str] = []
    alternatives: List[str] = []
    questions: List[str] = []

    if pattern.support_count < min_count:
        flags.append("SAMPLE_TOO_SMALL")
        alternatives.append("apparent recurrence may be coincidence")

    if pattern.independent_support_count <= 1:
        flags.append("SOURCE_DEPENDENCY_HIGH")
        alternatives.append("single upstream feed or mirrored dataset")

    if pattern.duplicate_count > 0:
        flags.append("DUPLICATE_INFLATION_PRESENT_BEFORE_DEDUP")
        alternatives.append("repeated ingestion of same event")

    if pattern.seasonality.get("state") == SeasonalityState.SEASONALITY_EXPLAINS.name:
        flags.append("SEASONALITY_MAY_EXPLAIN_PATTERN")
        alternatives.extend(["scheduled automation", "business process", "maintenance window"])

    if not tests.get("survives_seasonality_control_for_anomaly", False):
        flags.append("ADVERSARIAL_OR_ANOMALOUS_INTERPRETATION_NOT_SUPPORTED")
        alternatives.append("normal operational cycle")

    if not tests.get("reproduces_in_holdout", False):
        flags.append("HOLDOUT_NOT_REPRODUCED")
        alternatives.append("temporary episode rather than stable pattern")

    questions.extend(
        [
            "Are we seeing apophenia from sparse data?",
            "Is the pattern driven by duplicated data?",
            "Are popular entities creating artificial links?",
            "Is the baseline appropriate for this domain?",
            "Has seasonality been controlled?",
            "Are sources actually independent?",
            "Are we turning correlation into causation?",
            "Are we converting group/system patterns into individual predictions?",
        ]
    )

    return {
        "pattern_id": pattern.pattern_id,
        "flags": flags,
        "alternative_explanations": sorted(set(alternatives)),
        "diagnostic_questions": questions,
        "review_outcome": "PARTIAL_AGREEMENT" if flags else "AGREE",
        "privacy_boundary": "Aggregate/system-level only; no private-person profiling.",
    }


def build_hypotheses(
    top: Optional[PatternObject],
    scope: Dict[str, Any],
    existing_facts: Dict[str, Any],
) -> List[Hypothesis]:
    min_count = int(scope.get("min_recurrence", 3))

    if top is None:
        return [
            Hypothesis(
                id="H1",
                description="No sufficiently supported recurring pattern was identified.",
                support_evidence=["No pattern met minimum recurrence/source-independence threshold."],
                opposition_evidence=[],
                unknowns=["Whether additional authorized data exists."],
                falsification_criteria="Upgrade if independent recurrence appears after deduplication and baseline control.",
                status=HypothesisStatus.INCONCLUSIVE,
            )
        ]

    hypotheses: List[Hypothesis] = []

    hypotheses.append(
        Hypothesis(
            id="H1",
            description="A recurring activity/structure pattern exists in the authorized dataset.",
            support_evidence=[
                f"{top.support_count} unique observations after deduplication.",
                f"{top.independent_support_count} independent upstream source families.",
                f"Pattern state: {top.status.name}.",
            ],
            opposition_evidence=top.contradictions,
            unknowns=["Causal mechanism", "External trigger", "Operational meaning"],
            falsification_criteria="Reject if pattern disappears after independent source validation or entity-resolution correction.",
            status=HypothesisStatus.CONFIRMED if top.status in (PatternState.SUPPORTED, PatternState.STRONGLY_SUPPORTED) else HypothesisStatus.ACTIVE,
        )
    )

    adversarial_candidate = (
        top.out_of_seasonality_count >= min_count
        and top.independent_support_count >= min_count
        and top.confidence.get("baseline_significance", 0.0) >= 0.5
    )

    hypotheses.append(
        Hypothesis(
            id="H2",
            description="The recurrence reflects an adversarial, malicious, or anomalous operation.",
            support_evidence=[
                f"Out-of-seasonality observations: {top.out_of_seasonality_count}.",
                f"Baseline significance: {top.confidence.get('baseline_significance', 0.0)}.",
            ]
            if adversarial_candidate
            else [],
            opposition_evidence=[
                "Seasonality or business process may explain most observations.",
                "Pattern recurrence alone does not establish intent, guilt, or actor attribution.",
            ]
            + top.contradictions,
            unknowns=["Intent", "Actor", "Campaign", "Operational objective"],
            falsification_criteria="Reject if normal operational cycle, scheduled automation, reporting bias, or data artifact explains recurrence.",
            status=HypothesisStatus.CANDIDATE if adversarial_candidate else HypothesisStatus.REJECTED,
        )
    )

    data_artifact_rejected = bool(
        top.falsification_tests.get("survives_deduplication")
        and top.falsification_tests.get("survives_source_independence")
    )

    hypotheses.append(
        Hypothesis(
            id="H3",
            description="The pattern is primarily a data artifact caused by duplicates, syndication, or collection changes.",
            support_evidence=[
                f"Duplicate count before deduplication: {top.duplicate_count}.",
                f"Independent upstream families: {top.independent_support_count}.",
            ],
            opposition_evidence=[
                "Pattern survives deduplication." if top.falsification_tests.get("survives_deduplication") else "",
                "Pattern has multiple independent upstream families." if top.falsification_tests.get("survives_source_independence") else "",
            ],
            unknowns=["Upstream collection pipeline changes", "Feed duplication policy"],
            falsification_criteria="Reject if pattern persists after deduplication and independent-source validation.",
            status=HypothesisStatus.REJECTED if data_artifact_rejected else HypothesisStatus.CANDIDATE,
        )
    )

    seasonality_supported = top.seasonality.get("state") == SeasonalityState.SEASONALITY_EXPLAINS.name
    hypotheses.append(
        Hypothesis(
            id="H4",
            description="The recurrence is explained by seasonality, scheduled automation, or business/reporting cycles.",
            support_evidence=[
                f"Seasonality state: {top.seasonality.get('state')}.",
                f"Controlled observations: {top.seasonality.get('control_count')}.",
                f"Verification: {top.seasonality.get('verification')}.",
            ]
            if seasonality_supported
            else [],
            opposition_evidence=[
                f"Out-of-seasonality observations: {top.out_of_seasonality_count}."
            ],
            unknowns=["Whether maintenance calendar is independently authoritative"],
            falsification_criteria="Reject if most recurrence remains after removing seasonal/business controls.",
            status=HypothesisStatus.CONFIRMED if seasonality_supported and top.seasonality.get("verification") == "INDEPENDENTLY_VERIFIED" else HypothesisStatus.ACTIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H5",
            description="A common external event triggered multiple observations.",
            support_evidence=[],
            opposition_evidence=["No externally verified common trigger is present in supplied facts."],
            unknowns=["External event timeline", "Independent event correlation"],
            falsification_criteria="Reject if observations remain dispersed without shared external trigger.",
            status=HypothesisStatus.INCONCLUSIVE,
        )
    )

    return hypotheses


def build_graphical_memory(
    patterns: List[PatternObject],
    observations: List[ObservationObject],
    hypotheses: List[Hypothesis],
    gaps: List[Dict[str, Any]],
    contradictions: List[str],
) -> Dict[str, Any]:
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []

    def add_node(node_id: str, node_type: str, attributes: Dict[str, Any]) -> None:
        nodes[node_id] = GraphNode(node_id=node_id, type=node_type, attributes=attributes)

    def add_edge(source: str, target: str, relation: str, confidence: float, evidence_ids: List[str]) -> None:
        edges.append(
            GraphEdge(
                edge_id=new_id("EDGE"),
                source_node_id=source,
                target_node_id=target,
                relation=relation,
                confidence=confidence,
                evidence_ids=evidence_ids,
            )
        )

    obs_by_id = {o.obs_id: o for o in observations}

    for p in patterns:
        p_node = f"N_PATTERN_{p.pattern_id}"
        add_node(
            p_node,
            "Pattern",
            {
                "pattern_type": p.pattern_type.name,
                "status": p.status.name,
                "domain": p.domain,
                "support_count": p.support_count,
                "independent_support_count": p.independent_support_count,
                "confidence": p.confidence,
            },
        )

        method_node = f"N_METHOD_{p.pattern_id}"
        add_node(method_node, "Method", p.method)
        add_edge(p_node, method_node, "GENERATED_BY_METHOD", 1.0, [])

        baseline_node = f"N_BASELINE_{p.pattern_id}"
        add_node(baseline_node, "Baseline", p.baseline)
        add_edge(p_node, baseline_node, "COMPARED_TO_BASELINE", 0.9, [])

        for oid in p.observation_ids:
            o = obs_by_id.get(oid)
            if not o:
                continue

            o_node = f"N_OBS_{oid}"
            add_node(
                o_node,
                "Observation",
                {
                    "domain": o.domain,
                    "timestamp_utc": o.timestamp_utc.isoformat(),
                    "source_id": o.source_id,
                    "upstream_source_id": o.upstream_source_id,
                    "entity_ids": o.entity_ids,
                },
            )
            add_edge(p_node, o_node, "CONTAINS", 1.0, [oid])

            source_node = f"N_SOURCE_{o.source_id}"
            add_node(source_node, "Source", {"source_id": o.source_id, "upstream_source_id": o.upstream_source_id})
            add_edge(o_node, source_node, "OBSERVED_IN", o.reliability, [oid])

            for eid in o.entity_ids:
                ent_node = f"N_ENTITY_{eid}"
                if ent_node not in nodes:
                    add_node(ent_node, "Entity", {"entity_id": eid})
                add_edge(o_node, ent_node, "OBSERVED_IN", 0.9, [oid])

        for contradiction in p.contradictions:
            c_node = f"N_CONTRADICTION_{hashlib.md5(contradiction.encode()).hexdigest()[:10]}"
            if c_node not in nodes:
                add_node(c_node, "Contradiction", {"text": contradiction})
            add_edge(p_node, c_node, "CONTRADICTS", 0.8, [])

    for h in hypotheses:
        h_node = f"N_HYPOTHESIS_{h.id}"
        add_node(
            h_node,
            "Hypothesis",
            {
                "description": h.description,
                "status": h.status.name,
                "support_evidence": h.support_evidence,
                "opposition_evidence": h.opposition_evidence,
            },
        )
        if patterns:
            add_edge(patterns[0].pattern_id and f"N_PATTERN_{patterns[0].pattern_id}", h_node, "SUPPORTED_BY", 0.7, [])

    for gap in gaps:
        g_node = f"N_GAP_{gap['gap_id']}"
        add_node(g_node, "Gap", gap)

    for contradiction in contradictions:
        c_node = f"N_CONTRADICTION_GLOBAL_{hashlib.md5(contradiction.encode()).hexdigest()[:10]}"
        if c_node not in nodes:
            add_node(c_node, "Contradiction", {"text": contradiction})

    return {
        "nodes": [asdict(n) for n in nodes.values()],
        "edges": [asdict(e) for e in edges],
    }


# ==============================================================================
# MAIN ENGINE: PATTERNINT AI EMPLOYEE
# ==============================================================================

class PatternIntEmployee:
    """
    Defensive PATTERNINT employee.

    Consumes already-collected authorized observations.
    Does not collect private data, track individuals, predict criminality,
    infer intent/guilt, or generate targeting/attack recommendations.
    """

    def __init__(self, model_mode: str = "LOCAL_ONLY"):
        self.model_mode = model_mode.upper()
        logger.info("PATTERNINT employee initialized in mode=%s", self.model_mode)

    def process_case(
        self,
        case_id: str,
        task_id: str,
        objective: str,
        scope: Dict[str, Any],
        observations_input: List[Dict[str, Any]],
        existing_facts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        existing_facts = existing_facts or {}
        now = datetime.now(timezone.utc)

        try:
            enforce_policy(objective, scope)
        except PolicyViolation as exc:
            return {
                "case_id": case_id,
                "task_id": task_id,
                "objective": objective,
                "status": "POLICY_BLOCKED",
                "error": str(exc),
                "privacy_flags": [
                    "NO_PRIVATE_INDIVIDUAL_TRACKING",
                    "NO_PREDICTIVE_POLICING",
                    "NO_INTENT_OR_GUILT_INFERENCE",
                    "NO_TARGETING_RECOMMENDATIONS",
                    "NO_ATTACK_OPTIMIZATION",
                ],
            }

        logger.info("Starting PATTERNINT case=%s task=%s", case_id, task_id)

        observations = [observation_from_dict(d, case_id, now) for d in observations_input]

        if not observations:
            return {
                "case_id": case_id,
                "task_id": task_id,
                "objective": objective,
                "status": "INSUFFICIENT_DATA",
                "patterns": [],
                "analyst_summary": "No observations supplied. Pattern analysis cannot proceed without evidence.",
                "knowledge_gaps": [{"gap_id": new_id("GAP"), "description": "No observations supplied."}],
            }

        unique_obs, duplicate_groups = deduplicate_observations(observations, scope)
        obs_by_id = {o.obs_id: o for o in unique_obs}
        source_independence = analyze_source_independence(unique_obs)
        time_range = parse_time_range(scope, unique_obs, now)

        temporal_groups = group_temporal_patterns(unique_obs, scope)
        patterns: List[PatternObject] = []

        for signature, group in temporal_groups.items():
            if len(group) < 2:
                continue

            p = build_pattern_from_group(
                group=group,
                scope=scope,
                all_unique=unique_obs,
                duplicate_groups=duplicate_groups,
                existing_facts=existing_facts,
                time_range=time_range,
                now=now,
                signature=signature,
            )
            patterns.append(p)

        sequence_patterns, transitions = detect_sequence_patterns(
            unique_obs, scope, duplicate_groups, existing_facts, time_range, now
        )
        patterns.extend(sequence_patterns)

        spatial_patterns, spatial_patterns_meta = detect_spatial_patterns(
            unique_obs, scope, duplicate_groups, existing_facts, time_range, now
        )
        patterns.extend(spatial_patterns)

        graph_motifs = detect_graph_motifs(unique_obs, scope)

        patterns, pattern_dedup_log = deduplicate_patterns(patterns)

        falsification_results: List[Dict[str, Any]] = []
        skeptic_reviews: List[Dict[str, Any]] = []

        for p in patterns:
            tests = run_fact_gate(p, obs_by_id, scope, existing_facts)
            falsification_results.append({"pattern_id": p.pattern_id, "tests": tests})

            review = independent_skeptic_review(p, tests, scope)
            skeptic_reviews.append(review)

            p.limitations = sorted(set(p.limitations + [f"Skeptic flag: {flag}" for flag in review["flags"]]))

        patterns.sort(
            key=lambda x: (
                x.confidence.get("composite_transparent_ranking_score", 0.0),
                x.independent_support_count,
                x.support_count,
            ),
            reverse=True,
        )

        top = patterns[0] if patterns else None
        hypotheses = build_hypotheses(top, scope, existing_facts)

        # Episodes: temporary bursts inside larger patterns.
        episodes: List[Dict[str, Any]] = []
        if top:
            episode_gap_seconds = int(scope.get("episode_gap_seconds", 7 * 86400))
            group_obs = [obs_by_id[oid] for oid in top.observation_ids if oid in obs_by_id]
            group_obs.sort(key=lambda x: x.timestamp_utc)

            current: List[ObservationObject] = []
            for o in group_obs:
                if not current:
                    current = [o]
                elif (o.timestamp_utc - current[-1].timestamp_utc).total_seconds() <= episode_gap_seconds:
                    current.append(o)
                else:
                    episodes.append(
                        {
                            "episode_id": new_id("EP"),
                            "pattern_id": top.pattern_id,
                            "start": current[0].timestamp_utc.isoformat(),
                            "end": current[-1].timestamp_utc.isoformat(),
                            "count": len(current),
                            "observation_ids": [x.obs_id for x in current],
                        }
                    )
                    current = [o]

            if current:
                episodes.append(
                    {
                        "episode_id": new_id("EP"),
                        "pattern_id": top.pattern_id,
                        "start": current[0].timestamp_utc.isoformat(),
                        "end": current[-1].timestamp_utc.isoformat(),
                        "count": len(current),
                        "observation_ids": [x.obs_id for x in current],
                    }
                )

        # Trend/change summaries for top pattern.
        trends = [p.features.get("trend", {}) for p in patterns]
        change_points = [p.features.get("change_point", {}) for p in patterns]

        # Multi-domain correlation candidates.
        multi_domain_patterns: List[Dict[str, Any]] = []
        for p1, p2 in combinations(patterns, 2):
            if p1.domain != p2.domain and set(p1.entity_ids) & set(p2.entity_ids):
                s1 = parse_dt(p1.time_window["start"])
                e1 = parse_dt(p1.time_window["end"])
                s2 = parse_dt(p2.time_window["start"])
                e2 = parse_dt(p2.time_window["end"])

                if s1 and e1 and s2 and e2 and s1 <= e2 and s2 <= e1:
                    multi_domain_patterns.append(
                        {
                            "correlation_id": new_id("MD"),
                            "pattern_ids": [p1.pattern_id, p2.pattern_id],
                            "shared_entities": sorted(set(p1.entity_ids) & set(p2.entity_ids)),
                            "temporal_overlap": True,
                            "interpretation": "Cross-domain candidate correlation. Mechanism unresolved. Not causation.",
                            "confidence": round(min(p1.confidence.get("composite_transparent_ranking_score", 0.0), p2.confidence.get("composite_transparent_ranking_score", 0.0)) * 0.5, 4),
                        }
                    )

        # Knowledge gaps.
        gaps: List[Dict[str, Any]] = []

        def add_gap(description: str, importance: str, recommended_source: str, specialist: str, expected_information_value: str) -> None:
            gaps.append(
                {
                    "gap_id": new_id("GAP"),
                    "description": description,
                    "importance": importance,
                    "recommended_source": recommended_source,
                    "specialist": specialist,
                    "expected_information_value": expected_information_value,
                }
            )

        if top and top.baseline.get("baseline_quality") != "SCOPE_PROVIDED":
            add_gap(
                "Independent baseline unavailable; in-sample domain approximation used.",
                "HIGH",
                "historical authorized operational data",
                "PATTERNINT / LOGINT",
                "Improves anomaly significance and reduces false pattern risk.",
            )

        if top and top.independent_support_count <= 2:
            add_gap(
                "Source independence is limited; pattern may be affected by shared upstream feeds.",
                "HIGH",
                "independent telemetry or secondary SIEM/feed",
                "LOGINT / CYBINT",
                "Confirms whether recurrence is real or source-dependent.",
            )

        if top and top.out_of_seasonality_count > 0:
            add_gap(
                "Out-of-seasonality observations remain unexplained.",
                "MEDIUM",
                "change tickets, maintenance calendar, incident records",
                "INCIDENTINT / ORGINT",
                "Determines whether residual events are anomalous or operational.",
            )

        if top and top.seasonality.get("verification") == "FEATURE_CLAIM_ONLY":
            add_gap(
                "Seasonality controls are feature-claimed and not independently verified.",
                "MEDIUM",
                "authoritative maintenance/change calendar",
                "ORGINT / LOGINT",
                "Strengthens alternative-explanation testing.",
            )

        add_gap(
            "Entity resolution is limited to supplied identifiers.",
            "MEDIUM",
            "master data / asset inventory / identity graph",
            "ENTITYINT / ORGINT",
            "Reduces false clustering from aliases or duplicate entities.",
        )

        # Next best actions.
        recommended_next_actions: List[Dict[str, Any]] = []

        if top:
            recommended_next_actions.extend(
                [
                    {
                        "action": "Obtain independent baseline or longer historical window for the same domain/entity.",
                        "reason": "Reduces false-pattern risk from small sample or inappropriate baseline.",
                        "specialist": "PATTERNINT / LOGINT",
                        "privacy": "AUTHORIZED_AGGREGATE_ONLY",
                    },
                    {
                        "action": "Validate seasonality/maintenance claims against authoritative change calendar.",
                        "reason": "Tests scheduled automation/business-process explanation.",
                        "specialist": "ORGINT / LOGINT",
                        "privacy": "AUTHORIZED_ONLY",
                    },
                    {
                        "action": "Compare out-of-seasonality observations against incident/change records.",
                        "reason": "Determines whether residual recurrence requires defensive specialist review.",
                        "specialist": "INCIDENTINT / CYBINT",
                        "privacy": "AUTHORIZED_ONLY",
                    },
                    {
                        "action": "Re-run pattern detection after adding at least one independent source family.",
                        "reason": "Confirms cross-source support and reduces syndication artifact risk.",
                        "specialist": "PATTERNINT",
                        "privacy": "AUTHORIZED_ONLY",
                    },
                ]
            )

        recommended_next_actions.append(
            {
                "action": "Do not escalate to individual monitoring, targeting, predictive policing, or intent attribution.",
                "reason": "PATTERNINT boundary is aggregate/system pattern detection only.",
                "specialist": "GOVERNANCE / HUMAN_REVIEW",
                "privacy": "PRIVACY_BOUNDARY",
            }
        )

        # Specialist handoffs.
        specialist_handoffs: List[Dict[str, Any]] = [
            {"specialist": "LOGINT", "reason": "Log normalization, retention, collection changes, and duplicate ingestion context."},
            {"specialist": "EVENTINT", "reason": "Event resolution and external trigger correlation."},
        ]

        if top:
            domain = top.domain.lower()
            if "cyber" in domain or "ioc" in domain or "ttp" in domain:
                specialist_handoffs.extend(
                    [
                        {"specialist": "CYBINT", "reason": "Cyber meaning of recurring telemetry."},
                        {"specialist": "INCIDENTINT", "reason": "Whether recurrence constitutes incident(s)."},
                        {"specialist": "TTPINT", "reason": "TTP recurrence interpretation."},
                        {"specialist": "IOCINT", "reason": "IOC recurrence and infrastructure context."},
                    ]
                )
            if "transaction" in domain or "financial" in domain or "fraud" in domain:
                specialist_handoffs.extend(
                    [
                        {"specialist": "FININT", "reason": "Financial pattern meaning."},
                        {"specialist": "FRAUDINT", "reason": "Fraud hypothesis assessment, not pattern-only conclusion."},
                    ]
                )
            if "trade" in domain:
                specialist_handoffs.append({"specialist": "TRADEINT", "reason": "Trade pattern meaning."})
            if "logistic" in domain:
                specialist_handoffs.append({"specialist": "LOGINT", "reason": "Logistics pattern meaning."})
            if "supply" in domain:
                specialist_handoffs.append({"specialist": "SUPPLYCHAININT", "reason": "Supply-chain dependency pattern meaning."})
            if "narrative" in domain or "influence" in domain:
                specialist_handoffs.extend(
                    [
                        {"specialist": "NARRATIVEINT", "reason": "Narrative recurrence meaning."},
                        {"specialist": "INFLUENCEINT", "reason": "Influence propagation meaning."},
                    ]
                )
            if "environment" in domain or "sensor" in domain:
                specialist_handoffs.append({"specialist": "ENVINT", "reason": "Environmental/sensor pattern meaning."})

        # Early warning / forecast context.
        early_warning_signals: List[Dict[str, Any]] = []
        if top and top.out_of_seasonality_count > 0:
            early_warning_signals.append(
                {
                    "signal_id": new_id("EW"),
                    "pattern_id": top.pattern_id,
                    "type": "WATCH_CONDITION_MET",
                    "description": (
                        f"{top.out_of_seasonality_count} observation(s) occurred outside identified seasonality controls. "
                        "This is a defensive watch condition, not a prediction."
                    ),
                    "confidence": round(top.confidence.get("composite_transparent_ranking_score", 0.0) * 0.5, 4),
                    "time_horizon": "NOT_PREDICTIVE",
                    "false_positive_history": "UNAVAILABLE",
                    "required_human_review": True,
                }
            )

        forecast_context = {
            "forecasting_allowed": bool(scope.get("allow_forecasting", False)),
            "method": "NONE_AUTONOMOUS",
            "statement": "Historical recurrence only. No deterministic future event forecast is produced.",
            "horizon": "NOT_APPLICABLE",
            "calibration": "UNAVAILABLE",
        }

        # Source reliability / pedigree.
        source_reliability: Dict[str, Dict[str, Any]] = {}
        source_pedigree: Dict[str, Dict[str, Any]] = {}

        for o in observations:
            source_reliability[o.source_id] = {
                "upstream_source_id": o.upstream_source_id,
                "reliability": o.reliability,
                "observation_count_raw": source_reliability.get(o.source_id, {}).get("observation_count_raw", 0) + 1,
            }
            source_pedigree[o.obs_id] = {
                "source_id": o.source_id,
                "upstream_source_id": o.upstream_source_id,
                "timestamp_utc": o.timestamp_utc.isoformat(),
                "ingest_time": o.ingest_time.isoformat() if o.ingest_time else None,
                "publication_time": o.publication_time.isoformat() if o.publication_time else None,
            }

        # Facts / contradictions / alternatives.
        supported_facts = [
            {
                "fact": p.description,
                "pattern_id": p.pattern_id,
                "evidence_ids": p.evidence_ids,
                "confidence": p.confidence,
            }
            for p in patterns
            if p.status in (PatternState.SUPPORTED, PatternState.STRONGLY_SUPPORTED)
        ]

        candidate_facts = [
            {
                "fact": p.description,
                "pattern_id": p.pattern_id,
                "evidence_ids": p.evidence_ids,
                "confidence": p.confidence,
            }
            for p in patterns
            if p.status in (PatternState.CANDIDATE, PatternState.WEAK, PatternState.EMERGING)
        ]

        all_contradictions = sorted({c for p in patterns for c in p.contradictions})
        all_alternatives = sorted({a for p in patterns for a in p.alternative_explanations})

        # Observability / coverage.
        observability = {
            "raw_observation_count": len(observations),
            "unique_observation_count": len(unique_obs),
            "duplicate_representations_removed": len(observations) - len(unique_obs),
            "unique_sources": len({o.source_id for o in observations}),
            "unique_upstream_families": len({o.upstream_source_id for o in observations}),
            "time_range_start": time_range[0].isoformat(),
            "time_range_end": time_range[1].isoformat(),
            "coverage_days": round((time_range[1] - time_range[0]).total_seconds() / 86400.0, 4),
            "missing_data_note": "Absence of observation is not evidence of absence of event.",
        }

        # Graphical memory.
        graphical_memory = build_graphical_memory(patterns, unique_obs, hypotheses, gaps, all_contradictions)

        # Analyst summary.
        analyst_summary = self._generate_analyst_summary(top, scope, observability, duplicate_groups, hypotheses)

        status = "COMPLETED" if patterns else "INCONCLUSIVE"

        result: Dict[str, Any] = {
            "case_id": case_id,
            "task_id": task_id,
            "objective": objective,
            "status": status,
            "model_mode": self.model_mode,
            "questions": scope.get("questions", []),
            "authorized_scope": scope,
            "pattern_ids": [p.pattern_id for p in patterns],
            "pattern_types": [p.pattern_type.name for p in patterns],
            "patterns": [asdict(p) for p in patterns],
            "episodes": episodes,
            "entities": sorted({eid for p in patterns for eid in p.entity_ids}),
            "events": sorted({eid for p in patterns for eid in p.event_ids}),
            "relationships": {
                "co_occurrence_pairs": [m for m in graph_motifs if m["motif_type"] == "EDGE_RECURRENCE"],
                "triads": [m for m in graph_motifs if m["motif_type"] == "TRIAD_RECURRENCE"],
            },
            "time_ranges": {p.pattern_id: p.time_window for p in patterns},
            "baseline_ranges": {p.pattern_id: p.baseline_window for p in patterns},
            "features": {p.pattern_id: p.features for p in patterns},
            "sequences": transitions,
            "transitions": transitions,
            "frequency": {p.pattern_id: p.frequency for p in patterns},
            "rates": {p.pattern_id: p.frequency.get("rate_per_day") for p in patterns},
            "support_counts": {p.pattern_id: p.support_count for p in patterns},
            "independent_support_counts": {p.pattern_id: p.independent_support_count for p in patterns},
            "periodicity": {p.pattern_id: periodicity_state(p.support_count, p.recurrence_interval).name for p in patterns},
            "seasonality": {p.pattern_id: p.seasonality for p in patterns},
            "bursts": episodes,
            "trends": trends,
            "change_points": change_points,
            "clusters": {
                "pattern_clusters": [
                    {
                        "cluster_id": p.pattern_id,
                        "observation_ids": p.observation_ids,
                        "entity_ids": p.entity_ids,
                        "confidence": p.confidence,
                    }
                    for p in patterns
                ]
            },
            "communities": [],
            "graph_motifs": graph_motifs,
            "spatial_patterns": spatial_patterns_meta,
            "spatiotemporal_patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "spatial_scope": p.spatial_scope,
                    "time_window": p.time_window,
                }
                for p in patterns
                if p.spatial_scope
            ],
            "transaction_patterns": [asdict(p) for p in patterns if p.domain in {"transactional", "financial", "fraud"}],
            "cyber_patterns": [asdict(p) for p in patterns if p.domain in {"cyber", "ioc", "ttp"}],
            "ttp_patterns": [asdict(p) for p in patterns if "ttp" in p.domain.lower()],
            "ioc_patterns": [asdict(p) for p in patterns if "ioc" in p.domain.lower()],
            "fraud_patterns": [asdict(p) for p in patterns if "fraud" in p.domain.lower()],
            "trade_patterns": [asdict(p) for p in patterns if "trade" in p.domain.lower()],
            "logistics_patterns": [asdict(p) for p in patterns if "logistic" in p.domain.lower()],
            "supply_chain_patterns": [asdict(p) for p in patterns if "supply" in p.domain.lower()],
            "organizational_patterns": [asdict(p) for p in patterns if "org" in p.domain.lower()],
            "narrative_patterns": [asdict(p) for p in patterns if "narrative" in p.domain.lower()],
            "influence_patterns": [asdict(p) for p in patterns if "influence" in p.domain.lower()],
            "environmental_patterns": [asdict(p) for p in patterns if p.domain in {"environmental", "sensor", "satellite", "ais", "radar", "seismic"}],
            "multi_domain_patterns": multi_domain_patterns,
            "pattern_stability": {p.pattern_id: p.stability for p in patterns},
            "pattern_drift": {p.pattern_id: p.drift for p in patterns},
            "pattern_lifecycle": {p.pattern_id: p.lifecycle for p in patterns},
            "pattern_similarity": {
                "deduplication_log": pattern_dedup_log,
                "note": "Similarity is structural overlap only; it does not prove identity or common cause.",
            },
            "source_reliability": source_reliability,
            "source_bias": [
                "Collection density may vary over time.",
                "SIEM/log retention changes may create apparent increases or decreases.",
                "Commercial feeds may share upstream telemetry.",
                "Reporting policies may change during the window.",
            ],
            "source_limitations": [
                "No private-person tracking.",
                "No unauthorized data collection.",
                "No causal inference from recurrence alone.",
                "No intent, guilt, or actor attribution from pattern alone.",
            ],
            "source_pedigree": source_pedigree,
            "source_independence": source_independence,
            "baseline_quality": {p.pattern_id: p.baseline.get("baseline_quality") for p in patterns},
            "coverage": observability,
            "observability": observability,
            "candidate_facts": candidate_facts,
            "supported_facts": supported_facts,
            "contradictions": all_contradictions,
            "alternative_explanations": all_alternatives,
            "hypotheses": [asdict(h) for h in hypotheses],
            "falsification_results": falsification_results,
            "skeptic_reviews": skeptic_reviews,
            "early_warning_signals": early_warning_signals,
            "forecast_context": forecast_context,
            "unknowns": [
                "Causal mechanism unresolved.",
                "Intent unresolved and not inferred.",
                "Actor attribution unresolved and not inferred.",
                "Whether out-of-seasonality observations are operational anomalies remains unresolved.",
            ],
            "knowledge_gaps": gaps,
            "specialist_handoffs": specialist_handoffs,
            "recommended_next_actions": recommended_next_actions,
            "limitations": [
                "PATTERNINT detects/validates/explains recurring patterns only.",
                "Correlation is not causation.",
                "Recurrence is not intent.",
                "Cluster is not real-world entity.",
                "Centrality is not target value.",
                "Early-warning signals are watch conditions, not certain predictions.",
            ],
            "privacy_flags": [
                "AGGREGATE_OR_SYSTEM_LEVEL_ONLY",
                "NO_PRIVATE_PERSON_MOVEMENT_PROFILES",
                "NO_PREDICTIVE_POLICING",
                "NO_SENSITIVE_TRAIT_INFERENCE",
                "NO_TARGETING_RECOMMENDATIONS",
                "NO_ATTACK_OPTIMIZATION",
            ],
            "human_review_triggers": [
                "Criminal/fraud attribution",
                "Employment consequences",
                "Law-enforcement action",
                "Financial blocking",
                "High-impact cyber response",
                "Private-person behavioural prediction",
                "Sensitive-trait implications",
                "Material model disagreement",
            ],
            "analyst_summary": analyst_summary,
            "graphical_memory": graphical_memory,
            "replay_manifest": {
                "case_id": case_id,
                "task_id": task_id,
                "model_mode": self.model_mode,
                "generated_at": now.isoformat(),
                "raw_observation_count": len(observations),
                "unique_observation_count": len(unique_obs),
                "duplicate_groups": duplicate_groups,
                "source_independence": source_independence,
                "pattern_ids": [p.pattern_id for p in patterns],
                "methods": {p.pattern_id: p.method for p in patterns},
                "baselines": {p.pattern_id: p.baseline for p in patterns},
                "falsification_results": falsification_results,
                "skeptic_reviews": skeptic_reviews,
                "dataset_filters": scope.get("filters", {}),
                "normalization_version": "patternint-normalization-1.0",
                "entity_resolution_version": "supplied-identifiers-only-1.0",
            },
        }

        logger.info("PATTERNINT case completed. patterns=%s top=%s", len(patterns), top.pattern_id if top else None)
        return result

    def _generate_analyst_summary(
        self,
        top: Optional[PatternObject],
        scope: Dict[str, Any],
        observability: Dict[str, Any],
        duplicate_groups: List[Dict[str, Any]],
        hypotheses: List[Hypothesis],
    ) -> str:
        lines: List[str] = []
        lines.append("=== PATTERNINT REQUIRED ANALYST SUMMARY ===")

        if not top:
            lines.append("PATTERN: none sufficiently supported")
            lines.append("STATUS: INCONCLUSIVE")
            lines.append("NEXT ACTION: obtain independent baseline and additional authorized observations.")
            return "\n".join(lines)

        min_count = int(scope.get("min_recurrence", 3))

        lines.append(f"PATTERN NAME: {top.pattern_name}")
        lines.append(f"PATTERN TYPE: {top.pattern_type.name}")
        lines.append(f"DOMAIN: {top.domain}")
        lines.append(f"TIME WINDOW: {top.time_window['start']} to {top.time_window['end']}")
        lines.append(f"ENTITIES: {', '.join(top.entity_ids) if top.entity_ids else 'none'}")
        lines.append(f"EVENTS: {', '.join(top.event_ids) if top.event_ids else 'none'}")
        lines.append(f"BASELINE: rate/day={top.baseline.get('baseline_rate_per_day')}, expected={top.baseline.get('expected_count_in_window')}, quality={top.baseline.get('baseline_quality')}")
        lines.append(f"SUPPORT COUNT: {top.support_count} unique observations")
        lines.append(f"RAW COUNT: {top.raw_count} observations before deduplication")
        lines.append(f"DUPLICATION: {top.duplicate_count} duplicate representations removed")
        lines.append(f"INDEPENDENT SUPPORT COUNT: {top.independent_support_count} upstream source families")
        lines.append(f"RECURRENCE RATE: {top.frequency.get('rate_per_day')} per day")
        lines.append(f"PERIODICITY: {periodicity_state(top.support_count, top.recurrence_interval).name}")
        lines.append(f"SEASONALITY: {top.seasonality.get('state')} ({top.seasonality.get('verification')})")
        lines.append(f"SEQUENCE: {top.sequence if top.sequence else 'none'}")
        lines.append(f"SPATIAL CONTEXT: {top.spatial_scope or 'none'}")
        lines.append(f"STABILITY: {top.stability}")
        lines.append(f"DRIFT: {top.drift}")
        lines.append(f"LIFECYCLE: {top.lifecycle}")
        lines.append(f"SOURCE RELIABILITY: {len(top.source_ids)} sources, {len(top.upstream_source_ids)} upstream families")
        lines.append(f"SOURCE INDEPENDENCE: {'SUPPORTED' if top.independent_support_count >= 2 else 'LIMITED'}")
        lines.append(f"ALTERNATIVE EXPLANATIONS: {', '.join(top.alternative_explanations)}")
        lines.append(f"CONTRADICTIONS: {', '.join(top.contradictions) if top.contradictions else 'none'}")
        lines.append(f"FALSIFICATION: {json.dumps(top.falsification_tests, default=json_serial)}")

        if (
            top.seasonality.get("state") == SeasonalityState.SEASONALITY_EXPLAINS.name
            and top.out_of_seasonality_count < min_count
        ):
            lines.append("ASSESSMENT: RECURRING_ACTIVITY_PATTERN = SUPPORTED.")
            lines.append("ASSESSMENT: ADVERSARIAL_OR_ANOMALOUS_PATTERN = NOT_SUPPORTED_BY_CURRENT_EVIDENCE.")
        else:
            lines.append(f"ASSESSMENT: PATTERN_STATUS = {top.status.name}.")
            lines.append("ASSESSMENT: CAUSATION / INTENT / ACTOR ATTRIBUTION = NOT_ESTABLISHED.")

        predictive_value = "LOW_OR_UNCALIBRATED"
        if top.falsification_tests.get("reproduces_in_holdout") and top.independent_support_count >= 3:
            predictive_value = "CANDIDATE_LEADING_SIGNAL_ONLY"
        lines.append(f"PREDICTIVE VALUE: {predictive_value}")

        lines.append("UNKNOWN: causal mechanism, intent, actor, operational significance.")
        lines.append("NEXT ACTION: validate baseline, verify seasonality controls, compare out-of-window events to change/incident records, and hand off domain meaning to specialist. Do not escalate to individual targeting or intent attribution.")

        return "\n".join(lines)


# ==============================================================================
# EXAMPLE EXECUTION
# ==============================================================================

# Interrupted upload example preserved in packages/archive_sources/intelligence-suite.
