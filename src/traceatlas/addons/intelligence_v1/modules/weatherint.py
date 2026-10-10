#!/usr/bin/env python3
"""
TRACEATLAS WEATHERINT main.py
=============================

Evidence-first, uncertainty-aware, safety-aware weather / meteorological
intelligence scaffold.

This module:
- Does NOT fetch live weather data.
- Does NOT invent observations, forecasts, radar products, satellite products,
  warnings, storms, rainfall, wind, temperature, visibility, or lightning.
- Does NOT provide targeting, attack timing, concealment, evasion, smuggling,
  or harmful operational optimization.
- Does NOT override official meteorological, aviation, maritime, or emergency
  authorities.
- Does NOT merge forecast with observation.
- Does NOT merge station weather with exact-site weather.
- Does NOT merge radar/satellite-derived estimates with ground measurements.
- Does NOT treat weather correlation as causation.

It consumes deterministic weather records supplied by authorized/public sources:
- weather station observations
- METAR/SPECI-like station records
- forecast products
- deterministic model runs
- ensemble forecasts
- meteorological radar products
- weather satellite products
- official warnings/advisories/watches
- historical weather records
- reanalysis products
- climate normals
- event context for correlation only

It produces an evidence-linked WEATHERINTResult with:
- location/time normalization
- unit normalization
- station representativeness assessment
- observation/forecast separation
- radar/satellite-derived separation
- source reliability / pedigree / independence
- model consensus and ensemble spread
- forecast verification where possible
- threshold checks from supplied criteria
- contradiction preservation
- competing hypotheses and falsification
- dual-AI style skeptic review
- safety flags
- graphical memory scaffold
- analyst summary and report-ready result object
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "0.1.0"

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

DATA_OBSERVATION = "OBSERVATION"
DATA_FORECAST = "FORECAST"
DATA_RADAR_DERIVED = "RADAR_DERIVED"
DATA_SATELLITE_DERIVED = "SATELLITE_DERIVED"
DATA_REANALYSIS_DERIVED = "REANALYSIS_DERIVED"
DATA_CLIMATE_NORMAL = "CLIMATE_NORMAL"
DATA_HISTORICAL_OBSERVATION = "HISTORICAL_OBSERVATION"

ALLOWED_ALERT_TYPES = {
    "WATCH",
    "ADVISORY",
    "WARNING",
    "EMERGENCY",
    "ALL_CLEAR",
    "OTHER",
    "UNKNOWN",
}

ALLOWED_HORIZONS = {
    "NOWCAST",
    "SHORT_RANGE",
    "MEDIUM_RANGE",
    "EXTENDED_RANGE",
    "SEASONAL",
    "OTHER",
    "UNKNOWN",
}

SEVERE_QUALITY_FLAGS = {
    "sensor_offline",
    "outlier",
    "unit_error",
    "missing_time",
    "missing_location",
    "low_quality",
    "failed_qc",
    "suspect",
    "timing_conflict",
    "unit_quantity_mismatch",
}

BLOCK_PHRASES = [
    # harmful operational use
    "strike timing",
    "attack timing",
    "targeting window",
    "military targeting",
    "concealment window",
    "evasion window",
    "evade detection using weather",
    "use storm cover",
    "storm exploitation",
    "smuggling route",
    "smuggling optimization",
    "criminal evasion",
    "surveillance avoidance using weather",
    "harmful navigation",
    "weapon optimization",
    "optimize violent attack",
    "dangerous travel contrary to warning",
    "override emergency warning",
    "override aviation authority",
    "override maritime authority",
    "fabricate warning",
    "fabricate observation",
]

MEASUREMENT_QUANTITY = {
    "temperature": "temperature",
    "air_temperature": "temperature",
    "dew_point": "temperature",
    "surface_temperature": "temperature",
    "land_surface_temperature": "temperature",
    "apparent_temperature": "temperature",
    "heat_index": "temperature",
    "wind_chill": "temperature",

    "wind_speed": "wind_speed",
    "sustained_wind": "wind_speed",
    "wind_gust": "wind_speed",
    "gust": "wind_speed",

    "pressure": "pressure",
    "station_pressure": "pressure",
    "sea_level_pressure": "pressure",
    "mean_sea_level_pressure": "pressure",
    "altimeter_setting": "pressure",

    "precipitation": "precipitation",
    "rainfall": "precipitation",
    "precipitation_accumulation": "precipitation",
    "rainfall_accumulation": "precipitation",
    "snowfall": "precipitation",
    "snow_water_equivalent": "precipitation",

    "precipitation_rate": "precipitation_rate",
    "rain_rate": "precipitation_rate",

    "visibility": "length",
    "cloud_ceiling": "length",
    "snow_depth": "length",
    "wave_height": "length",
    "significant_wave_height": "length",

    "cloud_cover": "fraction",
    "cloud_fraction": "fraction",

    "wind_direction": "angle",
    "azimuth": "angle",

    "lightning_count": "count",
    "flash_count": "count",
    "stroke_count": "count",
}

UNIT_ALIASES = {
    "celsius": "c",
    "centigrade": "c",
    "fahrenheit": "f",
    "kelvin": "k",

    "mps": "m/s",
    "metres_per_second": "m/s",
    "meters_per_second": "m/s",
    "kms": "km/h",
    "kmph": "km/h",
    "kilometres_per_hour": "km/h",
    "knot": "kt",
    "kts": "kt",
    "knots": "kt",
    "mph": "mph",
    "miles_per_hour": "mph",

    "hectopascal": "hpa",
    "millibar": "mb",
    "millibars": "mb",
    "inches_mercury": "inhg",
    "inch_mercury": "inhg",

    "millimetre": "mm",
    "millimetres": "mm",
    "millimeter": "mm",
    "millimeters": "mm",
    "centimetre": "cm",
    "centimeters": "cm",
    "inch": "in",
    "inches": "in",

    "metre": "m",
    "metres": "m",
    "meter": "m",
    "meters": "m",
    "kilometre": "km",
    "kilometers": "km",
    "mile": "mi",
    "miles": "mi",
    "foot": "ft",
    "feet": "ft",

    "degree": "deg",
    "degrees": "deg",
    "degs": "deg",

    "fraction": "fraction",
    "ratio": "fraction",
    "%": "percent",
    "pct": "percent",
    "percentage": "percent",
    "oktas": "okta",
    "octa": "okta",

    "counts": "count",
    "flashes": "count",
    "strokes": "count",
}

# dimension, linear_factor, additive_offset_to_canonical
UNIT_INFO = {
    # temperature -> Celsius
    "c": ("temperature", 1.0, 0.0),
    "k": ("temperature", 1.0, -273.15),
    "f": ("temperature", 5.0 / 9.0, -17.77777777777778),

    # wind speed -> m/s
    "m/s": ("wind_speed", 1.0, 0.0),
    "km/h": ("wind_speed", 1.0 / 3.6, 0.0),
    "kt": ("wind_speed", 0.5144444444444445, 0.0),
    "mph": ("wind_speed", 0.44704, 0.0),

    # pressure -> Pa
    "pa": ("pressure", 1.0, 0.0),
    "hpa": ("pressure", 100.0, 0.0),
    "kpa": ("pressure", 1000.0, 0.0),
    "mb": ("pressure", 100.0, 0.0),
    "inhg": ("pressure", 3386.389, 0.0),

    # precipitation amount -> mm
    "mm": ("precipitation", 1.0, 0.0),
    "cm": ("precipitation", 10.0, 0.0),
    "in": ("precipitation", 25.4, 0.0),

    # precipitation rate -> mm/h
    "mm/h": ("precipitation_rate", 1.0, 0.0),
    "in/h": ("precipitation_rate", 25.4, 0.0),

    # length -> m
    "m": ("length", 1.0, 0.0),
    "km": ("length", 1000.0, 0.0),
    "mi": ("length", 1609.344, 0.0),
    "ft": ("length", 0.3048, 0.0),

    # angle -> deg
    "deg": ("angle", 1.0, 0.0),

    # fraction -> 0..1
    "fraction": ("fraction", 1.0, 0.0),
    "percent": ("fraction", 0.01, 0.0),
    "okta": ("fraction", 1.0 / 8.0, 0.0),

    # count
    "count": ("count", 1.0, 0.0),
}

CANONICAL_UNITS = {
    "temperature": "C",
    "wind_speed": "m/s",
    "pressure": "Pa",
    "precipitation": "mm",
    "precipitation_rate": "mm/h",
    "length": "m",
    "angle": "deg",
    "fraction": "fraction",
    "count": "count",
    "other": "other",
    "unknown": "unknown",
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


def haversine_km(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
) -> Optional[float]:
    if None in (lat1, lon1, lat2, lon2):
        return None
    try:
        lat1_f = float(lat1)
        lon1_f = float(lon1)
        lat2_f = float(lat2)
        lon2_f = float(lon2)
    except Exception:
        return None

    r = 6371.0
    phi1 = math.radians(lat1_f)
    phi2 = math.radians(lat2_f)
    dphi = math.radians(lat2_f - lat1_f)
    dlmb = math.radians(lon2_f - lon1_f)

    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


def normalize_measurement_type(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = s.replace("-", "_").replace(" ", "_")
    return s or "unknown"


def normalize_unit_token(unit: Any) -> str:
    if unit is None:
        return ""
    raw = str(unit).strip().replace("°", "").replace("µ", "u").replace("μ", "u")
    raw = raw.replace("deg", "").replace(" ", "").lower()
    return UNIT_ALIASES.get(raw, raw)


def infer_quantity(measurement_type: Any, quantity_hint: Any = None) -> str:
    qt = str(quantity_hint or "").strip().lower()
    if qt in CANONICAL_UNITS and qt not in ("unknown", "other"):
        return qt

    mt = normalize_measurement_type(measurement_type)
    return MEASUREMENT_QUANTITY.get(mt, qt or "other")


def normalize_value_unit(
    value: Any,
    uncertainty: Any,
    unit: Any,
    quantity_hint: Any = None,
) -> Dict[str, Any]:
    """
    Deterministically normalize recognized units.

    Preserves original value/unit. Never invents missing values.
    """
    original_unit = str(unit).strip() if unit is not None else None
    token = normalize_unit_token(original_unit)
    info = UNIT_INFO.get(token)

    v = to_float(value)
    u = to_float(uncertainty)

    flags: List[str] = []

    if u is not None and u < 0:
        flags.append("negative_uncertainty")
        u = abs(u)

    hint = str(quantity_hint or "").strip().lower()
    if hint not in CANONICAL_UNITS:
        hint = "unknown"

    if not info:
        return {
            "original_value": v,
            "original_unit": original_unit,
            "normalized_value": v,
            "normalized_unit": original_unit,
            "normalized_uncertainty": u,
            "quantity_type": hint if hint != "unknown" else "unknown",
            "conversion_factor": None,
            "conversion_offset": None,
            "flags": flags + (["unit_unknown"] if original_unit else ["unit_missing"]),
        }

    dimension, factor, offset = info

    if hint not in ("unknown", "other") and dimension != hint:
        flags.append("unit_quantity_mismatch")

    norm_v = None
    norm_u = None

    if v is not None:
        norm_v = v * factor + offset
    if u is not None:
        norm_u = abs(factor) * u

    canonical_unit = CANONICAL_UNITS.get(dimension, dimension)

    return {
        "original_value": v,
        "original_unit": original_unit,
        "normalized_value": norm_v,
        "normalized_unit": canonical_unit,
        "normalized_uncertainty": norm_u,
        "quantity_type": dimension,
        "conversion_factor": factor,
        "conversion_offset": offset,
        "flags": flags,
    }


def extract_coords(obj: Dict[str, Any]) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[float], Optional[str]]:
    """
    Returns lat, lon, elevation_m, accuracy_m, area_id.
    """
    lat = lon = elev = acc = None
    area_id = obj.get("area_id") or obj.get("location_area_id") or obj.get("region_id")

    loc = obj.get("location")
    if isinstance(loc, dict):
        lat = to_float(loc.get("latitude") if loc.get("latitude") is not None else loc.get("lat"))
        lon = to_float(loc.get("longitude") if loc.get("longitude") is not None else loc.get("lon"))
        elev = to_float(
            loc.get("elevation_m")
            if loc.get("elevation_m") is not None
            else loc.get("altitude_m")
            if loc.get("altitude_m") is not None
            else loc.get("elevation")
        )
        acc = to_float(loc.get("accuracy_m") if loc.get("accuracy_m") is not None else loc.get("uncertainty_m"))
        area_id = loc.get("area_id") or loc.get("region_id") or area_id
    elif isinstance(loc, list) and len(loc) >= 2:
        lat = to_float(loc[0])
        lon = to_float(loc[1])
        if len(loc) >= 3:
            elev = to_float(loc[2])

    if lat is None:
        lat = to_float(obj.get("latitude") if obj.get("latitude") is not None else obj.get("lat"))
    if lon is None:
        lon = to_float(obj.get("longitude") if obj.get("longitude") is not None else obj.get("lon"))
    if elev is None:
        elev = to_float(
            obj.get("elevation_m")
            if obj.get("elevation_m") is not None
            else obj.get("altitude_m")
            if obj.get("altitude_m") is not None
            else obj.get("elevation")
        )
    if acc is None:
        acc = to_float(obj.get("accuracy_m") if obj.get("accuracy_m") is not None else obj.get("uncertainty_m"))

    if lat is not None and not (-90.0 <= lat <= 90.0):
        lat = None
    if lon is not None and not (-180.0 <= lon <= 180.0):
        lon = None

    return lat, lon, elev, acc, area_id


def location_key(item: Dict[str, Any]) -> str:
    return str(item.get("_location_id") or item.get("_spatial_cluster_id") or "UNKNOWN_LOCATION")


def item_time(item: Dict[str, Any]) -> Optional[datetime]:
    return (
        item.get("_valid_time")
        or item.get("_observation_time")
        or item.get("_timestamp")
        or item.get("_event_time")
        or item.get("_collection_time")
    )


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
            reasons.append(f"Forbidden WEATHERINT action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    requested = case.get("requested_outputs") if isinstance(case.get("requested_outputs"), dict) else {}

    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    if scope.get("defensive_only") is False:
        reasons.append("scope.defensive_only must not be false")

    prohibited_scope_flags = [
        "targeting",
        "attack_timing",
        "concealment",
        "evasion",
        "smuggling_optimization",
        "override_emergency_authority",
        "override_aviation_authority",
        "override_maritime_authority",
        "fabricate_warning",
        "fabricate_observation",
    ]

    for flag in prohibited_scope_flags:
        if scope.get(flag) is True:
            reasons.append(f"scope.{flag} is prohibited")

    prohibited_requested = [
        "targeting_window",
        "attack_timing",
        "concealment_window",
        "evasion_plan",
        "smuggling_route",
        "override_official_warning",
        "fabricated_observation",
        "fabricated_warning",
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
            "NO_TARGETING",
            "NO_ATTACK_TIMING",
            "NO_CONCEALMENT_PLANNING",
            "NO_EVASION_PLANNING",
            "NO_SMUGGLING_OPTIMIZATION",
            "NO_OVERRIDE_EMERGENCY_AUTHORITIES",
            "NO_OVERRIDE_AVIAATION_AUTHORITIES",
            "NO_OVERRIDE_MARITIME_AUTHORITIES",
            "NO_FABRICATED_WARNINGS",
            "NO_FABRICATED_OBSERVATIONS",
        ],
        "recommended_next_actions": [
            "Restate objective as lawful weather awareness, safety, resilience, historical analysis, or event correlation",
            "Use authoritative public/authorized meteorological sources",
            "Preserve separation between observation, forecast, warning, radar, and satellite products",
            "Escalate life-safety decisions to official meteorological/emergency authorities",
        ],
        "limitations": [
            "Requested or detected use crosses WEATHERINT safety boundary.",
            "No targeting, attack timing, concealment, evasion, smuggling, authority override, or fabricated weather support is provided.",
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
# Validation
# -----------------------------------------------------------------------------

def validate_locations(case: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    locations: List[Dict[str, Any]] = []

    raw = case.get("locations") or []
    if case.get("location"):
        raw = list(raw) + [case.get("location")]

    for idx, loc in enumerate(raw):
        if not isinstance(loc, dict):
            issues.append(f"locations[{idx}] is not an object")
            continue

        lid = loc.get("location_id") or loc.get("id") or f"LOC-{idx + 1}"
        loc["location_id"] = lid

        lat, lon, elev, acc, area = extract_coords(loc)
        loc["_lat"] = lat
        loc["_lon"] = lon
        loc["_elevation_m"] = elev
        loc["_accuracy_m"] = acc
        loc["_area_id"] = area
        loc["_timezone"] = loc.get("timezone")

        if lat is None and lon is None and not area:
            issues.append(f"location {lid} has no usable coordinates or area_id")
            continue

        locations.append(loc)

    return locations, issues


def validate_sources(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    sources: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(case.get("sources") or case.get("weather_sources") or []):
        if not isinstance(s, dict):
            issues.append(f"sources[{idx}] is not an object")
            continue

        sid = s.get("source_id") or s.get("id") or f"SRC-{idx + 1}"
        s["source_id"] = sid

        stype = str(s.get("source_type", "UNKNOWN")).strip().upper()
        s["_source_type"] = stype

        rel = str(s.get("reliability", "")).strip().upper()
        if rel not in {"HIGH", "MODERATE", "LOW", "UNKNOWN"}:
            if stype in {
                "NATIONAL_MET_SERVICE",
                "OFFICIAL_AGENCY",
                "GOVERNMENT_WEATHER_SERVICE",
                "WEATHER_RADAR",
                "METEOROLOGICAL_SATELLITE",
                "OFFICIAL_WARNING_AUTHORITY",
            }:
                rel = "HIGH"
            elif stype in {
                "AIRPORT_STATION",
                "WEATHER_STATION",
                "BUOY",
                "SHIP",
                "RADIOSONDE",
                "LIGHTNING_NETWORK",
                "RAIN_GAUGE",
                "WEATHER_MODEL",
                "ENSEMBLE_MODEL",
                "REANALYSIS",
            }:
                rel = "MODERATE"
            elif stype in {
                "COMMERCIAL_PROVIDER",
                "CROWDSOURCED_STATION",
                "PERSONAL_WEATHER_STATION",
                "SOCIAL_REPORT",
            }:
                rel = "LOW"
            else:
                rel = "UNKNOWN"

        s["_reliability"] = rel
        s["_independence_group"] = str(
            s.get("independence_group")
            or s.get("upstream_model_id")
            or s.get("upstream_station_id")
            or s.get("upstream_radar_id")
            or s.get("upstream_satellite_product_id")
            or sid
        ).strip().upper()

        sources[sid] = s

    if not sources:
        issues.append("No weather sources supplied")

    return sources, issues


def validate_stations(
    case: Dict[str, Any],
    locations: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    stations: Dict[str, Dict[str, Any]] = {}

    for idx, st in enumerate(case.get("stations") or []):
        if not isinstance(st, dict):
            issues.append(f"stations[{idx}] is not an object")
            continue

        sid = st.get("station_id") or st.get("id") or f"STA-{idx + 1}"
        st["station_id"] = sid

        src = st.get("source_id")
        st["_source_id"] = src
        if src and src not in sources:
            warnings.append(f"station {sid} references unknown source_id={src}")

        lat, lon, elev, acc, area = extract_coords(st)
        st["_lat"] = lat
        st["_lon"] = lon
        st["_elevation_m"] = elev
        st["_accuracy_m"] = acc
        st["_area_id"] = area

        st["_station_type"] = str(st.get("station_type", "UNKNOWN")).strip().upper()

        if lat is None or lon is None:
            warnings.append(f"station {sid} missing coordinates; representativeness limited")
            add_flag(st, "missing_location")

        assessments: Dict[str, Dict[str, Any]] = {}

        for loc in locations:
            lid = loc.get("location_id")
            dist = haversine_km(lat, lon, loc.get("_lat"), loc.get("_lon"))
            elev_diff = None
            if elev is not None and loc.get("_elevation_m") is not None:
                elev_diff = abs(elev - loc.get("_elevation_m"))

            rep = "UNKNOWN"
            reasons: List[str] = []

            if dist is None:
                reasons.append("station or target coordinates missing")
            elif dist <= 5.0 and (elev_diff is None or elev_diff <= 50.0):
                if st["_station_type"] in {"OFFICIAL", "NATIONAL_MET_SERVICE", "AIRPORT", "RAINFALL_GAUGE", "SYNOP"}:
                    rep = "HIGH"
                else:
                    rep = "MODERATE"
            elif dist <= 15.0 and (elev_diff is None or elev_diff <= 150.0):
                rep = "MODERATE"
            elif dist <= 50.0:
                rep = "LOW"
            else:
                rep = "LOW"
                reasons.append("station far from target location")

            if st.get("terrain_microclimate_risk") in {"HIGH", "MEDIUM"}:
                if rep == "HIGH":
                    rep = "MODERATE"
                elif rep == "MODERATE":
                    rep = "LOW"
                reasons.append("terrain/microclimate risk supplied")

            if st.get("urban_risk") is True:
                reasons.append("urban siting may affect local temperature/visibility")

            assessments[lid] = {
                "distance_km": dist,
                "elevation_difference_m": elev_diff,
                "representativeness": rep,
                "reasons": reasons,
            }

        st["_target_assessments"] = assessments
        stations[sid] = st

    return stations, issues, warnings


def validate_models(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    models: Dict[str, Dict[str, Any]] = {}

    for idx, m in enumerate(case.get("models") or case.get("weather_models") or []):
        if not isinstance(m, dict):
            issues.append(f"models[{idx}] is not an object")
            continue

        mid = m.get("model_id") or m.get("id") or f"MODEL-{idx + 1}"
        m["model_id"] = mid

        m["_model_name"] = m.get("model_name") or m.get("name")
        m["_model_version"] = m.get("model_version") or m.get("version")
        m["_run_time"] = parse_dt(m.get("run_time") or m.get("model_run_time"))
        m["_horizontal_resolution_m"] = to_float(m.get("horizontal_resolution_m") or m.get("resolution_m"))
        m["_ensemble_or_deterministic"] = str(m.get("ensemble_or_deterministic", "UNKNOWN")).upper()
        m["_model_family"] = str(m.get("model_family") or m.get("upstream_model_id") or mid).upper()

        models[mid] = m

    return models, issues


def assign_location(
    item: Dict[str, Any],
    locations: List[Dict[str, Any]],
    radius_km: float,
) -> None:
    lat = item.get("_lat")
    lon = item.get("_lon")
    area = item.get("_area_id")

    best_loc = None
    best_dist = None

    if lat is not None and lon is not None:
        for loc in locations:
            d = haversine_km(lat, lon, loc.get("_lat"), loc.get("_lon"))
            if d is None:
                continue
            if best_dist is None or d < best_dist:
                best_dist = d
                best_loc = loc

        if best_loc is not None and best_dist is not None and best_dist <= radius_km:
            item["_location_id"] = best_loc.get("location_id")
            item["_target_distance_km"] = best_dist
            return

    if area:
        for loc in locations:
            if loc.get("_area_id") == area:
                item["_location_id"] = loc.get("location_id")
                item["_target_distance_km"] = None
                return

    if lat is not None and lon is not None:
        item["_spatial_cluster_id"] = f"POINT:{round(lat, 3)},{round(lon, 3)}"
        item["_target_distance_km"] = best_dist
    elif area:
        item["_spatial_cluster_id"] = f"AREA:{area}"
    else:
        item["_spatial_cluster_id"] = "UNKNOWN_LOCATION"


def normalize_numeric_record(
    obj: Dict[str, Any],
    value_key: str = "value",
    unit_key: str = "unit",
    uncertainty_key: str = "uncertainty",
    measurement_type_key: str = "measurement_type",
    quantity_key: str = "quantity_type",
) -> None:
    mt = normalize_measurement_type(obj.get(measurement_type_key))
    obj["_measurement_type"] = mt

    qty_hint = obj.get(quantity_key)
    quantity = infer_quantity(mt, qty_hint)
    obj["_quantity_type"] = quantity

    norm = normalize_value_unit(
        obj.get(value_key),
        obj.get(uncertainty_key),
        obj.get(unit_key),
        quantity,
    )

    obj["_original_value"] = norm["original_value"]
    obj["_original_unit"] = norm["original_unit"]
    obj["_value_norm"] = norm["normalized_value"]
    obj["_unit_norm"] = norm["normalized_unit"]
    obj["_unc_norm"] = norm["normalized_uncertainty"]
    obj["_quantity_type"] = norm["quantity_type"] or quantity

    for f in norm["flags"]:
        add_flag(obj, f)


def validate_observations(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    stations: Dict[str, Dict[str, Any]],
    locations: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    observations: List[Dict[str, Any]] = []

    for idx, o in enumerate(case.get("weather_observations") or case.get("observations") or []):
        if not isinstance(o, dict):
            issues.append(f"weather_observations[{idx}] is not an object")
            continue

        oid = o.get("observation_id") or o.get("id") or f"OBS-{idx + 1}"
        o["observation_id"] = oid
        o["_data_class"] = DATA_OBSERVATION

        src = o.get("source_id")
        o["_source_id"] = src
        if src and src not in sources:
            warnings.append(f"observation {oid} references unknown source_id={src}")

        sta = o.get("station_id")
        o["_station_id"] = sta
        if sta and sta not in stations:
            issues.append(f"observation {oid} references unknown station_id={sta}")

        station = stations.get(sta, {}) if sta else {}

        ts = parse_dt(o.get("observation_time") or o.get("valid_time") or o.get("timestamp"))
        if ts is None:
            issues.append(f"observation {oid} missing/unparseable observation_time")
            add_flag(o, "missing_time")
        o["_observation_time"] = ts
        o["_valid_time"] = ts

        lat, lon, elev, acc, area = extract_coords(o)
        if lat is None and station:
            lat = station.get("_lat")
            lon = station.get("_lon")
            elev = station.get("_elevation_m")
            area = station.get("_area_id")

        o["_lat"] = lat
        o["_lon"] = lon
        o["_elevation_m"] = elev
        o["_accuracy_m"] = acc
        o["_area_id"] = area

        if lat is None and lon is None and not area:
            warnings.append(f"observation {oid} missing location")
            add_flag(o, "missing_location")

        normalize_numeric_record(o)
        assign_location(o, locations, settings["location_match_radius_km"])

        o["_source_ids"] = [x for x in ensure_list(o.get("source_id") or o.get("source_ids")) if x]
        o["_evidence_ids"] = [x for x in ensure_list(o.get("evidence_id") or o.get("evidence_ids")) if x]

        observations.append(o)

    if not observations:
        issues.append("No weather observations supplied")

    return observations, issues, warnings


def validate_forecasts(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    models: Dict[str, Dict[str, Any]],
    locations: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    forecasts: List[Dict[str, Any]] = []

    for idx, f in enumerate(case.get("forecasts") or []):
        if not isinstance(f, dict):
            issues.append(f"forecasts[{idx}] is not an object")
            continue

        fid = f.get("forecast_id") or f.get("id") or f"FCST-{idx + 1}"
        f["forecast_id"] = fid
        f["_data_class"] = DATA_FORECAST

        src = f.get("source_id")
        f["_source_id"] = src
        if src and src not in sources:
            warnings.append(f"forecast {fid} references unknown source_id={src}")

        mid = f.get("model_id")
        f["_model_id"] = mid
        if mid and mid not in models:
            warnings.append(f"forecast {fid} references unknown model_id={mid}")

        issue_time = parse_dt(f.get("issue_time") or f.get("issued_at"))
        valid_time = parse_dt(f.get("valid_time") or f.get("forecast_time"))

        f["_issue_time"] = issue_time
        f["_valid_time"] = valid_time

        if issue_time and valid_time and valid_time < issue_time:
            add_flag(f, "timing_conflict")
            warnings.append(f"forecast {fid} valid_time precedes issue_time")

        lead_h = None
        if issue_time and valid_time:
            lead_h = (valid_time - issue_time).total_seconds() / 3600.0
        f["_lead_hours"] = lead_h

        if lead_h is None:
            horizon = str(f.get("forecast_horizon", "UNKNOWN")).upper()
        elif lead_h <= 2:
            horizon = "NOWCAST"
        elif lead_h <= 12:
            horizon = "SHORT_RANGE"
        elif lead_h <= 72:
            horizon = "MEDIUM_RANGE"
        else:
            horizon = "EXTENDED_RANGE"

        if horizon not in ALLOWED_HORIZONS:
            horizon = "UNKNOWN"
        f["_horizon"] = horizon

        lat, lon, elev, acc, area = extract_coords(f)
        f["_lat"] = lat
        f["_lon"] = lon
        f["_elevation_m"] = elev
        f["_accuracy_m"] = acc
        f["_area_id"] = area

        normalize_numeric_record(f)
        assign_location(f, locations, settings["location_match_radius_km"])

        f["_ensemble_member"] = f.get("ensemble_member") or f.get("member_id")
        f["_source_ids"] = [x for x in ensure_list(f.get("source_id") or f.get("source_ids")) if x]
        f["_evidence_ids"] = [x for x in ensure_list(f.get("evidence_id") or f.get("evidence_ids")) if x]

        forecasts.append(f)

    return forecasts, issues, warnings


def validate_radar(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    locations: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    products: List[Dict[str, Any]] = []

    for idx, r in enumerate(case.get("radar_products") or []):
        if not isinstance(r, dict):
            issues.append(f"radar_products[{idx}] is not an object")
            continue

        pid = r.get("product_id") or r.get("id") or f"RADAR-{idx + 1}"
        r["product_id"] = pid
        r["_data_class"] = DATA_RADAR_DERIVED

        src = r.get("source_id")
        r["_source_id"] = src
        if src and src not in sources:
            warnings.append(f"radar {pid} references unknown source_id={src}")

        ts = parse_dt(r.get("valid_time") or r.get("timestamp"))
        if ts is None:
            issues.append(f"radar {pid} missing valid_time")
            add_flag(r, "missing_time")
        r["_valid_time"] = ts

        lat, lon, elev, acc, area = extract_coords(r)
        r["_lat"] = lat
        r["_lon"] = lon
        r["_area_id"] = area

        normalize_numeric_record(r)
        assign_location(r, locations, settings["location_match_radius_km"])

        r["_source_ids"] = [x for x in ensure_list(r.get("source_id") or r.get("source_ids")) if x]
        r["_evidence_ids"] = [x for x in ensure_list(r.get("evidence_id") or r.get("evidence_ids")) if x]

        products.append(r)

    return products, issues, warnings


def validate_satellite(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    locations: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    products: List[Dict[str, Any]] = []

    for idx, s in enumerate(case.get("satellite_products") or []):
        if not isinstance(s, dict):
            issues.append(f"satellite_products[{idx}] is not an object")
            continue

        pid = s.get("product_id") or s.get("id") or f"SAT-{idx + 1}"
        s["product_id"] = pid
        s["_data_class"] = DATA_SATELLITE_DERIVED

        src = s.get("source_id")
        s["_source_id"] = src
        if src and src not in sources:
            warnings.append(f"satellite {pid} references unknown source_id={src}")

        ts = parse_dt(s.get("valid_time") or s.get("timestamp"))
        if ts is None:
            issues.append(f"satellite {pid} missing valid_time")
            add_flag(s, "missing_time")
        s["_valid_time"] = ts

        lat, lon, elev, acc, area = extract_coords(s)
        s["_lat"] = lat
        s["_lon"] = lon
        s["_area_id"] = area

        normalize_numeric_record(s)
        assign_location(s, locations, settings["location_match_radius_km"])

        s["_source_ids"] = [x for x in ensure_list(s.get("source_id") or s.get("source_ids")) if x]
        s["_evidence_ids"] = [x for x in ensure_list(s.get("evidence_id") or s.get("evidence_ids")) if x]

        products.append(s)

    return products, issues, warnings


def validate_warnings(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    locations: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings_list: List[str] = []
    warnings: List[Dict[str, Any]] = []

    for idx, w in enumerate(case.get("warnings") or []):
        if not isinstance(w, dict):
            issues.append(f"warnings[{idx}] is not an object")
            continue

        wid = w.get("warning_id") or w.get("id") or f"WARN-{idx + 1}"
        w["warning_id"] = wid

        src = w.get("source_id")
        w["_source_id"] = src
        if src and src not in sources:
            warnings_list.append(f"warning {wid} references unknown source_id={src}")

        alert = str(w.get("alert_type") or w.get("warning_type") or "UNKNOWN").strip().upper()
        if alert not in ALLOWED_ALERT_TYPES:
            alert = "UNKNOWN"
        w["_alert_type"] = alert

        w["_issue_time"] = parse_dt(w.get("issue_time") or w.get("issued_at"))
        w["_expiry_time"] = parse_dt(w.get("expiry_time") or w.get("expires_at"))
        w["_effective_start"] = parse_dt(w.get("effective_start"))
        w["_effective_end"] = parse_dt(w.get("effective_end"))
        w["_event_type"] = str(w.get("event_type", "UNKNOWN")).upper()
        w["_status"] = str(w.get("status", "ACTIVE")).upper()
        w["_supersedes"] = w.get("supersedes")

        lat, lon, elev, acc, area = extract_coords(w)
        w["_lat"] = lat
        w["_lon"] = lon
        w["_area_id"] = area
        w["_radius_km"] = to_float(w.get("radius_km"))

        matched_locations: List[str] = []
        for loc in locations:
            lid = loc.get("location_id")
            if area and loc.get("_area_id") == area:
                matched_locations.append(lid)
                continue
            if lat is not None and lon is not None and w.get("_radius_km") is not None:
                d = haversine_km(lat, lon, loc.get("_lat"), loc.get("_lon"))
                if d is not None and d <= w["_radius_km"]:
                    matched_locations.append(lid)

        w["_matched_locations"] = matched_locations
        w["_source_ids"] = [x for x in ensure_list(w.get("source_id") or w.get("source_ids")) if x]
        w["_evidence_ids"] = [x for x in ensure_list(w.get("evidence_id") or w.get("evidence_ids")) if x]

        warnings.append(w)

    # Preserve warning version history; do not overwrite.
    warnings.sort(key=lambda x: x.get("_issue_time") or datetime.min.replace(tzinfo=timezone.utc))

    return warnings, issues, warnings_list


def validate_historical(
    case: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    locations: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    records: List[Dict[str, Any]] = []

    raw = (
        case.get("historical_weather")
        or case.get("reanalysis_context")
        or case.get("climate_normals")
        or []
    )

    for idx, h in enumerate(raw):
        if not isinstance(h, dict):
            issues.append(f"historical/reanalysis/climate records[{idx}] is not an object")
            continue

        rid = h.get("record_id") or h.get("id") or f"HIST-{idx + 1}"
        h["record_id"] = rid

        rtype = str(h.get("record_type", "HISTORICAL_OBSERVATION")).strip().upper()
        if rtype in {"REANALYSIS", "REANALYSIS_DERIVED"}:
            h["_data_class"] = DATA_REANALYSIS_DERIVED
        elif rtype in {"CLIMATE_NORMAL", "CLIMATOLOGY"}:
            h["_data_class"] = DATA_CLIMATE_NORMAL
        else:
            h["_data_class"] = DATA_HISTORICAL_OBSERVATION

        src = h.get("source_id")
        h["_source_id"] = src
        if src and src not in sources:
            warnings.append(f"historical record {rid} references unknown source_id={src}")

        h["_start_time"] = parse_dt(h.get("start_time") or h.get("valid_time"))
        h["_end_time"] = parse_dt(h.get("end_time"))

        lat, lon, elev, acc, area = extract_coords(h)
        h["_lat"] = lat
        h["_lon"] = lon
        h["_area_id"] = area

        normalize_numeric_record(h)
        assign_location(h, locations, settings["location_match_radius_km"])

        h["_source_ids"] = [x for x in ensure_list(h.get("source_id") or h.get("source_ids")) if x]
        h["_evidence_ids"] = [x for x in ensure_list(h.get("evidence_id") or h.get("evidence_ids")) if x]

        records.append(h)

    return records, issues, warnings


def validate_events(case: Dict[str, Any], locations: List[Dict[str, Any]], settings: Dict[str, float]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for idx, e in enumerate(case.get("event_context") or case.get("events") or []):
        if not isinstance(e, dict):
            continue

        eid = e.get("event_id") or e.get("id") or f"EVT-{idx + 1}"
        e["event_id"] = eid

        e["_event_time"] = parse_dt(e.get("event_time") or e.get("start_time") or e.get("timestamp"))
        e["_event_type"] = str(e.get("event_type", "UNKNOWN")).upper()

        lat, lon, elev, acc, area = extract_coords(e)
        e["_lat"] = lat
        e["_lon"] = lon
        e["_area_id"] = area

        assign_location(e, locations, settings["location_match_radius_km"])
        events.append(e)

    return events


# -----------------------------------------------------------------------------
# Source reliability / independence
# -----------------------------------------------------------------------------

def source_reliability_label(source: Dict[str, Any]) -> str:
    return str(source.get("_reliability") or source.get("reliability") or "UNKNOWN").upper()


def source_independence(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    if not a or not b:
        return "UNKNOWN"
    if a.get("source_id") == b.get("source_id"):
        return "DEPENDENT"

    shared_keys = [
        "upstream_model_id",
        "upstream_station_id",
        "upstream_radar_id",
        "upstream_satellite_product_id",
        "independence_group",
        "provider",
    ]

    for k in shared_keys:
        av = a.get(k)
        bv = b.get(k)
        if av is not None and bv is not None and av == bv:
            return "DEPENDENT"

    ag = a.get("_independence_group")
    bg = b.get("_independence_group")
    if ag and bg and ag == bg:
        return "DEPENDENT"

    if ag and bg and ag != bg:
        return "INDEPENDENT"

    return "UNKNOWN"


def summarize_source_independence(source_ids: List[str], sources: Dict[str, Dict[str, Any]]) -> str:
    ids = [s for s in source_ids if s]
    if len(ids) < 2:
        return "SINGLE_SOURCE"

    states: List[str] = []
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            states.append(source_independence(sources.get(ids[i], {}), sources.get(ids[j], {})))

    if all(s == "INDEPENDENT" for s in states):
        return "INDEPENDENT"
    if any(s == "DEPENDENT" for s in states):
        return "DEPENDENT_OR_UNKNOWN"
    if any(s == "PARTIALLY_DEPENDENT" for s in states):
        return "PARTIALLY_DEPENDENT"
    return "UNKNOWN"


def item_confidence(item: Dict[str, Any], sources: Dict[str, Dict[str, Any]]) -> str:
    flags = set(item.get("_quality_flags") or [])
    severe = bool(flags & SEVERE_QUALITY_FLAGS)

    src_ids = item.get("_source_ids") or ([item.get("_source_id")] if item.get("_source_id") else [])
    reliabilities = [source_reliability_label(sources.get(sid, {})) for sid in src_ids]

    if severe:
        return "LOW"

    if "HIGH" in reliabilities:
        if item.get("_data_class") in {DATA_RADAR_DERIVED, DATA_SATELLITE_DERIVED, DATA_REANALYSIS_DERIVED}:
            return "MODERATE"
        return "HIGH"
    if "MODERATE" in reliabilities:
        return "MODERATE"
    if reliabilities:
        return "LOW"
    return "UNKNOWN"


# -----------------------------------------------------------------------------
# Thresholds, verification, ensembles, consensus
# -----------------------------------------------------------------------------

def compare_operator(value: float, operator: str, threshold: float) -> Optional[bool]:
    op = str(operator or ">=").strip()
    if op in {">=", "ge", "greater_or_equal"}:
        return value >= threshold
    if op in {">", "gt", "greater"}:
        return value > threshold
    if op in {"<=", "le", "less_or_equal"}:
        return value <= threshold
    if op in {"<", "lt", "less"}:
        return value < threshold
    if op in {"==", "eq", "equal"}:
        return abs(value - threshold) <= 1e-9
    if op in {"!=", "ne", "not_equal"}:
        return abs(value - threshold) > 1e-9
    return None


def evaluate_thresholds(
    items: List[Dict[str, Any]],
    thresholds_raw: List[Any],
) -> List[Dict[str, Any]]:
    assessments: List[Dict[str, Any]] = []

    for idx, th in enumerate(thresholds_raw or []):
        if not isinstance(th, dict):
            continue

        tid = th.get("threshold_id") or f"TH-{idx + 1}"
        measurement_types = {normalize_measurement_type(x) for x in ensure_list(th.get("measurement_types") or th.get("measurement_type")) if x}
        quantity = str(th.get("quantity") or th.get("quantity_type") or "").strip().lower()
        unit = th.get("unit")
        value = th.get("value")
        operator = th.get("operator", ">=")

        th_norm = normalize_value_unit(value, None, unit, quantity)
        th_value = th_norm["normalized_value"]
        th_unit = th_norm["normalized_unit"]
        th_quantity = th_norm["quantity_type"]

        matching_items = []
        for it in items:
            if it.get("_value_norm") is None:
                continue
            if measurement_types and it.get("_measurement_type") not in measurement_types:
                continue
            if th_quantity and th_quantity != "other" and it.get("_quantity_type") != th_quantity:
                continue
            if th_unit and it.get("_unit_norm") != th_unit:
                continue
            matching_items.append(it)

        states: List[str] = []
        details: List[Dict[str, Any]] = []

        for it in matching_items:
            cmp = compare_operator(float(it["_value_norm"]), operator, float(th_value)) if th_value is not None else None
            if cmp is None:
                state = "UNKNOWN"
            elif cmp:
                dc = it.get("_data_class")
                if dc == DATA_OBSERVATION:
                    state = "OBSERVED_THRESHOLD_EXCEEDED"
                elif dc == DATA_FORECAST:
                    state = "FORECAST_THRESHOLD_INDICATED"
                elif dc in {DATA_RADAR_DERIVED, DATA_SATELLITE_DERIVED}:
                    state = "DERIVED_THRESHOLD_CANDIDATE"
                elif dc in {DATA_REANALYSIS_DERIVED, DATA_HISTORICAL_OBSERVATION}:
                    state = "HISTORICAL_THRESHOLD_OBSERVED"
                elif dc == DATA_CLIMATE_NORMAL:
                    state = "CLIMATE_THRESHOLD_CONTEXT"
                else:
                    state = "THRESHOLD_CANDIDATE"
            else:
                state = "BELOW_THRESHOLD"

            states.append(state)
            details.append(
                {
                    "item_id": it.get("observation_id") or it.get("forecast_id") or it.get("product_id") or it.get("record_id"),
                    "data_class": it.get("_data_class"),
                    "value": it.get("_value_norm"),
                    "unit": it.get("_unit_norm"),
                    "state": state,
                }
            )

        if not states:
            aggregate = "UNKNOWN_NO_MATCHING_DATA"
        elif "OBSERVED_THRESHOLD_EXCEEDED" in states:
            aggregate = "OBSERVED_THRESHOLD_EXCEEDED"
        elif "HISTORICAL_THRESHOLD_OBSERVED" in states:
            aggregate = "HISTORICAL_THRESHOLD_OBSERVED"
        elif "DERIVED_THRESHOLD_CANDIDATE" in states:
            aggregate = "DERIVED_THRESHOLD_CANDIDATE"
        elif "FORECAST_THRESHOLD_INDICATED" in states:
            aggregate = "FORECAST_THRESHOLD_INDICATED"
        elif all(s == "BELOW_THRESHOLD" for s in states):
            aggregate = "BELOW_THRESHOLD"
        else:
            aggregate = "UNKNOWN"

        assessments.append(
            {
                "threshold_id": tid,
                "description": th.get("description"),
                "measurement_types": sorted(measurement_types) if measurement_types else [],
                "quantity": th_quantity,
                "threshold_value": th_value,
                "threshold_unit": th_unit,
                "operator": operator,
                "state": aggregate,
                "matching_item_count": len(matching_items),
                "details": details[:50],
                "limitations": [
                    "Threshold state depends on supplied threshold definition and matching data.",
                    "Forecast or derived threshold indication is not observed confirmation.",
                ],
            }
        )

    return assessments


def forecast_verification(
    forecasts: List[Dict[str, Any]],
    observations: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    obs_by_key: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)

    for o in observations:
        if o.get("_value_norm") is None or o.get("_observation_time") is None:
            continue
        key = (
            str(o.get("_measurement_type")),
            str(o.get("_unit_norm")),
            location_key(o),
        )
        obs_by_key[key].append(o)

    for f in forecasts:
        if f.get("_value_norm") is None or f.get("_valid_time") is None:
            continue

        key = (
            str(f.get("_measurement_type")),
            str(f.get("_unit_norm")),
            location_key(f),
        )

        best_o = None
        best_dt = None
        for o in obs_by_key.get(key, []):
            dt = abs((o["_observation_time"] - f["_valid_time"]).total_seconds())
            if dt <= settings["forecast_match_window_s"]:
                if best_dt is None or dt < best_dt:
                    best_dt = dt
                    best_o = o

        if not best_o:
            continue

        err = float(f["_value_norm"]) - float(best_o["_value_norm"])
        abs_err = abs(err)

        unc_combined = None
        fu = f.get("_unc_norm")
        ou = best_o.get("_unc_norm")
        if fu is not None and ou is not None:
            unc_combined = math.sqrt(fu * fu + ou * ou)
        elif fu is not None:
            unc_combined = fu
        elif ou is not None:
            unc_combined = ou

        matches.append(
            {
                "forecast_id": f.get("forecast_id"),
                "observation_id": best_o.get("observation_id"),
                "model_id": f.get("_model_id"),
                "measurement_type": f.get("_measurement_type"),
                "unit": f.get("_unit_norm"),
                "forecast_value": f.get("_value_norm"),
                "observed_value": best_o.get("_value_norm"),
                "error": err,
                "absolute_error": abs_err,
                "time_difference_s": best_dt,
                "combined_uncertainty": unc_combined,
                "exceeds_uncertainty": (
                    unc_combined is not None and unc_combined > 0 and abs_err > settings["conflict_sigma"] * unc_combined
                ),
            }
        )

    stats: Dict[str, Any] = {}
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for m in matches:
        grouped[(str(m.get("model_id")), str(m.get("measurement_type")), str(m.get("unit")))].append(m)

    for (mid, mt, unit), items in grouped.items():
        errs = [x["error"] for x in items if x.get("error") is not None]
        abserrs = [x["absolute_error"] for x in items if x.get("absolute_error") is not None]
        if not errs:
            continue
        stats[f"{mid}|{mt}|{unit}"] = {
            "model_id": mid,
            "measurement_type": mt,
            "unit": unit,
            "sample_count": len(items),
            "mae": statistics.fmean(abserrs) if abserrs else None,
            "rmse": math.sqrt(statistics.fmean([e * e for e in errs])) if errs else None,
            "bias": statistics.fmean(errs) if errs else None,
            "limitation": "Verification is limited by supplied forecast/observation pairing and representativeness.",
        }

    return matches, stats


def ensemble_analysis(forecasts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)

    for f in forecasts:
        if f.get("_ensemble_member") is None or f.get("_value_norm") is None:
            continue
        key = (
            f.get("_model_id"),
            f.get("_measurement_type"),
            f.get("_unit_norm"),
            location_key(f),
            iso_or_none(f.get("_valid_time")),
        )
        groups[key].append(f)

    results: List[Dict[str, Any]] = []
    for idx, (key, items) in enumerate(groups.items(), 1):
        vals = [float(x["_value_norm"]) for x in items if x.get("_value_norm") is not None]
        if len(vals) < 2:
            continue

        results.append(
            {
                "ensemble_group_id": f"ENS-{idx}",
                "model_id": key[0],
                "measurement_type": key[1],
                "unit": key[2],
                "location_key": key[3],
                "valid_time": key[4],
                "member_count": len(vals),
                "min": min(vals),
                "max": max(vals),
                "mean": statistics.fmean(vals),
                "std": safe_std(vals),
                "range": max(vals) - min(vals),
                "limitation": "Low ensemble spread indicates model consistency, not correctness.",
            }
        )

    return results


def model_consensus(forecasts: List[Dict[str, Any]], models: Dict[str, Dict[str, Any]], sources: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    families = set()
    source_ids = set()

    for f in forecasts:
        mid = f.get("_model_id")
        model = models.get(mid, {})
        fam = model.get("_model_family") or model.get("model_family") or mid
        if fam:
            families.add(str(fam).upper())
        for sid in f.get("_source_ids") or []:
            source_ids.add(sid)

    return {
        "unique_model_families": sorted(families),
        "unique_forecast_sources": sorted(source_ids),
        "source_count": len(source_ids),
        "model_family_count": len(families),
        "dependency_note": (
            "Multiple sources/apps using the same upstream model family are not independent forecasts."
            if len(source_ids) > len(families)
            else "Supplied forecast sources appear to represent distinct model families, subject to source metadata."
        ),
    }


# -----------------------------------------------------------------------------
# Contradictions
# -----------------------------------------------------------------------------

def conflict_between(a: Dict[str, Any], b: Dict[str, Any], sigma: float) -> Tuple[bool, Optional[float], Optional[float]]:
    va = a.get("_value_norm")
    vb = b.get("_value_norm")
    if va is None or vb is None:
        return False, None, None

    diff = abs(float(va) - float(vb))
    ua = a.get("_unc_norm")
    ub = b.get("_unc_norm")

    if ua is not None and ub is not None:
        comb = math.sqrt(float(ua) * float(ua) + float(ub) * float(ub))
        if comb > 0:
            return diff > sigma * comb, diff, comb

    # No uncertainty: flag only large relative disagreement.
    scale = max(abs(float(va)), abs(float(vb)), 1e-9)
    return (diff / scale) > 0.5, diff, None


def detect_contradictions(
    observations: List[Dict[str, Any]],
    forecasts: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    verification_matches: List[Dict[str, Any]],
    settings: Dict[str, float],
    initial_contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    contradictions = list(initial_contradictions)

    # Observation vs observation conflicts.
    groups: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for o in observations:
        if o.get("_value_norm") is None:
            continue
        groups[(str(o.get("_measurement_type")), str(o.get("_unit_norm")), location_key(o))].append(o)

    for key, items in groups.items():
        items = sorted(items, key=lambda x: x.get("_observation_time") or datetime.min.replace(tzinfo=timezone.utc))
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                a, b = items[i], items[j]
                ta = a.get("_observation_time")
                tb = b.get("_observation_time")
                if ta and tb and abs((ta - tb).total_seconds()) > settings["observation_conflict_window_s"]:
                    continue
                conflict, diff, comb = conflict_between(a, b, settings["conflict_sigma"])
                if conflict:
                    contradictions.append(
                        {
                            "type": "observation_conflict",
                            "measurement_type": key[0],
                            "unit": key[1],
                            "location_key": key[2],
                            "observation_ids": [a.get("observation_id"), b.get("observation_id")],
                            "value_difference": diff,
                            "combined_uncertainty": comb,
                            "note": "Preserve conflict. Do not average incompatible observations into false precision.",
                        }
                    )

    # Derived vs ground precipitation disagreement.
    precip_obs = [o for o in observations if o.get("_quantity_type") == "precipitation" and o.get("_value_norm") is not None]
    derived_precip = [
        x
        for x in radar + satellite
        if x.get("_quantity_type") in {"precipitation", "precipitation_rate"} and x.get("_value_norm") is not None
    ]

    for d in derived_precip:
        for o in precip_obs:
            if location_key(d) != location_key(o):
                continue
            td = d.get("_valid_time")
            to = o.get("_observation_time")
            if td and to and abs((td - to).total_seconds()) > settings["derived_ground_match_window_s"]:
                continue

            dv = float(d["_value_norm"])
            ov = float(o["_value_norm"])

            if dv >= settings["derived_ground_disagreement_mm"] and ov <= 0.1:
                contradictions.append(
                    {
                        "type": "derived_vs_ground_precipitation_disagreement",
                        "derived_id": d.get("product_id"),
                        "observation_id": o.get("observation_id"),
                        "derived_value": dv,
                        "ground_value": ov,
                        "unit": d.get("_unit_norm"),
                        "note": "Radar/satellite estimate may be spatial, beam-height, attenuation, or retrieval affected. Ground gauge may have undercatch or local miss.",
                    }
                )

    # Forecast vs observation large error.
    for m in verification_matches:
        if m.get("exceeds_uncertainty") is True:
            contradictions.append(
                {
                    "type": "forecast_observation_disagreement",
                    "forecast_id": m.get("forecast_id"),
                    "observation_id": m.get("observation_id"),
                    "measurement_type": m.get("measurement_type"),
                    "error": m.get("error"),
                    "combined_uncertainty": m.get("combined_uncertainty"),
                    "note": "Forecast error may reflect model limitation, local variability, station representativeness, or timing mismatch.",
                }
            )

    # Warning without local observational support is not a contradiction, but preserve as verification gap.
    for w in warnings:
        if w.get("_alert_type") not in {"WARNING", "EMERGENCY"}:
            continue
        matched_locs = set(w.get("_matched_locations") or [])
        if not matched_locs:
            continue

        wt_start = w.get("_effective_start") or w.get("_issue_time")
        wt_end = w.get("_effective_end") or w.get("_expiry_time")

        supporting_obs = []
        for o in observations:
            if location_key(o) not in matched_locs:
                continue
            ot = o.get("_observation_time")
            if wt_start and wt_end and ot and not (wt_start <= ot <= wt_end):
                continue
            supporting_obs.append(o.get("observation_id"))

        if not supporting_obs:
            contradictions.append(
                {
                    "type": "warning_without_local_observation",
                    "warning_id": w.get("warning_id"),
                    "alert_type": w.get("_alert_type"),
                    "matched_locations": sorted(matched_locs),
                    "note": "Warning indicates authoritative risk assessment, not confirmed local observation. Absence of local observation may reflect coverage gap.",
                }
            )

    return contradictions


# -----------------------------------------------------------------------------
# Facts, hypotheses, dual review
# -----------------------------------------------------------------------------

def build_facts(
    locations: List[Dict[str, Any]],
    stations: Dict[str, Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    observations: List[Dict[str, Any]],
    forecasts: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    historical: List[Dict[str, Any]],
    threshold_assessments: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "Forecast is not observation.",
        "Warning is not confirmed local event.",
        "Model output is not sensor measurement.",
        "Station weather is not exact site weather.",
        "Grid cell is not point measurement.",
        "Radar reflectivity is not exact rainfall.",
        "Satellite cloud is not surface precipitation.",
        "Lightning is not severe thunderstorm damage.",
        "Velocity couplet is not confirmed tornado.",
        "Forecast cone is not impact area.",
        "Low ensemble spread is not certainty.",
        "Multiple apps using same model are not independent forecasts.",
        "Reanalysis is not direct observation.",
        "Land-surface temperature is not air temperature.",
        "Gust is not sustained wind.",
        "Snowfall is not snow depth.",
        "Rain rate is not accumulation.",
        "Weather correlation is not event causation.",
        "Regional weather is not microclimate condition.",
        "One extreme day is not climate trend.",
    ]

    loc_by_id = {l.get("location_id"): l for l in locations}

    def location_phrase(item: Dict[str, Any]) -> str:
        lid = item.get("_location_id")
        if lid and lid in loc_by_id:
            loc = loc_by_id[lid]
            return f"near target location {lid} ({loc.get('name') or loc.get('area_id') or 'unnamed'})"
        return f"at spatial cluster {location_key(item)}"

    def station_phrase(item: Dict[str, Any]) -> str:
        sid = item.get("_station_id")
        if not sid:
            return ""
        st = stations.get(sid, {})
        lid = item.get("_location_id")
        assess = (st.get("_target_assessments") or {}).get(lid, {})
        dist = assess.get("distance_km")
        rep = assess.get("representativeness")
        if dist is None:
            return f"station {sid}"
        return f"station {sid}, {dist:.1f} km away, representativeness {rep}"

    for o in observations:
        conf = item_confidence(o, sources)
        val = o.get("_value_norm")
        unit = o.get("_unit_norm")
        mt = o.get("_measurement_type")
        ts = iso_or_none(o.get("_observation_time"))
        src = o.get("_source_id") or (o.get("_source_ids") or ["UNKNOWN_SOURCE"])[0]

        if val is None:
            partial.append(
                {
                    "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
                    "statement": f"Source {src} supplied no numeric value for {mt} at {ts}.",
                    "observation_id": o.get("observation_id"),
                    "confidence": "UNKNOWN",
                    "limitation": "Missing value is not zero.",
                }
            )
            continue

        stmt = (
            f"{station_phrase(o) or 'Source ' + str(src)} observed {mt}={val} {unit} "
            f"{location_phrase(o)} at {ts}."
        )

        item = {
            "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": stmt,
            "observation_id": o.get("observation_id"),
            "confidence": conf,
            "quality_flags": o.get("_quality_flags"),
            "limitation": "Observation is site-specific to the sensor/station, not automatically exact target-site weather.",
        }

        if conf == "HIGH":
            supported.append(item)
        elif conf == "MODERATE":
            candidates.append(item)
        else:
            partial.append(item)

    for f in forecasts:
        conf = item_confidence(f, sources)
        val = f.get("_value_norm")
        unit = f.get("_unit_norm")
        mt = f.get("_measurement_type")
        vt = iso_or_none(f.get("_valid_time"))
        it = iso_or_none(f.get("_issue_time"))
        mid = f.get("_model_id") or "UNKNOWN_MODEL"

        if val is None:
            continue

        candidates.append(
            {
                "fact_id": f"FCT-FCST-{len(candidates) + 1}",
                "statement": f"Model {mid} forecast {mt}={val} {unit} {location_phrase(f)} valid {vt}, issued {it}.",
                "forecast_id": f.get("forecast_id"),
                "confidence": conf,
                "limitation": "Forecast is not observation.",
            }
        )

    for r in radar + satellite:
        conf = item_confidence(r, sources)
        val = r.get("_value_norm")
        unit = r.get("_unit_norm")
        mt = r.get("_measurement_type")
        vt = iso_or_none(r.get("_valid_time"))
        kind = "Radar" if r.get("_data_class") == DATA_RADAR_DERIVED else "Satellite"

        if val is None:
            continue

        candidates.append(
            {
                "fact_id": f"FCT-DERIVED-{len(candidates) + 1}",
                "statement": f"{kind} product {r.get('product_id')} derived {mt}={val} {unit} {location_phrase(r)} at {vt}.",
                "product_id": r.get("product_id"),
                "confidence": conf,
                "limitation": f"{kind}-derived value is not a ground measurement.",
            }
        )

    for w in warnings:
        src = w.get("_source_id") or (w.get("_source_ids") or ["UNKNOWN_AUTHORITY"])[0]
        rel = source_reliability_label(sources.get(src, {}))
        stmt = (
            f"Authority/source {src} issued {w.get('_alert_type')} for {w.get('_event_type')} "
            f"covering locations {', '.join(w.get('_matched_locations') or []) or 'unspecified'} "
            f"issue={iso_or_none(w.get('_issue_time'))} effective={iso_or_none(w.get('_effective_start'))} to {iso_or_none(w.get('_effective_end'))}."
        )
        item = {
            "fact_id": f"FCT-WARN-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": stmt,
            "warning_id": w.get("warning_id"),
            "confidence": "HIGH" if rel == "HIGH" else "MODERATE" if rel == "MODERATE" else "LOW",
            "limitation": "Warning is an authoritative risk assessment, not confirmed local occurrence at every point.",
        }
        if item["confidence"] == "HIGH":
            supported.append(item)
        else:
            candidates.append(item)

    for th in threshold_assessments:
        if th.get("state") == "OBSERVED_THRESHOLD_EXCEEDED":
            supported.append(
                {
                    "fact_id": f"FCT-TH-{len(supported) + 1}",
                    "statement": f"Threshold {th.get('threshold_id')} was exceeded by at least one observation: {th.get('state')}.",
                    "threshold_id": th.get("threshold_id"),
                    "confidence": "MODERATE",
                    "limitation": "Threshold applicability depends on supplied definition and station representativeness.",
                }
            )
        elif th.get("state") in {"DERIVED_THRESHOLD_CANDIDATE", "FORECAST_THRESHOLD_INDICATED", "HISTORICAL_THRESHOLD_OBSERVED"}:
            candidates.append(
                {
                    "fact_id": f"FCT-TH-{len(candidates) + 1}",
                    "statement": f"Threshold {th.get('threshold_id')} state is {th.get('state')}.",
                    "threshold_id": th.get("threshold_id"),
                    "confidence": "LOW",
                    "limitation": "Non-observation threshold state is not confirmed local weather.",
                }
            )

    for h in historical:
        candidates.append(
            {
                "fact_id": f"FCT-HIST-{len(candidates) + 1}",
                "statement": f"Historical/reanalysis/climate record {h.get('record_id')} reports {h.get('_measurement_type')}={h.get('_value_norm')} {h.get('_unit_norm')} for {location_phrase(h)}.",
                "record_id": h.get("record_id"),
                "confidence": item_confidence(h, sources),
                "limitation": "Reanalysis and climate normals are derived/statistical context, not direct point observation.",
            }
        )

    for c in contradictions:
        disputed.append(
            {
                "disputed_id": f"DIS-{len(disputed) + 1}",
                "type": c.get("type"),
                "statement": "Material weather contradiction or disagreement present; do not silently resolve.",
                "details": c,
            }
        )

    return supported, candidates, partial, disputed, not_facts


def build_hypotheses(
    events: List[Dict[str, Any]],
    observations: List[Dict[str, Any]],
    forecasts: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    threshold_assessments: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    def near_event(item: Dict[str, Any], event: Dict[str, Any], window_s: float, radius_km: float) -> bool:
        it = item_time(item)
        et = event.get("_event_time")
        if it and et and abs((it - et).total_seconds()) > window_s:
            return False

        iloc = location_key(item)
        elic = location_key(event)
        if iloc == elic:
            return True

        d = haversine_km(item.get("_lat"), item.get("_lon"), event.get("_lat"), event.get("_lon"))
        return d is not None and d <= radius_km

    for idx, ev in enumerate(events, 1):
        eid = ev.get("event_id")
        etype = ev.get("_event_type")

        nearby_obs = [o for o in observations if near_event(o, ev, 3 * 3600, 25)]
        nearby_derived = [x for x in radar + satellite if near_event(x, ev, 3 * 3600, 25)]
        nearby_forecasts = [f for f in forecasts if near_event(f, ev, 6 * 3600, 50)]
        nearby_warnings = [w for w in warnings if near_event(w, ev, 6 * 3600, 50)]
        nearby_thresholds = [t for t in threshold_assessments if t.get("state") in {"OBSERVED_THRESHOLD_EXCEEDED", "DERIVED_THRESHOLD_CANDIDATE", "FORECAST_THRESHOLD_INDICATED"}]

        base = {
            "hypothesis_set_id": f"HSET-EVT-{idx}",
            "event_id": eid,
            "event_type": etype,
        }

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-WEATHER_CONTRIBUTED_POSSIBLE",
                "statement": "Weather may have contributed to the event context.",
                "support": [
                    f"{len(nearby_obs)} nearby observations." if nearby_obs else "No nearby observations.",
                    f"{len(nearby_derived)} nearby radar/satellite-derived products." if nearby_derived else "No nearby derived products.",
                    f"{len(nearby_warnings)} nearby warnings/advisories." if nearby_warnings else "No nearby warnings.",
                    f"{len(nearby_thresholds)} threshold indications." if nearby_thresholds else "No threshold indications.",
                ],
                "opposition": [
                    "Contradictions present." if contradictions else "No contradictions recorded.",
                    "Station representativeness may be low." if any((o.get("_quality_flags") or []) for o in nearby_obs) else "No severe observation quality flags recorded.",
                ],
                "unknowns": ["exact causal mechanism", "local microclimate", "terrain/hydrology", "human/operational factors"],
                "falsification_conditions": [
                    "Independent local observations show no relevant weather at event time/place.",
                    "Radar/satellite artifacts explain derived signal.",
                    "Event evidence shows cause independent of weather.",
                ],
                "restriction": "Weather correlation is not causation.",
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-WEATHER_PRESENT_NOT_CAUSAL",
                "statement": "Weather was present but may not have caused or materially affected the event.",
                "support": ["Nearby weather evidence exists." if nearby_obs or nearby_derived else "No nearby weather evidence."],
                "opposition": ["No event-specific weather linkage recorded." if not nearby_thresholds and not nearby_warnings else "Threshold/warning context present."],
                "unknowns": ["event mechanism", "exposure", "threshold sensitivity"],
                "falsification_conditions": ["Engineering/operational evidence shows weather-independent cause."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-LOCALIZED_WEATHER_MISSED_BY_STATION",
                "statement": "Localized weather may have occurred at the event site but was missed or underrepresented by nearest station.",
                "support": [
                    "Convective/localized event type." if etype in {"THUNDERSTORM", "FLOOD", "FLASH_FLOOD", "HAIL", "TORNADO", "DOWNBURST"} else "Not explicitly localized event type.",
                    "Station distance/representativeness limitations." if nearby_obs else "No station observations.",
                ],
                "opposition": ["Dense independent local observations." if len({o.get('_station_id') for o in nearby_obs if o.get('_station_id')}) >= 3 else "No dense local station network recorded."],
                "unknowns": ["microclimate", "radar beam height", "gauge undercatch", "terrain"],
                "falsification_conditions": ["Independent local sensor/video/incident evidence confirms no localized weather."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-RADAR_SATELLITE_ARTIFACT",
                "statement": "Radar/satellite-derived weather signal may be artifact, non-meteorological echo, beam effect, or retrieval error.",
                "support": ["Derived products present." if nearby_derived else "No derived products."],
                "opposition": ["Ground observations corroborate." if nearby_obs else "No ground corroboration recorded."],
                "unknowns": ["radar calibration", "attenuation", "bright band", "ground clutter", "satellite retrieval"],
                "falsification_conditions": ["Ground station/gauge/video confirms physical weather."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-FORECAST_MODEL_ERROR",
                "statement": "Forecast/model disagreement may reflect model error, resolution limits, or ensemble uncertainty.",
                "support": ["Forecasts present." if nearby_forecasts else "No forecasts."],
                "opposition": ["Observations confirm forecast." if nearby_obs and not contradictions else "No observational confirmation recorded."],
                "unknowns": ["model bias", "initial conditions", "convection parameterization"],
                "falsification_conditions": ["Verification against independent observations shows forecast skill for this variable/location/time."],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-SENSOR_OR_REPORT_ERROR",
                "statement": "Observation or report may be affected by sensor error, unit error, timestamp error, or low-quality source.",
                "support": ["Quality flags present." if any((o.get('_quality_flags') or []) for o in nearby_obs) else "No quality flags recorded."],
                "opposition": ["Multiple independent calibrated sources agree." if len({o.get('_source_id') for o in nearby_obs}) >= 2 and not contradictions else "No strong independence recorded."],
                "unknowns": ["sensor calibration", "siting", "maintenance", "metadata integrity"],
                "falsification_conditions": ["Nearby authoritative station/radar/gauge reproduces measurement."],
            }
        )

    if not events:
        for idx, th in enumerate(threshold_assessments, 1):
            if th.get("state") in {"OBSERVED_THRESHOLD_EXCEEDED", "DERIVED_THRESHOLD_CANDIDATE", "FORECAST_THRESHOLD_INDICATED"}:
                hypotheses.append(
                    {
                        "hypothesis_set_id": f"HSET-TH-{idx}",
                        "hypothesis_id": f"HTH-{idx}-REAL_LOCAL_WEATHER",
                        "statement": f"Threshold {th.get('threshold_id')} may reflect real local weather.",
                        "support": [f"State={th.get('state')}"],
                        "opposition": ["Contradictions present." if contradictions else "No contradictions recorded."],
                        "falsification_conditions": ["Independent local observation excludes threshold exceedance."],
                    }
                )
                hypotheses.append(
                    {
                        "hypothesis_set_id": f"HSET-TH-{idx}",
                        "hypothesis_id": f"HTH-{idx}-REPRESENTATIVENESS_OR_ARTIFACT",
                        "statement": f"Threshold {th.get('threshold_id')} may reflect station unrepresentativeness, sensor artifact, or derived-product error.",
                        "support": ["Derived/forecast state." if th.get("state") != "OBSERVED_THRESHOLD_EXCEEDED" else "Observation state."],
                        "opposition": ["Multiple independent ground observations." if th.get("state") == "OBSERVED_THRESHOLD_EXCEEDED" else "No independent ground confirmation recorded."],
                        "falsification_conditions": ["Nearby authoritative observations confirm or exclude threshold."],
                    }
                )

    if issues:
        hypotheses.append(
            {
                "hypothesis_set_id": "HSET-GLOBAL",
                "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
                "statement": "Validation issues materially weaken all weather interpretations.",
                "support": issues[:10],
                "opposition": ["No independent clean source supplied yet."],
                "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
            }
        )

    return hypotheses


def dual_ai_review(
    observations: List[Dict[str, Any]],
    forecasts: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary Weather Analyst",
        "assessment": (
            "Weather observations, forecasts, derived products, and/or warnings exist."
            if observations or forecasts or radar or satellite or warnings
            else "No usable weather records were supplied."
        ),
        "classification": "Exact-site and causal conclusions remain conservative and evidence-bounded.",
    }

    if not observations and not forecasts and not radar and not satellite and not warnings:
        skeptic = {
            "role": "Independent Meteorological Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No deterministic weather records were supplied. Do not infer weather from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Meteorological Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Meteorological Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions must be preserved; do not silently average conflicting sources.",
        }
    elif observations and any(item.get("_data_class") == DATA_OBSERVATION for item in observations):
        skeptic = {
            "role": "Independent Meteorological Skeptic",
            "verdict": "AGREE_ON_OBSERVED_WEATHER_ONLY",
            "reason": "Observations may support station/region weather assessment only, not exact-site or causal conclusions without further evidence.",
        }
    else:
        skeptic = {
            "role": "Independent Meteorological Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Forecast/derived/warning evidence supports candidate context only.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not meteorological corroboration. Human/official authority review required for consequential safety decisions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    locations: List[Dict[str, Any]],
    stations: Dict[str, Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    observations: List[Dict[str, Any]],
    forecasts: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    historical: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
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

    for loc in locations:
        add_node(loc.get("location_id"), "Location", public_dict(loc))

    for sid, s in sources.items():
        add_node(sid, "Source", public_dict(s))

    for sid, st in stations.items():
        add_node(sid, "Station", public_dict(st))
        if st.get("_source_id"):
            add_edge(sid, st["_source_id"], "MEASURED_BY", {"station_id": sid})

    for o in observations:
        oid = o.get("observation_id")
        add_node(
            oid,
            "WeatherObservation",
            {
                "station_id": o.get("_station_id"),
                "source_id": o.get("_source_id"),
                "measurement_type": o.get("_measurement_type"),
                "value": o.get("_value_norm"),
                "unit": o.get("_unit_norm"),
                "observation_time": iso_or_none(o.get("_observation_time")),
                "location_id": o.get("_location_id"),
                "spatial_cluster_id": o.get("_spatial_cluster_id"),
                "quality_flags": o.get("_quality_flags"),
            },
        )
        if o.get("_station_id"):
            add_edge(oid, o["_station_id"], "OBSERVED_AT", {"observation_id": oid})
        if o.get("_source_id"):
            add_edge(oid, o["_source_id"], "SUPPORTED_BY", {"observation_id": oid})
        if o.get("_location_id"):
            add_edge(oid, o["_location_id"], "OBSERVED_AT", {"observation_id": oid})

    for f in forecasts:
        fid = f.get("forecast_id")
        add_node(
            fid,
            "Forecast",
            {
                "model_id": f.get("_model_id"),
                "source_id": f.get("_source_id"),
                "measurement_type": f.get("_measurement_type"),
                "value": f.get("_value_norm"),
                "unit": f.get("_unit_norm"),
                "issue_time": iso_or_none(f.get("_issue_time")),
                "valid_time": iso_or_none(f.get("_valid_time")),
                "horizon": f.get("_horizon"),
                "location_id": f.get("_location_id"),
                "spatial_cluster_id": f.get("_spatial_cluster_id"),
            },
        )
        if f.get("_model_id"):
            add_node(f["_model_id"], "WeatherModel", {"model_id": f.get("_model_id")})
            add_edge(fid, f["_model_id"], "DERIVED_FROM", {"forecast_id": fid})
        if f.get("_source_id"):
            add_edge(fid, f["_source_id"], "SUPPORTED_BY", {"forecast_id": fid})

    for r in radar:
        rid = r.get("product_id")
        add_node(rid, "RadarProduct", public_dict(r))
        if r.get("_source_id"):
            add_edge(rid, r["_source_id"], "SUPPORTED_BY", {"product_id": rid})

    for s in satellite:
        sid = s.get("product_id")
        add_node(sid, "SatelliteProduct", public_dict(s))
        if s.get("_source_id"):
            add_edge(sid, s["_source_id"], "SUPPORTED_BY", {"product_id": sid})

    for w in warnings:
        wid = w.get("warning_id")
        add_node(wid, "Warning", public_dict(w))
        if w.get("_source_id"):
            add_edge(wid, w["_source_id"], "ISSUED_BY", {"warning_id": wid})
        for lid in w.get("_matched_locations") or []:
            add_edge(wid, lid, "VALID_FOR", {"warning_id": wid})

    for h in historical:
        hid = h.get("record_id")
        add_node(hid, "HistoricalWeatherRecord", public_dict(h))

    for e in events:
        eid = e.get("event_id")
        add_node(eid, "EnvironmentalEvent" if "FLOOD" in str(e.get("_event_type")) or "WILDFIRE" in str(e.get("_event_type")) else "WeatherEvent", public_dict(e))

    for fac in facts:
        fid = fac.get("fact_id")
        add_node(fid, "Fact", fac)
        for key in ("observation_id", "forecast_id", "product_id", "warning_id", "record_id", "threshold_id"):
            if fac.get(key):
                add_edge(fid, fac[key], "SUPPORTED_BY", {"fact_id": fid})

    for h in hypotheses:
        add_node(h.get("hypothesis_id"), "Hypothesis", h)

    for c in contradictions:
        cid = f"CONTRA-{len([x for x in nodes if x.get('type') == 'Contradiction']) + 1}"
        add_node(cid, "Contradiction", c)

    for g in gaps:
        gid = g.get("gap_id") or f"GAP-{len(gaps)}"
        add_node(gid, "Gap", g)

    return {"nodes": nodes, "edges": edges, "version": VERSION}


# -----------------------------------------------------------------------------
# Gaps, actions, handoffs, summary
# -----------------------------------------------------------------------------

def build_knowledge_gaps(
    locations: List[Dict[str, Any]],
    stations: Dict[str, Dict[str, Any]],
    observations: List[Dict[str, Any]],
    forecasts: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    historical: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not locations:
        gaps.append(
            {
                "gap_id": "GAP-LOCATION-UNRESOLVED",
                "gap": "No target location supplied",
                "importance": "HIGH",
                "recommended_source": "Coordinates, place name, station ID, or area polygon",
                "expected_information_value": "Enables spatial representativeness assessment",
            }
        )

    if not observations:
        gaps.append(
            {
                "gap_id": "GAP-NO-OBSERVATIONS",
                "gap": "No weather observations supplied",
                "importance": "HIGH",
                "recommended_source": "Official station/METAR/SPECI/gauge records",
                "expected_information_value": "Establishes measured weather",
            }
        )

    if not radar:
        gaps.append(
            {
                "gap_id": "GAP-RADAR-UNAVAILABLE",
                "gap": "No meteorological radar products supplied",
                "importance": "MODERATE",
                "recommended_source": "Authorized/public radar archive",
                "expected_information_value": "Improves precipitation/storm spatial context",
            }
        )

    if not satellite:
        gaps.append(
            {
                "gap_id": "GAP-SATELLITE-UNAVAILABLE",
                "gap": "No weather satellite products supplied",
                "importance": "MODERATE",
                "recommended_source": "Authorized/public satellite imagery/products",
                "expected_information_value": "Improves cloud/storm/regional context",
            }
        )

    if not forecasts:
        gaps.append(
            {
                "gap_id": "GAP-FORECAST-UNAVAILABLE",
                "gap": "No forecast/model records supplied",
                "importance": "MODERATE",
                "recommended_source": "Authoritative forecast, deterministic model, or ensemble archive",
                "expected_information_value": "Supports forecast verification and uncertainty analysis",
            }
        )

    if not warnings:
        gaps.append(
            {
                "gap_id": "GAP-WARNING-UNAVAILABLE",
                "gap": "No official warning/advisory records supplied",
                "importance": "MODERATE",
                "recommended_source": "Official meteorological/emergency warning archive",
                "expected_information_value": "Supports severe-weather context without fabricating alerts",
            }
        )

    if not historical:
        gaps.append(
            {
                "gap_id": "GAP-HISTORICAL-CONTEXT-MISSING",
                "gap": "No historical/reanalysis/climate context supplied",
                "importance": "LOW",
                "recommended_source": "Station archives, reanalysis, climate normals",
                "expected_information_value": "Supports anomaly context",
            }
        )

    # Station representativeness gaps.
    for loc in locations:
        lid = loc.get("location_id")
        nearby = []
        for st in stations.values():
            assess = (st.get("_target_assessments") or {}).get(lid, {})
            dist = assess.get("distance_km")
            rep = assess.get("representativeness")
            if dist is not None and rep in {"LOW", "UNKNOWN"}:
                nearby.append((st.get("station_id"), dist, rep))

        if not any((st.get("_target_assessments") or {}).get(lid, {}).get("representativeness") in {"HIGH", "MODERATE"} for st in stations.values()):
            gaps.append(
                {
                    "gap_id": f"GAP-STATION-REPRESENTATIVENESS-{lid}",
                    "gap": f"No high/moderate representativeness station identified for location {lid}",
                    "importance": "HIGH",
                    "recommended_source": "Nearest official station, gauge, airport observation, or local sensor",
                    "expected_information_value": "Reduces false exact-site weather claims",
                    "details": [{"station_id": s, "distance_km": d, "representativeness": r} for s, d, r in nearby[:10]],
                }
            )

    if contradictions:
        gaps.append(
            {
                "gap_id": "GAP-CONTRADICTIONS",
                "gap": "Material weather contradictions/disagreements present",
                "importance": "HIGH",
                "recommended_source": "Raw source records, station metadata, radar/satellite product metadata, warning version history",
                "expected_information_value": "Prevents silent false resolution",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Input validation issues present",
                "importance": "HIGH",
                "recommended_source": "Corrected source metadata, units, timestamps, coordinates",
                "expected_information_value": "Improves measurement trust",
            }
        )

    return gaps


def build_next_actions(
    locations: List[Dict[str, Any]],
    observations: List[Dict[str, Any]],
    forecasts: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not locations:
        actions.append("Supply target coordinates, station ID, area polygon, or unambiguous location reference")

    if not observations:
        actions.append("Supply deterministic official/public station observations with time, location, units, and quality flags")

    if any(g["gap_id"].startswith("GAP-STATION-REPRESENTATIVENESS") for g in gaps):
        actions.append("Retrieve nearest official station/gauge and report distance/elevation difference")

    if not radar:
        actions.append("Retrieve meteorological radar archive if precipitation/storm context is needed")

    if not satellite:
        actions.append("Retrieve weather satellite products if cloud/regional storm context is needed")

    if not forecasts:
        actions.append("Retrieve authoritative forecast/model/ensemble records if forecast context is needed")

    if not warnings:
        actions.append("Retrieve official warning/archive records if severe-weather context is needed")

    if contradictions:
        actions.append("Preserve contradictions and compare raw source metadata before resolving disagreements")

    if any("FLOOD" in str(g.get("gap_id", "")).upper() for g in gaps) or any("FLOOD" in str(o.get("_measurement_type", "")).upper() for o in observations):
        actions.append("Handoff hydrology/soil/terrain/drainage questions to ENVINT/GEOINT; precipitation alone is insufficient for flood causation")

    actions.append("Maintain safety boundary: official meteorological, aviation, maritime, and emergency authorities govern consequential decisions")
    actions.append("Do not use weather intelligence for targeting, attack timing, concealment, evasion, smuggling, or harmful operational optimization")

    return actions


def build_specialist_handoffs(
    observations: List[Dict[str, Any]],
    radar: List[Dict[str, Any]],
    satellite: List[Dict[str, Any]],
    warnings: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if satellite:
        handoffs.append(
            {
                "to": "SATINT",
                "reason": "Satellite product interpretation and sensor/product provenance may require specialist review",
                "restrictions": ["Satellite-derived value is not ground measurement"],
            }
        )

    if radar:
        handoffs.append(
            {
                "to": "RADINT / meteorological radar specialist",
                "reason": "Radar artifact, beam height, attenuation, velocity, and dual-pol interpretation may require specialist review",
                "restrictions": ["Weather radar only; no military/surveillance radar targeting"],
            }
        )

    if any("FLOOD" in str(e.get("_event_type", "")).upper() for e in events) or any(o.get("_measurement_type") in {"precipitation", "rainfall"} for o in observations):
        handoffs.append(
            {
                "to": "ENVINT",
                "reason": "Hydrology, soil moisture, drainage, river state, and environmental impact exceed weather observation alone",
                "restrictions": ["Precipitation alone is not flood causation"],
            }
        )

    if events:
        handoffs.append(
            {
                "to": "GEOINT",
                "reason": "Terrain, elevation, land use, and spatial context may affect microclimate and event correlation",
                "restrictions": ["No targeting coordinates", "No harmful operational planning"],
            }
        )
        handoffs.append(
            {
                "to": "EVENTINT / TRANSPORTINT / INCIDENTINT as appropriate",
                "reason": "Event causation and operational impact require non-weather evidence",
                "restrictions": ["Weather correlation is not causation"],
            }
        )

    if warnings:
        handoffs.append(
            {
                "to": "official meteorological / emergency authority",
                "reason": "Life-safety warning interpretation and action remain with authoritative services",
                "restrictions": ["WEATHERINT does not override official warnings"],
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

    obs = r.get("weather_observations") or []
    fcst = r.get("forecasts") or []
    radar = r.get("radar_products") or []
    sat = r.get("satellite_products") or []
    warn = r.get("warnings") or []
    thresholds = r.get("threshold_assessments") or []
    gaps = r.get("knowledge_gaps") or []

    lines = [
        "LOCATION: " + fmt_list([l.get("location_id") for l in (r.get("locations") or [])]),
        "TIME RANGE: " + str(r.get("time_range")),
        "DATA COVERAGE: observations=" + str(len(obs)) + " forecasts=" + str(len(fcst)) + " radar=" + str(len(radar)) + " satellite=" + str(len(sat)) + " warnings=" + str(len(warn)),
        "OBSERVED WEATHER: " + fmt_list([f"{o.get('observation_id')}:{o.get('measurement_type')}={o.get('value')} {o.get('unit')}" for o in obs[:10]]),
        "FORECAST WEATHER: " + fmt_list([f"{f.get('forecast_id')}:{f.get('measurement_type')}={f.get('value')} {f.get('unit')} valid={f.get('valid_time')}" for f in fcst[:10]]),
        "TEMPERATURE: " + json.dumps(r.get("temperature") or {}, default=str),
        "PRECIPITATION: " + json.dumps(r.get("precipitation") or {}, default=str),
        "WIND / GUSTS: " + json.dumps(r.get("wind") or {}, default=str),
        "HUMIDITY / DEW POINT: " + json.dumps(r.get("humidity") or {}, default=str),
        "PRESSURE: " + json.dumps(r.get("pressure") or {}, default=str),
        "VISIBILITY: " + json.dumps(r.get("visibility") or {}, default=str),
        "CLOUD / CEILING: " + json.dumps(r.get("cloud") or {}, default=str),
        "STORMS / LIGHTNING: " + json.dumps(r.get("storm_lightning_context") or {}, default=str),
        "SEVERE WEATHER: " + fmt_list([t.get("state") for t in thresholds if "THRESHOLD" in str(t.get("state"))]),
        "WARNINGS: " + fmt_list([f"{w.get('warning_id')}:{w.get('alert_type')}:{w.get('event_type')}" for w in warn[:10]]),
        "RADAR CONTEXT: " + str(len(radar)),
        "SATELLITE CONTEXT: " + str(len(sat)),
        "MODEL CONSENSUS: " + json.dumps(r.get("forecast_consensus") or {}, default=str),
        "ENSEMBLE UNCERTAINTY: " + fmt_list([f"{e.get('ensemble_group_id')} std={e.get('std')}" for e in (r.get("ensemble_runs") or [])[:5]]),
        "HISTORICAL CONTEXT: " + str(len(r.get("historical_weather") or [])),
        "MICROCLIMATE / REPRESENTATIVENESS: " + fmt_list([f"{sid}:{list((st.get('_target_assessments') or {}).values())[0].get('representativeness') if st.get('_target_assessments') else 'UNKNOWN'}" for sid, st in (r.get("stations") or {}).items()][:10]),
        "SOURCE RELIABILITY: " + fmt_list([f"{s.get('source_id')}={s.get('reliability')}" for s in (r.get("source_reliability") or [])]),
        "SOURCE INDEPENDENCE: " + str(r.get("source_independence")),
        "CONTRADICTIONS: " + str(len(r.get("contradictions") or [])),
        "EVENT CORRELATION: " + fmt_list([f"{e.get('event_id')}:{e.get('weather_correlation_state')}" for e in (r.get("event_correlations") or [])]),
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

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    settings = {
        "location_match_radius_km": setting_float("location_match_radius_km", 25.0),
        "forecast_match_window_s": setting_float("forecast_match_window_s", 3 * 3600),
        "observation_conflict_window_s": setting_float("observation_conflict_window_s", 3600),
        "derived_ground_match_window_s": setting_float("derived_ground_match_window_s", 3 * 3600),
        "conflict_sigma": setting_float("conflict_sigma", 3.0),
        "derived_ground_disagreement_mm": setting_float("derived_ground_disagreement_mm", 1.0),
    }

    locations, loc_issues = validate_locations(case)
    sources, src_issues = validate_sources(case)
    stations, sta_issues, sta_warnings = validate_stations(case, locations, sources)
    models, model_issues = validate_models(case)

    observations, obs_issues, obs_warnings = validate_observations(case, sources, stations, locations, settings)
    forecasts, fcst_issues, fcst_warnings = validate_forecasts(case, sources, models, locations, settings)
    radar, radar_issues, radar_warnings = validate_radar(case, sources, locations, settings)
    satellite, sat_issues, sat_warnings = validate_satellite(case, sources, locations, settings)
    warnings, warn_issues, warn_warnings = validate_warnings(case, sources, locations, settings)
    historical, hist_issues, hist_warnings = validate_historical(case, sources, locations, settings)
    events = validate_events(case, locations, settings)

    issues = (
        loc_issues
        + src_issues
        + sta_issues
        + model_issues
        + obs_issues
        + fcst_issues
        + radar_issues
        + sat_issues
        + warn_issues
        + hist_issues
    )
    warnings_list = sta_warnings + obs_warnings + fcst_warnings + radar_warnings + sat_warnings + warn_warnings + hist_warnings

    all_numeric_items = observations + forecasts + radar + satellite + historical
    threshold_assessments = evaluate_thresholds(all_numeric_items, settings_raw.get("thresholds") or [])

    verification_matches, verification_stats = forecast_verification(forecasts, observations, settings)
    ensembles = ensemble_analysis(forecasts)
    consensus = model_consensus(forecasts, models, sources)

    contradictions = detect_contradictions(
        observations,
        forecasts,
        radar,
        satellite,
        warnings,
        verification_matches,
        settings,
        list(case.get("existing_contradictions") or []),
    )

    supported_facts, candidate_facts, partial_facts, disputed_facts, not_facts = build_facts(
        locations,
        stations,
        sources,
        observations,
        forecasts,
        radar,
        satellite,
        warnings,
        historical,
        threshold_assessments,
        contradictions,
    )

    hypotheses = build_hypotheses(
        events,
        observations,
        forecasts,
        radar,
        satellite,
        warnings,
        threshold_assessments,
        contradictions,
        issues,
    )

    dual = dual_ai_review(
        observations,
        forecasts,
        radar,
        satellite,
        warnings,
        contradictions,
        issues,
    )

    gaps = build_knowledge_gaps(
        locations,
        stations,
        observations,
        forecasts,
        radar,
        satellite,
        warnings,
        historical,
        contradictions,
        issues,
    )

    next_actions = build_next_actions(
        locations,
        observations,
        forecasts,
        radar,
        satellite,
        warnings,
        gaps,
        contradictions,
    )

    handoffs = build_specialist_handoffs(
        observations,
        radar,
        satellite,
        warnings,
        events,
    )

    # Event correlations.
    event_correlations: List[Dict[str, Any]] = []
    for ev in events:
        nearby_obs = [
            o
            for o in observations
            if (
                location_key(o) == location_key(ev)
                or haversine_km(o.get("_lat"), o.get("_lon"), ev.get("_lat"), ev.get("_lon")) is not None
                and haversine_km(o.get("_lat"), o.get("_lon"), ev.get("_lat"), ev.get("_lon")) <= 25.0
            )
        ]
        nearby_derived = [
            x
            for x in radar + satellite
            if (
                location_key(x) == location_key(ev)
                or haversine_km(x.get("_lat"), x.get("_lon"), ev.get("_lat"), ev.get("_lon")) is not None
                and haversine_km(x.get("_lat"), x.get("_lon"), ev.get("_lat"), ev.get("_lon")) <= 25.0
            )
        ]
        nearby_warnings = [
            w
            for w in warnings
            if location_key(w) == location_key(ev) or ev.get("_location_id") in set(w.get("_matched_locations") or [])
        ]
        nearby_thresholds = [t for t in threshold_assessments if t.get("state") in {"OBSERVED_THRESHOLD_EXCEEDED", "DERIVED_THRESHOLD_CANDIDATE", "FORECAST_THRESHOLD_INDICATED"}]

        if nearby_obs and nearby_thresholds and not contradictions:
            state = "WEATHER_CONTRIBUTED_POSSIBLE"
        elif nearby_obs or nearby_derived:
            state = "WEATHER_PRESENT"
        elif nearby_warnings:
            state = "WEATHER_WARNING_CONTEXT_PRESENT"
        else:
            state = "NO_WEATHER_LINK_FOUND"

        event_correlations.append(
            {
                "event_id": ev.get("event_id"),
                "event_type": ev.get("_event_type"),
                "event_time": iso_or_none(ev.get("_event_time")),
                "location_id": ev.get("_location_id"),
                "spatial_cluster_id": ev.get("_spatial_cluster_id"),
                "nearby_observation_ids": [o.get("observation_id") for o in nearby_obs[:20]],
                "nearby_derived_product_ids": [x.get("product_id") for x in nearby_derived[:20]],
                "nearby_warning_ids": [w.get("warning_id") for w in nearby_warnings[:20]],
                "threshold_states": [t.get("state") for t in nearby_thresholds[:20]],
                "weather_correlation_state": state,
                "limitations": [
                    "Weather correlation is not causation.",
                    "Station/derived representativeness and timing uncertainty apply.",
                ],
            }
        )

    # Variable summaries.
    def summarize_variable(items: List[Dict[str, Any]], quantity: str) -> Dict[str, Any]:
        selected = [x for x in items if x.get("_quantity_type") == quantity and x.get("_value_norm") is not None]
        by_loc: Dict[str, List[float]] = defaultdict(list)
        for x in selected:
            by_loc[location_key(x)].append(float(x["_value_norm"]))

        return {
            "overall": numeric_summary([x.get("_value_norm") for x in selected]),
            "by_location": {k: numeric_summary(v) for k, v in by_loc.items()},
            "item_count": len(selected),
            "limitation": "Summary is limited to supplied records and does not imply exact-site measurement.",
        }

    temperature = summarize_variable(all_numeric_items, "temperature")
    precipitation = summarize_variable(all_numeric_items, "precipitation")
    precipitation_rate = summarize_variable(all_numeric_items, "precipitation_rate")
    wind = summarize_variable(all_numeric_items, "wind_speed")
    pressure = summarize_variable(all_numeric_items, "pressure")
    visibility = summarize_variable(all_numeric_items, "length")
    humidity = {
        "note": "Relative humidity/dew point/specific humidity should be preserved separately by measurement_type.",
        "by_measurement_type": {
            mt: numeric_summary([x.get("_value_norm") for x in all_numeric_items if x.get("_measurement_type") == mt])
            for mt in sorted({x.get("_measurement_type") for x in all_numeric_items if "humidity" in str(x.get("_measurement_type")) or "dew" in str(x.get("_measurement_type"))})
        },
    }
    cloud = {
        "fraction_summary": summarize_variable(all_numeric_items, "fraction"),
        "ceiling_summary": summarize_variable(all_numeric_items, "length"),
    }
    storm_lightning_context = {
        "lightning_count_summary": summarize_variable(all_numeric_items, "count"),
        "warning_event_types": sorted({w.get("_event_type") for w in warnings if w.get("_event_type")}),
        "radar_product_count": len(radar),
        "satellite_product_count": len(satellite),
        "limitation": "Lightning, radar structure, and warnings are context; they do not alone confirm tornado/hail/damage.",
    }

    # Public objects.
    observation_public = []
    for o in observations:
        observation_public.append(
            {
                "observation_id": o.get("observation_id"),
                "source_id": o.get("_source_id"),
                "station_id": o.get("_station_id"),
                "measurement_type": o.get("_measurement_type"),
                "quantity_type": o.get("_quantity_type"),
                "original_value": o.get("_original_value"),
                "original_unit": o.get("_original_unit"),
                "value": o.get("_value_norm"),
                "unit": o.get("_unit_norm"),
                "uncertainty": o.get("_unc_norm"),
                "observation_time": iso_or_none(o.get("_observation_time")),
                "location": {
                    "latitude": o.get("_lat"),
                    "longitude": o.get("_lon"),
                    "elevation_m": o.get("_elevation_m"),
                    "area_id": o.get("_area_id"),
                    "location_id": o.get("_location_id"),
                    "spatial_cluster_id": o.get("_spatial_cluster_id"),
                    "target_distance_km": o.get("_target_distance_km"),
                },
                "quality_flags": o.get("_quality_flags"),
                "confidence": item_confidence(o, sources),
                "source_ids": o.get("_source_ids"),
                "evidence_ids": o.get("_evidence_ids"),
                "limitations": [
                    "Station observation is not automatically exact target-site weather.",
                    "Missing value is not zero.",
                ],
            }
        )

    forecast_public = []
    for f in forecasts:
        forecast_public.append(
            {
                "forecast_id": f.get("forecast_id"),
                "source_id": f.get("_source_id"),
                "model_id": f.get("_model_id"),
                "measurement_type": f.get("_measurement_type"),
                "quantity_type": f.get("_quantity_type"),
                "original_value": f.get("_original_value"),
                "original_unit": f.get("_original_unit"),
                "value": f.get("_value_norm"),
                "unit": f.get("_unit_norm"),
                "uncertainty": f.get("_unc_norm"),
                "issue_time": iso_or_none(f.get("_issue_time")),
                "valid_time": iso_or_none(f.get("_valid_time")),
                "lead_hours": f.get("_lead_hours"),
                "horizon": f.get("_horizon"),
                "ensemble_member": f.get("_ensemble_member"),
                "location": {
                    "latitude": f.get("_lat"),
                    "longitude": f.get("_lon"),
                    "area_id": f.get("_area_id"),
                    "location_id": f.get("_location_id"),
                    "spatial_cluster_id": f.get("_spatial_cluster_id"),
                },
                "quality_flags": f.get("_quality_flags"),
                "confidence": item_confidence(f, sources),
                "limitations": ["Forecast is not observation."],
            }
        )

    radar_public = [
        {
            "product_id": r.get("product_id"),
            "source_id": r.get("_source_id"),
            "measurement_type": r.get("_measurement_type"),
            "value": r.get("_value_norm"),
            "unit": r.get("_unit_norm"),
            "uncertainty": r.get("_unc_norm"),
            "valid_time": iso_or_none(r.get("_valid_time")),
            "location_id": r.get("_location_id"),
            "spatial_cluster_id": r.get("_spatial_cluster_id"),
            "quality_flags": r.get("_quality_flags"),
            "confidence": item_confidence(r, sources),
            "limitations": ["Radar-derived estimate is not ground measurement."],
        }
        for r in radar
    ]

    satellite_public = [
        {
            "product_id": s.get("product_id"),
            "source_id": s.get("_source_id"),
            "measurement_type": s.get("_measurement_type"),
            "value": s.get("_value_norm"),
            "unit": s.get("_unit_norm"),
            "uncertainty": s.get("_unc_norm"),
            "valid_time": iso_or_none(s.get("_valid_time")),
            "location_id": s.get("_location_id"),
            "spatial_cluster_id": s.get("_spatial_cluster_id"),
            "quality_flags": s.get("_quality_flags"),
            "confidence": item_confidence(s, sources),
            "limitations": ["Satellite-derived product is not ground measurement."],
        }
        for s in satellite
    ]

    warning_public = [
        {
            "warning_id": w.get("warning_id"),
            "source_id": w.get("_source_id"),
            "alert_type": w.get("_alert_type"),
            "event_type": w.get("_event_type"),
            "status": w.get("_status"),
            "issue_time": iso_or_none(w.get("_issue_time")),
            "expiry_time": iso_or_none(w.get("_expiry_time")),
            "effective_start": iso_or_none(w.get("_effective_start")),
            "effective_end": iso_or_none(w.get("_effective_end")),
            "matched_locations": w.get("_matched_locations"),
            "supersedes": w.get("_supersedes"),
            "limitations": ["Warning is not confirmed local occurrence."],
        }
        for w in warnings
    ]

    historical_public = [
        {
            "record_id": h.get("record_id"),
            "data_class": h.get("_data_class"),
            "measurement_type": h.get("_measurement_type"),
            "value": h.get("_value_norm"),
            "unit": h.get("_unit_norm"),
            "start_time": iso_or_none(h.get("_start_time")),
            "end_time": iso_or_none(h.get("_end_time")),
            "location_id": h.get("_location_id"),
            "spatial_cluster_id": h.get("_spatial_cluster_id"),
            "limitations": [
                "Reanalysis is derived.",
                "Climate normals are statistical context.",
                "Historical observation may have station representativeness limits.",
            ],
        }
        for h in historical
    ]

    source_reliability = [
        {
            "source_id": s.get("source_id"),
            "provider": s.get("provider"),
            "source_type": s.get("_source_type"),
            "reliability": s.get("_reliability"),
            "independence_group": s.get("_independence_group"),
            "upstream_model_id": s.get("upstream_model_id"),
            "upstream_station_id": s.get("upstream_station_id"),
            "upstream_radar_id": s.get("upstream_radar_id"),
            "upstream_satellite_product_id": s.get("upstream_satellite_product_id"),
            "limitations": s.get("limitations"),
        }
        for s in sources.values()
    ]

    all_source_ids = sorted(
        {
            sid
            for item in all_numeric_items + warnings
            for sid in (item.get("_source_ids") or ([item.get("_source_id")] if item.get("_source_id") else []))
            if sid
        }
    )

    source_independence = summarize_source_independence(all_source_ids, sources)

    unknowns: List[str] = []
    if not locations:
        unknowns.append("Target location unresolved")
    if not observations:
        unknowns.append("Observed weather unresolved")
    if not radar:
        unknowns.append("Radar context unavailable")
    if not satellite:
        unknowns.append("Satellite context unavailable")
    if not forecasts:
        unknowns.append("Forecast context unavailable")
    if not warnings:
        unknowns.append("Official warning context unavailable")
    if contradictions:
        unknowns.append("Source disagreements unresolved")
    unknowns.append("Exact-site microclimate unresolved unless local evidence supports it")
    unknowns.append("Weather causation unresolved by design")

    time_values = [
        item_time(x)
        for x in all_numeric_items + warnings + events
        if item_time(x) is not None
    ]
    time_range = {
        "start": iso_or_none(min(time_values)) if time_values else None,
        "end": iso_or_none(max(time_values)) if time_values else None,
    }

    if contradictions:
        status = "SOURCE_CONFLICT"
    elif issues:
        status = "PARTIAL"
    elif not observations and not forecasts and not radar and not satellite and not warnings:
        status = "INCONCLUSIVE"
    elif supported_facts and not issues and not contradictions:
        status = "SUCCEEDED"
    else:
        status = "PARTIAL"

    graph = build_graph(
        locations,
        stations,
        sources,
        observations,
        forecasts,
        radar,
        satellite,
        warnings,
        historical,
        events,
        supported_facts + candidate_facts + partial_facts,
        hypotheses,
        contradictions,
        gaps,
    )

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "locations": [public_dict(l) for l in locations],
        "coordinates": {
            l.get("location_id"): {
                "latitude": l.get("_lat"),
                "longitude": l.get("_lon"),
                "elevation_m": l.get("_elevation_m"),
                "accuracy_m": l.get("_accuracy_m"),
                "area_id": l.get("_area_id"),
            }
            for l in locations
        },
        "time_range": time_range,
        "timezone": case.get("timezone"),
        "source_ids": sorted(sources.keys()),
        "evidence_ids": sorted(
            {
                eid
                for item in all_numeric_items + warnings
                for eid in (item.get("_evidence_ids") or [])
                if eid
            }
        ),
        "stations": {sid: public_dict(st) for sid, st in stations.items()},
        "station_distances": {
            sid: st.get("_target_assessments")
            for sid, st in stations.items()
        },
        "station_representativeness": {
            sid: {
                lid: assess.get("representativeness")
                for lid, assess in (st.get("_target_assessments") or {}).items()
            }
            for sid, st in stations.items()
        },
        "weather_observations": observation_public,
        "forecasts": forecast_public,
        "model_runs": [public_dict(m) for m in models.values()],
        "ensemble_runs": ensembles,
        "radar_products": radar_public,
        "satellite_products": satellite_public,
        "warnings": warning_public,
        "temperature": temperature,
        "apparent_temperature": {
            "note": "Apparent temperature/heat index/wind chill are derived values and require formula/input preservation.",
            "records": [x for x in all_numeric_items if "apparent" in str(x.get("_measurement_type")) or "heat_index" in str(x.get("_measurement_type")) or "wind_chill" in str(x.get("_measurement_type"))],
        },
        "dew_point": {x.get("_measurement_type"): numeric_summary([x.get("_value_norm") for x in all_numeric_items if x.get("_measurement_type") == x.get("_measurement_type") and "dew" in str(x.get("_measurement_type"))]) for x in all_numeric_items if "dew" in str(x.get("_measurement_type"))},
        "humidity": humidity,
        "pressure": pressure,
        "wind": wind,
        "gusts": {
            "note": "Gust and sustained wind are kept separate by measurement_type.",
            "gust_summary": numeric_summary([x.get("_value_norm") for x in all_numeric_items if "gust" in str(x.get("_measurement_type"))]),
        },
        "precipitation": precipitation,
        "rainfall_accumulation": precipitation,
        "precipitation_rate": precipitation_rate,
        "snowfall": {x.get("measurement_type"): x for x in all_numeric_items if "snow" in str(x.get("_measurement_type"))},
        "snow_depth": {x.get("product_id") or x.get("observation_id"): x.get("_value_norm") for x in all_numeric_items if "snow_depth" in str(x.get("_measurement_type"))},
        "hail_context": {
            "states": ["HAIL_INDICATED", "HAIL_REPORTED", "HAIL_CONFIRMED_BY_MULTIPLE_SOURCES"],
            "records": [x for x in all_numeric_items + warnings if "hail" in str(x.get("_measurement_type", "")) or "hail" in str(x.get("_event_type", ""))],
            "limitation": "Radar indication is not confirmed hail without ground/report evidence.",
        },
        "visibility": visibility,
        "fog": [x for x in all_numeric_items + warnings if "fog" in str(x.get("_measurement_type", "")) or "fog" in str(x.get("_event_type", ""))],
        "cloud_cover": cloud,
        "cloud_ceiling": cloud,
        "lightning": storm_lightning_context,
        "thunderstorm_context": [w for w in warnings if "THUNDERSTORM" in str(w.get("_event_type", "")).upper()],
        "cyclone_context": [w for w in warnings if any(k in str(w.get("_event_type", "")).upper() for k in ["CYCLONE", "HURRICANE", "TYPHOON", "TROPICAL"])],
        "tornado_context": [w for w in warnings if "TORNADO" in str(w.get("_event_type", "")).upper()],
        "heat_context": [x for x in threshold_assessments if "heat" in str(x.get("description", "")).lower() or "temperature" in str(x.get("measurement_types", []))],
        "cold_context": [x for x in threshold_assessments if "cold" in str(x.get("description", "")).lower() or "freeze" in str(x.get("description", "")).lower()],
        "marine_weather": [x for x in all_numeric_items if "wave" in str(x.get("_measurement_type")) or "sea" in str(x.get("_measurement_type"))],
        "aviation_weather": [x for x in all_numeric_items if x.get("_station_id") and stations.get(x.get("_station_id"), {}).get("_station_type") in {"AIRPORT", "METAR", "AVIATION"}],
        "mountain_weather": {
            "note": "Terrain/elevation-aware analysis requires GEOINT/elevation data.",
            "elevation_differences": {
                sid: {
                    lid: assess.get("elevation_difference_m")
                    for lid, assess in (st.get("_target_assessments") or {}).items()
                }
                for sid, st in stations.items()
            },
        },
        "urban_weather": {
            "note": "Urban heat island/building effects require local land-use/sensor siting context.",
            "stations_with_urban_risk": [sid for sid, st in stations.items() if st.get("urban_risk") is True],
        },
        "historical_weather": historical_public,
        "reanalysis_context": [h for h in historical_public if h.get("data_class") == DATA_REANALYSIS_DERIVED],
        "climate_normals": [h for h in historical_public if h.get("data_class") == DATA_CLIMATE_NORMAL],
        "weather_anomalies": {
            "note": "Anomaly claims require explicit climatological baseline, location, season, variable, and period.",
            "threshold_assessments": threshold_assessments,
        },
        "forecast_consensus": consensus,
        "forecast_disagreement": verification_stats,
        "forecast_verification_matches": verification_matches,
        "threshold_assessments": threshold_assessments,
        "uncertainty": {
            "measurement_uncertainty": numeric_summary([x.get("_unc_norm") for x in all_numeric_items]),
            "spatial_uncertainty": {
                "location_match_radius_km": settings["location_match_radius_km"],
                "station_distances": {sid: st.get("_target_assessments") for sid, st in stations.items()},
            },
            "temporal_uncertainty": {
                "forecast_match_window_s": settings["forecast_match_window_s"],
                "observation_conflict_window_s": settings["observation_conflict_window_s"],
            },
            "model_uncertainty": {
                "ensemble_groups": len(ensembles),
                "consensus": consensus,
            },
            "source_uncertainty": source_independence,
            "classification_uncertainty": "Threshold/severe states depend on supplied definitions and source quality.",
        },
        "event_correlations": event_correlations,
        "timeline_updates": sorted(
            [
                {
                    "kind": "observation",
                    "id": o.get("observation_id"),
                    "time": iso_or_none(o.get("_observation_time")),
                    "measurement_type": o.get("_measurement_type"),
                }
                for o in observations
            ]
            + [
                {
                    "kind": "forecast",
                    "id": f.get("forecast_id"),
                    "time": iso_or_none(f.get("_valid_time")),
                    "issue_time": iso_or_none(f.get("_issue_time")),
                    "measurement_type": f.get("_measurement_type"),
                }
                for f in forecasts
            ]
            + [
                {
                    "kind": "radar",
                    "id": r.get("product_id"),
                    "time": iso_or_none(r.get("_valid_time")),
                    "measurement_type": r.get("_measurement_type"),
                }
                for r in radar
            ]
            + [
                {
                    "kind": "satellite",
                    "id": s.get("product_id"),
                    "time": iso_or_none(s.get("_valid_time")),
                    "measurement_type": s.get("_measurement_type"),
                }
                for s in satellite
            ]
            + [
                {
                    "kind": "warning",
                    "id": w.get("warning_id"),
                    "time": iso_or_none(w.get("_issue_time")),
                    "alert_type": w.get("_alert_type"),
                }
                for w in warnings
            ]
            + [
                {
                    "kind": "event",
                    "id": e.get("event_id"),
                    "time": iso_or_none(e.get("_event_time")),
                    "event_type": e.get("_event_type"),
                }
                for e in events
            ],
            key=lambda x: x.get("time") or "",
        ),
        "observations": observation_public,
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "source_reliability": source_reliability,
        "source_bias": case.get("source_bias") or [
            "Station siting, elevation, urbanization, and coastal effects can bias representativeness.",
            "Radar beam height, attenuation, ground clutter, and bright-band effects can bias precipitation estimates.",
            "Satellite retrievals depend on sensor, angle, cloud, surface, and day/night conditions.",
            "Models have resolution and parameterization biases.",
            "Commercial apps may reuse the same upstream model.",
        ],
        "source_limitations": case.get("source_limitations") or [
            "Missing data is not zero.",
            "Non-detection is not absence.",
            "Forecast is not observation.",
            "Warning is not confirmed local event.",
            "Derived products are not ground measurements.",
        ],
        "source_pedigree": case.get("source_pedigree") or [
            {
                "source_id": s.get("source_id"),
                "provider": s.get("provider"),
                "source_type": s.get("_source_type"),
                "upstream_model_id": s.get("upstream_model_id"),
                "upstream_station_id": s.get("upstream_station_id"),
                "upstream_radar_id": s.get("upstream_radar_id"),
                "upstream_satellite_product_id": s.get("upstream_satellite_product_id"),
                "independence_group": s.get("_independence_group"),
            }
            for s in sources.values()
        ],
        "source_independence": source_independence,
        "contradictions": contradictions,
        "hypotheses": hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.get("hypothesis_id"),
                "status": "WEAKENED_BY_CONTRADICTIONS" if contradictions else "NOT_FALSIFIED_WITH_CURRENT_EVIDENCE",
                "required_additional_evidence": [
                    "Nearest official station/gauge",
                    "Radar archive",
                    "Satellite product",
                    "Official warning archive",
                    "Independent local observation/video/incident record",
                    "Terrain/elevation context",
                ],
            }
            for h in hypotheses
        ],
        "safety_flags": [
            "NO_TARGETING",
            "NO_ATTACK_TIMING",
            "NO_CONCEALMENT_PLANNING",
            "NO_EVASION_PLANNING",
            "NO_SMUGGLING_OPTIMIZATION",
            "NO_OVERRIDE_EMERGENCY_AUTHORITIES",
            "NO_OVERRIDE_AVIAATION_AUTHORITIES",
            "NO_OVERRIDE_MARITIME_AUTHORITIES",
            "NO_FABRICATED_WARNINGS",
            "NO_FABRICATED_OBSERVATIONS",
            "OFFICIAL_AUTHORITIES_GOVERN_SAFETY_DECISIONS",
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not fetch live weather data.",
            "It consumes deterministic weather records only.",
            "It does not invent observations, forecasts, radar/satellite products, warnings, or events.",
            "It separates observation, forecast, warning, radar-derived, satellite-derived, reanalysis, and climate context.",
            "It does not treat station weather as exact-site weather.",
            "It does not treat weather correlation as causation.",
            "It does not provide targeting, attack timing, concealment, evasion, smuggling, or harmful operational optimization.",
        ],
        "dual_ai_review": dual,
        "not_facts": not_facts,
        "graphical_memory": graph,
        "validation_issues": issues,
        "validation_warnings": warnings_list,
        "analysis_settings": settings,
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
            "deterministic_operations": [
                "coordinate validation",
                "timestamp normalization",
                "unit normalization",
                "station distance/elevation representativeness",
                "location assignment",
                "threshold evaluation",
                "forecast-observation verification",
                "ensemble spread calculation",
                "model family consensus",
                "source independence grouping",
                "contradiction detection",
                "fact gate",
            ],
            "note": "Replay requires raw source records, station metadata, coordinates, elevation, units, quality flags, model versions, run times, ensemble members, radar/satellite product metadata, warning version history, and source pedigree.",
        },
    }

    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": "Placeholders only. Replace with deterministic authorized/public weather records. Do not treat this template as real measurement.",
        "case_id": "CASE-WEATHERINT-EXAMPLE",
        "task_id": "TASK-WEATHERINT-EXAMPLE",
        "objective": "Authorized historical/weather-context analysis for safety and event correlation, not targeting or evasion.",
        "questions": [
            "What weather was observed near the location/time?",
            "What was forecast versus observed?",
            "Do radar/satellite products support localized precipitation?",
            "What source disagreements or uncertainties remain?",
            "What is unresolved?",
        ],
        "scope": {
            "authorized_only": True,
            "defensive_only": True,
            "safety_aware": True,
            "no_targeting": True,
            "no_attack_timing": True,
            "no_concealment": True,
            "no_evasion": True,
            "no_smuggling_optimization": True,
            "no_override_official_authorities": True,
        },
        "authorization": {
            "lawful_basis": "PUBLIC_OR_AUTHORIZED_WEATHER_RESEARCH",
            "purpose": "SAFETY_AWARE_WEATHER_CONTEXT_AND_EVENT_CORRELATION",
            "approval_reference": "AUTH-WEATHERINT-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "locations": [
            {
                "location_id": "LOC-SITE-A",
                "name": "Example Site A",
                "latitude": 0.0,
                "longitude": 0.0,
                "elevation_m": 120,
                "area_id": "REGION_A",
                "timezone": "UTC",
            }
        ],
        "time_range": {
            "start_time": "2026-10-08T09:00:00Z",
            "end_time": "2026-10-08T15:00:00Z",
        },
        "analysis_settings": {
            "location_match_radius_km": 25,
            "forecast_match_window_s": 10800,
            "observation_conflict_window_s": 3600,
            "derived_ground_match_window_s": 10800,
            "conflict_sigma": 3,
            "derived_ground_disagreement_mm": 1.0,
            "thresholds": [
                {
                    "threshold_id": "TH-HEAVY-RAIN-1H",
                    "description": "Heavy rainfall candidate over approximately 1 hour",
                    "measurement_types": ["precipitation", "rainfall", "precipitation_accumulation"],
                    "quantity": "precipitation",
                    "unit": "mm",
                    "operator": ">=",
                    "value": 10,
                },
                {
                    "threshold_id": "TH-HIGH-WIND",
                    "description": "High sustained wind candidate",
                    "measurement_types": ["wind_speed", "sustained_wind"],
                    "quantity": "wind_speed",
                    "unit": "m/s",
                    "operator": ">=",
                    "value": 17,
                },
                {
                    "threshold_id": "TH-LOW-VISIBILITY",
                    "description": "Low visibility candidate",
                    "measurement_types": ["visibility"],
                    "quantity": "length",
                    "unit": "m",
                    "operator": "<=",
                    "value": 1000,
                },
            ],
        },
        "sources": [
            {
                "source_id": "SRC-NMS",
                "provider": "EXAMPLE_NATIONAL_MET_SERVICE",
                "source_type": "NATIONAL_MET_SERVICE",
                "reliability": "HIGH",
                "independence_group": "NMS_A",
                "limitations": ["Station representativeness depends on distance/elevation/terrain."],
            },
            {
                "source_id": "SRC-RADAR",
                "provider": "EXAMPLE_WEATHER_RADAR_NETWORK",
                "source_type": "WEATHER_RADAR",
                "reliability": "HIGH",
                "independence_group": "RADAR_A",
                "upstream_radar_id": "RADAR-STATION-1",
                "limitations": ["Radar estimates are derived and affected by beam height/attenuation/clutter."],
            },
            {
                "source_id": "SRC-SAT",
                "provider": "EXAMPLE_SATELLITE_PRODUCT_PROVIDER",
                "source_type": "METEOROLOGICAL_SATELLITE",
                "reliability": "MODERATE",
                "independence_group": "SAT_B",
                "upstream_satellite_product_id": "SAT-PRODUCT-1",
                "limitations": ["Satellite products are remote-sensing derived, not ground measurements."],
            },
            {
                "source_id": "SRC-MODEL",
                "provider": "EXAMPLE_WEATHER_MODEL_CENTER",
                "source_type": "WEATHER_MODEL",
                "reliability": "MODERATE",
                "independence_group": "MODEL_FAMILY_A",
                "upstream_model_id": "MODEL_FAMILY_A",
                "limitations": ["Model output is simulation, not measurement."],
            },
        ],
        "stations": [
            {
                "station_id": "STA-1",
                "station_type": "OFFICIAL",
                "source_id": "SRC-NMS",
                "latitude": 0.02,
                "longitude": 0.01,
                "elevation_m": 100,
                "terrain_microclimate_risk": "LOW",
                "urban_risk": False,
            }
        ],
        "models": [
            {
                "model_id": "MODEL-1",
                "model_name": "EXAMPLE_NWP",
                "model_version": "v1",
                "run_time": "2026-10-08T00:00:00Z",
                "horizontal_resolution_m": 3000,
                "ensemble_or_deterministic": "DETERMINISTIC",
                "model_family": "MODEL_FAMILY_A",
            }
        ],
        "weather_observations": [
            {
                "observation_id": "OBS-1",
                "source_id": "SRC-NMS",
                "station_id": "STA-1",
                "observation_time": "2026-10-08T12:00:00Z",
                "measurement_type": "temperature",
                "value": 28.0,
                "unit": "C",
                "uncertainty": 0.5,
                "quality_flags": [],
                "evidence_id": "EVD-OBS-1",
            },
            {
                "observation_id": "OBS-2",
                "source_id": "SRC-NMS",
                "station_id": "STA-1",
                "observation_time": "2026-10-08T12:00:00Z",
                "measurement_type": "wind_speed",
                "value": 18.0,
                "unit": "m/s",
                "uncertainty": 1.0,
                "quality_flags": [],
                "evidence_id": "EVD-OBS-2",
            },
            {
                "observation_id": "OBS-3",
                "source_id": "SRC-NMS",
                "station_id": "STA-1",
                "observation_time": "2026-10-08T13:00:00Z",
                "measurement_type": "precipitation",
                "value": 4.0,
                "unit": "mm",
                "uncertainty": 0.5,
                "quality_flags": [],
                "evidence_id": "EVD-OBS-3",
            },
        ],
        "forecasts": [
            {
                "forecast_id": "FCST-1",
                "source_id": "SRC-MODEL",
                "model_id": "MODEL-1",
                "issue_time": "2026-10-08T00:00:00Z",
                "valid_time": "2026-10-08T13:00:00Z",
                "location": {"latitude": 0.0, "longitude": 0.0, "area_id": "REGION_A"},
                "measurement_type": "precipitation",
                "value": 12.0,
                "unit": "mm",
                "uncertainty": 3.0,
                "evidence_id": "EVD-FCST-1",
            }
        ],
        "radar_products": [
            {
                "product_id": "RADAR-1",
                "source_id": "SRC-RADAR",
                "valid_time": "2026-10-08T12:30:00Z",
                "location": {"latitude": 0.01, "longitude": 0.005, "area_id": "REGION_A"},
                "measurement_type": "precipitation",
                "value": 14.0,
                "unit": "mm",
                "uncertainty": 4.0,
                "quality_flags": [],
                "evidence_id": "EVD-RADAR-1",
            }
        ],
        "satellite_products": [
            {
                "product_id": "SAT-1",
                "source_id": "SRC-SAT",
                "valid_time": "2026-10-08T12:15:00Z",
                "location": {"latitude": 0.0, "longitude": 0.0, "area_id": "REGION_A"},
                "measurement_type": "cloud_top_temperature",
                "value": 210.0,
                "unit": "K",
                "uncertainty": 3.0,
                "quality_flags": [],
                "evidence_id": "EVD-SAT-1",
            }
        ],
        "warnings": [
            {
                "warning_id": "WARN-1",
                "source_id": "SRC-NMS",
                "alert_type": "WARNING",
                "event_type": "THUNDERSTORM",
                "issue_time": "2026-10-08T11:00:00Z",
                "effective_start": "2026-10-08T12:00:00Z",
                "effective_end": "2026-10-08T15:00:00Z",
                "latitude": 0.0,
                "longitude": 0.0,
                "radius_km": 50,
                "status": "ACTIVE",
                "evidence_id": "EVD-WARN-1",
            }
        ],
        "historical_weather": [
            {
                "record_id": "HIST-1",
                "record_type": "REANALYSIS",
                "source_id": "SRC-MODEL",
                "start_time": "2026-10-08T12:00:00Z",
                "end_time": "2026-10-08T13:00:00Z",
                "location": {"latitude": 0.0, "longitude": 0.0, "area_id": "REGION_A"},
                "measurement_type": "temperature",
                "value": 27.5,
                "unit": "C",
                "evidence_id": "EVD-HIST-1",
            }
        ],
        "event_context": [
            {
                "event_id": "EVT-1",
                "event_type": "LOCALIZED_FLOODING_CANDIDATE",
                "event_time": "2026-10-08T13:10:00Z",
                "latitude": 0.0,
                "longitude": 0.0,
                "area_id": "REGION_A",
            }
        ],
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
            "TRACEATLAS WEATHERINT evidence-first safety-aware weather intelligence scaffold. "
            "Consumes deterministic weather records; does not fetch live data, invent weather, "
            "target, optimize attacks, conceal/evasion/smuggle, or override official authorities."
        )
    )
    parser.add_argument("--input", "-i", help="Path to WEATHERINT input JSON")
    parser.add_argument("--output", "-o", default="weatherint_result.json", help="Output WEATHERINTResult JSON path")
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
