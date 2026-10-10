#!/usr/bin/env python3
"""
TRACEATLAS MASINT main.py
=========================

Lawful, authorized, defensive, evidence-first, physics-aware Measurement and
Signature Intelligence scaffold.

This module:
- Does NOT fetch live sensor data.
- Does NOT invent measurements, calibration, uncertainty, signatures, or sources.
- Does NOT design weapons or targeting solutions.
- Does NOT provide CBRN synthesis/production/dissemination/dose optimization.
- Does NOT provide sensor evasion, stealth optimization, jamming, spoofing, or ECM design.
- Does NOT track private persons or produce personal biometric/thermal/gait dossiers.

It consumes deterministic measurement records supplied by authorized/public sources:
- sensor metadata
- calibration records
- measurements
- environmental conditions
- baselines
- reference signatures
- source pedigree / independence metadata

It produces an evidence-linked MASINTResult with:
- sensor validation
- unit normalization
- quality control
- uncertainty handling
- baseline/anomaly analysis
- feature extraction from supplied numeric series
- signature comparison from supplied feature vectors / spectral bands
- multi-sensor fusion with independence checks
- physics consistency checks
- contradiction preservation
- competing hypotheses and falsification
- dual-AI style skeptic review
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

ALLOWED_SENSOR_STATUS = {
    "CALIBRATED",
    "CALIBRATION_EXPIRED",
    "UNCALIBRATED",
    "CALIBRATION_UNKNOWN",
    "DEGRADED",
    "SATURATED",
    "OUT_OF_RANGE",
    "OFFLINE",
    "UNKNOWN",
}

ALLOWED_PROCESSING_LEVELS = {
    "RAW",
    "CALIBRATED",
    "CORRECTED",
    "FILTERED",
    "FEATURE_EXTRACTED",
    "CLASSIFIED",
    "DERIVED_PRODUCT",
    "UNKNOWN",
}

ALLOWED_DETECTION_STATES = {
    "DETECTED",
    "LIKELY_DETECTED",
    "WEAK_DETECTION",
    "NOT_DETECTED",
    "INCONCLUSIVE",
}

ANOMALY_STATES = {
    "WITHIN_BASELINE",
    "MINOR_DEVIATION",
    "SIGNIFICANT_DEVIATION",
    "ANOMALY_SUPPORTED",
    "ANOMALY_DISPUTED",
    "UNKNOWN",
}

SEVERE_QUALITY_FLAGS = {
    "saturated",
    "out_of_range",
    "impossible_value",
    "sensor_config_expired",
    "calibration_expired",
    "uncalibrated_sensor",
    "calibration_unknown",
    "unit_unknown",
    "missing_timestamp",
    "negative_uncertainty",
    "below_detection_limit",
    "missing_detection_state",
}

# -----------------------------------------------------------------------------
# Unit normalization
# -----------------------------------------------------------------------------

# Canonical units:
# temperature: K
# distance: m
# time: s
# frequency: Hz
# pressure: Pa
# mass: kg
# speed: m/s
# power: W
# energy: J
# voltage: V
# current: A
# level: dB-like, no canonical conversion
# count/rate/activity/dose/concentration: preserve simple factors

UNIT_INFO: Dict[str, Tuple[str, float, float]] = {
    # temperature -> K
    "K": ("temperature", 1.0, 0.0),
    "C": ("temperature", 1.0, 273.15),
    "F": ("temperature", 5.0 / 9.0, 255.3722222222222),

    # distance -> m
    "m": ("distance", 1.0, 0.0),
    "km": ("distance", 1000.0, 0.0),
    "cm": ("distance", 0.01, 0.0),
    "mm": ("distance", 0.001, 0.0),
    "ft": ("distance", 0.3048, 0.0),
    "mi": ("distance", 1609.344, 0.0),
    "nm": ("distance", 1852.0, 0.0),

    # time -> s
    "s": ("time", 1.0, 0.0),
    "ms": ("time", 0.001, 0.0),
    "us": ("time", 1e-6, 0.0),
    "ns": ("time", 1e-9, 0.0),
    "min": ("time", 60.0, 0.0),
    "h": ("time", 3600.0, 0.0),
    "d": ("time", 86400.0, 0.0),

    # frequency -> Hz
    "Hz": ("frequency", 1.0, 0.0),
    "kHz": ("frequency", 1e3, 0.0),
    "MHz": ("frequency", 1e6, 0.0),
    "GHz": ("frequency", 1e9, 0.0),
    "THz": ("frequency", 1e12, 0.0),

    # pressure -> Pa
    "Pa": ("pressure", 1.0, 0.0),
    "kPa": ("pressure", 1e3, 0.0),
    "MPa": ("pressure", 1e6, 0.0),
    "bar": ("pressure", 1e5, 0.0),
    "mbar": ("pressure", 100.0, 0.0),
    "psi": ("pressure", 6894.757293168361, 0.0),

    # mass -> kg
    "kg": ("mass", 1.0, 0.0),
    "g": ("mass", 0.001, 0.0),
    "mg": ("mass", 1e-6, 0.0),
    "lb": ("mass", 0.45359237, 0.0),
    "tonne": ("mass", 1000.0, 0.0),

    # speed -> m/s
    "m/s": ("speed", 1.0, 0.0),
    "km/h": ("speed", 1.0 / 3.6, 0.0),
    "kt": ("speed", 0.5144444444444445, 0.0),
    "mph": ("speed", 0.44704, 0.0),

    # power -> W
    "W": ("power", 1.0, 0.0),
    "kW": ("power", 1e3, 0.0),
    "MW": ("power", 1e6, 0.0),

    # energy -> J
    "J": ("energy", 1.0, 0.0),
    "kJ": ("energy", 1e3, 0.0),

    # electrical
    "V": ("voltage", 1.0, 0.0),
    "mV": ("voltage", 0.001, 0.0),
    "A": ("current", 1.0, 0.0),
    "mA": ("current", 0.001, 0.0),

    # logarithmic / level
    "dB": ("level", 1.0, 0.0),
    "dBm": ("level", 1.0, 0.0),
    "dBA": ("level", 1.0, 0.0),

    # counts / radiation / chemistry, simplified
    "count": ("count", 1.0, 0.0),
    "cps": ("count_rate", 1.0, 0.0),
    "Bq": ("activity", 1.0, 0.0),
    "kBq": ("activity", 1e3, 0.0),
    "MBq": ("activity", 1e6, 0.0),
    "Gy": ("dose", 1.0, 0.0),
    "mGy": ("dose", 0.001, 0.0),
    "Sv": ("dose_equiv", 1.0, 0.0),
    "mSv": ("dose_equiv", 0.001, 0.0),
    "ppm": ("concentration", 1.0, 0.0),
    "ppb": ("concentration", 0.001, 0.0),
    "percent": ("concentration", 10000.0, 0.0),
}

UNIT_ALIASES: Dict[str, str] = {
    "c": "C",
    "k": "K",
    "f": "F",
    "pa": "Pa",
    "kpa": "kPa",
    "mpa": "MPa",
    "bar": "bar",
    "mbar": "mbar",
    "psi": "psi",
    "m": "m",
    "km": "km",
    "cm": "cm",
    "mm": "mm",
    "ft": "ft",
    "mi": "mi",
    "nm": "nm",
    "s": "s",
    "ms": "ms",
    "us": "us",
    "ns": "ns",
    "min": "min",
    "h": "h",
    "d": "d",
    "hz": "Hz",
    "khz": "kHz",
    "mhz": "MHz",
    "ghz": "GHz",
    "thz": "THz",
    "kg": "kg",
    "g": "g",
    "mg": "mg",
    "lb": "lb",
    "tonne": "tonne",
    "m/s": "m/s",
    "km/h": "km/h",
    "kt": "kt",
    "mph": "mph",
    "w": "W",
    "kw": "kW",
    "mw": "MW",
    "j": "J",
    "kj": "kJ",
    "v": "V",
    "mv": "mV",
    "a": "A",
    "ma": "mA",
    "db": "dB",
    "dbm": "dBm",
    "dba": "dBA",
    "count": "count",
    "cps": "cps",
    "bq": "Bq",
    "kbq": "kBq",
    "mbq": "MBq",
    "gy": "Gy",
    "mgy": "mGy",
    "sv": "Sv",
    "msv": "mSv",
    "ppm": "ppm",
    "ppb": "ppb",
    "percent": "percent",
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


def dbm_to_mw(dbm: float) -> float:
    return 10.0 ** (dbm / 10.0)


def normalize_unit_token(unit: Any) -> str:
    if unit is None:
        return ""
    raw = str(unit).strip()
    cleaned = raw.replace("°", "").replace("deg", "").replace(" ", "")
    lower = cleaned.lower()
    return UNIT_ALIASES.get(lower, cleaned)


def normalize_value_unit(
    value: Any,
    uncertainty: Any,
    unit: Any,
) -> Dict[str, Any]:
    """
    Deterministically normalize a value and 1-sigma-style uncertainty to a
    canonical unit when the unit is recognized.

    Preserves original value/unit. Never invents missing values.
    """
    original_unit = str(unit).strip() if unit is not None else None
    token = normalize_unit_token(original_unit)
    info = UNIT_INFO.get(token)

    v = to_float(value)
    u = to_float(uncertainty)

    flags: List[str] = []

    if not info:
        return {
            "original_value": v,
            "original_unit": original_unit,
            "normalized_value": v,
            "normalized_unit": original_unit,
            "normalized_uncertainty": u,
            "dimension": "UNKNOWN",
            "conversion_factor": None,
            "conversion_offset": None,
            "flags": flags + (["unit_unknown"] if original_unit else ["unit_missing"]),
        }

    dimension, factor, offset = info

    if u is not None and u < 0:
        flags.append("negative_uncertainty")
        u = abs(u)

    norm_v = None
    norm_u = None

    if v is not None:
        norm_v = v * factor + offset
    if u is not None:
        norm_u = abs(factor) * u

    canonical_unit = {
        "temperature": "K",
        "distance": "m",
        "time": "s",
        "frequency": "Hz",
        "pressure": "Pa",
        "mass": "kg",
        "speed": "m/s",
        "power": "W",
        "energy": "J",
        "voltage": "V",
        "current": "A",
        "level": token or "dB",
        "count": "count",
        "count_rate": "cps",
        "activity": "Bq",
        "dose": "Gy",
        "dose_equiv": "Sv",
        "concentration": "ppm",
    }.get(dimension, token)

    return {
        "original_value": v,
        "original_unit": original_unit,
        "normalized_value": norm_v,
        "normalized_unit": canonical_unit,
        "normalized_uncertainty": norm_u,
        "dimension": dimension,
        "conversion_factor": factor,
        "conversion_offset": offset,
        "flags": flags,
    }


def normalize_scalar_with_unit(value: Any, unit: Any) -> Dict[str, Any]:
    return normalize_value_unit(value, None, unit)


# -----------------------------------------------------------------------------
# Policy gate
# -----------------------------------------------------------------------------

BLOCK_PHRASES = [
    # weapons / targeting
    "design weapon",
    "optimize weapon",
    "firing solution",
    "fire control",
    "fire-control",
    "strike coordinate",
    "strike coordinates",
    "targeting solution",
    "aim point",
    "target package",
    "engagement priority",
    "vulnerable strike point",
    "blast effect optimization",
    "explosive design",

    # CBRN harmful development
    "synthesis procedure",
    "production procedure",
    "weaponization",
    "dissemination optimization",
    "dose optimization",
    "harmful agent synthesis",
    "biological cultivation",
    "radiological device design",

    # sensor evasion / EW / countermeasures
    "sensor evasion",
    "stealth optimization",
    "radar evasion",
    "acoustic signature reduction for evasion",
    "thermal signature suppression for evasion",
    "electromagnetic signature suppression for attack",
    "jam sensor",
    "spoof sensor",
    "electronic countermeasure design",
    "anti-sensor tactic",
    "military penetration route",

    # privacy / person tracking
    "private person tracking",
    "biometric gait",
    "personal thermal tracking",
    "private residence monitoring",
    "persistent person tracking",
]


def policy_block_reasons(case: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []

    scanned_parts: List[str] = []
    for key in ("objective", "questions", "scope", "authorization", "requested_outputs", "tags"):
        val = case.get(key)
        if val is not None:
            scanned_parts.append(json.dumps(val, ensure_ascii=False, default=str))

    text = " ".join(scanned_parts).lower()

    for phrase in BLOCK_PHRASES:
        if phrase in text:
            reasons.append(f"Forbidden MASINT action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}

    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    if scope.get("defensive_only") is False:
        reasons.append("scope.defensive_only must not be false")

    if scope.get("weapon_design") is True:
        reasons.append("scope.weapon_design is prohibited")
    if scope.get("targeting") is True:
        reasons.append("scope.targeting is prohibited")
    if scope.get("cbrn_development") is True:
        reasons.append("scope.cbrn_development is prohibited")
    if scope.get("sensor_evasion") is True:
        reasons.append("scope.sensor_evasion is prohibited")

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
            "NO_WEAPON_DESIGN",
            "NO_TARGETING",
            "NO_FIRE_CONTROL",
            "NO_CBRN_DEVELOPMENT",
            "NO_SENSOR_EVASION",
            "NO_STEALTH_OPTIMIZATION",
            "NO_JAMMING",
            "NO_SPOOFING",
            "NO_ELECTRONIC_COUNTERMEASURE_DESIGN",
            "NO_PRIVATE_PERSON_TRACKING",
        ],
        "privacy_flags": [
            "NO_BIOMETRIC_GAIT_IDENTIFICATION",
            "NO_PERSONAL_THERMAL_TRACKING",
            "NO_PRIVATE_RESIDENCE_MONITORING",
            "METADATA_MINIMIZATION",
        ],
        "recommended_next_actions": [
            "Restate objective as lawful defensive measurement/signature analysis",
            "Provide authorized sensor exports with calibration and uncertainty",
            "Use baselines and independent sensors for anomaly verification",
            "Escalate hazardous or safety-relevant findings to authorized human responders",
        ],
        "limitations": [
            "Requested or detected use crosses MASINT defensive boundary.",
            "No weapon design, targeting, CBRN development, sensor evasion, jamming, spoofing, or private tracking support is provided.",
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
# Validation and normalization
# -----------------------------------------------------------------------------

def validate_sensors(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    sensors: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(case.get("sensors") or []):
        if not isinstance(s, dict):
            issues.append(f"sensors[{idx}] is not an object")
            continue

        sid = s.get("sensor_id")
        if not sid:
            issues.append(f"sensors[{idx}] missing sensor_id")
            continue

        status = str(s.get("calibration_status", "CALIBRATION_UNKNOWN")).strip().upper()
        if status not in ALLOWED_SENSOR_STATUS:
            issues.append(f"sensor {sid} has unknown calibration_status={status}; set to CALIBRATION_UNKNOWN")
            status = "CALIBRATION_UNKNOWN"

        s["_calibration_status"] = status
        s["_usable_for_high_confidence"] = status == "CALIBRATED"

        sensors[sid] = s

    if not sensors:
        issues.append("No authorized sensors supplied")

    return sensors, issues


def extract_location(m: Dict[str, Any]) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[str]]:
    loc = m.get("location")
    lat = lon = acc = None
    area_id = m.get("area_id")

    if isinstance(loc, dict):
        lat = to_float(loc.get("latitude") if loc.get("latitude") is not None else loc.get("lat"))
        lon = to_float(loc.get("longitude") if loc.get("longitude") is not None else loc.get("lon"))
        acc = to_float(loc.get("accuracy_m") if loc.get("accuracy_m") is not None else loc.get("uncertainty_m"))
        area_id = loc.get("area_id") or area_id
    elif isinstance(loc, list) and len(loc) >= 2:
        lat = to_float(loc[0])
        lon = to_float(loc[1])
        if len(loc) >= 3:
            acc = to_float(loc[2])

    if lat is not None and not (-90.0 <= lat <= 90.0):
        lat = None
    if lon is not None and not (-180.0 <= lon <= 180.0):
        lon = None

    return lat, lon, acc, area_id


def validate_measurements(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    measurements: List[Dict[str, Any]] = []

    for idx, m in enumerate(case.get("measurements") or []):
        if not isinstance(m, dict):
            issues.append(f"measurements[{idx}] is not an object")
            continue

        mid = m.get("measurement_id") or f"MEAS-{idx + 1}"
        m["measurement_id"] = mid

        sid = m.get("sensor_id")
        if sid not in sensors:
            issues.append(f"measurement {mid} references unknown sensor_id={sid}")

        sensor = sensors.get(sid, {})

        ts = parse_dt(m.get("timestamp"))
        if ts is None:
            issues.append(f"measurement {mid} has missing/unparseable timestamp")
            m["_quality_flags"] = list(m.get("quality_flags") or []) + ["missing_timestamp"]
        m["_timestamp"] = ts

        # Sensor validity window
        valid_from = parse_dt(sensor.get("valid_from"))
        valid_to = parse_dt(sensor.get("valid_to"))
        if ts and valid_from and ts < valid_from:
            m.setdefault("_quality_flags", []).append("sensor_config_expired")
        if ts and valid_to and ts > valid_to:
            m.setdefault("_quality_flags", []).append("sensor_config_expired")

        cal_status = sensor.get("_calibration_status", "CALIBRATION_UNKNOWN")
        m["_sensor_calibration_state"] = cal_status

        if cal_status == "CALIBRATION_UNKNOWN":
            m.setdefault("_quality_flags", []).append("calibration_unknown")
        elif cal_status == "UNCALIBRATED":
            m.setdefault("_quality_flags", []).append("uncalibrated_sensor")
        elif cal_status == "CALIBRATION_EXPIRED":
            m.setdefault("_quality_flags", []).append("calibration_expired")
        elif cal_status in ("DEGRADED", "SATURATED", "OUT_OF_RANGE", "OFFLINE"):
            m.setdefault("_quality_flags", []).append(cal_status.lower())

        # Detection state
        det = str(m.get("detection_state", "")).strip().upper()
        if det not in ALLOWED_DETECTION_STATES:
            if m.get("value") is None:
                det = "INCONCLUSIVE"
                m.setdefault("_quality_flags", []).append("missing_detection_state")
            else:
                det = "DETECTED"
        m["_detection_state"] = det

        # Unit/value normalization
        norm = normalize_value_unit(m.get("value"), m.get("uncertainty"), m.get("unit"))
        m["_value_norm"] = norm["normalized_value"]
        m["_unit_norm"] = norm["normalized_unit"]
        m["_dimension"] = norm["dimension"]
        m["_unc_norm"] = norm["normalized_uncertainty"]
        m["_original_value"] = norm["original_value"]
        m["_original_unit"] = norm["original_unit"]
        m.setdefault("_quality_flags", []).extend(norm["flags"])

        # Processing level
        proc = str(m.get("processing_level", "UNKNOWN")).strip().upper()
        if proc not in ALLOWED_PROCESSING_LEVELS:
            warnings.append(f"measurement {mid} unknown processing_level={proc}; set UNKNOWN")
            proc = "UNKNOWN"
        m["_processing_level"] = proc

        # Location
        lat, lon, loc_acc, area_id = extract_location(m)
        m["_lat"] = lat
        m["_lon"] = lon
        m["_location_accuracy_m"] = loc_acc
        m["_area_id"] = area_id

        # Duration
        dur = to_float(m.get("duration"))
        dur_norm = normalize_value_unit(dur, None, m.get("duration_unit") or m.get("unit"))
        m["_duration_s"] = dur_norm["normalized_value"] if dur_norm["dimension"] == "time" else None
        if m["_duration_s"] is not None and m["_duration_s"] < 0:
            m.setdefault("_quality_flags", []).append("negative_duration")

        # Dynamic range / saturation / out-of-range
        dr = sensor.get("dynamic_range") or sensor.get("measurement_range")
        if isinstance(dr, dict) and m["_value_norm"] is not None:
            dr_norm_min = normalize_value_unit(dr.get("min"), None, dr.get("unit") or m.get("unit"))
            dr_norm_max = normalize_value_unit(dr.get("max"), None, dr.get("unit") or m.get("unit"))
            vmin = dr_norm_min["normalized_value"]
            vmax = dr_norm_max["normalized_value"]
            if vmin is not None and vmax is not None and m["_dimension"] == dr_norm_min["dimension"]:
                eps = 1e-9
                if m["_value_norm"] < vmin - eps or m["_value_norm"] > vmax + eps:
                    m.setdefault("_quality_flags", []).append("out_of_range")
                if abs(m["_value_norm"] - vmax) <= eps or abs(m["_value_norm"] - vmin) <= eps:
                    m.setdefault("_quality_flags", []).append("saturated")

        # Explicit saturation flag
        if m.get("saturated") is True:
            m.setdefault("_quality_flags", []).append("saturated")

        # Detection limit
        lod = m.get("detection_limit") or sensor.get("detection_limit")
        if lod is not None and m["_value_norm"] is not None:
            lod_norm = normalize_value_unit(lod, None, m.get("detection_limit_unit") or sensor.get("detection_limit_unit") or m.get("unit"))
            if lod_norm["dimension"] == m["_dimension"] and lod_norm["normalized_value"] is not None:
                m["_detection_limit_norm"] = lod_norm["normalized_value"]
                if m["_value_norm"] < lod_norm["normalized_value"]:
                    m.setdefault("_quality_flags", []).append("below_detection_limit")
            else:
                m["_detection_limit_norm"] = None
        else:
            m["_detection_limit_norm"] = None

        # Impossible physical values
        if m["_value_norm"] is not None:
            dim = m["_dimension"]
            val = m["_value_norm"]
            if dim == "temperature" and val < -1e-9:
                m.setdefault("_quality_flags", []).append("impossible_value")
            elif dim in ("distance", "frequency", "mass") and val < -1e-9:
                m.setdefault("_quality_flags", []).append("impossible_value")

        # Source/evidence IDs
        m["_source_ids"] = ensure_list(m.get("source_id") or m.get("source_ids"))
        m["_evidence_ids"] = ensure_list(m.get("evidence_id") or m.get("evidence_ids"))

        # De-duplicate quality flags while preserving order
        seen = set()
        uniq_flags = []
        for f in m.get("_quality_flags", []):
            fs = str(f).strip().lower()
            if fs and fs not in seen:
                seen.add(fs)
                uniq_flags.append(fs)
        m["_quality_flags"] = uniq_flags

        measurements.append(m)

    if not measurements:
        issues.append("No measurements supplied")

    return measurements, issues, warnings


def normalize_baselines(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    baselines: List[Dict[str, Any]] = []

    for idx, b in enumerate(case.get("baselines") or []):
        if not isinstance(b, dict):
            continue

        bid = b.get("baseline_id") or f"BASE-{idx + 1}"
        b["baseline_id"] = bid

        mean_norm = normalize_value_unit(b.get("mean"), b.get("uncertainty"), b.get("unit"))
        b["_mean_norm"] = mean_norm["normalized_value"]
        b["_unc_norm"] = mean_norm["normalized_uncertainty"]
        b["_dimension"] = mean_norm["dimension"]
        b["_unit_norm"] = mean_norm["normalized_unit"]

        std = to_float(b.get("std"))
        if std is not None and mean_norm["conversion_factor"] is not None:
            b["_std_norm"] = abs(mean_norm["conversion_factor"]) * std
        else:
            b["_std_norm"] = std

        b["_valid_from"] = parse_dt(b.get("valid_from"))
        b["_valid_to"] = parse_dt(b.get("valid_to"))

        baselines.append(b)

    return baselines


# -----------------------------------------------------------------------------
# Baseline / anomaly analysis
# -----------------------------------------------------------------------------

def select_baseline(m: Dict[str, Any], baselines: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    best = None
    best_score = -1

    phenomenon = m.get("phenomenon")
    dimension = m.get("_dimension")
    sensor_id = m.get("sensor_id")
    spatial_id = m.get("_spatial_cluster_id") or m.get("_area_id")
    ts = m.get("_timestamp")

    for b in baselines:
        if b.get("phenomenon") and phenomenon and b["phenomenon"] != phenomenon:
            continue
        if b.get("_dimension") and dimension and b["_dimension"] != dimension:
            continue

        if b.get("sensor_id") and b["sensor_id"] != sensor_id:
            continue
        if b.get("spatial_cluster_id") and b["spatial_cluster_id"] != spatial_id:
            continue
        if b.get("area_id") and b["area_id"] != m.get("_area_id"):
            continue

        score = 0
        if b.get("sensor_id") == sensor_id:
            score += 3
        if b.get("spatial_cluster_id") == spatial_id or b.get("area_id") == m.get("_area_id"):
            score += 2
        if b.get("phenomenon") == phenomenon:
            score += 1

        vf = b.get("_valid_from")
        vt = b.get("_valid_to")
        if ts:
            if vf and ts < vf:
                continue
            if vt and ts > vt:
                continue
            score += 1

        if score > best_score:
            best = b
            best_score = score

    return best


def analyze_anomaly(
    m: Dict[str, Any],
    baselines: List[Dict[str, Any]],
) -> Dict[str, Any]:
    value = m.get("_value_norm")
    unc = m.get("_unc_norm")
    flags = set(m.get("_quality_flags") or [])
    cal = m.get("_sensor_calibration_state", "CALIBRATION_UNKNOWN")

    result = {
        "measurement_id": m.get("measurement_id"),
        "phenomenon": m.get("phenomenon"),
        "anomaly_state": "UNKNOWN",
        "baseline_id": None,
        "z_score": None,
        "deviation": None,
        "confidence": "UNKNOWN",
        "notes": [],
    }

    if value is None:
        result["anomaly_state"] = "UNKNOWN"
        result["notes"].append("No numeric value available; non-detection is not absence.")
        return result

    b = select_baseline(m, baselines)
    if not b:
        result["anomaly_state"] = "UNKNOWN"
        result["notes"].append("No compatible baseline supplied.")
        return result

    mean = b.get("_mean_norm")
    std = b.get("_std_norm") or 0.0
    b_unc = b.get("_unc_norm") or 0.0

    if mean is None:
        result["anomaly_state"] = "UNKNOWN"
        result["notes"].append("Baseline mean unavailable.")
        return result

    sigma_sq = (std or 0.0) ** 2 + (unc or 0.0) ** 2 + (b_unc or 0.0) ** 2
    sigma = math.sqrt(sigma_sq) if sigma_sq > 0 else 0.0
    dev = value - mean

    if sigma == 0:
        tol = max(1e-9, abs(mean) * 1e-6)
        z = 0.0 if abs(dev) <= tol else float("inf")
        result["notes"].append("Baseline zero variance; treat as data-quality limitation.")
    else:
        z = dev / sigma

    overlap = True
    if (std or 0.0) > 0 or (unc or 0.0) > 0 or (b_unc or 0.0) > 0:
        lower_b = mean - (std or 0.0) - (b_unc or 0.0)
        upper_b = mean + (std or 0.0) + (b_unc or 0.0)
        lower_m = value - (unc or 0.0)
        upper_m = value + (unc or 0.0)
        overlap = not (upper_m < lower_b or lower_m > upper_b)

    severe = bool(flags & SEVERE_QUALITY_FLAGS)
    calibrated = cal == "CALIBRATED"

    abs_z = abs(z) if z is not None and not math.isinf(z) else float("inf")

    if overlap and abs_z < 3.0:
        state = "WITHIN_BASELINE"
    elif abs_z < 2.0:
        state = "WITHIN_BASELINE"
    elif abs_z < 3.0:
        state = "MINOR_DEVIATION"
    elif abs_z < 5.0:
        state = "SIGNIFICANT_DEVIATION"
    else:
        state = "ANOMALY_SUPPORTED" if calibrated and not severe else "SIGNIFICANT_DEVIATION"

    if severe:
        state = "ANOMALY_DISPUTED" if state not in ("WITHIN_BASELINE", "UNKNOWN") else state
        result["notes"].append("Severe quality flags present; anomaly interpretation disputed.")

    confidence = "UNKNOWN"
    if state == "WITHIN_BASELINE":
        confidence = "HIGH" if calibrated and not severe else "MODERATE"
    elif state in ("MINOR_DEVIATION", "SIGNIFICANT_DEVIATION"):
        confidence = "MODERATE" if calibrated and not severe else "LOW"
    elif state == "ANOMALY_SUPPORTED":
        confidence = "MODERATE"
    elif state == "ANOMALY_DISPUTED":
        confidence = "LOW"

    result.update(
        {
            "baseline_id": b.get("baseline_id"),
            "anomaly_state": state,
            "z_score": z if not math.isinf(z) else None,
            "deviation": dev,
            "deviation_unit": m.get("_unit_norm"),
            "confidence": confidence,
            "baseline_mean": mean,
            "baseline_std": std,
            "measurement_value": value,
            "measurement_uncertainty": unc,
        }
    )

    return result


# -----------------------------------------------------------------------------
# Feature extraction
# -----------------------------------------------------------------------------

def linear_regression(xs: List[float], ys: List[float]) -> Optional[Dict[str, Any]]:
    pairs = [(x, y) for x, y in zip(xs, ys) if x is not None and y is not None]
    n = len(pairs)
    if n < 2:
        return None

    xs2 = [p[0] for p in pairs]
    ys2 = [p[1] for p in pairs]

    xmean = statistics.fmean(xs2)
    ymean = statistics.fmean(ys2)

    sxx = sum((x - xmean) ** 2 for x in xs2)
    sxy = sum((x - xmean) * (y - ymean) for x, y in pairs)

    if sxx == 0:
        return {
            "slope": 0.0,
            "intercept": ymean,
            "n": n,
            "slope_std_error": None,
            "r2": None,
            "note": "Zero variance in x; slope undefined/set 0.",
        }

    slope = sxy / sxx
    intercept = ymean - slope * xmean

    residuals = [y - (slope * x + intercept) for x, y in pairs]
    sse = sum(r * r for r in residuals)
    sst = sum((y - ymean) ** 2 for y in ys2)
    r2 = 1.0 - (sse / sst) if sst > 0 else None

    slope_se = None
    if n > 2 and sxx > 0:
        mse = sse / (n - 2)
        slope_se = math.sqrt(mse / sxx)

    return {
        "slope": slope,
        "intercept": intercept,
        "n": n,
        "slope_std_error": slope_se,
        "r2": r2,
        "method": "ordinary_least_squares",
        "limitation": "Linear trend is descriptive only; does not establish causality.",
    }


def extract_spectral_features(bands: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(bands, list) or not bands:
        return None

    centers: List[float] = []
    powers: List[float] = []

    for b in bands:
        if not isinstance(b, dict):
            continue
        c = to_float(b.get("center_hz") or b.get("frequency_hz") or b.get("center"))
        p_dbm = to_float(b.get("power_dbm"))
        p_lin = to_float(b.get("power_linear") or b.get("power"))

        if c is None:
            continue
        if p_lin is None and p_dbm is not None:
            p_lin = dbm_to_mw(p_dbm)
        if p_lin is None:
            continue

        centers.append(c)
        powers.append(max(0.0, p_lin))

    if not centers or not powers:
        return None

    total = sum(powers)
    if total <= 0:
        return None

    centroid = sum(c * p for c, p in zip(centers, powers)) / total
    max_power = max(powers)
    max_idx = powers.index(max_power)

    return {
        "band_count": len(centers),
        "total_power_linear": total,
        "max_power_linear": max_power,
        "max_center_hz": centers[max_idx],
        "spectral_centroid_hz": centroid,
        "method": "power_weighted_centroid_from_supplied_bands",
        "limitation": "Features are derived only from supplied band data; no FFT was performed by this script.",
    }


def build_features(measurements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)

    for m in measurements:
        if m.get("_value_norm") is None or m.get("_timestamp") is None:
            continue
        key = (
            m.get("phenomenon") or "UNKNOWN_PHENOMENON",
            m.get("sensor_id") or "UNKNOWN_SENSOR",
            m.get("_dimension") or "UNKNOWN",
            m.get("_spatial_cluster_id") or m.get("_area_id") or "UNKNOWN_LOCATION",
        )
        groups[key].append(m)

    features: List[Dict[str, Any]] = []

    for idx, (key, items) in enumerate(groups.items(), 1):
        items = sorted(items, key=lambda x: x.get("_timestamp") or datetime.min.replace(tzinfo=timezone.utc))
        vals = [x.get("_value_norm") for x in items if x.get("_value_norm") is not None]
        if not vals:
            continue

        ts0 = items[0].get("_timestamp")
        xs = []
        for it in items:
            t = it.get("_timestamp")
            if isinstance(ts0, datetime) and isinstance(t, datetime):
                xs.append((t - ts0).total_seconds())
            else:
                xs.append(None)

        stats = numeric_summary(vals)
        trend = linear_regression([x for x in xs if x is not None], vals) if len(vals) >= 2 else None

        feat = {
            "feature_id": f"FEAT-{idx}",
            "phenomenon": key[0],
            "sensor_id": key[1],
            "dimension": key[2],
            "spatial_cluster_id": key[3],
            "count": stats["count"],
            "mean": stats["mean"],
            "std": stats["std"],
            "min": stats["min"],
            "max": stats["max"],
            "median": stats["median"],
            "unit": items[0].get("_unit_norm"),
            "duration_s": (xs[-1] - xs[0]) if xs and xs[0] is not None and xs[-1] is not None else None,
            "trend": trend,
            "method": "deterministic_time_series_statistics",
            "limitations": [
                "Features describe supplied measurements only.",
                "Trend does not establish cause or source identity.",
            ],
        }

        # Per-measurement supplied spectral/vector features
        spectral_feats = []
        vector_feats = []
        for it in items:
            sf = extract_spectral_features(it.get("spectral_bands"))
            if sf:
                sf["measurement_id"] = it.get("measurement_id")
                spectral_feats.append(sf)
            fv = it.get("feature_vector")
            if isinstance(fv, list):
                nums = [to_float(x) for x in fv]
                nums = [x for x in nums if x is not None]
                if nums:
                    vector_feats.append(
                        {
                            "measurement_id": it.get("measurement_id"),
                            "feature_vector": nums,
                            "method": "supplied_numeric_feature_vector",
                        }
                    )

        if spectral_feats:
            feat["spectral_features"] = spectral_feats
        if vector_feats:
            feat["vector_features"] = vector_feats

        features.append(feat)

    return features


# -----------------------------------------------------------------------------
# Signature analysis
# -----------------------------------------------------------------------------

def cosine_similarity(a: List[float], b: List[float]) -> Optional[float]:
    if len(a) != len(b) or not a:
        return None
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return None
    return dot / (na * nb)


def vector_from_spectral_bands(bands: Any) -> Optional[List[float]]:
    feats = extract_spectral_features(bands)
    if not feats:
        return None
    return [
        float(feats.get("band_count") or 0),
        float(feats.get("total_power_linear") or 0),
        float(feats.get("max_power_linear") or 0),
        float(feats.get("spectral_centroid_hz") or 0),
    ]


def get_signature_vector(obj: Dict[str, Any]) -> Optional[List[float]]:
    fv = obj.get("feature_vector")
    if isinstance(fv, list):
        nums = [to_float(x) for x in fv]
        nums = [x for x in nums if x is not None]
        if nums:
            return nums

    vec = vector_from_spectral_bands(obj.get("spectral_bands"))
    if vec:
        return vec

    return None


def build_signatures_and_matches(
    measurements: List[Dict[str, Any]],
    reference_signatures: List[Dict[str, Any]],
    threshold: float,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    signatures: List[Dict[str, Any]] = []
    matches: List[Dict[str, Any]] = []

    refs_with_vecs: List[Tuple[Dict[str, Any], List[float]]] = []
    for r in reference_signatures or []:
        if not isinstance(r, dict):
            continue
        rv = get_signature_vector(r)
        if rv:
            refs_with_vecs.append((r, rv))

    for m in measurements:
        mv = get_signature_vector(m)
        if not mv:
            continue

        sid = f"SIG-{m.get('measurement_id')}"
        sig = {
            "signature_id": sid,
            "measurement_id": m.get("measurement_id"),
            "sensor_id": m.get("sensor_id"),
            "phenomenon": m.get("phenomenon"),
            "time_window": iso_or_none(m.get("_timestamp")),
            "spatial_extent": m.get("_spatial_cluster_id") or m.get("_area_id"),
            "normalization_method": "supplied_feature_vector_or_spectral_summary",
            "vector_dimension": len(mv),
            "limitations": [
                "Signature vector is derived only from supplied features/bands.",
                "Similarity does not establish same source or exact identity.",
            ],
        }
        signatures.append(sig)

        for ref, rv in refs_with_vecs:
            sim = cosine_similarity(mv, rv)
            if sim is None:
                continue

            match_state = "NO_STRONG_MATCH"
            if sim >= threshold:
                match_state = "SIMILARITY_CANDIDATE"
            if sim >= max(0.95, threshold + 0.1):
                match_state = "CLASS_CANDIDATE"

            matches.append(
                {
                    "match_id": f"MATCH-{len(matches) + 1}",
                    "signature_id": sid,
                    "reference_signature_id": ref.get("reference_signature_id") or ref.get("signature_id"),
                    "reference_class": ref.get("class_label") or ref.get("source_class"),
                    "similarity": sim,
                    "metric": "cosine_similarity",
                    "match_state": match_state,
                    "threshold": threshold,
                    "limitations": [
                        "Reference library may be incomplete or condition-dependent.",
                        "Signature similarity is not source identity.",
                    ],
                }
            )

    return signatures, matches


# -----------------------------------------------------------------------------
# Source independence and fusion
# -----------------------------------------------------------------------------

def sensor_independence(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    if not a or not b:
        return "UNKNOWN"
    if a.get("sensor_id") == b.get("sensor_id"):
        return "DEPENDENT"

    shared_keys = [
        "independence_group",
        "upstream_sensor_id",
        "detector_id",
        "processor_id",
        "platform_id",
        "calibration_reference",
    ]

    for k in shared_keys:
        av = a.get(k)
        bv = b.get(k)
        if av is not None and bv is not None and av == bv:
            return "DEPENDENT"

    missing = any(a.get(k) is None or b.get(k) is None for k in ["independence_group", "platform_id", "detector_id"])
    if missing:
        return "UNKNOWN"

    if a.get("platform") == b.get("platform") and a.get("sensor_type") == b.get("sensor_type"):
        return "PARTIALLY_DEPENDENT"

    return "INDEPENDENT"


def summarize_independence(sensor_ids: List[str], sensors: Dict[str, Dict[str, Any]]) -> str:
    ids = [s for s in sensor_ids if s]
    if len(ids) < 2:
        return "SINGLE_SENSOR"

    states = []
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            states.append(sensor_independence(sensors.get(ids[i], {}), sensors.get(ids[j], {})))

    if all(s == "INDEPENDENT" for s in states):
        return "INDEPENDENT"
    if any(s == "DEPENDENT" for s in states):
        return "DEPENDENT_OR_UNKNOWN"
    if any(s == "PARTIALLY_DEPENDENT" for s in states):
        return "PARTIALLY_DEPENDENT"
    return "UNKNOWN"


def build_spatial_clusters(measurements: List[Dict[str, Any]], distance_km: float) -> List[Dict[str, Any]]:
    clusters: List[Dict[str, Any]] = []
    next_id = 1

    for m in measurements:
        lat = m.get("_lat")
        lon = m.get("_lon")

        if lat is None or lon is None:
            area = m.get("_area_id") or "UNKNOWN_LOCATION"
            m["_spatial_cluster_id"] = f"AREA:{area}"
            continue

        assigned = None
        for c in clusters:
            d = haversine_km(lat, lon, c["lat"], c["lon"])
            if d is not None and d <= distance_km:
                assigned = c
                break

        if assigned:
            n = assigned["count"] + 1
            assigned["lat"] = (assigned["lat"] * assigned["count"] + lat) / n
            assigned["lon"] = (assigned["lon"] * assigned["count"] + lon) / n
            assigned["count"] = n
            m["_spatial_cluster_id"] = assigned["id"]
        else:
            cid = f"SPATIAL-{next_id}"
            next_id += 1
            clusters.append({"id": cid, "lat": lat, "lon": lon, "count": 1})
            m["_spatial_cluster_id"] = cid

    return clusters


def segment_by_time(items: List[Dict[str, Any]], max_gap_s: float) -> List[List[Dict[str, Any]]]:
    def sort_key(x: Dict[str, Any]) -> datetime:
        return x.get("_timestamp") or x.get("_start") or datetime.min.replace(tzinfo=timezone.utc)

    ordered = sorted(items, key=sort_key)
    segments: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    last_ts: Optional[datetime] = None

    for m in ordered:
        ts = m.get("_timestamp") or m.get("_start")
        if current and last_ts and ts and (ts - last_ts).total_seconds() > max_gap_s:
            segments.append(current)
            current = []
        current.append(m)
        last_ts = ts

    if current:
        segments.append(current)

    return segments


def fuse_measurements(
    measurements: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    settings: Dict[str, float],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    fused: List[Dict[str, Any]] = []
    contradictions: List[Dict[str, Any]] = []

    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)

    for m in measurements:
        if m.get("_value_norm") is None:
            continue
        key = (
            m.get("phenomenon") or "UNKNOWN_PHENOMENON",
            m.get("_dimension") or "UNKNOWN",
            m.get("_spatial_cluster_id") or "UNKNOWN_LOCATION",
        )
        groups[key].append(m)

    for gidx, (key, items) in enumerate(groups.items(), 1):
        segments = segment_by_time(items, settings["fusion_time_window_s"])

        for sidx, seg in enumerate(segments, 1):
            usable = [x for x in seg if x.get("_value_norm") is not None]
            if len(usable) < 2:
                continue

            sensor_ids = sorted({x.get("sensor_id") for x in usable if x.get("sensor_id")})
            if len(sensor_ids) < 2:
                continue

            vals = [x.get("_value_norm") for x in usable]
            uncs = [x.get("_unc_norm") for x in usable]

            weighted = all(u is not None and u > 0 for u in uncs)
            if weighted:
                weights = [1.0 / (u * u) for u in uncs]
                wsum = sum(weights)
                fused_val = sum(w * v for w, v in zip(weights, vals)) / wsum
                fused_unc = math.sqrt(1.0 / wsum) if wsum > 0 else None
                method = "inverse_variance_weighted_mean"
            else:
                fused_val = statistics.fmean(vals)
                sd = safe_std(vals)
                fused_unc = (sd / math.sqrt(len(vals))) if sd is not None and len(vals) > 1 else None
                method = "unweighted_mean_with_dispersion_uncertainty"
                if fused_unc is None:
                    usable[0].setdefault("_quality_flags", []).append("fusion_uncertainty_unavailable")

            # Pairwise consistency checks
            conflict_found = False
            for i in range(len(usable)):
                for j in range(i + 1, len(usable)):
                    vi = usable[i].get("_value_norm")
                    vj = usable[j].get("_value_norm")
                    ui = usable[i].get("_unc_norm")
                    uj = usable[j].get("_unc_norm")
                    if vi is None or vj is None:
                        continue
                    if ui is not None and uj is not None:
                        combined = math.sqrt(ui * ui + uj * uj)
                        if combined > 0 and abs(vi - vj) > settings["conflict_sigma"] * combined:
                            conflict_found = True
                            contradictions.append(
                                {
                                    "type": "sensor_measurement_conflict",
                                    "phenomenon": key[0],
                                    "spatial_cluster_id": key[2],
                                    "measurement_ids": [usable[i].get("measurement_id"), usable[j].get("measurement_id")],
                                    "sensor_ids": [usable[i].get("sensor_id"), usable[j].get("sensor_id")],
                                    "value_difference": abs(vi - vj),
                                    "combined_uncertainty": combined,
                                    "note": "Preserve contradiction. Do not average conflicting measurements into false precision.",
                                }
                            )

            independence = summarize_independence(sensor_ids, sensors)

            start_ts = min((x.get("_timestamp") for x in usable if x.get("_timestamp")), default=None)
            end_ts = max((x.get("_timestamp") for x in usable if x.get("_timestamp")), default=None)

            fid = f"FUSED-{gidx}-{sidx}"
            fused_obj = {
                "measurement_id": fid,
                "phenomenon": key[0],
                "sensor_id": None,
                "sensor_ids": sensor_ids,
                "value": fused_val,
                "unit": usable[0].get("_unit_norm"),
                "dimension": key[1],
                "uncertainty": fused_unc,
                "timestamp": iso_or_none(start_ts),
                "start_time": iso_or_none(start_ts),
                "end_time": iso_or_none(end_ts),
                "_timestamp": start_ts,
                "_start": start_ts,
                "_end": end_ts,
                "_value_norm": fused_val,
                "_unit_norm": usable[0].get("_unit_norm"),
                "_dimension": key[1],
                "_unc_norm": fused_unc,
                "_spatial_cluster_id": key[2],
                "_lat": None,
                "_lon": None,
                "_area_id": usable[0].get("_area_id"),
                "_processing_level": "DERIVED_PRODUCT",
                "_detection_state": "DETECTED",
                "_quality_flags": ["derived_product"] + (["sensor_conflict"] if conflict_found else []),
                "_source_ids": sorted({sid for x in usable for sid in (x.get("_source_ids") or [])}),
                "_evidence_ids": sorted({eid for x in usable for eid in (x.get("_evidence_ids") or [])}),
                "_sensor_calibration_state": "MIXED_OR_UNKNOWN",
                "fusion_method": method,
                "source_independence": independence,
                "contributing_measurement_ids": [x.get("measurement_id") for x in usable],
                "limitations": [
                    "Fused value is a derived product, not a raw sensor measurement.",
                    "Independence depends on supplied sensor pedigree metadata.",
                    "Contradictions are preserved and reduce confidence.",
                ],
            }

            fused.append(fused_obj)

    return fused, contradictions


# -----------------------------------------------------------------------------
# Contradictions, facts, hypotheses, dual review
# -----------------------------------------------------------------------------

def detect_additional_contradictions(
    measurements: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    signatures: List[Dict[str, Any]],
    matches: List[Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    threshold: float,
) -> List[Dict[str, Any]]:
    contradictions: List[Dict[str, Any]] = []

    # Classification conflicts among measurements with same phenomenon/spatial/time-ish group
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)
    for m in measurements:
        cls = m.get("classification_candidate")
        if not cls:
            continue
        key = (m.get("phenomenon"), m.get("_spatial_cluster_id"))
        groups[key].append(m)

    for key, items in groups.items():
        classes = sorted({str(x.get("classification_candidate")).upper() for x in items if x.get("classification_candidate")})
        if len(classes) > 1 and "UNKNOWN" not in classes:
            contradictions.append(
                {
                    "type": "classification_conflict",
                    "phenomenon": key[0],
                    "spatial_cluster_id": key[1],
                    "classes": classes,
                    "note": "Preserve conflict. Do not force one classification without stronger evidence.",
                }
            )

    # Calibration conflict: sensor marked CALIBRATED but validity expired relative to measurement
    for m in measurements:
        sid = m.get("sensor_id")
        s = sensors.get(sid, {})
        ts = m.get("_timestamp")
        if s.get("_calibration_status") == "CALIBRATED" and "sensor_config_expired" in (m.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "calibration_conflict",
                    "measurement_id": m.get("measurement_id"),
                    "sensor_id": sid,
                    "note": "Sensor labeled calibrated but measurement falls outside supplied validity window.",
                }
            )

    # Unit/dimension conflict in same phenomenon/spatial group
    dim_groups: Dict[Tuple[Any, ...], set] = defaultdict(set)
    for m in measurements:
        if m.get("_value_norm") is None:
            continue
        dim_groups[(m.get("phenomenon"), m.get("_spatial_cluster_id"))].add(m.get("_dimension"))
    for key, dims in dim_groups.items():
        clean = {d for d in dims if d and d != "UNKNOWN"}
        if len(clean) > 1:
            contradictions.append(
                {
                    "type": "unit_dimension_conflict",
                    "phenomenon": key[0],
                    "spatial_cluster_id": key[1],
                    "dimensions": sorted(clean),
                    "note": "Same phenomenon group contains incompatible measurement dimensions.",
                }
            )

    # Reference mismatch: strong match claimed but similarity below threshold
    for match in matches:
        if match.get("match_state") in {"CLASS_CANDIDATE", "SIMILARITY_CANDIDATE"}:
            sim = match.get("similarity")
            if sim is not None and sim < threshold:
                contradictions.append(
                    {
                        "type": "reference_match_inconsistency",
                        "match_id": match.get("match_id"),
                        "similarity": sim,
                        "threshold": threshold,
                        "note": "Match state inconsistent with similarity threshold.",
                    }
                )

    return contradictions


def measurement_confidence(m: Dict[str, Any]) -> str:
    flags = set(m.get("_quality_flags") or [])
    cal = m.get("_sensor_calibration_state", "CALIBRATION_UNKNOWN")
    proc = m.get("_processing_level", "UNKNOWN")

    severe = bool(flags & SEVERE_QUALITY_FLAGS)

    if proc == "DERIVED_PRODUCT":
        if "sensor_conflict" in flags:
            return "LOW"
        if m.get("source_independence") == "INDEPENDENT":
            return "MODERATE"
        return "LOW"

    if cal == "CALIBRATED" and not severe:
        return "HIGH"
    if cal in ("CALIBRATED", "PARTIALLY_CALIBRATED") and not severe:
        return "MODERATE"
    if severe or cal in ("UNCALIBRATED", "CALIBRATION_UNKNOWN", "CALIBRATION_EXPIRED"):
        return "LOW"
    return "UNKNOWN"


def build_facts(
    measurements: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    matches: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "No weapon design or targeting conclusion is supported.",
        "No CBRN synthesis, production, dissemination, or dose optimization is supported.",
        "No sensor evasion, stealth optimization, jamming, spoofing, or ECM design is supported.",
        "No private-person identity, location, or movement pattern is inferred.",
        "Non-detection is not absence.",
        "Measurement is not interpretation.",
        "Detection is not classification.",
        "Classification is not identification.",
        "Identification is not attribution.",
        "Signature similarity is not same source.",
        "Calibration is not perfect accuracy.",
        "AI classifier confidence is not real-world probability.",
    ]

    anomaly_by_meas = {a.get("measurement_id"): a for a in anomalies}

    for m in measurements + fused:
        conf = measurement_confidence(m)
        val = m.get("_value_norm")
        unit = m.get("_unit_norm")
        ts = iso_or_none(m.get("_timestamp") or m.get("_start"))
        sid = m.get("sensor_id")
        sids = m.get("sensor_ids")
        source = sid or (", ".join(sids) if sids else "UNKNOWN_SOURCE")
        phen = m.get("phenomenon") or "UNKNOWN_PHENOMENON"

        if val is None:
            stmt = f"{source} reports no numeric value for {phen} at {ts}; detection_state={m.get('_detection_state')}."
            item = {
                "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
                "statement": stmt,
                "measurement_id": m.get("measurement_id"),
                "confidence": "UNKNOWN",
                "limitation": "Non-detection is not absence.",
            }
            partial.append(item)
            continue

        stmt = f"{source} measured {val} {unit} for {phen} at {ts}."
        item = {
            "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": stmt,
            "measurement_id": m.get("measurement_id"),
            "confidence": conf,
            "quality_flags": m.get("_quality_flags"),
            "processing_level": m.get("_processing_level"),
        }

        if conf == "HIGH":
            supported.append(item)
        elif conf == "MODERATE":
            candidates.append(item)
        else:
            partial.append(item)

        a = anomaly_by_meas.get(m.get("measurement_id"))
        if a and a.get("anomaly_state") in {"MINOR_DEVIATION", "SIGNIFICANT_DEVIATION", "ANOMALY_SUPPORTED"}:
            candidates.append(
                {
                    "fact_id": f"FCT-ANOM-{len(candidates) + 1}",
                    "statement": f"Measurement {m.get('measurement_id')} deviates from selected baseline: {a.get('anomaly_state')}.",
                    "measurement_id": m.get("measurement_id"),
                    "confidence": a.get("confidence", "LOW"),
                    "limitation": "Anomaly does not establish maliciousness, danger, or source identity.",
                }
            )

    for match in matches:
        if match.get("match_state") in {"SIMILARITY_CANDIDATE", "CLASS_CANDIDATE"}:
            candidates.append(
                {
                    "fact_id": f"FCT-SIG-{len(candidates) + 1}",
                    "statement": (
                        f"Signature {match.get('signature_id')} is similar to reference "
                        f"{match.get('reference_signature_id')} (similarity={match.get('similarity')})."
                    ),
                    "match_id": match.get("match_id"),
                    "confidence": "MODERATE" if match.get("match_state") == "CLASS_CANDIDATE" else "LOW",
                    "limitation": "Signature similarity is not source identity.",
                }
            )

    for c in contradictions:
        disputed.append(
            {
                "disputed_id": f"DIS-{len(disputed) + 1}",
                "type": c.get("type"),
                "statement": "Material contradiction present; do not silently resolve.",
                "details": c,
            }
        )

    return supported, candidates, partial, disputed, not_facts


def build_hypotheses(
    anomalies: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    measurements: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    meas_by_id = {m.get("measurement_id"): m for m in measurements + fused}

    focus_items = []
    for a in anomalies:
        if a.get("anomaly_state") in {"MINOR_DEVIATION", "SIGNIFICANT_DEVIATION", "ANOMALY_SUPPORTED", "ANOMALY_DISPUTED"}:
            focus_items.append(a)

    for f in fused:
        focus_items.append(
            {
                "measurement_id": f.get("measurement_id"),
                "phenomenon": f.get("phenomenon"),
                "anomaly_state": "DERIVED_FUSION",
                "confidence": measurement_confidence(f),
            }
        )

    for idx, a in enumerate(focus_items, 1):
        mid = a.get("measurement_id")
        m = meas_by_id.get(mid, {})
        flags = set(m.get("_quality_flags") or [])
        independence = m.get("source_independence", "UNKNOWN")
        cal = m.get("_sensor_calibration_state", "UNKNOWN")
        env = m.get("environmental_context")

        base = {
            "hypothesis_set_id": f"HSET-{idx}",
            "measurement_id": mid,
            "phenomenon": a.get("phenomenon") or m.get("phenomenon"),
        }

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-REAL-PHENOMENON",
                "statement": "The measurement reflects a real physical phenomenon above baseline/within sensor limits.",
                "support": [
                    "Numeric measurement supplied." if m.get("_value_norm") is not None else "No numeric value.",
                    "Independent multi-sensor fusion." if independence == "INDEPENDENT" else "No independent multi-sensor confirmation recorded.",
                    "Calibrated sensor." if cal == "CALIBRATED" else f"Sensor calibration state: {cal}.",
                ],
                "opposition": [
                    "Quality flags present." if flags else "No severe quality flags recorded.",
                    "Contradictions present." if contradictions else "No contradictions recorded.",
                ],
                "unknowns": ["Source identity", "operator", "intent", "exact material/equipment"],
                "falsification_conditions": [
                    "Independent sensor fails to reproduce phenomenon within uncertainty.",
                    "Calibration/health check reveals sensor fault.",
                    "Environmental correction removes anomaly.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-SENSOR-FAULT",
                "statement": "The observation may be caused by sensor fault, drift, saturation, or calibration error.",
                "support": [
                    "Severe quality flags present." if flags & SEVERE_QUALITY_FLAGS else "No severe quality flags recorded.",
                    f"Calibration state: {cal}.",
                ],
                "opposition": [
                    "Independent calibrated sensors agree." if independence == "INDEPENDENT" and cal == "CALIBRATED" else "No strong independent corroboration recorded.",
                ],
                "unknowns": ["Sensor health logs", "calibration certificate", "configuration era"],
                "falsification_conditions": [
                    "Sensor self-test/calibration record confirms healthy operation.",
                    "Independent sensor reproduces same measurement within uncertainty.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-ENVIRONMENTAL-CONFOUNDER",
                "statement": "The observation may be explained by environmental conditions or background variation.",
                "support": [
                    "Environmental context supplied." if env else "Environmental context missing.",
                    "Baseline deviation is minor." if a.get("anomaly_state") == "MINOR_DEVIATION" else "Anomaly state not minor.",
                ],
                "opposition": [
                    "Deviation remains after baseline comparison." if a.get("anomaly_state") in {"SIGNIFICANT_DEVIATION", "ANOMALY_SUPPORTED"} else "No strong deviation recorded.",
                ],
                "unknowns": ["Weather", "terrain", "season", "operating mode", "load state"],
                "falsification_conditions": [
                    "Matching environmental baseline explains full deviation.",
                    "Control location/time shows same pattern without source presence.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-PROCESSING-ARTIFACT",
                "statement": "The observation may be a processing, filtering, aliasing, or unit-conversion artifact.",
                "support": [
                    "Processing level unknown or derived." if m.get("_processing_level") in ("UNKNOWN", "DERIVED_PRODUCT") else "Processing level documented.",
                    "Unit/dimension issues present." if "unit_unknown" in flags or "unit_missing" in flags else "No unit flags recorded.",
                ],
                "opposition": [
                    "Deterministic unit normalization completed." if m.get("_dimension") != "UNKNOWN" else "Unit dimension unresolved.",
                ],
                "unknowns": ["Algorithm version", "filter parameters", "raw hash", "pipeline provenance"],
                "falsification_conditions": [
                    "Raw data reprocessing removes artifact.",
                    "Independent pipeline reproduces measurement.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-ORDINARY-BASELINE-VARIATION",
                "statement": "The observation may be ordinary variation not represented adequately by the selected baseline.",
                "support": [
                    "Baseline may be incomplete or context-mismatched.",
                    "Anomaly state is not strongly supported." if a.get("anomaly_state") != "ANOMALY_SUPPORTED" else "Anomaly state is strongly deviant.",
                ],
                "opposition": [
                    "Large z-score/deviation." if a.get("z_score") is not None and abs(a.get("z_score")) >= 3 else "No large deviation recorded.",
                ],
                "unknowns": ["Seasonal baseline", "operating-state baseline", "location-specific baseline"],
                "falsification_conditions": [
                    "Context-matched baseline shows measurement within normal variation.",
                    "Repeated observations show same pattern under known ordinary conditions.",
                ],
            }
        )

    if issues:
        hypotheses.append(
            {
                "hypothesis_set_id": "HSET-GLOBAL",
                "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
                "statement": "Validation issues materially weaken all measurement interpretations.",
                "support": issues[:10],
                "opposition": ["No independent clean source supplied yet."],
                "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
            }
        )

    return hypotheses


def dual_ai_review(
    measurements: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary MASINT Analyst",
        "assessment": (
            "Measurable physical observations and/or derived fusion products exist."
            if measurements or fused
            else "No usable measurements were supplied."
        ),
        "classification": "Signature/classification conclusions remain conservative and evidence-bounded.",
    }

    if not measurements and not fused:
        skeptic = {
            "role": "Independent Scientific Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No deterministic measurements were supplied. Do not infer physical phenomena from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Scientific Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Scientific Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions must be preserved; do not silently resolve sensor conflicts.",
        }
    elif fused and any(f.get("source_independence") == "INDEPENDENT" for f in fused):
        skeptic = {
            "role": "Independent Scientific Skeptic",
            "verdict": "AGREE_ON_PHYSICAL_OBSERVATION_ONLY",
            "reason": "Independent multi-sensor support may justify physical observation assessment only, not source attribution or weapon/targeting use.",
        }
    else:
        skeptic = {
            "role": "Independent Scientific Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Single-source or incomplete evidence supports candidate observations only.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not sensor corroboration. Human review required for consequential conclusions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    sensors: Dict[str, Dict[str, Any]],
    measurements: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    features: List[Dict[str, Any]],
    signatures: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
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

    for sid, s in sensors.items():
        add_node(sid, "Sensor", public_dict(s))

    for m in measurements + fused:
        mid = m.get("measurement_id")
        add_node(
            mid,
            "Measurement",
            {
                "phenomenon": m.get("phenomenon"),
                "sensor_id": m.get("sensor_id"),
                "sensor_ids": m.get("sensor_ids"),
                "value": m.get("_value_norm"),
                "unit": m.get("_unit_norm"),
                "uncertainty": m.get("_unc_norm"),
                "timestamp": iso_or_none(m.get("_timestamp") or m.get("_start")),
                "processing_level": m.get("_processing_level"),
                "quality_flags": m.get("_quality_flags"),
                "source_independence": m.get("source_independence"),
            },
        )
        if m.get("sensor_id"):
            add_edge(mid, m["sensor_id"], "MEASURED_BY", {"measurement_id": mid})
        for sid in m.get("sensor_ids") or []:
            add_edge(mid, sid, "MEASURED_BY", {"measurement_id": mid, "fused_input": True})
        if m.get("phenomenon"):
            pid = f"PHEN:{m['phenomenon']}"
            add_node(pid, "Phenomenon", {"name": m["phenomenon"]})
            add_edge(mid, pid, "OBSERVED_PHENOMENON", {"measurement_id": mid})

    for f in features:
        fid = f.get("feature_id")
        add_node(fid, "Feature", f)

    for s in signatures:
        sid = s.get("signature_id")
        add_node(sid, "Signature", s)
        if s.get("measurement_id"):
            add_edge(sid, s["measurement_id"], "DERIVED_FROM", {"signature_id": sid})

    for a in anomalies:
        aid = f"ANOM-{a.get('measurement_id')}"
        add_node(
            aid,
            "Anomaly",
            {
                "measurement_id": a.get("measurement_id"),
                "state": a.get("anomaly_state"),
                "z_score": a.get("z_score"),
                "confidence": a.get("confidence"),
            },
        )
        if a.get("measurement_id"):
            add_edge(aid, a["measurement_id"], "BASED_ON", {"anomaly_id": aid})

    for fac in facts:
        fid = fac.get("fact_id")
        add_node(fid, "Fact", fac)
        if fac.get("measurement_id"):
            add_edge(fid, fac["measurement_id"], "SUPPORTED_BY", {"fact_id": fid})

    for h in hypotheses:
        hid = h.get("hypothesis_id")
        add_node(hid, "Hypothesis", h)

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
    measurements: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
    sensors: Dict[str, Dict[str, Any]],
    baselines: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not measurements and not fused:
        gaps.append(
            {
                "gap_id": "GAP-NO-MEASUREMENTS",
                "gap": "No deterministic measurements supplied",
                "importance": "HIGH",
                "recommended_source": "Authorized sensor export with calibration and uncertainty",
                "expected_information_value": "Establishes whether any physical phenomenon is measurable",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Input validation issues present",
                "importance": "HIGH",
                "recommended_source": "Corrected sensor metadata, calibration records, unit definitions",
                "expected_information_value": "Improves measurement trust",
            }
        )

    unknown_cal = [sid for sid, s in sensors.items() if s.get("_calibration_status") in ("CALIBRATION_UNKNOWN", "UNCALIBRATED", "CALIBRATION_EXPIRED")]
    if unknown_cal:
        gaps.append(
            {
                "gap_id": "GAP-CALIBRATION",
                "gap": f"Calibration insufficient for sensors: {', '.join(unknown_cal)}",
                "importance": "HIGH",
                "recommended_source": "Calibration certificate / traceable reference measurement",
                "expected_information_value": "Allows stronger quantitative interpretation",
            }
        )

    if not baselines:
        gaps.append(
            {
                "gap_id": "GAP-BASELINE",
                "gap": "No baselines supplied",
                "importance": "MODERATE",
                "recommended_source": "Historical/context-matched measurement baseline",
                "expected_information_value": "Enables anomaly discrimination",
            }
        )

    if any(a.get("anomaly_state") in {"SIGNIFICANT_DEVIATION", "ANOMALY_SUPPORTED", "ANOMALY_DISPUTED"} for a in anomalies):
        gaps.append(
            {
                "gap_id": "GAP-ANOMALY-CORROBORATION",
                "gap": "Anomalous measurement requires independent corroboration",
                "importance": "HIGH",
                "recommended_source": "Independent sensor / different phenomenology",
                "expected_information_value": "Reduces false detection/classification risk",
            }
        )

    if contradictions:
        gaps.append(
            {
                "gap_id": "GAP-CONTRADICTIONS",
                "gap": "Material contradictions present",
                "importance": "HIGH",
                "recommended_source": "Raw sensor records, calibration logs, processing provenance",
                "expected_information_value": "Prevents silent false resolution",
            }
        )

    if not any(m.get("environmental_context") for m in measurements):
        gaps.append(
            {
                "gap_id": "GAP-ENVIRONMENT",
                "gap": "Environmental context missing for many measurements",
                "importance": "MODERATE",
                "recommended_source": "Weather, terrain, operating-state, background records",
                "expected_information_value": "Supports alternative-explanation testing",
            }
        )

    gaps.append(
        {
            "gap_id": "GAP-SOURCE-IDENTITY",
            "gap": "Source identity unresolved by design unless stronger evidence exists",
            "importance": "CONTEXTUAL",
            "recommended_source": "TECHINT / authorized equipment records / independent phenomenology",
            "expected_information_value": "MASINT alone rarely establishes attribution",
        }
    )

    return gaps


def build_next_actions(
    measurements: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not measurements and not fused:
        actions.append("Supply deterministic authorized sensor exports with units, timestamps, uncertainty, and calibration metadata")

    if any(g["gap_id"] == "GAP-CALIBRATION" for g in gaps):
        actions.append("Obtain calibration record or recalibrate sensor before high-confidence interpretation")

    if any(g["gap_id"] == "GAP-BASELINE" for g in gaps):
        actions.append("Build context-matched baseline from historical comparable measurements")

    if any(g["gap_id"] == "GAP-ANOMALY-CORROBORATION" for g in gaps):
        actions.append("Seek independent sensor or different phenomenology to corroborate anomaly")

    if contradictions:
        actions.append("Preserve contradictions and inspect raw sensor/processing provenance before resolution")

    if fused:
        actions.append("Review fused derived products separately from raw measurements")

    actions.append("Maintain lawful defensive posture; no weapon design, targeting, CBRN development, sensor evasion, jamming, spoofing, or private tracking")

    return actions


def build_specialist_handoffs(
    measurements: List[Dict[str, Any]],
    fused: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if measurements or fused:
        handoffs.append(
            {
                "to": "GEOINT",
                "reason": "Location/terrain/spatial registration may require broader geospatial validation",
                "restrictions": ["No private-person location", "No targeting coordinates"],
            }
        )
        handoffs.append(
            {
                "to": "TECHINT",
                "reason": "Equipment/product identity exceeds signature similarity alone",
                "restrictions": ["No weapon design", "No countermeasure optimization"],
            }
        )

    if any(str(m.get("phenomenon", "")).lower().find("electromagnetic") >= 0 for m in measurements + fused):
        handoffs.append(
            {
                "to": "SIGINT / ELINT",
                "reason": "Electronic emitter/signal questions require specialized authorized disciplines",
                "restrictions": ["No jamming", "No spoofing", "No ECM design"],
            }
        )

    if any(a.get("anomaly_state") in {"SIGNIFICANT_DEVIATION", "ANOMALY_SUPPORTED", "ANOMALY_DISPUTED"} for a in anomalies):
        handoffs.append(
            {
                "to": "INCIDENTINT",
                "reason": "Anomalous physical measurement may require incident/safety review",
                "restrictions": ["No attack planning", "No hazardous intervention without authorized responders"],
            }
        )

    if contradictions:
        handoffs.append(
            {
                "to": "SCIENTIFIC_SUPERVISOR / QUALITY_SUPERVISOR",
                "reason": "Contradictions and measurement-quality disputes require expert review",
                "restrictions": ["Do not force resolution", "Preserve uncertainty"],
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

    anomalies = r.get("anomalies") or []
    fused = r.get("multisensor_fusion") or []
    measurements = r.get("measurements") or []

    lines = [
        "PHENOMENON: " + fmt_list(sorted({m.get("phenomenon") for m in measurements if m.get("phenomenon")})),
        "SENSOR / PLATFORM: " + fmt_list(r.get("sensor_ids")),
        "MEASUREMENT COUNT: " + str(len(measurements)),
        "UNIT: " + fmt_list(sorted({m.get("unit") for m in measurements if m.get("unit")})),
        "CALIBRATION STATUS: " + fmt_list([f"{k}={v}" for k, v in (r.get("sensor_status") or {}).items()]),
        "QUALITY FLAGS: " + fmt_list(sorted({flag for m in measurements for flag in (m.get("quality_flags") or [])})),
        "UNCERTAINTY: " + json.dumps(r.get("uncertainty") or {}, default=str),
        "DETECTION LIMIT: " + fmt_list([m.get("detection_limit") for m in measurements if m.get("detection_limit") is not None]),
        "TIME RANGE: " + str(r.get("time_range")),
        "LOCATION / FOOTPRINT: " + fmt_list(sorted({m.get("spatial_cluster_id") for m in measurements if m.get("spatial_cluster_id")})),
        "ENVIRONMENTAL CONDITIONS: " + fmt_list([m.get("environmental_context") for m in measurements if m.get("environmental_context")]),
        "BASELINE: " + fmt_list([a.get("baseline_id") for a in anomalies if a.get("baseline_id")]),
        "ANOMALY STATUS: " + fmt_list([f"{a.get('measurement_id')}={a.get('anomaly_state')}" for a in anomalies]),
        "FEATURES: " + str(len(r.get("features") or [])),
        "SIGNATURE: " + str(len(r.get("signatures") or [])),
        "REFERENCE MATCHES: " + fmt_list([f"{m.get('reference_signature_id')}={m.get('match_state')}" for m in (r.get("signature_matches") or [])]),
        "ALTERNATIVE EXPLANATIONS: " + str(len(r.get("hypotheses") or [])),
        "MULTI-SENSOR SUPPORT: " + fmt_list([f"{f.get('measurement_id')}={f.get('source_independence')}" for f in fused]),
        "CLASSIFICATION: " + fmt_list(r.get("classifications")),
        "IDENTIFICATION STATUS: " + fmt_list(r.get("identification_candidates")),
        "CONTRADICTIONS: " + str(len(r.get("contradictions") or [])),
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

    sensors, sensor_issues = validate_sensors(case)
    measurements, meas_issues, meas_warnings = validate_measurements(case, sensors)
    issues = sensor_issues + meas_issues

    settings_raw = case.get("analysis_settings") or {}

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    settings = {
        "spatial_cluster_distance_km": setting_float("spatial_cluster_distance_km", 1.0),
        "fusion_time_window_s": setting_float("fusion_time_window_s", 300.0),
        "conflict_sigma": setting_float("conflict_sigma", 3.0),
        "signature_similarity_threshold": setting_float("signature_similarity_threshold", 0.80),
    }

    # Spatial clustering before fusion/features
    spatial_clusters = build_spatial_clusters(measurements, settings["spatial_cluster_distance_km"])

    baselines = normalize_baselines(case)

    # Anomaly analysis for raw measurements
    anomalies = [analyze_anomaly(m, baselines) for m in measurements]

    # Features
    features = build_features(measurements)

    # Signatures and reference matching
    reference_signatures = case.get("reference_signatures") or []
    signatures, signature_matches = build_signatures_and_matches(
        measurements,
        reference_signatures,
        settings["signature_similarity_threshold"],
    )

    # Multi-sensor fusion
    fused, fusion_contradictions = fuse_measurements(measurements, sensors, settings)

    # Analyze fused products against baselines too
    fused_anomalies = [analyze_anomaly(f, baselines) for f in fused]
    anomalies.extend(fused_anomalies)

    # Contradictions
    contradictions = list(case.get("existing_contradictions") or [])
    contradictions.extend(fusion_contradictions)
    contradictions.extend(
        detect_additional_contradictions(
            measurements,
            fused,
            signatures,
            signature_matches,
            sensors,
            settings["signature_similarity_threshold"],
        )
    )

    # Mark disputed anomalies if contradictions involve their measurement
    disputed_ids = {c.get("measurement_id") for c in contradictions if c.get("measurement_id")}
    for a in anomalies:
        if a.get("measurement_id") in disputed_ids and a.get("anomaly_state") not in ("UNKNOWN", "WITHIN_BASELINE"):
            a["anomaly_state"] = "ANOMALY_DISPUTED"
            a["confidence"] = "LOW"
            a.setdefault("notes", []).append("Contradiction affects this measurement; anomaly disputed.")

    supported_facts, candidate_facts, partial_facts, disputed_facts, not_facts = build_facts(
        measurements,
        fused,
        anomalies,
        signature_matches,
        contradictions,
    )

    hypotheses = build_hypotheses(anomalies, fused, measurements, contradictions, issues)
    dual = dual_ai_review(measurements, fused, anomalies, contradictions, issues)

    gaps = build_knowledge_gaps(
        measurements,
        fused,
        anomalies,
        contradictions,
        issues,
        sensors,
        baselines,
    )
    next_actions = build_next_actions(measurements, fused, anomalies, gaps, contradictions)
    handoffs = build_specialist_handoffs(measurements, fused, anomalies, contradictions)

    graph = build_graph(
        sensors,
        measurements,
        fused,
        features,
        signatures,
        anomalies,
        supported_facts + candidate_facts + partial_facts,
        hypotheses,
        contradictions,
        gaps,
    )

    # Summaries
    sensor_status = {sid: s.get("_calibration_status", "CALIBRATION_UNKNOWN") for sid, s in sensors.items()}

    measurement_public = []
    for m in measurements + fused:
        measurement_public.append(
            {
                "measurement_id": m.get("measurement_id"),
                "sensor_id": m.get("sensor_id"),
                "sensor_ids": m.get("sensor_ids"),
                "phenomenon": m.get("phenomenon"),
                "original_value": m.get("_original_value") if m.get("_original_value") is not None else m.get("value"),
                "original_unit": m.get("_original_unit") or m.get("unit"),
                "value": m.get("_value_norm"),
                "unit": m.get("_unit_norm"),
                "dimension": m.get("_dimension"),
                "uncertainty": m.get("_unc_norm"),
                "detection_limit": m.get("_detection_limit_norm"),
                "detection_state": m.get("_detection_state"),
                "timestamp": iso_or_none(m.get("_timestamp") or m.get("_start")),
                "start_time": iso_or_none(m.get("_start")),
                "end_time": iso_or_none(m.get("_end")),
                "duration_s": m.get("_duration_s"),
                "location": {
                    "latitude": m.get("_lat"),
                    "longitude": m.get("_lon"),
                    "accuracy_m": m.get("_location_accuracy_m"),
                    "area_id": m.get("_area_id"),
                    "spatial_cluster_id": m.get("_spatial_cluster_id"),
                },
                "quality_flags": m.get("_quality_flags"),
                "processing_level": m.get("_processing_level"),
                "environmental_context": m.get("environmental_context"),
                "source_ids": m.get("_source_ids"),
                "evidence_ids": m.get("_evidence_ids"),
                "calibration_reference": m.get("calibration_reference"),
                "classification_candidate": m.get("classification_candidate"),
                "source_independence": m.get("source_independence"),
                "fusion_method": m.get("fusion_method"),
                "contributing_measurement_ids": m.get("contributing_measurement_ids"),
                "confidence": measurement_confidence(m),
                "limitations": m.get("limitations") or [
                    "Measurement value is only as reliable as supplied sensor metadata and processing provenance."
                ],
            }
        )

    units_used = sorted({m.get("_unit_norm") for m in measurements + fused if m.get("_unit_norm")})
    dimensions_used = sorted({m.get("_dimension") for m in measurements + fused if m.get("_dimension") and m.get("_dimension") != "UNKNOWN"})

    uncertainty_summary = {
        "measurements_with_uncertainty": sum(1 for m in measurements + fused if m.get("_unc_norm") is not None),
        "measurements_without_uncertainty": sum(1 for m in measurements + fused if m.get("_unc_norm") is None),
        "note": "Missing uncertainty reduces confidence; do not infer precision from display resolution.",
    }

    detection_limits = [m.get("_detection_limit_norm") for m in measurements + fused if m.get("_detection_limit_norm") is not None]

    coverage = {
        "measurement_count": len(measurements),
        "fused_product_count": len(fused),
        "sensor_count": len(sensors),
        "spatial_clusters": len(spatial_clusters),
        "time_range": {
            "start": iso_or_none(min((m.get("_timestamp") for m in measurements if m.get("_timestamp")), default=None)),
            "end": iso_or_none(max((m.get("_timestamp") for m in measurements if m.get("_timestamp")), default=None)),
        },
        "limitations": [
            "Coverage is limited to supplied measurements.",
            "Non-detection outside coverage is not absence.",
        ],
    }

    classifications = sorted(
        {
            str(m.get("classification_candidate")).upper()
            for m in measurements + fused
            if m.get("classification_candidate")
        }
    )

    identification_candidates = []
    for match in signature_matches:
        if match.get("match_state") == "CLASS_CANDIDATE":
            identification_candidates.append(
                {
                    "candidate_id": f"IDCAND-{len(identification_candidates) + 1}",
                    "signature_id": match.get("signature_id"),
                    "reference_class": match.get("reference_class"),
                    "state": "CLASS_CANDIDATE",
                    "confidence": "LOW_TO_MODERATE",
                    "limitation": "Not exact source identification; requires stronger independent evidence.",
                }
            )

    temporal_correlations = []
    spatial_correlations = []

    # Simple co-occurrence by phenomenon/spatial cluster/time segment
    by_phen_sp = defaultdict(list)
    for m in measurements:
        if m.get("_timestamp") is None:
            continue
        by_phen_sp[(m.get("phenomenon"), m.get("_spatial_cluster_id"))].append(m)

    for (phen, sp), items in by_phen_sp.items():
        if len(items) < 2:
            continue
        times = sorted([x.get("_timestamp") for x in items if x.get("_timestamp")])
        if len(times) >= 2:
            span = (times[-1] - times[0]).total_seconds()
            temporal_correlations.append(
                {
                    "phenomenon": phen,
                    "spatial_cluster_id": sp,
                    "observation_count": len(items),
                    "time_span_s": span,
                    "note": "Temporal co-occurrence only; not causality.",
                }
            )
            spatial_correlations.append(
                {
                    "phenomenon": phen,
                    "spatial_cluster_id": sp,
                    "observation_count": len(items),
                    "note": "Spatial co-location within supplied clustering threshold; not source identity.",
                }
            )

    multisensor_fusion_public = []
    for f in fused:
        multisensor_fusion_public.append(
            {
                "measurement_id": f.get("measurement_id"),
                "phenomenon": f.get("phenomenon"),
                "sensor_ids": f.get("sensor_ids"),
                "value": f.get("_value_norm"),
                "unit": f.get("_unit_norm"),
                "uncertainty": f.get("_unc_norm"),
                "source_independence": f.get("source_independence"),
                "fusion_method": f.get("fusion_method"),
                "contributing_measurement_ids": f.get("contributing_measurement_ids"),
                "quality_flags": f.get("_quality_flags"),
                "limitations": f.get("limitations"),
            }
        )

    source_reliability = []
    for sid, s in sensors.items():
        status = s.get("_calibration_status", "CALIBRATION_UNKNOWN")
        if status == "CALIBRATED":
            rel = "HIGH"
        elif status in ("DEGRADED", "PARTIALLY_CALIBRATED"):
            rel = "MODERATE"
        elif status in ("UNCALIBRATED", "CALIBRATION_EXPIRED", "CALIBRATION_UNKNOWN"):
            rel = "LOW"
        else:
            rel = "UNKNOWN"
        source_reliability.append(
            {
                "sensor_id": sid,
                "sensor_type": s.get("sensor_type"),
                "platform": s.get("platform"),
                "calibration_status": status,
                "reliability": rel,
                "known_limitations": s.get("known_limitations"),
                "independence_group": s.get("independence_group"),
                "upstream_sensor_id": s.get("upstream_sensor_id"),
            }
        )

    source_independence_overall = "UNKNOWN"
    if fused:
        states = {f.get("source_independence") for f in fused}
        if "INDEPENDENT" in states:
            source_independence_overall = "INDEPENDENT_OBSERVATION_AVAILABLE"
        elif "DEPENDENT_OR_UNKNOWN" in states:
            source_independence_overall = "DEPENDENT_OR_UNKNOWN"
        elif "PARTIALLY_DEPENDENT" in states:
            source_independence_overall = "PARTIALLY_DEPENDENT"
    elif len(sensors) > 1:
        source_independence_overall = "MULTI_SENSOR_NOT_FUSED"
    elif sensors:
        source_independence_overall = "SINGLE_SENSOR"

    unknowns: List[str] = []
    if not measurements:
        unknowns.append("No measurable physical activity supplied")
    if not baselines:
        unknowns.append("Baseline unresolved")
    if any(m.get("_dimension") == "UNKNOWN" for m in measurements):
        unknowns.append("Unit/dimension unresolved for some measurements")
    if not fused:
        unknowns.append("Independent multi-sensor corroboration unavailable")
    unknowns.append("Source identity unresolved by design unless stronger evidence exists")
    unknowns.append("Operator/attribution unresolved")

    if contradictions:
        status = "SENSOR_CONFLICT"
    elif issues:
        status = "PARTIAL"
    elif not measurements:
        status = "INCONCLUSIVE"
    elif fused and any(f.get("source_independence") == "INDEPENDENT" for f in fused):
        status = "PARTIAL"
    else:
        status = "PARTIAL"

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "sensor_ids": list(sensors.keys()),
        "sensor_types": sorted({str(s.get("sensor_type")) for s in sensors.values() if s.get("sensor_type")}),
        "sensor_platforms": sorted({str(s.get("platform")) for s in sensors.values() if s.get("platform")}),
        "sensor_status": sensor_status,
        "calibration_records": case.get("calibration_records") or [
            {
                "sensor_id": sid,
                "calibration_status": s.get("_calibration_status"),
                "calibration_date": s.get("calibration_date"),
                "calibration_reference": s.get("calibration_reference"),
                "valid_from": s.get("valid_from"),
                "valid_to": s.get("valid_to"),
            }
            for sid, s in sensors.items()
        ],
        "measurements": measurement_public,
        "measurement_series": features,
        "units": units_used,
        "dimensions": dimensions_used,
        "uncertainty": uncertainty_summary,
        "detection_limits": numeric_summary(detection_limits),
        "coverage": coverage,
        "quality_flags": sorted({flag for m in measurements + fused for flag in (m.get("_quality_flags") or [])}),
        "environmental_context": [
            {
                "measurement_id": m.get("measurement_id"),
                "environmental_context": m.get("environmental_context"),
            }
            for m in measurements
            if m.get("environmental_context")
        ],
        "processing_levels": sorted({m.get("_processing_level") for m in measurements + fused if m.get("_processing_level")}),
        "features": features,
        "signatures": signatures,
        "reference_signatures": [public_dict(r) for r in reference_signatures if isinstance(r, dict)],
        "signature_matches": signature_matches,
        "spectral_context": [f.get("spectral_features") for f in features if f.get("spectral_features")],
        "thermal_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("thermal") >= 0],
        "infrared_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("infrared") >= 0],
        "multispectral_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("multispectral") >= 0],
        "hyperspectral_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("hyperspectral") >= 0],
        "acoustic_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("acoustic") >= 0],
        "hydroacoustic_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("hydroacoustic") >= 0],
        "seismic_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("seismic") >= 0],
        "vibration_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("vibration") >= 0],
        "electromagnetic_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("electromagnetic") >= 0],
        "radar_measurement_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("radar") >= 0],
        "radiometric_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("radiometric") >= 0],
        "radiological_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("radiolog") >= 0],
        "chemical_sensor_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("chemical") >= 0],
        "biological_sensor_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("biolog") >= 0],
        "material_context": [m.get("material_candidate") for m in measurements if m.get("material_candidate")],
        "geophysical_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("geophys") >= 0],
        "lidar_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("lidar") >= 0],
        "motion_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("motion") >= 0],
        "industrial_context": [m for m in measurement_public if str(m.get("phenomenon", "")).lower().find("industrial") >= 0],
        "detections": [
            {
                "measurement_id": m.get("measurement_id"),
                "detection_state": m.get("_detection_state"),
                "phenomenon": m.get("phenomenon"),
                "confidence": measurement_confidence(m),
            }
            for m in measurements + fused
        ],
        "anomalies": anomalies,
        "classifications": classifications,
        "identification_candidates": identification_candidates,
        "sensor_independence": source_independence_overall,
        "temporal_correlations": temporal_correlations,
        "spatial_correlations": spatial_correlations,
        "multisensor_fusion": multisensor_fusion_public,
        "observations": measurement_public,
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "source_reliability": source_reliability,
        "source_bias": case.get("source_bias") or [
            "Sensor coverage may be geographic, spectral, temporal, or resolution biased.",
            "Provider filtering can create apparent absence.",
            "Reference libraries may be incomplete or condition-dependent.",
        ],
        "source_limitations": case.get("source_limitations") or [
            "Non-detection is not absence.",
            "Calibration reduces systematic uncertainty but does not eliminate noise.",
            "Derived fusion products are not raw measurements.",
        ],
        "source_pedigree": case.get("source_pedigree") or [
            {
                "sensor_id": sid,
                "platform": s.get("platform"),
                "upstream_sensor_id": s.get("upstream_sensor_id"),
                "independence_group": s.get("independence_group"),
                "processor_id": s.get("processor_id"),
                "calibration_reference": s.get("calibration_reference"),
            }
            for sid, s in sensors.items()
        ],
        "contradictions": contradictions,
        "hypotheses": hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.get("hypothesis_id"),
                "status": "WEAKENED_BY_CONTRADICTIONS" if contradictions else "NOT_FALSIFIED_WITH_CURRENT_EVIDENCE",
                "required_additional_evidence": [
                    "Independent sensor",
                    "Calibration record",
                    "Environmental context",
                    "Context-matched baseline",
                    "Processing provenance",
                ],
            }
            for h in hypotheses
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not perform live sensing or fetch data.",
            "It consumes deterministic measurement records only.",
            "It does not invent measurements, calibration, uncertainty, signatures, or sources.",
            "It separates measurement, detection, classification, identification, and attribution.",
            "It blocks weapon design, targeting, CBRN development, sensor evasion, jamming, spoofing, and private tracking.",
            "Derived fusion products are labeled as DERIVED_PRODUCT, not raw observations.",
        ],
        "safety_flags": [
            "NO_WEAPON_DESIGN",
            "NO_TARGETING",
            "NO_FIRE_CONTROL",
            "NO_CBRN_DEVELOPMENT",
            "NO_SENSOR_EVASION",
            "NO_STEALTH_OPTIMIZATION",
            "NO_JAMMING",
            "NO_SPOOFING",
            "NO_ELECTRONIC_COUNTERMEASURE_DESIGN",
            "NO_PRIVATE_PERSON_TRACKING",
        ],
        "privacy_flags": [
            "NO_BIOMETRIC_GAIT_IDENTIFICATION",
            "NO_PERSONAL_THERMAL_TRACKING",
            "NO_PRIVATE_RESIDENCE_MONITORING",
            "METADATA_MINIMIZATION",
        ],
        "dual_ai_review": dual,
        "not_facts": not_facts,
        "graphical_memory": graph,
        "validation_issues": issues,
        "validation_warnings": meas_warnings,
        "analysis_settings": settings,
        "replay_manifest": {
            "generated_at": started,
            "finished_at": utcnow_iso(),
            "code_version": VERSION,
            "input_path": input_path,
            "input_sha256": input_hash,
            "deterministic_operations": [
                "unit normalization",
                "timestamp normalization",
                "sensor validity checks",
                "quality flagging",
                "baseline z-score anomaly analysis",
                "time-series feature statistics",
                "linear trend regression",
                "spectral feature extraction from supplied bands",
                "cosine similarity signature matching",
                "spatial clustering",
                "inverse-variance or dispersion-based fusion",
                "source independence summarization",
                "contradiction detection",
                "fact gate",
            ],
            "note": "Replay requires raw measurement references, sensor configuration eras, calibration certificates, processing algorithms/versions, filter parameters, reference library versions, and source pedigree.",
        },
    }

    result["time_range"] = result["coverage"]["time_range"]
    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": "Placeholders only. Replace with deterministic authorized/public measurement exports. Do not treat this template as real measurement.",
        "case_id": "CASE-MASINT-EXAMPLE",
        "task_id": "TASK-MASINT-EXAMPLE",
        "objective": "Authorized defensive analysis of an industrial thermal/acoustic signature for safety and maintenance context.",
        "questions": [
            "What physical phenomenon was measured?",
            "Is the observation above context-matched baseline?",
            "Do independent sensors corroborate it?",
            "What alternative explanations remain?",
            "What is unresolved?",
        ],
        "scope": {
            "authorized_only": True,
            "defensive_only": True,
            "lawful_only": True,
            "metadata_minimization": True,
            "no_weapon_design": True,
            "no_targeting": True,
            "no_cbrn_development": True,
            "no_sensor_evasion": True,
            "no_private_person_tracking": True,
        },
        "authorization": {
            "lawful_basis": "AUTHORIZED_INDUSTRIAL_SAFETY_MONITORING",
            "purpose": "DEFENSIVE_MEASUREMENT_AND_SIGNATURE_INTELLIGENCE",
            "approval_reference": "AUTH-MASINT-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "analysis_settings": {
            "spatial_cluster_distance_km": 1.0,
            "fusion_time_window_s": 300,
            "conflict_sigma": 3.0,
            "signature_similarity_threshold": 0.8,
        },
        "sensors": [
            {
                "sensor_id": "THERM-1",
                "sensor_type": "THERMAL_IMAGER",
                "sensor_model": "EXAMPLE_THERMAL",
                "platform": "FIXED_GROUND",
                "location": {"latitude": 0.0, "longitude": 0.0, "accuracy_m": 10, "area_id": "PLANT_ZONE_A"},
                "calibration_status": "CALIBRATED",
                "calibration_date": "2026-09-01T00:00:00Z",
                "calibration_reference": "CAL-REC-001",
                "valid_from": "2026-09-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "dynamic_range": {"min": 250.0, "max": 1000.0, "unit": "K"},
                "detection_limit": 0.5,
                "detection_limit_unit": "K",
                "independence_group": "THERM_GROUP_A",
                "known_limitations": ["Emissivity assumptions affect absolute temperature."],
            },
            {
                "sensor_id": "ACOU-1",
                "sensor_type": "ACOUSTIC_SENSOR",
                "sensor_model": "EXAMPLE_ACOUSTIC",
                "platform": "FIXED_GROUND",
                "location": {"latitude": 0.001, "longitude": 0.001, "accuracy_m": 10, "area_id": "PLANT_ZONE_A"},
                "calibration_status": "CALIBRATED",
                "calibration_date": "2026-09-15T00:00:00Z",
                "calibration_reference": "CAL-REC-002",
                "valid_from": "2026-09-15T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "dynamic_range": {"min": 0.0, "max": 140.0, "unit": "dB"},
                "independence_group": "ACOU_GROUP_B",
                "known_limitations": ["Wind and background machinery affect acoustic spectrum."],
            },
        ],
        "measurements": [
            {
                "measurement_id": "MEAS-T-1",
                "sensor_id": "THERM-1",
                "phenomenon": "thermal_radiance_temperature",
                "value": 350.0,
                "unit": "K",
                "uncertainty": 1.2,
                "timestamp": "2026-10-08T09:00:00Z",
                "duration": 60,
                "duration_unit": "s",
                "location": {"latitude": 0.0, "longitude": 0.0, "area_id": "PLANT_ZONE_A"},
                "detection_state": "DETECTED",
                "processing_level": "CALIBRATED",
                "environmental_context": {"ambient_temperature_C": 20, "wind_speed_m_s": 2, "solar_load": "LOW"},
                "source_id": "SRC-THERM-1",
                "evidence_id": "EVD-THERM-1",
                "quality_flags": [],
            },
            {
                "measurement_id": "MEAS-A-1",
                "sensor_id": "ACOU-1",
                "phenomenon": "acoustic_pressure_level",
                "value": 82.0,
                "unit": "dB",
                "uncertainty": 1.5,
                "timestamp": "2026-10-08T09:00:30Z",
                "duration": 60,
                "duration_unit": "s",
                "location": {"latitude": 0.001, "longitude": 0.001, "area_id": "PLANT_ZONE_A"},
                "detection_state": "DETECTED",
                "processing_level": "FILTERED",
                "environmental_context": {"ambient_temperature_C": 20, "wind_speed_m_s": 2},
                "source_id": "SRC-ACOU-1",
                "evidence_id": "EVD-ACOU-1",
                "feature_vector": [82.0, 120.0, 250.0, 500.0, 1000.0],
                "quality_flags": [],
            },
        ],
        "baselines": [
            {
                "baseline_id": "BASE-THERM-A",
                "phenomenon": "thermal_radiance_temperature",
                "sensor_id": "THERM-1",
                "area_id": "PLANT_ZONE_A",
                "mean": 315.0,
                "std": 5.0,
                "uncertainty": 0.8,
                "unit": "K",
                "sample_size": 100,
                "valid_from": "2026-09-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
            },
            {
                "baseline_id": "BASE-ACOU-A",
                "phenomenon": "acoustic_pressure_level",
                "sensor_id": "ACOU-1",
                "area_id": "PLANT_ZONE_A",
                "mean": 72.0,
                "std": 3.0,
                "uncertainty": 0.5,
                "unit": "dB",
                "sample_size": 100,
                "valid_from": "2026-09-15T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
            },
        ],
        "reference_signatures": [
            {
                "reference_signature_id": "REF-INDUSTRIAL-FAN-CLASS",
                "class_label": "ROTATING_MACHINERY_CLASS_CANDIDATE",
                "feature_vector": [80.0, 118.0, 245.0, 495.0, 990.0],
                "collection_conditions": "Example authorized industrial reference; not exact device identity.",
                "limitations": ["Reference may vary with load, maintenance, and environment."],
            }
        ],
        "sources": [
            {
                "source_id": "SRC-THERM-1",
                "provider": "AUTHORIZED_PLANT_MONITORING",
                "source_type": "AUTHORIZED_SENSOR_EXPORT",
                "upstream_feed": "THERM_NETWORK_A",
                "limitations": ["Fixed sensor coverage only."],
            },
            {
                "source_id": "SRC-ACOU-1",
                "provider": "AUTHORIZED_PLANT_MONITORING",
                "source_type": "AUTHORIZED_SENSOR_EXPORT",
                "upstream_feed": "ACOUSTIC_NETWORK_B",
                "limitations": ["Acoustic propagation affected by wind and structures."],
            },
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
            "TRACEATLAS MASINT lawful defensive measurement/signature scaffold. "
            "Consumes deterministic measurement records; does not fetch live data, "
            "invent measurements, design weapons, target, develop CBRN, evade sensors, jam, spoof, or track private persons."
        )
    )
    parser.add_argument("--input", "-i", help="Path to MASINT input JSON")
    parser.add_argument("--output", "-o", default="masint_result.json", help="Output MASINTResult JSON path")
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