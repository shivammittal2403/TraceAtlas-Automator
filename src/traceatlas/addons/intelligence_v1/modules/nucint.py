#!/usr/bin/env python3
"""
TRACEATLAS NUCINT main.py
=========================

Defensive, authorized, evidence-first, non-proliferation-aligned nuclear /
radiological signature intelligence scaffold.

This module:
- Does NOT fetch live sensor data.
- Does NOT invent radionuclides, measurements, samples, lab results, facility
  activity, nuclear events, or source attribution.
- Does NOT design or optimize nuclear weapons.
- Does NOT provide yield, critical-mass, implosion, initiator, detonation,
  enrichment, centrifuge, separative-work, reprocessing, or weapons-material
  production guidance.
- Does NOT provide radiological dispersal device construction guidance.
- Does NOT provide detector evasion, portal-monitor bypass, shielding for
  concealment, smuggling, covert transport, sabotage, or targeting guidance.
- Does NOT provide unauthorized sampling or sensor-bypass actions.

It consumes deterministic records supplied by authorized/public sources:
- radiation sensor metadata
- calibration context
- count-rate / dose-rate / activity / concentration measurements
- gamma/neutron spectral feature metadata, if supplied by deterministic tools
- environmental sample records
- chain-of-custody metadata
- laboratory results
- background / baseline records
- facility declarations and public regulatory context
- official reports
- weather / atmospheric transport context, at high level
- seismic / satellite correlation context, at high level
- source pedigree / independence metadata

It produces an evidence-linked NUCINTResult with:
- measurement validation
- calibration / quality flags
- background / baseline anomaly analysis
- radionuclide candidate handling without overclaiming
- source-class candidates
- facility association uncertainty
- environmental release candidate assessment
- multi-sensor / sample / lab correlation
- source independence checks
- contradiction preservation
- competing benign hypotheses
- falsification conditions
- dual-AI style skeptic review
- safety / legal flags
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

ALLOWED_CALIBRATION = {
    "CALIBRATED",
    "PARTIALLY_CALIBRATED",
    "UNCALIBRATED",
    "CALIBRATION_UNKNOWN",
    "CALIBRATION_EXPIRED",
    "DEGRADED",
    "OFFLINE",
    "UNKNOWN",
}

ALLOWED_QUANTITY_TYPES = {
    "COUNT",
    "COUNT_RATE",
    "ACTIVITY",
    "CONCENTRATION",
    "DOSE",
    "DOSE_RATE",
    "ENERGY",
    "RATIO",
    "OTHER",
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
    "WITHIN_EXPECTED_BACKGROUND",
    "MINOR_DEVIATION",
    "MATERIAL_DEVIATION",
    "SIGNATURE_OF_INTEREST",
    "UNKNOWN",
}

RELEASE_STATES = {
    "RELEASE_CONFIRMED",
    "RELEASE_SUPPORTED",
    "RELEASE_CANDIDATE",
    "BACKGROUND_VARIATION",
    "UNKNOWN",
}

FACILITY_ASSOCIATION_STATES = {
    "DIRECTLY_SUPPORTED",
    "SUPPORTED",
    "POSSIBLE",
    "WEAK",
    "CONTRADICTED",
    "UNKNOWN",
}

SOURCE_CLASSES = {
    "NATURAL",
    "MEDICAL",
    "INDUSTRIAL",
    "RESEARCH",
    "POWER_REACTOR",
    "FUEL_CYCLE",
    "WASTE",
    "UNKNOWN",
}

SENSITIVE_MEASUREMENT_TYPES = {
    "GAMMA_SPECTRUM",
    "NEUTRON_SPECTRUM",
    "LABORATORY_ANALYSIS",
    "ISOTOPIC_ANALYSIS",
}

SEVERE_QUALITY_FLAGS = {
    "calibration_unknown",
    "uncalibrated",
    "calibration_expired",
    "saturated",
    "below_detection_limit",
    "missing_timestamp",
    "unit_unknown",
    "unit_missing",
    "quantity_type_unknown",
    "chain_of_custody_gap",
    "chain_of_custody_incomplete",
    "sample_contamination_suspected",
    "missing_method",
    "missing_quality_controls",
    "nuclide_claim_without_spectral_or_lab_support",
    "timing_conflict",
    "sensor_conflict",
    "lab_conflict",
    "facility_status_conflict",
    "transport_context_conflict",
    "sample_provenance_conflict",
}

BLOCK_PHRASES = [
    # weapon design / optimization
    "design nuclear weapon",
    "optimize nuclear weapon",
    "weapon design",
    "weapon-yield optimization",
    "yield optimization",
    "critical mass optimization",
    "critical-mass optimization",
    "implosion design",
    "initiator design",
    "detonation optimization",
    "weapon physics calculations",
    "fissile material production",
    "fissile-material production",
    "weapons material production",
    "weapons-material production",
    "plutonium production optimization",
    "enrichment optimization",
    "enrichment plant design",
    "centrifuge optimization",
    "cascade design",
    "separative work planning",
    "weapon-grade production",
    "reprocessing procedures",
    "reprocessing for weapons",
    "chemical separation procedures",
    "weapons-purpose reprocessing",

    # RDD / harmful dispersal
    "radiological dispersal device construction",
    "rdd construction",
    "dirty bomb construction",
    "dispersal optimization",
    "contaminate environments",
    "harmful source acquisition",

    # evasion / smuggling / sabotage / targeting
    "detector evasion",
    "detection evasion",
    "portal monitor bypass",
    "radiation portal monitor bypass",
    "shielding for concealment",
    "smuggling methods",
    "covert transport",
    "concealed material",
    "move concealed material",
    "facility sabotage",
    "reactor sabotage",
    "attack planning against nuclear infrastructure",
    "targeting guidance",
    "strike guidance",
    "sensor placement optimized for bypass",
    "sensor placement optimized for evasion",
    "bypass detector",
    "unauthorized samples",
    "collect unauthorized samples",
]

MEASUREMENT_TYPE_TO_QUANTITY = {
    "COUNT": "COUNT",
    "COUNTS": "COUNT",
    "COUNT_RATE": "COUNT_RATE",
    "ACTIVITY": "ACTIVITY",
    "CONCENTRATION": "CONCENTRATION",
    "DOSE": "DOSE",
    "DOSE_RATE": "DOSE_RATE",
    "GAMMA_SPECTRUM": "OTHER",
    "NEUTRON_COUNT": "COUNT_RATE",
    "NEUTRON_SPECTRUM": "OTHER",
    "LABORATORY_ANALYSIS": "ACTIVITY",
    "ISOTOPIC_ANALYSIS": "RATIO",
    "RATIO": "RATIO",
    "ENERGY": "ENERGY",
}

FACILITY_TYPE_TO_SOURCE_CLASS = {
    "NUCLEAR_POWER": "POWER_REACTOR",
    "RESEARCH_REACTOR": "RESEARCH",
    "RESEARCH": "RESEARCH",
    "FUEL_FABRICATION": "FUEL_CYCLE",
    "URANIUM_PROCESSING": "FUEL_CYCLE",
    "ENRICHMENT_REPORTED": "FUEL_CYCLE",
    "REPROCESSING_REPORTED": "FUEL_CYCLE",
    "WASTE_STORAGE": "WASTE",
    "ISOTOPE_PRODUCTION": "RESEARCH",
    "MEDICAL": "MEDICAL",
    "INDUSTRIAL": "INDUSTRIAL",
}

UNIT_ALIASES = {
    "bq": "Bq",
    "kbq": "kBq",
    "mbq": "MBq",
    "gbq": "GBq",
    "count": "count",
    "counts": "count",
    "cps": "cps",
    "cpm": "cpm",
    "gy": "Gy",
    "mgy": "mGy",
    "sv": "Sv",
    "msv": "mSv",
    "usv": "uSv",
    "sv/h": "Sv/h",
    "usv/h": "uSv/h",
    "bq/m3": "Bq/m3",
    "bq/kg": "Bq/kg",
    "bq/l": "Bq/L",
}

# quantity_type, linear_factor, additive_offset
UNIT_INFO = {
    "Bq": ("ACTIVITY", 1.0, 0.0),
    "kBq": ("ACTIVITY", 1e3, 0.0),
    "MBq": ("ACTIVITY", 1e6, 0.0),
    "GBq": ("ACTIVITY", 1e9, 0.0),
    "count": ("COUNT", 1.0, 0.0),
    "cps": ("COUNT_RATE", 1.0, 0.0),
    "cpm": ("COUNT_RATE", 1.0 / 60.0, 0.0),
    "Gy": ("DOSE", 1.0, 0.0),
    "mGy": ("DOSE", 1e-3, 0.0),
    "Sv": ("DOSE_EQUIV", 1.0, 0.0),
    "mSv": ("DOSE_EQUIV", 1e-3, 0.0),
    "uSv": ("DOSE_EQUIV", 1e-6, 0.0),
    "Sv/h": ("DOSE_RATE", 1.0 / 3600.0, 0.0),
    "uSv/h": ("DOSE_RATE", 1e-6 / 3600.0, 0.0),
    "Bq/m3": ("CONCENTRATION", 1.0, 0.0),
    "Bq/kg": ("CONCENTRATION", 1.0, 0.0),
    "Bq/L": ("CONCENTRATION", 1.0, 0.0),
}

CANONICAL_UNITS = {
    "ACTIVITY": "Bq",
    "COUNT": "count",
    "COUNT_RATE": "cps",
    "DOSE": "Gy",
    "DOSE_EQUIV": "Sv",
    "DOSE_RATE": "Sv/s",
    "ENERGY": "J",
    "RATIO": "ratio",
    "OTHER": "other",
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


def normalize_unit_token(unit: Any) -> str:
    if unit is None:
        return ""
    raw = str(unit).strip().replace("µ", "u").replace("μ", "u").replace(" ", "")
    lower = raw.lower()
    return UNIT_ALIASES.get(lower, raw)


def infer_quantity_type(obj: Dict[str, Any]) -> str:
    mt = str(obj.get("measurement_type", "")).strip().upper()
    if mt in MEASUREMENT_TYPE_TO_QUANTITY:
        return MEASUREMENT_TYPE_TO_QUANTITY[mt]

    qt = str(obj.get("quantity_type", "")).strip().upper()
    if qt in ALLOWED_QUANTITY_TYPES:
        return qt

    return "UNKNOWN"


def normalize_value_unit(
    value: Any,
    uncertainty: Any,
    unit: Any,
    quantity_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Deterministically normalize recognized units.

    Preserves original value/unit. Never invents missing values.
    Does not mix incompatible quantity types.
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

    hint = str(quantity_hint or "UNKNOWN").strip().upper()
    if hint not in ALLOWED_QUANTITY_TYPES:
        hint = "UNKNOWN"

    if not info:
        return {
            "original_value": v,
            "original_unit": original_unit,
            "normalized_value": v,
            "normalized_unit": original_unit,
            "normalized_uncertainty": u,
            "quantity_type": hint,
            "conversion_factor": None,
            "conversion_offset": None,
            "flags": flags + (["unit_unknown"] if original_unit else ["unit_missing"]),
        }

    quantity_type, factor, offset = info

    norm_v = None
    norm_u = None

    if v is not None:
        norm_v = v * factor + offset
    if u is not None:
        norm_u = abs(factor) * u

    if quantity_type == "CONCENTRATION":
        canonical_unit = token
    else:
        canonical_unit = CANONICAL_UNITS.get(quantity_type, token)

    return {
        "original_value": v,
        "original_unit": original_unit,
        "normalized_value": norm_v,
        "normalized_unit": canonical_unit,
        "normalized_uncertainty": norm_u,
        "quantity_type": quantity_type,
        "conversion_factor": factor,
        "conversion_offset": offset,
        "flags": flags,
    }


def extract_location(obj: Dict[str, Any]) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[str]]:
    loc = obj.get("location")
    lat = lon = acc = None
    area_id = obj.get("area_id") or obj.get("location_area_id")

    if isinstance(loc, dict):
        lat = to_float(loc.get("latitude") if loc.get("latitude") is not None else loc.get("lat"))
        lon = to_float(loc.get("longitude") if loc.get("longitude") is not None else loc.get("lon"))
        acc = to_float(loc.get("accuracy_m") if loc.get("accuracy_m") is not None else loc.get("uncertainty_m"))
        area_id = loc.get("area_id") or loc.get("location_area_id") or area_id
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


# -----------------------------------------------------------------------------
# Policy gate
# -----------------------------------------------------------------------------

def policy_block_reasons(case: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []

    # Scan intent fields, not scientific data values, to avoid false positives
    # from declared facility types such as ENRICHMENT_REPORTED.
    scanned_parts: List[str] = []
    for key in ("objective", "questions", "scope", "authorization", "requested_outputs", "tags", "next_action_requests"):
        val = case.get(key)
        if val is not None:
            scanned_parts.append(json.dumps(val, ensure_ascii=False, default=str))

    text = " ".join(scanned_parts).lower()

    for phrase in BLOCK_PHRASES:
        if phrase in text:
            reasons.append(f"Forbidden NUCINT action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    requested = case.get("requested_outputs") if isinstance(case.get("requested_outputs"), dict) else {}

    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    if scope.get("defensive_only") is False:
        reasons.append("scope.defensive_only must not be false")

    if scope.get("non_proliferation") is False:
        reasons.append("scope.non_proliferation must not be false")

    prohibited_scope_flags = [
        "weapon_design",
        "weapon_optimization",
        "enrichment_planning",
        "centrifuge_optimization",
        "reprocessing_procedures",
        "fissile_material_production",
        "rdd_construction",
        "detector_evasion",
        "portal_monitor_bypass",
        "shielding_for_concealment",
        "smuggling",
        "sabotage",
        "targeting",
        "strike_guidance",
        "unauthorized_sampling",
    ]

    for flag in prohibited_scope_flags:
        if scope.get(flag) is True:
            reasons.append(f"scope.{flag} is prohibited")

    prohibited_requested = [
        "weapon_design",
        "yield_calculation",
        "enrichment_guidance",
        "reprocessing_guidance",
        "rdd_construction",
        "detector_evasion",
        "smuggling_guidance",
        "sabotage_guidance",
        "targeting_coordinates",
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
            "NO_WEAPON_DESIGN",
            "NO_WEAPON_OPTIMIZATION",
            "NO_YIELD_CALCULATION",
            "NO_CRITICAL_MASS_GUIDANCE",
            "NO_ENRICHMENT_PLANNING",
            "NO_CENTRIFUGE_OPTIMIZATION",
            "NO_REPROCESSING_PROCEDURES",
            "NO_FISSILE_MATERIAL_PRODUCTION_GUIDANCE",
            "NO_RDD_CONSTRUCTION",
            "NO_DETECTOR_EVASION",
            "NO_PORTAL_MONITOR_BYPASS",
            "NO_SHIELDING_FOR_CONCEALMENT",
            "NO_SMUGGLING_GUIDANCE",
            "NO_SABOTAGE_GUIDANCE",
            "NO_TARGETING_GUIDANCE",
            "NO_UNAUTHORIZED_SAMPLING",
        ],
        "legal_flags": [
            "HUMAN_REVIEW_REQUIRED_FOR_CONSEQUENTIAL_NUCLEAR_CLAIMS",
            "NON_PROLIFERATION_BOUNDARY",
            "OFFICIAL_AUTHORITY_GOVERNANCE_REQUIRED",
        ],
        "recommended_next_actions": [
            "Restate objective as lawful defensive nuclear/radiological signature analysis",
            "Use authorized/public monitoring, laboratory, safeguards, and regulatory records",
            "Preserve measurement uncertainty and chain of custody",
            "Test benign explanations before any facility or event attribution",
            "Escalate consequential findings to authorized human regulators / safeguards authorities",
        ],
        "limitations": [
            "Requested or detected use crosses NUCINT defensive / non-proliferation boundary.",
            "No weapon design, material production, detector evasion, smuggling, sabotage, targeting, or RDD guidance is provided.",
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

def validate_sensors(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    sensors: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(case.get("sensors") or case.get("sensor_records") or []):
        if not isinstance(s, dict):
            issues.append(f"sensors[{idx}] is not an object")
            continue

        sid = s.get("sensor_id")
        if not sid:
            issues.append(f"sensors[{idx}] missing sensor_id")
            continue

        cal = str(s.get("calibration_status", "CALIBRATION_UNKNOWN")).strip().upper()
        if cal not in ALLOWED_CALIBRATION:
            issues.append(f"sensor {sid} unknown calibration_status={cal}; set CALIBRATION_UNKNOWN")
            cal = "CALIBRATION_UNKNOWN"

        s["_calibration_status"] = cal
        s["_usable_for_high_confidence"] = cal == "CALIBRATED"

        if cal != "CALIBRATED":
            add_flag(s, cal.lower())

        sensors[sid] = s

    if not sensors:
        issues.append("No authorized sensors supplied")

    return sensors, issues


def validate_samples(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    samples: Dict[str, Dict[str, Any]] = {}

    raw_samples = case.get("sample_records") or case.get("samples") or []

    for idx, s in enumerate(raw_samples):
        if not isinstance(s, dict):
            issues.append(f"sample_records[{idx}] is not an object")
            continue

        sid = s.get("sample_id") or f"SAMP-{idx + 1}"
        s["sample_id"] = sid

        s["_sample_type"] = str(s.get("sample_type", "UNKNOWN")).strip().upper()
        s["_collection_time"] = parse_dt(s.get("collection_time"))
        s["_analysis_time"] = parse_dt(s.get("analysis_time"))

        lat, lon, acc, area = extract_location(s)
        s["_lat"] = lat
        s["_lon"] = lon
        s["_location_accuracy_m"] = acc
        s["_area_id"] = area

        if s["_collection_time"] is None:
            issues.append(f"sample {sid} missing collection_time")
            add_flag(s, "missing_timestamp")

        if lat is None or lon is None:
            warnings.append(f"sample {sid} missing valid collection location")
            add_flag(s, "missing_location")

        collector = s.get("collector")
        custody = s.get("chain_of_custody")

        if not collector:
            add_flag(s, "chain_of_custody_gap")
            warnings.append(f"sample {sid} missing collector")

        if not isinstance(custody, list) or not custody:
            add_flag(s, "chain_of_custody_gap")
        else:
            for transfer in custody:
                if not isinstance(transfer, dict):
                    add_flag(s, "chain_of_custody_incomplete")
                    continue
                if not transfer.get("timestamp") or not transfer.get("from") or not transfer.get("to"):
                    add_flag(s, "chain_of_custody_incomplete")

        if s.get("contamination_suspected") is True:
            add_flag(s, "sample_contamination_suspected")

        if not s.get("preservation_method"):
            warnings.append(f"sample {sid} missing preservation_method")

        s["_source_ids"] = [x for x in ensure_list(s.get("source_id") or s.get("source_ids")) if x]
        s["_evidence_ids"] = [x for x in ensure_list(s.get("evidence_id") or s.get("evidence_ids")) if x]

        samples[sid] = s

    return samples, issues, warnings


def validate_measurements(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    measurements: List[Dict[str, Any]] = []

    for idx, m in enumerate(case.get("measurements") or case.get("sensor_records") or []):
        if not isinstance(m, dict):
            issues.append(f"measurements[{idx}] is not an object")
            continue

        mid = m.get("measurement_id") or f"MEAS-{idx + 1}"
        m["measurement_id"] = mid

        sid = m.get("sensor_id")
        if sid and sid not in sensors:
            issues.append(f"measurement {mid} references unknown sensor_id={sid}")

        sample_id = m.get("sample_id")
        if sample_id and sample_id not in samples:
            warnings.append(f"measurement {mid} references unknown sample_id={sample_id}")

        ts = parse_dt(m.get("measurement_time") or m.get("timestamp"))
        if ts is None:
            issues.append(f"measurement {mid} missing/unparseable measurement_time")
            add_flag(m, "missing_timestamp")
        m["_timestamp"] = ts

        m["_collection_time"] = parse_dt(m.get("collection_time"))
        m["_analysis_time"] = parse_dt(m.get("analysis_time"))

        if m["_analysis_time"] and m["_collection_time"] and m["_analysis_time"] < m["_collection_time"]:
            add_flag(m, "timing_conflict")

        if m["_timestamp"] and m["_collection_time"] and m["_timestamp"] < m["_collection_time"]:
            add_flag(m, "timing_conflict")

        lat, lon, acc, area = extract_location(m)
        m["_lat"] = lat
        m["_lon"] = lon
        m["_location_accuracy_m"] = acc
        m["_area_id"] = area

        if lat is None and lon is None and not area:
            warnings.append(f"measurement {mid} missing location/area")
            add_flag(m, "missing_location")

        mt = str(m.get("measurement_type", "UNKNOWN")).strip().upper()
        m["_measurement_type"] = mt

        qt_hint = infer_quantity_type(m)
        norm = normalize_value_unit(m.get("value"), m.get("uncertainty"), m.get("unit"), qt_hint)

        m["_original_value"] = norm["original_value"]
        m["_original_unit"] = norm["original_unit"]
        m["_value_norm"] = norm["normalized_value"]
        m["_unit_norm"] = norm["normalized_unit"]
        m["_unc_norm"] = norm["normalized_uncertainty"]
        m["_quantity_type"] = norm["quantity_type"]
        for f in norm["flags"]:
            add_flag(m, f)

        if m["_quantity_type"] == "UNKNOWN" and m["_value_norm"] is not None:
            add_flag(m, "quantity_type_unknown")

        det = str(m.get("detection_state", "")).strip().upper()
        if det not in ALLOWED_DETECTION_STATES:
            if m["_value_norm"] is None:
                det = "INCONCLUSIVE"
            else:
                det = "DETECTED"
        m["_detection_state"] = det

        sensor = sensors.get(sid, {}) if sid else {}
        cal = sensor.get("_calibration_status", "CALIBRATION_UNKNOWN" if sid else "NO_SENSOR")
        m["_sensor_calibration_state"] = cal

        if cal in ("UNCALIBRATED", "CALIBRATION_UNKNOWN", "CALIBRATION_EXPIRED", "DEGRADED"):
            add_flag(m, cal.lower())

        if m.get("saturated") is True:
            add_flag(m, "saturated")

        lod = m.get("detection_limit") or sensor.get("detection_limit")
        lod_unit = m.get("detection_limit_unit") or sensor.get("detection_limit_unit") or m.get("unit")
        if lod is not None:
            lod_norm = normalize_value_unit(lod, None, lod_unit, m["_quantity_type"])
            m["_detection_limit_norm"] = lod_norm["normalized_value"]
            m["_detection_limit_unit"] = lod_norm["normalized_unit"]
            if (
                m["_value_norm"] is not None
                and m["_detection_limit_norm"] is not None
                and m["_unit_norm"] == m["_detection_limit_unit"]
                and m["_value_norm"] < m["_detection_limit_norm"]
            ):
                add_flag(m, "below_detection_limit")
        else:
            m["_detection_limit_norm"] = None
            m["_detection_limit_unit"] = None

        nuclides = m.get("radionuclide_candidates") or m.get("nuclide_candidates") or []
        m["_radionuclide_candidates"] = [x for x in ensure_list(nuclides) if x]

        if m["_radionuclide_candidates"] and mt not in SENSITIVE_MEASUREMENT_TYPES:
            add_flag(m, "nuclide_claim_without_spectral_or_lab_support")

        m["_source_class_candidates"] = [
            str(x).strip().upper()
            for x in ensure_list(m.get("source_class_candidates") or m.get("source_classes"))
            if x
        ]

        m["_source_ids"] = [x for x in ensure_list(m.get("source_id") or m.get("source_ids")) if x]
        m["_evidence_ids"] = [x for x in ensure_list(m.get("evidence_id") or m.get("evidence_ids")) if x]

        measurements.append(m)

    if not measurements:
        issues.append("No measurements supplied")

    return measurements, issues, warnings


def validate_laboratory_results(
    case: Dict[str, Any],
    samples: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    issues: List[str] = []
    warnings: List[str] = []
    labs: List[Dict[str, Any]] = []

    for idx, lr in enumerate(case.get("laboratory_results") or []):
        if not isinstance(lr, dict):
            issues.append(f"laboratory_results[{idx}] is not an object")
            continue

        rid = lr.get("result_id") or f"LAB-{idx + 1}"
        lr["result_id"] = rid

        sample_id = lr.get("sample_id")
        lr["_sample_id"] = sample_id
        if sample_id and sample_id not in samples:
            warnings.append(f"lab result {rid} references unknown sample_id={sample_id}")

        lr["_analysis_time"] = parse_dt(lr.get("analysis_time") or lr.get("timestamp"))
        if lr["_analysis_time"] is None:
            issues.append(f"lab result {rid} missing analysis_time")
            add_flag(lr, "missing_timestamp")

        sample = samples.get(sample_id, {}) if sample_id else {}
        if lr["_analysis_time"] and sample.get("_collection_time") and lr["_analysis_time"] < sample["_collection_time"]:
            add_flag(lr, "timing_conflict")

        if not lr.get("method"):
            add_flag(lr, "missing_method")
            warnings.append(f"lab result {rid} missing method")

        if not lr.get("quality_controls"):
            add_flag(lr, "missing_quality_controls")

        nuclides: List[Dict[str, Any]] = []
        raw_nuclides = lr.get("nuclides") or lr.get("radionuclide_reports") or lr.get("results") or []

        for n in ensure_list(raw_nuclides):
            if not isinstance(n, dict):
                n = {"nuclide": str(n)}

            value = n.get("activity") if n.get("activity") is not None else n.get("value")
            unit = n.get("unit") or lr.get("unit") or "Bq"
            norm = normalize_value_unit(value, n.get("uncertainty"), unit, "ACTIVITY")

            entry = {
                "nuclide_candidate": n.get("nuclide") or n.get("radionuclide") or n.get("nuclide_candidate"),
                "original_value": norm["original_value"],
                "original_unit": norm["original_unit"],
                "activity_norm": norm["normalized_value"],
                "unit_norm": norm["normalized_unit"],
                "uncertainty_norm": norm["normalized_uncertainty"],
                "quantity_type": norm["quantity_type"],
                "method": n.get("method") or lr.get("method"),
                "confidence": str(n.get("confidence", "UNKNOWN")).upper(),
                "quality_flags": n.get("quality_flags") or [],
            }

            if not entry["nuclide_candidate"]:
                add_flag(lr, "nuclide_missing_identity")

            nuclides.append(entry)

        lr["_nuclides"] = nuclides
        lr["_source_ids"] = [x for x in ensure_list(lr.get("source_id") or lr.get("source_ids")) if x]
        lr["_evidence_ids"] = [x for x in ensure_list(lr.get("evidence_id") or lr.get("evidence_ids")) if x]

        labs.append(lr)

    return labs, issues, warnings


def validate_facilities(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    facilities: Dict[str, Dict[str, Any]] = {}

    for idx, f in enumerate(case.get("facilities") or []):
        if not isinstance(f, dict):
            issues.append(f"facilities[{idx}] is not an object")
            continue

        fid = f.get("facility_id") or f"FAC-{idx + 1}"
        f["facility_id"] = fid

        f["_facility_type"] = str(f.get("facility_type", "UNKNOWN")).strip().upper()
        f["_declared_status"] = str(f.get("declared_status", "UNKNOWN")).strip().upper()
        f["_operational_status"] = str(f.get("operational_status", "UNKNOWN")).strip().upper()

        lat, lon, acc, area = extract_location(f)
        f["_lat"] = lat
        f["_lon"] = lon
        f["_location_accuracy_m"] = acc
        f["_area_id"] = area

        f["_valid_from"] = parse_dt(f.get("valid_from"))
        f["_valid_to"] = parse_dt(f.get("valid_to"))

        facilities[fid] = f

    return facilities, issues


def validate_backgrounds(
    case: Dict[str, Any],
    sensors: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    backgrounds: List[Dict[str, Any]] = []

    raw = case.get("background_data") or case.get("baselines") or []

    for idx, b in enumerate(raw):
        if not isinstance(b, dict):
            issues.append(f"background_data[{idx}] is not an object")
            continue

        bid = b.get("baseline_id") or b.get("background_id") or f"BG-{idx + 1}"
        b["baseline_id"] = bid

        sid = b.get("sensor_id")
        if sid and sid not in sensors:
            issues.append(f"background {bid} references unknown sensor_id={sid}")

        b["_measurement_type"] = str(b.get("measurement_type", "")).strip().upper()
        qt_hint = str(b.get("quantity_type", "")).strip().upper()
        if qt_hint not in ALLOWED_QUANTITY_TYPES:
            qt_hint = MEASUREMENT_TYPE_TO_QUANTITY.get(b["_measurement_type"], "UNKNOWN")

        mean_norm = normalize_value_unit(b.get("mean"), b.get("uncertainty"), b.get("unit"), qt_hint)
        b["_mean_norm"] = mean_norm["normalized_value"]
        b["_unc_norm"] = mean_norm["normalized_uncertainty"]
        b["_unit_norm"] = mean_norm["normalized_unit"]
        b["_quantity_type"] = mean_norm["quantity_type"]

        std = to_float(b.get("std"))
        if std is not None and mean_norm["conversion_factor"] is not None:
            b["_std_norm"] = abs(mean_norm["conversion_factor"]) * std
        else:
            b["_std_norm"] = std

        b["_valid_from"] = parse_dt(b.get("valid_from"))
        b["_valid_to"] = parse_dt(b.get("valid_to"))

        lat, lon, acc, area = extract_location(b)
        b["_lat"] = lat
        b["_lon"] = lon
        b["_area_id"] = area

        backgrounds.append(b)

    return backgrounds, issues


# -----------------------------------------------------------------------------
# Spatial clustering / temporal segmentation
# -----------------------------------------------------------------------------

def build_spatial_clusters(items: List[Dict[str, Any]], distance_km: float) -> List[Dict[str, Any]]:
    clusters: List[Dict[str, Any]] = []
    next_id = 1

    for it in items:
        lat = it.get("_lat")
        lon = it.get("_lon")

        if lat is None or lon is None:
            area = it.get("_area_id") or "UNKNOWN_LOCATION"
            it["_spatial_cluster_id"] = f"AREA:{area}"
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
            it["_spatial_cluster_id"] = assigned["id"]
        else:
            cid = f"SPATIAL-{next_id}"
            next_id += 1
            clusters.append({"id": cid, "lat": lat, "lon": lon, "count": 1})
            it["_spatial_cluster_id"] = cid

    return clusters


def segment_by_time(items: List[Dict[str, Any]], max_gap_s: float) -> List[List[Dict[str, Any]]]:
    def sort_key(x: Dict[str, Any]) -> datetime:
        return x.get("_timestamp") or x.get("_collection_time") or datetime.min.replace(tzinfo=timezone.utc)

    ordered = sorted(items, key=sort_key)
    segments: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    last_ts: Optional[datetime] = None

    for m in ordered:
        ts = m.get("_timestamp") or m.get("_collection_time")
        if current and last_ts and ts and (ts - last_ts).total_seconds() > max_gap_s:
            segments.append(current)
            current = []
        current.append(m)
        last_ts = ts

    if current:
        segments.append(current)

    return segments


# -----------------------------------------------------------------------------
# Background / anomaly analysis
# -----------------------------------------------------------------------------

def select_baseline(m: Dict[str, Any], backgrounds: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    best = None
    best_score = -1

    phenomenon_type = m.get("_measurement_type")
    quantity_type = m.get("_quantity_type")
    unit = m.get("_unit_norm")
    sensor_id = m.get("sensor_id")
    spatial_id = m.get("_spatial_cluster_id")
    area_id = m.get("_area_id")
    ts = m.get("_timestamp") or m.get("_collection_time")

    for b in backgrounds:
        if b.get("sensor_id") and b["sensor_id"] != sensor_id:
            continue
        if b.get("_measurement_type") and phenomenon_type and b["_measurement_type"] != phenomenon_type:
            continue
        if b.get("_quantity_type") and quantity_type and b["_quantity_type"] != quantity_type:
            continue
        if b.get("_unit_norm") and unit and b["_unit_norm"] != unit:
            continue
        if b.get("spatial_cluster_id") and b["spatial_cluster_id"] != spatial_id:
            continue
        if b.get("_spatial_cluster_id") and b["_spatial_cluster_id"] != spatial_id:
            continue
        if b.get("area_id") and area_id and b["area_id"] != area_id:
            continue
        if b.get("_area_id") and area_id and b["_area_id"] != area_id:
            continue

        vf = b.get("_valid_from")
        vt = b.get("_valid_to")
        if ts:
            if vf and ts < vf:
                continue
            if vt and ts > vt:
                continue

        score = 0
        if b.get("sensor_id") == sensor_id:
            score += 4
        if b.get("_spatial_cluster_id") == spatial_id or b.get("spatial_cluster_id") == spatial_id:
            score += 3
        if b.get("_area_id") == area_id or b.get("area_id") == area_id:
            score += 2
        if b.get("_measurement_type") == phenomenon_type:
            score += 1
        if ts:
            score += 1

        if score > best_score:
            best = b
            best_score = score

    return best


def analyze_anomaly(m: Dict[str, Any], backgrounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    result = {
        "measurement_id": m.get("measurement_id"),
        "sample_id": m.get("sample_id"),
        "phenomenon": m.get("_measurement_type"),
        "anomaly_state": "UNKNOWN",
        "baseline_id": None,
        "z_score": None,
        "deviation": None,
        "confidence": "UNKNOWN",
        "notes": [],
    }

    value = m.get("_value_norm")
    if value is None:
        result["notes"].append("No numeric value available; non-detection is not absence.")
        return result

    b = select_baseline(m, backgrounds)
    if not b:
        result["notes"].append("No compatible background/baseline supplied.")
        return result

    mean = b.get("_mean_norm")
    std = b.get("_std_norm") or 0.0
    unc = m.get("_unc_norm") or 0.0
    b_unc = b.get("_unc_norm") or 0.0

    if mean is None:
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

    flags = set(m.get("_quality_flags") or [])
    severe = bool(flags & SEVERE_QUALITY_FLAGS)
    calibrated = m.get("_sensor_calibration_state") == "CALIBRATED"

    abs_z = abs(z) if z is not None and not math.isinf(z) else float("inf")

    if severe:
        state = "UNKNOWN"
        result["notes"].append("Severe quality flags present; anomaly interpretation disputed.")
    elif overlap and abs_z < 2.0:
        state = "WITHIN_EXPECTED_BACKGROUND"
    elif abs_z < 3.0:
        state = "MINOR_DEVIATION"
    elif abs_z < 5.0:
        state = "MATERIAL_DEVIATION"
    else:
        state = "SIGNATURE_OF_INTEREST" if calibrated else "MATERIAL_DEVIATION"

    confidence = "UNKNOWN"
    if state == "WITHIN_EXPECTED_BACKGROUND":
        confidence = "HIGH" if calibrated and not severe else "MODERATE"
    elif state in ("MINOR_DEVIATION", "MATERIAL_DEVIATION"):
        confidence = "MODERATE" if calibrated and not severe else "LOW"
    elif state == "SIGNATURE_OF_INTEREST":
        confidence = "MODERATE"
    elif state == "UNKNOWN":
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
# Radionuclide / source-class candidates
# -----------------------------------------------------------------------------

def collect_radionuclide_candidates(
    measurements: List[Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    for m in measurements:
        for n in m.get("_radionuclide_candidates") or []:
            if isinstance(n, dict):
                nuclide = n.get("nuclide") or n.get("radionuclide") or n.get("nuclide_candidate")
                activity = n.get("activity") or n.get("value")
                unit = n.get("unit") or m.get("_unit_norm")
                uncertainty = n.get("uncertainty")
                method = n.get("method") or m.get("_measurement_type")
                confidence = str(n.get("confidence", "UNKNOWN")).upper()
            else:
                nuclide = str(n)
                activity = None
                unit = None
                uncertainty = None
                method = m.get("_measurement_type")
                confidence = "UNKNOWN"

            norm = normalize_value_unit(activity, uncertainty, unit, "ACTIVITY")

            if m.get("_measurement_type") in SENSITIVE_MEASUREMENT_TYPES:
                state = "SPECTRAL_CANDIDATE"
            else:
                state = "WEAK_UNSUPPORTED_CANDIDATE"

            severe = bool(set(m.get("_quality_flags") or []) & SEVERE_QUALITY_FLAGS)
            if severe:
                state = "DISPUTED_CANDIDATE"

            candidates.append(
                {
                    "candidate_id": f"NUC-{len(candidates) + 1}",
                    "nuclide_candidate": nuclide,
                    "state": state,
                    "method": method,
                    "activity_norm": norm["normalized_value"],
                    "unit_norm": norm["normalized_unit"],
                    "uncertainty_norm": norm["normalized_uncertainty"],
                    "sensor_id": m.get("sensor_id"),
                    "sample_id": m.get("sample_id"),
                    "measurement_id": m.get("measurement_id"),
                    "timestamp": iso_or_none(m.get("_timestamp")),
                    "evidence_ids": m.get("_evidence_ids"),
                    "source_ids": m.get("_source_ids"),
                    "limitations": [
                        "Radionuclide candidate is not source identity.",
                        "Count rate alone does not establish isotope identity.",
                        "Spectral/lab support is required for stronger nuclide claims.",
                    ],
                }
            )

    for lr in lab_results:
        for n in lr.get("_nuclides") or []:
            severe = bool(set(lr.get("_quality_flags") or []) & SEVERE_QUALITY_FLAGS)
            state = "LAB_REPORTED_NUCLIDE"
            if severe:
                state = "DISPUTED_LAB_NUCLIDE"
            if not n.get("nuclide_candidate"):
                state = "NUCLIDE_MISSING_IDENTITY"

            candidates.append(
                {
                    "candidate_id": f"NUC-{len(candidates) + 1}",
                    "nuclide_candidate": n.get("nuclide_candidate"),
                    "state": state,
                    "method": n.get("method") or lr.get("method"),
                    "activity_norm": n.get("activity_norm"),
                    "unit_norm": n.get("unit_norm"),
                    "uncertainty_norm": n.get("uncertainty_norm"),
                    "sensor_id": None,
                    "sample_id": lr.get("_sample_id"),
                    "laboratory_result_id": lr.get("result_id"),
                    "timestamp": iso_or_none(lr.get("_analysis_time")),
                    "evidence_ids": lr.get("_evidence_ids"),
                    "source_ids": lr.get("_source_ids"),
                    "limitations": [
                        "Laboratory result identifies measured sample content, not automatic event origin.",
                        "Source/facility attribution requires spatial, temporal, meteorological, and independent evidence.",
                    ],
                }
            )

    return candidates


def source_state_rank(state: str) -> int:
    return {
        "SUPPORTED": 3,
        "DIRECTLY_SUPPORTED": 4,
        "CANDIDATE": 2,
        "WEAK": 1,
        "UNKNOWN": 0,
    }.get(str(state).upper(), 0)


def merge_source_class_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for c in candidates:
        sc = str(c.get("source_class") or "UNKNOWN").upper()
        if sc not in SOURCE_CLASSES:
            sc = "UNKNOWN"

        cur = merged.get(sc)
        if not cur:
            merged[sc] = dict(c)
            merged[sc]["source_class"] = sc
            merged[sc]["evidence_ids"] = list(set(c.get("evidence_ids") or []))
            merged[sc]["source_ids"] = list(set(c.get("source_ids") or []))
            continue

        if source_state_rank(c.get("state", "UNKNOWN")) > source_state_rank(cur.get("state", "UNKNOWN")):
            cur["state"] = c.get("state")
            cur["confidence"] = c.get("confidence")
            cur["basis"] = c.get("basis")

        cur["evidence_ids"] = sorted(set(cur.get("evidence_ids") or []) | set(c.get("evidence_ids") or []))
        cur["source_ids"] = sorted(set(cur.get("source_ids") or []) | set(c.get("source_ids") or []))
        cur.setdefault("limitations", [])
        for lim in c.get("limitations") or []:
            if lim not in cur["limitations"]:
                cur["limitations"].append(lim)

    return list(merged.values())


def collect_source_class_candidates(
    measurements: List[Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    facilities: Dict[str, Dict[str, Any]],
    facility_associations: List[Dict[str, Any]],
    official_reports: List[Dict[str, Any]],
    case: Dict[str, Any],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    # Supplied candidates
    for obj in measurements + list(samples.values()) + lab_results:
        for sc in obj.get("_source_class_candidates") or obj.get("source_class_candidates") or []:
            sc_up = str(sc).upper()
            if sc_up not in SOURCE_CLASSES:
                sc_up = "UNKNOWN"
            candidates.append(
                {
                    "source_class": sc_up,
                    "state": "SUPPLIED_CANDIDATE",
                    "confidence": "LOW",
                    "basis": "supplied_source_class_candidate",
                    "evidence_ids": obj.get("_evidence_ids") or [],
                    "source_ids": obj.get("_source_ids") or [],
                    "limitations": ["Supplied candidate requires independent corroboration."],
                }
            )

    # Facility context candidates
    for assoc in facility_associations:
        fid = assoc.get("facility_id")
        f = facilities.get(fid, {})
        ft = f.get("_facility_type")
        sc = FACILITY_TYPE_TO_SOURCE_CLASS.get(str(ft).upper())
        if not sc:
            continue

        state = "CANDIDATE"
        if assoc.get("state") in {"SUPPORTED", "DIRECTLY_SUPPORTED"}:
            state = "SUPPORTED"
        elif assoc.get("state") == "WEAK":
            state = "WEAK"

        candidates.append(
            {
                "source_class": sc,
                "state": state,
                "confidence": "MODERATE" if state == "SUPPORTED" else "LOW",
                "basis": f"facility_context:{fid}:{ft}",
                "evidence_ids": assoc.get("evidence_ids") or [],
                "source_ids": assoc.get("source_ids") or [],
                "limitations": [
                    "Facility type does not prove active process.",
                    "Declared status is source-reported until independently supported.",
                    "Proximity alone is not source attribution.",
                ],
            }
        )

    # Explicit context blocks
    for ctx_key, sc in [
        ("medical_source_context", "MEDICAL"),
        ("industrial_source_context", "INDUSTRIAL"),
        ("research_source_context", "RESEARCH"),
        ("natural_source_context", "NATURAL"),
    ]:
        ctx = case.get(ctx_key)
        if ctx:
            candidates.append(
                {
                    "source_class": sc,
                    "state": "CANDIDATE",
                    "confidence": "LOW",
                    "basis": ctx_key,
                    "evidence_ids": [],
                    "source_ids": [],
                    "limitations": ["Context supplied by input; requires measurement correlation."],
                }
            )

    # Official report context
    for rep in official_reports:
        sc = str(rep.get("source_class") or "").upper()
        if sc in SOURCE_CLASSES:
            candidates.append(
                {
                    "source_class": sc,
                    "state": "SUPPORTED" if rep.get("source_reliability") in {"HIGH", "MODERATE"} else "CANDIDATE",
                    "confidence": rep.get("source_reliability", "UNKNOWN"),
                    "basis": f"official_report:{rep.get('report_id')}",
                    "evidence_ids": rep.get("evidence_ids") or [],
                    "source_ids": rep.get("source_ids") or [rep.get("source_id")],
                    "limitations": ["Official report is important evidence but may still require physical verification."],
                }
            )

    return merge_source_class_candidates(candidates)


# -----------------------------------------------------------------------------
# Facility association
# -----------------------------------------------------------------------------

def valid_range_contains(valid_from: Optional[datetime], valid_to: Optional[datetime], ts: Optional[datetime]) -> bool:
    if valid_from is None and valid_to is None:
        return True
    if ts is None:
        return True
    if valid_from is not None and ts < valid_from:
        return False
    if valid_to is not None and ts > valid_to:
        return False
    return True


def associate_facilities(
    items: List[Dict[str, Any]],
    facilities: Dict[str, Dict[str, Any]],
    weather: Dict[str, Any],
    official_reports: List[Dict[str, Any]],
    settings: Dict[str, float],
) -> List[Dict[str, Any]]:
    associations: List[Dict[str, Any]] = []

    transport_regions = weather.get("candidate_source_regions") or []

    for it in items:
        obs_id = it.get("measurement_id") or it.get("sample_id") or it.get("result_id")
        ts = it.get("_timestamp") or it.get("_collection_time") or it.get("_analysis_time")
        lat = it.get("_lat")
        lon = it.get("_lon")

        for fid, f in facilities.items():
            if not valid_range_contains(f.get("_valid_from"), f.get("_valid_to"), ts):
                continue

            state = "UNKNOWN"
            notes: List[str] = []
            distance_km = None

            f_lat = f.get("_lat")
            f_lon = f.get("_lon")

            if lat is not None and lon is not None and f_lat is not None and f_lon is not None:
                distance_km = haversine_km(lat, lon, f_lat, f_lon)
                if distance_km is not None and distance_km <= settings["facility_radius_km"]:
                    state = "POSSIBLE"
                    notes.append(f"Observation within {settings['facility_radius_km']} km of facility.")

                    op = f.get("_operational_status")
                    if op in {"OPERATIONAL_REPORTED", "MAINTENANCE_REPORTED"}:
                        notes.append("Facility operational status is reported active/maintenance.")
                    elif op == "SHUTDOWN_REPORTED":
                        state = "WEAK"
                        notes.append("Facility reported shutdown; proximity alone is weak.")
                    else:
                        state = "WEAK"
                        notes.append("Facility operational status unknown.")

            # Transport candidate region support
            facility_in_transport_region = False
            for region in transport_regions:
                if not isinstance(region, dict):
                    continue
                region_facility_id = region.get("facility_id")
                region_name = str(region.get("name") or "").upper()
                fac_name = str(f.get("name") or "").upper()

                if region_facility_id == fid or (region_name and region_name == fac_name):
                    rw_from = parse_dt(region.get("start_time"))
                    rw_to = parse_dt(region.get("end_time"))
                    if ts and rw_from and rw_to and not (rw_from <= ts <= rw_to):
                        continue
                    facility_in_transport_region = True
                    state = "POSSIBLE" if state in {"UNKNOWN", "WEAK"} else state
                    notes.append("Facility appears in supplied atmospheric transport candidate region.")

            # Official report linkage
            for rep in official_reports:
                if rep.get("facility_id") != fid:
                    continue
                linked = (
                    rep.get("linked_observation_id") == obs_id
                    or rep.get("sample_id") == it.get("sample_id")
                    or rep.get("measurement_id") == it.get("measurement_id")
                )
                rep_time = parse_dt(rep.get("report_time") or rep.get("event_time"))
                time_close = False
                if ts and rep_time:
                    time_close = abs((ts - rep_time).total_seconds()) <= settings["official_report_time_window_s"]

                if linked or (rep.get("release_confirmed") is True and time_close):
                    if rep.get("source_reliability") in {"HIGH", "MODERATE"} or rep.get("release_confirmed") is True:
                        state = "SUPPORTED"
                    else:
                        state = "POSSIBLE"
                    notes.append(f"Official/public report linkage: {rep.get('report_id')}.")

            if state == "UNKNOWN":
                continue

            associations.append(
                {
                    "association_id": f"ASSOC-{len(associations) + 1}",
                    "observation_id": obs_id,
                    "facility_id": fid,
                    "facility_type": f.get("_facility_type"),
                    "facility_operational_status": f.get("_operational_status"),
                    "state": state,
                    "distance_km": distance_km,
                    "transport_region_supported": facility_in_transport_region,
                    "timestamp": iso_or_none(ts),
                    "evidence_ids": it.get("_evidence_ids") or [],
                    "source_ids": it.get("_source_ids") or [],
                    "notes": notes,
                    "limitations": [
                        "Facility association is not source proof.",
                        "Proximity, declared status, and transport context are supporting evidence only.",
                        "No intent, operator, or weapon-related conclusion is made.",
                    ],
                }
            )

    return associations


# -----------------------------------------------------------------------------
# Release assessment
# -----------------------------------------------------------------------------

def assess_release_candidates(
    measurements: List[Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    radionuclide_candidates: List[Dict[str, Any]],
    facility_associations: List[Dict[str, Any]],
    official_reports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    anomaly_by_meas = {a.get("measurement_id"): a for a in anomalies}
    assoc_by_obs = defaultdict(list)
    for a in facility_associations:
        assoc_by_obs[a.get("observation_id")].append(a)

    nuc_by_meas = defaultdict(list)
    nuc_by_sample = defaultdict(list)
    for n in radionuclide_candidates:
        if n.get("measurement_id"):
            nuc_by_meas[n["measurement_id"]].append(n)
        if n.get("sample_id"):
            nuc_by_sample[n["sample_id"]].append(n)

    labs_by_sample = defaultdict(list)
    for lr in lab_results:
        labs_by_sample[lr.get("_sample_id")].append(lr)

    def official_confirmed(obs_id: Optional[str], sample_id: Optional[str]) -> bool:
        for rep in official_reports:
            if rep.get("release_confirmed") is not True:
                continue
            if rep.get("linked_observation_id") == obs_id:
                return True
            if sample_id and rep.get("sample_id") == sample_id:
                return True
        return False

    # Measurement-based release candidates
    for m in measurements:
        mid = m.get("measurement_id")
        sid = m.get("sample_id")
        anomaly = anomaly_by_meas.get(mid, {})
        nuclides = nuc_by_meas.get(mid, []) + nuc_by_sample.get(sid, [])
        assocs = assoc_by_obs.get(mid, []) + assoc_by_obs.get(sid, [])
        labs = labs_by_sample.get(sid, [])

        if not nuclides and not labs:
            continue

        confirmed = official_confirmed(mid, sid)
        supported_assoc = any(a.get("state") in {"SUPPORTED", "DIRECTLY_SUPPORTED"} for a in assocs)
        possible_assoc = any(a.get("state") == "POSSIBLE" for a in assocs)
        lab_confirmed = any(
            lr.get("_nuclides")
            and not (set(lr.get("_quality_flags") or []) & SEVERE_QUALITY_FLAGS)
            for lr in labs
        )
        anomaly_state = anomaly.get("anomaly_state", "UNKNOWN")

        if confirmed:
            state = "RELEASE_CONFIRMED"
        elif lab_confirmed and (supported_assoc or (possible_assoc and anomaly_state in {"MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"})):
            state = "RELEASE_SUPPORTED"
        elif anomaly_state in {"MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"} and nuclides:
            state = "RELEASE_CANDIDATE"
        elif anomaly_state == "WITHIN_EXPECTED_BACKGROUND":
            state = "BACKGROUND_VARIATION"
        else:
            state = "UNKNOWN"

        candidates.append(
            {
                "release_candidate_id": f"REL-{len(candidates) + 1}",
                "state": state,
                "measurement_id": mid,
                "sample_id": sid,
                "timestamp": iso_or_none(m.get("_timestamp")),
                "location": {
                    "latitude": m.get("_lat"),
                    "longitude": m.get("_lon"),
                    "area_id": m.get("_area_id"),
                    "spatial_cluster_id": m.get("_spatial_cluster_id"),
                },
                "radionuclide_candidates": [n.get("nuclide_candidate") for n in nuclides],
                "facility_associations": assocs,
                "anomaly": anomaly,
                "laboratory_results": [lr.get("result_id") for lr in labs],
                "limitations": [
                    "Release candidate is not source attribution.",
                    "Detection time is not necessarily release time.",
                    "Environmental transport may delay observation.",
                    "No intent, operator, or weapon-related conclusion is made.",
                ],
            }
        )

    # Sample/lab-only release candidates
    for sid, sample in samples.items():
        labs = labs_by_sample.get(sid, [])
        if not labs:
            continue

        nuclides = nuc_by_sample.get(sid, [])
        if not nuclides:
            continue

        assocs = assoc_by_obs.get(sid, [])
        confirmed = official_confirmed(None, sid)
        supported_assoc = any(a.get("state") in {"SUPPORTED", "DIRECTLY_SUPPORTED"} for a in assocs)
        possible_assoc = any(a.get("state") == "POSSIBLE" for a in assocs)
        lab_confirmed = any(
            lr.get("_nuclides")
            and not (set(lr.get("_quality_flags") or []) & SEVERE_QUALITY_FLAGS)
            for lr in labs
        )

        if confirmed:
            state = "RELEASE_CONFIRMED"
        elif lab_confirmed and (supported_assoc or possible_assoc):
            state = "RELEASE_SUPPORTED"
        elif lab_confirmed:
            state = "RELEASE_CANDIDATE"
        else:
            state = "UNKNOWN"

        candidates.append(
            {
                "release_candidate_id": f"REL-{len(candidates) + 1}",
                "state": state,
                "measurement_id": None,
                "sample_id": sid,
                "timestamp": iso_or_none(sample.get("_collection_time")),
                "location": {
                    "latitude": sample.get("_lat"),
                    "longitude": sample.get("_lon"),
                    "area_id": sample.get("_area_id"),
                    "spatial_cluster_id": sample.get("_spatial_cluster_id"),
                },
                "radionuclide_candidates": [n.get("nuclide_candidate") for n in nuclides],
                "facility_associations": assocs,
                "anomaly": None,
                "laboratory_results": [lr.get("result_id") for lr in labs],
                "limitations": [
                    "Sample detection is not automatic event origin.",
                    "Chain of custody and lab quality control matter.",
                    "Source/facility attribution requires independent spatial/temporal/transport evidence.",
                ],
            }
        )

    return candidates


# -----------------------------------------------------------------------------
# Independence / fusion
# -----------------------------------------------------------------------------

def sensor_independence(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    if not a or not b:
        return "UNKNOWN"
    if a.get("sensor_id") == b.get("sensor_id"):
        return "DEPENDENT"

    shared_keys = [
        "upstream_sensor_id",
        "processor_id",
        "independence_group",
        "calibration_reference",
        "platform_id",
    ]

    for k in shared_keys:
        av = a.get(k)
        bv = b.get(k)
        if av is not None and bv is not None and av == bv:
            return "DEPENDENT"

    if a.get("sensor_type") == b.get("sensor_type") and a.get("operator") == b.get("operator"):
        return "PARTIALLY_DEPENDENT"

    if a.get("location") is None or b.get("location") is None:
        return "UNKNOWN"

    return "INDEPENDENT"


def summarize_sensor_independence(sensor_ids: List[str], sensors: Dict[str, Dict[str, Any]]) -> str:
    ids = [s for s in sensor_ids if s]
    if len(ids) < 2:
        return "SINGLE_SENSOR"

    states: List[str] = []
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


def sample_independence(s1: Dict[str, Any], s2: Dict[str, Any]) -> str:
    if not s1 or not s2:
        return "UNKNOWN"
    if s1.get("sample_id") == s2.get("sample_id"):
        return "DEPENDENT"
    if s1.get("parent_sample_id") and s1.get("parent_sample_id") == s2.get("parent_sample_id"):
        return "DEPENDENT"
    if s1.get("collection_event_id") and s1.get("collection_event_id") == s2.get("collection_event_id"):
        return "PARTIALLY_DEPENDENT"
    return "UNKNOWN"


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
            m.get("_spatial_cluster_id") or "UNKNOWN_LOCATION",
            m.get("_measurement_type") or "UNKNOWN",
            m.get("_unit_norm") or "UNKNOWN",
            m.get("_quantity_type") or "UNKNOWN",
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
                                    "spatial_cluster_id": key[0],
                                    "measurement_type": key[1],
                                    "unit": key[2],
                                    "measurement_ids": [usable[i].get("measurement_id"), usable[j].get("measurement_id")],
                                    "sensor_ids": [usable[i].get("sensor_id"), usable[j].get("sensor_id")],
                                    "value_difference": abs(vi - vj),
                                    "combined_uncertainty": combined,
                                    "note": "Preserve contradiction. Do not average conflicting sensors into false precision.",
                                }
                            )

            independence = summarize_sensor_independence(sensor_ids, sensors)

            if conflict_found:
                agreement = "CONFLICT"
            elif independence == "INDEPENDENT":
                agreement = "AGREE"
            elif independence == "PARTIALLY_DEPENDENT":
                agreement = "PARTIAL"
            else:
                agreement = "INSUFFICIENT"

            start_ts = min((x.get("_timestamp") for x in usable if x.get("_timestamp")), default=None)
            end_ts = max((x.get("_timestamp") for x in usable if x.get("_timestamp")), default=None)

            fid = f"FUSED-{gidx}-{sidx}"
            fused.append(
                {
                    "fusion_id": fid,
                    "spatial_cluster_id": key[0],
                    "measurement_type": key[1],
                    "unit": key[2],
                    "quantity_type": key[3],
                    "sensor_ids": sensor_ids,
                    "value": fused_val,
                    "uncertainty": fused_unc,
                    "start_time": iso_or_none(start_ts),
                    "end_time": iso_or_none(end_ts),
                    "fusion_method": method,
                    "source_independence": independence,
                    "agreement": agreement,
                    "contributing_measurement_ids": [x.get("measurement_id") for x in usable],
                    "limitations": [
                        "Fused value is a derived product, not a raw sensor measurement.",
                        "Independence depends on supplied sensor pedigree metadata.",
                        "Conflicts are preserved and reduce confidence.",
                    ],
                }
            )

    return fused, contradictions


def correlate_samples_and_labs(
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    measurements: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    correlations: List[Dict[str, Any]] = []

    labs_by_sample: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for lr in lab_results:
        if lr.get("_sample_id"):
            labs_by_sample[lr["_sample_id"]].append(lr)

    meas_by_sample: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for m in measurements:
        if m.get("sample_id"):
            meas_by_sample[m["sample_id"]].append(m)

    for sid, labs in labs_by_sample.items():
        sample = samples.get(sid, {})
        related_measurements = meas_by_sample.get(sid, [])

        independence = "SINGLE_LAB"
        if len(labs) >= 2:
            states = []
            for i in range(len(labs)):
                for j in range(i + 1, len(labs)):
                    # Multiple lab analyses on same sample are not independent environmental observations.
                    states.append("DEPENDENT")
            independence = "DEPENDENT"

        correlations.append(
            {
                "correlation_id": f"SAMPLELAB-{len(correlations) + 1}",
                "sample_id": sid,
                "laboratory_result_ids": [lr.get("result_id") for lr in labs],
                "measurement_ids": [m.get("measurement_id") for m in related_measurements],
                "sample_independence": independence,
                "note": "Multiple lab runs on the same sample may confirm analysis but are not independent environmental observations.",
                "limitations": [
                    "Sample result is not automatic source attribution.",
                    "Chain of custody and lab quality control must be preserved.",
                ],
            }
        )

    return correlations


# -----------------------------------------------------------------------------
# Contradictions
# -----------------------------------------------------------------------------

def detect_contradictions(
    measurements: List[Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    fusion: List[Dict[str, Any]],
    facility_associations: List[Dict[str, Any]],
    facilities: Dict[str, Dict[str, Any]],
    official_reports: List[Dict[str, Any]],
    weather: Dict[str, Any],
    issues: List[str],
    initial_contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    contradictions = list(initial_contradictions)

    # Count-rate / dose-rate nuclide overclaim
    for m in measurements:
        if "nuclide_claim_without_spectral_or_lab_support" in (m.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "nuclide_identification_overclaim",
                    "measurement_id": m.get("measurement_id"),
                    "note": "Count rate or dose rate alone does not establish radionuclide identity.",
                }
            )

    # Fusion conflicts
    for f in fusion:
        if f.get("agreement") == "CONFLICT":
            contradictions.append(
                {
                    "type": "multi_sensor_conflict",
                    "fusion_id": f.get("fusion_id"),
                    "sensor_ids": f.get("sensor_ids"),
                    "note": "Independent or partially independent sensors disagree beyond uncertainty.",
                }
            )

    # Lab disagreement on same sample
    labs_by_sample: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for lr in lab_results:
        if lr.get("_sample_id"):
            labs_by_sample[lr["_sample_id"]].append(lr)

    for sid, labs in labs_by_sample.items():
        if len(labs) < 2:
            continue
        for i in range(len(labs)):
            for j in range(i + 1, len(labs)):
                n1 = {
                    str(x.get("nuclide_candidate")).upper(): x
                    for x in labs[i].get("_nuclides") or []
                    if x.get("nuclide_candidate")
                }
                n2 = {
                    str(x.get("nuclide_candidate")).upper(): x
                    for x in labs[j].get("_nuclides") or []
                    if x.get("nuclide_candidate")
                }

                common = set(n1) & set(n2)
                for nu in common:
                    a1 = n1[nu].get("activity_norm")
                    a2 = n2[nu].get("activity_norm")
                    u1 = n1[nu].get("uncertainty_norm")
                    u2 = n2[nu].get("uncertainty_norm")
                    if a1 is None or a2 is None:
                        continue
                    if u1 is not None and u2 is not None:
                        combined = math.sqrt(u1 * u1 + u2 * u2)
                        if combined > 0 and abs(a1 - a2) > 3.0 * combined:
                            contradictions.append(
                                {
                                    "type": "lab_activity_conflict",
                                    "sample_id": sid,
                                    "nuclide_candidate": nu,
                                    "laboratory_result_ids": [labs[i].get("result_id"), labs[j].get("result_id")],
                                    "note": "Same-sample lab activities conflict beyond uncertainty.",
                                }
                            )

                if set(n1) != set(n2):
                    contradictions.append(
                        {
                            "type": "lab_nuclide_presence_disagreement",
                            "sample_id": sid,
                            "laboratory_result_ids": [labs[i].get("result_id"), labs[j].get("result_id")],
                            "nuclides_lab_1": sorted(n1),
                            "nuclides_lab_2": sorted(n2),
                            "note": "May reflect method sensitivity, detection limits, or sample heterogeneity; preserve contradiction.",
                        }
                    )

    # Timing conflicts
    for m in measurements:
        if "timing_conflict" in (m.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "timing_conflict",
                    "measurement_id": m.get("measurement_id"),
                    "note": "Measurement/collection/analysis timestamps are inconsistent.",
                }
            )

    for lr in lab_results:
        if "timing_conflict" in (lr.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "timing_conflict",
                    "laboratory_result_id": lr.get("result_id"),
                    "note": "Lab analysis time precedes sample collection time.",
                }
            )

    # Facility status conflict
    for assoc in facility_associations:
        fid = assoc.get("facility_id")
        f = facilities.get(fid, {})
        if assoc.get("state") in {"SUPPORTED", "POSSIBLE"} and f.get("_operational_status") == "SHUTDOWN_REPORTED":
            if not assoc.get("transport_region_supported") and not any(
                rep.get("facility_id") == fid and rep.get("release_confirmed") is True for rep in official_reports
            ):
                contradictions.append(
                    {
                        "type": "facility_status_conflict",
                        "association_id": assoc.get("association_id"),
                        "facility_id": fid,
                        "note": "Facility association is weak or contradicted by reported shutdown status.",
                    }
                )

    # Transport context conflict
    transport_regions = weather.get("candidate_source_regions") or []
    if transport_regions:
        for assoc in facility_associations:
            if assoc.get("state") == "POSSIBLE" and not assoc.get("transport_region_supported"):
                if (assoc.get("distance_km") or 0) <= 50:
                    contradictions.append(
                        {
                            "type": "transport_context_conflict",
                            "association_id": assoc.get("association_id"),
                            "facility_id": assoc.get("facility_id"),
                            "note": "Facility proximity exists but supplied transport candidate regions do not include facility.",
                        }
                    )

    # Sample provenance conflict with significant lab result
    for lr in lab_results:
        sid = lr.get("_sample_id")
        sample = samples.get(sid, {})
        if lr.get("_nuclides") and "chain_of_custody_gap" in (sample.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "sample_provenance_conflict",
                    "sample_id": sid,
                    "laboratory_result_id": lr.get("result_id"),
                    "note": "Laboratory result exists but sample chain of custody is incomplete.",
                }
            )

    # Background insufficiency for claimed signature
    for a in anomalies:
        if a.get("anomaly_state") == "SIGNATURE_OF_INTEREST" and not a.get("baseline_id"):
            contradictions.append(
                {
                    "type": "background_insufficient",
                    "measurement_id": a.get("measurement_id"),
                    "note": "Signature-of-interest state without compatible baseline is not supported.",
                }
            )

    return contradictions


# -----------------------------------------------------------------------------
# Facts / hypotheses / dual review
# -----------------------------------------------------------------------------

def measurement_confidence(m: Dict[str, Any]) -> str:
    flags = set(m.get("_quality_flags") or [])
    cal = m.get("_sensor_calibration_state", "CALIBRATION_UNKNOWN")
    severe = bool(flags & SEVERE_QUALITY_FLAGS)

    if severe:
        return "LOW"
    if cal == "CALIBRATED":
        return "HIGH"
    if cal == "PARTIALLY_CALIBRATED":
        return "MODERATE"
    return "UNKNOWN"


def build_facts(
    measurements: List[Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    radionuclide_candidates: List[Dict[str, Any]],
    release_candidates: List[Dict[str, Any]],
    facility_associations: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "No nuclear weapon design or optimization is supported.",
        "No fissile-material production or enrichment/reprocessing procedure is supported.",
        "No detector evasion, smuggling, sabotage, or targeting conclusion is supported.",
        "Radiation measurement is not material identity.",
        "Count rate is not isotope identification.",
        "Isotope identification is not source facility attribution.",
        "Facility proximity is not source attribution.",
        "Nuclear facility is not weapons activity.",
        "Fuel-cycle activity is not proliferation.",
        "Anomaly is not illicit activity.",
        "Non-detection is not absence.",
        "First detection is not release time.",
        "Satellite activity is not nuclear material confirmation.",
        "Seismic event is not nuclear event automatically.",
        "Thermal activity is not reactor operation uniquely.",
        "Plume/vapor is not radiological release uniquely.",
        "Multiple reports from one regulator are not independent sources.",
        "Multiple lab runs on same sample are not independent environmental observations.",
        "AI agreement is not scientific corroboration.",
    ]

    anomaly_by_meas = {a.get("measurement_id"): a for a in anomalies}

    for m in measurements:
        conf = measurement_confidence(m)
        val = m.get("_value_norm")
        unit = m.get("_unit_norm")
        ts = iso_or_none(m.get("_timestamp"))
        sid = m.get("sensor_id")
        phen = m.get("_measurement_type")

        if val is None:
            partial.append(
                {
                    "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
                    "statement": f"{sid or 'UNKNOWN_SOURCE'} reports no numeric value for {phen} at {ts}; detection_state={m.get('_detection_state')}.",
                    "measurement_id": m.get("measurement_id"),
                    "confidence": "UNKNOWN",
                    "limitation": "Non-detection is not absence.",
                }
            )
            continue

        item = {
            "fact_id": f"FCT-{len(supported) + len(candidates) + len(partial) + 1}",
            "statement": f"{sid or 'UNKNOWN_SOURCE'} measured {val} {unit} for {phen} at {ts}.",
            "measurement_id": m.get("measurement_id"),
            "confidence": conf,
            "quality_flags": m.get("_quality_flags"),
        }

        if conf == "HIGH":
            supported.append(item)
        elif conf == "MODERATE":
            candidates.append(item)
        else:
            partial.append(item)

        a = anomaly_by_meas.get(m.get("measurement_id"))
        if a and a.get("anomaly_state") in {"MINOR_DEVIATION", "MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"}:
            candidates.append(
                {
                    "fact_id": f"FCT-ANOM-{len(candidates) + 1}",
                    "statement": f"Measurement {m.get('measurement_id')} deviates from selected baseline: {a.get('anomaly_state')}.",
                    "measurement_id": m.get("measurement_id"),
                    "confidence": a.get("confidence", "LOW"),
                    "limitation": "Anomaly does not establish illicit activity, weapon event, or source identity.",
                }
            )

    for lr in lab_results:
        conf = "LOW"
        if not (set(lr.get("_quality_flags") or []) & SEVERE_QUALITY_FLAGS) and lr.get("method") and lr.get("quality_controls"):
            conf = "MODERATE"

        candidates.append(
            {
                "fact_id": f"FCT-LAB-{len(candidates) + 1}",
                "statement": f"Laboratory result {lr.get('result_id')} reports nuclides for sample {lr.get('_sample_id')} at {iso_or_none(lr.get('_analysis_time'))}.",
                "laboratory_result_id": lr.get("result_id"),
                "confidence": conf,
                "limitation": "Lab result is not automatic event origin or facility attribution.",
            }
        )

    for n in radionuclide_candidates:
        if n.get("state") in {"SPECTRAL_CANDIDATE", "LAB_REPORTED_NUCLIDE"}:
            candidates.append(
                {
                    "fact_id": f"FCT-NUC-{len(candidates) + 1}",
                    "statement": f"Radionuclide candidate {n.get('nuclide_candidate')} is supported by {n.get('method')}.",
                    "candidate_id": n.get("candidate_id"),
                    "confidence": "MODERATE" if n.get("state") == "LAB_REPORTED_NUCLIDE" else "LOW",
                    "limitation": "Radionuclide candidate is not source identity.",
                }
            )
        else:
            partial.append(
                {
                    "fact_id": f"FCT-NUC-{len(partial) + 1}",
                    "statement": f"Radionuclide candidate {n.get('nuclide_candidate')} is weak/disputed.",
                    "candidate_id": n.get("candidate_id"),
                    "confidence": "LOW",
                    "limitation": "Insufficient spectral/lab support or quality issues.",
                }
            )

    for rel in release_candidates:
        if rel.get("state") in {"RELEASE_CONFIRMED", "RELEASE_SUPPORTED"}:
            supported.append(
                {
                    "fact_id": f"FCT-REL-{len(supported) + 1}",
                    "statement": f"Environmental release assessment for {rel.get('release_candidate_id')} is {rel.get('state')}.",
                    "release_candidate_id": rel.get("release_candidate_id"),
                    "confidence": "MODERATE" if rel.get("state") == "RELEASE_SUPPORTED" else "HIGH",
                    "limitation": "Release assessment is not source, operator, or intent attribution.",
                }
            )
        elif rel.get("state") == "RELEASE_CANDIDATE":
            candidates.append(
                {
                    "fact_id": f"FCT-REL-{len(candidates) + 1}",
                    "statement": f"Environmental release candidate {rel.get('release_candidate_id')} is {rel.get('state')}.",
                    "release_candidate_id": rel.get("release_candidate_id"),
                    "confidence": "LOW",
                    "limitation": "Candidate requires independent corroboration.",
                }
            )

    for assoc in facility_associations:
        if assoc.get("state") in {"SUPPORTED", "DIRECTLY_SUPPORTED"}:
            candidates.append(
                {
                    "fact_id": f"FCT-ASSOC-{len(candidates) + 1}",
                    "statement": f"Facility association {assoc.get('association_id')} for {assoc.get('facility_id')} is {assoc.get('state')}.",
                    "association_id": assoc.get("association_id"),
                    "confidence": "MODERATE",
                    "limitation": "Facility association is not proof of active process, operator, or intent.",
                }
            )
        else:
            partial.append(
                {
                    "fact_id": f"FCT-ASSOC-{len(partial) + 1}",
                    "statement": f"Facility association {assoc.get('association_id')} for {assoc.get('facility_id')} is {assoc.get('state')}.",
                    "association_id": assoc.get("association_id"),
                    "confidence": "LOW",
                    "limitation": "Proximity or declared status alone is weak evidence.",
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
    release_candidates: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    radionuclide_candidates: List[Dict[str, Any]],
    facility_associations: List[Dict[str, Any]],
    weather: Dict[str, Any],
    issues: List[str],
    contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    focus = []

    for rel in release_candidates:
        if rel.get("state") in {"RELEASE_CANDIDATE", "RELEASE_SUPPORTED", "RELEASE_CONFIRMED"}:
            focus.append(("release", rel))

    for a in anomalies:
        if a.get("anomaly_state") in {"MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"}:
            focus.append(("anomaly", a))

    for idx, (kind, obj) in enumerate(focus, 1):
        base = {
            "hypothesis_set_id": f"HSET-{idx}",
            "kind": kind,
            "id": obj.get("release_candidate_id") or obj.get("measurement_id"),
        }

        assoc = obj.get("facility_associations") if kind == "release" else []
        transport_regions = weather.get("candidate_source_regions") or []
        severe = bool(set((obj.get("anomaly") or {}).get("notes", [])) & {"Severe quality flags present; anomaly interpretation disputed."})

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-NATURAL_BACKGROUND",
                "statement": "Observation may be natural background variation or local geological/environmental variability.",
                "support": [
                    "Baseline comparison available." if obj.get("anomaly", {}).get("baseline_id") or obj.get("state") == "BACKGROUND_VARIATION" else "No strong baseline objection recorded.",
                    "No independent corroborating signature recorded." if not radionuclide_candidates else "Radionuclide candidate present, weakening pure background hypothesis.",
                ],
                "opposition": [
                    "Material deviation or lab-confirmed radionuclide present." if obj.get("state") in {"RELEASE_CANDIDATE", "RELEASE_SUPPORTED"} or (obj.get("anomaly") or {}).get("anomaly_state") in {"MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"} else "No strong deviation recorded.",
                ],
                "unknowns": ["Local geology", "seasonal background", "sensor baseline adequacy"],
                "falsification_conditions": [
                    "Context-matched natural background baseline explains full observation.",
                    "Independent sensors show same pattern without source presence.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-MEDICAL_SOURCE",
                "statement": "Observation may originate from medical isotope use, transport, waste, or patient-related traces.",
                "support": ["Medical source context supplied." if any(a.get("source_class") == "MEDICAL" for a in facility_associations) else "No explicit medical context recorded."],
                "opposition": ["Radionuclide/lab evidence may not match typical medical context." if radionuclide_candidates else "No radionuclide evidence recorded."],
                "unknowns": ["Hospital/clinic activity", "transport records", "waste handling"],
                "falsification_conditions": [
                    "Authorized medical records exclude relevant activity during time window.",
                    "Isotope/lab signature inconsistent with medical sources.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-INDUSTRIAL_SOURCE",
                "statement": "Observation may originate from licensed industrial radiography, gauging, well logging, or other industrial sources.",
                "support": ["Industrial source context supplied." if any(a.get("source_class") == "INDUSTRIAL" for a in facility_associations) else "No explicit industrial context recorded."],
                "opposition": ["Radionuclide/lab evidence may require stronger industrial correlation." if radionuclide_candidates else "No radionuclide evidence recorded."],
                "unknowns": ["Industrial license records", "source inventory", "operations schedule"],
                "falsification_conditions": [
                    "Authorized industrial records exclude relevant source/activity.",
                    "Spectral/lab signature inconsistent with industrial sources.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-RESEARCH_ACTIVITY",
                "statement": "Observation may relate to lawful research institution handling of radioactive sources.",
                "support": ["Research facility context supplied." if any(a.get("source_class") == "RESEARCH" for a in facility_associations) else "No explicit research context recorded."],
                "opposition": ["No independent facility/report correlation." if not assoc else "Facility association present but not proof."],
                "unknowns": ["Research license", "experiment schedule", "source inventory"],
                "falsification_conditions": [
                    "Authorized research records exclude relevant activity.",
                    "Environmental transport/timing does not support research source.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-DECLARED_FACILITY_OPERATION",
                "statement": "Observation may relate to declared civilian nuclear facility operation or regulated activity.",
                "support": [
                    "Facility association possible/supported." if any(a.get("state") in {"POSSIBLE", "SUPPORTED", "DIRECTLY_SUPPORTED"} for a in assoc) else "No facility association recorded.",
                    "Official/public report linkage present." if any(a.get("state") == "SUPPORTED" for a in assoc) else "No official linkage recorded.",
                ],
                "opposition": [
                    "Facility reported shutdown or status unknown." if any(a.get("facility_operational_status") in {"SHUTDOWN_REPORTED", "UNKNOWN"} for a in assoc) else "No status objection recorded.",
                    "Transport context does not support facility." if transport_regions and not any(a.get("transport_region_supported") for a in assoc) else "No transport objection recorded.",
                ],
                "unknowns": ["Declared activity", "operational state", "regulatory findings"],
                "falsification_conditions": [
                    "Official safeguards/regulatory records exclude relevant release or operation.",
                    "Independent environmental sampling and transport analysis exclude facility.",
                ],
                "restriction": "Declared fuel-cycle activity is not automatically proliferation or weapons activity.",
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-ENVIRONMENTAL_TRANSPORT",
                "statement": "Observation may be transported from another region by atmosphere, water, or particulate movement.",
                "support": [
                    "Weather/transport candidate regions supplied." if transport_regions else "No transport model supplied.",
                    "Detection timing/location may not match local source." if not assoc else "Local facility association exists but transport may still apply.",
                ],
                "opposition": [
                    "Strong local facility/report correlation." if any(a.get("state") in {"SUPPORTED", "DIRECTLY_SUPPORTED"} for a in assoc) else "No strong local correlation recorded.",
                ],
                "unknowns": ["Wind field", "precipitation", "air-mass history", "deposition"],
                "falsification_conditions": [
                    "Independent transport model excludes all plausible source regions.",
                    "Multiple independent sensors localize source locally with high confidence.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-SENSOR_CALIBRATION_ARTIFACT",
                "statement": "Observation may be caused by sensor drift, calibration error, saturation, electronics, or processing artifact.",
                "support": [
                    "Quality flags present." if severe or issues else "No severe quality flags recorded.",
                    "Calibration state not fully trusted." if any(a.get("state") == "WEAK" for a in assoc) or issues else "No calibration objection recorded.",
                ],
                "opposition": [
                    "Independent calibrated sensors/lab agree." if any(a.get("state") == "SUPPORTED" for a in assoc) and not issues else "No strong independent corroboration recorded.",
                ],
                "unknowns": ["Sensor health logs", "calibration certificate", "processing pipeline"],
                "falsification_conditions": [
                    "Sensor self-test/calibration record confirms healthy operation.",
                    "Independent sensor reproduces same measurement within uncertainty.",
                ],
            }
        )

        hypotheses.append(
            {
                **base,
                "hypothesis_id": f"H{idx}-UNRESOLVED_RADIOLOGICAL_EVENT",
                "statement": "Observation may represent an unresolved radiological event requiring authorized human/scientific review.",
                "support": [
                    "Material deviation or lab-confirmed radionuclide present." if obj.get("state") in {"RELEASE_CANDIDATE", "RELEASE_SUPPORTED", "RELEASE_CONFIRMED"} or (obj.get("anomaly") or {}).get("anomaly_state") in {"MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"} else "No strong event indicator recorded.",
                    "Contradictions present." if contradictions else "No contradictions recorded.",
                ],
                "opposition": [
                    "Benign explanation fully supported." if obj.get("state") == "BACKGROUND_VARIATION" else "No benign explanation fully recorded.",
                ],
                "unknowns": ["Source", "facility", "operator", "intent", "material identity"],
                "falsification_conditions": [
                    "Authorized regulator/safeguards/laboratory evidence resolves source class.",
                    "Independent measurements exclude anomalous event.",
                ],
                "restriction": "Unresolved radiological event is not automatically nuclear weapon activity.",
            }
        )

    if issues:
        hypotheses.append(
            {
                "hypothesis_set_id": "HSET-GLOBAL",
                "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
                "statement": "Validation issues materially weaken all nuclear/radiological interpretations.",
                "support": issues[:10],
                "opposition": ["No independent clean source supplied yet."],
                "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
            }
        )

    return hypotheses


def dual_ai_review(
    measurements: List[Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    release_candidates: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary Nuclear Signature Analyst",
        "assessment": (
            "Radiological measurements and/or laboratory results exist."
            if measurements or lab_results
            else "No usable nuclear/radiological measurements were supplied."
        ),
        "classification": "Source-class and facility-association conclusions remain conservative and evidence-bounded.",
    }

    if not measurements and not lab_results:
        skeptic = {
            "role": "Independent Nuclear Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No deterministic measurements or lab results were supplied. Do not infer nuclear events from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Nuclear Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Nuclear Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions must be preserved; do not silently resolve sensor/lab/facility conflicts.",
        }
    elif any(r.get("state") in {"RELEASE_SUPPORTED", "RELEASE_CONFIRMED"} for r in release_candidates):
        skeptic = {
            "role": "Independent Nuclear Skeptic",
            "verdict": "AGREE_ON_RADIOLOGICAL_OBSERVATION_ONLY",
            "reason": "Independent measurement/lab/official context may support radiological observation assessment only, not weapon, operator, or intent attribution.",
        }
    else:
        skeptic = {
            "role": "Independent Nuclear Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Single-source or incomplete evidence supports candidate observations only.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not independent scientific corroboration. Human review required for consequential nuclear/radiological conclusions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    facilities: Dict[str, Dict[str, Any]],
    sensors: Dict[str, Dict[str, Any]],
    measurements: List[Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    radionuclide_candidates: List[Dict[str, Any]],
    source_class_candidates: List[Dict[str, Any]],
    release_candidates: List[Dict[str, Any]],
    facility_associations: List[Dict[str, Any]],
    facts: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    official_reports: List[Dict[str, Any]],
    seismic_context: List[Dict[str, Any]],
    satellite_context: List[Dict[str, Any]],
    weather: Dict[str, Any],
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

    for fid, f in facilities.items():
        add_node(fid, "Facility", public_dict(f))

    for sid, s in sensors.items():
        add_node(sid, "Sensor", public_dict(s))

    for m in measurements:
        mid = m.get("measurement_id")
        add_node(
            mid,
            "Measurement",
            {
                "sensor_id": m.get("sensor_id"),
                "sample_id": m.get("sample_id"),
                "measurement_type": m.get("_measurement_type"),
                "value": m.get("_value_norm"),
                "unit": m.get("_unit_norm"),
                "uncertainty": m.get("_unc_norm"),
                "timestamp": iso_or_none(m.get("_timestamp")),
                "quality_flags": m.get("_quality_flags"),
                "spatial_cluster_id": m.get("_spatial_cluster_id"),
            },
        )
        if m.get("sensor_id"):
            add_edge(mid, m["sensor_id"], "MEASURED_BY", {"measurement_id": mid})
        if m.get("sample_id"):
            add_edge(mid, m["sample_id"], "OBSERVED_AT", {"measurement_id": mid})

    for sid, s in samples.items():
        add_node(
            sid,
            "Sample",
            {
                "sample_type": s.get("_sample_type"),
                "collection_time": iso_or_none(s.get("_collection_time")),
                "location": {
                    "latitude": s.get("_lat"),
                    "longitude": s.get("_lon"),
                    "area_id": s.get("_area_id"),
                },
                "quality_flags": s.get("_quality_flags"),
            },
        )

    for lr in lab_results:
        rid = lr.get("result_id")
        add_node(
            rid,
            "Laboratory",
            {
                "sample_id": lr.get("_sample_id"),
                "method": lr.get("method"),
                "instrument": lr.get("instrument"),
                "analysis_time": iso_or_none(lr.get("_analysis_time")),
                "quality_flags": lr.get("_quality_flags"),
            },
        )
        if lr.get("_sample_id"):
            add_edge(rid, lr["_sample_id"], "ANALYZED_BY", {"result_id": rid})

    for n in radionuclide_candidates:
        nid = n.get("candidate_id")
        add_node(nid, "RadionuclideCandidate", n)
        if n.get("measurement_id"):
            add_edge(nid, n["measurement_id"], "SUPPORTED_BY", {"candidate_id": nid})
        if n.get("laboratory_result_id"):
            add_edge(nid, n["laboratory_result_id"], "SUPPORTED_BY", {"candidate_id": nid})

    for sc in source_class_candidates:
        scid = f"SRCCLASS:{sc.get('source_class')}"
        add_node(scid, "MaterialClass", sc)

    for rel in release_candidates:
        rid = rel.get("release_candidate_id")
        add_node(rid, "ReleaseCandidate", rel)
        if rel.get("measurement_id"):
            add_edge(rid, rel["measurement_id"], "SUPPORTED_BY", {"release_candidate_id": rid})
        if rel.get("sample_id"):
            add_edge(rid, rel["sample_id"], "SUPPORTED_BY", {"release_candidate_id": rid})

    for assoc in facility_associations:
        aid = assoc.get("association_id")
        add_node(aid, "EnvironmentalObservation", assoc)
        if assoc.get("facility_id"):
            add_edge(aid, assoc["facility_id"], "ASSOCIATED_WITH_CANDIDATE", {"association_id": aid})
        if assoc.get("observation_id"):
            add_edge(assoc["observation_id"], aid, "CORRELATED_WITH", {"association_id": aid})

    for rep in official_reports:
        rid = rep.get("report_id")
        add_node(rid, "SafeguardsReport" if str(rep.get("report_type", "")).upper() in {"SAFEGUARDS", "TREATY"} else "Regulator", rep)
        if rep.get("facility_id"):
            add_edge(rid, rep["facility_id"], "REPORTED_BY", {"report_id": rid})

    for ev in seismic_context:
        eid = ev.get("event_id")
        add_node(eid, "SeismicEvent", ev)

    for ob in satellite_context:
        oid = ob.get("observation_id")
        add_node(oid, "SatelliteObservation", ob)

    if weather:
        add_node("WEATHER_CONTEXT", "WeatherObservation", weather)

    for fac in facts:
        fid = fac.get("fact_id")
        add_node(fid, "Fact", fac)
        for key in ("measurement_id", "sample_id", "laboratory_result_id", "release_candidate_id", "association_id", "candidate_id"):
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
# Gaps / actions / handoffs / summary
# -----------------------------------------------------------------------------

def build_knowledge_gaps(
    measurements: List[Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    release_candidates: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
    sensors: Dict[str, Dict[str, Any]],
    backgrounds: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not measurements and not samples and not lab_results:
        gaps.append(
            {
                "gap_id": "GAP-NO-MEASUREMENTS",
                "gap": "No deterministic nuclear/radiological measurements or samples supplied",
                "importance": "HIGH",
                "recommended_source": "Authorized radiation monitoring network / accredited laboratory / official regulator",
                "expected_information_value": "Establishes whether any radiological signature is measurable",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Input validation issues present",
                "importance": "HIGH",
                "recommended_source": "Corrected sensor metadata, calibration records, sample chain of custody, lab QC",
                "expected_information_value": "Improves measurement trust",
            }
        )

    unknown_cal = [sid for sid, s in sensors.items() if s.get("_calibration_status") in ("UNCALIBRATED", "CALIBRATION_UNKNOWN", "CALIBRATION_EXPIRED")]
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

    if not backgrounds:
        gaps.append(
            {
                "gap_id": "GAP-BACKGROUND",
                "gap": "No background/baseline records supplied",
                "importance": "HIGH",
                "recommended_source": "Local/time-relevant background radiation baseline",
                "expected_information_value": "Prevents fake anomalies from natural variation",
            }
        )

    if any(a.get("anomaly_state") in {"MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"} for a in anomalies):
        gaps.append(
            {
                "gap_id": "GAP-ANOMALY-CORROBORATION",
                "gap": "Anomalous radiological measurement requires independent corroboration",
                "importance": "HIGH",
                "recommended_source": "Independent sensor / accredited laboratory / official regulator",
                "expected_information_value": "Reduces false nuclear-event risk",
            }
        )

    if any(not s.get("collector") or "chain_of_custody_gap" in (s.get("_quality_flags") or []) for s in samples.values()):
        gaps.append(
            {
                "gap_id": "GAP-CHAIN-OF-CUSTODY",
                "gap": "Sample chain of custody incomplete",
                "importance": "HIGH",
                "recommended_source": "Authorized collector records / lab custody transfer logs",
                "expected_information_value": "Supports evidentiary reliability",
            }
        )

    if contradictions:
        gaps.append(
            {
                "gap_id": "GAP-CONTRADICTIONS",
                "gap": "Material contradictions present",
                "importance": "HIGH",
                "recommended_source": "Raw sensor records, lab methods, official reports, transport model metadata",
                "expected_information_value": "Prevents silent false resolution",
            }
        )

    if release_candidates and all(r.get("state") in {"RELEASE_CANDIDATE", "UNKNOWN"} for r in release_candidates):
        gaps.append(
            {
                "gap_id": "GAP-RELEASE-UNRESOLVED",
                "gap": "Environmental release remains unresolved",
                "importance": "MODERATE",
                "recommended_source": "Independent sampling, lab confirmation, atmospheric transport, official facility status",
                "expected_information_value": "Distinguishes release candidate from background/artifact",
            }
        )

    gaps.append(
        {
            "gap_id": "GAP-SOURCE-IDENTITY",
            "gap": "Source/facility/operator identity unresolved by design unless stronger evidence exists",
            "importance": "CONTEXTUAL",
            "recommended_source": "Authorized safeguards/regulatory records / independent environmental evidence",
            "expected_information_value": "NUCINT alone rarely establishes attribution",
        }
    )

    return gaps


def build_next_actions(
    measurements: List[Dict[str, Any]],
    samples: Dict[str, Dict[str, Any]],
    lab_results: List[Dict[str, Any]],
    release_candidates: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not measurements and not samples and not lab_results:
        actions.append("Supply deterministic authorized radiation measurements, environmental samples, and/or laboratory results")

    if any(g["gap_id"] == "GAP-CALIBRATION" for g in gaps):
        actions.append("Obtain calibration record or recalibrate sensor before high-confidence interpretation")

    if any(g["gap_id"] == "GAP-BACKGROUND" for g in gaps):
        actions.append("Build local/time-relevant background baseline before anomaly interpretation")

    if any(g["gap_id"] == "GAP-CHAIN-OF-CUSTODY" for g in gaps):
        actions.append("Complete sample chain-of-custody records before relying on laboratory results")

    if any(g["gap_id"] == "GAP-ANOMALY-CORROBORATION" for g in gaps):
        actions.append("Request independent sensor measurement and/or accredited laboratory analysis")

    if contradictions:
        actions.append("Preserve contradictions and inspect raw sensor/lab/official provenance before resolution")

    if release_candidates:
        actions.append("Correlate release candidates with official facility status, weather transport, seismic/satellite context, and independent sampling")

    actions.append("Maintain lawful defensive / non-proliferation posture; no weapon design, material production, detector evasion, smuggling, sabotage, or targeting support")

    return actions


def build_specialist_handoffs(
    release_candidates: List[Dict[str, Any]],
    facility_associations: List[Dict[str, Any]],
    seismic_context: List[Dict[str, Any]],
    satellite_context: List[Dict[str, Any]],
    weather: Dict[str, Any],
    official_reports: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if seismic_context or any(r.get("state") in {"RELEASE_CANDIDATE", "RELEASE_SUPPORTED"} for r in release_candidates):
        handoffs.append(
            {
                "to": "SEISINT",
                "reason": "Seismic correlation may support or contradict event hypothesis",
                "restrictions": ["Seismic event alone is not nuclear event", "Preserve uncertainty"],
            }
        )

    if satellite_context or facility_associations:
        handoffs.append(
            {
                "to": "SATINT",
                "reason": "Facility/construction/thermal/surface-change context may support high-level correlation",
                "restrictions": ["Satellite activity is not nuclear material confirmation"],
            }
        )

    if weather.get("candidate_source_regions") or release_candidates:
        handoffs.append(
            {
                "to": "GEOINT / atmospheric specialist",
                "reason": "Transport, deposition, terrain, and spatial validation may be required",
                "restrictions": ["Transport model is not source proof", "No targeting coordinates"],
            }
        )

    if official_reports:
        handoffs.append(
            {
                "to": "LEGALINT / safeguards authority",
                "reason": "Official regulatory/safeguards/treaty context requires human/legal governance",
                "restrictions": ["AI does not make legal conclusions", "Humans govern consequential nuclear claims"],
            }
        )

    if any(a.get("state") in {"SUPPORTED", "POSSIBLE"} for a in facility_associations):
        handoffs.append(
            {
                "to": "CORPINT / ORGINT",
                "reason": "Operator/organization context exceeds radiological signature evidence",
                "restrictions": ["No intent attribution", "No proliferation conclusion without authoritative evidence"],
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

    measurements = r.get("measurements") or []
    anomalies = r.get("anomalies") or []
    releases = r.get("release_candidates") or []
    assoc = r.get("facility_associations") or []
    nuclides = r.get("radionuclide_candidates") or []

    lines = [
        "NUCLEAR / RADIOLOGICAL STATUS: " + str(r.get("status")),
        "MEASUREMENT TYPE: " + fmt_list(sorted({m.get("measurement_type") for m in measurements if m.get("measurement_type")})),
        "SENSOR / SAMPLE: sensors=" + fmt_list(r.get("sensor_ids")) + " samples=" + fmt_list(list((r.get("samples") or {}).keys())),
        "LOCATION: " + fmt_list(sorted({m.get("location", {}).get("spatial_cluster_id") for m in measurements if m.get("location")})),
        "TIME RANGE: " + str(r.get("time_range")),
        "BACKGROUND CONTEXT: baselines=" + str(len(r.get("background_models") or [])),
        "CALIBRATION / QUALITY: " + fmt_list([f"{k}={v}" for k, v in (r.get("calibration_context") or {}).items()]),
        "SIGNATURE: anomalies=" + fmt_list([f"{a.get('measurement_id')}={a.get('anomaly_state')}" for a in anomalies]),
        "RADIONUCLIDE CANDIDATES: " + fmt_list([f"{n.get('nuclide_candidate')}:{n.get('state')}" for n in nuclides]),
        "SOURCE CLASS CANDIDATES: " + fmt_list([f"{s.get('source_class')}:{s.get('state')}" for s in (r.get("material_class_candidates") or [])]),
        "FACILITY CONTEXT: " + fmt_list([f"{a.get('facility_id')}={a.get('state')}" for a in assoc]),
        "ENVIRONMENTAL CONTEXT: releases=" + fmt_list([f"{x.get('release_candidate_id')}={x.get('state')}" for x in releases]),
        "SEISMIC CONTEXT: " + str(len(r.get("seismic_context") or [])),
        "SATELLITE CONTEXT: " + str(len(r.get("satellite_context") or [])),
        "WEATHER / TRANSPORT CONTEXT: " + json.dumps(r.get("weather_context") or {}, default=str),
        "MULTI-SENSOR AGREEMENT: " + fmt_list([f"{f.get('fusion_id')}={f.get('agreement')}" for f in (r.get("multi_sensor_fusion") or [])]),
        "SOURCE RELIABILITY: " + fmt_list([f"{s.get('source_id')}={s.get('reliability')}" for s in (r.get("source_reliability") or [])]),
        "SOURCE INDEPENDENCE: " + str(r.get("source_independence")),
        "CONTRADICTIONS: " + str(len(r.get("contradictions") or [])),
        "BENIGN EXPLANATIONS: " + str(len(r.get("hypotheses") or [])),
        "EVENT ASSESSMENT: " + fmt_list([f"{x.get('release_candidate_id')}={x.get('state')}" for x in releases]),
        "UNCERTAINTY: " + json.dumps(r.get("uncertainties") or {}, default=str),
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
    samples, sample_issues, sample_warnings = validate_samples(case)
    measurements, meas_issues, meas_warnings = validate_measurements(case, sensors, samples)
    lab_results, lab_issues, lab_warnings = validate_laboratory_results(case, samples)
    facilities, fac_issues = validate_facilities(case)
    backgrounds, bg_issues = validate_backgrounds(case, sensors)

    issues = sensor_issues + sample_issues + meas_issues + lab_issues + fac_issues + bg_issues
    warnings = sample_warnings + meas_warnings + lab_warnings

    settings_raw = case.get("analysis_settings") or {}

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    settings = {
        "spatial_cluster_distance_km": setting_float("spatial_cluster_distance_km", 10.0),
        "fusion_time_window_s": setting_float("fusion_time_window_s", 3600.0),
        "conflict_sigma": setting_float("conflict_sigma", 3.0),
        "facility_radius_km": setting_float("facility_radius_km", 50.0),
        "official_report_time_window_s": setting_float("official_report_time_window_s", 86400.0),
    }

    # Spatial clustering
    all_spatial_items = measurements + list(samples.values())
    spatial_clusters = build_spatial_clusters(all_spatial_items, settings["spatial_cluster_distance_km"])

    # Anomaly analysis
    anomalies = [analyze_anomaly(m, backgrounds) for m in measurements]

    # Radionuclide candidates
    radionuclide_candidates = collect_radionuclide_candidates(measurements, lab_results)

    # Facility associations
    facility_associations = associate_facilities(
        measurements + list(samples.values()) + lab_results,
        facilities,
        case.get("weather_context") or case.get("weather_data") or {},
        case.get("official_reports") or [],
        settings,
    )

    # Source class candidates
    source_class_candidates = collect_source_class_candidates(
        measurements,
        samples,
        lab_results,
        facilities,
        facility_associations,
        case.get("official_reports") or [],
        case,
    )

    # Release candidates
    release_candidates = assess_release_candidates(
        measurements,
        samples,
        lab_results,
        anomalies,
        radionuclide_candidates,
        facility_associations,
        case.get("official_reports") or [],
    )

    # Fusion / correlation
    fusion, fusion_contradictions = fuse_measurements(measurements, sensors, settings)
    sample_lab_correlations = correlate_samples_and_labs(samples, lab_results, measurements)

    weather = case.get("weather_context") or case.get("weather_data") or {}
    seismic_context = ensure_list(case.get("seismic_context"))
    satellite_context = ensure_list(case.get("satellite_context"))
    official_reports = ensure_list(case.get("official_reports"))

    contradictions = detect_contradictions(
        measurements,
        samples,
        lab_results,
        anomalies,
        fusion,
        facility_associations,
        facilities,
        official_reports,
        weather,
        issues,
        list(case.get("existing_contradictions") or []) + fusion_contradictions,
    )

    supported_facts, candidate_facts, partial_facts, disputed_facts, not_facts = build_facts(
        measurements,
        samples,
        lab_results,
        anomalies,
        radionuclide_candidates,
        release_candidates,
        facility_associations,
        contradictions,
    )

    hypotheses = build_hypotheses(
        release_candidates,
        anomalies,
        radionuclide_candidates,
        facility_associations,
        weather,
        issues,
        contradictions,
    )

    dual = dual_ai_review(
        measurements,
        lab_results,
        release_candidates,
        anomalies,
        contradictions,
        issues,
    )

    gaps = build_knowledge_gaps(
        measurements,
        samples,
        lab_results,
        anomalies,
        release_candidates,
        contradictions,
        issues,
        sensors,
        backgrounds,
    )

    next_actions = build_next_actions(
        measurements,
        samples,
        lab_results,
        release_candidates,
        gaps,
        contradictions,
    )

    handoffs = build_specialist_handoffs(
        release_candidates,
        facility_associations,
        seismic_context,
        satellite_context,
        weather,
        official_reports,
    )

    graph = build_graph(
        facilities,
        sensors,
        measurements,
        samples,
        lab_results,
        radionuclide_candidates,
        source_class_candidates,
        release_candidates,
        facility_associations,
        supported_facts + candidate_facts + partial_facts,
        hypotheses,
        contradictions,
        gaps,
        official_reports,
        seismic_context,
        satellite_context,
        weather,
    )

    # Public measurement objects
    measurement_public = []
    for m in measurements:
        measurement_public.append(
            {
                "measurement_id": m.get("measurement_id"),
                "sensor_id": m.get("sensor_id"),
                "sample_id": m.get("sample_id"),
                "facility_id": m.get("facility_id"),
                "measurement_type": m.get("_measurement_type"),
                "quantity_type": m.get("_quantity_type"),
                "original_value": m.get("_original_value"),
                "original_unit": m.get("_original_unit"),
                "value": m.get("_value_norm"),
                "unit": m.get("_unit_norm"),
                "uncertainty": m.get("_unc_norm"),
                "detection_limit": m.get("_detection_limit_norm"),
                "detection_limit_unit": m.get("_detection_limit_unit"),
                "detection_state": m.get("_detection_state"),
                "timestamp": iso_or_none(m.get("_timestamp")),
                "collection_time": iso_or_none(m.get("_collection_time")),
                "analysis_time": iso_or_none(m.get("_analysis_time")),
                "location": {
                    "latitude": m.get("_lat"),
                    "longitude": m.get("_lon"),
                    "accuracy_m": m.get("_location_accuracy_m"),
                    "area_id": m.get("_area_id"),
                    "spatial_cluster_id": m.get("_spatial_cluster_id"),
                },
                "method": m.get("method"),
                "instrument_type": m.get("instrument_type"),
                "calibration_reference": m.get("calibration_reference"),
                "quality_flags": m.get("_quality_flags"),
                "radionuclide_candidates": m.get("_radionuclide_candidates"),
                "source_class_candidates": m.get("_source_class_candidates"),
                "source_ids": m.get("_source_ids"),
                "evidence_ids": m.get("_evidence_ids"),
                "confidence": measurement_confidence(m),
                "limitations": [
                    "Measurement is not material identity.",
                    "Count rate is not isotope identification.",
                    "Non-detection is not absence.",
                ],
            }
        )

    sample_public = {
        sid: {
            "sample_id": s.get("sample_id"),
            "sample_type": s.get("_sample_type"),
            "collection_location": {
                "latitude": s.get("_lat"),
                "longitude": s.get("_lon"),
                "accuracy_m": s.get("_location_accuracy_m"),
                "area_id": s.get("_area_id"),
                "spatial_cluster_id": s.get("_spatial_cluster_id"),
            },
            "collection_time": iso_or_none(s.get("_collection_time")),
            "collector": s.get("collector"),
            "chain_of_custody": s.get("chain_of_custody"),
            "preservation_method": s.get("preservation_method"),
            "analysis_lab": s.get("analysis_lab"),
            "analysis_method": s.get("analysis_method"),
            "quality_flags": s.get("_quality_flags"),
            "source_ids": s.get("_source_ids"),
            "evidence_ids": s.get("_evidence_ids"),
            "limitations": [
                "Sample result is not automatic event origin.",
                "Chain of custody affects evidentiary reliability.",
            ],
        }
        for sid, s in samples.items()
    }

    lab_public = []
    for lr in lab_results:
        lab_public.append(
            {
                "result_id": lr.get("result_id"),
                "sample_id": lr.get("_sample_id"),
                "lab_id": lr.get("lab_id"),
                "method": lr.get("method"),
                "instrument": lr.get("instrument"),
                "analysis_time": iso_or_none(lr.get("_analysis_time")),
                "quality_controls": lr.get("quality_controls"),
                "nuclides": lr.get("_nuclides"),
                "quality_flags": lr.get("_quality_flags"),
                "source_ids": lr.get("_source_ids"),
                "evidence_ids": lr.get("_evidence_ids"),
                "limitations": [
                    "Laboratory result is not source/facility attribution.",
                    "Same-sample repeat analyses are not independent environmental observations.",
                ],
            }
        )

    facility_public = {
        fid: {
            "facility_id": f.get("facility_id"),
            "facility_type": f.get("_facility_type"),
            "operator": f.get("operator"),
            "location": {
                "latitude": f.get("_lat"),
                "longitude": f.get("_lon"),
                "accuracy_m": f.get("_location_accuracy_m"),
                "area_id": f.get("_area_id"),
            },
            "declared_status": f.get("_declared_status"),
            "operational_status": f.get("_operational_status"),
            "public_regulatory_context": f.get("public_regulatory_context"),
            "known_activities": f.get("known_activities"),
            "valid_from": iso_or_none(f.get("_valid_from")),
            "valid_to": iso_or_none(f.get("_valid_to")),
            "limitations": [
                "Facility type does not prove active process.",
                "Declared status is source-reported until independently supported.",
            ],
        }
        for fid, f in facilities.items()
    }

    background_public = [
        {
            "baseline_id": b.get("baseline_id"),
            "sensor_id": b.get("sensor_id"),
            "measurement_type": b.get("_measurement_type"),
            "quantity_type": b.get("_quantity_type"),
            "mean": b.get("_mean_norm"),
            "std": b.get("_std_norm"),
            "uncertainty": b.get("_unc_norm"),
            "unit": b.get("_unit_norm"),
            "valid_from": iso_or_none(b.get("_valid_from")),
            "valid_to": iso_or_none(b.get("_valid_to")),
            "limitations": ["Baseline must be location-, sensor-, time-, and instrument-matched."],
        }
        for b in backgrounds
    ]

    units_used = sorted({m.get("_unit_norm") for m in measurements if m.get("_unit_norm")})
    quantity_types_used = sorted({m.get("_quantity_type") for m in measurements if m.get("_quantity_type") and m.get("_quantity_type") != "UNKNOWN"})

    uncertainty_summary = {
        "measurements_with_uncertainty": sum(1 for m in measurements if m.get("_unc_norm") is not None),
        "measurements_without_uncertainty": sum(1 for m in measurements if m.get("_unc_norm") is None),
        "lab_results_with_uncertainty": sum(
            1
            for lr in lab_results
            for n in (lr.get("_nuclides") or [])
            if n.get("uncertainty_norm") is not None
        ),
        "note": "Missing uncertainty reduces confidence; do not infer precision from display resolution.",
    }

    detection_limits = [m.get("_detection_limit_norm") for m in measurements if m.get("_detection_limit_norm") is not None]

    coverage = {
        "measurement_count": len(measurements),
        "sample_count": len(samples),
        "laboratory_result_count": len(lab_results),
        "sensor_count": len(sensors),
        "facility_count": len(facilities),
        "spatial_clusters": len(spatial_clusters),
        "time_range": {
            "start": iso_or_none(
                min(
                    [m.get("_timestamp") for m in measurements if m.get("_timestamp")]
                    + [s.get("_collection_time") for s in samples.values() if s.get("_collection_time")]
                    + [lr.get("_analysis_time") for lr in lab_results if lr.get("_analysis_time")],
                    default=None,
                )
            ),
            "end": iso_or_none(
                max(
                    [m.get("_timestamp") for m in measurements if m.get("_timestamp")]
                    + [s.get("_collection_time") for s in samples.values() if s.get("_collection_time")]
                    + [lr.get("_analysis_time") for lr in lab_results if lr.get("_analysis_time")],
                    default=None,
                )
            ),
        },
        "limitations": [
            "Coverage is limited to supplied measurements/samples/lab results.",
            "Non-detection outside coverage is not absence.",
        ],
    }

    spectral_context = [
        m.get("spectral_features")
        for m in case.get("measurements") or []
        if isinstance(m, dict) and m.get("spectral_features")
    ]

    neutron_context = [
        m.get("neutron_context")
        for m in case.get("measurements") or []
        if isinstance(m, dict) and m.get("neutron_context")
    ]

    temporal_correlations = []
    spatial_correlations = []

    by_phen_sp = defaultdict(list)
    for m in measurements:
        if m.get("_timestamp") is None:
            continue
        by_phen_sp[(m.get("_measurement_type"), m.get("_spatial_cluster_id"))].append(m)

    for (phen, sp), items in by_phen_sp.items():
        if len(items) < 2:
            continue
        times = sorted([x.get("_timestamp") for x in items if x.get("_timestamp")])
        if len(times) >= 2:
            span = (times[-1] - times[0]).total_seconds()
            temporal_correlations.append(
                {
                    "measurement_type": phen,
                    "spatial_cluster_id": sp,
                    "observation_count": len(items),
                    "time_span_s": span,
                    "note": "Temporal co-occurrence only; not causality.",
                }
            )
            spatial_correlations.append(
                {
                    "measurement_type": phen,
                    "spatial_cluster_id": sp,
                    "observation_count": len(items),
                    "note": "Spatial co-location within supplied clustering threshold; not source identity.",
                }
            )

    source_reliability = []
    for sid, s in sensors.items():
        status = s.get("_calibration_status", "CALIBRATION_UNKNOWN")
        if status == "CALIBRATED":
            rel = "HIGH"
        elif status in ("PARTIALLY_CALIBRATED", "DEGRADED"):
            rel = "MODERATE"
        elif status in ("UNCALIBRATED", "CALIBRATION_EXPIRED", "CALIBRATION_UNKNOWN"):
            rel = "LOW"
        else:
            rel = "UNKNOWN"
        source_reliability.append(
            {
                "source_id": sid,
                "source_type": "AUTHORIZED_SENSOR",
                "sensor_type": s.get("sensor_type"),
                "operator": s.get("operator"),
                "calibration_status": status,
                "reliability": rel,
                "known_limitations": s.get("known_limitations"),
                "independence_group": s.get("independence_group"),
                "upstream_sensor_id": s.get("upstream_sensor_id"),
            }
        )

    for lr in lab_results:
        severe = bool(set(lr.get("_quality_flags") or []) & SEVERE_QUALITY_FLAGS)
        rel = "LOW" if severe else ("MODERATE" if lr.get("method") and lr.get("quality_controls") else "UNKNOWN")
        source_reliability.append(
            {
                "source_id": lr.get("result_id"),
                "source_type": "LABORATORY_ANALYSIS",
                "lab_id": lr.get("lab_id"),
                "method": lr.get("method"),
                "reliability": rel,
                "quality_flags": lr.get("_quality_flags"),
            }
        )

    for rep in official_reports:
        st = str(rep.get("source_type", "")).upper()
        if st in {"OFFICIAL_REGULATOR", "SAFEGUARDS", "TREATY", "GOVERNMENT_REPORT"}:
            rel = "HIGH"
        elif st in {"FACILITY_SELF_REPORT", "PUBLIC_RESEARCH_NETWORK"}:
            rel = "MODERATE"
        elif st in {"MEDIA", "PUBLIC_ALLEGATION"}:
            rel = "LOW"
        else:
            rel = "UNKNOWN"
        rep.setdefault("source_reliability", rel)
        source_reliability.append(
            {
                "source_id": rep.get("report_id") or rep.get("source_id"),
                "source_type": st or "OFFICIAL_REPORT",
                "reliability": rel,
                "details": public_dict(rep),
            }
        )

    source_independence = "UNKNOWN"
    if fusion:
        states = {f.get("source_independence") for f in fusion}
        if "INDEPENDENT" in states:
            source_independence = "INDEPENDENT_OBSERVATION_AVAILABLE"
        elif "DEPENDENT_OR_UNKNOWN" in states:
            source_independence = "DEPENDENT_OR_UNKNOWN"
        elif "PARTIALLY_DEPENDENT" in states:
            source_independence = "PARTIALLY_DEPENDENT"
    elif len(sensors) > 1:
        source_independence = "MULTI_SENSOR_NOT_FUSED"
    elif sensors:
        source_independence = "SINGLE_SENSOR"

    unknowns: List[str] = []
    if not measurements and not samples and not lab_results:
        unknowns.append("No measurable nuclear/radiological activity supplied")
    if not backgrounds:
        unknowns.append("Background/baseline unresolved")
    if not radionuclide_candidates:
        unknowns.append("Radionuclide identity unresolved")
    if not source_class_candidates:
        unknowns.append("Source class unresolved")
    if not release_candidates:
        unknowns.append("Environmental release unresolved")
    if not facility_associations:
        unknowns.append("Facility association unresolved")
    unknowns.append("Operator/intent/weapon-related activity unresolved by design unless authoritative evidence exists")

    if contradictions:
        status = "DISPUTED"
    elif issues:
        status = "PARTIAL"
    elif not measurements and not samples and not lab_results:
        status = "INCONCLUSIVE"
    elif any(r.get("state") in {"RELEASE_CONFIRMED", "RELEASE_SUPPORTED"} for r in release_candidates):
        status = "EVENT_SUPPORTED"
    elif any(r.get("state") == "RELEASE_CANDIDATE" for r in release_candidates):
        status = "EVENT_CANDIDATE"
    elif any(a.get("anomaly_state") in {"MATERIAL_DEVIATION", "SIGNATURE_OF_INTEREST"} for a in anomalies):
        status = "RADIOLOGICAL_SIGNATURE_SUPPORTED"
    elif any(sc.get("state") in {"SUPPORTED", "CANDIDATE"} for sc in source_class_candidates):
        status = "SOURCE_CLASS_CANDIDATE"
    elif measurements or samples or lab_results:
        status = "NORMAL_BACKGROUND"
    else:
        status = "INCONCLUSIVE"

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "source_ids": sorted(
            {
                sid
                for obj in measurements + list(samples.values()) + lab_results + official_reports
                for sid in (obj.get("_source_ids") or obj.get("source_ids") or [])
                if sid
            }
        ),
        "evidence_ids": sorted(
            {
                eid
                for obj in measurements + list(samples.values()) + lab_results
                for eid in (obj.get("_evidence_ids") or obj.get("evidence_ids") or [])
                if eid
            }
        ),
        "facilities": facility_public,
        "facility_types": sorted({f.get("_facility_type") for f in facilities.values() if f.get("_facility_type")}),
        "facility_status": {fid: f.get("_operational_status") for fid, f in facilities.items()},
        "sensors": list(sensors.keys()),
        "sensor_types": sorted({str(s.get("sensor_type")) for s in sensors.values() if s.get("sensor_type")}),
        "sensor_quality": {sid: s.get("_calibration_status") for sid, s in sensors.items()},
        "calibration_context": {
            sid: {
                "calibration_status": s.get("_calibration_status"),
                "last_calibration": s.get("last_calibration"),
                "calibration_reference": s.get("calibration_reference"),
            }
            for sid, s in sensors.items()
        },
        "measurements": measurement_public,
        "measurement_types": sorted({m.get("_measurement_type") for m in measurements if m.get("_measurement_type")}),
        "units": units_used,
        "quantity_types": quantity_types_used,
        "background_models": background_public,
        "anomalies": anomalies,
        "spectral_features": spectral_context,
        "radionuclide_candidates": radionuclide_candidates,
        "material_class_candidates": source_class_candidates,
        "neutron_context": neutron_context,
        "samples": sample_public,
        "sample_types": sorted({s.get("_sample_type") for s in samples.values() if s.get("_sample_type")}),
        "sample_provenance": {
            sid: {
                "collector": s.get("collector"),
                "chain_of_custody": s.get("chain_of_custody"),
                "preservation_method": s.get("preservation_method"),
                "quality_flags": s.get("_quality_flags"),
            }
            for sid, s in samples.items()
        },
        "chain_of_custody": {
            sid: s.get("chain_of_custody") or []
            for sid, s in samples.items()
        },
        "laboratory_results": lab_public,
        "environmental_context": case.get("environmental_context") or {},
        "release_candidates": release_candidates,
        "medical_source_context": case.get("medical_source_context") or [],
        "industrial_source_context": case.get("industrial_source_context") or [],
        "research_source_context": case.get("research_source_context") or [],
        "natural_source_context": case.get("natural_source_context") or [],
        "fuel_cycle_context": case.get("fuel_cycle_context") or [],
        "safeguards_context": case.get("safeguards_context") or [],
        "regulatory_context": case.get("regulatory_context") or [],
        "seismic_context": seismic_context,
        "satellite_context": satellite_context,
        "weather_context": weather,
        "transport_context": weather.get("transport_model_output") or weather.get("candidate_source_regions") or [],
        "temporal_correlations": temporal_correlations,
        "spatial_correlations": spatial_correlations,
        "multi_sensor_fusion": fusion,
        "sample_lab_correlations": sample_lab_correlations,
        "facility_associations": facility_associations,
        "timeline_updates": sorted(
            [
                {
                    "kind": "measurement",
                    "id": m.get("measurement_id"),
                    "time": iso_or_none(m.get("_timestamp")),
                    "measurement_type": m.get("_measurement_type"),
                }
                for m in measurements
            ]
            + [
                {
                    "kind": "sample",
                    "id": s.get("sample_id"),
                    "time": iso_or_none(s.get("_collection_time")),
                    "sample_type": s.get("_sample_type"),
                }
                for s in samples.values()
            ]
            + [
                {
                    "kind": "lab_result",
                    "id": lr.get("result_id"),
                    "time": iso_or_none(lr.get("_analysis_time")),
                    "sample_id": lr.get("_sample_id"),
                }
                for lr in lab_results
            ]
            + [
                {
                    "kind": "release_candidate",
                    "id": r.get("release_candidate_id"),
                    "time": r.get("timestamp"),
                    "state": r.get("state"),
                }
                for r in release_candidates
            ],
            key=lambda x: x.get("time") or "",
        ),
        "observations": measurement_public + lab_public,
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "source_reliability": source_reliability,
        "source_bias": case.get("source_bias") or [
            "Facility self-reporting may be incomplete or delayed.",
            "Regulatory reporting may lag physical events.",
            "Public monitoring networks may have uneven coverage.",
            "Media/political framing is not technical verification.",
        ],
        "source_limitations": case.get("source_limitations") or [
            "Non-detection is not absence.",
            "Calibration reduces systematic uncertainty but does not eliminate noise.",
            "Derived fusion products are not raw measurements.",
            "Same-sample lab repeats are not independent environmental observations.",
        ],
        "source_pedigree": case.get("source_pedigree") or [
            {
                "sensor_id": sid,
                "operator": s.get("operator"),
                "upstream_sensor_id": s.get("upstream_sensor_id"),
                "independence_group": s.get("independence_group"),
                "calibration_reference": s.get("calibration_reference"),
            }
            for sid, s in sensors.items()
        ]
        + [
            {
                "sample_id": sid,
                "collector": s.get("collector"),
                "analysis_lab": s.get("analysis_lab"),
                "chain_of_custody": s.get("chain_of_custody"),
            }
            for sid, s in samples.items()
        ],
        "source_independence": source_independence,
        "contradictions": contradictions,
        "hypotheses": hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.get("hypothesis_id"),
                "status": "WEAKENED_BY_CONTRADICTIONS" if contradictions else "NOT_FALSIFIED_WITH_CURRENT_EVIDENCE",
                "required_additional_evidence": [
                    "Independent authorized sensor",
                    "Accredited laboratory result",
                    "Calibration record",
                    "Background baseline",
                    "Chain-of-custody completion",
                    "Official regulator/safeguards report",
                    "Atmospheric transport model metadata",
                ],
            }
            for h in hypotheses
        ],
        "uncertainties": uncertainty_summary,
        "detection_limits": numeric_summary(detection_limits),
        "coverage": coverage,
        "time_range": coverage["time_range"],
        "safety_flags": [
            "NO_WEAPON_DESIGN",
            "NO_WEAPON_OPTIMIZATION",
            "NO_YIELD_CALCULATION",
            "NO_CRITICAL_MASS_GUIDANCE",
            "NO_ENRICHMENT_PLANNING",
            "NO_CENTRIFUGE_OPTIMIZATION",
            "NO_REPROCESSING_PROCEDURES",
            "NO_FISSILE_MATERIAL_PRODUCTION_GUIDANCE",
            "NO_RDD_CONSTRUCTION",
            "NO_DETECTOR_EVASION",
            "NO_PORTAL_MONITOR_BYPASS",
            "NO_SHIELDING_FOR_CONCEALMENT",
            "NO_SMUGGLING_GUIDANCE",
            "NO_SABOTAGE_GUIDANCE",
            "NO_TARGETING_GUIDANCE",
            "NO_UNAUTHORIZED_SAMPLING",
        ],
        "legal_flags": [
            "HUMAN_REVIEW_REQUIRED_FOR_CONSEQUENTIAL_NUCLEAR_CLAIMS",
            "NON_PROLIFERATION_BOUNDARY",
            "OFFICIAL_AUTHORITY_GOVERNANCE_REQUIRED",
            "TREATY/SAFEGUARDS_CONCLUSIONS_REQUIRE_HUMAN_LEGAL_REVIEW",
        ],
        "privacy_flags": [
            "NO_PRIVATE_PERSON_TRACKING",
            "NO_UNAUTHORIZED_FACILITY_APPROACH",
            "METADATA_MINIMIZATION",
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not perform live sensing or fetch data.",
            "It consumes deterministic measurement/sample/lab records only.",
            "It does not invent radionuclides, measurements, facility activity, or nuclear events.",
            "It separates measurement, detection, classification, identification, and attribution.",
            "It blocks weapon design, material production, detector evasion, smuggling, sabotage, targeting, and RDD guidance.",
            "Derived fusion products are labeled as derived, not raw observations.",
        ],
        "dual_ai_review": dual,
        "not_facts": not_facts,
        "graphical_memory": graph,
        "validation_issues": issues,
        "validation_warnings": warnings,
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
                "sensor/sample/lab validation",
                "quality flagging",
                "background z-score anomaly analysis",
                "radionuclide candidate collection from supplied spectral/lab records",
                "facility association geometry/time checks",
                "release candidate assessment",
                "inverse-variance or dispersion-based sensor fusion",
                "source independence summarization",
                "sample/lab correlation",
                "contradiction detection",
                "fact gate",
            ],
            "note": "Replay requires raw measurement references, sensor metadata, calibration certificates, background baselines, sample IDs, chain of custody, lab methodology, unit normalization, statistical calculations, weather/transport model versions, seismic/satellite correlation sources, official report provenance, and source pedigree.",
        },
    }

    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": "Placeholders only. Replace with deterministic authorized/public nuclear/radiological records. Do not treat this template as real measurement.",
        "case_id": "CASE-NUCINT-EXAMPLE",
        "task_id": "TASK-NUCINT-EXAMPLE",
        "objective": "Authorized defensive analysis of a public environmental radiological anomaly for safety and non-proliferation verification support.",
        "questions": [
            "What radiological signature was measured?",
            "Is the observation above local background?",
            "Do independent sensors or laboratory results corroborate it?",
            "What benign source classes are plausible?",
            "What remains unresolved?",
        ],
        "scope": {
            "authorized_only": True,
            "defensive_only": True,
            "non_proliferation": True,
            "metadata_minimization": True,
            "no_weapon_design": True,
            "no_targeting": True,
            "no_detector_evasion": True,
            "no_unauthorized_sampling": True,
        },
        "authorization": {
            "lawful_basis": "AUTHORIZED_ENVIRONMENTAL_RADIOLOGICAL_MONITORING",
            "purpose": "DEFENSIVE_NUCLEAR_SIGNATURE_AND_SAFETY_ANALYSIS",
            "approval_reference": "AUTH-NUCINT-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "analysis_settings": {
            "spatial_cluster_distance_km": 10,
            "fusion_time_window_s": 3600,
            "conflict_sigma": 3,
            "facility_radius_km": 50,
            "official_report_time_window_s": 86400,
        },
        "sensors": [
            {
                "sensor_id": "GAM-1",
                "sensor_type": "GAMMA",
                "operator": "AUTHORIZED_ENVIRONMENTAL_AGENCY",
                "location": {"latitude": 0.0, "longitude": 0.0, "accuracy_m": 50, "area_id": "REGION_A"},
                "mobility": "FIXED",
                "measurement_mode": "CONTINUOUS_COUNT_RATE",
                "calibration_status": "CALIBRATED",
                "last_calibration": "2026-09-01T00:00:00Z",
                "calibration_reference": "CAL-GAM-001",
                "operating_status": "ONLINE",
                "detection_limit": 0.05,
                "detection_limit_unit": "uSv/h",
                "independence_group": "GROUP_A",
                "known_limitations": ["Count rate alone does not identify radionuclide."],
            },
            {
                "sensor_id": "GAM-2",
                "sensor_type": "GAMMA",
                "operator": "AUTHORIZED_ENVIRONMENTAL_AGENCY",
                "location": {"latitude": 0.05, "longitude": 0.0, "accuracy_m": 50, "area_id": "REGION_A"},
                "mobility": "FIXED",
                "measurement_mode": "CONTINUOUS_COUNT_RATE",
                "calibration_status": "CALIBRATED",
                "last_calibration": "2026-09-15T00:00:00Z",
                "calibration_reference": "CAL-GAM-002",
                "operating_status": "ONLINE",
                "detection_limit": 0.05,
                "detection_limit_unit": "uSv/h",
                "independence_group": "GROUP_B",
                "known_limitations": ["Count rate alone does not identify radionuclide."],
            },
        ],
        "facilities": [
            {
                "facility_id": "FAC-MED-1",
                "facility_type": "MEDICAL",
                "operator": "EXAMPLE_MEDICAL_OPERATOR",
                "location": {"latitude": 0.02, "longitude": 0.0, "area_id": "REGION_A"},
                "declared_status": "OPERATIONAL_REPORTED",
                "operational_status": "OPERATIONAL_REPORTED",
                "public_regulatory_context": "LICENSED_MEDICAL_ISOTOPE_USE",
                "known_activities": ["EXAMPLE_MEDICAL_ISOTOPE_HANDLING"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
            }
        ],
        "measurements": [
            {
                "measurement_id": "MEAS-GAM-1",
                "sensor_id": "GAM-1",
                "measurement_type": "DOSE_RATE",
                "value": 0.18,
                "unit": "uSv/h",
                "uncertainty": 0.02,
                "measurement_time": "2026-10-08T09:00:00Z",
                "location": {"latitude": 0.0, "longitude": 0.0, "area_id": "REGION_A"},
                "detection_state": "DETECTED",
                "detection_limit": 0.05,
                "detection_limit_unit": "uSv/h",
                "method": "AUTHORIZED_ENVIRONMENTAL_MONITOR",
                "instrument_type": "GAMMA_DOSE_RATE_METER",
                "calibration_reference": "CAL-GAM-001",
                "source_id": "SRC-ENV-A",
                "evidence_id": "EVD-ENV-A",
                "quality_flags": [],
            },
            {
                "measurement_id": "MEAS-GAM-2",
                "sensor_id": "GAM-2",
                "measurement_type": "DOSE_RATE",
                "value": 0.16,
                "unit": "uSv/h",
                "uncertainty": 0.02,
                "measurement_time": "2026-10-08T09:05:00Z",
                "location": {"latitude": 0.05, "longitude": 0.0, "area_id": "REGION_A"},
                "detection_state": "DETECTED",
                "detection_limit": 0.05,
                "detection_limit_unit": "uSv/h",
                "method": "AUTHORIZED_ENVIRONMENTAL_MONITOR",
                "instrument_type": "GAMMA_DOSE_RATE_METER",
                "calibration_reference": "CAL-GAM-002",
                "source_id": "SRC-ENV-B",
                "evidence_id": "EVD-ENV-B",
                "quality_flags": [],
            },
        ],
        "sample_records": [
            {
                "sample_id": "SAMP-AIR-1",
                "sample_type": "AIR",
                "collection_location": {"latitude": 0.01, "longitude": 0.0, "area_id": "REGION_A"},
                "collection_time": "2026-10-08T09:10:00Z",
                "collector": "AUTHORIZED_SAMPLING_TEAM",
                "chain_of_custody": [
                    {
                        "timestamp": "2026-10-08T10:00:00Z",
                        "from": "AUTHORIZED_SAMPLING_TEAM",
                        "to": "ACCREDITED_LAB_1",
                        "seal": "INTACT",
                    }
                ],
                "preservation_method": "FILTER_REFRIGERATED",
                "analysis_lab": "ACCREDITED_LAB_1",
                "analysis_method": "GAMMA_SPECTROMETRY",
                "source_id": "SRC-SAMP-A",
                "evidence_id": "EVD-SAMP-A",
                "quality_flags": [],
            }
        ],
        "laboratory_results": [
            {
                "result_id": "LAB-1",
                "sample_id": "SAMP-AIR-1",
                "lab_id": "ACCREDITED_LAB_1",
                "method": "GAMMA_SPECTROMETRY",
                "instrument": "HPGE_EXAMPLE",
                "analysis_time": "2026-10-09T09:00:00Z",
                "quality_controls": ["BLANK", "STANDARD", "SPIKE_RECOVERY"],
                "nuclides": [
                    {
                        "nuclide": "EXAMPLE_RADIONUCLIDE",
                        "activity": 12.5,
                        "unit": "mBq",
                        "uncertainty": 1.1,
                        "confidence": "MODERATE",
                    }
                ],
                "source_id": "SRC-LAB-1",
                "evidence_id": "EVD-LAB-1",
                "quality_flags": [],
            }
        ],
        "background_data": [
            {
                "baseline_id": "BG-GAM-1",
                "sensor_id": "GAM-1",
                "measurement_type": "DOSE_RATE",
                "mean": 0.10,
                "std": 0.015,
                "uncertainty": 0.005,
                "unit": "uSv/h",
                "valid_from": "2026-09-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
            },
            {
                "baseline_id": "BG-GAM-2",
                "sensor_id": "GAM-2",
                "measurement_type": "DOSE_RATE",
                "mean": 0.095,
                "std": 0.014,
                "uncertainty": 0.005,
                "unit": "uSv/h",
                "valid_from": "2026-09-15T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
            },
        ],
        "weather_context": {
            "wind": {"direction_deg": 270, "speed_m_s": 3.0},
            "candidate_source_regions": [
                {
                    "region_id": "REGION_A",
                    "facility_id": "FAC-MED-1",
                    "start_time": "2026-10-08T06:00:00Z",
                    "end_time": "2026-10-08T12:00:00Z",
                }
            ],
            "transport_model_output": "EXAMPLE_HIGH_LEVEL_BACK_TRAJECTORY",
        },
        "official_reports": [
            {
                "report_id": "REP-1",
                "source_id": "SRC-REGULATOR",
                "source_type": "OFFICIAL_REGULATOR",
                "report_type": "ENVIRONMENTAL_MONITORING",
                "report_time": "2026-10-08T12:00:00Z",
                "facility_id": "FAC-MED-1",
                "linked_observation_id": "MEAS-GAM-1",
                "release_confirmed": False,
                "claim": "EXAMPLE_PUBLIC_REGULATORY_CONTEXT",
                "evidence_ids": ["EVD-REP-1"],
            }
        ],
        "seismic_context": [],
        "satellite_context": [],
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
            "TRACEATLAS NUCINT defensive non-proliferation nuclear/radiological signature scaffold. "
            "Consumes deterministic measurement/sample/lab records; does not fetch live data, invent measurements, "
            "design weapons, provide enrichment/reprocessing guidance, evade detectors, smuggle, sabotage, or target."
        )
    )
    parser.add_argument("--input", "-i", help="Path to NUCINT input JSON")
    parser.add_argument("--output", "-o", default="nucint_result.json", help="Output NUCINTResult JSON path")
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