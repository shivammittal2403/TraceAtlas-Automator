#!/usr/bin/env python3
"""
TRACEATLAS LOGINT main.py
=========================

Lawful, authorized, evidence-first, resilience-aware logistics intelligence
scaffold.

This module:
- Does NOT fetch live carrier/port/warehouse/tracking data.
- Does NOT invent shipments, cargo, routes, carriers, nodes, events, custody,
  deliveries, inventory, capacity, customs events, delays, or disruptions.
- Does NOT plan sabotage, attacks, interdiction, ambushes, cargo theft,
  hijacking, convoy attacks, or military logistics targeting.
- Does NOT optimize smuggling routes, customs evasion, inspection avoidance,
  cargo concealment, false manifests, false bills of lading, AIS manipulation,
  GPS spoofing, transponder disabling, or container seal tampering.
- Does NOT provide warehouse intrusion, stolen credential use, or unauthorized
  access to private logistics systems.
- Does NOT track private persons or expose sensitive delivery locations beyond
  authorized defensive/logistics necessity.
- Does NOT autonomously reroute, cancel, release, reassign, or alter shipments.
  It only produces evidence-linked assessment and recommended human actions.

It consumes deterministic logistics records supplied by authorized/public sources:
- shipment records
- order records
- cargo/product records
- container records
- carrier / freight forwarder / 3PL / 4PL records
- warehouse / distribution center / port / terminal / airport / rail hub records
- route and transport-leg records
- shipment events / tracking events / EDI events
- custody-chain events
- delivery and proof-of-delivery records
- customs event records
- inventory snapshots and movements
- capacity / throughput records
- cold-chain sensor records
- disruption records
- weather / environmental / seismic / satellite / AIS context, at high level
- source pedigree / reliability / independence metadata

It produces an evidence-linked LOGINTResult with:
- shipment/order/cargo/carrier/node resolution status
- planned vs estimated vs actual separation
- route confidence handling without route generation
- custody-chain analysis and custody-gap detection
- event deduplication and source-dependency handling
- delay, lead-time, transit-time, dwell-time deterministic calculations
- inventory and capacity arithmetic with explicit units
- delivery / POD verification status
- customs event correlation without offense inference
- cold-chain excursion detection from supplied sensor limits
- disruption impact correlation with evidence limits
- node/carrier/route concentration and resilience analysis
- common-mode dependency detection
- contradiction preservation
- competing hypotheses and falsification
- dual-AI style skeptic review
- privacy / safety / operational-action flags
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "0.1.0"

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

MODES = {
    "ROAD",
    "RAIL",
    "MARITIME",
    "AIR",
    "INLAND_WATERWAY",
    "PIPELINE",
    "COURIER",
    "MULTIMODAL",
    "OTHER",
    "UNKNOWN",
}

NODE_TYPES = {
    "WAREHOUSE",
    "DISTRIBUTION_CENTER",
    "PORT",
    "TERMINAL",
    "AIRPORT",
    "RAIL_HUB",
    "CUSTOMS_POINT",
    "CROSS_DOCK",
    "SUPPLIER",
    "FACTORY",
    "CUSTOMER_SITE",
    "OTHER",
    "UNKNOWN",
}

SHIPMENT_STATES = {
    "CREATED",
    "BOOKED",
    "PICKUP_SCHEDULED",
    "PICKED_UP",
    "ORIGIN_PROCESSING",
    "DEPARTED",
    "IN_TRANSIT",
    "TRANSSHIPMENT",
    "CUSTOMS_PENDING",
    "CUSTOMS_CLEARED_REPORTED",
    "OUT_FOR_DELIVERY",
    "DELIVERED_REPORTED",
    "DELIVERY_VERIFIED",
    "FAILED_DELIVERY",
    "RETURNING",
    "RETURNED",
    "CANCELLED",
    "UNKNOWN",
}

EVENT_TYPES = {
    "BOOKED",
    "PICKED_UP",
    "LOADED",
    "DEPARTED",
    "ARRIVED",
    "UNLOADED",
    "GATE_IN",
    "GATE_OUT",
    "TRANSSHIPMENT",
    "CUSTOMS_ENTRY",
    "CUSTOMS_RELEASE",
    "WAREHOUSE_RECEIPT",
    "WAREHOUSE_DISPATCH",
    "OUT_FOR_DELIVERY",
    "DELIVERED",
    "RETURNED",
    "DELAYED",
    "CANCELLED",
    "UNKNOWN",
}

CUSTODY_ROLES = {
    "SHIPPER",
    "CARRIER",
    "FORWARDER",
    "WAREHOUSE",
    "CUSTOMS",
    "TERMINAL",
    "CONSIGNEE",
    "THREE_PL",
    "FOUR_PL",
    "OTHER",
    "UNKNOWN",
}

DELIVERY_STATES = {
    "DELIVERY_NOT_STARTED",
    "IN_TRANSIT",
    "OUT_FOR_DELIVERY",
    "DELIVERED_REPORTED",
    "DELIVERY_VERIFIED",
    "FAILED",
    "RETURNED",
    "UNKNOWN",
}

POD_STATES = {
    "NOT_AVAILABLE",
    "REPORTED",
    "VERIFIED",
    "FAILED",
    "UNKNOWN",
}

CAPACITY_STATES = {
    "DESIGN_CAPACITY",
    "CLAIMED_CAPACITY",
    "OBSERVED_CAPACITY",
    "AVAILABLE_CAPACITY",
    "UTILIZED_CAPACITY",
    "UNKNOWN",
}

STOCK_STATES = {
    "AVAILABLE",
    "RESERVED",
    "ALLOCATED",
    "IN_TRANSIT",
    "QUARANTINED",
    "DAMAGED",
    "RETURNED",
    "UNKNOWN",
}

IMPACT_STATES = {
    "NO_CONFIRMED_IMPACT",
    "POTENTIAL_IMPACT",
    "PARTIAL_IMPACT",
    "DIRECT_IMPACT_SUPPORTED",
    "MAJOR_IMPACT_SUPPORTED",
    "UNKNOWN",
}

RESILIENCE_STATES = {
    "HIGH_REDUNDANCY",
    "MODERATE_REDUNDANCY",
    "LOW_REDUNDANCY",
    "SINGLE_DEPENDENCY_CANDIDATE",
    "UNKNOWN",
}

ROUTE_CONFIDENCE = {
    "OBSERVED",
    "STRONGLY_SUPPORTED",
    "SUPPORTED",
    "INFERRED",
    "SPECULATIVE",
    "UNKNOWN",
}

DUPLICATE_STATES = {
    "EXACT_DUPLICATE",
    "PROBABLE_DUPLICATE",
    "SAME_PHYSICAL_EVENT",
    "RELATED_EVENT",
    "DISTINCT",
    "UNKNOWN",
}

FACILITY_STATUS = {
    "OPERATIONAL",
    "DEGRADED",
    "PARTIALLY_CLOSED",
    "CLOSED_REPORTED",
    "CLOSED_VERIFIED",
    "UNKNOWN",
}

DELAY_CAUSE_STATES = {
    "SOURCE_REPORTED_CAUSE",
    "SUPPORTED_CAUSE",
    "PROBABLE_CAUSE",
    "UNKNOWN",
}

SEVERE_QUALITY_FLAGS = {
    "missing_shipment_id",
    "missing_time",
    "timing_conflict",
    "unit_unknown",
    "quantity_unresolved",
    "source_unknown",
    "route_observed_without_evidence",
    "delivery_without_pod",
    "custody_gap",
    "negative_inventory",
    "capacity_unit_mismatch",
    "sensor_unreliable",
    "duplicate_source_dependency",
    "event_conflict",
    "customs_sequence_conflict",
    "privacy_private_delivery_redacted",
}

PRIVATE_TAGS = {
    "private_residence",
    "home",
    "personal_address",
    "person_location",
    "private_person",
    "stalking_target",
}

SENSITIVE_FIELD_HINTS = (
    "home_address",
    "private_phone",
    "personal_phone",
    "family",
    "private_location",
    "resident",
    "driver_home",
    "staff_home",
)

BLOCK_PHRASES = [
    # sabotage / attack / interdiction / military targeting
    "sabotage plan",
    "sabotage planning",
    "attack chokepoint",
    "optimal attack",
    "attack route",
    "strike logistics",
    "interdiction plan",
    "interdiction optimization",
    "ambush location",
    "ambush route",
    "convoy attack",
    "cargo theft plan",
    "hijacking plan",
    "military logistics targeting",
    "munition transport targeting",
    "fuel depot attack",
    "weapon delivery logistics",

    # smuggling / customs / concealment / document fraud
    "smuggling route",
    "smuggling optimization",
    "customs evasion",
    "inspection avoidance",
    "avoid inspection",
    "cargo concealment",
    "conceal cargo",
    "false manifest",
    "falsify manifest",
    "false bill of lading",
    "falsify bill of lading",
    "false waybill",
    "false origin document",
    "misdeclare cargo",

    # tracking / AIS / GPS / seal tampering
    "ais manipulation",
    "gps spoofing",
    "transponder disabling",
    "disable tracking",
    "container seal tampering",
    "seal bypass",
    "seal replication",

    # unauthorized access / privacy
    "warehouse intrusion",
    "stolen credentials",
    "unauthorized access",
    "track private person",
    "private person tracking",
    "stalk",
    "stalking",
]

SOURCE_TYPE_RELIABILITY = {
    "AUTHORIZED_TMS": "HIGH",
    "AUTHORIZED_WMS": "HIGH",
    "ERP_LOGISTICS_MODULE": "HIGH",
    "OFFICIAL_PORT_RECORD": "HIGH",
    "OFFICIAL_TERMINAL_RECORD": "HIGH",
    "CUSTOMS_RECORD": "HIGH",
    "BILL_OF_LADING": "HIGH",
    "AIR_WAYBILL": "HIGH",
    "CARRIER_API": "MODERATE",
    "CARRIER_RECORD": "MODERATE",
    "FREIGHT_FORWARDER_RECORD": "MODERATE",
    "WAREHOUSE_RECORD": "MODERATE",
    "PROOF_OF_DELIVERY": "MODERATE",
    "AUTHORIZED_TELEMATICS": "MODERATE",
    "AUTHORIZED_IOT": "MODERATE",
    "PUBLIC_AIS": "MODERATE",
    "PUBLIC_SCHEDULE": "MODERATE",
    "SATELLITE_OBSERVATION": "LOW",
    "MEDIA": "LOW",
    "SOCIAL_REPORT": "LOW",
    "UNKNOWN": "UNKNOWN",
}

WEIGHT_UNITS = {
    "kg": 1.0,
    "kgs": 1.0,
    "kilogram": 1.0,
    "kilograms": 1.0,
    "t": 1000.0,
    "tonne": 1000.0,
    "tonnes": 1000.0,
    "ton": 1000.0,
    "tons": 1000.0,
    "lb": 0.45359237,
    "lbs": 0.45359237,
    "pound": 0.45359237,
    "pounds": 0.45359237,
    "g": 0.001,
    "gram": 0.001,
    "grams": 0.001,
}

VOLUME_UNITS = {
    "m3": 1.0,
    "cbm": 1.0,
    "cubic_meter": 1.0,
    "cubic_meters": 1.0,
    "l": 0.001,
    "liter": 0.001,
    "liters": 0.001,
    "gal": 0.00378541,
    "gallon": 0.00378541,
    "gallons": 0.00378541,
}

TIME_UNITS = {
    "s": 1.0,
    "sec": 1.0,
    "second": 1.0,
    "seconds": 1.0,
    "min": 60.0,
    "minute": 60.0,
    "minutes": 60.0,
    "h": 3600.0,
    "hr": 3600.0,
    "hour": 3600.0,
    "hours": 3600.0,
    "d": 86400.0,
    "day": 86400.0,
    "days": 86400.0,
}

CANONICAL_UNITS = {
    "weight": "kg",
    "volume": "m3",
    "time": "s",
    "quantity": "count",
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


def dt_sort_key(dt: Optional[datetime]) -> float:
    return dt.timestamp() if isinstance(dt, datetime) else 0.0


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


def normalize_choice(value: Any, allowed: Iterable[str], default: str = "UNKNOWN") -> str:
    s = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    return s if s in set(allowed) else default


def normalize_mode(value: Any) -> str:
    return normalize_choice(value, MODES, "UNKNOWN")


def normalize_node_type(value: Any) -> str:
    return normalize_choice(value, NODE_TYPES, "UNKNOWN")


def normalize_event_type(value: Any) -> str:
    return normalize_choice(value, EVENT_TYPES, "UNKNOWN")


def normalize_id(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def normalize_container_id(value: Any) -> Dict[str, Any]:
    original = str(value).strip() if value is not None else ""
    norm = original.upper().replace(" ", "").replace("-", "")
    flags: List[str] = []
    if not original:
        flags.append("container_id_missing")
    elif len(norm) != 11:
        # Preserve original; do not silently correct ambiguous IDs.
        flags.append("container_id_nonstandard_length")
    return {
        "original": original or None,
        "normalized_upper": norm or None,
        "flags": flags,
    }


def normalize_quantity(
    value: Any,
    unit: Any,
    kind: str,
) -> Dict[str, Any]:
    v = to_float(value)
    u = str(unit or "").strip().lower().replace(" ", "_")
    table = {
        "weight": WEIGHT_UNITS,
        "volume": VOLUME_UNITS,
        "time": TIME_UNITS,
        "quantity": {"count": 1.0, "unit": 1.0, "units": 1.0, "pcs": 1.0, "piece": 1.0, "pieces": 1.0},
    }.get(kind, {})

    factor = table.get(u)
    flags: List[str] = []

    if v is None:
        flags.append("quantity_unresolved")
    if factor is None:
        flags.append("unit_unknown")

    canonical = CANONICAL_UNITS.get(kind, kind)
    norm_v = None if v is None or factor is None else v * factor

    return {
        "original_value": v,
        "original_unit": str(unit).strip() if unit is not None else None,
        "normalized_value": norm_v,
        "normalized_unit": canonical if factor is not None else None,
        "quantity_kind": kind,
        "flags": flags,
    }


def extract_location(obj: Dict[str, Any]) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[str], Optional[str]]:
    loc = obj.get("location") if isinstance(obj.get("location"), dict) else {}
    lat = to_float(loc.get("latitude") if loc.get("latitude") is not None else loc.get("lat") or obj.get("latitude") or obj.get("lat"))
    lon = to_float(loc.get("longitude") if loc.get("longitude") is not None else loc.get("lon") or obj.get("longitude") or obj.get("lon"))
    acc = to_float(loc.get("accuracy_m") if loc.get("accuracy_m") is not None else loc.get("uncertainty_m"))
    unlocode = normalize_id(loc.get("unlocode") or loc.get("un_locode") or obj.get("unlocode") or obj.get("un_locode"))
    area = normalize_id(loc.get("area_id") or loc.get("city") or obj.get("area_id") or obj.get("city"))

    if lat is not None and not (-90.0 <= lat <= 90.0):
        lat = None
    if lon is not None and not (-180.0 <= lon <= 180.0):
        lon = None

    return lat, lon, acc, unlocode, area


def get_tags(obj: Dict[str, Any]) -> set:
    return {str(x).strip().lower() for x in ensure_list(obj.get("tags") or obj.get("sensitive_tags")) if x}


def redact_private_fields(obj: Dict[str, Any], tags: set, authorized_exact: bool) -> bool:
    if not (tags & PRIVATE_TAGS) or authorized_exact:
        return False

    for k in list(obj.keys()):
        lk = str(k).lower()
        if any(h in lk for h in SENSITIVE_FIELD_HINTS):
            obj[k] = "REDACTED"

    add_flag(obj, "privacy_private_delivery_redacted")
    return True


def get_records(case: Dict[str, Any], *keys: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for k in keys:
        v = case.get(k)
        if isinstance(v, list):
            out.extend([x for x in v if isinstance(x, dict)])
        elif isinstance(v, dict):
            out.append(v)
    return out


def time_overlap(
    a_start: Optional[datetime],
    a_end: Optional[datetime],
    b_start: Optional[datetime],
    b_end: Optional[datetime],
) -> Optional[bool]:
    if not (a_start and b_start):
        return None
    ae = a_end or a_start
    be = b_end or b_start
    return not (ae < b_start or be < a_start)


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
            reasons.append(f"Forbidden LOGINT action/request detected: '{phrase}'")

    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}
    auth = case.get("authorization") if isinstance(case.get("authorization"), dict) else {}
    requested = case.get("requested_outputs") if isinstance(case.get("requested_outputs"), dict) else {}

    if scope.get("authorized_only") is not True:
        reasons.append("scope.authorized_only must be true")

    if scope.get("lawful_only") is False:
        reasons.append("scope.lawful_only must not be false")

    prohibited_scope_flags = [
        "sabotage_planning",
        "attack_route_selection",
        "interdiction_planning",
        "customs_evasion",
        "smuggling_optimization",
        "cargo_theft",
        "hijacking",
        "military_targeting",
        "private_person_tracking",
        "disable_tracking",
        "falsify_documents",
        "seal_tampering",
        "ais_manipulation",
        "gps_spoofing",
        "unauthorized_access",
        "warehouse_intrusion",
    ]

    for flag in prohibited_scope_flags:
        if scope.get(flag) is True:
            reasons.append(f"scope.{flag} is prohibited")

    prohibited_requested = [
        "attack_chokepoint",
        "interdiction_plan",
        "smuggling_route",
        "customs_evasion_route",
        "cargo_theft_plan",
        "military_targeting",
        "disable_tracking",
        "falsify_manifest",
        "seal_tampering",
        "private_person_tracking",
        "autonomous_reroute",
        "autonomous_cancel",
        "autonomous_release_cargo",
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
            "NO_SABOTAGE_PLANNING",
            "NO_ATTACK_CHOKEPOINT_IDENTIFICATION",
            "NO_INTERDICTION_PLANNING",
            "NO_MILITARY_LOGISTICS_TARGETING",
            "NO_SMUGGLING_OPTIMIZATION",
            "NO_CUSTOMS_EVASION",
            "NO_INSPECTION_AVOIDANCE",
            "NO_CARGO_CONCEALMENT",
            "NO_FALSE_DOCUMENTS",
            "NO_SEAL_TAMPERING",
            "NO_AIS_MANIPULATION",
            "NO_GPS_SPOOFING",
            "NO_UNAUTHORIZED_ACCESS",
            "NO_PRIVATE_PERSON_TRACKING",
            "NO_AUTONOMOUS_OPERATIONAL_ACTION",
        ],
        "privacy_flags": [
            "NO_DRIVER_OR_STAFF_PRIVATE_DATA_EXPOSURE",
            "NO_PRIVATE_RESIDENCE_LOCATION_EXPOSURE",
            "MINIMUM_NECESSARY_LOGISTICS_GRANULARITY",
        ],
        "recommended_next_actions": [
            "Restate objective as lawful logistics resilience, compliance, investigation support, or defensive supply-flow analysis",
            "Use authorized/public shipment, carrier, warehouse, port, customs, and inventory records",
            "Separate planned, estimated, observed, and inferred events",
            "Escalate consequential operational decisions to authorized humans",
            "Do not request sabotage, smuggling, evasion, interdiction, targeting, or private tracking outputs",
        ],
        "limitations": [
            "Requested or detected use crosses LOGINT lawful/safety boundary.",
            "No sabotage, attack routing, interdiction, smuggling, customs evasion, cargo theft, falsified documents, tracking disablement, or private-person tracking support is provided.",
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
# Source / independence
# -----------------------------------------------------------------------------

def source_reliability_label(source: Dict[str, Any]) -> str:
    rel = str(source.get("reliability") or source.get("_reliability") or "").strip().upper()
    if rel in {"HIGH", "MODERATE", "LOW", "UNKNOWN"}:
        return rel
    stype = str(source.get("source_type") or source.get("_source_type") or "UNKNOWN").strip().upper()
    return SOURCE_TYPE_RELIABILITY.get(stype, "UNKNOWN")


def source_independence(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    if not a or not b:
        return "UNKNOWN"
    if a.get("source_id") == b.get("source_id"):
        return "DEPENDENT"

    shared_keys = [
        "upstream_source_id",
        "independence_group",
        "provider",
        "carrier_id",
        "tms_id",
        "wms_id",
        "portal_id",
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


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def validate_sources(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    sources: Dict[str, Dict[str, Any]] = {}

    for idx, s in enumerate(get_records(case, "sources", "logistics_sources")):
        sid = normalize_id(s.get("source_id") or s.get("id")) or f"SRC-{idx + 1}"
        s["source_id"] = sid

        stype = str(s.get("source_type", "UNKNOWN")).strip().upper()
        s["_source_type"] = stype
        s["_reliability"] = source_reliability_label(s)
        s["_independence_group"] = str(
            s.get("independence_group")
            or s.get("upstream_source_id")
            or s.get("provider")
            or s.get("carrier_id")
            or s.get("tms_id")
            or s.get("wms_id")
            or sid
        ).strip().upper()

        sources[sid] = s

    if not sources:
        issues.append("No logistics sources supplied")

    return sources, issues


def validate_parties(case: Dict[str, Any], settings: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    parties: Dict[str, Dict[str, Any]] = {}

    raw = get_records(
        case,
        "parties",
        "organizations",
        "shippers",
        "consignees",
        "buyers",
        "sellers",
        "suppliers",
        "manufacturers",
        "customers",
    )

    for idx, p in enumerate(raw):
        pid = normalize_id(p.get("party_id") or p.get("organization_id") or p.get("id")) or f"PARTY-{idx + 1}"
        p["party_id"] = pid
        p["_roles"] = [str(x).strip().upper() for x in ensure_list(p.get("roles") or p.get("role")) if x]
        tags = get_tags(p)
        p["_tags"] = tags
        redact_private_fields(p, tags, settings.get("sensitive_exact_authorized", False))
        parties[pid] = p

    return parties, issues


def validate_orders(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    orders: Dict[str, Dict[str, Any]] = {}

    for idx, o in enumerate(get_records(case, "orders", "purchase_orders")):
        oid = normalize_id(o.get("order_id") or o.get("purchase_order_id") or o.get("id")) or f"ORD-{idx + 1}"
        o["order_id"] = oid
        o["_created_time"] = parse_dt(o.get("created_time") or o.get("order_time") or o.get("timestamp"))
        o["_buyer"] = normalize_id(o.get("buyer") or o.get("buyer_id"))
        o["_seller"] = normalize_id(o.get("seller") or o.get("seller_id"))
        o["_cargo_ids"] = [normalize_id(x) for x in ensure_list(o.get("cargo_ids") or o.get("cargo") or o.get("products")) if x]
        o["_quantity"] = normalize_quantity(o.get("quantity"), o.get("quantity_unit") or "count", "quantity")
        for f in o["_quantity"]["flags"]:
            add_flag(o, f)
        orders[oid] = o

    return orders, issues


def validate_cargo(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    cargo: Dict[str, Dict[str, Any]] = {}

    for idx, c in enumerate(get_records(case, "cargo", "products", "commodities")):
        cid = normalize_id(c.get("cargo_id") or c.get("product_id") or c.get("id")) or f"CARGO-{idx + 1}"
        c["cargo_id"] = cid
        c["_description"] = c.get("description") or c.get("commodity") or c.get("product")
        c["_quantity"] = normalize_quantity(c.get("quantity"), c.get("quantity_unit") or "count", "quantity")
        c["_weight"] = normalize_quantity(c.get("weight"), c.get("weight_unit") or "kg", "weight")
        c["_volume"] = normalize_quantity(c.get("volume"), c.get("volume_unit") or "m3", "volume")
        c["_temperature_required"] = bool(c.get("temperature_requirements") or c.get("cold_chain_required"))
        c["_hazard_class"] = c.get("hazard_class")
        c["_handling_requirements"] = c.get("handling_requirements")

        for obj in (c["_quantity"], c["_weight"], c["_volume"]):
            for f in obj.get("flags", []):
                add_flag(c, f)

        if isinstance(c["_description"], str) and len(c["_description"].strip()) < 3:
            add_flag(c, "vague_cargo_description")

        cargo[cid] = c

    return cargo, issues


def validate_containers(case: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    containers: Dict[str, Dict[str, Any]] = {}

    for idx, c in enumerate(get_records(case, "containers")):
        cid = normalize_id(c.get("container_id") or c.get("id")) or f"CONT-{idx + 1}"
        c["container_id"] = cid
        c["_container_norm"] = normalize_container_id(c.get("container_number") or cid)
        for f in c["_container_norm"].get("flags", []):
            add_flag(c, f)
        c["_shipment_ids"] = [normalize_id(x) for x in ensure_list(c.get("shipment_ids") or c.get("shipments")) if x]
        c["_seal_reference"] = c.get("seal_reference") or c.get("seal_number")
        c["_carrier"] = normalize_id(c.get("carrier") or c.get("carrier_id"))
        containers[cid] = c

    return containers, issues


def validate_actor_records(
    case: Dict[str, Any],
    keys: Tuple[str, ...],
    prefix: str,
    role: str,
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    actors: Dict[str, Dict[str, Any]] = {}

    for idx, a in enumerate(get_records(case, *keys)):
        aid = normalize_id(a.get("carrier_id") or a.get("forwarder_id") or a.get("provider_id") or a.get("id")) or f"{prefix}-{idx + 1}"
        a["actor_id"] = aid
        a["_role"] = role
        a["_legal_entity_reference"] = a.get("legal_entity_reference") or a.get("company_id")
        a["_modes"] = [normalize_mode(x) for x in ensure_list(a.get("modes") or a.get("mode")) if x]
        a["_service_type"] = str(a.get("service_type", "UNKNOWN")).upper()
        a["_valid_from"] = parse_dt(a.get("valid_from"))
        a["_valid_to"] = parse_dt(a.get("valid_to"))
        if a["_valid_from"] and a["_valid_to"] and a["_valid_to"] < a["_valid_from"]:
            add_flag(a, "timing_conflict")
        actors[aid] = a

    return actors, issues


def validate_nodes(
    case: Dict[str, Any],
    settings: Dict[str, Any],
    now: datetime,
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    issues: List[str] = []
    nodes: Dict[str, Dict[str, Any]] = {}

    node_key_types = {
        "warehouses": "WAREHOUSE",
        "distribution_centers": "DISTRIBUTION_CENTER",
        "ports": "PORT",
        "terminals": "TERMINAL",
        "airports": "AIRPORT",
        "rail_hubs": "RAIL_HUB",
        "customs_points": "CUSTOMS_POINT",
        "nodes": "OTHER",
    }

    for key, default_type in node_key_types.items():
        for idx, n in enumerate(case.get(key) or []):
            if not isinstance(n, dict):
                issues.append(f"{key}[{idx}] is not an object")
                continue

            nid = normalize_id(n.get("node_id") or n.get("id") or n.get("warehouse_id") or n.get("port_id")) or f"{default_type}-{idx + 1}"
            n["node_id"] = nid
            n["_node_type"] = normalize_node_type(n.get("node_type") or default_type)
            n["_operator"] = normalize_id(n.get("operator") or n.get("operator_id"))
            lat, lon, acc, unlocode, area = extract_location(n)
            n["_lat"] = lat
            n["_lon"] = lon
            n["_accuracy_m"] = acc
            n["_unlocode"] = unlocode
            n["_area_id"] = area

            tags = get_tags(n)
            n["_tags"] = tags
            if redact_private_fields(n, tags, settings.get("sensitive_exact_authorized", False)):
                n["_lat"] = None
                n["_lon"] = None
                n["_location_text"] = "REDACTED"

            n["_warehouse_type"] = str(n.get("warehouse_type", "UNKNOWN")).upper()
            n["_temperature_capability"] = n.get("temperature_capability")
            n["_bonded_status"] = str(n.get("bonded_status", "UNKNOWN")).upper()
            n["_operational_status"] = normalize_choice(n.get("operational_status") or n.get("status"), FACILITY_STATUS, "UNKNOWN")
            n["_valid_from"] = parse_dt(n.get("valid_from"))
            n["_valid_to"] = parse_dt(n.get("valid_to"))
            n["_capacity_claim"] = n.get("capacity_claim")
            n["_observed_capacity_context"] = n.get("observed_capacity_context")
            n["_alternative_nodes"] = [
                normalize_id(x.get("node_id") if isinstance(x, dict) else x)
                for x in ensure_list(n.get("alternative_nodes") or n.get("alternatives"))
                if x
            ]

            if n["_valid_from"] and n["_valid_to"] and n["_valid_to"] < n["_valid_from"]:
                add_flag(n, "timing_conflict")

            if n["_valid_to"] and now > n["_valid_to"]:
                add_flag(n, "historical_node_state")

            nodes[nid] = n

    if not nodes:
        issues.append("No logistics nodes supplied")

    return nodes, issues


def validate_shipments(
    case: Dict[str, Any],
    settings: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    shipments: List[Dict[str, Any]] = []

    for idx, s in enumerate(get_records(case, "shipments")):
        sid = normalize_id(s.get("shipment_id") or s.get("id")) or f"SHIP-{idx + 1}"
        s["shipment_id"] = sid
        s["_status"] = normalize_choice(s.get("status") or s.get("shipment_status"), SHIPMENT_STATES, "UNKNOWN")
        s["_order_reference"] = normalize_id(s.get("order_reference") or s.get("order_id"))
        s["_cargo_ids"] = [normalize_id(x) for x in ensure_list(s.get("cargo_ids") or s.get("cargo")) if x]
        s["_container_ids"] = [normalize_id(x) for x in ensure_list(s.get("container_ids") or s.get("containers")) if x]
        s["_shipper"] = normalize_id(s.get("shipper") or s.get("shipper_id"))
        s["_consignee"] = normalize_id(s.get("consignee") or s.get("consignee_id"))
        s["_carrier"] = normalize_id(s.get("carrier") or s.get("carrier_id"))
        s["_forwarder"] = normalize_id(s.get("forwarder") or s.get("forwarder_id"))
        s["_origin_node"] = normalize_id(s.get("origin_node") or s.get("origin"))
        s["_destination_node"] = normalize_id(s.get("destination_node") or s.get("destination"))
        s["_modes"] = [normalize_mode(x) for x in ensure_list(s.get("transport_modes") or s.get("mode")) if x]
        s["_delay_cause"] = s.get("delay_cause")

        s["_planned_departure"] = parse_dt(s.get("planned_departure"))
        s["_actual_departure"] = parse_dt(s.get("actual_departure"))
        s["_planned_arrival"] = parse_dt(s.get("planned_arrival"))
        s["_actual_arrival"] = parse_dt(s.get("actual_arrival"))
        s["_delivery_status"] = normalize_choice(s.get("delivery_status"), DELIVERY_STATES, "UNKNOWN")
        s["_pod_state"] = normalize_choice(s.get("pod_state") or s.get("proof_of_delivery_state"), POD_STATES, "UNKNOWN")

        if not s["_planned_departure"] and not s["_actual_departure"]:
            add_flag(s, "missing_departure_time")
        if not s["_planned_arrival"] and not s["_actual_arrival"]:
            add_flag(s, "missing_arrival_time")

        if s["_actual_departure"] and s["_actual_arrival"] and s["_actual_arrival"] < s["_actual_departure"]:
            add_flag(s, "timing_conflict")

        if s["_status"] in {"DELIVERED_REPORTED", "DELIVERY_VERIFIED"} and s["_pod_state"] in {"NOT_AVAILABLE", "UNKNOWN"}:
            add_flag(s, "delivery_without_pod")

        s["_source_ids"] = [normalize_id(x) for x in ensure_list(s.get("source_ids") or s.get("source_id")) if x]
        s["_evidence_ids"] = [normalize_id(x) for x in ensure_list(s.get("evidence_ids") or s.get("evidence_id")) if x]

        shipments.append(s)

    if not shipments:
        issues.append("No shipments supplied")

    return shipments, issues


def validate_routes(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    routes: List[Dict[str, Any]] = []

    for idx, r in enumerate(get_records(case, "routes")):
        rid = normalize_id(r.get("route_id") or r.get("id")) or f"ROUTE-{idx + 1}"
        r["route_id"] = rid
        r["_shipment_id"] = normalize_id(r.get("shipment_id"))
        r["_origin"] = normalize_id(r.get("origin") or r.get("origin_node"))
        r["_destination"] = normalize_id(r.get("destination") or r.get("destination_node"))
        r["_leg_ids"] = [normalize_id(x) for x in ensure_list(r.get("legs") or r.get("leg_ids")) if x]
        r["_planned_path"] = r.get("planned_path") or r.get("planned_route")
        r["_observed_path"] = r.get("observed_path") or r.get("actual_route")
        r["_confidence"] = normalize_choice(r.get("confidence") or r.get("route_confidence"), ROUTE_CONFIDENCE, "UNKNOWN")
        r["_distance_m"] = to_float(r.get("distance_m") or r.get("distance"))
        r["_duration_s"] = to_float(r.get("duration_s") or r.get("duration"))
        r["_alternative_routes"] = [
            normalize_id(x.get("route_id") if isinstance(x, dict) else x)
            for x in ensure_list(r.get("alternative_routes") or r.get("alternatives"))
            if x
        ]

        if r["_confidence"] == "OBSERVED" and not r["_observed_path"] and not r["_leg_ids"]:
            add_flag(r, "route_observed_without_evidence")

        if r["_origin"] and r["_origin"] not in nodes:
            add_flag(r, "origin_node_unresolved")
        if r["_destination"] and r["_destination"] not in nodes:
            add_flag(r, "destination_node_unresolved")

        r["_source_ids"] = [normalize_id(x) for x in ensure_list(r.get("source_ids") or r.get("source_id")) if x]
        r["_evidence_ids"] = [normalize_id(x) for x in ensure_list(r.get("evidence_ids") or r.get("evidence_id")) if x]

        routes.append(r)

    return routes, issues


def validate_legs(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    legs: List[Dict[str, Any]] = []

    for idx, l in enumerate(get_records(case, "transport_legs", "legs")):
        lid = normalize_id(l.get("leg_id") or l.get("id")) or f"LEG-{idx + 1}"
        l["leg_id"] = lid
        l["_shipment_id"] = normalize_id(l.get("shipment_id"))
        l["_route_id"] = normalize_id(l.get("route_id"))
        l["_mode"] = normalize_mode(l.get("mode") or l.get("transport_mode"))
        l["_carrier"] = normalize_id(l.get("carrier") or l.get("carrier_id"))
        l["_origin_node"] = normalize_id(l.get("origin_node") or l.get("origin"))
        l["_destination_node"] = normalize_id(l.get("destination_node") or l.get("destination"))
        l["_asset_reference"] = l.get("vehicle_or_asset_reference") or l.get("asset_reference")

        l["_planned_start"] = parse_dt(l.get("planned_start"))
        l["_actual_start"] = parse_dt(l.get("actual_start"))
        l["_planned_end"] = parse_dt(l.get("planned_end"))
        l["_actual_end"] = parse_dt(l.get("actual_end"))

        if l["_planned_start"] and l["_planned_end"]:
            l["_planned_duration_s"] = (l["_planned_end"] - l["_planned_start"]).total_seconds()
        if l["_actual_start"] and l["_actual_end"]:
            l["_actual_duration_s"] = (l["_actual_end"] - l["_actual_start"]).total_seconds()
            if l["_actual_end"] < l["_actual_start"]:
                add_flag(l, "timing_conflict")

        if l["_origin_node"] and l["_origin_node"] not in nodes:
            add_flag(l, "origin_node_unresolved")
        if l["_destination_node"] and l["_destination_node"] not in nodes:
            add_flag(l, "destination_node_unresolved")

        l["_source_ids"] = [normalize_id(x) for x in ensure_list(l.get("source_ids") or l.get("source_id")) if x]
        l["_evidence_ids"] = [normalize_id(x) for x in ensure_list(l.get("evidence_ids") or l.get("evidence_id")) if x]

        legs.append(l)

    return legs, issues


def validate_events(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    events: List[Dict[str, Any]] = []

    for idx, e in enumerate(get_records(case, "shipment_events", "tracking_events", "edi_events", "events")):
        eid = normalize_id(e.get("event_id") or e.get("id")) or f"EVT-{idx + 1}"
        e["event_id"] = eid
        e["_shipment_id"] = normalize_id(e.get("shipment_id"))
        e["_event_type"] = normalize_event_type(e.get("event_type") or e.get("type"))
        e["_node_id"] = normalize_id(e.get("node_id") or e.get("location") or e.get("facility_id"))
        e["_carrier"] = normalize_id(e.get("carrier") or e.get("carrier_id"))
        e["_container_id"] = normalize_id(e.get("container_id"))

        e["_planned_time"] = parse_dt(e.get("planned_time"))
        e["_estimated_time"] = parse_dt(e.get("estimated_time") or e.get("eta"))
        e["_actual_time"] = parse_dt(e.get("actual_time") or e.get("event_time") or e.get("timestamp"))
        e["_reported_time"] = parse_dt(e.get("reported_time"))
        e["_ingestion_time"] = parse_dt(e.get("ingestion_time") or e.get("retrieved_at"))

        if not e["_actual_time"] and not e["_estimated_time"] and not e["_planned_time"]:
            add_flag(e, "missing_time")

        if e["_node_id"] and e["_node_id"] not in nodes:
            add_flag(e, "node_unresolved")

        e["_source_ids"] = [normalize_id(x) for x in ensure_list(e.get("source_ids") or e.get("source_id")) if x]
        e["_evidence_ids"] = [normalize_id(x) for x in ensure_list(e.get("evidence_ids") or e.get("evidence_id")) if x]

        events.append(e)

    return events, issues


def deduplicate_events(
    events: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    settings: Dict[str, Any],
) -> None:
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)

    for e in events:
        at = e.get("_actual_time")
        minute = at.replace(second=0, microsecond=0).isoformat() if at else None
        key = (e.get("_shipment_id"), e.get("_event_type"), e.get("_node_id"), minute)
        groups[key].append(e)

    for gid, (key, items) in enumerate(groups.items(), 1):
        if len(items) < 2:
            continue

        source_ids = sorted({sid for e in items for sid in (e.get("_source_ids") or []) if sid})
        states: List[str] = []
        for i in range(len(source_ids)):
            for j in range(i + 1, len(source_ids)):
                states.append(source_independence(sources.get(source_ids[i], {}), sources.get(source_ids[j], {})))

        if len(source_ids) <= 1:
            dup_state = "EXACT_DUPLICATE"
        elif states and all(s == "DEPENDENT" for s in states):
            dup_state = "PROBABLE_DUPLICATE"
        elif "INDEPENDENT" in states:
            dup_state = "SAME_PHYSICAL_EVENT"
        else:
            dup_state = "UNKNOWN"

        for e in items:
            e["_duplicate_group_id"] = f"DUP-{gid}"
            e["_duplicate_state"] = dup_state
            e["_duplicate_source_ids"] = source_ids
            if dup_state in {"EXACT_DUPLICATE", "PROBABLE_DUPLICATE"}:
                add_flag(e, "duplicate_source_dependency")


def validate_custody(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    custody: List[Dict[str, Any]] = []

    for idx, c in enumerate(get_records(case, "custody_events", "custody")):
        cid = normalize_id(c.get("event_id") or c.get("custody_id") or c.get("id")) or f"CUST-{idx + 1}"
        c["custody_id"] = cid
        c["_shipment_id"] = normalize_id(c.get("shipment_id"))
        c["_from_custodian"] = normalize_id(c.get("from_custodian") or c.get("from"))
        c["_to_custodian"] = normalize_id(c.get("to_custodian") or c.get("to"))
        c["_from_role"] = normalize_choice(c.get("from_role"), CUSTODY_ROLES, "UNKNOWN")
        c["_to_role"] = normalize_choice(c.get("to_role"), CUSTODY_ROLES, "UNKNOWN")
        c["_node_id"] = normalize_id(c.get("node_id") or c.get("location"))
        c["_time"] = parse_dt(c.get("time") or c.get("event_time") or c.get("timestamp"))

        if not c["_time"]:
            add_flag(c, "missing_time")
        if c["_node_id"] and c["_node_id"] not in nodes:
            add_flag(c, "node_unresolved")

        c["_source_ids"] = [normalize_id(x) for x in ensure_list(c.get("source_ids") or c.get("source_id")) if x]
        c["_evidence_ids"] = [normalize_id(x) for x in ensure_list(c.get("evidence_ids") or c.get("evidence_id")) if x]

        custody.append(c)

    return custody, issues


def validate_inventory(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    inventory: List[Dict[str, Any]] = []

    for idx, i in enumerate(get_records(case, "inventory_records", "inventory_snapshots", "inventory")):
        iid = normalize_id(i.get("inventory_id") or i.get("id")) or f"INV-{idx + 1}"
        i["inventory_id"] = iid
        i["_location_id"] = normalize_id(i.get("location_id") or i.get("node_id") or i.get("warehouse_id"))
        i["_product_id"] = normalize_id(i.get("product_id") or i.get("cargo_id"))
        i["_quantity"] = normalize_quantity(i.get("quantity"), i.get("unit") or "count", "quantity")
        i["_stock_state"] = normalize_choice(i.get("stock_state") or i.get("status"), STOCK_STATES, "UNKNOWN")
        i["_snapshot_time"] = parse_dt(i.get("snapshot_time") or i.get("as_of_time") or i.get("timestamp"))
        i["_lot"] = i.get("lot") or i.get("batch")

        if not i["_snapshot_time"]:
            add_flag(i, "missing_time")
        if i["_location_id"] and i["_location_id"] not in nodes:
            add_flag(i, "node_unresolved")
        if i["_quantity"]["normalized_value"] is not None and i["_quantity"]["normalized_value"] < 0:
            add_flag(i, "negative_inventory")

        for f in i["_quantity"].get("flags", []):
            add_flag(i, f)

        i["_source_ids"] = [normalize_id(x) for x in ensure_list(i.get("source_ids") or i.get("source_id")) if x]
        i["_evidence_ids"] = [normalize_id(x) for x in ensure_list(i.get("evidence_ids") or i.get("evidence_id")) if x]

        inventory.append(i)

    return inventory, issues


def validate_inventory_movements(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    movements: List[Dict[str, Any]] = []

    for idx, m in enumerate(get_records(case, "inventory_movements", "stock_movements")):
        mid = normalize_id(m.get("movement_id") or m.get("id")) or f"MOVE-{idx + 1}"
        m["movement_id"] = mid
        m["_product_id"] = normalize_id(m.get("product_id") or m.get("cargo_id"))
        m["_from_location"] = normalize_id(m.get("from_location") or m.get("origin_node"))
        m["_to_location"] = normalize_id(m.get("to_location") or m.get("destination_node"))
        m["_quantity"] = normalize_quantity(m.get("quantity"), m.get("unit") or "count", "quantity")
        m["_time"] = parse_dt(m.get("time") or m.get("movement_time") or m.get("timestamp"))

        if not m["_time"]:
            add_flag(m, "missing_time")
        if m["_quantity"]["normalized_value"] is not None and m["_quantity"]["normalized_value"] <= 0:
            add_flag(m, "nonpositive_movement")
        if m["_from_location"] and m["_from_location"] not in nodes:
            add_flag(m, "node_unresolved")
        if m["_to_location"] and m["_to_location"] not in nodes:
            add_flag(m, "node_unresolved")

        for f in m["_quantity"].get("flags", []):
            add_flag(m, f)

        m["_source_ids"] = [normalize_id(x) for x in ensure_list(m.get("source_ids") or m.get("source_id")) if x]
        m["_evidence_ids"] = [normalize_id(x) for x in ensure_list(m.get("evidence_ids") or m.get("evidence_id")) if x]

        movements.append(m)

    return movements, issues


def validate_capacity(case: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    capacity: List[Dict[str, Any]] = []

    for idx, c in enumerate(get_records(case, "capacity_records", "capacity")):
        cid = normalize_id(c.get("capacity_id") or c.get("id")) or f"CAP-{idx + 1}"
        c["capacity_id"] = cid
        c["_node_id"] = normalize_id(c.get("node_id") or c.get("warehouse_id") or c.get("terminal_id"))
        c["_capacity_type"] = str(c.get("capacity_type", "UNKNOWN")).upper()
        c["_capacity_state"] = normalize_choice(c.get("capacity_state"), CAPACITY_STATES, "UNKNOWN")
        c["_unit"] = c.get("unit")
        c["_design"] = to_float(c.get("design_capacity"))
        c["_claimed"] = to_float(c.get("claimed_capacity"))
        c["_observed"] = to_float(c.get("observed_capacity"))
        c["_available"] = to_float(c.get("available_capacity"))
        c["_utilized"] = to_float(c.get("utilized_capacity"))
        c["_throughput"] = to_float(c.get("throughput"))
        c["_throughput_unit"] = c.get("throughput_unit")
        c["_as_of_time"] = parse_dt(c.get("as_of_time") or c.get("timestamp"))

        if c["_available"] is not None and c["_utilized"] is not None and c["_available"] > 0:
            c["_utilization_rate"] = c["_utilized"] / c["_available"]
        else:
            c["_utilization_rate"] = None

        if c["_available"] is not None and c["_utilized"] is not None and c["_unit"] and c["_throughput_unit"] and c["_unit"] != c["_throughput_unit"]:
            add_flag(c, "capacity_unit_mismatch")

        c["_source_ids"] = [normalize_id(x) for x in ensure_list(c.get("source_ids") or c.get("source_id")) if x]
        c["_evidence_ids"] = [normalize_id(x) for x in ensure_list(c.get("evidence_ids") or c.get("evidence_id")) if x]

        capacity.append(c)

    return capacity, issues


def validate_deliveries(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    settings: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    deliveries: List[Dict[str, Any]] = []

    for idx, d in enumerate(get_records(case, "deliveries", "delivery_records", "proof_of_delivery")):
        did = normalize_id(d.get("delivery_id") or d.get("pod_id") or d.get("id")) or f"DEL-{idx + 1}"
        d["delivery_id"] = did
        d["_shipment_id"] = normalize_id(d.get("shipment_id"))
        d["_status"] = normalize_choice(d.get("status") or d.get("delivery_status"), DELIVERY_STATES, "UNKNOWN")
        d["_pod_state"] = normalize_choice(d.get("pod_state") or d.get("proof_of_delivery_state"), POD_STATES, "UNKNOWN")
        d["_time"] = parse_dt(d.get("time") or d.get("delivery_time") or d.get("timestamp"))
        d["_node_id"] = normalize_id(d.get("node_id") or d.get("location_id") or d.get("delivery_location_id"))
        d["_recipient_role"] = str(d.get("recipient_role", "UNKNOWN")).upper()
        d["_pod_type"] = str(d.get("pod_type") or d.get("evidence_type") or "UNKNOWN").upper()

        tags = get_tags(d)
        d["_tags"] = tags
        if redact_private_fields(d, tags, settings.get("sensitive_exact_authorized", False)):
            d["_node_id"] = None
            d["_location_text"] = "REDACTED"

        if not d["_time"]:
            add_flag(d, "missing_time")
        if d["_node_id"] and d["_node_id"] not in nodes:
            add_flag(d, "node_unresolved")
        if d["_status"] in {"DELIVERED_REPORTED", "DELIVERY_VERIFIED"} and d["_pod_state"] in {"NOT_AVAILABLE", "UNKNOWN"}:
            add_flag(d, "delivery_without_pod")

        d["_source_ids"] = [normalize_id(x) for x in ensure_list(d.get("source_ids") or d.get("source_id")) if x]
        d["_evidence_ids"] = [normalize_id(x) for x in ensure_list(d.get("evidence_ids") or d.get("evidence_id")) if x]

        deliveries.append(d)

    return deliveries, issues


def validate_customs(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    customs: List[Dict[str, Any]] = []

    for idx, c in enumerate(get_records(case, "customs_records", "customs_events")):
        cid = normalize_id(c.get("customs_event_id") or c.get("id")) or f"CU-{idx + 1}"
        c["customs_event_id"] = cid
        c["_shipment_id"] = normalize_id(c.get("shipment_id"))
        c["_event_type"] = str(c.get("event_type") or c.get("type") or "UNKNOWN").upper()
        c["_time"] = parse_dt(c.get("time") or c.get("event_time") or c.get("timestamp"))
        c["_node_id"] = normalize_id(c.get("node_id") or c.get("customs_point_id") or c.get("location"))
        c["_status"] = str(c.get("status", "UNKNOWN")).upper()

        if not c["_time"]:
            add_flag(c, "missing_time")
        if c["_node_id"] and c["_node_id"] not in nodes:
            add_flag(c, "node_unresolved")

        c["_source_ids"] = [normalize_id(x) for x in ensure_list(c.get("source_ids") or c.get("source_id")) if x]
        c["_evidence_ids"] = [normalize_id(x) for x in ensure_list(c.get("evidence_ids") or c.get("evidence_id")) if x]

        customs.append(c)

    # Sequence sanity: release/clearance should not precede entry if both known.
    by_shipment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in customs:
        if c.get("_shipment_id") and c.get("_time"):
            by_shipment[c["_shipment_id"]].append(c)

    for sid, items in by_shipment.items():
        entries = [x for x in items if x.get("_event_type") in {"ENTRY", "CUSTOMS_ENTRY"}]
        releases = [x for x in items if x.get("_event_type") in {"RELEASE", "CUSTOMS_RELEASE", "CLEARANCE"}]
        if entries and releases:
            earliest_entry = min(entries, key=lambda x: x["_time"])
            latest_release = max(releases, key=lambda x: x["_time"])
            if latest_release["_time"] < earliest_entry["_time"]:
                for x in releases:
                    add_flag(x, "customs_sequence_conflict")

    return customs, issues


def validate_disruptions(
    case: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    routes: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    disruptions: List[Dict[str, Any]] = []
    route_ids = {r.get("route_id") for r in routes if r.get("route_id")}

    for idx, d in enumerate(get_records(case, "disruptions", "incidents")):
        did = normalize_id(d.get("disruption_id") or d.get("incident_id") or d.get("id")) or f"DISR-{idx + 1}"
        d["disruption_id"] = did
        d["_type"] = str(d.get("type") or d.get("disruption_type") or "UNKNOWN").upper()
        d["_node_id"] = normalize_id(d.get("node_id") or d.get("facility_id") or d.get("port_id") or d.get("warehouse_id"))
        d["_route_id"] = normalize_id(d.get("route_id"))
        d["_start_time"] = parse_dt(d.get("start_time") or d.get("time"))
        d["_end_time"] = parse_dt(d.get("end_time"))
        d["_impact_state"] = normalize_choice(d.get("impact_state"), IMPACT_STATES, "UNKNOWN")
        d["_reported_cause"] = d.get("cause") or d.get("reported_cause")

        if d["_node_id"] and d["_node_id"] not in nodes:
            add_flag(d, "node_unresolved")
        if d["_route_id"] and d["_route_id"] not in route_ids:
            add_flag(d, "route_unresolved")
        if d["_start_time"] and d["_end_time"] and d["_end_time"] < d["_start_time"]:
            add_flag(d, "timing_conflict")

        d["_source_ids"] = [normalize_id(x) for x in ensure_list(d.get("source_ids") or d.get("source_id")) if x]
        d["_evidence_ids"] = [normalize_id(x) for x in ensure_list(d.get("evidence_ids") or d.get("evidence_id")) if x]

        disruptions.append(d)

    return disruptions, issues


def validate_cold_chain(case: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    issues: List[str] = []
    cold: List[Dict[str, Any]] = []

    for idx, c in enumerate(get_records(case, "cold_chain_records", "temperature_records", "sensor_records")):
        cid = normalize_id(c.get("record_id") or c.get("sensor_event_id") or c.get("id")) or f"COLD-{idx + 1}"
        c["record_id"] = cid
        c["_shipment_id"] = normalize_id(c.get("shipment_id"))
        c["_sensor_id"] = normalize_id(c.get("sensor_id"))
        c["_time"] = parse_dt(c.get("time") or c.get("timestamp"))
        c["_temperature_c"] = to_float(c.get("temperature_c") or c.get("value"))
        c["_unit"] = c.get("unit") or "C"
        c["_limit_min_c"] = to_float(c.get("limit_min_c") or c.get("min_c"))
        c["_limit_max_c"] = to_float(c.get("limit_max_c") or c.get("max_c"))
        c["_calibration_status"] = str(c.get("calibration_status", "UNKNOWN")).upper()

        if not c["_time"]:
            add_flag(c, "missing_time")
        if c["_calibration_status"] in {"UNCALIBRATED", "UNKNOWN", "EXPIRED"}:
            add_flag(c, "sensor_unreliable")

        t = c.get("_temperature_c")
        mn = c.get("_limit_min_c")
        mx = c.get("_limit_max_c")
        c["_excursion"] = False
        if t is not None:
            if mn is not None and t < mn:
                c["_excursion"] = True
            if mx is not None and t > mx:
                c["_excursion"] = True

        c["_source_ids"] = [normalize_id(x) for x in ensure_list(c.get("source_ids") or c.get("source_id")) if x]
        c["_evidence_ids"] = [normalize_id(x) for x in ensure_list(c.get("evidence_ids") or c.get("evidence_id")) if x]

        cold.append(c)

    return cold, issues


def check_references(
    shipments: List[Dict[str, Any]],
    orders: Dict[str, Dict[str, Any]],
    cargo: Dict[str, Dict[str, Any]],
    containers: Dict[str, Dict[str, Any]],
    carriers: Dict[str, Dict[str, Any]],
    forwarders: Dict[str, Dict[str, Any]],
    nodes: Dict[str, Dict[str, Any]],
    legs: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    custody: List[Dict[str, Any]],
    deliveries: List[Dict[str, Any]],
    customs: List[Dict[str, Any]],
    disruptions: List[Dict[str, Any]],
) -> List[str]:
    warnings: List[str] = []

    shipment_ids = {s.get("shipment_id") for s in shipments if s.get("shipment_id")}

    for s in shipments:
        if s.get("_order_reference") and s["_order_reference"] not in orders:
            warnings.append(f"shipment {s.get('shipment_id')} references unknown order {s['_order_reference']}")
        for cid in s.get("_cargo_ids") or []:
            if cid not in cargo:
                warnings.append(f"shipment {s.get('shipment_id')} references unknown cargo {cid}")
        for cont in s.get("_container_ids") or []:
            if cont not in containers:
                warnings.append(f"shipment {s.get('shipment_id')} references unknown container {cont}")
        if s.get("_carrier") and s["_carrier"] not in carriers:
            warnings.append(f"shipment {s.get('shipment_id')} references unknown carrier {s['_carrier']}")
        if s.get("_forwarder") and s["_forwarder"] not in forwarders:
            warnings.append(f"shipment {s.get('shipment_id')} references unknown forwarder {s['_forwarder']}")
        if s.get("_origin_node") and s["_origin_node"] not in nodes:
            warnings.append(f"shipment {s.get('shipment_id')} references unknown origin node {s['_origin_node']}")
        if s.get("_destination_node") and s["_destination_node"] not in nodes:
            warnings.append(f"shipment {s.get('shipment_id')} references unknown destination node {s['_destination_node']}")

    for l in legs:
        if l.get("_shipment_id") and l["_shipment_id"] not in shipment_ids:
            warnings.append(f"leg {l.get('leg_id')} references unknown shipment {l['_shipment_id']}")
        if l.get("_carrier") and l["_carrier"] not in carriers:
            warnings.append(f"leg {l.get('leg_id')} references unknown carrier {l['_carrier']}")

    for coll in (events, custody, deliveries, customs):
        for item in coll:
            sid = item.get("_shipment_id")
            if sid and sid not in shipment_ids:
                warnings.append(f"{item.get('event_id') or item.get('custody_id') or item.get('delivery_id') or item.get('customs_event_id')} references unknown shipment {sid}")

    for d in disruptions:
        if d.get("_node_id") and d["_node_id"] not in nodes:
            warnings.append(f"disruption {d.get('disruption_id')} references unknown node {d['_node_id']}")

    return warnings


# -----------------------------------------------------------------------------
# Analysis
# -----------------------------------------------------------------------------

def analyze_route_confidence(
    routes: List[Dict[str, Any]],
    legs: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> None:
    legs_by_route: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for l in legs:
        if l.get("_route_id"):
            legs_by_route[l["_route_id"]].append(l)

    events_by_shipment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("_shipment_id"):
            events_by_shipment[e["_shipment_id"]].append(e)

    for r in routes:
        rid = r.get("route_id")
        route_legs = legs_by_route.get(rid, [])
        observed_legs = [l for l in route_legs if l.get("_actual_start") and l.get("_actual_end")]
        shipment_events = events_by_shipment.get(r.get("_shipment_id") or "", [])

        if r.get("_confidence") == "UNKNOWN":
            if observed_legs and len(observed_legs) == len(route_legs):
                r["_confidence"] = "OBSERVED"
            elif observed_legs:
                r["_confidence"] = "SUPPORTED"
            elif route_legs:
                r["_confidence"] = "INFERRED"
            elif r.get("_planned_path"):
                r["_confidence"] = "SPECULATIVE"
            else:
                r["_confidence"] = "UNKNOWN"

        if r.get("_confidence") == "OBSERVED" and not observed_legs and not shipment_events:
            add_flag(r, "route_observed_without_evidence")


def analyze_custody(
    custody: List[Dict[str, Any]],
    shipments: List[Dict[str, Any]],
    settings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    by_shipment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in custody:
        if c.get("_shipment_id"):
            by_shipment[c["_shipment_id"]].append(c)

    shipment_by_id = {s.get("shipment_id"): s for s in shipments}
    results: List[Dict[str, Any]] = []
    gap_threshold_s = float(settings.get("custody_gap_threshold_s", 86400.0))

    for sid, items in by_shipment.items():
        items = sorted(items, key=lambda x: dt_sort_key(x.get("_time")))
        gaps: List[Dict[str, Any]] = []
        prev: Optional[Dict[str, Any]] = None

        for c in items:
            if prev and prev.get("_time") and c.get("_time"):
                delta = (c["_time"] - prev["_time"]).total_seconds()
                if delta > gap_threshold_s:
                    gaps.append(
                        {
                            "type": "time_gap",
                            "from_event_id": prev.get("custody_id"),
                            "to_event_id": c.get("custody_id"),
                            "gap_hours": delta / 3600.0,
                            "note": "Custody gap may reflect missing scan, offline system, data-source gap, or manual handling. Do not infer theft automatically.",
                        }
                    )
            prev = c

        s = shipment_by_id.get(sid, {})
        start_ok = bool(items) and (items[0].get("_from_custodian") == s.get("_shipper") or items[0].get("_from_role") in {"SHIPPER", "UNKNOWN"})
        end_ok = bool(items) and (items[-1].get("_to_custodian") == s.get("_consignee") or items[-1].get("_to_role") in {"CONSIGNEE", "UNKNOWN"})

        if not start_ok:
            gaps.append({"type": "origin_custody_unresolved", "note": "First custody event does not clearly begin with shipper/origin custodian."})
        if not end_ok:
            gaps.append({"type": "destination_custody_unresolved", "note": "Last custody event does not clearly end with consignee/destination custodian."})

        for g in gaps:
            for c in items:
                add_flag(c, "custody_gap")

        results.append(
            {
                "shipment_id": sid,
                "custody_event_ids": [c.get("custody_id") for c in items],
                "custody_gap_count": len(gaps),
                "gaps": gaps,
                "last_supported_custodian": (items[-1].get("_to_custodian") if items else None),
                "last_custody_time": iso_or_none(items[-1].get("_time")) if items else None,
                "limitations": [
                    "Custody is operational possession, not ownership.",
                    "Custody gap is not automatically loss, theft, or fraud.",
                ],
            }
        )

    return results


def disruption_affects_shipment(
    disruption: Dict[str, Any],
    shipment: Dict[str, Any],
    legs: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    nodes: Dict[str, Dict[str, Any]],
) -> Tuple[bool, List[str]]:
    evidence: List[str] = []
    sid = shipment.get("shipment_id")
    d_node = disruption.get("_node_id")
    d_route = disruption.get("_route_id")
    d_start = disruption.get("_start_time")
    d_end = disruption.get("_end_time")

    for l in legs:
        if l.get("_shipment_id") != sid:
            continue
        if d_route and l.get("_route_id") == d_route:
            evidence.append(f"leg {l.get('leg_id')} uses disrupted route {d_route}")
        if d_node and l.get("_origin_node") == d_node:
            evidence.append(f"leg {l.get('leg_id')} originates at disrupted node {d_node}")
        if d_node and l.get("_destination_node") == d_node:
            evidence.append(f"leg {l.get('leg_id')} arrives at disrupted node {d_node}")

    for e in events:
        if e.get("_shipment_id") != sid:
            continue
        if d_node and e.get("_node_id") == d_node:
            if time_overlap(d_start, d_end, e.get("_actual_time"), e.get("_actual_time")):
                evidence.append(f"event {e.get('event_id')} occurred at disrupted node within disruption window")
            else:
                evidence.append(f"event {e.get('event_id')} occurred at disrupted node outside supplied disruption window")

    return bool(evidence), evidence


def analyze_delays(
    shipments: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    legs: List[Dict[str, Any]],
    disruptions: List[Dict[str, Any]],
    weather_context: Dict[str, Any],
    settings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    events_by_shipment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("_shipment_id"):
            events_by_shipment[e["_shipment_id"]].append(e)

    results: List[Dict[str, Any]] = []
    delay_threshold_h = float(settings.get("delay_threshold_hours", 1.0))

    for s in shipments:
        sid = s.get("shipment_id")
        sevts = events_by_shipment.get(sid, [])

        dep_actual = s.get("_actual_departure")
        arr_actual = s.get("_actual_arrival")

        dep_events = [e for e in sevts if e.get("_event_type") == "DEPARTED" and e.get("_actual_time")]
        arr_events = [e for e in sevts if e.get("_event_type") in {"ARRIVED", "DELIVERED"} and e.get("_actual_time")]

        if not dep_actual and dep_events:
            dep_actual = min((e["_actual_time"] for e in dep_events), key=dt_sort_key)
        if not arr_actual and arr_events:
            arr_actual = max((e["_actual_time"] for e in arr_events), key=dt_sort_key)

        planned_dep = s.get("_planned_departure")
        planned_arr = s.get("_planned_arrival")

        dep_delay_h = None
        arr_delay_h = None

        if planned_dep and dep_actual:
            dep_delay_h = (dep_actual - planned_dep).total_seconds() / 3600.0
        if planned_arr and arr_actual:
            arr_delay_h = (arr_actual - planned_arr).total_seconds() / 3600.0

        max_delay_h = max([x for x in (dep_delay_h, arr_delay_h) if x is not None], default=None)
        delayed = max_delay_h is not None and max_delay_h >= delay_threshold_h

        causes: List[Dict[str, Any]] = []

        if s.get("_delay_cause"):
            causes.append(
                {
                    "cause": s["_delay_cause"],
                    "state": "SOURCE_REPORTED_CAUSE",
                    "evidence": ["shipment record supplied delay cause"],
                }
            )

        for d in disruptions:
            affected, evidence = disruption_affects_shipment(d, s, legs, sevts, {})
            if affected:
                state = "SUPPORTED_CAUSE" if d.get("_impact_state") in {"DIRECT_IMPACT_SUPPORTED", "MAJOR_IMPACT_SUPPORTED"} else "PROBABLE_CAUSE"
                causes.append(
                    {
                        "cause": d.get("_type") or d.get("_reported_cause") or "disruption",
                        "state": state,
                        "disruption_id": d.get("disruption_id"),
                        "evidence": evidence[:10],
                    }
                )

        if weather_context and delayed and not causes:
            causes.append(
                {
                    "cause": "weather_context_supplied_but_not_operationally_linked",
                    "state": "UNKNOWN",
                    "evidence": ["Weather near route does not prove weather-caused delay without operational evidence."],
                }
            )

        results.append(
            {
                "shipment_id": sid,
                "planned_departure": iso_or_none(planned_dep),
                "actual_departure": iso_or_none(dep_actual),
                "planned_arrival": iso_or_none(planned_arr),
                "actual_arrival": iso_or_none(arr_actual),
                "departure_delay_hours": dep_delay_h,
                "arrival_delay_hours": arr_delay_h,
                "max_delay_hours": max_delay_h,
                "delayed": delayed,
                "delay_causes": causes,
                "limitations": [
                    "Delay is planned-vs-actual difference, not negligence.",
                    "Cause state depends on independent operational evidence.",
                    "Weather or disruption proximity alone does not prove causation.",
                ],
            }
        )

    return results


def analyze_lead_and_dwell_times(
    shipments: List[Dict[str, Any]],
    legs: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    orders: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    legs_by_shipment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for l in legs:
        if l.get("_shipment_id"):
            legs_by_shipment[l["_shipment_id"]].append(l)

    events_by_shipment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        if e.get("_shipment_id"):
            events_by_shipment[e["_shipment_id"]].append(e)

    lead_times: List[Dict[str, Any]] = []
    dwell_times: List[Dict[str, Any]] = []

    for s in shipments:
        sid = s.get("shipment_id")
        order = orders.get(s.get("_order_reference") or "", {})
        order_created = order.get("_created_time")
        actual_dep = s.get("_actual_departure")
        actual_arr = s.get("_actual_arrival")

        if not actual_dep:
            dep_events = [e for e in events_by_shipment.get(sid, []) if e.get("_event_type") == "DEPARTED" and e.get("_actual_time")]
            if dep_events:
                actual_dep = min((e["_actual_time"] for e in dep_events), key=dt_sort_key)
        if not actual_arr:
            arr_events = [e for e in events_by_shipment.get(sid, []) if e.get("_event_type") in {"ARRIVED", "DELIVERED"} and e.get("_actual_time")]
            if arr_events:
                actual_arr = max((e["_actual_time"] for e in arr_events), key=dt_sort_key)

        if order_created and actual_dep:
            lead_times.append(
                {
                    "shipment_id": sid,
                    "metric": "order_to_departure",
                    "hours": (actual_dep - order_created).total_seconds() / 3600.0,
                    "limitation": "Order creation to departure includes processing and may not equal transit time.",
                }
            )

        if actual_dep and actual_arr:
            lead_times.append(
                {
                    "shipment_id": sid,
                    "metric": "transit_time",
                    "hours": (actual_arr - actual_dep).total_seconds() / 3600.0,
                    "limitation": "Transit time is movement period only, not full lead time.",
                }
            )

        # Dwell from ARRIVED to next DEPARTED at same node.
        node_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for e in events_by_shipment.get(sid, []):
            if e.get("_node_id") and e.get("_actual_time"):
                node_events[e["_node_id"]].append(e)

        for node, items in node_events.items():
            items = sorted(items, key=lambda x: dt_sort_key(x.get("_actual_time")))
            arrived: Optional[datetime] = None
            for e in items:
                if e.get("_event_type") == "ARRIVED" and arrived is None:
                    arrived = e["_actual_time"]
                elif e.get("_event_type") in {"DEPARTED", "GATE_OUT", "WAREHOUSE_DISPATCH"} and arrived is not None:
                    dwell_times.append(
                        {
                            "shipment_id": sid,
                            "node_id": node,
                            "arrival_time": iso_or_none(arrived),
                            "departure_time": iso_or_none(e["_actual_time"]),
                            "dwell_hours": (e["_actual_time"] - arrived).total_seconds() / 3600.0,
                            "limitation": "Dwell is event-based and may be affected by scan latency.",
                        }
                    )
                    arrived = None

    return {
        "lead_times": lead_times,
        "dwell_times": dwell_times,
        "lead_time_summary": numeric_summary([x.get("hours") for x in lead_times]),
        "dwell_time_summary": numeric_summary([x.get("dwell_hours") for x in dwell_times]),
    }


def analyze_inventory(records: List[Dict[str, Any]], movements: List[Dict[str, Any]]) -> Dict[str, Any]:
    snapshots: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        key = (str(r.get("_product_id") or "UNKNOWN"), str(r.get("_location_id") or "UNKNOWN"))
        snapshots[key].append(r)

    latest_snapshots: List[Dict[str, Any]] = []
    for key, items in snapshots.items():
        items = sorted(items, key=lambda x: dt_sort_key(x.get("_snapshot_time")))
        if items:
            latest_snapshots.append(items[-1])

    movement_net: Dict[Tuple[str, str], float] = defaultdict(float)
    for m in movements:
        q = m.get("_quantity", {}).get("normalized_value")
        if q is None:
            continue
        prod = str(m.get("_product_id") or "UNKNOWN")
        if m.get("_from_location"):
            movement_net[(prod, str(m["_from_location"]))] -= q
        if m.get("_to_location"):
            movement_net[(prod, str(m["_to_location"]))] += q

    negative_flags = [r.get("inventory_id") for r in records if "negative_inventory" in (r.get("_quality_flags") or [])]

    return {
        "snapshot_count": len(records),
        "movement_count": len(movements),
        "latest_snapshots": [
            {
                "inventory_id": r.get("inventory_id"),
                "product_id": r.get("_product_id"),
                "location_id": r.get("_location_id"),
                "quantity": r.get("_quantity", {}).get("normalized_value"),
                "unit": r.get("_quantity", {}).get("normalized_unit"),
                "stock_state": r.get("_stock_state"),
                "snapshot_time": iso_or_none(r.get("_snapshot_time")),
                "quality_flags": r.get("_quality_flags"),
            }
            for r in latest_snapshots
        ],
        "movement_net_by_product_location": [
            {"product_id": k[0], "location_id": k[1], "net_quantity": v}
            for k, v in sorted(movement_net.items())
        ],
        "negative_inventory_ids": negative_flags,
        "limitations": [
            "Inventory is temporal; all assertions are as-of snapshot time.",
            "Negative inventory may indicate timing lag, system error, returns, or data-quality issue, not automatically theft/fraud.",
            "Movements are not reconciled to opening inventory unless snapshots cover the same product/location/time basis.",
        ],
    }


def analyze_capacity(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: List[Dict[str, Any]] = []
    for c in records:
        out.append(
            {
                "capacity_id": c.get("capacity_id"),
                "node_id": c.get("_node_id"),
                "capacity_type": c.get("_capacity_type"),
                "capacity_state": c.get("_capacity_state"),
                "unit": c.get("_unit"),
                "design_capacity": c.get("_design"),
                "claimed_capacity": c.get("_claimed"),
                "observed_capacity": c.get("_observed"),
                "available_capacity": c.get("_available"),
                "utilized_capacity": c.get("_utilized"),
                "utilization_rate": c.get("_utilization_rate"),
                "throughput": c.get("_throughput"),
                "throughput_unit": c.get("_throughput_unit"),
                "as_of_time": iso_or_none(c.get("_as_of_time")),
                "quality_flags": c.get("_quality_flags"),
                "limitations": [
                    "Claimed capacity is source-reported, not observed capacity.",
                    "Capacity is storage/availability, not throughput.",
                    "Utilization is deterministic only when available and utilized values share units.",
                ],
            }
        )

    return {
        "capacity_records": out,
        "utilization_summary": numeric_summary([c.get("_utilization_rate") for c in records]),
    }


def analyze_service_levels(
    shipments: List[Dict[str, Any]],
    deliveries: List[Dict[str, Any]],
    orders: Dict[str, Dict[str, Any]],
    delay_results: List[Dict[str, Any]],
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    delay_by_shipment = {d.get("shipment_id"): d for d in delay_results}
    deliveries_by_shipment: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for d in deliveries:
        if d.get("_shipment_id"):
            deliveries_by_shipment[d["_shipment_id"]].append(d)

    eligible = 0
    on_time = 0
    otif_eligible = 0
    otif = 0
    details: List[Dict[str, Any]] = []

    on_time_window_h = float(settings.get("on_time_window_hours", 0.0))

    for s in shipments:
        sid = s.get("shipment_id")
        planned_arr = s.get("_planned_arrival")
        del_result = delay_by_shipment.get(sid, {})
        actual_arr = parse_dt(del_result.get("actual_arrival"))

        if not planned_arr or not actual_arr:
            continue

        eligible += 1
        is_on_time = (actual_arr - planned_arr).total_seconds() / 3600.0 <= on_time_window_h
        if is_on_time:
            on_time += 1

        order = orders.get(s.get("_order_reference") or "", {})
        ordered_qty = order.get("_quantity", {}).get("normalized_value")
        delivered_qty = None
        for d in deliveries_by_shipment.get(sid, []):
            dq = normalize_quantity(d.get("delivered_quantity"), d.get("delivered_unit") or "count", "quantity")
            if dq.get("normalized_value") is not None:
                delivered_qty = dq["normalized_value"]
                break

        if ordered_qty is not None and delivered_qty is not None:
            otif_eligible += 1
            if is_on_time and abs(delivered_qty - ordered_qty) <= 1e-9:
                otif += 1

        details.append(
            {
                "shipment_id": sid,
                "on_time": is_on_time,
                "ordered_quantity": ordered_qty,
                "delivered_quantity": delivered_qty,
                "otif": bool(is_on_time and ordered_qty is not None and delivered_qty is not None and abs(delivered_qty - ordered_qty) <= 1e-9),
            }
        )

    return {
        "eligible_deliveries": eligible,
        "on_time_deliveries": on_time,
        "on_time_rate": (on_time / eligible) if eligible else None,
        "otif_eligible": otif_eligible,
        "otif_count": otif,
        "otif_rate": (otif / otif_eligible) if otif_eligible else None,
        "definition": {
            "on_time_window_hours": on_time_window_h,
            "otif_requires": "agreed time, ordered quantity, delivered quantity",
        },
        "details": details[:200],
        "limitations": [
            "Service metrics are descriptive, not causal.",
            "Small samples can produce unstable rates.",
            "Carrier delay may arise from port, customs, weather, shipper, consignee, or infrastructure.",
        ],
    }


def analyze_cold_chain(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    excursions = [r for r in records if r.get("_excursion")]
    unreliable = [r for r in records if "sensor_unreliable" in (r.get("_quality_flags") or [])]

    return {
        "record_count": len(records),
        "excursion_count": len(excursions),
        "excursion_records": [
            {
                "record_id": r.get("record_id"),
                "shipment_id": r.get("_shipment_id"),
                "sensor_id": r.get("_sensor_id"),
                "time": iso_or_none(r.get("_time")),
                "temperature_c": r.get("_temperature_c"),
                "limit_min_c": r.get("_limit_min_c"),
                "limit_max_c": r.get("_limit_max_c"),
                "quality_flags": r.get("_quality_flags"),
            }
            for r in excursions[:200]
        ],
        "unreliable_sensor_count": len(unreliable),
        "limitations": [
            "Temperature excursion is sensor-based and depends on calibration, placement, and product limits.",
            "Excursion does not automatically prove product spoilage or safety failure.",
        ],
    }


def analyze_dependencies_and_resilience(
    shipments: List[Dict[str, Any]],
    legs: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    nodes: Dict[str, Dict[str, Any]],
    carriers: Dict[str, Dict[str, Any]],
    routes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    node_load: Counter = Counter()
    carrier_load: Counter = Counter()
    route_load: Counter = Counter()
    node_carriers: Dict[str, set] = defaultdict(set)

    for l in legs:
        if l.get("_origin_node"):
            node_load[l["_origin_node"]] += 1
        if l.get("_destination_node"):
            node_load[l["_destination_node"]] += 1
        if l.get("_carrier"):
            carrier_load[l["_carrier"]] += 1
            if l.get("_origin_node"):
                node_carriers[l["_origin_node"]].add(l["_carrier"])
            if l.get("_destination_node"):
                node_carriers[l["_destination_node"]].add(l["_carrier"])
        if l.get("_route_id"):
            route_load[l["_route_id"]] += 1

    for e in events:
        if e.get("_node_id"):
            node_load[e["_node_id"]] += 1
        if e.get("_carrier"):
            carrier_load[e["_carrier"]] += 1

    total_legs = max(1, len(legs))
    node_results: List[Dict[str, Any]] = []

    for nid, count in node_load.most_common():
        node = nodes.get(nid, {})
        alternatives = [x for x in node.get("_alternative_nodes") or [] if x]
        share = count / total_legs
        if count >= 3 and not alternatives:
            resilience = "SINGLE_DEPENDENCY_CANDIDATE"
        elif alternatives and share < 0.2:
            resilience = "HIGH_REDUNDANCY"
        elif alternatives:
            resilience = "MODERATE_REDUNDANCY"
        elif share >= 0.5:
            resilience = "LOW_REDUNDANCY"
        else:
            resilience = "UNKNOWN"

        node_results.append(
            {
                "node_id": nid,
                "node_type": node.get("_node_type"),
                "load_count": count,
                "load_share_of_legs": share,
                "alternative_node_ids": alternatives,
                "resilience_state": resilience,
                "critical_dependency_candidate": count >= 3 and not alternatives,
                "limitations": [
                    "Critical dependency is a resilience concept, not an attack target.",
                    "Load count is limited to supplied legs/events and does not prove real-world volume.",
                    "Mapped alternatives are not tested alternatives.",
                ],
            }
        )

    carrier_results: List[Dict[str, Any]] = []
    for cid, count in carrier_load.most_common():
        carrier = carriers.get(cid, {})
        alternatives = [x for x in ensure_list(carrier.get("alternative_carriers") or carrier.get("alternatives")) if x]
        resilience = "SINGLE_DEPENDENCY_CANDIDATE" if count >= 3 and not alternatives else ("MODERATE_REDUNDANCY" if alternatives else "UNKNOWN")
        carrier_results.append(
            {
                "carrier_id": cid,
                "load_count": count,
                "alternative_carrier_ids": alternatives,
                "resilience_state": resilience,
                "limitations": [
                    "Carrier dependency is limited to supplied records.",
                    "Alternative carrier must be assessed for mode, capacity, compatibility, lead time, cost, and regulation by humans.",
                ],
            }
        )

    common_mode: List[Dict[str, Any]] = []
    for nid, carrier_set in node_carriers.items():
        if len(carrier_set) > 1:
            common_mode.append(
                {
                    "node_id": nid,
                    "carrier_ids": sorted(carrier_set),
                    "note": "Multiple carriers share this node; multi-carrier arrangements may still have common-mode dependency.",
                }
            )

    route_results: List[Dict[str, Any]] = []
    for rid, count in route_load.most_common():
        route = next((r for r in routes if r.get("route_id") == rid), {})
        alternatives = [x for x in route.get("_alternative_routes") or [] if x]
        route_results.append(
            {
                "route_id": rid,
                "load_count": count,
                "alternative_route_ids": alternatives,
                "resilience_state": "SINGLE_DEPENDENCY_CANDIDATE" if count >= 3 and not alternatives else "UNKNOWN",
                "limitations": [
                    "Route load is supplied-record based.",
                    "No route generation or evasion optimization is performed.",
                ],
            }
        )

    return {
        "node_dependencies": node_results,
        "carrier_dependencies": carrier_results,
        "route_dependencies": route_results,
        "common_mode_dependencies": common_mode,
        "limitations": [
            "Resilience analysis is defensive and business-continuity oriented.",
            "Criticality is not converted into attack value.",
            "Documented alternatives are not tested alternatives.",
        ],
    }


def detect_contradictions(
    shipments: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    custody_results: List[Dict[str, Any]],
    deliveries: List[Dict[str, Any]],
    customs: List[Dict[str, Any]],
    inventory: List[Dict[str, Any]],
    routes: List[Dict[str, Any]],
    delay_results: List[Dict[str, Any]],
    initial_contradictions: List[Dict[str, Any]],
    settings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    contradictions = list(initial_contradictions)

    for r in routes:
        if "route_observed_without_evidence" in (r.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "route_confidence_overclaim",
                    "route_id": r.get("route_id"),
                    "note": "Route marked observed without supporting observed legs/events.",
                }
            )

    for s in shipments:
        if "delivery_without_pod" in (s.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "delivery_without_pod",
                    "shipment_id": s.get("shipment_id"),
                    "note": "Shipment delivery status asserted without POD state.",
                }
            )
        if "timing_conflict" in (s.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "shipment_timing_conflict",
                    "shipment_id": s.get("shipment_id"),
                    "note": "Actual arrival precedes actual departure.",
                }
            )

    for e in events:
        if "duplicate_source_dependency" in (e.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "duplicate_tracking_dependency",
                    "event_id": e.get("event_id"),
                    "duplicate_state": e.get("_duplicate_state"),
                    "note": "Duplicate or dependent tracking events should not be counted as independent evidence.",
                }
            )
        if "event_conflict" in (e.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "event_conflict",
                    "event_id": e.get("event_id"),
                    "note": "Conflicting event times for same shipment/event/node.",
                }
            )

    for c in customs:
        if "customs_sequence_conflict" in (c.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "customs_sequence_conflict",
                    "customs_event_id": c.get("customs_event_id"),
                    "note": "Customs release/clearance precedes entry in supplied records.",
                }
            )

    for i in inventory:
        if "negative_inventory" in (i.get("_quality_flags") or []):
            contradictions.append(
                {
                    "type": "negative_inventory",
                    "inventory_id": i.get("inventory_id"),
                    "note": "Negative inventory may be data-quality/timing issue, not automatically theft/fraud.",
                }
            )

    for cust in custody_results:
        if cust.get("custody_gap_count", 0) > 0:
            contradictions.append(
                {
                    "type": "custody_gap",
                    "shipment_id": cust.get("shipment_id"),
                    "gap_count": cust.get("custody_gap_count"),
                    "note": "Custody gap preserved; do not infer theft automatically.",
                }
            )

    # Event conflict detection: same shipment/type/node but different actual times beyond tolerance.
    groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)
    tolerance_s = float(settings.get("event_conflict_tolerance_s", 3600.0))

    for e in events:
        if e.get("_actual_time"):
            key = (e.get("_shipment_id"), e.get("_event_type"), e.get("_node_id"))
            groups[key].append(e)

    for key, items in groups.items():
        if len(items) < 2:
            continue
        times = [x["_actual_time"] for x in items]
        span = (max(times, key=dt_sort_key) - min(times, key=dt_sort_key)).total_seconds()
        if span > tolerance_s:
            for e in items:
                add_flag(e, "event_conflict")
            contradictions.append(
                {
                    "type": "event_time_conflict",
                    "shipment_id": key[0],
                    "event_type": key[1],
                    "node_id": key[2],
                    "event_ids": [e.get("event_id") for e in items],
                    "time_span_s": span,
                    "note": "Conflicting event times may reflect correction, timezone, scan latency, or source error. Preserve conflict.",
                }
            )

    return contradictions


# -----------------------------------------------------------------------------
# Facts / hypotheses / dual review
# -----------------------------------------------------------------------------

def item_confidence(item: Dict[str, Any], sources: Dict[str, Dict[str, Any]]) -> str:
    flags = set(item.get("_quality_flags") or [])
    severe = bool(flags & SEVERE_QUALITY_FLAGS)
    src_ids = item.get("_source_ids") or ([item.get("_source_id")] if item.get("_source_id") else [])
    rels = [source_reliability_label(sources.get(sid, {})) for sid in src_ids]

    if severe:
        return "LOW"
    if "HIGH" in rels:
        return "HIGH"
    if "MODERATE" in rels:
        return "MODERATE"
    if rels:
        return "LOW"
    return "UNKNOWN"


def build_facts(
    shipments: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    custody_results: List[Dict[str, Any]],
    deliveries: List[Dict[str, Any]],
    customs: List[Dict[str, Any]],
    inventory: Dict[str, Any],
    capacity: Dict[str, Any],
    delay_results: List[Dict[str, Any]],
    dependencies: Dict[str, Any],
    cold_chain: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    supported: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    partial: List[Dict[str, Any]] = []
    disputed: List[Dict[str, Any]] = []

    not_facts = [
        "Order is not shipment.",
        "Shipment dispatch is not delivery.",
        "Shipment is not payment settlement.",
        "Planned route is not actual route.",
        "ETA is not arrival.",
        "Arrival is not unloading.",
        "Port call is not cargo delivery.",
        "Carrier is not necessarily freight forwarder.",
        "Shipper is not necessarily manufacturer.",
        "Consignee is not necessarily end user.",
        "Custody is not ownership.",
        "Container is not shipment.",
        "GPS location is not cargo presence.",
        "Customs hold is not offense.",
        "Transshipment is not evasion.",
        "Route change is not suspicious activity.",
        "Custody gap is not theft.",
        "Delivery scan is not verified correct recipient.",
        "Capacity is not throughput.",
        "Delay is not negligence.",
        "Congestion is not closure.",
        "Critical node is not attack target.",
        "Single provider is not confirmed SPOF without alternatives review.",
        "Multi-carrier is not true redundancy if common bottleneck exists.",
        "Weather near route is not weather-caused delay.",
        "Earthquake proximity is not facility damage.",
        "Satellite observation is not shipment identity.",
        "Vessel movement is not specific cargo.",
        "AI agreement is not logistics corroboration.",
        "No sabotage, smuggling, evasion, interdiction, targeting, or private tracking conclusion is supported.",
    ]

    def bucket(conf: str) -> List[Dict[str, Any]]:
        if conf == "HIGH":
            return supported
        if conf == "MODERATE":
            return candidates
        return partial

    for e in events:
        conf = item_confidence(e, sources)
        bucket(conf).append(
            {
                "fact_id": f"FCT-EVT-{len(supported) + len(candidates) + len(partial) + 1}",
                "statement": (
                    f"Source(s) {', '.join(e.get('_source_ids') or ['UNKNOWN'])} reported "
                    f"{e.get('_event_type')} for shipment {e.get('_shipment_id')} "
                    f"at node {e.get('_node_id')} at {iso_or_none(e.get('_actual_time'))}."
                ),
                "event_id": e.get("event_id"),
                "confidence": conf,
                "quality_flags": e.get("_quality_flags"),
                "limitation": "Event report is not automatically cargo unload, transfer, delivery, or custody change.",
            }
        )

    for cust in custody_results:
        if cust.get("last_supported_custodian"):
            candidates.append(
                {
                    "fact_id": f"FCT-CUST-{len(candidates) + 1}",
                    "statement": (
                        f"Last supported custody event places shipment {cust.get('shipment_id')} "
                        f"with {cust.get('last_supported_custodian')} at {cust.get('last_custody_time')}."
                    ),
                    "shipment_id": cust.get("shipment_id"),
                    "confidence": "MODERATE",
                    "limitation": "Custody is operational possession, not ownership.",
                }
            )
        if cust.get("custody_gap_count", 0) > 0:
            partial.append(
                {
                    "fact_id": f"FCT-CUSTGAP-{len(partial) + 1}",
                    "statement": f"Shipment {cust.get('shipment_id')} has {cust.get('custody_gap_count')} custody gap indicator(s).",
                    "shipment_id": cust.get("shipment_id"),
                    "confidence": "LOW",
                    "limitation": "Custody gap may be missing scan, offline system, data-source gap, or manual handling.",
                }
            )

    for d in deliveries:
        conf = item_confidence(d, sources)
        bucket(conf).append(
            {
                "fact_id": f"FCT-DEL-{len(supported) + len(candidates) + len(partial) + 1}",
                "statement": (
                    f"Delivery record {d.get('delivery_id')} reports status {d.get('_status')} "
                    f"and POD state {d.get('_pod_state')} for shipment {d.get('_shipment_id')} at {iso_or_none(d.get('_time'))}."
                ),
                "delivery_id": d.get("delivery_id"),
                "confidence": conf,
                "limitation": "Delivery record may not prove intended recipient received goods.",
            }
        )

    for c in customs:
        conf = item_confidence(c, sources)
        bucket(conf).append(
            {
                "fact_id": f"FCT-CU-{len(supported) + len(candidates) + len(partial) + 1}",
                "statement": (
                    f"Customs record {c.get('customs_event_id')} reports {c.get('_event_type')} "
                    f"for shipment {c.get('_shipment_id')} at {iso_or_none(c.get('_time'))}."
                ),
                "customs_event_id": c.get("customs_event_id"),
                "confidence": conf,
                "limitation": "Customs hold/release is process state, not offense or final delivery.",
            }
        )

    for dr in delay_results:
        if dr.get("delayed"):
            candidates.append(
                {
                    "fact_id": f"FCT-DELAY-{len(candidates) + 1}",
                    "statement": (
                        f"Shipment {dr.get('shipment_id')} shows max delay "
                        f"{dr.get('max_delay_hours')} hours versus planned schedule."
                    ),
                    "shipment_id": dr.get("shipment_id"),
                    "confidence": "MODERATE",
                    "limitation": "Delay is planned-vs-actual difference, not negligence.",
                }
            )

    if inventory.get("negative_inventory_ids"):
        partial.append(
            {
                "fact_id": f"FCT-INV-{len(partial) + 1}",
                "statement": f"Negative inventory indicators present for records: {', '.join(inventory['negative_inventory_ids'][:20])}.",
                "confidence": "LOW",
                "limitation": "Negative inventory may be timing lag, system error, returns, or data-quality issue.",
            }
        )

    for cap in capacity.get("capacity_records", []):
        if cap.get("utilization_rate") is not None:
            candidates.append(
                {
                    "fact_id": f"FCT-CAP-{len(candidates) + 1}",
                    "statement": f"Capacity record {cap.get('capacity_id')} shows utilization rate {cap.get('utilization_rate')}.",
                    "capacity_id": cap.get("capacity_id"),
                    "confidence": "MODERATE" if cap.get("capacity_state") in {"OBSERVED_CAPACITY", "AVAILABLE_CAPACITY", "UTILIZED_CAPACITY"} else "LOW",
                    "limitation": "Utilization depends on supplied available/utilized values and unit consistency.",
                }
            )

    for node in dependencies.get("node_dependencies", []):
        if node.get("critical_dependency_candidate"):
            candidates.append(
                {
                    "fact_id": f"FCT-RES-{len(candidates) + 1}",
                    "statement": f"Node {node.get('node_id')} is a single-dependency candidate under supplied records.",
                    "node_id": node.get("node_id"),
                    "confidence": "LOW",
                    "limitation": "Critical dependency is resilience language, not attack targeting.",
                }
            )

    if cold_chain.get("excursion_count", 0) > 0:
        candidates.append(
            {
                "fact_id": f"FCT-COLD-{len(candidates) + 1}",
                "statement": f"Cold-chain excursion indicators present in {cold_chain.get('excursion_count')} supplied record(s).",
                "confidence": "MODERATE",
                "limitation": "Excursion does not automatically prove product spoilage or safety failure.",
            }
        )

    for c in contradictions:
        disputed.append(
            {
                "disputed_id": f"DIS-{len(disputed) + 1}",
                "type": c.get("type"),
                "statement": "Material logistics contradiction present; do not silently resolve.",
                "details": c,
            }
        )

    return supported, candidates, partial, disputed, not_facts


def build_hypotheses(
    delay_results: List[Dict[str, Any]],
    custody_results: List[Dict[str, Any]],
    dependencies: Dict[str, Any],
    disruptions: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> List[Dict[str, Any]]:
    hypotheses: List[Dict[str, Any]] = []

    for idx, dr in enumerate(delay_results, 1):
        if not dr.get("delayed"):
            continue
        sid = dr.get("shipment_id")
        base = {"hypothesis_set_id": f"HSET-DELAY-{idx}", "shipment_id": sid}

        for cause, label in [
            ("PORT_CONGESTION", "port/terminal congestion"),
            ("MISSED_CONNECTION", "missed planned connection"),
            ("STALE_TRACKING", "tracking feed latency or stale data"),
            ("REROUTE", "scheduled or operational reroute"),
            ("CUSTOMS_HOLD", "customs hold or inspection"),
            ("WEATHER", "weather impact"),
            ("CARRIER_ISSUE", "carrier capacity/equipment/labor issue"),
            ("DOCUMENTATION", "documentation issue"),
            ("UNKNOWN", "unresolved delay cause"),
        ]:
            hypotheses.append(
                {
                    **base,
                    "hypothesis_id": f"HD{idx}-{cause}",
                    "statement": f"Shipment {sid} delay may be caused by {label}.",
                    "support": [
                        f"Delay observed: {dr.get('max_delay_hours')} hours." if dr.get("max_delay_hours") is not None else "No delay metric.",
                        f"Supplied cause states: {[c.get('cause') for c in dr.get('delay_causes') or []]}" if dr.get("delay_causes") else "No supplied cause.",
                    ],
                    "opposition": ["Contradictions present." if contradictions else "No contradictions recorded."],
                    "unknowns": ["actual physical status", "custody", "carrier internal cause", "customer/shipper cause"],
                    "falsification_conditions": [
                        "Independent terminal/carrier/customs event excludes this cause.",
                        "Tracking latency is demonstrated by ingestion-time analysis.",
                        "Operational records show normal schedule adherence.",
                    ],
                    "restriction": "Delay is not negligence; cause requires evidence.",
                }
            )

    for idx, cust in enumerate(custody_results, 1):
        if cust.get("custody_gap_count", 0) == 0:
            continue
        sid = cust.get("shipment_id")
        base = {"hypothesis_set_id": f"HSET-CUST-{idx}", "shipment_id": sid}

        for cause, label in [
            ("MISSING_SCAN", "missing scan or manual handling"),
            ("OFFLINE_SYSTEM", "offline carrier/warehouse system"),
            ("DATA_SOURCE_GAP", "data-source coverage gap"),
            ("CUSTODY_TRANSFER_UNRECORDED", "unrecorded custody transfer"),
            ("POSSIBLE_LOSS", "possible loss or exception requiring investigation"),
        ]:
            hypotheses.append(
                {
                    **base,
                    "hypothesis_id": f"HC{idx}-{cause}",
                    "statement": f"Custody gap for shipment {sid} may reflect {label}.",
                    "support": [f"Gap count: {cust.get('custody_gap_count')}."],
                    "opposition": ["Independent scans confirm continuous custody." if not contradictions else "Contradictions present."],
                    "unknowns": ["physical location", "custodian", "cargo integrity"],
                    "falsification_conditions": [
                        "Independent carrier/warehouse/customs scan fills gap.",
                        "System logs show scan omission rather than physical exception.",
                    ],
                    "restriction": "Custody gap is not automatically theft, loss, or fraud.",
                }
            )

    for idx, node in enumerate(dependencies.get("node_dependencies", []), 1):
        if not node.get("critical_dependency_candidate"):
            continue
        hypotheses.append(
            {
                "hypothesis_set_id": f"HSET-RES-{idx}",
                "hypothesis_id": f"HR{idx}-SINGLE_NODE_DEPENDENCY",
                "statement": f"Node {node.get('node_id')} may be a single-node dependency under supplied records.",
                "support": [f"Load count {node.get('load_count')}; alternatives {node.get('alternative_node_ids') or 'none supplied'}."],
                "opposition": ["Unlisted fallback capacity may exist.", "Documented alternatives may be untested."],
                "falsification_conditions": ["Authorized BCP records show tested alternate node/carrier/route."],
                "restriction": "Critical dependency is for resilience only, never attack targeting.",
            }
        )
        hypotheses.append(
            {
                "hypothesis_set_id": f"HSET-RES-{idx}",
                "hypothesis_id": f"HR{idx}-ALTERNATIVES_EXIST",
                "statement": f"Node {node.get('node_id')} may have unlisted or untested alternatives.",
                "support": ["Supplied records may be incomplete."],
                "opposition": ["No alternative supplied in current records." if not node.get("alternative_node_ids") else "Alternatives supplied."],
                "falsification_conditions": ["Independent operational records confirm no viable alternative."],
            }
        )

    for idx, d in enumerate(disruptions, 1):
        hypotheses.append(
            {
                "hypothesis_set_id": f"HSET-DISR-{idx}",
                "hypothesis_id": f"HDISR{idx}-DIRECT_IMPACT",
                "statement": f"Disruption {d.get('disruption_id')} directly impacted supplied logistics records.",
                "support": [f"Impact state {d.get('_impact_state')}."],
                "opposition": ["Only proximity or timing overlap recorded." if d.get("_impact_state") in {"POTENTIAL_IMPACT", "UNKNOWN"} else "No opposition recorded."],
                "falsification_conditions": ["Independent operational records show unaffected route/node/shipment."],
            }
        )
        hypotheses.append(
            {
                "hypothesis_set_id": f"HSET-DISR-{idx}",
                "hypothesis_id": f"HDISR{idx}-NO_CONFIRMED_IMPACT",
                "statement": f"Disruption {d.get('disruption_id')} may have no confirmed logistics impact.",
                "support": ["Impact state may be potential or unknown."],
                "opposition": ["Direct shipment/node evidence present." if d.get("_impact_state") in {"DIRECT_IMPACT_SUPPORTED", "MAJOR_IMPACT_SUPPORTED"} else "No direct evidence recorded."],
                "falsification_conditions": ["Carrier/port/warehouse operational records confirm impact."],
            }
        )

    if issues:
        hypotheses.append(
            {
                "hypothesis_set_id": "HSET-GLOBAL",
                "hypothesis_id": "H-GLOBAL-VALIDATION-WEAKNESS",
                "statement": "Validation issues materially weaken all logistics interpretations.",
                "support": issues[:10],
                "opposition": ["No independent clean source supplied yet."],
                "falsification_conditions": ["Resolve validation issues and rerun deterministic ingestion."],
            }
        )

    return hypotheses


def dual_ai_review(
    shipments: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    custody_results: List[Dict[str, Any]],
    delay_results: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
) -> Dict[str, Any]:
    primary = {
        "role": "Primary Logistics Analyst",
        "assessment": (
            "Shipment, event, custody, and/or delay records exist."
            if shipments or events or custody_results or delay_results
            else "No usable logistics records were supplied."
        ),
        "classification": "Route, custody, delivery, cause, and resilience conclusions remain conservative and evidence-bounded.",
    }

    if not shipments and not events:
        skeptic = {
            "role": "Independent Logistics Skeptic",
            "verdict": "INSUFFICIENT_EVIDENCE",
            "reason": "No deterministic logistics records were supplied. Do not infer shipments, routes, delivery, or disruption from narrative.",
        }
    elif issues:
        skeptic = {
            "role": "Independent Logistics Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Validation issues require downgraded confidence.",
        }
    elif contradictions:
        skeptic = {
            "role": "Independent Logistics Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Contradictions must be preserved; do not silently resolve event/custody/delivery/source conflicts.",
        }
    elif events and any(e.get("_actual_time") for e in events):
        skeptic = {
            "role": "Independent Logistics Skeptic",
            "verdict": "AGREE_ON_REPORTED_EVENTS_ONLY",
            "reason": "Source-reported events may support logistics chronology only, not cargo unload, delivery, ownership, intent, or harmful targeting.",
        }
    else:
        skeptic = {
            "role": "Independent Logistics Skeptic",
            "verdict": "PARTIAL_AGREEMENT",
            "reason": "Planned or incomplete records support candidate logistics context only.",
        }

    return {
        "primary": primary,
        "skeptic": skeptic,
        "comparison": skeptic.get("verdict", "INSUFFICIENT_EVIDENCE"),
        "note": "Rule-based dual-review scaffold. AI agreement is not independent logistics corroboration. Humans govern consequential logistics actions.",
    }


# -----------------------------------------------------------------------------
# Graphical memory scaffold
# -----------------------------------------------------------------------------

def build_graph(
    sources: Dict[str, Dict[str, Any]],
    parties: Dict[str, Dict[str, Any]],
    orders: Dict[str, Dict[str, Any]],
    cargo: Dict[str, Dict[str, Any]],
    containers: Dict[str, Dict[str, Any]],
    carriers: Dict[str, Dict[str, Any]],
    forwarders: Dict[str, Dict[str, Any]],
    third: Dict[str, Dict[str, Any]],
    nodes: Dict[str, Dict[str, Any]],
    shipments: List[Dict[str, Any]],
    routes: List[Dict[str, Any]],
    legs: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    custody: List[Dict[str, Any]],
    deliveries: List[Dict[str, Any]],
    customs: List[Dict[str, Any]],
    inventory: List[Dict[str, Any]],
    movements: List[Dict[str, Any]],
    capacity: List[Dict[str, Any]],
    disruptions: List[Dict[str, Any]],
    cold_chain: List[Dict[str, Any]],
    facts: List[Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes_out: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    def add_node(node_id: str, node_type: str, props: Dict[str, Any]) -> None:
        if not node_id:
            return
        if any(n.get("id") == node_id for n in nodes_out):
            return
        nodes_out.append({"id": node_id, "type": node_type, "properties": props})

    def add_edge(src: str, dst: str, rel: str, props: Dict[str, Any]) -> None:
        if not src or not dst:
            return
        edges.append({"from": src, "to": dst, "type": rel, "properties": props})

    for sid, s in sources.items():
        add_node(sid, "Source", public_dict(s))

    for pid, p in parties.items():
        add_node(pid, "Party", public_dict(p))

    for oid, o in orders.items():
        add_node(oid, "Order", public_dict(o))

    for cid, c in cargo.items():
        add_node(cid, "Cargo", public_dict(c))

    for cid, c in containers.items():
        add_node(cid, "Container", public_dict(c))

    for aid, a in carriers.items():
        add_node(aid, "Carrier", public_dict(a))

    for aid, a in forwarders.items():
        add_node(aid, "FreightForwarder", public_dict(a))

    for aid, a in third.items():
        add_node(aid, "ThreePL" if a.get("_role") == "3PL" else "FourPL", public_dict(a))

    for nid, n in nodes.items():
        add_node(nid, n.get("_node_type").title() if n.get("_node_type") else "Node", public_dict(n))

    for s in shipments:
        sid = s.get("shipment_id")
        add_node(sid, "Shipment", public_dict(s))
        if s.get("_order_reference"):
            add_edge(sid, s["_order_reference"], "FULFILLS_ORDER", {"shipment_id": sid})
        for cid in s.get("_cargo_ids") or []:
            add_edge(sid, cid, "CONTAINS_CARGO", {"shipment_id": sid})
        for cont in s.get("_container_ids") or []:
            add_edge(sid, cont, "USES_CONTAINER", {"shipment_id": sid})
        if s.get("_carrier"):
            add_edge(sid, s["_carrier"], "CARRIED_BY", {"shipment_id": sid})
        if s.get("_forwarder"):
            add_edge(sid, s["_forwarder"], "FORWARDED_BY", {"shipment_id": sid})
        if s.get("_origin_node"):
            add_edge(sid, s["_origin_node"], "DEPARTED_FROM_CANDIDATE", {"shipment_id": sid})
        if s.get("_destination_node"):
            add_edge(sid, s["_destination_node"], "ARRIVED_AT_CANDIDATE", {"shipment_id": sid})

    for r in routes:
        rid = r.get("route_id")
        add_node(rid, "Route", public_dict(r))
        if r.get("_shipment_id"):
            add_edge(rid, r["_shipment_id"], "PART_OF_ROUTE", {"route_id": rid})
        for lid in r.get("_leg_ids") or []:
            add_edge(rid, lid, "NEXT_LEG", {"route_id": rid})

    for l in legs:
        lid = l.get("leg_id")
        add_node(lid, "TransportLeg", public_dict(l))
        if l.get("_shipment_id"):
            add_edge(lid, l["_shipment_id"], "PART_OF_ROUTE", {"leg_id": lid})
        if l.get("_origin_node"):
            add_edge(lid, l["_origin_node"], "DEPARTED_FROM", {"leg_id": lid})
        if l.get("_destination_node"):
            add_edge(lid, l["_destination_node"], "ARRIVED_AT", {"leg_id": lid})
        if l.get("_carrier"):
            add_edge(lid, l["_carrier"], "CARRIED_BY", {"leg_id": lid})

    for e in events:
        eid = e.get("event_id")
        add_node(eid, "ShipmentEvent", public_dict(e))
        if e.get("_shipment_id"):
            add_edge(eid, e["_shipment_id"], "SUPPORTED_BY", {"event_id": eid})
        if e.get("_node_id"):
            add_edge(eid, e["_node_id"], "ARRIVED_AT" if e.get("_event_type") in {"ARRIVED", "GATE_IN", "WAREHOUSE_RECEIPT"} else "TRANSITED_VIA", {"event_id": eid})
        for sid in e.get("_source_ids") or []:
            add_edge(eid, sid, "SUPPORTED_BY", {"event_id": eid})

    for c in custody:
        cid = c.get("custody_id")
        add_node(cid, "CustodyEvent", public_dict(c))
        if c.get("_shipment_id"):
            add_edge(cid, c["_shipment_id"], "IN_CUSTODY_OF", {"custody_id": cid})
        if c.get("_to_custodian"):
            add_edge(cid, c["_to_custodian"], "HANDOFF_TO", {"custody_id": cid})

    for d in deliveries:
        did = d.get("delivery_id")
        add_node(did, "Delivery", public_dict(d))
        if d.get("_shipment_id"):
            add_edge(did, d["_shipment_id"], "DELIVERED_TO", {"delivery_id": did})

    for c in customs:
        cid = c.get("customs_event_id")
        add_node(cid, "CustomsEvent", public_dict(c))
        if c.get("_shipment_id"):
            add_edge(cid, c["_shipment_id"], "CUSTOMS_PROCESSED_AT", {"customs_event_id": cid})

    for i in inventory:
        iid = i.get("inventory_id")
        add_node(iid, "InventorySnapshot", public_dict(i))
        if i.get("_location_id"):
            add_edge(iid, i["_location_id"], "STORED_AT", {"inventory_id": iid})

    for m in movements:
        mid = m.get("movement_id")
        add_node(mid, "InventoryMovement", public_dict(m))
        if m.get("_from_location"):
            add_edge(mid, m["_from_location"], "TRANSFERRED_FROM", {"movement_id": mid})
        if m.get("_to_location"):
            add_edge(mid, m["_to_location"], "TRANSFERRED_TO", {"movement_id": mid})

    for c in capacity:
        cid = c.get("capacity_id")
        add_node(cid, "CapacityRecord", public_dict(c))
        if c.get("_node_id"):
            add_edge(cid, c["_node_id"], "CAPACITY_CONTEXT", {"capacity_id": cid})

    for d in disruptions:
        did = d.get("disruption_id")
        add_node(did, "Disruption", public_dict(d))
        if d.get("_node_id"):
            add_edge(did, d["_node_id"], "IMPACTED_BY", {"disruption_id": did})
        if d.get("_route_id"):
            add_edge(did, d["_route_id"], "IMPACTED_BY", {"disruption_id": did})

    for c in cold_chain:
        cid = c.get("record_id")
        add_node(cid, "ColdChainRecord", public_dict(c))
        if c.get("_shipment_id"):
            add_edge(cid, c["_shipment_id"], "IMPACTED_BY", {"record_id": cid})

    for fac in facts:
        fid = fac.get("fact_id")
        add_node(fid, "Fact", fac)
        for key in ("event_id", "shipment_id", "delivery_id", "customs_event_id", "capacity_id", "node_id"):
            if fac.get(key):
                add_edge(fid, fac[key], "SUPPORTED_BY", {"fact_id": fid})

    for h in hypotheses:
        add_node(h.get("hypothesis_id"), "Hypothesis", h)

    for c in contradictions:
        cid = f"CONTRA-{len([x for x in nodes_out if x.get('type') == 'Contradiction']) + 1}"
        add_node(cid, "Contradiction", c)

    for g in gaps:
        gid = g.get("gap_id") or f"GAP-{len(gaps)}"
        add_node(gid, "Gap", g)

    return {"nodes": nodes_out, "edges": edges, "version": VERSION}


# -----------------------------------------------------------------------------
# Gaps / actions / handoffs / summary
# -----------------------------------------------------------------------------

def build_knowledge_gaps(
    shipments: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    custody_results: List[Dict[str, Any]],
    deliveries: List[Dict[str, Any]],
    inventory: Dict[str, Any],
    capacity: Dict[str, Any],
    dependencies: Dict[str, Any],
    contradictions: List[Dict[str, Any]],
    issues: List[str],
    sources: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not shipments:
        gaps.append(
            {
                "gap_id": "GAP-NO-SHIPMENTS",
                "gap": "No shipments supplied",
                "importance": "HIGH",
                "recommended_source": "Authorized TMS/ERP/carrier/forwarder shipment export",
                "expected_information_value": "Establishes logistics objects for analysis",
            }
        )

    if not events:
        gaps.append(
            {
                "gap_id": "GAP-NO-EVENTS",
                "gap": "No shipment/tracking/EDI events supplied",
                "importance": "HIGH",
                "recommended_source": "Carrier API, terminal scan, warehouse event, customs event",
                "expected_information_value": "Separates planned from actual movement",
            }
        )

    if any(c.get("custody_gap_count", 0) > 0 for c in custody_results):
        gaps.append(
            {
                "gap_id": "GAP-CUSTODY",
                "gap": "Custody-chain gaps present",
                "importance": "HIGH",
                "recommended_source": "Independent carrier/warehouse/customs scan records",
                "expected_information_value": "Distinguishes missing scan from physical exception",
            }
        )

    if not deliveries:
        gaps.append(
            {
                "gap_id": "GAP-DELIVERY-UNVERIFIED",
                "gap": "No delivery/POD records supplied",
                "importance": "HIGH",
                "recommended_source": "Proof-of-delivery, signature, scan, geofence, recipient confirmation",
                "expected_information_value": "Verifies delivery without overattributing recipient",
            }
        )

    if not inventory.get("latest_snapshots"):
        gaps.append(
            {
                "gap_id": "GAP-INVENTORY-UNKNOWN",
                "gap": "Inventory snapshots unavailable",
                "importance": "MODERATE",
                "recommended_source": "Authorized WMS/ERP inventory snapshot with as-of time",
                "expected_information_value": "Supports stock positioning and stockout context",
            }
        )

    if not capacity.get("capacity_records"):
        gaps.append(
            {
                "gap_id": "GAP-CAPACITY-UNKNOWN",
                "gap": "Capacity/throughput records unavailable",
                "importance": "MODERATE",
                "recommended_source": "Authorized warehouse/terminal capacity records",
                "expected_information_value": "Supports resilience and bottleneck assessment",
            }
        )

    if any(n.get("critical_dependency_candidate") for n in dependencies.get("node_dependencies", [])):
        gaps.append(
            {
                "gap_id": "GAP-SINGLE-NODE-DEPENDENCY",
                "gap": "Single-node dependency candidate present",
                "importance": "HIGH",
                "recommended_source": "BCP/DR records, tested alternate nodes, carrier contracts",
                "expected_information_value": "Distinguishes candidate dependency from confirmed SPOF",
            }
        )

    if contradictions:
        gaps.append(
            {
                "gap_id": "GAP-CONTRADICTIONS",
                "gap": "Material logistics contradictions present",
                "importance": "HIGH",
                "recommended_source": "Raw carrier/warehouse/customs records, event ingestion logs, source pedigree",
                "expected_information_value": "Prevents silent false resolution",
            }
        )

    if issues:
        gaps.append(
            {
                "gap_id": "GAP-VALIDATION-ISSUES",
                "gap": "Input validation issues present",
                "importance": "HIGH",
                "recommended_source": "Corrected shipment/event/timezone/unit/source metadata",
                "expected_information_value": "Improves logistics measurement trust",
            }
        )

    if summarize_source_independence(sorted(sources.keys()), sources) != "INDEPENDENT" and len(sources) > 1:
        gaps.append(
            {
                "gap_id": "GAP-SOURCE-DEPENDENCY",
                "gap": "Source independence unresolved or dependent",
                "importance": "MODERATE",
                "recommended_source": "Upstream carrier/TMS/WMS/port/customs pedigree",
                "expected_information_value": "Prevents counting duplicate feeds as independent evidence",
            }
        )

    return gaps


def build_next_actions(
    shipments: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    custody_results: List[Dict[str, Any]],
    deliveries: List[Dict[str, Any]],
    delay_results: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[str]:
    actions: List[str] = []

    if not shipments:
        actions.append("Supply deterministic authorized shipment records with IDs, times, nodes, carriers, and source pedigree")

    if not events:
        actions.append("Supply carrier/terminal/warehouse/customs events with planned, estimated, actual, reported, and ingestion times")

    if any(c.get("custody_gap_count", 0) > 0 for c in custody_results):
        actions.append("Obtain independent scan/custody records before interpreting custody gaps")

    if not deliveries:
        actions.append("Obtain proof-of-delivery or destination receipt records before closing logistics chain")

    if any(d.get("delayed") for d in delay_results):
        actions.append("Compare planned vs actual events and request carrier/terminal/customs status updates for delayed shipments")

    if any(g["gap_id"] == "GAP-SINGLE-NODE-DEPENDENCY" for g in gaps):
        actions.append("Review documented BCP/DR alternates and testability before declaring confirmed SPOF")

    if contradictions:
        actions.append("Preserve contradictions and inspect raw source latency, duplicate feeds, timezone, and event corrections before resolution")

    actions.append("Recommend human review for consequential reroute, cancellation, cargo release, consignee change, or customs actions")
    actions.append("Maintain lawful boundary: no sabotage, smuggling, customs evasion, interdiction, targeting, cargo theft, or private-person tracking")

    return actions


def build_specialist_handoffs(
    shipments: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    customs: List[Dict[str, Any]],
    inventory: Dict[str, Any],
    dependencies: Dict[str, Any],
    disruptions: List[Dict[str, Any]],
    cold_chain: Dict[str, Any],
) -> List[Dict[str, Any]]:
    handoffs: List[Dict[str, Any]] = []

    if customs:
        handoffs.append(
            {
                "to": "TRADEINT / LEGALINT",
                "reason": "Customs classification, trade controls, legal status, and compliance conclusions exceed logistics movement analysis",
                "restrictions": ["Customs hold is not offense", "No evasion guidance"],
            }
        )

    if inventory.get("latest_snapshots") or dependencies.get("node_dependencies"):
        handoffs.append(
            {
                "to": "SUPPLYCHAININT",
                "reason": "Supplier concentration, nth-party risk, and vendor resilience require supply-chain intelligence",
                "restrictions": ["No attack targeting", "No harmful exploitation"],
            }
        )

    if any(e.get("_event_type") in {"ARRIVED", "DEPARTED"} and e.get("_carrier") for e in events):
        handoffs.append(
            {
                "to": "TRANSPORTINT / AISINT / aviation worker as appropriate",
                "reason": "Vehicle/vessel/aircraft movement and transport-asset identity exceed cargo logistics records",
                "restrictions": ["Vessel movement is not specific cargo", "No interdiction or targeting"],
            }
        )

    if disruptions:
        handoffs.append(
            {
                "to": "ENVINT / WEATHERINT / SEISINT / SATINT as appropriate",
                "reason": "Environmental, weather, seismic, and satellite impact interpretation requires specialists",
                "restrictions": ["Proximity is not causation", "Satellite observation is not shipment identity"],
            }
        )

    if cold_chain.get("excursion_count", 0) > 0:
        handoffs.append(
            {
                "to": "QUALITY / REGULATORY / PRODUCT SPECIALIST",
                "reason": "Cold-chain excursion product-safety determination requires applicable specialist and regulatory evidence",
                "restrictions": ["Excursion is not automatic spoilage or safety failure"],
            }
        )

    if any("privacy_private_delivery_redacted" in (s.get("_quality_flags") or []) for s in shipments):
        handoffs.append(
            {
                "to": "PRIVACY / LEGAL / ORGINT",
                "reason": "Private delivery location handling requires authorization and minimization review",
                "restrictions": ["No private-person tracking", "No stalking"],
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

    shipments = r.get("shipments") or []
    events = r.get("shipment_events") or []
    delays = r.get("delay_analysis") or []
    custody = r.get("custody_analysis") or []
    deliveries = r.get("deliveries") or []
    dependencies = r.get("resilience_context") or {}
    contradictions = r.get("contradictions") or []

    lines = [
        "SHIPMENT: count=" + str(len(shipments)),
        "CARGO: " + fmt_list(sorted({cid for s in shipments for cid in (s.get('cargo_ids') or [])})),
        "ORIGIN: " + fmt_list(sorted({s.get('origin_node') for s in shipments if s.get('origin_node')})),
        "DESTINATION: " + fmt_list(sorted({s.get('destination_node') for s in shipments if s.get('destination_node')})),
        "CARRIER: " + fmt_list(sorted({s.get('carrier') for s in shipments if s.get('carrier')})),
        "FORWARDER: " + fmt_list(sorted({s.get('forwarder') for s in shipments if s.get('forwarder')})),
        "TRANSPORT MODES: " + fmt_list(sorted({m for s in shipments for m in (s.get('transport_modes') or [])})),
        "CONTAINERS: " + fmt_list(sorted({c for s in shipments for c in (s.get('container_ids') or [])})),
        "PLANNED ROUTE: " + fmt_list([f"{rt.get('route_id')}:{rt.get('confidence')}" for rt in (r.get('routes') or []) if rt.get('planned_path')]),
        "OBSERVED ROUTE: " + fmt_list([f"{rt.get('route_id')}:{rt.get('confidence')}" for rt in (r.get('routes') or []) if rt.get('observed_path')]),
        "INFERRED ROUTE: " + fmt_list([f"{rt.get('route_id')}:{rt.get('confidence')}" for rt in (r.get('routes') or []) if rt.get('confidence') == 'INFERRED']),
        "DEPARTURE: " + fmt_list([f"{d.get('shipment_id')} actual={d.get('actual_departure')}" for d in delays[:10]]),
        "ARRIVAL: " + fmt_list([f"{d.get('shipment_id')} actual={d.get('actual_arrival')}" for d in delays[:10]]),
        "CUSTOMS STATUS: " + fmt_list([f"{c.get('customs_event_id')}:{c.get('event_type')}:{c.get('status')}" for c in (r.get('customs_context') or [])[:10]]),
        "CUSTODY CHAIN: gaps=" + str(sum(c.get('custody_gap_count', 0) for c in custody)),
        "DELIVERY STATUS: " + fmt_list([f"{d.get('shipment_id')}={d.get('status')}/{d.get('pod_state')}" for d in deliveries[:10]]),
        "PROOF OF DELIVERY: " + fmt_list([f"{d.get('delivery_id')}={d.get('pod_state')}" for d in deliveries[:10]]),
        "WAREHOUSE / HUBS: " + fmt_list(sorted({n.get('node_id') for n in (r.get('nodes') or {}).values() if n.get('node_type') in {'WAREHOUSE','DISTRIBUTION_CENTER','PORT','TERMINAL','AIRPORT','RAIL_HUB'}})),
        "INVENTORY CONTEXT: snapshots=" + str((r.get('inventory_context') or {}).get('snapshot_count', 0)),
        "CAPACITY: records=" + str(len((r.get('capacity_context') or {}).get('capacity_records', []))),
        "LEAD TIME: " + json.dumps((r.get('lead_time_analysis') or {}).get('lead_time_summary', {}), default=str),
        "DWELL TIME: " + json.dumps((r.get('lead_time_analysis') or {}).get('dwell_time_summary', {}), default=str),
        "DELAYS: " + fmt_list([f"{d.get('shipment_id')}={d.get('max_delay_hours')}h" for d in delays if d.get('delayed')][:10]),
        "CONGESTION: " + fmt_list([f"{d.get('disruption_id')}:{d.get('type')}" for d in (r.get('disruptions') or []) if 'CONGESTION' in str(d.get('type')).upper()]),
        "COLD CHAIN: excursions=" + str((r.get('cold_chain_context') or {}).get('excursion_count', 0)),
        "DISRUPTIONS: " + str(len(r.get('disruptions') or [])),
        "NODE DEPENDENCIES: " + fmt_list([f"{n.get('node_id')}={n.get('resilience_state')}" for n in dependencies.get('node_dependencies', [])[:10]]),
        "CARRIER DEPENDENCY: " + fmt_list([f"{c.get('carrier_id')}={c.get('resilience_state')}" for c in dependencies.get('carrier_dependencies', [])[:10]]),
        "ALTERNATIVES: supplied only; no route generation",
        "RESILIENCE: " + fmt_list([n.get('resilience_state') for n in dependencies.get('node_dependencies', [])]),
        "SOURCE RELIABILITY: " + fmt_list([f"{s.get('source_id')}={s.get('reliability')}" for s in (r.get('source_reliability') or [])]),
        "SOURCE INDEPENDENCE: " + str(r.get('source_independence')),
        "CONTRADICTIONS: " + str(len(contradictions)),
        "UNKNOWN: " + fmt_list(r.get('unknowns')),
        "NEXT ACTION: " + ((r.get('recommended_next_actions') or ['NONE'])[0]),
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
    scope = case.get("scope") if isinstance(case.get("scope"), dict) else {}

    def setting_float(name: str, default: float) -> float:
        try:
            return float(settings_raw.get(name, default))
        except Exception:
            return default

    settings: Dict[str, Any] = {
        "sensitive_exact_authorized": scope.get("sensitive_location_exact_authorized") is True,
        "custody_gap_threshold_s": setting_float("custody_gap_threshold_s", 86400.0),
        "delay_threshold_hours": setting_float("delay_threshold_hours", 1.0),
        "on_time_window_hours": setting_float("on_time_window_hours", 0.0),
        "event_conflict_tolerance_s": setting_float("event_conflict_tolerance_s", 3600.0),
    }

    now = parse_dt(case.get("knowledge_time")) or datetime.now(timezone.utc)

    sources, src_issues = validate_sources(case)
    parties, party_issues = validate_parties(case, settings)
    orders, order_issues = validate_orders(case)
    cargo, cargo_issues = validate_cargo(case)
    containers, cont_issues = validate_containers(case)
    carriers, carrier_issues = validate_actor_records(case, ("carriers",), "CAR", "CARRIER")
    forwarders, fwd_issues = validate_actor_records(case, ("freight_forwarders", "forwarders"), "FWD", "FORWARDER")
    third, third_issues = validate_actor_records(case, ("three_pls", "four_pls", "logistics_providers"), "3P4P", "3PL/4PL")
    nodes, node_issues = validate_nodes(case, settings, now)
    shipments, ship_issues = validate_shipments(case, settings)
    routes, route_issues = validate_routes(case, nodes)
    legs, leg_issues = validate_legs(case, nodes)
    events, event_issues = validate_events(case, nodes)
    deduplicate_events(events, sources, settings)
    custody, custody_issues = validate_custody(case, nodes)
    inventory_records, inv_issues = validate_inventory(case, nodes)
    movements, mov_issues = validate_inventory_movements(case, nodes)
    capacity_records, cap_issues = validate_capacity(case)
    deliveries, del_issues = validate_deliveries(case, nodes, settings)
    customs, cu_issues = validate_customs(case, nodes)
    disruptions, dis_issues = validate_disruptions(case, nodes, routes)
    cold_chain_records, cold_issues = validate_cold_chain(case)

    issues = (
        src_issues
        + party_issues
        + order_issues
        + cargo_issues
        + cont_issues
        + carrier_issues
        + fwd_issues
        + third_issues
        + node_issues
        + ship_issues
        + route_issues
        + leg_issues
        + event_issues
        + custody_issues
        + inv_issues
        + mov_issues
        + cap_issues
        + del_issues
        + cu_issues
        + dis_issues
        + cold_issues
    )

    warnings = check_references(
        shipments,
        orders,
        cargo,
        containers,
        carriers,
        forwarders,
        nodes,
        legs,
        events,
        custody,
        deliveries,
        customs,
        disruptions,
    )

    analyze_route_confidence(routes, legs, events)
    custody_results = analyze_custody(custody, shipments, settings)
    delay_results = analyze_delays(
        shipments,
        events,
        legs,
        disruptions,
        case.get("weather_context") or {},
        settings,
    )
    lead_dwell = analyze_lead_and_dwell_times(shipments, legs, events, orders)
    inventory_context = analyze_inventory(inventory_records, movements)
    capacity_context = analyze_capacity(capacity_records)
    service_levels = analyze_service_levels(shipments, deliveries, orders, delay_results, settings)
    cold_chain_context = analyze_cold_chain(cold_chain_records)
    dependencies = analyze_dependencies_and_resilience(shipments, legs, events, nodes, carriers, routes)

    contradictions = detect_contradictions(
        shipments,
        events,
        custody_results,
        deliveries,
        customs,
        inventory_records,
        routes,
        delay_results,
        list(case.get("existing_contradictions") or []),
        settings,
    )

    supported_facts, candidate_facts, partial_facts, disputed_facts, not_facts = build_facts(
        shipments,
        events,
        custody_results,
        deliveries,
        customs,
        inventory_context,
        capacity_context,
        delay_results,
        dependencies,
        cold_chain_context,
        contradictions,
        sources,
    )

    hypotheses = build_hypotheses(
        delay_results,
        custody_results,
        dependencies,
        disruptions,
        contradictions,
        issues,
    )

    dual = dual_ai_review(
        shipments,
        events,
        custody_results,
        delay_results,
        contradictions,
        issues,
    )

    gaps = build_knowledge_gaps(
        shipments,
        events,
        custody_results,
        deliveries,
        inventory_context,
        capacity_context,
        dependencies,
        contradictions,
        issues,
        sources,
    )

    next_actions = build_next_actions(
        shipments,
        events,
        custody_results,
        deliveries,
        delay_results,
        gaps,
        contradictions,
    )

    handoffs = build_specialist_handoffs(
        shipments,
        events,
        customs,
        inventory_context,
        dependencies,
        disruptions,
        cold_chain_context,
    )

    graph = build_graph(
        sources,
        parties,
        orders,
        cargo,
        containers,
        carriers,
        forwarders,
        third,
        nodes,
        shipments,
        routes,
        legs,
        events,
        custody,
        deliveries,
        customs,
        inventory_records,
        movements,
        capacity_records,
        disruptions,
        cold_chain_records,
        supported_facts + candidate_facts + partial_facts,
        hypotheses,
        contradictions,
        gaps,
    )

    # Public objects
    shipment_public = [
        {
            "shipment_id": s.get("shipment_id"),
            "status": s.get("_status"),
            "order_reference": s.get("_order_reference"),
            "cargo_ids": s.get("_cargo_ids"),
            "container_ids": s.get("_container_ids"),
            "shipper": s.get("_shipper"),
            "consignee": s.get("_consignee"),
            "carrier": s.get("_carrier"),
            "forwarder": s.get("_forwarder"),
            "origin_node": s.get("_origin_node"),
            "destination_node": s.get("_destination_node"),
            "transport_modes": s.get("_modes"),
            "planned_departure": iso_or_none(s.get("_planned_departure")),
            "actual_departure": iso_or_none(s.get("_actual_departure")),
            "planned_arrival": iso_or_none(s.get("_planned_arrival")),
            "actual_arrival": iso_or_none(s.get("_actual_arrival")),
            "delivery_status": s.get("_delivery_status"),
            "pod_state": s.get("_pod_state"),
            "quality_flags": s.get("_quality_flags"),
            "source_ids": s.get("_source_ids"),
            "evidence_ids": s.get("_evidence_ids"),
            "limitations": [
                "Shipment is not order, delivery, payment, or ownership.",
                "Planned times are not actual times.",
            ],
        }
        for s in shipments
    ]

    event_public = [
        {
            "event_id": e.get("event_id"),
            "shipment_id": e.get("_shipment_id"),
            "event_type": e.get("_event_type"),
            "node_id": e.get("_node_id"),
            "carrier": e.get("_carrier"),
            "container_id": e.get("_container_id"),
            "planned_time": iso_or_none(e.get("_planned_time")),
            "estimated_time": iso_or_none(e.get("_estimated_time")),
            "actual_time": iso_or_none(e.get("_actual_time")),
            "reported_time": iso_or_none(e.get("_reported_time")),
            "ingestion_time": iso_or_none(e.get("_ingestion_time")),
            "duplicate_group_id": e.get("_duplicate_group_id"),
            "duplicate_state": e.get("_duplicate_state"),
            "quality_flags": e.get("_quality_flags"),
            "source_ids": e.get("_source_ids"),
            "evidence_ids": e.get("_evidence_ids"),
            "confidence": item_confidence(e, sources),
            "limitations": [
                "Event report is not cargo unload, transfer, delivery, or custody change without evidence.",
                "Duplicate/dependent feeds are not independent evidence.",
            ],
        }
        for e in events
    ]

    route_public = [
        {
            "route_id": r.get("route_id"),
            "shipment_id": r.get("_shipment_id"),
            "origin": r.get("_origin"),
            "destination": r.get("_destination"),
            "leg_ids": r.get("_leg_ids"),
            "planned_path": r.get("_planned_path"),
            "observed_path": r.get("_observed_path"),
            "confidence": r.get("_confidence"),
            "distance_m": r.get("_distance_m"),
            "duration_s": r.get("_duration_s"),
            "alternative_route_ids": r.get("_alternative_routes"),
            "quality_flags": r.get("_quality_flags"),
            "limitations": [
                "Planned route is not actual route.",
                "Inferred route is not observed route.",
                "No route generation or evasion optimization is performed.",
            ],
        }
        for r in routes
    ]

    leg_public = [
        {
            "leg_id": l.get("leg_id"),
            "shipment_id": l.get("_shipment_id"),
            "route_id": l.get("_route_id"),
            "mode": l.get("_mode"),
            "carrier": l.get("_carrier"),
            "origin_node": l.get("_origin_node"),
            "destination_node": l.get("_destination_node"),
            "asset_reference": l.get("_asset_reference"),
            "planned_start": iso_or_none(l.get("_planned_start")),
            "actual_start": iso_or_none(l.get("_actual_start")),
            "planned_end": iso_or_none(l.get("_planned_end")),
            "actual_end": iso_or_none(l.get("_actual_end")),
            "planned_duration_s": l.get("_planned_duration_s"),
            "actual_duration_s": l.get("_actual_duration_s"),
            "quality_flags": l.get("_quality_flags"),
            "source_ids": l.get("_source_ids"),
            "evidence_ids": l.get("_evidence_ids"),
            "limitations": ["A leg record may represent only one segment, not the full shipment route."],
        }
        for l in legs
    ]

    custody_public = [
        {
            "custody_id": c.get("custody_id"),
            "shipment_id": c.get("_shipment_id"),
            "from_custodian": c.get("_from_custodian"),
            "to_custodian": c.get("_to_custodian"),
            "from_role": c.get("_from_role"),
            "to_role": c.get("_to_role"),
            "node_id": c.get("_node_id"),
            "time": iso_or_none(c.get("_time")),
            "quality_flags": c.get("_quality_flags"),
            "source_ids": c.get("_source_ids"),
            "evidence_ids": c.get("_evidence_ids"),
            "limitations": ["Custody is operational possession, not ownership."],
        }
        for c in custody
    ]

    delivery_public = [
        {
            "delivery_id": d.get("delivery_id"),
            "shipment_id": d.get("_shipment_id"),
            "status": d.get("_status"),
            "pod_state": d.get("_pod_state"),
            "time": iso_or_none(d.get("_time")),
            "node_id": d.get("_node_id"),
            "recipient_role": d.get("_recipient_role"),
            "pod_type": d.get("_pod_type"),
            "quality_flags": d.get("_quality_flags"),
            "source_ids": d.get("_source_ids"),
            "evidence_ids": d.get("_evidence_ids"),
            "limitations": ["Delivery record may not prove intended recipient received goods."],
        }
        for d in deliveries
    ]

    customs_public = [
        {
            "customs_event_id": c.get("customs_event_id"),
            "shipment_id": c.get("_shipment_id"),
            "event_type": c.get("_event_type"),
            "time": iso_or_none(c.get("_time")),
            "node_id": c.get("_node_id"),
            "status": c.get("_status"),
            "quality_flags": c.get("_quality_flags"),
            "source_ids": c.get("_source_ids"),
            "evidence_ids": c.get("_evidence_ids"),
            "limitations": ["Customs hold/release is process state, not offense or final delivery."],
        }
        for c in customs
    ]

    disruption_public = [
        {
            "disruption_id": d.get("disruption_id"),
            "type": d.get("_type"),
            "node_id": d.get("_node_id"),
            "route_id": d.get("_route_id"),
            "start_time": iso_or_none(d.get("_start_time")),
            "end_time": iso_or_none(d.get("_end_time")),
            "impact_state": d.get("_impact_state"),
            "reported_cause": d.get("_reported_cause"),
            "quality_flags": d.get("_quality_flags"),
            "source_ids": d.get("_source_ids"),
            "evidence_ids": d.get("_evidence_ids"),
            "limitations": ["Disruption is not total failure; assess actual impact with operational evidence."],
        }
        for d in disruptions
    ]

    source_reliability = [
        {
            "source_id": s.get("source_id"),
            "source_type": s.get("_source_type"),
            "reliability": s.get("_reliability"),
            "independence_group": s.get("_independence_group"),
            "upstream_source_id": s.get("upstream_source_id"),
            "provider": s.get("provider"),
            "carrier_id": s.get("carrier_id"),
            "tms_id": s.get("tms_id"),
            "wms_id": s.get("wms_id"),
            "limitations": s.get("limitations"),
        }
        for s in sources.values()
    ]

    all_source_ids = sorted(
        {
            sid
            for obj in shipments + events + custody + deliveries + customs + inventory_records + movements + capacity_records + disruptions + cold_chain_records
            for sid in (obj.get("_source_ids") or [])
            if sid
        }
    )
    source_independence = summarize_source_independence(all_source_ids, sources)

    unknowns: List[str] = []
    if not shipments:
        unknowns.append("Shipment resolution unresolved")
    if not events:
        unknowns.append("Observed logistics events unresolved")
    if any(c.get("custody_gap_count", 0) > 0 for c in custody_results):
        unknowns.append("Custody chain incomplete")
    if not deliveries:
        unknowns.append("Delivery verification unresolved")
    if not inventory_context.get("latest_snapshots"):
        unknowns.append("Inventory position unresolved")
    if not capacity_context.get("capacity_records"):
        unknowns.append("Capacity/throughput unresolved")
    if contradictions:
        unknowns.append("Source/event/custody contradictions unresolved")
    unknowns.append("Ownership, intent, end user, and operational cause unresolved by design unless separate evidence exists")
    unknowns.append("No sabotage, smuggling, evasion, interdiction, targeting, or private tracking conclusion is supported")

    if contradictions:
        status = "SOURCE_CONFLICT"
    elif issues:
        status = "PARTIAL"
    elif not shipments and not events:
        status = "INCONCLUSIVE"
    elif supported_facts:
        status = "SUCCEEDED"
    else:
        status = "PARTIAL"

    result: Dict[str, Any] = {
        "case_id": case.get("case_id"),
        "task_id": case.get("task_id"),
        "objective": case.get("objective"),
        "questions": case.get("questions") or [],
        "mode": case.get("model_mode", "LOCAL_ONLY"),
        "status": status,
        "source_ids": sorted(sources.keys()),
        "evidence_ids": sorted(
            {
                eid
                for obj in shipments + events + custody + deliveries + customs + inventory_records + movements + capacity_records + disruptions + cold_chain_records
                for eid in (obj.get("_evidence_ids") or [])
                if eid
            }
        ),
        "shipments": shipment_public,
                "orders": {oid: public_dict(o) for oid, o in orders.items()},
        "cargo": {cid: public_dict(c) for cid, c in cargo.items()},
        "products": {
            cid: {
                "cargo_id": cid,
                "description": c.get("_description"),
                "quantity": c.get("_quantity"),
                "weight": c.get("_weight"),
                "volume": c.get("_volume"),
                "temperature_required": c.get("_temperature_required"),
                "hazard_class": c.get("_hazard_class"),
                "handling_requirements": c.get("_handling_requirements"),
                "quality_flags": c.get("_quality_flags"),
            }
            for cid, c in cargo.items()
        },
        "commodities": {
            cid: {
                "cargo_id": cid,
                "commodity": c.get("commodity"),
                "product": c.get("product"),
                "description": c.get("_description"),
            }
            for cid, c in cargo.items()
            if c.get("commodity") or c.get("product")
        },
        "containers": {cid: public_dict(c) for cid, c in containers.items()},
        "carriers": {aid: public_dict(a) for aid, a in carriers.items()},
        "freight_forwarders": {aid: public_dict(a) for aid, a in forwarders.items()},
        "three_pls": {
            aid: public_dict(a)
            for aid, a in third.items()
            if "3PL" in str(a.get("_role") or "")
        },
        "four_pls": {
            aid: public_dict(a)
            for aid, a in third.items()
            if "4PL" in str(a.get("_role") or "")
        },
        "logistics_providers": {aid: public_dict(a) for aid, a in third.items()},
        "nodes": {
            nid: (
                {
                    "node_id": nid,
                    "redacted": True,
                    "quality_flags": n.get("_quality_flags"),
                    "limitations": ["Private or sensitive node location redacted by privacy boundary."],
                }
                if "privacy_private_delivery_redacted" in (n.get("_quality_flags") or [])
                else public_dict(n)
            )
            for nid, n in nodes.items()
        },
        "warehouses": {
            nid: public_dict(n)
            for nid, n in nodes.items()
            if n.get("_node_type") == "WAREHOUSE"
        },
        "distribution_centers": {
            nid: public_dict(n)
            for nid, n in nodes.items()
            if n.get("_node_type") == "DISTRIBUTION_CENTER"
        },
        "ports": {
            nid: public_dict(n)
            for nid, n in nodes.items()
            if n.get("_node_type") == "PORT"
        },
        "terminals": {
            nid: public_dict(n)
            for nid, n in nodes.items()
            if n.get("_node_type") == "TERMINAL"
        },
        "airports": {
            nid: public_dict(n)
            for nid, n in nodes.items()
            if n.get("_node_type") == "AIRPORT"
        },
        "rail_hubs": {
            nid: public_dict(n)
            for nid, n in nodes.items()
            if n.get("_node_type") == "RAIL_HUB"
        },
        "customs_points": {
            nid: public_dict(n)
            for nid, n in nodes.items()
            if n.get("_node_type") == "CUSTOMS_POINT"
        },
        "routes": route_public,
        "transport_legs": leg_public,
        "planned_routes": [
            r
            for r in route_public
            if r.get("planned_path")
        ],
        "observed_routes": [
            r
            for r in route_public
            if r.get("observed_path")
        ],
        "inferred_routes": [
            r
            for r in route_public
            if r.get("confidence") == "INFERRED"
        ],
        "route_confidence": {
            r.get("route_id"): r.get("confidence")
            for r in route_public
            if r.get("route_id")
        },
        "shipment_events": event_public,
        "planned_times": (
            [
                {
                    "object_type": "shipment",
                    "object_id": s.get("shipment_id"),
                    "event": "departure",
                    "time": iso_or_none(s.get("_planned_departure")),
                }
                for s in shipments
                if s.get("_planned_departure")
            ]
            + [
                {
                    "object_type": "shipment",
                    "object_id": s.get("shipment_id"),
                    "event": "arrival",
                    "time": iso_or_none(s.get("_planned_arrival")),
                }
                for s in shipments
                if s.get("_planned_arrival")
            ]
            + [
                {
                    "object_type": "leg",
                    "object_id": l.get("leg_id"),
                    "event": "start",
                    "time": iso_or_none(l.get("_planned_start")),
                }
                for l in legs
                if l.get("_planned_start")
            ]
            + [
                {
                    "object_type": "leg",
                    "object_id": l.get("leg_id"),
                    "event": "end",
                    "time": iso_or_none(l.get("_planned_end")),
                }
                for l in legs
                if l.get("_planned_end")
            ]
            + [
                {
                    "object_type": "event",
                    "object_id": e.get("event_id"),
                    "event": e.get("_event_type"),
                    "time": iso_or_none(e.get("_planned_time")),
                }
                for e in events
                if e.get("_planned_time")
            ]
        ),
        "estimated_times": (
            [
                {
                    "object_type": "event",
                    "object_id": e.get("event_id"),
                    "event": e.get("_event_type"),
                    "time": iso_or_none(e.get("_estimated_time")),
                }
                for e in events
                if e.get("_estimated_time")
            ]
        ),
        "actual_times": (
            [
                {
                    "object_type": "shipment",
                    "object_id": s.get("shipment_id"),
                    "event": "departure",
                    "time": iso_or_none(s.get("_actual_departure")),
                }
                for s in shipments
                if s.get("_actual_departure")
            ]
            + [
                {
                    "object_type": "shipment",
                    "object_id": s.get("shipment_id"),
                    "event": "arrival",
                    "time": iso_or_none(s.get("_actual_arrival")),
                }
                for s in shipments
                if s.get("_actual_arrival")
            ]
            + [
                {
                    "object_type": "leg",
                    "object_id": l.get("leg_id"),
                    "event": "start",
                    "time": iso_or_none(l.get("_actual_start")),
                }
                for l in legs
                if l.get("_actual_start")
            ]
            + [
                {
                    "object_type": "leg",
                    "object_id": l.get("leg_id"),
                    "event": "end",
                    "time": iso_or_none(l.get("_actual_end")),
                }
                for l in legs
                if l.get("_actual_end")
            ]
            + [
                {
                    "object_type": "event",
                    "object_id": e.get("event_id"),
                    "event": e.get("_event_type"),
                    "time": iso_or_none(e.get("_actual_time")),
                }
                for e in events
                if e.get("_actual_time")
            ]
        ),
        "custody_events": custody_public,
        "custody_analysis": custody_results,
        "delivery_status": {
            s.get("shipment_id"): {
                "shipment_status": s.get("_status"),
                "delivery_status": s.get("_delivery_status"),
                "pod_state": s.get("_pod_state"),
                "delivery_record_ids": [
                    d.get("delivery_id")
                    for d in deliveries
                    if d.get("_shipment_id") == s.get("shipment_id")
                ],
            }
            for s in shipments
            if s.get("shipment_id")
        },
        "proof_of_delivery": delivery_public,
        "deliveries": delivery_public,
        "inventory_snapshots": inventory_context.get("latest_snapshots", []),
        "inventory_movements": [public_dict(m) for m in movements],
        "stock_states": [
            {
                "inventory_id": r.get("inventory_id"),
                "product_id": r.get("_product_id"),
                "location_id": r.get("_location_id"),
                "stock_state": r.get("_stock_state"),
                "quantity": r.get("_quantity", {}).get("normalized_value"),
                "unit": r.get("_quantity", {}).get("normalized_unit"),
                "snapshot_time": iso_or_none(r.get("_snapshot_time")),
                "quality_flags": r.get("_quality_flags"),
            }
            for r in inventory_records
        ],
        "inventory_context": inventory_context,
        "capacity_context": capacity_context,
        "throughput": [
            c
            for c in capacity_context.get("capacity_records", [])
            if c.get("throughput") is not None
        ],
        "lead_time_analysis": lead_dwell,
        "lead_times": lead_dwell.get("lead_times", []),
        "transit_times": [
            x
            for x in lead_dwell.get("lead_times", [])
            if x.get("metric") == "transit_time"
        ],
        "dwell_times": lead_dwell.get("dwell_times", []),
        "delay_analysis": delay_results,
        "delay_events": [
            d
            for d in delay_results
            if d.get("delayed")
        ],
        "delay_causes": [
            {
                "shipment_id": d.get("shipment_id"),
                **cause,
            }
            for d in delay_results
            for cause in d.get("delay_causes", [])
        ],
        "congestion_context": [
            d
            for d in disruption_public
            if "CONGESTION" in str(d.get("type") or "").upper()
        ],
        "cold_chain_context": cold_chain_context,
        "temperature_excursions": cold_chain_context.get("excursion_records", []),
        "service_level_context": service_levels,
        "on_time_performance": {
            "eligible_deliveries": service_levels.get("eligible_deliveries"),
            "on_time_deliveries": service_levels.get("on_time_deliveries"),
            "on_time_rate": service_levels.get("on_time_rate"),
            "definition": service_levels.get("definition"),
            "limitations": service_levels.get("limitations"),
        },
        "reverse_logistics": [
            d
            for d in delivery_public
            if d.get("status") in {"RETURNED", "FAILED"}
        ],
        "returns": [
            d
            for d in delivery_public
            if d.get("status") == "RETURNED"
        ],
        "customs_context": customs_public,
        "trade_context": case.get("trade_context") or [],
        "supply_chain_context": case.get("supply_chain_context") or [],
        "environmental_context": case.get("environmental_context") or {},
        "weather_context": case.get("weather_context") or {},
        "seismic_context": case.get("seismic_context") or [],
        "satellite_context": case.get("satellite_context") or [],
        "ais_context": case.get("ais_context") or [],
        "disruptions": disruption_public,
        "node_criticality": [
            {
                "node_id": n.get("node_id"),
                "node_type": n.get("node_type"),
                "load_count": n.get("load_count"),
                "load_share_of_legs": n.get("load_share_of_legs"),
                "critical_dependency_candidate": n.get("critical_dependency_candidate"),
                "resilience_state": n.get("resilience_state"),
                "alternative_node_ids": n.get("alternative_node_ids"),
                "limitations": [
                    "Criticality is resilience language, not attack value.",
                    "Load count is limited to supplied legs/events and does not prove real-world volume.",
                    "Documented alternatives are not tested alternatives.",
                ],
            }
            for n in dependencies.get("node_dependencies", [])
        ],
        "concentration_risk": {
            "top_nodes": dependencies.get("node_dependencies", [])[:10],
            "top_carriers": dependencies.get("carrier_dependencies", [])[:10],
            "top_routes": dependencies.get("route_dependencies", [])[:10],
            "limitations": [
                "Concentration analysis is defensive and business-continuity oriented.",
                "It does not identify attack chokepoints or sabotage targets.",
            ],
        },
        "common_mode_dependencies": dependencies.get("common_mode_dependencies", []),
        "alternative_routes": [
            {
                "route_id": r.get("route_id"),
                "alternative_route_ids": r.get("alternative_route_ids"),
                "limitations": [
                    "Alternative route analysis is for resilience only.",
                    "No evasion, inspection avoidance, or harmful routing optimization is performed.",
                ],
            }
            for r in dependencies.get("route_dependencies", [])
            if r.get("alternative_route_ids")
        ],
        "alternative_carriers": [
            {
                "carrier_id": c.get("carrier_id"),
                "alternative_carrier_ids": c.get("alternative_carrier_ids"),
                "limitations": [
                    "Alternative carrier assessment requires human review of mode, capacity, compatibility, lead time, cost, and regulation.",
                    "No smuggling, evasion, or harmful optimization is supported.",
                ],
            }
            for c in dependencies.get("carrier_dependencies", [])
            if c.get("alternative_carrier_ids")
        ],
        "resilience_context": dependencies,
        "timeline_updates": sorted(
            [
                {
                    "kind": "shipment",
                    "id": s.get("shipment_id"),
                    "time": iso_or_none(s.get("_actual_departure")),
                    "status": s.get("_status"),
                }
                for s in shipments
            ]
            + [
                {
                    "kind": "event",
                    "id": e.get("event_id"),
                    "time": iso_or_none(e.get("_actual_time")),
                    "event_type": e.get("_event_type"),
                    "shipment_id": e.get("_shipment_id"),
                }
                for e in events
            ]
            + [
                {
                    "kind": "leg",
                    "id": l.get("leg_id"),
                    "time": iso_or_none(l.get("_actual_start")),
                    "mode": l.get("_mode"),
                    "shipment_id": l.get("_shipment_id"),
                }
                for l in legs
            ]
            + [
                {
                    "kind": "custody",
                    "id": c.get("custody_id"),
                    "time": iso_or_none(c.get("_time")),
                    "shipment_id": c.get("_shipment_id"),
                    "to_custodian": c.get("_to_custodian"),
                }
                for c in custody
            ]
            + [
                {
                    "kind": "delivery",
                    "id": d.get("delivery_id"),
                    "time": iso_or_none(d.get("_time")),
                    "shipment_id": d.get("_shipment_id"),
                    "status": d.get("_status"),
                }
                for d in deliveries
            ]
            + [
                {
                    "kind": "customs",
                    "id": c.get("customs_event_id"),
                    "time": iso_or_none(c.get("_time")),
                    "shipment_id": c.get("_shipment_id"),
                    "event_type": c.get("_event_type"),
                }
                for c in customs
            ]
            + [
                {
                    "kind": "disruption",
                    "id": d.get("disruption_id"),
                    "time": iso_or_none(d.get("_start_time")),
                    "type": d.get("_type"),
                    "node_id": d.get("_node_id"),
                    "route_id": d.get("_route_id"),
                }
                for d in disruptions
            ]
            + [
                {
                    "kind": "cold_chain",
                    "id": c.get("record_id"),
                    "time": iso_or_none(c.get("_time")),
                    "shipment_id": c.get("_shipment_id"),
                    "temperature_c": c.get("_temperature_c"),
                    "excursion": c.get("_excursion"),
                }
                for c in cold_chain_records
            ],
            key=lambda x: x.get("time") or "",
        ),
        "observations": (
            event_public
            + delivery_public
            + customs_public
            + [public_dict(c) for c in cold_chain_records]
            + [public_dict(d) for d in disruptions]
        ),
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "source_reliability": source_reliability,
        "source_bias": case.get("source_bias") or [
            "Carrier self-reporting may be incomplete or delayed.",
            "Customer complaint data may overrepresent failures.",
            "Commercial tracking aggregators may drop or replay events.",
            "Public schedules may lag actual operations.",
            "Customs data may have reporting latency.",
            "Satellite observations may have revisit and occlusion limits.",
            "AIS coverage may have gaps or transmission interruptions.",
        ],
        "source_limitations": case.get("source_limitations") or [
            "Event report is not automatically cargo unload, transfer, delivery, or custody change.",
            "Duplicate or dependent feeds are not independent evidence.",
            "Planned times are not actual times.",
            "Capacity is not throughput.",
            "Delay is not negligence.",
            "Custody gap is not automatically theft or loss.",
            "Weather or disruption proximity alone does not prove causation.",
        ],
        "source_pedigree": case.get("source_pedigree") or [
            {
                "source_id": s.get("source_id"),
                "provider": s.get("provider"),
                "source_type": s.get("_source_type"),
                "upstream_source_id": s.get("upstream_source_id"),
                "independence_group": s.get("_independence_group"),
                "carrier_id": s.get("carrier_id"),
                "tms_id": s.get("tms_id"),
                "wms_id": s.get("wms_id"),
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
                    "Independent carrier event",
                    "Terminal or warehouse scan",
                    "Customs release/hold record",
                    "Proof of delivery",
                    "Custody transfer record",
                    "Ingestion-time logs to detect latency",
                    "BCP/DR records for alternative testing",
                    "Environmental or weather operational impact evidence",
                ],
            }
            for h in hypotheses
        ],
        "privacy_flags": [
            "NO_PRIVATE_PERSON_TRACKING",
            "NO_STALKING",
            "PRIVATE_DELIVERY_LOCATION_REDACTED_WHEN_REQUIRED",
            "DRIVER_STAFF_PRIVATE_DATA_MINIMIZED",
            "HIGH_VALUE_CARGO_REALTIME_LOCATION_RESTRICTED",
            "MINIMUM_NECESSARY_LOGISTICS_GRANULARITY",
        ],
        "legal_flags": [
            "NO_AUTONOMOUS_OPERATIONAL_ACTION",
            "HUMAN_REVIEW_REQUIRED_FOR_REROUTE_CANCEL_RELEASE_CONSIGNEE_CHANGE",
            "NO_FALSIFIED_DOCUMENTS",
            "NO_CUSTOMS_EVASION",
            "NO_SMUGGLING_SUPPORT",
            "NO_INTERDICTION_OR_TARGETING",
            "AUTHORIZED_SOURCES_ONLY",
        ],
        "safety_flags": [
            "NO_SABOTAGE_PLANNING",
            "NO_ATTACK_CHOKEPOINT_IDENTIFICATION",
            "NO_INTERDICTION_PLANNING",
            "NO_MILITARY_LOGISTICS_TARGETING",
            "NO_SMUGGLING_OPTIMIZATION",
            "NO_CUSTOMS_EVASION",
            "NO_INSPECTION_AVOIDANCE",
            "NO_CARGO_CONCEALMENT",
            "NO_FALSE_DOCUMENTS",
            "NO_SEAL_TAMPERING",
            "NO_AIS_MANIPULATION",
            "NO_GPS_SPOOFING",
            "NO_UNAUTHORIZED_ACCESS",
            "NO_PRIVATE_PERSON_TRACKING",
            "NO_AUTONOMOUS_OPERATIONAL_ACTION",
        ],
        "unknowns": unknowns,
        "knowledge_gaps": gaps,
        "recommended_next_actions": next_actions,
        "specialist_handoffs": handoffs,
        "limitations": [
            "This scaffold does not fetch live carrier, port, warehouse, customs, or tracking data.",
            "It consumes deterministic logistics records only.",
            "It does not invent shipments, routes, carriers, deliveries, inventory, customs events, capacity, or disruption causes.",
            "It separates order, shipment, delivery, payment, custody, ownership, planned, estimated, observed, and inferred states.",
            "It does not generate routes or optimize evasion, smuggling, interdiction, sabotage, or targeting.",
            "It does not autonomously reroute, cancel, release cargo, change consignee, change carrier, or modify documents.",
            "It redacts or minimizes private delivery/person location data unless separately authorized for benign lawful purpose.",
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
                "timestamp parsing and timezone normalization",
                "shipment/event/custody/delivery/customs ID normalization",
                "container ID normalization without silent correction",
                "quantity/unit normalization for weight, volume, time, and count",
                "planned vs estimated vs actual separation",
                "event deduplication and duplicate-state labeling",
                "custody-chain ordering and gap detection",
                "delay calculation from planned vs actual times",
                "lead-time, transit-time, and dwell-time calculation",
                "inventory snapshot latest-state selection",
                "inventory movement net calculation",
                "capacity utilization arithmetic",
                "cold-chain excursion threshold checks",
                "service-level on-time and OTIF calculation",
                "node/carrier/route load and common-mode dependency detection",
                "source independence grouping",
                "contradiction detection",
                "fact gate",
            ],
            "note": (
                "Replay requires original shipment documents, event feeds, carrier/TMS/WMS exports, "
                "port/terminal/customs records, timezone metadata, unit metadata, source pedigree, "
                "duplicate-feed decisions, custody edges, delay-cause decisions, and model versions."
            ),
        },
    }

    result["required_analyst_summary"] = analyst_summary(result)
    return result


# -----------------------------------------------------------------------------
# Template
# -----------------------------------------------------------------------------

def template_case() -> Dict[str, Any]:
    return {
        "_template_note": (
            "Placeholders only. Replace with deterministic authorized/public logistics records. "
            "Do not treat this template as real shipment, route, delivery, inventory, or disruption evidence."
        ),
        "case_id": "CASE-LOGINT-EXAMPLE",
        "task_id": "TASK-LOGINT-EXAMPLE",
        "objective": (
            "Authorized lawful logistics resilience and shipment-status analysis for a public/authorized "
            "supply-flow investigation. Not sabotage, smuggling, customs evasion, interdiction, targeting, "
            "or private-person tracking."
        ),
        "questions": [
            "What shipment is referenced?",
            "What cargo and containers are associated?",
            "Which carrier, forwarder, and nodes are supported by records?",
            "What route was planned versus observed versus inferred?",
            "Where are custody gaps or delivery verification gaps?",
            "What delays are supported and what causes remain unresolved?",
            "What resilience dependencies or common-mode risks exist?",
            "What remains unknown?",
        ],
        "scope": {
            "authorized_only": True,
            "lawful_only": True,
            "defensive_only": True,
            "resilience_aware": True,
            "no_sabotage_planning": True,
            "no_attack_chokepoint_identification": True,
            "no_interdiction_planning": True,
            "no_military_targeting": True,
            "no_smuggling_optimization": True,
            "no_customs_evasion": True,
            "no_inspection_avoidance": True,
            "no_cargo_concealment": True,
            "no_false_documents": True,
            "no_seal_tampering": True,
            "no_ais_manipulation": True,
            "no_gps_spoofing": True,
            "no_unauthorized_access": True,
            "no_private_person_tracking": True,
            "no_autonomous_operational_action": True,
            "sensitive_location_exact_authorized": False,
        },
        "authorization": {
            "lawful_basis": "AUTHORIZED_LOGISTICS_RESILIENCE_AND_INVESTIGATION_SUPPORT",
            "purpose": "DEFENSIVE_SUPPLY_FLOW_AND_SHIPMENT_STATUS_ANALYSIS",
            "approval_reference": "AUTH-LOGINT-001",
            "data_retention": "MINIMUM_NECESSARY",
        },
        "model_mode": "LOCAL_ONLY",
        "knowledge_time": "2026-10-08T12:00:00Z",
        "analysis_settings": {
            "custody_gap_threshold_s": 86400,
            "delay_threshold_hours": 1.0,
            "on_time_window_hours": 0.0,
            "event_conflict_tolerance_s": 3600,
        },
        "sources": [
            {
                "source_id": "SRC-TMS",
                "source_type": "AUTHORIZED_TMS",
                "provider": "EXAMPLE_TMS_PROVIDER",
                "reliability": "HIGH",
                "independence_group": "TMS_A",
                "tms_id": "TMS-1",
                "limitations": ["TMS events may be delayed or corrected."],
            },
            {
                "source_id": "SRC-CARRIER",
                "source_type": "CARRIER_API",
                "provider": "EXAMPLE_CARRIER",
                "reliability": "MODERATE",
                "independence_group": "CARRIER_A",
                "carrier_id": "CAR-1",
                "limitations": ["Carrier API may aggregate or replay scans."],
            },
            {
                "source_id": "SRC-PORT",
                "source_type": "OFFICIAL_PORT_RECORD",
                "provider": "EXAMPLE_PORT_AUTHORITY",
                "reliability": "HIGH",
                "independence_group": "PORT_A",
                "limitations": ["Port record may not identify specific cargo inside container."],
            },
            {
                "source_id": "SRC-WMS",
                "source_type": "AUTHORIZED_WMS",
                "provider": "EXAMPLE_WAREHOUSE_OPERATOR",
                "reliability": "HIGH",
                "independence_group": "WMS_A",
                "wms_id": "WMS-1",
                "limitations": ["Inventory is snapshot-based and time-bound."],
            },
        ],
        "parties": [
            {
                "party_id": "PARTY-SHIPPER",
                "name": "Example Shipper",
                "roles": ["SHIPPER", "SELLER"],
            },
            {
                "party_id": "PARTY-CONSIGNEE",
                "name": "Example Consignee",
                "roles": ["CONSIGNEE", "BUYER"],
            },
        ],
        "orders": [
            {
                "order_id": "ORD-1",
                "created_time": "2026-10-01T09:00:00Z",
                "buyer": "PARTY-CONSIGNEE",
                "seller": "PARTY-SHIPPER",
                "cargo_ids": ["CARGO-1"],
                "quantity": 100,
                "quantity_unit": "count",
                "source_ids": ["SRC-TMS"],
                "evidence_ids": ["EVD-ORD-1"],
            }
        ],
        "cargo": [
            {
                "cargo_id": "CARGO-1",
                "description": "Example general consumer goods",
                "commodity": "GENERAL_GOODS",
                "quantity": 100,
                "quantity_unit": "count",
                "weight": 850,
                "weight_unit": "kg",
                "volume": 4.2,
                "volume_unit": "m3",
                "temperature_requirements": False,
                "hazard_class": None,
                "handling_requirements": ["Standard handling"],
                "source_ids": ["SRC-TMS"],
                "evidence_ids": ["EVD-CARGO-1"],
            }
        ],
        "containers": [
            {
                "container_id": "CONT-1",
                "container_number": "EXAMPLEU1234567",
                "container_type": "20GP",
                "shipment_ids": ["SHIP-1"],
                "seal_reference": "SEAL-EXAMPLE-001",
                "carrier": "CAR-1",
                "source_ids": ["SRC-CARRIER"],
                "evidence_ids": ["EVD-CONT-1"],
            }
        ],
        "carriers": [
            {
                "carrier_id": "CAR-1",
                "legal_entity_reference": "EXAMPLE_CARRIER_LTD",
                "modes": ["MARITIME", "ROAD"],
                "service_type": "MULTIMODAL",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "alternative_carriers": ["CAR-2"],
                "source_ids": ["SRC-TMS"],
            },
            {
                "carrier_id": "CAR-2",
                "legal_entity_reference": "EXAMPLE_ALT_CARRIER_LTD",
                "modes": ["ROAD"],
                "service_type": "LAST_MILE",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "source_ids": ["SRC-TMS"],
            },
        ],
        "freight_forwarders": [
            {
                "forwarder_id": "FWD-1",
                "legal_entity_reference": "EXAMPLE_FORWARDER_LTD",
                "modes": ["MULTIMODAL"],
                "service_type": "FREIGHT_FORWARDING",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "source_ids": ["SRC-TMS"],
            }
        ],
        "three_pls": [],
        "four_pls": [],
        "warehouses": [
            {
                "node_id": "WH-ORIGIN",
                "node_type": "WAREHOUSE",
                "name": "Example Origin Warehouse",
                "operator": "EXAMPLE_WAREHOUSE_OPERATOR",
                "location": {"latitude": 0.0, "longitude": 0.0, "accuracy_m": 50, "area_id": "REGION_A"},
                "warehouse_type": "GENERAL",
                "temperature_capability": "AMBIENT",
                "bonded_status": "NOT_BONDED",
                "operational_status": "OPERATIONAL",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "capacity_claim": {"pallet_positions": 5000, "source": "CLAIMED_CAPACITY"},
                "alternative_nodes": ["WH-ALT"],
                "source_ids": ["SRC-WMS"],
                "evidence_ids": ["EVD-WH-ORIGIN"],
            },
            {
                "node_id": "WH-DEST",
                "node_type": "WAREHOUSE",
                "name": "Example Destination Warehouse",
                "operator": "EXAMPLE_WAREHOUSE_OPERATOR",
                "location": {"latitude": 0.1, "longitude": 0.1, "accuracy_m": 50, "area_id": "REGION_B"},
                "warehouse_type": "DISTRIBUTION_CENTER",
                "temperature_capability": "AMBIENT",
                "bonded_status": "UNKNOWN",
                "operational_status": "OPERATIONAL",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "capacity_claim": {"pallet_positions": 8000, "source": "CLAIMED_CAPACITY"},
                "alternative_nodes": [],
                "source_ids": ["SRC-WMS"],
                "evidence_ids": ["EVD-WH-DEST"],
            },
            {
                "node_id": "WH-ALT",
                "node_type": "WAREHOUSE",
                "name": "Example Alternate Warehouse",
                "operator": "EXAMPLE_ALT_OPERATOR",
                "location": {"latitude": 0.02, "longitude": 0.0, "accuracy_m": 100, "area_id": "REGION_A"},
                "warehouse_type": "GENERAL",
                "temperature_capability": "AMBIENT",
                "bonded_status": "UNKNOWN",
                "operational_status": "OPERATIONAL",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": "2026-12-31T23:59:59Z",
                "source_ids": ["SRC-WMS"],
            },
        ],
        "ports": [
            {
                "node_id": "PORT-1",
                "node_type": "PORT",
                "name": "Example Port",
                "unlocode": "EXAMPLEPORT",
                "location": {"latitude": 0.05, "longitude": 0.05, "accuracy_m": 100, "area_id": "REGION_A"},
                "cargo_types": ["CONTAINER"],
                "operational_status": "OPERATIONAL",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-PORT-1"],
            }
        ],
        "terminals": [
            {
                "node_id": "TERM-1",
                "node_type": "TERMINAL",
                "name": "Example Container Terminal",
                "location": {"latitude": 0.0501, "longitude": 0.0501, "accuracy_m": 50, "area_id": "REGION_A"},
                "operational_status": "DEGRADED",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-TERM-1"],
            }
        ],
        "customs_points": [
            {
                "node_id": "CU-1",
                "node_type": "CUSTOMS_POINT",
                "name": "Example Customs Office",
                "location": {"latitude": 0.0502, "longitude": 0.0502, "accuracy_m": 50, "area_id": "REGION_A"},
                "operational_status": "OPERATIONAL",
                "source_ids": ["SRC-PORT"],
            }
        ],
        "shipments": [
            {
                "shipment_id": "SHIP-1",
                "order_reference": "ORD-1",
                "status": "IN_TRANSIT",
                "cargo_ids": ["CARGO-1"],
                "container_ids": ["CONT-1"],
                "shipper": "PARTY-SHIPPER",
                "consignee": "PARTY-CONSIGNEE",
                "carrier": "CAR-1",
                "forwarder": "FWD-1",
                "origin_node": "WH-ORIGIN",
                "destination_node": "WH-DEST",
                "transport_modes": ["ROAD", "MARITIME", "ROAD"],
                "planned_departure": "2026-10-02T08:00:00Z",
                "actual_departure": "2026-10-02T10:30:00Z",
                "planned_arrival": "2026-10-07T12:00:00Z",
                "actual_arrival": None,
                "delivery_status": "IN_TRANSIT",
                "pod_state": "NOT_AVAILABLE",
                "delay_cause": None,
                "source_ids": ["SRC-TMS", "SRC-CARRIER"],
                "evidence_ids": ["EVD-SHIP-1"],
            }
        ],
        "routes": [
            {
                "route_id": "ROUTE-1",
                "shipment_id": "SHIP-1",
                "origin": "WH-ORIGIN",
                "destination": "WH-DEST",
                "legs": ["LEG-1", "LEG-2", "LEG-3"],
                "planned_path": ["WH-ORIGIN", "PORT-1", "TERM-1", "WH-DEST"],
                "observed_path": ["WH-ORIGIN", "PORT-1"],
                "confidence": "SUPPORTED",
                "distance_m": 1200000,
                "duration_s": 432000,
                "alternative_routes": ["ROUTE-ALT-1"],
                "source_ids": ["SRC-TMS"],
                "evidence_ids": ["EVD-ROUTE-1"],
            },
            {
                "route_id": "ROUTE-ALT-1",
                "shipment_id": "SHIP-1",
                "origin": "WH-ORIGIN",
                "destination": "WH-DEST",
                "legs": [],
                "planned_path": ["WH-ORIGIN", "RAIL-HUB-1", "WH-DEST"],
                "observed_path": [],
                "confidence": "INFERRED",
                "distance_m": 1100000,
                "duration_s": 396000,
                "source_ids": ["SRC-TMS"],
            }
        ],
        "transport_legs": [
            {
                "leg_id": "LEG-1",
                "shipment_id": "SHIP-1",
                "route_id": "ROUTE-1",
                "mode": "ROAD",
                "carrier": "CAR-1",
                "origin_node": "WH-ORIGIN",
                "destination_node": "PORT-1",
                "planned_start": "2026-10-02T08:00:00Z",
                "actual_start": "2026-10-02T10:30:00Z",
                "planned_end": "2026-10-02T14:00:00Z",
                "actual_end": "2026-10-02T17:15:00Z",
                "vehicle_or_asset_reference": "TRUCK-EXAMPLE-1",
                "source_ids": ["SRC-CARRIER"],
                "evidence_ids": ["EVD-LEG-1"],
            },
            {
                "leg_id": "LEG-2",
                "shipment_id": "SHIP-1",
                "route_id": "ROUTE-1",
                "mode": "MARITIME",
                "carrier": "CAR-1",
                "origin_node": "PORT-1",
                "destination_node": "TERM-1",
                "planned_start": "2026-10-03T06:00:00Z",
                "actual_start": "2026-10-03T09:00:00Z",
                "planned_end": "2026-10-05T06:00:00Z",
                "actual_end": None,
                "vehicle_or_asset_reference": "VESSEL-EXAMPLE-1",
                "source_ids": ["SRC-PORT", "SRC-CARRIER"],
                "evidence_ids": ["EVD-LEG-2"],
            },
            {
                "leg_id": "LEG-3",
                "shipment_id": "SHIP-1",
                "route_id": "ROUTE-1",
                "mode": "ROAD",
                "carrier": "CAR-2",
                "origin_node": "TERM-1",
                "destination_node": "WH-DEST",
                "planned_start": "2026-10-06T08:00:00Z",
                "actual_start": None,
                "planned_end": "2026-10-07T12:00:00Z",
                "actual_end": None,
                "vehicle_or_asset_reference": None,
                "source_ids": ["SRC-TMS"],
                "evidence_ids": ["EVD-LEG-3"],
            }
        ],
        "shipment_events": [
            {
                "event_id": "EVT-1",
                "shipment_id": "SHIP-1",
                "event_type": "BOOKED",
                "node_id": "WH-ORIGIN",
                "carrier": "CAR-1",
                "container_id": "CONT-1",
                "planned_time": "2026-10-01T12:00:00Z",
                "estimated_time": None,
                "actual_time": "2026-10-01T12:10:00Z",
                "reported_time": "2026-10-01T12:15:00Z",
                "ingestion_time": "2026-10-01T12:20:00Z",
                "source_ids": ["SRC-TMS"],
                "evidence_ids": ["EVD-EVT-1"],
            },
            {
                "event_id": "EVT-2",
                "shipment_id": "SHIP-1",
                "event_type": "PICKED_UP",
                "node_id": "WH-ORIGIN",
                "carrier": "CAR-1",
                "container_id": "CONT-1",
                "planned_time": "2026-10-02T08:00:00Z",
                "estimated_time": None,
                "actual_time": "2026-10-02T10:30:00Z",
                "reported_time": "2026-10-02T10:35:00Z",
                "ingestion_time": "2026-10-02T10:40:00Z",
                "source_ids": ["SRC-CARRIER"],
                "evidence_ids": ["EVD-EVT-2"],
            },
            {
                "event_id": "EVT-3",
                "shipment_id": "SHIP-1",
                "event_type": "ARRIVED",
                "node_id": "PORT-1",
                "carrier": "CAR-1",
                "container_id": "CONT-1",
                "planned_time": "2026-10-02T14:00:00Z",
                "estimated_time": None,
                "actual_time": "2026-10-02T17:15:00Z",
                "reported_time": "2026-10-02T17:20:00Z",
                "ingestion_time": "2026-10-02T17:30:00Z",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-EVT-3"],
            },
            {
                "event_id": "EVT-4",
                "shipment_id": "SHIP-1",
                "event_type": "CUSTOMS_ENTRY",
                "node_id": "CU-1",
                "carrier": "CAR-1",
                "container_id": "CONT-1",
                "planned_time": "2026-10-03T05:00:00Z",
                "estimated_time": None,
                "actual_time": "2026-10-03T07:00:00Z",
                "reported_time": "2026-10-03T07:10:00Z",
                "ingestion_time": "2026-10-03T07:20:00Z",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-EVT-4"],
            }
        ],
        "custody_events": [
            {
                "custody_id": "CUST-1",
                "shipment_id": "SHIP-1",
                "from_custodian": "PARTY-SHIPPER",
                "to_custodian": "CAR-1",
                "from_role": "SHIPPER",
                "to_role": "CARRIER",
                "node_id": "WH-ORIGIN",
                "time": "2026-10-02T10:30:00Z",
                "source_ids": ["SRC-CARRIER"],
                "evidence_ids": ["EVD-CUST-1"],
            },
            {
                "custody_id": "CUST-2",
                "shipment_id": "SHIP-1",
                "from_custodian": "CAR-1",
                "to_custodian": "PORT-1",
                "from_role": "CARRIER",
                "to_role": "TERMINAL",
                "node_id": "PORT-1",
                "time": "2026-10-02T17:15:00Z",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-CUST-2"],
            }
        ],
        "inventory_records": [
            {
                "inventory_id": "INV-1",
                "location_id": "WH-ORIGIN",
                "product_id": "CARGO-1",
                "quantity": 100,
                "unit": "count",
                "stock_state": "ALLOCATED",
                "lot": "LOT-EXAMPLE-1",
                "snapshot_time": "2026-10-01T08:00:00Z",
                "source_ids": ["SRC-WMS"],
                "evidence_ids": ["EVD-INV-1"],
            }
        ],
        "inventory_movements": [
            {
                "movement_id": "MOVE-1",
                "product_id": "CARGO-1",
                "from_location": "WH-ORIGIN",
                "to_location": "PORT-1",
                "quantity": 100,
                "unit": "count",
                "time": "2026-10-02T17:15:00Z",
                "source_ids": ["SRC-WMS", "SRC-PORT"],
                "evidence_ids": ["EVD-MOVE-1"],
            }
        ],
        "capacity_records": [
            {
                "capacity_id": "CAP-1",
                "node_id": "TERM-1",
                "capacity_type": "CONTAINER_YARD",
                "capacity_state": "AVAILABLE_CAPACITY",
                "unit": "teu",
                "available_capacity": 1200,
                "utilized_capacity": 1050,
                "throughput": 300,
                "throughput_unit": "containers/day",
                "as_of_time": "2026-10-03T00:00:00Z",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-CAP-1"],
            }
        ],
        "deliveries": [],
        "customs_records": [
            {
                "customs_event_id": "CU-EVT-1",
                "shipment_id": "SHIP-1",
                "event_type": "CUSTOMS_ENTRY",
                "time": "2026-10-03T07:00:00Z",
                "node_id": "CU-1",
                "status": "PENDING",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-CU-1"],
            }
        ],
        "disruptions": [
            {
                "disruption_id": "DISR-1",
                "type": "TERMINAL_CONGESTION",
                "node_id": "TERM-1",
                "route_id": "ROUTE-1",
                "start_time": "2026-10-02T18:00:00Z",
                "end_time": None,
                "impact_state": "PARTIAL_IMPACT",
                "cause": "Reported yard congestion",
                "source_ids": ["SRC-PORT"],
                "evidence_ids": ["EVD-DISR-1"],
            }
        ],
        "cold_chain_records": [],
        "weather_context": {
            "note": "Weather context alone does not prove delay causation.",
            "events": [
                {
                    "weather_event_id": "WX-1",
                    "type": "HIGH_WIND",
                    "start_time": "2026-10-02T12:00:00Z",
                    "end_time": "2026-10-02T18:00:00Z",
                    "area_id": "REGION_A",
                }
            ],
        },
        "environmental_context": {},
        "seismic_context": [],
        "satellite_context": [],
        "ais_context": [],
        "trade_context": [],
        "supply_chain_context": [],
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
            "TRACEATLAS LOGINT lawful authorized evidence-first logistics intelligence scaffold. "
            "Consumes deterministic logistics records; does not fetch live data, invent shipments/routes/"
            "deliveries/inventory/customs events, plan sabotage/smuggling/customs evasion/interdiction/"
            "targeting, falsify documents, tamper seals, manipulate AIS/GPS, access unauthorized systems, "
            "track private persons, or autonomously alter operations."
        )
    )
    parser.add_argument("--input", "-i", help="Path to LOGINT input JSON")
    parser.add_argument("--output", "-o", default="logint_result.json", help="Output LOGINTResult JSON path")
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
