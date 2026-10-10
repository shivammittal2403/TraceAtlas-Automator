import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
import re
import csv
import hashlib
import uuid

from collections import defaultdict, Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


APP_TITLE = "TraceAtlas TACTINT AI Employee — Authorized / Defensive / Non-Targeting / Force-Protection Tactical Intelligence Panel"
APP_VERSION = "TraceAtlas TACTINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("area_of_interest", "Area of Interest (AOI)", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "TACTINT Questions", "text"),

    ("actors", "Actors / Units (Candidates)", "text"),
    ("events", "Events / Incidents", "text"),
    ("movements", "Movement Observations", "text"),
    ("equipment", "Equipment / Vehicles Observed", "text"),
    ("terrain", "Terrain / Weather Context", "text"),
    ("infrastructure", "Infrastructure / Facilities", "text"),
    ("civilian_sites", "Civilian / Protected Sites", "text"),
    
    ("event_paths", "Event Report / Incident Log Paths", "text"),
    ("imagery_paths", "Imagery Metadata / Geo-tagged Files Paths", "text"),
    ("sensor_paths", "Authorized Sensor / Telemetry Paths", "text"),
    ("public_report_paths", "Public News / OSINT Report Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (GEOINT/IMINT/etc.)", "text"),
]


TARGET_TYPES = [
    "defensive_situation_assessment",
    "incident_reconstruction",
    "force_protection_review",
    "historical_event_analysis",
    "exercise_evaluation",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "actors",
    "events",
    "movements",
    "equipment",
    "terrain",
    "infrastructure",
    "civilian_sites",
    "event_paths",
    "imagery_paths",
    "sensor_paths",
    "public_report_paths",
    "stix_misp_paths",
    "source_limits",
    "configured_connectors",
}


DICT_FIELDS = {
    "scope",
    "authorization",
    "time_range",
}


SENSITIVE_TARGET_TYPES = {
    "defensive_situation_assessment",
    "force_protection_review",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR TACTICAL HARM/TARGETING
POLICY_BLOCK_PATTERNS = [
    r"\b(?:select|identify|rank|prioritize)\b[^\n]{0,140}\b(?:target|strike coordinate|kill chain|fire solution|weapon employment)\b",
    r"\b(?:plan|design|optimize)\b[^\n]{0,140}\b(?:attack route|ambush location|sniper position|breach point|interception window)\b",
    r"\b(?:provide|recommend)\b[^\n]{0,140}\b(?:munitions selection|lethality optimization|countermeasure evasion|radar jamming)\b",
    r"\b(?:sabotage|destroy|disable)\b[^\n]{0,140}\b(?:infrastructure|command post|logistics node|convoy)\b",
    r"\b(?:expose|reveal)\b[^\n]{0,140}\b(?:precise live location|current troop position|private personnel identity)\b",
]


SAFE_ALTERNATIVES = [
    "Provide authorized/defensive/non-targeting tactical intelligence: resolve events/units/movements, assess threat/capability/intent separately, evaluate civilian/friendly-force risk, and generate force-protection recommendations without providing targeting data or attack plans.",
    "Do not select targets, provide coordinates, plan attacks/sabotage, optimize lethality, or expose precise live locations of personnel/assets for harmful use.",
    "Separate Capability from Intent, Presence from Control, Movement from Attack, Observation from Verification, and Historical from Current State.",
    "Use deterministic arithmetic for distances/times. Apply strict location precision controls (Region/City/Area). Escalate consequential live-threat assessments to authorized human review.",
]


SECRET_PATTERNS = [
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S | re.I),
    ),
    (
        "PASSWORD_OR_TOKEN_ASSIGNMENT",
        re.compile(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|apikey|secret|"
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential)\b"
            r"\s*[:=]\s*[^\s,;\"']+"
        ),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}"),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"execute\s+(?:this\s+)?(?:script|code|macro)",
    r"send\s+(?:this\s+)?(?:document|data)",
    r"delete\s+(?:the\s+)?(?:record|log)",
    r"target\s+(?:this|here|that)",
]


# Regex helpers for tactical identifiers
LAT_LON_RE = re.compile(r"\b([-+]?\d{1,3}\.\d+)\s*,\s*([-+]?\d{1,3}\.\d+)\b")
UNIT_ID_RE = re.compile(r"\b(?:Unit|Detachment|Platoon|Company|Battalion|Brigade)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)
VEHICLE_RE = re.compile(r"\b(?:Tank|IFV|APC|Truck|Vehicle|Convoy|Aircraft|Helicopter|Drone|UAV|Ship|Vessel)\s*[A-Z0-9\-]*\b", re.I)


ENTITY_ROLE_KEYS = [
    "actor",
    "unit",
    "formation",
    "group",
    "organization",
]


EVENT_KEYS = [
    "event",
    "incident",
    "engagement",
    "observation",
]


MOVEMENT_KEYS = [
    "movement",
    "travel",
    "displacement",
    "route",
]


EQUIPMENT_KEYS = [
    "equipment",
    "vehicle",
    "platform",
    "asset",
    "weapon_system", # Only for identification class, not usage
]


LOCATION_PRECISION_MAP = {
    "country": "COUNTRY",
    "region": "REGION",
    "city": "CITY",
    "area": "AREA",
    "site": "SITE",
    "exact": "EXACT_AUTHORIZED_ONLY",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def normalize_key(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    return s.strip("_")


def parse_list(value: str) -> List[Any]:
    value = str(value or "").strip()
    if not value:
        return []

    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    normalized = value.replace(",", "\n")
    parts = [p.strip() for p in normalized.splitlines()]
    return [p for p in parts if p]


def parse_dict(value: str) -> Dict[str, Any]:
    value = str(value or "").strip()
    if not value:
        return {}

    try:
        parsed = json.loads(value)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    result: Dict[str, Any] = {}
    for line in value.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        result[key.strip()] = val.strip()
    return result


def listify(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return [value]


def unique_preserve_order(items: List[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) if isinstance(item, (dict, list)) else str(item)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def truncate_list(items: List[Any], limit: int) -> Tuple[List[Any], bool]:
    if len(items) <= limit:
        return items, False
    return items[:limit], True


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_secrets(text: str) -> Tuple[str, List[str]]:
    flags: List[str] = []
    if not text:
        return "", flags

    out = text
    for name, rx in SECRET_PATTERNS:
        if rx.search(out):
            flags.append(name)
            out = rx.sub("[REDACTED_SECRET]", out)

    return out, sorted(set(flags))


def detect_prompt_injection(text: str) -> List[str]:
    flags: List[str] = []
    low = normalize_text(text)
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, low, re.I):
            flags.append(pattern)
    return sorted(set(flags))


def safe_str(value: Any, limit: int = 300) -> str:
    return redact_secrets(str(value or ""))[0].strip()[:limit]


def content_tokens(text: str) -> List[str]:
    redacted, _ = redact_secrets(str(text or ""))
    low = normalize_text(redacted)
    return re.findall(r"[a-z0-9]+", low)


def content_fingerprint(text: str) -> str:
    tokens = content_tokens(text)
    if not tokens:
        return ""
    return sha256_text(" ".join(sorted(set(tokens))))[:32]


def get_field(rec: Dict[str, Any], keys: List[str], as_list: bool = False) -> Any:
    if not isinstance(rec, dict):
        return [] if as_list else None

    lower = {normalize_key(k): v for k, v in rec.items()}
    for key in keys:
        nk = normalize_key(key)
        if nk in lower and lower[nk] not in (None, ""):
            val = lower[nk]
            if as_list:
                return listify(val)
            if isinstance(val, list):
                return val[0] if val else None
            return val
    return [] if as_list else None


def sanitize_location(loc_str: str) -> Tuple[str, str]:
    """
    Returns (sanitized_loc, precision_level).
    Strips exact coordinates unless explicitly authorized (which this demo does not support fully).
    """
    if not loc_str:
        return "UNKNOWN", "UNKNOWN"
    
    # Check for Lat/Lon pattern
    match = LAT_LON_RE.search(loc_str)
    if match:
        # Replace with generic area marker to prevent leakage
        sanitized = LAT_LON_RE.sub("[COORDINATES_REDUCED_TO_AREA]", loc_str)
        return sanitized, "AREA"
        
    # Simple heuristics for other levels
    low = normalize_text(loc_str)
    if any(w in low for w in ["city", "town", "village"]):
        return loc_str, "CITY"
    if any(w in low for w in ["region", "province", "state", "district"]):
        return loc_str, "REGION"
    if any(w in low for w in ["base", "facility", "airport", "port"]):
        return loc_str, "SITE"
        
    return loc_str, "UNKNOWN"


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "actors": [],
        "events": [],
        "movements": [],
        "equipment": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "threat_assessments": [],
        "civilian_risk_flags": [],
    }


def add_note(parsed: Dict[str, Any], note_type: str, **kwargs: Any) -> None:
    if len(parsed.get("notes", [])) >= 200000:
        return
    note = {"type": note_type}
    note.update(kwargs)
    parsed["notes"].append(note)


def add_observation(parsed: Dict[str, Any], statement: str, source_id: str, evidence_id: str, context: str = "") -> None:
    if len(parsed.get("observations", [])) >= 200000:
        return

    redacted, secret_flags = redact_secrets(str(statement or "")[:1000])
    injection_flags = detect_prompt_injection(str(statement or ""))
    
    # Location Sanitization
    sanitized_redacted, precision = sanitize_location(redacted)
    
    if precision == "AREA" and "[COORDINATES_REDUCED]" in sanitized_redacted:
         add_note(parsed, "PRECISION_REDUCTION", detail="Exact coordinates detected and reduced to Area level for safety.", source_id=source_id)

    parsed["observations"].append({
        "observation_id": f"OBS-{uuid.uuid4()}",
        "statement": sanitized_redacted,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": context[:200],
        "state": "SOURCE_OBSERVED",
        "secret_flags": secret_flags,
        "prompt_injection_flags": injection_flags,
        "content_hash": sha256_text(str(statement or "")),
        "limitations": [
            "Observation records what was stated/published, not necessarily its factual truth.",
            "Location precision has been reduced where necessary for safety.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in tactical docs are ignored.")


def add_source(
    parsed: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    filename: str = "",
    file_hash: str = "",
    publisher: str = "",
    title: str = "",
    source_type: str = "",
    markings: str = "",
    content_fp: str = "",
) -> None:
    for s in parsed["sources"]:
        if s.get("source_id") == source_id:
            if file_hash and not s.get("file_hash"):
                s["file_hash"] = file_hash
            if publisher and not s.get("publisher"):
                s["publisher"] = publisher
            if title and not s.get("title"):
                s["title"] = title
            if content_fp and not s.get("content_fingerprint"):
                s["content_fingerprint"] = content_fp
            return

    parsed["sources"].append({
        "source_id": source_id,
        "evidence_id": evidence_id,
        "filename": filename,
        "file_hash": file_hash,
        "publisher": publisher,
        "title": title,
        "source_type": source_type or "UNKNOWN",
        "markings": markings,
        "content_fingerprint": content_fp,
        "retrieved_at": now_utc(),
        "state": "SOURCE_REGISTERED",
        "source_independence_state": "UNKNOWN",
        "limitations": [
            "Source registration is local provenance metadata.",
            "Multiple social posts sharing one video/image are not independent sources.",
        ],
    })


def add_actor(
    parsed: Dict[str, Any],
    name: Any,
    actor_type: Any,
    location: Any,
    time_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    norm = normalize_text(n)
    at = safe_str(actor_type, 100).upper() or "UNKNOWN"
    
    for a in parsed["actors"]:
        if a.get("normalized_name") == norm and a.get("actor_type") == at:
            return a.get("actor_id")

    aid = f"ACT-{uuid.uuid4()}"
    loc_san, prec = sanitize_location(location)
    
    parsed["actors"].append({
        "actor_id": aid,
        "name": n,
        "normalized_name": norm,
        "actor_type": at,
        "location_sanitized": loc_san,
        "location_precision": prec,
        "time_reference": safe_str(time_ref, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ACTOR_CANDIDATE",
        "limitations": [
            "Unit resolution requires corroborating evidence. One sighting is insufficient.",
            "Presence does not equal Control.",
        ],
    })
    return aid


def add_event(
    parsed: Dict[str, Any],
    desc: Any,
    event_type: Any,
    actors_involved: Any,
    location: Any,
    start_time: Any,
    end_time: Any,
    confidence: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    ed = safe_str(desc, 500)
    if not ed:
        return
        
    eid = f"EVT-{uuid.uuid4()}"
    loc_san, prec = sanitize_location(location)
    
    conf_norm = normalize_text(confidence).upper()
    canonical_conf = "UNKNOWN"
    if "HIGH" in conf_norm or "CONFIRMED" in conf_norm:
        canonical_conf = "SUPPORTED"
    elif "MED" in conf_norm or "PROBABLE" in conf_norm:
        canonical_conf = "PARTIALLY_SUPPORTED"
    elif "LOW" in conf_norm or "POSSIBLE" in conf_norm:
        canonical_conf = "SOURCE_REPORTED"
        
    parsed["events"].append({
        "event_id": eid,
        "description": ed,
        "event_type": safe_str(event_type, 100).upper() or "UNKNOWN",
        "actor_refs": listify(actors_involved)[:50],
        "location_sanitized": loc_san,
        "location_precision": prec,
        "start_time": safe_str(start_time, 100),
        "end_time": safe_str(end_time, 100),
        "confidence": canonical_conf,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "EVENT_PARSED",
        "limitations": [
            "Event reconstruction relies on temporal alignment of sources.",
            "Correlation does not prove causation.",
        ],
    })


def add_movement(
    parsed: Dict[str, Any],
    actor_ref: Any,
    origin: Any,
    destination: Any,
    direction: Any,
    speed_class: Any,
    timestamp: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    mid = f"MVMT-{uuid.uuid4()}"
    
    orig_san, orig_prec = sanitize_location(origin)
    dest_san, dest_prec = sanitize_location(destination)
    
    spd_norm = normalize_text(speed_class).upper()
    canonical_speed = "UNKNOWN"
    if "FOOT" in spd_norm or "WALK" in spd_norm:
        canonical_speed = "FOOT"
    elif "VEHICLE" in spd_norm or "CAR" in spd_norm or "TRUCK" in spd_norm:
        canonical_speed = "LIGHT_VEHICLE"
    elif "HEAVY" in spd_norm or "TANK" in spd_norm or "ARTILLERY" in spd_norm:
        canonical_speed = "HEAVY_VEHICLE"
        
    parsed["movements"].append({
        "movement_id": mid,
        "actor_ref": actor_ref,
        "origin_sanitized": orig_san,
        "origin_precision": orig_prec,
        "destination_sanitized": dest_san,
        "destination_precision": dest_prec,
        "direction": safe_str(direction, 100),
        "speed_class": canonical_speed,
        "timestamp": safe_str(timestamp, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "MOVEMENT_PARSED",
        "limitations": [
            "Movement observation does not prove intent.",
            "Routes are analyzed for defensive/humanitarian context only.",
        ],
    })


def add_equipment(
    parsed: Dict[str, Any],
    eq_desc: Any,
    eq_class: Any,
    quantity: Any,
    status: Any, # Visible, Active, Damaged, Decoy?
    location: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    eid = f"EQP-{uuid.uuid4()}"
    
    loc_san, prec = sanitize_location(location)
    
    stat_norm = normalize_text(status).upper()
    canonical_status = "VISIBLE"
    if "ACTIVE" in stat_norm or "OPERATIONAL" in stat_norm:
        canonical_status = "OPERATIONAL_CANDIDATE"
    elif "DAMAGED" in stat_norm or "DISABLED" in stat_norm:
        canonical_status = "DAMAGED"
    elif "DECOY" in stat_norm or "MOCKUP" in stat_norm:
        canonical_status = "DECOY_POSSIBLE"
        
    qty_val = None
    if quantity:
        try:
            qty_val = int(str(quantity).replace(",", ""))
        except:
            pass

    parsed["equipment"].append({
        "equipment_id": eid,
        "description": safe_str(eq_desc, 300),
        "equipment_class": safe_str(eq_class, 100).upper() or "UNKNOWN",
        "quantity_visible": qty_val,
        "status": canonical_status,
        "location_sanitized": loc_san,
        "location_precision": prec,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "EQUIPMENT_PARSED",
        "limitations": [
            "Visible equipment != Operational readiness.",
            "Decoys/training props are possible explanations.",
        ],
    })


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    if not isinstance(rec, dict):
        return

    rec_ctx = context or "json_record"

    text_blob = json.dumps(rec, ensure_ascii=False, default=str)[:12000]
    process_text_block(text_blob, source_id, evidence_id, parsed, context=rec_ctx)

    # Resolve Actors
    actor_refs = []
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                aname = val.get("name") or val.get("id")
                atype = val.get("type") or key.upper()
                aloc = val.get("location")
                atime = val.get("time")
            else:
                aname = str(val)
                atype = key.upper()
                aloc = rec.get("location")
                atime = rec.get("time")
            
            aref = add_actor(parsed, aname, atype, aloc, atime, source_id, evidence_id, f"{rec_ctx}/{key}")
            if aref:
                actor_refs.append(aref)

    primary_actor_ref = actor_refs[0] if actor_refs else None

    # Resolve Events
    evt_items = get_field(rec, EVENT_KEYS, as_list=True)
    for item in evt_items:
        if isinstance(item, dict):
            add_event(
                parsed,
                item.get("description") or item.get("summary"),
                item.get("type"),
                item.get("actors") or actor_refs,
                item.get("location"),
                item.get("start_time") or item.get("timestamp"),
                item.get("end_time"),
                item.get("confidence"),
                source_id,
                evidence_id,
                f"{rec_ctx}/event"
            )

    # Resolve Movements
    mvmt_items = get_field(rec, MOVEMENT_KEYS, as_list=True)
    for item in mvmt_items:
        if isinstance(item, dict):
            add_movement(
                parsed,
                item.get("actor") or primary_actor_ref,
                item.get("origin") or item.get("from"),
                item.get("destination") or item.get("to"),
                item.get("direction"),
                item.get("speed") or item.get("mode"),
                item.get("timestamp"),
                source_id,
                evidence_id,
                f"{rec_ctx}/movement"
            )

    # Resolve Equipment
    eq_items = get_field(rec, EQUIPMENT_KEYS, as_list=True)
    for item in eq_items:
        if isinstance(item, dict):
            add_equipment(
                parsed,
                item.get("description") or item.get("model"),
                item.get("class") or item.get("type"),
                item.get("quantity") or item.get("count"),
                item.get("status"),
                item.get("location"),
                source_id,
                evidence_id,
                f"{rec_ctx}/equipment"
            )


def process_text_block(
    text: str,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    raw = str(text or "")
    if not raw.strip():
        return

    redacted, secret_flags = redact_secrets(raw)
    injection_flags = detect_prompt_injection(raw)

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Tactical texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["moved", "travel", "advance", "retreat"]):
        signals.append("MOVEMENT_CONTEXT")
    if any(k in low for k in ["explosion", "fire", "gunshot", "blast"]):
        signals.append("ENGAGEMENT_CONTEXT")
    if any(k in low for k in ["tank", "truck", "aircraft", "ship", "drone"]):
        signals.append("EQUIPMENT_CONTEXT")
    if any(k in low for k in ["civilian", "hospital", "school", "residential"]):
        signals.append("CIVILIAN_RISK_CONTEXT")
    if any(k in low for k in ["fog", "rain", "night", "visibility"]):
        signals.append("ENVIRONMENTAL_CONTEXT")

    if signals:
        add_note(parsed, "TACTICAL_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_TACT_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "event" in fname or "incident" in fname:
        return "EVENT_LOG"
    if "movement" in fname or "track" in fname:
        return "MOVEMENT_TRACK"
    if "image" in fname or "photo" in fname or "geo" in fname:
        return "MEDIA_METADATA"

    return "GENERIC_TACT_EVIDENCE"


def walk_json(
    data: Any,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    depth: int = 0,
    path: str = "",
) -> None:
    if depth > 14 or len(parsed.get("observations", [])) > 200000:
        return

    if isinstance(data, dict):
        process_json_record(data, source_id, evidence_id, parsed, context=path or "json")
        for k, v in data.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_json(v, source_id, evidence_id, parsed, depth + 1, new_path)
    elif isinstance(data, list):
        for item in data[:100000]:
            walk_json(item, source_id, evidence_id, parsed, depth + 1, path)
    elif isinstance(data, str):
        process_text_block(data, source_id, evidence_id, parsed, context=path or "json_string")


def process_json_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    data = json.loads(raw)
    kind = classify_json_payload(data, path.name)

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    walk_json(data, source_id, evidence_id, parsed)
    return kind, parsed


def process_csv_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)
    kind = "CSV_TACT_DATA"

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        sample = f.read(1_000_000)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t| ")
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        for idx, row in enumerate(reader):
            if idx >= 200000:
                break
            process_json_record(row, source_id, evidence_id, parsed, context=f"csv_row_{idx}")

    return kind, parsed


def process_text_file(path: Path, source_id: str, evidence_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:10_000_000]
    redacted_raw, _ = redact_secrets(raw)
    fp = content_fingerprint(redacted_raw)

    low = redacted_raw.lower()[:30000]
    if "incident" in low or "report" in low:
        kind = "TEXT_INCIDENT_REPORT"
    elif "movement" in low or "track" in low:
        kind = "TEXT_MOVEMENT_LOG"
    else:
        kind = "TEXT_GENERIC_TACT_DOC"

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    for line_no, line in enumerate(raw.splitlines()[:200000]):
        if line.strip():
            process_text_block(line, source_id, evidence_id, parsed, context=f"text_line_{line_no}")

    return kind, parsed


def detect_format(path: Path) -> Dict[str, str]:
    suffix = path.suffix.lower()

    try:
        with path.open("rb") as f:
            head = f.read(256)
    except Exception as exc:
        return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream", "format_error": str(exc)}

    binary_suffixes = {
        ".exe", ".dll", ".sys", ".elf", ".so", ".dylib", ".bin", ".fw", ".img",
        ".iso", ".apk", ".jar", ".class", ".zip", ".gz", ".tar", ".7z", ".rar",
        ".pcap", ".pcapng", ".cap", ".msi", ".cab", ".pdf", ".docx", ".xlsx",
        ".pptx", ".mp3", ".wav", ".mp4", ".avi", ".jpg", ".jpeg", ".png", ".tif", ".tiff",
    }

    if suffix in binary_suffixes:
        return {"format_detected": "BINARY_ARTIFACT", "mime_type": "application/octet-stream"}

    stripped = head.lstrip()

    if suffix == ".json" or stripped.startswith(b"{") or stripped.startswith(b"["):
        return {"format_detected": "JSON", "mime_type": "application/json"}

    if suffix in {".csv", ".tsv"}:
        return {"format_detected": "CSV", "mime_type": "text/csv"}

    if b"," in head and b"\n" in head and all(b in b"\x09\x0a\x0d\x20" or 32 <= b <= 126 for b in head[:64]):
        return {"format_detected": "CSV", "mime_type": "text/csv"}

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".tact", ".evt"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_tact_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path = Path(path_str).expanduser()
    source_id = f"SRC-{uuid.uuid4()}"
    evidence_id = f"EVD-{uuid.uuid4()}"

    file_evidence: Dict[str, Any] = {
        "evidence_id": evidence_id,
        "source_id": source_id,
        "case_id": case_id,
        "task_id": task_id,
        "path": str(path),
        "filename": path.name,
        "retrieved_at": now_utc(),
        "acquisition_method": "local_authorized_or_public_file_access",
        "status": "PENDING",
        "limitations": [
            "No targeting, no strike planning, no real-time operational exploitation.",
            "Binary artifacts are hash/metadata preserved only.",
            "Tactical documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Location precision strictly controlled.",
        ],
    }

    parsed = empty_parsed()

    if not path.exists():
        file_evidence["status"] = "FAILED_FILE_NOT_FOUND"
        return file_evidence, parsed

    try:
        st = path.stat()
        file_evidence["size_bytes"] = st.st_size
        file_evidence["filesystem_modified_at"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    except Exception as exc:
        file_evidence["status"] = "FAILED_STAT"
        file_evidence["error"] = str(exc)
        return file_evidence, parsed

    try:
        file_evidence["sha256"] = sha256_file(path)
    except Exception as exc:
        file_evidence["sha256_error"] = str(exc)

    fmt = detect_format(path)
    file_evidence.update(fmt)
    format_detected = file_evidence.get("format_detected", "UNKNOWN")

    try:
        if format_detected == "JSON":
            kind, parsed = process_json_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "CSV":
            kind, parsed = process_csv_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "TEXT":
            kind, parsed = process_text_file(path, source_id, evidence_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "BINARY_ARTIFACT":
            file_evidence["content_kind"] = "BINARY_TACT_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary tactical document/media detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse images deeply, or access restricted sensors."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_actor_count"] = len(parsed.get("actors", []))
    file_evidence["parsed_event_count"] = len(parsed.get("events", []))
    file_evidence["parsed_mvmt_count"] = len(parsed.get("movements", []))

    return file_evidence, parsed


def aggregate_parsed(parsed_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    agg = empty_parsed()
    for p in parsed_list:
        for key in agg.keys():
            if isinstance(agg[key], list) and isinstance(p.get(key), list):
                agg[key].extend(p[key])
        for key in agg.keys():
            if isinstance(agg[key], list):
                agg[key] = unique_preserve_order(agg[key])[:200000]
    return agg


def build_source_independence(parsed: Dict[str, Any]) -> None:
    sources = parsed.get("sources", [])
    hash_groups: Dict[str, List[str]] = defaultdict(list)
    fp_groups: Dict[str, List[str]] = defaultdict(list)
    publisher_groups: Dict[str, List[str]] = defaultdict(list)

    for s in sources:
        sid = s.get("source_id")
        fh = s.get("file_hash")
        fp = s.get("content_fingerprint")
        pub = normalize_text(s.get("publisher") or "")
        if fh:
            hash_groups[fh].append(sid)
        if fp:
            fp_groups[fp].append(sid)
        if pub:
            publisher_groups[pub].append(sid)

    for s in sources:
        fh = s.get("file_hash")
        fp = s.get("content_fingerprint")
        pub = normalize_text(s.get("publisher") or "")

        if fh and len(hash_groups.get(fh, [])) > 1:
            s["source_independence_state"] = "DEPENDENT_COPIES"
            s["source_family_count"] = 1
        elif fp and len(fp_groups.get(fp, [])) > 1:
            s["source_independence_state"] = "DEPENDENT_CONTENT_FAMILY"
            s["source_family_count"] = 1
        elif pub and len(publisher_groups.get(pub, [])) > 1:
            s["source_independence_state"] = "PARTIALLY_DEPENDENT_PENDING_REVIEW"
            s["source_family_count"] = 1
        elif len(sources) > 1:
            s["source_independence_state"] = "UNKNOWN_POTENTIALLY_INDEPENDENT"
            s["source_family_count"] = len(sources)
        else:
            s["source_independence_state"] = "SINGLE_SOURCE"
            s["source_family_count"] = 1


def assess_threat_and_civilian_risk(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates threat level based on observed activity/equipment, while flagging civilian risk.
    """
    assessments = []
    
    # Simple heuristic: High threat if heavy equipment + movement + engagement events
    heavy_eq = [e for e in parsed.get("equipment", []) if e.get("equipment_class") in ["HEAVY_VEHICLE", "ARMORED", "ARTILLERY"]]
    engagements = [ev for ev in parsed.get("events", []) if ev.get("event_type") in ["ENGAGEMENT", "EXPLOSION", "FIRE"]]
    
    threat_score = "LOW"
    if heavy_eq and engagements:
        threat_score = "HIGH"
    elif heavy_eq or engagements:
        threat_score = "MODERATE"
        
    # Civilian Risk Check
    civ_risk = "UNKNOWN"
    # In a real system, we'd cross-reference location with known civilian zones
    # Here we just flag if any civilian keywords appeared in observations
    obs_text = " ".join([o.get("statement", "") for o in parsed.get("observations", [])]).lower()
    if any(k in obs_text for k in ["civilian", "hospital", "school", "residential", "market"]):
        civ_risk = "MEDIUM" # Conservative estimate
        
    assessments.append({
        "assessment_id": f"TAC-{uuid.uuid4()}",
        "threat_level": threat_score,
        "civilian_risk": civ_risk,
        "basis": f"Heavy Equipment Count: {len(heavy_eq)}, Engagement Events: {len(engagements)}",
        "limitations": [
            "Heuristic assessment. Requires human verification.",
            "Threat level refers to defensive concern, NOT target priority.",
        ]
    })
    
    return assessments


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting Event Times for same description
    evt_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for ev in parsed.get("events", []):
        desc = ev.get("description")
        if desc:
            evt_map[desc].append(ev)
            
    for desc, group in evt_map.items():
        times = {g.get("start_time") for g in group if g.get("start_time")}
        if len(times) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "EVENT_TIME_CONFLICT",
                "subject": desc[:50],
                "values": list(times),
                "possible_explanations": [
                    "Different events with similar descriptions",
                    "Time zone error",
                    "Stale media reuse",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify original source timestamps.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    movements = parsed.get("movements", [])
    equipment = parsed.get("equipment", [])
    
    if not movements and not equipment:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient tactical data to form movement or capability hypotheses.",
            "supporting_facts": ["No movements or equipment parsed."],
            "opposing_facts": [],
            "unknowns": ["activity type", "actor presence"],
            "next_test": "Import valid sensor/event exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if movements:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed movement indicates logistical relocation OR operational deployment.",
            "supporting_facts": [f"{len(movements)} movement record(s) found."],
            "opposing_facts": ["Could be training exercise."],
            "unknowns": ["intent", "destination purpose"],
            "falsification_conditions": ["Destination confirmed as rear-area storage."],
            "next_test": "Analyze destination infrastructure and historical patterns.",
            "status": "ANALYTICAL",
        })

    if any(e.get("status") == "DECOY_POSSIBLE" for e in equipment):
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Some observed equipment may be decoys or non-operational.",
            "supporting_facts": ["Status flagged as DECOY_POSSIBLE."],
            "opposing_facts": ["Visual confirmation limited."],
            "unknowns": ["actual inventory"],
            "falsification_conditions": ["Higher-res imagery confirms functional systems."],
            "next_test": "Handoff to IMINT for detailed technical analysis.",
            "status": "CAUTION",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    events = parsed.get("events", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized tactical evidence exists?",
            "missing_evidence": "No local TACTINT artifact supplied.",
            "likely_source": "Incident Report, Sensor Log, Public Media Archive.",
            "specialist_owner": "TACTINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline tactical awareness.",
            "safety_boundary": "No targeting, no classified solicitation.",
        })

    if events and not any(e.get("confidence") == "SUPPORTED" for e in events):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are reported events independently verified?",
            "missing_evidence": "Confidence remains SOURCE_REPORTED.",
            "likely_source": "Second Independent Source, Physical Evidence.",
            "specialist_owner": "TACTINT / GEOINT",
            "priority": "HIGH",
            "expected_information_value": "Prevents acting on false alarms.",
            "safety_boundary": "Do not assume propaganda is fact.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    equipment = parsed.get("equipment", [])
    events = parsed.get("events", [])
    
    if any(e.get("equipment_class") in ["RADAR", "COMMS", "EW"] for e in equipment):
        handoffs.append({
            "specialist": "ELINT / SIGINT",
            "reason": "Electronic/Emission systems identified.",
            "expected_output": "Emitter classification (non-targeting).",
            "question": "What is the general class/activity of these emissions?",
        })
        
    if events:
        handoffs.append({
            "specialist": "INCIDENTINT / LEGALINT",
            "reason": "Engagement/Incident events detected.",
            "expected_output": "Root cause, legal implications, attribution verification.",
            "question": "Who is responsible and what are the rules of engagement implications?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "TACTINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Is current situational awareness sufficient for defensive decisions?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["threat_assessments"] = assess_threat_and_civilian_risk(parsed)
    parsed["contradictions"] = detect_contradictions(parsed)
    parsed["hypotheses"] = build_hypotheses(parsed)
    parsed["knowledge_gaps"] = build_knowledge_gaps(payload, files or [], parsed)
    parsed["specialist_handoffs"] = build_specialist_handoffs(parsed)
    return parsed


def build_next_best_action(
    payload: Dict[str, Any],
    policy: Dict[str, Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> Dict[str, str]:
    threats = parsed.get("threat_assessments", [])
    high_threat = any(t.get("threat_level") == "HIGH" for t in threats)
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited targeting, strike planning, or harm facilitation behavior.",
            "reason": "TACTINT is defensive intelligence, not an attack planner.",
            "owner": "TACTINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized incident/sensor/event exports before analysis.",
            "reason": "No TACTINT evidence artifact available.",
            "owner": "TACTINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if high_threat:
        return {
            "action": "Activate authorized force-protection protocols. Increase monitoring. Verify evacuation routes.",
            "reason": "High defensive threat indicated by equipment/activity correlation.",
            "owner": "OPS COMMANDER / SECURITY LEAD",
            "expected_output": "Enhanced defensive posture.",
        }

    return {
        "action": "Continue passive monitoring. Seek independent verification of reported events.",
        "reason": "Threat level moderate/low. Avoid premature escalation.",
        "owner": "TACTINT Analyst",
        "expected_output": "Updated situation picture.",
    }


def build_collection_plan(
    payload: Dict[str, Any],
    questions: List[Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    plan = []
    priority = 1
    questions_limited, _ = truncate_list([str(q) for q in questions], 8)

    has_files = bool(files)
    has_events = bool(parsed.get("events"))
    has_movements = bool(parsed.get("movements"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General TACTINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Authorized / defensive / non-targeting tactical intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_tactical_questions_scope",
        "TACTINT Manager",
        "Convert objective into tactical questions, allowed sources, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_tactical_evidence",
        "local evidence store",
        "Store original reports/logs and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "TactEvidenceObject with SHA256.",
    )

    add(
        "parse_event_movement_equipment_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT tactical metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized events/movements/equipment.",
    )

    add(
        "apply_location_precision_control",
        "local filter",
        "Reduce all location data to Region/City/Area level unless explicitly authorized.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_SAFETY_CHECK",
        "Safe-granularity spatial data.",
        safety_risk="CRITICAL_IF_EXACT_COORDS_LEAKED",
    )

    add(
        "assess_civilian_risk_context",
        "TACTINT Analyst",
        "Identify potential civilian proximity in AOI for protection planning.",
        "PLANNED_ANALYTIC",
        "Civilian Risk Register.",
        safety_risk="HIGH_IF_IGNORED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "area_of_interest",
        "questions",
        "actors",
        "events",
        "movements",
        "equipment",
    ]

    parts: List[str] = []
    for key in scanned_fields:
        val = payload.get(key)
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        elif isinstance(val, dict):
            parts.append(json.dumps(val, ensure_ascii=False, default=str))
        else:
            parts.append(str(val or ""))

    scanned = " \n ".join(parts).lower()

    blocked_reasons: List[str] = []
    for pat in POLICY_BLOCK_PATTERNS:
        rx = re.compile(pat, re.I)
        for m in rx.finditer(scanned):
            start = max(0, m.start() - 180)
            prefix = scanned[start:m.start()]
            if NEGATION_RE.search(prefix):
                continue
            blocked_reasons.append(pat)
            break

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive tactical context detected. Analysis must remain authorized, defensive, and non-targeting. "
            "No strike planning, no aimpoints, no real-time operational exploitation."
        )

    if payload.get("civilian_sites") or "civilian" in scanned:
        human_review_required = True
        safety_notes.append(
            "Civilian context detected. Prioritize harm avoidance. Do not expose vulnerable populations unnecessarily."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal targeting, strike planning, or harm facilitation."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    if human_review_required:
        return {
            "status": "HUMAN_REVIEW_REQUIRED",
            "reasons": [],
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "No obvious hard policy violation detected, but sensitive tactical/civilian context applies. "
                "Conclusions must remain defensive, evidence-linked, and human-reviewed before consequential action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": (
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful tactical evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "area_of_interest", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No TACTINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "event_paths",
        "imagery_paths",
        "sensor_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No tactical evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Tactical situation is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "What is the current tactical situation in the Area of Interest?",
        "Which actors/units are present or reported?",
        "What activities (movement/logistics/engagement) are observed?",
        "What equipment is visible, and is it operational?",
        "What is the estimated threat level for friendly forces?",
        "Are there civilians or protected sites in the vicinity?",
        "How reliable and independent are the sources?",
        "What remains unknown regarding intent or capability?",
        "What defensive actions should be considered?",
        "What specialist handoffs are required for verification?",
    ]


class TraceAtlasTACTINTPanel(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1380x940")
        self.minsize(1100, 760)

        self.entries: Dict[str, Any] = {}
        self.last_result: Dict[str, Any] = {}

        self.analyzed_files: List[Dict[str, Any]] = []
        self.parsed: Dict[str, Any] = empty_parsed()

        self._configure_style()
        self._build_ui()
        self._set_defaults()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.configure(bg="#0b0f19")
        style.configure("TFrame", background="#0b0f19")
        style.configure("TLabel", background="#0b0f19", foreground="#e5e7eb", font=("Segoe UI", 10))
        style.configure("Header.TLabel", background="#0b0f19", foreground="#a78bfa", font=("Segoe UI", 17, "bold")) # Violet accent for Tactical
        style.configure("Subheader.TLabel", background="#0b0f19", foreground="#94a3b8", font=("Segoe UI", 9))
        style.configure("TNotebook", background="#0b0f19", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground="#111827", foreground="#e5e7eb", insertcolor="#ffffff", bordercolor="#334155")
        style.configure("TCombobox", fieldbackground="#111827", foreground="#e5e7eb", arrowcolor="#e5e7eb", bordercolor="#334155")
        style.configure("TButton", padding=7, font=("Segoe UI", 10, "bold"), background="#1f2937", foreground="#e5e7eb", bordercolor="#475569")
        style.map("TButton", background=[("active", "#334155")], foreground=[("active", "#ffffff")])
        style.configure("Vertical.TScrollbar", background="#1f2937", troughcolor="#0b0f19", arrowcolor="#e5e7eb")

    def _build_ui(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))
        ttk.Label(header, text="TraceAtlas TACTINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Authorized / defensive / non-targeting / force-protection tactical intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT event/movement/equipment parsing only • "
                "No targeting / No strike coords / No attack plans / No real-time exploitation • "
                "Capability != Intent • Presence != Control • Precision Controlled"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="TACTINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Tact Plan / Evidence")

        self._build_input_tab()
        self._build_output_tab()

    def _build_input_tab(self) -> None:
        container = ttk.Frame(self.input_tab)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg="#0b0f19", highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.form = ttk.Frame(self.canvas)

        self.form.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas_window = self.canvas.create_window((0, 0), window=self.form, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        row = 0
        for key, label, kind in FIELDS:
            ttk.Label(self.form, text=label).grid(row=row, column=0, sticky="nw", padx=10, pady=6)
            if kind == "entry":
                widget = ttk.Entry(self.form, width=102)
            elif kind == "combo":
                widget = ttk.Combobox(self.form, values=TARGET_TYPES if key == "target_type" else [], width=100, state="readonly")
            else:
                widget = tk.Text(self.form, height=3, width=102, bg="#111827", fg="#e5e7eb", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Segoe UI", 10), wrap="word")
            widget.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        buttons1 = ttk.Frame(self.input_tab)
        buttons1.pack(fill="x", padx=10, pady=(12, 4))
        buttons2 = ttk.Frame(self.input_tab)
        buttons2.pack(fill="x", padx=10, pady=(0, 12))

        ttk.Button(buttons1, text="Add Event Reports", command=self.add_events).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Imagery Metadata", command=self.add_imagery).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Sensor Logs", command=self.add_sensors).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Public Reports", command=self.add_public).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local TACTINT Evidence", command=self.analyze_local_tact).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Tact Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#ddd6fe", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "TACT-CASE-001")
        self.set_widget_value("task_id", "TACT-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive tactical intelligence using evidence-first methods.")
        self.set_widget_value("area_of_interest", "Illustrative Example Sector Alpha")
        self.set_widget_value("target_type", "defensive_situation_assessment")
        self.set_widget_value("questions", "\n".join(default_questions({"area_of_interest": "Illustrative Example Sector Alpha"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["official_incident_log", "public_media_archive"], "prohibited_actions": ["generate_target_list", "provide_strike_coords"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_force_protection_review"}, indent=2))
        self.set_widget_value("configured_connectors", "None configured.")

    def get_widget_value(self, key: str) -> str:
        widget = self.entries.get(key)
        if widget is None: return ""
        if isinstance(widget, tk.Text): return widget.get("1.0", "end-1c").strip()
        if isinstance(widget, ttk.Combobox): return widget.get().strip()
        if isinstance(widget, ttk.Entry): return widget.get().strip()
        return ""

    def set_widget_value(self, key: str, value: str) -> None:
        widget = self.entries.get(key)
        if widget is None: return
        if isinstance(widget, tk.Text):
            widget.delete("1.0", "end")
            widget.insert("1.0", value)
        elif isinstance(widget, ttk.Combobox):
            widget.set(value)
        elif isinstance(widget, ttk.Entry):
            widget.delete(0, "end")
            widget.insert(0, value)

    def collect_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        for key, _, _ in FIELDS:
            raw = self.get_widget_value(key)
            if key in LIST_FIELDS: payload[key] = parse_list(raw)
            elif key in DICT_FIELDS: payload[key] = parse_dict(raw)
            else: payload[key] = raw
        payload["generated_at"] = now_utc()
        payload["panel_version"] = APP_VERSION
        payload["operating_mode"] = "PLANNING_ONLY_AUTHORIZED_DEFENSIVE_NON_TARGETING"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_events(self): self._append_paths("event_paths", filedialog.askopenfilenames(title="Select Event Reports", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_imagery(self): self._append_paths("imagery_paths", filedialog.askopenfilenames(title="Select Imagery Metadata", filetypes=[("Meta", "*.json *.txt"), ("All", "*.*")]), "Added")
    def add_sensors(self): self._append_paths("sensor_paths", filedialog.askopenfilenames(title="Select Sensor Logs", filetypes=[("Logs", "*.json *.csv *.txt *.log"), ("All", "*.*")]), "Added")
    def add_public(self): self._append_paths("public_report_paths", filedialog.askopenfilenames(title="Select Public Reports", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_stix_misp(self): self._append_paths("stix_misp_paths", filedialog.askopenfilenames(title="Select STIX/MISP", filetypes=[("Intel", "*.json *.xml"), ("All", "*.*")]), "Added")

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        result = {"mode": "POLICY_SCREEN_ONLY", "policy_screen": policy}
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Policy Blocked.")
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning("Review", "Human Review Required.")
        else:
            messagebox.showinfo("OK", "Allowed.")

    def analyze_local_tact(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["event_paths", "imagery_paths", "sensor_paths", "public_report_paths", "stix_misp_paths"]
        all_paths = []
        seen = set()
        for field in path_fields:
            for p in payload.get(field, []):
                sp = str(p).strip()
                if sp and sp not in seen:
                    seen.add(sp)
                    all_paths.append(sp)

        if not all_paths:
            messagebox.showwarning("No Evidence", "Add files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing...\n")
        self.notebook.select(self.output_tab)
        self.update()

        files = []
        parsed_list = []
        for p in all_paths[:30]:
            f, parsed = analyze_tact_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nEvents: {len(aggregated['events'])}\nMovements: {len(aggregated['movements'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("events") and not self.parsed.get("movements"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "actors_preview": self.parsed.get("actors", [])[:100],
            "events_preview": self.parsed.get("events", [])[:100],
            "movements_preview": self.parsed.get("movements", [])[:100],
            "equipment_preview": self.parsed.get("equipment", [])[:100],
            "threat_assessments": self.parsed.get("threat_assessments", []),
            "hypotheses": self.parsed.get("hypotheses", []),
            "knowledge_gaps": self.parsed.get("knowledge_gaps", []),
            "specialist_handoffs": self.parsed.get("specialist_handoffs", []),
            "next_best_action": next_action,
            "collection_plan": collection_plan,
        }
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

    def _build_local_analysis_report(self, files, parsed, payload, policy) -> Dict[str, Any]:
        return {
            "mode": "LOCAL_DETERMINISTIC_TACTINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "actors": parsed.get("actors", [])[:300],
            "events": parsed.get("events", [])[:300],
            "movements": parsed.get("movements", [])[:300],
            "equipment": parsed.get("equipment", [])[:300],
            "threat_assessments": parsed.get("threat_assessments", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No targeting, no strike planning, no real-time ops.",
                "Capability != Intent.",
                "Location precision reduced for safety.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def export_json(self) -> None:
        if not self.last_result: self.generate_plan()
        data = self.last_result
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Saved", path)

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            messagebox.showinfo("Copied", "Output copied.")

    def clear_form(self) -> None:
        if messagebox.askyesno("Confirm", "Clear all?"):
            self._set_defaults()
            self.output.delete("1.0", "end")
            self.last_result = {}
            self.analyzed_files = []
            self.parsed = empty_parsed()


if __name__ == "__main__":
    try:
        app = TraceAtlasTACTINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")