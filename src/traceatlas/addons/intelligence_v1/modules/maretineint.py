import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
from .panel_state import sync_inputs, invalidate, begin_work, apply_result
import re
import csv
import hashlib
import uuid

from collections import defaultdict, Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


APP_TITLE = "TraceAtlas MARINT AI Employee — Lawful / Public-Authorized / Evidence-First / Safety-Aware Maritime Intelligence Panel"
APP_VERSION = "TraceAtlas MARINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_vessel_or_port", "Target Vessel / IMO / Port Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "MARINT Questions", "text"),

    ("vessels", "Vessels (IMO/MMSI/Name)", "text"),
    ("owners", "Owners / Operators / Managers", "text"),
    ("ports", "Ports / Terminals / Anchorages", "text"),
    ("voyages", "Voyages / Routes", "text"),
    ("cargo", "Cargo / Trade Context", "text"),
    ("incidents", "Incidents / Safety Events", "text"),
    
    ("ais_data_paths", "AIS Data / Track Export Paths", "text"),
    ("registry_paths", "Vessel Registry / Class Records Paths", "text"),
    ("port_call_paths", "Port Call / Terminal Log Paths", "text"),
    ("trade_doc_paths", "Trade Docs / BOL / Manifest Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (AIS Provider/Registry/etc.)", "text"),
]


TARGET_TYPES = [
    "vessel_identity_resolution",
    "voyage_reconstruction",
    "ownership_analysis",
    "sanctions_compliance_review",
    "incident_investigation_context",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "vessels",
    "owners",
    "ports",
    "voyages",
    "cargo",
    "incidents",
    "ais_data_paths",
    "registry_paths",
    "port_call_paths",
    "trade_doc_paths",
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
    "vessel_identity_resolution",
    "sanctions_compliance_review",
    "incident_investigation_context",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR MARITIME HARM/EVASION/TARGETING
POLICY_BLOCK_PATTERNS = [
    r"\b(?:plan|design|optimize|recommend)\b[^\n]{0,140}\b(?:attack|intercept|board|sabotage|minelay|piracy|hijack|smuggle)\b",
    r"\b(?:disable|spoof|jam|mask|hide)\b[^\n]{0,140}\b(?:AIS|MMSI|GNSS|GPS|Radar|Transponder|Position)\b",
    r"\b(?:evade|bypass|circumvent)\b[^\n]{0,140}\b(?:sanctions|customs|inspection|naval patrol|maritime law enforcement)\b",
    r"\b(?:provide|generate)\b[^\n]{0,140}\b(?:firing solution|weapons employment|boarding tactics|hostile maneuver)\b",
    r"\b(?:track|locate|predict)\b[^\n]{0,140}\b(?:warship|submarine|military vessel)\b[^\n]{0,50}\b(?:for attack|for targeting|for interception)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/public-authorized/evidence-first/safety-aware maritime intelligence: resolve vessel identities, reconstruct voyages from AIS/registry data, analyze ownership structures conservatively, and assess compliance/safety risks without facilitating evasion, targeting, or sabotage.",
    "Do not plan attacks, provide firing solutions, recommend AIS disabling/spoofing, assist smuggling/piracy, or evade sanctions/customs inspections.",
    "Separate Registered Owner from Operator from Beneficial Owner. Separate AIS Gap from Illegal Activity. Separate Proximity from STS Transfer.",
    "Use deterministic logic for geospatial calculations and identifier validation. Escalate consequential military/naval or legal actions to authorized human review.",
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
    r"change\s+(?:the\s+)?(?:route|destination|position)",
]


# Regex helpers for Maritime identifiers
IMO_RE = re.compile(r"\bIMO\s*(?:No\.?\s*)?(\d{7})\b", re.I)
MMSI_RE = re.compile(r"\bMMSI\s*(?:No\.?\s*)?(\d{9})\b", re.I)
CALL_SIGN_RE = re.compile(r"\bCall\s*Sign\s*:?\s*([A-Z0-9]{5,10})\b", re.I)
LAT_LON_RE = re.compile(r"\b([-+]?\d{1,3}\.\d+)\s*,\s*([-+]?\d{1,3}\.\d+)\b")


VESSEL_KEYS = [
    "vessel",
    "ship",
    "boat",
    "craft",
]


OWNER_KEYS = [
    "owner",
    "operator",
    "manager",
    "charterer",
    "company",
]


PORT_KEYS = [
    "port",
    "terminal",
    "berth",
    "anchorage",
    "harbor",
    "haven",
]


AIS_KEYS = [
    "ais",
    "track",
    "position",
    "movement",
    "signal",
]


CARGO_KEYS = [
    "cargo",
    "manifest",
    "bol",
    "bill of lading",
    "container",
    "bulk",
    "tanker",
]


INCIDENT_KEYS = [
    "incident",
    "accident",
    "collision",
    "grounding",
    "fire",
    "spill",
    "pollution",
]


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


def validate_imo(imo_str: str) -> bool:
    """Simple checksum validation for IMO numbers."""
    digits = "".join(filter(str.isdigit, imo_str or ""))
    if len(digits) != 7:
        return False
    # Standard IMO checksum algorithm
    total = sum(int(d) * (7 - i) for i, d in enumerate(digits[:-1]))
    return (total % 10) == int(digits[-1])


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
    if any(w in low for w in ["city", "town", "port"]):
        return loc_str, "CITY"
    if any(w in low for w in ["region", "state", "country"]):
        return loc_str, "REGION"
    if any(w in low for w in ["anchorage", "terminal", "berth"]):
        return loc_str, "SITE"
        
    return loc_str, "UNKNOWN"


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "vessels": [],
        "owners": [],
        "ports": [],
        "voyages": [],
        "ais_obs": [],
        "cargo": [],
        "incidents": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "risk_dimensions": {},
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
         add_note(parsed, "PRECISION_REDUCTION", detail="Exact coordinates detected and reduced to Area level for safety/compliance.", source_id=source_id)

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
            "Observation records what was reported/logged, not necessarily its verified operational truth.",
            "AIS data can contain errors, delays, or manual entry mistakes.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in maritime docs are ignored.")


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
            "Multiple websites displaying same upstream AIS feed are not independent sources.",
        ],
    })


def add_vessel(
    parsed: Dict[str, Any],
    name: Any,
    imo: Any,
    mmsi: Any,
    call_sign: Any,
    flag: Any,
    owner_ref: Any,
    operator_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    i = safe_str(imo, 50)
    m = safe_str(mmsi, 50)
    cs = safe_str(call_sign, 50)
    fl = safe_str(flag, 100)
    
    if not n and not i and not m:
        return None
        
    vid = f"VSL-{uuid.uuid4()}"
    
    imo_valid = validate_imo(i) if i else False
    
    parsed["vessels"].append({
        "vessel_id": vid,
        "name": n,
        "imo": i,
        "imo_checksum_valid": imo_valid,
        "mmsi": m,
        "call_sign": cs,
        "flag_state": fl,
        "registered_owner_ref": owner_ref,
        "operator_ref": operator_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "VESSEL_PARSED",
        "limitations": [
            "MMSI can change/be reused. Cross-check with IMO/Physical specs.",
            "Registered Owner != Beneficial Owner.",
        ],
    })
    return vid


def add_owner(
    parsed: Dict[str, Any],
    name: Any,
    role: Any, # OWNER/OPERATOR/MANAGER
    country: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    oid = f"OWN-{uuid.uuid4()}"
    
    parsed["owners"].append({
        "owner_id": oid,
        "name": n,
        "role": safe_str(role, 50).upper() or "UNKNOWN",
        "jurisdiction": safe_str(country, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "OWNER_PARSED",
        "limitations": [
            "Company structure may involve SPVs. Deep ownership requires OWNERSHIPINT.",
        ],
    })
    return oid


def add_port(
    parsed: Dict[str, Any],
    name: Any,
    unloco: Any,
    country: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    u = safe_str(unloco, 20)
    
    if not n and not u:
        return None
        
    pid = f"PRT-{uuid.uuid4()}"
    
    parsed["ports"].append({
        "port_id": pid,
        "name": n,
        "unlocode": u,
        "country": safe_str(country, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PORT_PARSED",
        "limitations": [
            "Port Name collisions exist. Use UN/LOCODE where available.",
        ],
    })
    return pid


def add_ais_obs(
    parsed: Dict[str, Any],
    vessel_ref: Any,
    lat: Any,
    lon: Any,
    speed: Any,
    course: Any,
    timestamp: Any,
    destination: Any,
    draught: Any,
    nav_status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    aid = f"AIS-{uuid.uuid4()}"
    
    # Basic plausibility check could go here
    
    parsed["ais_obs"].append({
        "ais_id": aid,
        "vessel_ref": vessel_ref,
        "lat_reported": lat,
        "lon_reported": lon,
        "speed_over_ground_knots": speed,
        "course_over_ground_degrees": course,
        "timestamp": safe_str(timestamp, 100),
        "destination_manual_entry": safe_str(destination, 200),
        "draught_reported_meters": draught,
        "navigation_status": safe_str(nav_status, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "AIS_OBS_PARSED",
        "limitations": [
            "AIS Destination is manually entered and often unreliable.",
            "Speed/Course are observational, not engine settings.",
            "Gaps do not automatically imply intentional shutdown.",
        ],
    })


def add_voyage(
    parsed: Dict[str, Any],
    vessel_ref: Any,
    origin_port_ref: Any,
    dest_port_ref: Any,
    departure_time: Any,
    arrival_time: Any,
    route_evidence: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    vid = f"VOY-{uuid.uuid4()}"
    
    parsed["voyages"].append({
        "voyage_id": vid,
        "vessel_ref": vessel_ref,
        "origin_port_ref": origin_port_ref,
        "destination_port_ref": dest_port_ref,
        "departure_time": safe_str(departure_time, 100),
        "arrival_time": safe_str(arrival_time, 100),
        "route_evidence_type": safe_str(route_evidence, 100).upper() or "UNKNOWN", # AIS/PORT_CALL/SCHEDULE
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "VOYAGE_PARSED",
        "limitations": [
            "Route changes due to weather/congestion/orders are normal.",
            "Voyage movement does not prove commercial contract details.",
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

    # Resolve Owners/Operators first so vessels can reference them
    own_refs = {}
    for key in OWNER_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                oname = val.get("name") or val.get("id")
                orole = val.get("role") or key.upper()
                ocountry = val.get("country") or val.get("jurisdiction")
            else:
                oname = str(val)
                orole = key.upper()
                ocountry = ""
            
            oref = add_owner(parsed, oname, orole, ocountry, source_id, evidence_id, f"{rec_ctx}/{key}")
            if oref:
                own_refs[normalize_text(oname)] = oref
                
    primary_owner_ref = list(own_refs.values())[0] if own_refs else None
    primary_operator_ref = None # Simplified for demo

    # Resolve Ports
    port_refs = {}
    for key in PORT_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                pname = val.get("name") or val.get("id")
                punloco = val.get("unlocode") or val.get("code")
                pcountry = val.get("country")
            else:
                pname = str(val)
                punloco = ""
                pcountry = ""
            
            pref = add_port(parsed, pname, punloco, pcountry, source_id, evidence_id, f"{rec_ctx}/{key}")
            if pref:
                port_refs[normalize_text(pname)] = pref
                
    primary_origin_port = list(port_refs.values())[0] if port_refs else None
    primary_dest_port = list(port_refs.values())[-1] if len(port_refs) > 1 else None

    # Resolve Vessels
    ves_refs = []
    for key in VESSEL_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                vname = val.get("name") or val.get("id")
                vimo = val.get("imo")
                vmmsi = val.get("mmsi")
                vcs = val.get("callsign") or val.get("call_sign")
                vflag = val.get("flag") or val.get("flag_state")
                vowner = val.get("owner") or primary_owner_ref
                vop = val.get("operator") or primary_operator_ref
            else:
                vname = str(val)
                vimo = ""
                vmmsi = ""
                vcs = ""
                vflag = ""
                vowner = primary_owner_ref
                vop = primary_operator_ref
            
            vref = add_vessel(parsed, vname, vimo, vmmsi, vcs, vflag, vowner, vop, source_id, evidence_id, f"{rec_ctx}/{key}")
            if vref:
                ves_refs.append(vref)
                
    primary_vessel_ref = ves_refs[0] if ves_refs else None

    # Resolve AIS Observations
    ais_items = get_field(rec, AIS_KEYS, as_list=True)
    for item in ais_items:
        if isinstance(item, dict):
            add_ais_obs(
                parsed,
                item.get("vessel") or primary_vessel_ref,
                item.get("lat") or item.get("latitude"),
                item.get("lon") or item.get("longitude"),
                item.get("sog") or item.get("speed"),
                item.get("cog") or item.get("course"),
                item.get("timestamp") or item.get("time"),
                item.get("dest") or item.get("destination"),
                item.get("draft") or item.get("draught"),
                item.get("nav_status") or item.get("status"),
                source_id,
                evidence_id,
                f"{rec_ctx}/ais"
            )

    # Resolve Voyages
    voy_items = get_field(rec, ["voyage", "trip", "journey"], as_list=True)
    for item in voy_items:
        if isinstance(item, dict):
            add_voyage(
                parsed,
                item.get("vessel") or primary_vessel_ref,
                item.get("origin") or primary_origin_port,
                item.get("destination") or primary_dest_port,
                item.get("depart") or item.get("start_time"),
                item.get("arrive") or item.get("end_time"),
                item.get("evidence") or "AIS_TRACK",
                source_id,
                evidence_id,
                f"{rec_ctx}/voyage"
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
                 caution="Maritime texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["imo", "mmsi", "callsign", "vessel name"]):
        signals.append("IDENTIFIER_CONTEXT")
    if any(k in low for k in ["ais", "track", "position", "lat", "lon"]):
        signals.append("MOVEMENT_CONTEXT")
    if any(k in low for k in ["port", "terminal", "berth", "anchor"]):
        signals.append("PORT_CONTEXT")
    if any(k in low for k in ["cargo", "manifest", "bol", "container", "oil", "gas"]):
        signals.append("CARGO_CONTEXT")
    if any(k in low for k in ["collision", "grounding", "fire", "spill", "incident"]):
        signals.append("SAFETY_INCIDENT_CONTEXT")

    if signals:
        add_note(parsed, "MAR_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_MAR_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "ais" in fname or "track" in fname or "pos" in fname:
        return "AIS_TRACK_DATA"
    if "registry" in fname or "class" in fname or "detail" in fname:
        return "VESSEL_REGISTRY_DETAIL"
    if "port" in fname or "call" in fname or "terminal" in fname:
        return "PORT_CALL_LOG"
    if "cargo" in fname or "bol" in fname or "manifest" in fname:
        return "TRADE_CARGO_DOC"

    return "GENERIC_MAR_EVIDENCE"


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
    kind = "CSV_MAR_DATA"

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
    if "ais" in low or "track" in low:
        kind = "TEXT_AIS_LOG"
    elif "registry" in low or "class" in low:
        kind = "TEXT_REGISTRY_RECORD"
    elif "port" in low or "call" in low:
        kind = "TEXT_PORT_REPORT"
    else:
        kind = "TEXT_GENERIC_MAR_DOC"

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
        ".pptx", ".mp3", ".wav", ".mp4", ".avi",
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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".mar", ".nmea"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_mar_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No targeting, no interception, no AIS spoofing, no sanctions evasion.",
            "Binary artifacts are hash/metadata preserved only.",
            "Maritime documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "AIS Gap != Illegal Activity. Proximity != Transfer.",
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
            file_evidence["content_kind"] = "BINARY_MAR_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary maritime document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_vessel_count"] = len(parsed.get("vessels", []))
    file_evidence["parsed_ais_count"] = len(parsed.get("ais_obs", []))
    file_evidence["parsed_port_count"] = len(parsed.get("ports", []))

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


def analyze_ais_quality(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Report the unimplemented check explicitly; zero is not a measured result."""
    return {
        "status": "NOT_IMPLEMENTED",
        "total_observations": len(parsed.get("ais_obs", [])),
        "gaps_detected": None,
        "anomalies_detected": None,
        "note": "AIS gap and anomaly analysis has not been implemented.",
        "limitations": [
            "No gap or speed checks were executed.",
            "AIS gaps alone do not establish intentional shutdown.",
        ],
    }



def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting MMSI for same IMO
    ves_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for v in parsed.get("vessels", []):
        imo = v.get("imo")
        if imo:
            ves_map[imo].append(v)
            
    for imo, group in ves_map.items():
        mmsis = {g.get("mmsi") for g in group if g.get("mmsi")}
        if len(mmsis) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "MMSI_CONFLICT_FOR_IMO",
                "subject": f"IMO {imo}",
                "values": list(mmsis),
                "possible_explanations": [
                    "MMSI changed over time",
                    "Data error",
                    "Identity collision",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify temporal validity of each MMSI.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    ais_q = parsed.get("risk_dimensions", {}).get("ais_quality", {})
    gaps = ais_q.get("gaps_detected")
    
    if gaps is not None and gaps > 0:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "AIS observation gaps may be due to coverage limitations OR intentional transmission cessation.",
            "supporting_facts": [f"{gaps} gap(s) detected in track."],
            "opposing_facts": ["Coverage maps often show blind spots."],
            "unknowns": ["receiver status", "satellite visibility"],
            "falsification_conditions": ["Independent satellite imagery confirms vessel presence during gap."],
            "next_test": "Cross-reference with another AIS provider or SAR satellite data.",
            "status": "ANALYTICAL",
        })

    if not hyps and ais_q.get("status") == "SUCCEEDED":
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No significant AIS anomalies or identity conflicts detected in parsed dataset.",
            "supporting_facts": ["Clean track data."],
            "opposing_facts": [],
            "unknowns": ["future movements"],
            "next_test": "Continue monitoring.",
            "status": "BASELINE",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    vessels = parsed.get("vessels", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized maritime evidence exists?",
            "missing_evidence": "No local MARINT artifact supplied.",
            "likely_source": "AIS Export, Registry Extract, Port Call Log.",
            "specialist_owner": "MARINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline vessel/voyage analysis.",
            "safety_boundary": "No targeting, no evasion advice.",
        })

    if vessels and not any(v.get("registered_owner_ref") for v in vessels):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Who is the registered owner/operator?",
            "missing_evidence": "Ownership records missing.",
            "likely_source": "Flag State Registry, Classification Society Record.",
            "specialist_owner": "MARINT / CORPINT",
            "priority": "HIGH",
            "expected_information_value": "Clarifies liability and control.",
            "safety_boundary": "Do not infer beneficial ownership from management alone.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    cargo = parsed.get("cargo", [])
    incidents = parsed.get("incidents", [])
    
    if cargo:
        handoffs.append({
            "specialist": "TRADEINT / FININT",
            "reason": "Cargo/trade indicators detected.",
            "expected_output": "Commodity verification, value assessment, buyer/seller resolution.",
            "question": "What is the specific nature and value of the cargo?",
        })
        
    if incidents:
        handoffs.append({
            "specialist": "INCIDENTINT / LEGALINT",
            "reason": "Safety/Environmental incidents detected.",
            "expected_output": "Root cause analysis, liability determination.",
            "question": "What caused the incident and who is liable?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "MARINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Is current vessel awareness sufficient for decision support?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["risk_dimensions"]["ais_quality"] = analyze_ais_quality(parsed)
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
    ais_q = parsed.get("risk_dimensions", {}).get("ais_quality", {})
    gaps = ais_q.get("gaps_detected")
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited targeting, evasion, or sabotage behavior.",
            "reason": "MARINT is defensive intelligence, not an attack/enabler tool.",
            "owner": "MARINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized AIS/Registry/Port exports before analysis.",
            "reason": "No MARINT evidence artifact available.",
            "owner": "MARINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if gaps is not None and gaps > 0:
        return {
            "action": "Seek independent AIS source or satellite imagery to resolve observation gaps.",
            "reason": "Track discontinuity detected. Cause unknown (coverage vs shutdown).",
            "owner": "MARINT Analyst / SATINT",
            "expected_output": "Verified continuous track or confirmed gap reason.",
        }

    if gaps is None:
        return {
            "action": "Review AIS observations with a validated gap/anomaly analysis tool.",
            "reason": "Automated AIS quality checks have not run; track consistency is unknown.",
            "owner": "MARINT Analyst",
            "expected_output": "Documented AIS quality findings and limitations.",
        }

    return {
        "action": "Monitor voyage progress against schedule. Verify port calls upon arrival.",
        "reason": "Track data appears consistent.",
        "owner": "MARINT Analyst",
        "expected_output": "Updated voyage status.",
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
    has_vessels = bool(parsed.get("vessels"))
    has_ais = bool(parsed.get("ais_obs"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General MARINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Lawful / public-authorized / evidence-first / safety-aware maritime intelligence only.",
            "authorization_status": "NOT_VERIFIED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_maritime_questions_scope",
        "MARINT Manager",
        "Convert objective into maritime questions, allowed sources, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_maritime_records",
        "local evidence store",
        "Store original AIS/Registry/Port logs and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "MarEvidenceObject with SHA256.",
    )

    add(
        "parse_vessel_ais_port_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT maritime metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized vessels/AIS/ports.",
    )

    add(
        "validate_identifiers_and_checksums",
        "local analyzer",
        "Check IMO checksums and MMSI formats. Flag conflicts.",
        "COMPLETED_LOCAL" if has_vessels else "PLANNED_ANALYTIC",
        "Identifier Validation Report.",
        safety_risk="HIGH_IF_IDENTITY_ERROR",
    )

    add(
        "assess_ais_coverage_gaps",
        "MARINT Analyst",
        "Identify track discontinuities and propose benign explanations.",
        "COMPLETED_LOCAL" if has_ais else "PLANNED_ANALYTIC",
        "AIS Quality Assessment.",
        safety_risk="HIGH_IF_GAP_CALLED_ILLEGAL",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_vessel_or_port",
        "questions",
        "vessels",
        "owners",
        "voyages",
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
            "Sensitive maritime context detected. Analysis must remain lawful, evidence-first, and safety-aware. "
            "No targeting, no interception, no AIS manipulation."
        )

    if payload.get("incidents") or "incident" in scanned:
        human_review_required = True
        safety_notes.append(
            "Incident context detected. Correlate impact carefully. Do not assign fault without official investigation."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal targeting, evasion, or sabotage."
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
                "No obvious hard policy violation detected, but sensitive maritime/incident context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/lawful maritime evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target_vessel_or_port", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No MARINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "ais_data_paths",
        "registry_paths",
        "port_call_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No maritime evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Maritime status is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which vessel is being referenced?",
        "What are its current/historical identifiers (IMO/MMSI/Name)?",
        "Who is the registered owner vs operator?",
        "What is the current voyage/route evidence?",
        "Are there AIS gaps or anomalies?",
        "What cargo/trade context is supported?",
        "Are there any sanctions/compliance flags?",
        "How reliable and independent are the sources?",
        "What remains unknown regarding intent or ownership?",
        "What is the safest next investigative step?",
    ]


class TraceAtlasMARINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#0ea5e9", font=("Segoe UI", 17, "bold")) # Sky Blue accent for Maritime/Ocean
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
        ttk.Label(header, text="TraceAtlas MARINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Lawful / public-authorized / evidence-first / safety-aware maritime intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT vessel/AIS/port parsing only • "
                "No targeting / No interception / No AIS spoofing / No sanctions evasion • "
                "AIS Gap != Illegal • Proximity != Transfer • Owner != Operator"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="MARINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Mar Plan / Evidence")

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

        ttk.Button(buttons1, text="Add AIS / Track Data", command=self.add_ais).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Registry / Class Records", command=self.add_registry).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Port Calls / Terminal Logs", command=self.add_ports).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Trade Docs / BOL", command=self.add_trade).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local MARINT Evidence", command=self.analyze_local_mar).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Mar Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#bae6fd", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "MAR-CASE-001")
        self.set_widget_value("task_id", "MAR-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/public-authorized/safety-aware maritime intelligence using evidence-first methods.")
        self.set_widget_value("target_vessel_or_port", "Illustrative Example Vessel MV TEST / Port XYZ")
        self.set_widget_value("target_type", "vessel_identity_resolution")
        self.set_widget_value("questions", "\n".join(default_questions({"target_vessel_or_port": "Illustrative Example Vessel MV TEST"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public_ais_feed", "official_registry"], "prohibited_actions": ["intercept_vessel", "spoof_ais"]}, indent=2))
        self.set_widget_value("authorization", "{}")
        self.set_widget_value("configured_connectors", "")

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
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_SAFETY_AWARE_MARITIME"
        sync_inputs(self, payload, empty_parsed)
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_ais(self): self._append_paths("ais_data_paths", filedialog.askopenfilenames(title="Select AIS Data", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_registry(self): self._append_paths("registry_paths", filedialog.askopenfilenames(title="Select Registry Records", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_ports(self): self._append_paths("port_call_paths", filedialog.askopenfilenames(title="Select Port Calls", filetypes=[("Logs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_trade(self): self._append_paths("trade_doc_paths", filedialog.askopenfilenames(title="Select Trade Docs", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_mar(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["ais_data_paths", "registry_paths", "port_call_paths", "trade_doc_paths", "stix_misp_paths"]
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
        self.update_idletasks()

        files = []
        parsed_list = []
        for p in all_paths[:30]:
            f, parsed = analyze_mar_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nVessels: {len(aggregated['vessels'])}\nAIS Obs: {len(aggregated['ais_obs'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            self.last_result = {"mode": "POLICY_BLOCKED", "payload": payload, "policy_screen": policy, "evidence_inventory": []}
            self._write_output(self.last_result)
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("vessels") and not self.parsed.get("ais_obs"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "vessels_preview": self.parsed.get("vessels", [])[:100],
            "owners_preview": self.parsed.get("owners", [])[:100],
            "ports_preview": self.parsed.get("ports", [])[:100],
            "ais_obs_preview": self.parsed.get("ais_obs", [])[:100],
            "voyages_preview": self.parsed.get("voyages", [])[:100],
            "risk_dimensions": self.parsed.get("risk_dimensions", {}),
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
            "mode": "LOCAL_DETERMINISTIC_MARINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "vessels": parsed.get("vessels", [])[:300],
            "owners": parsed.get("owners", [])[:300],
            "ports": parsed.get("ports", [])[:300],
            "ais_obs": parsed.get("ais_obs", [])[:300],
            "voyages": parsed.get("voyages", [])[:300],
            "risk_dimensions": parsed.get("risk_dimensions", {}),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No targeting, no interception, no AIS manipulation.",
                "AIS Gap != Illegal Activity.",
                "Proximity != STS Transfer.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def export_json(self) -> None:
        self.collect_payload()  # Invalidate results from a changed case before export.
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
            invalidate(self, empty_parsed)
            self._set_defaults()
            self.output.delete("1.0", "end")
            self.last_result = {}
            self.analyzed_files = []
            self.parsed = empty_parsed()


if __name__ == "__main__":
    try:
        app = TraceAtlasMARINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")
