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


APP_TITLE = "TraceAtlas MILINT AI Employee — Lawful / Authorized / Evidence-First / Non-Targeting Military Intelligence Panel"
APP_VERSION = "TraceAtlas MILINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_country", "Target Country / Force Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "MILINT Questions", "text"),

    ("countries", "Countries / Theaters", "text"),
    ("services", "Services (Army/Navy/AirForce/etc.)", "text"),
    ("commands", "Commands / Formations", "text"),
    ("units", "Units / Regiments / Battalions", "text"),
    ("equipment", "Equipment / Platforms", "text"),
    ("bases", "Bases / Facilities (Public Level)", "text"),
    ("exercises", "Exercises / Operations", "text"),
    ("procurement", "Procurement Programs", "text"),
    ("budgets", "Defense Budget References", "text"),
    
    ("force_structure_paths", "Force Structure / ORBAT Paths", "text"),
    ("equipment_paths", "Equipment Inventory / Tech Specs Paths", "text"),
    ("doctrine_paths", "Doctrine / Training Manuals Paths", "text"),
    ("exercise_paths", "Exercise Reports / Notices Paths", "text"),
    ("conflict_paths", "Conflict Event / Loss Report Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Gov DB/Public Source/etc.)", "text"),
]


TARGET_TYPES = [
    "force_structure_analysis",
    "equipment_capability_review",
    "exercise_doctrine_context",
    "procurement_modernization_track",
    "conflict_event_verification",
    "strategic_posture_assessment",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "countries",
    "services",
    "commands",
    "units",
    "equipment",
    "bases",
    "exercises",
    "procurement",
    "budgets",
    "force_structure_paths",
    "equipment_paths",
    "doctrine_paths",
    "exercise_paths",
    "conflict_paths",
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
    "force_structure_analysis",
    "equipment_capability_review",
    "conflict_event_verification",
    "strategic_posture_assessment",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR MILITARY TARGETING/HARM
POLICY_BLOCK_PATTERNS = [
    r"\b(?:generate|create|produce)\b[^\n]{0,140}\b(?:target list|aimpoint|strike coordinate|firing solution|kill chain|weapon target pairing)\b",
    r"\b(?:plan|design|optimize)\b[^\n]{0,140}\b(?:attack route|ambush|interdiction|penetration|strike window|battle damage assessment optimization)\b",
    r"\b(?:identify|locate|track)\b[^\n]{0,140}\b(?:current troop location|command post coordinates|radar position|air defense gap|vulnerable logistics node)\b",
    r"\b(?:bypass|evade|jam|spoof)\b[^\n]{0,140}\b(?:radar|air defense|countermeasure|encryption|authentication)\b",
    r"\b(?:sabotage|destroy|disable)\b[^\n]{0,140}\b(?:infrastructure|network|system|facility)\b",
    r"\b(?:real time|live)\b[^\n]{0,140}\b(?:troop tracking|convoy tracking|missile launch detection)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/authorized/evidence-first/non-targeting military intelligence: resolve force structures/units/equipment/doctrines/exercises, separate capability from readiness and intent, verify conflict claims using source independence checks, and produce strategic/historical assessments with precision safety filters.",
    "Do not generate target lists, aimpoints, strike coordinates, firing solutions, attack plans, ambush strategies, or real-time operational tracking data that could facilitate harm.",
    "Separate Contract from Delivery, Delivery from Fielding, Capability from Readiness, Readiness from Intent, Exercise from Attack Preparation, Public Claim from Verified Fact.",
    "Use deterministic arithmetic for budgets/inventory counts. Apply precision reduction to all location-based outputs. Escalate consequential nuclear/CBRN/Special Ops analysis to authorized human review.",
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
    r"unlock\s+(?:the\s+)?(?:classified|restricted)\s+(?:file|data)",
]


# Regex helpers for military identifiers
UNIT_ID_RE = re.compile(r"\b(?:Unit|Regiment|Battalion|Brigade|Division|Corps|Wing|Squadron|Fleet)\s*(?:No\.?\s*)?[A-Z0-9\-\/]+\b", re.I)
PLATFORM_RE = re.compile(r"\b(?:Tank|IFV|APC|Artillery|Radar|Missile|Aircraft|Helicopter|Ship|Submarine|Drone|UAV)\s*[A-Z0-9\-]+\b", re.I)
COORDINATE_RE = re.compile(r"\b[-+]?\d{1,3}\.\d+\s*[,/\s]\s*[-+]?\d{1,3}\.\d+\b") # Detects lat/long pairs


ENTITY_ROLE_KEYS = [
    "service",
    "command",
    "formation",
    "unit",
    "brigade",
    "division",
    "regiment",
    "battalion",
    "wing",
    "squadron",
    "fleet",
    "base",
    "facility",
]


EQUIPMENT_KEYS = [
    "equipment",
    "platform",
    "vehicle",
    "aircraft",
    "ship",
    "submarine",
    "drone",
    "uav",
    "tank",
    "ifv",
    "apc",
    "artillery",
    "radar",
    "missile",
    "sensor",
]


DOCTRINE_KEYS = [
    "doctrine",
    "manual",
    "concept",
    "strategy",
    "tactic_high_level",
]


EXERCISE_KEYS = [
    "exercise",
    "operation",
    "training_cycle",
    "drill",
]


CONFLICT_KEYS = [
    "engagement",
    "battle",
    "incident",
    "loss",
    "damage",
    "territorial_change",
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


def extract_unit_ids(text: str) -> List[str]:
    return [m.group(0).strip() for m in UNIT_ID_RE.finditer(text or "")]


def extract_platforms(text: str) -> List[str]:
    return [m.group(0).strip() for m in PLATFORM_RE.finditer(text or "")]


def check_coordinate_presence(text: str) -> bool:
    """Detects potential precise coordinates which must be filtered/reduced."""
    return bool(COORDINATE_RE.search(text or ""))


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "organizations": [], # Services, Commands, Units
        "equipment": [],
        "doctrines": [],
        "exercises": [],
        "procurement": [],
        "conflict_events": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "safety_flags": [],
    }


def add_note(parsed: Dict[str, Any], note_type: str, **kwargs: Any) -> None:
    if len(parsed.get("notes", [])) >= 200000:
        return
    note = {"type": note_type}
    note.update(kwargs)
    parsed["notes"].append(note)


def add_safety_flag(parsed: Dict[str, Any], flag_type: str, detail: str, action_taken: str) -> None:
    parsed["safety_flags"].append({
        "flag_id": f"SF-{uuid.uuid4()}",
        "type": flag_type,
        "detail": detail,
        "action_taken": action_taken,
        "timestamp": now_utc(),
    })


def add_observation(parsed: Dict[str, Any], statement: str, source_id: str, evidence_id: str, context: str = "") -> None:
    if len(parsed.get("observations", [])) >= 200000:
        return

    redacted, secret_flags = redact_secrets(str(statement or "")[:1000])
    injection_flags = detect_prompt_injection(str(statement or ""))
    
    # SAFETY CHECK: Coordinates
    has_coords = check_coordinate_presence(redacted)
    if has_coords:
        # Replace coords with generic region marker to prevent leakage
        redacted = COORDINATE_RE.sub("[REGION_COORDINATES_REDUCED]", redacted)
        add_safety_flag(parsed, "COORDINATE_FILTER", "Precise coordinates detected in source text.", "Coordinates replaced with regional placeholder.")

    parsed["observations"].append({
        "observation_id": f"OBS-{uuid.uuid4()}",
        "statement": redacted,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": context[:200],
        "state": "SOURCE_OBSERVED",
        "secret_flags": secret_flags,
        "prompt_injection_flags": injection_flags,
        "content_hash": sha256_text(str(statement or "")),
        "limitations": [
            "Observation records what was stated/published, not necessarily its factual truth or current status.",
            "Public military sources may contain propaganda or exaggerated claims.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in mil docs are ignored.")


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
            "Multiple OSINT accounts reposting one video/image are not independent sources.",
        ],
    })


def add_organization(
    parsed: Dict[str, Any],
    name: Any,
    org_type: Any,
    country: Any,
    parent_ref: Any = None,
    source_id: str = "",
    evidence_id: str = "",
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    norm = normalize_text(n)
    ot = safe_str(org_type, 100).upper() or "UNKNOWN"
    
    for o in parsed["organizations"]:
        if o.get("normalized_name") == norm and o.get("org_type") == ot:
            if country and not o.get("country"):
                o["country"] = safe_str(country, 100)
            if parent_ref and not o.get("parent_ref"):
                o["parent_ref"] = parent_ref
            return o.get("org_id")

    oid = f"ORG-{uuid.uuid4()}"
    parsed["organizations"].append({
        "org_id": oid,
        "name": n,
        "normalized_name": norm,
        "org_type": ot,
        "country": safe_str(country, 100),
        "parent_ref": parent_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ORG_CANDIDATE",
        "limitations": [
            "Unit identity requires careful resolution. Similar names exist across countries/time.",
            "Home station does not equal current deployment.",
        ],
    })
    return oid


def add_equipment(
    parsed: Dict[str, Any],
    platform_name: Any,
    eq_type: Any,
    status: Any, # ORDERED, DELIVERED, IN_SERVICE, RETIRED
    quantity: Any,
    unit_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    pn = safe_str(platform_name, 200)
    if not pn:
        return
        
    eid = f"EQP-{uuid.uuid4()}"
    
    stat_norm = normalize_text(status).upper()
    canonical_status = "UNKNOWN"
    if "ORDER" in stat_norm or "CONTRACT" in stat_norm:
        canonical_status = "ORDERED_CONTRACTED"
    elif "DELIVER" in stat_norm:
        canonical_status = "DELIVERED_REPORTED"
    elif "SERVICE" in stat_norm or "ACTIVE" in stat_norm or "OPERATIONAL" in stat_norm:
        canonical_status = "IN_SERVICE"
    elif "RETIRE" in stat_norm or "DISPOSE" in stat_norm:
        canonical_status = "RETIRED"
        
    qty_val = None
    if quantity:
        try:
            qty_val = int(str(quantity).replace(",", ""))
        except:
            pass

    parsed["equipment"].append({
        "equipment_id": eid,
        "platform_name": pn,
        "equipment_type": safe_str(eq_type, 100).upper() or "UNKNOWN",
        "inventory_status": canonical_status,
        "quantity_reported": qty_val,
        "unit_ref": unit_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "EQUIPMENT_PARSED",
        "limitations": [
            "Contract != Delivery. Delivery != Operational Readiness.",
            "Variant identification often uncertain without TECHINT.",
        ],
    })


def add_exercise(
    parsed: Dict[str, Any],
    ex_name: Any,
    participants: Any, # List of Org IDs
    location_region: Any,
    date_start: Any,
    date_end: Any,
    objective: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    en = safe_str(ex_name, 200)
    if not en:
        return
        
    xid = f"EXR-{uuid.uuid4()}"
    
    parsed["exercises"].append({
        "exercise_id": xid,
        "name": en,
        "participant_refs": listify(participants)[:50],
        "location_region": safe_str(location_region, 200), # Keep high level
        "date_start": safe_str(date_start, 100),
        "date_end": safe_str(date_end, 100),
        "stated_objective": safe_str(objective, 500),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "EXERCISE_PARSED",
        "limitations": [
            "Exercise != Attack Preparation.",
            "Script != War Plan.",
        ],
    })


def add_conflict_event(
    parsed: Dict[str, Any],
    event_desc: Any,
    involved_units: Any,
    claimed_losses: Any,
    visual_confirmation: Any,
    date: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    ed = safe_str(event_desc, 500)
    if not ed:
        return
        
    cid = f"CONF-{uuid.uuid4()}"
    
    parsed["conflict_events"].append({
        "event_id": cid,
        "description": ed,
        "involved_unit_refs": listify(involved_units)[:50],
        "claimed_loss_status": safe_str(claimed_losses, 200), # e.g., "Party A Claims X Destroyed"
        "visual_confirmation_status": safe_str(visual_confirmation, 200), # e.g., "Geolocated Video Exists"
        "date": safe_str(date, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "CONFLICT_EVENT_PARSED",
        "limitations": [
            "Claim != Fact. Propaganda sources may exaggerate.",
            "One image/video does not prove total destruction or mission kill.",
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

    # Resolve Organizations
    org_refs = []
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                oname = val.get("name") or val.get("id")
                otype = val.get("type") or key.upper()
                ocountry = val.get("country")
            else:
                oname = str(val)
                otype = key.upper()
                ocountry = rec.get("country")
            
            oref = add_organization(parsed, oname, otype, ocountry, None, source_id, evidence_id, f"{rec_ctx}/{key}")
            if oref:
                org_refs.append(oref)

    primary_org_ref = org_refs[0] if org_refs else None

    # Resolve Equipment
    eq_items = get_field(rec, EQUIPMENT_KEYS, as_list=True)
    for item in eq_items:
        if isinstance(item, dict):
            add_equipment(
                parsed,
                item.get("name") or item.get("model"),
                item.get("type"),
                item.get("status"),
                item.get("quantity"),
                primary_org_ref,
                source_id,
                evidence_id,
                f"{rec_ctx}/equipment"
            )

    # Resolve Exercises
    ex_items = get_field(rec, EXERCISE_KEYS, as_list=True)
    for item in ex_items:
        if isinstance(item, dict):
            add_exercise(
                parsed,
                item.get("name"),
                item.get("participants") or org_refs,
                item.get("location"),
                item.get("start_date"),
                item.get("end_date"),
                item.get("objective"),
                source_id,
                evidence_id,
                f"{rec_ctx}/exercise"
            )

    # Resolve Conflict Events
    conf_items = get_field(rec, CONFLICT_KEYS, as_list=True)
    for item in conf_items:
        if isinstance(item, dict):
            add_conflict_event(
                parsed,
                item.get("description") or item.get("event"),
                item.get("units_involved") or org_refs,
                item.get("claims"),
                item.get("verification"),
                item.get("date"),
                source_id,
                evidence_id,
                f"{rec_ctx}/conflict"
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
                 caution="Mil docs are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["unit", "battalion", "brigade", "division"]):
        signals.append("FORCE_STRUCTURE_CONTEXT")
    if any(k in low for k in ["tank", "jet", "ship", "missile", "radar"]):
        signals.append("EQUIPMENT_CONTEXT")
    if any(k in low for k in ["exercise", "drill", "training"]):
        signals.append("TRAINING_EXERCISE_CONTEXT")
    if any(k in low for k in ["battle", "engagement", "loss", "destroyed"]):
        signals.append("CONFLICT_EVENT_CONTEXT")
    if any(k in low for k in ["doctrine", "manual", "concept"]):
        signals.append("DOCTRINE_CONTEXT")

    if signals:
        add_note(parsed, "MIL_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_MIL_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "orbat" in fname or "order_of_battle" in fname or "unit" in keys:
        return "FORCE_STRUCTURE_RECORD"
    if "equipment" in fname or "inventory" in fname or "platform" in keys:
        return "EQUIPMENT_INVENTORY"
    if "exercise" in fname or "drill" in fname:
        return "EXERCISE_REPORT"
    if "conflict" in fname or "battle" in fname or "loss" in fname:
        return "CONFLICT_EVENT_LOG"

    return "GENERIC_MIL_EVIDENCE"


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
    kind = "CSV_MIL_DATA"

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
    if "orbat" in low or "order of battle" in low:
        kind = "TEXT_ORBAT_DOC"
    elif "exercise" in low or "drill" in low:
        kind = "TEXT_EXERCISE_NOTICE"
    elif "battle" in low or "engagement" in low:
        kind = "TEXT_CONFLICT_REPORT"
    else:
        kind = "TEXT_GENERIC_MIL_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".orbat", ".mil"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_mil_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No targeting, no strike planning, no real-time operational tracking for harm.",
            "Binary artifacts are hash/metadata preserved only.",
            "Military documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Capability != Readiness. Readiness != Intent.",
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
            file_evidence["content_kind"] = "BINARY_MIL_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary military document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access classified systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_org_count"] = len(parsed.get("organizations", []))
    file_evidence["parsed_eq_count"] = len(parsed.get("equipment", []))
    file_evidence["parsed_ex_count"] = len(parsed.get("exercises", []))
    file_evidence["parsed_conf_count"] = len(parsed.get("conflict_events", []))

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


def assess_readiness_vs_intent(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Separates observed activity (Readiness indicators) from inferred Intent.
    """
    assessments = []
    
    exercises = parsed.get("exercises", [])
    mobilization_indicators = [] # Placeholder for future logic
    
    for ex in exercises:
        assessments.append({
            "assessment_id": f"ASM-{uuid.uuid4()}",
            "subject": ex.get("exercise_id"),
            "observed_activity": "EXERCISE_PARTICIPATION",
            "readiness_implication": "ELEVATED_TRAINING_ACTIVITY",
            "intent_implication": "UNKNOWN", # Explicitly unknown
            "limitations": [
                "Exercise participation does not prove offensive intent.",
                "Could be routine training, deterrence signaling, or interoperability test.",
            ]
        })
        
    return assessments


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting inventory statuses for same platform/unit
    eq_map: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for eq in parsed.get("equipment", []):
        pn = eq.get("platform_name")
        ur = eq.get("unit_ref")
        if pn and ur:
            eq_map[(pn, ur)].append(eq)
            
    for (pn, ur), group in eq_map.items():
        statuses = {g.get("inventory_status") for g in group}
        if len(statuses) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "EQUIPMENT_STATUS_CONFLICT",
                "subject": f"{pn} @ {ur}",
                "values": list(statuses),
                "possible_explanations": [
                    "Different dates",
                    "Rotation",
                    "Partial delivery",
                    "Misidentification",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify latest official procurement/delivery notice.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    orgs = parsed.get("organizations", [])
    conflicts = parsed.get("conflict_events", [])
    
    if not orgs:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No military organizations identified in local dataset.",
            "supporting_facts": ["Empty org list."],
            "opposing_facts": [],
            "unknowns": ["structure", "command"],
            "next_test": "Import valid ORBAT/Directory exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if conflicts:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Conflict events detected. Verification of losses/damage required.",
            "supporting_facts": [f"{len(conflicts)} event(s) parsed."],
            "opposing_facts": ["Claims may be propaganda."],
            "unknowns": ["actual damage extent", "mission impact"],
            "falsification_conditions": ["Independent imagery confirms no damage."],
            "next_test": "Handoff to IMINT/GEOINT for visual verification (non-targeting).",
            "status": "MONITORING",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    orgs = parsed.get("organizations", [])
    eq = parsed.get("equipment", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized military evidence exists?",
            "missing_evidence": "No local MILINT artifact supplied.",
            "likely_source": "Defense White Paper, Official Gazette, Public ORBAT.",
            "specialist_owner": "MILINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline force analysis.",
            "safety_boundary": "No targeting, no classified solicitation.",
        })

    if orgs and not eq:
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What equipment is assigned to these units?",
            "missing_evidence": "Equipment records missing.",
            "likely_source": "Official inventory reports, Procurement notices.",
            "specialist_owner": "MILINT / PROCUREMENTINT",
            "priority": "HIGH",
            "expected_information_value": "Determines capability baseline.",
            "safety_boundary": "Do not infer readiness from inventory alone.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    conflicts = parsed.get("conflict_events", [])
    eq = parsed.get("equipment", [])
    
    if conflicts:
        handoffs.append({
            "specialist": "IMINT / GEOINT / DISINFOINT",
            "reason": "Conflict events/Loss claims detected.",
            "expected_output": "Visual verification, geolocation, disinfo check.",
            "question": "Can the claimed losses/damage be visually confirmed independently?",
        })
        
    if any(e.get("equipment_type") in ["RADAR", "MISSILE", "AIR_DEFENSE"] for e in eq):
        handoffs.append({
            "specialist": "TECHINT",
            "reason": "Sensitive technical systems identified.",
            "expected_output": "Technical characteristic analysis (non-operational).",
            "question": "What are the public technical specifications of this system?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "MILINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Are current insights sufficient for strategic assessment?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["readiness_intent_assessments"] = assess_readiness_vs_intent(parsed)
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
    orgs = parsed.get("organizations", [])
    conflicts = parsed.get("conflict_events", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited targeting, strike planning, or real-time operational tracking behavior.",
            "reason": "MILINT is defensive strategic intelligence, not a combat support system.",
            "owner": "MILINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized ORBAT/equipment/exercise exports before analysis.",
            "reason": "No MILINT evidence artifact available.",
            "owner": "MILINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if conflicts:
        return {
            "action": "Handoff conflict events to IMINT/GEOINT for independent visual verification (non-targeting).",
            "reason": "Battlefield claims require corroboration beyond party statements.",
            "owner": "MILINT / IMINT",
            "expected_output": "Verified loss/damage assessment.",
        }

    return {
        "action": "Proceed with force-structure and capability trend analysis using historical/public data.",
        "reason": "Basic structural analysis complete.",
        "owner": "MILINT Analyst",
        "expected_output": "Strategic posture report.",
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
    has_orgs = bool(parsed.get("organizations"))
    has_eq = bool(parsed.get("equipment"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General MILINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Lawful / authorized / evidence-first / NON-TARGETING military intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_military_questions_scope",
        "MILINT Manager",
        "Convert objective into military questions, allowed sources, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_military_records",
        "local evidence store",
        "Store original ORBATs/equipment lists/exercises and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "MilEvidenceObject with SHA256.",
    )

    add(
        "parse_force_structure_equipment_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT military metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized orgs/equipment/exercises/conflicts.",
    )

    add(
        "separate_capability_from_readiness",
        "local analyzer",
        "Ensure output distinguishes owned equipment from operational availability.",
        "COMPLETED_LOCAL" if has_eq else "PLANNED_ANALYTIC",
        "Capability vs Readiness register.",
        safety_risk="HIGH_IF_CAPABILITY_CALLED_COMBAT_POWER",
    )

    add(
        "apply_precision_safety_filter",
        "local filter",
        "Reduce geographic precision of all location data to regional/theater level.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_SAFETY_CHECK",
        "Safe-granularity spatial data.",
        safety_risk="CRITICAL_IF_PRECISE_COORDS_LEAKED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_country",
        "questions",
        "countries",
        "units",
        "equipment",
        "exercises",
        "conflict_paths",
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
            "Sensitive military context detected. Analysis must remain lawful, authorized, and non-targeting. "
            "No strike planning, no aimpoints, no real-time operational exploitation."
        )

    if payload.get("conflict_paths") or "conflict" in scanned:
        human_review_required = True
        safety_notes.append(
            "Conflict context detected. Verify claims independently. Do not amplify propaganda or unverified casualty figures."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal targeting, strike planning, or operational harm facilitation."
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
                "No obvious hard policy violation detected, but sensitive military/conflict context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful military evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target_country", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No MILINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "countries",
        "services",
        "units",
        "force_structure_paths",
        "equipment_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No military evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Military posture is highly temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No gov db/public source connector configured. External correlation remains planning-only.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which military organizations and services are involved?",
        "What is the documented force structure and command hierarchy?",
        "What equipment platforms are publicly attributed to these units?",
        "Is the equipment contracted, delivered, or operationally fielded?",
        "What recent exercises or training activities are evidenced?",
        "Do these activities indicate elevated readiness or just routine training?",
        "Are there any reported conflict events or loss claims?",
        "How reliable and independent are the sources for these claims?",
        "What strategic implications can be supported by evidence without crossing targeting boundaries?",
        "What remains unknown regarding current deployment or capability?",
    ]


class TraceAtlasMILINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#ef4444", font=("Segoe UI", 17, "bold")) # Red accent for Military/Warning
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
        ttk.Label(header, text="TraceAtlas MILINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Lawful / authorized / evidence-first / NON-TARGETING military intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT ORBAT/equipment/exercise parsing only • "
                "No targeting / No strike planning / No aimpoints / No real-time operational tracking for harm • "
                "Capability != Readiness • Readiness != Intent • Exercise != Attack Prep"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="MILINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Mil Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Force Structure / ORBAT", command=self.add_force_structures).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Equipment / Inventory", command=self.add_equipment).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Doctrine / Training", command=self.add_doctrine).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Exercises / Ops", command=self.add_exercises).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local MILINT Evidence", command=self.analyze_local_mil).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Mil Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#fecaca", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "MIL-CASE-001")
        self.set_widget_value("task_id", "MIL-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive military intelligence using evidence-first methods.")
        self.set_widget_value("target_country", "Illustrative Example Nation")
        self.set_widget_value("target_type", "force_structure_analysis")
        self.set_widget_value("questions", "\n".join(default_questions({"target_country": "Illustrative Example Nation"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public_defense_ministry", "official_gazette"], "prohibited_actions": ["generate_target_list", "provide_strike_coords"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_strategic_risk_assessment"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_NON_TARGETING_EVIDENCE_FIRST"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_force_structures(self): self._append_paths("force_structure_paths", filedialog.askopenfilenames(title="Select ORBATs", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_equipment(self): self._append_paths("equipment_paths", filedialog.askopenfilenames(title="Select Equipment Lists", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_doctrine(self): self._append_paths("doctrine_paths", filedialog.askopenfilenames(title="Select Doctrine Docs", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_exercises(self): self._append_paths("exercise_paths", filedialog.askopenfilenames(title="Select Exercise Reports", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_mil(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["force_structure_paths", "equipment_paths", "doctrine_paths", "exercise_paths", "conflict_paths", "stix_misp_paths"]
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
            f, parsed = analyze_mil_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nOrgs: {len(aggregated['organizations'])}\nEquip: {len(aggregated['equipment'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("organizations") and not self.parsed.get("equipment"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "organizations_preview": self.parsed.get("organizations", [])[:100],
            "equipment_preview": self.parsed.get("equipment", [])[:100],
            "exercises_preview": self.parsed.get("exercises", [])[:100],
            "conflict_events_preview": self.parsed.get("conflict_events", [])[:100],
            "readiness_intent_assessments": self.parsed.get("readiness_intent_assessments", []),
            "hypotheses": self.parsed.get("hypotheses", []),
            "knowledge_gaps": self.parsed.get("knowledge_gaps", []),
            "specialist_handoffs": self.parsed.get("specialist_handoffs", []),
            "safety_flags": self.parsed.get("safety_flags", []),
            "next_best_action": next_action,
            "collection_plan": collection_plan,
        }
        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

    def _build_local_analysis_report(self, files, parsed, payload, policy) -> Dict[str, Any]:
        return {
            "mode": "LOCAL_DETERMINISTIC_MILINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "organizations": parsed.get("organizations", [])[:300],
            "equipment": parsed.get("equipment", [])[:300],
            "exercises": parsed.get("exercises", [])[:300],
            "conflict_events": parsed.get("conflict_events", [])[:300],
            "readiness_intent_assessments": parsed.get("readiness_intent_assessments", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "safety_flags": parsed.get("safety_flags", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No targeting, no strike planning, no real-time ops.",
                "Capability != Readiness.",
                "Readiness != Intent.",
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
        app = TraceAtlasMILINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")