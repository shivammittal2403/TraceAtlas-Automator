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


APP_TITLE = "TraceAtlas MILINT AI Employee — Lawful / Public-Authorized / Non-Targeting / Analytical Military Intelligence Panel"
APP_VERSION = "TraceAtlas MILINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_entity_or_unit", "Target Country / Unit / Platform Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "MILINT Questions", "text"),

    ("countries", "Countries / Armed Forces", "text"),
    ("units", "Units / Formations / Commands", "text"),
    ("platforms", "Platforms / Equipment / Systems", "text"),
    ("procurement", "Procurement Programs / Contracts", "text"),
    ("exercises", "Exercises / Training Events", "text"),
    ("doctrine", "Doctrine / Strategy Documents", "text"),
    
    ("org_chart_paths", "Official Org Charts / OB Paths", "text"),
    ("procurement_paths", "Budget / Procurement Records Paths", "text"),
    ("equipment_meta_paths", "Equipment Specs / Manual Paths", "text"),
    ("exercise_report_paths", "Exercise Reports / Press Releases Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Defense DB/Public Archives/etc.)", "text"),
]


TARGET_TYPES = [
    "force_structure_analysis",
    "capability_assessment",
    "procurement_modernization_review",
    "exercise_doctrine_context",
    "strategic_readiness_indicators",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "countries",
    "units",
    "platforms",
    "procurement",
    "exercises",
    "doctrine",
    "org_chart_paths",
    "procurement_paths",
    "equipment_meta_paths",
    "exercise_report_paths",
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
    "capability_assessment",
    "strategic_readiness_indicators",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR MILITARY HARM/TARGETING/WEAPONIZATION
POLICY_BLOCK_PATTERNS = [
    r"\b(?:generate|provide|calculate)\b[^\n]{0,140}\b(?:strike coordinate|fire solution|attack route|kill chain|target list)\b",
    r"\b(?:optimize|maximize|enhance)\b[^\n]{0,140}\b(?:weapon lethality|munition effect|blast radius|penetration power)\b",
    r"\b(?:plan|design|execute)\b[^\n]{0,140}\b(?:sabotage|infiltration|ambush|raid|assassination|hostage op)\b",
    r"\b(?:advise|guide|teach)\b[^\n]{0,140}\b(?:radar evasion|air defense suppression|electronic attack|jamming spoofing)\b",
    r"\b(?:track|locate|identify)\b[^\n]{0,140}\b(?:live troop position|current convoy location|real-time special forces)\b",
    r"\b(?:construct|assemble|synthesize)\b[^\n]{0,140}\b(?:CBRN agent|nuclear device|explosive compound|biological weapon)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/public-authorized/non-targeting/analytical military intelligence: resolve force structures, assess capabilities based on evidence, analyze procurement/modernization trends, and contextualize exercises/doctrines without generating targeting data or operational plans.",
    "Do not produce strike coordinates, firing solutions, attack routes, or optimize weapon employment. Do not track live troops or provide CBRN/nuclear construction guidance.",
    "Separate Unit Existence from Combat Readiness, Platform Delivery from Operational Capability, Readiness from Intent, Exercise from War Plan, and Mobilization Indicator from Invasion.",
    "Use deterministic logic for inventory counts and timeline validation. Escalate consequential active-conflict analyses to authorized human review with strict safety boundaries.",
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


# Regex helpers for Military identifiers
UNIT_ID_RE = re.compile(r"\b(?:Unit|Battalion|Regiment|Brigade|Division|Corps)\s*(?:No\.?\s*)?[A-Z0-9\-]+\b", re.I)
PLATFORM_ID_RE = re.compile(r"\b(?:Tank|IFV|APC|Artillery|Radar|Missile System|Aircraft|Ship|Submarine)\s*[A-Z0-9\-]*\b", re.I)


ENTITY_ROLE_KEYS = [
    "country",
    "service",
    "command",
    "formation",
    "unit",
    "base",
]


PLATFORM_KEYS = [
    "platform",
    "equipment",
    "system",
    "vehicle",
    "aircraft",
    "ship",
]


PROCUREMENT_KEYS = [
    "program",
    "contract",
    "procurement",
    "acquisition",
]


EXERCISE_KEYS = [
    "exercise",
    "drill",
    "training",
    "maneuver",
]


DOCTRINE_KEYS = [
    "doctrine",
    "strategy",
    "concept",
    "manual",
]


INVENTORY_STATE_MAP = {
    "ordered": "ORDERED",
    "contracted": "CONTRACTED",
    "production": "IN_PRODUCTION",
    "delivered": "DELIVERED",
    "testing": "ACCEPTANCE_TESTING",
    "operational": "OPERATIONAL_REPORTED",
    "ready": "READY_REPORTED",
    "reserve": "RESERVE",
    "stored": "STORED",
    "retired": "RETIRED",
    "lost": "LOST",
    "unknown": "UNKNOWN",
}


READINESS_STATE_MAP = {
    "high": "HIGH_CONFIDENCE_READY",
    "moderate": "PARTIALLY_READY",
    "low": "LIMITED_READINESS",
    "unclear": "READINESS_UNCLEAR",
    "unknown": "UNKNOWN",
}


CAPABILITY_STATE_MAP = {
    "claimed": "CLAIMED",
    "supported": "SUPPORTED",
    "demonstrated": "DEMONSTRATED",
    "partial": "PARTIAL",
    "historical": "HISTORICAL",
    "disputed": "DISPUTED",
    "unknown": "UNKNOWN",
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


def map_inventory_state(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return INVENTORY_STATE_MAP.get(norm, "UNKNOWN")


def map_readiness_state(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return READINESS_STATE_MAP.get(norm, "UNKNOWN")


def map_capability_state(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return CAPABILITY_STATE_MAP.get(norm, "UNKNOWN")


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "entities": [], # Countries/Services/Commands
        "units": [],
        "platforms": [],
        "procurement": [],
        "exercises": [],
        "doctrine": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "capability_assessments": [],
        "readiness_indicators": [],
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
            "Capability claims require independent verification.",
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
            "Multiple news articles quoting one MoD statement are not independent sources.",
        ],
    })


def add_entity(
    parsed: Dict[str, Any],
    name: Any,
    etype: Any, # COUNTRY/SERVICE/COMMAND
    parent_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    eid = f"ENT-{uuid.uuid4()}"
    
    parsed["entities"].append({
        "entity_id": eid,
        "name": n,
        "entity_type": safe_str(etype, 50).upper() or "UNKNOWN",
        "parent_entity_ref": parent_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ENTITY_PARSED",
        "limitations": [
            "Organizational hierarchy may vary by country/service.",
        ],
    })
    return eid


def add_unit(
    parsed: Dict[str, Any],
    name: Any,
    utype: Any, # BATTALION/BRIGADE etc
    parent_ent_ref: Any,
    base_location_region: Any, # Keep coarse
    equipment_refs: Any,
    personnel_strength_claim: Any,
    readiness_claim: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    uid = f"UNI-{uuid.uuid4()}"
    
    rd_norm = normalize_text(readiness_claim).upper()
    canonical_rd = "UNKNOWN"
    if "HIGH" in rd_norm or "FULL" in rd_norm:
        canonical_rd = "READY_REPORTED"
    elif "MED" in rd_norm or "PARTIAL" in rd_norm:
        canonical_rd = "PARTIALLY_READY"
    elif "LOW" in rd_norm or "LIMITED" in rd_norm:
        canonical_rd = "LIMITED_READINESS"
        
    parsed["units"].append({
        "unit_id": uid,
        "designation": n,
        "unit_type": safe_str(utype, 50).upper() or "UNKNOWN",
        "parent_entity_ref": parent_ent_ref,
        "base_region_coarse": safe_str(base_location_region, 100), # No exact coords
        "equipment_refs": listify(equipment_refs)[:50],
        "personnel_strength_claim": safe_str(personnel_strength_claim, 100),
        "readiness_state": canonical_rd,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "UNIT_PARSED",
        "limitations": [
            "Unit designation alone does not prove current composition.",
            "Readiness reports vary by source reliability.",
        ],
    })
    return uid


def add_platform(
    parsed: Dict[str, Any],
    name: Any,
    ptype: Any, # TANK/AIRCRAFT/SHIP
    manufacturer: Any,
    inventory_state: Any,
    quantity_claim: Any,
    capability_claim: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    pid = f"PLT-{uuid.uuid4()}"
    
    inv_norm = normalize_text(inventory_state).upper()
    canonical_inv = "UNKNOWN"
    if "OPERATIONAL" in inv_norm or "ACTIVE" in inv_norm:
        canonical_inv = "OPERATIONAL_REPORTED"
    elif "DELIVERED" in inv_norm or "FIELD" in inv_norm:
        canonical_inv = "DELIVERED"
    elif "ORDERED" in inv_norm or "CONTRACT" in inv_norm:
        canonical_inv = "ORDERED"
    elif "RETIRE" in inv_norm or "SCRAP" in inv_norm:
        canonical_inv = "RETIRED"
        
    cap_norm = normalize_text(capability_claim).upper()
    canonical_cap = "UNKNOWN"
    if "DEMONSTRATED" in cap_norm or "TESTED" in cap_norm:
        canonical_cap = "DEMONSTRATED"
    elif "SUPPORTED" in cap_norm or "VERIFIED" in cap_norm:
        canonical_cap = "SUPPORTED"
    elif "CLAIMED" in cap_norm or "SPEC" in cap_norm:
        canonical_cap = "CLAIMED"
        
    qty_val = None
    if quantity_claim:
        try:
            qty_val = int(str(quantity_claim).replace(",", ""))
        except:
            pass

    parsed["platforms"].append({
        "platform_id": pid,
        "name": n,
        "platform_type": safe_str(ptype, 50).upper() or "UNKNOWN",
        "manufacturer": safe_str(manufacturer, 100),
        "inventory_state": canonical_inv,
        "quantity_visible_or_claimed": qty_val,
        "capability_state": canonical_cap,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PLATFORM_PARSED",
        "limitations": [
            "Possession of platform != Operational Readiness.",
            "Manufacturer specs != Measured Performance.",
        ],
    })
    return pid


def add_procurement(
    parsed: Dict[str, Any],
    prog_name: Any,
    supplier: Any,
    recipient: Any,
    system_ref: Any,
    contract_value: Any,
    status: Any,
    delivery_schedule: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    prid = f"PRC-{uuid.uuid4()}"
    
    stat_norm = normalize_text(status).upper()
    canonical_stat = "UNKNOWN"
    if "AWARD" in stat_norm or "SIGN" in stat_norm:
        canonical_stat = "CONTRACTED"
    elif "PROD" in stat_norm or "BUILD" in stat_norm:
        canonical_stat = "IN_PRODUCTION"
    elif "DELIV" in stat_norm or "HANDOVER" in stat_norm:
        canonical_stat = "DELIVERED"
        
    parsed["procurement"].append({
        "procurement_id": prid,
        "program_name": safe_str(prog_name, 200),
        "supplier": safe_str(supplier, 200),
        "recipient_force": safe_str(recipient, 200),
        "system_ref": system_ref,
        "contract_value_estimated": safe_str(contract_value, 100),
        "status": canonical_stat,
        "delivery_schedule_public": safe_str(delivery_schedule, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PROCUREMENT_PARSED",
        "limitations": [
            "Announcement != Fielding.",
            "Contract Value != Final Cost.",
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

    # Resolve Entities (Country/Service/Command)
    ent_refs = {}
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                ename = val.get("name") or val.get("id")
                etype = val.get("type") or key.upper()
                eparent = val.get("parent")
            else:
                ename = str(val)
                etype = key.upper()
                eparent = None
            
            eref = add_entity(parsed, ename, etype, eparent, source_id, evidence_id, f"{rec_ctx}/{key}")
            if eref:
                ent_refs[normalize_text(ename)] = eref
                
    primary_ent_ref = list(ent_refs.values())[0] if ent_refs else None

    # Resolve Units
    unit_items = get_field(rec, ["unit", "formation", "brigade", "division"], as_list=True)
    for item in unit_items:
        if isinstance(item, dict):
            add_unit(
                parsed,
                item.get("designation") or item.get("name"),
                item.get("type"),
                item.get("parent_command") or primary_ent_ref,
                item.get("base_region") or item.get("location_coarse"),
                item.get("equipment"),
                item.get("strength"),
                item.get("readiness"),
                source_id,
                evidence_id,
                f"{rec_ctx}/unit"
            )

    # Resolve Platforms
    plat_items = get_field(rec, PLATFORM_KEYS, as_list=True)
    for item in plat_items:
        if isinstance(item, dict):
            add_platform(
                parsed,
                item.get("name") or item.get("model"),
                item.get("type") or item.get("class"),
                item.get("manufacturer"),
                item.get("status") or item.get("inventory_state"),
                item.get("quantity") or item.get("count"),
                item.get("capability") or item.get("performance_claim"),
                source_id,
                evidence_id,
                f"{rec_ctx}/platform"
            )

    # Resolve Procurement
    proc_items = get_field(rec, PROCUREMENT_KEYS, as_list=True)
    for item in proc_items:
        if isinstance(item, dict):
            add_procurement(
                parsed,
                item.get("program") or item.get("name"),
                item.get("supplier") or item.get("vendor"),
                item.get("customer") or item.get("buyer"),
                item.get("system"),
                item.get("value") or item.get("cost"),
                item.get("status"),
                item.get("schedule") or item.get("timeline"),
                source_id,
                evidence_id,
                f"{rec_ctx}/procurement"
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
                 caution="Mil texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["exercise", "drill", "maneuver"]):
        signals.append("EXERCISE_CONTEXT")
    if any(k in low for k in ["procurement", "contract", "purchase", "order"]):
        signals.append("PROCUREMENT_CONTEXT")
    if any(k in low for k in ["doctrine", "strategy", "concept"]):
        signals.append("DOCTRINE_CONTEXT")
    if any(k in low for k in ["deployment", "rotation", "garrison"]):
        signals.append("DEPLOYMENT_CONTEXT")
    if any(k in low for k in ["readiness", "alert", "standby"]):
        signals.append("READINESS_CONTEXT")

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

    if "org" in fname or "structure" in fname or "ob" in fname:
        return "FORCE_STRUCTURE_OB"
    if "procure" in fname or "budget" in fname or "contract" in fname:
        return "PROCUREMENT_BUDGET_RECORD"
    if "equip" in fname or "spec" in fname or "manual" in fname:
        return "EQUIPMENT_SPEC_DOCS"
    if "exercise" in fname or "report" in fname:
        return "EXERCISE_TRAINING_REPORT"

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
    if "org chart" in low or "order of battle" in low:
        kind = "TEXT_FORCE_STRUCTURE"
    elif "budget" in low or "procurement" in low:
        kind = "TEXT_PROCUREMENT_BUDGET"
    elif "doctrine" in low or "manual" in low:
        kind = "TEXT_DOCTRINE_MANUAL"
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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".mil", ".def"}:
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
            "No targeting, no strike planning, no weapon optimization, no live tracking.",
            "Binary artifacts are hash/metadata preserved only.",
            "Military documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Unit Existence != Readiness. Delivery != Operational.",
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
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_unit_count"] = len(parsed.get("units", []))
    file_evidence["parsed_plat_count"] = len(parsed.get("platforms", []))
    file_evidence["parsed_proc_count"] = len(parsed.get("procurement", []))

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


def assess_capabilities_and_readiness(parsed: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Separates Capability Claims from Verified States.
    Separates Readiness Indicators from Conclusions.
    """
    caps = []
    reads = []
    
    platforms = parsed.get("platforms", [])
    units = parsed.get("units", [])
    
    for p in platforms:
        caps.append({
            "assessment_id": f"CAP-{uuid.uuid4()}",
            "subject_ref": p.get("platform_id"),
            "claimed_state": p.get("capability_state"),
            "inventory_state": p.get("inventory_state"),
            "basis": f"Quantity Claim: {p.get('quantity_visible_or_claimed')}, Manufacturer: {p.get('manufacturer')}",
            "limitations": [
                "Manufacturer spec != Measured performance.",
                "Inventory state does not guarantee availability.",
            ]
        })
        
    for u in units:
        reads.append({
            "indicator_id": f"RDY-{uuid.uuid4()}",
            "subject_ref": u.get("unit_id"),
            "reported_state": u.get("readiness_state"),
            "basis": f"Parent Command: {u.get('parent_entity_ref')}, Base Region: {u.get('base_region_coarse')}",
            "limitations": [
                "Readiness report source reliability varies.",
                "Readiness != Intent to act.",
            ]
        })
        
    return caps, reads


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting Inventory States for same Platform Name
    plat_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in parsed.get("platforms", []):
        nm = p.get("name")
        if nm:
            plat_map[nm].append(p)
            
    for nm, group in plat_map.items():
        states = {g.get("inventory_state") for g in group}
        if len(states) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "INVENTORY_STATE_CONFLICT",
                "subject": nm,
                "values": list(states),
                "possible_explanations": [
                    "Different batches/lots",
                    "Retirement vs New Order",
                    "Data error",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify specific serial ranges or contract IDs.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    exercises = parsed.get("exercises", []) # Note: Exercises aren't fully modeled in simple parser, but placeholder
    deployments = [o for o in parsed.get("observations", []) if "deploy" in o.get("statement", "").lower()]
    
    if exercises or deployments:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed activity may be routine exercise OR rotational deployment OR readiness demonstration.",
            "supporting_facts": ["Activity indicators present."],
            "opposing_facts": ["Could be preparation for operational action (requires more evidence)."],
            "unknowns": ["intent", "scale", "duration"],
            "falsification_conditions": ["Official press release confirms annual scheduled drill."],
            "next_test": "Compare with historical patterns and official doctrine statements.",
            "status": "ANALYTICAL",
        })

    if not hyps:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient dynamic activity data to form movement/deployment hypotheses.",
            "supporting_facts": ["Static structure/equipment data only."],
            "opposing_facts": [],
            "unknowns": ["current posture"],
            "next_test": "Import recent exercise reports or deployment notices.",
            "status": "OPEN",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    units = parsed.get("units", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized military evidence exists?",
            "missing_evidence": "No local MILINT artifact supplied.",
            "likely_source": "Official MoD Publication, Treaty Disclosure, Academic Research.",
            "specialist_owner": "MILINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline force structure analysis.",
            "safety_boundary": "No targeting, no classified solicitation.",
        })

    if units and not any(u.get("readiness_state") != "UNKNOWN" for u in units):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the reported readiness of identified units?",
            "missing_evidence": "Readiness indicators missing.",
            "likely_source": "Annual Defense Report, Official Inspection Summary.",
            "specialist_owner": "MILINT Analyst",
            "priority": "HIGH",
            "expected_information_value": "Clarifies force effectiveness vs paper strength.",
            "safety_boundary": "Do not infer combat intent from readiness alone.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    platforms = parsed.get("platforms", [])
    
    if any(p.get("platform_type") in ["RADAR", "SENSOR", "UAV"] for p in platforms):
        handoffs.append({
            "specialist": "ISRINT / TECHINT",
            "reason": "Sensor/ISR platforms identified.",
            "expected_output": "Technical coverage analysis (non-tactical).",
            "question": "What are the high-level technical characteristics of these sensors?",
        })
        
    if any(p.get("platform_type") in ["MISSILE SYSTEM", "ARTILLERY"] for p in platforms):
        handoffs.append({
            "specialist": "TECHINT / STRATEGIC ANALYST",
            "reason": "Firepower systems identified.",
            "expected_output": "Strategic implication analysis ONLY. No targeting data.",
            "question": "What is the strategic deterrent/defense role of these systems?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "MILINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Is current force understanding sufficient for strategic reporting?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    caps, reads = assess_capabilities_and_readiness(parsed)
    parsed["capability_assessments"] = caps
    parsed["readiness_indicators"] = reads
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
    caps = parsed.get("capability_assessments", [])
    unverified_caps = [c for c in caps if c.get("claimed_state") == "CLAIMED"]
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited targeting, weapon optimization, or live tracking behavior.",
            "reason": "MILINT is strategic intelligence, not a fire-control system.",
            "owner": "MILINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized org charts/procurement/exercise exports before analysis.",
            "reason": "No MILINT evidence artifact available.",
            "owner": "MILINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if unverified_caps:
        return {
            "action": "Seek independent verification for claimed capabilities (e.g., via TECHINT or historical exercise data).",
            "reason": "Capabilities are currently 'Claimed' rather than 'Supported/Demonstrated'.",
            "owner": "MILINT / TECHINT",
            "expected_output": "Upgraded capability confidence level.",
        }

    return {
        "action": "Monitor for changes in procurement status or official exercise announcements.",
        "reason": "Baseline force structure established.",
        "owner": "MILINT Analyst",
        "expected_output": "Updated strategic picture.",
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
    has_units = bool(parsed.get("units"))
    has_procs = bool(parsed.get("procurement"))

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
            "policy_note": "Lawful / public-authorized / non-targeting / analytical military intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_military_questions_scope",
        "MILINT Manager",
        "Convert objective into strategic questions, allowed sources, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_military_records",
        "local evidence store",
        "Store original org charts/reports and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "MilEvidenceObject with SHA256.",
    )

    add(
        "parse_unit_platform_procurement_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT military metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized units/platforms/procs.",
    )

    add(
        "verify_capability_vs_claim",
        "local analyzer",
        "Distinguish between Manufacturer Claims and Demonstrated Capabilities.",
        "COMPLETED_LOCAL" if has_units else "PLANNED_ANALYTIC",
        "Capability Confidence Register.",
        safety_risk="HIGH_IF_PROPAGANDA_ACCEPTED_AS_FACT",
    )

    add(
        "separate_readiness_from_intent",
        "MILINT Analyst",
        "Ensure readiness indicators are not interpreted as hostile intent.",
        "PLANNED_ANALYTIC",
        "Intent-Free Assessment.",
        safety_risk="CRITICAL_IF_INTENT_ASSUMED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_entity_or_unit",
        "questions",
        "units",
        "platforms",
        "procurement",
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
            "Sensitive military context detected. Analysis must remain lawful, public-source, and non-targeting. "
            "No strike planning, no live tracking, no weapon optimization."
        )

    if payload.get("units") or payload.get("platforms"):
        human_review_required = True
        safety_notes.append(
            "Force element context detected. Apply strict safety boundaries. Do not expose sensitive operational details."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal targeting, weapon optimization, or operational harm facilitation."
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
                "No obvious hard policy violation detected, but sensitive military context applies. "
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

    required = ["case_id", "task_id", "objective", "target_entity_or_unit", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No MILINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "org_chart_paths",
        "procurement_paths",
        "equipment_meta_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No military evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Military status is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "What is the organizational structure of the target force?",
        "Which units/formations are publicly documented?",
        "What platforms/equipment are listed in inventories?",
        "Are procurement programs delivered or just ordered?",
        "What is the claimed vs demonstrated capability?",
        "How do exercises reflect doctrinal priorities?",
        "What are the strategic readiness indicators?",
        "How reliable and independent are the sources?",
        "What remains unknown regarding current disposition?",
        "What is the safest next investigative step?",
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#64748b", font=("Segoe UI", 17, "bold")) # Slate Grey accent for Military/Neutral
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
                "Lawful / public-authorized / non-targeting / analytical military intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT unit/platform/procurement parsing only • "
                "No targeting / No strike coords / No weapon optimization / No live tracking • "
                "Existence != Readiness • Delivery != Operational • Readiness != Intent"
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

        ttk.Button(buttons1, text="Add Org Charts / OB", command=self.add_orgs).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Procurement / Budget", command=self.add_procs).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Equipment Specs / Manuals", command=self.add_equip).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Exercise Reports", command=self.add_exers).pack(side="left", padx=4)
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
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#cbd5e1", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "MIL-CASE-001")
        self.set_widget_value("task_id", "MIL-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/public-authorized/non-targeting military intelligence using evidence-first methods.")
        self.set_widget_value("target_entity_or_unit", "Illustrative Example Force F / Unit U")
        self.set_widget_value("target_type", "force_structure_analysis")
        self.set_widget_value("questions", "\n".join(default_questions({"target_entity_or_unit": "Illustrative Example Force F"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["official_mod_pub", "academic_research"], "prohibited_actions": ["generate_strike_coords", "track_live_troops"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_strategic_review"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_NON_TARGETING_MILITARY"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_orgs(self): self._append_paths("org_chart_paths", filedialog.askopenfilenames(title="Select Org Charts", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_procs(self): self._append_paths("procurement_paths", filedialog.askopenfilenames(title="Select Procurement/Budget", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_equip(self): self._append_paths("equipment_meta_paths", filedialog.askopenfilenames(title="Select Equipment Specs", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_exers(self): self._append_paths("exercise_report_paths", filedialog.askopenfilenames(title="Select Exercise Reports", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

        path_fields = ["org_chart_paths", "procurement_paths", "equipment_meta_paths", "exercise_report_paths", "stix_misp_paths"]
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
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nUnits: {len(aggregated['units'])}\nPlatforms: {len(aggregated['platforms'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("units") and not self.parsed.get("platforms"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "entities_preview": self.parsed.get("entities", [])[:100],
            "units_preview": self.parsed.get("units", [])[:100],
            "platforms_preview": self.parsed.get("platforms", [])[:100],
            "procurement_preview": self.parsed.get("procurement", [])[:100],
            "capability_assessments": self.parsed.get("capability_assessments", []),
            "readiness_indicators": self.parsed.get("readiness_indicators", []),
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
            "mode": "LOCAL_DETERMINISTIC_MILINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "entities": parsed.get("entities", [])[:300],
            "units": parsed.get("units", [])[:300],
            "platforms": parsed.get("platforms", [])[:300],
            "procurement": parsed.get("procurement", [])[:300],
            "capability_assessments": parsed.get("capability_assessments", []),
            "readiness_indicators": parsed.get("readiness_indicators", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No targeting, no strike planning, no live tracking.",
                "Existence != Readiness.",
                "Delivery != Operational.",
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
