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


APP_TITLE = "TraceAtlas CTINT AI Employee — Defensive / Lawful / Authorized / Rights-Aware Counter-Terrorism Intelligence Panel"
APP_VERSION = "TraceAtlas CTINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_org_or_incident", "Target Organization / Incident Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "CTINT Questions", "text"),

    ("organizations", "Organizations / Groups (Labels/Aliases)", "text"),
    ("persons", "Persons / Actors (Candidates)", "text"),
    ("incidents", "Incidents / Events", "text"),
    ("claims", "Claims of Responsibility", "text"),
    ("networks", "Networks / Associations", "text"),
    ("financing", "Financing / Support Context", "text"),
    ("propaganda", "Propaganda / Narrative Themes", "text"),
    
    ("org_report_paths", "Official Org Reports / Designations Paths", "text"),
    ("incident_log_paths", "Incident Logs / Court Records Paths", "text"),
    ("media_meta_paths", "Media Metadata / Provenance Paths", "text"),
    ("financial_paths", "Financial / Sanctions Data Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Gov DB/Court/Sanctions/etc.)", "text"),
]


TARGET_TYPES = [
    "organization_resolution",
    "incident_attribution_review",
    "claim_authenticity_check",
    "network_association_analysis",
    "financing_context_review",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "organizations",
    "persons",
    "incidents",
    "claims",
    "networks",
    "financing",
    "propaganda",
    "org_report_paths",
    "incident_log_paths",
    "media_meta_paths",
    "financial_paths",
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
    "organization_resolution",
    "incident_attribution_review",
    "claim_authenticity_check",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR TERRORISM FACILITATION/HARM
POLICY_BLOCK_PATTERNS = [
    r"\b(?:plan|design|optimize|provide)\b[^\n]{0,140}\b(?:attack|bomb|explosive|weapon|assault|hostage|kidnap|sabotage)\b",
    r"\b(?:teach|guide|instruct)\b[^\n]{0,140}\b(?:how to make bomb|construct weapon|evade surveillance|cross border illegally|launder money)\b",
    r"\b(?:create|generate|write)\b[^\n]{0,140}\b(?:propaganda|recruitment material|radicalization content|manifesto)\b",
    r"\b(?:contact|infiltrate|impersonate)\b[^\n]{0,140}\b(?:terrorist group|suspect|extremist channel)\b",
    r"\b(?:surveil|track|monitor)\b[^\n]{0,140}\b(?:private person|family member|journalist|researcher)\b",
]


SAFE_ALTERNATIVES = [
    "Provide defensive/lawful/rights-aware counter-terrorism intelligence: resolve organizations/incidents/claims, analyze networks and financing contexts conservatively, verify source independence, and support human-led legal/investigative processes without facilitating violence or violating civil liberties.",
    "Do not plan attacks, provide weapon construction details, generate propaganda, conduct unlawful surveillance, or profile based on religion/ethnicity/nationality.",
    "Separate Ideology from Violence, Association from Membership, Membership from Participation, and Claim from Verified Responsibility.",
    "Use deterministic logic for designation matching and timeline analysis. Escalate consequential real-person attributions to authorized human review with strict privacy safeguards.",
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
    r"join\s+(?:the\s+)?(?:group|channel)",
]


# Regex helpers for CTINT identifiers
ORG_ID_RE = re.compile(r"\b(?:Org|Group|Cell|Branch)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)
INCIDENT_ID_RE = re.compile(r"\b(?:Incident|Event|Attack)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)


ENTITY_ROLE_KEYS = [
    "organization",
    "group",
    "entity",
    "actor",
    "person",
    "alias",
]


INCIDENT_KEYS = [
    "incident",
    "event",
    "attack",
    "plot",
    "arrest",
]


CLAIM_KEYS = [
    "claim",
    "responsibility",
    "statement",
]


NETWORK_KEYS = [
    "network",
    "association",
    "link",
    "connection",
]


FINANCIAL_KEYS = [
    "finance",
    "fund",
    "transfer",
    "payment",
    "charity",
]


PROPAGANDA_KEYS = [
    "propaganda",
    "narrative",
    "publication",
    "media",
]


PROTECTED_TRAIT_KEYWORDS = [
    "religion",
    "ethnicity",
    "race",
    "nationality",
    "political belief",
    "immigration status",
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


def check_protected_traits(text: str) -> List[str]:
    """Flags if text uses prohibited demographic factors as indicators."""
    low = normalize_text(text)
    found = []
    for kw in PROTECTED_TRAIT_KEYWORDS:
        if kw in low:
            found.append(kw)
    return found


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "organizations": [],
        "persons": [],
        "incidents": [],
        "claims": [],
        "networks": [],
        "financing": [],
        "propaganda": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "threat_assessments": [],
        "rights_flags": [],
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
    
    # Protected Trait Check
    trait_flags = check_protected_traits(redacted)
    if trait_flags:
        add_note(parsed, "PROTECTED_TRAIT_RISK", keywords=trait_flags, source_id=source_id, 
                 caution="Demographic factor mentioned. Do NOT use as threat indicator.")

    parsed["observations"].append({
        "observation_id": f"OBS-{uuid.uuid4()}",
        "statement": redacted,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": context[:200],
        "state": "SOURCE_OBSERVED",
        "secret_flags": secret_flags,
        "prompt_injection_flags": injection_flags,
        "protected_trait_flags": trait_flags,
        "content_hash": sha256_text(str(statement or "")),
        "limitations": [
            "Observation records what was stated/published, not necessarily its factual truth or legal standing.",
            "Ideology/Rhetoric != Operational Intent.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in terror docs are ignored.")


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
            "Multiple news articles quoting one police release are not independent sources.",
        ],
    })


def add_organization(
    parsed: Dict[str, Any],
    name: Any,
    org_id: Any,
    designation_status: Any,
    aliases: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    oi = safe_str(org_id, 200)
    
    if not n and not oi:
        return None
        
    oid = f"ORG-{uuid.uuid4()}"
    
    des_norm = normalize_text(designation_status).upper()
    canonical_des = "UNKNOWN"
    if "DESIGNATED" in des_norm or "SANCTIONED" in des_norm:
        canonical_des = "OFFICIALLY_DESIGNATED"
    elif "ALLEGED" in des_norm or "REPORTED" in des_norm:
        canonical_des = "SOURCE_REPORTED"
        
    parsed["organizations"].append({
        "organization_id": oid,
        "canonical_name": n,
        "external_org_id": oi,
        "designation_status": canonical_des,
        "alias_candidates": listify(aliases)[:20],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ORG_PARSED",
        "limitations": [
            "Designation by Authority A does not mean universal guilt of all members.",
            "Alias resolution requires strong corroboration.",
        ],
    })
    return oid


def add_person(
    parsed: Dict[str, Any],
    name: Any,
    role_claim: Any,
    association_type: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    pid = f"PER-{uuid.uuid4()}"
    
    assoc_norm = normalize_text(association_type).upper()
    canonical_assoc = "UNKNOWN"
    if "MEMBER" in assoc_norm:
        canonical_assoc = "MEMBERSHIP_CLAIM"
    elif "ASSOCIATE" in assoc_norm or "CONTACT" in assoc_norm:
        canonical_assoc = "ASSOCIATION_CANDIDATE"
    elif "LEADER" in assoc_norm:
        canonical_assoc = "LEADERSHIP_CLAIM"
        
    parsed["persons"].append({
        "person_id": pid,
        "display_name": n,
        "claimed_role": safe_str(role_claim, 100).upper() or "UNKNOWN",
        "association_state": canonical_assoc,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PERSON_PARSED",
        "limitations": [
            "Association != Membership. Membership != Participation.",
            "Family/Friendship alone does not establish complicity.",
        ],
    })
    return pid


def add_incident(
    parsed: Dict[str, Any],
    desc: Any,
    inc_type: Any,
    location: Any,
    time_occurred: Any,
    casualties: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    ed = safe_str(desc, 500)
    if not ed:
        return
        
    iid = f"INC-{uuid.uuid4()}"
    
    typ_norm = normalize_text(inc_type).upper()
    canonical_typ = "UNKNOWN"
    if "ATTACK" in typ_norm or "BOMB" in typ_norm or "SHOOTING" in typ_norm:
        canonical_typ = "VIOLENT_INCIDENT"
    elif "ARREST" in typ_norm or "RAID" in typ_norm:
        canonical_typ = "LAW_ENFORCEMENT_ACTION"
    elif "PROPAGANDA" in typ_norm or "VIDEO" in typ_norm:
        canonical_typ = "MEDIA_EVENT"
        
    parsed["incidents"].append({
        "incident_id": iid,
        "description": ed,
        "incident_type": canonical_typ,
        "location_general": safe_str(location, 200), # Keep high level
        "time_occurred": safe_str(time_occurred, 100),
        "casualty_claims": safe_str(casualties, 200),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "INCIDENT_PARSED",
        "limitations": [
            "Casualty counts vary by source. Do not average silently.",
            "Method classification is high-level only. No construction details.",
        ],
    })


def add_claim(
    parsed: Dict[str, Any],
    claimant_org: Any,
    incident_ref: Any,
    authenticity_state: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    cid = f"CLM-{uuid.uuid4()}"
    
    auth_norm = normalize_text(authenticity_state).upper()
    canonical_auth = "UNVERIFIED"
    if "AUTHENTIC" in auth_norm or "CONFIRMED" in auth_norm:
        canonical_auth = "CHANNEL_AUTHENTIC"
    elif "FALSE" in auth_norm or "DISPUTED" in auth_norm:
        canonical_auth = "DISPUTED"
        
    parsed["claims"].append({
        "claim_id": cid,
        "claimant_org_ref": claimant_org,
        "incident_ref": incident_ref,
        "authenticity_state": canonical_auth,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "CLAIM_PARSED",
        "limitations": [
            "Authentic Channel != True Responsibility.",
            "Claims may be opportunistic or propaganda-driven.",
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
                odes = val.get("designation") or val.get("status")
                oalias = val.get("aliases")
            else:
                oname = str(val)
                odes = ""
                oalias = []
            
            oref = add_organization(parsed, oname, "", odes, oalias, source_id, evidence_id, f"{rec_ctx}/{key}")
            if oref:
                org_refs.append(oref)

    primary_org_ref = org_refs[0] if org_refs else None

    # Resolve Persons
    pers_items = get_field(rec, ["person", "actor", "individual"], as_list=True)
    for item in pers_items:
        if isinstance(item, dict):
            add_person(
                parsed,
                item.get("name") or item.get("id"),
                item.get("role"),
                item.get("association") or item.get("relationship"),
                source_id,
                evidence_id,
                f"{rec_ctx}/person"
            )

    # Resolve Incidents
    inc_items = get_field(rec, INCIDENT_KEYS, as_list=True)
    inc_refs = []
    for item in inc_items:
        if isinstance(item, dict):
            iiref = f"INC_LOCAL_{len(inc_refs)}" # Placeholder ref
            add_incident(
                parsed,
                item.get("description") or item.get("summary"),
                item.get("type"),
                item.get("location"),
                item.get("time") or item.get("date"),
                item.get("casualties"),
                source_id,
                evidence_id,
                f"{rec_ctx}/incident"
            )
            inc_refs.append(iiref)

    # Resolve Claims
    clm_items = get_field(rec, CLAIM_KEYS, as_list=True)
    for item in clm_items:
        if isinstance(item, dict):
            add_claim(
                parsed,
                item.get("organization") or primary_org_ref,
                item.get("incident") or (inc_refs[0] if inc_refs else None),
                item.get("authenticity") or item.get("verification"),
                source_id,
                evidence_id,
                f"{rec_ctx}/claim"
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
                 caution="Terror texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["attack", "bomb", "shooting", "explosion"]):
        signals.append("VIOLENT_INCIDENT_CONTEXT")
    if any(k in low for k in ["claim", "responsibility", "we did it"]):
        signals.append("CLAIM_OF_RESPONSIBILITY_CONTEXT")
    if any(k in low for k in ["member", "leader", "commander"]):
        signals.append("ROLE_CLAIM_CONTEXT")
    if any(k in low for k in ["fund", "money", "donation", "support"]):
        signals.append("FINANCING_CONTEXT")
    if any(k in low for k in ["video", "magazine", "broadcast", "message"]):
        signals.append("PROPAGANDA_CONTEXT")

    if signals:
        add_note(parsed, "CT_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_CT_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "designat" in fname or "sanction" in fname:
        return "DESIGNATION_SANCTIONS_RECORD"
    if "court" in fname or "indictment" in fname:
        return "LEGAL_COURT_RECORD"
    if "incident" in fname or "report" in fname:
        return "INCIDENT_REPORT"
    if "propaganda" in fname or "media" in fname:
        return "MEDIA_PROPAGANDA_META"

    return "GENERIC_CT_EVIDENCE"


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
    kind = "CSV_CT_DATA"

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
    if "designat" in low or "sanction" in low:
        kind = "TEXT_DESIGNATION_LIST"
    elif "court" in low or "verdict" in low:
        kind = "TEXT_COURT_JUDGMENT"
    elif "incident" in low or "attack" in low:
        kind = "TEXT_INCIDENT_REPORT"
    else:
        kind = "TEXT_GENERIC_CT_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".ct", ".terror"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_ct_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No attack planning, no weapon construction, no surveillance abuse.",
            "Binary artifacts are hash/metadata preserved only.",
            "Terror documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Religion/Ethnicity/Nationality NEVER used as indicators.",
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
            file_evidence["content_kind"] = "BINARY_CT_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary terrorism document/media detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_org_count"] = len(parsed.get("organizations", []))
    file_evidence["parsed_inc_count"] = len(parsed.get("incidents", []))
    file_evidence["parsed_claim_count"] = len(parsed.get("claims", []))

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


def assess_threat_dimensions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Separates Capability, Intent, and Imminence without collapsing into one score.
    """
    assessments = []
    
    incidents = parsed.get("incidents", [])
    claims = parsed.get("claims", [])
    
    capability_indicator = "PRESENT" if incidents else "ABSENT"
    intent_indicator = "UNKNOWN"
    
    # Check for authenticated claims linking to specific incidents
    for clm in claims:
        if clm.get("authenticity_state") == "CHANNEL_AUTHENTIC":
            intent_indicator = "SUGGESTED_BY_CLAIM"
            break
            
    imminence_indicator = "INCONCLUSIVE" # Always inconclusive without live intel
    
    assessments.append({
        "assessment_id": f"THR-{uuid.uuid4()}",
        "capability_state": capability_indicator,
        "intent_state": intent_indicator,
        "imminence_state": imminence_indicator,
        "evidence_basis": f"Incidents: {len(incidents)}, Authenticated Claims: {sum(1 for c in claims if c.get('authenticity_state')=='CHANNEL_AUTHENTIC')}",
        "limitations": [
            "Capability != Intent.",
            "Claim Authenticity != Truth of Action.",
            "Imminence cannot be determined from static data.",
        ]
    })
    
    return assessments


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting Designation statuses for same org name
    org_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for o in parsed.get("organizations", []):
        nm = o.get("canonical_name")
        if nm:
            org_map[nm].append(o)
            
    for nm, group in org_map.items():
        statuses = {g.get("designation_status") for g in group}
        if len(statuses) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "DESIGNATION_STATUS_CONFLICT",
                "subject": nm,
                "values": list(statuses),
                "possible_explanations": [
                    "Different jurisdictions",
                    "Different time periods",
                    "Delisting occurred",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify specific authority and date for each designation.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    incidents = parsed.get("incidents", [])
    claims = parsed.get("claims", [])
    
    if not incidents and not claims:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient terrorism-related data to form attribution hypotheses.",
            "supporting_facts": ["Empty incident/claim lists."],
            "opposing_facts": [],
            "unknowns": ["actor identity", "operational link"],
            "next_test": "Import valid court/designation/incident exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if incidents:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed incidents may be coordinated by a single actor OR coincidental/localized events.",
            "supporting_facts": [f"{len(incidents)} incident(s) found."],
            "opposing_facts": ["Similar methods can be copycat or independent."],
            "unknowns": ["command structure", "communication links"],
            "falsification_conditions": ["Independent forensic evidence shows different perpetrators."],
            "next_test": "Analyze communication intercepts (if authorized) and financial trails.",
            "status": "ANALYTICAL",
        })

    if claims:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Claims of responsibility may be authentic OR opportunistic propaganda.",
            "supporting_facts": [f"{len(claims)} claim(s) logged."],
            "opposing_facts": ["Channels can be hijacked or impersonated."],
            "unknowns": ["channel control history"],
            "falsification_conditions": ["Channel was seized/hijacked at time of claim."],
            "next_test": "Verify channel provenance and linguistic fingerprinting.",
            "status": "CAUTION",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    persons = parsed.get("persons", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized CTINT evidence exists?",
            "missing_evidence": "No local CTINT artifact supplied.",
            "likely_source": "UN Sanctions List, Court Judgment, Official Gov Report.",
            "specialist_owner": "CTINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline organization/incident analysis.",
            "safety_boundary": "No infiltration, no contact, no surveillance abuse.",
        })

    if persons and not any(p.get("association_state") in ["MEMBERSHIP_SUPPORTED", "OPERATIONAL_PARTICIPATION_SUPPORTED"] for p in persons):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Is there evidence of actual membership/participation vs mere association?",
            "missing_evidence": "Strong relational evidence missing.",
            "likely_source": "Forensic digital evidence, Witness testimony (HUMINT), Financial records.",
            "specialist_owner": "CTINT / HUMINT / FININT",
            "priority": "HIGH",
            "expected_information_value": "Prevents false positive labeling of associates/family.",
            "safety_boundary": "Do not infer guilt from friendship/family ties.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    financing = parsed.get("financing", [])
    media = parsed.get("propaganda", [])
    
    if financing:
        handoffs.append({
            "specialist": "FININT / CRYPTOINT / PAYMENTINT",
            "reason": "Financial/support indicators detected.",
            "expected_output": "Transaction tracing, entity resolution, purpose verification.",
            "question": "Can these flows be linked to organizational command structures?",
        })
        
    if media:
        handoffs.append({
            "specialist": "SOCMINT / DARKINT / IMINT",
            "reason": "Propaganda/Media artifacts detected.",
            "expected_output": "Provenance verification, channel authentication, narrative analysis.",
            "question": "Are these channels officially controlled by the designated group?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "CTINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Is current attribution confidence sufficient for legal action?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["threat_assessments"] = assess_threat_dimensions(parsed)
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
    high_intent = any(t.get("intent_state") == "SUGGESTED_BY_CLAIM" for t in threats)
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited attack planning, surveillance abuse, or bias behavior.",
            "reason": "CTINT is defensive intelligence, not an offensive tool.",
            "owner": "CTINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized court/designation/incident exports before analysis.",
            "reason": "No CTINT evidence artifact available.",
            "owner": "CTINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if high_intent:
        return {
            "action": "Prioritize verification of claim authenticity and channel provenance. Seek independent corroboration.",
            "reason": "Authenticated claims suggest potential organizational involvement but require proof of action.",
            "owner": "CTINT Analyst / SOCMINT",
            "expected_output": "Verified attribution or falsified claim.",
        }

    return {
        "action": "Continue monitoring public designations and court records. Update network maps conservatively.",
        "reason": "No immediate high-confidence threat indicators.",
        "owner": "CTINT Analyst",
        "expected_output": "Updated baseline knowledge graph.",
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
    has_incidents = bool(parsed.get("incidents"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General CTINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Defensive / lawful / rights-aware counter-terrorism intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_ct_questions_scope",
        "CTINT Manager",
        "Convert objective into CTINT questions, allowed sources, and rights boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_ct_evidence",
        "local evidence store",
        "Store original reports/court records and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "CtEvidenceObject with SHA256.",
    )

    add(
        "parse_org_incident_claim_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT terrorism metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized orgs/incidents/claims.",
    )

    add(
        "verify_designation_and_legal_status",
        "local analyzer",
        "Ensure designation matches specific authority/jurisdiction. Separate charge from conviction.",
        "PLANNED_ANALYTIC",
        "Legal Status Register.",
        safety_risk="HIGH_IF_LEGAL_CONFUSION",
    )

    add(
        "check_protected_traits_bias",
        "local filter",
        "Ensure religion/ethnicity/nationality are excluded from risk scoring.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_SAFETY_CHECK",
        "Bias-Free Assessment Flag.",
        safety_risk="CRITICAL_IF_BIAS_PRESENT",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_org_or_incident",
        "questions",
        "organizations",
        "persons",
        "incidents",
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
            "Sensitive CTINT context detected. Analysis must remain defensive, lawful, and rights-aware. "
            "No attack planning, no surveillance abuse, no profiling."
        )

    if payload.get("persons") or payload.get("organizations"):
        human_review_required = True
        safety_notes.append(
            "Entity identification context detected. Apply strict privacy safeguards. Do not expose unnecessary PII."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal attack planning, surveillance abuse, or discriminatory profiling."
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
                "No obvious hard policy violation detected, but sensitive terrorism/legal context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/lawful CTINT evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target_org_or_incident", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No CTINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "org_report_paths",
        "incident_log_paths",
        "legal_records_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No CTINT evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Legal/Designation status is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which organizations are designated or alleged involved?",
        "What incidents are reported and how are they attributed?",
        "Are claims of responsibility from authentic channels?",
        "What is the difference between association and membership here?",
        "Is there evidence of financing or material support?",
        "How reliable and independent are the sources?",
        "Are protected traits (religion/ethnicity) being incorrectly used?",
        "What legal/court outcomes exist?",
        "What remains unknown regarding operational intent?",
        "What is the safest next investigative step?",
    ]


class TraceAtlasCTINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#dc2626", font=("Segoe UI", 17, "bold")) # Deep Red accent for Terror/Threat Severity
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
        ttk.Label(header, text="TraceAtlas CTINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Defensive / lawful / authorized / rights-aware counter-terrorism intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT org/incident/claim parsing only • "
                "No attack planning / No weapon construction / No surveillance abuse / No profiling • "
                "Ideology != Violence • Association != Membership • Claim != Responsibility"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="CTINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Ct Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Org Reports / Designations", command=self.add_orgs).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Incident / Court Records", command=self.add_incidents).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Media / Propaganda Meta", command=self.add_media).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Financial / Sanctions Data", command=self.add_financial).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local CTINT Evidence", command=self.analyze_local_ct).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Ct Plan", command=self.generate_plan).pack(side="left", padx=4)
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
        self.set_widget_value("case_id", "CT-CASE-001")
        self.set_widget_value("task_id", "CT-TASK-001")
        self.set_widget_value("objective", "Analyze defensive/lawful/rights-aware counter-terrorism intelligence using evidence-first methods.")
        self.set_widget_value("target_org_or_incident", "Illustrative Example Group X / Incident Y")
        self.set_widget_value("target_type", "organization_resolution")
        self.set_widget_value("questions", "\n".join(default_questions({"target_org_or_incident": "Illustrative Example Group X"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public_court_db", "un_sanctions_list"], "prohibited_actions": ["plan_attack", "surveil_private"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_security_review"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_DEFENSIVE_LAWFUL_RIGHTS_AWARE"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_orgs(self): self._append_paths("org_report_paths", filedialog.askopenfilenames(title="Select Org Reports", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_incidents(self): self._append_paths("incident_log_paths", filedialog.askopenfilenames(title="Select Incident/Court Records", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_media(self): self._append_paths("media_meta_paths", filedialog.askopenfilenames(title="Select Media Meta", filetypes=[("Meta", "*.json *.txt"), ("All", "*.*")]), "Added")
    def add_financial(self): self._append_paths("financial_paths", filedialog.askopenfilenames(title="Select Financial Data", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_ct(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["org_report_paths", "incident_log_paths", "media_meta_paths", "financial_paths", "stix_misp_paths"]
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
            f, parsed = analyze_ct_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nOrgs: {len(aggregated['organizations'])}\nIncidents: {len(aggregated['incidents'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("organizations") and not self.parsed.get("incidents"):
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
            "persons_preview": self.parsed.get("persons", [])[:100],
            "incidents_preview": self.parsed.get("incidents", [])[:100],
            "claims_preview": self.parsed.get("claims", [])[:100],
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
            "mode": "LOCAL_DETERMINISTIC_CTINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "organizations": parsed.get("organizations", [])[:300],
            "persons": parsed.get("persons", [])[:300],
            "incidents": parsed.get("incidents", [])[:300],
            "claims": parsed.get("claims", [])[:300],
            "threat_assessments": parsed.get("threat_assessments", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No attack planning, no surveillance abuse, no profiling.",
                "Association != Membership.",
                "Claim != Responsibility.",
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
        app = TraceAtlasCTINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")