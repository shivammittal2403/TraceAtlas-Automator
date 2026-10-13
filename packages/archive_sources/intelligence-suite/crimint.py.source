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


APP_TITLE = "TraceAtlas CRIMINT AI Employee — Authorized / Evidence-First / Privacy-Aware / Human-Governed Criminal Intelligence Panel"
APP_VERSION = "TraceAtlas CRIMINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_case_ref", "Target Case Reference / Incident ID", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "CRIMINT Questions", "text"),

    ("jurisdictions", "Jurisdictions", "text"),
    ("persons", "Persons / Subjects / Witnesses / Victims", "text"),
    ("organizations", "Organizations / Groups", "text"),
    ("aliases", "Aliases / Handles / Personas", "text"),
    ("accounts", "Accounts (Bank/Crypto/Digital)", "text"),
    ("vehicles", "Vehicles / Assets", "text"),
    ("locations", "Locations / Scenes", "text"),
    ("communications", "Communications Context", "text"),
    ("transactions", "Transactions / Payments", "text"),
    
    ("case_report_paths", "Case Report / Complaint Paths", "text"),
    ("court_record_paths", "Court Record / Legal Status Paths", "text"),
    ("forensic_paths", "Forensic / Digital Evidence Paths", "text"),
    ("financial_paths", "Financial / Transaction Log Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Legal Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (LEA System/Court DB/etc.)", "text"),
]


TARGET_TYPES = [
    "case_linkage_analysis",
    "entity_resolution_check",
    "legal_status_verification",
    "modus_operandi_comparison",
    "network_association_review",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "jurisdictions",
    "persons",
    "organizations",
    "aliases",
    "accounts",
    "vehicles",
    "locations",
    "communications",
    "transactions",
    "case_report_paths",
    "court_record_paths",
    "forensic_paths",
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
    "case_linkage_analysis",
    "entity_resolution_check",
    "legal_status_verification",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR CRIME ENABLEMENT/EVASION/HARM
POLICY_BLOCK_PATTERNS = [
    r"\b(?:teach|explain|guide|instruct)\b[^\n]{0,140}\b(?:how to commit crime|evidence destruction|forensic evasion|police evasion|money laundering|smuggling|trafficking|fraud method)\b",
    r"\b(?:plan|design|optimize)\b[^\n]{0,140}\b(?:burglary|robbery|hacking|phishing|extortion|kidnapping|surveillance evasion)\b",
    r"\b(?:hack|intrude|access|steal)\b[^\n]{0,140}\b(?:suspect account|private data|law enforcement system|court database)\b",
    r"\b(?:threaten|coerce|intimidate|blackmail|dox|harass)\b[^\n]{0,140}\b(?:witness|subject|victim|official)\b",
    r"\b(?:impersonate|pretend to be)\b[^\n]{0,140}\b(?:police|investigator|judge|lawyer)\b",
    r"\b(?:fabricate|forge|create false)\b[^\n]{0,140}\b(?:evidence|witness statement|court record|transaction log)\b",
]


SAFE_ALTERNATIVES = [
    "Provide authorized/evidence-first/privacy-aware/human-governed criminal intelligence: resolve cases/entities/legal statuses, analyze associations and modus operandi patterns conservatively, preserve exculpatory evidence, and generate investigative gaps without facilitating crime, evasion, or harm.",
    "Do not teach crime methods, evade forensics/police, launder money, hack systems, threaten witnesses, impersonate officials, or fabricate evidence.",
    "Separate Allegation from Fact, Arrest from Conviction, Association from Participation, Account from Person, and Vehicle Owner from Driver.",
    "Use deterministic logic for legal status ladders. Escalate consequential attributions to authorized human review with strict privacy safeguards.",
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
    r"contact\s+(?:the\s+)?(?:suspect|witness)",
]


# Regex helpers for identifiers
CASE_ID_RE = re.compile(r"\b(?:Case|Incident|File)\s*(?:No\.?\s*)?[A-Z0-9\-\/]+\b", re.I)
PERSON_NAME_RE = re.compile(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b") # Simple heuristic


ENTITY_ROLE_KEYS = [
    "person",
    "subject",
    "witness",
    "victim",
    "accused",
    "suspect",
    "organization",
    "group",
    "company",
]


LEGAL_STATUS_MAP = {
    "unknown_person": "UNKNOWN_PERSON",
    "person_of_relevance": "PERSON_OF_RELEVANCE",
    "witness": "WITNESS",
    "victim": "VICTIM",
    "complainant": "COMPLAINANT",
    "subject_of_report": "SUBJECT_OF_REPORT",
    "investigative_lead": "INVESTIGATIVE_LEAD",
    "suspect_candidate": "SUSPECT_CANDIDATE",
    "official_suspect": "OFFICIAL_SUSPECT",
    "accused": "ACCUSED",
    "arrested": "ARRESTED",
    "charged": "CHARGED",
    "indicted": "INDICTED",
    "on_trial": "ON_TRIAL",
    "convicted": "CONVICTED",
    "acquitted": "ACQUITTED",
    "case_dismissed": "CASE_DISMISSED",
    "exonerated": "EXONERATED",
    "cleared": "CLEARED",
}


RELATIONSHIP_TYPES = [
    "FAMILY_RELATIONSHIP_REPORTED",
    "SOCIAL_ASSOCIATION",
    "BUSINESS_ASSOCIATION",
    "CO_WORKER",
    "COMMUNICATED_WITH",
    "TRANSACTED_WITH",
    "TRAVELED_WITH",
    "CO_LOCATED_WITH",
    "SHARED_ACCOUNT_CANDIDATE",
    "SHARED_ASSET",
    "CO_ACCUSED",
    "SOURCE_REPORTED_ASSOCIATE",
    "UNKNOWN",
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


def map_legal_status(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return LEGAL_STATUS_MAP.get(norm, "STATUS_UNKNOWN")


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "cases": [],
        "events": [],
        "persons": [],
        "organizations": [],
        "relationships": [],
        "allegations": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "exculpatory_evidence": [],
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
            "Observation records what was stated/reported, not necessarily its factual truth or legal standing.",
            "Allegation is distinct from verified fact.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in case docs are ignored.")


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


def add_case(
    parsed: Dict[str, Any],
    case_ref: Any,
    jurisdiction: Any,
    case_type: Any,
    opened_at: Any,
    closed_at: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    cr = safe_str(case_ref, 200)
    if not cr:
        return None
        
    cid = f"CASE-{uuid.uuid4()}"
    parsed["cases"].append({
        "case_record_id": cid,
        "external_case_ref": cr,
        "jurisdiction": safe_str(jurisdiction, 100),
        "case_type": safe_str(case_type, 100).upper() or "UNKNOWN",
        "opened_at": safe_str(opened_at, 100),
        "closed_at": safe_str(closed_at, 100),
        "status": map_legal_status(status), # Reusing map for simplicity, though case status differs slightly
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "CASE_PARSED",
        "limitations": [
            "Case linkage requires multiple diagnostic indicators.",
            "Open case does not imply guilt of any subject.",
        ],
    })
    return cid


def add_event(
    parsed: Dict[str, Any],
    event_desc: Any,
    event_type: Any,
    time_occurred: Any,
    location: Any,
    participants: Any, # List of Person IDs
    victims: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    ed = safe_str(event_desc, 500)
    if not ed:
        return
        
    eid = f"EVT-{uuid.uuid4()}"
    
    parsed["events"].append({
        "event_id": eid,
        "description": ed,
        "event_type": safe_str(event_type, 100).upper() or "UNKNOWN",
        "time_occurred": safe_str(time_occurred, 100),
        "location": safe_str(location, 200),
        "participant_refs": listify(participants)[:50],
        "victim_refs": listify(victims)[:50],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "EVENT_PARSED",
        "limitations": [
            "Event observation does not prove intent or specific actor responsibility without corroboration.",
        ],
    })


def add_person(
    parsed: Dict[str, Any],
    name: Any,
    role: Any,
    legal_status: Any,
    aliases: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    pid = f"PER-{uuid.uuid4()}"
    
    stat_norm = normalize_text(legal_status).upper()
    canonical_stat = "STATUS_UNKNOWN"
    if "CONVICTED" in stat_norm:
        canonical_stat = "CONVICTED"
    elif "ACQUITTED" in stat_norm or "DISMISSED" in stat_norm:
        canonical_stat = "ACQUITTED"
    elif "CHARGED" in stat_norm or "INDICTED" in stat_norm:
        canonical_stat = "CHARGED"
    elif "ARRESTED" in stat_norm:
        canonical_stat = "ARRESTED"
    elif "SUSPECT" in stat_norm:
        canonical_stat = "SUSPECT_CANDIDATE"
        
    parsed["persons"].append({
        "person_id": pid,
        "display_name": n,
        "role_in_case": safe_str(role, 100).upper() or "UNKNOWN",
        "legal_status": canonical_stat,
        "alias_candidates": listify(aliases)[:20],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PERSON_PARSED",
        "limitations": [
            "Name match alone is insufficient for identity resolution.",
            "Legal status must be tracked temporally. Acquittal supersedes prior charge.",
        ],
    })
    return pid


def add_relationship(
    parsed: Dict[str, Any],
    entity_a: Any,
    entity_b: Any,
    rel_type: Any,
    valid_from: Any,
    valid_to: Any,
    confidence: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    rid = f"REL-{uuid.uuid4()}"
    
    rt = safe_str(rel_type, 100).upper()
    conf_norm = normalize_text(confidence).upper()
    
    parsed["relationships"].append({
        "relationship_id": rid,
        "entity_a_ref": entity_a,
        "entity_b_ref": entity_b,
        "relationship_type": rt if rt in RELATIONSHIP_TYPES else "UNKNOWN",
        "valid_from": safe_str(valid_from, 100),
        "valid_to": safe_str(valid_to, 100),
        "confidence": conf_norm or "LOW",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "RELATIONSHIP_PARSED",
        "limitations": [
            "Association does not equal conspiracy or participation.",
            "Communication frequency does not prove coordination.",
        ],
    })


def add_allegation(
    parsed: Dict[str, Any],
    claimant: Any,
    subject: Any,
    conduct: Any,
    verification_state: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    aid = f"ALG-{uuid.uuid4()}"
    
    ver_norm = normalize_text(verification_state).upper()
    canonical_ver = "UNVERIFIED"
    if "SUPPORTED" in ver_norm or "CORROBORATED" in ver_norm:
        canonical_ver = "SUPPORTED"
    elif "REFUTED" in ver_norm or "CLEAR" in ver_norm:
        canonical_ver = "REFUTED"
        
    parsed["allegations"].append({
        "allegation_id": aid,
        "claimant_ref": claimant,
        "subject_ref": subject,
        "alleged_conduct": safe_str(conduct, 500),
        "verification_state": canonical_ver,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ALLEGATION_PARSED",
        "limitations": [
            "Allegation is a claim, not a fact.",
            "Exculpatory evidence must be actively sought.",
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

    # Resolve Cases
    case_items = get_field(rec, ["case", "incident", "file"], as_list=True)
    primary_case_ref = None
    for item in case_items:
        if isinstance(item, dict):
            cref = add_case(
                parsed,
                item.get("id") or item.get("reference"),
                item.get("jurisdiction"),
                item.get("type"),
                item.get("opened_at"),
                item.get("closed_at"),
                item.get("status"),
                source_id,
                evidence_id,
                f"{rec_ctx}/case"
            )
            if cref and not primary_case_ref:
                primary_case_ref = cref

    # Resolve Persons
    person_refs = []
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                pname = val.get("name") or val.get("id")
                prole = val.get("role") or key.upper()
                pst = val.get("legal_status") or val.get("status")
                palias = val.get("aliases")
            else:
                pname = str(val)
                prole = key.upper()
                pst = "UNKNOWN"
                palias = []
            
            pref = add_person(parsed, pname, prole, pst, palias, source_id, evidence_id, f"{rec_ctx}/{key}")
            if pref:
                person_refs.append(pref)

    # Resolve Events
    evt_items = get_field(rec, ["event", "occurrence", "incident_detail"], as_list=True)
    for item in evt_items:
        if isinstance(item, dict):
            add_event(
                parsed,
                item.get("description") or item.get("summary"),
                item.get("type"),
                item.get("time") or item.get("timestamp"),
                item.get("location"),
                item.get("participants") or person_refs,
                item.get("victims"),
                source_id,
                evidence_id,
                f"{rec_ctx}/event"
            )

    # Resolve Relationships
    rel_items = get_field(rec, ["relationship", "association", "link"], as_list=True)
    for item in rel_items:
        if isinstance(item, dict):
            ea = item.get("entity_a") or (person_refs[0] if person_refs else None)
            eb = item.get("entity_b") or (person_refs[1] if len(person_refs) > 1 else None)
            if ea and eb:
                add_relationship(
                    parsed,
                    ea,
                    eb,
                    item.get("type"),
                    item.get("start_date"),
                    item.get("end_date"),
                    item.get("confidence"),
                    source_id,
                    evidence_id,
                    f"{rec_ctx}/relationship"
                )

    # Resolve Allegations
    alg_items = get_field(rec, ["allegation", "claim", "accusation"], as_list=True)
    for item in alg_items:
        if isinstance(item, dict):
            subj = item.get("subject") or (person_refs[0] if person_refs else None)
            clmt = item.get("claimant") or (person_refs[1] if len(person_refs) > 1 else None)
            if subj:
                add_allegation(
                    parsed,
                    clmt,
                    subj,
                    item.get("conduct") or item.get("description"),
                    item.get("verification"),
                    source_id,
                    evidence_id,
                    f"{rec_ctx}/allegation"
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
                 caution="Case texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["arrest", "charge", "indictment"]):
        signals.append("LEGAL_PROCESS_CONTEXT")
    if any(k in low for k in ["convict", "acquit", "dismiss", "exonerate"]):
        signals.append("COURT_OUTCOME_CONTEXT")
    if any(k in low for k in ["witness", "testimony", "statement"]):
        signals.append("TESTIMONY_CONTEXT")
    if any(k in low for k in ["payment", "transfer", "transaction"]):
        signals.append("FINANCIAL_CONTEXT")
    if any(k in low for k in ["ip", "domain", "email", "phone"]):
        signals.append("DIGITAL_INFRASTRUCTURE_CONTEXT")

    if signals:
        add_note(parsed, "CRIM_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_CRIM_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "court" in fname or "judgment" in fname or "verdict" in fname:
        return "COURT_RECORD"
    if "police" in fname or "report" in fname or "complaint" in fname:
        return "POLICE_COMPLAINT_REPORT"
    if "bank" in fname or "txn" in fname or "payment" in fname:
        return "FINANCIAL_TRANSACTION_LOG"
    if "forensic" in fname or "device" in fname:
        return "FORENSIC_EVIDENCE_MANIFEST"

    return "GENERIC_CRIM_EVIDENCE"


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
    kind = "CSV_CRIM_DATA"

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
    if "court" in low or "judgment" in low:
        kind = "TEXT_COURT_RECORD"
    elif "police" in low or "report" in low:
        kind = "TEXT_POLICE_REPORT"
    elif "forensic" in low or "lab" in low:
        kind = "TEXT_FORENSIC_REPORT"
    else:
        kind = "TEXT_GENERIC_CRIM_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".crim", ".legal"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_crim_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No crime planning, no evasion teaching, no coercion, no fabrication.",
            "Binary artifacts are hash/metadata preserved only.",
            "Case documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Allegation != Fact. Arrest != Conviction.",
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
            file_evidence["content_kind"] = "BINARY_CRIM_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary criminal document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted LEA systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_case_count"] = len(parsed.get("cases", []))
    file_evidence["parsed_person_count"] = len(parsed.get("persons", []))
    file_evidence["parsed_rel_count"] = len(parsed.get("relationships", []))

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


def check_exculpatory_evidence(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flags allegations that have been refuted or persons who have been acquitted/dismissed.
    """
    exculpations = []
    
    # Check Persons with Acquired/Dismissed status
    for p in parsed.get("persons", []):
        if p.get("legal_status") in ["ACQUITTED", "CASE_DISMISSED", "EXONERATED", "CLEARED"]:
            exculpations.append({
                "exculpation_id": f"EXC-{uuid.uuid4()}",
                "subject_ref": p.get("person_id"),
                "basis": "LEGAL_STATUS_CLEAR",
                "details": f"Person {p.get('display_name')} has legal status {p.get('legal_status')}.",
                "impact": "Removes suspicion associated with this individual for the relevant timeframe/offense.",
            })
            
    # Check Allegations marked Refuted
    for a in parsed.get("allegations", []):
        if a.get("verification_state") == "REFUTED":
            exculpations.append({
                "exculpation_id": f"EXC-{uuid.uuid4()}",
                "allegation_ref": a.get("allegation_id"),
                "basis": "ALLEGATION_REFUTED",
                "details": f"Allegation regarding {a.get('alleged_conduct')} has been refuted by evidence.",
                "impact": "Weakens prosecution-style narrative.",
            })
            
    return exculpations


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting legal statuses for same person/name
    pers_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for p in parsed.get("persons", []):
        nm = p.get("display_name")
        if nm:
            pers_map[nm].append(p)
            
    for nm, group in pers_map.items():
        statuses = {g.get("legal_status") for g in group}
        if len(statuses) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "LEGAL_STATUS_CONFLICT",
                "subject": nm,
                "values": list(statuses),
                "possible_explanations": [
                    "Different people with same name",
                    "Status change over time (needs temporal sorting)",
                    "Data entry error",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify identity resolution before assuming conflict.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    relationships = parsed.get("relationships", [])
    events = parsed.get("events", [])
    
    if not relationships and not events:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient relational/event data to form case-linkage hypotheses.",
            "supporting_facts": ["Empty relationship/event lists."],
            "opposing_facts": [],
            "unknowns": ["network structure", "event timeline"],
            "next_test": "Import valid court/case/financial exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if relationships:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed associations may indicate social/business links OR criminal conspiracy.",
            "supporting_facts": [f"{len(relationships)} relationship(s) found."],
            "opposing_facts": ["Association does not prove participation."],
            "unknowns": ["intent behind communication", "nature of transaction"],
            "falsification_conditions": ["Independent evidence shows innocent explanation for contact."],
            "next_test": "Analyze content/context of communications and payments (via FININT/COMINT).",
            "status": "ANALYTICAL",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    persons = parsed.get("persons", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized criminal evidence exists?",
            "missing_evidence": "No local CRIMINT artifact supplied.",
            "likely_source": "Court Judgment, Police Report, Bank Statement (Authorized).",
            "specialist_owner": "CRIMINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline case analysis.",
            "safety_boundary": "No hacking, no coercion, no fabrication.",
        })

    if persons and not any(p.get("legal_status") != "STATUS_UNKNOWN" for p in persons):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the current legal status of identified subjects?",
            "missing_evidence": "Legal status records missing.",
            "likely_source": "Official Court Registry / LEA Case Management System.",
            "specialist_owner": "CRIMINT / LEGALINT",
            "priority": "HIGH",
            "expected_information_value": "Prevents conflating suspect with convict.",
            "safety_boundary": "Do not assume guilt from association.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    transactions = parsed.get("transactions", []) # Note: Transactions aren't fully modeled in simple parser, but placeholder
    cyber_indicators = [o for o in parsed.get("observations", []) if any(k in o.get("statement", "").lower() for k in ["ip", "domain", "crypto", "wallet"])]
    
    if cyber_indicators:
        handoffs.append({
            "specialist": "CTI / CRYPTOINT / INFRAINT",
            "reason": "Digital infrastructure/crypto indicators detected.",
            "expected_output": "Technical attribution, wallet clustering, IP resolution.",
            "question": "Can digital identifiers be linked to real-world entities via authorized technical means?",
        })
        
    if any(p.get("role_in_case") == "VICTIM" for p in parsed.get("persons", [])):
         handoffs.append({
            "specialist": "HUMINT / VICTIM_SUPPORT",
            "reason": "Victim involvement detected.",
            "expected_output": "Sensitive testimony handling, support coordination.",
            "question": "How can victim privacy and safety be maintained during investigation?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "CRIMINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Are current insights sufficient for investigative prioritization?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["exculpatory_evidence"] = check_exculpatory_evidence(parsed)
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
    persons = parsed.get("persons", [])
    exculpations = parsed.get("exculpatory_evidence", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited crime facilitation, evasion, or coercion behavior.",
            "reason": "CRIMINT is investigative intelligence, not a crime tool.",
            "owner": "CRIMINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized case/court/financial exports before analysis.",
            "reason": "No CRIMINT evidence artifact available.",
            "owner": "CRIMINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if exculpations:
        return {
            "action": "Prioritize review of exculpatory evidence. Ensure cleared individuals are removed from active suspect lists.",
            "reason": "Ethical obligation to prevent wrongful focus.",
            "owner": "CRIMINT Analyst / Prosecutor",
            "expected_output": "Updated investigative priority list excluding cleared parties.",
        }

    if persons and not any(p.get("legal_status") == "CONVICTED" for p in persons):
        return {
            "action": "Seek independent corroboration for allegations. Do not treat charges as convictions.",
            "reason": "Legal status remains pre-trial/unresolved.",
            "owner": "CRIMINT / LEGALINT",
            "expected_output": "Verified fact vs allegation register.",
        }

    return {
        "action": "Proceed with network analysis and case linkage using conservative criteria.",
        "reason": "Basic structural analysis complete.",
        "owner": "CRIMINT Analyst",
        "expected_output": "Linkage hypothesis report.",
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
    has_cases = bool(parsed.get("cases"))
    has_pers = bool(parsed.get("persons"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General CRIMINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Authorized / evidence-first / privacy-aware / human-governed criminal intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_criminal_questions_scope",
        "CRIMINT Manager",
        "Convert objective into investigative questions, allowed sources, and privacy boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_criminal_evidence",
        "local evidence store",
        "Store original reports/records and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "CrimEvidenceObject with SHA256.",
    )

    add(
        "parse_case_entity_legal_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT criminal metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized cases/persons/statuses.",
    )

    add(
        "check_exculpatory_evidence_first",
        "local analyzer",
        "Actively search for acquittals/dismissals/refutations before building prosecution narrative.",
        "COMPLETED_LOCAL" if has_pers else "PLANNED_ANALYTIC",
        "Exculpatory Register.",
        safety_risk="HIGH_IF_IGNORED",
    )

    add(
        "conservative_case_linkage",
        "CRIMINT Analyst",
        "Link cases only via multiple diagnostic indicators, avoiding generic similarities.",
        "PLANNED_ANALYTIC",
        "Linkage Hypothesis Matrix.",
        safety_risk="HIGH_IF_OVER_LINKING",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_case_ref",
        "questions",
        "persons",
        "organizations",
        "accounts",
        "communications",
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
            "Sensitive criminal context detected. Analysis must remain authorized, evidence-first, and privacy-aware. "
            "No crime facilitation, no coercion, no fabrication."
        )

    if payload.get("persons") or payload.get("organizations"):
        human_review_required = True
        safety_notes.append(
            "Entity identification context detected. Apply strict privacy safeguards. Do not dox or expose unnecessary PII."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal crime facilitation, evasion, or coercion."
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
                "No obvious hard policy violation detected, but sensitive criminal/privacy context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/lawful criminal evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target_case_ref", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No CRIMINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "case_report_paths",
        "court_record_paths",
        "forensic_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No criminal evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Legal status is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which cases/incidents are under review?",
        "Who are the identified persons and what are their legal statuses?",
        "Are there any acquittals or dismissals that must be respected?",
        "What relationships exist between subjects?",
        "Do these relationships constitute mere association or potential conspiracy?",
        "Is there exculpatory evidence contradicting allegations?",
        "What financial/digital trails support or weaken the case?",
        "How reliable and independent are the sources?",
        "What remains unknown regarding identity or intent?",
        "What is the safest next investigative step?",
    ]


class TraceAtlasCRIMINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#f43f5e", font=("Segoe UI", 17, "bold")) # Rose/Red accent for Crime/Legal Danger
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
        ttk.Label(header, text="TraceAtlas CRIMINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Authorized / evidence-first / privacy-aware / human-governed criminal intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT case/entity/legal parsing only • "
                "No crime planning / No evasion teaching / No coercion / No fabrication • "
                "Allegation != Fact • Arrest != Conviction • Association != Participation"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="CRIMINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Crim Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Case Reports / Complaints", command=self.add_cases).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Court Records / Judgments", command=self.add_courts).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Forensic / Digital Evidence", command=self.add_forensics).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Financial / Transaction Logs", command=self.add_financials).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local CRIMINT Evidence", command=self.analyze_local_crim).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Crim Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#fecdd3", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "CRIM-CASE-001")
        self.set_widget_value("task_id", "CRIM-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive criminal intelligence using evidence-first methods.")
        self.set_widget_value("target_case_ref", "Illustrative Example Case #12345")
        self.set_widget_value("target_type", "case_linkage_analysis")
        self.set_widget_value("questions", "\n".join(default_questions({"target_case_ref": "Illustrative Example Case #12345"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["official_court_db", "authorized_lea_system"], "prohibited_actions": ["hack_account", "threaten_witness"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_investigation_support"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_AUTHORIZED_PRIVACY_AWARE_HUMAN_GOVERNED"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_cases(self): self._append_paths("case_report_paths", filedialog.askopenfilenames(title="Select Case Reports", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_courts(self): self._append_paths("court_record_paths", filedialog.askopenfilenames(title="Select Court Records", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_forensics(self): self._append_paths("forensic_paths", filedialog.askopenfilenames(title="Select Forensic Evidence", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_financials(self): self._append_paths("financial_paths", filedialog.askopenfilenames(title="Select Financial Logs", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_crim(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["case_report_paths", "court_record_paths", "forensic_paths", "financial_paths", "stix_misp_paths"]
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
            f, parsed = analyze_crim_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nCases: {len(aggregated['cases'])}\nPersons: {len(aggregated['persons'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("cases") and not self.parsed.get("persons"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "cases_preview": self.parsed.get("cases", [])[:100],
            "persons_preview": self.parsed.get("persons", [])[:100],
            "relationships_preview": self.parsed.get("relationships", [])[:100],
            "allegations_preview": self.parsed.get("allegations", [])[:100],
            "exculpatory_evidence": self.parsed.get("exculpatory_evidence", []),
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
            "mode": "LOCAL_DETERMINISTIC_CRIMINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "cases": parsed.get("cases", [])[:300],
            "persons": parsed.get("persons", [])[:300],
            "relationships": parsed.get("relationships", [])[:300],
            "allegations": parsed.get("allegations", [])[:300],
            "exculpatory_evidence": parsed.get("exculpatory_evidence", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No crime planning, no coercion, no fabrication.",
                "Allegation != Fact.",
                "Arrest != Conviction.",
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
        app = TraceAtlasCRIMINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")