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


APP_TITLE = "TraceAtlas GOVINT AI Employee — Lawful / Public-Record / Authorized / Nonpartisan Government Intelligence Panel"
APP_VERSION = "TraceAtlas GOVINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Entity / Official / Program Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "GOVINT Questions", "text"),

    ("jurisdictions", "Jurisdictions (Country/State/City)", "text"),
    ("entities", "Government Entities (Ministries/Agencies/Commissions)", "text"),
    ("offices", "Public Offices", "text"),
    ("officeholders", "Officeholders (Names/IDs)", "text"),
    ("programs", "Programs / Schemes", "text"),
    ("policies", "Policies / Regulations", "text"),
    ("budgets", "Budget References (FY/Line Items)", "text"),
    ("grants", "Grants / Subsidies", "text"),
    ("procurements", "Procurement / Contracts", "text"),
    ("projects", "Public Projects", "text"),
    ("licenses", "Licenses / Permits", "text"),
    
    ("gazette_paths", "Official Gazette Paths", "text"),
    ("budget_paths", "Budget / Appropriation Paths", "text"),
    ("appointment_paths", "Appointment / Notification Paths", "text"),
    ("policy_paths", "Policy / Regulation Text Paths", "text"),
    ("project_paths", "Project / Audit Report Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Gov Portal/Open Data API/etc.)", "text"),
]


TARGET_TYPES = [
    "entity_resolution",
    "officeholder_verification",
    "budget_expenditure_analysis",
    "program_status_check",
    "regulatory_action_context",
    "public_project_audit",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "jurisdictions",
    "entities",
    "offices",
    "officeholders",
    "programs",
    "policies",
    "budgets",
    "grants",
    "procurements",
    "projects",
    "licenses",
    "gazette_paths",
    "budget_paths",
    "appointment_paths",
    "policy_paths",
    "project_paths",
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
    "officeholder_verification",
    "budget_expenditure_analysis",
    "regulatory_action_context",
    "public_project_audit",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


POLICY_BLOCK_PATTERNS = [
    r"\b(?:hack|intrude|breach|access|bypass)\b[^\n]{0,140}\b(?:government system|classified database|restricted portal|internal network)\b",
    r"\b(?:impersonate|pretend to be|pose as)\b[^\n]{0,140}\b(?:official|agent|journalist|citizen|law enforcement)\b",
    r"\b(?:dox|expose|publish private address|harass|intimidate)\b[^\n]{0,140}\b(?:public servant|official|citizen|politician)\b",
    r"\b(?:fabricate|forge|create false)\b[^\n]{0,140}\b(?:gazette entry|official document|budget record|appointment letter)\b",
    r"\b(?:microtarget|manipulate voters|suppress participation)\b[^\n]{0,140}\b(?:election|civic process)\b",
    r"\b(?:bribe|blackmail|coerce)\b[^\n]{0,140}\b(?:official|agency staff)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/public-record/authorized/nonpartisan government intelligence: resolve entities/offices/officeholders, parse gazettes/budgets/appointments/policies, separate announcement from implementation, appropriation from expenditure, and produce source-linked reports with human review escalation.",
    "Do not hack systems, impersonate officials, dox public servants, fabricate documents, manipulate elections, or bribe/coerce officials.",
    "Separate Government from Agency, Office from Officeholder, Bill from Law, Enacted from Effective, Announcement from Implementation, Appropriation from Expenditure, Grant Award from Disbursement, and Contractor from Government Unit.",
    "Use deterministic arithmetic for budget totals. Escalate consequential legal interpretations, corruption allegations, or security-sensitive infrastructure details to authorized human/legal/compliance review.",
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
    r"approve\s+(?:this\s+)?(?:contract|payment)",
]


# Regex helpers for government identifiers
GAZETTE_REF_RE = re.compile(r"\b(?:Gazette|Notification|Order|Circular)\s*(?:No\.?\s*)?[A-Z0-9\-\/\.]+\b", re.I)
OFFICE_ID_RE = re.compile(r"\b(?:Office|Post|Designation)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)
BUDGET_LINE_RE = re.compile(r"\b(?:Head of Account|HoA|Budget Head|Line Item)\s*(?:Code|No\.?)\s*:?\s*\d+\b", re.I)


ENTITY_ROLE_KEYS = [
    "ministry",
    "department",
    "agency",
    "commission",
    "authority",
    "board",
    "council",
    "municipality",
    "body",
    "institution",
    "organization",
    "entity",
]


OFFICEHOLDER_ROLE_KEYS = [
    "minister",
    "secretary",
    "director general",
    "chairperson",
    "member",
    "officer",
    "appointee",
    "nominee",
]


PROGRAM_KEYS = [
    "program",
    "scheme",
    "initiative",
    "mission",
    "project",
]


BUDGET_KEYS = [
    "budget",
    "appropriation",
    "allocation",
    "expenditure",
    "spending",
    "grant",
    "subsidy",
]


REGULATORY_KEYS = [
    "regulation",
    "rule",
    "notification",
    "order",
    "circular",
    "guidance",
    "act",
    "bill",
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


def parse_money(value: Any) -> Tuple[Optional[Decimal], str]:
    if value is None:
        return None, ""

    s = str(value).strip()
    if not s:
        return None, ""

    currency = ""
    upper = s.upper()

    if "$" in s:
        currency = "USD"
    elif "€" in s:
        currency = "EUR"
    elif "£" in s:
        currency = "GBP"
    elif "₹" in s:
        currency = "INR"

    cur_match = re.search(r"\b(USD|EUR|GBP|INR|CAD|AUD|JPY|CHF)\b", upper)
    if cur_match:
        currency = cur_match.group(1)

    cleaned = re.sub(r"[^0-9.\-]", "", s)
    if not cleaned or cleaned in {"-", ".", "-."}:
        return None, currency

    try:
        dec = Decimal(cleaned)
    except InvalidOperation:
        return None, currency

    return dec, currency


def dec(value: Any) -> Decimal:
    if value in (None, ""):
        return Decimal("0")
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return Decimal("0")


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "entities": [], # Ministries, Agencies, Commissions
        "offices": [],
        "officeholders": [],
        "appointments": [],
        "programs": [],
        "policies": [],
        "regulations": [],
        "budgets": [],
        "grants": [],
        "projects": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "status_timeline": [],
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
            "Observation records what was published/stated, not necessarily its legal effect or current status.",
            "Press release is evidence of announcement, not implementation.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in gov docs are ignored.")


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
            "Multiple news sites reprinting one ministry press release are not independent sources.",
        ],
    })


def add_entity(
    parsed: Dict[str, Any],
    name: Any,
    entity_type: Any,
    jurisdiction: Any,
    parent_ref: Any = None,
    mandate: Any = "",
    source_id: str = "",
    evidence_id: str = "",
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    norm = normalize_text(n)
    et = safe_str(entity_type, 100).upper() or "UNKNOWN"
    
    for e in parsed["entities"]:
        if e.get("normalized_name") == norm and e.get("entity_type") == et:
            if jurisdiction and not e.get("jurisdiction"):
                e["jurisdiction"] = safe_str(jurisdiction, 100)
            if parent_ref and not e.get("parent_ref"):
                e["parent_ref"] = parent_ref
            if mandate and not e.get("mandate"):
                e["mandate"] = safe_str(mandate, 500)
            return e.get("entity_id")

    eid = f"ENT-{uuid.uuid4()}"
    parsed["entities"].append({
        "entity_id": eid,
        "name": n,
        "normalized_name": norm,
        "entity_type": et,
        "jurisdiction": safe_str(jurisdiction, 100),
        "parent_ref": parent_ref,
        "mandate": safe_str(mandate, 500),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ENTITY_CANDIDATE",
        "limitations": [
            "Entity resolution requires legal instrument verification. Name similarity alone is insufficient.",
            "Mission statement on website is not statutory authority.",
        ],
    })
    return eid


def add_office(
    parsed: Dict[str, Any],
    title: Any,
    entity_ref: Any,
    jurisdiction: Any,
    legal_basis: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    t = safe_str(title, 200)
    if not t:
        return None
        
    oid = f"OFF-{uuid.uuid4()}"
    parsed["offices"].append({
        "office_id": oid,
        "title": t,
        "entity_ref": entity_ref,
        "jurisdiction": safe_str(jurisdiction, 100),
        "legal_basis": safe_str(legal_basis, 300),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "OFFICE_PARSED",
        "limitations": [
            "Office exists independently of officeholder. Do not merge them.",
        ],
    })
    return oid


def add_appointment(
    parsed: Dict[str, Any],
    person_name: Any,
    office_ref: Any,
    appointment_date: Any,
    assumption_date: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    pid = safe_str(person_name, 200)
    if not pid:
        return
        
    aid = f"APT-{uuid.uuid4()}"
    
    stat_norm = normalize_text(status).upper()
    canonical_status = "UNKNOWN"
    if "APPOINTED" in stat_norm:
        canonical_status = "APPOINTED"
    elif "ASSUMED" in stat_norm or "JOINED" in stat_norm:
        canonical_status = "ASSUMED_OFFICE"
    elif "RESIGNED" in stat_norm:
        canonical_status = "RESIGNED"
    elif "REMOVED" in stat_norm:
        canonical_status = "REMOVED"
    elif "ACTING" in stat_norm:
        canonical_status = "ACTING"
        
    parsed["appointments"].append({
        "appointment_id": aid,
        "person_name": pid,
        "office_ref": office_ref,
        "appointment_date": safe_str(appointment_date, 100),
        "assumption_date": safe_str(assumption_date, 100),
        "status": canonical_status,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "APPOINTMENT_PARSED",
        "limitations": [
            "Nomination/Appointment does not equal Assumption of Office automatically.",
            "Acting status may differ from permanent authority.",
        ],
    })


def add_budget_entry(
    parsed: Dict[str, Any],
    entity_ref: Any,
    fiscal_year: Any,
    stage: Any, # PROPOSED, APPROPRIATED, EXPENDED
    amount: Any,
    currency: Any,
    head_account: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    bid = f"BUD-{uuid.uuid4()}"
    
    amt_val, amt_cur = parse_money(amount)
    if currency:
        amt_cur = safe_str(currency, 20).upper() or amt_cur
        
    stage_norm = normalize_text(stage).upper()
    canonical_stage = "UNKNOWN"
    if "PROPOS" in stage_norm or "PLAN" in stage_norm:
        canonical_stage = "PROPOSED"
    elif "APPROP" in stage_norm or "ALLOC" in stage_norm:
        canonical_stage = "APPROPRIATED"
    elif "EXPEND" in stage_norm or "SPEND" in stage_norm or "DISBURS" in stage_norm:
        canonical_stage = "EXPENDED"
        
    parsed["budgets"].append({
        "budget_id": bid,
        "entity_ref": entity_ref,
        "fiscal_year": safe_str(fiscal_year, 20),
        "stage": canonical_stage,
        "amount_decimal": str(amt_val) if amt_val is not None else None,
        "currency": amt_cur or "UNKNOWN",
        "head_account": safe_str(head_account, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "BUDGET_ENTRY_PARSED",
        "limitations": [
            "Appropriation is authorization, not cash payment.",
            "Expenditure requires evidence of actual spending/disbursement.",
        ],
    })


def add_program(
    parsed: Dict[str, Any],
    prog_name: Any,
    entity_ref: Any,
    status: Any,
    start_date: Any,
    end_date: Any,
    budget_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    pn = safe_str(prog_name, 200)
    if not pn:
        return
        
    prid = f"PRG-{uuid.uuid4()}"
    
    stat_norm = normalize_text(status).upper()
    canonical_status = "UNKNOWN"
    if "ANNOUNCED" in stat_norm or "LAUNCHED" in stat_norm:
        canonical_status = "ANNOUNCED"
    elif "FUNDED" in stat_norm or "APPROVED" in stat_norm:
        canonical_status = "FUNDED"
    elif "IMPLEMENT" in stat_norm or "STARTED" in stat_norm:
        canonical_status = "IMPLEMENTATION_STARTED"
    elif "COMPLETED" in stat_norm or "FINISHED" in stat_norm:
        canonical_status = "COMPLETED_REPORTED"
        
    parsed["programs"].append({
        "program_id": prid,
        "name": pn,
        "entity_ref": entity_ref,
        "status": canonical_status,
        "start_date": safe_str(start_date, 100),
        "end_date": safe_str(end_date, 100),
        "budget_ref": budget_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PROGRAM_PARSED",
        "limitations": [
            "Announcement is not Implementation.",
            "Funding is not Completion.",
            "Output (centers built) is not Outcome (crime reduced).",
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

    # Resolve Entities
    ent_refs = []
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                ename = val.get("name") or val.get("id")
                etype = val.get("type") or key.upper()
                ejur = val.get("jurisdiction")
                emandate = val.get("mandate")
            else:
                ename = str(val)
                etype = key.upper()
                ejur = ""
                emandate = ""
            
            eref = add_entity(parsed, ename, etype, ejur, None, emandate, source_id, evidence_id, f"{rec_ctx}/{key}")
            if eref:
                ent_refs.append(eref)

    primary_ent_ref = ent_refs[0] if ent_refs else None

    # Resolve Offices/Appointments
    office_items = get_field(rec, ["office", "post", "designation"], as_list=True)
    for item in office_items:
        if isinstance(item, dict):
            o_title = item.get("title") or item.get("name")
            o_ref = add_office(parsed, o_title, primary_ent_ref, rec.get("jurisdiction"), item.get("legal_basis"), source_id, evidence_id, f"{rec_ctx}/office")
            
            # Nested appointments
            appts = item.get("appointments", [])
            for apt in listify(appts):
                if isinstance(apt, dict):
                    add_appointment(
                        parsed,
                        apt.get("person") or apt.get("name"),
                        o_ref,
                        apt.get("appointed_at"),
                        apt.get("assumed_at"),
                        apt.get("status"),
                        source_id,
                        evidence_id,
                        f"{rec_ctx}/appointment"
                    )

    # Resolve Budgets
    bud_items = get_field(rec, BUDGET_KEYS, as_list=True)
    for item in bud_items:
        if isinstance(item, dict):
            add_budget_entry(
                parsed,
                primary_ent_ref,
                item.get("fiscal_year") or rec.get("year"),
                item.get("stage") or item.get("type"),
                item.get("amount") or item.get("value"),
                item.get("currency"),
                item.get("head_account") or item.get("ho_a"),
                source_id,
                evidence_id,
                f"{rec_ctx}/budget"
            )

    # Resolve Programs
    prog_items = get_field(rec, PROGRAM_KEYS, as_list=True)
    for item in prog_items:
        if isinstance(item, dict):
            add_program(
                parsed,
                item.get("name") or item.get("title"),
                primary_ent_ref,
                item.get("status"),
                item.get("start_date"),
                item.get("end_date"),
                item.get("budget_ref"),
                source_id,
                evidence_id,
                f"{rec_ctx}/program"
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
                 caution="Gov docs are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["gazette", "notification", "order", "circular"]):
        signals.append("GAZETTE_CONTEXT")
    if any(k in low for k in ["appointed", "resigned", "removed", "acting"]):
        signals.append("APPOINTMENT_CONTEXT")
    if any(k in low for k in ["budget", "appropriation", "expenditure", "spent"]):
        signals.append("BUDGET_CONTEXT")
    if any(k in low for k in ["launched", "announced", "implemented", "completed"]):
        signals.append("PROGRAM_STATUS_CONTEXT")
    if any(k in low for k in ["investigation", "fine", "penalty", "revoked"]):
        signals.append("REGULATORY_ACTION_CONTEXT")

    if signals:
        add_note(parsed, "GOV_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified legal status.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_GOV_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "gazette" in fname or "notification" in fname:
        return "GAZETTE_RECORD"
    if "budget" in fname or "appropriation" in fname:
        return "BUDGET_RECORD"
    if "appointment" in fname or "order" in fname:
        return "APPOINTMENT_ORDER"
    if "program" in fname or "scheme" in fname:
        return "PROGRAM_RECORD"
    if "audit" in fname or "report" in fname:
        return "AUDIT_REPORT"

    return "GENERIC_GOV_EVIDENCE"


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
    kind = "CSV_GOV_DATA"

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
    if "gazette" in low or "notification" in low:
        kind = "TEXT_GAZETTE_NOTE"
    elif "budget" in low or "appropriation" in low:
        kind = "TEXT_BUDGET_NOTE"
    elif "appointment" in low or "order" in low:
        kind = "TEXT_APPOINTMENT_NOTE"
    else:
        kind = "TEXT_GENERIC_GOV_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".gazette", ".budget"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_gov_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No hacking, no impersonation, no doxxing, no fabrication of official records.",
            "Binary artifacts are hash/metadata preserved only.",
            "Gov documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Announcement != Implementation. Appropriation != Expenditure.",
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
            file_evidence["content_kind"] = "BINARY_GOV_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary government document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted portals."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_entity_count"] = len(parsed.get("entities", []))
    file_evidence["parsed_appointment_count"] = len(parsed.get("appointments", []))
    file_evidence["parsed_budget_count"] = len(parsed.get("budgets", []))
    file_evidence["parsed_program_count"] = len(parsed.get("programs", []))

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


def calculate_budget_variance(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Compares Appropriated vs Expended amounts deterministically.
    """
    variances = []
    
    # Group by Entity + Fiscal Year
    bud_map: Dict[Tuple[str, str], Dict[str, Decimal]] = defaultdict(lambda: {"APPROPRIATED": Decimal("0"), "EXPENDED": Decimal("0")})
    
    for b in parsed.get("budgets", []):
        ent = b.get("entity_ref")
        fy = b.get("fiscal_year")
        stage = b.get("stage")
        amt_str = b.get("amount_decimal")
        
        if not ent or not fy or not amt_str:
            continue
            
        try:
            amt = Decimal(amt_str)
        except:
            continue
            
        if stage == "APPROPRIATED":
            bud_map[(ent, fy)]["APPROPRIATED"] += amt
        elif stage == "EXPENDED":
            bud_map[(ent, fy)]["EXPENDED"] += amt
            
    for (ent, fy), sums in bud_map.items():
        appr = sums["APPROPRIATED"]
        expd = sums["EXPENDED"]
        
        if appr > 0:
            utilization_pct = (expd / appr) * 100
            variance_amt = appr - expd
            
            variances.append({
                "variance_id": f"VAR-{uuid.uuid4()}",
                "entity_ref": ent,
                "fiscal_year": fy,
                "appropriated_total": str(appr),
                "expended_total": str(expd),
                "utilization_percent": round(float(utilization_pct), 2),
                "unspent_balance": str(variance_amt),
                "limitations": [
                    "Utilization % does not prove efficiency or waste.",
                    "Data completeness depends on source ingestion.",
                ]
            })
            
    return variances


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting appointment statuses for same office/person/time
    # Simplified: Flag if multiple active appointments exist for same office without resignation/removal
    
    # Check for Policy Status conflicts (Announced but not Funded?)
    # In real system, this requires cross-referencing Budgets and Policies.
    
    # Example: Program marked COMPLETED but no Expenditure recorded?
    prog_completed = [p for p in parsed.get("programs", []) if p.get("status") == "COMPLETED_REPORTED"]
    for pc in prog_completed:
        # Find associated budget entries
        # This is a simplified heuristic check
        pass 

    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    entities = parsed.get("entities", [])
    appointments = parsed.get("appointments", [])
    budgets = parsed.get("budgets", [])
    
    if not entities:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No government entities identified in local dataset.",
            "supporting_facts": ["Empty entity list."],
            "opposing_facts": [],
            "unknowns": ["jurisdiction", "structure"],
            "next_test": "Import valid gazette/directory exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if appointments:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Officeholder tenure analysis indicates potential succession gaps or acting roles.",
            "supporting_facts": [f"{len(appointments)} appointment record(s) found."],
            "opposing_facts": ["Records may be incomplete."],
            "unknowns": ["current validity", "legal basis of acting role"],
            "falsification_conditions": ["Official gazette confirms permanent appointment."],
            "next_test": "Verify latest notification for each office.",
            "status": "MONITORING",
        })

    if budgets:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Budget utilization variance detected between appropriation and expenditure stages.",
            "supporting_facts": [f"{len(budgets)} budget entry(ies) parsed."],
            "opposing_facts": ["Timing differences may explain gap."],
            "unknowns": ["actual cash flow", "accrual adjustments"],
            "falsification_conditions": ["Audited accounts show full expenditure."],
            "next_test": "Retrieve audited public accounts for reconciliation.",
            "status": "ANALYTICAL",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    entities = parsed.get("entities", [])
    appointments = parsed.get("appointments", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized government records exist?",
            "missing_evidence": "No local GOVINT artifact supplied.",
            "likely_source": "Official Gazette, Ministry Directory, Open Data Portal.",
            "specialist_owner": "GOVINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline government analysis.",
            "safety_boundary": "No hacking, no impersonation.",
        })

    if entities and not appointments:
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Who currently holds the offices in these entities?",
            "missing_evidence": "Appointment records missing.",
            "likely_source": "Latest Executive Order/Gazette Notification.",
            "specialist_owner": "GOVINT",
            "priority": "HIGH",
            "expected_information_value": "Resolves accountability structure.",
            "safety_boundary": "Do not infer current holder from historical data.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    entities = parsed.get("entities", [])
    budgets = parsed.get("budgets", [])
    
    if any(e.get("entity_type") == "STATE_OWNED_ENTERPRISE" for e in entities):
        handoffs.append({
            "specialist": "CORPINT / OWNERSHIPINT",
            "reason": "State-Owned Enterprise identified.",
            "expected_output": "Corporate identity resolution, ownership chain.",
            "question": "What is the precise legal ownership/control structure of this SOE?",
        })
        
    if budgets:
        handoffs.append({
            "specialist": "FININT / AUDITINT",
            "reason": "Budget/Appropriation data detected.",
            "expected_output": "Financial flow verification, audit trail reconciliation.",
            "question": "Does the expenditure data match audited financial statements?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "GOVINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Are current insights sufficient for institutional risk assessment?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["budget_variances"] = calculate_budget_variance(parsed)
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
    entities = parsed.get("entities", [])
    appointments = parsed.get("appointments", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited hacking, impersonation, or doxxing behavior.",
            "reason": "GOVINT is defensive public-record intelligence, not an intrusion tool.",
            "owner": "GOVINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized gazette/budget/appointment exports before analysis.",
            "reason": "No GOVINT evidence artifact available.",
            "owner": "GOVINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if entities and not appointments:
        return {
            "action": "Retrieve latest Appointment Notifications/Gazettes to identify current officeholders.",
            "reason": "Entity structure is known, but accountability is unresolved.",
            "owner": "GOVINT Analyst",
            "expected_output": "Current officeholder register.",
        }

    return {
        "action": "Proceed with budget-utilization analysis and program-status verification.",
        "reason": "Basic structural analysis complete.",
        "owner": "GOVINT / FININT",
        "expected_output": "Institutional performance report.",
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
    has_ents = bool(parsed.get("entities"))
    has_buds = bool(parsed.get("budgets"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General GOVINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Lawful / public-record / authorized / nonpartisan government intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_government_questions_scope",
        "GOVINT Manager",
        "Convert objective into government questions, allowed sources, and privacy boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_government_records",
        "local evidence store",
        "Store original gazettes/budgets/appointments and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "GovEvidenceObject with SHA256.",
    )

    add(
        "parse_entity_office_budget_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT government metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized entities/offices/appointments/budgets.",
    )

    add(
        "resolve_officeholder_tenures",
        "local resolver",
        "Link appointments to offices and track temporal validity.",
        "COMPLETED_LOCAL" if has_ents else "PLANNED_REQUIRES_ENTITY_EVIDENCE",
        "Officeholder timeline with acting/permanent distinctions.",
        safety_risk="HIGH_IF_HISTORICAL_CONTAMINATES_CURRENT",
    )

    add(
        "calculate_budget_utilization_deterministically",
        "local analyzer",
        "Compute variance between appropriated and expended funds using exact arithmetic.",
        "COMPLETED_LOCAL" if has_buds else "PLANNED_ANALYTIC",
        "Budget variance register.",
        safety_risk="HIGH_IF_APPROPRIATION_CALLED_EXPENDITURE",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target",
        "questions",
        "jurisdictions",
        "entities",
        "officeholders",
        "programs",
        "budgets",
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
            "Sensitive government context detected. Analysis must remain lawful, public-record, and nonpartisan. "
            "No hacking, no impersonation, no doxxing."
        )

    if payload.get("officeholders") or payload.get("appointments"):
        human_review_required = True
        safety_notes.append(
            "Officeholder context detected. Privacy minimization applies. Do not expose unrelated personal data."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal government intrusion, impersonation, or harassment."
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
                "No obvious hard policy violation detected, but sensitive government/privacy/security context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful government evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No GOVINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "jurisdictions",
        "entities",
        "gazette_paths",
        "budget_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No government evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Government status is highly temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No gov portal/open-data connector configured. External correlation remains planning-only.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which government entities and jurisdictions are involved?",
        "What is the statutory mandate of these entities?",
        "Who currently holds the relevant public offices?",
        "When were they appointed and when did they assume office?",
        "What programs/schemes are announced vs. implemented?",
        "What budget was proposed vs. appropriated vs. expended?",
        "Are there any regulatory actions or audits affecting these entities?",
        "Which sources are independent vs. dependent copies?",
        "What remains unknown regarding current operational control?",
        "What defensive next actions preserve integrity without accessing restricted data?",
    ]


class TraceAtlasGOVINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#fbbf24", font=("Segoe UI", 17, "bold")) # Amber/Yellow accent for Gov
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
        ttk.Label(header, text="TraceAtlas GOVINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Lawful / public-record / authorized / nonpartisan government intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT gazette/budget/appointment parsing only • "
                "No hacking / no impersonation / no doxxing / no fabrication / no political manipulation • "
                "Gov != Agency • Office != Holder • Bill != Law • Approp != Spend"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="GOVINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Gov Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Gazettes / Notifications", command=self.add_gazettes).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Budgets / Appropriations", command=self.add_budgets).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Appointments / Orders", command=self.add_appointments).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Policies / Programs", command=self.add_policies).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local GOVINT Evidence", command=self.analyze_local_gov).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Gov Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#fef3c7", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "GOV-CASE-001")
        self.set_widget_value("task_id", "GOV-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive government intelligence using evidence-first methods.")
        self.set_widget_value("target", "Illustrative example.com / authorized government context")
        self.set_widget_value("target_type", "entity_resolution")
        self.set_widget_value("questions", "\n".join(default_questions({"target": "Illustrative example.com"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["official_gazette", "open_data_portal"], "prohibited_actions": ["hack_system", "impersonate_official"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_compliance_review"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_PUBLIC_RECORD_NONPARTISAN"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_gazettes(self): self._append_paths("gazette_paths", filedialog.askopenfilenames(title="Select Gazettes", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_budgets(self): self._append_paths("budget_paths", filedialog.askopenfilenames(title="Select Budgets", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_appointments(self): self._append_paths("appointment_paths", filedialog.askopenfilenames(title="Select Appointments", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_policies(self): self._append_paths("policy_paths", filedialog.askopenfilenames(title="Select Policies", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_gov(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["gazette_paths", "budget_paths", "appointment_paths", "policy_paths", "project_paths", "stix_misp_paths"]
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
            f, parsed = analyze_gov_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nEntities: {len(aggregated['entities'])}\nAppointments: {len(aggregated['appointments'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("entities") and not self.parsed.get("budgets"):
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
            "offices_preview": self.parsed.get("offices", [])[:100],
            "appointments_preview": self.parsed.get("appointments", [])[:100],
            "budgets_preview": self.parsed.get("budgets", [])[:100],
            "programs_preview": self.parsed.get("programs", [])[:100],
            "budget_variances": self.parsed.get("budget_variances", []),
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
            "mode": "LOCAL_DETERMINISTIC_GOVINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "entities": parsed.get("entities", [])[:300],
            "offices": parsed.get("offices", [])[:300],
            "appointments": parsed.get("appointments", [])[:300],
            "budgets": parsed.get("budgets", [])[:300],
            "programs": parsed.get("programs", [])[:300],
            "budget_variances": parsed.get("budget_variances", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No hacking, impersonation, or doxxing.",
                "Announcement != Implementation.",
                "Appropriation != Expenditure.",
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
        app = TraceAtlasGOVINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")