import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
import re
import csv
import hashlib
import uuid
import unicodedata

from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


APP_TITLE = "TraceAtlas REGINT AI Employee — Lawful / Public-Source / Authorized / Evidence-First Regulatory Intelligence Panel"
APP_VERSION = "TraceAtlas REGINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_org", "Target Organization / Entity", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "REGINT Questions", "text"),

    ("jurisdictions", "Jurisdictions", "text"),
    ("regulators", "Regulators / Authorities", "text"),
    ("sectors", "Sectors / Industries", "text"),
    ("activities", "Business Activities", "text"),
    ("data_types", "Data Types Handled", "text"),
    ("products_services", "Products / Services", "text"),
    
    ("instruments", "Regulatory Instruments (IDs/Titles)", "text"),
    ("obligations", "Known Obligations", "text"),
    ("controls", "Existing Controls", "text"),
    ("evidence", "Compliance Evidence", "text"),
    ("incidents", "Incidents / Breaches", "text"),
    ("licenses", "Licenses / Registrations", "text"),
    
    ("instrument_paths", "Regulation / Statute Text Paths", "text"),
    ("guidance_paths", "Guidance / Circular Paths", "text"),
    ("enforcement_paths", "Enforcement Action Paths", "text"),
    ("consultation_paths", "Consultation / Draft Rule Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Applicability Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Gov Portal/Legal DB/etc.)", "text"),
]


TARGET_TYPES = [
    "applicability_check",
    "obligation_mapping",
    "gap_analysis",
    "change_monitoring",
    "enforcement_context",
    "licensing_requirement",
    "cross_jurisdiction_comparison",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "jurisdictions",
    "regulators",
    "sectors",
    "activities",
    "data_types",
    "products_services",
    "instruments",
    "obligations",
    "controls",
    "evidence",
    "incidents",
    "licenses",
    "instrument_paths",
    "guidance_paths",
    "enforcement_paths",
    "consultation_paths",
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
    "applicability_check",
    "obligation_mapping",
    "gap_analysis",
    "enforcement_context",
    "licensing_requirement",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


POLICY_BLOCK_PATTERNS = [
    r"\b(?:evade|circumvent|bypass|avoid)\b[^\n]{0,140}\b(?:regulation|law|requirement|reporting|notification|audit|inspection)\b",
    r"\b(?:conceal|hide|mask|delay)\b[^\n]{0,140}\b(?:violation|breach|incident|reportable event|penalty)\b",
    r"\b(?:fabricate|forge|create false)\b[^\n]{0,140}\b(?:license|certificate|audit evidence|compliance record|registration)\b",
    r"\b(?:impersonate|pretend to be)\b[^\n]{0,140}\b(?:regulator|authority|official|inspector)\b",
    r"\b(?:submit|file)\b[^\n]{0,140}\b(?:regulatory filing|report|notice)\b[^\n]{0,80}\b(?:autonomously|automatically|without human review)\b",
    r"\b(?:sham|fake)\b[^\n]{0,140}\b(?:compliance|control|policy|procedure)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/public-source/authorized/evidence-first regulatory intelligence: resolve jurisdictions/regulators/instruments, extract obligations/prohibitions/exemptions, determine applicability based on entity/activity facts, map controls to obligations, identify compliance gaps, track changes/amendments, and produce source-linked reports with human/legal review escalation.",
    "Do not advise evasion, conceal violations, fabricate licenses/evidence, impersonate regulators, submit filings autonomously, or design sham compliance structures.",
    "Separate proposed from final rules, enacted from effective dates, effective from applicable scopes, applicable from violations, guidance from binding law, policy existence from control effectiveness, and compliance gaps from legal breaches.",
    "Use deterministic arithmetic for deadlines/thresholds. Escalate consequential legal interpretations, mandatory notifications, or penalty exposures to authorized human/legal/compliance review.",
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
    r"approve\s+(?:this\s+)?(?:exemption|waiver)",
]


# Regex helpers for regulatory text extraction
DATE_RE = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b|\b\d{4}-\d{2}-\d{2}\b", re.I)
SECTION_RE = re.compile(r"\b(?:Section|Art\.?|Article|§|Para\.?)\s*(\d+[a-zA-Z]*)\b", re.I)
OBLIGATION_KEYWORDS = ["shall", "must", "required to", "obliged to", "prohibited from", "may not"]
EXEMPTION_KEYWORDS = ["exempt", "except", "does not apply", "notwithstanding", "provided that"]


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


def parse_date_safe(date_str: str) -> Optional[datetime]:
    """Attempts to parse date string to datetime object."""
    if not date_str:
        return None
    
    # Try ISO first
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        pass
        
    # Try common formats
    formats = [
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%d %B %Y",
        "%d %b %Y",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
            
    return None


def calculate_deadline(trigger_date_str: str, offset_days: int, business_days_only: bool = False) -> Optional[str]:
    """
    Deterministic deadline calculation.
    Note: Business day logic here is simplified (Mon-Fri). Real world needs holiday calendars.
    """
    trigger_dt = parse_date_safe(trigger_date_str)
    if not trigger_dt:
        return None
        
    if business_days_only:
        current = trigger_dt
        added = 0
        while added < offset_days:
            current += timedelta(days=1)
            if current.weekday() < 5: # Mon-Fri
                added += 1
        return current.isoformat()
    else:
        return (trigger_dt + timedelta(days=offset_days)).isoformat()


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "jurisdictions": [],
        "regulators": [],
        "instruments": [],
        "definitions": [],
        "obligations": [],
        "prohibitions": [],
        "permissions": [],
        "exemptions": [],
        "thresholds": [],
        "deadlines": [],
        "licenses": [],
        "controls": [],
        "evidence": [],
        "gaps": [],
        "changes": [],
        "enforcement_actions": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
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
            "Observation records what was stated in the source, not necessarily its legal effect.",
            "Guidance is distinct from binding law.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in regulatory docs are ignored.")


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
            "Multiple news articles citing one regulator announcement are not independent sources.",
        ],
    })


def add_jurisdiction(parsed: Dict[str, Any], name: Any, country: Any, subnational: Any, source_id: str, evidence_id: str) -> Optional[str]:
    n = safe_str(name, 100)
    if not n:
        return None
        
    jid = f"JUR-{uuid.uuid4()}"
    parsed["jurisdictions"].append({
        "jurisdiction_id": jid,
        "name": n,
        "country": safe_str(country, 50),
        "subnational_area": safe_str(subnational, 50),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "JURISDICTION_CANDIDATE",
        "limitations": ["Jurisdiction determines scope. Extraterritoriality requires specific legal basis."],
    })
    return jid


def add_regulator(parsed: Dict[str, Any], name: Any, jurisdiction_ref: Any, mandate: Any, source_id: str, evidence_id: str) -> Optional[str]:
    n = safe_str(name, 100)
    if not n:
        return None
        
    rid = f"REG-{uuid.uuid4()}"
    parsed["regulators"].append({
        "regulator_id": rid,
        "name": n,
        "jurisdiction_ref": jurisdiction_ref,
        "statutory_mandate": safe_str(mandate, 300),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "REGULATOR_CANDIDATE",
        "limitations": ["Regulator powers are defined by statute. Agency name does not imply unlimited authority."],
    })
    return rid


def add_instrument(
    parsed: Dict[str, Any],
    inst_id: Any,
    title: Any,
    inst_type: Any,
    status: Any,
    pub_date: Any,
    eff_date: Any,
    trans_end: Any,
    repeal_date: Any,
    jur_ref: Any,
    reg_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    iid = safe_str(inst_id, 200)
    t = safe_str(title, 300)
    
    if not iid and not t:
        return None
        
    id_val = f"INST-{uuid.uuid4()}"
    
    # Normalize Status
    stat_norm = normalize_text(status).upper()
    canonical_status = "UNKNOWN"
    if "PROPOSED" in stat_norm or "DRAFT" in stat_norm or "CONSULTATION" in stat_norm:
        canonical_status = "PROPOSED"
    elif "ENACTED" in stat_norm or "ADOPTED" in stat_norm or "FINAL" in stat_norm:
        canonical_status = "ENACTED_NOT_EFFECTIVE" # Needs check against eff_date
    elif "EFFECTIVE" in stat_norm or "IN FORCE" in stat_norm:
        canonical_status = "EFFECTIVE"
    elif "REPEALED" in stat_norm or "WITHDRAWN" in stat_norm:
        canonical_status = "REPEALED"
    elif "AMENDED" in stat_norm:
        canonical_status = "AMENDED"
        
    # Refine Enacted vs Effective based on dates
    if canonical_status == "ENACTED_NOT_EFFECTIVE" and eff_date:
        eff_dt = parse_date_safe(eff_date)
        if eff_dt and eff_dt <= datetime.now(timezone.utc):
            canonical_status = "EFFECTIVE"
            
    parsed["instruments"].append({
        "instrument_record_id": id_val,
        "external_instrument_id": iid,
        "official_title": t,
        "instrument_type": safe_str(inst_type, 50).upper() or "UNKNOWN",
        "legal_status": canonical_status,
        "publication_date": safe_str(pub_date, 100),
        "effective_date": safe_str(eff_date, 100),
        "transition_end_date": safe_str(trans_end, 100),
        "repeal_date": safe_str(repeal_date, 100),
        "jurisdiction_ref": jur_ref,
        "regulator_ref": reg_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "INSTRUMENT_PARSED",
        "limitations": [
            "Proposed rules are not binding.",
            "Enacted rules may not yet be effective.",
            "Effective rules may not apply to all entities.",
        ],
    })
    return id_val


def add_obligation(
    parsed: Dict[str, Any],
    inst_ref: Any,
    provision: Any,
    ob_type: Any,
    subject: Any,
    action: Any,
    trigger: Any,
    deadline_rule: Any,
    threshold: Any,
    exemption: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    oid = f"OBG-{uuid.uuid4()}"
    
    parsed["obligations"].append({
        "obligation_id": oid,
        "instrument_ref": inst_ref,
        "provision_reference": safe_str(provision, 100),
        "obligation_type": safe_str(ob_type, 50).upper() or "UNKNOWN",
        "subject": safe_str(subject, 200),
        "required_action": safe_str(action, 500),
        "trigger_event": safe_str(trigger, 200),
        "deadline_rule": safe_str(deadline_rule, 200),
        "threshold_condition": safe_str(threshold, 200),
        "exemption_clause": safe_str(exemption, 200),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "OBLIGATION_EXTRACTED",
        "limitations": [
            "Extraction is heuristic. Semantic verification required.",
            "'Shall/Must' indicates obligation, but context matters.",
        ],
    })


def add_exemption(
    parsed: Dict[str, Any],
    inst_ref: Any,
    provision: Any,
    condition: Any,
    source_id: str,
    evidence_id: str,
) -> None:
    eid = f"EXM-{uuid.uuid4()}"
    parsed["exemptions"].append({
        "exemption_id": eid,
        "instrument_ref": inst_ref,
        "provision_reference": safe_str(provision, 100),
        "condition": safe_str(condition, 500),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "EXEMPTION_IDENTIFIED",
        "limitations": ["Exemptions must be explicitly verified against entity facts."],
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

    # Resolve Jurisdiction/Regulator
    jur_name = get_field(rec, ["jurisdiction", "country", "region"])
    jur_ref = None
    if jur_name:
        jur_ref = add_jurisdiction(parsed, jur_name, rec.get("country"), rec.get("state_province"), source_id, evidence_id)

    reg_name = get_field(rec, ["regulator", "authority", "agency"])
    reg_ref = None
    if reg_name:
        reg_ref = add_regulator(parsed, reg_name, jur_ref, rec.get("mandate"), source_id, evidence_id)

    # Resolve Instrument
    inst_id = get_field(rec, ["instrument_id", "regulation_id", "rule_id", "citation"])
    inst_title = get_field(rec, ["title", "name", "official_title"])
    inst_type = get_field(rec, ["type", "instrument_type"])
    inst_status = get_field(rec, ["status", "legal_status"])
    pub_date = get_field(rec, ["published_at", "publication_date"])
    eff_date = get_field(rec, ["effective_from", "effective_date"])
    trans_end = get_field(rec, ["transition_end", "implementation_deadline"])
    
    inst_ref = None
    if inst_id or inst_title:
        inst_ref = add_instrument(
            parsed, 
            inst_id, 
            inst_title, 
            inst_type, 
            inst_status, 
            pub_date, 
            eff_date, 
            trans_end, 
            get_field(rec, ["repealed_at"]),
            jur_ref, 
            reg_ref, 
            source_id, 
            evidence_id, 
            rec_ctx
        )

    # Extract Obligations from nested lists or keywords
    obl_items = get_field(rec, ["obligations", "requirements"], as_list=True)
    for item in obl_items:
        if isinstance(item, dict):
            add_obligation(
                parsed,
                inst_ref,
                item.get("section") or item.get("article"),
                item.get("type") or "MANDATORY",
                item.get("subject") or "REGULATED_ENTITY",
                item.get("action") or item.get("text"),
                item.get("trigger"),
                item.get("deadline"),
                item.get("threshold"),
                item.get("exemption"),
                source_id,
                evidence_id,
                f"{rec_ctx}/obligation"
            )
            
    # Simple Keyword Scan for Obligations if no structured data
    if not obl_items and inst_ref:
        full_text = json.dumps(rec, ensure_ascii=False).lower()
        if any(kw in full_text for kw in OBLIGATION_KEYWORDS):
             # Heuristic: Create a generic obligation placeholder
             add_obligation(
                parsed,
                inst_ref,
                "UNKNOWN_SECTION",
                "HEURISTIC_DETECTED",
                "REGULATED_ENTITY",
                "SEE_TEXT",
                None,
                None,
                None,
                None,
                source_id,
                evidence_id,
                f"{rec_ctx}/keyword_scan"
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
                 caution="Regulatory texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["shall", "must", "required"]):
        signals.append("MANDATORY_LANGUAGE")
    if any(k in low for k in ["may", "can", "optional"]):
        signals.append("PERMISSIVE_LANGUAGE")
    if any(k in low for k in ["exempt", "except", "not applicable"]):
        signals.append("EXEMPTION_CONTEXT")
    if any(k in low for k in ["within", "days", "hours", "by"]):
        signals.append("DEADLINE_CONTEXT")
    if any(k in low for k in ["propose", "draft", "consultation"]):
        signals.append("PROPOSED_STATUS_CONTEXT")
    if any(k in low for k in ["effective", "force", "commence"]):
        signals.append("EFFECTIVE_DATE_CONTEXT")

    if signals:
        add_note(parsed, "REGULATORY_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified legal status.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_REG_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "regulation" in fname or "rule" in fname or "statute" in keys:
        return "REGULATORY_INSTRUMENT"
    if "guidance" in fname or "circular" in fname:
        return "REGULATOR_GUIDANCE"
    if "enforcement" in fname or "fine" in fname or "penalty" in keys:
        return "ENFORCEMENT_ACTION"
    if "consultation" in fname or "draft" in fname:
        return "CONSULTATION_DOCUMENT"

    return "GENERIC_REG_EVIDENCE"


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
    kind = "CSV_REG_DATA"

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
    if "regulation" in low or "act" in low:
        kind = "TEXT_STATUTORY_TEXT"
    elif "guidance" in low or "circular" in low:
        kind = "TEXT_GUIDANCE_NOTE"
    elif "enforcement" in low or "fine" in low:
        kind = "TEXT_ENFORCEMENT_NOTE"
    else:
        kind = "TEXT_GENERIC_REG_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".reg", ".law"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_reg_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No fabrication of regulations/deadlines. No evasion advice. No autonomous filing.",
            "Binary artifacts are hash/metadata preserved only.",
            "Regulatory documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Heuristic extraction requires semantic verification.",
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
            file_evidence["content_kind"] = "BINARY_REG_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary regulatory document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access private systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_instrument_count"] = len(parsed.get("instruments", []))
    file_evidence["parsed_obligation_count"] = len(parsed.get("obligations", []))
    file_evidence["parsed_exemption_count"] = len(parsed.get("exemptions", []))

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


def assess_applicability(parsed: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Simplified applicability engine.
    Checks if instruments are EFFECTIVE and if basic sector/jurisdiction matches exist.
    """
    results = []
    target_jurs = [normalize_text(j) for j in payload.get("jurisdictions", [])]
    target_sectors = [normalize_text(s) for s in payload.get("sectors", [])]
    as_of_str = payload.get("as_of_date") or now_utc()
    as_of_dt = parse_date_safe(as_of_str)
    
    if not as_of_dt:
        as_of_dt = datetime.now(timezone.utc)

    for inst in parsed.get("instruments", []):
        if inst.get("legal_status") != "EFFECTIVE":
            continue
            
        # Check Jurisdiction Match
        jur_match = False
        if target_jurs and inst.get("jurisdiction_ref"):
            # In real system, resolve ref to name. Here we assume simple string match in context if available
            # For this demo, we'll skip deep resolution and mark as INSUFFICIENT_FACTS if no direct link
            pass 
        
        # Check Effective Date
        eff_date_str = inst.get("effective_date")
        if eff_date_str:
            eff_dt = parse_date_safe(eff_date_str)
            if eff_dt and eff_dt > as_of_dt:
                status = "NOT_YET_EFFECTIVE_AT_AS_OF_DATE"
            else:
                status = "EFFECTIVE_AT_AS_OF_DATE"
        else:
            status = "EFFECTIVE_DATE_UNKNOWN"
            
        results.append({
            "assessment_id": f"ASM-{uuid.uuid4()}",
            "instrument_ref": inst.get("instrument_record_id"),
            "instrument_title": inst.get("official_title"),
            "status_at_as_of_date": status,
            "applicability_state": "INSUFFICIENT_FACTS", # Requires entity activity mapping
            "limitations": [
                "Entity-specific activity mapping required for definitive applicability.",
                "Thresholds and exemptions not evaluated in this automated pass.",
            ]
        })
        
    return results


def detect_compliance_gaps(parsed: Dict[str, Any], payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Compares extracted obligations against provided controls/evidence.
    """
    gaps = []
    known_controls = payload.get("controls", [])
    known_evidence = payload.get("evidence", [])
    
    # Very simplistic matching for demo purposes
    control_texts = " ".join([str(c) for c in known_controls]).lower()
    evidence_texts = " ".join([str(e) for e in known_evidence]).lower()
    
    for obl in parsed.get("obligations", []):
        action = normalize_text(obl.get("required_action", ""))
        if not action:
            continue
            
        # Check if keywords from action appear in controls or evidence
        found_control = any(word in control_texts for word in action.split() if len(word) > 3)
        found_evidence = any(word in evidence_texts for word in action.split() if len(word) > 3)
        
        if not found_control and not found_evidence:
            gaps.append({
                "gap_id": f"GAP-{uuid.uuid4()}",
                "obligation_ref": obl.get("obligation_id"),
                "gap_type": "NO_CONTROL_OR_EVIDENCE_MAPPED",
                "description": f"No obvious control or evidence mapped to action: '{action}'",
                "confidence": "LOW_HEURISTIC",
                "limitations": [
                    "Keyword matching is weak. Semantic analysis required.",
                    "Gap does not prove violation, only lack of mapped evidence.",
                ]
            })
            
    return gaps


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for multiple versions of same instrument with conflicting statuses
    inst_by_id: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for inst in parsed.get("instruments", []):
        ext_id = inst.get("external_instrument_id")
        if ext_id:
            inst_by_id[ext_id].append(inst)
            
    for ext_id, group in inst_by_id.items():
        if len(group) > 1:
            statuses = {g.get("legal_status") for g in group}
            if len(statuses) > 1:
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "INSTRUMENT_STATUS_CONFLICT",
                    "subject": ext_id,
                    "values": list(statuses),
                    "possible_explanations": [
                        "Different versions/amendments",
                        "Stale data in one source",
                        "Transition period overlap",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Verify latest official gazette entry.",
                })
                
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    instruments = parsed.get("instruments", [])
    obligations = parsed.get("obligations", [])
    gaps = parsed.get("gaps", [])
    
    if not instruments:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No regulatory instruments identified in local dataset.",
            "supporting_facts": ["Empty instrument list."],
            "opposing_facts": [],
            "unknowns": ["jurisdiction", "sector"],
            "next_test": "Import valid regulation/statute exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if any(i.get("legal_status") == "PROPOSED" for i in instruments):
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Some identified instruments are PROPOSED/DRAFT, not yet binding.",
            "supporting_facts": ["Status field indicates PROPOSED."],
            "opposing_facts": ["May become effective soon."],
            "unknowns": ["final adoption date", "scope changes"],
            "falsification_conditions": ["Official gazette confirms enactment."],
            "next_test": "Monitor consultation outcomes and final publication.",
            "status": "MONITORING",
        })

    if gaps:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Potential compliance gaps detected due to unmapped controls/evidence.",
            "supporting_facts": [f"{len(gaps)} gap candidate(s) identified."],
            "opposing_facts": ["Heuristic matching may miss existing controls."],
            "unknowns": ["actual control state", "evidence availability"],
            "falsification_conditions": ["Manual review confirms controls exist and are effective."],
            "next_test": "Conduct detailed control-obligation mapping workshop.",
            "status": "REVIEW_REQUIRED",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    instruments = parsed.get("instruments", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized regulatory sources exist?",
            "missing_evidence": "No local REGINT artifact supplied.",
            "likely_source": "Official Gazette, Regulator Website, Legal Database.",
            "specialist_owner": "REGINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline regulatory analysis.",
            "safety_boundary": "No evasion, no fabrication.",
        })

    if instruments and not any(i.get("effective_date") for i in instruments):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "When do these instruments become effective?",
            "missing_evidence": "Effective dates missing.",
            "likely_source": "Official commencement order or gazette notice.",
            "specialist_owner": "REGINT / LEGALINT",
            "priority": "HIGH",
            "expected_information_value": "Determines temporal applicability.",
            "safety_boundary": "Do not assume immediate effect without proof.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    instruments = parsed.get("instruments", [])
    gaps = parsed.get("gaps", [])
    
    if any(i.get("legal_status") == "UNKNOWN" for i in instruments):
        handoffs.append({
            "specialist": "LEGALINT",
            "reason": "Legal status of some instruments is ambiguous.",
            "expected_output": "Definitive interpretation of binding force.",
            "question": "Is this guidance legally binding or advisory?",
        })
        
    if gaps:
        handoffs.append({
            "specialist": "COMPLIANCE OFFICER / AUDIT",
            "reason": "Potential compliance gaps identified.",
            "expected_output": "Verification of control effectiveness.",
            "question": "Do existing controls actually satisfy the obligation?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "REGINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Are current insights sufficient for risk decisions?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["applicability_assessments"] = assess_applicability(parsed, payload)
    parsed["gaps"] = detect_compliance_gaps(parsed, payload)
    parsed["contradictions"] = build_contradictions(parsed)
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
    instruments = parsed.get("instruments", [])
    gaps = parsed.get("gaps", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited evasion, concealment, or fabrication behavior.",
            "reason": "REGINT is defensive compliance intelligence, not an evasion tool.",
            "owner": "REGINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized regulation/guidance/enforcement exports before analysis.",
            "reason": "No REGINT evidence artifact available.",
            "owner": "REGINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if any(i.get("legal_status") == "PROPOSED" for i in instruments):
        return {
            "action": "Set up monitoring for final adoption and effective dates of proposed rules.",
            "reason": "Proposed rules may change before enactment.",
            "owner": "REGINT Analyst",
            "expected_output": "Change alert configuration.",
        }

    if gaps:
        return {
            "action": "Conduct manual control-obligation mapping to validate heuristic gap findings.",
            "reason": "Automated keyword matching has low confidence.",
            "owner": "COMPLIANCE / AUDIT",
            "expected_output": "Verified compliance state or confirmed remediation plan.",
        }

    return {
        "action": "Proceed with detailed applicability analysis using entity-specific activity data.",
        "reason": "Basic instrument ingestion complete.",
        "owner": "REGINT / CORPINT",
        "expected_output": "Entity-specific obligation register.",
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
    has_insts = bool(parsed.get("instruments"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General REGINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Lawful / public-source / authorized / evidence-first regulatory intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_regulatory_questions_scope",
        "REGINT Manager",
        "Convert objective into regulatory questions, allowed sources, and privacy boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_regulatory_records",
        "local evidence store",
        "Store original regulations/guidance/enforcement actions and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "RegulatoryEvidenceObject with SHA256.",
    )

    add(
        "parse_instrument_obligation_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT regulatory metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized instruments/obligations/exemptions.",
    )

    add(
        "assess_temporal_status",
        "local analyzer",
        "Determine if instruments are Proposed, Enacted, or Effective relative to As-Of Date.",
        "COMPLETED_LOCAL" if has_insts else "PLANNED_ANALYTIC",
        "Temporal status register.",
        safety_risk="HIGH_IF_PROPOSED_TAKEN_AS_FINAL",
    )

    add(
        "map_obligations_to_controls",
        "REGINT Analyst / Compliance Team",
        "Link extracted obligations to organizational controls and evidence.",
        "PLANNED_ANALYTIC",
        "Control-Obligation matrix and Gap candidates.",
        safety_risk="HIGH_IF_GAP_CALLED_VIOLATION",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_org",
        "questions",
        "jurisdictions",
        "regulators",
        "activities",
        "instruments",
        "obligations",
        "controls",
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
            "Sensitive regulatory context detected. Analysis must remain lawful, public-source, and evidence-first. "
            "No evasion, no fabrication, no autonomous filing."
        )

    if payload.get("obligations") or payload.get("controls"):
        human_review_required = True
        safety_notes.append(
            "Obligation/Control context detected. Consequential compliance conclusions require human/legal review."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal regulatory evasion, concealment, or fabrication."
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
                "No obvious hard policy violation detected, but sensitive regulatory/compliance context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful regulatory evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target_org", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No REGINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "jurisdictions",
        "regulators",
        "sectors",
        "instrument_paths",
        "guidance_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No regulatory evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Regulatory applicability is time-dependent.")

    if not payload.get("configured_connectors"):
        warnings.append("No gov portal/legal-db connector configured. External correlation remains planning-only.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which regulators and jurisdictions are relevant to this entity?",
        "Which regulatory instruments are currently EFFECTIVE?",
        "Are there any PROPOSED rules that may impact future compliance?",
        "What specific obligations apply to our business activities?",
        "Are there any exemptions or thresholds that might exclude us?",
        "What are the critical reporting/notification deadlines?",
        "Do our existing controls adequately map to these obligations?",
        "Where are the potential compliance gaps?",
        "What recent enforcement actions signal regulator priorities?",
        "What remains legally unresolved requiring counsel review?",
    ]


class TraceAtlasREGINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#34d399", font=("Segoe UI", 17, "bold")) # Green accent
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
        ttk.Label(header, text="TraceAtlas REGINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Lawful / public-source / authorized / evidence-first regulatory intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT regulation/guidance/enforcement parsing only • "
                "No evasion / no fabrication / no autonomous filing / no concealment • "
                "Proposed != Final • Enacted != Effective • Effective != Applicable • Guidance != Law"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="REGINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Regulatory Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Regulations / Statutes", command=self.add_instruments).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Guidance / Circulars", command=self.add_guidance).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Enforcement Actions", command=self.add_enforcement).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Consultations / Drafts", command=self.add_consultations).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local REGINT Evidence", command=self.analyze_local_reg).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Regulatory Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#bbf7d0", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "REG-CASE-001")
        self.set_widget_value("task_id", "REG-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive regulatory intelligence using evidence-first methods.")
        self.set_widget_value("target_org", "Illustrative Example Corp")
        self.set_widget_value("target_type", "applicability_check")
        self.set_widget_value("questions", "\n".join(default_questions({"target_org": "Illustrative Example Corp"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["official_gazette", "regulator_site"], "prohibited_actions": ["evade_reg", "fabricate_license"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_compliance_audit"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_PUBLIC_SOURCE_EVIDENCE_FIRST"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_instruments(self): self._append_paths("instrument_paths", filedialog.askopenfilenames(title="Select Regulations", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_guidance(self): self._append_paths("guidance_paths", filedialog.askopenfilenames(title="Select Guidance", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_enforcement(self): self._append_paths("enforcement_paths", filedialog.askopenfilenames(title="Select Enforcement", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_consultations(self): self._append_paths("consultation_paths", filedialog.askopenfilenames(title="Select Consultations", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_reg(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["instrument_paths", "guidance_paths", "enforcement_paths", "consultation_paths", "stix_misp_paths"]
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
            f, parsed = analyze_reg_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nInstruments: {len(aggregated['instruments'])}\nObligations: {len(aggregated['obligations'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("instruments") and not self.parsed.get("obligations"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "instruments_preview": self.parsed.get("instruments", [])[:100],
            "obligations_preview": self.parsed.get("obligations", [])[:100],
            "exemptions_preview": self.parsed.get("exemptions", [])[:100],
            "applicability_assessments": self.parsed.get("applicability_assessments", []),
            "gaps": self.parsed.get("gaps", []),
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
            "mode": "LOCAL_DETERMINISTIC_REGINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "instruments": parsed.get("instruments", [])[:300],
            "obligations": parsed.get("obligations", [])[:300],
            "exemptions": parsed.get("exemptions", [])[:300],
            "applicability_assessments": parsed.get("applicability_assessments", []),
            "gaps": parsed.get("gaps", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No evasion, no fabrication, no autonomous filing.",
                "Proposed != Final.",
                "Enacted != Effective.",
                "Gap != Violation.",
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
        app = TraceAtlasREGINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")