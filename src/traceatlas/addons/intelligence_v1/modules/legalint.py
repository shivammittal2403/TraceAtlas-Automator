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


APP_TITLE = "TraceAtlas LEGALINT AI Employee — Lawful / Public-Record / Authorized / Evidence-First Legal Intelligence Panel"
APP_VERSION = "TraceAtlas LEGALINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID (Internal)", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Party / Case Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "LEGALINT Questions", "text"),

    ("jurisdictions", "Jurisdictions", "text"),
    ("courts", "Courts / Tribunals", "text"),
    ("regulators", "Regulators / Agencies", "text"),
    ("case_names", "Case Names", "text"),
    ("case_numbers", "Case Numbers / Docket IDs", "text"),
    ("parties", "Parties (Plaintiff/Defendant/Petitioner etc.)", "text"),
    
    ("documents", "Legal Documents (Complaints/Orders/Judgments/etc.)", "text"),
    ("dockets", "Docket Entries", "text"),
    ("statutes", "Statutes / Codes", "text"),
    ("regulations", "Regulations / Rules", "text"),
    ("enforcement_actions", "Enforcement Actions / Notices", "text"),
    ("settlements", "Settlements / Consent Decrees", "text"),
    ("licenses", "Licenses / Permits", "text"),
    ("debarments", "Debarments / Exclusions", "text"),

    ("legal_record_paths", "General Legal Record Paths", "text"),
    ("docket_paths", "Docket Export Paths", "text"),
    ("judgment_paths", "Judgment / Opinion Paths", "text"),
    ("statute_paths", "Statute / Regulation Text Paths", "text"),
    ("enforcement_paths", "Enforcement / License / Debarment Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Court API/Legal DB/etc.)", "text"),
]


TARGET_TYPES = [
    "case_status_check",
    "party_litigation_history",
    "regulatory_enforcement_context",
    "statute_interpretation_support",
    "precedent_analysis",
    "compliance_gap_analysis",
    "fraud_legal_context",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "jurisdictions",
    "courts",
    "regulators",
    "case_names",
    "case_numbers",
    "parties",
    "documents",
    "dockets",
    "statutes",
    "regulations",
    "enforcement_actions",
    "settlements",
    "licenses",
    "debarments",
    "legal_record_paths",
    "docket_paths",
    "judgment_paths",
    "statute_paths",
    "enforcement_paths",
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
    "case_status_check",
    "party_litigation_history",
    "regulatory_enforcement_context",
    "statute_interpretation_support",
    "precedent_analysis",
    "compliance_gap_analysis",
    "fraud_legal_context",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


POLICY_BLOCK_PATTERNS = [
    r"\b(?:file|submit|serve)\b[^\n]{0,140}\b(?:lawsuit|motion|document|paper|pleading|subpoena)\b",
    r"\b(?:contact|call|email|message)\b[^\n]{0,140}\b(?:judge|regulator|opposing counsel|witness|party)\b[^\n]{0,80}\b(?:autonomously|directly|secretly|without authorization)\b",
    r"\b(?:fabricate|forge|invent|create)\b[^\n]{0,140}\b(?:citation|case law|statute|regulation|judgment|evidence|affidavit)\b",
    r"\b(?:alter|tamper|destroy|hide)\b[^\n]{0,140}\b(?:evidence|record|document|file)\b",
    r"\b(?:coach|intimidate|harrass|threaten)\b[^\n]{0,140}\b(?:witness|litigant|party|official)\b",
    r"\b(?:access|bypass|steal)\b[^\n]{0,140}\b(?:sealed record|private data|court system|database credential)\b",
    r"\b(?:evade|obstruct|contempt)\b[^\n]{0,140}\b(?:legal process|court order|investigation)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/public-record/authorized/evidence-first legal intelligence: resolve jurisdictions/courts/parties/cases, parse dockets/judgments/statutes/regulations, separate allegations from findings, track procedural posture/appeals/stays/reversals, verify current status/effective dates, and produce source-linked reports with human review escalation.",
    "Do not fabricate citations/cases/statutes/findings, alter/destroy/hide evidence, coach witnesses/perjury, intimidate parties, access sealed records without authorization, bypass court systems, file documents autonomously, contact judges/regulators/witnesses directly, or provide tactics for evading legal process.",
    "Separate allegation from finding, charge from conviction, complaint from fact, motion filed from motion granted, order from final judgment, trial judgment from final unappealable result, appeal from stay, settlement from admission, dismissal from exoneration, guidance from binding law, and current law from historical law.",
    "Use deterministic extraction for case numbers/dates/citations/statuses. Escalate consequential legal advice, filing decisions, deadline calculations, or liability determinations to authorized human/legal team review.",
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
    r"delete\s+(?:the\s+)?(?:record|evidence)",
    r"change\s+(?:the\s+)?(?:outcome|finding|status)",
]


# Regex patterns for legal identifiers
CASE_NUM_RE = re.compile(r"\b(?:No\.?\s*)?[A-Z0-9\-\/]{5,20}\b", re.I)
CITATION_RE = re.compile(r"\b\d+\s+[A-Z\s\.]+\s+\d+\b|\b[A-Z]{2,}\s+Civ\.\s*\d+\b", re.I) # Very loose heuristic
DATE_RE = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b|\b\d{4}-\d{2}-\d{2}\b", re.I)


ENTITY_ROLE_KEYS = [
    "party",
    "parties",
    "plaintiff",
    "defendant",
    "petitioner",
    "respondent",
    "appellant",
    "appellee",
    "accused",
    "claimant",
    "regulator",
    "licensee",
    "intervenor",
    "amicus",
    "third_party",
    "organization",
    "companies",
    "person",
    "persons",
]


DOCUMENT_TYPE_KEYS = [
    "complaint",
    "petition",
    "indictment",
    "information",
    "answer",
    "response",
    "counterclaim",
    "affidavit",
    "declaration",
    "motion",
    "brief",
    "memorandum",
    "exhibit",
    "transcript",
    "order",
    "opinion",
    "judgment",
    "decree",
    "settlement",
    "consent_decree",
    "notice",
    "decision",
    "appeal",
    "mandate",
    "statute",
    "regulation",
    "rule",
    "guidance",
]


STATUS_MAP = {
    "filed": "FILED",
    "pending": "PENDING",
    "active": "ACTIVE",
    "stayed": "STAYED",
    "dismissed": "DISMISSED",
    "with prejudice": "DISMISSED_WITH_PREJUDICE",
    "without prejudice": "DISMISSED_WITHOUT_PREJUDICE",
    "judgment entered": "JUDGMENT_ENTERED",
    "settled": "SETTLED",
    "appeal pending": "APPEAL_PENDING",
    "remanded": "REMANDED",
    "closed": "CLOSED",
    "reopened": "REOPENED",
    "granted": "GRANTED",
    "denied": "DENIED",
    "moot": "MOOT",
    "withdrawn": "WITHDRAWN",
    "affirmed": "AFFIRMED",
    "reversed": "REVERSED",
    "vacated": "VACATED",
    "modified": "MODIFIED",
    "convicted": "CONVICTED",
    "acquitted": "ACQUITTED",
    "charged": "CHARGED",
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


def extract_case_numbers(text: str) -> List[str]:
    return [m.group(0).strip() for m in CASE_NUM_RE.finditer(text or "")]


def extract_citations(text: str) -> List[str]:
    return [m.group(0).strip() for m in CITATION_RE.finditer(text or "")]


def extract_dates(text: str) -> List[str]:
    return [m.group(0).strip() for m in DATE_RE.finditer(text or "")]


def map_status(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return STATUS_MAP.get(norm, raw.upper() if raw else "UNKNOWN")


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "jurisdictions": [],
        "courts": [],
        "regulators": [],
        "cases": [],
        "parties": [],
        "documents": [],
        "dockets": [],
        "allegations": [],
        "findings": [],
        "orders": [],
        "judgments": [],
        "appeals": [],
        "statutes": [],
        "regulations": [],
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
            "Observation is a record of what was stated/filed, not necessarily a judicial finding.",
            "Party filings are advocacy; court orders/judgments are adjudications.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in legal docs are ignored.")


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
            "Multiple databases reproducing one judgment are not independent sources.",
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
        "limitations": ["Jurisdiction determines applicable law/procedure. Same term may differ across jurisdictions."],
    })
    return jid


def add_court(parsed: Dict[str, Any], name: Any, jurisdiction_ref: Any, level: Any, source_id: str, evidence_id: str) -> Optional[str]:
    n = safe_str(name, 100)
    if not n:
        return None
        
    cid = f"CRT-{uuid.uuid4()}"
    parsed["courts"].append({
        "court_id": cid,
        "name": n,
        "jurisdiction_ref": jurisdiction_ref,
        "level": safe_str(level, 50).upper() or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "COURT_CANDIDATE",
        "limitations": ["Court hierarchy affects precedent/binding status. Trial vs Appellate distinction matters."],
    })
    return cid


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
        "limitations": ["Regulator powers are statutory. Agency name does not imply unlimited authority."],
    })
    return rid


def add_party(parsed: Dict[str, Any], name: Any, role: Any, entity_type: Any, source_id: str, evidence_id: str, context: str = "") -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    norm = normalize_text(n)
    r = safe_str(role, 50).upper() or "UNKNOWN"
    et = safe_str(entity_type, 50).upper() or "ORGANIZATION"
    
    for p in parsed["parties"]:
        if p.get("normalized_name") == norm and p.get("role") == r:
            return p.get("party_id")

    pid = f"PTY-{uuid.uuid4()}"
    parsed["parties"].append({
        "party_id": pid,
        "name": n,
        "normalized_name": norm,
        "role": r,
        "entity_type": et,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PARTY_CANDIDATE",
        "limitations": [
            "Party role (Defendant/Accused) does not prove wrongdoing.",
            "Same name does not automatically mean same party. Identity resolution required.",
        ],
    })
    return pid


def add_case(parsed: Dict[str, Any], case_number: Any, case_name: Any, court_ref: Any, jur_ref: Any, filing_date: Any, status: Any, matter_type: Any, source_id: str, evidence_id: str, context: str = "") -> Optional[str]:
    cn = safe_str(case_number, 100)
    cname = safe_str(case_name, 200)
    
    if not cn and not cname:
        return None
        
    cid = f"CASE-{uuid.uuid4()}"
    parsed["cases"].append({
        "case_id": cid,
        "case_number": cn,
        "case_name": cname,
        "court_ref": court_ref,
        "jurisdiction_ref": jur_ref,
        "filing_date": safe_str(filing_date, 100),
        "status": map_status(status),
        "matter_type": safe_str(matter_type, 50).upper() or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "CASE_CANDIDATE",
        "limitations": [
            "Case identity requires number+court+parties verification.",
            "Status changes over time (Appeal/Stay/Reversal). Current status must be checked.",
        ],
    })
    return cid


def add_document(parsed: Dict[str, Any], doc_type: Any, title: Any, date: Any, issuer: Any, content_summary: Any, citation: Any, source_id: str, evidence_id: str, context: str = "") -> Optional[str]:
    dt = safe_str(doc_type, 50).upper() or "UNKNOWN"
    t = safe_str(title, 200)
    
    did = f"DOC-{uuid.uuid4()}"
    parsed["documents"].append({
        "document_id": did,
        "document_type": dt,
        "title": t,
        "date": safe_str(date, 100),
        "issuer": safe_str(issuer, 200),
        "content_summary": safe_str(content_summary, 1000),
        "citation": safe_str(citation, 200),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "DOCUMENT_PARSED",
        "limitations": [
            "Document type dictates evidentiary weight (Complaint=Allegation, Judgment=Finding).",
            "OCR/Summaries may contain errors. Primary source verification recommended.",
        ],
    })
    return did


def add_allegation(parsed: Dict[str, Any], case_ref: Any, party_ref: Any, text: Any, source_doc_ref: Any, source_id: str, evidence_id: str) -> None:
    aid = f"ALG-{uuid.uuid4()}"
    parsed["allegations"].append({
        "allegation_id": aid,
        "case_ref": case_ref,
        "party_ref": party_ref,
        "text": safe_str(text, 1000),
        "source_doc_ref": source_doc_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "PARTY_ALLEGATION",
        "limitations": [
            "This is an assertion by a party, NOT a judicial finding.",
            "Do not treat allegation as established fact.",
        ],
    })


def add_finding(parsed: Dict[str, Any], case_ref: Any, court_ref: Any, text: Any, source_doc_ref: Any, source_id: str, evidence_id: str) -> None:
    fid = f"FND-{uuid.uuid4()}"
    parsed["findings"].append({
        "finding_id": fid,
        "case_ref": case_ref,
        "court_ref": court_ref,
        "text": safe_str(text, 1000),
        "source_doc_ref": source_doc_ref,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "COURT_FINDING",
        "limitations": [
            "This is a determination by the court/regulator.",
            "Subject to appeal/stay/reversal. Check current status.",
        ],
    })


def add_appeal(parsed: Dict[str, Any], lower_case_ref: Any, appellate_court_ref: Any, appellant_ref: Any, appellee_ref: Any, outcome: Any, date: Any, source_id: str, evidence_id: str) -> None:
    apid = f"APP-{uuid.uuid4()}"
    parsed["appeals"].append({
        "appeal_id": apid,
        "lower_case_ref": lower_case_ref,
        "appellate_court_ref": appellate_court_ref,
        "appellant_ref": appellant_ref,
        "appellee_ref": appellee_ref,
        "outcome": map_status(outcome),
        "date": safe_str(date, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "state": "APPEAL_RECORD",
        "limitations": [
            "Appeal filed does not automatically stay lower decision.",
            "Outcome (Affirm/Reverse/Vacate) changes current legal status.",
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

    # Resolve Jurisdiction/Court/Regulator
    jur_name = get_field(rec, ["jurisdiction", "country", "region"])
    jur_ref = None
    if jur_name:
        jur_ref = add_jurisdiction(parsed, jur_name, rec.get("country"), rec.get("state_province"), source_id, evidence_id)

    court_name = get_field(rec, ["court", "tribunal", "forum"])
    court_ref = None
    if court_name:
        court_ref = add_court(parsed, court_name, jur_ref, rec.get("court_level"), source_id, evidence_id)

    reg_name = get_field(rec, ["regulator", "agency", "commission"])
    reg_ref = None
    if reg_name:
        reg_ref = add_regulator(parsed, reg_name, jur_ref, rec.get("mandate"), source_id, evidence_id)

    # Resolve Parties
    party_refs = []
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                pname = val.get("name") or val.get("legal_name") or val.get("id")
                prole = val.get("role") or key.upper()
                ptype = val.get("type") or "ORGANIZATION"
            else:
                pname = str(val)
                prole = key.upper()
                ptype = "UNKNOWN"
            
            pref = add_party(parsed, pname, prole, ptype, source_id, evidence_id, f"{rec_ctx}/{key}")
            if pref:
                party_refs.append(pref)

    # Resolve Case
    case_num = get_field(rec, ["case_number", "docket_id", "case_no"])
    case_name = get_field(rec, ["case_name", "caption", "title"])
    case_status = get_field(rec, ["status", "procedural_posture"])
    matter_type = get_field(rec, ["matter_type", "case_type"])
    filing_dt = get_field(rec, ["filing_date", "initiated_at"])
    
    case_ref = None
    if case_num or case_name:
        case_ref = add_case(parsed, case_num, case_name, court_ref, jur_ref, filing_dt, case_status, matter_type, source_id, evidence_id, rec_ctx)

    # Process Documents
    doc_items = get_field(rec, DOCUMENT_TYPE_KEYS, as_list=True)
    for item in doc_items:
        if isinstance(item, dict):
            dtype = item.get("type") or item.get("document_type") or "UNKNOWN"
            dtitle = item.get("title") or item.get("name")
            ddate = item.get("date") or item.get("filed_at")
            dissuer = item.get("issuer") or item.get("author") or item.get("court")
            dsummary = item.get("summary") or item.get("text") or item.get("content")
            dcite = item.get("citation") or item.get("reference")
            
            doc_ref = add_document(parsed, dtype, dtitle, ddate, dissuer, dsummary, dcite, source_id, evidence_id, f"{rec_ctx}/doc")
            
            # If it's a Complaint/Petition, extract Allegations
            if normalize_key(dtype) in ["complaint", "petition", "indictment", "information", "charge_sheet"]:
                alleg_text = item.get("allegations") or item.get("claims") or dsummary
                if alleg_text and case_ref:
                    # Simplified: attach first party as plaintiff/alleging party if available
                    alleging_party = party_refs[0] if party_refs else None
                    add_allegation(parsed, case_ref, alleging_party, alleg_text, doc_ref, source_id, evidence_id)
            
            # If it's a Judgment/Order/Finding, extract Findings
            elif normalize_key(dtype) in ["judgment", "order", "opinion", "decision", "finding"]:
                find_text = item.get("findings") or item.get("holding") or dsummary
                if find_text and case_ref:
                    add_finding(parsed, case_ref, court_ref, find_text, doc_ref, source_id, evidence_id)

    # Process Appeals
    appeal_items = get_field(rec, ["appeal", "appeals"], as_list=True)
    for item in appeal_items:
        if isinstance(item, dict):
            lower_c = item.get("lower_case") or case_ref
            app_ct = item.get("appellate_court") or court_ref
            applnt = item.get("appellant") or party_refs[0] if party_refs else None
            appll = item.get("appellee") or party_refs[1] if len(party_refs)>1 else None
            outc = item.get("outcome") or item.get("decision")
            adt = item.get("date") or item.get("decided_at")
            
            add_appeal(parsed, lower_c, app_ct, applnt, appll, outc, adt, source_id, evidence_id)


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
                 caution="Legal docs are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["complaint", "petition", "alleges", "claims"]):
        signals.append("PLEADING_CONTEXT")
    if any(k in low for k in ["order", "judgment", "found", "held", "decided"]):
        signals.append("ADJUDICATION_CONTEXT")
    if any(k in low for k in ["appeal", "reversed", "vacated", "affirmed", "remanded"]):
        signals.append("APPELLATE_HISTORY_CONTEXT")
    if any(k in low for k in ["statute", "regulation", "section", "code"]):
        signals.append("STATUTORY_CONTEXT")
    if any(k in low for k in ["fine", "penalty", "sanction", "debarred"]):
        signals.append("ENFORCEMENT_CONTEXT")
    if any(k in low for k in ["seal", "confidential", "privileged"]):
        signals.append("RESTRICTED_ACCESS_CONTEXT")

    if signals:
        add_note(parsed, "LEGAL_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified legal status.")

    # Auto-extract identifiers
    case_nums = extract_case_numbers(redacted)
    if case_nums:
        add_note(parsed, "CASE_NUMBER_DETECTED", values=case_nums[:10], source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Case number detection is heuristic. Verify against official docket.")
                 
    cites = extract_citations(redacted)
    if cites:
        add_note(parsed, "CITATION_DETECTED", values=cites[:10], source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Citation extraction is heuristic. Fabricated citations are prohibited.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_LEGAL_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "docket" in fname or "entries" in keys:
        return "DOCKET_EXPORT"
    if "judgment" in fname or "opinion" in fname or "order" in keys:
        return "JUDICIAL_DECISION"
    if "statute" in fname or "code" in fname or "regulation" in keys:
        return "STATUTORY_TEXT"
    if "enforcement" in fname or "fine" in fname or "sanction" in keys:
        return "ENFORCEMENT_ACTION"
    if "case" in fname or "litigation" in fname:
        return "CASE_RECORD"

    return "GENERIC_LEGAL_EVIDENCE"


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
    kind = "CSV_LEGAL_DATA"

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
    if "docket" in low or "entry" in low:
        kind = "TEXT_DOCKET_LOG"
    elif "judgment" in low or "opinion" in low:
        kind = "TEXT_JUDICIAL_OPINION"
    elif "statute" in low or "section" in low:
        kind = "TEXT_STATUTORY_TEXT"
    else:
        kind = "TEXT_GENERIC_LEGAL_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".docket", ".judgment", ".statute"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_legal_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No fabrication of citations/cases/statutes. No alteration/destruction of evidence. No autonomous filing/contacting.",
            "Binary artifacts are hash/metadata preserved only.",
            "Legal documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Allegations are not findings. Charges are not convictions.",
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
            file_evidence["content_kind"] = "BINARY_LEGAL_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary legal document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access sealed/private systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_case_count"] = len(parsed.get("cases", []))
    file_evidence["parsed_party_count"] = len(parsed.get("parties", []))
    file_evidence["parsed_document_count"] = len(parsed.get("documents", []))
    file_evidence["parsed_finding_count"] = len(parsed.get("findings", []))

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


def resolve_current_status(parsed: Dict[str, Any]) -> None:
    """
    Updates case status based on appeals/findings.
    Logic: If Appeal Outcome is REVERSED/VACATED, update Case Status.
    """
    case_map = {c["case_id"]: c for c in parsed.get("cases", [])}
    
    for app in parsed.get("appeals", []):
        lc_ref = app.get("lower_case_ref")
        if lc_ref and lc_ref in case_map:
            outcome = app.get("outcome")
            if outcome in ["REVERSED", "VACATED", "MODIFIED"]:
                # Mark that the original status might be superseded
                case_map[lc_ref]["superseded_by_appeal"] = True
                case_map[lc_ref]["appeal_outcome"] = outcome
                
    # Note: Full temporal resolution requires complex graph traversal. 
    # Here we just flag conflicts for human review.


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for Allegation vs Finding conflict on same issue (simplified)
    # In real system, this would require semantic matching of issues.
    # Here we check if a case has both ALLEGATIONS and FINDINGS but status is DISMISSED without prejudice?
    
    case_map = {c["case_id"]: c for c in parsed.get("cases", [])}
    
    for alg in parsed.get("allegations", []):
        c_ref = alg.get("case_ref")
        if c_ref and c_ref in case_map:
            status = case_map[c_ref].get("status")
            if status == "DISMISSED_WITHOUT_PREJUDICE":
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "PROCEDURAL_DISMISSAL_VS_MERITS",
                    "subject": c_ref,
                    "details": "Case dismissed without prejudice. Allegations remain unresolved on merits.",
                    "caution": "Do not interpret dismissal as exoneration of alleged conduct.",
                })
                
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    cases = parsed.get("cases", [])
    findings = parsed.get("findings", [])
    appeals = parsed.get("appeals", [])
    
    if not cases:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No specific legal matters identified in local dataset.",
            "supporting_facts": ["Empty case list."],
            "opposing_facts": [],
            "unknowns": ["jurisdiction", "parties", "status"],
            "next_test": "Import valid docket/judgment exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    for c in cases:
        c_id = c["case_id"]
        c_findings = [f for f in findings if f.get("case_ref") == c_id]
        c_appeals = [a for a in appeals if a.get("lower_case_ref") == c_id]
        
        if c_findings and not c_appeals:
            hyps.append({
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": f"Findings exist for Case {c_id}, but no appeal record found in dataset.",
                "supporting_facts": [f"{len(c_findings)} finding(s) recorded."],
                "opposing_facts": ["Appeal may be pending/not digitized/sealed."],
                "unknowns": ["finality", "current enforceability"],
                "falsification_conditions": ["Official docket shows Notice of Appeal filed."],
                "next_test": "Verify current docket status for appeal filings.",
                "status": "OPEN",
            })
            
        if c_appeals:
            for a in c_appeals:
                if a.get("outcome") == "REVERSED":
                     hyps.append({
                        "hypothesis_id": f"HYP-{uuid.uuid4()}",
                        "statement": f"Trial finding in Case {c_id} was reversed on appeal.",
                        "supporting_facts": ["Appellate outcome: REVERSED."],
                        "opposing_facts": ["Remand may reinstate portions."],
                        "unknowns": ["scope of reversal", "new trial ordered?"],
                        "falsification_conditions": ["Appellate opinion clarifies partial affirmance."],
                        "next_test": "Read full appellate opinion to determine scope of reversal.",
                        "status": "HIGH_PRIORITY",
                    })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    cases = parsed.get("cases", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized legal records exist?",
            "missing_evidence": "No local LEGALINT artifact supplied.",
            "likely_source": "Court PACER/ECF export, Official Gazette, Regulator website.",
            "specialist_owner": "LEGALINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline legal analysis.",
            "safety_boundary": "No sealed record access, no fabricated citations.",
        })

    if cases and not any(c.get("status") != "UNKNOWN" for c in cases):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the current procedural status of identified cases?",
            "missing_evidence": "Status field missing/unknown.",
            "likely_source": "Latest docket entry.",
            "specialist_owner": "LEGALINT",
            "priority": "HIGH",
            "expected_information_value": "Determines if matter is active/closed/appealed.",
            "safety_boundary": "Absence of status does not mean case closed.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    parties = parsed.get("parties", [])
    findings = parsed.get("findings", [])
    
    if any(p.get("entity_type") == "COMPANY" for p in parties):
        handoffs.append({
            "specialist": "CORPINT / OWNERSHIPINT",
            "reason": "Corporate party involved.",
            "expected_output": "Legal entity resolution, director/officer mapping.",
            "question": "Is the named corporate party correctly identified and currently active?",
        })
        
    if findings:
        handoffs.append({
            "specialist": "FRAUDINT / FININT",
            "reason": "Court findings detected.",
            "expected_output": "Financial impact assessment, fraud correlation.",
            "question": "Do court findings support financial loss or fraudulent intent hypotheses?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "LEGALINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Are current insights sufficient for compliance/risk decisions?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    resolve_current_status(parsed)
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
    cases = parsed.get("cases", [])
    findings = parsed.get("findings", [])
    appeals = parsed.get("appeals", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited fabrication, evidence tampering, witness intimidation, or autonomous filing behavior.",
            "reason": "LEGALINT is defensive legal-record intelligence, not litigation execution.",
            "owner": "LEGALINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized docket/judgment/statute exports before analysis.",
            "reason": "No LEGALINT evidence artifact available.",
            "owner": "LEGALINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if cases and not findings:
        return {
            "action": "Retrieve final judgments/orders to determine if allegations resulted in findings.",
            "reason": "Complaints are allegations. Judgments are findings.",
            "owner": "LEGALINT",
            "expected_output": "Resolved factual/legal status.",
        }

    if findings and not appeals:
        return {
            "action": "Check docket for Notice of Appeal to verify finality.",
            "reason": "Trial findings may be appealed/stayed/reversed.",
            "owner": "LEGALINT",
            "expected_output": "Current legal status (Final vs Pending Appeal).",
        }

    return {
        "action": "Proceed with source-linked reporting and human legal review for consequential decisions.",
        "reason": "Local evidence exists, but legal interpretation requires qualified human counsel.",
        "owner": "LEGALINT / HUMAN LAWYER",
        "expected_output": "Evidence-linked legal intelligence report.",
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
    has_docs = bool(parsed.get("documents"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General LEGALINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Lawful / public-record / authorized / evidence-first legal intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_legal_questions_scope",
        "LEGALINT Manager",
        "Convert objective into legal questions, allowed sources, and privacy boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_legal_records",
        "local evidence store",
        "Store original dockets/judgments/statutes and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "LegalEvidenceObject with SHA256.",
    )

    add(
        "parse_docket_judgment_statute_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT legal metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized cases/parties/documents/findings/appeals.",
    )

    add(
        "resolve_jurisdiction_court_party_entities",
        "local resolver",
        "Resolve jurisdictions, courts, regulators, and parties while avoiding false identity merging.",
        "COMPLETED_LOCAL" if has_cases else "PLANNED_REQUIRES_ENTITY_EVIDENCE",
        "Canonical legal entity candidates.",
    )

    add(
        "separate_allegations_from_findings",
        "local analyzer",
        "Classify document types to distinguish party assertions from judicial determinations.",
        "COMPLETED_LOCAL" if has_docs else "PLANNED_ANALYTIC",
        "Allegation/Finding register with source links.",
        safety_risk="HIGH_IF_ALLEGATION_TAKEN_AS_FACT",
    )

    add(
        "track_appeal_stay_reversal_history",
        "LEGALINT Analyst",
        "Link appeals to lower cases and update current status based on outcomes.",
        "COMPLETED_LOCAL" if parsed.get("appeals") else "PLANNED_ANALYTIC",
        "Temporal legal status graph.",
        safety_risk="HIGH_IF_CURRENT_STATUS_IGNORED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target",
        "questions",
        "jurisdictions",
        "courts",
        "parties",
        "documents",
        "statutes",
        "enforcement_actions",
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
            "Sensitive legal context detected. Analysis must remain lawful, public-record, and evidence-first. "
            "No fabrication, no autonomous filing, no witness intimidation."
        )

    if payload.get("documents") or payload.get("dockets"):
        human_review_required = True
        safety_notes.append(
            "Legal document context detected. Respect privilege/sealing. Do not expose restricted data."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal legal manipulation, fabrication, evidence tampering, or unauthorized access."
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
                "No obvious hard policy violation detected, but sensitive legal/privilege/context applies. "
                "Conclusions must remain defensive, evidence-linked, and human-reviewed before consequential legal action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": (
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful legal evidence is configured."
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
        warnings.append("No LEGALINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "jurisdictions",
        "courts",
        "case_numbers",
        "parties",
        "legal_record_paths",
        "docket_paths",
        "judgment_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No legal evidence provided. Output remains planning-only.")

    if not payload.get("time_range"):
        warnings.append("No time range provided. Law is time-dependent (effective dates/amendments).")

    if not payload.get("configured_connectors"):
        warnings.append("No court/legal-db connector configured. External correlation remains planning-only.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which jurisdiction and court/regulator are involved?",
        "What is the case number and current procedural status?",
        "Who are the parties and what are their roles?",
        "What allegations have been made by which party?",
        "Have any judicial findings or judgments been entered?",
        "Has the matter been appealed, stayed, reversed, or vacated?",
        "What is the CURRENT legal status as of today?",
        "Which statutes/regulations apply at the relevant time?",
        "Are there any privilege/sealing restrictions noted?",
        "What remains legally unresolved?",
    ]


class TraceAtlasLEGALINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#60a5fa", font=("Segoe UI", 17, "bold")) # Blue accent
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
        ttk.Label(header, text="TraceAtlas LEGALINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Lawful / public-record / authorized / evidence-first legal intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT docket/judgment/statute parsing only • "
                "No fabrication / no autonomous filing / no witness intimidation / no sealed record access • "
                "Allegation != Finding • Charge != Conviction • Complaint != Fact • Appeal != Stay"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="LEGALINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Legal Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Dockets", command=self.add_dockets).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Judgments / Orders", command=self.add_judgments).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Statutes / Regulations", command=self.add_statutes).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Enforcement / Licenses", command=self.add_enforcement).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local LEGALINT Evidence", command=self.analyze_local_legal).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Legal Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#bfdbfe", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "LEGAL-CASE-001")
        self.set_widget_value("task_id", "LEGAL-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive legal intelligence using evidence-first methods.")
        self.set_widget_value("target", "Illustrative example.com / authorized legal context")
        self.set_widget_value("target_type", "case_status_check")
        self.set_widget_value("questions", "\n".join(default_questions({"target": "Illustrative example.com"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public_court", "official_gazette"], "prohibited_actions": ["fabricate_citation", "access_sealed"]}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_PUBLIC_RECORD_EVIDENCE_FIRST"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_dockets(self): self._append_paths("docket_paths", filedialog.askopenfilenames(title="Select Dockets", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_judgments(self): self._append_paths("judgment_paths", filedialog.askopenfilenames(title="Select Judgments", filetypes=[("Docs", "*.json *.csv *.txt *.pdf"), ("All", "*.*")]), "Added")
    def add_statutes(self): self._append_paths("statute_paths", filedialog.askopenfilenames(title="Select Statutes", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_enforcement(self): self._append_paths("enforcement_paths", filedialog.askopenfilenames(title="Select Enforcement", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_legal(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["legal_record_paths", "docket_paths", "judgment_paths", "statute_paths", "enforcement_paths", "stix_misp_paths"]
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
            f, parsed = analyze_legal_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nCases: {len(aggregated['cases'])}\nFindings: {len(aggregated['findings'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("cases") and not self.parsed.get("documents"):
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
            "parties_preview": self.parsed.get("parties", [])[:100],
            "documents_preview": self.parsed.get("documents", [])[:100],
            "allegations_preview": self.parsed.get("allegations", [])[:100],
            "findings_preview": self.parsed.get("findings", [])[:100],
            "appeals_preview": self.parsed.get("appeals", [])[:100],
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
            "mode": "LOCAL_DETERMINISTIC_LEGALINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "cases": parsed.get("cases", [])[:300],
            "parties": parsed.get("parties", [])[:300],
            "documents": parsed.get("documents", [])[:300],
            "allegations": parsed.get("allegations", [])[:300],
            "findings": parsed.get("findings", [])[:300],
            "appeals": parsed.get("appeals", [])[:300],
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No fabrication of citations/cases.",
                "Allegation != Finding.",
                "Charge != Conviction.",
                "Current status requires docket verification.",
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
        app = TraceAtlasLEGALINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")