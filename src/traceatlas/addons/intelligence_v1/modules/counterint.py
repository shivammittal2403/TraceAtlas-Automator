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


APP_TITLE = "TraceAtlas COUNTERINT AI Employee — Defensive / Authorized / Evidence-First / Privacy-Aware Counterintelligence Panel"
APP_VERSION = "TraceAtlas COUNTERINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target_asset_or_identity", "Target Asset / Identity / Account Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "COUNTERINT Questions", "text"),

    ("organizations", "Organizations / Units", "text"),
    ("identities", "Identities / Employees / Contractors", "text"),
    ("accounts", "Accounts / Sessions", "text"),
    ("devices", "Devices / Endpoints", "text"),
    ("assets", "Sensitive Assets / Repositories / Datasets", "text"),
    ("roles", "Roles / Permissions Context", "text"),
    
    ("iam_log_paths", "IAM / Access Log Paths", "text"),
    ("dlp_alert_paths", "DLP / Data Movement Alert Paths", "text"),
    ("edr_log_paths", "EDR / Endpoint Security Log Paths", "text"),
    ("hr_role_paths", "Authorized HR Role / Permission Metadata Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (SIEM/IAM/DLP/etc.)", "text"),
]


TARGET_TYPES = [
    "insider_risk_assessment",
    "hostile_collection_indicator_review",
    "account_compromise_investigation",
    "data_exfiltration_context_check",
    "privileged_access_anomaly_review",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "organizations",
    "identities",
    "accounts",
    "devices",
    "assets",
    "roles",
    "iam_log_paths",
    "dlp_alert_paths",
    "edr_log_paths",
    "hr_role_paths",
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
    "insider_risk_assessment",
    "hostile_collection_indicator_review",
    "account_compromise_investigation",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR UNLAWFUL SURVEILLANCE/ENTRAPMENT/BIAS
POLICY_BLOCK_PATTERNS = [
    r"\b(?:conduct|perform|initiate)\b[^\n]{0,140}\b(?:unlawful surveillance|covert recruitment|entrapment|blackmail|threaten employee)\b",
    r"\b(?:hack|access|steal|compromise)\b[^\n]{0,140}\b(?:employee private account|personal device|private communication|home network)\b",
    r"\b(?:profile|score|risk rank)\b[^\n]{0,140}\b(?:based on nationality|based on ethnicity|based on religion|based on political belief|based on union membership)\b",
    r"\b(?:retaliate against|punish|silence)\b[^\n]{0,140}\b(?:whistleblower|journalist|security researcher|union member)\b",
    r"\b(?:deploy|install)\b[^\n]{0,140}\b(?:spyware|keylogger|hidden camera|microphone recorder)\b",
]


SAFE_ALTERNATIVES = [
    "Provide defensive/authorized/evidence-first/privacy-aware counterintelligence: resolve identities/accounts/devices/assets, correlate access events with authorization context, test benign explanations rigorously, protect whistleblowers/journalists/researchers, and recommend human-led review without conducting unlawful surveillance or bias-based profiling.",
    "Do not hack devices, intercept private comms, entrap, blackmail, recruit covertly, or profile based on nationality/ethnicity/politics/union status.",
    "Separate Account from Person, Device from User, Anomaly from Malice, Policy Violation from Espionage, and Download from Exfiltration.",
    "Use deterministic logic for permission checks and timeline alignment. Escalate consequential insider-risk assessments to authorized human review with strict privacy safeguards.",
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
    r"disable\s+(?:the\s+)?(?:logging|audit|security)",
]


# Regex helpers for CI identifiers
ASSET_ID_RE = re.compile(r"\b(?:Asset|Repo|Dataset|Doc)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)
ACCOUNT_ID_RE = re.compile(r"\b(?:Account|User|Principal)\s*(?:ID|Name)\s*:?\s*[A-Z0-9@.\-_]+\b", re.I)
DEVICE_ID_RE = re.compile(r"\b(?:Device|Endpoint|Host)\s*(?:ID|MAC|Serial)\s*:?\s*[A-Z0-9:\-]+\b", re.I)


ENTITY_ROLE_KEYS = [
    "identity",
    "employee",
    "contractor",
    "vendor",
    "user",
    "principal",
]


ASSET_KEYS = [
    "asset",
    "repository",
    "dataset",
    "document",
    "file",
    "resource",
]


ACCESS_ACTION_KEYS = [
    "view",
    "read",
    "download",
    "copy",
    "export",
    "print",
    "modify",
    "delete",
    "share",
    "upload",
    "sync",
    "clone",
    "archive",
]


ALERT_TYPE_KEYS = [
    "dlp",
    "edr",
    "siem",
    "casb",
    "iam",
    "alert",
    "incident",
]


PROTECTED_ACTIVITY_KEYWORDS = [
    "whistleblow",
    "union",
    "journalist",
    "press",
    "lawyer",
    "regulator",
    "researcher",
    "academic",
    "complaint",
    "grievance",
    "disagreement",
]


NATIONALITY_BIAS_KEYWORDS = [
    "nationality",
    "ethnicity",
    "religion",
    "race",
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


def check_protected_activity(text: str) -> List[str]:
    """Flags if text contains keywords related to protected activities."""
    low = normalize_text(text)
    found = []
    for kw in PROTECTED_ACTIVITY_KEYWORDS:
        if kw in low:
            found.append(kw)
    return found


def check_nationality_bias(text: str) -> List[str]:
    """Flags if text attempts to use prohibited demographic factors."""
    low = normalize_text(text)
    found = []
    for kw in NATIONALITY_BIAS_KEYWORDS:
        if kw in low:
            found.append(kw)
    return found


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "identities": [],
        "accounts": [],
        "devices": [],
        "assets": [],
        "permissions": [],
        "access_events": [],
        "alerts": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "benign_explanations_tested": [],
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
    
    # Protected Activity Check
    prot_flags = check_protected_activity(redacted)
    if prot_flags:
        add_note(parsed, "PROTECTED_ACTIVITY_DETECTED", keywords=prot_flags, source_id=source_id, 
                 caution="Whistleblowing/Journalism/Union activity detected. Do NOT treat as threat indicator.")

    # Nationality Bias Check
    bias_flags = check_nationality_bias(redacted)
    if bias_flags:
        add_note(parsed, "NATIONALITY_BIAS_RISK", keywords=bias_flags, source_id=source_id,
                 caution="Prohibited demographic factor mentioned. Ignore for risk scoring.")

    parsed["observations"].append({
        "observation_id": f"OBS-{uuid.uuid4()}",
        "statement": redacted,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": context[:200],
        "state": "SOURCE_OBSERVED",
        "secret_flags": secret_flags,
        "prompt_injection_flags": injection_flags,
        "protected_activity_flags": prot_flags,
        "content_hash": sha256_text(str(statement or "")),
        "limitations": [
            "Observation records what was logged/stated, not necessarily its malicious intent.",
            "Account activity does not automatically prove the named person performed it.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in logs/docs are ignored.")


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
            "Multiple SIEM alerts triggered by one user action are not independent events.",
        ],
    })


def add_identity(
    parsed: Dict[str, Any],
    name: Any,
    id_ref: Any,
    role: Any,
    org: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    ir = safe_str(id_ref, 200)
    
    if not n and not ir:
        return None
        
    iid = f"ID-{uuid.uuid4()}"
    parsed["identities"].append({
        "identity_id": iid,
        "display_name": n,
        "external_id_ref": ir,
        "role_hint": safe_str(role, 100).upper() or "UNKNOWN",
        "organization": safe_str(org, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "IDENTITY_CANDIDATE",
        "limitations": [
            "Identity resolution requires authoritative HR/IAM data.",
            "Name match alone is insufficient.",
        ],
    })
    return iid


def add_account(
    parsed: Dict[str, Any],
    acc_name: Any,
    acc_id: Any,
    identity_ref: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    an = safe_str(acc_name, 200)
    ai = safe_str(acc_id, 200)
    
    if not an and not ai:
        return None
        
    aid = f"ACC-{uuid.uuid4()}"
    parsed["accounts"].append({
        "account_id": aid,
        "username": an,
        "external_acc_id": ai,
        "associated_identity_ref": identity_ref, # Weak link until verified
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ACCOUNT_PARSED",
        "limitations": [
            "Account != Person. Credentials may be stolen/shared.",
            "Service accounts should not be attributed to humans without session data.",
        ],
    })
    return aid


def add_device(
    parsed: Dict[str, Any],
    dev_name: Any,
    dev_id: Any,
    os_type: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    dn = safe_str(dev_name, 200)
    di = safe_str(dev_id, 200)
    
    if not dn and not di:
        return None
        
    did = f"DEV-{uuid.uuid4()}"
    parsed["devices"].append({
        "device_id": did,
        "hostname": dn,
        "external_dev_id": di,
        "os_type": safe_str(os_type, 100).upper() or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "DEVICE_PARSED",
        "limitations": [
            "Device != Person. Devices can be shared/compromised/virtual.",
        ],
    })
    return did


def add_asset(
    parsed: Dict[str, Any],
    asset_name: Any,
    asset_id: Any,
    classification: Any,
    owner_org: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    an = safe_str(asset_name, 200)
    ai = safe_str(asset_id, 200)
    
    if not an and not ai:
        return None
        
    astid = f"AST-{uuid.uuid4()}"
    cls_norm = normalize_text(classification).upper()
    canonical_cls = "INTERNAL"
    if "PUBLIC" in cls_norm:
        canonical_cls = "PUBLIC"
    elif "CONFIDENTIAL" in cls_norm or "RESTRICTED" in cls_norm:
        canonical_cls = "RESTRICTED"
        
    parsed["assets"].append({
        "asset_id": astid,
        "name": an,
        "external_asset_id": ai,
        "classification": canonical_cls,
        "owner_org": safe_str(owner_org, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ASSET_PARSED",
        "limitations": [
            "Classification may be incorrect. Review required if mismatch suspected.",
        ],
    })
    return astid


def add_permission(
    parsed: Dict[str, Any],
    identity_ref: Any,
    asset_ref: Any,
    perm_type: Any,
    valid_from: Any,
    valid_to: Any,
    business_purpose: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    pid = f"PERM-{uuid.uuid4()}"
    
    parsed["permissions"].append({
        "permission_id": pid,
        "identity_ref": identity_ref,
        "asset_ref": asset_ref,
        "permission_type": safe_str(perm_type, 100).upper() or "READ",
        "valid_from": safe_str(valid_from, 100),
        "valid_to": safe_str(valid_to, 100),
        "business_purpose": safe_str(business_purpose, 300),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PERMISSION_PARSED",
        "limitations": [
            "Permission exists does not mean legitimate use occurred at specific time.",
            "Check role-at-event-time.",
        ],
    })


def add_access_event(
    parsed: Dict[str, Any],
    account_ref: Any,
    device_ref: Any,
    asset_ref: Any,
    action: Any,
    timestamp: Any,
    destination: Any,
    volume: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    eid = f"EVT-{uuid.uuid4()}"
    
    act_norm = normalize_text(action).upper()
    canonical_act = "UNKNOWN"
    if "DOWNLOAD" in act_norm or "EXPORT" in act_norm or "COPY" in act_norm:
        canonical_act = "DATA_MOVEMENT"
    elif "VIEW" in act_norm or "READ" in act_norm:
        canonical_act = "VIEW"
    elif "UPLOAD" in act_norm or "SYNC" in act_norm:
        canonical_act = "EXTERNAL_TRANSFER"
        
    vol_val = None
    if volume:
        try:
            vol_val = float(str(volume).replace(",", ""))
        except:
            pass

    parsed["access_events"].append({
        "event_id": eid,
        "account_ref": account_ref,
        "device_ref": device_ref,
        "asset_ref": asset_ref,
        "action_category": canonical_act,
        "raw_action": safe_str(action, 100),
        "timestamp": safe_str(timestamp, 100),
        "destination": safe_str(destination, 200),
        "volume_estimate": vol_val,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ACCESS_EVENT_PARSED",
        "limitations": [
            "View != Exfiltration. Download != Disclosure.",
            "Requires authorization check against role/time.",
        ],
    })


def add_alert(
    parsed: Dict[str, Any],
    alert_src: Any, # DLP/EDR/SIEM
    rule_name: Any,
    severity: Any,
    subject_ref: Any, # Account/Device/User
    timestamp: Any,
    details: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    aid = f"ALT-{uuid.uuid4()}"
    
    sev_norm = normalize_text(severity).upper()
    canonical_sev = "INFO"
    if "HIGH" in sev_norm or "CRITICAL" in sev_norm:
        canonical_sev = "HIGH"
    elif "MED" in sev_norm or "MODERATE" in sev_norm:
        canonical_sev = "MEDIUM"
        
    parsed["alerts"].append({
        "alert_id": aid,
        "alert_source": safe_str(alert_src, 50).upper() or "UNKNOWN",
        "rule_name": safe_str(rule_name, 200),
        "severity": canonical_sev,
        "subject_ref": subject_ref,
        "timestamp": safe_str(timestamp, 100),
        "details": safe_str(details, 500),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ALERT_PARSED",
        "limitations": [
            "Alert is a signal, not proof of guilt.",
            "False positives common in DLP/EDR.",
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

    # Resolve Identities
    ident_refs = []
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                iname = val.get("name") or val.get("id")
                iref = val.get("employee_id") or val.get("uid")
                irole = val.get("role") or val.get("job_title")
                iorg = val.get("org") or val.get("department")
            else:
                iname = str(val)
                iref = ""
                irole = ""
                iorg = ""
            
            iref_id = add_identity(parsed, iname, iref, irole, iorg, source_id, evidence_id, f"{rec_ctx}/{key}")
            if iref_id:
                ident_refs.append(iref_id)

    primary_ident_ref = ident_refs[0] if ident_refs else None

    # Resolve Accounts
    acc_items = get_field(rec, ["account", "user", "principal"], as_list=True)
    acc_refs = []
    for item in acc_items:
        if isinstance(item, dict):
            aref = add_account(
                parsed,
                item.get("username") or item.get("name"),
                item.get("id") or item.get("sam_account_name"),
                primary_ident_ref,
                source_id,
                evidence_id,
                f"{rec_ctx}/account"
            )
            if aref:
                acc_refs.append(aref)
                
    primary_acc_ref = acc_refs[0] if acc_refs else None

    # Resolve Devices
    dev_items = get_field(rec, ["device", "endpoint", "host"], as_list=True)
    dev_refs = []
    for item in dev_items:
        if isinstance(item, dict):
            dref = add_device(
                parsed,
                item.get("hostname") or item.get("name"),
                item.get("id") or item.get("mac_address"),
                item.get("os") or item.get("platform"),
                source_id,
                evidence_id,
                f"{rec_ctx}/device"
            )
            if dref:
                dev_refs.append(dref)
                
    primary_dev_ref = dev_refs[0] if dev_refs else None

    # Resolve Assets
    ast_items = get_field(rec, ASSET_KEYS, as_list=True)
    ast_refs = []
    for item in ast_items:
        if isinstance(item, dict):
            astref = add_asset(
                parsed,
                item.get("name") or item.get("path") or item.get("repo_url"),
                item.get("id") or item.get("guid"),
                item.get("classification") or item.get("label"),
                item.get("owner") or item.get("team"),
                source_id,
                evidence_id,
                f"{rec_ctx}/asset"
            )
            if astref:
                ast_refs.append(astref)
                
    primary_ast_ref = ast_refs[0] if ast_refs else None

    # Resolve Access Events
    evt_items = get_field(rec, ["event", "activity", "log_entry", "action"], as_list=True)
    for item in evt_items:
        if isinstance(item, dict):
            add_access_event(
                parsed,
                item.get("account") or primary_acc_ref,
                item.get("device") or primary_dev_ref,
                item.get("asset") or primary_ast_ref,
                item.get("action") or item.get("operation"),
                item.get("timestamp") or item.get("time"),
                item.get("destination") or item.get("to"),
                item.get("size") or item.get("bytes"),
                source_id,
                evidence_id,
                f"{rec_ctx}/access_event"
            )

    # Resolve Alerts
    alt_items = get_field(rec, ALERT_TYPE_KEYS, as_list=True)
    for item in alt_items:
        if isinstance(item, dict):
            add_alert(
                parsed,
                item.get("source") or item.get("engine"),
                item.get("rule") or item.get("policy"),
                item.get("severity") or item.get("level"),
                item.get("subject") or primary_acc_ref or primary_dev_ref,
                item.get("timestamp") or item.get("detected_at"),
                item.get("description") or item.get("details"),
                source_id,
                evidence_id,
                f"{rec_ctx}/alert"
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
                 caution="Logs/texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["login", "auth", "sso", "mfa"]):
        signals.append("AUTH_CONTEXT")
    if any(k in low for k in ["download", "export", "copy", "usb"]):
        signals.append("DATA_MOVEMENT_CONTEXT")
    if any(k in low for k in ["alert", "warning", "block", "deny"]):
        signals.append("SECURITY_ALERT_CONTEXT")
    if any(k in low for k in ["admin", "root", "sudo", "elevated"]):
        signals.append("PRIVILEGED_ACCESS_CONTEXT")

    if signals:
        add_note(parsed, "CI_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified threats.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_CI_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "iam" in fname or "access" in fname or "login" in fname:
        return "IAM_ACCESS_LOG"
    if "dlp" in fname or "data_loss" in fname:
        return "DLP_ALERT_LOG"
    if "edr" in fname or "endpoint" in fname:
        return "EDR_TELEMETRY"
    if "hr" in fname or "role" in fname or "perm" in fname:
        return "HR_PERMISSION_METADATA"

    return "GENERIC_CI_EVIDENCE"


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
    kind = "CSV_CI_DATA"

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
    if "iam" in low or "access log" in low:
        kind = "TEXT_IAM_LOG"
    elif "dlp" in low or "alert" in low:
        kind = "TEXT_DLP_ALERT"
    elif "hr" in low or "role" in low:
        kind = "TEXT_HR_METADATA"
    else:
        kind = "TEXT_GENERIC_CI_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".ci", ".sec"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_ci_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No unlawful surveillance, no entrapment, no bias profiling.",
            "Binary artifacts are hash/metadata preserved only.",
            "Logs/documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Anomaly != Threat. Account != Person.",
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
            file_evidence["content_kind"] = "BINARY_CI_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary security document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_ident_count"] = len(parsed.get("identities", []))
    file_evidence["parsed_acc_count"] = len(parsed.get("accounts", []))
    file_evidence["parsed_evt_count"] = len(parsed.get("access_events", []))
    file_evidence["parsed_alt_count"] = len(parsed.get("alerts", []))

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


def test_benign_explanations(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Checks if observed anomalies have potential benign explanations.
    """
    explanations = []
    
    events = parsed.get("access_events", [])
    alerts = parsed.get("alerts", [])
    
    # Heuristic: If high volume download but also EDR shows backup software running
    # Or if after-hours access but shift roster says night shift
    
    for evt in events:
        if evt.get("action_category") == "DATA_MOVEMENT":
            explanations.append({
                "explanation_id": f"BEN-{uuid.uuid4()}",
                "event_ref": evt.get("event_id"),
                "potential_cause": "LEGITIMATE_BACKUP_OR_MIGRATION",
                "confidence": "LOW_UNVERIFIED",
                "verification_needed": "Check change management tickets and backup schedules.",
            })
            
    for alt in alerts:
        if alt.get("alert_source") == "DLP":
            explanations.append({
                "explanation_id": f"BEN-{uuid.uuid4()}",
                "alert_ref": alt.get("alert_id"),
                "potential_cause": "FALSE_POSITIVE_RULE_MATCH",
                "confidence": "MEDIUM_COMMON",
                "verification_needed": "Review matched regex/policy and user business justification.",
            })
            
    return explanations


def assess_insider_risk(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates risk dimensions WITHOUT combining into a single opaque score.
    """
    dims = {
        "ACCESS_ANOMALY": "NONE",
        "DATA_MOVEMENT": "NONE",
        "PRIVILEGE_ABUSE": "NONE",
        "ACCOUNT_COMPROMISE_RISK": "UNKNOWN",
        "POLICY_VIOLATION": "NONE",
        "INTENT_EVIDENCE": "NONE",
        "SOURCE_CONFIDENCE": "LOW",
    }
    
    events = parsed.get("access_events", [])
    perms = parsed.get("permissions", [])
    
    # Simple heuristic: Unusual action category count
    movement_count = sum(1 for e in events if e.get("action_category") == "DATA_MOVEMENT")
    if movement_count > 0:
        dims["DATA_MOVEMENT"] = "OBSERVED"
        
    # Check for privilege mismatches (simplified)
    # In real system, compare event time vs permission valid_from/to
    
    return dims


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting Account-Identity links
    acc_map: Dict[str, List[str]] = defaultdict(list)
    for acc in parsed.get("accounts", []):
        aid = acc.get("account_id")
        iref = acc.get("associated_identity_ref")
        if aid and iref:
            acc_map[aid].append(iref)
            
    for aid, refs in acc_map.items():
        if len(set(refs)) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "IDENTITY_ACCOUNT_CONFLICT",
                "subject": aid,
                "values": list(set(refs)),
                "possible_explanations": [
                    "Shared account",
                    "Data error",
                    "Account takeover",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Do not attribute action to specific person yet.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    events = parsed.get("access_events", [])
    alerts = parsed.get("alerts", [])
    
    if not events and not alerts:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No significant access anomalies or alerts detected.",
            "supporting_facts": ["Empty event/alert lists."],
            "opposing_facts": [],
            "unknowns": ["baseline activity"],
            "next_test": "Import broader telemetry window.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if events:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed data movement may be legitimate work OR policy violation OR compromise.",
            "supporting_facts": [f"{len(events)} event(s) parsed."],
            "opposing_facts": ["Benign explanations not yet ruled out."],
            "unknowns": ["intent", "account control"],
            "falsification_conditions": ["Change ticket confirms approved migration."],
            "next_test": "Correlate with IAM auth logs and endpoint process trees.",
            "status": "ANALYTICAL",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    events = parsed.get("access_events", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized security telemetry exists?",
            "missing_evidence": "No local COUNTERINT artifact supplied.",
            "likely_source": "SIEM Export, IAM Audit Log, DLP Report.",
            "specialist_owner": "COUNTERINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline anomaly detection.",
            "safety_boundary": "No hacking, no unlawful surveillance.",
        })

    if events and not parsed.get("permissions"):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Was this access authorized for this role at this time?",
            "missing_evidence": "Permission metadata missing.",
            "likely_source": "IAM Directory Export, HR Role Database.",
            "specialist_owner": "COUNTERINT / ORGINT",
            "priority": "HIGH",
            "expected_information_value": "Determines if anomaly is unauthorized.",
            "safety_boundary": "Do not assume malice without permission check.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    alerts = parsed.get("alerts", [])
    
    if any(a.get("alert_source") == "EDR" for a in alerts):
        handoffs.append({
            "specialist": "INCIDENTINT / MALINT",
            "reason": "Endpoint security alerts detected.",
            "expected_output": "Malware analysis, process tree reconstruction.",
            "question": "Is the endpoint compromised by external malware?",
        })
        
    if any(a.get("alert_source") == "DLP" for a in alerts):
        handoffs.append({
            "specialist": "LOGINT / NETINT",
            "reason": "Data loss prevention alerts detected.",
            "expected_output": "Traffic analysis, destination verification.",
            "question": "Did data actually leave the corporate perimeter?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "COUNTERINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Is current risk assessment sufficient for human review?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["benign_explanations_tested"] = test_benign_explanations(parsed)
    parsed["risk_dimensions"] = assess_insider_risk(parsed)
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
    risks = parsed.get("risk_dimensions", {})
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited surveillance, entrapment, or bias behavior.",
            "reason": "COUNTERINT is defensive intelligence, not an offensive tool.",
            "owner": "COUNTERINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized IAM/DLP/EDR exports before analysis.",
            "reason": "No COUNTERINT evidence artifact available.",
            "owner": "COUNTERINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if risks.get("DATA_MOVEMENT") == "OBSERVED":
        return {
            "action": "Verify destination and authorization. Preserve logs. Initiate human interview via HUMINT if warranted.",
            "reason": "Data movement observed. Benign explanation not yet confirmed.",
            "owner": "COUNTERINT Analyst / IR Lead",
            "expected_output": "Confirmed benign or escalated incident.",
        }

    return {
        "action": "Continue monitoring. Review false-positive rates for active rules.",
        "reason": "No immediate high-risk indicators.",
        "owner": "SOC / COUNTERINT",
        "expected_output": "Updated baseline.",
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
    has_events = bool(parsed.get("access_events"))
    has_perms = bool(parsed.get("permissions"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General COUNTERINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Defensive / authorized / evidence-first / privacy-aware counterintelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_ci_questions_scope",
        "COUNTERINT Manager",
        "Convert objective into CI questions, allowed sources, and privacy boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_security_logs",
        "local evidence store",
        "Store original IAM/DLP/EDR logs and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "CiEvidenceObject with SHA256.",
    )

    add(
        "parse_identity_access_permission_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT security metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized identities/accounts/events/perms.",
    )

    add(
        "test_benign_explanations_first",
        "local analyzer",
        "Actively seek legitimate business reasons before labeling as threat.",
        "COMPLETED_LOCAL" if has_events else "PLANNED_ANALYTIC",
        "Benign Explanation Register.",
        safety_risk="HIGH_IF_SKIPPED",
    )

    add(
        "check_protected_activities",
        "local filter",
        "Ensure whistleblowing/journalism/union activity is excluded from risk scoring.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_SAFETY_CHECK",
        "Protected Activity Flag Register.",
        safety_risk="CRITICAL_IF_IGNORED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target_asset_or_identity",
        "questions",
        "identities",
        "accounts",
        "assets",
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
            "Sensitive CI context detected. Analysis must remain defensive, authorized, and privacy-aware. "
            "No unlawful surveillance, no entrapment, no bias profiling."
        )

    if payload.get("identities") or payload.get("accounts"):
        human_review_required = True
        safety_notes.append(
            "Personnel context detected. Apply strict privacy safeguards. Do not expose unnecessary PII."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal surveillance, entrapment, or discriminatory profiling."
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
                "No obvious hard policy violation detected, but sensitive personnel/security context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/lawful security evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target_asset_or_identity", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No COUNTERINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "iam_log_paths",
        "dlp_alert_paths",
        "edr_log_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No security evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Security state is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which sensitive assets were accessed?",
        "Who holds the accounts involved?",
        "Was the access authorized for that role at that time?",
        "Are there signs of account compromise?",
        "Did data move externally?",
        "Have benign explanations been tested?",
        "Are protected activities (whistleblowing etc.) being wrongly flagged?",
        "What is the confidence level in identity attribution?",
        "What defensive actions are recommended?",
        "What knowledge gaps remain?",
    ]


class TraceAtlasCOUNTERINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#10b981", font=("Segoe UI", 17, "bold")) # Emerald/Green accent for Defense/Security
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
        ttk.Label(header, text="TraceAtlas COUNTERINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Defensive / authorized / evidence-first / privacy-aware counterintelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT IAM/DLP/EDR parsing only • "
                "No unlawful surveillance / No entrapment / No bias profiling / No whistleblower retaliation • "
                "Account != Person • Anomaly != Threat • Benign Test First"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="COUNTERINT Task Input")
        self.notebook.add(self.output_tab, text="Output / CI Plan / Evidence")

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

        ttk.Button(buttons1, text="Add IAM / Access Logs", command=self.add_iam).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add DLP / Data Alerts", command=self.add_dlp).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add EDR / Endpoint Logs", command=self.add_edr).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add HR / Role Metadata", command=self.add_hr).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local COUNTERINT Evidence", command=self.analyze_local_ci).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate CI Plan", command=self.generate_plan).pack(side="left", padx=4)
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
        self.set_widget_value("case_id", "CI-CASE-001")
        self.set_widget_value("task_id", "CI-TASK-001")
        self.set_widget_value("objective", "Analyze defensive/authorized/privacy-aware counterintelligence using evidence-first methods.")
        self.set_widget_value("target_asset_or_identity", "Illustrative Example Repo R / Account A")
        self.set_widget_value("target_type", "insider_risk_assessment")
        self.set_widget_value("questions", "\n".join(default_questions({"target_asset_or_identity": "Illustrative Example Repo R"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["internal_siem_export", "authorized_iam_log"], "prohibited_actions": ["hack_device", "entrap_employee"]}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_DEFENSIVE_AUTHORIZED_PRIVACY_AWARE"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_iam(self): self._append_paths("iam_log_paths", filedialog.askopenfilenames(title="Select IAM Logs", filetypes=[("Logs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_dlp(self): self._append_paths("dlp_alert_paths", filedialog.askopenfilenames(title="Select DLP Alerts", filetypes=[("Alerts", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_edr(self): self._append_paths("edr_log_paths", filedialog.askopenfilenames(title="Select EDR Logs", filetypes=[("Logs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_hr(self): self._append_paths("hr_role_paths", filedialog.askopenfilenames(title="Select HR Metadata", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_ci(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["iam_log_paths", "dlp_alert_paths", "edr_log_paths", "hr_role_paths", "stix_misp_paths"]
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
            f, parsed = analyze_ci_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nEvents: {len(aggregated['access_events'])}\nAlerts: {len(aggregated['alerts'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("access_events") and not self.parsed.get("alerts"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "identities_preview": self.parsed.get("identities", [])[:100],
            "accounts_preview": self.parsed.get("accounts", [])[:100],
            "access_events_preview": self.parsed.get("access_events", [])[:100],
            "alerts_preview": self.parsed.get("alerts", [])[:100],
            "benign_explanations_tested": self.parsed.get("benign_explanations_tested", []),
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
            "mode": "LOCAL_DETERMINISTIC_COUNTERINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "identities": parsed.get("identities", [])[:300],
            "accounts": parsed.get("accounts", [])[:300],
            "access_events": parsed.get("access_events", [])[:300],
            "alerts": parsed.get("alerts", [])[:300],
            "benign_explanations_tested": parsed.get("benign_explanations_tested", []),
            "risk_dimensions": parsed.get("risk_dimensions", {}),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No unlawful surveillance, no entrapment, no bias profiling.",
                "Account != Person.",
                "Anomaly != Threat.",
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
        app = TraceAtlasCOUNTERINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")