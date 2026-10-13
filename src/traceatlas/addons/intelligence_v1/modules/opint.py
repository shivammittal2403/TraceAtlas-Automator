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


APP_TITLE = "TraceAtlas OPINT AI Employee — Authorized / Evidence-First / Defensive / Decision-Support Operational Intelligence Panel"
APP_VERSION = "TraceAtlas OPINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("operation_name", "Operation Name / Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "OPINT Questions", "text"),

    ("operations", "Operations (IDs/Names)", "text"),
    ("tasks", "Tasks (IDs/Descriptions)", "text"),
    ("resources", "Resources (Personnel/System/Asset)", "text"),
    ("dependencies", "Dependencies", "text"),
    ("incidents", "Incidents / Alerts", "text"),
    ("systems", "Systems / Services Status", "text"),
    ("facilities", "Facilities / Locations", "text"),
    
    ("op_plan_paths", "Operation Plan / Task Tracker Paths", "text"),
    ("status_report_paths", "Status Report / SITREP Paths", "text"),
    ("telemetry_paths", "Telemetry / Log Export Paths", "text"),
    ("incident_paths", "Incident Ticket / Alert Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("as_of_date", "As-Of Date for Current Status Check", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (SIEM/ITSM/Monitoring/etc.)", "text"),
]


TARGET_TYPES = [
    "situational_awareness_check",
    "task_completion_verification",
    "resource_readiness_assessment",
    "dependency_bottleneck_analysis",
    "incident_impact_correlation",
    "sla_performance_review",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "operations",
    "tasks",
    "resources",
    "dependencies",
    "incidents",
    "systems",
    "facilities",
    "op_plan_paths",
    "status_report_paths",
    "telemetry_paths",
    "incident_paths",
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
    "situational_awareness_check",
    "resource_readiness_assessment",
    "incident_impact_correlation",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR OPERATIONAL HARM/AUTONOMY
POLICY_BLOCK_PATTERNS = [
    r"\b(?:autonomously|automatically)\b[^\n]{0,140}\b(?:command|order|dispatch|deploy|terminate|block|shutdown|restart)\b[^\n]{0,80}\b(?:personnel|system|service|asset|human)\b",
    r"\b(?:select|identify|rank|prioritize)\b[^\n]{0,140}\b(?:attack target|strike coordinate|kill chain|weapon employment|sabotage point)\b",
    r"\b(?:plan|design|optimize)\b[^\n]{0,140}\b(?:violent operation|raid|ambush|assassination|hostile infiltration|offensive cyber intrusion)\b",
    r"\b(?:disable|bypass|evade)\b[^\n]{0,140}\b(?:safety system|authentication|security control|emergency protocol)\b",
    r"\b(?:exploit|intrude|scan)\b[^\n]{0,140}\b(?:unauthorized network|private system|critical infrastructure)\b",
]


SAFE_ALTERNATIVES = [
    "Provide authorized/evidence-first/defensive operational intelligence: resolve operations/tasks/resources/incidents, verify task completion vs reporting, assess readiness/capacity/bottlenecks, correlate incident impacts, and generate safe next-action recommendations for human decision-makers.",
    "Do not autonomously command humans/systems, plan violence/targeting/sabotage, bypass safety controls, or conduct unauthorized intrusions.",
    "Separate Plan from Execution, Assignment from Start, Start from Completion, Reported Completion from Verified Success, Capability from Capacity, and Readiness from Performance.",
    "Use deterministic arithmetic for KPIs/SLAs/Utilization. Escalate consequential physical-safety/legal/financial actions to authorized human review.",
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
    r"change\s+(?:the\s+)?(?:objective|status|outcome)",
]


# Regex helpers for operational identifiers
OP_ID_RE = re.compile(r"\b(?:OP|Operation|Mission)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)
TASK_ID_RE = re.compile(r"\b(?:Task|Job|Ticket)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)
INCIDENT_ID_RE = re.compile(r"\b(?:Incident|Alert|Event)\s*(?:ID|No\.?)\s*:?\s*[A-Z0-9\-]+\b", re.I)


OPERATION_ROLE_KEYS = [
    "operation",
    "mission",
    "campaign",
    "project",
]


TASK_ROLE_KEYS = [
    "task",
    "job",
    "ticket",
    "work_item",
    "activity",
]


RESOURCE_ROLE_KEYS = [
    "resource",
    "personnel",
    "team",
    "system",
    "server",
    "asset",
    "vehicle",
    "facility",
    "vendor",
]


STATUS_MAP = {
    "planned": "PLANNED",
    "queued": "QUEUED",
    "ready": "READY",
    "running": "RUNNING",
    "paused": "PAUSED",
    "blocked": "BLOCKED",
    "partially_completed": "PARTIALLY_COMPLETED",
    "completed_reported": "COMPLETED_REPORTED",
    "completed_verified": "COMPLETED_VERIFIED",
    "failed": "FAILED",
    "cancelled": "CANCELLED",
    "skipped": "SKIPPED",
    "available": "AVAILABLE",
    "assigned": "ASSIGNED",
    "in_use": "IN_USE",
    "degraded": "DEGRADED",
    "unavailable": "UNAVAILABLE",
    "maintenance": "MAINTENANCE",
    "reserved": "RESERVED",
    "exhausted": "EXHAUSTED",
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


def map_status(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return STATUS_MAP.get(norm, raw.upper() if raw else "UNKNOWN")


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "operations": [],
        "objectives": [],
        "tasks": [],
        "resources": [],
        "dependencies": [],
        "incidents": [],
        "systems": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "metrics": {},
        "bottlenecks": [],
        "critical_path_candidates": [],
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
            "Observation records what was reported/logged, not necessarily its verified operational truth.",
            "Self-reported status requires independent verification.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in op docs are ignored.")


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
            "Multiple dashboards derived from same sensor are not independent sources.",
        ],
    })


def add_operation(
    parsed: Dict[str, Any],
    op_id: Any,
    name: Any,
    obj_desc: Any,
    start_time: Any,
    end_time: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    oid = safe_str(op_id, 200)
    nm = safe_str(name, 200)
    
    if not oid and not nm:
        return None
        
    rec_id = f"OP-{uuid.uuid4()}"
    parsed["operations"].append({
        "operation_record_id": rec_id,
        "external_op_id": oid,
        "name": nm,
        "objective_description": safe_str(obj_desc, 500),
        "start_time": safe_str(start_time, 100),
        "end_time": safe_str(end_time, 100),
        "status": map_status(status),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "OPERATION_PARSED",
        "limitations": [
            "Operation status must be verified against task/resource telemetry.",
            "Plan versioning matters. Ensure current plan is used.",
        ],
    })
    return rec_id


def add_task(
    parsed: Dict[str, Any],
    task_id: Any,
    desc: Any,
    op_ref: Any,
    owner_role: Any,
    planned_start: Any,
    planned_end: Any,
    actual_start: Any,
    actual_end: Any,
    status: Any,
    blocking_reason: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    tid = safe_str(task_id, 200)
    if not tid:
        return
        
    rec_id = f"TSK-{uuid.uuid4()}"
    
    parsed["tasks"].append({
        "task_record_id": rec_id,
        "external_task_id": tid,
        "description": safe_str(desc, 500),
        "operation_ref": op_ref,
        "owner_role": safe_str(owner_role, 100),
        "planned_start": safe_str(planned_start, 100),
        "planned_end": safe_str(planned_end, 100),
        "actual_start": safe_str(actual_start, 100),
        "actual_end": safe_str(actual_end, 100),
        "status": map_status(status),
        "blocking_reason": safe_str(blocking_reason, 300),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "TASK_PARSED",
        "limitations": [
            "Assigned != Started. Started != Completed. Completed_Reported != Verified.",
            "Verify completion via deliverable/outcome evidence.",
        ],
    })


def add_resource(
    parsed: Dict[str, Any],
    res_id: Any,
    name: Any,
    res_type: Any,
    state: Any,
    availability: Any, # YES/NO/PARTIAL
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    rid = safe_str(res_id, 200)
    nm = safe_str(name, 200)
    
    if not rid and not nm:
        return
        
    rec_id = f"RSRC-{uuid.uuid4()}"
    
    avail_norm = normalize_text(availability).upper()
    canonical_avail = "UNKNOWN"
    if "YES" in avail_norm or "TRUE" in avail_norm or "AVAILABLE" in avail_norm:
        canonical_avail = "AVAILABLE"
    elif "NO" in avail_norm or "FALSE" in avail_norm or "UNAVAILABLE" in avail_norm:
        canonical_avail = "UNAVAILABLE"
        
    parsed["resources"].append({
        "resource_record_id": rec_id,
        "external_res_id": rid,
        "name": nm,
        "resource_type": safe_str(res_type, 100).upper() or "UNKNOWN",
        "state": map_status(state),
        "availability_flag": canonical_avail,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "RESOURCE_PARSED",
        "limitations": [
            "Assignment does not equal Availability. Availability does not equal Effectiveness.",
            "Check maintenance/degradation states.",
        ],
    })


def add_dependency(
    parsed: Dict[str, Any],
    dep_type: Any, # DEPENDS_ON/BLOCKED_BY
    subject_ref: Any,
    object_ref: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    did = f"DEP-{uuid.uuid4()}"
    
    parsed["dependencies"].append({
        "dependency_id": did,
        "dependency_type": safe_str(dep_type, 50).upper() or "DEPENDS_ON",
        "subject_ref": subject_ref,
        "object_ref": object_ref,
        "status": safe_str(status, 100).upper() or "ACTIVE",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "DEPENDENCY_PARSED",
        "limitations": [
            "Dependency edge exists in graph. Verify if it is currently causing blockage.",
        ],
    })


def add_incident(
    parsed: Dict[str, Any],
    inc_id: Any,
    desc: Any,
    affected_resources: Any,
    severity: Any,
    timestamp: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    iid = safe_str(inc_id, 200)
    if not iid:
        return
        
    rec_id = f"INC-{uuid.uuid4()}"
    
    sev_norm = normalize_text(severity).upper()
    canonical_sev = "UNKNOWN"
    if "CRITICAL" in sev_norm:
        canonical_sev = "CRITICAL"
    elif "HIGH" in sev_norm:
        canonical_sev = "HIGH"
    elif "MEDIUM" in sev_norm or "MODERATE" in sev_norm:
        canonical_sev = "MEDIUM"
    elif "LOW" in sev_norm:
        canonical_sev = "LOW"
        
    parsed["incidents"].append({
        "incident_record_id": rec_id,
        "external_incident_id": iid,
        "description": safe_str(desc, 500),
        "affected_resource_refs": listify(affected_resources)[:50],
        "severity": canonical_sev,
        "timestamp": safe_str(timestamp, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "INCIDENT_PARSED",
        "limitations": [
            "Incident correlation != Root Cause. Use INCIDENTINT for RCA.",
            "Severity assessment depends on impact analysis.",
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

    # Resolve Operations
    op_items = get_field(rec, OPERATION_ROLE_KEYS, as_list=True)
    primary_op_ref = None
    for item in op_items:
        if isinstance(item, dict):
            oref = add_operation(
                parsed,
                item.get("id") or item.get("operation_id"),
                item.get("name"),
                item.get("objective") or item.get("goal"),
                item.get("start_time"),
                item.get("end_time"),
                item.get("status"),
                source_id,
                evidence_id,
                f"{rec_ctx}/operation"
            )
            if oref and not primary_op_ref:
                primary_op_ref = oref

    # Resolve Tasks
    task_items = get_field(rec, TASK_ROLE_KEYS, as_list=True)
    for item in task_items:
        if isinstance(item, dict):
            add_task(
                parsed,
                item.get("id") or item.get("task_id"),
                item.get("description") or item.get("summary"),
                item.get("operation_ref") or primary_op_ref,
                item.get("owner") or item.get("assignee"),
                item.get("planned_start"),
                item.get("planned_end"),
                item.get("actual_start"),
                item.get("actual_end"),
                item.get("status"),
                item.get("blocking_reason") or item.get("error"),
                source_id,
                evidence_id,
                f"{rec_ctx}/task"
            )

    # Resolve Resources
    res_items = get_field(rec, RESOURCE_ROLE_KEYS, as_list=True)
    for item in res_items:
        if isinstance(item, dict):
            add_resource(
                parsed,
                item.get("id") or item.get("resource_id"),
                item.get("name"),
                item.get("type"),
                item.get("state") or item.get("status"),
                item.get("available") or item.get("is_available"),
                source_id,
                evidence_id,
                f"{rec_ctx}/resource"
            )

    # Resolve Incidents
    inc_items = get_field(rec, ["incident", "alert", "event"], as_list=True)
    for item in inc_items:
        if isinstance(item, dict):
            add_incident(
                parsed,
                item.get("id") or item.get("incident_id"),
                item.get("description") or item.get("summary"),
                item.get("affected_resources") or item.get("impacted_assets"),
                item.get("severity") or item.get("priority"),
                item.get("timestamp") or item.get("detected_at"),
                source_id,
                evidence_id,
                f"{rec_ctx}/incident"
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
                 caution="Op docs are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["completed", "done", "finished"]):
        signals.append("COMPLETION_CLAIM")
    if any(k in low for k in ["failed", "error", "timeout", "exception"]):
        signals.append("FAILURE_SIGNAL")
    if any(k in low for k in ["blocked", "waiting", "pending approval"]):
        signals.append("BLOCKAGE_SIGNAL")
    if any(k in low for k in ["degraded", "slow", "latency", "outage"]):
        signals.append("PERFORMANCE_DEGRADATION")
    if any(k in low for k in ["incident", "alert", "breach", "attack"]):
        signals.append("SECURITY_INCIDENT_CONTEXT")

    if signals:
        add_note(parsed, "OP_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified operational state.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_OP_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "task" in fname or "ticket" in fname or "jira" in fname:
        return "TASK_TRACKER_EXPORT"
    if "incident" in fname or "alert" in fname or "siem" in fname:
        return "INCIDENT_ALERT_LOG"
    if "status" in fname or "sitrep" in fname or "report" in fname:
        return "SITUATION_REPORT"
    if "plan" in fname or "project" in fname:
        return "OPERATION_PLAN"

    return "GENERIC_OP_EVIDENCE"


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
    kind = "CSV_OP_DATA"

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
    if "sitrep" in low or "status report" in low:
        kind = "TEXT_SITREP"
    elif "incident" in low or "alert" in low:
        kind = "TEXT_INCIDENT_LOG"
    elif "plan" in low or "schedule" in low:
        kind = "TEXT_OPERATION_PLAN"
    else:
        kind = "TEXT_GENERIC_OP_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".sitrep", ".ops"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_op_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No autonomous commanding, no violence planning, no targeting, no sabotage.",
            "Binary artifacts are hash/metadata preserved only.",
            "Operational documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Plan != Execution. Assigned != Available.",
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
            file_evidence["content_kind"] = "BINARY_OP_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary operational document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access restricted systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_op_count"] = len(parsed.get("operations", []))
    file_evidence["parsed_task_count"] = len(parsed.get("tasks", []))
    file_evidence["parsed_res_count"] = len(parsed.get("resources", []))
    file_evidence["parsed_inc_count"] = len(parsed.get("incidents", []))

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


def calculate_metrics(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic calculation of basic operational metrics.
    """
    tasks = parsed.get("tasks", [])
    resources = parsed.get("resources", [])
    
    total_tasks = len(tasks)
    completed_verified = sum(1 for t in tasks if t.get("status") == "COMPLETED_VERIFIED")
    completed_reported = sum(1 for t in tasks if t.get("status") == "COMPLETED_REPORTED")
    blocked = sum(1 for t in tasks if t.get("status") == "BLOCKED")
    running = sum(1 for t in tasks if t.get("status") == "RUNNING")
    
    total_resources = len(resources)
    available_res = sum(1 for r in resources if r.get("availability_flag") == "AVAILABLE")
    
    completion_rate = 0.0
    if total_tasks > 0:
        completion_rate = round((completed_verified / total_tasks) * 100, 2)
        
    availability_rate = 0.0
    if total_resources > 0:
        availability_rate = round((available_res / total_resources) * 100, 2)
        
    return {
        "total_tasks": total_tasks,
        "completed_verified_count": completed_verified,
        "completed_reported_count": completed_reported,
        "blocked_count": blocked,
        "running_count": running,
        "completion_rate_percent": completion_rate,
        "total_resources": total_resources,
        "available_resource_count": available_res,
        "resource_availability_percent": availability_rate,
        "limitations": [
            "Rates based on parsed dataset completeness.",
            "Completed_Reported != Verified. Check discrepancy.",
        ]
    }


def identify_bottlenecks(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Identifies tasks blocked by unavailable resources or dependencies.
    """
    bottlenecks = []
    
    # Map Resource IDs to States
    res_map = {r["resource_record_id"]: r for r in parsed.get("resources", [])}
    
    for task in parsed.get("tasks", []):
        if task.get("status") == "BLOCKED":
            # In a real system, we'd traverse the dependency graph here.
            # For this demo, we flag any blocked task as a potential bottleneck candidate.
            bottlenecks.append({
                "bottleneck_id": f"BN-{uuid.uuid4()}",
                "subject_task_ref": task.get("task_record_id"),
                "reason_code": "TASK_STATUS_BLOCKED",
                "details": f"Task {task.get('external_task_id')} is marked BLOCKED. Reason: {task.get('blocking_reason', 'Unknown')}",
                "impact_scope": "LOCAL_TASK_DELAY",
                "limitations": [
                    "Root cause requires dependency tracing.",
                    "Do not interpret bottleneck as attack target.",
                ]
            })
            
    return bottlenecks


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for Task Status conflicts (e.g., COMPLETED but also RUNNING in different records)
    task_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in parsed.get("tasks", []):
        ext_id = t.get("external_task_id")
        if ext_id:
            task_map[ext_id].append(t)
            
    for ext_id, group in task_map.items():
        statuses = {g.get("status") for g in group}
        if len(statuses) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "TASK_STATUS_CONFLICT",
                "subject": ext_id,
                "values": list(statuses),
                "possible_explanations": [
                    "Different time snapshots",
                    "Stale tracker data",
                    "Parallel execution paths",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify latest telemetry/status update.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    tasks = parsed.get("tasks", [])
    incidents = parsed.get("incidents", [])
    
    if not tasks:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No operational tasks identified in local dataset.",
            "supporting_facts": ["Empty task list."],
            "opposing_facts": [],
            "unknowns": ["operation scope", "current state"],
            "next_test": "Import valid task tracker/SITREP exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    blocked_tasks = [t for t in tasks if t.get("status") == "BLOCKED"]
    if blocked_tasks:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": f"{len(blocked_tasks)} task(s) are blocked. Primary hypothesis: Dependency failure or Resource Unavailability.",
            "supporting_facts": ["Task status = BLOCKED."],
            "opposing_facts": ["Could be administrative hold or scope change."],
            "unknowns": ["specific blocker root cause"],
            "falsification_conditions": ["Resource check shows all AVAILABLE and Dependencies MET."],
            "next_test": "Inspect linked resources and upstream dependencies for these tasks.",
            "status": "ANALYTICAL",
        })
        
    if incidents:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Active incidents may be contributing to task delays or failures.",
            "supporting_facts": [f"{len(incidents)} incident(s) logged."],
            "opposing_facts": ["Incidents may be resolved or unrelated."],
            "unknowns": ["correlation strength"],
            "falsification_conditions": ["Timeline analysis shows no overlap between incident and delay."],
            "next_test": "Correlate incident timestamps with task state transitions.",
            "status": "MONITORING",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    tasks = parsed.get("tasks", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized operational evidence exists?",
            "missing_evidence": "No local OPINT artifact supplied.",
            "likely_source": "Jira/ServiceNow Export, SIEM Alert, Monitoring Dashboard Snapshot.",
            "specialist_owner": "OPINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline situational awareness.",
            "safety_boundary": "No autonomous action, no targeting.",
        })

    if tasks and not any(t.get("status") == "COMPLETED_VERIFIED" for t in tasks):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are any tasks truly verified as complete?",
            "missing_evidence": "Only self-reported or intermediate statuses found.",
            "likely_source": "Deliverable inspection, Test results, Downstream confirmation.",
            "specialist_owner": "OPINT / QA",
            "priority": "HIGH",
            "expected_information_value": "Prevents false sense of progress.",
            "safety_boundary": "Do not assume success without evidence.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    incidents = parsed.get("incidents", [])
    tasks = parsed.get("tasks", [])
    
    if incidents:
        handoffs.append({
            "specialist": "INCIDENTINT / MALINT",
            "reason": "Security/Technical incidents detected.",
            "expected_output": "Root cause analysis, threat actor identification (if applicable).",
            "question": "What is the technical root cause of these incidents?",
        })
        
    if any(t.get("status") == "BLOCKED" for t in tasks):
        handoffs.append({
            "specialist": "PROJECT_MANAGER / OPS_LEAD",
            "reason": "Tasks are blocked.",
            "expected_output": "Unblocking decision, resource reallocation, or scope adjustment.",
            "question": "Authorize next step to resolve blockers.",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "OPINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Is current situational awareness sufficient?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["metrics"] = calculate_metrics(parsed)
    parsed["bottlenecks"] = identify_bottlenecks(parsed)
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
    tasks = parsed.get("tasks", [])
    bottlenecks = parsed.get("bottlenecks", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited autonomous commanding, violence planning, or targeting behavior.",
            "reason": "OPINT is defensive decision support, not an autonomous operator.",
            "owner": "OPINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized task tracker/incident/status exports before analysis.",
            "reason": "No OPINT evidence artifact available.",
            "owner": "OPINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if bottlenecks:
        return {
            "action": "Investigate specific blockers for blocked tasks. Verify resource availability and dependency health.",
            "reason": "Tasks are stalled. Human intervention or resource adjustment may be needed.",
            "owner": "OPS LEAD / PROJECT MANAGER",
            "expected_output": "Unblocking plan or revised schedule.",
        }

    return {
        "action": "Continue monitoring. Verify 'Completed_Reported' tasks against deliverables to confirm 'Completed_Verified'.",
        "reason": "Basic flow is active, but verification gap exists.",
        "owner": "OPINT Analyst / QA",
        "expected_output": "Verified outcome register.",
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
    has_tasks = bool(parsed.get("tasks"))
    has_incidents = bool(parsed.get("incidents"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General OPINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Authorized / evidence-first / defensive / non-autonomous operational intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_operational_questions_scope",
        "OPINT Manager",
        "Convert objective into operational questions, allowed sources, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_operational_records",
        "local evidence store",
        "Store original plans/tasks/incidents and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "OpEvidenceObject with SHA256.",
    )

    add(
        "parse_task_resource_incident_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT operational metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized tasks/resources/incidents.",
    )

    add(
        "verify_task_completion_states",
        "local analyzer",
        "Distinguish Reported Completion from Verified Success using deliverable checks.",
        "PLANNED_ANALYTIC",
        "Verified Outcome Register.",
        safety_risk="HIGH_IF_FALSE_COMPLETION_ACCEPTED",
    )

    add(
        "map_dependencies_and_bottlenecks",
        "OPINT Analyst",
        "Identify blocked tasks and their upstream causes (resources/services).",
        "COMPLETED_LOCAL" if has_tasks else "PLANNED_ANALYTIC",
        "Bottleneck Analysis Report.",
        safety_risk="HIGH_IF_BOTTLENECK_USED_FOR_ATTACK",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "operation_name",
        "questions",
        "operations",
        "tasks",
        "resources",
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
            "Sensitive operational context detected. Analysis must remain authorized, evidence-first, and defensive. "
            "No autonomous commanding, no violence planning."
        )

    if payload.get("incidents") or "incident" in scanned:
        human_review_required = True
        safety_notes.append(
            "Incident context detected. Correlate impact carefully. Do not infer malice without evidence."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal autonomous commanding, violence planning, or targeting."
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
                "No obvious hard policy violation detected, but sensitive operational/incident context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/lawful operational evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "operation_name", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No OPINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "op_plan_paths",
        "status_report_paths",
        "telemetry_paths",
        "incident_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No operational evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Operational status is highly temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No SIEM/ITSM/Monitoring connector configured. External correlation remains planning-only.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which operations and tasks are currently active?",
        "What is the verified status of critical tasks (vs self-reported)?",
        "Which resources are actually available vs assigned?",
        "Are there any blocked tasks, and what are the specific dependencies?",
        "How do recent incidents impact ongoing operations?",
        "What are the current bottlenecks in the workflow?",
        "Is the operation meeting its SLA/KPI targets?",
        "What remains unknown regarding current execution state?",
        "What is the safest next action for human operators?",
        "Are there any common-mode failure risks in redundant systems?",
    ]


class TraceAtlasOPINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#fb923c", font=("Segoe UI", 17, "bold")) # Orange accent for Ops/Urgency
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
        ttk.Label(header, text="TraceAtlas OPINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Authorized / evidence-first / defensive / decision-support operational intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT task/resource/incident parsing only • "
                "No autonomous commanding / No violence planning / No targeting / No sabotage • "
                "Plan != Exec • Assigned != Avail • Reported != Verified"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="OPINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Op Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Operation Plans / Trackers", command=self.add_plans).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Status Reports / SITREPs", command=self.add_sitreps).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Telemetry / Logs", command=self.add_telemetry).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Incidents / Alerts", command=self.add_incidents).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local OPINT Evidence", command=self.analyze_local_op).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Op Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#fed7aa", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "OP-CASE-001")
        self.set_widget_value("task_id", "OP-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive operational intelligence using evidence-first methods.")
        self.set_widget_value("operation_name", "Illustrative Example Operation Alpha")
        self.set_widget_value("target_type", "situational_awareness_check")
        self.set_widget_value("questions", "\n".join(default_questions({"operation_name": "Illustrative Example Operation Alpha"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["internal_tracker", "monitoring_api"], "prohibited_actions": ["auto_command", "plan_attack"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_ops_review"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_AUTHORIZED_DEFENSIVE_DECISION_SUPPORT"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_plans(self): self._append_paths("op_plan_paths", filedialog.askopenfilenames(title="Select Plans/Trackers", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_sitreps(self): self._append_paths("status_report_paths", filedialog.askopenfilenames(title="Select SITREPs", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_telemetry(self): self._append_paths("telemetry_paths", filedialog.askopenfilenames(title="Select Telemetry/Logs", filetypes=[("Logs", "*.json *.csv *.txt *.log"), ("All", "*.*")]), "Added")
    def add_incidents(self): self._append_paths("incident_paths", filedialog.askopenfilenames(title="Select Incidents", filetypes=[("Docs", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_op(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["op_plan_paths", "status_report_paths", "telemetry_paths", "incident_paths", "stix_misp_paths"]
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
            f, parsed = analyze_op_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nTasks: {len(aggregated['tasks'])}\nIncidents: {len(aggregated['incidents'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("tasks") and not self.parsed.get("incidents"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "operations_preview": self.parsed.get("operations", [])[:100],
            "tasks_preview": self.parsed.get("tasks", [])[:100],
            "resources_preview": self.parsed.get("resources", [])[:100],
            "incidents_preview": self.parsed.get("incidents", [])[:100],
            "metrics": self.parsed.get("metrics", {}),
            "bottlenecks": self.parsed.get("bottlenecks", []),
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
            "mode": "LOCAL_DETERMINISTIC_OPINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "operations": parsed.get("operations", [])[:300],
            "tasks": parsed.get("tasks", [])[:300],
            "resources": parsed.get("resources", [])[:300],
            "incidents": parsed.get("incidents", [])[:300],
            "metrics": parsed.get("metrics", {}),
            "bottlenecks": parsed.get("bottlenecks", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No autonomous commanding, no violence planning.",
                "Reported Completion != Verified Success.",
                "Assignment != Availability.",
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
        app = TraceAtlasOPINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")