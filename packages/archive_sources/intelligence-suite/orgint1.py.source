import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
import re
import csv
import hashlib
import uuid

from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


APP_TITLE = "TraceAtlas ORGINT AI Employee — Lawful / Authorized / Privacy-Aware Organizational Intelligence Panel"
APP_VERSION = "TraceAtlas ORGINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Organization / Institution Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "ORGINT Questions", "text"),

    ("organization_names", "Organization Names / Aliases", "text"),
    ("organization_ids", "Organization IDs / Legal Entity References", "text"),
    ("organization_type", "Organization Type(s)", "text"),
    ("departments", "Departments", "text"),
    ("divisions", "Divisions", "text"),
    ("teams", "Teams", "text"),
    ("roles", "Roles / Positions", "text"),
    ("people", "Public / Authorized Role Holders", "text"),
    ("programs", "Programs", "text"),
    ("projects", "Projects", "text"),
    ("committees", "Committees", "text"),
    ("boards", "Boards", "text"),
    ("locations", "Locations / Offices / Sites", "text"),

    ("org_charts", "Inline Org Chart Notes", "text"),
    ("directories", "Inline Staff Directory Notes", "text"),
    ("policies", "Inline Policy / Charter Notes", "text"),
    ("annual_reports", "Inline Annual Report Notes", "text"),
    ("strategy_documents", "Inline Strategy Document Notes", "text"),
    ("job_descriptions", "Inline Job Description Notes", "text"),
    ("process_documents", "Inline Process Document Notes", "text"),
    ("project_records", "Inline Project Record Notes", "text"),
    ("authorized_internal_metadata", "Authorized Internal Metadata Notes", "text"),

    ("org_chart_paths", "Org Chart Export Paths", "text"),
    ("directory_paths", "Staff Directory Export Paths", "text"),
    ("policy_paths", "Policy / Charter Export Paths", "text"),
    ("annual_report_paths", "Annual Report Export Paths", "text"),
    ("job_description_paths", "Job Description Export Paths", "text"),
    ("project_record_paths", "Project Record Export Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (HR/Directory/PM/Docs/etc.)", "text"),
]


TARGET_TYPES = [
    "organization_structure",
    "governance_analysis",
    "role_reporting",
    "program_capability",
    "restructuring_change",
    "external_partners_vendors",
    "workforce_staffing",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "organization_names",
    "organization_ids",
    "organization_type",
    "departments",
    "divisions",
    "teams",
    "roles",
    "people",
    "programs",
    "projects",
    "committees",
    "boards",
    "locations",
    "org_charts",
    "directories",
    "policies",
    "annual_reports",
    "strategy_documents",
    "job_descriptions",
    "process_documents",
    "project_records",
    "authorized_internal_metadata",
    "org_chart_paths",
    "directory_paths",
    "policy_paths",
    "annual_report_paths",
    "job_description_paths",
    "project_record_paths",
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
    "organization_structure",
    "governance_analysis",
    "role_reporting",
    "program_capability",
    "restructuring_change",
    "external_partners_vendors",
    "workforce_staffing",
}


POLICY_BLOCK_PATTERNS = [
    r"\b(?:infiltrate|penetrate|embed\s+inside|covertly\s+join)\b[^\n]{0,140}\b(?:organization|company|agency|team|staff|department)\b",
    r"\b(?:impersonate|pretend\s+to\s+be|fake\s+identity)\b[^\n]{0,140}\b(?:employee|staff|manager|executive|colleague|hr)\b",
    r"\b(?:phish|social\s+engineer|manipulate|trick)\b[^\n]{0,140}\b(?:employee|staff|worker|hr|manager)\b",
    r"\b(?:recruit|turn|handle)\b[^\n]{0,140}\b(?:insider|employee|staff)\b\s+(?:covertly|secretly|clandestinely)",
    r"\b(?:blackmail|coerce|threaten|extort)\b[^\n]{0,140}\b(?:employee|staff|manager|executive)\b",
    r"\b(?:access|enter|login)\b[^\n]{0,140}\b(?:private\s+hr|hr\s+system|personnel\s+file|employee\s+record)\b\s+(?:without\s+authorization|illegally|stealthily)",
    r"\b(?:dox|expose|publish)\b[^\n]{0,140}\b(?:home\s+address|private\s+phone|personal\s+email|family|medical|religion|political\s+belief)\b",
    r"\b(?:sabotage|disrupt|attack|damage)\b[^\n]{0,140}\b(?:organization|workflow|approval|supply\s+chain|team|capability)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/authorized/evidence-first organizational intelligence: organization resolution, mandate/mission analysis, governance, formal vs functional structure, units, roles, role holders, reporting lines, decision rights, programs, capabilities, dependencies, partners/vendors/contractors, restructuring/change, and privacy-aware reporting.",
    "Do not infiltrate organizations, impersonate employees, phish/social engineer staff, covertly recruit insiders, blackmail employees, access private HR systems without authorization, dox employees, publish private home addresses, infer sensitive personal traits, or provide sabotage/disruption guidance.",
    "Separate role from person, formal from functional structure, responsibility from authority, vendor/contractor/partner from internal membership, and org chart from current operational reality.",
    "Use role-first analysis and minimize private-person data. Escalate consequential employment/legal/safety matters to authorized human review.",
]


SECRET_PATTERNS = [
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S | re.I,
        ),
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
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "JWT_LIKE_TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"send\s+(?:employee|staff|directory)\s+list",
    r"change\s+investigation",
    r"execute\s+(?:script|code)",
    r"access\s+private\s+hr",
]


DOMAIN_RE = re.compile(r"\b(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


UNIT_KEYS = [
    "units",
    "divisions",
    "departments",
    "directorates",
    "sections",
    "teams",
    "offices",
    "branches",
    "regions",
    "program_offices",
    "project_offices",
    "labs",
    "centers",
    "centres",
    "working_groups",
    "task_forces",
]


UNIT_TYPE_SET = {
    "unit",
    "division",
    "department",
    "directorate",
    "section",
    "team",
    "office",
    "branch",
    "region",
    "program office",
    "project office",
    "lab",
    "laboratory",
    "center",
    "centre",
    "working group",
    "task force",
    "taskforce",
}


PROGRAM_TYPES = {"program", "programme"}
PROJECT_TYPES = {"project"}
COMMITTEE_TYPES = {"committee"}
BOARD_TYPES = {"board"}
LOCATION_TYPES = {"location", "headquarters", "hq", "site", "campus", "facility", "office_location"}
CAPABILITY_TYPES = {"capability", "capacity", "competency"}
DEPENDENCY_TYPES = {"dependency", "depends_on", "vendor", "contractor", "partner"}
CHANGE_TYPES = {
    "change",
    "restructuring",
    "renamed",
    "merged",
    "split",
    "disbanded",
    "appointed",
    "resigned",
    "interim",
    "acting",
}


ROLE_KEYS = ["roles", "positions", "jobs", "titles", "postings"]
PERSON_KEYS = ["people", "staff", "employees", "role_holders", "personnel", "members", "incumbents"]
REPORT_KEYS = ["reports_to", "reporting_to", "manager", "supervisor", "reports_under", "dotted_line_to"]
PROGRAM_KEYS = ["programs", "programmes"]
PROJECT_KEYS = ["projects"]
COMMITTEE_KEYS = ["committees"]
BOARD_KEYS = ["boards"]
LOCATION_KEYS = ["locations", "headquarters", "hq", "sites", "campuses", "facilities", "operating_locations"]
CAPABILITY_KEYS = ["capabilities", "capacity", "competencies"]
DEPENDENCY_KEYS = ["dependencies", "depends_on", "vendor_relationships", "contractor_relationships", "partner_relationships"]
CHANGE_KEYS = ["changes", "restructuring_events", "organizational_changes", "leadership_changes", "role_changes"]


ORG_TEXT_KEYS = {"organization", "org", "institution", "agency", "company", "entity"}
TOP_UNIT_TEXT_KEYS = {"division", "department", "directorate", "business_unit", "region"}
SUB_UNIT_TEXT_KEYS = {
    "team", "section", "office", "branch", "unit", "working_group", "task_force",
    "lab", "center", "centre", "program_office", "project_office",
}
UNIT_TEXT_KEYS = TOP_UNIT_TEXT_KEYS | SUB_UNIT_TEXT_KEYS
ROLE_TEXT_KEYS = {"role", "position", "title", "job_title", "post"}
PERSON_TEXT_KEYS = {"person", "employee", "staff", "holder", "incumbent", "occupied_by"}
REPORT_TEXT_KEYS = {"reports_to", "reporting_to", "manager", "supervisor", "reports_under", "dotted_line_to"}
PROGRAM_TEXT_KEYS = {"program", "programme"}
PROJECT_TEXT_KEYS = {"project"}
COMMITTEE_TEXT_KEYS = {"committee"}
BOARD_TEXT_KEYS = {"board"}
LOCATION_TEXT_KEYS = {"location", "headquarters", "hq", "site", "campus", "facility", "office_location"}
CAPABILITY_TEXT_KEYS = {"capability", "capacity", "competency"}
DEPENDENCY_TEXT_KEYS = {"depends_on", "dependency", "vendor", "contractor", "partner"}
CHANGE_TEXT_KEYS = {
    "change", "restructuring", "renamed", "merged", "split", "disbanded",
    "appointed", "resigned", "interim", "acting",
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


def extract_domains(text: str) -> List[str]:
    out = []
    for m in DOMAIN_RE.finditer(text or ""):
        d = m.group(1).lower()
        if d not in out:
            out.append(d)
    return out


def extract_emails(text: str) -> List[str]:
    out = []
    for m in EMAIL_RE.finditer(text or ""):
        e = m.group(0).lower()
        if e not in out:
            out.append(e)
    return out


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


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "organizations": [],
        "units": [],
        "roles": [],
        "role_holders": [],
        "reporting_relationships": [],
        "programs": [],
        "projects": [],
        "committees": [],
        "boards": [],
        "locations": [],
        "capabilities": [],
        "dependencies": [],
        "changes": [],
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
            "Organizational source statement is evidence about structure/role/relationship, not verified operational reality.",
            "Job title does not automatically establish authority.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in organizational documents are ignored.")


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
            "Copied org charts/directories/press releases are not independent sources.",
        ],
    })


def add_organization(
    parsed: Dict[str, Any],
    name: Any,
    organization_id: Any,
    organization_type: Any,
    jurisdiction: Any,
    mandate: Any,
    mission: Any,
    status: Any,
    headquarters: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    oid = safe_str(organization_id, 100)
    if not n and not oid:
        return None

    norm = normalize_text(n or oid)

    for org in parsed["organizations"]:
        if org.get("normalized_name") == norm or (oid and org.get("external_organization_id") == oid):
            if n and not org.get("name"):
                org["name"] = n
            if oid and not org.get("external_organization_id"):
                org["external_organization_id"] = oid
            if organization_type and not org.get("organization_type"):
                org["organization_type"] = safe_str(organization_type, 100)
            if jurisdiction and not org.get("jurisdiction"):
                org["jurisdiction"] = safe_str(jurisdiction, 100)
            if mandate and not org.get("mandate"):
                org["mandate"] = safe_str(mandate, 500)
            if mission and not org.get("mission"):
                org["mission"] = safe_str(mission, 500)
            if status and not org.get("status"):
                org["status"] = safe_str(status, 100)
            if headquarters and not org.get("headquarters_candidate"):
                org["headquarters_candidate"] = safe_str(headquarters, 300)
            if n and n not in org.get("aliases", []):
                org["aliases"].append(n)
            return org.get("organization_id")

    org_id = f"ORG-{uuid.uuid4()}"
    parsed["organizations"].append({
        "organization_id": org_id,
        "name": n or oid,
        "normalized_name": norm,
        "aliases": unique_preserve_order([n, oid])[:50],
        "external_organization_id": oid,
        "organization_type": safe_str(organization_type, 100) or "UNKNOWN",
        "jurisdiction": safe_str(jurisdiction, 100),
        "mandate": safe_str(mandate, 500),
        "mission": safe_str(mission, 500),
        "status": safe_str(status, 100) or "UNKNOWN",
        "headquarters_candidate": safe_str(headquarters, 300),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ORGANIZATION_CANDIDATE",
        "limitations": [
            "Organization is not necessarily a legal entity.",
            "Same name does not prove same organization.",
            "Mandate/mission statements are source claims, not demonstrated capability.",
        ],
    })
    return org_id


def add_unit(
    parsed: Dict[str, Any],
    organization_ref: Any,
    name: Any,
    unit_type: Any,
    parent_unit_ref: Any,
    mandate: Any,
    functions: Any,
    leader_role_ref: Any,
    locations: Any,
    valid_from: Any,
    valid_to: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    norm = normalize_text(n)
    org_ref = safe_str(organization_ref, 200)
    parent_ref = safe_str(parent_unit_ref, 200)

    for unit in parsed["units"]:
        if unit.get("normalized_name") == norm and unit.get("organization_ref") == org_ref:
            if parent_ref and not unit.get("parent_unit_ref"):
                unit["parent_unit_ref"] = parent_ref
            if unit_type and not unit.get("unit_type"):
                unit["unit_type"] = safe_str(unit_type, 100)
            if mandate and not unit.get("mandate"):
                unit["mandate"] = safe_str(mandate, 500)
            if leader_role_ref and not unit.get("leader_role_ref"):
                unit["leader_role_ref"] = safe_str(leader_role_ref, 200)
            return unit.get("unit_id")

    unit_id = f"UNIT-{uuid.uuid4()}"
    parsed["units"].append({
        "unit_id": unit_id,
        "organization_ref": org_ref,
        "name": n,
        "normalized_name": norm,
        "unit_type": safe_str(unit_type, 100) or "UNKNOWN",
        "parent_unit_ref": parent_ref,
        "mandate": safe_str(mandate, 500),
        "functions": unique_preserve_order(listify(functions))[:100],
        "leader_role_ref": safe_str(leader_role_ref, 200),
        "locations": unique_preserve_order(listify(locations))[:100],
        "valid_from": safe_str(valid_from, 100),
        "valid_to": safe_str(valid_to, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "UNIT_CANDIDATE",
        "limitations": [
            "Unit existence is source-reported until corroborated.",
            "Department name does not prove function ownership or authority.",
        ],
    })
    return unit_id


def add_role(
    parsed: Dict[str, Any],
    organization_ref: Any,
    unit_ref: Any,
    title: Any,
    role_type: Any,
    responsibilities: Any,
    authority_scope: Any,
    decision_rights: Any,
    reports_to_titles: Any,
    manages_titles: Any,
    valid_from: Any,
    valid_to: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    t = safe_str(title, 200)
    if not t:
        return None

    norm = normalize_text(t)
    org_ref = safe_str(organization_ref, 200)
    u_ref = safe_str(unit_ref, 200)

    for role in parsed["roles"]:
        if role.get("normalized_title") == norm and role.get("unit_ref") == u_ref and role.get("organization_ref") == org_ref:
            if role_type and not role.get("role_type"):
                role["role_type"] = safe_str(role_type, 100)
            if responsibilities and not role.get("responsibilities"):
                role["responsibilities"] = unique_preserve_order(listify(responsibilities))[:100]
            if authority_scope and not role.get("authority_scope"):
                role["authority_scope"] = safe_str(authority_scope, 300)
            if decision_rights and not role.get("decision_rights"):
                role["decision_rights"] = unique_preserve_order(listify(decision_rights))[:100]
            return role.get("role_id")

    role_id = f"ROLE-{uuid.uuid4()}"
    parsed["roles"].append({
        "role_id": role_id,
        "organization_ref": org_ref,
        "unit_ref": u_ref,
        "title": t,
        "normalized_title": norm,
        "role_type": safe_str(role_type, 100) or "UNKNOWN",
        "responsibilities": unique_preserve_order(listify(responsibilities))[:100],
        "authority_scope": safe_str(authority_scope, 300),
        "decision_rights": unique_preserve_order(listify(decision_rights))[:100],
        "reports_to_titles": unique_preserve_order(listify(reports_to_titles))[:100],
        "manages_titles": unique_preserve_order(listify(manages_titles))[:100],
        "valid_from": safe_str(valid_from, 100),
        "valid_to": safe_str(valid_to, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ROLE_CANDIDATE",
        "limitations": [
            "Role is not person.",
            "Job title does not automatically establish authority.",
            "Director title may not mean legal corporate director.",
        ],
    })
    return role_id


def add_role_holder(
    parsed: Dict[str, Any],
    role_ref: Any,
    person_name: Any,
    appointment_date: Any,
    end_date: Any,
    employment_status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    r_ref = safe_str(role_ref, 200)
    p_name = safe_str(person_name, 200)
    if not r_ref or not p_name:
        return None

    holder_id = f"HOLDER-{uuid.uuid4()}"
    parsed["role_holders"].append({
        "role_holder_id": holder_id,
        "role_ref": r_ref,
        "person_display": p_name,
        "person_normalized": normalize_text(p_name),
        "appointment_date": safe_str(appointment_date, 100),
        "end_date": safe_str(end_date, 100),
        "employment_status": safe_str(employment_status, 100) or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ROLE_HOLDER_SOURCE_REPORTED",
        "limitations": [
            "Role holder resolution requires authorized/public evidence.",
            "Social profile title is not authoritative employment record by default.",
            "Avoid unnecessary private-person profiling.",
        ],
    })
    return holder_id


def add_reporting_relationship(
    parsed: Dict[str, Any],
    from_role_ref: Any,
    to_role_ref: Any,
    relationship_type: Any,
    valid_from: Any,
    valid_to: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    f_ref = safe_str(from_role_ref, 200)
    t_ref = safe_str(to_role_ref, 200)
    if not f_ref or not t_ref:
        return None

    rel_type = safe_str(relationship_type, 100) or "SOURCE_REPORTED_REPORTS_TO"

    for rel in parsed["reporting_relationships"]:
        if rel.get("from_role_ref") == f_ref and rel.get("to_role_ref") == t_ref and rel.get("relationship_type") == rel_type:
            return rel.get("relationship_id")

    rel_id = f"REP-{uuid.uuid4()}"
    parsed["reporting_relationships"].append({
        "relationship_id": rel_id,
        "from_role_ref": f_ref,
        "to_role_ref": t_ref,
        "relationship_type": rel_type,
        "valid_from": safe_str(valid_from, 100),
        "valid_to": safe_str(valid_to, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "REPORTING_RELATIONSHIP_SOURCE_REPORTED",
        "limitations": [
            "Reporting relationship does not automatically imply financial control, legal ownership, or complete decision authority.",
            "Formal and functional reporting must be kept separate.",
        ],
    })
    return rel_id


def add_program(
    parsed: Dict[str, Any],
    name: Any,
    organization_ref: Any,
    owner_unit_ref: Any,
    executive_sponsor_ref: Any,
    manager_role_ref: Any,
    objective: Any,
    scope: Any,
    start_date: Any,
    end_date: Any,
    projects: Any,
    partners: Any,
    funding_context: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    norm = normalize_text(n)
    org_ref = safe_str(organization_ref, 200)

    for prog in parsed["programs"]:
        if prog.get("normalized_name") == norm and prog.get("organization_ref") == org_ref:
            return prog.get("program_id")

    program_id = f"PRG-{uuid.uuid4()}"
    parsed["programs"].append({
        "program_id": program_id,
        "name": n,
        "normalized_name": norm,
        "organization_ref": org_ref,
        "owner_unit_ref": safe_str(owner_unit_ref, 200),
        "executive_sponsor_ref": safe_str(executive_sponsor_ref, 200),
        "manager_role_ref": safe_str(manager_role_ref, 200),
        "objective": safe_str(objective, 500),
        "scope": safe_str(scope, 500),
        "start_date": safe_str(start_date, 100),
        "end_date": safe_str(end_date, 100),
        "projects": unique_preserve_order(listify(projects))[:200],
        "partners": unique_preserve_order(listify(partners))[:200],
        "funding_context": safe_str(funding_context, 300),
        "status": safe_str(status, 100) or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PROGRAM_CANDIDATE",
        "limitations": [
            "Program may span multiple departments.",
            "Program ownership requires evidence.",
        ],
    })
    return program_id


def add_project(
    parsed: Dict[str, Any],
    name: Any,
    program_ref: Any,
    owner_unit_ref: Any,
    manager_role_ref: Any,
    team: Any,
    objectives: Any,
    dependencies: Any,
    timeline: Any,
    status: Any,
    partners: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    norm = normalize_text(n)
    proj_id = f"PRJ-{uuid.uuid4()}"
    parsed["projects"].append({
        "project_id": proj_id,
        "name": n,
        "normalized_name": norm,
        "program_ref": safe_str(program_ref, 200),
        "owner_unit_ref": safe_str(owner_unit_ref, 200),
        "manager_role_ref": safe_str(manager_role_ref, 200),
        "team": unique_preserve_order(listify(team))[:200],
        "objectives": safe_str(objectives, 500),
        "dependencies": unique_preserve_order(listify(dependencies))[:200],
        "timeline": safe_str(timeline, 300),
        "status": safe_str(status, 100) or "UNKNOWN",
        "partners": unique_preserve_order(listify(partners))[:200],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "PROJECT_CANDIDATE",
        "limitations": [
            "Project team is not necessarily permanent organizational structure.",
        ],
    })
    return proj_id


def add_committee(
    parsed: Dict[str, Any],
    name: Any,
    organization_ref: Any,
    mandate: Any,
    members: Any,
    chair_ref: Any,
    reporting_body_ref: Any,
    meeting_period: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    norm = normalize_text(n)
    com_id = f"COM-{uuid.uuid4()}"
    parsed["committees"].append({
        "committee_id": com_id,
        "name": n,
        "normalized_name": norm,
        "organization_ref": safe_str(organization_ref, 200),
        "mandate": safe_str(mandate, 500),
        "members": unique_preserve_order(listify(members))[:200],
        "chair_ref": safe_str(chair_ref, 200),
        "reporting_body_ref": safe_str(reporting_body_ref, 200),
        "meeting_period": safe_str(meeting_period, 100),
        "status": safe_str(status, 100) or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "COMMITTEE_CANDIDATE",
        "limitations": [
            "Committee may cut across departments.",
            "Committee membership is not employment by default.",
        ],
    })
    return com_id


def add_board(
    parsed: Dict[str, Any],
    name: Any,
    organization_ref: Any,
    members: Any,
    oversight_responsibilities: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    board_id = f"BRD-{uuid.uuid4()}"
    parsed["boards"].append({
        "board_id": board_id,
        "name": n,
        "normalized_name": normalize_text(n),
        "organization_ref": safe_str(organization_ref, 200),
        "members": unique_preserve_order(listify(members))[:200],
        "oversight_responsibilities": unique_preserve_order(listify(oversight_responsibilities))[:100],
        "status": safe_str(status, 100) or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "BOARD_CANDIDATE",
        "limitations": [
            "Board membership does not imply day-to-day management.",
        ],
    })
    return board_id


def add_location(
    parsed: Dict[str, Any],
    name: Any,
    organization_ref: Any,
    unit_ref: Any,
    location_type: Any,
    address_summary: Any,
    valid_from: Any,
    valid_to: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    loc_id = f"LOC-{uuid.uuid4()}"
    parsed["locations"].append({
        "location_id": loc_id,
        "name": n,
        "normalized_name": normalize_text(n),
        "organization_ref": safe_str(organization_ref, 200),
        "unit_ref": safe_str(unit_ref, 200),
        "location_type": safe_str(location_type, 100) or "UNKNOWN",
        "address_summary": safe_str(address_summary, 300),
        "valid_from": safe_str(valid_from, 100),
        "valid_to": safe_str(valid_to, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "LOCATION_CANDIDATE",
        "limitations": [
            "Avoid private residences.",
            "Headquarters is not necessarily registered office.",
        ],
    })
    return loc_id


def add_capability(
    parsed: Dict[str, Any],
    name: Any,
    organization_ref: Any,
    provided_by_unit_ref: Any,
    depends_on: Any,
    evidence_type: Any,
    capability_state: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    cap_id = f"CAP-{uuid.uuid4()}"
    parsed["capabilities"].append({
        "capability_id": cap_id,
        "name": n,
        "normalized_name": normalize_text(n),
        "organization_ref": safe_str(organization_ref, 200),
        "provided_by_unit_ref": safe_str(provided_by_unit_ref, 200),
        "depends_on": unique_preserve_order(listify(depends_on))[:100],
        "evidence_type": safe_str(evidence_type, 100) or "UNKNOWN",
        "capability_state": safe_str(capability_state, 100) or "CLAIMED",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "CAPABILITY_CANDIDATE",
        "limitations": [
            "Claimed capability is not demonstrated capability.",
            "Mission statement does not prove operational ability.",
        ],
    })
    return cap_id


def add_dependency(
    parsed: Dict[str, Any],
    from_entity_ref: Any,
    to_entity_ref: Any,
    dependency_type: Any,
    description: Any,
    valid_from: Any,
    valid_to: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    f_ref = safe_str(from_entity_ref, 200)
    t_ref = safe_str(to_entity_ref, 200)
    if not f_ref or not t_ref:
        return None

    dep_id = f"DEP-{uuid.uuid4()}"
    parsed["dependencies"].append({
        "dependency_id": dep_id,
        "from_entity_ref": f_ref,
        "to_entity_ref": t_ref,
        "dependency_type": safe_str(dependency_type, 100) or "UNKNOWN",
        "description": safe_str(description, 500),
        "valid_from": safe_str(valid_from, 100),
        "valid_to": safe_str(valid_to, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "DEPENDENCY_CANDIDATE",
        "limitations": [
            "Dependency does not equal control.",
            "Use for resilience/governance only; no sabotage guidance.",
        ],
    })
    return dep_id


def add_change(
    parsed: Dict[str, Any],
    change_type: Any,
    entity_ref: Any,
    old_state: Any,
    new_state: Any,
    effective_at: Any,
    announced_at: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    c_type = safe_str(change_type, 100)
    e_ref = safe_str(entity_ref, 200)
    if not c_type and not e_ref:
        return None

    ch_id = f"CHG-{uuid.uuid4()}"
    parsed["changes"].append({
        "change_id": ch_id,
        "change_type": c_type or "UNKNOWN",
        "entity_ref": e_ref,
        "old_state": safe_str(old_state, 300),
        "new_state": safe_str(new_state, 300),
        "effective_at": safe_str(effective_at, 100),
        "announced_at": safe_str(announced_at, 100),
        "status": safe_str(status, 100) or "UNKNOWN",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "CHANGE_CANDIDATE",
        "limitations": [
            "Announcement does not prove implemented structure.",
            "Historical change must not overwrite current state without evidence.",
        ],
    })
    return ch_id


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
    parent_org_ref: str = "",
    parent_unit_ref: str = "",
) -> Tuple[str, str]:
    if not isinstance(rec, dict):
        return parent_org_ref, parent_unit_ref

    rec_ctx = context or "json_record"

    org_name = get_field(rec, [
        "organization", "organization_name", "org_name", "institution",
        "agency", "company_name", "entity_name",
    ])
    org_ext_id = get_field(rec, ["organization_id", "org_id", "legal_entity_id"])
    org_type = get_field(rec, ["organization_type", "institution_type", "org_type"])
    org_jurisdiction = get_field(rec, ["jurisdiction", "country", "region"])
    org_mandate = get_field(rec, ["mandate", "charter", "statute"])
    org_mission = get_field(rec, ["mission", "mission_statement"])
    org_status = get_field(rec, ["status", "organization_status"])
    org_hq = get_field(rec, ["headquarters", "hq", "registered_office"])

    current_org_ref = parent_org_ref
    if org_name or org_ext_id:
        current_org_ref = add_organization(
            parsed,
            org_name,
            org_ext_id,
            org_type,
            org_jurisdiction,
            org_mandate,
            org_mission,
            org_status,
            org_hq,
            source_id,
            evidence_id,
            rec_ctx,
        ) or current_org_ref

    current_unit_ref = parent_unit_ref

    explicit_unit_name = get_field(rec, ["unit_name"])
    node_name = get_field(rec, ["name", "label"])
    node_type = get_field(rec, ["unit_type", "type"])
    nt = normalize_text(node_type)

    if explicit_unit_name or (node_name and current_org_ref and nt in UNIT_TYPE_SET):
        current_unit_ref = add_unit(
            parsed,
            current_org_ref or parent_org_ref,
            explicit_unit_name or node_name,
            node_type,
            get_field(rec, ["parent", "parent_unit"]) or parent_unit_ref,
            get_field(rec, ["mandate", "purpose"]),
            get_field(rec, ["functions", "responsibilities"], as_list=True),
            get_field(rec, ["leader_role", "head_role"]),
            get_field(rec, ["locations"], as_list=True),
            get_field(rec, ["valid_from", "effective_from"]),
            get_field(rec, ["valid_to", "effective_to"]),
            source_id,
            evidence_id,
            rec_ctx,
        ) or current_unit_ref

    role_title = get_field(rec, ["role", "position", "job_title", "post"])
    if not role_title and nt not in UNIT_TYPE_SET | PROGRAM_TYPES | PROJECT_TYPES | COMMITTEE_TYPES | BOARD_TYPES:
        role_title = get_field(rec, ["title"])

    role_indicators = any(get_field(rec, [k]) for k in [
        "holder", "person", "employee", "manager", "reports_to", "supervisor",
        "responsibilities", "decision_rights", "authority_scope",
    ])

    if role_title and (role_indicators or nt not in UNIT_TYPE_SET | PROGRAM_TYPES | PROJECT_TYPES | COMMITTEE_TYPES | BOARD_TYPES):
        role_ref = add_role(
            parsed,
            current_org_ref or parent_org_ref,
            get_field(rec, ["unit", "unit_ref", "department"]) or current_unit_ref or parent_unit_ref,
            role_title,
            get_field(rec, ["role_type", "type"]),
            get_field(rec, ["responsibilities"], as_list=True),
            get_field(rec, ["authority_scope", "authority"]),
            get_field(rec, ["decision_rights"], as_list=True),
            get_field(rec, ["reports_to", "manager"], as_list=True),
            get_field(rec, ["manages", "direct_reports"], as_list=True),
            get_field(rec, ["valid_from", "appointed"]),
            get_field(rec, ["valid_to", "ended"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

        holder = get_field(rec, ["holder", "person", "employee"])
        if role_ref and holder:
            add_role_holder(
                parsed,
                role_ref,
                holder,
                get_field(rec, ["appointed", "valid_from"]),
                get_field(rec, ["ended", "valid_to"]),
                get_field(rec, ["employment_status", "status"]),
                source_id,
                evidence_id,
                f"{rec_ctx}/holder",
            )

        manager = get_field(rec, ["manager", "reports_to", "supervisor", "dotted_line_to"])
        if role_ref and manager:
            add_reporting_relationship(
                parsed,
                role_ref,
                manager,
                get_field(rec, ["relationship_type"]) or "SOURCE_REPORTED_REPORTS_TO",
                get_field(rec, ["valid_from", "appointed"]),
                get_field(rec, ["valid_to", "ended"]),
                source_id,
                evidence_id,
                f"{rec_ctx}/reporting",
            )

    program_name = get_field(rec, ["program_name", "programme_name"])
    if not program_name and nt in PROGRAM_TYPES:
        program_name = node_name
    if program_name:
        add_program(
            parsed,
            program_name,
            current_org_ref or parent_org_ref,
            get_field(rec, ["owner_unit", "unit"]) or current_unit_ref or parent_unit_ref,
            get_field(rec, ["executive_sponsor", "sponsor"]),
            get_field(rec, ["manager_role", "manager"]),
            get_field(rec, ["objective"]),
            get_field(rec, ["scope"]),
            get_field(rec, ["start_date"]),
            get_field(rec, ["end_date"]),
            get_field(rec, ["projects"], as_list=True),
            get_field(rec, ["partners"], as_list=True),
            get_field(rec, ["funding_context"]),
            get_field(rec, ["status"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    project_name = get_field(rec, ["project_name"])
    if not project_name and nt in PROJECT_TYPES:
        project_name = node_name
    if project_name:
        add_project(
            parsed,
            project_name,
            get_field(rec, ["program", "program_ref"]),
            get_field(rec, ["owner_unit", "unit"]) or current_unit_ref or parent_unit_ref,
            get_field(rec, ["manager_role", "manager"]),
            get_field(rec, ["team"], as_list=True),
            get_field(rec, ["objectives"]),
            get_field(rec, ["dependencies"], as_list=True),
            get_field(rec, ["timeline"]),
            get_field(rec, ["status"]),
            get_field(rec, ["partners"], as_list=True),
            source_id,
            evidence_id,
            rec_ctx,
        )

    committee_name = get_field(rec, ["committee_name"])
    if not committee_name and nt in COMMITTEE_TYPES:
        committee_name = node_name
    if committee_name:
        add_committee(
            parsed,
            committee_name,
            current_org_ref or parent_org_ref,
            get_field(rec, ["mandate"]),
            get_field(rec, ["members"], as_list=True),
            get_field(rec, ["chair"]),
            get_field(rec, ["reports_to", "reporting_body"]),
            get_field(rec, ["meeting_period"]),
            get_field(rec, ["status"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    board_name = get_field(rec, ["board_name"])
    if not board_name and nt in BOARD_TYPES:
        board_name = node_name
    if board_name:
        add_board(
            parsed,
            board_name,
            current_org_ref or parent_org_ref,
            get_field(rec, ["members"], as_list=True),
            get_field(rec, ["oversight_responsibilities", "responsibilities"], as_list=True),
            get_field(rec, ["status"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    location_name = get_field(rec, ["location_name"])
    if not location_name and nt in LOCATION_TYPES:
        location_name = node_name
    if location_name:
        add_location(
            parsed,
            location_name,
            current_org_ref or parent_org_ref,
            get_field(rec, ["unit"]) or current_unit_ref or parent_unit_ref,
            node_type or get_field(rec, ["location_type"]),
            get_field(rec, ["address_summary", "address"]),
            get_field(rec, ["valid_from"]),
            get_field(rec, ["valid_to"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    capability_name = get_field(rec, ["capability_name"])
    if not capability_name and nt in CAPABILITY_TYPES:
        capability_name = node_name
    if capability_name:
        add_capability(
            parsed,
            capability_name,
            current_org_ref or parent_org_ref,
            get_field(rec, ["provided_by_unit", "unit"]) or current_unit_ref or parent_unit_ref,
            get_field(rec, ["depends_on"], as_list=True),
            get_field(rec, ["evidence_type"]),
            get_field(rec, ["state", "capability_state"]) or "CLAIMED",
            source_id,
            evidence_id,
            rec_ctx,
        )

    dependency_from = get_field(rec, ["from", "from_entity"])
    dependency_to = get_field(rec, ["to", "to_entity", "depends_on"])
    if not dependency_from and nt in DEPENDENCY_TYPES:
        dependency_from = current_unit_ref or parent_unit_ref
    if dependency_from and dependency_to:
        add_dependency(
            parsed,
            dependency_from,
            dependency_to,
            node_type or get_field(rec, ["dependency_type"]),
            get_field(rec, ["description"]),
            get_field(rec, ["valid_from"]),
            get_field(rec, ["valid_to"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    change_type = get_field(rec, ["change_type"])
    if not change_type and nt in CHANGE_TYPES:
        change_type = node_type
    if change_type:
        add_change(
            parsed,
            change_type,
            get_field(rec, ["entity", "entity_ref"]) or current_unit_ref or parent_unit_ref,
            get_field(rec, ["old_state"]),
            get_field(rec, ["new_state"]),
            get_field(rec, ["effective_at", "effective_date"]),
            get_field(rec, ["announced_at", "announced_date"]),
            get_field(rec, ["status"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    return current_org_ref, current_unit_ref


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
                 caution="Embedded instructions in organizational documents are ignored.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["org chart", "organization chart", "reports to", "reporting to", "department", "division", "team"]):
        signals.append("ORG_STRUCTURAL_LANGUAGE")
    if any(k in low for k in ["acting", "interim", "vacant", "appointed", "resigned"]):
        signals.append("ROLE_TEMPORAL_UNCERTAINTY")
    if any(k in low for k in ["vendor", "contractor", "partner", "consultant", "secondment"]):
        signals.append("EXTERNAL_RELATIONSHIP_CANDIDATE")
    if any(k in low for k in ["depends on", "dependency", "approval dependency", "single point"]):
        signals.append("DEPENDENCY_SIGNAL")
    if any(k in low for k in ["restructure", "restructuring", "merger", "split", "renamed", "disbanded"]):
        signals.append("ORG_CHANGE_SIGNAL")
    if any(k in low for k in ["capability", "capacity", "certification", "laboratory", "facility", "platform"]):
        signals.append("CAPABILITY_LANGUAGE")

    if signals:
        add_note(parsed, "ORGANIZATIONAL_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified structure or authority.")

    domains = extract_domains(redacted)
    emails = extract_emails(redacted)
    if domains:
        add_note(parsed, "DOMAIN_MENTION", domains=domains[:20], source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Domain mention is not verified organizational affiliation.")
    if emails:
        add_note(parsed, "EMAIL_MENTION", email_count=len(emails), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Email mention is not verified employment proof and is not stored raw in notes.")


def process_structured_text_line(
    line: str,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    state: Dict[str, str],
) -> None:
    redacted = safe_str(line, 500)
    if not redacted or ":" not in redacted:
        return

    key_raw, val_raw = redacted.split(":", 1)
    key = normalize_key(key_raw)
    val = val_raw.strip()
    if not key or not val:
        return

    if key in ORG_TEXT_KEYS:
        state["org"] = add_organization(
            parsed, val, "", "", "", "", "", "", "", source_id, evidence_id, f"text:{key}"
        ) or state.get("org", "")
        state["unit"] = ""
        state["role"] = ""
        return

    if key in UNIT_TEXT_KEYS:
        parent = state.get("unit", "") if key in SUB_UNIT_TEXT_KEYS else state.get("org", "")
        state["unit"] = add_unit(
            parsed,
            state.get("org", ""),
            val,
            key,
            parent,
            "",
            [],
            "",
            [],
            "",
            "",
            source_id,
            evidence_id,
            f"text:{key}",
        ) or state.get("unit", "")
        state["role"] = ""
        return

    if key in ROLE_TEXT_KEYS:
        state["role"] = add_role(
            parsed,
            state.get("org", ""),
            state.get("unit", ""),
            val,
            "UNKNOWN",
            [],
            "",
            [],
            [],
            [],
            "",
            "",
            source_id,
            evidence_id,
            f"text:{key}",
        ) or state.get("role", "")
        return

    if key in PERSON_TEXT_KEYS:
        if state.get("role"):
            add_role_holder(
                parsed,
                state["role"],
                val,
                "",
                "",
                "UNKNOWN",
                source_id,
                evidence_id,
                f"text:{key}",
            )
        return

    if key in REPORT_TEXT_KEYS:
        if state.get("role"):
            add_reporting_relationship(
                parsed,
                state["role"],
                val,
                "SOURCE_REPORTED_REPORTS_TO",
                "",
                "",
                source_id,
                evidence_id,
                f"text:{key}",
            )
        return

    if key in PROGRAM_TEXT_KEYS:
        add_program(
            parsed,
            val,
            state.get("org", ""),
            state.get("unit", ""),
            "",
            state.get("role", ""),
            "",
            "",
            "",
            "",
            [],
            [],
            "",
            "UNKNOWN",
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return

    if key in PROJECT_TEXT_KEYS:
        add_project(
            parsed,
            val,
            "",
            state.get("unit", ""),
            state.get("role", ""),
            [],
            "",
            [],
            "",
            "UNKNOWN",
            [],
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return

    if key in COMMITTEE_TEXT_KEYS:
        add_committee(
            parsed,
            val,
            state.get("org", ""),
            "",
            [],
            "",
            "",
            "",
            "UNKNOWN",
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return

    if key in BOARD_TEXT_KEYS:
        add_board(
            parsed,
            val,
            state.get("org", ""),
            [],
            [],
            "UNKNOWN",
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return

    if key in LOCATION_TEXT_KEYS:
        add_location(
            parsed,
            val,
            state.get("org", ""),
            state.get("unit", ""),
            key,
            "",
            "",
            "",
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return

    if key in CAPABILITY_TEXT_KEYS:
        add_capability(
            parsed,
            val,
            state.get("org", ""),
            state.get("unit", ""),
            [],
            "SOURCE_CLAIM",
            "CLAIMED",
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return

    if key in DEPENDENCY_TEXT_KEYS:
        add_dependency(
            parsed,
            state.get("unit", "") or state.get("role", ""),
            val,
            key,
            "",
            "",
            "",
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return

    if key in CHANGE_TEXT_KEYS:
        add_change(
            parsed,
            key,
            state.get("unit", "") or state.get("role", ""),
            "",
            val,
            "",
            "",
            "UNKNOWN",
            source_id,
            evidence_id,
            f"text:{key}",
        )
        return


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:20000].lower()
    fname = normalize_text(filename)

    if "org_chart" in fname or "organization_chart" in low or ("units" in keys and "roles" in keys):
        return "ORG_CHART_RECORD"
    if "directory" in fname or "staff" in fname or "employees" in keys:
        return "STAFF_DIRECTORY_RECORD"
    if "policy" in fname or "charter" in fname or "bylaw" in low:
        return "POLICY_OR_CHARTER_RECORD"
    if "annual_report" in fname or "annual report" in low:
        return "ANNUAL_REPORT_RECORD"
    if "job_description" in fname or "job_posting" in low:
        return "JOB_DESCRIPTION_RECORD"
    if "project" in fname or "program" in fname:
        return "PROGRAM_PROJECT_RECORD"
    if "organization" in keys or "institution" in keys:
        return "ORGANIZATIONAL_RECORD"

    return "GENERIC_ORGANIZATIONAL_DATA"


def walk_json(
    data: Any,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    depth: int = 0,
    path: str = "",
    parent_org_ref: str = "",
    parent_unit_ref: str = "",
) -> None:
    if depth > 14 or len(parsed.get("observations", [])) > 200000:
        return

    if isinstance(data, dict):
        org_ref, unit_ref = process_json_record(
            data,
            source_id,
            evidence_id,
            parsed,
            context=path or "json",
            parent_org_ref=parent_org_ref,
            parent_unit_ref=parent_unit_ref,
        )

        for k, v in data.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_json(v, source_id, evidence_id, parsed, depth + 1, new_path, org_ref, unit_ref)

    elif isinstance(data, list):
        for item in data[:100000]:
            walk_json(item, source_id, evidence_id, parsed, depth + 1, path, parent_org_ref, parent_unit_ref)

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
    kind = "CSV_ORGANIZATIONAL_DATA"

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

    low = redacted_raw.lower()[:20000]
    if "org chart" in low or "organization chart" in low:
        kind = "TEXT_ORG_CHART"
    elif "staff directory" in low or "employee list" in low:
        kind = "TEXT_STAFF_DIRECTORY"
    elif "policy" in low or "charter" in low:
        kind = "TEXT_POLICY"
    elif "job description" in low:
        kind = "TEXT_JOB_DESCRIPTION"
    else:
        kind = "TEXT_ORGANIZATIONAL_NOTE"

    add_source(
        parsed,
        source_id,
        evidence_id,
        filename=path.name,
        file_hash=sha256_file(path),
        source_type=kind,
        content_fp=fp,
    )

    state: Dict[str, str] = {}
    for line_no, line in enumerate(raw.splitlines()[:200000]):
        if line.strip():
            ctx = f"text_line_{line_no}"
            process_text_block(line, source_id, evidence_id, parsed, context=ctx)
            process_structured_text_line(line, source_id, evidence_id, parsed, state)

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".orgchart"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_orgint_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No covert infiltration, impersonation, phishing/social engineering, insider recruitment, blackmail, unauthorized private HR access, doxxing, private home address publication, sensitive trait inference, or sabotage guidance performed.",
            "Binary artifacts (PDF/XLSX/DOCX/media) are hash/metadata preserved only; no deep parsing/executed content analysis performed in this stdlib-only panel.",
            "Organizational documents are untrusted evidence, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Structure/role/relationship records are source-reported until corroborated.",
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
            file_evidence["content_kind"] = "BINARY_ORG_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary organizational document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX/XLSX deeply, or extract hidden layers."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_organization_count"] = len(parsed.get("organizations", []))
    file_evidence["parsed_unit_count"] = len(parsed.get("units", []))
    file_evidence["parsed_role_count"] = len(parsed.get("roles", []))
    file_evidence["parsed_reporting_count"] = len(parsed.get("reporting_relationships", []))

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


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []

    org_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for o in parsed.get("organizations", []):
        org_map[o.get("normalized_name")].append(o)

    for norm, group in org_map.items():
        if len(group) > 1:
            ext_ids = {g.get("external_organization_id") for g in group if g.get("external_organization_id")}
            juris = {g.get("jurisdiction") for g in group if g.get("jurisdiction")}
            if len(ext_ids) > 1 or len(juris) > 1:
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "ORGANIZATION_RESOLUTION_AMBIGUITY",
                    "subject": norm,
                    "values": {
                        "external_ids": list(ext_ids)[:10],
                        "jurisdictions": list(juris)[:10],
                    },
                    "possible_explanations": [
                        "Distinct organizations with similar names",
                        "Historical rename with inconsistent source metadata",
                        "Data-provider merge error",
                        "Alias/acronym collision",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Do not merge organizations solely by name.",
                })

    unit_map: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for u in parsed.get("units", []):
        unit_map[(u.get("organization_ref", ""), u.get("normalized_name", ""))].append(u)

    for key, group in unit_map.items():
        if len(group) > 1:
            parents = {g.get("parent_unit_ref") for g in group if g.get("parent_unit_ref")}
            if len(parents) > 1:
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "UNIT_PARENT_CONFLICT",
                    "subject": key,
                    "values": list(parents)[:10],
                    "possible_explanations": [
                        "Matrix reporting",
                        "Restructuring",
                        "Outdated org chart",
                        "Different organizational layers",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Preserve formal vs functional differences.",
                })

    holder_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for h in parsed.get("role_holders", []):
        holder_map[h.get("role_ref", "")].append(h)

    for role_ref, group in holder_map.items():
        if len(group) > 1 and all(not g.get("end_date") for g in group):
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "POSSIBLE_MULTIPLE_CURRENT_ROLE_HOLDERS",
                "subject": role_ref,
                "values": [g.get("person_display") for g in group][:10],
                "possible_explanations": [
                    "Acting/interim overlap",
                    "Co-leadership",
                    "Outdated directory",
                    "Name collision",
                    "Data duplication",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Do not infer one true holder without temporal evidence.",
            })

    rep_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in parsed.get("reporting_relationships", []):
        rep_map[r.get("from_role_ref", "")].append(r)

    for from_ref, group in rep_map.items():
        if len(group) > 1:
            tos = {g.get("to_role_ref") for g in group if g.get("to_role_ref")}
            types = {g.get("relationship_type") for g in group if g.get("relationship_type")}
            if len(tos) > 1 and all(not g.get("valid_to") for g in group):
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "REPORTING_LINE_CONFLICT",
                    "subject": from_ref,
                    "values": {
                        "to_roles": list(tos)[:10],
                        "relationship_types": list(types)[:10],
                    },
                    "possible_explanations": [
                        "Matrix reporting",
                        "Dotted-line relationship",
                        "Restructuring",
                        "Formal vs functional difference",
                        "Outdated source",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Do not collapse multiple reporting edges into one authority claim.",
                })

    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    orgs = parsed.get("organizations", [])
    units = parsed.get("units", [])
    roles = parsed.get("roles", [])
    reps = parsed.get("reporting_relationships", [])
    caps = parsed.get("capabilities", [])
    deps = parsed.get("dependencies", [])
    changes = parsed.get("changes", [])

    if not orgs and not units and not roles:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Current local deterministic evidence is insufficient to assess organizational structure, governance, roles, capabilities, or dependencies.",
            "supporting_facts": ["No organization/unit/role records parsed."],
            "opposing_facts": [],
            "assumptions": ["Evidence may be missing, unsupported, binary-only, or unavailable."],
            "unknowns": ["organization identity", "formal structure", "role holders", "reporting lines", "authority"],
            "falsification_conditions": ["New authorized/public organizational evidence changes assessment."],
            "next_test": "Attach org charts, staff directories, policies, annual reports, job descriptions, or project records.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if reps:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Observed reporting relationships may represent formal structure, but functional/operational reporting may differ.",
            "supporting_facts": [f"{len(reps)} reporting relationship record(s) parsed."],
            "opposing_facts": ["No independent workflow/authorized directory evidence processed yet."],
            "unknowns": ["matrix reporting", "interim roles", "outdated org chart", "formal vs functional difference"],
            "falsification_conditions": ["Latest authorized policy/workflow records confirm alternative functional reporting."],
            "next_test": "Compare latest official org chart with authorized workflow/project ownership records.",
            "status": "OPEN",
        })

    if changes:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Organizational change/restructuring may be announced, planned, in progress, or implemented; current state remains uncertain.",
            "supporting_facts": [f"{len(changes)} change record(s) parsed."],
            "opposing_facts": ["Some changes may be historical or cancelled."],
            "unknowns": ["effective date", "implementation status", "successor units", "current role holders"],
            "falsification_conditions": ["Official implementation notice or updated org chart confirms final structure."],
            "next_test": "Retrieve dated implementation records and compare pre/post structure.",
            "status": "OPEN",
        })

    if caps:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Claimed capabilities may not equal demonstrated capabilities.",
            "supporting_facts": [f"{len(caps)} capability record(s) parsed."],
            "opposing_facts": ["Some capabilities may be supported by facilities/staff/systems evidence."],
            "unknowns": ["operational evidence", "budget", "staffing", "systems", "certifications"],
            "falsification_conditions": "Independent operational outputs demonstrate capability.",
            "next_test": "Correlate capability claims with authorized operational evidence.",
            "status": "OPEN",
        })

    if deps:
        incoming = Counter(d.get("to_entity_ref") for d in deps if d.get("to_entity_ref"))
        if incoming and max(incoming.values()) >= 3:
            hyps.append({
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "One or more units/roles/functions may represent a single-point organizational dependency relevant to resilience/governance.",
                "supporting_facts": [f"{len(deps)} dependency record(s); highest incoming dependency count={max(incoming.values())}."],
                "opposing_facts": ["Dependency may be normal shared-service architecture."],
                "unknowns": ["redundancy", "alternate units", "cross-training", "approval delegation"],
                "falsification_conditions": ["Redundant teams/processes are evidenced."],
                "next_test": "Review governance/process documents for redundancy and delegation. Do not generate disruption guidance.",
                "status": "OPEN",
            })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    orgs = parsed.get("organizations", [])
    units = parsed.get("units", [])
    roles = parsed.get("roles", [])
    holders = parsed.get("role_holders", [])
    reps = parsed.get("reporting_relationships", [])
    caps = parsed.get("capabilities", [])
    changes = parsed.get("changes", [])

    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized organizational evidence exists?",
            "missing_evidence": "No local ORGINT artifact supplied.",
            "likely_source": "Official org chart, staff directory, policy/charter, annual report, job description, project record.",
            "specialist_owner": "ORGINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline organizational planning.",
            "safety_boundary": "No infiltration, impersonation, phishing, private HR access, doxxing, or sabotage guidance.",
        })

    if not orgs:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Which organization is being analyzed?",
            "missing_evidence": "No organization records parsed.",
            "likely_source": "Official website, charter, annual report, registry/legal entity reference.",
            "specialist_owner": "ORGINT / CORPINT",
            "priority": "HIGH",
            "expected_information_value": "Establishes organization identity and type.",
            "safety_boundary": "Do not invent organization identity.",
        })

    if orgs and not units:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the current formal organizational structure?",
            "missing_evidence": "Units/divisions/departments/teams missing.",
            "likely_source": "Latest official org chart, governance charter, annual report.",
            "specialist_owner": "ORGINT",
            "priority": "HIGH",
            "expected_information_value": "Establishes hierarchy and unit boundaries.",
            "safety_boundary": "Do not force hierarchy where matrix/flat/networked structure is evidenced.",
        })

    if units and not roles:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Which roles/positions exist within units?",
            "missing_evidence": "Role records missing.",
            "likely_source": "Job descriptions, authorized directory, org chart role boxes.",
            "specialist_owner": "ORGINT",
            "priority": "MEDIUM_HIGH",
            "expected_information_value": "Establishes role structure separate from persons.",
            "safety_boundary": "Role != person.",
        })

    if roles and not holders:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Who currently holds key roles, where lawful/authorized evidence exists?",
            "missing_evidence": "Role-holder records missing.",
            "likely_source": "Official staff directory, authorized HR metadata, public leadership page.",
            "specialist_owner": "ORGINT",
            "priority": "MEDIUM",
            "expected_information_value": "Supports role-holder resolution without private profiling.",
            "safety_boundary": "Use role-first analysis; avoid unnecessary private-person data.",
        })

    if roles and not reps:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What are the formal and functional reporting lines?",
            "missing_evidence": "Reporting relationships missing.",
            "likely_source": "Org chart connectors, policy, delegation matrix, authorized workflow metadata.",
            "specialist_owner": "ORGINT",
            "priority": "HIGH",
            "expected_information_value": "Establishes authority/coordination pathways.",
            "safety_boundary": "Reporting line != total control.",
        })

    if caps and all(c.get("capability_state") in {"CLAIMED", "SOURCE_REPORTED"} for c in caps):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are claimed capabilities demonstrated by operational evidence?",
            "missing_evidence": "No demonstrated capability evidence parsed.",
            "likely_source": "Completed programs, certifications, operational outputs, authorized system/staff evidence.",
            "specialist_owner": "ORGINT",
            "priority": "MEDIUM",
            "expected_information_value": "Distinguishes marketing/mission claims from ability.",
            "safety_boundary": "Mission statement != capability.",
        })

    if changes:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Which organizational changes are implemented versus announced?",
            "missing_evidence": "Implementation status uncertain.",
            "likely_source": "Dated implementation notice, updated org chart, policy effective date.",
            "specialist_owner": "ORGINT",
            "priority": "HIGH",
            "expected_information_value": "Prevents historical-to-current contamination.",
            "safety_boundary": "Announcement != implemented structure.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    orgs = parsed.get("organizations", [])
    deps = parsed.get("dependencies", [])
    caps = parsed.get("capabilities", [])
    changes = parsed.get("changes", [])

    if any(o.get("external_organization_id") for o in orgs):
        handoffs.append({
            "specialist": "CORPINT",
            "reason": "Legal entity/registration references detected.",
            "expected_output": "Legal entity resolution, registration status, directors/shareholders where public/authorized.",
            "question": "Is the organizational reference tied to a specific legal entity?",
        })

    if any(d.get("dependency_type") in {"vendor", "contractor", "partner", "VENDOR_DEPENDENCY", "PERSONNEL_DEPENDENCY"} for d in deps):
        handoffs.append({
            "specialist": "PROCUREMENTINT / FININT",
            "reason": "Vendor/contractor/partner dependency context detected.",
            "expected_output": "Contract/award/payment context, vendor organizational separation.",
            "question": "Are external dependencies contractual/vendor relationships rather than internal units?",
        })

    if caps:
        handoffs.append({
            "specialist": "ORGINT Manager",
            "reason": "Capability claims require evidence grading.",
            "expected_output": "Claimed vs demonstrated capability assessment.",
            "question": "What operational evidence supports or falsifies each capability claim?",
        })

    if changes:
        handoffs.append({
            "specialist": "ORGINT / HUMINT / DOCINT",
            "reason": "Restructuring/change events detected.",
            "expected_output": "Temporal change verification, policy/org-chart versioning.",
            "question": "Which changes are announced, planned, in progress, implemented, or cancelled?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "ORGINT Manager",
            "reason": "No immediate specialist trigger detected from current local deterministic evidence alone.",
            "expected_output": "Review scope, approve authorized connectors, assign structure collection tasks.",
            "question": "What organizational intelligence gap should be filled next?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    build_source_independence(parsed)
    parsed["contradictions"] = build_contradictions(parsed)
    parsed["hypotheses"] = build_hypotheses(parsed)
    parsed["knowledge_gaps"] = build_knowledge_gaps(payload or {}, files or [], parsed)
    parsed["specialist_handoffs"] = build_specialist_handoffs(parsed)
    return parsed


def build_next_best_action(
    payload: Dict[str, Any],
    policy: Dict[str, Any],
    files: List[Dict[str, Any]],
    parsed: Dict[str, Any],
) -> Dict[str, str]:
    orgs = parsed.get("organizations", [])
    units = parsed.get("units", [])
    roles = parsed.get("roles", [])
    reps = parsed.get("reporting_relationships", [])
    changes = parsed.get("changes", [])
    caps = parsed.get("capabilities", [])

    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited infiltration, impersonation, phishing/social engineering, private HR access, doxxing, or sabotage behavior.",
            "reason": "ORGINT is lawful/authorized organizational intelligence, not covert manipulation or private-person targeting.",
            "owner": "ORGINT Manager",
            "expected_output": "Policy-compliant defensive ORGINT scope and question set.",
        }

    if policy.get("status") == "HUMAN_REVIEW_REQUIRED":
        return {
            "action": "Route to human ORGINT/HR/legal reviewer before consequential employment, governance, disclosure, or operational decisions.",
            "reason": "Organizational structure/role/authority findings can be privacy-sensitive and consequential.",
            "owner": "ORGINT Manager",
            "expected_output": "Approved defensive verification plan, evidence gaps, and handoffs.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized/public org charts, staff directories, policies, annual reports, job descriptions, or project records before analysis.",
            "reason": "No ORGINT evidence artifact is available for local deterministic analysis.",
            "owner": "ORGINT AI Employee",
            "expected_output": "Organizational evidence inventory with hashes and provenance.",
        }

    if not orgs:
        return {
            "action": "Resolve organization identity and type from official charter, website, annual report, or legal entity reference.",
            "reason": "Organization resolution is prerequisite to structure analysis.",
            "owner": "ORGINT / CORPINT",
            "expected_output": "Canonical organization object.",
        }

    if orgs and not units:
        return {
            "action": "Retrieve latest official org chart or governance document to establish formal units.",
            "reason": "Structure cannot be assessed without unit evidence.",
            "owner": "ORGINT",
            "expected_output": "Formal unit hierarchy candidates with effective dates.",
        }

    if units and not reps:
        return {
            "action": "Resolve reporting relationships and distinguish formal from functional reporting where evidence exists.",
            "reason": "Reporting lines are central to governance and authority analysis.",
            "owner": "ORGINT",
            "expected_output": "Time-bounded reporting edges.",
        }

    if changes:
        return {
            "action": "Verify restructuring/change implementation status using dated official records before updating current structure.",
            "reason": "Announced changes may not be implemented.",
            "owner": "ORGINT / DOCINT",
            "expected_output": "Temporal change register.",
        }

    if caps:
        return {
            "action": "Grade capability claims against demonstrated operational evidence.",
            "reason": "Mission/marketing statements are not capability proof.",
            "owner": "ORGINT",
            "expected_output": "Capability confidence states.",
        }

    return {
        "action": "Proceed with role-holder resolution, decision-rights analysis, dependency mapping, and formal-vs-observed structure comparison.",
        "reason": "Local evidence exists, but authority/function/capability remain source-reported until corroborated.",
        "owner": "ORGINT / CORPINT / HUMINT as authorized",
        "expected_output": "Evidence-linked organizational intelligence report with limitations and next actions.",
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
    has_units = bool(parsed.get("units"))
    has_roles = bool(parsed.get("roles"))
    has_reps = bool(parsed.get("reporting_relationships"))
    has_caps = bool(parsed.get("capabilities"))
    has_changes = bool(parsed.get("changes"))

    def add(
        operation: str,
        tool: str,
        purpose: str,
        status: str,
        expected_output: str,
        safety_risk: str = "LOW",
        policy_note: str = "Lawful / authorized / privacy-aware / evidence-first organizational intelligence only.",
    ) -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General ORGINT collection planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": policy_note,
            "authorization_status": "ALLOWED_LAWFUL_AUTHORIZED_PUBLIC",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_orgint_questions_scope",
        "ORGINT Manager / ORGINT AI Employee",
        "Convert objective into organizational questions, allowed sources, privacy boundaries, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven defensive ORGINT collection plan.",
        policy_note="No infiltration, impersonation, phishing, private HR access, doxxing, or sabotage guidance.",
    )

    add(
        "preserve_original_org_evidence",
        "local evidence store",
        "Store original org charts, directories, policies, reports, job descriptions, and hashes without modifying originals.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "OrganizationalEvidenceObject with SHA256 and provenance fields.",
    )

    add(
        "safe_parse_json_csv_text_org_metadata",
        "local deterministic parser",
        "Parse lawful/authorized/public JSON/CSV/TXT organizational metadata without executing scripts, opening archives, or accessing private HR systems.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized organizations, units, roles, holders, reporting edges, programs, capabilities, and observations.",
        safety_risk="HIGH_IF_UNTRUSTED_CONTENT_TREATED_AS_INSTRUCTION",
        policy_note="Organizational documents are untrusted evidence.",
    )

    add(
        "organization_resolution",
        "local resolver",
        "Resolve organization name/alias/type/jurisdiction while avoiding false merges.",
        "COMPLETED_LOCAL" if has_orgs else "PLANNED_REQUIRES_ORGANIZATION_EVIDENCE",
        "Canonical organization candidates.",
        safety_risk="MEDIUM_IF_FALSE_MERGE",
        policy_note="Same name != same organization.",
    )

    add(
        "unit_hierarchy_resolution",
        "local graph builder",
        "Resolve divisions/departments/teams/offices and preserve flat/matrix/networked structures where evidenced.",
        "COMPLETED_LOCAL" if has_units else "PLANNED_REQUIRES_STRUCTURE_EVIDENCE",
        "Time-bounded unit graph.",
        safety_risk="MEDIUM_IF_FORCED_HIERARCHY",
        policy_note="Do not force hierarchy when structure is flat/matrixed/networked.",
    )

    add(
        "role_and_role_holder_separation",
        "local resolver",
        "Separate role objects from role-holder person candidates and preserve appointment timelines.",
        "COMPLETED_LOCAL" if has_roles else "PLANNED_REQUIRES_ROLE_EVIDENCE",
        "Role objects and role-holder candidates.",
        safety_risk="HIGH_PRIVACY_SENSITIVE",
        policy_note="Role != person. Minimize private-person data.",
    )

    add(
        "reporting_relationship_analysis",
        "local graph builder",
        "Resolve formal/functional/dotted-line/project reporting relationships with temporal validity.",
        "COMPLETED_LOCAL" if has_reps else "PLANNED_REQUIRES_REPORTING_EVIDENCE",
        "Reporting-edge graph with relationship types.",
        safety_risk="HIGH_IF_AUTHORITY_OVERCLAIMED",
        policy_note="Reporting line != total control.",
    )

    add(
        "capability_evidence_grading",
        "ORGINT Analyst",
        "Distinguish claimed, supported, demonstrated, partial, and historical capabilities.",
        "COMPLETED_LOCAL" if has_caps else "PLANNED_ANALYTIC",
        "Capability confidence states.",
        safety_risk="MEDIUM_IF_MARKETING_TAKEN_AS_PROOF",
        policy_note="Mission statement != demonstrated capability.",
    )

    add(
        "restructuring_temporal_validation",
        "ORGINT / DOCINT",
        "Compare announced/planned/in-progress/implemented/cancelled changes using effective dates.",
        "COMPLETED_LOCAL" if has_changes else "PLANNED_ANALYTIC",
        "Change register with validity periods.",
        safety_risk="HIGH_IF_HISTORICAL_TO_CURRENT_CONTAMINATION",
        policy_note="Announcement != implemented structure.",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_text = " ".join(
        [
            str(payload.get("objective", "")),
            " ".join(str(q) for q in payload.get("questions", [])),
            str(payload.get("target", "")),
            " ".join(str(s) for s in payload.get("organization_names", [])),
            " ".join(str(s) for s in payload.get("departments", [])),
            " ".join(str(s) for s in payload.get("roles", [])),
            " ".join(str(s) for s in payload.get("people", [])),
            " ".join(str(s) for s in payload.get("org_charts", [])),
            " ".join(str(s) for s in payload.get("directories", [])),
            " ".join(str(s) for s in payload.get("policies", [])),
            " ".join(str(s) for s in payload.get("authorized_internal_metadata", [])),
        ]
    ).lower()

    blocked_reasons = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned_text, re.IGNORECASE)]

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive organizational context detected. Analysis must remain lawful, authorized, privacy-aware, and evidence-first. "
            "No infiltration, impersonation, phishing/social engineering, private HR access, doxxing, or sabotage guidance."
        )

    if payload.get("people") or payload.get("directories") or payload.get("authorized_internal_metadata"):
        human_review_required = True
        safety_notes.append(
            "Person/role-holder/directory/internal metadata context detected. Apply strict privacy minimization, tenant isolation, purpose limitation, and role-first analysis."
        )

    if payload.get("org_chart_paths") or payload.get("directory_paths") or payload.get("policy_paths"):
        human_review_required = True
        safety_notes.append(
            "Org chart/directory/policy evidence context detected. Source documents may be outdated, simplified, or non-authoritative for operational reality."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require covert infiltration, employee impersonation, phishing/social engineering, "
                "covert insider recruitment, blackmail, unauthorized private HR access, doxxing, sensitive trait inference, or sabotage/disruption guidance."
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
                "No obvious hard policy violation detected, but sensitive organizational, role-holder, directory, policy, or internal metadata context applies. "
                "Conclusions must remain defensive, privacy-aware, evidence-linked, and human-reviewed before consequential employment/governance action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_LAWFUL_AUTHORIZED_PUBLIC",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": (
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful organizational documents or connectors are configured."
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
        warnings.append("No ORGINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "organization_names",
        "organization_ids",
        "departments",
        "divisions",
        "teams",
        "roles",
        "people",
        "programs",
        "projects",
        "committees",
        "boards",
        "locations",
        "org_charts",
        "directories",
        "policies",
        "annual_reports",
        "job_descriptions",
        "org_chart_paths",
        "directory_paths",
        "policy_paths",
        "annual_report_paths",
        "job_description_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No organizational evidence provided. Output remains planning-only.")

    if not payload.get("time_range"):
        warnings.append("No time range provided. Organizational structure, roles, and reporting lines are highly temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No HR/Directory/PM/Docs connector configured. External correlation remains planning-only.")

    if payload.get("people") or payload.get("directories") or payload.get("authorized_internal_metadata"):
        warnings.append(
            "Person/directory/internal metadata context triggers privacy controls. "
            "Use role-first analysis and avoid unnecessary private-person data."
        )

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which organization is being analyzed, and what type of organization is it?",
        "What is its mandate/mission, and what is formally versus observedly operated?",
        "What is the current formal organizational structure?",
        "Which divisions/departments/teams/offices/committees/boards exist?",
        "Which roles/positions exist, and who holds them where lawful/authorized evidence exists?",
        "What are the formal and functional reporting lines?",
        "Which roles have decision/approval authority, and what evidence supports that?",
        "Which programs/projects exist, and who owns/manages them?",
        "What capabilities are claimed versus demonstrated?",
        "Which external partners/vendors/contractors matter, and how are they separated from internal structure?",
        "What organizational changes/restructurings occurred, and are they implemented?",
        "Where do formal and observed structures differ?",
        "What remains unknown?",
    ]


class TraceAtlasORGINTPanel(tk.Tk):
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
        style.configure(
            "Header.TLabel",
            background="#0b0f19",
            foreground="#38bdf8",
            font=("Segoe UI", 17, "bold"),
        )
        style.configure(
            "Subheader.TLabel",
            background="#0b0f19",
            foreground="#94a3b8",
            font=("Segoe UI", 9),
        )
        style.configure("TNotebook", background="#0b0f19", borderwidth=0)
        style.configure("TNotebook.Tab", padding=[14, 7], font=("Segoe UI", 10, "bold"))

        style.configure(
            "TEntry",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            insertcolor="#ffffff",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TCombobox",
            fieldbackground="#111827",
            foreground="#e5e7eb",
            arrowcolor="#e5e7eb",
            bordercolor="#334155",
            lightcolor="#334155",
            darkcolor="#334155",
        )

        style.configure(
            "TButton",
            padding=7,
            font=("Segoe UI", 10, "bold"),
            background="#1f2937",
            foreground="#e5e7eb",
            bordercolor="#475569",
            lightcolor="#475569",
            darkcolor="#475569",
        )

        style.map(
            "TButton",
            background=[("active", "#334155")],
            foreground=[("active", "#ffffff")],
        )

        style.configure(
            "Vertical.TScrollbar",
            background="#1f2937",
            troughcolor="#0b0f19",
            arrowcolor="#e5e7eb",
        )

    def _build_ui(self) -> None:
        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 8))

        ttk.Label(header, text="TraceAtlas ORGINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Lawful / authorized / evidence-first / privacy-aware organizational intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT org-chart/directory/policy/job-description parsing only • "
                "No infiltration / no impersonation / no phishing / no social engineering / no covert insider recruitment / no private HR access / no doxxing / no sabotage guidance • "
                "Role != Person • Formal != Functional • Title != Authority • Vendor != Employee • Org Chart != Current Reality"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="ORGINT Task Input")
        self.notebook.add(self.output_tab, text="Output / ORGINT Plan / Evidence")

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
                widget = ttk.Combobox(
                    self.form,
                    values=TARGET_TYPES if key == "target_type" else [],
                    width=100,
                    state="readonly",
                )

            else:
                widget = tk.Text(
                    self.form,
                    height=3,
                    width=102,
                    bg="#111827",
                    fg="#e5e7eb",
                    insertbackground="white",
                    relief="flat",
                    highlightthickness=1,
                    highlightbackground="#334155",
                    font=("Segoe UI", 10),
                    wrap="word",
                )

            widget.grid(row=row, column=1, sticky="ew", padx=10, pady=6)
            self.entries[key] = widget
            row += 1

        self.form.columnconfigure(1, weight=1)

        buttons1 = ttk.Frame(self.input_tab)
        buttons1.pack(fill="x", padx=10, pady=(12, 4))

        buttons2 = ttk.Frame(self.input_tab)
        buttons2.pack(fill="x", padx=10, pady=(0, 12))

        ttk.Button(buttons1, text="Add Org Charts", command=self.add_org_charts).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Directories", command=self.add_directories).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Policies / Charters", command=self.add_policies).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Annual Reports", command=self.add_annual_reports).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Job Descriptions", command=self.add_job_descriptions).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Project Records", command=self.add_project_records).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local ORGINT Evidence", command=self.analyze_local_orgint).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate ORGINT Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)

        self.output = tk.Text(
            container,
            wrap="word",
            bg="#020617",
            fg="#bae6fd",
            insertbackground="white",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#334155",
            font=("Consolas", 11),
        )

        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)

        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "ORGINT-CASE-001")
        self.set_widget_value("task_id", "ORGINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Analyze lawful/authorized/public organizational intelligence using privacy-aware, evidence-first ORGINT methods. "
            "Preserve originals, parse safe org-chart/directory/policy/job-description metadata deterministically, resolve organizations/units/roles separately, "
            "map formal and functional reporting with temporal validity, grade capabilities, detect restructuring/change status, separate vendors/contractors/partners from internal membership, "
            "and produce defensive organizational assessments without infiltration, impersonation, phishing/social engineering, private HR access, doxxing, or sabotage guidance.",
        )
        self.set_widget_value("target", "Illustrative example.com / authorized organizational context")
        self.set_widget_value("target_type", "organization_structure")
        self.set_widget_value(
            "questions",
            "\n".join(default_questions({"target": "Illustrative example.com / authorized organizational context"})),
        )

        for field in [
            "organization_names",
            "organization_ids",
            "organization_type",
            "departments",
            "divisions",
            "teams",
            "roles",
            "people",
            "programs",
            "projects",
            "committees",
            "boards",
            "locations",
            "org_charts",
            "directories",
            "policies",
            "annual_reports",
            "strategy_documents",
            "job_descriptions",
            "process_documents",
            "project_records",
            "authorized_internal_metadata",
            "org_chart_paths",
            "directory_paths",
            "policy_paths",
            "annual_report_paths",
            "job_description_paths",
            "project_record_paths",
            "stix_misp_paths",
        ]:
            self.set_widget_value(field, "")

        self.set_widget_value(
            "time_range",
            json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2),
        )
        self.set_widget_value("jurisdiction", "")
        self.set_widget_value(
            "scope",
            json.dumps(
                {
                    "allowed_source_types": [
                        "official organization websites",
                        "official org charts",
                        "annual reports",
                        "institutional reports",
                        "governance documents",
                        "staff directories where authorized/public",
                        "board pages",
                        "committee pages",
                        "organizational policies",
                        "charters",
                        "bylaws",
                        "public filings",
                        "public job descriptions",
                        "public recruitment pages",
                        "public program/project pages",
                        "public budgets",
                        "public procurement documents",
                        "government gazettes",
                        "official directories",
                        "public meeting minutes",
                        "public academic/research pages",
                        "authorized internal HR metadata",
                        "authorized internal org charts",
                        "authorized policy/process documents",
                        "authorized project-management exports",
                        "authorized directory services",
                        "authorized collaboration metadata",
                        "STIX",
                        "MISP",
                        "public news/research",
                    ],
                    "prohibited_sources_and_actions": [
                        "infiltrate organizations",
                        "impersonate employees",
                        "social engineer staff",
                        "phish employees",
                        "solicit passwords",
                        "use stolen credentials",
                        "access private HR systems without authorization",
                        "obtain confidential personnel files unlawfully",
                        "dox employees",
                        "publish private home addresses",
                        "infer sensitive personal traits",
                        "recruit insiders covertly",
                        "blackmail employees",
                        "create workplace influence operations",
                        "conduct private-person surveillance",
                        "make autonomous employment decisions",
                        "provide sabotage or disruption guidance",
                    ],
                    "data_minimization_rules": [
                        "focus on roles, functions, and organizational relationships",
                        "avoid unnecessary private-person data",
                        "use role-first analysis",
                        "preserve temporal validity for every structure/role/reporting edge",
                    ],
                    "authorized_use": "internal defensive/authorized organizational intelligence analysis only",
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "authorization",
            json.dumps(
                {
                    "authorized_by": "ORGINT Manager / Institutional / Organizational Intelligence Manager",
                    "authorization_basis": "customer-authorized lawful/public/authorized defensive ORGINT engagement",
                    "permitted_actions": [
                        "local organizational evidence hashing",
                        "authorized/public org-chart/directory/policy/job-description metadata parsing",
                        "organization/unit/role resolution",
                        "formal vs functional reporting analysis",
                        "capability evidence grading",
                        "restructuring temporal validation",
                        "defensive specialist handoff",
                    ],
                    "prohibited_actions": [
                        "covert infiltration",
                        "employee impersonation",
                        "phishing",
                        "social engineering",
                        "covert insider recruitment",
                        "unauthorized private HR access",
                        "doxxing",
                        "sabotage guidance",
                    ],
                },
                indent=2,
            ),
        )
        self.set_widget_value("source_limits", "")
        self.set_widget_value("budget", "")
        self.set_widget_value("deadline", "")
        self.set_widget_value(
            "configured_connectors",
            "None configured. No HR/Directory/PM/Docs connector invoked. Planning-only for external enrichment.",
        )

    def get_widget_value(self, key: str) -> str:
        widget = self.entries.get(key)
        if widget is None:
            return ""

        if isinstance(widget, tk.Text):
            return widget.get("1.0", "end-1c").strip()

        if isinstance(widget, ttk.Combobox):
            return widget.get().strip()

        if isinstance(widget, ttk.Entry):
            return widget.get().strip()

        return ""

    def set_widget_value(self, key: str, value: str) -> None:
        widget = self.entries.get(key)
        if widget is None:
            return

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

            if key in LIST_FIELDS:
                payload[key] = parse_list(raw)
            elif key in DICT_FIELDS:
                payload[key] = parse_dict(raw)
            else:
                payload[key] = raw

        payload["generated_at"] = now_utc()
        payload["panel_version"] = APP_VERSION
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_AUTHORIZED_PRIVACY_AWARE_EVIDENCE_FIRST"
        payload["source_boundary"] = "LAWFUL_AUTHORIZED_EVIDENCE_FIRST_PRIVACY_AWARE_ORGINT_ONLY"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added to {field}.")

    def add_org_charts(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select org chart export files",
            filetypes=[
                ("Org charts", "*.json *.csv *.tsv *.txt *.log *.md *.orgchart"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("org_chart_paths", paths, "Org Chart Files Added")

    def add_directories(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select staff directory export files",
            filetypes=[
                ("Directories", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("directory_paths", paths, "Directory Files Added")

    def add_policies(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select policy / charter export files",
            filetypes=[
                ("Policies / Charters", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("policy_paths", paths, "Policy Files Added")

    def add_annual_reports(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select annual report export files",
            filetypes=[
                ("Annual reports", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("annual_report_paths", paths, "Annual Report Files Added")

    def add_job_descriptions(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select job description export files",
            filetypes=[
                ("Job descriptions", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("job_description_paths", paths, "Job Description Files Added")

    def add_project_records(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select project / program record files",
            filetypes=[
                ("Project records", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("project_record_paths", paths, "Project Record Files Added")

    def add_stix_misp(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select STIX / MISP export files",
            filetypes=[
                ("STIX / MISP", "*.json *.xml *.csv *.tsv *.txt *.stix *.taxii *.misp"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("stix_misp_paths", paths, "STIX / MISP Files Added")

    def run_policy_screen(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        result = {
            "mode": "POLICY_SCREEN_ONLY",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "payload_preview": {
                "case_id": payload.get("case_id"),
                "task_id": payload.get("task_id"),
                "objective": payload.get("objective"),
                "target": payload.get("target"),
                "target_type": payload.get("target_type"),
                "has_organizations": bool(payload.get("organization_names")),
                "has_units": bool(payload.get("departments") or payload.get("divisions") or payload.get("teams")),
                "has_roles": bool(payload.get("roles")),
                "has_people": bool(payload.get("people")),
                "has_org_charts": bool(payload.get("org_charts") or payload.get("org_chart_paths")),
                "has_directories": bool(payload.get("directories") or payload.get("directory_paths")),
                "has_policies": bool(payload.get("policies") or payload.get("policy_paths")),
                "has_internal_metadata": bool(payload.get("authorized_internal_metadata")),
            },
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This ORGINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only lawful/authorized alternatives.",
            )
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning(
                "Human Review Required",
                "No hard policy block detected, but sensitive organizational/person/directory/internal-metadata context applies.",
            )
        else:
            messagebox.showinfo(
                "Policy Screen",
                "No obvious policy violation detected. Planning-only mode remains active.",
            )

    def analyze_local_orgint(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "evidence_inventory": [],
                "organizations_preview": [],
                "units_preview": [],
                "roles_preview": [],
                "observations": [],
                "candidate_facts": [],
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning("Policy Blocked", "Local ORGINT evidence analysis blocked by policy screen.")
            return

        path_fields = [
            "org_chart_paths",
            "directory_paths",
            "policy_paths",
            "annual_report_paths",
            "job_description_paths",
            "project_record_paths",
            "stix_misp_paths",
        ]

        all_paths: List[str] = []
        seen = set()

        for field in path_fields:
            for p in payload.get(field, []):
                sp = str(p).strip()
                if sp and sp not in seen:
                    seen.add(sp)
                    all_paths.append(sp)

        if not all_paths:
            messagebox.showwarning("No ORGINT Evidence", "Add local lawful/authorized/public organizational evidence files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing local lawful/authorized/public ORGINT evidence. Hashing and parsing may take time...\n")
        self.notebook.select(self.output_tab)

        files: List[Dict[str, Any]] = []
        parsed_list: List[Dict[str, Any]] = []

        for p in all_paths[:30]:
            f, parsed = analyze_orgint_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)

        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(
            files=files,
            parsed=aggregated,
            payload=payload,
            policy=policy,
        )

        self.last_result = report
        self._write_output(report)

        succeeded = sum(1 for f in files if str(f.get("status", "")).startswith("SUCCEEDED"))
        messagebox.showinfo(
            "Local ORGINT Evidence Analysis Complete",
            f"Processed {len(files)} evidence file(s).\n"
            f"Succeeded/partial: {succeeded}\n"
            f"Organizations: {len(aggregated.get('organizations', []))}\n"
            f"Units: {len(aggregated.get('units', []))}\n"
            f"Roles: {len(aggregated.get('roles', []))}\n"
            f"Reporting relationships: {len(aggregated.get('reporting_relationships', []))}\n"
            "Review output for limitations and next actions.",
        )

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "warnings": warnings,
                "payload": payload,
                "orgint_collection_plan": [],
                "next_best_action": {
                    "action": "Revise task to remove prohibited infiltration, impersonation, phishing/social engineering, private HR access, doxxing, or sabotage behavior.",
                    "owner": "ORGINT Manager",
                    "expected_output": "Policy-compliant defensive ORGINT scope and question set.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "ORGINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or default_questions(payload)

        if not self.parsed.get("organizations") and not self.parsed.get("units") and not self.parsed.get("roles"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        files = self.analyzed_files
        parsed = self.parsed

        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, questions, files, parsed)

        overall_status = "PLANNING_ONLY"
        if policy["status"] == "HUMAN_REVIEW_REQUIRED":
            overall_status = "HUMAN_REVIEW_REQUIRED"
        if files or parsed.get("organizations") or parsed.get("units") or parsed.get("roles"):
            overall_status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE"

        result = {
            "mode": overall_status,
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not infiltrate organizations, impersonate employees, phish/social engineer staff, covertly recruit insiders, "
                "blackmail employees, access private HR systems without authorization, dox employees, publish private home addresses, "
                "infer sensitive personal traits, or provide sabotage/disruption guidance. "
                "Local deterministic analysis is limited to hashing, safe JSON/CSV/TXT organizational metadata parsing, organization/unit/role resolution, "
                "role-holder separation, formal/functional reporting analysis, decision-rights candidates, program/project mapping, capability evidence grading, "
                "dependency mapping, restructuring temporal validation, contradiction detection, competing hypotheses, falsification, secret redaction, "
                "prompt-injection flagging, and defensive specialist handoff planning. "
                "Live HR/Directory/PM/Docs enrichment, employment decisions, public accusation, law-enforcement referral, and consequential governance action remain planning-only unless configured/authorized/human-reviewed."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "evidence_inventory": files,
            "organizations_preview": parsed.get("organizations", [])[:300],
            "units_preview": parsed.get("units", [])[:300],
            "roles_preview": parsed.get("roles", [])[:300],
            "role_holders_preview": parsed.get("role_holders", [])[:300],
            "reporting_relationships_preview": parsed.get("reporting_relationships", [])[:300],
            "programs_preview": parsed.get("programs", [])[:300],
            "projects_preview": parsed.get("projects", [])[:300],
            "committees_preview": parsed.get("committees", [])[:300],
            "boards_preview": parsed.get("boards", [])[:300],
            "locations_preview": parsed.get("locations", [])[:300],
            "capabilities_preview": parsed.get("capabilities", [])[:300],
            "dependencies_preview": parsed.get("dependencies", [])[:300],
            "changes_preview": parsed.get("changes", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "next_best_action": next_action,
            "orgint_collection_plan": collection_plan,
            **self._policy_sections(),
            **self._schemas(),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "ORGINT plan generated with warnings:\n\n" + "\n".join(warnings),
            )

    def _build_local_analysis_report(
        self,
        files: List[Dict[str, Any]],
        parsed: Dict[str, Any],
        payload: Dict[str, Any],
        policy: Dict[str, Any],
    ) -> Dict[str, Any]:
        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, default_questions(payload), files, parsed)

        observations: List[Dict[str, Any]] = []

        for f in files:
            observations.append({
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"A local lawful/authorized/public ORGINT evidence file was accessed and hashed: {f.get('filename')}.",
                "evidence_id": f.get("evidence_id"),
                "source_id": f.get("source_id"),
                "observed_at": now_utc(),
                "extraction_method": "local_deterministic_file_hash",
                "limitations": "File hash does not prove current organizational reality, authority, or capability.",
            })

        observations.extend([
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(files)} ORGINT evidence file(s) were parsed locally.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "safe_json_csv_text_org_parser",
                "limitations": "Parser output is normalized evidence, not verified external reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": (
                    f"{len(parsed.get('organizations', []))} organization record(s), "
                    f"{len(parsed.get('units', []))} unit record(s), "
                    f"{len(parsed.get('roles', []))} role record(s), and "
                    f"{len(parsed.get('reporting_relationships', []))} reporting relationship record(s) were extracted."
                ),
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_ORG_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "organization_unit_role_reporting_extraction",
                "limitations": "Source-reported structure is not verified operational reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": "No covert infiltration, impersonation, phishing/social engineering, private HR access, doxxing, or sabotage guidance was performed.",
                "evidence_id": "LOCAL_PANEL_POLICY",
                "source_id": "LOCAL_POLICY_GUARD",
                "observed_at": now_utc(),
                "extraction_method": "lawful_privacy_aware_policy",
                "limitations": "Planning/local deterministic panel only.",
            },
        ])

        observations, _ = truncate_list(observations, 500)

        candidate_facts: List[Dict[str, Any]] = []

        for f in files:
            if f.get("sha256"):
                candidate_facts.append({
                    "candidate_fact": f"The preserved local ORGINT evidence artifact {f.get('filename')} has SHA256 {f.get('sha256')}.",
                    "status": "SUPPORTED",
                    "evidence_ids": [f.get("evidence_id")],
                    "notes": "Supported by deterministic local hashing. Does not prove current structure or authority.",
                })

        candidate_facts.extend([
            {
                "candidate_fact": f"{len(parsed.get('organizations', []))} organization candidate(s) were extracted.",
                "status": "SUPPORTED_AS_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified current operational structure",
                    "verified authority",
                    "verified capability",
                    "verified role holder identity",
                ],
            },
            {
                "candidate_fact": f"{len(parsed.get('reporting_relationships', []))} reporting relationship candidate(s) were extracted.",
                "status": "SUPPORTED_AS_SOURCE_REPORTED_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified functional reporting",
                    "verified decision authority",
                    "verified total control",
                ],
            },
            {
                "candidate_fact": "No covert infiltration, impersonation, phishing/social engineering, private HR access, doxxing, or sabotage guidance was performed.",
                "status": "SUPPORTED",
                "evidence_ids": ["LOCAL_PANEL_POLICY"],
                "notes": "Lawful/privacy-aware planning boundary.",
            },
        ])

        candidate_facts, _ = truncate_list(candidate_facts, 200)

        fact_gate = {
            "status": "LOCAL_DETERMINISTIC_ONLY" if files or parsed.get("organizations") or parsed.get("units") or parsed.get("roles") else "NO_LOCAL_ORGINT_EVIDENCE",
            "supported": [
                "file/source existence and SHA256 hash",
                "parsed organization candidates",
                "parsed unit candidates",
                "parsed role candidates",
                "parsed role-holder candidates",
                "parsed reporting relationship candidates",
                "parsed program/project candidates",
                "parsed capability candidates",
                "parsed dependency candidates",
                "parsed change candidates",
                "contradiction candidates",
                "competing hypotheses",
                "secret redaction flags",
                "prompt-injection flags",
            ],
            "not_supported": [
                "verified current operational structure",
                "verified authority",
                "verified decision rights",
                "verified capability",
                "verified role holder identity",
                "verified employment status",
                "verified private-person attributes",
                "final legal determination",
                "autonomous employment decision",
                "autonomous public accusation",
                "autonomous law-enforcement referral",
                "covert infiltration",
                "impersonation",
                "phishing",
                "social engineering",
                "private HR access",
                "doxxing",
                "sabotage guidance",
            ],
            "safety_status": (
                "No covert infiltration, impersonation, phishing/social engineering, covert insider recruitment, blackmail, "
                "unauthorized private HR access, doxxing, private home address publication, sensitive trait inference, or sabotage/disruption guidance performed."
            ),
        }

        return {
            "mode": "LOCAL_DETERMINISTIC_ORGINT_ANALYSIS",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "covert_infiltration_performed": False,
            "employee_impersonation_performed": False,
            "phishing_performed": False,
            "social_engineering_performed": False,
            "covert_insider_recruitment_performed": False,
            "blackmail_performed": False,
            "unauthorized_private_hr_access_performed": False,
            "doxxing_performed": False,
            "private_home_address_publication_performed": False,
            "sensitive_trait_inference_performed": False,
            "sabotage_guidance_performed": False,
            "evidence_inventory": files,
            "organizations_preview": parsed.get("organizations", [])[:300],
            "units_preview": parsed.get("units", [])[:300],
            "roles_preview": parsed.get("roles", [])[:300],
            "role_holders_preview": parsed.get("role_holders", [])[:300],
            "reporting_relationships_preview": parsed.get("reporting_relationships", [])[:300],
            "programs_preview": parsed.get("programs", [])[:300],
            "projects_preview": parsed.get("projects", [])[:300],
            "committees_preview": parsed.get("committees", [])[:300],
            "boards_preview": parsed.get("boards", [])[:300],
            "locations_preview": parsed.get("locations", [])[:300],
            "capabilities_preview": parsed.get("capabilities", [])[:300],
            "dependencies_preview": parsed.get("dependencies", [])[:300],
            "changes_preview": parsed.get("changes", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "observations": observations,
            "candidate_facts": candidate_facts,
            "fact_gate": fact_gate,
            "recommended_next_actions": next_action,
            "orgint_collection_plan_preview": collection_plan[:20],
            "limitations": [
                "Only local deterministic checks were performed.",
                "No network access was performed.",
                "No covert infiltration, impersonation, phishing/social engineering, private HR access, doxxing, or sabotage guidance was performed.",
                "Organization is not necessarily legal entity.",
                "Organization is not necessarily company.",
                "Role is not person.",
                "Job title is not authority.",
                "Formal structure is not functional structure.",
                "Reporting line is not total control.",
                "Responsibility is not approval authority.",
                "Approval authority is not execution responsibility.",
                "Board membership is not day-to-day management.",
                "Committee membership is not employment.",
                "Partner is not internal unit.",
                "Vendor is not employee.",
                "Contractor is not employee.",
                "Email domain is not verified employment.",
                "Communication centrality is not organizational power.",
                "Social profile title is not current official role.",
                "Job posting is not existing capability.",
                "Staff count is not capability.",
                "Mission statement is not demonstrated capability.",
                "Policy is not actual execution.",
                "Org chart is not current operational reality.",
                "Historical role is not current role.",
                "Dependency is not control.",
                "Multiple copied org charts are not independent sources.",
                "AI agreement is not organizational corroboration.",
                "Exposed secrets were redacted heuristically and not used.",
                "Organizational documents were treated as untrusted evidence.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self) -> Dict[str, Any]:
        return {
            "role": {
                "employee": "ORGINT AI Employee",
                "hierarchy": [
                    "Chief Intelligence Manager",
                    "Institutional / Organizational Intelligence Manager",
                    "ORGINT Manager",
                    "ORGINT AI Employee",
                    "Structure / Governance / Role / Function / Capability / Relationship / Change Intelligence Skills",
                ],
                "not": [
                    "covert infiltration system",
                    "social-engineering system",
                    "employee-manipulation system",
                    "private-person surveillance engine",
                    "doxxing system",
                    "insider recruitment system",
                    "workplace harassment system",
                    "unauthorized HR-data collector",
                    "autonomous employment decision system",
                ],
            },
            "core_principle": [
                "ORGANIZATION REFERENCE",
                "ORGANIZATION RESOLUTION",
                "MANDATE",
                "STRUCTURE",
                "GOVERNANCE",
                "UNITS",
                "ROLES",
                "RESPONSIBILITIES",
                "REPORTING / AUTHORITY",
                "PROGRAMS / CAPABILITIES",
                "EXTERNAL RELATIONSHIPS",
                "TEMPORAL VALIDATION",
                "SOURCE RELIABILITY",
                "SOURCE INDEPENDENCE",
                "FACT GATE",
                "ORGANIZATIONAL ASSESSMENT",
            ],
            "critical_separations": [
                "organization != legal entity",
                "organization != company",
                "role != person",
                "job title != authority",
                "formal structure != functional structure",
                "reporting line != total control",
                "responsibility != approval authority",
                "approval authority != execution responsibility",
                "board membership != day-to-day management",
                "committee membership != employment",
                "partner != internal unit",
                "vendor != employee",
                "contractor != employee",
                "email domain != verified employment",
                "communication centrality != organizational power",
                "social profile title != current official role",
                "job posting != existing capability",
                "staff count != capability",
                "mission statement != demonstrated capability",
                "policy != actual execution",
                "org chart != current operational reality",
                "historical role != current role",
                "dependency != control",
                "multiple copied org charts != independent sources",
                "AI agreement != organizational corroboration",
            ],
            "hard_restrictions": [
                "Do not infiltrate organizations.",
                "Do not impersonate employees.",
                "Do not phish employees.",
                "Do not social-engineer staff.",
                "Do not recruit insiders covertly.",
                "Do not blackmail employees.",
                "Do not access private HR systems without authorization.",
                "Do not dox employees.",
                "Do not publish private home addresses.",
                "Do not infer sensitive personal traits.",
                "Do not use organizational intelligence to plan sabotage.",
            ],
            "non_negotiable_rules": [
                "DO NOT INFILTRATE ORGANIZATIONS.",
                "DO NOT IMPERSONATE EMPLOYEES.",
                "DO NOT PHISH STAFF.",
                "DO NOT SOCIAL-ENGINEER STAFF.",
                "DO NOT RECRUIT INSIDERS COVERTLY.",
                "DO NOT BLACKMAIL EMPLOYEES.",
                "DO NOT ACCESS PRIVATE HR SYSTEMS WITHOUT AUTHORIZATION.",
                "DO NOT DOX EMPLOYEES.",
                "DO NOT PUBLISH PRIVATE HOME ADDRESSES.",
                "DO NOT INFER SENSITIVE PERSONAL TRAITS.",
                "DO NOT USE ORGANIZATIONAL INTELLIGENCE TO PLAN SABOTAGE.",
                "DO NOT EQUATE ROLE WITH PERSON.",
                "DO NOT EQUATE JOB TITLE WITH AUTHORITY.",
                "DO NOT EQUATE FORMAL ORG CHART WITH CURRENT OPERATIONAL REALITY.",
                "DO NOT EQUATE VENDOR WITH EMPLOYEE.",
                "DO NOT EQUATE CONTRACTOR WITH EMPLOYEE.",
                "DO NOT EQUATE HISTORICAL ROLE WITH CURRENT ROLE.",
            ],
        }

    def _schemas(self) -> Dict[str, Any]:
        return {
            "organization_schema": {
                "organization_id": "Unique organization identifier",
                "name": "Organization name",
                "aliases": "Known aliases/acronyms/historical names",
                "organization_type": "COMPANY/GOVERNMENT_AGENCY/NGO/UNIVERSITY/etc.",
                "legal_entity_reference_if_any": "Optional legal entity reference",
                "jurisdiction": "Jurisdiction",
                "mandate": "Formal mandate/charter/statute",
                "mission": "Public mission statement",
                "status": "Current status where evidenced",
                "headquarters_candidate": "Operational HQ candidate",
                "valid_from": "Validity start",
                "valid_to": "Validity end",
                "limitations": [
                    "Organization is not necessarily legal entity.",
                    "Mandate/mission statements are source claims.",
                ],
            },
            "unit_schema": {
                "unit_id": "Unique unit identifier",
                "organization_ref": "Organization reference",
                "name": "Unit name",
                "unit_type": "DIVISION/DEPARTMENT/TEAM/etc.",
                "parent_unit_ref": "Parent unit reference",
                "mandate": "Unit mandate",
                "functions": "Functions owned/supported",
                "leader_role_ref": "Leader role reference",
                "valid_from": "Validity start",
                "valid_to": "Validity end",
                "limitations": [
                    "Unit existence is source-reported until corroborated.",
                ],
            },
            "role_schema": {
                "role_id": "Unique role identifier",
                "organization_ref": "Organization reference",
                "unit_ref": "Unit reference",
                "title": "Role title",
                "role_type": "Role type",
                "responsibilities": "Responsibilities",
                "authority_scope": "Authority scope where evidenced",
                "decision_rights": "Decision rights where evidenced",
                "valid_from": "Validity start",
                "valid_to": "Validity end",
                "limitations": [
                    "Role is not person.",
                    "Job title does not automatically establish authority.",
                ],
            },
            "orgint_result_schema": [
                "case_id",
                "task_id",
                "objective",
                "questions",
                "source_ids",
                "evidence_ids",
                "organizations",
                "organization_types",
                "aliases",
                "mandates",
                "missions",
                "governance_models",
                "organizational_units",
                "divisions",
                "departments",
                "teams",
                "offices",
                "branches",
                "regions",
                "boards",
                "committees",
                "working_groups",
                "programs",
                "projects",
                "roles",
                "positions",
                "role_holders",
                "role_holder_states",
                "reporting_relationships",
                "formal_reporting",
                "functional_reporting",
                "decision_rights",
                "approval_authorities",
                "delegations",
                "responsibilities",
                "functions",
                "capabilities",
                "processes",
                "policies",
                "locations",
                "staffing_counts",
                "staffing_ranges",
                "workforce_distribution",
                "partner_relationships",
                "vendor_relationships",
                "contractor_relationships",
                "dependencies",
                "leadership_history",
                "role_history",
                "unit_history",
                "restructuring_events",
                "formal_vs_observed_structure",
                "org_chart_versions",
                "timeline_updates",
                "observations",
                "candidate_facts",
                "supported_facts",
                "partial_facts",
                "disputed_facts",
                "source_reliability",
                "source_bias",
                "source_limitations",
                "source_pedigree",
                "source_independence",
                "contradictions",
                "hypotheses",
                "falsification_results",
                "privacy_flags",
                "unknowns",
                "knowledge_gaps",
                "recommended_next_actions",
                "specialist_handoffs",
                "limitations",
                "status",
            ],
        }

    def export_json(self) -> None:
        if not self.last_result:
            self.generate_plan()

        data = self.last_result or self.collect_payload()

        payload_for_name = data.get("payload") or data.get("payload_preview") or data
        case_id = payload_for_name.get("case_id", "orgint")
        task_id = payload_for_name.get("task_id", "task")

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"{case_id}_{task_id}.json",
        )

        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Export Complete", f"ORGINT JSON saved to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end-1c").strip()
        if not text:
            messagebox.showinfo("Copy Output", "No output to copy.")
            return

        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copy Output", "Output copied to clipboard.")

    def clear_form(self) -> None:
        confirm = messagebox.askyesno(
            "Clear Form",
            "Are you sure you want to clear all fields, analyzed ORGINT evidence, and reset defaults?",
        )
        if not confirm:
            return

        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result = {}
        self.analyzed_files = []
        self.parsed = empty_parsed()


if __name__ == "__main__":
    app = TraceAtlasORGINTPanel()
    app.mainloop()