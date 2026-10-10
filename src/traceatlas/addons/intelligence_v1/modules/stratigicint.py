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


APP_TITLE = "TraceAtlas STRATINT AI Employee — Evidence-First / Long-Horizon / Decision-Support / Non-Targeting Strategic Intelligence Panel"
APP_VERSION = "TraceAtlas STRATINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("strategic_question", "Strategic Question", "text"),
    ("target_type", "Target Type", "combo"),
    ("time_horizon", "Time Horizon", "combo"),

    ("actors", "Strategic Actors (States/Orgs/Groups)", "text"),
    ("regions", "Regions / Jurisdictions", "text"),
    ("sectors", "Sectors / Industries", "text"),
    ("drivers", "Structural Drivers", "text"),
    ("trends", "Observed Trends", "text"),
    ("capabilities", "Capability Assessments", "text"),
    ("intentions", "Intent Indicators", "text"),
    ("constraints", "Constraints / Dependencies", "text"),
    ("scenarios", "Proposed Scenarios", "text"),
    ("indicators", "Key Indicators / Signposts", "text"),
    
    ("economic_data_paths", "Economic Data Paths", "text"),
    ("political_data_paths", "Political/Diplomatic Data Paths", "text"),
    ("military_context_paths", "Military Strategic Context Paths", "text"),
    ("trade_supply_paths", "Trade / Supply Chain Paths", "text"),
    ("tech_regulatory_paths", "Tech / Regulatory Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("as_of_date", "As-Of Date", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget_limit", "Analysis Budget Limit", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Data Feeds/etc.)", "text"),
]


TARGET_TYPES = [
    "geopolitical_risk",
    "economic_resilience",
    "technological_competition",
    "military_strategic_posture",
    "supply_chain_dependency",
    "policy_impact_forecast",
    "unknown",
]


TIME_HORIZONS = [
    "IMMEDIATE_CONTEXT_0_30_DAYS",
    "NEAR_TERM_1_6_MONTHS",
    "MID_TERM_6_24_MONTHS",
    "LONG_TERM_2_5_YEARS",
    "DEEP_HORIZON_5_10_PLUS_YEARS",
]


LIST_FIELDS = {
    "actors",
    "regions",
    "sectors",
    "drivers",
    "trends",
    "capabilities",
    "intentions",
    "constraints",
    "scenarios",
    "indicators",
    "economic_data_paths",
    "political_data_paths",
    "military_context_paths",
    "trade_supply_paths",
    "tech_regulatory_paths",
    "stix_misp_paths",
    "source_limits",
    "configured_connectors",
}


DICT_FIELDS = {
    "scope",
    "authorization",
}


SENSITIVE_TARGET_TYPES = {
    "geopolitical_risk",
    "military_strategic_posture",
    "policy_impact_forecast",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


# STRICT POLICY BLOCKS FOR STRATEGIC HARM/TARGETING
POLICY_BLOCK_PATTERNS = [
    r"\b(?:select|identify|generate)\b[^\n]{0,140}\b(?:target list|aimpoint|strike coordinate|kill chain|attack vector)\b",
    r"\b(?:plan|design|optimize)\b[^\n]{0,140}\b(?:sabotage|assassination|kidnapping|covert action|destabilization campaign|influence operation)\b",
    r"\b(?:provide|recommend)\b[^\n]{0,140}\b(?:sanctions evasion|export control evasion|surveillance of private persons|cyber intrusion method)\b",
    r"\b(?:autonomously execute|make final decision on)\b[^\n]{0,140}\b(?:government policy|military order|legal judgment)\b",
    r"\b(?:exploit|vulnerability for attack)\b[^\n]{0,140}\b(?:critical infrastructure|power grid|water system|financial network)\b",
]


SAFE_ALTERNATIVES = [
    "Provide lawful/evidence-first/non-targeting strategic intelligence: resolve actors/drivers/trends/capabilities/intents, generate competing hypotheses and scenarios, define indicators/signposts, assess risks/opportunities using net assessment frameworks, and support human decision-making without executing policy or facilitating harm.",
    "Do not select targets, provide coordinates, plan attacks/sabotage/covert actions, evade sanctions, surveil private individuals, or autonomously execute government/military decisions.",
    "Separate Capability from Intent, Intent from Decision, Event from Trend, Dependency from Vulnerability, Scenario from Forecast, and Forecast from Certainty.",
    "Use deterministic arithmetic for trends/time-series. Expose key assumptions. Escalate consequential military/political/legal interpretations to authorized human review.",
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
    r"override\s+(?:the\s+)?(?:policy|safety|boundary)",
]


# Regex helpers for strategic data
DATE_RE = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b|\b\d{4}-\d{2}-\d{2}\b", re.I)
NUMBER_RE = re.compile(r"\b[-+]?\d[\d,.]*\b")
PERCENT_RE = re.compile(r"\b(\d{1,3}(?:\.\d+)?)%\b")


ENTITY_ROLE_KEYS = [
    "actor",
    "state",
    "organization",
    "company",
    "group",
    "alliance",
    "coalition",
    "institution",
]


DRIVER_KEYS = [
    "driver",
    "factor",
    "cause",
    "impetus",
]


TREND_KEYS = [
    "trend",
    "pattern",
    "shift",
    "movement",
]


CAPABILITY_KEYS = [
    "capability",
    "capacity",
    "resource",
    "asset",
    "skill",
]


INTENT_KEYS = [
    "intent",
    "goal",
    "objective",
    "motivation",
    "desire",
]


SCENARIO_KEYS = [
    "scenario",
    "future",
    "outcome",
    "possibility",
]


INDICATOR_KEYS = [
    "indicator",
    "signpost",
    "metric",
    "signal",
    "warning",
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


def extract_numbers(text: str) -> List[float]:
    nums = []
    for m in NUMBER_RE.finditer(text or ""):
        try:
            clean = m.group(0).replace(",", "")
            nums.append(float(clean))
        except ValueError:
            pass
    return nums


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "actors": [],
        "drivers": [],
        "trends": [],
        "capabilities": [],
        "intentions": [],
        "constraints": [],
        "dependencies": [],
        "scenarios": [],
        "indicators": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "net_assessment_components": [],
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
            "Observation records what was stated/published, not necessarily its strategic truth or current status.",
            "Events are distinct from structural drivers.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in strategic docs are ignored.")


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
            "Multiple news articles citing one government report are not independent sources.",
        ],
    })


def add_actor(
    parsed: Dict[str, Any],
    name: Any,
    actor_type: Any,
    jurisdiction: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None
        
    norm = normalize_text(n)
    at = safe_str(actor_type, 100).upper() or "UNKNOWN"
    
    for a in parsed["actors"]:
        if a.get("normalized_name") == norm and a.get("actor_type") == at:
            if jurisdiction and not a.get("jurisdiction"):
                a["jurisdiction"] = safe_str(jurisdiction, 100)
            return a.get("actor_id")

    aid = f"ACT-{uuid.uuid4()}"
    parsed["actors"].append({
        "actor_id": aid,
        "name": n,
        "normalized_name": norm,
        "actor_type": at,
        "jurisdiction": safe_str(jurisdiction, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ACTOR_CANDIDATE",
        "limitations": [
            "Actor resolution requires distinguishing State from Leader from Institution.",
            "Stated intent does not equal actual intent.",
        ],
    })
    return aid


def add_driver(
    parsed: Dict[str, Any],
    desc: Any,
    category: Any,
    direction: Any, # POSITIVE/NEGATIVE/NEUTRAL
    strength: Any,   # HIGH/MEDIUM/LOW
    affected_actors: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    d_desc = safe_str(desc, 500)
    if not d_desc:
        return
        
    did = f"DRV-{uuid.uuid4()}"
    
    cat_norm = normalize_text(category).upper()
    dir_norm = normalize_text(direction).upper()
    str_norm = normalize_text(strength).upper()
    
    parsed["drivers"].append({
        "driver_id": did,
        "description": d_desc,
        "category": cat_norm or "UNKNOWN",
        "direction": dir_norm or "NEUTRAL",
        "strength": str_norm or "MEDIUM",
        "affected_actor_refs": listify(affected_actors)[:50],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "DRIVER_PARSED",
        "limitations": [
            "Driver is persistent force, not single event.",
            "Strength assessment is subjective without quantitative model.",
        ],
    })


def add_trend(
    parsed: Dict[str, Any],
    desc: Any,
    direction: Any,
    magnitude: Any,
    duration: Any,
    confidence: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    t_desc = safe_str(desc, 500)
    if not t_desc:
        return
        
    tid = f"TRD-{uuid.uuid4()}"
    
    dir_norm = normalize_text(direction).upper()
    mag_norm = normalize_text(magnitude).upper()
    dur_norm = normalize_text(duration).upper()
    conf_norm = normalize_text(confidence).upper()
    
    parsed["trends"].append({
        "trend_id": tid,
        "description": t_desc,
        "direction": dir_norm or "UNKNOWN",
        "magnitude": mag_norm or "UNKNOWN",
        "duration_estimate": dur_norm or "UNKNOWN",
        "confidence": conf_norm or "LOW",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "TREND_PARSED",
        "limitations": [
            "One data point is not a trend.",
            "Cyclical fluctuations must be distinguished from structural shifts.",
        ],
    })


def add_capability(
    parsed: Dict[str, Any],
    actor_ref: Any,
    cap_type: Any,
    description: Any,
    status: Any, # CLAIMED/OBSERVED/DEMONSTRATED
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    cid = f"CAP-{uuid.uuid4()}"
    
    st_norm = normalize_text(status).upper()
    canonical_status = "UNKNOWN"
    if "CLAIM" in st_norm or "ANNOUNC" in st_norm:
        canonical_status = "CLAIMED"
    elif "OBSERV" in st_norm or "SEE" in st_norm:
        canonical_status = "OBSERVED"
    elif "DEMONSTR" in st_norm or "TEST" in st_norm:
        canonical_status = "DEMONSTRATED"
        
    parsed["capabilities"].append({
        "capability_id": cid,
        "actor_ref": actor_ref,
        "capability_type": safe_str(cap_type, 100).upper() or "UNKNOWN",
        "description": safe_str(description, 500),
        "status": canonical_status,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "CAPABILITY_PARSED",
        "limitations": [
            "Capability != Intent.",
            "Possessing resource != Effective power.",
        ],
    })


def add_intent(
    parsed: Dict[str, Any],
    actor_ref: Any,
    stated_intent: Any,
    inferred_intent: Any,
    behavioral_evidence: Any,
    confidence: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    iid = f"INT-{uuid.uuid4()}"
    
    conf_norm = normalize_text(confidence).upper()
    
    parsed["intentions"].append({
        "intent_id": iid,
        "actor_ref": actor_ref,
        "stated_intent": safe_str(stated_intent, 500),
        "inferred_intent": safe_str(inferred_intent, 500),
        "behavioral_evidence": safe_str(behavioral_evidence, 500),
        "confidence": conf_norm or "LOW",
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "INTENT_PARSED",
        "limitations": [
            "Leader statement != State policy.",
            "Stated intent may be signaling/negotiation tactic.",
        ],
    })


def add_scenario(
    parsed: Dict[str, Any],
    title: Any,
    description: Any,
    likelihood_band: Any, # LOW/MODERATE/HIGH
    key_drivers: Any,
    signposts: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    sid = f"SCN-{uuid.uuid4()}"
    
    lb_norm = normalize_text(likelihood_band).upper()
    
    parsed["scenarios"].append({
        "scenario_id": sid,
        "title": safe_str(title, 200),
        "description": safe_str(description, 1000),
        "likelihood_band": lb_norm or "UNKNOWN",
        "key_driver_refs": listify(key_drivers)[:20],
        "signpost_refs": listify(signposts)[:20],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "SCENARIO_PARSED",
        "limitations": [
            "Scenario explores possibility, it is not a forecast of certainty.",
            "Scenarios should differ meaningfully.",
        ],
    })


def add_indicator(
    parsed: Dict[str, Any],
    desc: Any,
    scenario_ref: Any,
    threshold: Any,
    frequency: Any,
    lead_time: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    ind_id = f"IND-{uuid.uuid4()}"
    
    parsed["indicators"].append({
        "indicator_id": ind_id,
        "description": safe_str(desc, 500),
        "scenario_ref": scenario_ref,
        "threshold": safe_str(threshold, 200),
        "frequency": safe_str(frequency, 100),
        "lead_time_estimate": safe_str(lead_time, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "INDICATOR_PARSED",
        "limitations": [
            "Indicator updates probability, rarely proves alone.",
            "Weak signals require corroboration before promotion.",
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

    # Resolve Actors
    actor_refs = []
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                aname = val.get("name") or val.get("id")
                atype = val.get("type") or key.upper()
                ajur = val.get("jurisdiction")
            else:
                aname = str(val)
                atype = key.upper()
                ajur = rec.get("jurisdiction")
            
            aref = add_actor(parsed, aname, atype, ajur, source_id, evidence_id, f"{rec_ctx}/{key}")
            if aref:
                actor_refs.append(aref)

    primary_actor_ref = actor_refs[0] if actor_refs else None

    # Process Drivers
    drv_items = get_field(rec, DRIVER_KEYS, as_list=True)
    for item in drv_items:
        if isinstance(item, dict):
            add_driver(
                parsed,
                item.get("description") or item.get("text"),
                item.get("category"),
                item.get("direction"),
                item.get("strength"),
                item.get("affected_actors") or actor_refs,
                source_id,
                evidence_id,
                f"{rec_ctx}/driver"
            )

    # Process Trends
    trd_items = get_field(rec, TREND_KEYS, as_list=True)
    for item in trd_items:
        if isinstance(item, dict):
            add_trend(
                parsed,
                item.get("description") or item.get("text"),
                item.get("direction"),
                item.get("magnitude"),
                item.get("duration"),
                item.get("confidence"),
                source_id,
                evidence_id,
                f"{rec_ctx}/trend"
            )

    # Process Capabilities
    cap_items = get_field(rec, CAPABILITY_KEYS, as_list=True)
    for item in cap_items:
        if isinstance(item, dict):
            add_capability(
                parsed,
                item.get("actor") or primary_actor_ref,
                item.get("type"),
                item.get("description"),
                item.get("status"),
                source_id,
                evidence_id,
                f"{rec_ctx}/capability"
            )

    # Process Intentions
    int_items = get_field(rec, INTENT_KEYS, as_list=True)
    for item in int_items:
        if isinstance(item, dict):
            add_intent(
                parsed,
                item.get("actor") or primary_actor_ref,
                item.get("stated"),
                item.get("inferred"),
                item.get("evidence"),
                item.get("confidence"),
                source_id,
                evidence_id,
                f"{rec_ctx}/intent"
            )

    # Process Scenarios
    scn_items = get_field(rec, SCENARIO_KEYS, as_list=True)
    for item in scn_items:
        if isinstance(item, dict):
            add_scenario(
                parsed,
                item.get("title"),
                item.get("description"),
                item.get("likelihood"),
                item.get("drivers"),
                item.get("signposts"),
                source_id,
                evidence_id,
                f"{rec_ctx}/scenario"
            )

    # Process Indicators
    ind_items = get_field(rec, INDICATOR_KEYS, as_list=True)
    for item in ind_items:
        if isinstance(item, dict):
            add_indicator(
                parsed,
                item.get("description"),
                item.get("scenario_ref"),
                item.get("threshold"),
                item.get("frequency"),
                item.get("lead_time"),
                source_id,
                evidence_id,
                f"{rec_ctx}/indicator"
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
                 caution="Strategic texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["growth", "decline", "increase", "decrease", "trend"]):
        signals.append("TREND_CONTEXT")
    if any(k in low for k in ["capability", "capacity", "resource", "weapon", "technology"]):
        signals.append("CAPABILITY_CONTEXT")
    if any(k in low for k in ["intent", "goal", "objective", "strategy", "plan"]):
        signals.append("INTENT_CONTEXT")
    if any(k in low for k in ["risk", "threat", "vulnerability", "crisis"]):
        signals.append("RISK_CONTEXT")
    if any(k in low for k in ["scenario", "future", "projection", "forecast"]):
        signals.append("SCENARIO_CONTEXT")

    if signals:
        add_note(parsed, "STRATEGIC_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified strategic facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_STRAT_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "scenario" in fname or "forecast" in fname:
        return "SCENARIO_FORECAST_DATA"
    if "driver" in fname or "trend" in fname:
        return "STRUCTURAL_DRIVER_DATA"
    if "actor" in fname or "entity" in fname:
        return "ACTOR_PROFILE_DATA"
    if "indicator" in fname or "iw" in fname or "warning" in fname:
        return "INDICATION_WARNING_DATA"

    return "GENERIC_STRATEGIC_EVIDENCE"


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
    kind = "CSV_STRAT_DATA"

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
    if "scenario" in low or "forecast" in low:
        kind = "TEXT_SCENARIO_NOTE"
    elif "driver" in low or "trend" in low:
        kind = "TEXT_STRUCTURAL_ANALYSIS"
    elif "actor" in low or "profile" in low:
        kind = "TEXT_ACTOR_BIO"
    else:
        kind = "TEXT_GENERIC_STRAT_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".strat", ".intel"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_strat_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No targeting, no sabotage, no covert influence, no autonomous policy execution.",
            "Binary artifacts are hash/metadata preserved only.",
            "Strategic documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Capability != Intent. Event != Trend.",
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
            file_evidence["content_kind"] = "BINARY_STRAT_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary strategic document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access classified systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_actor_count"] = len(parsed.get("actors", []))
    file_evidence["parsed_driver_count"] = len(parsed.get("drivers", []))
    file_evidence["parsed_scenario_count"] = len(parsed.get("scenarios", []))

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


def perform_net_assessment(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Simplified Net Assessment comparing Actor Capabilities vs Constraints.
    """
    assessments = []
    
    actor_caps: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for cap in parsed.get("capabilities", []):
        ar = cap.get("actor_ref")
        if ar:
            actor_caps[ar].append(cap)
            
    for aid, caps in actor_caps.items():
        total_strength = sum(1 for c in caps if c.get("status") in ["DEMONSTRATED", "OBSERVED"])
        claimed_only = sum(1 for c in caps if c.get("status") == "CLAIMED")
        
        assessments.append({
            "assessment_id": f"NA-{uuid.uuid4()}",
            "actor_ref": aid,
            "demonstrated_capabilities_count": total_strength,
            "claimed_only_capabilities_count": claimed_only,
            "net_position_summary": "MIXED" if total_strength > 0 and claimed_only > 0 else ("STRONG" if total_strength > 2 else "WEAK/UNCLEAR"),
            "limitations": [
                "Count-based proxy. Does not account for quality/interop.",
                "Does not equate capability with intent.",
            ]
        })
        
    return assessments


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for Capability Status conflicts for same actor/type
    cap_map: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for cap in parsed.get("capabilities", []):
        ar = cap.get("actor_ref")
        ct = cap.get("capability_type")
        if ar and ct:
            cap_map[(ar, ct)].append(cap)
            
    for (ar, ct), group in cap_map.items():
        statuses = {g.get("status") for g in group}
        if "DEMONSTRATED" in statuses and "CLAIMED" in statuses:
             # Not necessarily contradiction, but worth noting discrepancy
             pass
             
        if len(statuses) > 1 and "UNKNOWN" not in statuses:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "CAPABILITY_STATUS_CONFLICT",
                "subject": f"{ar} : {ct}",
                "values": list(statuses),
                "possible_explanations": [
                    "Different dates",
                    "Different variants/configurations",
                    "Propaganda vs Reality",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify latest technical intelligence (TECHINT).",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    actors = parsed.get("actors", [])
    intents = parsed.get("intentions", [])
    
    if not actors:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "No strategic actors identified in local dataset.",
            "supporting_facts": ["Empty actor list."],
            "opposing_facts": [],
            "unknowns": ["who matters?", "what drives them?"],
            "next_test": "Import valid actor/profile exports.",
            "status": "OPEN",
        })
        return hyps[:1000]

    # Leading Hypothesis based on most frequent actor
    if actors:
        primary_actor = actors[0]
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": f"Primary strategic dynamic revolves around Actor: {primary_actor['name']}.",
            "supporting_facts": ["Highest mention count in parsed entities."],
            "opposing_facts": ["May be secondary player in larger coalition."],
            "unknowns": ["True weight in decision making"],
            "falsification_conditions": ["Evidence shows another actor dominates resources."],
            "next_test": "Map command relationships and resource flows.",
            "status": "LEADING",
        })
        
    # Alternative Hypothesis: Defensive Posture
    hyps.append({
        "hypothesis_id": f"HYP-{uuid.uuid4()}",
        "statement": "Observed activities reflect defensive deterrence rather than offensive expansion.",
        "supporting_facts": ["Many modernizations have dual-use/defensive applications."],
        "opposing_facts": ["Aggressive rhetoric present in some statements."],
        "unknowns": ["Actual doctrine interpretation"],
        "falsification_conditions": ["Pre-positioning of forward assets confirmed."],
        "next_test": "Analyze logistics tail and deployment patterns (via MILINT handoff).",
        "status": "ALTERNATIVE",
    })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    actors = parsed.get("actors", [])
    capabilities = parsed.get("capabilities", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized strategic evidence exists?",
            "missing_evidence": "No local STRATINT artifact supplied.",
            "likely_source": "National Strategy Doc, Economic Report, Think Tank Analysis.",
            "specialist_owner": "STRATINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline strategic analysis.",
            "safety_boundary": "No targeting, no classified solicitation.",
        })

    if actors and not capabilities:
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What are the concrete capabilities of these actors?",
            "missing_evidence": "Capability records missing.",
            "likely_source": "Defense White Papers, Industrial Reports, Tech Patents.",
            "specialist_owner": "STRATINT / TECHINT / MILINT",
            "priority": "HIGH",
            "expected_information_value": "Determines ability to act.",
            "safety_boundary": "Do not infer intent from capability alone.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    actors = parsed.get("actors", [])
    trends = parsed.get("trends", [])
    
    if any(a.get("actor_type") == "STATE" or a.get("actor_type") == "GOVERNMENT" for a in actors):
        handoffs.append({
            "specialist": "MILINT / GOVINT",
            "reason": "State actor identified.",
            "expected_output": "Force structure details, public record verification.",
            "question": "What is the specific military/government posture supporting this strategic view?",
        })
        
    if trends:
        handoffs.append({
            "specialist": "FININT / TRADEINT",
            "reason": "Economic/Trade trends detected.",
            "expected_output": "Financial flow verification, supply chain mapping.",
            "question": "Are these trends structurally entrenched or cyclical noise?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "STRATINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Are current insights sufficient for strategic decision support?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["net_assessment_components"] = perform_net_assessment(parsed)
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
    actors = parsed.get("actors", [])
    scenarios = parsed.get("scenarios", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited targeting, sabotage, or covert influence behavior.",
            "reason": "STRATINT is decision support, not operational execution.",
            "owner": "STRATINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized strategic data exports before analysis.",
            "reason": "No STRATINT evidence artifact available.",
            "owner": "STRATINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if actors and not scenarios:
        return {
            "action": "Generate competing scenarios based on identified drivers and constraints.",
            "reason": "Understanding possible futures is critical for warning.",
            "owner": "STRATINT Analyst",
            "expected_output": "Scenario matrix with signposts.",
        }

    return {
        "action": "Monitor defined indicators against baseline to update warning state.",
        "reason": "Scenarios established.",
        "owner": "STRATINT / I&W Specialist",
        "expected_output": "Updated strategic watchlist.",
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
    has_actors = bool(parsed.get("actors"))
    has_scen = bool(parsed.get("scenarios"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General STRATINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Lawful / evidence-first / non-targeting strategic intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_strategic_questions_scope",
        "STRATINT Manager",
        "Convert objective into strategic questions, allowed sources, and privacy boundaries.",
        "COMPLETED_LOCAL" if payload.get("strategic_question") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_strategic_records",
        "local evidence store",
        "Store original reports/data and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "StratEvidenceObject with SHA256.",
    )

    add(
        "parse_actor_driver_trend_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT strategic metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized actors/drivers/trends/scenarios.",
    )

    add(
        "separate_capability_from_intent",
        "local analyzer",
        "Ensure output distinguishes what actors CAN do from what they WANT to do.",
        "COMPLETED_LOCAL" if has_actors else "PLANNED_ANALYTIC",
        "Capability vs Intent register.",
        safety_risk="HIGH_IF_CAPABILITY_CALLED_THREAT",
    )

    add(
        "generate_competing_hypotheses",
        "STRATINT Analyst",
        "Create ACH matrix with leading and alternative explanations.",
        "PLANNED_ANALYTIC",
        "Hypothesis set with falsification criteria.",
        safety_risk="HIGH_IF_SINGLE_NARRATIVE_ADOPTED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "strategic_question",
        "actors",
        "regions",
        "capabilities",
        "intentions",
        "scenarios",
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
            "Sensitive strategic context detected. Analysis must remain lawful, evidence-first, and non-targeting. "
            "No strike planning, no sabotage, no covert influence."
        )

    if payload.get("military_context_paths") or "military" in scanned:
        human_review_required = True
        safety_notes.append(
            "Military context detected. Handoff detailed force structure to MILINT. Do not generate tactical outputs."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal targeting, sabotage, or covert manipulation."
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
                "No obvious hard policy violation detected, but sensitive strategic/military context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful strategic evidence is configured."
        ),
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "strategic_question", "target_type", "time_horizon"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("actors"):
        warnings.append("No strategic actors provided. Analysis will be generic.")

    evidence_keys = [
        "economic_data_paths",
        "political_data_paths",
        "military_context_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No strategic evidence provided. Output remains planning-only.")

    if not payload.get("as_of_date"):
        warnings.append("No As-Of Date provided. Strategic context is highly temporal.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Who are the key strategic actors and what are their objectives?",
        "What structural drivers are influencing the situation?",
        "What capabilities do these actors possess vs claim?",
        "What constraints limit their ability to act?",
        "What are the plausible scenarios for the next time horizon?",
        "Which indicators would signal a shift between scenarios?",
        "What are the second-order effects of the leading scenario?",
        "Where are our key assumptions weakest?",
        "What intelligence gaps prevent higher confidence?",
        "What decision options are supported by this analysis?",
    ]


class TraceAtlasSTRATINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#38bdf8", font=("Segoe UI", 17, "bold")) # Cyan accent for Strategic/Tech
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
        ttk.Label(header, text="TraceAtlas STRATINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Evidence-first / long-horizon / decision-support / NON-TARGETING strategic intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT actor/driver/scenario parsing only • "
                "No targeting / No sabotage / No covert influence / No autonomous policy execution • "
                "Capability != Intent • Event != Trend • Scenario != Forecast"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="STRATINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Strat Plan / Evidence")

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
                values = TARGET_TYPES if key == "target_type" else (TIME_HORIZONS if key == "time_horizon" else [])
                widget = ttk.Combobox(self.form, values=values, width=100, state="readonly")
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

        ttk.Button(buttons1, text="Add Economic Data", command=self.add_econ).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Political/Diplo Data", command=self.add_pol).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Military Context", command=self.add_mil).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Trade/Supply Chain", command=self.add_trade).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local STRATINT Evidence", command=self.analyze_local_strat).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Strategic Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#bae6fd", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "STRAT-CASE-001")
        self.set_widget_value("task_id", "STRAT-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive strategic intelligence using evidence-first methods.")
        self.set_widget_value("strategic_question", "Illustrative: What are the key risks to supply chain resilience in Region X over the next 2 years?")
        self.set_widget_value("target_type", "supply_chain_dependency")
        self.set_widget_value("time_horizon", "MID_TERM_6_24_MONTHS")
        self.set_widget_value("questions", "\n".join(default_questions({"strategic_question": "Illustrative"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("as_of_date", now_utc()[:10])
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["public_reports", "official_stats"], "prohibited_actions": ["target_infra", "covert_op"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "internal_risk_management"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_EVIDENCE_FIRST_NON_TARGETING"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_econ(self): self._append_paths("economic_data_paths", filedialog.askopenfilenames(title="Select Econ Data", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_pol(self): self._append_paths("political_data_paths", filedialog.askopenfilenames(title="Select Pol Data", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_mil(self): self._append_paths("military_context_paths", filedialog.askopenfilenames(title="Select Mil Context", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_trade(self): self._append_paths("trade_supply_paths", filedialog.askopenfilenames(title="Select Trade Data", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
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

    def analyze_local_strat(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["economic_data_paths", "political_data_paths", "military_context_paths", "trade_supply_paths", "tech_regulatory_paths", "stix_misp_paths"]
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
            f, parsed = analyze_strat_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nActors: {len(aggregated['actors'])}\nScenarios: {len(aggregated['scenarios'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("actors") and not self.parsed.get("scenarios"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        next_action = build_next_best_action(payload, policy, self.analyzed_files, self.parsed)
        collection_plan = build_collection_plan(payload, questions, self.analyzed_files, self.parsed)

        result = {
            "mode": "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE" if self.analyzed_files else "PLANNING_ONLY",
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "evidence_inventory": self.analyzed_files,
            "actors_preview": self.parsed.get("actors", [])[:100],
            "drivers_preview": self.parsed.get("drivers", [])[:100],
            "trends_preview": self.parsed.get("trends", [])[:100],
            "capabilities_preview": self.parsed.get("capabilities", [])[:100],
            "intentions_preview": self.parsed.get("intentions", [])[:100],
            "scenarios_preview": self.parsed.get("scenarios", [])[:100],
            "indicators_preview": self.parsed.get("indicators", [])[:100],
            "net_assessment_components": self.parsed.get("net_assessment_components", []),
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
            "mode": "LOCAL_DETERMINISTIC_STRATINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "actors": parsed.get("actors", [])[:300],
            "drivers": parsed.get("drivers", [])[:300],
            "trends": parsed.get("trends", [])[:300],
            "capabilities": parsed.get("capabilities", [])[:300],
            "intentions": parsed.get("intentions", [])[:300],
            "scenarios": parsed.get("scenarios", [])[:300],
            "indicators": parsed.get("indicators", [])[:300],
            "net_assessment_components": parsed.get("net_assessment_components", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No targeting, no sabotage, no covert influence.",
                "Capability != Intent.",
                "Scenario != Forecast.",
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
        app = TraceAtlasSTRATINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")