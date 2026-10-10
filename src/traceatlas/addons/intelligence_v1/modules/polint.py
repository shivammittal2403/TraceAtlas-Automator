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


APP_TITLE = "TraceAtlas POLINT AI Employee — Analytical / Evidence-First / Non-Partisan / Public-Source Political Intelligence Panel"
APP_VERSION = "TraceAtlas POLINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Actor / Institution / Election Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "POLINT Questions", "text"),

    ("jurisdictions", "Jurisdictions / Countries", "text"),
    ("institutions", "Institutions (Govt/Parliament/Courts)", "text"),
    ("parties", "Political Parties", "text"),
    ("actors", "Public Political Actors", "text"),
    ("coalitions", "Coalitions / Alliances", "text"),
    ("elections", "Elections / Referendums", "text"),
    ("bills", "Bills / Legislation", "text"),
    ("policies", "Policies / Regulations", "text"),
    
    ("polls", "Poll Data", "text"),
    ("statements", "Public Statements / Speeches", "text"),
    ("votes", "Voting Records", "text"),
    ("finance_records", "Campaign Finance / Lobbying Records", "text"),
    ("events", "Political Events / Protests", "text"),

    ("election_result_paths", "Official Election Result Paths", "text"),
    ("poll_data_paths", "Poll Methodology/Data Paths", "text"),
    ("legislative_paths", "Bill/Legislative Record Paths", "text"),
    ("statement_paths", "Speech/Statement Transcript Paths", "text"),
    ("finance_paths", "Finance/Lobbying Register Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Electoral Commission/Legislative DB/etc.)", "text"),
]


TARGET_TYPES = [
    "election_forecast_context",
    "policy_risk_analysis",
    "government_stability_check",
    "actor_position_tracking",
    "foreign_influence_claim_review",
    "corruption_allegation_context",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "jurisdictions",
    "institutions",
    "parties",
    "actors",
    "coalitions",
    "elections",
    "bills",
    "policies",
    "polls",
    "statements",
    "votes",
    "finance_records",
    "events",
    "election_result_paths",
    "poll_data_paths",
    "legislative_paths",
    "statement_paths",
    "finance_paths",
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
    "election_forecast_context",
    "government_stability_check",
    "foreign_influence_claim_review",
    "corruption_allegation_context",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only)\b",
    re.I,
)


POLICY_BLOCK_PATTERNS = [
    r"\b(?:microtarget|target|persuade|manipulate)\b[^\n]{0,140}\b(?:voter|constituent|citizen|demographic|psychographic)\b",
    r"\b(?:generate|create|spread|amplify)\b[^\n]{0,140}\b(?:propaganda|disinformation|fake news|rumor)\b",
    r"\b(?:hack|intrude|steal|leak)\b[^\n]{0,140}\b(?:campaign data|party server|election system|private communication)\b",
    r"\b(?:suppress|intimidate|threaten|harass)\b[^\n]{0,140}\b(?:voter|participant|opponent|journalist)\b",
    r"\b(?:impersonate|pretend to be)\b[^\n]{0,140}\b(?:candidate|official|journalist|agency)\b",
    r"\b(?:infer|profile|guess)\b[^\n]{0,140}\b(?:private belief|ideology|vote intention|political affiliation)\b[^\n]{0,80}\b(?:from personal data|from ethnicity|from religion)\b",
]


SAFE_ALTERNATIVES = [
    "Provide analytical/evidence-first/non-partisan political intelligence: resolve institutions/actors/parties/coalitions, parse official election results/polls/bills/statements, separate rhetoric from policy, verify source independence, assess stability risks using seat arithmetic and documented events, and produce scenario-based reports without targeting or manipulation.",
    "Do not microtarget voters, generate propaganda, hack systems, suppress voting, impersonate officials, profile private beliefs, or facilitate coercion/violence.",
    "Separate Party from Government, Government from Country, Bill from Law, Poll from Result, Projection from Certified Outcome, Allegation from Guilt, Donation from Control, and Rhetoric from Policy.",
    "Use deterministic arithmetic for seat counts/majority thresholds. Escalate consequential corruption/foreign-influence/election-integrity conclusions to authorized human review with multi-source corroboration.",
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
    r"change\s+(?:the\s+)?(?:result|outcome|vote)",
]


# Regex helpers
NUMBER_RE = re.compile(r"\b\d[\d,.]*\b")
PERCENT_RE = re.compile(r"\b(\d{1,3}(?:\.\d+)?)%\b")
DATE_RE = re.compile(r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b|\b\d{4}-\d{2}-\d{2}\b", re.I)


ENTITY_ROLE_KEYS = [
    "party",
    "parties",
    "actor",
    "actors",
    "candidate",
    "candidates",
    "institution",
    "institutions",
    "government",
    "ministry",
    "agency",
    "coalition",
    "coalitions",
    "bloc",
    "blocs",
]


CLAIM_TYPE_MAP = {
    "official_fact": "OFFICIAL_FACT",
    "legal_fact": "LEGAL_FACT",
    "election_result": "ELECTION_RESULT",
    "public_statement": "PUBLIC_STATEMENT",
    "public_position": "PUBLIC_POSITION",
    "party_position": "PARTY_POSITION",
    "policy_proposal": "POLICY_PROPOSAL",
    "source_claim": "SOURCE_CLAIM",
    "analyst_inference": "ANALYST_INFERENCE",
    "scenario": "SCENARIO",
    "prediction": "PREDICTION",
    "unknown": "UNKNOWN",
}


BILL_STATUS_MAP = {
    "proposed": "PROPOSED",
    "introduced": "INTRODUCED",
    "committee": "COMMITTEE",
    "passed_one_chamber": "PASSED_ONE_CHAMBER",
    "passed_legislature": "PASSED_LEGISLATURE",
    "signed": "SIGNED",
    "vetoed": "VETOED",
    "enacted": "ENACTED",
    "withdrawn": "WITHDRAWN",
    "expired": "EXPIRED",
}


RESULT_STATE_MAP = {
    "projection": "PROJECTION",
    "preliminary": "PRELIMINARY",
    "partial_count": "PARTIAL_COUNT",
    "official_provisional": "OFFICIAL_PROVISIONAL",
    "certified": "CERTIFIED",
    "contested": "CONTESTED",
    "annulled": "ANNULLED",
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


def extract_numbers(text: str) -> List[float]:
    nums = []
    for m in NUMBER_RE.finditer(text or ""):
        try:
            # Remove commas for float conversion
            clean = m.group(0).replace(",", "")
            nums.append(float(clean))
        except ValueError:
            pass
    return nums


def extract_percents(text: str) -> List[float]:
    pcts = []
    for m in PERCENT_RE.finditer(text or ""):
        try:
            pcts.append(float(m.group(1)))
        except ValueError:
            pass
    return pcts


def map_bill_status(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return BILL_STATUS_MAP.get(norm, raw.upper() if raw else "UNKNOWN")


def map_result_state(value: Any) -> str:
    raw = safe_str(value, 100)
    norm = normalize_key(raw)
    return RESULT_STATE_MAP.get(norm, raw.upper() if raw else "UNKNOWN")


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "entities": [], # Parties, Actors, Institutions
        "offices": [],
        "coalitions": [],
        "elections": [],
        "results": [],
        "polls": [],
        "bills": [],
        "policies": [],
        "statements": [],
        "votes": [],
        "finance_records": [],
        "events": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "knowledge_gaps": [],
        "specialist_handoffs": [],
        "scenarios": [],
        "risk_assessments": [],
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
            "Observation records what was stated/published, not necessarily its factual truth or institutional effect.",
            "Social media engagement does not equal population support.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in political docs are ignored.")


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
            "Multiple news outlets repeating one agency wire report are not independent sources.",
        ],
    })


def add_entity(
    parsed: Dict[str, Any],
    name: Any,
    entity_type: Any,
    role: Any = "",
    jurisdiction: Any = "",
    source_id: str = "",
    evidence_id: str = "",
    context: str = "",
) -> Optional[str]:
    n = safe_str(name, 200)
    if not n:
        return None

    norm = normalize_text(n)
    et = safe_str(entity_type, 100).upper() or "UNKNOWN"
    r = safe_str(role, 100).upper() or et

    for e in parsed["entities"]:
        if e.get("normalized_name") == norm and e.get("entity_type") == et:
            if jurisdiction and not e.get("jurisdiction"):
                e["jurisdiction"] = safe_str(jurisdiction, 100)
            if r and r != "UNKNOWN" and e.get("role") in ("", "UNKNOWN"):
                e["role"] = r
            return e.get("entity_id")

    eid = f"ENT-{uuid.uuid4()}"
    parsed["entities"].append({
        "entity_id": eid,
        "name": n,
        "normalized_name": norm,
        "entity_type": et,
        "role": r,
        "jurisdiction": safe_str(jurisdiction, 100),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ENTITY_CANDIDATE",
        "limitations": [
            "Entity resolution requires temporal tracking. Officeholders change; parties split/merge.",
            "Party membership does not imply agreement with all party positions.",
        ],
    })
    return eid


def add_election(
    parsed: Dict[str, Any],
    election_id: Any,
    name: Any,
    jurisdiction_ref: Any,
    date: Any,
    type: Any,
    status: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    eid = safe_str(election_id, 200)
    nm = safe_str(name, 200)
    
    if not eid and not nm:
        return None
        
    rec_id = f"ELEC-{uuid.uuid4()}"
    parsed["elections"].append({
        "election_record_id": rec_id,
        "external_election_id": eid,
        "name": nm,
        "jurisdiction_ref": jurisdiction_ref,
        "date": safe_str(date, 100),
        "type": safe_str(type, 100).upper() or "GENERAL",
        "status": map_result_state(status),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ELECTION_PARSED",
        "limitations": [
            "Projection/Preliminary results are not Certified Results.",
            "Contested/Annulled statuses require legal verification.",
        ],
    })
    return rec_id


def add_result(
    parsed: Dict[str, Any],
    election_ref: Any,
    candidate_or_party_ref: Any,
    votes: Any,
    seats: Any,
    percentage: Any,
    state: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    rid = f"RES-{uuid.uuid4()}"
    
    vote_val = None
    if votes is not None:
        try:
            vote_val = int(str(votes).replace(",", ""))
        except:
            pass
            
    seat_val = None
    if seats is not None:
        try:
            seat_val = int(str(seats).replace(",", ""))
        except:
            pass
            
    pct_val = None
    if percentage is not None:
        try:
            pct_val = float(str(percentage).replace("%", ""))
        except:
            pass

    parsed["results"].append({
        "result_id": rid,
        "election_ref": election_ref,
        "entity_ref": candidate_or_party_ref,
        "votes_raw": votes,
        "votes_int": vote_val,
        "seats_raw": seats,
        "seats_int": seat_val,
        "percentage_float": pct_val,
        "state": map_result_state(state),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "RESULT_SOURCE_REPORTED",
        "limitations": [
            "Results must be verified against Official Election Commission data.",
            "Seat arithmetic determines majority; vote share alone may not.",
        ],
    })


def add_poll(
    parsed: Dict[str, Any],
    poll_id: Any,
    sponsor: Any,
    field_start: Any,
    field_end: Any,
    sample_size: Any,
    methodology: Any,
    candidates_parties: Any, # List of dicts with name/score
    margin_error: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    pid = safe_str(poll_id, 200)
    if not pid:
        pid = f"POLL-{uuid.uuid4()}"
        
    ss = None
    if sample_size:
        try:
            ss = int(str(sample_size).replace(",", ""))
        except:
            pass
            
    me = None
    if margin_error:
        try:
            me = float(str(margin_error).replace("+/-", "").replace("%", "").strip())
        except:
            pass

    parsed["polls"].append({
        "poll_id": pid,
        "sponsor": safe_str(sponsor, 200),
        "field_start": safe_str(field_start, 100),
        "field_end": safe_str(field_end, 100),
        "sample_size_int": ss,
        "methodology": safe_str(methodology, 500),
        "data_points": listify(candidates_parties)[:50],
        "margin_error_float": me,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "POLL_PARSED",
        "limitations": [
            "Polls are estimates, not predictions with certainty.",
            "Margin of error and sample size determine statistical significance.",
            "Correlated polls (same sponsor/method) are not independent confirmations.",
        ],
    })


def add_bill(
    parsed: Dict[str, Any],
    bill_id: Any,
    title: Any,
    sponsor_ref: Any,
    status: Any,
    introduction_date: Any,
    chamber_progression: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    bid = safe_str(bill_id, 200)
    if not bid:
        return
        
    parsed["bills"].append({
        "bill_id": bid,
        "title": safe_str(title, 300),
        "sponsor_ref": sponsor_ref,
        "status": map_bill_status(status),
        "introduction_date": safe_str(introduction_date, 100),
        "chamber_progression": safe_str(chamber_progression, 500),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "BILL_PARSED",
        "limitations": [
            "A Bill is not a Law until Enacted/Signed.",
            "Committee passage does not equal Legislature passage.",
        ],
    })


def add_statement(
    parsed: Dict[str, Any],
    speaker_ref: Any,
    text: Any,
    date: Any,
    venue: Any,
    claim_type: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    sid = f"STM-{uuid.uuid4()}"
    
    ct = safe_str(claim_type, 100).upper()
    canonical_ct = CLAIM_TYPE_MAP.get(normalize_key(ct), ct or "PUBLIC_STATEMENT")

    parsed["statements"].append({
        "statement_id": sid,
        "speaker_ref": speaker_ref,
        "text_excerpt": safe_str(text, 1000),
        "date": safe_str(date, 100),
        "venue": safe_str(venue, 200),
        "claim_type": canonical_ct,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "STATEMENT_PARSED",
        "limitations": [
            "Rhetoric is not automatically Policy.",
            "Public Position is distinct from Private Belief.",
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
    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            if isinstance(val, dict):
                ename = val.get("name") or val.get("id")
                etype = val.get("type") or key.upper()
                ejur = val.get("jurisdiction")
            else:
                ename = str(val)
                etype = key.upper()
                ejur = ""
            
            add_entity(parsed, ename, etype, "", ejur, source_id, evidence_id, f"{rec_ctx}/{key}")

    # Process Elections
    elec_items = get_field(rec, ["election", "elections"], as_list=True)
    for item in elec_items:
        if isinstance(item, dict):
            jur_ref = item.get("jurisdiction") # Simplified ref
            el_rec = add_election(
                parsed,
                item.get("election_id") or item.get("id"),
                item.get("name"),
                jur_ref,
                item.get("date"),
                item.get("type"),
                item.get("status"),
                source_id,
                evidence_id,
                f"{rec_ctx}/election"
            )
            
            # Process Results within Election
            res_items = item.get("results", [])
            for r_item in listify(res_items):
                if isinstance(r_item, dict):
                    ent_ref = r_item.get("party") or r_item.get("candidate")
                    add_result(
                        parsed,
                        el_rec,
                        ent_ref,
                        r_item.get("votes"),
                        r_item.get("seats"),
                        r_item.get("percentage"),
                        r_item.get("state") or item.get("status"),
                        source_id,
                        evidence_id,
                        f"{rec_ctx}/result"
                    )

    # Process Polls
    poll_items = get_field(rec, ["poll", "polls"], as_list=True)
    for item in poll_items:
        if isinstance(item, dict):
            add_poll(
                parsed,
                item.get("poll_id") or item.get("id"),
                item.get("sponsor"),
                item.get("field_start"),
                item.get("field_end"),
                item.get("sample_size"),
                item.get("methodology"),
                item.get("data"), # Expecting list of {name, score}
                item.get("margin_error"),
                source_id,
                evidence_id,
                f"{rec_ctx}/poll"
            )

    # Process Bills
    bill_items = get_field(rec, ["bill", "bills", "legislation"], as_list=True)
    for item in bill_items:
        if isinstance(item, dict):
            sp_ref = item.get("sponsor")
            add_bill(
                parsed,
                item.get("bill_id") or item.get("number"),
                item.get("title"),
                sp_ref,
                item.get("status"),
                item.get("introduced_at"),
                item.get("progress"),
                source_id,
                evidence_id,
                f"{rec_ctx}/bill"
            )

    # Process Statements
    stm_items = get_field(rec, ["statement", "speech", "quote"], as_list=True)
    for item in stm_items:
        if isinstance(item, dict):
            spkr_ref = item.get("speaker")
            add_statement(
                parsed,
                spkr_ref,
                item.get("text") or item.get("content"),
                item.get("date"),
                item.get("venue"),
                item.get("type") or "PUBLIC_STATEMENT",
                source_id,
                evidence_id,
                f"{rec_ctx}/statement"
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
                 caution="Political texts are untrusted data.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    signals = []

    if any(k in low for k in ["won", "lost", "votes", "seats", "majority"]):
        signals.append("ELECTORAL_CONTEXT")
    if any(k in low for k in ["poll", "survey", "%", "points"]):
        signals.append("POLLING_CONTEXT")
    if any(k in low for k in ["bill", "law", "act", "passed", "veto"]):
        signals.append("LEGISLATIVE_CONTEXT")
    if any(k in low for k in ["said", "stated", "claimed", "argued"]):
        signals.append("RHETORIC_CONTEXT")
    if any(k in low for k in ["coalition", "alliance", "partner"]):
        signals.append("COALITION_CONTEXT")
    if any(k in low for k in ["protest", "rally", "march", "strike"]):
        signals.append("CIVIC_EVENT_CONTEXT")

    if signals:
        add_note(parsed, "POLITICAL_SIGNAL", signals=unique_preserve_order(signals), source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Signals indicate analytical attention, not verified facts.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY_POL_DATA"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "election" in fname or "result" in fname or "ballot" in keys:
        return "ELECTION_DATASET"
    if "poll" in fname or "survey" in fname:
        return "POLL_DATASET"
    if "bill" in fname or "legislation" in fname or "law" in keys:
        return "LEGISLATIVE_RECORD"
    if "speech" in fname or "statement" in fname:
        return "PUBLIC_STATEMENT_TRANSCRIPT"

    return "GENERIC_POLITICAL_EVIDENCE"


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
    kind = "CSV_POLITICAL_DATA"

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
    if "election" in low or "vote" in low:
        kind = "TEXT_ELECTION_REPORT"
    elif "poll" in low or "survey" in low:
        kind = "TEXT_POLL_SUMMARY"
    elif "bill" in low or "act" in low:
        kind = "TEXT_LEGISLATIVE_NOTE"
    else:
        kind = "TEXT_GENERIC_POLITICS_DOC"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".transcript", ".speech"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_political_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No targeted persuasion, microtargeting, propaganda, hacking, or private profiling performed.",
            "Binary artifacts are hash/metadata preserved only.",
            "Political documents are untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Projections/Polls are not Certified Results/Facts.",
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
            file_evidence["content_kind"] = "BINARY_POL_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary political document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX deeply, or access private systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_entity_count"] = len(parsed.get("entities", []))
    file_evidence["parsed_election_count"] = len(parsed.get("elections", []))
    file_evidence["parsed_poll_count"] = len(parsed.get("polls", []))
    file_evidence["parsed_bill_count"] = len(parsed.get("bills", []))

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


def calculate_seat_arithmetic(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Deterministic calculation of majorities based on parsed results.
    """
    assessments = []
    
    # Group results by Election
    elec_results: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for res in parsed.get("results", []):
        er = res.get("election_ref")
        if er:
            elec_results[er].append(res)
            
    for er, results in elec_results.items():
        total_seats = sum(r.get("seats_int", 0) for r in results if r.get("seats_int"))
        if total_seats == 0:
            continue
            
        majority_threshold = (total_seats // 2) + 1
        
        # Check if any single entity has majority
        dominant = None
        for r in results:
            if r.get("seats_int", 0) >= majority_threshold:
                dominant = r
                
        assessments.append({
            "assessment_id": f"ASM-{uuid.uuid4()}",
            "election_ref": er,
            "total_seats": total_seats,
            "majority_threshold": majority_threshold,
            "dominant_entity": dominant.get("entity_ref") if dominant else None,
            "status": "MAJORITY_IDENTIFIED" if dominant else "HUNG_PARLIAMENT_CANDIDATE",
            "limitations": [
                "Calculation assumes simple majority rule. Jurisdiction-specific rules (supermajority, abstentions) may vary.",
                "Based on parsed dataset completeness. Missing parties/results invalidate calculation.",
            ]
        })
        
    return assessments


def detect_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Check for conflicting poll numbers for same entity/timeframe
    # Simplified: Just flag if multiple polls exist for same election with wide variance
    
    # Check for Bill Status conflicts (e.g., marked VETOED but also SIGNED in different records)
    bill_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for b in parsed.get("bills", []):
        bid = b.get("bill_id")
        if bid:
            bill_map[bid].append(b)
            
    for bid, group in bill_map.items():
        statuses = {g.get("status") for g in group}
        if len(statuses) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "BILL_STATUS_CONFLICT",
                "subject": bid,
                "values": list(statuses),
                "possible_explanations": [
                    "Different chambers",
                    "Amendment cycle",
                    "Stale data in one source",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Verify latest official legislative record.",
            })
            
    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    elections = parsed.get("elections", [])
    results = parsed.get("results", [])
    polls = parsed.get("polls", [])
    
    if not elections and not results:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient electoral data to form stability or outcome hypotheses.",
            "supporting_facts": ["No elections or results parsed."],
            "opposing_facts": [],
            "unknowns": ["current government composition", "upcoming schedules"],
            "next_test": "Import official election commission datasets.",
            "status": "OPEN",
        })
        return hyps[:1000]

    # Scenario: Hung Parliament
    hung_elec_ids = [a["election_ref"] for a in parsed.get("seat_arithmetics", []) if a.get("status") == "HUNG_PARLIAMENT_CANDIDATE"]
    if hung_elec_ids:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Hung parliament scenario indicated by seat arithmetic. Coalition formation required.",
            "supporting_facts": [f"{len(hung_elec_ids)} election(s) lack clear majority."],
            "opposing_facts": ["Data incompleteness may hide majority."],
            "unknowns": ["party willingness to negotiate", "informal alliances"],
            "falsification_conditions": ["Missing results added show clear majority."],
            "next_test": "Analyze public statements regarding coalition talks.",
            "status": "MONITORING",
        })

    # Scenario: Poll Volatility
    if polls:
        # Check for large swings between consecutive polls (simplified heuristic)
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Poll volatility suggests uncertain electorate preference.",
            "supporting_facts": [f"{len(polls)} poll(s) detected."],
            "opposing_facts": ["Methodological consistency may mask real trends."],
            "unknowns": ["sampling bias", "question wording effects"],
            "falsification_conditions": ["Independent polls converge on stable trend."],
            "next_test": "Compare poll methodologies and sponsors for independence.",
            "status": "ANALYTICAL",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    entities = parsed.get("entities", [])
    elections = parsed.get("elections", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized political evidence exists?",
            "missing_evidence": "No local POLINT artifact supplied.",
            "likely_source": "Electoral Commission CSV, Parliamentary Hansard, Official Gazette.",
            "specialist_owner": "POLINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline political analysis.",
            "safety_boundary": "No hacking, no private data scraping.",
        })

    if elections and not any(e.get("status") == "CERTIFIED" for e in elections):
         gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are election results officially certified?",
            "missing_evidence": "Certification status unknown/preliminary.",
            "likely_source": "Official Returning Officer declaration.",
            "specialist_owner": "POLINT",
            "priority": "CRITICAL",
            "expected_information_value": "Prevents treating projections as facts.",
            "safety_boundary": "Do not announce winner before certification.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    statements = parsed.get("statements", [])
    bills = parsed.get("bills", [])
    
    if any(s.get("claim_type") == "CORRUPTION_ALLEGATION" for s in statements):
        handoffs.append({
            "specialist": "FRAUDINT / LEGALINT",
            "reason": "Corruption allegation detected in public statements.",
            "expected_output": "Verification of legal findings/investigations.",
            "question": "Is there an official investigation or court finding supporting this allegation?",
        })
        
    if any(b.get("status") == "ENACTED" for b in bills):
        handoffs.append({
            "specialist": "REGINT",
            "reason": "New legislation enacted.",
            "expected_output": "Regulatory impact assessment.",
            "question": "How does this new law affect organizational compliance obligations?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "POLINT Manager",
            "reason": "Standard analysis completed.",
            "expected_output": "Review findings, approve closure or deep dive.",
            "question": "Are current insights sufficient for strategic decision making?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    parsed["seat_arithmetics"] = calculate_seat_arithmetic(parsed)
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
    elections = parsed.get("elections", [])
    polls = parsed.get("polls", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited persuasion, microtargeting, hacking, or profiling behavior.",
            "reason": "POLINT is analytical intelligence, not a campaign tool.",
            "owner": "POLINT Manager",
            "expected_output": "Policy-compliant defensive scope.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized election/poll/legislative exports before analysis.",
            "reason": "No POLINT evidence artifact available.",
            "owner": "POLINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if elections and not any(e.get("status") == "CERTIFIED" for e in elections):
        return {
            "action": "Wait for official certification before drawing conclusive winners. Monitor provisional updates.",
            "reason": "Projections are not facts.",
            "owner": "POLINT Analyst",
            "expected_output": "Updated status once certified.",
        }

    if polls:
        return {
            "action": "Assess poll quality (sample size, methodology, sponsor independence) before aggregating.",
            "reason": "Low-quality or correlated polls skew averages.",
            "owner": "POLINT Analyst",
            "expected_output": "Weighted confidence interval.",
        }

    return {
        "action": "Proceed with narrative analysis and risk assessment based on verified institutional facts.",
        "reason": "Basic structural analysis complete.",
        "owner": "POLINT / STRATEGIC INT",
        "expected_output": "Scenario-based political risk report.",
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
    has_elec = bool(parsed.get("elections"))
    has_bills = bool(parsed.get("bills"))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General POLINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": "Analytical / evidence-first / non-partisan / public-source political intelligence only.",
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_political_questions_scope",
        "POLINT Manager",
        "Convert objective into political questions, allowed sources, and privacy boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven collection plan.",
    )

    add(
        "preserve_original_political_evidence",
        "local evidence store",
        "Store original election results/polls/bills/statements and hashes without modification.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "PoliticalEvidenceObject with SHA256.",
    )

    add(
        "parse_election_poll_legislative_metadata",
        "local deterministic parser",
        "Parse JSON/CSV/TXT political metadata safely.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized elections/polls/bills/statements.",
    )

    add(
        "calculate_seat_arithmetic_deterministically",
        "local analyzer",
        "Compute majorities and coalitions using integer math, not LLM estimation.",
        "COMPLETED_LOCAL" if has_elec else "PLANNED_ANALYTIC",
        "Majority/Hung Parliament status.",
        safety_risk="HIGH_IF_ARITHMETIC_HALLUCINATED",
    )

    add(
        "verify_source_independence_for_polls",
        "POLINT Analyst",
        "Check if polls share sponsors/methodologies to avoid false corroboration.",
        "PLANNED_ANALYTIC",
        "Independence-adjusted poll aggregation.",
        safety_risk="HIGH_IF_CORRELATED_POLLS_AVERAGED",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target",
        "questions",
        "jurisdictions",
        "actors",
        "parties",
        "elections",
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
            "Sensitive political context detected. Analysis must remain analytical, non-partisan, and evidence-first. "
            "No targeting, no persuasion, no hacking."
        )

    if payload.get("foreign_influence_claims") or "foreign" in scanned:
        human_review_required = True
        safety_notes.append(
            "Foreign influence context detected. Consequential attribution requires multi-source corroboration and human review."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require illegal political manipulation, hacking, propaganda, or private profiling."
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
                "No obvious hard policy violation detected, but sensitive political/foreign-influence/corruption context applies. "
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
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful political evidence is configured."
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
        warnings.append("No POLINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "jurisdictions",
        "election_result_paths",
        "poll_data_paths",
        "legislative_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No political evidence provided. Output remains planning-only.")

    if not payload.get("time_range"):
        warnings.append("No time range provided. Political context is highly temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No electoral commission/legislative db connector configured. External correlation remains planning-only.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "Which jurisdictions and institutions are involved?",
        "What are the current officeholders and their tenures?",
        "What election results are officially certified vs. projected?",
        "What do independent polls indicate, and what are their margins of error?",
        "Which bills are currently in legislative progression?",
        "What are the documented public positions of key actors?",
        "Are there signs of coalition instability or government fragility?",
        "What foreign-influence or corruption allegations exist, and what is their evidentiary status?",
        "What scenarios are plausible for the next 6-12 months?",
        "What remains unknown requiring further verification?",
    ]


class TraceAtlasPOLINTPanel(tk.Tk):
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
        style.configure("Header.TLabel", background="#0b0f19", foreground="#c084fc", font=("Segoe UI", 17, "bold")) # Purple accent
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
        ttk.Label(header, text="TraceAtlas POLINT AI Employee", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text=(
                "Analytical / evidence-first / non-partisan / public-source political intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT election/poll/legislative parsing only • "
                "No targeting / no persuasion / no hacking / no propaganda / no private profiling • "
                "Party != Govt • Bill != Law • Poll != Result • Projection != Certified"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="POLINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Political Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Election Results", command=self.add_elections).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Poll Data", command=self.add_polls).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Legislative Records", command=self.add_legislation).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Statements / Speeches", command=self.add_statements).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local POLINT Evidence", command=self.analyze_local_political).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Political Plan", command=self.generate_plan).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Export JSON", command=self.export_json).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Clear Form", command=self.clear_form).pack(side="left", padx=4)

    def _build_output_tab(self) -> None:
        container = ttk.Frame(self.output_tab)
        container.pack(fill="both", expand=True)
        self.output = tk.Text(container, wrap="word", bg="#020617", fg="#e9d5ff", insertbackground="white", relief="flat", highlightthickness=1, highlightbackground="#334155", font=("Consolas", 11))
        output_scroll = ttk.Scrollbar(container, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=output_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")

    def _set_defaults(self) -> None:
        self.set_widget_value("case_id", "POLIT-CASE-001")
        self.set_widget_value("task_id", "POLIT-TASK-001")
        self.set_widget_value("objective", "Analyze lawful/authorized/defensive political intelligence using evidence-first methods.")
        self.set_widget_value("target", "Illustrative example.com / authorized political context")
        self.set_widget_value("target_type", "election_forecast_context")
        self.set_widget_value("questions", "\n".join(default_questions({"target": "Illustrative example.com"})))
        
        for field in LIST_FIELDS.union(DICT_FIELDS):
            if field not in ["questions", "scope", "authorization", "time_range"]:
                 self.set_widget_value(field, "")
                 
        self.set_widget_value("time_range", json.dumps({"from": "", "to": "", "timezone": "UTC"}, indent=2))
        self.set_widget_value("scope", json.dumps({"allowed_sources": ["official_commission", "parliament_db"], "prohibited_actions": ["microtarget", "hack_campaign"]}, indent=2))
        self.set_widget_value("authorization", json.dumps({"basis": "strategic_risk_assessment"}, indent=2))
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
        payload["operating_mode"] = "PLANNING_ONLY_ANALYTICAL_NON_PARTISAN"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths: return
        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added.")

    def add_elections(self): self._append_paths("election_result_paths", filedialog.askopenfilenames(title="Select Election Results", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_polls(self): self._append_paths("poll_data_paths", filedialog.askopenfilenames(title="Select Polls", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_legislation(self): self._append_paths("legislative_paths", filedialog.askopenfilenames(title="Select Bills", filetypes=[("Data", "*.json *.csv *.txt"), ("All", "*.*")]), "Added")
    def add_statements(self): self._append_paths("statement_paths", filedialog.askopenfilenames(title="Select Statements", filetypes=[("Text", "*.txt *.json"), ("All", "*.*")]), "Added")
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

    def analyze_local_political(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Analysis blocked.")
            return

        path_fields = ["election_result_paths", "poll_data_paths", "legislative_paths", "statement_paths", "finance_paths", "stix_misp_paths"]
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
            f, parsed = analyze_political_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
            files.append(f)
            parsed_list.append(parsed)

        aggregated = finalize_parsed(aggregate_parsed(parsed_list), payload, files)
        self.analyzed_files = files
        self.parsed = aggregated

        report = self._build_local_analysis_report(files, aggregated, payload, policy)
        self.last_result = report
        self._write_output(report)
        
        messagebox.showinfo("Done", f"Parsed {len(files)} files.\nElections: {len(aggregated['elections'])}\nPolls: {len(aggregated['polls'])}\nBills: {len(aggregated['bills'])}")

    def generate_plan(self) -> None:
        payload = self.collect_payload()
        warnings = validate_payload(payload)
        policy = policy_screen(payload)
        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning("Blocked", "Plan blocked.")
            return

        questions = payload.get("questions") or default_questions(payload)
        if not self.parsed.get("elections") and not self.parsed.get("bills"):
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
            "elections_preview": self.parsed.get("elections", [])[:100],
            "results_preview": self.parsed.get("results", [])[:100],
            "polls_preview": self.parsed.get("polls", [])[:100],
            "bills_preview": self.parsed.get("bills", [])[:100],
            "statements_preview": self.parsed.get("statements", [])[:100],
            "seat_arithmetics": self.parsed.get("seat_arithmetics", []),
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
            "mode": "LOCAL_DETERMINISTIC_POLINT_ANALYSIS",
            "policy_screen": policy,
            "evidence_inventory": files,
            "entities": parsed.get("entities", [])[:300],
            "elections": parsed.get("elections", [])[:300],
            "results": parsed.get("results", [])[:300],
            "polls": parsed.get("polls", [])[:300],
            "bills": parsed.get("bills", [])[:300],
            "statements": parsed.get("statements", [])[:300],
            "seat_arithmetics": parsed.get("seat_arithmetics", []),
            "hypotheses": parsed.get("hypotheses", []),
            "contradictions": parsed.get("contradictions", []),
            "limitations": [
                "Only local deterministic checks performed.",
                "No network access.",
                "No targeting, persuasion, hacking, or profiling.",
                "Projections != Certified Results.",
                "Polls != Facts.",
                "Bills != Laws.",
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
        app = TraceAtlasPOLINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print(f"GUI Error: {exc}")
        print("Logic usable as library.")