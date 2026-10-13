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


APP_TITLE = "TraceAtlas HUMINT AI Employee — Ethical / Consensual / Authorized Human-Source Intelligence Panel"
APP_VERSION = "TraceAtlas HUMINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Subject / Incident Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "HUMINT Questions", "text"),

    ("source_pseudonyms", "Source Pseudonyms / IDs", "text"),
    ("source_types", "Source Types (Employee/Witness/Expert/etc.)", "text"),
    ("source_roles", "Source Roles / Titles", "text"),
    ("interview_transcripts", "Interview Transcripts / Notes", "text"),
    ("statements", "Statements / Testimonies", "text"),
    ("public_statements", "Public Statements / Declarations", "text"),
    ("recording_references", "Recording References / Hashes", "text"),
    ("consent_states", "Consent States / Records", "text"),
    ("source_access_context", "Source Access Context / Permissions", "text"),
    ("known_facts", "Known Facts / Baseline", "text"),
    ("known_evidence", "Known Evidence / Documents / Logs", "text"),
    ("known_contradictions", "Known Contradictions", "text"),

    ("interview_paths", "Interview Transcript Paths", "text"),
    ("statement_paths", "Statement / Testimony Paths", "text"),
    ("document_corroboration_paths", "Document Corroboration Paths", "text"),
    ("log_corroboration_paths", "Log / Telemetry Corroboration Paths", "text"),
    ("media_corroboration_paths", "Media / Image / Audio Corroboration Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (DocInt/LogInt/AudInt/VidInt/etc.)", "text"),
]


TARGET_TYPES = [
    "interview",
    "witness_statement",
    "expert_testimony",
    "employee_interview",
    "incident_debrief",
    "public_statement",
    "source_report",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "source_pseudonyms",
    "source_types",
    "source_roles",
    "interview_transcripts",
    "statements",
    "public_statements",
    "recording_references",
    "consent_states",
    "source_access_context",
    "known_facts",
    "known_evidence",
    "known_contradictions",
    "interview_paths",
    "statement_paths",
    "document_corroboration_paths",
    "log_corroboration_paths",
    "media_corroboration_paths",
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
    "interview",
    "witness_statement",
    "expert_testimony",
    "employee_interview",
    "incident_debrief",
    "public_statement",
    "source_report",
}


POLICY_BLOCK_PATTERNS = [
    r"\b(?:coerce|threaten|intimidate|blackmail|extort|pressure)\b[^\n]{0,140}\b(?:source|interviewee|witness|employee|person|individual)\b",
    r"\b(?:impersonate|pretend|fake identity|masquerade)\b[^\n]{0,140}\b(?:official|employer|police|friend|family|colleague)\b",
    r"\b(?:phish|social engineer|solicit password|solicit mfa|solicit token|solicit key)\b",
    r"\b(?:entrap|set up|frame)\b[^\n]{0,140}\b(?:source|target|suspect|person)\b",
    r"\b(?:exploit trauma|exploit grief|exploit addiction|exploit financial desperation|exploit medical vulnerability)\b",
    r"\b(?:covert recruit|clandestine approach|dead drop|cover legend|spy tradecraft)\b",
    r"\b(?:lie detector|polygraph|microexpression analysis|demeanor analysis|voice stress analysis)\b",
    r"\b(?:record secretly|unauthorized recording|surveil private person|stalk individual)\b",
    r"\b(?:interview minor without guardian|question child autonomously)\b",
]


SAFE_ALTERNATIVES = [
    "Provide ethical/consensual/authorized human-source intelligence: claim extraction, basis-of-knowledge analysis, source-access assessment, firsthand vs hearsay distinction, memory-quality caution, timeline reconstruction, contradiction analysis, corroboration planning, source independence, alternative hypotheses, falsification, and privacy-aware reporting.",
    "Do not coerce, threaten, blackmail, entrap, impersonate, phish, socially engineer, exploit vulnerabilities, conduct covert recruitment, use AI as a lie detector, infer deception from demeanor, or record without authorization.",
    "Treat source statements as untrusted evidence about propositions, not self-validating facts.",
    "Preserve verbatim quotes where possible; clearly distinguish analyst summaries from direct speech.",
    "Escalate consequential findings (misconduct attribution, legal action, safety risks) to authorized human reviewers.",
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
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential|mfa_seed|totp|recovery_code)\b"
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
    r"send\s+(?:this\s+)?elsewhere",
    r"contact\s+me",
    r"change\s+investigation",
    r"delete\s+evidence",
    r"alter\s+transcript",
]


BASIS_OF_KNOWLEDGE_KEYWORDS = {
    "DIRECT_OBSERVATION": ["i saw", "i witnessed", "i observed", "my eyes", "directly seen"],
    "DIRECT_PARTICIPATION": ["i did", "i performed", "i executed", "i clicked", "i typed"],
    "DIRECT_COMMUNICATION": ["they told me", "she said", "he stated", "we spoke", "conversation with"],
    "DOCUMENT_SEEN": ["i read", "document shows", "email says", "report states", "file contains"],
    "SYSTEM_SEEN": ["logs show", "dashboard displays", "console output", "screen showed", "system recorded"],
    "HEARD_FROM_NAMED_SOURCE": ["john said", "mary reported", "manager told me", "colleague mentioned"],
    "HEARD_FROM_UNNAMED_SOURCE": ["someone said", "people are saying", "rumor is", "i heard that"],
    "INFERENCE": ["i think", "i believe", "probably", "likely", "must have been", "assumed"],
    "ASSUMPTION": ["assuming", "presumably", "given that", "if true then"],
    "RUMOR": ["rumor", "gossip", "word on the street", "chatter"],
    "MEMORY": ["i remember", "from my memory", "recall", "vaguely remember"],
}

SOURCE_CERTAINTY_KEYWORDS = {
    "CERTAIN": ["definitely", "absolutely", "100%", "without doubt", "certainly"],
    "HIGH": ["sure", "confident", "positive", "know for a fact"],
    "MODERATE": ["fairly sure", "pretty sure", "mostly", "likely"],
    "LOW": ["maybe", "perhaps", "possibly", "could be", "might"],
    "UNSURE": ["not sure", "unsure", "unclear", "don't know", "can't say"],
    "GUESS": ["guess", "estimate", "rough idea", "ballpark"],
}

CONSENT_STATES = [
    "CONSENT_CONFIRMED",
    "CONSENT_RESTRICTED",
    "CONSENT_WITHDRAWN",
    "CONSENT_NOT_REQUIRED_FOR_PUBLIC_STATEMENT",
    "CONSENT_UNCLEAR",
    "HUMAN_REVIEW_REQUIRED",
]

RECORDING_CONSENT_STATES = [
    "RECORDING_AUTHORIZED",
    "RECORDING_DENIED",
    "RECORDING_UNSPECIFIED",
    "JURISDICTION_REVIEW_REQUIRED",
]

SOURCE_ROLES = [
    "EMPLOYEE",
    "CONTRACTOR",
    "EXECUTIVE",
    "TECHNICAL_EXPERT",
    "SUBJECT_MATTER_EXPERT",
    "INCIDENT_WITNESS",
    "SYSTEM_ADMINISTRATOR",
    "CUSTOMER",
    "VENDOR",
    "RESEARCHER",
    "JOURNALIST",
    "PUBLIC_OFFICIAL",
    "PUBLIC_SPOKESPERSON",
    "PUBLIC_WITNESS",
    "AUTHORIZED_COMPLAINANT",
    "AUTHORIZED_WHISTLEBLOWER",
    "UNKNOWN",
]

ACCESS_LEVELS = [
    "DIRECT_ACCESS",
    "ROLE_BASED_ACCESS",
    "PARTIAL_ACCESS",
    "INDIRECT_ACCESS",
    "NO_DEMONSTRATED_ACCESS",
    "UNKNOWN",
]

TEMPORAL_PRECISION = [
    "EXACT",
    "APPROXIMATE",
    "DATE_ONLY",
    "RELATIVE",
    "SEQUENCE_ONLY",
    "UNKNOWN",
]

CORROBORATION_STATES = [
    "UNCORROBORATED",
    "SINGLE_SOURCE_SUPPORTED",
    "MULTI_SOURCE_DEPENDENT",
    "MULTI_SOURCE_INDEPENDENT",
    "DOCUMENT_CORROBORATED",
    "TECHNICALLY_CORROBORATED",
    "CONTRADICTED",
    "INCONCLUSIVE",
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


def classify_basis_of_knowledge(text: str) -> str:
    low = normalize_text(text)
    
    # Check specific keywords first
    for bok, keywords in BASIS_OF_KNOWLEDGE_KEYWORDS.items():
        if any(k in low for k in keywords):
            return bok
            
    # Default fallback
    if "heard" in low or "said" in low or "told" in low:
        return "HEARD_FROM_UNNAMED_SOURCE"
    if "think" in low or "believe" in low or "assume" in low:
        return "INFERENCE"
        
    return "UNKNOWN"


def classify_source_certainty(text: str) -> str:
    low = normalize_text(text)
    
    for cert, keywords in SOURCE_CERTAINTY_KEYWORDS.items():
        if any(k in low for k in keywords):
            return cert
            
    return "UNKNOWN"


def extract_temporal(rec: Dict[str, Any]) -> Dict[str, str]:
    temporal: Dict[str, str] = {}
    mappings = {
        "event_time": ["event_time", "occurred_at", "when_it_happened", "incident_time"],
        "statement_time": ["statement_time", "observed_at", "timestamp", "time_spoken"],
        "interview_time": ["interview_time", "collection_time", "recorded_at"],
        "first_seen": ["first_seen", "created"],
        "last_seen": ["last_seen", "updated"],
    }

    for canonical, aliases in mappings.items():
        val = get_field(rec, aliases)
        if val not in (None, ""):
            temporal[canonical] = str(val)

    return temporal


def get_field(rec: Dict[str, Any], keys: List[str]) -> Any:
    if not isinstance(rec, dict):
        return None

    lower = {normalize_key(k): v for k, v in rec.items()}
    for key in keys:
        nk = normalize_key(key)
        if nk in lower and lower[nk] not in (None, ""):
            val = lower[nk]
            if isinstance(val, list):
                return val[0] if val else None
            return val
    return None


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "interviews": [],
        "statements": [],
        "claims": [],
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
            "Human statement is evidence about a proposition, not self-validating fact.",
            "Confidence does not equal accuracy.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in transcripts/statements are ignored.")


def add_source(
    parsed: Dict[str, Any],
    source_id: str,
    pseudonym: str,
    source_type: str = "",
    role: str = "",
    access_level: str = "UNKNOWN",
    consent_state: str = "CONSENT_UNCLEAR",
    recording_consent: str = "RECORDING_UNSPECIFIED",
    reliability_history: str = "UNKNOWN",
) -> None:
    for s in parsed["sources"]:
        if s.get("source_id") == source_id:
            if pseudonym and not s.get("pseudonym"):
                s["pseudonym"] = pseudonym
            if source_type and not s.get("source_type"):
                s["source_type"] = source_type
            if role and not s.get("role"):
                s["role"] = role
            return

    parsed["sources"].append({
        "source_id": source_id,
        "pseudonym": pseudonym,
        "source_type": source_type or "UNKNOWN",
        "role": role or "UNKNOWN",
        "access_level": access_level,
        "consent_state": consent_state,
        "recording_consent": recording_consent,
        "reliability_history": reliability_history,
        "registered_at": now_utc(),
        "state": "SOURCE_REGISTERED",
        "limitations": [
            "Source registration is local provenance metadata.",
            "Identity protection: prefer pseudonyms over real names.",
        ],
    })


def add_interview(
    parsed: Dict[str, Any],
    interview_id: str,
    source_id: str,
    date: str = "",
    location: str = "",
    interviewer: str = "",
    duration_minutes: int = 0,
    transcript_reference: str = "",
    quality_score: str = "UNKNOWN",
) -> None:
    parsed["interviews"].append({
        "interview_id": interview_id,
        "source_id": source_id,
        "date": date,
        "location": location,
        "interviewer": interviewer,
        "duration_minutes": duration_minutes,
        "transcript_reference": transcript_reference,
        "quality_score": quality_score,
        "state": "INTERVIEW_LOGGED",
        "limitations": [
            "Interview quality affects data reliability.",
            "Leading questions must be avoided.",
        ],
    })


def add_statement(
    parsed: Dict[str, Any],
    statement_id: str,
    source_id: str,
    interview_id: Optional[str],
    content: str,
    timestamp: str = "",
    speaker: str = "",
    language: str = "en",
    translation_reference: str = "",
    verbatim_flag: bool = True,
) -> None:
    redacted, secret_flags = redact_secrets(content)
    injection_flags = detect_prompt_injection(content)
    
    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=statement_id, context="statement")
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=statement_id, context="statement")

    parsed["statements"].append({
        "statement_id": statement_id,
        "source_id": source_id,
        "interview_id": interview_id,
        "content": redacted,
        "timestamp": timestamp,
        "speaker": speaker,
        "language": language,
        "translation_reference": translation_reference,
        "verbatim_flag": verbatim_flag,
        "content_hash": sha256_text(redacted),
        "state": "STATEMENT_RECORDED",
        "limitations": [
            "Statement is raw input; claims must be decomposed separately.",
            "Verbatim preservation prevents paraphrase bias.",
        ],
    })


def add_claim(
    parsed: Dict[str, Any],
    claim_id: str,
    source_id: str,
    statement_id: str,
    subject: str,
    predicate: str,
    object_entity: str,
    time_reference: str,
    location_reference: str,
    basis_of_knowledge: str,
    certainty_expression: str,
    directness: str,
    corroboration_state: str = "UNCORROBORATED",
    contradiction_state: str = "NONE_KNOWN",
    confidence: str = "LOW",
) -> None:
    parsed["claims"].append({
        "claim_id": claim_id,
        "source_id": source_id,
        "statement_id": statement_id,
        "subject": subject,
        "predicate": predicate,
        "object": object_entity,
        "time_reference": time_reference,
        "location_reference": location_reference,
        "basis_of_knowledge": basis_of_knowledge,
        "certainty_expression": certainty_expression,
        "directness": directness,
        "corroboration_state": corroboration_state,
        "contradiction_state": contradiction_state,
        "confidence": confidence,
        "state": "CLAIM_EXTRACTED",
        "limitations": [
            "Claim is an assertion by a source, not a verified fact.",
            "Basis of knowledge determines evidentiary weight.",
        ],
    })


def process_text_block(
    text: str,
    source_id: str,
    statement_id: str,
    parsed: Dict[str, Any],
    context: str = "",
    temporal: Optional[Dict[str, Any]] = None,
) -> None:
    raw = str(text or "")
    if not raw.strip():
        return

    # Decompose into sentences for claim extraction
    sentences = re.split(r"(?<=[.!?])\s+", raw)
    
    for sent_idx, sentence in enumerate(sentences[:50]): # Limit per block
        s = sentence.strip()
        if not s or len(s) < 10:
            continue
            
        bok = classify_basis_of_knowledge(s)
        certainty = classify_source_certainty(s)
        
        # Simple heuristic for directness
        if bok in {"DIRECT_OBSERVATION", "DIRECT_PARTICIPATION"}:
            directness = "FIRSTHAND"
        elif bok in {"HEARD_FROM_NAMED_SOURCE", "HEARD_FROM_UNNAMED_SOURCE", "RUMOR"}:
            directness = "SECONDHAND"
        elif bok in {"INFERENCE", "ASSUMPTION"}:
            directness = "INFERRED"
        else:
            directness = "UNKNOWN"
            
        # Extract simple SVO structure heuristically
        # This is a simplified parser; real NLP would be better but stdlib only here.
        words = s.split()
        subject = words[0] if words else "Unknown"
        predicate = " ".join(words[1:-1]) if len(words) > 2 else "stated"
        obj = words[-1] if words else "Unknown"
        
        claim_id = f"CLM-{uuid.uuid4()}"
        add_claim(
            parsed,
            claim_id=claim_id,
            source_id=source_id,
            statement_id=statement_id,
            subject=subject,
            predicate=predicate,
            object_entity=obj,
            time_reference=(temporal or {}).get("event_time", "UNKNOWN"),
            location_reference="UNKNOWN",
            basis_of_knowledge=bok,
            certainty_expression=certainty,
            directness=directness,
            confidence="LOW", # Initial confidence always low until corroborated
        )


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:20000].lower()
    fname = normalize_text(filename)

    if "interview" in fname or "transcript" in keys or "q&a" in low:
        return "INTERVIEW_TRANSCRIPT"
    if "statement" in fname or "testimony" in keys:
        return "WITNESS_STATEMENT"
    if "source" in keys or "pseudonym" in keys:
        return "SOURCE_PROFILE"
    if "claim" in keys or "assertion" in keys:
        return "CLAIM_RECORD"
        
    return "GENERIC_JSON"


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    statement_id: str,
    parsed: Dict[str, Any],
    context: str = "",
) -> None:
    if not isinstance(rec, dict):
        return

    temporal = extract_temporal(rec)
    
    # Update Source if present
    src_pseudo = get_field(rec, ["pseudonym", "source_alias", "id"])
    if src_pseudo:
        add_source(
            parsed,
            source_id=source_id,
            pseudonym=str(src_pseudo),
            source_type=str(get_field(rec, ["type", "category"]) or "UNKNOWN"),
            role=str(get_field(rec, ["role", "title"]) or "UNKNOWN"),
            access_level=str(get_field(rec, ["access", "permission_level"]) or "UNKNOWN"),
            consent_state=str(get_field(rec, ["consent", "agreement_status"]) or "CONSENT_UNCLEAR"),
        )

    # Add Statement if content exists
    content = get_field(rec, ["content", "text", "quote", "body", "statement"])
    if content:
        add_statement(
            parsed,
            statement_id=statement_id,
            source_id=source_id,
            interview_id=get_field(rec, ["interview_id"]),
            content=str(content),
            timestamp=str(get_field(rec, ["timestamp", "time", "date"]) or ""),
            speaker=str(get_field(rec, ["speaker", "who"]) or ""),
            verbatim_flag=bool(get_field(rec, ["verbatim", "exact_quote"]) or True),
        )
        
        # Process text for claims
        process_text_block(
            str(content),
            source_id,
            statement_id,
            parsed,
            context=context or "json_content",
            temporal=temporal,
        )
        
    # If explicit claims are provided
    claims_list = get_field(rec, ["claims", "assertions"], as_list=True)
    if isinstance(claims_list, list):
        for c_item in claims_list:
            if isinstance(c_item, dict):
                add_claim(
                    parsed,
                    claim_id=f"CLM-{uuid.uuid4()}",
                    source_id=source_id,
                    statement_id=statement_id,
                    subject=str(c_item.get("subject", "Unknown")),
                    predicate=str(c_item.get("predicate", "claimed")),
                    object_entity=str(c_item.get("object", "Unknown")),
                    time_reference=str(c_item.get("time", "UNKNOWN")),
                    location_reference=str(c_item.get("location", "UNKNOWN")),
                    basis_of_knowledge=str(c_item.get("basis", "UNKNOWN")),
                    certainty_expression=str(c_item.get("certainty", "UNKNOWN")),
                    directness=str(c_item.get("directness", "UNKNOWN")),
                    confidence=str(c_item.get("confidence", "LOW")),
                )


def walk_json(
    data: Any,
    source_id: str,
    statement_id: str,
    parsed: Dict[str, Any],
    depth: int = 0,
    path: str = "",
) -> None:
    if depth > 14 or len(parsed.get("observations", [])) > 200000:
        return

    if isinstance(data, dict):
        process_json_record(data, source_id, statement_id, parsed, context=path or "json")
        for k, v in data.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_json(v, source_id, statement_id, parsed, depth + 1, new_path)
    elif isinstance(data, list):
        for item in data[:100000]:
            walk_json(item, source_id, statement_id, parsed, depth + 1, path)
    elif isinstance(data, str):
        process_text_block(data, source_id, statement_id, parsed, context=path or "json_string")


def process_json_file(path: Path, source_id: str, statement_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    data = json.loads(raw)
    kind = classify_json_payload(data, path.name)

    # Register source from file if implicit
    add_source(parsed, source_id, pseudonym=f"PSEUDO_{path.stem}", source_type=kind)
    
    walk_json(data, source_id, statement_id, parsed)
    return kind, parsed


def process_csv_file(path: Path, source_id: str, statement_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:30_000_000]
    redacted_raw, _ = redact_secrets(raw)
    kind = "CSV_HUMINT_DATA"

    add_source(parsed, source_id, pseudonym=f"PSEUDO_{path.stem}", source_type=kind)

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
            process_json_record(row, source_id, statement_id, parsed, context=f"csv_row_{idx}")

    return kind, parsed


def process_text_file(path: Path, source_id: str, statement_id: str) -> Tuple[str, Dict[str, Any]]:
    parsed = empty_parsed()
    raw = path.read_text(encoding="utf-8", errors="replace")[:10_000_000]
    redacted_raw, _ = redact_secrets(raw)
    kind = "TEXT_TRANSCRIPT"

    add_source(parsed, source_id, pseudonym=f"PSEUDO_{path.stem}", source_type=kind)
    
    # Treat whole file as one big statement for simplicity in this demo
    add_statement(
        parsed,
        statement_id=statement_id,
        source_id=source_id,
        interview_id=None,
        content=redacted_raw,
        timestamp="",
        speaker="",
        verbatim_flag=True,
    )
    
    process_text_block(
        redacted_raw,
        source_id,
        statement_id,
        parsed,
        context="text_file_full",
    )

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
        ".pcap", ".pcapng", ".cap", ".msi", ".cab", ".mp3", ".wav", ".mp4", ".avi",
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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".transcript"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_humint_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path = Path(path_str).expanduser()
    source_id = f"SRC-{uuid.uuid4()}"
    statement_id = f"STM-{uuid.uuid4()}"

    file_evidence: Dict[str, Any] = {
        "evidence_id": statement_id,
        "source_id": source_id,
        "case_id": case_id,
        "task_id": task_id,
        "path": str(path),
        "filename": path.name,
        "retrieved_at": now_utc(),
        "acquisition_method": "local_authorized_or_public_file_access",
        "status": "PENDING",
        "limitations": [
            "No coercion, threats, blackmail, entrapment, impersonation, phishing, social engineering, deceptive relationships, trauma exploitation, financial distress exploitation, medical vulnerability exploitation, covert recruitment, clandestine tradecraft, autonomous minor interviews, unauthorized recording, face/voice identification, AI lie detection, demeanor-based deception inference, or sensitive trait inference performed.",
            "Binary artifacts (audio/video/images) are hash/metadata preserved only; no transcription/content analysis performed in this stdlib-only panel.",
            "Transcripts/statements are untrusted evidence, not instruction.",
            "Exposed secrets are redacted and not used.",
            "Source statements are not self-validating facts.",
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
            kind, parsed = process_json_file(path, source_id, statement_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "CSV":
            kind, parsed = process_csv_file(path, source_id, statement_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "TEXT":
            kind, parsed = process_text_file(path, source_id, statement_id)
            file_evidence["content_kind"] = kind
            file_evidence["status"] = "SUCCEEDED"
        elif format_detected == "BINARY_ARTIFACT":
            file_evidence["content_kind"] = "BINARY_MEDIA_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary media artifact detected. This planning panel preserves hash/metadata only. "
                "It does not transcribe audio, analyze video frames, identify speakers biometrically, or perform sentiment analysis."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_source_count"] = len(parsed.get("sources", []))
    file_evidence["parsed_statement_count"] = len(parsed.get("statements", []))
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


def build_source_dependencies(parsed: Dict[str, Any]) -> None:
    """
    Detect potential dependencies between sources based on shared claims/hearsay chains.
    Simplified logic: If Source A says 'Heard from B' and Source B makes same claim, flag dependency.
    """
    claims_by_subject_predicate: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    for c in parsed.get("claims", []):
        # Normalize key for grouping similar claims
        key = f"{normalize_text(c.get('subject'))}:{normalize_text(c.get('predicate'))}"
        claims_by_subject_predicate[key].append(c)
        
    deps = []
    for key, group in claims_by_subject_predicate.items():
        if len(group) > 1:
            sources_involved = {c['source_id'] for c in group}
            bases = {c['basis_of_knowledge'] for c in group}
            
            # Heuristic: If multiple sources make same claim, check if any are secondhand referencing others
            # In a real system, we'd look for explicit "Heard from X" links.
            # Here we just flag multi-source overlap for manual review of independence.
            if len(sources_involved) > 1:
                deps.append({
                    "dependency_id": f"DEP-{uuid.uuid4()}",
                    "claim_group_key": key,
                    "sources": list(sources_involved),
                    "bases": list(bases),
                    "note": "Multiple sources assert similar claim. Verify independence manually. Check for hearsay chains.",
                    "state": "POTENTIAL_DEPENDENCY_CANDIDATE",
                })
                
    parsed["source_dependencies"] = deps


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []
    
    # Group claims by subject/object to find conflicting predicates or times
    claims_by_topic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in parsed.get("claims", []):
        topic = f"{normalize_text(c.get('subject'))}-{normalize_text(c.get('object'))}"
        claims_by_topic[topic].append(c)
        
    for topic, group in claims_by_topic.items():
        if len(group) < 2:
            continue
            
        # Check for time conflicts
        times = {c.get("time_reference") for c in group if c.get("time_reference")}
        if len(times) > 1:
             # Only flag if significantly different (simple string diff for demo)
             contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "TEMPORAL_CONTRADICTION",
                "subject": topic,
                "values": list(times)[:10],
                "possible_explanations": [
                    "Memory error",
                    "Different events confused",
                    "Timeline ambiguity",
                    "Deception",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Inconsistency does not automatically prove lying.",
            })
            
        # Check for basis conflicts (Firsthand vs Rumor for same core event)
        bases = {c.get("basis_of_knowledge") for c in group}
        if "DIRECT_OBSERVATION" in bases and "RUMOR" in bases:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "EVIDENTIARY_WEIGHT_CONFLICT",
                "subject": topic,
                "values": list(bases),
                "possible_explanations": [
                    "One source saw it, another heard rumor",
                    "Misattribution of source",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Weigh firsthand observation higher than rumor, but verify both.",
            })

    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    claims = parsed.get("claims", [])
    
    if not claims:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Insufficient claims extracted to form hypotheses.",
            "supporting_facts": [],
            "opposing_facts": [],
            "unknowns": ["source intent", "event reality", "timeline"],
            "falsification_conditions": ["New testimony or evidence emerges."],
            "next_test": "Conduct further neutral interviews or seek documentary corroboration.",
            "status": "OPEN",
        })
        return hyps[:1000]

    # Example generic hypothesis generation based on high-volume topics
    topic_counts = Counter()
    for c in claims:
        topic_counts[c.get("subject")] += 1
        
    top_topics = topic_counts.most_common(5)
    
    for topic, count in top_topics:
        if count > 1:
            hyps.append({
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": f"Event involving '{topic}' occurred as described by sources.",
                "supporting_facts": [f"{count} claims reference this subject."],
                "opposing_facts": ["No contradictory evidence processed yet."],
                "assumptions": ["Sources are acting in good faith.", "Claims refer to same event instance."],
                "unknowns": ["Exact timing", "Actor identities", "Motivations"],
                "falsification_conditions": ["Independent telemetry contradicts account.", "Witnesses admit collusion/error."],
                "next_test": "Correlate with LOGINT/DOCINT for technical verification.",
                "status": "OPEN",
            })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    sources = parsed.get("sources", [])
    claims = parsed.get("claims", [])
    
    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized human-source evidence exists?",
            "missing_evidence": "No local HUMINT artifact supplied.",
            "likely_source": "Authorized interview transcript, witness statement, public testimony.",
            "specialist_owner": "HUMINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline human-intel planning.",
            "safety_boundary": "No coercion, impersonation, or illegal collection.",
        })

    if sources and any(s.get("consent_state") == "CONSENT_UNCLEAR" for s in sources):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Is informed consent confirmed for all sources?",
            "missing_evidence": "Consent status ambiguous.",
            "likely_source": "Signed consent forms, verbal confirmation records.",
            "specialist_owner": "Legal / Compliance / Interviewer",
            "priority": "CRITICAL_LEGAL_ETHICAL",
            "expected_information_value": "Ensures admissibility and ethical compliance.",
            "safety_boundary": "Do not proceed with unclear consent.",
        })
        
    if claims and all(c.get("basis_of_knowledge") == "UNKNOWN" for c in claims):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the basis of knowledge for these claims?",
            "missing_evidence": "Direct vs Hearsay distinction missing.",
            "likely_source": "Follow-up clarification questions.",
            "specialist_owner": "HUMINT Analyst",
            "priority": "HIGH_ANALYTICAL",
            "expected_information_value": "Determines evidentiary weight.",
            "safety_boundary": "Ask neutrally; do not lead.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    claims = parsed.get("claims", [])
    
    # Detect references to documents/logs/media
    doc_refs = [c for c in claims if c.get("basis_of_knowledge") == "DOCUMENT_SEEN"]
    sys_refs = [c for c in claims if c.get("basis_of_knowledge") == "SYSTEM_SEEN"]
    
    if doc_refs:
        handoffs.append({
            "specialist": "DOCINT",
            "reason": "Source referenced documents.",
            "expected_output": "Authenticity, content analysis, metadata verification.",
            "question": "Do referenced documents support the source's claims?",
        })
        
    if sys_refs:
        handoffs.append({
            "specialist": "LOGINT / INCIDENTINT",
            "reason": "Source referenced system logs/console.",
            "expected_output": "Telemetry correlation, timestamp verification.",
            "question": "Do authorized logs corroborate the observed events?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "HUMINT Manager",
            "reason": "No immediate specialist trigger detected.",
            "expected_output": "Review interview plan, schedule follow-ups.",
            "question": "What additional clarity is needed from sources?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    build_source_dependencies(parsed)
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
    sources = parsed.get("sources", [])
    claims = parsed.get("claims", [])
    
    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited coercion, impersonation, entrapment, or illegal collection behavior.",
            "reason": "HUMINT is lawful/consensual/ethical, not coercive/deceptive.",
            "owner": "HUMINT Manager",
            "expected_output": "Policy-compliant ethical HUMINT scope.",
        }

    if not files:
        return {
            "action": "Attach authorized interview transcripts, witness statements, or public testimonies.",
            "reason": "No HUMINT evidence available.",
            "owner": "HUMINT AI Employee",
            "expected_output": "Evidence inventory.",
        }

    if any(s.get("consent_state") == "CONSENT_UNCLEAR" for s in sources):
        return {
            "action": "Pause analysis and verify informed consent with authorized human interviewer/legal team.",
            "reason": "Ethical/Legal boundary: Unclear consent invalidates collection legitimacy.",
            "owner": "Legal / Compliance / Senior Interviewer",
            "expected_output": "Confirmed consent state or withdrawal.",
        }

    if claims and all(c.get("basis_of_knowledge") == "UNKNOWN" for c in claims):
        return {
            "action": "Design neutral follow-up questions to clarify basis of knowledge (Firsthand vs Hearsay).",
            "reason": "Analytical rigor requires distinguishing observation from inference/rumor.",
            "owner": "HUMINT Analyst",
            "expected_output": "Refined claim objects with BoK tags.",
        }

    return {
        "action": "Proceed with corroboration planning against DOCINT/LOGINT and contradiction resolution.",
        "reason": "Baseline claims extracted; next step is external validation.",
        "owner": "HUMINT / CTI / INCIDENTINT",
        "expected_output": "Corroborated or Disputed Fact Set.",
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
    has_sources = bool(parsed.get("sources"))
    has_claims = bool(parsed.get("claims"))
    has_consents = any(s.get("consent_state") != "CONSENT_UNCLEAR" for s in parsed.get("sources", []))

    def add(operation: str, tool: str, purpose: str, status: str, expected_output: str, safety_risk: str = "LOW", policy_note: str = "Lawful / Consensual / Ethical.") -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General HUMINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": policy_note,
            "authorization_status": "ALLOWED_LAWFUL_CONSENSUAL",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "verify_consent_and_legality",
        "Legal / Compliance / Interviewer",
        "Ensure all sources provided informed consent and collection was lawful.",
        "COMPLETED_LOCAL" if has_consents else "REQUIRED_BEFORE_COLLECTION",
        "Consent audit trail.",
        safety_risk="CRITICAL_IF_MISSING",
        policy_note="No unethical/coercive methods.",
    )

    add(
        "preserve_verbatim_transcripts",
        "Local Parser",
        "Hash and store original transcripts without alteration.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Immutable evidence objects.",
    )

    add(
        "extract_atomic_claims",
        "Local Analyzer",
        "Decompose narratives into discrete, testable assertions.",
        "COMPLETED_LOCAL" if has_claims else "PLANNED_ANALYTIC",
        "Claim objects with BoK/Directness.",
        safety_risk="MEDIUM_IF_OVER_INTERPRETED",
        policy_note="Separate observation from inference.",
    )

    add(
        "map_source_dependencies",
        "Graph Builder",
        "Identify hearsay chains and shared upstream sources.",
        "PLANNED_ANALYTIC",
        "Dependency graph showing lack of independence.",
        safety_risk="HIGH_IF_FALSE_INDEPENDENCE_ASSUMED",
        policy_note="Three people repeating one rumor is one source.",
    )

    add(
        "plan_neutral_followups",
        "HUMINT Analyst",
        "Generate open-ended, non-leading questions to clarify ambiguities.",
        "PLANNED_ANALYTIC",
        "Question bank for next interview cycle.",
        safety_risk="HIGH_IF_LEADING",
        policy_note="Avoid contaminating memory.",
    )

    add(
        "trigger_specialist_corroboration",
        "DOCINT / LOGINT / IMINT",
        "Hand off document/log references for technical verification.",
        "PLANNED_HANDOFF",
        "External evidence reports.",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_text = " ".join(
        [
            str(payload.get("objective", "")),
            " ".join(str(q) for q in payload.get("questions", [])),
            str(payload.get("target", "")),
            " ".join(str(s) for s in payload.get("source_pseudonyms", [])),
            " ".join(str(s) for s in payload.get("interview_transcripts", [])),
            " ".join(str(s) for s in payload.get("statements", [])),
            " ".join(str(s) for s in payload.get("public_statements", [])),
        ]
    ).lower()

    blocked_reasons = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned_text, re.IGNORECASE)]

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive human-source context detected. Analysis must remain lawful, consensual, and ethical. "
            "No coercion, impersonation, entrapment, or deceptive practices."
        )

    if payload.get("consent_states") and any("WITHDRAWN" in str(c).upper() for c in payload.get("consent_states", [])):
        human_review_required = True
        safety_notes.append(
            "Consent withdrawn detected. Halt collection/analysis immediately unless legally mandated otherwise (requires senior legal review)."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to involve coercion, impersonation, entrapment, social engineering, "
                "illegal recording, or unethical manipulation of human sources."
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
                "No obvious hard policy violation detected, but sensitive human-source, consent, or vulnerability context applies. "
                "Conclusions must be reviewed by authorized humans before action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_LAWFUL_CONSENSUAL",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": "No obvious policy violation detected. Planning-only mode remains active.",
        "safe_alternatives": [],
    }


def validate_payload(payload: Dict[str, Any]) -> List[str]:
    warnings: List[str] = []

    required = ["case_id", "task_id", "objective", "target", "target_type"]
    for field in required:
        if not payload.get(field):
            warnings.append(f"Missing required field: {field}")

    if not payload.get("questions"):
        warnings.append("No HUMINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "source_pseudonyms",
        "interview_transcripts",
        "statements",
        "public_statements",
        "interview_paths",
        "statement_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No human-source evidence provided. Output remains planning-only.")

    if not payload.get("consent_states"):
        warnings.append("No consent state provided. Ethical HUMINT requires clear consent tracking.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "What exactly did the source observe versus infer?",
        "Did the source have direct access to the claimed information?",
        "Is the claim firsthand, secondhand, or rumor?",
        "How certain is the source about this statement?",
        "Does this claim contradict other sources or known evidence?",
        "What documents or logs could corroborate this statement?",
        "Are there signs of source contamination or collusion?",
        "What follow-up questions would clarify the basis of knowledge?",
    ]


class TraceAtlasHUMINTPanel(tk.Tk):
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
            foreground="#60a5fa", # Blue for Humint
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

        ttk.Label(header, text="TraceAtlas HUMINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Lawful / Consensual / Authorized / Evidence-first human-source intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT transcript/statement parsing only • "
                "No coercion / no impersonation / no entrapment / no social engineering / no AI lie detection / no demeanor analysis / no unauthorized recording / no minor interviews • "
                "Confidence != Accuracy • Reliability != Truth • Access != Proof • Multiple Witnesses != Independent Sources"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="HUMINT Task Input")
        self.notebook.add(self.output_tab, text="Output / HUMINT Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Interviews", command=self.add_interviews).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Statements", command=self.add_statements).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Public Testimony", command=self.add_public_testimony).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Doc Corroboration", command=self.add_doc_corroboration).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Log Corroboration", command=self.add_log_corroboration).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Media Corroboration", command=self.add_media_corroboration).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local HUMINT Evidence", command=self.analyze_local_humint).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate HUMINT Plan", command=self.generate_plan).pack(side="left", padx=4)
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
            fg="#bfdbfe", # Light blue text
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
        self.set_widget_value("case_id", "HUMINT-CASE-001")
        self.set_widget_value("task_id", "HUMINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Analyze lawful/consensual/authorized human-source intelligence using ethical, evidence-first HUMINT methods. "
            "Preserve originals, parse safe transcript/statement metadata deterministically, extract atomic claims, classify basis of knowledge, "
            "assess source access and firsthand vs hearsay, track consent states, map source dependencies, identify contradictions, "
            "generate competing hypotheses, and produce defensive corroboration plans without coercion, impersonation, entrapment, "
            "social engineering, AI lie detection, or unauthorized recording.",
        )
        self.set_widget_value("target", "Illustrative example.com / authorized human context")
        self.set_widget_value("target_type", "interview")
        self.set_widget_value(
            "questions",
            "\n".join(default_questions({"target": "Illustrative example.com / authorized human context"})),
        )

        for field in [
            "source_pseudonyms",
            "source_types",
            "source_roles",
            "interview_transcripts",
            "statements",
            "public_statements",
            "recording_references",
            "consent_states",
            "source_access_context",
            "known_facts",
            "known_evidence",
            "known_contradictions",
            "interview_paths",
            "statement_paths",
            "document_corroboration_paths",
            "log_corroboration_paths",
            "media_corroboration_paths",
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
                        "authorized employees",
                        "consenting witnesses",
                        "voluntary experts",
                        "public officials",
                        "journalists",
                        "customers",
                        "vendors",
                    ],
                    "prohibited_sources_and_actions": [
                        "coercion",
                        "threats",
                        "blackmail",
                        "bribery for illegal info",
                        "deception about identity",
                        "impersonation",
                        "phishing",
                        "social engineering",
                        "entrapment",
                        "psychological pressure",
                        "exploitation of trauma/vulnerability",
                        "covert recruitment",
                        "unauthorized recording",
                        "AI lie detection",
                        "demeanor analysis",
                    ],
                    "data_minimization_rules": [
                        "collect only relevant objective info",
                        "avoid unnecessary family/health/sexual/political/religious details",
                        "pseudonymize sources by default",
                        "protect confidential source identity",
                    ],
                    "authorized_use": "internal defensive/authorized ethical HUMINT analysis only",
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "authorization",
            json.dumps(
                {
                    "authorized_by": "HUMINT Manager / Chief Intelligence Manager",
                    "authorization_basis": "customer-authorized lawful/consensual/public engagement",
                    "permitted_actions": [
                        "local transcript hashing",
                        "authorized interview analysis",
                        "claim decomposition",
                        "basis-of-knowledge classification",
                        "source-dependency mapping",
                        "contradiction detection",
                        "neutral follow-up question generation",
                        "specialist handoff planning",
                    ],
                    "prohibited_actions": [
                        "coercion",
                        "impersonation",
                        "entrapment",
                        "social engineering",
                        "unauthorized recording",
                        "biometric identification",
                        "deception",
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
            "None configured. No live DocInt/LogInt/AudInt connector invoked. Planning-only for external corroboration.",
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
        payload["operating_mode"] = "PLANNING_ONLY_LAWFUL_CONSENSUAL_ETHICAL"
        payload["source_boundary"] = "LAWFUL_CONSENSUAL_AUTHORIZED_EVIDENCE_FIRST_HUMINT_ONLY"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added to {field}.")

    def add_interviews(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select interview transcript files",
            filetypes=[
                ("Transcripts", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("interview_paths", paths, "Interview Files Added")

    def add_statements(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select statement/testimony files",
            filetypes=[
                ("Statements", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("statement_paths", paths, "Statement Files Added")

    def add_public_testimony(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select public testimony files",
            filetypes=[
                ("Public Testimony", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("statement_paths", paths, "Public Testimony Files Added")

    def add_doc_corroboration(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select document corroboration files",
            filetypes=[
                ("Documents", "*.json *.csv *.tsv *.txt *.log *.pdf *.docx"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("document_corroboration_paths", paths, "Document Corroboration Files Added")

    def add_log_corroboration(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select log/telemetry corroboration files",
            filetypes=[
                ("Logs", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("log_corroboration_paths", paths, "Log Corroboration Files Added")

    def add_media_corroboration(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select media corroboration files (metadata only)",
            filetypes=[
                ("Media Metadata", "*.json *.csv *.txt"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("media_corroboration_paths", paths, "Media Corroboration Files Added")

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
                "has_sources": bool(payload.get("source_pseudonyms")),
                "has_interviews": bool(payload.get("interview_transcripts") or payload.get("interview_paths")),
                "has_statements": bool(payload.get("statements") or payload.get("statement_paths")),
                "has_consent": bool(payload.get("consent_states")),
            },
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This HUMINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only lawful/consensual alternatives.",
            )
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning(
                "Human Review Required",
                "No hard policy block detected, but sensitive human-source/consent context applies.",
            )
        else:
            messagebox.showinfo(
                "Policy Screen",
                "No obvious policy violation detected. Planning-only mode remains active.",
            )

    def analyze_local_humint(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "evidence_inventory": [],
                "sources_preview": [],
                "claims_preview": [],
                "observations": [],
                "candidate_facts": [],
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning("Policy Blocked", "Local HUMINT evidence analysis blocked by policy screen.")
            return

        path_fields = [
            "interview_paths",
            "statement_paths",
            "document_corroboration_paths",
            "log_corroboration_paths",
            "media_corroboration_paths",
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
            messagebox.showwarning("No HUMINT Evidence", "Add local authorized/lawful human-source evidence files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing local lawful/consensual HUMINT evidence. Hashing and parsing may take time...\n")
        self.notebook.select(self.output_tab)

        files: List[Dict[str, Any]] = []
        parsed_list: List[Dict[str, Any]] = []

        for p in all_paths[:30]:
            f, parsed = analyze_humint_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
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
            "Local HUMINT Evidence Analysis Complete",
            f"Processed {len(files)} evidence file(s).\n"
            f"Succeeded/partial: {succeeded}\n"
            f"Sources: {len(aggregated.get('sources', []))}\n"
            f"Statements: {len(aggregated.get('statements', []))}\n"
            f"Claims: {len(aggregated.get('claims', []))}\n"
            f"Contradictions: {len(aggregated.get('contradictions', []))}\n"
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
                "humint_collection_plan": [],
                "next_best_action": {
                    "action": "Revise task to remove prohibited coercion, impersonation, entrapment, or illegal collection behavior.",
                    "owner": "HUMINT Manager",
                    "expected_output": "Policy-compliant lawful/consensual HUMINT scope.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "HUMINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or default_questions(payload)

        if not self.parsed.get("sources") and not self.parsed.get("claims"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        files = self.analyzed_files
        parsed = self.parsed

        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, questions, files, parsed)

        overall_status = "PLANNING_ONLY"
        if policy["status"] == "HUMAN_REVIEW_REQUIRED":
            overall_status = "HUMAN_REVIEW_REQUIRED"
        if files or parsed.get("sources") or parsed.get("claims"):
            overall_status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE"

        result = {
            "mode": overall_status,
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not coerce, threaten, blackmail, entrap, impersonate, phish, socially engineer, create deceptive relationships, "
                "exploit trauma/vulnerabilities, conduct covert recruitment, provide clandestine tradecraft, interview minors autonomously, "
                "record without authorization, identify people from faces/voices, use AI as a lie detector, infer deception from demeanor, "
                "or infer sensitive traits. Local deterministic analysis is limited to hashing, safe JSON/CSV/TXT transcript/statement parsing, "
                "claim decomposition, basis-of-knowledge classification, source-access assessment, firsthand/secondhand distinction, "
                "source-dependency mapping, contradiction detection, competing hypotheses, falsification, secret redaction, prompt-injection flagging, "
                "and defensive specialist handoff planning. Live DocInt/LogInt/AudInt/VidInt enrichment, notification, legal action, and consequential "
                "conclusions remain planning-only unless configured/authorized/human-reviewed."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "evidence_inventory": files,
            "sources_preview": parsed.get("sources", [])[:300],
            "interviews_preview": parsed.get("interviews", [])[:300],
            "statements_preview": parsed.get("statements", [])[:300],
            "claims_preview": parsed.get("claims", [])[:300],
            "source_dependencies": parsed.get("source_dependencies", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "next_best_action": next_action,
            "humint_collection_plan": collection_plan,
            **self._policy_sections(),
            **self._schemas(),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "HUMINT plan generated with warnings:\n\n" + "\n".join(warnings),
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
                "statement": f"A local lawful/consensual HUMINT evidence file was accessed and hashed: {f.get('filename')}.",
                "evidence_id": f.get("evidence_id"),
                "source_id": f.get("source_id"),
                "observed_at": now_utc(),
                "extraction_method": "local_deterministic_file_hash",
                "limitations": "File hash does not prove truth, accuracy, or source honesty.",
            })

        observations.extend([
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(files)} HUMINT evidence file(s) were parsed locally.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "safe_json_csv_text_humint_parser",
                "limitations": "Parser output is normalized evidence, not verified external reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(parsed.get('sources', []))} source record(s), {len(parsed.get('statements', []))} statement record(s), and {len(parsed.get('claims', []))} claim record(s) were extracted.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_CLAIM_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "claim_extraction_normalization",
                "limitations": "Claims are source-reported, not verified facts.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": "No coercion, impersonation, entrapment, social engineering, AI lie detection, or unauthorized recording was performed.",
                "evidence_id": "LOCAL_PANEL_POLICY",
                "source_id": "LOCAL_POLICY_GUARD",
                "observed_at": now_utc(),
                "extraction_method": "lawful_consensual_ethical_policy",
                "limitations": "Planning/local deterministic panel only.",
            },
        ])

        observations, _ = truncate_list(observations, 500)

        candidate_facts: List[Dict[str, Any]] = []

        for f in files:
            if f.get("sha256"):
                candidate_facts.append({
                    "candidate_fact": f"The preserved local HUMINT evidence artifact {f.get('filename')} has SHA256 {f.get('sha256')}.",
                    "status": "SUPPORTED",
                    "evidence_ids": [f.get("evidence_id")],
                    "notes": "Supported by deterministic local hashing. Does not prove truth.",
                })

        candidate_facts.extend([
            {
                "candidate_fact": f"{len(parsed.get('claims', []))} claim candidate(s) were extracted and decomposed.",
                "status": "SUPPORTED_AS_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified truth",
                    "verified source honesty",
                    "verified event occurrence",
                    "verified actor identity",
                ],
            },
            {
                "candidate_fact": "No coercion, impersonation, entrapment, social engineering, AI lie detection, or unauthorized recording was performed.",
                "status": "SUPPORTED",
                "evidence_ids": ["LOCAL_PANEL_POLICY"],
                "notes": "Lawful/consensual/ethical planning boundary.",
            },
        ])

        candidate_facts, _ = truncate_list(candidate_facts, 200)

        fact_gate = {
            "status": "LOCAL_DETERMINISTIC_ONLY" if files or parsed.get("claims") else "NO_LOCAL_HUMINT_EVIDENCE",
            "supported": [
                "file/source existence and SHA256 hash",
                "parsed source profiles",
                "parsed statements",
                "parsed claims",
                "parsed basis-of-knowledge classifications",
                "parsed source-dependency candidates",
                "parsed contradiction candidates",
                "competing hypotheses",
                "secret redaction flags",
                "prompt-injection flags",
            ],
            "not_supported": [
                "verified truth of claims",
                "verified source honesty",
                "verified event occurrence",
                "verified actor identity",
                "verified motive",
                "coercion",
                "impersonation",
                "entrapment",
                "social engineering",
                "AI lie detection",
                "unauthorized recording",
            ],
            "safety_status": "No coercion, impersonation, entrapment, social engineering, AI lie detection, or unauthorized recording performed.",
        }

        return {
            "mode": "LOCAL_DETERMINISTIC_HUMINT_ANALYSIS",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "coercion_performed": False,
            "impersonation_performed": False,
            "entrapment_performed": False,
            "social_engineering_performed": False,
            "ai_lie_detection_performed": False,
            "unauthorized_recording_performed": False,
            "evidence_inventory": files,
            "sources_preview": parsed.get("sources", [])[:300],
            "interviews_preview": parsed.get("interviews", [])[:300],
            "statements_preview": parsed.get("statements", [])[:300],
            "claims_preview": parsed.get("claims", [])[:300],
            "source_dependencies": parsed.get("source_dependencies", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "observations": observations,
            "candidate_facts": candidate_facts,
            "fact_gate": fact_gate,
            "recommended_next_actions": next_action,
            "humint_collection_plan_preview": collection_plan[:20],
            "limitations": [
                "Only local deterministic checks were performed.",
                "No network access was performed.",
                "No coercion, impersonation, entrapment, social engineering, AI lie detection, or unauthorized recording was performed.",
                "Source confidence is not accuracy.",
                "Source reliability is not claim truth.",
                "Access is not proof.",
                "Consistency is not truth.",
                "Inconsistency is not lying.",
                "Multiple witnesses are not independent sources.",
                "Hearsay is not firsthand evidence.",
                "Role/title is not expertise.",
                "Refusal to answer is not guilt.",
                "Memory gap is not deception.",
                "Public claim of responsibility is not verified responsibility.",
                "AI agreement is not human-source corroboration.",
                "Exposed secrets were redacted heuristically and not used.",
                "Transcripts/statements were treated as untrusted evidence.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self) -> Dict[str, Any]:
        return {
            "role": {
                "employee": "HUMINT AI Employee",
                "hierarchy": [
                    "Chief Intelligence Manager",
                    "Human / Investigative Intelligence Manager",
                    "HUMINT Manager",
                    "HUMINT AI Employee",
                    "Interview / Debrief / Source / Testimony / Corroboration / Reliability / Verification Skills",
                ],
                "not": [
                    "interrogator",
                    "covert recruiter",
                    "coercive interviewer",
                    "blackmail system",
                    "deception planner",
                    "undercover operator",
                    "entrapment system",
                    "social-engineering agent",
                    "psychological manipulation system",
                    "lie detector",
                    "private-person surveillance system",
                ],
            },
            "core_principle": [
                "HUMAN STATEMENT",
                "CLAIM EXTRACTION",
                "BASIS OF KNOWLEDGE",
                "SOURCE ACCESS ASSESSMENT",
                "SOURCE RELIABILITY",
                "INFORMATION CREDIBILITY",
                "TEMPORAL CHECK",
                "INDEPENDENCE CHECK",
                "EXTERNAL CORROBORATION",
                "CONTRADICTIONS",
                "FACT GATE",
                "ANALYTICAL ASSESSMENT",
            ],
            "critical_separations": [
                "source confidence != accuracy",
                "source reliability != claim truth",
                "access != truth",
                "consistency != truth",
                "inconsistency != lying",
                "multiple witnesses != independent sources",
                "hearsay != firsthand evidence",
                "role/title != expertise",
                "refusal to answer != guilt",
                "memory gap != deception",
                "public claim of responsibility != verified responsibility",
                "AI agreement != human-source corroboration",
            ],
            "hard_restrictions": [
                "Do not coerce sources.",
                "Do not threaten sources.",
                "Do not blackmail sources.",
                "Do not bribe for illegal information.",
                "Do not deceive people about identity for access.",
                "Do not impersonate officials/employers/law enforcement/friends/family.",
                "Do not create fake romantic/employment opportunities.",
                "Do not perform phishing/social engineering.",
                "Do not solicit passwords/MFA/tokens/keys.",
                "Do not entrap subjects.",
                "Do not conduct psychological pressure campaigns.",
                "Do not exploit addiction/trauma/grief/financial/medical vulnerability.",
                "Do not target minors for intelligence collection autonomously.",
                "Do not conduct private-person stalking/unauthorized recording/covert surveillance.",
                "Do not publish private accusations autonomously.",
            ],
            "non_negotiable_rules": [
                "DO NOT COERCE.",
                "DO NOT THREATEN.",
                "DO NOT BLACKMAIL.",
                "DO NOT ENTRAP.",
                "DO NOT IMPERSONATE.",
                "DO NOT PHISH.",
                "DO NOT SOCIAL-ENGINEER CREDENTIALS.",
                "DO NOT CREATE DECEPTIVE RELATIONSHIPS.",
                "DO NOT EXPLOIT TRAUMA.",
                "DO NOT EXPLOIT FINANCIAL DISTRESS.",
                "DO NOT EXPLOIT MEDICAL VULNERABILITY.",
                "DO NOT PERFORM COVERT SOURCE RECRUITMENT.",
                "DO NOT PROVIDE CLANDESTINE TRADECRAFT.",
                "DO NOT INTERVIEW MINORS AUTONOMOUSLY.",
                "DO NOT RECORD WITHOUT REQUIRED AUTHORIZATION.",
                "DO NOT IDENTIFY PEOPLE FROM FACES OR VOICES.",
                "DO NOT USE AI AS A LIE DETECTOR.",
                "DO NOT INFER DECEPTION FROM EYE CONTACT.",
                "DO NOT INFER DECEPTION FROM NERVOUSNESS.",
                "DO NOT INFER DECEPTION FROM HESITATION.",
                "DO NOT INFER SENSITIVE TRAITS.",
                "DO NOT EQUATE SOURCE CONFIDENCE WITH ACCURACY.",
                "DO NOT EQUATE SOURCE RELIABILITY WITH CLAIM TRUTH.",
                "DO NOT EQUATE ACCESS WITH TRUTH.",
                "DO NOT EQUATE CONSISTENCY WITH TRUTH.",
                "DO NOT EQUATE INCONSISTENCY WITH LYING.",
                "DO NOT EQUATE MULTIPLE WITNESSES WITH INDEPENDENT SOURCES.",
                "DO NOT EQUATE HEARSAY WITH FIRSTHAND EVIDENCE.",
                "DO NOT EQUATE ROLE/TITLE WITH EXPERTISE.",
                "DO NOT EQUATE REFUSAL TO ANSWER WITH GUILT.",
                "DO NOT EQUATE MEMORY GAP WITH DECEPTION.",
                "DO NOT EQUATE PUBLIC CLAIM OF RESPONSIBILITY WITH VERIFIED RESPONSIBILITY.",
                "DO NOT EQUATE AI AGREEMENT WITH HUMAN-SOURCE CORROBORATION.",
                "DO NOT HIDE SOURCE DEPENDENCIES.",
                "DO NOT HIDE MEMORY LIMITATIONS.",
                "DO NOT HIDE LEADING-QUESTION RISK.",
                "DO NOT HIDE CONTRADICTIONS.",
                "DO NOT HIDE TRANSLATION UNCERTAINTY.",
                "DO NOT INVENT SOURCE STATEMENTS.",
                "DO NOT INVENT SOURCE ACCESS.",
                "DO NOT INVENT MOTIVATIONS.",
                "DO NOT INVENT IDENTITIES.",
                "DO NOT INVENT EVENTS.",
                "DO NOT OVERWRITE PRIOR TESTIMONY.",
            ],
        }

    def _schemas(self) -> Dict[str, Any]:
        return {
            "source_schema": {
                "source_id": "Unique source identifier",
                "pseudonym": "Anonymous alias",
                "source_type": "Employee/Witness/Expert/etc.",
                "role": "Job title/function",
                "access_level": "Direct/Role-Based/Indirect/None",
                "consent_state": "Confirmed/Restricted/Withdrawn/Unclear",
                "recording_consent": "Authorized/Denied/Unspecified",
                "reliability_history": "Past accuracy notes",
                "limitations": [
                    "Identity protected via pseudonymization.",
                    "Reliability is separate from claim credibility.",
                ],
            },
            "statement_schema": {
                "statement_id": "Unique statement identifier",
                "source_id": "Associated source",
                "interview_id": "Associated interview",
                "content": "Redacted verbatim or summary text",
                "timestamp": "When spoken",
                "speaker": "Who spoke",
                "verbatim_flag": "True if exact quote",
                "limitations": [
                    "Statement is raw input; claims must be decomposed.",
                    "Paraphrasing introduces bias risk.",
                ],
            },
            "claim_schema": {
                "claim_id": "Unique claim identifier",
                "source_id": "Associated source",
                "statement_id": "Associated statement",
                "subject": "Who/What",
                "predicate": "Action/State",
                "object": "Target/Result",
                "time_reference": "When",
                "location_reference": "Where",
                "basis_of_knowledge": "Direct Obs/Hearsay/Inference/Rumor",
                "certainty_expression": "Certain/Unsure/Guess",
                "directness": "Firsthand/Secondhand/Inferred",
                "corroboration_state": "Uncorroborated/Supported/Contradicted",
                "confidence": "Analyst confidence in claim validity",
                "limitations": [
                    "Claim is an assertion, not a fact.",
                    "BoK determines evidentiary weight.",
                ],
            },
            "humint_result_schema": [
                "case_id",
                "task_id",
                "objective",
                "questions",
                "source_ids",
                "interview_ids",
                "statement_ids",
                "claim_ids",
                "source_types",
                "source_roles",
                "source_access",
                "basis_of_knowledge",
                "directness",
                "consent_states",
                "handling_classification",
                "source_reliability",
                "claim_credibility",
                "source_confidence",
                "source_bias",
                "source_motivation_context",
                "source_dependencies",
                "independent_sources",
                "timeline",
                "event_sequence",
                "temporal_precision",
                "entities",
                "relationships",
                "documents_referenced",
                "technical_claims",
                "observations",
                "candidate_facts",
                "supported_facts",
                "partial_facts",
                "disputed_facts",
                "uncorroborated_claims",
                "contradictions",
                "corroboration_results",
                "hypotheses",
                "ach_matrix",
                "falsification_results",
                "interview_quality",
                "privacy_flags",
                "unknowns",
                "knowledge_gaps",
                "recommended_followups",
                "recommended_next_actions",
                "specialist_handoffs",
                "limitations",
                "status",
            ],
            "required_analyst_summary_format": [
                "SOURCE",
                "SOURCE ROLE",
                "SOURCE ACCESS",
                "CONSENT / HANDLING",
                "BASIS OF KNOWLEDGE",
                "KEY CLAIMS",
                "FIRSTHAND CLAIMS",
                "SECONDHAND CLAIMS",
                "SOURCE UNCERTAINTY",
                "TIMELINE",
                "CORROBORATED CLAIMS",
                "UNCORROBORATED CLAIMS",
                "CONTRADICTIONS",
                "SOURCE DEPENDENCIES",
                "SOURCE RELIABILITY",
                "CLAIM CREDIBILITY",
                "EXTERNAL EVIDENCE",
                "COMPETING HYPOTHESES",
                "UNKNOWN",
                "FOLLOW-UP",
                "NEXT ACTION",
            ],
        }

    def export_json(self) -> None:
        if not self.last_result:
            self.generate_plan()

        data = self.last_result or self.collect_payload()

        payload_for_name = data.get("payload") or data.get("payload_preview") or data
        case_id = payload_for_name.get("case_id", "humint")
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
            messagebox.showinfo("Export Complete", f"HUMINT JSON saved to:\n{path}")
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
            "Are you sure you want to clear all fields, analyzed HUMINT evidence, and reset defaults?",
        )
        if not confirm:
            return

        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result = {}
        self.analyzed_files = []
        self.parsed = empty_parsed()


if __name__ == "__main__":
    app = TraceAtlasHUMINTPanel()
    app.mainloop()