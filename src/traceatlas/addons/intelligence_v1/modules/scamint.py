import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import json
from .panel_state import sync_inputs, invalidate, begin_work, apply_result
import re
import csv
import hashlib
import uuid

from collections import defaultdict, Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


APP_TITLE = "TraceAtlas SCAMINT / FRAUDINT AI Employee — Defensive / Authorized / Evidence-First Fraud Intelligence Panel"
APP_VERSION = "TraceAtlas SCAMINT / FRAUDINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Person / Organization / Merchant / Domain Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "SCAMINT / FRAUDINT Questions", "text"),

    ("persons", "Persons / Victims / Suspects / Role Holders", "text"),
    ("organizations", "Organizations", "text"),
    ("companies", "Companies", "text"),
    ("brands", "Brands", "text"),
    ("merchants", "Merchants", "text"),
    ("vendors", "Vendors", "text"),
    ("suppliers", "Suppliers", "text"),

    ("domains", "Domains", "text"),
    ("emails", "Emails", "text"),
    ("phones", "Phones", "text"),
    ("handles", "Handles / Personas / Social Accounts", "text"),

    ("accounts", "Accounts", "text"),
    ("payment_accounts", "Payment Accounts", "text"),
    ("payment_instruments", "Payment Instruments", "text"),
    ("crypto_addresses", "Crypto Addresses / Wallets", "text"),
    ("wallets", "Wallets", "text"),

    ("invoices", "Invoices", "text"),
    ("transactions", "Transactions", "text"),
    ("communications", "Communications / Messages / Emails", "text"),
    ("complaints", "Complaints", "text"),
    ("victim_reports", "Victim Reports", "text"),
    ("chargebacks", "Chargebacks", "text"),
    ("refunds", "Refunds", "text"),
    ("marketplace_listings", "Marketplace Listings", "text"),

    ("incident_context", "Incident Context", "text"),
    ("breach_context", "Breach Context", "text"),
    ("credential_context", "Credential Context", "text"),

    ("evidence_paths", "General Evidence Paths", "text"),
    ("transaction_paths", "Transaction Record Paths", "text"),
    ("communication_paths", "Communication / Mailbox Export Paths", "text"),
    ("invoice_paths", "Invoice / Receipt Paths", "text"),
    ("complaint_paths", "Complaint / Victim Report Paths", "text"),
    ("marketplace_paths", "Marketplace Listing / Dispute Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (Mailbox/Payment/CRM/Case/CTI/etc.)", "text"),
]


TARGET_TYPES = [
    "fraud_case_review",
    "impersonation_analysis",
    "bec_context",
    "invoice_fraud_context",
    "payment_diversion_context",
    "merchant_fraud_context",
    "marketplace_fraud_context",
    "investment_crypto_scam_context",
    "job_recruitment_scam_context",
    "tech_support_scam_context",
    "romance_social_scam_defensive",
    "identity_synthetic_context",
    "account_takeover_context",
    "complaint_campaign_clustering",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "persons",
    "organizations",
    "companies",
    "brands",
    "merchants",
    "vendors",
    "suppliers",
    "domains",
    "emails",
    "phones",
    "handles",
    "accounts",
    "payment_accounts",
    "payment_instruments",
    "crypto_addresses",
    "wallets",
    "invoices",
    "transactions",
    "communications",
    "complaints",
    "victim_reports",
    "chargebacks",
    "refunds",
    "marketplace_listings",
    "incident_context",
    "breach_context",
    "credential_context",
    "evidence_paths",
    "transaction_paths",
    "communication_paths",
    "invoice_paths",
    "complaint_paths",
    "marketplace_paths",
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
    "fraud_case_review",
    "impersonation_analysis",
    "bec_context",
    "invoice_fraud_context",
    "payment_diversion_context",
    "merchant_fraud_context",
    "marketplace_fraud_context",
    "investment_crypto_scam_context",
    "job_recruitment_scam_context",
    "tech_support_scam_context",
    "romance_social_scam_defensive",
    "identity_synthetic_context",
    "account_takeover_context",
    "complaint_campaign_clustering",
}


NEGATION_RE = re.compile(
    r"\b(?:do not|don't|dont|must not|shall not|should not|avoid|without|never|not to|prohibit|policy blocked|safe alternative|defensive only|not for|no need to)\b",
    re.I,
)


POLICY_BLOCK_PATTERNS = [
    r"\b(?:create|write|generate|draft|produce|build)\b[^\n]{0,140}\b(?:scam|phishing lure|fraud message|social engineering campaign|impersonation persona|fake company|fake invoice|fake receipt|fake payment confirmation|deceptive website|credential harvesting page)\b",
    r"\b(?:optimize|improve|make more persuasive|enhance)\b[^\n]{0,140}\b(?:fraud|phishing|scam|social engineering|deception)\b",
    r"\b(?:forge|fabricate|counterfeit|fake)\b[^\n]{0,140}\b(?:identity document|bank document|invoice|receipt|payment confirmation|contract|certificate)\b",
    r"\b(?:steal|capture|harvest|use|reuse|apply)\b[^\n]{0,140}\b(?:credential|password|otp|mfa code|recovery code|session cookie|api key|token|private key)\b",
    r"\b(?:take over|hijack|compromise|break into)\b[^\n]{0,140}\b(?:account|mailbox|session|identity|profile)\b",
    r"\b(?:redirect|divert|routing)\b[^\n]{0,140}\b(?:payment|transfer|funds|beneficiary|wire|crypto)\b",
    r"\b(?:initiate|send|move|transfer|push)\b[^\n]{0,140}\b(?:money|funds|payment|wire|crypto|transaction)\b",
    r"\b(?:recruit|onboard|use|employ)\b[^\n]{0,140}\b(?:money mule|mule account|intermediary account|cash-out account)\b",
    r"\b(?:launder|clean|layer|mix)\b[^\n]{0,140}\b(?:money|funds|crypto|proceeds|transaction)\b",
    r"\b(?:evade|avoid|bypass|defeat)\b[^\n]{0,140}\b(?:fraud detection|aml|kyc|transaction monitoring|sanctions|regulatory reporting|security control)\b",
    r"\b(?:coach|train|help|assist)\b[^\n]{0,140}\b(?:chargeback fraud|refund fraud|marketplace manipulation|dispute abuse|payment evasion)\b",
    r"\b(?:contact|message|reply to|engage|call)\b[^\n]{0,140}\b(?:suspected scammer|fraudster|victim|merchant|bank|law enforcement|regulator)\b[^\n]{0,80}\b(?:autonomously|directly|without authorization|secretly)\b",
]


SAFE_ALTERNATIVES = [
    "Provide defensive/authorized/evidence-first fraud intelligence: preserve evidence, resolve entities, extract claims, normalize transactions/communications/invoices/complaints, test benign explanations, calculate loss deterministically, deduplicate complaints, cluster campaign candidates cautiously, and produce privacy-aware escalation recommendations.",
    "Do not create scams, write deployable phishing lures, optimize social engineering, generate impersonation personas, create fake companies/invoices/receipts/payment confirmations, steal/use credentials, take over accounts, solicit OTP/MFA/recovery codes, redirect payments, initiate transfers, recruit money mules, design laundering chains, evade AML/KYC/fraud detection, coach chargeback/refund fraud, or autonomously contact victims/suspects.",
    "Separate anomaly from fraud, complaint from verified fraud, victim report from complete factual record, chargeback from fraud, refund from fraud, account holder from operator, persona from person, domain/email/phone/handle from real person, and shared infrastructure from same actor.",
    "Use deterministic arithmetic for loss, refunds, reversals, and chargebacks. Escalate consequential legal, financial, privacy, law-enforcement, or real-person attribution decisions to authorized human/legal review.",
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
            r"access[_-]?key|auth[_-]?key|client[_-]?secret|authorization|cookie|session|credential|otp|mfa[_-]?code|recovery[_-]?code)\b"
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
    r"send\s+(?:money|funds|payment|crypto|wire)",
    r"login\s+here",
    r"execute\s+(?:script|code|command)",
    r"disable\s+(?:security|fraud|detection)\s+controls",
    r"reveal\s+(?:victim|customer|account|credential)\s+data",
    r"transfer\s+(?: funds| money| crypto)",
]


DOMAIN_RE = re.compile(r"\b(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,})\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CRYPTO_RE = re.compile(
    r"\b(?:"
    r"bc1[a-z0-9]{20,90}|"
    r"0x[a-fA-F0-9]{40}|"
    r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    r")\b"
)
INVOICE_NUMBER_RE = re.compile(r"(?i)\binvoice\s*(?:no\.?|number|#|ref)?\s*[:\-]?\s*([A-Z0-9][A-Z0-9\-_/]{2,})\b")
AMOUNT_RE = re.compile(r"(\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)")


ENTITY_ROLE_KEYS = [
    "person",
    "persons",
    "organization",
    "organizations",
    "company",
    "companies",
    "brand",
    "brands",
    "merchant",
    "merchants",
    "vendor",
    "vendors",
    "supplier",
    "suppliers",
    "persona",
    "personas",
    "account",
    "accounts",
    "payment_account",
    "payment_accounts",
    "payment_instrument",
    "payment_instruments",
    "crypto_address",
    "crypto_addresses",
    "wallet",
    "wallets",
    "email",
    "emails",
    "phone",
    "phones",
    "handle",
    "handles",
    "domain",
    "domains",
    "website",
    "websites",
    "marketplace_account",
    "marketplace_accounts",
]


COMMUNICATION_KEYS = [
    "communication",
    "communications",
    "message",
    "messages",
    "email",
    "emails",
    "thread",
    "threads",
    "chat",
    "chats",
]


TRANSACTION_KEYS = [
    "transaction",
    "transactions",
    "payment",
    "payments",
    "transfer",
    "transfers",
]


INVOICE_KEYS = [
    "invoice",
    "invoices",
    "receipt",
    "receipts",
    "bill",
    "bills",
]


COMPLAINT_KEYS = [
    "complaint",
    "complaints",
    "victim_report",
    "victim_reports",
    "report",
    "reports",
    "dispute",
    "disputes",
]


MARKETPLACE_KEYS = [
    "marketplace_listing",
    "marketplace_listings",
    "listing",
    "listings",
]


INDICATOR_KEYS = [
    "fraud_indicator",
    "fraud_indicators",
    "indicator",
    "indicators",
    "signal",
    "signals",
    "scam_signal",
    "scam_signals",
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


def extract_domain(value: Any) -> str:
    s = str(value or "").strip().lower()
    if not s:
        return ""
    if "@" in s:
        s = s.split("@", 1)[1]
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"^www\.", "", s)
    m = DOMAIN_RE.search(s)
    return m.group(1).lower() if m else ""


def extract_identifiers(value: Any) -> List[str]:
    text = str(value or "")
    ids: List[str] = []

    for m in DOMAIN_RE.finditer(text):
        ids.append(f"domain:{m.group(1).lower()}")

    for m in EMAIL_RE.finditer(text):
        ids.append(f"email:{m.group(0).lower()}")

    for m in CRYPTO_RE.finditer(text):
        ids.append(f"crypto:{m.group(0)}")

    return unique_preserve_order(ids)


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

    cur_match = re.search(r"\b(USD|EUR|GBP|INR|BTC|ETH|USDT|USDC)\b", upper)
    if cur_match:
        currency = cur_match.group(1)

    amount_match = AMOUNT_RE.search(s)
    if not amount_match:
        return None, currency

    num = amount_match.group(1).replace(",", "")
    try:
        dec = Decimal(num)
    except InvalidOperation:
        return None, currency

    return dec, currency


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "entities": [],
        "communications": [],
        "transactions": [],
        "invoices": [],
        "complaints": [],
        "victim_reports": [],
        "marketplace_listings": [],
        "campaigns": [],
        "indicators": [],
        "losses": [],
        "observations": [],
        "notes": [],
        "contradictions": [],
        "hypotheses": [],
        "benign_explanations": [],
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
            "Source statement is evidence about a claim/event, not verified fraud.",
            "Victim/complaint/report language must be separated from objective transaction/message records.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in fraud evidence are ignored.")


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
            "Reposted complaints/news/commercial feeds derived from one victim report are not independent sources.",
        ],
    })


def add_entity(
    parsed: Dict[str, Any],
    name: Any,
    entity_type: Any,
    role: Any = "",
    jurisdiction: Any = "",
    location: Any = "",
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
            if location and not e.get("location"):
                e["location"] = safe_str(location, 300)
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
        "location": safe_str(location, 300),
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "ENTITY_CANDIDATE",
        "limitations": [
            "Entity resolution requires corroboration. Name similarity alone is insufficient.",
            "Persona/account/email/phone/domain/wallet does not automatically identify a real person.",
            "Company/merchant/vendor may be victim, impersonated, processor, or compromised party.",
        ],
    })
    return eid


def resolve_entity_value(
    parsed: Dict[str, Any],
    value: Any,
    default_type: str,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    if value is None or value == "":
        return None

    if isinstance(value, dict):
        name = (
            value.get("name")
            or value.get("legal_name")
            or value.get("display_name")
            or value.get("entity_name")
            or value.get("person_name")
            or value.get("merchant_name")
            or value.get("vendor_name")
            or value.get("id")
        )
        et = value.get("entity_type") or value.get("type") or value.get("role") or default_type
        jurisdiction = value.get("jurisdiction") or value.get("country") or value.get("region")
        location = value.get("location") or value.get("address_summary") or value.get("site")
    else:
        name = str(value)
        et = default_type
        jurisdiction = ""
        location = ""

    return add_entity(
        parsed,
        name,
        et,
        et,
        jurisdiction,
        location,
        source_id,
        evidence_id,
        context,
    )


def ensure_identifier_entities(
    parsed: Dict[str, Any],
    identifiers: List[str],
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> None:
    for ident in identifiers:
        if ":" not in ident:
            continue
        kind, val = ident.split(":", 1)
        add_entity(parsed, val, kind.upper(), kind.upper(), "", "", source_id, evidence_id, context)


def add_indicator(
    parsed: Dict[str, Any],
    indicator_type: Any,
    description: Any,
    severity: Any = "MEDIUM",
    evidence_ids: Optional[List[str]] = None,
    entity_refs: Optional[List[str]] = None,
    source_id: str = "",
    evidence_id: str = "",
    context: str = "",
) -> str:
    ind_id = f"IND-{uuid.uuid4()}"
    parsed["indicators"].append({
        "indicator_id": ind_id,
        "indicator_type": safe_str(indicator_type, 100).upper() or "UNKNOWN",
        "description": safe_str(description, 500),
        "severity": safe_str(severity, 50).upper() or "MEDIUM",
        "evidence_ids": unique_preserve_order(evidence_ids or [])[:100],
        "entity_refs": unique_preserve_order(entity_refs or [])[:100],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "INDICATOR_CANDIDATE",
        "limitations": [
            "Indicator is not fraud confirmation.",
            "Benign explanations must be tested.",
        ],
    })
    return ind_id


def add_communication(
    parsed: Dict[str, Any],
    channel: Any,
    sender_identifier: Any,
    recipient_identifier: Any,
    timestamp: Any,
    thread_id: Any,
    claimed_identity: Any,
    requested_action: Any,
    claimed_reason: Any,
    payment_request_present: Any,
    credential_request_present: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    text_blob = " ".join([
        str(sender_identifier or ""),
        str(recipient_identifier or ""),
        str(claimed_identity or ""),
        str(requested_action or ""),
        str(claimed_reason or ""),
    ])
    identifiers = extract_identifiers(text_blob)
    ensure_identifier_entities(parsed, identifiers, source_id, evidence_id, context)

    comm_id = f"COMM-{uuid.uuid4()}"
    parsed["communications"].append({
        "communication_id": comm_id,
        "channel": safe_str(channel, 100).upper() or "UNKNOWN",
        "sender_identifier": safe_str(sender_identifier, 300),
        "sender_domain": extract_domain(sender_identifier),
        "recipient_identifier": safe_str(recipient_identifier, 300),
        "timestamp": safe_str(timestamp, 100),
        "thread_id": safe_str(thread_id, 200),
        "claimed_identity": safe_str(claimed_identity, 300),
        "requested_action": safe_str(requested_action, 500),
        "claimed_reason": safe_str(claimed_reason, 500),
        "payment_request_present": bool(payment_request_present),
        "credential_request_present": bool(credential_request_present),
        "identifiers": identifiers[:200],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "COMMUNICATION_SOURCE_REPORTED",
        "limitations": [
            "Message content proves that a claim was made, not that the claim is true.",
            "Display name is not email identity.",
            "DMARC/SPF/DKIM pass does not prove human sender if legitimate account was compromised.",
        ],
    })
    return comm_id


def add_transaction(
    parsed: Dict[str, Any],
    transaction_id: Any,
    payer: Any,
    payee: Any,
    amount: Any,
    currency: Any,
    transaction_time: Any,
    payment_rail: Any,
    status: Any,
    reference: Any,
    invoice_reference: Any,
    merchant: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    payer_ref = resolve_entity_value(parsed, payer, "ACCOUNT", source_id, evidence_id, f"{context}/payer") if payer else None
    payee_ref = resolve_entity_value(parsed, payee, "PAYMENT_ACCOUNT", source_id, evidence_id, f"{context}/payee") if payee else None
    merchant_ref = resolve_entity_value(parsed, merchant, "MERCHANT", source_id, evidence_id, f"{context}/merchant") if merchant else None

    parsed_amount, parsed_currency = parse_money(amount)
    if currency:
        parsed_currency = safe_str(currency, 20).upper() or parsed_currency

    identifiers = extract_identifiers(" ".join([
        str(payer or ""),
        str(payee or ""),
        str(reference or ""),
        str(invoice_reference or ""),
        str(merchant or ""),
    ]))
    ensure_identifier_entities(parsed, identifiers, source_id, evidence_id, context)

    txn_id = safe_str(transaction_id, 200) or f"TXN-{uuid.uuid4()}"

    for t in parsed["transactions"]:
        if t.get("external_transaction_id") == txn_id and t.get("source_id") == source_id:
            return t.get("transaction_record_id")

    rec_id = f"TXNR-{uuid.uuid4()}"
    parsed["transactions"].append({
        "transaction_record_id": rec_id,
        "external_transaction_id": txn_id,
        "payer_ref": payer_ref,
        "payer_display": safe_str(payer, 200),
        "payee_ref": payee_ref,
        "payee_display": safe_str(payee, 200),
        "merchant_ref": merchant_ref,
        "merchant_display": safe_str(merchant, 200),
        "amount_decimal": str(parsed_amount) if parsed_amount is not None else None,
        "amount_display": safe_str(amount, 100),
        "currency": parsed_currency or "UNKNOWN",
        "transaction_time": safe_str(transaction_time, 100),
        "payment_rail": safe_str(payment_rail, 100).upper() or "UNKNOWN",
        "status": safe_str(status, 100).upper() or "UNKNOWN",
        "reference": safe_str(reference, 200),
        "invoice_reference": safe_str(invoice_reference, 200),
        "identifiers": identifiers[:200],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "TRANSACTION_SOURCE_REPORTED",
        "limitations": [
            "Transaction record must be corroborated by primary financial source where authorized.",
            "Reversals/refunds/chargebacks must not be double-counted as additional loss.",
        ],
    })
    return rec_id


def add_invoice(
    parsed: Dict[str, Any],
    invoice_number: Any,
    issuer: Any,
    recipient: Any,
    amount: Any,
    currency: Any,
    bank_details: Any,
    invoice_date: Any,
    due_date: Any,
    line_items: Any,
    document_hash: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    issuer_ref = resolve_entity_value(parsed, issuer, "VENDOR", source_id, evidence_id, f"{context}/issuer") if issuer else None
    recipient_ref = resolve_entity_value(parsed, recipient, "ORGANIZATION", source_id, evidence_id, f"{context}/recipient") if recipient else None

    parsed_amount, parsed_currency = parse_money(amount)
    if currency:
        parsed_currency = safe_str(currency, 20).upper() or parsed_currency

    identifiers = extract_identifiers(" ".join([
        str(invoice_number or ""),
        str(issuer or ""),
        str(recipient or ""),
        str(bank_details or ""),
    ]))
    ensure_identifier_entities(parsed, identifiers, source_id, evidence_id, context)

    inv_id = safe_str(invoice_number, 200) or f"INV-{uuid.uuid4()}"
    rec_id = f"INVR-{uuid.uuid4()}"

    parsed["invoices"].append({
        "invoice_record_id": rec_id,
        "invoice_number": inv_id,
        "issuer_ref": issuer_ref,
        "issuer_display": safe_str(issuer, 200),
        "recipient_ref": recipient_ref,
        "recipient_display": safe_str(recipient, 200),
        "amount_decimal": str(parsed_amount) if parsed_amount is not None else None,
        "amount_display": safe_str(amount, 100),
        "currency": parsed_currency or "UNKNOWN",
        "bank_details": safe_str(bank_details, 500),
        "invoice_date": safe_str(invoice_date, 100),
        "due_date": safe_str(due_date, 100),
        "line_items": unique_preserve_order(listify(line_items))[:200],
        "document_hash": safe_str(document_hash, 120),
        "identifiers": identifiers[:200],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "INVOICE_SOURCE_REPORTED",
        "limitations": [
            "Invoice existence does not prove payment.",
            "Document mismatch is an indicator, not fraud proof.",
            "Metadata can be edited/stripped/regenerated.",
        ],
    })
    return rec_id


def add_complaint_or_report(
    parsed: Dict[str, Any],
    record_type: str,
    complaint_id: Any,
    subject_entity: Any,
    complainant_pseudonym: Any,
    complaint_type: Any,
    event_date: Any,
    report_date: Any,
    claimed_loss: Any,
    channel: Any,
    narrative: Any,
    evidence_references: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    subject_ref = resolve_entity_value(parsed, subject_entity, "MERCHANT", source_id, evidence_id, f"{context}/subject") if subject_entity else None

    parsed_loss, loss_currency = parse_money(claimed_loss)
    identifiers = extract_identifiers(" ".join([
        str(subject_entity or ""),
        str(complaint_id or ""),
        str(channel or ""),
        str(narrative or ""),
    ]))
    ensure_identifier_entities(parsed, identifiers, source_id, evidence_id, context)

    rec_id = f"{'CMP' if record_type == 'COMPLAINT' else 'VR'}-{uuid.uuid4()}"
    fingerprint = sha256_text("|".join([
        normalize_text(subject_entity),
        normalize_text(event_date),
        normalize_text(report_date),
        normalize_text(claimed_loss),
        content_fingerprint(str(narrative or "")),
    ]))

    obj = {
        "record_id": rec_id,
        "record_type": record_type,
        "external_complaint_id": safe_str(complaint_id, 200),
        "subject_ref": subject_ref,
        "subject_display": safe_str(subject_entity, 200),
        "complainant_pseudonym": safe_str(complainant_pseudonym, 200),
        "complaint_type": safe_str(complaint_type, 100).upper() or "UNKNOWN",
        "event_date": safe_str(event_date, 100),
        "report_date": safe_str(report_date, 100),
        "claimed_loss_decimal": str(parsed_loss) if parsed_loss is not None else None,
        "claimed_loss_display": safe_str(claimed_loss, 100),
        "loss_currency": loss_currency or "UNKNOWN",
        "channel": safe_str(channel, 100),
        "narrative_redacted": safe_str(narrative, 1000),
        "evidence_references": unique_preserve_order(listify(evidence_references))[:100],
        "identifiers": identifiers[:200],
        "fingerprint": fingerprint,
        "duplicate_count": 1,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "COMPLAINT_SOURCE_REPORTED" if record_type == "COMPLAINT" else "VICTIM_REPORT_SOURCE_REPORTED",
        "limitations": [
            "Complaint/victim report establishes that a report exists, not verified fraud.",
            "Victims may misremember sequence/time/amount/channel; this does not imply dishonesty.",
            "Reposted complaints across platforms may be dependent sources.",
        ],
    }

    if record_type == "COMPLAINT":
        parsed["complaints"].append(obj)
    else:
        parsed["victim_reports"].append(obj)

    return rec_id


def add_marketplace_listing(
    parsed: Dict[str, Any],
    listing_id: Any,
    seller_account: Any,
    buyer_account: Any,
    product: Any,
    price: Any,
    platform: Any,
    status: Any,
    delivery_evidence: Any,
    dispute: Any,
    source_id: str,
    evidence_id: str,
    context: str = "",
) -> Optional[str]:
    seller_ref = resolve_entity_value(parsed, seller_account, "MARKETPLACE_ACCOUNT", source_id, evidence_id, f"{context}/seller") if seller_account else None
    buyer_ref = resolve_entity_value(parsed, buyer_account, "MARKETPLACE_ACCOUNT", source_id, evidence_id, f"{context}/buyer") if buyer_account else None
    platform_ref = resolve_entity_value(parsed, platform, "ORGANIZATION", source_id, evidence_id, f"{context}/platform") if platform else None

    parsed_price, currency = parse_money(price)
    identifiers = extract_identifiers(" ".join([
        str(listing_id or ""),
        str(seller_account or ""),
        str(product or ""),
        str(platform or ""),
    ]))
    ensure_identifier_entities(parsed, identifiers, source_id, evidence_id, context)

    rec_id = f"MKT-{uuid.uuid4()}"
    parsed["marketplace_listings"].append({
        "marketplace_listing_id": rec_id,
        "listing_id": safe_str(listing_id, 200),
        "seller_ref": seller_ref,
        "seller_display": safe_str(seller_account, 200),
        "buyer_ref": buyer_ref,
        "buyer_display": safe_str(buyer_account, 200),
        "product": safe_str(product, 300),
        "price_decimal": str(parsed_price) if parsed_price is not None else None,
        "price_display": safe_str(price, 100),
        "currency": currency or "UNKNOWN",
        "platform_ref": platform_ref,
        "platform_display": safe_str(platform, 200),
        "status": safe_str(status, 100).upper() or "UNKNOWN",
        "delivery_evidence": safe_str(delivery_evidence, 500),
        "dispute": safe_str(dispute, 500),
        "identifiers": identifiers[:200],
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "state": "MARKETPLACE_LISTING_SOURCE_REPORTED",
        "limitations": [
            "Listing proves advertisement existed, not inventory existence.",
            "Low price alone is not scam evidence.",
        ],
    })
    return rec_id


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

    for key in ENTITY_ROLE_KEYS:
        vals = get_field(rec, [key], as_list=True)
        for val in vals:
            resolve_entity_value(parsed, val, key.upper(), source_id, evidence_id, f"{rec_ctx}/{key}")

    comm_items = get_field(rec, COMMUNICATION_KEYS, as_list=True)
    for item in comm_items:
        if isinstance(item, dict):
            add_communication(
                parsed,
                item.get("channel") or item.get("medium") or get_field(rec, ["channel"]),
                item.get("sender") or item.get("from") or item.get("sender_identifier") or get_field(rec, ["sender", "from"]),
                item.get("recipient") or item.get("to") or item.get("recipient_identifier") or get_field(rec, ["recipient", "to"]),
                item.get("timestamp") or item.get("time") or item.get("date") or get_field(rec, ["timestamp", "time", "date"]),
                item.get("thread_id") or item.get("thread") or get_field(rec, ["thread_id", "thread"]),
                item.get("claimed_identity") or item.get("display_name") or item.get("impersonated_entity") or get_field(rec, ["claimed_identity", "display_name", "impersonated_entity"]),
                item.get("requested_action") or item.get("action_requested") or get_field(rec, ["requested_action", "action_requested"]),
                item.get("claimed_reason") or item.get("reason") or item.get("subject") or get_field(rec, ["claimed_reason", "reason", "subject"]),
                item.get("payment_request_present") or bool(item.get("payment_request")) or get_field(rec, ["payment_request_present", "payment_request"]),
                item.get("credential_request_present") or bool(item.get("credential_request")) or get_field(rec, ["credential_request_present", "credential_request"]),
                source_id,
                evidence_id,
                f"{rec_ctx}/communication",
            )
        elif item:
            add_communication(
                parsed,
                "UNKNOWN",
                "",
                "",
                "",
                "",
                "",
                "",
                str(item),
                False,
                False,
                source_id,
                evidence_id,
                f"{rec_ctx}/communication_text",
            )

    if get_field(rec, ["sender", "from"]) or get_field(rec, ["recipient", "to"]) or get_field(rec, ["message_body", "body", "content"]):
        add_communication(
            parsed,
            get_field(rec, ["channel", "medium"]),
            get_field(rec, ["sender", "from", "sender_identifier"]),
            get_field(rec, ["recipient", "to", "recipient_identifier"]),
            get_field(rec, ["timestamp", "time", "date"]),
            get_field(rec, ["thread_id", "thread"]),
            get_field(rec, ["claimed_identity", "display_name", "impersonated_entity"]),
            get_field(rec, ["requested_action", "action_requested"]),
            get_field(rec, ["claimed_reason", "reason", "subject", "message_body", "body", "content"]),
            get_field(rec, ["payment_request_present", "payment_request"]),
            get_field(rec, ["credential_request_present", "credential_request"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    txn_items = get_field(rec, TRANSACTION_KEYS, as_list=True)
    for item in txn_items:
        if isinstance(item, dict):
            add_transaction(
                parsed,
                item.get("transaction_id") or item.get("id") or item.get("reference"),
                item.get("payer") or item.get("from") or item.get("from_account") or item.get("source_account"),
                item.get("payee") or item.get("to") or item.get("to_account") or item.get("destination_account"),
                item.get("amount") or item.get("value"),
                item.get("currency"),
                item.get("transaction_time") or item.get("time") or item.get("date"),
                item.get("payment_rail") or item.get("rail") or item.get("method"),
                item.get("status"),
                item.get("reference") or item.get("txn_reference"),
                item.get("invoice_reference") or item.get("invoice_id"),
                item.get("merchant"),
                source_id,
                evidence_id,
                f"{rec_ctx}/transaction",
            )

    if get_field(rec, ["amount"]) and (get_field(rec, ["payer", "from", "from_account"]) or get_field(rec, ["payee", "to", "to_account"])):
        add_transaction(
            parsed,
            get_field(rec, ["transaction_id", "id", "reference"]),
            get_field(rec, ["payer", "from", "from_account", "source_account"]),
            get_field(rec, ["payee", "to", "to_account", "destination_account"]),
            get_field(rec, ["amount", "value"]),
            get_field(rec, ["currency"]),
            get_field(rec, ["transaction_time", "time", "date"]),
            get_field(rec, ["payment_rail", "rail", "method"]),
            get_field(rec, ["status"]),
            get_field(rec, ["reference", "txn_reference"]),
            get_field(rec, ["invoice_reference", "invoice_id"]),
            get_field(rec, ["merchant"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    inv_items = get_field(rec, INVOICE_KEYS, as_list=True)
    for item in inv_items:
        if isinstance(item, dict):
            add_invoice(
                parsed,
                item.get("invoice_number") or item.get("invoice_id") or item.get("number"),
                item.get("issuer") or item.get("vendor") or item.get("seller") or item.get("from"),
                item.get("recipient") or item.get("customer") or item.get("buyer") or item.get("to"),
                item.get("amount") or item.get("total"),
                item.get("currency"),
                item.get("bank_details") or item.get("payment_instructions") or item.get("account_details"),
                item.get("invoice_date") or item.get("date"),
                item.get("due_date"),
                item.get("line_items") or item.get("items"),
                item.get("document_hash") or item.get("hash"),
                source_id,
                evidence_id,
                f"{rec_ctx}/invoice",
            )

    if get_field(rec, ["invoice_number"]) or get_field(rec, ["invoice_id"]):
        add_invoice(
            parsed,
            get_field(rec, ["invoice_number", "invoice_id", "number"]),
            get_field(rec, ["issuer", "vendor", "seller", "from"]),
            get_field(rec, ["recipient", "customer", "buyer", "to"]),
            get_field(rec, ["amount", "total"]),
            get_field(rec, ["currency"]),
            get_field(rec, ["bank_details", "payment_instructions", "account_details"]),
            get_field(rec, ["invoice_date", "date"]),
            get_field(rec, ["due_date"]),
            get_field(rec, ["line_items", "items"]),
            get_field(rec, ["document_hash", "hash"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    complaint_items = get_field(rec, COMPLAINT_KEYS, as_list=True)
    for item in complaint_items:
        if isinstance(item, dict):
            rtype = "VICTIM_REPORT" if any(k in normalize_key(str(item.get("type", ""))) for k in ["victim", "report"]) else "COMPLAINT"
            add_complaint_or_report(
                parsed,
                rtype,
                item.get("complaint_id") or item.get("report_id") or item.get("id"),
                item.get("subject_entity") or item.get("subject") or item.get("merchant") or item.get("vendor") or item.get("company"),
                item.get("complainant_pseudonym") or item.get("complainant") or item.get("victim_pseudonym"),
                item.get("complaint_type") or item.get("type") or item.get("category"),
                item.get("event_date") or item.get("incident_date"),
                item.get("report_date") or item.get("submitted_at"),
                item.get("claimed_loss") or item.get("loss_amount") or item.get("amount"),
                item.get("channel") or item.get("source_channel"),
                item.get("narrative") or item.get("description") or item.get("text"),
                item.get("evidence_references") or item.get("evidence_ids"),
                source_id,
                evidence_id,
                f"{rec_ctx}/complaint",
            )

    if get_field(rec, ["complaint_id"]) or get_field(rec, ["victim_report_id"]) or get_field(rec, ["complaint_type"]):
        add_complaint_or_report(
            parsed,
            "VICTIM_REPORT" if get_field(rec, ["victim_report_id"]) else "COMPLAINT",
            get_field(rec, ["complaint_id", "victim_report_id", "report_id", "id"]),
            get_field(rec, ["subject_entity", "subject", "merchant", "vendor", "company"]),
            get_field(rec, ["complainant_pseudonym", "complainant", "victim_pseudonym"]),
            get_field(rec, ["complaint_type", "type", "category"]),
            get_field(rec, ["event_date", "incident_date"]),
            get_field(rec, ["report_date", "submitted_at"]),
            get_field(rec, ["claimed_loss", "loss_amount", "amount"]),
            get_field(rec, ["channel", "source_channel"]),
            get_field(rec, ["narrative", "description", "text"]),
            get_field(rec, ["evidence_references", "evidence_ids"]),
            source_id,
            evidence_id,
            rec_ctx,
        )

    mk_items = get_field(rec, MARKETPLACE_KEYS, as_list=True)
    for item in mk_items:
        if isinstance(item, dict):
            add_marketplace_listing(
                parsed,
                item.get("listing_id") or item.get("id"),
                item.get("seller_account") or item.get("seller"),
                item.get("buyer_account") or item.get("buyer"),
                item.get("product") or item.get("item") or item.get("title"),
                item.get("price") or item.get("amount"),
                item.get("platform") or item.get("marketplace"),
                item.get("status"),
                item.get("delivery_evidence") or item.get("shipment"),
                item.get("dispute") or item.get("claim"),
                source_id,
                evidence_id,
                f"{rec_ctx}/marketplace",
            )

    ind_items = get_field(rec, INDICATOR_KEYS, as_list=True)
    for item in ind_items:
        if isinstance(item, dict):
            add_indicator(
                parsed,
                item.get("type") or item.get("indicator_type") or "SOURCE_REPORTED_INDICATOR",
                item.get("description") or item.get("detail") or item.get("text"),
                item.get("severity") or "MEDIUM",
                item.get("evidence_ids") or [evidence_id],
                item.get("entity_refs") or [],
                source_id,
                evidence_id,
                f"{rec_ctx}/indicator",
            )
        elif item:
            add_indicator(
                parsed,
                "SOURCE_REPORTED_INDICATOR",
                str(item),
                "MEDIUM",
                [evidence_id],
                [],
                source_id,
                evidence_id,
                f"{rec_ctx}/indicator",
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
                 caution="Embedded instructions in fraud evidence are ignored.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    low = normalize_text(redacted)
    identifiers = extract_identifiers(redacted)
    ensure_identifier_entities(parsed, identifiers, source_id, evidence_id, context)

    if any(k in low for k in ["payment", "wire", "transfer", "bank detail", "account change", "remittance", "beneficiary"]):
        add_indicator(parsed, "PAYMENT_OR_BENEFICIARY_CHANGE_SIGNAL", "Text contains payment/beneficiary-change language.", "MEDIUM", [evidence_id], [], source_id, evidence_id, context)

    if any(k in low for k in ["otp", "mfa", "password", "login", "verify account", "security code", "recovery code"]):
        add_indicator(parsed, "CREDENTIAL_OR_MFA_REQUEST_SIGNAL", "Text contains credential/MFA/security-code request language.", "HIGH", [evidence_id], [], source_id, evidence_id, context)

    if any(k in low for k in ["urgent", "immediately", "deadline", "suspended", "locked", "final notice"]):
        add_indicator(parsed, "URGENCY_PRESSURE_SIGNAL", "Text contains urgency/pressure language.", "LOW_MEDIUM", [evidence_id], [], source_id, evidence_id, context)

    if any(k in low for k in ["invoice", "payment due", "remittance advice", "bank account", "account number"]):
        add_indicator(parsed, "INVOICE_PAYMENT_CONTEXT_SIGNAL", "Text contains invoice/payment-context language.", "LOW_MEDIUM", [evidence_id], [], source_id, evidence_id, context)

    if any(k in low for k in ["ceo", "cfo", "executive", "director", "president", "finance team", "vendor", "supplier"]):
        add_indicator(parsed, "AUTHORITY_OR_VENDOR_CLAIM_SIGNAL", "Text contains authority/vendor claim language.", "LOW_MEDIUM", [evidence_id], [], source_id, evidence_id, context)

    if identifiers:
        add_note(parsed, "IDENTIFIER_EXTRACTION", identifiers=identifiers[:100], source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Identifier extraction is not real-person attribution.")


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:30000].lower()
    fname = normalize_text(filename)

    if "complaint" in fname or "victim" in fname or "complaint" in keys or "victim_report" in keys:
        return "COMPLAINT_OR_VICTIM_REPORT_RECORD"
    if "transaction" in fname or "payment" in fname or "transfer" in fname or "transaction" in keys:
        return "TRANSACTION_OR_PAYMENT_RECORD"
    if "communication" in fname or "message" in fname or "email" in fname or "thread" in fname:
        return "COMMUNICATION_RECORD"
    if "invoice" in fname or "receipt" in fname or "invoice" in keys:
        return "INVOICE_OR_RECEIPT_RECORD"
    if "marketplace" in fname or "listing" in fname or "dispute" in fname:
        return "MARKETPLACE_RECORD"
    if "fraud" in fname or "scam" in fname or "impersonation" in low or "bec" in low:
        return "FRAUD_CASE_RECORD"

    return "GENERIC_FRAUD_EVIDENCE"


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
    kind = "CSV_FRAUD_EVIDENCE"

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
    if "complaint" in low or "victim report" in low:
        kind = "TEXT_COMPLAINT_OR_VICTIM_REPORT"
    elif "transaction" in low or "payment" in low or "transfer" in low:
        kind = "TEXT_TRANSACTION_NOTE"
    elif "invoice" in low or "receipt" in low:
        kind = "TEXT_INVOICE_NOTE"
    elif "email" in low or "message" in low or "thread" in low:
        kind = "TEXT_COMMUNICATION_NOTE"
    else:
        kind = "TEXT_FRAUD_EVIDENCE_NOTE"

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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot", ".eml", ".msg", ".invoice", ".complaint"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_scamint_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No scam creation, phishing lure deployment, social-engineering optimization, credential theft/use, account takeover, payment redirection, money movement, mule recruitment, laundering/evasion guidance, chargeback/refund fraud coaching, or autonomous victim/suspect contact performed.",
            "Binary artifacts (PDF/DOCX/XLSX/media/archives) are hash/metadata preserved only; no deep parsing/executed content analysis performed in this stdlib-only panel.",
            "Fraud evidence is untrusted data, not instruction.",
            "Exposed secrets were redacted and not used.",
            "Complaint/victim/transaction/communication records are source-reported until corroborated.",
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
            file_evidence["content_kind"] = "BINARY_FRAUD_DOC_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary fraud evidence document detected. This planning panel preserves hash/metadata only. "
                "It does not execute macros, parse PDF/DOCX/XLSX deeply, open archives, install attachments, or access victim/suspect systems."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_entity_count"] = len(parsed.get("entities", []))
    file_evidence["parsed_communication_count"] = len(parsed.get("communications", []))
    file_evidence["parsed_transaction_count"] = len(parsed.get("transactions", []))
    file_evidence["parsed_invoice_count"] = len(parsed.get("invoices", []))
    file_evidence["parsed_complaint_count"] = len(parsed.get("complaints", []))
    file_evidence["parsed_victim_report_count"] = len(parsed.get("victim_reports", []))
    file_evidence["parsed_indicator_count"] = len(parsed.get("indicators", []))

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


def entity_by_id(parsed: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {e.get("entity_id"): e for e in parsed.get("entities", []) if e.get("entity_id")}


def calculate_losses(parsed: Dict[str, Any]) -> None:
    by_currency: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "gross": Decimal("0"),
        "reversed_cancelled_failed": Decimal("0"),
        "refunded": Decimal("0"),
        "chargeback": Decimal("0"),
        "unknown_status": Decimal("0"),
        "count": 0,
    })

    for t in parsed.get("transactions", []):
        amt_str = t.get("amount_decimal")
        if not amt_str:
            continue
        try:
            amt = Decimal(amt_str)
        except InvalidOperation:
            continue

        cur = (t.get("currency") or "UNKNOWN").upper()
        status = (t.get("status") or "UNKNOWN").upper()
        bucket = by_currency[cur]
        bucket["count"] += 1

        if status in {"REVERSED", "CANCELLED", "FAILED"}:
            bucket["reversed_cancelled_failed"] += amt
        elif status == "REFUNDED":
            bucket["refunded"] += amt
        elif status == "CHARGEBACK":
            bucket["chargeback"] += amt
        elif status in {"POSTED", "SETTLED", "AUTHORIZED", "PENDING"}:
            bucket["gross"] += amt
        else:
            bucket["unknown_status"] += amt

    losses = []
    for cur, b in by_currency.items():
        gross = b["gross"]
        recovered_like = b["reversed_cancelled_failed"] + b["refunded"] + b["chargeback"]
        net_candidate = gross - recovered_like
        losses.append({
            "currency": cur,
            "gross_transfer_candidate": str(gross),
            "reversed_cancelled_failed": str(b["reversed_cancelled_failed"]),
            "refunded": str(b["refunded"]),
            "chargeback": str(b["chargeback"]),
            "unknown_status_amount": str(b["unknown_status"]),
            "net_verified_loss_candidate": str(net_candidate),
            "transaction_count": b["count"],
            "formula": "net_candidate = gross(posted/settled/authorized/pending) - reversed_cancelled_failed - refunded - chargeback",
            "limitations": [
                "Loss calculation depends on transaction status semantics and complete records.",
                "Attempted fraud may have zero realized loss.",
                "Refund/chargeback/reversal must not be double-counted.",
                "This is deterministic candidate arithmetic, not legal loss determination.",
            ],
        })

    parsed["losses"] = losses[:1000]


def deduplicate_complaints(parsed: Dict[str, Any]) -> None:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    all_reports = parsed.get("complaints", []) + parsed.get("victim_reports", [])

    for rec in all_reports:
        fp = rec.get("fingerprint")
        if fp:
            groups[fp].append(rec)

    for fp, group in groups.items():
        if len(group) > 1:
            for rec in group:
                rec["duplicate_count"] = len(group)
                rec["duplicate_fingerprint"] = fp
            add_note(parsed, "COMPLAINT_DUPLICATION_CANDIDATE", fingerprint=fp, count=len(group),
                     record_ids=[r.get("record_id") for r in group][:100],
                     caution="Duplicate complaints may be reposts of the same report, not independent victims.")


def build_official_identifier_sets(parsed: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[set, set]:
    official_names = set()
    official_identifiers = set()

    for key in ["organizations", "companies", "brands", "merchants", "vendors", "suppliers"]:
        for val in listify(payload.get(key, [])):
            if isinstance(val, dict):
                name = val.get("name") or val.get("legal_name") or val.get("display_name")
            else:
                name = str(val)
            if name:
                official_names.add(normalize_text(name))

    for key in ["domains", "emails"]:
        for val in listify(payload.get(key, [])):
            s = str(val).strip().lower()
            if not s:
                continue
            if key == "domains":
                official_identifiers.add(f"domain:{extract_domain(s) or s}")
            else:
                official_identifiers.add(f"email:{s}")

    for e in parsed.get("entities", []):
        if e.get("entity_type") in {"ORGANIZATION", "COMPANY", "BRAND", "MERCHANT", "VENDOR", "SUPPLIER"}:
            official_names.add(e.get("normalized_name", ""))
        if e.get("entity_type") in {"DOMAIN", "EMAIL"}:
            official_identifiers.add(f"{e.get('entity_type', '').lower()}:{e.get('normalized_name', '')}")

    official_names.discard("")
    return official_names, official_identifiers


def build_impersonation_indicators(parsed: Dict[str, Any], payload: Dict[str, Any]) -> None:
    official_names, official_identifiers = build_official_identifier_sets(parsed, payload)

    for comm in parsed.get("communications", []):
        claimed = normalize_text(comm.get("claimed_identity", ""))
        sender = str(comm.get("sender_identifier", ""))
        sender_domain = comm.get("sender_domain", "")
        sender_email = sender.lower() if "@" in sender else ""

        if not claimed:
            continue

        if claimed in official_names:
            sender_ids = set()
            if sender_domain:
                sender_ids.add(f"domain:{sender_domain}")
            if sender_email:
                sender_ids.add(f"email:{sender_email}")

            if official_identifiers and sender_ids and not (sender_ids & official_identifiers):
                add_indicator(
                    parsed,
                    "IMPERSONATION_CANDIDATE",
                    f"Communication claims identity '{comm.get('claimed_identity')}' but sender identifiers are not supported by supplied official domain/email set.",
                    "HIGH",
                    [comm.get("evidence_id", "")],
                    [],
                    comm.get("source_id", ""),
                    comm.get("evidence_id", ""),
                    comm.get("context", ""),
                )
        else:
            add_indicator(
                parsed,
                "CLAIMED_IDENTITY_UNRESOLVED",
                f"Communication claims identity '{comm.get('claimed_identity')}', but no supplied official entity match was found.",
                "MEDIUM",
                [comm.get("evidence_id", "")],
                [],
                comm.get("source_id", ""),
                comm.get("evidence_id", ""),
                comm.get("context", ""),
            )


def build_bec_invoice_indicators(parsed: Dict[str, Any], payload: Dict[str, Any]) -> None:
    authority_terms = ["ceo", "cfo", "executive", "director", "president", "finance", "accounts payable", "vendor", "supplier"]
    payment_terms = ["payment", "wire", "transfer", "bank detail", "account change", "beneficiary", "remittance", "invoice"]

    for comm in parsed.get("communications", []):
        claimed = normalize_text(comm.get("claimed_identity", ""))
        action = normalize_text(comm.get("requested_action", ""))
        reason = normalize_text(comm.get("claimed_reason", ""))
        blob = " ".join([claimed, action, reason])

        if any(t in blob for t in authority_terms) and any(t in blob for t in payment_terms):
            add_indicator(
                parsed,
                "BEC_CONTEXT_CANDIDATE",
                "Communication combines authority/vendor claim with payment/bank-change language.",
                "HIGH",
                [comm.get("evidence_id", "")],
                [],
                comm.get("source_id", ""),
                comm.get("evidence_id", ""),
                comm.get("context", ""),
            )

    invoice_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for inv in parsed.get("invoices", []):
        num = inv.get("invoice_number")
        if num:
            invoice_groups[num].append(inv)

    for num, group in invoice_groups.items():
        if len(group) > 1:
            banks = {normalize_text(g.get("bank_details", "")) for g in group if g.get("bank_details")}
            amounts = {g.get("amount_decimal") for g in group if g.get("amount_decimal")}
            if len(banks) > 1 or len(amounts) > 1:
                add_indicator(
                    parsed,
                    "INVOICE_ANOMALY_CANDIDATE",
                    f"Invoice number '{num}' appears with conflicting bank details or amounts.",
                    "HIGH",
                    [g.get("evidence_id", "") for g in group][:50],
                    [],
                    group[0].get("source_id", "") if group else "",
                    group[0].get("evidence_id", "") if group else "",
                    "invoice_duplicate_conflict",
                )


def build_campaign_candidates(parsed: Dict[str, Any]) -> None:
    mapping: Dict[str, set] = defaultdict(set)

    for coll_name in ["communications", "transactions", "invoices", "complaints", "victim_reports", "marketplace_listings"]:
        for rec in parsed.get(coll_name, []):
            rec_id = rec.get("communication_id") or rec.get("transaction_record_id") or rec.get("invoice_record_id") or rec.get("record_id") or rec.get("marketplace_listing_id")
            for ident in rec.get("identifiers", []):
                if rec_id:
                    mapping[ident].add(rec_id)

    campaigns = []
    for ident, members in mapping.items():
        if len(members) >= 2:
            campaigns.append({
                "campaign_id": f"CMPGN-{uuid.uuid4()}",
                "shared_identifier": ident,
                "member_record_ids": list(members)[:200],
                "member_count": len(members),
                "state": "POSSIBLE_CAMPAIGN",
                "limitations": [
                    "Shared identifier may reflect same campaign, shared service, processor, aggregator, recycled resource, or coincidence.",
                    "No single weak indicator proves same actor.",
                ],
            })

    parsed["campaigns"] = unique_preserve_order(campaigns)[:5000]


def build_mule_account_candidates(parsed: Dict[str, Any]) -> None:
    payee_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"count": 0, "payers": set(), "evidence_ids": []})

    for t in parsed.get("transactions", []):
        payee = t.get("payee_ref") or t.get("payee_display")
        payer = t.get("payer_ref") or t.get("payer_display")
        if not payee:
            continue
        entry = payee_map[str(payee)]
        entry["count"] += 1
        if payer:
            entry["payers"].add(str(payer))
        if t.get("evidence_id"):
            entry["evidence_ids"].append(t.get("evidence_id"))

    for payee, data in payee_map.items():
        if data["count"] >= 3 and len(data["payers"]) >= 3:
            add_indicator(
                parsed,
                "MULE_ACCOUNT_CANDIDATE",
                f"Payment account/reference '{payee}' received multiple transactions from distinct payers in parsed evidence.",
                "HIGH",
                data["evidence_ids"][:50],
                [payee],
                "DERIVED",
                "DERIVED",
                "transaction_payee_reuse",
            )


def build_contradictions(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    contradictions = []

    txn_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in parsed.get("transactions", []):
        ext = t.get("external_transaction_id")
        if ext:
            txn_groups[ext].append(t)

    for ext, group in txn_groups.items():
        if len(group) > 1:
            amounts = {g.get("amount_decimal") for g in group if g.get("amount_decimal")}
            statuses = {g.get("status") for g in group if g.get("status")}
            if len(amounts) > 1 or len(statuses) > 1:
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "TRANSACTION_RECORD_CONFLICT",
                    "subject": ext,
                    "values": {"amounts": list(amounts)[:20], "statuses": list(statuses)[:20]},
                    "possible_explanations": [
                        "Authorization/settlement pair",
                        "Reversal/refund record",
                        "Duplicate ledger copy",
                        "Different processor status semantics",
                        "Data-entry conflict",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Do not double-count loss or treat status conflict as fraud proof.",
                })

    inv_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for inv in parsed.get("invoices", []):
        num = inv.get("invoice_number")
        if num:
            inv_groups[num].append(inv)

    for num, group in inv_groups.items():
        if len(group) > 1:
            banks = {normalize_text(g.get("bank_details", "")) for g in group if g.get("bank_details")}
            amounts = {g.get("amount_decimal") for g in group if g.get("amount_decimal")}
            if len(banks) > 1 or len(amounts) > 1:
                contradictions.append({
                    "contradiction_id": f"CON-{uuid.uuid4()}",
                    "type": "INVOICE_RECORD_CONFLICT",
                    "subject": num,
                    "values": {"bank_details_count": len(banks), "amounts": list(amounts)[:20]},
                    "possible_explanations": [
                        "Corrected invoice",
                        "Duplicate submission",
                        "Different line items",
                        "Fraudulent alteration candidate",
                        "Template reuse",
                    ],
                    "resolution_status": "UNRESOLVED",
                    "caution": "Invoice mismatch is an indicator, not fraud proof.",
                })

    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_benign_explanations(parsed: Dict[str, Any]) -> None:
    explanations = []
    generic = [
        "administrative error",
        "billing error",
        "legitimate vendor banking-detail change",
        "refund or reversal",
        "legitimate new payee",
        "shared infrastructure or processor",
        "account compromise rather than account-holder intent",
        "identity mix-up",
        "customer dispute",
        "system/data lag",
        "duplicate complaint reposting",
    ]

    for ind in parsed.get("indicators", [])[:500]:
        explanations.append({
            "indicator_id": ind.get("indicator_id"),
            "indicator_type": ind.get("indicator_type"),
            "benign_explanations": generic,
            "required_disconfirming_evidence": [
                "primary transaction record",
                "authorized mailbox/header metadata",
                "independent vendor verification",
                "official company/regulatory record",
                "refund/reversal/chargeback status",
                "account ownership/operator separation evidence",
            ],
        })

    parsed["benign_explanations"] = explanations[:1000]


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    indicators = parsed.get("indicators", [])
    transactions = parsed.get("transactions", [])
    communications = parsed.get("communications", [])
    complaints = parsed.get("complaints", []) + parsed.get("victim_reports", [])
    campaigns = parsed.get("campaigns", [])

    if not indicators and not transactions and not communications and not complaints:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Current local deterministic evidence is insufficient to assess fraud, scam, impersonation, payment diversion, or campaign relationship.",
            "supporting_facts": ["No fraud-relevant records parsed."],
            "opposing_facts": [],
            "assumptions": ["Evidence may be missing, binary-only, unauthorized, or unavailable."],
            "unknowns": ["entity identity", "transaction status", "communication authenticity", "loss amount", "campaign relationship"],
            "falsification_conditions": ["New authorized/public evidence changes assessment."],
            "next_test": "Attach complaint/victim report, transaction record, communication export, invoice, marketplace dispute, or authorized mailbox metadata.",
            "status": "OPEN",
        })
        return hyps[:1000]

    if any(i.get("indicator_type") in {"IMPERSONATION_CANDIDATE", "BEC_CONTEXT_CANDIDATE"} for i in indicators):
        hyps.extend([
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Communication may be fraudulent impersonation/BEC-style deception.",
                "supporting_facts": ["Impersonation/BEC candidate indicator detected."],
                "opposing_facts": ["Sender may be legitimate; domain/email official set may be incomplete."],
                "unknowns": ["sender account control", "mailbox compromise", "authorized vendor change", "display-name spoofing"],
                "falsification_conditions": ["Independent verification confirms legitimate sender/vendor change."],
                "next_test": "Verify through authorized independent channel and mailbox/header metadata without contacting suspected actor.",
                "status": "OPEN",
            },
            {
                "hypothesis_id": f"HYP-{uuid.uuid4()}",
                "statement": "Communication may reflect legitimate vendor banking-detail change or administrative error.",
                "supporting_facts": ["Payment/beneficiary-change language alone is not fraud proof."],
                "opposing_facts": ["Impersonation candidate indicators exist."],
                "unknowns": ["vendor change process", "approval trail", "historical bank details"],
                "falsification_conditions": ["Authorized vendor records and change workflow support legitimacy."],
                "next_test": "Retrieve vendor change approval and independent vendor verification.",
                "status": "OPEN",
            },
        ])

    if any(i.get("indicator_type") == "INVOICE_ANOMALY_CANDIDATE" for i in indicators):
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Invoice may be fabricated, altered, duplicated, or simply corrected/reissued.",
            "supporting_facts": ["Invoice conflict indicator detected."],
            "opposing_facts": ["Accounting corrections and duplicate submissions are common."],
            "unknowns": ["original document", "issuer authenticity", "payment status", "document metadata integrity"],
            "falsification_conditions": ["Issuer confirms authentic invoice and payment records align."],
            "next_test": "Handoff document forensics to DOCINT/METADATAINT and verify payment through FININT/PAYMENTINT.",
            "status": "OPEN",
        })

    if campaigns:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Records may belong to a related scam/fraud campaign.",
            "supporting_facts": [f"{len(campaigns)} shared-identifier campaign candidate(s) detected."],
            "opposing_facts": ["Shared processor/hosting/aggregator can create false links."],
            "unknowns": ["operator identity", "template origin", "infrastructure control era", "account compromise"],
            "falsification_conditions": ["Identifiers are shown to be shared services or unrelated reuse."],
            "next_test": "Cluster using multiple independent indicators and preserve alternative explanations.",
            "status": "OPEN",
        })

    if complaints:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Complaint volume may reflect fraud, service failure, dispute, review campaign, or duplicate reposting.",
            "supporting_facts": [f"{len(complaints)} complaint/victim report record(s) parsed."],
            "opposing_facts": ["Complaint count alone does not prove fraud."],
            "unknowns": ["denominator", "duplicate fingerprints", "source independence", "resolution status"],
            "falsification_conditions": ["Complaints are duplicates or explained by non-fraud service issue."],
            "next_test": "Deduplicate complaints and normalize by customer/transaction denominator where available.",
            "status": "OPEN",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    entities = parsed.get("entities", [])
    comms = parsed.get("communications", [])
    txns = parsed.get("transactions", [])
    invoices = parsed.get("invoices", [])
    complaints = parsed.get("complaints", []) + parsed.get("victim_reports", [])
    indicators = parsed.get("indicators", [])
    losses = parsed.get("losses", [])

    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What lawful/authorized fraud evidence exists?",
            "missing_evidence": "No local SCAMINT/FRAUDINT artifact supplied.",
            "likely_source": "Victim report, complaint, transaction record, communication export, invoice, marketplace dispute, authorized mailbox metadata.",
            "specialist_owner": "SCAMINT / FRAUDINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables baseline fraud-review planning.",
            "safety_boundary": "No scam creation, credential use, account takeover, payment movement, or autonomous contact.",
        })

    if not entities:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Which persons, organizations, merchants, vendors, domains, emails, phones, accounts, or wallets are involved?",
            "missing_evidence": "No entity records parsed.",
            "likely_source": "Complaint metadata, transaction counterparty, communication header, invoice issuer, marketplace account.",
            "specialist_owner": "SCAMINT / CORPINT / SOCMINT / DOMAININT",
            "priority": "HIGH",
            "expected_information_value": "Establishes entity candidates without real-person attribution.",
            "safety_boundary": "Do not invent victims, scammers, accounts, or identities.",
        })

    if comms and not txns:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Did any requested payment/transfer actually occur?",
            "missing_evidence": "Transaction records missing.",
            "likely_source": "Authorized bank/payment record, processor ledger, card network record, crypto explorer where public/authorized.",
            "specialist_owner": "FININT / PAYMENTINT / CRYPTOINT",
            "priority": "HIGH",
            "expected_information_value": "Separates inducement from realized financial event.",
            "safety_boundary": "Do not initiate or redirect payments.",
        })

    if txns and not losses:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is verified gross/net loss after refunds, reversals, and chargebacks?",
            "missing_evidence": "Loss calculation inputs incomplete.",
            "likely_source": "Primary transaction status, refund/chargeback records, recovery workflow.",
            "specialist_owner": "FININT / PAYMENTINT / FRAUDINT",
            "priority": "HIGH",
            "expected_information_value": "Prevents double-counting and claimed-loss overstatement.",
            "safety_boundary": "Claimed loss is not verified loss.",
        })

    if indicators:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Which benign explanations are disconfirmed by independent evidence?",
            "missing_evidence": "Benign-explanation testing incomplete.",
            "likely_source": "Independent vendor verification, mailbox telemetry, transaction status, official company/regulatory record.",
            "specialist_owner": "FRAUDINT / LEGALINT / INCIDENTINT",
            "priority": "HIGH",
            "expected_information_value": "Reduces false fraud accusation risk.",
            "safety_boundary": "Anomaly is not fraud.",
        })

    if complaints:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are complaints independent or reposts of the same report?",
            "missing_evidence": "Source pedigree/independence unresolved.",
            "likely_source": "Original complaint timestamp, unique victim identifiers where authorized, upstream feed lineage.",
            "specialist_owner": "FRAUDINT / CTI",
            "priority": "MEDIUM_HIGH",
            "expected_information_value": "Prevents fake complaint volume.",
            "safety_boundary": "Multiple reposted complaints are not multiple independent victims.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    entities = parsed.get("entities", [])
    indicators = parsed.get("indicators", [])
    notes = parsed.get("notes", [])
    txns = parsed.get("transactions", [])
    invoices = parsed.get("invoices", [])
    comms = parsed.get("communications", [])

    if any(e.get("entity_type") in {"COMPANY", "ORGANIZATION", "MERCHANT", "VENDOR", "SUPPLIER"} for e in entities):
        handoffs.append({
            "specialist": "CORPINT",
            "reason": "Legal company/vendor/merchant identity resolution may be required.",
            "expected_output": "Legal entity resolution, registration status, parent/subsidiary context.",
            "question": "Is the claimed company/vendor/merchant tied to a legitimate legal entity or impersonated brand?",
        })

    if txns:
        handoffs.append({
            "specialist": "FININT / PAYMENTINT",
            "reason": "Transaction/payment records detected.",
            "expected_output": "Payment rail, settlement status, refund/reversal/chargeback context, verified loss.",
            "question": "Which financial events are verified, reversed, refunded, charged back, or unrecovered?",
        })

    if any(e.get("entity_type") in {"CRYPTO_ADDRESS", "WALLET"} for e in entities):
        handoffs.append({
            "specialist": "CRYPTOINT",
            "reason": "Crypto address/wallet context detected.",
            "expected_output": "Public blockchain transaction context, address clustering caveats, exchange/processer separation.",
            "question": "What blockchain events are verifiable without transferring funds or interacting with contracts?",
        })

    if any(i.get("indicator_type") in {"CREDENTIAL_OR_MFA_REQUEST_SIGNAL"} for i in indicators) or any(n.get("type") == "SECRET_REDACTION" for n in notes):
        handoffs.append({
            "specialist": "CREDINT / INCIDENTINT",
            "reason": "Credential/MFA/secret exposure context detected.",
            "expected_output": "Authorized credential rotation, session revocation, exposure assessment.",
            "question": "Are exposed credentials rotated through authorized workflow without using them?",
        })

    if comms:
        handoffs.append({
            "specialist": "INCIDENTINT / LOGINT / MAILINT",
            "reason": "Communication/mailbox context detected.",
            "expected_output": "Authorized mailbox telemetry, header analysis, compromise assessment, preservation.",
            "question": "Was mailbox/session compromised, spoofed, forwarded, or legitimately used?",
        })

    if invoices:
        handoffs.append({
            "specialist": "DOCINT / METADATAINT / IMINT",
            "reason": "Invoice/receipt document context detected.",
            "expected_output": "Document authenticity, metadata provenance, template comparison, image manipulation assessment.",
            "question": "Is the document original, altered, fabricated, or a legitimate correction?",
        })

    if any(e.get("entity_type") in {"DOMAIN", "WEBSITE"} for e in entities):
        handoffs.append({
            "specialist": "DOMAININT / DNSINT / INFRAINT / WEBINT",
            "reason": "Domain/website infrastructure context detected.",
            "expected_output": "Registration era, hosting, DNS history, lookalike analysis, control-era separation.",
            "question": "Is the domain historically/currently controlled by the claimed entity or a fraudulent registrant?",
        })

    if any(i.get("indicator_type") in {"MULE_ACCOUNT_CANDIDATE"} for i in indicators):
        handoffs.append({
            "specialist": "FININT / AML-COMPLIANCE / LEGALINT",
            "reason": "Mule-account candidate indicator detected.",
            "expected_output": "Authorized account-holder/operator separation, regulatory reporting assessment, freeze/blocking workflow.",
            "question": "Is the account compromised, coerced, shared, processor-aggregated, or under suspected intermediary control?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "SCAMINT / FRAUDINT Manager",
            "reason": "No immediate specialist trigger detected from current local deterministic evidence alone.",
            "expected_output": "Review scope, approve authorized connectors, assign evidence preservation and verification tasks.",
            "question": "What fraud-intelligence gap should be filled next?",
        })

    return handoffs


def finalize_parsed(parsed: Dict[str, Any], payload: Optional[Dict[str, Any]] = None, files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = payload or {}
    build_source_independence(parsed)
    calculate_losses(parsed)
    deduplicate_complaints(parsed)
    build_impersonation_indicators(parsed, payload)
    build_bec_invoice_indicators(parsed, payload)
    build_campaign_candidates(parsed)
    build_mule_account_candidates(parsed)
    parsed["contradictions"] = build_contradictions(parsed)
    build_benign_explanations(parsed)
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
    comms = parsed.get("communications", [])
    txns = parsed.get("transactions", [])
    invoices = parsed.get("invoices", [])
    complaints = parsed.get("complaints", []) + parsed.get("victim_reports", [])
    indicators = parsed.get("indicators", [])
    campaigns = parsed.get("campaigns", [])
    losses = parsed.get("losses", [])

    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited scam creation, phishing optimization, credential use, account takeover, payment movement, mule recruitment, laundering/evasion guidance, or autonomous contact behavior.",
            "reason": "SCAMINT/FRAUDINT is defensive fraud intelligence, not fraud operations.",
            "owner": "SCAMINT / FRAUDINT Manager",
            "expected_output": "Policy-compliant defensive fraud-review scope and question set.",
        }

    if policy.get("status") == "HUMAN_REVIEW_REQUIRED":
        return {
            "action": "Route to human fraud/legal/compliance/privacy reviewer before consequential account action, public warning, law-enforcement referral, real-person attribution, or financial recovery decision.",
            "reason": "Fraud findings can be legally and personally consequential.",
            "owner": "SCAMINT / FRAUDINT Manager",
            "expected_output": "Approved defensive verification plan, evidence gaps, and handoffs.",
        }

    if not files:
        return {
            "action": "Attach lawful/authorized/public victim report, complaint, transaction record, communication export, invoice, marketplace dispute, or authorized mailbox metadata before analysis.",
            "reason": "No SCAMINT/FRAUDINT evidence artifact is available for local deterministic analysis.",
            "owner": "SCAMINT / FRAUDINT AI Employee",
            "expected_output": "Fraud evidence inventory with hashes and provenance.",
        }

    if not entities:
        return {
            "action": "Resolve person/organization/merchant/vendor/domain/email/phone/account candidates from complaint, transaction, communication, or invoice metadata.",
            "reason": "Entity resolution is prerequisite to fraud analysis.",
            "owner": "SCAMINT / CORPINT / DOMAININT / SOCMINT",
            "expected_output": "Canonical entity candidates without real-person attribution.",
        }

    if comms and not txns:
        return {
            "action": "Retrieve authorized primary transaction/payment records to determine whether requested payment occurred.",
            "reason": "Communication claim is not financial event evidence.",
            "owner": "FININT / PAYMENTINT",
            "expected_output": "Verified transaction status and counterparty context.",
        }

    if txns and not losses:
        return {
            "action": "Complete transaction status inputs and calculate gross/refund/reversal/chargeback/net candidate deterministically.",
            "reason": "Claimed loss must be separated from verified loss.",
            "owner": "FRAUDINT / FININT / PAYMENTINT",
            "expected_output": "Transparent loss model with formulas and limitations.",
        }

    if any(i.get("indicator_type") in {"IMPERSONATION_CANDIDATE", "BEC_CONTEXT_CANDIDATE"} for i in indicators):
        return {
            "action": "Verify claimed identity through independent authorized channel and mailbox/header metadata; preserve evidence without contacting suspected actor.",
            "reason": "Impersonation/BEC hypothesis requires disconfirming legitimate-change and compromise explanations.",
            "owner": "FRAUDINT / INCIDENTINT / CORPINT",
            "expected_output": "Impersonation supported/candidate/unresolved status with evidence links.",
        }

    if invoices:
        return {
            "action": "Handoff invoice/document authenticity analysis to DOCINT/METADATAINT and verify payment status through FININT/PAYMENTINT.",
            "reason": "Invoice mismatch is an indicator, not fraud proof.",
            "owner": "DOCINT / METADATAINT / FININT",
            "expected_output": "Document authenticity and payment correlation.",
        }

    if campaigns:
        return {
            "action": "Cluster campaign candidates using multiple independent indicators and preserve shared-service alternative explanations.",
            "reason": "Shared identifier alone does not prove same actor.",
            "owner": "FRAUDINT / CTI / DOMAININT / INFRAINT",
            "expected_output": "Campaign candidate register with confidence and falsification tests.",
        }

    if complaints:
        return {
            "action": "Deduplicate complaints and assess source independence before treating volume as evidence.",
            "reason": "Reposted complaints may not be independent victims.",
            "owner": "FRAUDINT / CTI",
            "expected_output": "Independent complaint count and source pedigree.",
        }

    return {
        "action": "Proceed with benign-explanation testing, competing hypotheses, attribution ladder, privacy-preserving evidence preservation, and defensive escalation.",
        "reason": "Local evidence exists, but fraud status and real-person attribution remain source-reported until corroborated.",
        "owner": "SCAMINT / FRAUDINT / LEGALINT / INCIDENTINT as authorized",
        "expected_output": "Evidence-linked fraud report with limitations and next actions.",
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
    has_entities = bool(parsed.get("entities"))
    has_comms = bool(parsed.get("communications"))
    has_txns = bool(parsed.get("transactions"))
    has_invoices = bool(parsed.get("invoices"))
    has_complaints = bool(parsed.get("complaints") or parsed.get("victim_reports"))
    has_indicators = bool(parsed.get("indicators"))
    has_campaigns = bool(parsed.get("campaigns"))

    def add(
        operation: str,
        tool: str,
        purpose: str,
        status: str,
        expected_output: str,
        safety_risk: str = "LOW",
        policy_note: str = "Defensive / authorized / evidence-first / privacy-aware fraud intelligence only.",
    ) -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General SCAMINT/FRAUDINT planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": policy_note,
            "authorization_status": "NOT_VERIFIED",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_fraud_questions_scope",
        "SCAMINT / FRAUDINT Manager / AI Employee",
        "Convert objective into fraud questions, allowed sources, privacy boundaries, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven defensive fraud collection plan.",
        policy_note="No scam creation, phishing optimization, credential use, payment movement, or autonomous contact.",
    )

    add(
        "preserve_original_fraud_evidence",
        "local evidence store",
        "Store original messages, headers, transaction records, invoices, complaints, screenshots, and hashes without modifying originals.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "FraudEvidenceObject with SHA256 and provenance fields.",
    )

    add(
        "safe_parse_json_csv_text_fraud_metadata",
        "local deterministic parser",
        "Parse lawful/authorized/public JSON/CSV/TXT fraud metadata without executing attachments, scripts, macros, or accessing unauthorized systems.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized entities, communications, transactions, invoices, complaints, indicators, and observations.",
        safety_risk="HIGH_IF_UNTRUSTED_CONTENT_TREATED_AS_INSTRUCTION",
        policy_note="Fraud evidence is untrusted data.",
    )

    add(
        "entity_persona_account_resolution",
        "local resolver",
        "Resolve person/organization/merchant/vendor/persona/account/domain/email/phone/wallet candidates while avoiding false real-person attribution.",
        "COMPLETED_LOCAL" if has_entities else "PLANNED_REQUIRES_ENTITY_EVIDENCE",
        "Canonical entity candidates and unresolved identity flags.",
        safety_risk="HIGH_PRIVACY_SENSITIVE",
        policy_note="Persona/account/email/phone/domain/wallet != real person.",
    )

    add(
        "communication_claim_extraction",
        "local parser + AI analyst",
        "Extract claimed identity, requested action, claimed reason, payment request, and credential request separately from truth.",
        "COMPLETED_LOCAL" if has_comms else "PLANNED_REQUIRES_COMMUNICATION_EVIDENCE",
        "Communication objects with claim fields and limitations.",
        safety_risk="HIGH_IF_MESSAGE_TAKEN_AS_TRUTH",
        policy_note="Message proves claim was made, not claim is true.",
    )

    add(
        "transaction_loss_deterministic_calculation",
        "local deterministic arithmetic",
        "Normalize transactions, separate reversals/refunds/chargebacks, and compute gross/net candidate loss by currency.",
        "COMPLETED_LOCAL" if has_txns else "PLANNED_REQUIRES_TRANSACTION_EVIDENCE",
        "Transparent loss model with formulas.",
        safety_risk="HIGH_IF_DOUBLE_COUNTED",
        policy_note="Claimed loss != verified loss.",
    )

    add(
        "invoice_document_anomaly_analysis",
        "FRAUDINT / DOCINT / METADATAINT",
        "Detect invoice conflicts and handoff document authenticity analysis without treating metadata as proof.",
        "COMPLETED_LOCAL" if has_invoices else "PLANNED_ANALYTIC",
        "Invoice anomaly candidates and forensic handoffs.",
        safety_risk="MEDIUM_IF_DOCUMENT_MISMATCH_OVERCLAIMED",
        policy_note="Document mismatch is indicator, not fraud proof.",
    )

    add(
        "complaint_deduplication_source_independence",
        "local fingerprint analyzer",
        "Deduplicate complaints/victim reports and assess source pedigree/independence.",
        "COMPLETED_LOCAL" if has_complaints else "PLANNED_ANALYTIC",
        "Independent complaint count and duplicate clusters.",
        safety_risk="HIGH_IF_FAKE_VOLUME",
        policy_note="Reposted complaints are not independent victims.",
    )

    add(
        "campaign_clustering_benign_explanation_testing",
        "FRAUDINT Analyst",
        "Cluster shared infrastructure/identifiers and test benign explanations before campaign attribution.",
        "COMPLETED_LOCAL" if has_campaigns or has_indicators else "PLANNED_ANALYTIC",
        "Campaign candidates with alternative explanations.",
        safety_risk="HIGH_IF_SHARED_SERVICE_FALSE_LINK",
        policy_note="Shared infrastructure != same actor.",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_fields = [
        "objective",
        "target",
        "questions",
        "persons",
        "organizations",
        "companies",
        "brands",
        "merchants",
        "vendors",
        "suppliers",
        "domains",
        "emails",
        "phones",
        "handles",
        "accounts",
        "payment_accounts",
        "payment_instruments",
        "crypto_addresses",
        "wallets",
        "invoices",
        "transactions",
        "communications",
        "complaints",
        "victim_reports",
        "chargebacks",
        "refunds",
        "marketplace_listings",
        "incident_context",
        "breach_context",
        "credential_context",
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
            "Sensitive fraud/scam context detected. Analysis must remain defensive, authorized, evidence-first, and privacy-aware. "
            "No scam creation, phishing optimization, credential use, account takeover, payment movement, mule recruitment, laundering/evasion guidance, or autonomous contact."
        )

    if payload.get("persons") or payload.get("communications") or payload.get("victim_reports"):
        human_review_required = True
        safety_notes.append(
            "Person/communication/victim-report context detected. Apply strict privacy minimization, victim safety, and no autonomous contact."
        )

    if payload.get("transactions") or payload.get("payment_accounts") or payload.get("crypto_addresses"):
        human_review_required = True
        safety_notes.append(
            "Financial/payment/crypto context detected. Loss must be calculated deterministically and no funds may be moved."
        )

    if payload.get("credential_context") or payload.get("breach_context"):
        human_review_required = True
        safety_notes.append(
            "Credential/breach context detected. Exposed credentials must not be used; rotate through authorized workflow."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require creating scams/phishing/social engineering content, forging documents, stealing/using credentials, "
                "taking over accounts, moving/redirecting payments, recruiting mules, laundering/evasion guidance, coaching refund/chargeback fraud, "
                "or autonomously contacting victims/suspects."
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
                "No obvious hard policy violation detected, but sensitive fraud, victim, communication, financial, credential, or breach context applies. "
                "Conclusions must remain defensive, evidence-linked, privacy-aware, and human-reviewed before consequential legal/financial/privacy action."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": (
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/lawful fraud evidence or connectors are configured."
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
        warnings.append("No SCAMINT/FRAUDINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "persons",
        "organizations",
        "companies",
        "merchants",
        "vendors",
        "domains",
        "emails",
        "phones",
        "accounts",
        "payment_accounts",
        "crypto_addresses",
        "invoices",
        "transactions",
        "communications",
        "complaints",
        "victim_reports",
        "marketplace_listings",
        "evidence_paths",
        "transaction_paths",
        "communication_paths",
        "invoice_paths",
        "complaint_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No fraud evidence provided. Output remains planning-only.")

    if not payload.get("time_range"):
        warnings.append("No time range provided. Fraud events, complaints, transactions, and infrastructure control are highly temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No mailbox/payment/CRM/case/CTI connector configured. External correlation remains planning-only.")

    if payload.get("credential_context") or payload.get("breach_context"):
        warnings.append("Credential/breach context triggers no-use/no-takeover controls. Handoff rotation to CREDINT/INCIDENTINT.")

    if payload.get("transactions") or payload.get("payment_accounts"):
        warnings.append("Financial context triggers deterministic loss controls. Do not move, redirect, or initiate payments.")

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "What fraud or scam claim exists, and what exactly was reported versus objectively evidenced?",
        "Which entities are verified, unresolved, impersonated, compromised, or merely claimed?",
        "What communication or inducement occurred, and what action was requested?",
        "What transaction or financial event occurred, and what is its status?",
        "What is claimed loss, gross transfer, recovered, refunded, charged back, and net verified loss candidate?",
        "Which fraud typology or scam pattern is a candidate, and what benign explanations remain?",
        "Which complaints/victim reports are independent versus duplicates/reposts?",
        "Which infrastructure identifiers are shared, and does that support a campaign candidate or only shared service?",
        "What third-party/vendor/merchant/payment-processor context matters?",
        "What attribution ladder state is supported: event, infrastructure, account/persona, campaign, controller, real person?",
        "What defensive next action preserves evidence, prevents further loss, and avoids unauthorized contact?",
        "What remains unknown?",
    ]


class TraceAtlasSCAMINTPanel(tk.Tk):
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
            foreground="#f97316",
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

        ttk.Label(header, text="TraceAtlas SCAMINT / FRAUDINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Defensive / authorized / evidence-first / privacy-aware fraud intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT complaint/transaction/communication/invoice/marketplace parsing only • "
                "No scam creation / no phishing optimization / no credential use / no account takeover / no payment movement / no mule recruitment / no evasion guidance / no autonomous contact • "
                "Anomaly != Fraud • Complaint != Verified Fraud • Account Holder != Operator • Persona != Person • Shared Infrastructure != Same Actor"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="SCAMINT / FRAUDINT Task Input")
        self.notebook.add(self.output_tab, text="Output / Fraud Plan / Evidence")

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

        ttk.Button(buttons1, text="Add General Evidence", command=self.add_general_evidence).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Transactions", command=self.add_transactions).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Communications", command=self.add_communications).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Invoices / Receipts", command=self.add_invoices).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Complaints / Victim Reports", command=self.add_complaints).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Marketplace Records", command=self.add_marketplace).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Analyze Local SCAMINT / FRAUDINT Evidence", command=self.analyze_local_fraud).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate Fraud Plan", command=self.generate_plan).pack(side="left", padx=4)
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
            fg="#fed7aa",
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
        self.set_widget_value("case_id", "SCAMINT-CASE-001")
        self.set_widget_value("task_id", "FRAUDINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Analyze lawful/authorized/defensive scam and fraud intelligence using evidence-first, privacy-aware methods. "
            "Preserve originals, parse safe complaint/transaction/communication/invoice/marketplace metadata deterministically, resolve entities cautiously, "
            "separate claims from verified events, calculate loss with deterministic arithmetic, deduplicate complaints, test benign explanations, "
            "cluster campaign candidates conservatively, and produce defensive escalation recommendations without fraud creation, social engineering, money movement, or evasion.",
        )
        self.set_widget_value("target", "Illustrative example.com / authorized fraud-review context")
        self.set_widget_value("target_type", "fraud_case_review")
        self.set_widget_value(
            "questions",
            "\n".join(default_questions({"target": "Illustrative example.com / authorized fraud-review context"})),
        )

        for field in [
            "persons",
            "organizations",
            "companies",
            "brands",
            "merchants",
            "vendors",
            "suppliers",
            "domains",
            "emails",
            "phones",
            "handles",
            "accounts",
            "payment_accounts",
            "payment_instruments",
            "crypto_addresses",
            "wallets",
            "invoices",
            "transactions",
            "communications",
            "complaints",
            "victim_reports",
            "chargebacks",
            "refunds",
            "marketplace_listings",
            "incident_context",
            "breach_context",
            "credential_context",
            "evidence_paths",
            "transaction_paths",
            "communication_paths",
            "invoice_paths",
            "complaint_paths",
            "marketplace_paths",
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
                        "victim reports",
                        "complaints",
                        "support cases",
                        "fraud reports",
                        "authorized transaction records",
                        "authorized bank/payment records",
                        "authorized merchant data",
                        "authorized chargeback data",
                        "authorized account telemetry",
                        "authorized identity logs",
                        "authorized email-security data",
                        "authorized enterprise mailboxes",
                        "authorized CRM/ticketing records",
                        "authorized procurement data",
                        "authorized vendor records",
                        "authorized invoices",
                        "authorized ERP/accounting data",
                        "official company registries",
                        "consumer-protection databases",
                        "government advisories",
                        "regulatory actions",
                        "court findings",
                        "law-enforcement public notices",
                        "public scam warnings",
                        "public websites",
                        "public domains",
                        "public social-media posts",
                        "public marketplace listings",
                        "public crypto/blockchain data",
                        "licensed fraud intelligence",
                        "authorized security telemetry",
                        "public news/research",
                    ],
                    "prohibited_sources_and_actions": [
                        "creating scams",
                        "writing deployable phishing lures",
                        "optimizing social-engineering persuasion",
                        "generating impersonation personas",
                        "creating fake companies for fraud",
                        "fabricating invoices/receipts/payment confirmations",
                        "forging identity/bank documents",
                        "creating deceptive websites or credential-harvesting pages",
                        "stealing or using credentials",
                        "taking over accounts",
                        "soliciting OTP/MFA/recovery codes",
                        "redirecting payments",
                        "initiating money transfers",
                        "recruiting money mules",
                        "designing laundering chains",
                        "providing fraud-evasion instructions",
                        "bypassing KYC/AML/transaction monitoring",
                        "coaching chargeback/refund fraud",
                        "autonomously contacting victims or suspected scammers",
                    ],
                    "data_minimization_rules": [
                        "redact bank account/card/full phone/private email/national ID/home address/credentials in default reports",
                        "separate claimed identity from verified identity",
                        "separate account holder from account operator",
                        "preserve original evidence hashes",
                    ],
                    "authorized_use": "internal defensive/authorized fraud investigation support only",
                },
                indent=2,
            ),
        )
        self.set_widget_value("authorization", "{}")
        self.set_widget_value("source_limits", "")
        self.set_widget_value("budget", "")
        self.set_widget_value("deadline", "")
        self.set_widget_value(
            "configured_connectors",
            "None configured. No mailbox/payment/CRM/case/CTI connector invoked. Planning-only for external enrichment.",
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
        payload["operating_mode"] = "PLANNING_ONLY_DEFENSIVE_AUTHORIZED_EVIDENCE_FIRST_PRIVACY_AWARE"
        payload["source_boundary"] = "DEFENSIVE_AUTHORIZED_EVIDENCE_FIRST_PRIVACY_AWARE_SCAMINT_FRAUDINT_ONLY"
        sync_inputs(self, payload, empty_parsed)
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added to {field}.")

    def add_general_evidence(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select general fraud evidence files",
            filetypes=[
                ("Fraud evidence", "*.json *.csv *.tsv *.txt *.log *.md *.eml *.msg"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("evidence_paths", paths, "General Evidence Files Added")

    def add_transactions(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select transaction/payment record files",
            filetypes=[
                ("Transactions", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("transaction_paths", paths, "Transaction Files Added")

    def add_communications(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select communication/mailbox export files",
            filetypes=[
                ("Communications", "*.json *.csv *.tsv *.txt *.log *.md *.eml *.msg"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("communication_paths", paths, "Communication Files Added")

    def add_invoices(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select invoice/receipt files",
            filetypes=[
                ("Invoices / receipts", "*.json *.csv *.tsv *.txt *.log *.md *.invoice"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("invoice_paths", paths, "Invoice Files Added")

    def add_complaints(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select complaint/victim report files",
            filetypes=[
                ("Complaints / victim reports", "*.json *.csv *.tsv *.txt *.log *.md *.complaint"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("complaint_paths", paths, "Complaint Files Added")

    def add_marketplace(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select marketplace listing/dispute files",
            filetypes=[
                ("Marketplace records", "*.json *.csv *.tsv *.txt *.log *.md"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("marketplace_paths", paths, "Marketplace Files Added")

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
                "has_persons": bool(payload.get("persons")),
                "has_orgs": bool(payload.get("organizations") or payload.get("companies") or payload.get("merchants") or payload.get("vendors")),
                "has_communications": bool(payload.get("communications") or payload.get("communication_paths")),
                "has_transactions": bool(payload.get("transactions") or payload.get("transaction_paths")),
                "has_invoices": bool(payload.get("invoices") or payload.get("invoice_paths")),
                "has_complaints": bool(payload.get("complaints") or payload.get("victim_reports") or payload.get("complaint_paths")),
                "has_credential_context": bool(payload.get("credential_context") or payload.get("breach_context")),
            },
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This SCAMINT / FRAUDINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only defensive/authorized alternatives.",
            )
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning(
                "Human Review Required",
                "No hard policy block detected, but sensitive fraud/victim/financial/credential context applies.",
            )
        else:
            messagebox.showinfo(
                "Policy Screen",
                "No obvious policy violation detected. Planning-only mode remains active.",
            )

    def analyze_local_fraud(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "evidence_inventory": [],
                "entities_preview": [],
                "communications_preview": [],
                "transactions_preview": [],
                "invoices_preview": [],
                "complaints_preview": [],
                "observations": [],
                "candidate_facts": [],
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning("Policy Blocked", "Local SCAMINT / FRAUDINT evidence analysis blocked by policy screen.")
            return

        path_fields = [
            "evidence_paths",
            "transaction_paths",
            "communication_paths",
            "invoice_paths",
            "complaint_paths",
            "marketplace_paths",
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
            messagebox.showwarning("No SCAMINT / FRAUDINT Evidence", "Add local lawful/authorized/public fraud evidence files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing local defensive/authorized SCAMINT / FRAUDINT evidence. Hashing and parsing may take time...\n")
        self.notebook.select(self.output_tab)

        files: List[Dict[str, Any]] = []
        parsed_list: List[Dict[str, Any]] = []

        for p in all_paths[:30]:
            f, parsed = analyze_scamint_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
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
            "Local SCAMINT / FRAUDINT Evidence Analysis Complete",
            f"Processed {len(files)} evidence file(s).\n"
            f"Succeeded/partial: {succeeded}\n"
            f"Entities: {len(aggregated.get('entities', []))}\n"
            f"Communications: {len(aggregated.get('communications', []))}\n"
            f"Transactions: {len(aggregated.get('transactions', []))}\n"
            f"Invoices: {len(aggregated.get('invoices', []))}\n"
            f"Complaints/victim reports: {len(aggregated.get('complaints', [])) + len(aggregated.get('victim_reports', []))}\n"
            f"Indicators: {len(aggregated.get('indicators', []))}\n"
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
                "fraud_collection_plan": [],
                "next_best_action": {
                    "action": "Revise task to remove prohibited scam creation, phishing optimization, credential use, account takeover, payment movement, mule recruitment, laundering/evasion guidance, or autonomous contact behavior.",
                    "owner": "SCAMINT / FRAUDINT Manager",
                    "expected_output": "Policy-compliant defensive fraud-review scope and question set.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "SCAMINT / FRAUDINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or default_questions(payload)

        if not self.parsed.get("entities") and not self.parsed.get("communications") and not self.parsed.get("transactions"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        files = self.analyzed_files
        parsed = self.parsed

        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, questions, files, parsed)

        overall_status = "PLANNING_ONLY"
        if policy["status"] == "HUMAN_REVIEW_REQUIRED":
            overall_status = "HUMAN_REVIEW_REQUIRED"
        if files or parsed.get("entities") or parsed.get("communications") or parsed.get("transactions"):
            overall_status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE"

        result = {
            "mode": overall_status,
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not create scams, write deployable phishing lures, optimize social-engineering persuasion, generate impersonation personas, "
                "create fake companies/invoices/receipts/payment confirmations, forge identity/bank documents, steal/use credentials, take over accounts, "
                "solicit OTP/MFA/recovery codes, redirect payments, initiate money transfers, recruit money mules, design laundering chains, provide fraud-evasion instructions, "
                "bypass KYC/AML/transaction monitoring, coach chargeback/refund fraud, or autonomously contact victims/suspects. "
                "Local deterministic analysis is limited to hashing, safe JSON/CSV/TXT fraud metadata parsing, entity/persona/account resolution candidates, claim extraction, "
                "communication normalization, transaction normalization, deterministic loss calculation, invoice anomaly candidates, complaint deduplication, "
                "campaign candidate clustering, benign-explanation testing, source independence, contradiction detection, competing hypotheses, falsification, secret redaction, "
                "prompt-injection flagging, and defensive specialist handoff planning. "
                "Live mailbox/payment/CRM/case/CTI enrichment, account blocking, fund recovery, public accusation, law-enforcement referral, and real-person attribution remain planning-only unless configured/authorized/human-reviewed."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "evidence_inventory": files,
            "entities_preview": parsed.get("entities", [])[:300],
            "communications_preview": parsed.get("communications", [])[:300],
            "transactions_preview": parsed.get("transactions", [])[:300],
            "invoices_preview": parsed.get("invoices", [])[:300],
            "complaints_preview": parsed.get("complaints", [])[:300],
            "victim_reports_preview": parsed.get("victim_reports", [])[:300],
            "marketplace_listings_preview": parsed.get("marketplace_listings", [])[:300],
            "indicators": parsed.get("indicators", [])[:1000],
            "losses": parsed.get("losses", [])[:1000],
            "campaigns": parsed.get("campaigns", [])[:1000],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "benign_explanations": parsed.get("benign_explanations", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "next_best_action": next_action,
            "fraud_collection_plan": collection_plan,
            **self._policy_sections(),
            **self._schemas(),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "SCAMINT / FRAUDINT plan generated with warnings:\n\n" + "\n".join(warnings),
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
                "statement": f"A local defensive/authorized SCAMINT / FRAUDINT evidence file was accessed and hashed: {f.get('filename')}.",
                "evidence_id": f.get("evidence_id"),
                "source_id": f.get("source_id"),
                "observed_at": now_utc(),
                "extraction_method": "local_deterministic_file_hash",
                "limitations": "File hash does not prove fraud, identity, transaction legitimacy, or loss.",
            })

        observations.extend([
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(files)} SCAMINT / FRAUDINT evidence file(s) were parsed locally.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "safe_json_csv_text_fraud_parser",
                "limitations": "Parser output is normalized evidence, not verified external reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": (
                    f"{len(parsed.get('entities', []))} entity record(s), "
                    f"{len(parsed.get('communications', []))} communication record(s), "
                    f"{len(parsed.get('transactions', []))} transaction record(s), "
                    f"{len(parsed.get('invoices', []))} invoice record(s), "
                    f"{len(parsed.get('complaints', []) + parsed.get('victim_reports', []))} complaint/victim-report record(s), and "
                    f"{len(parsed.get('indicators', []))} indicator record(s) were extracted."
                ),
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_FRAUD_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "entity_communication_transaction_invoice_complaint_indicator_extraction",
                "limitations": "Source-reported fraud records are not verified fraud or legal findings.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": "No scam creation, phishing optimization, credential use, account takeover, payment movement, mule recruitment, laundering/evasion guidance, or autonomous contact was performed.",
                "evidence_id": "LOCAL_PANEL_POLICY",
                "source_id": "LOCAL_POLICY_GUARD",
                "observed_at": now_utc(),
                "extraction_method": "defensive_privacy_aware_policy",
                "limitations": "Planning/local deterministic panel only.",
            },
        ])

        observations, _ = truncate_list(observations, 500)

        candidate_facts: List[Dict[str, Any]] = []

        for f in files:
            if f.get("sha256"):
                candidate_facts.append({
                    "candidate_fact": f"The preserved local SCAMINT / FRAUDINT evidence artifact {f.get('filename')} has SHA256 {f.get('sha256')}.",
                    "status": "SUPPORTED",
                    "evidence_ids": [f.get("evidence_id")],
                    "notes": "Supported by deterministic local hashing. Does not prove fraud or identity.",
                })

        candidate_facts.extend([
            {
                "candidate_fact": f"{len(parsed.get('indicators', []))} fraud indicator candidate(s) were extracted or derived.",
                "status": "SUPPORTED_AS_INDICATOR_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified fraud",
                    "verified real-person attribution",
                    "verified account operator",
                    "verified loss",
                    "verified campaign actor",
                ],
            },
            {
                "candidate_fact": "No scam creation, phishing optimization, credential use, account takeover, payment movement, mule recruitment, laundering/evasion guidance, or autonomous contact was performed.",
                "status": "SUPPORTED",
                "evidence_ids": ["LOCAL_PANEL_POLICY"],
                "notes": "Defensive/privacy-aware planning boundary.",
            },
        ])

        candidate_facts, _ = truncate_list(candidate_facts, 200)

        fact_gate = {
            "status": "LOCAL_DETERMINISTIC_ONLY" if files or parsed.get("entities") or parsed.get("communications") or parsed.get("transactions") else "NO_LOCAL_SCAMINT_FRAUDINT_EVIDENCE",
            "supported": [
                "file/source existence and SHA256 hash",
                "parsed entity candidates",
                "parsed communication candidates",
                "parsed transaction candidates",
                "parsed invoice candidates",
                "parsed complaint/victim-report candidates",
                "parsed indicator candidates",
                "deterministic loss candidate arithmetic",
                "complaint duplicate fingerprint clusters",
                "campaign shared-identifier candidates",
                "contradiction candidates",
                "competing hypotheses",
                "benign explanation register",
                "secret redaction flags",
                "prompt-injection flags",
            ],
            "not_supported": [
                "verified fraud",
                "verified criminal intent",
                "verified real-person attribution",
                "verified account operator",
                "verified merchant/vendor fraud",
                "verified loss",
                "verified campaign actor",
                "final legal determination",
                "autonomous account blocking",
                "autonomous fund recovery",
                "autonomous public accusation",
                "autonomous law-enforcement referral",
            ],
            "safety_status": (
                "No scam creation, phishing lure deployment, social-engineering optimization, impersonation persona generation, fake document creation, "
                "credential theft/use, account takeover, OTP/MFA solicitation, payment redirection, money transfer, money-mule recruitment, laundering/evasion guidance, "
                "chargeback/refund fraud coaching, or autonomous victim/suspect contact performed."
            ),
        }

        return {
            "mode": "LOCAL_DETERMINISTIC_SCAMINT_FRAUDINT_ANALYSIS",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "scam_creation_performed": False,
            "phishing_optimization_performed": False,
            "social_engineering_performed": False,
            "credential_theft_or_use_performed": False,
            "account_takeover_performed": False,
            "payment_movement_or_redirection_performed": False,
            "money_mule_recruitment_performed": False,
            "laundering_or_evasion_guidance_performed": False,
            "chargeback_refund_fraud_coaching_performed": False,
            "autonomous_contact_performed": False,
            "evidence_inventory": files,
            "entities_preview": parsed.get("entities", [])[:300],
            "communications_preview": parsed.get("communications", [])[:300],
            "transactions_preview": parsed.get("transactions", [])[:300],
            "invoices_preview": parsed.get("invoices", [])[:300],
            "complaints_preview": parsed.get("complaints", [])[:300],
            "victim_reports_preview": parsed.get("victim_reports", [])[:300],
            "marketplace_listings_preview": parsed.get("marketplace_listings", [])[:300],
            "indicators": parsed.get("indicators", [])[:1000],
            "losses": parsed.get("losses", [])[:1000],
            "campaigns": parsed.get("campaigns", [])[:1000],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "benign_explanations": parsed.get("benign_explanations", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "observations": observations,
            "candidate_facts": candidate_facts,
            "fact_gate": fact_gate,
            "recommended_next_actions": next_action,
            "fraud_collection_plan_preview": collection_plan[:20],
            "limitations": [
                "Only local deterministic checks were performed.",
                "No network access was performed.",
                "No scam creation, phishing optimization, credential use, account takeover, payment movement, mule recruitment, laundering/evasion guidance, or autonomous contact was performed.",
                "Anomaly is not fraud.",
                "Complaint is not verified fraud.",
                "Victim report is not complete factual record.",
                "Chargeback is not fraud.",
                "Refund is not fraud.",
                "New payee is not fraud.",
                "New domain is not fraud.",
                "Professional website is not legitimacy.",
                "Company registration is not trustworthiness.",
                "Payment account holder is not fraud operator.",
                "Wallet is not real person.",
                "Email is not person.",
                "Phone is not person.",
                "Handle is not person.",
                "Shared hosting is not same actor.",
                "Shared script/template is not same actor.",
                "Shared payment processor is not same fraud campaign.",
                "Vendor incident is not vendor fraud.",
                "Account compromise is not account-holder intent.",
                "Mule indicator is not knowing money-mule participation.",
                "Multiple reposted complaints are not multiple independent victims.",
                "AI agreement is not fraud corroboration.",
                "Exposed secrets were redacted heuristically and not used.",
                "Fraud evidence was treated as untrusted data.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self) -> Dict[str, Any]:
        return {
            "role": {
                "employee": "SCAMINT / FRAUDINT AI Employee",
                "canonical_module": "FRAUDINT",
                "alias": "SCAMINT",
                "hierarchy": [
                    "Chief Intelligence Manager",
                    "Fraud / Financial Crime Intelligence Manager",
                    "SCAMINT / FRAUDINT Manager",
                    "Fraud Intelligence AI Employee",
                    "Entity / Campaign / Transaction / Complaint / Impersonation / Verification / Risk Skills",
                ],
                "not": [
                    "scam writer",
                    "phishing operator",
                    "social-engineering agent",
                    "fraud automation system",
                    "fake-document generator",
                    "money-mule recruiter",
                    "payment diversion system",
                    "account-takeover agent",
                    "laundering advisor",
                    "fraud-evasion consultant",
                ],
            },
            "core_principle": [
                "RAW REPORT / EVENT",
                "PRESERVE",
                "NORMALIZE",
                "ENTITY RESOLUTION",
                "CLAIM EXTRACTION",
                "TRANSACTION / COMMUNICATION RESOLUTION",
                "PATTERN IDENTIFICATION",
                "SOURCE RELIABILITY",
                "SOURCE INDEPENDENCE",
                "TEMPORAL ANALYSIS",
                "BENIGN EXPLANATIONS",
                "FACT GATE",
                "FRAUD HYPOTHESIS",
                "FALSIFICATION",
                "DEFENSIVE ASSESSMENT",
            ],
            "fraud_state_ladder": [
                "NORMAL_OR_UNKNOWN",
                "ANOMALY",
                "SCAM_SIGNAL",
                "FRAUD_INDICATOR",
                "FRAUD_HYPOTHESIS",
                "FRAUD_SUPPORTED",
                "FRAUD_STRONGLY_SUPPORTED",
                "LEGAL_FINDING / CONFIRMED_BY_AUTHORITY",
            ],
            "critical_separations": [
                "anomaly != fraud",
                "complaint != verified fraud",
                "victim report != complete factual record",
                "chargeback != fraud",
                "refund != fraud",
                "new payee != fraud",
                "new domain != fraud",
                "professional website != legitimacy",
                "company registration != trustworthiness",
                "payment account holder != fraud operator",
                "wallet != real person",
                "email != person",
                "phone != person",
                "handle/persona != person",
                "shared hosting != same actor",
                "shared script/template != same actor",
                "shared payment processor != same fraud campaign",
                "vendor incident != vendor fraud",
                "account compromise != account-holder intent",
                "mule indicator != knowing money-mule participation",
                "multiple reposted complaints != multiple independent victims",
                "multiple providers using one upstream case != independent sources",
                "AI agreement != fraud corroboration",
            ],
            "hard_restrictions": [
                "Do not create scams.",
                "Do not write deployable phishing lures.",
                "Do not optimize social-engineering persuasion.",
                "Do not impersonate people or companies.",
                "Do not create fake companies for fraud.",
                "Do not create fake invoices.",
                "Do not create fake receipts.",
                "Do not create fake payment confirmations.",
                "Do not create fraudulent websites.",
                "Do not steal credentials.",
                "Do not request OTPs or MFA codes.",
                "Do not use exposed credentials.",
                "Do not take over accounts.",
                "Do not redirect payments.",
                "Do not initiate money transfers.",
                "Do not recruit money mules.",
                "Do not help launder money.",
                "Do not help evade AML/KYC.",
                "Do not provide fraud-detection evasion guidance.",
                "Do not coach chargeback fraud.",
                "Do not coach refund fraud.",
                "Do not autonomously contact victims or suspected scammers.",
            ],
            "non_negotiable_rules": [
                "DO NOT CREATE SCAMS.",
                "DO NOT WRITE DEPLOYABLE PHISHING LURES.",
                "DO NOT OPTIMIZE SOCIAL-ENGINEERING PERSUASION.",
                "DO NOT IMPERSONATE PEOPLE OR COMPANIES.",
                "DO NOT CREATE FAKE COMPANIES FOR FRAUD.",
                "DO NOT CREATE FAKE INVOICES.",
                "DO NOT CREATE FAKE RECEIPTS.",
                "DO NOT CREATE FAKE PAYMENT CONFIRMATIONS.",
                "DO NOT CREATE FRAUDULENT WEBSITES.",
                "DO NOT STEAL CREDENTIALS.",
                "DO NOT REQUEST OTPs OR MFA CODES.",
                "DO NOT USE EXPOSED CREDENTIALS.",
                "DO NOT TAKE OVER ACCOUNTS.",
                "DO NOT REDIRECT PAYMENTS.",
                "DO NOT INITIATE MONEY TRANSFERS.",
                "DO NOT RECRUIT MONEY MULES.",
                "DO NOT HELP LAUNDER MONEY.",
                "DO NOT HELP EVADE AML/KYC.",
                "DO NOT PROVIDE FRAUD-DETECTION EVASION GUIDANCE.",
                "DO NOT COACH CHARGEBACK FRAUD.",
                "DO NOT COACH REFUND FRAUD.",
                "DO NOT EQUATE ANOMALY WITH FRAUD.",
                "DO NOT EQUATE COMPLAINT WITH VERIFIED FRAUD.",
                "DO NOT EQUATE VICTIM REPORT WITH COMPLETE FACTUAL RECORD.",
                "DO NOT EQUATE CHARGEBACK WITH FRAUD.",
                "DO NOT EQUATE REFUND WITH FRAUD.",
                "DO NOT EQUATE NEW PAYEE WITH FRAUD.",
                "DO NOT EQUATE NEW DOMAIN WITH FRAUD.",
                "DO NOT EQUATE PROFESSIONAL WEBSITE WITH LEGITIMACY.",
                "DO NOT EQUATE COMPANY REGISTRATION WITH TRUSTWORTHINESS.",
                "DO NOT EQUATE PAYMENT ACCOUNT HOLDER WITH FRAUD OPERATOR.",
                "DO NOT EQUATE WALLET WITH REAL PERSON.",
                "DO NOT EQUATE EMAIL WITH PERSON.",
                "DO NOT EQUATE PHONE WITH PERSON.",
                "DO NOT EQUATE HANDLE WITH PERSON.",
                "DO NOT EQUATE SHARED HOSTING WITH SAME ACTOR.",
                "DO NOT EQUATE SHARED SCRIPT/TEMPLATE WITH SAME ACTOR.",
                "DO NOT EQUATE SHARED PAYMENT PROCESSOR WITH SAME FRAUD CAMPAIGN.",
                "DO NOT EQUATE VENDOR INCIDENT WITH VENDOR FRAUD.",
                "DO NOT EQUATE VENDOR BREACH WITH FRAUD.",
                "DO NOT EQUATE ACCOUNT COMPROMISE WITH ACCOUNT HOLDER INTENT.",
                "DO NOT EQUATE THIRD-PARTY ACCOUNT WITH THIRD-PARTY COMPLICITY.",
                "DO NOT EQUATE MULE INDICATOR WITH KNOWING MONEY-MULE PARTICIPATION.",
                "DO NOT EQUATE MULTIPLE REPOSTED COMPLAINTS WITH MULTIPLE VICTIMS.",
                "DO NOT EQUATE MULTIPLE PROVIDERS USING ONE UPSTREAM CASE WITH INDEPENDENT SOURCES.",
                "DO NOT EQUATE AI AGREEMENT WITH FRAUD CORROBORATION.",
                "DO NOT HIDE BENIGN EXPLANATIONS.",
                "DO NOT HIDE REFUNDS OR REVERSALS.",
                "DO NOT HIDE COMPLAINT DUPLICATION.",
                "DO NOT HIDE ACCOUNT-COMPROMISE POSSIBILITY.",
                "DO NOT HIDE IDENTITY UNCERTAINTY.",
                "DO NOT HIDE SOURCE DEPENDENCIES.",
                "DO NOT HIDE LOSS UNCERTAINTY.",
                "DO NOT INVENT VICTIMS.",
                "DO NOT INVENT SCAMMERS.",
                "DO NOT INVENT TRANSACTIONS.",
                "DO NOT INVENT LOSSES.",
                "DO NOT INVENT ACCOUNT OWNERS.",
                "DO NOT INVENT CAMPAIGNS.",
                "DO NOT INVENT CRIMINAL INTENT.",
                "DO NOT INVENT FRAUD FINDINGS.",
                "DO NOT LOSE HISTORICAL IDENTIFIER / DOMAIN / ACCOUNT STATES.",
            ],
            "victim_safety": [
                "Do not shame victims.",
                "Do not blame victims.",
                "Do not publish victim identity unnecessarily.",
                "Do not contact suspected scammer from victim account.",
                "Do not encourage confrontation.",
                "Focus on evidence, containment, recovery, and authorized reporting workflow.",
            ],
            "privacy": [
                "Redact bank account, card number, full phone, private email where unnecessary, national ID, home address, and credentials in default reports.",
                "Never expose CVV, PIN, track data, or full PAN unnecessarily.",
                "Use masked/tokenized identifiers.",
                "If evidence contains password, OTP, token, session cookie, or private key, do not use it; hand off to CREDINT.",
                "Sensitive fraud cases should support LOCAL_ONLY processing.",
                "Cloud models may receive only redacted, aggregated, pseudonymized, policy-approved case data.",
            ],
            "deterministic_first": [
                "Use deterministic code for amount calculations, currency arithmetic, transaction matching, duplicate detection, refund/reversal matching, invoice matching, timestamp ordering, domain normalization, email normalization, phone normalization, hashing, graph traversal, and campaign fingerprint comparison.",
                "Use AI for claim interpretation, fraud-pattern proposals, communication analysis, hypothesis generation, contradiction analysis, and narrative synthesis.",
            ],
        }

    def _schemas(self) -> Dict[str, Any]:
        return {
            "fraud_evidence_schema": {
                "evidence_id": "Unique fraud evidence identifier",
                "case_id": "Case identifier",
                "source_id": "Source identifier",
                "source_type": "Complaint / transaction / communication / invoice / marketplace / etc.",
                "artifact_id": "Original artifact identifier",
                "complaint_id": "Complaint identifier if applicable",
                "transaction_id": "Transaction identifier if applicable",
                "communication_id": "Communication identifier if applicable",
                "entity_ids": "Related entity identifiers",
                "observed_at": "Observation time",
                "event_at": "Event time",
                "reported_at": "Report time",
                "retrieved_at": "Retrieval time",
                "content_hash": "SHA256",
                "raw_artifact_reference": "Secure local artifact reference",
                "parser_version": "Parser version",
                "normalizer_version": "Normalizer version",
                "authorization_context": "Authorization basis",
            },
            "fraud_case_schema": {
                "fraud_case_id": "Unique fraud case identifier",
                "case_id": "TraceAtlas case identifier",
                "objective": "Investigation objective",
                "suspected_pattern": "Candidate fraud typology",
                "victim_entities": "Victim/affected entity candidates",
                "subject_entities": "Suspected/claimed actor entity candidates",
                "transactions": "Transaction records",
                "communications": "Communication records",
                "infrastructure": "Domain/email/phone/account/wallet identifiers",
                "claims": "Extracted claims",
                "loss_claimed": "Claimed loss",
                "loss_verified": "Verified loss candidate",
                "first_seen": "First observed event time",
                "last_seen": "Last observed event time",
                "campaign_candidate": "Campaign cluster candidate",
                "fraud_status": "Fraud state ladder status",
                "confidence": "Evidence confidence",
                "limitations": "Analytical limitations",
            },
            "communication_schema": {
                "communication_id": "Unique communication identifier",
                "channel": "Email / chat / phone / marketplace / social / etc.",
                "sender_identifier": "Sender identifier as reported",
                "sender_domain": "Extracted sender domain if applicable",
                "recipient_identifier": "Recipient identifier",
                "timestamp": "Message timestamp",
                "thread_id": "Thread identifier",
                "claimed_identity": "Identity claimed by sender",
                "requested_action": "Action requested",
                "claimed_reason": "Reason claimed",
                "payment_request_present": "Whether payment request is present",
                "credential_request_present": "Whether credential/MFA request is present",
                "identifiers": "Extracted domain/email/phone/crypto identifiers",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "limitations": [
                    "Message content proves a claim was made, not that the claim is true.",
                    "Display name is not email identity.",
                    "DMARC/SPF/DKIM pass does not prove human sender if legitimate account was compromised.",
                ],
            },
            "transaction_schema": {
                "transaction_record_id": "Internal transaction record identifier",
                "external_transaction_id": "Source transaction identifier",
                "payer_ref": "Payer entity reference",
                "payee_ref": "Payee entity reference",
                "merchant_ref": "Merchant entity reference",
                "amount_decimal": "Deterministic decimal amount",
                "currency": "Currency/code",
                "transaction_time": "Transaction time",
                "payment_rail": "Payment rail/method",
                "status": "AUTHORIZED / PENDING / POSTED / SETTLED / FAILED / REVERSED / REFUNDED / CHARGEBACK / CANCELLED / UNKNOWN",
                "reference": "Payment reference",
                "invoice_reference": "Invoice reference",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "limitations": [
                    "Transaction record must be corroborated by primary financial source where authorized.",
                    "Reversals/refunds/chargebacks must not be double-counted as additional loss.",
                ],
            },
            "invoice_schema": {
                "invoice_record_id": "Internal invoice record identifier",
                "invoice_number": "Invoice number",
                "issuer_ref": "Issuer entity reference",
                "recipient_ref": "Recipient entity reference",
                "amount_decimal": "Deterministic decimal amount",
                "currency": "Currency/code",
                "bank_details": "Payment/bank details as reported",
                "invoice_date": "Invoice date",
                "due_date": "Due date",
                "line_items": "Line items",
                "document_hash": "Document hash if available",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "limitations": [
                    "Invoice existence does not prove payment.",
                    "Document mismatch is an indicator, not fraud proof.",
                    "Metadata can be edited/stripped/regenerated.",
                ],
            },
            "complaint_schema": {
                "record_id": "Complaint/victim-report record identifier",
                "record_type": "COMPLAINT / VICTIM_REPORT",
                "external_complaint_id": "Source complaint identifier",
                "subject_ref": "Subject entity reference",
                "complainant_pseudonym": "Pseudonymized complainant identifier",
                "complaint_type": "Complaint category",
                "event_date": "Reported event date",
                "report_date": "Report submission date",
                "claimed_loss_decimal": "Claimed loss decimal",
                "loss_currency": "Loss currency",
                "channel": "Complaint channel",
                "narrative_redacted": "Redacted narrative summary",
                "evidence_references": "Evidence references",
                "fingerprint": "Duplicate-detection fingerprint",
                "duplicate_count": "Detected duplicate cluster size",
                "limitations": [
                    "Complaint/victim report establishes that a report exists, not verified fraud.",
                    "Victims may misremember sequence/time/amount/channel; this does not imply dishonesty.",
                    "Reposted complaints across platforms may be dependent sources.",
                ],
            },
            "campaign_schema": {
                "campaign_id": "Campaign candidate identifier",
                "shared_identifier": "Identifier shared across records",
                "member_record_ids": "Related communication/transaction/invoice/complaint records",
                "member_count": "Number of linked records",
                "state": "POSSIBLE_CAMPAIGN / UNRESOLVED_CLUSTER / DISTINCT / SUPPORTED_CAMPAIGN / VERIFIED_CAMPAIGN",
                "limitations": [
                    "Shared identifier may reflect same campaign, shared service, processor, aggregator, recycled resource, or coincidence.",
                    "No single weak indicator proves same actor.",
                ],
            },
            "loss_model_schema": {
                "currency": "Currency/code",
                "gross_transfer_candidate": "Gross posted/settled/authorized/pending amount",
                "reversed_cancelled_failed": "Reversed/cancelled/failed amount",
                "refunded": "Refunded amount",
                "chargeback": "Chargeback amount",
                "unknown_status_amount": "Amount with unknown status",
                "net_verified_loss_candidate": "Deterministic net loss candidate",
                "transaction_count": "Count of transaction records",
                "formula": "net_candidate = gross(posted/settled/authorized/pending) - reversed_cancelled_failed - refunded - chargeback",
                "limitations": [
                    "Loss calculation depends on transaction status semantics and complete records.",
                    "Attempted fraud may have zero realized loss.",
                    "Refund/chargeback/reversal must not be double-counted.",
                    "This is deterministic candidate arithmetic, not legal loss determination.",
                ],
            },
            "fraudint_result_schema": [
                "case_id",
                "task_id",
                "objective",
                "questions",
                "source_ids",
                "evidence_ids",
                "fraud_cases",
                "fraud_status",
                "scam_patterns",
                "fraud_typologies",
                "fraud_campaigns",
                "persons",
                "personas",
                "organizations",
                "companies",
                "brands",
                "merchants",
                "vendors",
                "suppliers",
                "accounts",
                "payment_accounts",
                "payment_instruments",
                "crypto_addresses",
                "wallets",
                "emails",
                "phones",
                "handles",
                "domains",
                "urls",
                "websites",
                "marketplace_accounts",
                "communications",
                "messages",
                "invoices",
                "transactions",
                "refunds",
                "chargebacks",
                "complaints",
                "victim_reports",
                "claimed_losses",
                "verified_losses",
                "recovered_amounts",
                "net_verified_losses",
                "impersonation_context",
                "brand_impersonation",
                "vendor_impersonation",
                "bec_context",
                "invoice_fraud_context",
                "payment_diversion_context",
                "account_takeover_context",
                "merchant_fraud_context",
                "marketplace_context",
                "investment_scam_context",
                "crypto_scam_context",
                "job_scam_context",
                "romance_scam_context",
                "tech_support_context",
                "identity_fraud_context",
                "synthetic_identity_context",
                "mule_account_candidates",
                "third_party_context",
                "supplier_context",
                "campaign_fingerprints",
                "infrastructure_reuse",
                "transaction_anomalies",
                "financial_anomalies",
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
                "ach_matrix",
                "falsification_results",
                "benign_explanations",
                "risk_dimensions",
                "privacy_flags",
                "legal_flags",
                "unknowns",
                "knowledge_gaps",
                "recommended_next_actions",
                "specialist_handoffs",
                "limitations",
                "status",
            ],
        }

    def export_json(self) -> None:
        self.collect_payload()  # Invalidate results from a changed case before export.
        if not self.last_result:
            self.generate_plan()

        data = self.last_result or self.collect_payload()

        payload_for_name = data.get("payload") or data.get("payload_preview") or data
        case_id = payload_for_name.get("case_id", "scamint")
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
            messagebox.showinfo("Export Complete", f"SCAMINT / FRAUDINT JSON saved to:\n{path}")
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
            "Are you sure you want to clear all fields, analyzed SCAMINT / FRAUDINT evidence, and reset defaults?",
        )
        if not confirm:
            return

        invalidate(self, empty_parsed)
        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result = {}
        self.analyzed_files = []
        self.parsed = empty_parsed()


if __name__ == "__main__":
    try:
        app = TraceAtlasSCAMINTPanel()
        app.mainloop()
    except tk.TclError as exc:
        print("GUI could not start. This is expected in headless environments without display access.")
        print(f"TclError: {exc}")
        print("The SCAMINT / FRAUDINT logic remains usable as a library/module.")
