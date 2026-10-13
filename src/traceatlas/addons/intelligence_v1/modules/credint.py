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


APP_TITLE = "TraceAtlas CREDINT AI Employee — Defensive / Privacy-Aware Credential Exposure Intelligence Panel"
APP_VERSION = "TraceAtlas CREDINT Panel v0.1"


FIELDS = [
    ("case_id", "Case ID", "entry"),
    ("task_id", "Task ID", "entry"),
    ("objective", "Objective", "text"),
    ("target", "Target / Organization / Domain / Account Context", "entry"),
    ("target_type", "Target Type", "combo"),
    ("questions", "CREDINT Questions", "text"),

    ("organizations", "Organizations", "text"),
    ("domains", "Domains", "text"),
    ("email_domains", "Email Domains", "text"),
    ("authorized_accounts", "Authorized Accounts / Identifiers", "text"),
    ("authorized_identity_metadata", "Authorized Identity Metadata", "text"),
    
    ("credential_exposure_claims", "Inline Credential Exposure Claims", "text"),
    ("breach_sources", "Breach Sources / Datasets", "text"),
    ("stealer_log_metadata", "Stealer Log Metadata", "text"),
    ("combo_list_metadata", "Combo List Metadata", "text"),
    ("repository_exposure_metadata", "Repository Secret Exposure Metadata", "text"),
    ("secret_exposure_metadata", "Other Secret Exposure Metadata", "text"),
    ("incident_context", "Incident Context", "text"),

    ("credential_exposure_paths", "Credential Exposure Export Paths", "text"),
    ("breach_dataset_paths", "Breach Dataset Metadata Paths", "text"),
    ("stealer_log_paths", "Stealer Log Metadata Paths", "text"),
    ("combo_list_paths", "Combo List Metadata Paths", "text"),
    ("repository_scan_paths", "Repository Scan Result Paths", "text"),
    ("cloud_secret_paths", "Cloud Secret Exposure Paths", "text"),
    ("darkweb_credential_paths", "Dark-Web Credential Claim Paths", "text"),
    ("stix_misp_paths", "STIX / MISP Export Paths", "text"),

    ("time_range", "Time Range", "text"),
    ("jurisdiction", "Jurisdiction", "entry"),
    ("scope", "Scope / Allowed Sources", "text"),
    ("authorization", "Authorization Basis", "text"),
    ("source_limits", "Source Limits / Safety Limits", "text"),
    ("budget", "Budget", "entry"),
    ("deadline", "Deadline", "entry"),
    ("configured_connectors", "Configured Connectors (IdP/IAM/Breach-Monitoring/Repo-Scanner/etc.)", "text"),
]


TARGET_TYPES = [
    "credential_exposure",
    "breach_credential",
    "stealer_log",
    "combo_list",
    "repository_secret",
    "cloud_secret",
    "darkweb_claim",
    "identity_incident",
    "unknown",
]


LIST_FIELDS = {
    "questions",
    "organizations",
    "domains",
    "email_domains",
    "authorized_accounts",
    "authorized_identity_metadata",
    "credential_exposure_claims",
    "breach_sources",
    "stealer_log_metadata",
    "combo_list_metadata",
    "repository_exposure_metadata",
    "secret_exposure_metadata",
    "incident_context",
    "credential_exposure_paths",
    "breach_dataset_paths",
    "stealer_log_paths",
    "combo_list_paths",
    "repository_scan_paths",
    "cloud_secret_paths",
    "darkweb_credential_paths",
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
    "credential_exposure",
    "breach_credential",
    "stealer_log",
    "combo_list",
    "repository_secret",
    "cloud_secret",
    "darkweb_claim",
    "identity_incident",
}


POLICY_BLOCK_PATTERNS = [
    r"\b(?:test|validate|verify|check|login|log in|authenticate|use|redeem|replay)\b[^\n]{0,140}\b(?:password|credential|token|api key|cloud key|private key|session cookie|mfa seed|recovery code)\b",
    r"\b(?:crack|brute force|spray|stuff)\b[^\n]{0,140}\b(?:hash|password|credential|user)\b",
    r"\b(?:purchase|buy|acquire|obtain)\b[^\n]{0,140}\b(?:credential|access|database|dump|combo list)\b",
    r"\b(?:contact|message|impersonate)\b[^\n]{0,140}\b(?:seller|actor|user|victim|employee|customer)\b",
    r"\b(?:reset|disable|revoke|rotate)\b[^\n]{0,140}\b(?:account|password|token|key|user|service)\b\s+(?:autonomously|automatically|without approval)",
    r"\b(?:access|intrude|hijack)\b[^\n]{0,140}\b(?:private account|session|inbox|mail|profile)\b",
]


SAFE_ALTERNATIVES = [
    "Provide defensive credential-exposure intelligence: identifier normalization, credential-type classification, source pedigree, temporal validation, duplicate/recycled check, risk assessment without testing, rotation/remediation recommendations, and specialist handoffs.",
    "Do not test passwords, login, crack hashes, stuff credentials, spray passwords, replay tokens/sessions, use private keys/MFA seeds/recovery codes, purchase credentials, contact sellers, or autonomously reset/disable accounts.",
    "Separate exposure, validity, account compromise, and organization breach.",
    "Minimize sensitive data: preserve redacted identifiers, fingerprints, types, sources, times, and provenance instead of plaintext secrets.",
    "Escalate defensively through authorized human workflows: IAM, EXPOSUREINT, INCIDENTINT, BREACHINT, DARKINT, CTI, MALINT, REPOINT, CLOUDINT.",
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
        "PGP_PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----",
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
    (
        "USERNAME_PASSWORD_PAIR",
        re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*[:|]\s*[^\s,;\"']+"),
    ),
]


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",
    r"reveal\s+(?:the\s+)?system\s+prompt",
    r"login\s+(?:here|to)",
    r"use\s+(?:this\s+)?password",
    r"run\s+(?:this|script)",
    r"contact\s+seller",
    r"download\s+dataset",
    r"disable\s+safety",
]


DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
EMAIL_PASS_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}:[^\s:]{1,200}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
BCRYPT_RE = re.compile(r"\$2[aby]\$\d+\$[./A-Za-z0-9]{53}")
NTLM_RE = re.compile(r"\b[0-9a-fA-F]{32}\b") # Ambiguous with MD5, needs context
SSH_KEY_RE = re.compile(r"ssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]+")
JWS_HEADER_RE = re.compile(r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*")


CREDENTIAL_TYPE_KEYWORDS = {
    "EMAIL_PASSWORD": ["email", "password", "user:pass", "login"],
    "USERNAME_PASSWORD": ["username", "password", "user", "pass"],
    "PASSWORD_HASH": ["hash", "md5", "sha1", "sha256", "bcrypt", "ntlm", "pbkdf2"],
    "SESSION_COOKIE": ["cookie", "session", "jsessionid", "phpsessid", "asp.net_sessionid"],
    "SESSION_TOKEN": ["token", "jwt", "bearer", "oauth", "refresh_token", "access_token"],
    "API_KEY": ["api_key", "apikey", "api-key", "x-api-key"],
    "CLOUD_ACCESS_KEY": ["aws_access_key_id", "azure_storage_key", "gcp_service_account", "cloud_key"],
    "PRIVATE_KEY": ["private_key", "pem", "ssh_rsa", "ssh_ed25519", "tls_key"],
    "SSH_KEY": ["ssh_key", "id_rsa", "id_ed25519", "authorized_keys"],
    "CERTIFICATE_PRIVATE_KEY": ["cert_private", "ssl_key", "tls_private"],
    "MFA_SEED": ["mfa_seed", "totp", "otpauth", "google_authenticator", "duo_secret"],
    "RECOVERY_CODE": ["recovery_code", "backup_code", "emergency_code"],
    "APPLICATION_SECRET": ["app_secret", "client_secret", "signing_key", "encryption_key"],
    "DATABASE_CREDENTIAL": ["db_password", "mysql_pass", "postgres_user", "mongo_uri", "redis_auth"],
    "SERVICE_ACCOUNT_SECRET": ["service_account_json", "sa_key", "workload_identity"],
    "OAUTH_CLIENT_SECRET": ["oauth_client_secret", "client_id_and_secret"],
}


EXPOSURE_ORIGIN_KEYWORDS = {
    "FIRST_PARTY_BREACH": ["first-party", "internal breach", "our network", "our systems", "direct compromise"],
    "THIRD_PARTY_BREACH": ["third-party", "vendor", "supplier", "partner", "saas", "crm", "marketing platform"],
    "STEALER_LOG": ["stealer", "infostealer", "redline", "lumi", "venom", "browser data", "saved passwords", "cookies harvested"],
    "COMBO_LIST": ["combo list", "combolist", "aggregated", "multiple breaches", "credential stuffing collection"],
    "PHISHING_REPORT": ["phish", "spoof", "fake login", "credential harvesting page"],
    "REPOSITORY_EXPOSURE": ["github", "gitlab", "bitbucket", "repo", "source code", "commit history", "hardcoded secret"],
    "CLOUD_EXPOSURE": ["s3 bucket", "blob storage", "public database", "misconfigured iam", "cloud console"],
    "PASTE_LEAK": ["paste", "pastebin", "ghostbin", "anonfile", "leak site"],
    "DARKWEB_LISTING": ["marketplace", "forum post", "seller claim", "telegram channel"],
    "RANSOMWARE_DATASET": ["ransomware leak", "double extortion", "data dump publication"],
    "PUBLIC_DATA": ["public directory", "scraped", "open source intel", "osint"],
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


def normalize_domain(value: Any) -> str:
    original = str(value or "").strip().lower().rstrip(".")
    if not original:
        return ""

    if "://" in original:
        try:
            parsed = urlparse(original)
            original = (parsed.netloc or "").lower()
            if "@" in original:
                original = original.split("@", 1)[1]
            if ":" in original and not original.startswith("["):
                original = original.split(":", 1)[0]
        except Exception:
            pass

    if original.startswith("[") and original.endswith("]"):
        original = original[1:-1]

    try:
        original = original.encode("idna").decode("ascii")
    except Exception:
        pass

    return original


def redact_email_identifier(email: Any) -> str:
    raw = str(email or "").strip().lower()
    if "@" not in raw:
        return safe_str(raw, 120)
    local, domain = raw.split("@", 1)
    if len(local) <= 2:
        redacted_local = local[:1] + "***"
    else:
        redacted_local = local[:2] + "***"
    return f"{redacted_local}@{domain}"


def parse_datetime(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None

    s = str(value).strip()
    if not s:
        return None

    s = s.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass

    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
        except Exception:
            pass

    return None


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


def extract_temporal(rec: Dict[str, Any]) -> Dict[str, str]:
    temporal: Dict[str, str] = {}
    mappings = {
        "first_seen": ["first_seen", "firstseen", "first_observed", "created", "start_time", "start", "collection_date"],
        "last_seen": ["last_seen", "lastseen", "last_observed", "updated", "end_time", "end", "modified", "publication_date"],
        "observed_at": ["observed_at", "observedat", "timestamp", "time", "observed"],
        "published_at": ["published_at", "publishedat", "release_date"],
        "retrieved_at": ["retrieved_at", "retrievedat", "collected_at", "snapshot_at"],
        "rotation_time": ["rotated_at", "changed_at", "reset_date"],
    }

    for canonical, aliases in mappings.items():
        val = get_field(rec, aliases)
        if val not in (None, ""):
            temporal[canonical] = str(val)

    return temporal


def collect_tags(rec: Dict[str, Any]) -> List[str]:
    tags: List[str] = []

    for key in ["tags", "labels", "markings", "x_misp_tags", "tag", "label"]:
        val = rec.get(key)
        for item in listify(val):
            if isinstance(item, dict):
                name = item.get("name") or item.get("value") or item.get("label")
                if name:
                    tags.append(str(name))
            elif item not in (None, ""):
                tags.append(str(item))

    return unique_preserve_order(tags)[:200]


def content_tokens(text: str) -> List[str]:
    redacted, _ = redact_secrets(str(text or ""))
    low = normalize_text(redacted)
    return re.findall(r"[a-z0-9]+", low)


def content_fingerprint(text: str) -> str:
    tokens = content_tokens(text)
    if not tokens:
        return ""
    return sha256_text(" ".join(sorted(set(tokens))))[:32]


def classify_credential_type(text: str) -> List[str]:
    low = normalize_text(text)
    types = []
    for ctype, keywords in CREDENTIAL_TYPE_KEYWORDS.items():
        if any(k in low for k in keywords):
            types.append(ctype)
    
    # Specific regex checks for higher confidence
    if EMAIL_PASS_RE.search(text):
        if "EMAIL_PASSWORD" not in types:
            types.append("EMAIL_PASSWORD")
    
    if BCRYPT_RE.search(text):
        if "PASSWORD_HASH" not in types:
            types.append("PASSWORD_HASH")
            
    if JWS_HEADER_RE.search(text):
        if "SESSION_TOKEN" not in types:
            types.append("SESSION_TOKEN")
            
    if SSH_KEY_RE.search(text):
        if "SSH_KEY" not in types:
            types.append("SSH_KEY")

    return unique_preserve_order(types)


def classify_exposure_origin(text: str) -> List[str]:
    low = normalize_text(text)
    origins = []
    for origin, keywords in EXPOSURE_ORIGIN_KEYWORDS.items():
        if any(k in low for k in keywords):
            origins.append(origin)
    return unique_preserve_order(origins)


def infer_freshness(temporal: Optional[Dict[str, Any]]) -> str:
    if not temporal:
        return "UNKNOWN"
    
    first_dt = parse_datetime(temporal.get("first_seen"))
    last_dt = parse_datetime(temporal.get("last_seen"))
    rot_dt = parse_datetime(temporal.get("rotation_time"))
    
    now = datetime.now(timezone.utc)
    
    if rot_dt and rot_dt > (last_dt or now):
        return "ROTATED" # Special state indicating remediation
        
    target_dt = last_dt or first_dt
    if not target_dt:
        return "UNKNOWN"
        
    age_days = (now - target_dt).days
    
    if age_days <= 7:
        return "CURRENT"
    if age_days <= 30:
        return "RECENT"
    if age_days <= 180:
        return "AGING"
    if age_days <= 365:
        return "STALE"
    return "HISTORICAL"


def empty_parsed() -> Dict[str, Any]:
    return {
        "sources": [],
        "credentials": [],
        "identifiers": [],
        "accounts": [],
        "exposures": [],
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
            "Source observation is not verified credential validity, account compromise, or organization breach.",
        ],
    })

    if secret_flags:
        add_note(parsed, "SECRET_REDACTION", flags=secret_flags, source_id=source_id, evidence_id=evidence_id, context=context)
    if injection_flags:
        add_note(parsed, "PROMPT_INJECTION_FLAG", flags=injection_flags, source_id=source_id, evidence_id=evidence_id, context=context,
                 caution="Embedded instructions in credential/dataset/source content are ignored.")


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
            "Source registration is local provenance metadata, not independence verification.",
            "Aggregators/mirrors are not independent sources.",
        ],
    })


def add_identifier(
    parsed: Dict[str, Any],
    identifier_value: Any,
    id_type: str,
    source_id: str,
    evidence_id: str,
    context: str = "",
    temporal: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    val = safe_str(identifier_value, 200)
    if not val:
        return None
        
    # Normalize email/domain if applicable
    norm_val = val
    if id_type == "EMAIL":
        norm_val = val.lower()
        dom = val.split("@", 1)[1] if "@" in val else ""
        if dom:
             norm_dom = normalize_domain(dom)
             if norm_dom:
                 norm_val = f"{val.split('@')[0]}@{norm_dom}"
                 
    id_hash = sha256_text(norm_val)
    
    for item in parsed["identifiers"]:
        if item.get("normalized_hash") == id_hash:
            return item.get("identifier_id")

    ident_obj = {
        "identifier_id": f"IDN-{uuid.uuid4()}",
        "type": id_type,
        "raw_redacted": redact_email_identifier(val) if "@" in val else safe_str(val, 50),
        "normalized_hash": id_hash,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "context": safe_str(context, 300),
        "temporal": temporal or {},
        "state": "IDENTIFIER_NORMALIZED",
        "limitations": [
            "Identifier hash is used for deduplication/provenance tracking without storing raw PII unnecessarily.",
        ],
    }
    parsed["identifiers"].append(ident_obj)
    return ident_obj.get("identifier_id")


def add_credential(
    parsed: Dict[str, Any],
    identifier_id: Optional[str],
    cred_type: str,
    secret_state: str,
    exposure_origin: str,
    source_id: str,
    evidence_id: str,
    temporal: Optional[Dict[str, Any]] = None,
    freshness: str = "UNKNOWN",
    validity_state: str = "VALIDITY_NOT_TESTED",
    rotation_state: str = "ROTATION_NOT_ASSESSED",
    privilege_context: str = "UNKNOWN",
    account_type: str = "UNKNOWN",
    risk_level: str = "UNKNOWN",
) -> None:
    
    cred_obj = {
        "credential_id": f"CRD-{uuid.uuid4()}",
        "identifier_id": identifier_id,
        "credential_type": cred_type,
        "secret_state": secret_state, # PLAINTEXT_REPORTED, HASHED, REDACTED, etc.
        "exposure_origin": exposure_origin,
        "first_seen": (temporal or {}).get("first_seen"),
        "last_seen": (temporal or {}).get("last_seen"),
        "freshness": freshness,
        "validity_state": validity_state,
        "rotation_state": rotation_state,
        "privilege_context": privilege_context,
        "account_type": account_type,
        "risk_level": risk_level,
        "source_id": source_id,
        "evidence_id": evidence_id,
        "temporal": temporal or {},
        "state": "CREDENTIAL_EXPOSURE_METADATA",
        "limitations": [
            "Credential exposure metadata does not prove current validity.",
            "No login/testing performed.",
        ],
    }
    parsed["credentials"].append(cred_obj)


def process_text_block(
    text: str,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
    temporal: Optional[Dict[str, Any]] = None,
    org_hint: Any = None,
    domain_hint: Any = None,
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
                 caution="Embedded instructions in credential/dataset/source content are ignored.")

    add_observation(parsed, redacted[:1000], source_id, evidence_id, context=context)

    # Extract Emails
    emails = extract_emails(raw)
    domains = extract_domains(raw)
    
    primary_email = emails[0] if emails else None
    primary_domain = domain_hint or (domains[0] if domains else None)
    
    ident_id = None
    if primary_email:
        ident_id = add_identifier(parsed, primary_email, "EMAIL", source_id, evidence_id, context=context, temporal=temporal)
    elif primary_domain:
         # Treat domain-only mention as weak identifier context if no email
         pass 

    # Classify Types
    cred_types = classify_credential_type(raw)
    if not cred_types and secret_flags:
        # Heuristic: if secrets were found but no specific keyword match, assume generic secret
        if "PASSWORD_OR_TOKEN_ASSIGNMENT" in secret_flags or "USERNAME_PASSWORD_PAIR" in secret_flags:
            cred_types.append("UNKNOWN_SECRET")
            
    # Classify Origin
    origins = classify_exposure_origin(raw)
    primary_origin = origins[0] if origins else "UNKNOWN"
    
    # Determine Freshness
    freshness = infer_freshness(temporal)
    
    # Risk Heuristic (Simple)
    risk = "LOW"
    if primary_origin in {"STEALER_LOG", "FIRST_PARTY_BREACH", "CLOUD_EXPOSURE"}:
        risk = "HIGH"
    if "PRIVATE_KEY" in cred_types or "MFA_SEED" in cred_types or "SESSION_TOKEN" in cred_types:
        risk = "CRITICAL"
    if freshness == "CURRENT" and risk == "HIGH":
        risk = "EMERGENCY"

    for ct in cred_types:
        # Create a credential record for each type detected
        # Note: In real scenario, we'd link specific values to specific types. 
        # Here we create metadata records representing the exposure event.
        add_credential(
            parsed,
            identifier_id=ident_id,
            cred_type=ct,
            secret_state="REDACTED" if "PLAINTEXT" not in ct else "PLAINTEXT_REPORTED",
            exposure_origin=primary_origin,
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
            freshness=freshness,
            validity_state="VALIDITY_NOT_TESTED",
            rotation_state="ROTATION_NOT_ASSESSED",
            privilege_context="UNKNOWN",
            account_type="UNKNOWN",
            risk_level=risk,
        )


def extract_domains(text: str) -> List[str]:
    out = []
    for m in DOMAIN_RE.finditer(text or ""):
        d = normalize_domain(m.group(0))
        if d and d not in out and not d.endswith(".onion"):
            out.append(d)
    return out


def extract_emails(text: str) -> List[str]:
    out = []
    for m in EMAIL_RE.finditer(text or ""):
        e = m.group(0).lower()
        if e not in out:
            out.append(e)
    return out


def classify_json_payload(data: Any, filename: str = "") -> str:
    if isinstance(data, list):
        return "JSON_ARRAY"
    if not isinstance(data, dict):
        return "GENERIC_JSON"

    keys = {normalize_key(k) for k in data.keys()}
    low = json.dumps(data, ensure_ascii=False, default=str)[:20000].lower()
    fname = normalize_text(filename)

    if data.get("type") == "bundle" or "objects" in keys:
        return "STIX_PACKAGE"
    if "Event" in data or "Attribute" in data or "Object" in data or "misp" in fname:
        return "MISP_EVENT"
    if "stealer" in fname or "infostealer" in low or "browser_data" in keys:
        return "STEALER_LOG_METADATA"
    if "combo" in fname or "combolist" in low or "aggregated_credentials" in keys:
        return "COMBO_LIST_METADATA"
    if "repo" in fname or "github" in low or "gitlab" in low or "secret_scanning" in keys:
        return "REPOSITORY_SECRET_SCAN"
    if "cloud" in fname or "aws" in low or "azure" in low or "gcp" in low or "iam_policy" in keys:
        return "CLOUD_SECRET_EXPOSURE"
    if "breach" in fname or "compromised" in low or "dump" in low:
        return "BREACH_CREDENTIAL_METADATA"
    if "credential" in fname or "password" in low or "token" in low:
        return "CREDENTIAL_EXPOSURE_METADATA"

    return "GENERIC_JSON"


def process_json_record(
    rec: Dict[str, Any],
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    context: str = "",
    org_hint: Any = None,
    domain_hint: Any = None,
) -> None:
    if not isinstance(rec, dict):
        return

    temporal = extract_temporal(rec)
    rec_context = context or "json_record"

    email = get_field(rec, ["email", "user", "username", "identifier"])
    domain = get_field(rec, ["domain", "website", "url"]) or domain_hint
    org = get_field(rec, ["organization", "company", "target_org"]) or org_hint
    
    cred_type_raw = get_field(rec, ["credential_type", "type", "secret_type"])
    origin_raw = get_field(rec, ["origin", "source_type", "exposure_origin"])
    status_raw = get_field(rec, ["status", "state", "rotation_status"])
    
    # Map explicit fields to our schema if present
    if email:
        ident_id = add_identifier(parsed, email, "EMAIL", source_id, evidence_id, context=rec_context, temporal=temporal)
    else:
        ident_id = None

    # Infer types if not explicitly stated
    text_blob = json.dumps(rec, ensure_ascii=False, default=str)
    inferred_types = classify_credential_type(text_blob)
    final_types = [cred_type_raw] if cred_type_raw else inferred_types
    
    inferred_origins = classify_exposure_origin(text_blob)
    final_origin = origin_raw if origin_raw else (inferred_origins[0] if inferred_origins else "UNKNOWN")
    
    freshness = infer_freshness(temporal)
    
    # Simple risk mapping based on explicit fields or inference
    risk = "MEDIUM"
    if final_origin in {"STEALER_LOG", "FIRST_PARTY_BREACH"}:
        risk = "HIGH"
    if "ADMIN" in str(status_raw).upper() or "PRIVILEGED" in str(status_raw).upper():
        risk = "CRITICAL"
        
    for ct in final_types:
        add_credential(
            parsed,
            identifier_id=ident_id,
            cred_type=str(ct),
            secret_state="REDACTED", # Always redact in metadata layer unless specifically handled
            exposure_origin=str(final_origin),
            source_id=source_id,
            evidence_id=evidence_id,
            temporal=temporal,
            freshness=freshness,
            validity_state="VALIDITY_NOT_TESTED",
            rotation_state="ROTATION_NOT_ASSESSED",
            privilege_context="UNKNOWN",
            account_type="UNKNOWN",
            risk_level=risk,
        )

    # Process remaining text for hidden patterns
    process_text_block(
        text_blob,
        source_id,
        evidence_id,
        parsed,
        context=f"json:{rec_context}",
        temporal=temporal,
        org_hint=org,
        domain_hint=domain,
    )


def walk_json(
    data: Any,
    source_id: str,
    evidence_id: str,
    parsed: Dict[str, Any],
    depth: int = 0,
    path: str = "",
    org_hint: Any = None,
    domain_hint: Any = None,
) -> None:
    if depth > 14 or len(parsed.get("observations", [])) > 200000:
        return

    if isinstance(data, dict):
        process_json_record(data, source_id, evidence_id, parsed, context=path or "json", org_hint=org_hint, domain_hint=domain_hint)
        for k, v in data.items():
            new_path = f"{path}.{k}" if path else str(k)
            walk_json(v, source_id, evidence_id, parsed, depth + 1, new_path, org_hint, domain_hint)
    elif isinstance(data, list):
        for item in data[:100000]:
            walk_json(item, source_id, evidence_id, parsed, depth + 1, path, org_hint, domain_hint)
    elif isinstance(data, str):
        process_text_block(data, source_id, evidence_id, parsed, context=path or "json_string", org_hint=org_hint, domain_hint=domain_hint)


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
    kind = "CSV_CREDENTIAL_DATA"

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
    if any(k in low for k in ["stealer", "infostealer", "browser data"]):
        kind = "TEXT_STEALER_LOG"
    elif any(k in low for k in ["combo", "aggregated"]):
        kind = "TEXT_COMBO_LIST"
    elif any(k in low for k in ["github", "gitlab", "repo"]):
        kind = "TEXT_REPO_SECRET"
    else:
        kind = "TEXT_CREDENTIAL_CLAIM"

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
        ".pcap", ".pcapng", ".cap", ".msi", ".cab",
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

    if suffix in {".txt", ".log", ".md", ".yaml", ".yml", ".report", ".stix", ".taxii", ".misp", ".snapshot"}:
        return {"format_detected": "TEXT", "mime_type": "text/plain"}

    try:
        probe = head.decode("utf-8", errors="strict")
        if probe.strip():
            return {"format_detected": "TEXT", "mime_type": "text/plain"}
    except Exception:
        pass

    return {"format_detected": "UNKNOWN", "mime_type": "application/octet-stream"}


def analyze_credential_file(path_str: str, case_id: str = "", task_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
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
            "No login attempts, password testing, hash cracking, credential stuffing, token replay, session hijacking, private key use, MFA seed use, recovery code redemption, purchasing credentials, contacting sellers, or autonomous account changes performed.",
            "Binary artifacts are hash/metadata preserved only; no execution or deep parsing performed.",
            "Credential/dataset/source content is untrusted evidence, not instruction.",
            "Exposed secrets are redacted and not used.",
            "Exposure metadata is not proof of validity, compromise, or breach.",
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
            file_evidence["content_kind"] = "BINARY_ARTIFACT_METADATA_ONLY"
            file_evidence["status"] = "PARTIAL_BINARY_METADATA_ONLY"
            file_evidence["reason"] = (
                "Binary artifact detected. This planning panel preserves hash/metadata only. "
                "It does not execute, unpack, modify, reverse-engineer, fuzz, replay PCAPs, or deeply parse binary artifacts."
            )
        else:
            file_evidence["content_kind"] = "UNKNOWN_OR_UNSUPPORTED"
            file_evidence["status"] = "UNSUPPORTED_FORMAT"
    except Exception as exc:
        file_evidence["status"] = "PARTIAL_OR_FAILED"
        file_evidence["error"] = f"{exc.__class__.__name__}: {exc}"

    file_evidence["parsed_credential_count"] = len(parsed.get("credentials", []))
    file_evidence["parsed_identifier_count"] = len(parsed.get("identifiers", []))
    file_evidence["parsed_source_count"] = len(parsed.get("sources", []))

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
    
    # Group by Identifier Hash
    creds_by_ident: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for c in parsed.get("credentials", []):
        iid = c.get("identifier_id")
        if iid:
            creds_by_ident[iid].append(c)
            
    for iid, group in creds_by_ident.items():
        origins = sorted({c.get("exposure_origin") for c in group if c.get("exposure_origin")})
        if len(origins) > 1:
            contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "ORIGIN_CONFLICT_FOR_IDENTIFIER",
                "subject": iid,
                "values": origins[:100],
                "possible_explanations": [
                    "Multiple breaches involving same user",
                    "Recycled data labeled differently",
                    "Stealer log vs Breach confusion",
                    "Third-party vs First-party ambiguity",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Do not merge origins without lineage analysis.",
            })
            
        types = sorted({c.get("credential_type") for c in group if c.get("credential_type")})
        if len(types) > 1:
             contradictions.append({
                "contradiction_id": f"CON-{uuid.uuid4()}",
                "type": "TYPE_CONFLICT_FOR_IDENTIFIER",
                "subject": iid,
                "values": types[:100],
                "possible_explanations": [
                    "Different services exposed",
                    "Password vs Token vs Key",
                    "Metadata error",
                ],
                "resolution_status": "UNRESOLVED",
                "caution": "Identify specific service/context for each type.",
            })

    contradictions, _ = truncate_list(contradictions, 5000)
    return contradictions


def build_hypotheses(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    hyps = []
    creds = parsed.get("credentials", [])
    sources = parsed.get("sources", [])
    
    if not creds:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Current local deterministic evidence is insufficient to assess credential exposure, identity risk, or remediation priority.",
            "supporting_facts": ["No credential records parsed."],
            "opposing_facts": [],
            "assumptions": ["Evidence may be missing, unsupported, binary-only, or unavailable."],
            "unknowns": ["credential type", "origin", "validity", "rotation status", "account privilege"],
            "falsification_conditions": ["New authorized/public/licensed credential exposure evidence changes assessment."],
            "next_test": "Attach credential exposure exports, breach dataset metadata, stealer log metadata, combo list metadata, repository scan results, or dark-web claims.",
            "status": "OPEN",
        })
        return hyps[:1000]

    high_risk = [c for c in creds if c.get("risk_level") in {"CRITICAL", "EMERGENCY"}]
    if high_risk:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "High-risk credential exposures (Private Keys, MFA Seeds, Session Tokens, Admin Cloud Secrets) detected requiring immediate defensive review.",
            "supporting_facts": [f"{len(high_risk)} high-risk credential record(s)."],
            "opposing_facts": ["Validity is unknown; some may be expired/rotated."],
            "unknowns": ["current validity", "rotation status", "active session usage"],
            "falsification_conditions": ["Authorized IAM logs show recent rotation/revocation or inactive account status."],
            "next_test": "Handoff to IAM/Security Operations for revocation/rotation verification WITHOUT testing credentials.",
            "status": "OPEN",
        })

    stealer_logs = [c for c in creds if c.get("exposure_origin") == "STEALER_LOG"]
    if stealer_logs:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Stealer-log origin suggests endpoint/browser compromise rather than direct server breach.",
            "supporting_facts": [f"{len(stealer_logs)} stealer-log credential record(s)."],
            "opposing_facts": ["Credentials may also appear in breached datasets."],
            "unknowns": ["device ownership", "malware family", "campaign context"],
            "falsification_conditions": ["Independent incident evidence confirms server-side exfiltration."],
            "next_test": "Handoff to INCIDENTINT/MALINT for endpoint forensics. Reset credentials defensively.",
            "status": "OPEN",
        })

    combo_lists = [c for c in creds if c.get("exposure_origin") == "COMBO_LIST"]
    if combo_lists:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Combo-list origin suggests aggregated historical data rather than a new targeted breach.",
            "supporting_facts": [f"{len(combo_lists)} combo-list credential record(s)."],
            "opposing_facts": ["May contain fresh phished credentials mixed with old ones."],
            "unknowns": ["proportion of new vs old data", "specific source breaches"],
            "falsification_conditions": ["Lineage analysis shows all records are from known historical breaches."],
            "next_test": "Compare against historical breach corpus. Assess password-reuse risk.",
            "status": "OPEN",
        })

    dependent_sources = [s for s in sources if s.get("source_independence_state") in {"DEPENDENT_COPIES", "DEPENDENT_CONTENT_FAMILY", "PARTIALLY_DEPENDENT_PENDING_REVIEW"}]
    if dependent_sources:
        hyps.append({
            "hypothesis_id": f"HYP-{uuid.uuid4()}",
            "statement": "Apparent multiple sources may be dependent copies/aggregators rather than independent corroboration.",
            "supporting_facts": [f"{len(dependent_sources)} dependent/partially dependent source record(s)."],
            "opposing_facts": ["Some sources may still be independent."],
            "unknowns": ["upstream pedigree", "original reporter"],
            "falsification_conditions": ["Source pedigree analysis shows truly independent observation families."],
            "next_test": "Resolve original claim, first mirror, aggregators, and media/vendor republication.",
            "status": "OPEN",
        })

    hyps, _ = truncate_list(hyps, 1000)
    return hyps


def build_knowledge_gaps(payload: Dict[str, Any], files: List[Dict[str, Any]], parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    gaps = []
    creds = parsed.get("credentials", [])
    sources = parsed.get("sources", [])

    if not files:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What authorized/public/licensed credential exposure evidence exists?",
            "missing_evidence": "No local CREDINT evidence file supplied.",
            "likely_source": "Licensed breach-monitoring provider, authorized IdP logs, stealer-log feed, combo-list metadata, repository scan, dark-web claim export.",
            "specialist_owner": "CREDINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Enables credential exposure planning.",
            "safety_boundary": "No login, testing, cracking, stuffing, spraying, replay, purchasing, or contacting.",
        })

    if not creds:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Which credential exposures are being reported?",
            "missing_evidence": "No credential records parsed.",
            "likely_source": "Credential exposure metadata, breach dataset, stealer log, combo list, repository secret scan.",
            "specialist_owner": "CREDINT AI Employee",
            "priority": "HIGH",
            "expected_information_value": "Establishes exposure inventory.",
            "safety_boundary": "Do not invent credentials, accounts, or validity.",
        })

    if creds and all(c.get("validity_state") == "VALIDITY_NOT_TESTED" for c in creds):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are exposed credentials currently valid?",
            "missing_evidence": "Validity is unknown by design (no testing).",
            "likely_source": "Authorized IdP logs, password-reset timestamps, token-revocation events.",
            "specialist_owner": "IAM / Security Operations",
            "priority": "HIGH_IF_ACTIVE_ACCOUNT",
            "expected_information_value": "Determines urgency of remediation.",
            "safety_boundary": "CREDINT must NOT test validity via login.",
        })

    if any(c.get("exposure_origin") == "UNKNOWN" for c in creds):
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "What is the origin of these credential exposures?",
            "missing_evidence": "Origin unresolved (Breach vs Stealer vs Combo vs Repo).",
            "likely_source": "Dataset fingerprints, historical breach overlap, stealer-campaign correlation.",
            "specialist_owner": "BREACHINT / DARKINT / MALINT",
            "priority": "MEDIUM_HIGH",
            "expected_information_value": "Clarifies whether this is a new breach, recycled data, or endpoint malware.",
            "safety_boundary": "Do not assume first-party breach without evidence.",
        })

    if any(s.get("source_independence_state") in {"UNKNOWN", "UNKNOWN_POTENTIALLY_INDEPENDENT"} for s in sources) and len(sources) > 1:
        gaps.append({
            "gap_id": f"GAP-{uuid.uuid4()}",
            "question": "Are multiple reports actually independent?",
            "missing_evidence": "Source independence unresolved.",
            "likely_source": "Upstream pedigree, original post/listing, crawler/feed provenance.",
            "specialist_owner": "CREDINT / CTI",
            "priority": "HIGH",
            "expected_information_value": "Prevents fake corroboration from mirrors/copies/feeds.",
            "safety_boundary": "Do not count copied posts/mirrors as independent confirmation.",
        })

    gaps, _ = truncate_list(gaps, 500)
    return gaps


def build_specialist_handoffs(parsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    handoffs = []
    creds = parsed.get("credentials", [])
    
    origins = {c.get("exposure_origin") for c in creds}
    types = {c.get("credential_type") for c in creds}

    if "FIRST_PARTY_BREACH" in origins or "THIRD_PARTY_BREACH" in origins:
        handoffs.append({
            "specialist": "BREACHINT",
            "reason": "Breach-origin credential exposure detected.",
            "expected_output": "Breach truth, dataset origin, first-party vs third-party adjudication.",
            "question": "Is the underlying dataset authentic, new, or recycled?",
        })

    if "STEALER_LOG" in origins:
        handoffs.append({
            "specialist": "INCIDENTINT / MALINT",
            "reason": "Stealer-log origin detected.",
            "expected_output": "Endpoint compromise investigation, malware family identification, device scope.",
            "question": "Which endpoints/devices are infected, and what is the malware campaign?",
        })

    if "COMBO_LIST" in origins:
        handoffs.append({
            "specialist": "BREACHINT / EXPOSUREINT",
            "reason": "Combo-list origin detected.",
            "expected_output": "Historical lineage analysis, password-reuse risk assessment.",
            "question": "How much of this list is new vs recycled historical data?",
        })

    if "REPOSITORY_EXPOSURE" in origins or "GIT" in str(types).upper():
        handoffs.append({
            "specialist": "REPOINT / SUPPLYCHAININT",
            "reason": "Repository/code secret exposure detected.",
            "expected_output": "Commit history analysis, fork/cache propagation, secret rotation verification.",
            "question": "Has the secret been fully purged from history/forks/caches?",
        })

    if "CLOUD_EXPOSURE" in origins or "CLOUD_ACCESS_KEY" in types:
        handoffs.append({
            "specialist": "CLOUDINT / IAM",
            "reason": "Cloud secret exposure detected.",
            "expected_output": "IAM policy review, resource access audit, key rotation.",
            "question": "What resources are accessible with this key, and has it been revoked?",
        })

    if "PRIVATE_KEY" in types or "SSH_KEY" in types or "MFA_SEED" in types:
        handoffs.append({
            "specialist": "SECURITY OPERATIONS / IAM",
            "reason": "Critical authentication material (Keys/MFA) exposure detected.",
            "expected_output": "Immediate revocation/rotation, session invalidation, forensic review.",
            "question": "Have all associated sessions/keys been invalidated and replaced?",
        })

    if not handoffs:
        handoffs.append({
            "specialist": "CREDINT Manager",
            "reason": "No specialized handoff triggered from current local deterministic evidence alone.",
            "expected_output": "Review scope, approve authorized connectors, assign exposure collection tasks.",
            "question": "What credential intelligence gap should be filled next?",
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
    creds = parsed.get("credentials", [])
    risks = {c.get("risk_level") for c in creds}
    origins = {c.get("exposure_origin") for c in creds}

    if policy.get("status") == "POLICY_BLOCKED":
        return {
            "action": "Revise task to remove prohibited login, testing, cracking, stuffing, spraying, replay, purchasing, contacting, or autonomous account change behavior.",
            "reason": "CREDINT is defensive credential-exposure intelligence, not credential use or account access.",
            "owner": "Credential Intelligence Manager",
            "expected_output": "Policy-compliant defensive CREDINT scope and question set.",
        }

    if policy.get("status") == "HUMAN_REVIEW_REQUIRED":
        return {
            "action": "Route to human CREDINT/IAM/legal reviewer before consequential remediation, public disclosure, law-enforcement referral, or executive-account action.",
            "reason": "Credential exposure findings can be high-impact and privacy-sensitive.",
            "owner": "Credential Intelligence Manager",
            "expected_output": "Approved defensive verification plan, evidence gaps, and handoffs.",
        }

    if not files:
        return {
            "action": "Attach authorized/public/licensed credential exposure, breach dataset, stealer log, combo list, repository scan, or dark-web claim artifacts before analysis.",
            "reason": "No CREDINT evidence artifact is available for local deterministic analysis.",
            "owner": "CREDINT AI Employee",
            "expected_output": "Credential evidence inventory with hashes and provenance.",
        }

    if "EMERGENCY" in risks or "CRITICAL" in risks:
        return {
            "action": "Immediately escalate critical/high-risk exposures (Private Keys, MFA, Sessions, Cloud Admin) to IAM/SecOps for revocation/rotation verification WITHOUT testing.",
            "reason": "These secret types pose highest immediate risk if active.",
            "owner": "IAM / Security Operations",
            "expected_output": "Confirmed rotation/revocation status.",
        }

    if "STEALER_LOG" in origins:
        return {
            "action": "Handoff to INCIDENTINT/MALINT for endpoint forensics; reset affected user credentials defensively.",
            "reason": "Stealer logs indicate endpoint compromise, not necessarily server breach.",
            "owner": "INCIDENTINT / MALINT",
            "expected_output": "Device scope and malware campaign context.",
        }

    if "COMBO_LIST" in origins:
        return {
            "action": "Compare against historical breach corpus to determine proportion of new vs recycled data; assess password-reuse risk.",
            "reason": "Combo lists are often aggregates of old breaches.",
            "owner": "BREACHINT / EXPOSUREINT",
            "expected_output": "Lineage analysis and reuse-risk report.",
        }

    if "REPOSITORY_EXPOSURE" in origins:
        return {
            "action": "Handoff to REPOINT/SUPPLYCHAININT for commit-history purge verification and CI/CD secret rotation.",
            "reason": "Deleted secrets in repos may persist in history/forks/caches.",
            "owner": "REPOINT / SUPPLYCHAININT",
            "expected_output": "Full purge confirmation and rotation.",
        }

    return {
        "action": "Proceed with identifier resolution, source pedigree analysis, freshness assessment, and defensive remediation planning.",
        "reason": "Local evidence exists, but validity/compromise remains untested by design.",
        "owner": "CREDINT / IAM / EXPOSUREINT",
        "expected_output": "Evidence-linked credential intelligence report with limitations and next actions.",
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
    has_creds = bool(parsed.get("credentials"))
    has_ids = bool(parsed.get("identifiers"))
    has_steam = any(c.get("exposure_origin") == "STEALER_LOG" for c in parsed.get("credentials", []))
    has_combo = any(c.get("exposure_origin") == "COMBO_LIST" for c in parsed.get("credentials", []))
    has_repo = any(c.get("exposure_origin") == "REPOSITORY_EXPOSURE" for c in parsed.get("credentials", []))

    configured_connectors = payload.get("configured_connectors") or []
    has_connectors = bool(configured_connectors) and not any("None configured" in str(x) for x in configured_connectors)

    def add(
        operation: str,
        tool: str,
        purpose: str,
        status: str,
        expected_output: str,
        safety_risk: str = "LOW",
        policy_note: str = "Defensive / authorized / privacy-aware / evidence-first credential intelligence only.",
    ) -> None:
        nonlocal priority
        plan.append({
            "question": questions_limited[0] if questions_limited else "General CREDINT collection planning",
            "operation": operation,
            "tool_or_provider": tool,
            "purpose": purpose,
            "status": status,
            "expected_output": expected_output,
            "priority": priority,
            "safety_risk": safety_risk,
            "policy_note": policy_note,
            "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED_PUBLIC",
            "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
        })
        priority += 1

    add(
        "define_credint_questions_scope",
        "CREDINT Manager / CREDINT AI Employee",
        "Convert objective into credential-exposure questions, allowed sources, identity scope, temporal scope, privacy boundaries, and safety boundaries.",
        "COMPLETED_LOCAL" if payload.get("questions") else "REQUIRED_BEFORE_COLLECTION",
        "Requirement-driven defensive credential collection plan.",
        policy_note="No login, testing, cracking, stuffing, spraying, replay, purchasing, or contacting.",
    )

    add(
        "preserve_original_credential_evidence",
        "local evidence store",
        "Store original credential exports, breach metadata, stealer logs, combo lists, repo scans, and hashes without modifying originals.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "CredentialEvidenceObject with SHA256 and provenance fields.",
    )

    add(
        "safe_parse_json_csv_text_credential_metadata",
        "local deterministic parser",
        "Parse authorized/public/licensed JSON/CSV/TXT credential metadata without executing scripts, opening archives, or accessing live services.",
        "COMPLETED_LOCAL" if has_files else "PLANNED_REQUIRES_EVIDENCE",
        "Normalized credentials, identifiers, accounts, exposures, and observations.",
        safety_risk="HIGH_IF_UNTRUSTED_CONTENT_TREATED_AS_INSTRUCTION",
        policy_note="Credential/dataset/source content is untrusted evidence.",
    )

    add(
        "identifier_normalization_and_redaction",
        "local normalizer",
        "Normalize emails/domains/usernames safely; generate cryptographic hashes for deduplication; never store/display raw secrets.",
        "COMPLETED_LOCAL" if has_ids else "PLANNED_REQUIRES_IDENTITY_EVIDENCE",
        "Redacted identifiers with normalized hashes.",
        safety_risk="HIGH_PRIVACY_SENSITIVE",
        policy_note="Data minimization: prefer hashes over plaintext.",
    )

    add(
        "credential_type_and_origin_classification",
        "local classifier",
        "Classify credential types (Password, Token, Key, MFA, Cookie) and exposure origins (Breach, Stealer, Combo, Repo, Cloud).",
        "COMPLETED_LOCAL" if has_creds else "PLANNED_REQUIRES_CREDENTIAL_EVIDENCE",
        "Typed credential objects with origin metadata.",
        safety_risk="MEDIUM_IF_MISCLASSIFIED_RISK",
        policy_note="Origin explains source, not validity.",
    )

    add(
        "stealer_log_endpoint_correlation",
        "MALINT / INCIDENTINT",
        "Correlate stealer-log metadata with endpoint/device context for forensic investigation.",
        "COMPLETED_LOCAL" if has_steam else "PLANNED_ANALYTIC",
        "Device/host context candidates and malware family links.",
        safety_risk="HIGH_IF_ENDPOINT_IGNORED",
        policy_note="Stealer log != Server breach.",
    )

    add(
        "combo_list_lineage_analysis",
        "BREACHINT / Historical Corpus",
        "Compare combo-list entries against known historical breaches to determine new vs recycled ratio.",
        "COMPLETED_LOCAL" if has_combo else "PLANNED_ANALYTIC",
        "Lineage states: HISTORICAL_AGGREGATE / PARTIALLY_NEW / UNKNOWN.",
        safety_risk="MEDIUM_IF_FALSE_NEW_BREACH",
        policy_note="Combo list != New breach.",
    )

    add(
        "repository_secret_history_audit",
        "REPOINT / Git History Scanner",
        "Audit git history, forks, and caches for residual presence of 'deleted' secrets.",
        "COMPLETED_LOCAL" if has_repo else "PLANNED_ANALYTIC",
        "Purge verification and rotation requirements.",
        safety_risk="HIGH_IF_HISTORY_PERSISTS",
        policy_note="Deleted from HEAD != Removed from History.",
    )

    add(
        "risk_prioritization_without_testing",
        "CREDINT Analyst",
        "Assign risk levels (Emergency/Critical/High/Medium/Low) based on type, origin, freshness, and privilege WITHOUT validating credentials.",
        "PLANNED_ANALYTIC",
        "Prioritized remediation queue.",
        safety_risk="HIGH_IF_VALIDITY_ASSUMED",
        policy_note="Risk != Compromise. Validity Not Tested.",
    )

    return plan


def policy_screen(payload: Dict[str, Any]) -> Dict[str, Any]:
    scanned_text = " ".join(
        [
            str(payload.get("objective", "")),
            " ".join(str(q) for q in payload.get("questions", [])),
            str(payload.get("target", "")),
            " ".join(str(s) for s in payload.get("organizations", [])),
            " ".join(str(s) for s in payload.get("domains", [])),
            " ".join(str(s) for s in payload.get("email_domains", [])),
            " ".join(str(s) for s in payload.get("authorized_accounts", [])),
            " ".join(str(s) for s in payload.get("credential_exposure_claims", [])),
            " ".join(str(s) for s in payload.get("breach_sources", [])),
            " ".join(str(s) for s in payload.get("stealer_log_metadata", [])),
            " ".join(str(s) for s in payload.get("combo_list_metadata", [])),
            " ".join(str(s) for s in payload.get("repository_exposure_metadata", [])),
            " ".join(str(s) for s in payload.get("secret_exposure_metadata", [])),
            str(payload.get("incident_context", "")),
        ]
    ).lower()

    blocked_reasons = [p for p in POLICY_BLOCK_PATTERNS if re.search(p, scanned_text, re.IGNORECASE)]

    human_review_required = False
    safety_notes: List[str] = []

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        human_review_required = True
        safety_notes.append(
            "Sensitive credential/identity/exposure context detected. Analysis must remain defensive, authorized, privacy-aware, and evidence-first. "
            "No login, testing, cracking, stuffing, spraying, replay, purchasing, contacting, or autonomous account changes."
        )

    if payload.get("authorized_accounts") or payload.get("authorized_identity_metadata"):
        human_review_required = True
        safety_notes.append(
            "Authorized account/identity context detected. Respect tenant isolation, privacy, classification, and purpose limitation. Do not infer real person from identifier without authorized evidence."
        )

    if payload.get("credential_exposure_paths") or payload.get("breach_dataset_paths") or payload.get("stealer_log_paths") or payload.get("combo_list_paths"):
        human_review_required = True
        safety_notes.append(
            "Credential/Dataset/Stealer/Combo evidence context detected. Source claims are untrusted evidence, not verified validity, compromise, or breach."
        )

    if blocked_reasons:
        return {
            "status": "POLICY_BLOCKED",
            "reasons": sorted(set(blocked_reasons)),
            "human_review_required": True,
            "safety_notes": safety_notes,
            "explanation": (
                "The requested task appears to require logging in, testing passwords, cracking hashes, credential stuffing, password spraying, "
                "replaying tokens/sessions, using private keys/MFA seeds/recovery codes, purchasing credentials, contacting sellers, or autonomously resetting/disabling accounts."
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
                "No obvious hard policy violation detected, but sensitive credential, identity, exposure, stealer, combo, repository, or incident context applies. "
                "Conclusions must remain defensive, privacy-aware, evidence-linked, and human-reviewed before consequential remediation or notification."
            ),
            "safe_alternatives": SAFE_ALTERNATIVES,
        }

    return {
        "status": "ALLOWED_DEFENSIVE_AUTHORIZED_PUBLIC",
        "reasons": [],
        "human_review_required": False,
        "safety_notes": [],
        "explanation": (
            "No obvious policy violation detected. Execution remains planning-only unless authorized/public/licensed credential, breach, stealer, combo, repository, or STIX/MISP connectors/artifacts are configured."
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
        warnings.append("No CREDINT questions provided. Default questions will be inferred.")

    evidence_keys = [
        "organizations",
        "domains",
        "email_domains",
        "authorized_accounts",
        "authorized_identity_metadata",
        "credential_exposure_claims",
        "breach_sources",
        "stealer_log_metadata",
        "combo_list_metadata",
        "repository_exposure_metadata",
        "secret_exposure_metadata",
        "incident_context",
        "credential_exposure_paths",
        "breach_dataset_paths",
        "stealer_log_paths",
        "combo_list_paths",
        "repository_scan_paths",
        "cloud_secret_paths",
        "darkweb_credential_paths",
        "stix_misp_paths",
    ]

    if not any(payload.get(k) for k in evidence_keys):
        warnings.append("No credential/breach/stealer/combo/repository/cloud/dark-web evidence provided. Output remains planning-only.")

    if not payload.get("time_range"):
        warnings.append("No time range provided. Credential freshness, rotation, and decay are highly temporal.")

    if not payload.get("configured_connectors"):
        warnings.append("No IdP/IAM/Breach-Monitoring/Repo-Scanner connectors configured. External correlation remains planning-only.")

    if payload.get("target_type") in SENSITIVE_TARGET_TYPES:
        warnings.append(
            "Sensitive credential/identity context triggers defensive/privacy/legal controls. "
            "No login, testing, cracking, stuffing, spraying, replay, purchasing, contacting, or autonomous account changes is permitted."
        )

    return warnings


def default_questions(payload: Dict[str, Any]) -> List[str]:
    return [
        "What credential/secret exposure is reported, and for which identifiers/accounts?",
        "What credential type is involved (Password, Token, Key, MFA, Cookie)?",
        "Is the secret plaintext, hashed, tokenized, partial, or unknown?",
        "Where did the exposure originate (First-party Breach, Third-party, Stealer Log, Combo List, Repository, Cloud)?",
        "When was it first/last observed, and is it fresh, historical, or recycled?",
        "Are multiple sources independent, or do they share one upstream dataset?",
        "Does the affected identity belong to an employee, customer, privileged account, or service account (where authorized)?",
        "What risk exists without testing the credential?",
        "Has rotation/revocation been reported or verified by authorized systems?",
        "What defensive action is required (Reset, Revoke, Rotate, Investigate)?",
        "What remains unknown (Validity, Privilege, MFA Status, Account State)?",
        "Which specialist handoff is appropriate (IAM, INCIDENTINT, BREACHINT, MALINT, REPOINT)?",
    ]


class TraceAtlasCREDINTPanel(tk.Tk):
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
            foreground="#a78bfa", # Purple for Credint
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

        ttk.Label(header, text="TraceAtlas CREDINT AI Employee", style="Header.TLabel").pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Defensive / controlled / authorized / privacy-aware / evidence-first credential intelligence • Planning-only by default • "
                "Local deterministic JSON/CSV/TXT credential/secret/exposure metadata parsing only • "
                "No login / no password testing / no hash cracking / no credential stuffing / no token replay / no session hijacking / no private key use / no MFA seed use / no purchasing / no contacting sellers / no autonomous account changes • "
                "Exposure != Validity • Validity != Compromise • Compromise != Breach"
            ),
            style="Subheader.TLabel",
            wraplength=1280,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.input_tab = ttk.Frame(self.notebook)
        self.output_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.input_tab, text="CREDINT Task Input")
        self.notebook.add(self.output_tab, text="Output / CREDINT Plan / Evidence")

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

        ttk.Button(buttons1, text="Add Credential Exposures", command=self.add_credential_exposures).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Breach Datasets", command=self.add_breach_datasets).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Stealer Logs", command=self.add_stealer_logs).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Combo Lists", command=self.add_combo_lists).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Repo Scans", command=self.add_repo_scans).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Cloud Secrets", command=self.add_cloud_secrets).pack(side="left", padx=4)
        ttk.Button(buttons1, text="Add Dark-Web Claims", command=self.add_darkweb_claims).pack(side="left", padx=4)

        ttk.Button(buttons2, text="Add STIX / MISP", command=self.add_stix_misp).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Analyze Local CREDINT Evidence", command=self.analyze_local_credint).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Run Policy Screen", command=self.run_policy_screen).pack(side="left", padx=4)
        ttk.Button(buttons2, text="Generate CREDINT Plan", command=self.generate_plan).pack(side="left", padx=4)
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
            fg="#ddd6fe", # Light purple text
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
        self.set_widget_value("case_id", "CREDINT-CASE-001")
        self.set_widget_value("task_id", "CREDINT-TASK-001")
        self.set_widget_value(
            "objective",
            "Analyze authorized or publicly documented credential-exposure intelligence using defensive, privacy-aware, evidence-first CREDINT methods. "
            "Preserve originals, parse safe credential/secret/exposure metadata deterministically, normalize identifiers safely, classify credential types and exposure origins, "
            "assess freshness and rotation status without testing validity, resolve account contexts where authorized, prioritize remediation, and produce defensive escalation recommendations "
            "without login attempts, password testing, hash cracking, credential stuffing, token replay, session hijacking, private key use, MFA seed use, purchasing credentials, contacting sellers, or autonomous account changes.",
        )
        self.set_widget_value("target", "Illustrative example.com / authorized credential context")
        self.set_widget_value("target_type", "credential_exposure")
        self.set_widget_value(
            "questions",
            "\n".join(default_questions({"target": "Illustrative example.com / authorized credential context"})),
        )

        for field in [
            "organizations",
            "domains",
            "email_domains",
            "authorized_accounts",
            "authorized_identity_metadata",
            "credential_exposure_claims",
            "breach_sources",
            "stealer_log_metadata",
            "combo_list_metadata",
            "repository_exposure_metadata",
            "secret_exposure_metadata",
            "incident_context",
            "credential_exposure_paths",
            "breach_dataset_paths",
            "stealer_log_paths",
            "combo_list_paths",
            "repository_scan_paths",
            "cloud_secret_paths",
            "darkweb_credential_paths",
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
                        "authorized breach-monitoring providers",
                        "licensed credential-exposure providers",
                        "licensed dark-web intelligence",
                        "official breach disclosures",
                        "government/CERT reports",
                        "authorized identity-provider logs",
                        "authorized IAM metadata",
                        "authorized SIEM",
                        "authorized EDR/XDR",
                        "authorized incident-response evidence",
                        "authorized email-security data",
                        "authorized DLP data",
                        "authorized repository scanning",
                        "authorized secret scanning",
                        "authorized cloud-security platforms",
                        "authorized password-management metadata",
                        "authorized enterprise asset/account inventory",
                        "STIX",
                        "MISP",
                        "public threat reports",
                        "public ransomware reports",
                        "public security research",
                    ],
                    "prohibited_sources_and_actions": [
                        "attempt login",
                        "test passwords",
                        "test API keys",
                        "test cloud keys",
                        "test tokens",
                        "replay cookies",
                        "replay sessions",
                        "validate credentials against live services",
                        "perform password spraying",
                        "perform credential stuffing",
                        "perform brute force",
                        "crack passwords for validation",
                        "use recovery codes",
                        "use MFA seeds",
                        "use private keys",
                        "authenticate with exposed secrets",
                        "purchase credentials",
                        "purchase access",
                        "contact sellers",
                        "impersonate users",
                        "reset accounts autonomously",
                        "change passwords autonomously",
                        "disable users autonomously",
                        "access private accounts",
                        "access private messages",
                        "use compromised sessions",
                    ],
                    "data_minimization_rules": [
                        "collect only minimum necessary credential metadata",
                        "prefer redacted identifier, domain, credential type, hash of exposed value where appropriate, source, time, provenance, risk state, rotation state",
                        "avoid retaining plaintext password, full token, full cookie, private key, MFA seed, recovery code, full personal data",
                        "never display secrets in normal reports",
                        "store only where secure evidence handling explicitly requires it",
                    ],
                    "authorized_use": "internal defensive/authorized credential intelligence analysis only",
                },
                indent=2,
            ),
        )
        self.set_widget_value(
            "authorization",
            json.dumps(
                {
                    "authorized_by": "Credential Intelligence Manager / Cyber / Exposure Intelligence Manager",
                    "authorization_basis": "customer-authorized public/licensed/authorized defensive CREDINT engagement",
                    "permitted_actions": [
                        "local credential evidence hashing",
                        "authorized/public/licensed credential/secret/exposure metadata parsing",
                        "identifier normalization and redaction",
                        "credential-type classification",
                        "exposure-origin hypothesis generation",
                        "source pedigree/independence analysis",
                        "risk prioritization without testing",
                        "defensive remediation recommendation",
                        "defensive specialist handoff",
                    ],
                    "prohibited_actions": [
                        "login attempts",
                        "password testing",
                        "hash cracking",
                        "credential stuffing",
                        "password spraying",
                        "token replay",
                        "session hijacking",
                        "private key use",
                        "MFA seed use",
                        "recovery code redemption",
                        "purchasing credentials",
                        "contacting sellers",
                        "autonomous account resets",
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
            "None configured. No IdP/IAM/Breach-Monitoring/Repo-Scanner connector invoked. Planning-only for external enrichment.",
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
        payload["operating_mode"] = "PLANNING_ONLY_DEFENSIVE_PRIVACY_AWARE_EVIDENCE_FIRST"
        payload["source_boundary"] = "DEFENSIVE_CONTROLLED_AUTHORIZED_PRIVACY_AWARE_EVIDENCE_FIRST_CREDINT_ONLY"
        return payload

    def _append_paths(self, field: str, paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        current = self.get_widget_value(field)
        added = "\n".join(paths)
        new_value = current + ("\n" if current else "") + added
        self.set_widget_value(field, new_value)
        messagebox.showinfo(title, f"{len(paths)} path(s) added to {field}.")

    def _add_paths_to_fields(self, fields: List[str], paths: Tuple[str, ...], title: str) -> None:
        if not paths:
            return

        for field in fields:
            current = self.get_widget_value(field)
            added = "\n".join(paths)
            new_value = current + ("\n" if current else "") + added
            self.set_widget_value(field, new_value)

        messagebox.showinfo(title, f"{len(paths)} path(s) added to: {', '.join(fields)}.")

    def add_credential_exposures(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select credential exposure export files",
            filetypes=[
                ("Credential exposures", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("credential_exposure_paths", paths, "Credential Exposure Files Added")

    def add_breach_datasets(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select breach dataset metadata files",
            filetypes=[
                ("Breach datasets", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("breach_dataset_paths", paths, "Breach Dataset Files Added")

    def add_stealer_logs(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select stealer log metadata files",
            filetypes=[
                ("Stealer logs", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("stealer_log_paths", paths, "Stealer Log Files Added")

    def add_combo_lists(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select combo list metadata files",
            filetypes=[
                ("Combo lists", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("combo_list_paths", paths, "Combo List Files Added")

    def add_repo_scans(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select repository scan result files",
            filetypes=[
                ("Repo scans", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("repository_scan_paths", paths, "Repository Scan Files Added")

    def add_cloud_secrets(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select cloud secret exposure files",
            filetypes=[
                ("Cloud secrets", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("cloud_secret_paths", paths, "Cloud Secret Files Added")

    def add_darkweb_claims(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Select dark-web credential claim files",
            filetypes=[
                ("Dark-web claims", "*.json *.csv *.tsv *.txt *.log"),
                ("All files", "*.*"),
            ],
        )
        self._append_paths("darkweb_credential_paths", paths, "Dark-Web Claim Files Added")

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
                "has_organizations": bool(payload.get("organizations")),
                "has_domains": bool(payload.get("domains")),
                "has_email_domains": bool(payload.get("email_domains")),
                "has_authorized_accounts": bool(payload.get("authorized_accounts")),
                "has_credential_claims": bool(payload.get("credential_exposure_claims")),
                "has_breach_sources": bool(payload.get("breach_sources")),
                "has_stealer_metadata": bool(payload.get("stealer_log_metadata")),
                "has_combo_metadata": bool(payload.get("combo_list_metadata")),
                "has_repo_metadata": bool(payload.get("repository_exposure_metadata")),
                "has_secret_metadata": bool(payload.get("secret_exposure_metadata")),
                "has_incident_context": bool(payload.get("incident_context")),
                "has_credential_paths": bool(payload.get("credential_exposure_paths")),
                "has_breach_paths": bool(payload.get("breach_dataset_paths")),
                "has_stealer_paths": bool(payload.get("stealer_log_paths")),
                "has_combo_paths": bool(payload.get("combo_list_paths")),
                "has_repo_paths": bool(payload.get("repository_scan_paths")),
                "has_cloud_paths": bool(payload.get("cloud_secret_paths")),
                "has_darkweb_paths": bool(payload.get("darkweb_credential_paths")),
                "has_stix_misp_paths": bool(payload.get("stix_misp_paths")),
            },
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if policy["status"] == "POLICY_BLOCKED":
            messagebox.showwarning(
                "Policy Blocked",
                "This CREDINT request is policy-blocked.\n\n"
                + "\n".join(policy["reasons"])
                + "\n\nUse only defensive/authorized alternatives.",
            )
        elif policy["status"] == "HUMAN_REVIEW_REQUIRED":
            messagebox.showwarning(
                "Human Review Required",
                "No hard policy block detected, but sensitive credential/identity/exposure context applies.",
            )
        else:
            messagebox.showinfo(
                "Policy Screen",
                "No obvious policy violation detected. Planning-only mode remains active.",
            )

    def analyze_local_credint(self) -> None:
        payload = self.collect_payload()
        policy = policy_screen(payload)

        if policy["status"] == "POLICY_BLOCKED":
            result = {
                "mode": "POLICY_BLOCKED",
                "panel_version": APP_VERSION,
                "policy_screen": policy,
                "evidence_inventory": [],
                "credentials_preview": [],
                "identifiers_preview": [],
                "observations": [],
                "candidate_facts": [],
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning("Policy Blocked", "Local CREDINT evidence analysis blocked by policy screen.")
            return

        path_fields = [
            "credential_exposure_paths",
            "breach_dataset_paths",
            "stealer_log_paths",
            "combo_list_paths",
            "repository_scan_paths",
            "cloud_secret_paths",
            "darkweb_credential_paths",
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
            messagebox.showwarning("No CREDINT Evidence", "Add local authorized/public/licensed credential evidence files first.")
            return

        self.output.delete("1.0", "end")
        self.output.insert("1.0", "Analyzing local authorized/public/licensed CREDINT evidence. Hashing and parsing may take time...\n")
        self.notebook.select(self.output_tab)

        files: List[Dict[str, Any]] = []
        parsed_list: List[Dict[str, Any]] = []

        for p in all_paths[:30]:
            f, parsed = analyze_credential_file(p, payload.get("case_id", ""), payload.get("task_id", ""))
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
            "Local CREDINT Evidence Analysis Complete",
            f"Processed {len(files)} evidence file(s).\n"
            f"Succeeded/partial: {succeeded}\n"
            f"Credentials: {len(aggregated.get('credentials', []))}\n"
            f"Identifiers: {len(aggregated.get('identifiers', []))}\n"
            f"Sources: {len(aggregated.get('sources', []))}\n"
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
                "credint_collection_plan": [],
                "next_best_action": {
                    "action": "Revise task to remove prohibited login, testing, cracking, stuffing, spraying, replay, purchasing, contacting, or autonomous account change behavior.",
                    "owner": "Credential Intelligence Manager",
                    "expected_output": "Policy-compliant defensive CREDINT scope and question set.",
                },
            }
            self.last_result = result
            self._write_output(result)
            messagebox.showwarning(
                "Policy Blocked",
                "CREDINT plan not generated because the request is policy-blocked.",
            )
            return

        questions = payload.get("questions") or default_questions(payload)

        if not self.parsed.get("credentials") and not self.parsed.get("identifiers"):
            self.parsed = finalize_parsed(empty_parsed(), payload, self.analyzed_files)

        files = self.analyzed_files
        parsed = self.parsed

        next_action = build_next_best_action(payload, policy, files, parsed)
        collection_plan = build_collection_plan(payload, questions, files, parsed)

        overall_status = "PLANNING_ONLY"
        if policy["status"] == "HUMAN_REVIEW_REQUIRED":
            overall_status = "HUMAN_REVIEW_REQUIRED"
        if files or parsed.get("credentials") or parsed.get("identifiers"):
            overall_status = "PLANNING_PLUS_LOCAL_DETERMINISTIC_EVIDENCE"

        result = {
            "mode": overall_status,
            "panel_version": APP_VERSION,
            "policy": (
                "This output does not attempt login, test passwords, crack hashes, perform credential stuffing, password spraying, brute force, replay session cookies/tokens, "
                "use private keys, MFA seeds, or recovery codes, authenticate with exposed secrets, purchase credentials/access, contact sellers, impersonate users, "
                "reset/change/disable accounts autonomously, access private accounts/messages, or use compromised sessions. "
                "Local deterministic analysis is limited to hashing, safe JSON/CSV/TXT credential/secret/exposure metadata parsing, identifier normalization/redaction, "
                "credential-type classification, exposure-origin hypothesis generation, source pedigree/independence, temporal validation, duplicate/recycled check, "
                "risk prioritization without testing, contradiction detection, competing hypotheses, falsification, secret redaction, prompt-injection flagging, "
                "and defensive specialist handoff planning. Live IdP/IAM/Breach-Monitoring/Repo-Scanner enrichment, notification, legal action, and consequential remediation remain planning-only unless configured/authorized/human-reviewed."
            ),
            "policy_screen": policy,
            "warnings": warnings,
            "payload": payload,
            "intelligence_questions": questions,
            "evidence_inventory": files,
            "credentials_preview": parsed.get("credentials", [])[:300],
            "identifiers_preview": parsed.get("identifiers", [])[:300],
            "accounts_preview": parsed.get("accounts", [])[:300],
            "exposures_preview": parsed.get("exposures", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "next_best_action": next_action,
            "credint_collection_plan": collection_plan,
            **self._policy_sections(),
            **self._schemas(),
        }

        self.last_result = result
        self._write_output(result)
        self.notebook.select(self.output_tab)

        if warnings:
            messagebox.showwarning(
                "Validation Warnings",
                "CREDINT plan generated with warnings:\n\n" + "\n".join(warnings),
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
                "statement": f"A local authorized/public/licensed CREDINT evidence file was accessed and hashed: {f.get('filename')}.",
                "evidence_id": f.get("evidence_id"),
                "source_id": f.get("source_id"),
                "observed_at": now_utc(),
                "extraction_method": "local_deterministic_file_hash",
                "limitations": "File hash does not prove credential validity, account compromise, or organization breach.",
            })

        observations.extend([
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(files)} CREDINT evidence file(s) were parsed locally.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "safe_json_csv_text_credential_parser",
                "limitations": "Parser output is normalized evidence, not verified external reality.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": f"{len(parsed.get('credentials', []))} credential record(s) and {len(parsed.get('identifiers', []))} identifier record(s) were extracted.",
                "evidence_id": "AGGREGATE",
                "source_id": "LOCAL_CREDENTIAL_PARSER",
                "observed_at": now_utc(),
                "extraction_method": "credential_identifier_extraction_normalization",
                "limitations": "Credential exposure metadata is not proof of current validity.",
            },
            {
                "observation_id": f"OBS-{uuid.uuid4()}",
                "statement": "No login attempts, password testing, hash cracking, credential stuffing, token replay, session hijacking, private key use, MFA seed use, purchasing credentials, contacting sellers, or autonomous account changes were performed.",
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
                    "candidate_fact": f"The preserved local CREDINT evidence artifact {f.get('filename')} has SHA256 {f.get('sha256')}.",
                    "status": "SUPPORTED",
                    "evidence_ids": [f.get("evidence_id")],
                    "notes": "Supported by deterministic local hashing. Does not prove credential validity or compromise.",
                })

        candidate_facts.extend([
            {
                "candidate_fact": f"{len(parsed.get('credentials', []))} credential exposure candidate(s) were extracted.",
                "status": "SUPPORTED_AS_CANDIDATE_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "not_supported": [
                    "verified credential validity",
                    "verified account compromise",
                    "verified organization breach",
                    "verified actor attribution",
                ],
            },
            {
                "candidate_fact": f"{len(parsed.get('identifiers', []))} identifier normalization/redaction record(s) were created.",
                "status": "SUPPORTED_AS_IDENTIFIER_METADATA_ONLY",
                "evidence_ids": ["AGGREGATE"],
                "notes": "Identifiers are hashed/redacted for privacy-preserving deduplication.",
            },
            {
                "candidate_fact": "No login attempts, password testing, hash cracking, credential stuffing, token replay, session hijacking, private key use, MFA seed use, purchasing credentials, contacting sellers, or autonomous account changes were performed.",
                "status": "SUPPORTED",
                "evidence_ids": ["LOCAL_PANEL_POLICY"],
                "notes": "Defensive/privacy-aware planning boundary.",
            },
        ])

        candidate_facts, _ = truncate_list(candidate_facts, 200)

        fact_gate = {
            "status": "LOCAL_DETERMINISTIC_ONLY" if files or parsed.get("credentials") else "NO_LOCAL_CREDINT_EVIDENCE",
            "supported": [
                "file/source existence and SHA256 hash",
                "parsed credential exposure metadata",
                "parsed identifier normalization/redaction",
                "parsed credential-type classification",
                "parsed exposure-origin hypothesis",
                "parsed temporal freshness/decay states",
                "parsed source independence preliminary states",
                "contradiction candidates",
                "competing hypotheses",
                "secret redaction flags",
                "prompt-injection flags",
            ],
            "not_supported": [
                "verified credential validity",
                "verified account compromise",
                "verified organization breach",
                "verified actor attribution",
                "verified root cause",
                "verified initial access vector",
                "verified compromised host",
                "final legal determination",
                "autonomous user/customer/employee notification",
                "autonomous law-enforcement referral",
                "purchase of stolen data/credentials/access",
                "credential testing",
                "login using exposed credentials",
                "session-token replay",
                "API/private-key use",
                "seller contact",
                "ransomware negotiation/payment",
                "unnecessary full stolen-dataset acquisition",
                "redistribution of sensitive data",
                "unauthorized access",
                "exploitation",
            ],
            "safety_status": (
                "No login attempts, password testing, hash cracking, credential stuffing, token replay, session hijacking, "
                "private key use, MFA seed use, purchasing credentials, contacting sellers, or autonomous account changes performed."
            ),
        }

        return {
            "mode": "LOCAL_DETERMINISTIC_CREDINT_ANALYSIS",
            "panel_version": APP_VERSION,
            "policy_screen": policy,
            "login_attempt_performed": False,
            "password_testing_performed": False,
            "hash_cracking_performed": False,
            "credential_stuffing_performed": False,
            "password_spraying_performed": False,
            "token_replay_performed": False,
            "session_hijacking_performed": False,
            "private_key_use_performed": False,
            "mfa_seed_use_performed": False,
            "recovery_code_use_performed": False,
            "credential_purchase_performed": False,
            "seller_contact_performed": False,
            "autonomous_account_change_performed": False,
            "evidence_inventory": files,
            "credentials_preview": parsed.get("credentials", [])[:300],
            "identifiers_preview": parsed.get("identifiers", [])[:300],
            "accounts_preview": parsed.get("accounts", [])[:300],
            "exposures_preview": parsed.get("exposures", [])[:300],
            "contradictions": parsed.get("contradictions", [])[:1000],
            "hypotheses": parsed.get("hypotheses", [])[:1000],
            "knowledge_gaps": parsed.get("knowledge_gaps", [])[:500],
            "specialist_handoffs": parsed.get("specialist_handoffs", [])[:500],
            "observations": observations,
            "candidate_facts": candidate_facts,
            "fact_gate": fact_gate,
            "recommended_next_actions": next_action,
            "credint_collection_plan_preview": collection_plan[:20],
            "limitations": [
                "Only local deterministic checks were performed.",
                "No network access was performed.",
                "No login attempts, password testing, hash cracking, credential stuffing, token replay, session hijacking, private key use, MFA seed use, purchasing credentials, contacting sellers, or autonomous account changes were performed.",
                "Credential exposure is not validity.",
                "Valid credential is not compromised account.",
                "Account compromise is not organization breach.",
                "Employee email in dataset is not first-party breach.",
                "Stealer log is not server breach.",
                "Combo list is not new breach.",
                "Session exposure is not password exposure.",
                "MFA enabled is not zero risk.",
                "Account active is not password valid.",
                "Secret deleted from repository is not secret rotated.",
                "Source claim is not current validity.",
                "Multiple reposts are not multiple exposures.",
                "Multiple providers are not independent sources if they share the same dataset.",
                "AI agreement is not credential validity.",
                "Exposed secrets were redacted heuristically and not used.",
                "Credential/dataset/source content was treated as untrusted evidence.",
            ],
        }

    def _write_output(self, result: Dict[str, Any]) -> None:
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2, default=str))

    def _policy_sections(self) -> Dict[str, Any]:
        return {
            "role": {
                "employee": "CREDINT AI Employee",
                "hierarchy": [
                    "Chief Intelligence Manager",
                    "Cyber / Exposure Intelligence Manager",
                    "Credential Intelligence Manager",
                    "CREDINT AI Employee",
                    "Credential / Secret / Exposure / Provenance / Identity-Risk / Defensive-Response Skills",
                ],
                "not": [
                    "credential tester",
                    "login automation system",
                    "password cracker",
                    "credential-stuffing system",
                    "password-spraying system",
                    "session hijacker",
                    "token replay system",
                    "account takeover agent",
                    "identity impersonation system",
                ],
            },
            "core_principle": [
                "EXPOSURE CLAIM",
                "PRESERVE EVIDENCE",
                "IDENTIFIER NORMALIZATION",
                "CREDENTIAL-TYPE CLASSIFICATION",
                "ORGANIZATION / ACCOUNT RESOLUTION",
                "SOURCE PEDIGREE",
                "TEMPORAL VALIDATION",
                "DUPLICATE / RECYCLED CHECK",
                "SOURCE INDEPENDENCE",
                "RISK ASSESSMENT",
                "FACT GATE",
                "DEFENSIVE REMEDIATION",
            ],
            "critical_separations": [
                "credential exposure != validity",
                "valid credential != compromised account",
                "account compromise != organization breach",
                "employee email in dataset != first-party breach",
                "stealer log != server breach",
                "combo list != new breach",
                "session exposure != password exposure",
                "MFA enabled != zero risk",
                "account active != password valid",
                "secret deleted from repository != secret rotated",
                "source claim != current validity",
                "multiple reposts != multiple exposures",
                "multiple providers != independent sources if they share the same dataset",
                "AI agreement != credential validity",
            ],
            "hard_restrictions": [
                "Do not attempt login.",
                "Do not test passwords.",
                "Do not test API keys.",
                "Do not test cloud keys.",
                "Do not test tokens.",
                "Do not replay cookies.",
                "Do not replay sessions.",
                "Do not validate credentials against live services.",
                "Do not perform password spraying.",
                "Do not perform credential stuffing.",
                "Do not perform brute force.",
                "Do not crack passwords for validation.",
                "Do not use recovery codes.",
                "Do not use MFA seeds.",
                "Do not use private keys.",
                "Do not authenticate with exposed secrets.",
                "Do not purchase credentials.",
                "Do not purchase access.",
                "Do not contact sellers.",
                "Do not impersonate users.",
                "Do not reset accounts autonomously.",
                "Do not change passwords autonomously.",
                "Do not disable users autonomously.",
                "Do not access private accounts.",
                "Do not access private messages.",
                "Do not use compromised sessions.",
            ],
            "data_minimization_policy": [
                "Collect only minimum necessary credential metadata.",
                "Prefer redacted identifier, domain, credential type, hash of exposed value where appropriate, source, time, provenance, risk state, rotation state.",
                "Avoid retaining plaintext password, full token, full cookie, private key, MFA seed, recovery code, full personal data.",
            ],
            "secret_display_policy": [
                "Never display secrets in normal reports.",
                "Example: username: s***@example.com, password: [REDACTED], token: sha256:<fingerprint>, private key: [REDACTED_PRIVATE_KEY].",
                "Store only where secure evidence handling explicitly requires it.",
            ],
            "credential_types": [
                "EMAIL_PASSWORD",
                "USERNAME_PASSWORD",
                "PASSWORD_HASH",
                "SESSION_COOKIE",
                "SESSION_TOKEN",
                "ACCESS_TOKEN",
                "REFRESH_TOKEN",
                "API_KEY",
                "CLOUD_ACCESS_KEY",
                "PRIVATE_KEY",
                "SSH_KEY",
                "CERTIFICATE_PRIVATE_KEY",
                "MFA_SEED",
                "RECOVERY_CODE",
                "APPLICATION_SECRET",
                "DATABASE_CREDENTIAL",
                "SERVICE_ACCOUNT_SECRET",
                "OAUTH_CLIENT_SECRET",
                "OTHER_SECRET",
                "UNKNOWN",
            ],
            "secret_states": [
                "PLAINTEXT_REPORTED",
                "HASHED",
                "PARTIAL",
                "REDACTED",
                "TOKENIZED",
                "ENCRYPTED",
                "SECRET_VALUE_NOT_COLLECTED",
                "UNKNOWN",
            ],
            "exposure_origins": [
                "FIRST_PARTY_BREACH",
                "THIRD_PARTY_BREACH",
                "STEALER_LOG",
                "COMBO_LIST",
                "PHISHING_REPORT",
                "REPOSITORY_EXPOSURE",
                "CLOUD_EXPOSURE",
                "PASTE_LEAK",
                "DARKWEB_LISTING",
                "RANSOMWARE_DATASET",
                "PUBLIC_DATA",
                "UNKNOWN",
            ],
            "validity_states": [
                "VALIDITY_NOT_TESTED",
                "LIKELY_INVALID_BY_ROTATION",
                "REVOKED_VERIFIED_BY_OWNER_SYSTEM",
                "ACTIVE_STATUS_UNKNOWN",
                "EXPIRED_BY_METADATA",
                "UNKNOWN",
            ],
            "rotation_states": [
                "ROTATION_NOT_ASSESSED",
                "ROTATION_REQUIRED",
                "ROTATED_REPORTED",
                "ROTATED_VERIFIED_BY_AUTHORIZED_SYSTEM",
                "REVOKED_REPORTED",
                "REVOKED_VERIFIED",
                "UNKNOWN",
            ],
            "freshness_states": [
                "CURRENT",
                "RECENT",
                "AGING",
                "STALE",
                "HISTORICAL",
                "MIXED",
                "UNKNOWN",
            ],
            "risk_levels": [
                "EMERGENCY",
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFORMATIONAL",
                "UNKNOWN",
            ],
            "non_negotiable_rules": [
                "DO NOT TEST PASSWORDS.",
                "DO NOT TEST USERNAMES.",
                "DO NOT LOGIN USING EXPOSED CREDENTIALS.",
                "DO NOT PASSWORD SPRAY.",
                "DO NOT CREDENTIAL STUFF.",
                "DO NOT BRUTE FORCE.",
                "DO NOT CRACK PASSWORD HASHES TO VALIDATE EXPOSURE.",
                "DO NOT REPLAY SESSION COOKIES.",
                "DO NOT REPLAY ACCESS TOKENS.",
                "DO NOT EXCHANGE REFRESH TOKENS.",
                "DO NOT USE API KEYS.",
                "DO NOT USE CLOUD KEYS.",
                "DO NOT USE PRIVATE KEYS.",
                "DO NOT USE MFA SEEDS.",
                "DO NOT USE RECOVERY CODES.",
                "DO NOT PURCHASE CREDENTIALS.",
                "DO NOT PURCHASE ACCESS.",
                "DO NOT CONTACT SELLERS.",
                "DO NOT IMPERSONATE USERS.",
                "DO NOT ACCESS PRIVATE ACCOUNTS.",
                "DO NOT STORE RAW PLAINTEXT SECRETS IN NORMAL GRAPH MEMORY.",
                "DO NOT SEND SENSITIVE CREDENTIAL DATA TO CLOUD MODELS WITHOUT EXPLICIT APPROVAL.",
                "DO NOT EQUATE CREDENTIAL EXPOSURE WITH VALID CREDENTIAL.",
                "DO NOT EQUATE VALID CREDENTIAL WITH ACCOUNT COMPROMISE.",
                "DO NOT EQUATE ACCOUNT COMPROMISE WITH ORGANIZATION BREACH.",
                "DO NOT EQUATE EMPLOYEE EMAIL IN DATASET WITH FIRST-PARTY BREACH.",
                "DO NOT EQUATE STEALER LOG WITH SERVER BREACH.",
                "DO NOT EQUATE COMBO LIST WITH NEW BREACH.",
                "DO NOT EQUATE SESSION EXPOSURE WITH PASSWORD EXPOSURE.",
                "DO NOT EQUATE MFA ENABLED WITH ZERO RISK.",
                "DO NOT EQUATE ACCOUNT ACTIVE WITH PASSWORD VALID.",
                "DO NOT EQUATE ACCOUNT DISABLED WITH ALL TOKENS INVALID WITHOUT EVIDENCE.",
                "DO NOT EQUATE PASSWORD RESET WITH SESSION REVOCATION.",
                "DO NOT EQUATE SECRET DELETED FROM REPOSITORY WITH SECRET ROTATED.",
                "DO NOT EQUATE SOURCE CLAIM WITH CURRENT VALIDITY.",
                "DO NOT EQUATE MULTIPLE REPOSTS WITH MULTIPLE EXPOSURES.",
                "DO NOT EQUATE MULTIPLE PROVIDERS WITH INDEPENDENT SOURCES IF THEY SHARE THE SAME DATASET.",
                "DO NOT EQUATE AI AGREEMENT WITH CREDENTIAL VALIDITY.",
                "DO NOT HIDE THIRD-PARTY ORIGIN.",
                "DO NOT HIDE RECYCLING.",
                "DO NOT HIDE ROTATION UNCERTAINTY.",
                "DO NOT HIDE ACCOUNT-STATUS UNCERTAINTY.",
                "DO NOT HIDE PRIVACY RISK.",
                "DO NOT INVENT CREDENTIALS.",
                "DO NOT INVENT USERS.",
                "DO NOT INVENT VALIDITY.",
                "DO NOT INVENT ROTATION.",
                "DO NOT INVENT COMPROMISE.",
                "DO NOT LOSE EXPOSURE HISTORY.",
            ],
        }

    def _schemas(self) -> Dict[str, Any]:
        return {
            "credential_evidence_schema": {
                "evidence_id": "Unique CREDINT evidence identifier",
                "case_id": "Case identifier",
                "source_id": "Source identifier",
                "source_type": "Breach / Stealer / Combo / Repo / Cloud / Darkweb / STIX / MISP / etc.",
                "credential_type": "Detected credential type",
                "identifier_reference": "Reference to identifier object",
                "redacted_identifier": "Redacted form of identifier",
                "secret_fingerprint": "Hash of secret value if collected securely",
                "observed_at": "Observation timestamp",
                "first_seen": "First source-seen timestamp",
                "last_seen": "Last source-seen timestamp",
                "published_at": "Publication timestamp",
                "retrieved_at": "Retrieval timestamp",
                "content_hash": "SHA256 of original artifact/value",
                "raw_artifact_reference": "Secure path/object storage reference",
                "parser_version": "Parser version",
                "normalizer_version": "Normalizer version",
                "authorization_context": "Authorization basis/reference",
            },
            "credential_schema": {
                "credential_id": "Unique credential identifier",
                "identifier_id": "Associated identifier identifier",
                "credential_type": "Type of credential",
                "secret_state": "State of secret material",
                "exposure_source": "Direct source of exposure",
                "exposure_origin": "Broader origin category",
                "first_seen": "First seen timestamp",
                "last_seen": "Last seen timestamp",
                "freshness": "Freshness state",
                "validity_state": "Validity state (Not Tested)",
                "rotation_state": "Rotation/Revocation state",
                "privilege_context": "Privilege level if known",
                "account_type": "Account type if known",
                "risk": "Calculated risk level",
                "confidence": "Confidence in classification",
                "evidence_ids": "Linked evidence IDs",
                "limitations": [
                    "Credential exposure metadata does not prove current validity.",
                    "No login/testing performed.",
                ],
            },
            "identifier_schema": {
                "identifier_id": "Unique identifier",
                "type": "EMAIL / USERNAME / UPN / SERVICE_PRINCIPAL / etc.",
                "raw_redacted": "Redacted raw value",
                "normalized_hash": "SHA256 hash of normalized value for deduplication",
                "source_id": "Source identifier",
                "evidence_id": "Evidence identifier",
                "context": "Context of observation",
                "temporal": "Temporal metadata",
                "state": "IDENTIFIER_NORMALIZED",
                "limitations": [
                    "Identifier hash is used for deduplication/provenance tracking without storing raw PII unnecessarily.",
                ],
            },
            "credint_result_schema": [
                "case_id",
                "task_id",
                "objective",
                "questions",
                "source_ids",
                "evidence_ids",
                "credential_exposures",
                "identifiers",
                "redacted_identifiers",
                "accounts",
                "account_types",
                "account_states",
                "credential_types",
                "secret_states",
                "secret_fingerprints",
                "exposure_origins",
                "breach_context",
                "stealer_log_context",
                "combo_list_context",
                "repository_context",
                "darkweb_context",
                "first_seen",
                "last_seen",
                "freshness",
                "validity_states",
                "rotation_states",
                "revocation_states",
                "mfa_context",
                "session_context",
                "password_hash_context",
                "api_key_context",
                "cloud_secret_context",
                "private_key_context",
                "service_account_context",
                "machine_identity_context",
                "privilege_context",
                "password_reuse_risk",
                "identity_risk",
                "business_criticality",
                "source_pedigree",
                "duplicate_exposures",
                "credential_lineage",
                "timeline_updates",
                "observations",
                "candidate_facts",
                "supported_facts",
                "partial_facts",
                "disputed_facts",
                "source_reliability",
                "source_bias",
                "source_limitations",
                "source_independence",
                "contradictions",
                "hypotheses",
                "falsification_results",
                "incident_escalation_context",
                "remediation_priority",
                "privacy_flags",
                "unknowns",
                "knowledge_gaps",
                "recommended_next_actions",
                "specialist_handoffs",
                "limitations",
                "status",
            ],
            "required_analyst_summary_format": [
                "CREDENTIAL EXPOSURE STATUS",
                "IDENTIFIER",
                "ACCOUNT TYPE",
                "ACCOUNT STATUS",
                "CREDENTIAL / SECRET TYPE",
                "SOURCE",
                "EXPOSURE ORIGIN",
                "FIRST SEEN",
                "LAST SEEN",
                "FRESHNESS",
                "VALIDITY STATUS",
                "ROTATION / REVOCATION STATUS",
                "MFA / SESSION CONTEXT",
                "PRIVILEGE",
                "BUSINESS CRITICALITY",
                "STEALER / COMBO / BREACH CONTEXT",
                "PASSWORD-REUSE RISK",
                "SOURCE RELIABILITY",
                "SOURCE INDEPENDENCE",
                "DUPLICATE / RECYCLED EXPOSURE",
                "ACCOUNT-COMPROMISE EVIDENCE",
                "RISK",
                "UNKNOWN",
                "REMEDIATION",
                "NEXT ACTION",
            ],
            "credint_report_sections": [
                "Objective",
                "Authorized Scope",
                "Privacy / Handling Boundaries",
                "Credential Exposure Inventory",
                "Identifiers",
                "Account Resolution",
                "Credential Types",
                "Secret Types",
                "Exposure Origins",
                "Breach Context",
                "Stealer-Log Context",
                "Combo-List Context",
                "Repository / Secret Exposure",
                "Dark-Web Context",
                "Source Pedigree",
                "Credential Lineage",
                "Duplicate Exposure",
                "First Seen / Last Seen",
                "Freshness",
                "Validity Status",
                "Rotation / Revocation",
                "MFA Context",
                "Session Exposure",
                "Password Hash Context",
                "API Key / Cloud Secret Context",
                "Private Key Context",
                "Service Account / Machine Identity",
                "Privilege Context",
                "Password-Reuse Risk",
                "Identity Risk",
                "Business Criticality",
                "Incident Correlation",
                "Source Reliability",
                "Source Bias / Limitations",
                "Source Independence",
                "Facts",
                "Observations",
                "Contradictions",
                "Competing Hypotheses",
                "Falsification",
                "Risk Prioritization",
                "Privacy Flags",
                "Unknowns",
                "Knowledge Gaps",
                "Defensive Remediation",
                "Specialist Handoffs",
                "Limitations",
                "Evidence / Citations",
                "Replay Manifest",
            ],
            "replay_requirements_policy": {
                "preserve": [
                    "source",
                    "source version",
                    "dataset ID",
                    "credential fingerprint",
                    "identifier normalization",
                    "exposure timestamp",
                    "breach/stealer/combo origin",
                    "account-resolution evidence",
                    "rotation evidence",
                    "revocation evidence",
                    "source-pedigree graph",
                    "source-independence result",
                    "fact-gate result",
                    "risk calculation",
                    "redaction operations",
                    "model versions",
                    "graph updates",
                ],
                "rule": (
                    "Replay must answer WHERE DID THIS CREDENTIAL EXPOSURE COME FROM? WAS RAW SECRET RETAINED? "
                    "WHICH ACCOUNT WAS IT ASSOCIATED WITH? IS THE ACCOUNT STILL ACTIVE? WAS THE SECRET ROTATED? "
                    "WAS VALIDITY EVER TESTED? ANSWER MUST BE: NO, CREDINT DOES NOT TEST CREDENTIAL VALIDITY THROUGH LOGIN. "
                    "WHICH SOURCES ARE INDEPENDENT? WHAT EVIDENCE SUPPORTS ACCOUNT COMPROMISE, IF ANY?"
                ),
            },
            "collection_plan_schema": {
                "question": "CREDINT question or general collection planning",
                "operation": "Planned defensive CREDINT operation",
                "tool_or_provider": "Tool/source/connector",
                "purpose": "Why this operation matters",
                "status": "COMPLETED_LOCAL/PLANNED_REQUIRES_EVIDENCE/PLANNED_REQUIRES_IDENTITY_EVIDENCE/PLANNED_REQUIRES_CREDENTIAL_EVIDENCE/PLANNED_ANALYTIC/BLOCKED_CONFIGURATION/PLANNED_REQUIRES_CONNECTOR/REQUIRED_BEFORE_COLLECTION",
                "expected_output": "Expected intelligence output",
                "priority": "Rank",
                "safety_risk": "LOW/MEDIUM/HIGH/HIGH_PRIVACY_SENSITIVE",
                "policy_note": "Defensive/authorized/privacy-aware/evidence-first boundary",
                "authorization_status": "ALLOWED_DEFENSIVE_AUTHORIZED_PUBLIC",
                "execution_status": "NOT_EXECUTED_PLANNING_ONLY",
            },
        }

    def export_json(self) -> None:
        if not self.last_result:
            self.generate_plan()

        data = self.last_result or self.collect_payload()

        payload_for_name = data.get("payload") or data.get("payload_preview") or data
        case_id = payload_for_name.get("case_id", "credint")
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
            messagebox.showinfo("Export Complete", f"CREDINT JSON saved to:\n{path}")
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
            "Are you sure you want to clear all fields, analyzed CREDINT evidence, and reset defaults?",
        )
        if not confirm:
            return

        self._set_defaults()
        self.output.delete("1.0", "end")
        self.last_result = {}
        self.analyzed_files = []
        self.parsed = empty_parsed()


if __name__ == "__main__":
    app = TraceAtlasCREDINTPanel()
    app.mainloop()
