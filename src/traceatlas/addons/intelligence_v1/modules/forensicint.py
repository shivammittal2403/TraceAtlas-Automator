from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import statistics
import unicodedata
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

# ==============================================================================
# TRACEATLAS — FORENSICINT
# DIGITAL FORENSICS INTELLIGENCE AI EMPLOYEE
# MODE: DEFENSIVE / AUTHORIZED / EVIDENCE-FIRST / REPRODUCIBLE / PRIVACY-AWARE
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("TRACEATLAS.FORENSICINT")


# ==============================================================================
# SECTION 11: HARD RESTRICTIONS / POLICY ENGINE
# ==============================================================================

class PolicyViolation(Exception):
    pass


PROHIBITED_SCOPE_FLAGS = (
    "allow_device_intrusion",
    "allow_unauthorized_device_access",
    "allow_authentication_bypass",
    "allow_mfa_bypass",
    "allow_stolen_credentials",
    "allow_recovered_password_use",
    "allow_recovered_token_use",
    "allow_session_replay",
    "allow_private_key_use",
    "allow_spyware",
    "allow_microphone_activation",
    "allow_camera_activation",
    "allow_monitoring_agent_installation",
    "allow_target_exploitation",
    "allow_persistence",
    "allow_modify_original_evidence",
    "allow_write_to_forensic_image",
    "allow_delete_evidence",
    "allow_wipe_logs",
    "allow_tamper_timestamps",
    "allow_alter_files",
    "allow_disable_security_controls",
    "allow_perform_anti_forensics",
    "allow_teach_evidence_destruction",
    "allow_teach_log_wiping",
    "allow_teach_timestamp_manipulation",
    "allow_teach_secure_delete_evasion",
    "allow_deploy_malware",
    "allow_exfiltrate_data",
    "allow_contact_external_accounts_using_recovered_credentials",
    "allow_password_cracking",
    "allow_unauthorized_decryption",
)

PROHIBITED_OBJECTIVE_KEYWORDS = (
    "bypass login",
    "bypass authentication",
    "bypass mfa",
    "stolen credential",
    "use recovered password",
    "use recovered token",
    "replay session",
    "use private key",
    "deploy spyware",
    "activate microphone",
    "activate camera",
    "install monitoring agent",
    "exploit target",
    "perform persistence",
    "modify original evidence",
    "write to forensic image",
    "delete evidence",
    "wipe logs",
    "tamper timestamp",
    "alter file",
    "disable security control",
    "anti-forensic instruction",
    "anti forensics instruction",
    "evidence destruction instruction",
    "log wiping instruction",
    "timestamp manipulation instruction",
    "secure delete evasion",
    "deploy malware",
    "exfiltrate data",
    "crack password",
    "password cracking",
    "unauthorized decryption",
    "access unauthorized device",
    "login with recovered credential",
)


def enforce_policy(objective: str, scope: Dict[str, Any]) -> None:
    """
    Enforces FORENSICINT hard restrictions.

    Defensive, authorized, read-only forensic intelligence only.
    """
    if not isinstance(scope, dict):
        raise PolicyViolation("POLICY_BLOCKED: scope must be a dictionary.")

    # Read-only default.
    if scope.get("read_only", True) is False and not scope.get("authorized_forensic_write"):
        raise PolicyViolation(
            "POLICY_BLOCKED: FORENSICINT operates READ_ONLY by default. "
            "Original evidence must not be modified."
        )

    for flag in PROHIBITED_SCOPE_FLAGS:
        if scope.get(flag, False):
            raise PolicyViolation(f"POLICY_BLOCKED: prohibited scope flag '{flag}'.")

    objective_lower = (objective or "").lower()
    for keyword in PROHIBITED_OBJECTIVE_KEYWORDS:
        if keyword in objective_lower:
            raise PolicyViolation(
                f"POLICY_BLOCKED: objective contains prohibited concept '{keyword}'."
            )


# ==============================================================================
# ENUMS / STATES
# ==============================================================================

class ChainOfCustodyState(Enum):
    COMPLETE = auto()
    SUBSTANTIALLY_COMPLETE = auto()
    PARTIAL = auto()
    BROKEN = auto()
    UNKNOWN = auto()


class IntegrityState(Enum):
    VERIFIED = auto()
    MISMATCH = auto()
    UNVERIFIED = auto()
    UNKNOWN = auto()


class TimestampType(Enum):
    FILE_CREATED = auto()
    FILE_MODIFIED = auto()
    METADATA_CHANGED = auto()
    FILE_ACCESSED = auto()
    EVENT_LOG_TIME = auto()
    PROCESS_START = auto()
    PROCESS_END = auto()
    LOGIN_TIME = auto()
    BROWSER_VISIT_TIME = auto()
    EMAIL_TIME = auto()
    DOWNLOAD_TIME = auto()
    INSTALL_TIME = auto()
    REGISTRY_LAST_WRITE = auto()
    JOURNAL_TIME = auto()
    USB_FIRST_SEEN = auto()
    USB_LAST_SEEN = auto()
    NETWORK_CONNECTION_TIME = auto()
    OTHER = auto()


class TimestampPrecision(Enum):
    EXACT = auto()
    SECOND = auto()
    MINUTE = auto()
    HOUR = auto()
    DAY = auto()
    DATE_ONLY = auto()
    APPROXIMATE = auto()
    UNKNOWN = auto()


class ExecutionState(Enum):
    FILE_PRESENT = auto()
    EXECUTION_CANDIDATE = auto()
    EXECUTION_SUPPORTED = auto()
    EXECUTION_STRONGLY_SUPPORTED = auto()
    EXECUTION_VERIFIED_BY_MULTIPLE_ARTIFACTS = auto()
    UNKNOWN = auto()


class ArtifactReliability(Enum):
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    UNKNOWN = auto()


class ParserAgreement(Enum):
    AGREE = auto()
    FIELD_DIFFERENCE = auto()
    TIMESTAMP_DIFFERENCE = auto()
    SEMANTIC_DIFFERENCE = auto()
    PARSE_FAILURE = auto()
    UNRESOLVED = auto()


class SourceDependencyState(Enum):
    INDEPENDENT = auto()
    PARTIALLY_DEPENDENT = auto()
    DEPENDENT = auto()
    UNKNOWN = auto()


class ClaimType(Enum):
    DIRECT_ARTIFACT_FACT = auto()
    CORRELATED_FACT = auto()
    DERIVED_FACT = auto()
    ANALYTICAL_INFERENCE = auto()
    HYPOTHESIS = auto()
    UNKNOWN = auto()


class VerificationState(Enum):
    SUPPORTED = auto()
    PARTIALLY_SUPPORTED = auto()
    DISPUTED = auto()
    UNSUPPORTED = auto()
    INCONCLUSIVE = auto()


class HypothesisStatus(Enum):
    ACTIVE = auto()
    REJECTED = auto()
    CONFIRMED = auto()
    CANDIDATE = auto()
    INCONCLUSIVE = auto()


class AntiForensicIndicatorState(Enum):
    LOG_CLEARING_OBSERVED = auto()
    TIMESTAMP_ANOMALY_CANDIDATE = auto()
    HISTORY_GAP_CANDIDATE = auto()
    ARTIFACT_INCONSISTENCY_CANDIDATE = auto()
    CLEANUP_TOOL_CANDIDATE = auto()
    NONE = auto()
    UNKNOWN = auto()


# ==============================================================================
# DATA OBJECTS
# ==============================================================================

@dataclass
class TimestampRecord:
    raw_value: Optional[str]
    raw_timezone: Optional[str]
    utc: Optional[datetime]
    semantics: TimestampType
    precision: TimestampPrecision
    source: str
    confidence: float
    limitations: List[str] = field(default_factory=list)
    sort_key: str = ""


@dataclass
class CustodyEvent:
    event_id: str
    evidence_id: str
    action: str
    actor: Optional[str]
    timestamp: Optional[datetime]
    location: Optional[str]
    tool: Optional[str]
    notes: Optional[str] = None


@dataclass
class EvidenceObject:
    evidence_id: str
    case_id: str
    source_device_id: Optional[str]
    evidence_type: str
    artifact_type: str
    original_name: Optional[str]
    original_path: Optional[str]
    size: Optional[int]
    hashes: Dict[str, str]
    acquisition_method: Optional[str]
    acquisition_tool: Optional[str]
    acquisition_tool_version: Optional[str]
    collector: Optional[str]
    collection_time: Optional[datetime]
    source_timezone: Optional[str]
    chain_of_custody_state: ChainOfCustodyState
    integrity_state: IntegrityState
    storage_reference: Optional[str]
    authorization_context: str
    encrypted_unavailable: bool = False
    custody_events: List[CustodyEvent] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class ArtifactObject:
    artifact_id: str
    evidence_id: str
    artifact_type: str
    source_path: Optional[str]
    parser: Optional[str]
    parser_version: Optional[str]
    parsed_at: Optional[datetime]
    raw_reference: Optional[str]
    normalized_fields: Dict[str, Any]
    timestamps: List[TimestampRecord]
    owner_candidate: Optional[str]
    device_candidate: Optional[str]
    confidence: float
    limitations: List[str] = field(default_factory=list)
    parser_disagreement: Optional[str] = None


@dataclass
class ObservationObject:
    observation_id: str
    artifact_id: str
    field: str
    value: Any
    timestamp: Optional[datetime]
    timestamp_semantics: str
    source_locator: Optional[str]
    parser: Optional[str]
    confidence: float
    limitations: List[str] = field(default_factory=list)


@dataclass
class EventObject:
    event_id: str
    event_type: str
    device: Optional[str]
    user_candidate: Optional[str]
    account: Optional[str]
    process: Dict[str, Any]
    file: Dict[str, Any]
    network_context: Dict[str, Any]
    details: Dict[str, Any]
    timestamp: TimestampRecord
    timestamp_semantics: str
    timezone: Optional[str]
    evidence_ids: List[str]
    artifact_ids: List[str]
    artifact_types: List[str]
    execution_family: Optional[str]
    corroboration: List[str]
    confidence: float
    verification_state: VerificationState
    claim_type: ClaimType
    limitations: List[str]
    observations: List[str]


@dataclass
class DeviceObject:
    device_id: str
    device_type: str
    hostname: Optional[str]
    hardware_ids: List[str]
    installation_ids: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    confidence: float
    limitations: List[str] = field(default_factory=list)


@dataclass
class ExecutionEvidence:
    process_key: str
    process_name: Optional[str]
    process_path: Optional[str]
    state: ExecutionState
    families: List[str]
    independent_family_count: int
    strong_family_count: int
    event_ids: List[str]
    artifact_types: List[str]
    timestamps: List[str]
    account_candidates: List[str]
    device_candidates: List[str]
    confidence: float
    limitations: List[str]
    parser_disagreement: bool


@dataclass
class FactRecord:
    fact_id: str
    statement: str
    claim_type: ClaimType
    verification_state: VerificationState
    evidence_ids: List[str]
    artifact_ids: List[str]
    event_ids: List[str]
    confidence: float
    limitations: List[str]


@dataclass
class Hypothesis:
    id: str
    description: str
    support_evidence: List[str]
    opposition_evidence: List[str]
    unknowns: List[str]
    falsification_criteria: str
    status: HypothesisStatus


@dataclass
class GraphNode:
    node_id: str
    type: str
    attributes: Dict[str, Any]


@dataclass
class GraphEdge:
    edge_id: str
    source_node_id: str
    target_node_id: str
    relation: str
    confidence: float
    evidence_ids: List[str]


# ==============================================================================
# CONSTANTS
# ==============================================================================

CREDENTIAL_FIELD_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "private_key",
    "privatekey",
    "cookie",
    "session",
    "mfa",
    "otp",
    "credential",
)

SECRET_REGEXES = [
    re.compile(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|private[_-]?key|cookie|session[_-]?id|mfa|otp)\b\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
]

ARTIFACT_EVENT_MAP = {
    "PREFETCH": "PROCESS_EXECUTION_EVIDENCE",
    "AMCACHE": "PROCESS_PRESENCE_CONTEXT",
    "SHIMCACHE": "PROCESS_COMPATIBILITY_CACHE_CONTEXT",
    "MEMORY_PROCESS": "PROCESS_PRESENT",
    "EDR_PROCESS": "EDR_PROCESS_EXECUTION",
    "FILESYSTEM_FILE": "FILE_ACTIVITY",
    "MFT": "FILE_RECORD",
    "USN_JOURNAL": "FILESYSTEM_CHANGE",
    "CARVED_FILE": "CARVED_FILE_PRESENT",
    "BROWSER_HISTORY": "BROWSER_VISIT",
    "BROWSER_DOWNLOAD": "DOWNLOAD",
    "USBSTOR": "USB_CONNECTED",
    "REMOVABLE_MEDIA": "USB_CONNECTED",
    "SERVICE": "SERVICE_INSTALLED",
    "SCHEDULED_TASK": "SCHEDULED_TASK_CONFIGURED",
    "REGISTRY_RUN": "REGISTRY_RUN_KEY_PRESENT",
    "STARTUP": "STARTUP_ENTRY_PRESENT",
    "LAUNCH_AGENT": "LAUNCH_AGENT_PRESENT",
    "CRON": "CRON_JOB_CONFIGURED",
    "NETWORK_CONNECTION": "NETWORK_CONNECTION",
    "DNS": "DNS_QUERY",
    "FLOW": "FLOW_RECORD",
    "EMAIL": "EMAIL_MESSAGE",
    "RANSOM_NOTE": "RANSOM_NOTE_PRESENT",
    "EVENT_LOG": "EVENT_LOG_RECORD",
}

ARTIFACT_EXECUTION_FAMILY = {
    "PREFETCH": "prefetch",
    "AMCACHE": "amcache_presence",
    "SHIMCACHE": "shimcache_presence",
    "MEMORY_PROCESS": "memory_process",
    "EDR_PROCESS": "edr_process",
    "FILESYSTEM_FILE": "file_present",
    "MFT": "file_present",
    "USN_JOURNAL": "file_present",
    "CARVED_FILE": "file_present",
}

STRONG_EXECUTION_FAMILIES = {
    "prefetch",
    "event_log_process_start",
    "edr_process",
    "memory_process",
}

WEAK_EXECUTION_FAMILIES = {
    "amcache_presence",
    "shimcache_presence",
}

PERSISTENCE_EVENT_TYPES = {
    "SERVICE_INSTALLED",
    "SCHEDULED_TASK_CONFIGURED",
    "REGISTRY_RUN_KEY_PRESENT",
    "STARTUP_ENTRY_PRESENT",
    "LAUNCH_AGENT_PRESENT",
    "CRON_JOB_CONFIGURED",
}

USB_EVENT_TYPES = {
    "USB_CONNECTED",
    "REMOVABLE_MEDIA_MOUNTED",
}

NETWORK_EVENT_TYPES = {
    "NETWORK_CONNECTION",
    "DNS_QUERY",
    "FLOW_RECORD",
}

ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz")

EXECUTION_EVENT_TYPES = {
    "PROCESS_EXECUTION_EVIDENCE",
    "PROCESS_START",
    "PROCESS_PRESENT",
    "EDR_PROCESS_EXECUTION",
    "PROCESS_PRESENCE_CONTEXT",
    "PROCESS_COMPATIBILITY_CACHE_CONTEXT",
}


# ==============================================================================
# HELPERS
# ==============================================================================

def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def json_serial(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.name
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def enum_from_name(enum_cls, name: Any, default: Any) -> Any:
    try:
        return enum_cls[str(name).upper()]
    except Exception:
        return default


def is_credential_field(key: str) -> bool:
    k = str(key).lower()
    return any(token in k for token in CREDENTIAL_FIELD_TOKENS)


def redact_string(value: Any) -> Any:
    if not isinstance(value, str):
        return value

    s = value
    for rx in SECRET_REGEXES:
        s = rx.sub("[REDACTED_SECRET]", s)

    return s


def redact_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    for key, value in (fields or {}).items():
        if is_credential_field(key):
            out[key] = "[REDACTED_CREDENTIAL_ARTIFACT]"
            continue

        if isinstance(value, str):
            redacted = redact_string(value)
            if key.lower() in {"command_line", "cmdline", "arguments", "args"} and redacted != value:
                out[key] = "[REDACTED_COMMAND_LINE_CONTAINING_POSSIBLE_SECRET]"
            elif redacted != value:
                out[key] = "[REDACTED_POSSIBLE_SECRET_IN_FIELD]"
            else:
                out[key] = value
        elif isinstance(value, dict):
            out[key] = redact_fields(value)
        elif isinstance(value, list):
            out[key] = [
                redact_string(x) if isinstance(x, str) else redact_fields(x) if isinstance(x, dict) else x
                for x in value
            ]
        else:
            out[key] = value

    return out


def parse_dt(value: Any, tz_name: Optional[str] = None) -> Tuple[Optional[datetime], str]:
    """
    Returns (datetime_or_None, timezone_status).

    timezone_status:
      OK
      TIMEZONE_UNKNOWN
      TIMEZONE_UNRESOLVED
      UNPARSEABLE
    """
    if value is None:
        return None, "UNPARSEABLE"

    dt: Optional[datetime] = None

    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None, "UNPARSEABLE"

        text = text.replace("Z", "+00:00")

        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%d",
            ):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue

        if dt is None:
            return None, "UNPARSEABLE"

    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc), "OK"

    if tz_name:
        if ZoneInfo is not None:
            try:
                dt = dt.replace(tzinfo=ZoneInfo(tz_name))
                return dt.astimezone(timezone.utc), "OK"
            except Exception:
                return dt, "TIMEZONE_UNRESOLVED"
        return dt, "TIMEZONE_UNRESOLVED"

    return dt, "TIMEZONE_UNKNOWN"


def normalize_timestamp(
    raw_value: Any,
    raw_timezone: Optional[str],
    semantics: Any,
    precision: Any,
    source: str,
    base_confidence: float = 0.85,
) -> TimestampRecord:
    dt, tz_status = parse_dt(raw_value, raw_timezone)

    sem = enum_from_name(TimestampType, semantics, TimestampType.OTHER)
    prec = enum_from_name(TimestampPrecision, precision, TimestampPrecision.UNKNOWN)

    limitations: List[str] = []
    confidence = clamp(base_confidence)

    if tz_status == "TIMEZONE_UNKNOWN":
        limitations.append("TIMEZONE_UNKNOWN: original timestamp not silently assumed to be local time.")
        confidence *= 0.45
    elif tz_status == "TIMEZONE_UNRESOLVED":
        limitations.append("TIMEZONE_UNRESOLVED: named timezone could not be converted reliably.")
        confidence *= 0.55
    elif tz_status == "UNPARSEABLE":
        limitations.append("UNPARSEABLE_TIMESTAMP")
        confidence *= 0.20

    if prec in (TimestampPrecision.DATE_ONLY, TimestampPrecision.APPROXIMATE, TimestampPrecision.UNKNOWN):
        limitations.append("LOW_TIMESTAMP_PRECISION")
        confidence *= 0.65

    utc = dt if tz_status == "OK" else None
    sort_key = utc.isoformat() if utc else str(raw_value or "")

    return TimestampRecord(
        raw_value=str(raw_value) if raw_value is not None else None,
        raw_timezone=raw_timezone,
        utc=utc,
        semantics=sem,
        precision=prec,
        source=source,
        confidence=clamp(confidence),
        limitations=limitations,
        sort_key=sort_key,
    )


def compute_chain_state(events: List[CustodyEvent], broken: bool = False) -> ChainOfCustodyState:
    if broken:
        return ChainOfCustodyState.BROKEN

    if not events:
        return ChainOfCustodyState.UNKNOWN

    actions = {str(e.action).lower() for e in events}
    required = {"acquisition", "transfer", "storage", "processing"}

    if required.issubset(actions):
        return ChainOfCustodyState.COMPLETE
    if len(actions) >= 3:
        return ChainOfCustodyState.SUBSTANTIALLY_COMPLETE
    if len(actions) >= 1:
        return ChainOfCustodyState.PARTIAL

    return ChainOfCustodyState.UNKNOWN


def compute_integrity_state(item: Dict[str, Any]) -> IntegrityState:
    explicit = item.get("integrity_state")
    if explicit:
        return enum_from_name(IntegrityState, explicit, IntegrityState.UNKNOWN)

    if item.get("hash_mismatch"):
        return IntegrityState.MISMATCH

    hashes = item.get("hashes") or {}
    expected = item.get("expected_sha256") or item.get("acquisition_manifest_sha256")
    actual = hashes.get("sha256") or hashes.get("SHA256")

    if expected and actual and str(expected).lower() == str(actual).lower():
        return IntegrityState.VERIFIED

    if item.get("hash_verified"):
        return IntegrityState.VERIFIED

    if hashes:
        return IntegrityState.UNVERIFIED

    return IntegrityState.UNKNOWN


def register_evidence(item: Dict[str, Any], case_id: str, now: datetime) -> EvidenceObject:
    custody_events: List[CustodyEvent] = []

    for idx, ce in enumerate(item.get("custody_events", []) or []):
        custody_events.append(
            CustodyEvent(
                event_id=str(ce.get("event_id") or f"{item.get('evidence_id', 'EV')}_{idx}"),
                evidence_id=str(item.get("evidence_id", "UNKNOWN_EVIDENCE")),
                action=str(ce.get("action", "unknown")),
                actor=ce.get("actor"),
                timestamp=parse_dt(ce.get("timestamp"), item.get("source_timezone"))[0],
                location=ce.get("location"),
                tool=ce.get("tool"),
                notes=ce.get("notes"),
            )
        )

    chain_state = enum_from_name(
        ChainOfCustodyState,
        item.get("chain_of_custody_state"),
        compute_chain_state(custody_events, bool(item.get("chain_broken"))),
    )

    integrity_state = compute_integrity_state(item)

    encrypted = bool(item.get("encrypted"))
    authorized_decryption = bool(item.get("authorized_decryption"))
    encrypted_unavailable = encrypted and not authorized_decryption

    collection_dt, _ = parse_dt(item.get("collection_time"), item.get("source_timezone"))

    limitations: List[str] = []

    if encrypted_unavailable:
        limitations.append("ENCRYPTED_EVIDENCE_UNAVAILABLE: no unauthorized decryption performed.")

    if integrity_state == IntegrityState.MISMATCH:
        limitations.append("HASH_MISMATCH: evidence integrity is disputed.")

    if integrity_state == IntegrityState.UNVERIFIED:
        limitations.append("HASH_UNVERIFIED: hash exists but verification status was not supplied.")

    if chain_state in (ChainOfCustodyState.PARTIAL, ChainOfCustodyState.UNKNOWN, ChainOfCustodyState.BROKEN):
        limitations.append(f"CHAIN_OF_CUSTODY_{chain_state.name}")

    if not item.get("collector"):
        limitations.append("MISSING_ACQUISITION_COLLECTOR")

    if not item.get("acquisition_tool"):
        limitations.append("MISSING_ACQUISITION_TOOL")

    return EvidenceObject(
        evidence_id=str(item.get("evidence_id") or new_id("EVID")),
        case_id=case_id,
        source_device_id=item.get("source_device_id"),
        evidence_type=str(item.get("evidence_type", "UNKNOWN")),
        artifact_type=str(item.get("artifact_type", "UNKNOWN")),
        original_name=item.get("original_name"),
        original_path=item.get("original_path"),
        size=item.get("size"),
        hashes=dict(item.get("hashes", {}) or {}),
        acquisition_method=item.get("acquisition_method"),
        acquisition_tool=item.get("acquisition_tool"),
        acquisition_tool_version=item.get("acquisition_tool_version"),
        collector=item.get("collector"),
        collection_time=collection_dt,
        source_timezone=item.get("source_timezone"),
        chain_of_custody_state=chain_state,
        integrity_state=integrity_state,
        storage_reference=item.get("storage_reference"),
        authorization_context=str(item.get("authorization_context", "AUTHORIZED_FORENSIC_SCOPE")),
        encrypted_unavailable=encrypted_unavailable,
        custody_events=custody_events,
        limitations=limitations,
    )


def register_artifact(
    art: Dict[str, Any],
    evidence: EvidenceObject,
    now: datetime,
) -> ArtifactObject:
    timestamps: List[TimestampRecord] = []

    for ts in art.get("timestamps", []) or []:
        if isinstance(ts, dict):
            timestamps.append(
                normalize_timestamp(
                    raw_value=ts.get("value"),
                    raw_timezone=ts.get("timezone") or evidence.source_timezone,
                    semantics=ts.get("semantics"),
                    precision=ts.get("precision"),
                    source=str(art.get("artifact_id", "ARTIFACT")),
                    base_confidence=float(art.get("confidence", 0.80)),
                )
            )
        else:
            timestamps.append(
                normalize_timestamp(
                    raw_value=ts,
                    raw_timezone=evidence.source_timezone,
                    semantics=TimestampType.OTHER.name,
                    precision=TimestampPrecision.UNKNOWN.name,
                    source=str(art.get("artifact_id", "ARTIFACT")),
                    base_confidence=float(art.get("confidence", 0.80)),
                )
            )

    normalized_fields = redact_fields(art.get("normalized_fields", {}) or {})

    limitations: List[str] = list(art.get("limitations", []) or [])

    confidence = float(art.get("confidence", 0.75))

    if evidence.integrity_state == IntegrityState.MISMATCH:
        confidence *= 0.35
        limitations.append("Artifact confidence reduced due to evidence hash mismatch.")

    if evidence.integrity_state == IntegrityState.UNVERIFIED:
        confidence *= 0.75
        limitations.append("Artifact confidence reduced due to unverified evidence integrity.")

    if evidence.chain_of_custody_state == ChainOfCustodyState.BROKEN:
        confidence *= 0.45
        limitations.append("Artifact confidence reduced due to broken chain of custody.")

    if evidence.chain_of_custody_state in (ChainOfCustodyState.PARTIAL, ChainOfCustodyState.UNKNOWN):
        confidence *= 0.75
        limitations.append("Artifact confidence reduced due to incomplete chain of custody.")

    if not art.get("parser"):
        limitations.append("MISSING_PARSER_PROVENANCE")
        confidence *= 0.70

    parser_disagreement = art.get("parser_disagreement")
    if parser_disagreement:
        limitations.append(f"PARSER_DISAGREEMENT: {parser_disagreement}")
        confidence *= 0.65

    parsed_dt, _ = parse_dt(art.get("parsed_at"), evidence.source_timezone)

    return ArtifactObject(
        artifact_id=str(art.get("artifact_id") or new_id("ART")),
        evidence_id=evidence.evidence_id,
        artifact_type=str(art.get("artifact_type", "UNKNOWN")).upper(),
        source_path=art.get("source_path"),
        parser=art.get("parser"),
        parser_version=art.get("parser_version"),
        parsed_at=parsed_dt,
        raw_reference=art.get("raw_reference"),
        normalized_fields=normalized_fields,
        timestamps=timestamps,
        owner_candidate=art.get("owner_candidate"),
        device_candidate=art.get("device_candidate") or evidence.source_device_id,
        confidence=clamp(confidence),
        limitations=limitations,
        parser_disagreement=parser_disagreement,
    )


def observations_from_artifact(art: ArtifactObject) -> List[ObservationObject]:
    obs: List[ObservationObject] = []

    for field_name, value in art.normalized_fields.items():
        obs.append(
            ObservationObject(
                observation_id=new_id("OBS"),
                artifact_id=art.artifact_id,
                field=field_name,
                value=value,
                timestamp=art.timestamps[0].utc if art.timestamps else None,
                timestamp_semantics=art.timestamps[0].semantics.name if art.timestamps else "UNKNOWN",
                source_locator=art.source_path,
                parser=art.parser,
                confidence=art.confidence,
                limitations=art.limitations.copy(),
            )
        )

    for ts in art.timestamps:
        obs.append(
            ObservationObject(
                observation_id=new_id("OBS"),
                artifact_id=art.artifact_id,
                field=f"TIMESTAMP_{ts.semantics.name}",
                value=ts.raw_value,
                timestamp=ts.utc,
                timestamp_semantics=ts.semantics.name,
                source_locator=art.source_path,
                parser=art.parser,
                confidence=ts.confidence,
                limitations=ts.limitations.copy(),
            )
        )

    return obs


def first_timestamp(art: ArtifactObject, evidence: EvidenceObject) -> TimestampRecord:
    if art.timestamps:
        return art.timestamps[0]

    return normalize_timestamp(
        raw_value=None,
        raw_timezone=evidence.source_timezone,
        semantics=TimestampType.OTHER.name,
        precision=TimestampPrecision.UNKNOWN.name,
        source=art.artifact_id,
        base_confidence=0.20,
    )


def events_from_artifact(
    art: ArtifactObject,
    evidence: EvidenceObject,
    obs: List[ObservationObject],
    now: datetime,
) -> List[EventObject]:
    events: List[EventObject] = []

    atype = art.artifact_type.upper()
    fields = art.normalized_fields
    ts = first_timestamp(art, evidence)

    event_type = ARTIFACT_EVENT_MAP.get(atype, "UNKNOWN_ARTIFACT_EVENT")
    execution_family = ARTIFACT_EXECUTION_MAP_TO_FAMILY(art)

    process: Dict[str, Any] = {}
    file_info: Dict[str, Any] = {}
    network: Dict[str, Any] = {}
    details: Dict[str, Any] = dict(fields)

    user_candidate = fields.get("user") or fields.get("username") or art.owner_candidate
    account = fields.get("account") or fields.get("user_account") or user_candidate

    if atype == "EVENT_LOG":
        event_id = fields.get("event_id")
        raw_event_type = str(fields.get("event_type", "")).upper()

        if event_id == 1102 or "CLEAR" in raw_event_type or fields.get("log_cleared"):
            event_type = "LOG_CLEARING_OBSERVED"
        elif event_id == 4688 or "PROCESS_START" in raw_event_type:
            event_type = "PROCESS_START"
            execution_family = "event_log_process_start"
        elif event_id == 4624 or "LOGIN_SUCCESS" in raw_event_type:
            event_type = "LOGIN_SUCCESS"
        elif event_id == 4625 or "LOGIN_FAILURE" in raw_event_type:
            event_type = "LOGIN_FAILURE"
        elif event_id in (1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047) or "RDP" in raw_event_type:
            event_type = "REMOTE_SESSION"
        else:
            event_type = raw_event_type or f"EVENT_{event_id}"

    elif atype in {"FILESYSTEM_FILE", "MFT", "USN_JOURNAL", "CARVED_FILE"}:
        sem = ts.semantics.name
        if sem.startswith("FILE_"):
            event_type = sem
        else:
            event_type = f"FILE_{sem}" if sem != "OTHER" else "FILE_ACTIVITY"

        file_info = {
            "path": fields.get("path") or fields.get("filename") or art.source_path,
            "name": fields.get("name") or fields.get("filename"),
            "size": fields.get("size"),
            "hash": fields.get("sha256") or fields.get("md5"),
            "allocation_state": fields.get("allocation_state"),
            "carved": bool(fields.get("carved")) or atype == "CARVED_FILE",
        }

    elif atype == "PREFETCH":
        process = {
            "name": fields.get("process_name") or fields.get("executable"),
            "path": fields.get("process_path") or fields.get("executable_path"),
            "command_line": fields.get("command_line"),
            "execution_count": fields.get("execution_count"),
        }

    elif atype in {"AMCACHE", "SHIMCACHE"}:
        process = {
            "name": fields.get("process_name") or fields.get("executable") or fields.get("name"),
            "path": fields.get("process_path") or fields.get("path"),
        }

    elif atype == "MEMORY_PROCESS":
        process = {
            "pid": fields.get("pid"),
            "name": fields.get("process_name") or fields.get("name"),
            "path": fields.get("process_path") or fields.get("path"),
            "parent_pid": fields.get("parent_pid"),
            "session": fields.get("session"),
        }

    elif atype == "EDR_PROCESS":
        process = {
            "pid": fields.get("pid"),
            "name": fields.get("process_name") or fields.get("name"),
            "path": fields.get("process_path") or fields.get("path"),
            "parent_process": fields.get("parent_process"),
            "command_line": fields.get("command_line"),
        }

    elif atype == "BROWSER_DOWNLOAD":
        file_info = {
            "path": fields.get("download_path") or fields.get("path"),
            "name": fields.get("download_name") or fields.get("filename"),
            "source_url": fields.get("url") or fields.get("source_url"),
        }

    elif atype == "BROWSER_HISTORY":
        details["url"] = fields.get("url") or fields.get("visit_url")

    elif atype in {"USBSTOR", "REMOVABLE_MEDIA"}:
        details["device_serial"] = fields.get("serial") or fields.get("device_serial")
        details["vendor"] = fields.get("vendor")
        details["product"] = fields.get("product")

    elif atype in {"SERVICE", "SCHEDULED_TASK", "REGISTRY_RUN", "STARTUP", "LAUNCH_AGENT", "CRON"}:
        details["target"] = fields.get("target") or fields.get("image_path") or fields.get("command")
        details["name"] = fields.get("name") or fields.get("service_name") or fields.get("task_name")

    elif atype in {"NETWORK_CONNECTION", "DNS", "FLOW"}:
        network = {
            "remote_ip": fields.get("remote_ip") or fields.get("dst_ip"),
            "remote_port": fields.get("remote_port") or fields.get("dst_port"),
            "protocol": fields.get("protocol"),
            "domain": fields.get("domain") or fields.get("dns_query"),
            "bytes_sent": fields.get("bytes_sent"),
            "bytes_received": fields.get("bytes_received"),
            "process_name": fields.get("process_name") or process.get("name"),
        }

    elif atype == "EMAIL":
        details["message_id"] = fields.get("message_id")
        details["sender"] = fields.get("sender")
        details["recipient"] = fields.get("recipient")
        details["subject"] = fields.get("subject")

    confidence = art.confidence

    limitations: List[str] = []

    if ts.utc is None:
        limitations.extend(ts.limitations)
        confidence *= 0.65

    if ts.precision in (TimestampPrecision.DATE_ONLY, TimestampPrecision.APPROXIMATE, TimestampPrecision.UNKNOWN):
        limitations.append("Timestamp precision is insufficient for fine-grained sequencing.")
        confidence *= 0.75

    if evidence.integrity_state != IntegrityState.VERIFIED:
        limitations.append("Evidence integrity is not fully verified.")
        confidence *= 0.85

    if evidence.chain_of_custody_state in (ChainOfCustodyState.PARTIAL, ChainOfCustodyState.UNKNOWN, ChainOfCustodyState.BROKEN):
        limitations.append(f"Chain of custody state: {evidence.chain_of_custody_state.name}.")
        confidence *= 0.80

    events.append(
        EventObject(
            event_id=new_id("EVT"),
            event_type=event_type,
            device=art.device_candidate or evidence.source_device_id,
            user_candidate=user_candidate,
            account=account,
            process=process,
            file=file_info,
            network_context=network,
            details=details,
            timestamp=ts,
            timestamp_semantics=ts.semantics.name,
            timezone=evidence.source_timezone,
            evidence_ids=[evidence.evidence_id],
            artifact_ids=[art.artifact_id],
            artifact_types=[art.artifact_type],
            execution_family=execution_family,
            corroboration=[],
            confidence=clamp(confidence),
            verification_state=VerificationState.INCONCLUSIVE,
            claim_type=ClaimType.DIRECT_ARTIFACT_FACT,
            limitations=limitations,
            observations=[o.observation_id for o in obs],
        )
    )

    return events


def ARTIFACT_EXECUTION_MAP_TO_FAMILY(art: ArtifactObject) -> Optional[str]:
    return ARTIFACT_EXECUTION_FAMILY.get(art.artifact_type.upper())


def resolve_device(
    devices: Dict[str, DeviceObject],
    device_id: Optional[str],
    device_type: str = "UNKNOWN",
    hostname: Optional[str] = None,
    hardware_ids: Optional[List[str]] = None,
    installation_ids: Optional[List[str]] = None,
    first_seen: Optional[datetime] = None,
    last_seen: Optional[datetime] = None,
    confidence: float = 0.7,
) -> Optional[DeviceObject]:
    if not device_id:
        return None

    dev = devices.get(device_id)

    if dev is None:
        dev = DeviceObject(
            device_id=device_id,
            device_type=device_type,
            hostname=hostname,
            hardware_ids=list(hardware_ids or []),
            installation_ids=list(installation_ids or []),
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=clamp(confidence),
            limitations=[
                "Hostname is not a unique device identifier.",
                "Device resolution is limited to supplied authorized identifiers.",
            ],
        )
        devices[device_id] = dev
    else:
        if hostname and not dev.hostname:
            dev.hostname = hostname
        if hardware_ids:
            dev.hardware_ids = sorted(set(dev.hardware_ids + list(hardware_ids)))
        if installation_ids:
            dev.installation_ids = sorted(set(dev.installation_ids + list(installation_ids)))
        if first_seen and (dev.first_seen is None or first_seen < dev.first_seen):
            dev.first_seen = first_seen
        if last_seen and (dev.last_seen is None or last_seen > dev.last_seen):
            dev.last_seen = last_seen
        dev.confidence = clamp(max(dev.confidence, confidence))

    return dev


def classify_execution_state(
    families: Set[str],
    parser_disagreement: bool,
    average_confidence: float,
) -> Tuple[ExecutionState, float]:
    strong = families & STRONG_EXECUTION_FAMILIES
    weak = families & WEAK_EXECUTION_FAMILIES
    file_present = "file_present" in families

    if len(strong) >= 3 or (len(strong) >= 2 and not parser_disagreement):
        state = ExecutionState.EXECUTION_VERIFIED_BY_MULTIPLE_ARTIFACTS
    elif len(strong) >= 2:
        state = ExecutionState.EXECUTION_STRONGLY_SUPPORTED
    elif len(strong) == 1 and not parser_disagreement:
        state = ExecutionState.EXECUTION_SUPPORTED
    elif len(strong) == 1 or weak:
        state = ExecutionState.EXECUTION_CANDIDATE
    elif file_present:
        state = ExecutionState.FILE_PRESENT
    else:
        state = ExecutionState.UNKNOWN

    base = 0.15
    base += 0.22 * len(strong)
    base += 0.07 * len(weak)
    base += 0.05 if file_present else 0.0

    confidence = clamp(base * average_confidence)

    if parser_disagreement:
        confidence *= 0.60

    if state in (ExecutionState.EXECUTION_SUPPORTED, ExecutionState.EXECUTION_STRONGLY_SUPPORTED, ExecutionState.EXECUTION_VERIFIED_BY_MULTIPLE_ARTIFACTS):
        confidence = clamp(confidence, 0.55, 0.98)

    return state, confidence


def build_execution_evidence(
    events: List[EventObject],
    artifacts_by_id: Dict[str, ArtifactObject],
) -> Dict[str, ExecutionEvidence]:
    buckets: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "families": set(),
            "event_ids": [],
            "artifact_types": set(),
            "timestamps": [],
            "accounts": set(),
            "devices": set(),
            "confidences": [],
            "parser_disagreement": False,
            "process_name": None,
            "process_path": None,
            "limitations": set(),
        }
    )

    for e in events:
        if e.event_type not in EXECUTION_EVENT_TYPES and not e.execution_family:
            continue

        process_name = e.process.get("name")
        process_path = e.process.get("path")

        if not process_name and not process_path:
            continue

        key = str(process_path or process_name).lower()

        b = buckets[key]

        if e.execution_family:
            b["families"].add(e.execution_family)

        b["event_ids"].append(e.event_id)
        b["artifact_types"].update(e.artifact_types)
        b["confidences"].append(e.confidence)

        if e.process.get("name"):
            b["process_name"] = e.process.get("name")
        if e.process.get("path"):
            b["process_path"] = e.process.get("path")

        if e.account:
            b["accounts"].add(str(e.account))
        if e.device:
            b["devices"].add(str(e.device))

        if e.timestamp.utc:
            b["timestamps"].append(e.timestamp.utc.isoformat())
        elif e.timestamp.raw_value:
            b["timestamps"].append(e.timestamp.raw_value)

        b["limitations"].update(e.limitations)

        for aid in e.artifact_ids:
            art = artifacts_by_id.get(aid)
            if art and art.parser_disagreement:
                b["parser_disagreement"] = True

    out: Dict[str, ExecutionEvidence] = {}

    for key, b in buckets.items():
        families: Set[str] = b["families"]
        avg_conf = statistics.mean(b["confidences"]) if b["confidences"] else 0.4
        state, confidence = classify_execution_state(families, b["parser_disagreement"], avg_conf)

        limitations = sorted(b["limitations"])

        if state == ExecutionState.FILE_PRESENT:
            limitations.append("File presence alone does not establish execution.")

        if state in (ExecutionState.EXECUTION_CANDIDATE, ExecutionState.EXECUTION_SUPPORTED):
            limitations.append("Execution evidence is partial; corroborating artifact families are limited.")

        limitations.append("Execution does not establish user intent, real-person attribution, or maliciousness.")

        out[key] = ExecutionEvidence(
                process_key=key,
                process_name=b["process_name"],
                process_path=b["process_path"],
                state=state,
                families=sorted(families),
                independent_family_count=len(families),
                strong_family_count=len(families & STRONG_EXECUTION_FAMILIES),
                event_ids=sorted(set(b["event_ids"])),
                artifact_types=sorted(b["artifact_types"]),
                timestamps=sorted(set(b["timestamps"])),
                account_candidates=sorted(b["accounts"]),
                device_candidates=sorted(b["devices"]),
                confidence=round(confidence, 4),
                limitations=limitations,
                parser_disagreement=bool(b["parser_disagreement"]),
            )

    return out


def detect_persistence(events: List[EventObject]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for e in events:
        if e.event_type in PERSISTENCE_EVENT_TYPES:
            out.append(
                {
                    "event_id": e.event_id,
                    "type": e.event_type,
                    "device": e.device,
                    "account": e.account,
                    "target": e.details.get("target"),
                    "name": e.details.get("name"),
                    "timestamp": e.timestamp.raw_value,
                    "state": "PERSISTENCE_CONFIGURED",
                    "maliciousness": "UNKNOWN",
                    "limitations": [
                        "Persistence configuration alone does not prove malicious persistence.",
                        "Legitimate software, administrators, services, and installers may configure persistence.",
                    ],
                }
            )

    return out


def detect_usb(events: List[EventObject]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    usb_events = [e for e in events if e.event_type in USB_EVENT_TYPES]

    for e in usb_events:
        out.append(
            {
                "event_id": e.event_id,
                "device": e.device,
                "account": e.account,
                "serial": e.details.get("device_serial"),
                "vendor": e.details.get("vendor"),
                "product": e.details.get("product"),
                "timestamp": e.timestamp.raw_value,
                "state": "USB_CONNECTED",
                "file_transfer_established": False,
                "limitations": [
                    "USB connection alone does not prove file copy.",
                    "File copy alone does not prove exfiltration.",
                ],
            }
        )

    return out


def detect_network_and_exfiltration_candidates(
    events: List[EventObject],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    network_records: List[Dict[str, Any]] = []
    exfil_candidates: List[Dict[str, Any]] = []

    connections = [e for e in events if e.event_type in NETWORK_EVENT_TYPES]
    archive_creations = [
        e
        for e in events
        if e.event_type == "FILE_CREATED"
        and str(e.file.get("path") or "").lower().endswith(ARCHIVE_EXTENSIONS)
    ]

    for e in connections:
        network_records.append(
            {
                "event_id": e.event_id,
                "type": e.event_type,
                "device": e.device,
                "account": e.account,
                "remote_ip": e.network_context.get("remote_ip"),
                "remote_port": e.network_context.get("remote_port"),
                "protocol": e.network_context.get("protocol"),
                "domain": e.network_context.get("domain"),
                "bytes_sent": e.network_context.get("bytes_sent"),
                "bytes_received": e.network_context.get("bytes_received"),
                "process_name": e.network_context.get("process_name"),
                "timestamp": e.timestamp.raw_value,
                "state": "NETWORK_ACTIVITY_OBSERVED",
                "limitations": [
                    "Network connection alone does not prove C2.",
                    "DNS query alone does not prove connection.",
                    "Encrypted traffic alone does not prove malicious activity.",
                ],
            }
        )

        bytes_sent = e.network_context.get("bytes_sent")
        if isinstance(bytes_sent, (int, float)) and bytes_sent >= 10_000_000:
            nearby_archive = False

            if e.timestamp.utc:
                for a in archive_creations:
                    if a.timestamp.utc and abs((a.timestamp.utc - e.timestamp.utc).total_seconds()) <= 3600:
                        nearby_archive = True
                        break

            exfil_candidates.append(
                {
                    "candidate_id": new_id("EXFIL"),
                    "network_event_id": e.event_id,
                    "nearby_archive_creation": nearby_archive,
                    "bytes_sent": bytes_sent,
                    "remote_ip": e.network_context.get("remote_ip"),
                    "state": "EXFILTRATION_CANDIDATE",
                    "verification_state": VerificationState.INCONCLUSIVE.name,
                    "limitations": [
                        "Large transfer alone does not prove exfiltration.",
                        "Archive creation alone does not prove exfiltration.",
                        "Additional proxy/PCAP/flow/file-transfer evidence is required.",
                    ],
                }
            )

    return network_records, exfil_candidates


def detect_anti_forensic_indicators(
    events: List[EventObject],
    artifacts: List[ArtifactObject],
    evidence_items: List[EvidenceObject],
) -> List[Dict[str, Any]]:
    indicators: List[Dict[str, Any]] = []

    for e in events:
        if e.event_type == "LOG_CLEARING_OBSERVED":
            indicators.append(
                {
                    "indicator_id": new_id("AFI"),
                    "state": AntiForensicIndicatorState.LOG_CLEARING_OBSERVED.name,
                    "event_id": e.event_id,
                    "device": e.device,
                    "account": e.account,
                    "timestamp": e.timestamp.raw_value,
                    "intent": "UNKNOWN",
                    "limitations": [
                        "Log clearing may result from administration, maintenance, rotation, policy, or attacker activity.",
                        "This indicator does not establish malicious intent or operator identity.",
                    ],
                }
            )

    for art in artifacts:
        joined_limits = " ".join(art.limitations).lower()

        if "timestamp" in joined_limits and ("inconsisten" in joined_limits or "anomaly" in joined_limits):
            indicators.append(
                {
                    "indicator_id": new_id("AFI"),
                    "state": AntiForensicIndicatorState.TIMESTAMP_ANOMALY_CANDIDATE.name,
                    "artifact_id": art.artifact_id,
                    "intent": "UNKNOWN",
                    "limitations": ["Timestamp anomaly may reflect clock skew, copying, restore, parser issue, or tampering."],
                }
            )

        if "gap" in joined_limits or "rollover" in joined_limits or "missing" in joined_limits:
            indicators.append(
                {
                    "indicator_id": new_id("AFI"),
                    "state": AntiForensicIndicatorState.HISTORY_GAP_CANDIDATE.name,
                    "artifact_id": art.artifact_id,
                    "intent": "UNKNOWN",
                    "limitations": ["History gap may reflect retention, rotation, collection failure, outage, or tampering."],
                }
            )

    for ev in evidence_items:
        if ev.integrity_state == IntegrityState.MISMATCH:
            indicators.append(
                {
                    "indicator_id": new_id("AFI"),
                    "state": AntiForensicIndicatorState.ARTIFACT_INCONSISTENCY_CANDIDATE.name,
                    "evidence_id": ev.evidence_id,
                    "intent": "UNKNOWN",
                    "limitations": ["Hash mismatch indicates integrity dispute, not automatically malicious anti-forensics."],
                }
            )

    return indicators


def detect_contradictions(
    events: List[EventObject],
    execution_states: Dict[str, ExecutionEvidence],
    artifacts: List[ArtifactObject],
    evidence_items: List[EvidenceObject],
) -> List[str]:
    contradictions: List[str] = []

    for ev in evidence_items:
        if ev.integrity_state == IntegrityState.MISMATCH:
            contradictions.append(f"Evidence {ev.evidence_id} has hash mismatch.")

        if ev.chain_of_custody_state == ChainOfCustodyState.BROKEN:
            contradictions.append(f"Evidence {ev.evidence_id} has broken chain of custody.")

    for art in artifacts:
        if art.parser_disagreement:
            contradictions.append(f"Artifact {art.artifact_id} has parser disagreement: {art.parser_disagreement}")

    for key, ex in execution_states.items():
        utc_times: List[datetime] = []

        for eid in ex.event_ids:
            ev = next((e for e in events if e.event_id == eid), None)
            if ev and ev.timestamp.utc and ev.timestamp.precision in (
                TimestampPrecision.EXACT,
                TimestampPrecision.SECOND,
                TimestampPrecision.MINUTE,
            ):
                utc_times.append(ev.timestamp.utc)

        if len(utc_times) >= 2:
            span = (max(utc_times) - min(utc_times)).total_seconds()
            if span > 3600:
                contradictions.append(
                    f"Execution timestamp conflict for process '{key}': high-precision timestamps differ by {int(span)} seconds."
                )

        accounts = set(ex.account_candidates)
        if len(accounts) > 1:
            contradictions.append(
                f"Account candidates for process '{key}' differ: {sorted(accounts)}. This may reflect service/user/session context and requires resolution."
            )

    return contradictions


def source_dependency_for_events(
    event_ids: List[str],
    events_by_id: Dict[str, EventObject],
) -> SourceDependencyState:
    evidence_ids: Set[str] = set()
    artifact_types: Set[str] = set()
    artifact_ids: Set[str] = set()

    for eid in event_ids:
        e = events_by_id.get(eid)
        if not e:
            continue
        evidence_ids.update(e.evidence_ids)
        artifact_types.update(e.artifact_types)
        artifact_ids.update(e.artifact_ids)

    if len(evidence_ids) > 1:
        return SourceDependencyState.INDEPENDENT
    if len(artifact_types) > 1:
        return SourceDependencyState.PARTIALLY_DEPENDENT
    if len(artifact_ids) == 1:
        return SourceDependencyState.DEPENDENT

    return SourceDependencyState.UNKNOWN


def build_facts(
    evidence_items: List[EvidenceObject],
    events: List[EventObject],
    execution_states: Dict[str, ExecutionEvidence],
    persistence: List[Dict[str, Any]],
    usb: List[Dict[str, Any]],
    network_records: List[Dict[str, Any]],
    exfil_candidates: List[Dict[str, Any]],
    anti_forensic: List[Dict[str, Any]],
    contradictions: List[str],
) -> List[FactRecord]:
    facts: List[FactRecord] = []
    events_by_id = {e.event_id: e for e in events}

    for ev in evidence_items:
        if ev.integrity_state == IntegrityState.VERIFIED and ev.chain_of_custody_state in (
            ChainOfCustodyState.COMPLETE,
            ChainOfCustodyState.SUBSTANTIALLY_COMPLETE,
        ):
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"Evidence {ev.evidence_id} integrity is verified and chain of custody is {ev.chain_of_custody_state.name}.",
                    claim_type=ClaimType.DIRECT_ARTIFACT_FACT,
                    verification_state=VerificationState.SUPPORTED,
                    evidence_ids=[ev.evidence_id],
                    artifact_ids=[],
                    event_ids=[],
                    confidence=0.95,
                    limitations=["Integrity verification proves byte-level consistency, not content truth."],
                )
            )

    for key, ex in execution_states.items():
        if ex.state in (
            ExecutionState.EXECUTION_SUPPORTED,
            ExecutionState.EXECUTION_STRONGLY_SUPPORTED,
            ExecutionState.EXECUTION_VERIFIED_BY_MULTIPLE_ARTIFACTS,
        ):
            dep = source_dependency_for_events(ex.event_ids, events_by_id)

            verification = VerificationState.SUPPORTED
            if ex.state == ExecutionState.EXECUTION_SUPPORTED or dep != SourceDependencyState.INDEPENDENT:
                verification = VerificationState.PARTIALLY_SUPPORTED

            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"Execution of process '{ex.process_name or key}' is supported by forensic artifacts.",
                    claim_type=ClaimType.CORRELATED_FACT,
                    verification_state=verification,
                    evidence_ids=sorted({eid for eid in sum((events_by_id[e].evidence_ids for e in ex.event_ids if e in events_by_id), [])}),
                    artifact_ids=sorted({aid for aid in sum((events_by_id[e].artifact_ids for e in ex.event_ids if e in events_by_id), [])}),
                    event_ids=ex.event_ids,
                    confidence=ex.confidence,
                    limitations=[
                        "Execution does not establish user intent.",
                        "Execution does not establish real-person attribution.",
                        "Execution does not establish maliciousness.",
                        f"Source dependency state: {dep.name}.",
                    ],
                )
            )

        elif ex.state == ExecutionState.FILE_PRESENT:
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"File/process artifact for '{ex.process_name or key}' is present, but execution is not established.",
                    claim_type=ClaimType.DIRECT_ARTIFACT_FACT,
                    verification_state=VerificationState.INCONCLUSIVE,
                    evidence_ids=[],
                    artifact_ids=[],
                    event_ids=ex.event_ids,
                    confidence=ex.confidence,
                    limitations=["File presence alone does not prove execution."],
                )
            )

    for e in events:
        if e.event_type == "FILE_CREATED" and e.file.get("path"):
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"File creation observed for '{e.file.get('path')}'.",
                    claim_type=ClaimType.DIRECT_ARTIFACT_FACT,
                    verification_state=VerificationState.SUPPORTED if e.confidence >= 0.70 else VerificationState.PARTIALLY_SUPPORTED,
                    evidence_ids=e.evidence_ids,
                    artifact_ids=e.artifact_ids,
                    event_ids=[e.event_id],
                    confidence=e.confidence,
                    limitations=["File creation may result from download, copy, extract, install, sync, cache, or application behavior."],
                )
            )

        if e.event_type == "LOG_CLEARING_OBSERVED":
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement="Log clearing event was observed in authorized forensic evidence.",
                    claim_type=ClaimType.DIRECT_ARTIFACT_FACT,
                    verification_state=VerificationState.SUPPORTED,
                    evidence_ids=e.evidence_ids,
                    artifact_ids=e.artifact_ids,
                    event_ids=[e.event_id],
                    confidence=e.confidence,
                    limitations=[
                        "Log clearing does not by itself establish attacker cover-up.",
                        "Possible causes include administration, maintenance, rotation, policy, or attacker activity.",
                    ],
                )
            )

    for u in usb:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"USB/removable media connection observed for device serial '{u.get('serial')}'.",
                claim_type=ClaimType.DIRECT_ARTIFACT_FACT,
                verification_state=VerificationState.SUPPORTED,
                evidence_ids=[],
                artifact_ids=[],
                event_ids=[u["event_id"]],
                confidence=0.75,
                limitations=["USB connection alone does not prove file copy or exfiltration."],
            )
        )

    for n in network_records:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"Network activity observed to remote IP '{n.get('remote_ip')}' / domain '{n.get('domain')}'.",
                claim_type=ClaimType.DIRECT_ARTIFACT_FACT,
                verification_state=VerificationState.SUPPORTED,
                evidence_ids=[],
                artifact_ids=[],
                event_ids=[n["event_id"]],
                confidence=0.75,
                limitations=["Network connection alone does not prove C2 or exfiltration."],
            )
        )

    for x in exfil_candidates:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement="Exfiltration candidate exists based on large transfer and nearby archive creation, but is not established.",
                claim_type=ClaimType.ANALYTICAL_INFERENCE,
                verification_state=VerificationState.INCONCLUSIVE,
                evidence_ids=[],
                artifact_ids=[],
                event_ids=[x["network_event_id"]],
                confidence=0.35,
                limitations=[
                    "Large transfer alone does not prove exfiltration.",
                    "Archive creation alone does not prove exfiltration.",
                    "Additional file-transfer, proxy, PCAP, NetFlow, and cloud/storage evidence is required.",
                ],
            )
        )

    for af in anti_forensic:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"Anti-forensic indicator candidate observed: {af['state']}.",
                claim_type=ClaimType.DIRECT_ARTIFACT_FACT if af["state"] == AntiForensicIndicatorState.LOG_CLEARING_OBSERVED.name else ClaimType.ANALYTICAL_INFERENCE,
                verification_state=VerificationState.SUPPORTED if af["state"] == AntiForensicIndicatorState.LOG_CLEARING_OBSERVED.name else VerificationState.INCONCLUSIVE,
                evidence_ids=[af.get("evidence_id")] if af.get("evidence_id") else [],
                artifact_ids=[af.get("artifact_id")] if af.get("artifact_id") else [],
                event_ids=[af.get("event_id")] if af.get("event_id") else [],
                confidence=0.65,
                limitations=["Anti-forensic indicator does not establish malicious intent or operator identity."],
            )
        )

    facts.append(
        FactRecord(
            fact_id=new_id("FACT"),
            statement="Real-person attribution is not established by available forensic evidence.",
            claim_type=ClaimType.UNKNOWN,
            verification_state=VerificationState.INCONCLUSIVE,
            evidence_ids=[],
            artifact_ids=[],
            event_ids=[],
            confidence=0.99,
            limitations=[
                "Account, device, session, IP, and artifact activity do not automatically identify a real person.",
                "Consequential person attribution requires human review and independent evidence.",
            ],
        )
    )

    return facts


def build_hypotheses(
    execution_states: Dict[str, ExecutionEvidence],
    events: List[EventObject],
    persistence: List[Dict[str, Any]],
    network_records: List[Dict[str, Any]],
    exfil_candidates: List[Dict[str, Any]],
    anti_forensic: List[Dict[str, Any]],
) -> List[Hypothesis]:
    if not execution_states:
        return [
            Hypothesis(
                id="H0",
                description="No execution-supported process hypothesis is available from supplied artifacts.",
                support_evidence=["No execution artifact families met threshold."],
                opposition_evidence=[],
                unknowns=["Whether additional authorized artifacts exist."],
                falsification_criteria="Upgrade if Prefetch, EDR, process-start logs, or memory process artifacts appear.",
                status=HypothesisStatus.INCONCLUSIVE,
            )
        ]

    top_key, top = max(execution_states.items(), key=lambda kv: kv[1].confidence)

    near_events: List[EventObject] = []
    if top.timestamps:
        # Use first available timestamp as anchor.
        anchor_raw = top.timestamps[0]
        anchor_dt, _ = parse_dt(anchor_raw)
        if anchor_dt:
            for e in events:
                if e.timestamp.utc and abs((e.timestamp.utc - anchor_dt).total_seconds()) <= 3600:
                    near_events.append(e)
    else:
        near_events = events

    interactive = any(
        e.event_type == "LOGIN_SUCCESS" and str(e.details.get("logon_type", "")).lower() in {"2", "interactive"}
        for e in near_events
    )

    remote = any(e.event_type in {"REMOTE_SESSION", "LOGIN_SUCCESS"} and e.details.get("source_host") for e in near_events)

    scheduled = any(
        p.get("target") and top.process_name and str(top.process_name).lower() in str(p.get("target")).lower()
        for p in persistence
    ) or any(e.event_type == "SCHEDULED_TASK_CONFIGURED" for e in near_events)

    malware_context = any(
        e.event_type in {"RANSOM_NOTE_PRESENT", "MALWARE_ARTIFACT_CONTEXT"}
        for e in near_events
    ) or any(x.get("nearby_archive_creation") for x in exfil_candidates)

    installer = any(
        e.event_type in {"INSTALL_TIME", "FILE_CREATED"} and str(e.file.get("path", "")).lower().find("install") >= 0
        for e in near_events
    )

    hypotheses: List[Hypothesis] = []

    hypotheses.append(
        Hypothesis(
            id="H1",
            description=f"User account associated with session manually executed '{top.process_name or top_key}'.",
            support_evidence=["Interactive logon evidence near execution."] if interactive else [],
            opposition_evidence=["No interactive logon evidence near execution."] if not interactive else [],
            unknowns=["Real-person operator identity", "Intent"],
            falsification_criteria="Reject or downgrade if execution correlates with scheduled task, service, installer, or remote automation.",
            status=HypothesisStatus.CANDIDATE if interactive else HypothesisStatus.INCONCLUSIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H2",
            description=f"Scheduled task or automation executed '{top.process_name or top_key}'.",
            support_evidence=["Scheduled task configuration near execution."] if scheduled else [],
            opposition_evidence=["No scheduled-task evidence near execution."] if not scheduled else [],
            unknowns=["Task owner", "Trigger source"],
            falsification_criteria="Reject if task history or process parent shows interactive launch.",
            status=HypothesisStatus.CANDIDATE if scheduled else HypothesisStatus.INCONCLUSIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H3",
            description=f"Remote operator or remote service executed '{top.process_name or top_key}'.",
            support_evidence=["Remote session evidence near execution."] if remote else [],
            opposition_evidence=["No remote-session evidence near execution."] if not remote else [],
            unknowns=["Remote source identity", "Authorization status"],
            falsification_criteria="Reject if console/interactive evidence dominates and no remote service activity exists.",
            status=HypothesisStatus.CANDIDATE if remote else HypothesisStatus.INCONCLUSIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H4",
            description=f"Malicious software or attacker tooling executed '{top.process_name or top_key}'.",
            support_evidence=["Malware/ransom/exfiltration candidate context."] if malware_context else [],
            opposition_evidence=[
                "Execution alone does not establish maliciousness.",
                "Legitimate software, installer, admin tool, or service may explain activity.",
            ],
            unknowns=["Malware family", "Actor", "Campaign"],
            falsification_criteria="Reject if binary/signature/path/context supports legitimate software and no malicious artifact chain exists.",
            status=HypothesisStatus.CANDIDATE if malware_context else HypothesisStatus.INCONCLUSIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H5",
            description=f"Installer, updater, or application workflow generated execution artifacts for '{top.process_name or top_key}'.",
            support_evidence=["Installer/update artifact context."] if installer else [],
            opposition_evidence=["No installer/update artifact context."] if not installer else [],
            unknowns=["Package provenance", "Update mechanism"],
            falsification_criteria="Reject if process parent/command line/network context indicates manual or remote execution.",
            status=HypothesisStatus.CANDIDATE if installer else HypothesisStatus.INCONCLUSIVE,
        )
    )

    return hypotheses


def independent_skeptic_review(
    facts: List[FactRecord],
    execution_states: Dict[str, ExecutionEvidence],
    contradictions: List[str],
    anti_forensic: List[Dict[str, Any]],
    exfil_candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:
    flags: List[str] = []
    alternatives: List[str] = []
    questions: List[str] = []

    for f in facts:
        stmt = f.statement.lower()

        if "real person" in stmt and f.verification_state in (VerificationState.SUPPORTED, VerificationState.PARTIALLY_SUPPORTED):
            flags.append("POSSIBLE_REAL_PERSON_OVERATTRIBUTION")

        if "executed" in stmt and f.verification_state == VerificationState.SUPPORTED:
            matching = [
                ex
                for ex in execution_states.values()
                if ex.state not in (ExecutionState.EXECUTION_SUPPORTED, ExecutionState.EXECUTION_STRONGLY_SUPPORTED, ExecutionState.EXECUTION_VERIFIED_BY_MULTIPLE_ARTIFACTS)
            ]
            if matching:
                flags.append("POSSIBLE_EXECUTION_OVERCLAIM")

    if any(ex.state == ExecutionState.FILE_PRESENT for ex in execution_states.values()):
        alternatives.append("File presence may reflect download, copy, install, sync, cache, or backup rather than execution.")

    if contradictions:
        flags.append("CONTRADICTIONS_PRESENT")
        alternatives.append("Parser disagreement, clock skew, timezone issue, copying, restore, or collection gap may explain conflicts.")

    if anti_forensic:
        alternatives.extend(
            [
                "Log clearing may reflect administration, maintenance, rotation, or policy.",
                "History gaps may reflect retention, rollover, outage, or collection failure.",
            ]
        )
        flags.append("ANTI_FORENSIC_INTENT_NOT_ESTABLISHED")

    if exfil_candidates:
        alternatives.extend(
            [
                "Large transfer may reflect backup, update, sync, or legitimate business transfer.",
                "Archive creation may reflect backup, packaging, or authorized transfer.",
            ]
        )
        flags.append("EXFILTRATION_NOT_ESTABLISHED")

    questions.extend(
        [
            "Is this artifact actually evidence of execution?",
            "Are timestamps interpreted with correct semantics?",
            "Could this be automated system activity?",
            "Are user/account/person being conflated?",
            "Could collection be incomplete?",
            "Could parser semantics be wrong?",
            "Could multiple artifacts come from one underlying event?",
            "What evidence would disprove the leading narrative?",
        ]
    )

    return {
        "flags": sorted(set(flags)),
        "alternative_explanations": sorted(set(alternatives)),
        "diagnostic_questions": questions,
        "review_outcome": "PARTIAL_AGREEMENT" if flags else "AGREE",
        "privacy_boundary": "No real-person attribution, no credential use, no anti-forensic instruction.",
    }


def build_graphical_memory(
    evidence_items: List[EvidenceObject],
    artifacts: List[ArtifactObject],
    events: List[EventObject],
    devices: Dict[str, DeviceObject],
    execution_states: Dict[str, ExecutionEvidence],
    facts: List[FactRecord],
    hypotheses: List[Hypothesis],
    contradictions: List[str],
    gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []

    def add_node(node_id: str, node_type: str, attributes: Dict[str, Any]) -> None:
        nodes[node_id] = GraphNode(node_id=node_id, type=node_type, attributes=attributes)

    def add_edge(source: str, target: str, relation: str, confidence: float, evidence_ids: List[str]) -> None:
        edges.append(
            GraphEdge(
                edge_id=new_id("EDGE"),
                source_node_id=source,
                target_node_id=target,
                relation=relation,
                confidence=confidence,
                evidence_ids=evidence_ids,
            )
        )

    for ev in evidence_items:
        add_node(
            f"N_EVIDENCE_{ev.evidence_id}",
            "EvidenceItem",
            {
                "evidence_type": ev.evidence_type,
                "integrity_state": ev.integrity_state.name,
                "chain_of_custody_state": ev.chain_of_custody_state.name,
            },
        )

        if ev.source_device_id:
            add_edge(f"N_EVIDENCE_{ev.evidence_id}", f"N_DEVICE_{ev.source_device_id}", "ACQUIRED_FROM", 0.9, [ev.evidence_id])

    for dev in devices.values():
        add_node(
            f"N_DEVICE_{dev.device_id}",
            "Device",
            {
                "device_type": dev.device_type,
                "hostname": dev.hostname,
                "hardware_ids": dev.hardware_ids,
                "installation_ids": dev.installation_ids,
            },
        )

    for art in artifacts:
        add_node(
            f"N_ARTIFACT_{art.artifact_id}",
            "Artifact",
            {
                "artifact_type": art.artifact_type,
                "parser": art.parser,
                "parser_version": art.parser_version,
                "confidence": art.confidence,
            },
        )
        add_edge(f"N_ARTIFACT_{art.artifact_id}", f"N_EVIDENCE_{art.evidence_id}", "PARSED_FROM", art.confidence, [art.evidence_id])

    for e in events:
        add_node(
            f"N_EVENT_{e.event_id}",
            "TimelineEvent",
            {
                "event_type": e.event_type,
                "timestamp": e.timestamp.raw_value,
                "timestamp_semantics": e.timestamp.semantics.name,
                "confidence": e.confidence,
            },
        )

        for aid in e.artifact_ids:
            add_edge(f"N_EVENT_{e.event_id}", f"N_ARTIFACT_{aid}", "OBSERVED_ON", e.confidence, e.evidence_ids)

        if e.device:
            add_edge(f"N_EVENT_{e.event_id}", f"N_DEVICE_{e.device}", "OBSERVED_ON", e.confidence, e.evidence_ids)

        if e.account:
            acct_node = f"N_ACCOUNT_{e.account}"
            if acct_node not in nodes:
                add_node(acct_node, "UserAccount", {"account": e.account, "person_identity": "UNRESOLVED"})
            add_edge(f"N_EVENT_{e.event_id}", acct_node, "ASSOCIATED_WITH_ACCOUNT", e.confidence, e.evidence_ids)

        if e.process.get("name") or e.process.get("path"):
            proc_key = str(e.process.get("path") or e.process.get("name")).lower()
            proc_node = f"N_PROCESS_{hashlib.md5(proc_key.encode()).hexdigest()[:10]}"
            if proc_node not in nodes:
                add_node(proc_node, "Process", {"name": e.process.get("name"), "path": e.process.get("path")})
            add_edge(f"N_EVENT_{e.event_id}", proc_node, "EXECUTED_ON_CANDIDATE", e.confidence, e.evidence_ids)

        if e.file.get("path"):
            file_node = f"N_FILE_{hashlib.md5(str(e.file.get('path')).encode()).hexdigest()[:10]}"
            if file_node not in nodes:
                add_node(file_node, "File", {"path": e.file.get("path")})
            relation = "CREATED" if e.event_type == "FILE_CREATED" else "MODIFIED" if e.event_type == "FILE_MODIFIED" else "ACCESSED" if e.event_type == "FILE_ACCESSED" else "DELETED" if e.event_type == "FILE_DELETED" else "OBSERVED"
            add_edge(f"N_EVENT_{e.event_id}", file_node, relation, e.confidence, e.evidence_ids)

        if e.network_context.get("remote_ip"):
            ip_node = f"N_IP_{e.network_context.get('remote_ip')}"
            if ip_node not in nodes:
                add_node(ip_node, "IP", {"ip": e.network_context.get("remote_ip"), "person_identity": "UNRESOLVED"})
            add_edge(f"N_EVENT_{e.event_id}", ip_node, "CONNECTED_TO", e.confidence, e.evidence_ids)

    for key, ex in execution_states.items():
        proc_key = str(ex.process_path or ex.process_name or key).lower()
        proc_node = f"N_PROCESS_{hashlib.md5(proc_key.encode()).hexdigest()[:10]}"
        if proc_node not in nodes:
            add_node(proc_node, "Process", {"name": ex.process_name, "path": ex.process_path})

        add_node(
            f"N_EXEC_{hashlib.md5(key.encode()).hexdigest()[:10]}",
            "ExecutionEvidence",
            {
                "state": ex.state.name,
                "families": ex.families,
                "confidence": ex.confidence,
            },
        )

        for eid in ex.event_ids:
            add_edge(f"N_EXEC_{hashlib.md5(key.encode()).hexdigest()[:10]}", f"N_EVENT_{eid}", "SUPPORTED_BY", ex.confidence, [])

    for f in facts:
        add_node(
            f"N_FACT_{f.fact_id}",
            "Fact",
            {
                "statement": f.statement,
                "claim_type": f.claim_type.name,
                "verification_state": f.verification_state.name,
                "confidence": f.confidence,
            },
        )
        for eid in f.event_ids:
            add_edge(f"N_FACT_{f.fact_id}", f"N_EVENT_{eid}", "SUPPORTED_BY", f.confidence, f.evidence_ids)

    for h in hypotheses:
        add_node(
            f"N_HYPOTHESIS_{h.id}",
            "Hypothesis",
            {
                "description": h.description,
                "status": h.status.name,
                "support_evidence": h.support_evidence,
                "opposition_evidence": h.opposition_evidence,
            },
        )

    for c in contradictions:
        cid = hashlib.md5(c.encode()).hexdigest()[:10]
        add_node(f"N_CONTRADICTION_{cid}", "Contradiction", {"text": c})

    for g in gaps:
        add_node(f"N_GAP_{g['gap_id']}", "Gap", g)

    return {
        "nodes": [asdict(n) for n in nodes.values()],
        "edges": [asdict(e) for e in edges],
    }


def build_knowledge_gaps(
    evidence_items: List[EvidenceObject],
    artifacts: List[ArtifactObject],
    events: List[EventObject],
    execution_states: Dict[str, ExecutionEvidence],
    exfil_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    def add_gap(description: str, importance: str, recommended_source: str, specialist: str, expected_information_value: str) -> None:
        gaps.append(
            {
                "gap_id": new_id("GAP"),
                "description": description,
                "importance": importance,
                "recommended_source": recommended_source,
                "specialist": specialist,
                "expected_information_value": expected_information_value,
            }
        )

    for ev in evidence_items:
        if ev.integrity_state != IntegrityState.VERIFIED:
            add_gap(
                f"Evidence {ev.evidence_id} integrity is not fully verified.",
                "HIGH",
                "acquisition manifest / hash log",
                "FORENSICINT",
                "Confirms evidence was not altered between acquisition and analysis.",
            )

        if ev.chain_of_custody_state in (ChainOfCustodyState.PARTIAL, ChainOfCustodyState.UNKNOWN, ChainOfCustodyState.BROKEN):
            add_gap(
                f"Chain of custody for {ev.evidence_id} is {ev.chain_of_custody_state.name}.",
                "HIGH",
                "custody log / collector interview / lab records",
                "FORENSICINT / LEGAL_REVIEW",
                "Supports evidentiary reliability and reproducibility.",
            )

        if ev.encrypted_unavailable:
            add_gap(
                f"Evidence {ev.evidence_id} is encrypted and no authorized decryption result was supplied.",
                "HIGH",
                "authorized decryption workflow",
                "CREDINT / LEGAL_REVIEW",
                "May enable lawful analysis without unauthorized credential use.",
            )

    for art in artifacts:
        if not art.parser:
            add_gap(
                f"Artifact {art.artifact_id} lacks parser provenance.",
                "MEDIUM",
                "tool log / parser configuration",
                "FORENSICINT",
                "Supports reproducibility and parser-error assessment.",
            )

        if art.parser_disagreement:
            add_gap(
                f"Artifact {art.artifact_id} has parser disagreement.",
                "HIGH",
                "second parser / raw inspection",
                "FORENSICINT",
                "Resolves semantic or field-level conflict.",
            )

    for e in events:
        if e.timestamp.utc is None:
            add_gap(
                f"Event {e.event_id} has unresolved timezone or unparseable timestamp.",
                "MEDIUM",
                "system timezone config / NTP logs / acquisition metadata",
                "FORENSICINT",
                "Improves timeline ordering confidence.",
            )

    if execution_states:
        has_memory = any("memory_process" in ex.families for ex in execution_states.values())
        has_edr = any("edr_process" in ex.families for ex in execution_states.values())

        if not has_memory:
            add_gap(
                "Memory image or process telemetry not available for execution corroboration.",
                "MEDIUM",
                "authorized memory capture / EDR",
                "FORENSICINT / MALINT",
                "Strengthens process and parent-child reconstruction.",
            )

        if not has_edr:
            add_gap(
                "EDR telemetry not available for execution corroboration.",
                "MEDIUM",
                "EDR export",
                "FORENSICINT / INCIDENTINT",
                "Strengthens process, network, and persistence context.",
            )

    if exfil_candidates:
        add_gap(
            "Exfiltration candidate exists but file-transfer and payload evidence are unresolved.",
            "HIGH",
            "PCAP / NetFlow / proxy logs / cloud access logs",
            "NETINT / CLOUDINT / INCIDENTINT",
            "Determines whether archive/data was actually transmitted.",
        )

    add_gap(
        "Real-person operator attribution is unresolved.",
        "HIGH",
        "authorized identity evidence / HR records / access logs / human review",
        "FORENSICINT / HR_LEGAL_REVIEW",
        "Prevents unsupported person attribution from technical artifacts.",
    )

    return gaps


def generate_analyst_summary(
    evidence_items: List[EvidenceObject],
    devices: Dict[str, DeviceObject],
    artifacts: List[ArtifactObject],
    events: List[EventObject],
    execution_states: Dict[str, ExecutionEvidence],
    facts: List[FactRecord],
    contradictions: List[str],
    anti_forensic: List[Dict[str, Any]],
    exfil_candidates: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> str:
    lines: List[str] = []

    lines.append("=== FORENSICINT REQUIRED ANALYST SUMMARY ===")

    lines.append("EVIDENCE INVENTORY:")
    for ev in evidence_items:
        lines.append(
            f"- {ev.evidence_id}: type={ev.evidence_type}, integrity={ev.integrity_state.name}, custody={ev.chain_of_custody_state.name}"
        )

    lines.append("")
    lines.append("CHAIN OF CUSTODY:")
    for ev in evidence_items:
        lines.append(f"- {ev.evidence_id}: {ev.chain_of_custody_state.name}")

    lines.append("")
    lines.append("INTEGRITY:")
    for ev in evidence_items:
        lines.append(f"- {ev.evidence_id}: {ev.integrity_state.name}")

    lines.append("")
    lines.append("DEVICE / IMAGE:")
    for dev in devices.values():
        lines.append(f"- {dev.device_id}: type={dev.device_type}, hostname={dev.hostname}, hardware_ids={dev.hardware_ids}")

    lines.append("")
    lines.append("KEY ARTIFACTS:")
    type_counts = defaultdict(int)
    for art in artifacts:
        type_counts[art.artifact_type] += 1
    for t, c in sorted(type_counts.items()):
        lines.append(f"- {t}: {c}")

    lines.append("")
    lines.append("EXECUTION EVIDENCE:")
    if execution_states:
        for ex in sorted(execution_states.values(), key=lambda x: x.confidence, reverse=True):
            lines.append(
                f"- {ex.process_name or ex.process_key}: state={ex.state.name}, families={ex.families}, confidence={ex.confidence}"
            )
            lines.append("  CAUTION: Execution does not establish user intent, real-person attribution, or maliciousness.")
    else:
        lines.append("- No execution-supported process identified.")

    lines.append("")
    lines.append("FILE ACTIVITY:")
    file_events = [e for e in events if e.event_type.startswith("FILE_")]
    if file_events:
        for e in file_events[:10]:
            lines.append(f"- {e.event_type}: {e.file.get('path')} at {e.timestamp.raw_value}")
    else:
        lines.append("- No file activity events extracted.")

    lines.append("")
    lines.append("DELETED / CARVED DATA:")
    carved = [a for a in artifacts if a.artifact_type == "CARVED_FILE"]
    deleted = [e for e in events if e.event_type == "FILE_DELETED"]
    lines.append(f"- Carved artifacts: {len(carved)}")
    lines.append(f"- Deleted-file events: {len(deleted)}")
    lines.append("- Deleted state does not prove intentional deletion, actor, or motive.")

    lines.append("")
    lines.append("PERSISTENCE:")
    persistence_events = [e for e in events if e.event_type in PERSISTENCE_EVENT_TYPES]
    if persistence_events:
        for e in persistence_events[:10]:
            lines.append(f"- {e.event_type}: target={e.details.get('target')} name={e.details.get('name')}")
    else:
        lines.append("- No persistence configuration artifacts extracted.")
    lines.append("- Persistence configuration does not automatically mean malicious persistence.")

    lines.append("")
    lines.append("AUTHENTICATION / SESSIONS:")
    auth_events = [e for e in events if e.event_type in {"LOGIN_SUCCESS", "LOGIN_FAILURE", "REMOTE_SESSION"}]
    if auth_events:
        for e in auth_events[:10]:
            lines.append(f"- {e.event_type}: account={e.account} at {e.timestamp.raw_value}")
    else:
        lines.append("- No authentication/session events extracted.")
    lines.append("- Account activity does not automatically identify a real person.")

    lines.append("")
    lines.append("USB / REMOVABLE MEDIA:")
    usb_events = [e for e in events if e.event_type in USB_EVENT_TYPES]
    if usb_events:
        for e in usb_events[:10]:
            lines.append(f"- USB_CONNECTED: serial={e.details.get('device_serial')} at {e.timestamp.raw_value}")
    else:
        lines.append("- No USB/removable-media events extracted.")
    lines.append("- USB connection alone does not prove file copy or exfiltration.")

    lines.append("")
    lines.append("NETWORK CONTEXT:")
    net_events = [e for e in events if e.event_type in NETWORK_EVENT_TYPES]
    if net_events:
        for e in net_events[:10]:
            lines.append(
                f"- {e.event_type}: remote_ip={e.network_context.get('remote_ip')} domain={e.network_context.get('domain')} bytes_sent={e.network_context.get('bytes_sent')}"
            )
    else:
        lines.append("- No network-context events extracted.")
    lines.append("- Connection/DNS alone does not prove C2 or exfiltration.")

    lines.append("")
    lines.append("MALWARE CONTEXT:")
    malware_events = [e for e in events if e.event_type in {"RANSOM_NOTE_PRESENT", "MALWARE_ARTIFACT_CONTEXT"}]
    if malware_events:
        for e in malware_events[:10]:
            lines.append(f"- {e.event_type} at {e.timestamp.raw_value}")
    else:
        lines.append("- No malware-specific forensic context extracted.")
    lines.append("- Malware file presence does not prove execution; execution does not prove full incident scope.")

    lines.append("")
    lines.append("CLOUD / MOBILE CONTEXT:")
    cloud_mobile = [ev for ev in evidence_items if ev.evidence_type.upper() in {"CLOUD_EXPORT", "MOBILE_EXTRACTION"}]
    if cloud_mobile:
        for ev in cloud_mobile:
            lines.append(f"- {ev.evidence_id}: {ev.evidence_type}")
    else:
        lines.append("- No cloud/mobile extraction evidence supplied.")

    lines.append("")
    lines.append("TIMELINE:")
    sorted_events = sorted(events, key=lambda e: e.timestamp.sort_key)
    for e in sorted_events[:20]:
        lines.append(f"- {e.timestamp.sort_key}: {e.event_type} | device={e.device} | account={e.account}")

    lines.append("")
    lines.append("EARLIEST OBSERVED ACTIVITY:")
    if sorted_events:
        e0 = sorted_events[0]
        lines.append(f"- {e0.timestamp.sort_key}: {e0.event_type}")
        lines.append("- Earliest observed activity is not automatically initial access.")
    else:
        lines.append("- None.")

    lines.append("")
    lines.append("ANTI-FORENSIC INDICATORS:")
    if anti_forensic:
        for af in anti_forensic:
            lines.append(f"- {af['state']} | intent=UNKNOWN")
    else:
        lines.append("- None identified from supplied authorized artifacts.")
    lines.append("- Anti-forensic indicator does not establish malicious intent or operator identity.")

    lines.append("")
    lines.append("CORROBORATED EVENTS:")
    corroborated = [f for f in facts if f.verification_state in (VerificationState.SUPPORTED, VerificationState.PARTIALLY_SUPPORTED)]
    for f in corroborated[:10]:
        lines.append(f"- {f.statement} [{f.verification_state.name}]")

    lines.append("")
    lines.append("DISPUTED EVENTS:")
    disputed = [f for f in facts if f.verification_state in (VerificationState.DISPUTED, VerificationState.UNSUPPORTED)]
    if disputed:
        for f in disputed:
            lines.append(f"- {f.statement} [{f.verification_state.name}]")
    else:
        lines.append("- None.")

    lines.append("")
    lines.append("SOURCE / ARTIFACT RELIABILITY:")
    for art in artifacts[:10]:
        lines.append(f"- {art.artifact_id}: type={art.artifact_type}, parser={art.parser}, confidence={art.confidence}")

    lines.append("")
    lines.append("CONTRADICTIONS:")
    if contradictions:
        for c in contradictions:
            lines.append(f"- {c}")
    else:
        lines.append("- None detected from supplied evidence.")

    lines.append("")
    lines.append("COMPETING HYPOTHESES:")
    lines.append("- See hypotheses section. Technical execution evidence alone does not select operator, intent, or malware family.")

    lines.append("")
    lines.append("UNKNOWN:")
    lines.append("- Real-person operator identity.")
    lines.append("- Intent.")
    lines.append("- Maliciousness.")
    lines.append("- Full incident scope.")
    lines.append("- Whether network activity constituted exfiltration.")

    lines.append("")
    lines.append("NEXT ACTION:")
    lines.append("- Verify acquisition/hash logs and chain of custody.")
    lines.append("- Correlate execution with EDR/memory/process-start artifacts.")
    lines.append("- Correlate archive creation with proxy/PCAP/NetFlow/cloud storage evidence before any exfiltration conclusion.")
    lines.append("- Hand off malware classification to MALINT, network depth to NETINT, credential exposure to CREDINT, actor context to CTI.")
    lines.append("- Require human review before real-person, criminal, employment, or legal attribution.")

    return "\n".join(lines)


# ==============================================================================
# MAIN ENGINE: FORENSICINT AI EMPLOYEE
# ==============================================================================

class ForensicIntEmployee:
    """
    Defensive FORENSICINT employee.

    Consumes already-collected authorized forensic evidence representations.
    Does not access devices, bypass authentication, use credentials, crack passwords,
    modify evidence, execute malware, exfiltrate data, or provide anti-forensic instructions.
    """

    def __init__(self, model_mode: str = "LOCAL_ONLY"):
        self.model_mode = model_mode.upper()
        logger.info("FORENSICINT employee initialized in mode=%s", self.model_mode)

    def process_case(
        self,
        case_id: str,
        task_id: str,
        objective: str,
        scope: Dict[str, Any],
        evidence_input: List[Dict[str, Any]],
        known_facts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        known_facts = known_facts or {}
        now = datetime.now(timezone.utc)

        try:
            enforce_policy(objective, scope)
        except PolicyViolation as exc:
            return {
                "case_id": case_id,
                "task_id": task_id,
                "objective": objective,
                "status": "POLICY_BLOCKED",
                "error": str(exc),
                "privacy_flags": [
                    "READ_ONLY_DEFAULT",
                    "NO_DEVICE_INTRUSION",
                    "NO_CREDENTIAL_USE",
                    "NO_PASSWORD_CRACKING",
                    "NO_ANTI_FORENSIC_INSTRUCTIONS",
                    "NO_REAL_PERSON_AUTONOMOUS_ATTRIBUTION",
                ],
            }

        logger.info("Starting FORENSICINT case=%s task=%s", case_id, task_id)

        evidence_items: List[EvidenceObject] = []
        artifacts: List[ArtifactObject] = []
        observations: List[ObservationObject] = []
        events: List[EventObject] = []
        devices: Dict[str, DeviceObject] = {}
        artifacts_by_id: Dict[str, ArtifactObject] = {}

        for ev_input in evidence_input:
            evidence = register_evidence(ev_input, case_id, now)
            evidence_items.append(evidence)

            resolve_device(
                devices,
                evidence.source_device_id,
                device_type=str(ev_input.get("device_type", "UNKNOWN")),
                hostname=ev_input.get("hostname"),
                hardware_ids=ev_input.get("hardware_ids"),
                installation_ids=ev_input.get("installation_ids"),
                first_seen=evidence.collection_time,
                last_seen=evidence.collection_time,
                confidence=0.75 if evidence.integrity_state == IntegrityState.VERIFIED else 0.55,
            )

            if evidence.encrypted_unavailable:
                continue

            for art_input in ev_input.get("artifacts", []) or []:
                art = register_artifact(art_input, evidence, now)
                artifacts.append(art)
                artifacts_by_id[art.artifact_id] = art

                obs = observations_from_artifact(art)
                observations.extend(obs)

                evts = events_from_artifact(art, evidence, obs, now)
                events.extend(evts)

                resolve_device(
                    devices,
                    art.device_candidate or evidence.source_device_id,
                    device_type=str(ev_input.get("device_type", "UNKNOWN")),
                    hostname=ev_input.get("hostname"),
                    hardware_ids=ev_input.get("hardware_ids"),
                    installation_ids=ev_input.get("installation_ids"),
                    first_seen=art.timestamps[0].utc if art.timestamps else evidence.collection_time,
                    last_seen=art.timestamps[0].utc if art.timestamps else evidence.collection_time,
                    confidence=art.confidence,
                )

        execution_states = build_execution_evidence(events, artifacts_by_id)
        persistence = detect_persistence(events)
        usb = detect_usb(events)
        network_records, exfil_candidates = detect_network_and_exfiltration_candidates(events)
        anti_forensic = detect_anti_forensic_indicators(events, artifacts, evidence_items)
        contradictions = detect_contradictions(events, execution_states, artifacts, evidence_items)
        facts = build_facts(
            evidence_items=evidence_items,
            events=events,
            execution_states=execution_states,
            persistence=persistence,
            usb=usb,
            network_records=network_records,
            exfil_candidates=exfil_candidates,
            anti_forensic=anti_forensic,
            contradictions=contradictions,
        )
        hypotheses = build_hypotheses(
            execution_states=execution_states,
            events=events,
            persistence=persistence,
            network_records=network_records,
            exfil_candidates=exfil_candidates,
            anti_forensic=anti_forensic,
        )
        skeptic = independent_skeptic_review(
            facts=facts,
            execution_states=execution_states,
            contradictions=contradictions,
            anti_forensic=anti_forensic,
            exfil_candidates=exfil_candidates,
        )
        gaps = build_knowledge_gaps(
            evidence_items=evidence_items,
            artifacts=artifacts,
            events=events,
            execution_states=execution_states,
            exfil_candidates=exfil_candidates,
        )
        graph = build_graphical_memory(
            evidence_items=evidence_items,
            artifacts=artifacts,
            events=events,
            devices=devices,
            execution_states=execution_states,
            facts=facts,
            hypotheses=hypotheses,
            contradictions=contradictions,
            gaps=gaps,
        )
        analyst_summary = generate_analyst_summary(
            evidence_items=evidence_items,
            devices=devices,
            artifacts=artifacts,
            events=events,
            execution_states=execution_states,
            facts=facts,
            contradictions=contradictions,
            anti_forensic=anti_forensic,
            exfil_candidates=exfil_candidates,
            gaps=gaps,
        )

        supported_facts = [f for f in facts if f.verification_state == VerificationState.SUPPORTED]
        partial_facts = [f for f in facts if f.verification_state == VerificationState.PARTIALLY_SUPPORTED]
        candidate_facts = [f for f in facts if f.verification_state == VerificationState.INCONCLUSIVE]
        disputed_facts = [f for f in facts if f.verification_state in (VerificationState.DISPUTED, VerificationState.UNSUPPORTED)]

        recommended_next_actions = [
            {
                "action": "Verify acquisition metadata, hash logs, and chain-of-custody records for all evidence items.",
                "reason": "Forensic confidence depends on reproducible acquisition and custody.",
                "specialist": "FORENSICINT",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Correlate execution artifacts across Prefetch, process-start logs, EDR, and memory where authorized.",
                "reason": "Single-artifact execution claims are weak.",
                "specialist": "FORENSICINT / INCIDENTINT",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Obtain PCAP/NetFlow/proxy/cloud-storage evidence before any exfiltration conclusion.",
                "reason": "Connection, DNS, archive creation, or large transfer alone do not prove exfiltration.",
                "specialist": "NETINT / CLOUDINT / INCIDENTINT",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Hand off malware sample classification and capability analysis to MALINT.",
                "reason": "FORENSICINT does not execute samples or perform deep reverse engineering.",
                "specialist": "MALINT",
                "privacy": "AUTHORIZED_SANDBOX_ONLY",
            },
            {
                "action": "Hand off credential/token exposure references to CREDINT without using credentials.",
                "reason": "FORENSICINT must not replay, authenticate, or crack credentials.",
                "specialist": "CREDINT",
                "privacy": "RESTRICTED",
            },
            {
                "action": "Require human review before real-person, criminal, employment, legal, or law-enforcement attribution.",
                "reason": "Technical artifacts alone do not establish person identity or culpability.",
                "specialist": "HUMAN_REVIEW / LEGAL_REVIEW",
                "privacy": "PRIVACY_BOUNDARY",
            },
        ]

        specialist_handoffs = [
            {"specialist": "INCIDENTINT", "reason": "Incident sequence, root cause, impact, containment, response."},
            {"specialist": "LOGINT", "reason": "Large-scale log normalization and retention/collection-change context."},
            {"specialist": "MALINT", "reason": "Malware family, capabilities, behavior, and safe sandbox analysis."},
            {"specialist": "NETINT", "reason": "Deep PCAP/NetFlow/Zeek/firewall relationship analysis."},
            {"specialist": "CREDINT", "reason": "Credential exposure handling without credential use."},
            {"specialist": "CTI / THREATACTORINT", "reason": "Threat-actor context, campaign clustering, and attribution evidence."},
            {"specialist": "DOCINT", "reason": "Document metadata and content analysis."},
            {"specialist": "CLOUDINT", "reason": "Cloud control-plane, storage, identity, and container forensics."},
            {"specialist": "MOBILEINT", "reason": "Mobile extraction-specific artifact analysis where configured."},
        ]

        privacy_flags = [
            "READ_ONLY_DEFAULT",
            "MINIMUM_NECESSARY_EXTRACTION",
            "CREDENTIAL_ARTIFACTS_REDACTED",
            "NO_CREDENTIAL_USE",
            "NO_PASSWORD_CRACKING",
            "NO_REAL_PERSON_AUTONOMOUS_ATTRIBUTION",
            "NO_ANTI_FORENSIC_INSTRUCTIONS",
            "PRIVILEGED_CONTENT_ROUTE_IF_DETECTED",
        ]

        legal_flags = []

        for ev in evidence_items:
            if ev.chain_of_custody_state in (ChainOfCustodyState.PARTIAL, ChainOfCustodyState.UNKNOWN, ChainOfCustodyState.BROKEN):
                legal_flags.append(f"Chain-of-custody concern for {ev.evidence_id}: {ev.chain_of_custody_state.name}")

        if any("privileged" in str(a.normalized_fields).lower() for a in artifacts):
            legal_flags.append("PRIVILEGED_CONTENT_CANDIDATE: route to authorized legal review before exposure.")

        status = "COMPLETED" if events or evidence_items else "INSUFFICIENT_DATA"

        result: Dict[str, Any] = {
            "case_id": case_id,
            "task_id": task_id,
            "objective": objective,
            "status": status,
            "model_mode": self.model_mode,
            "questions": scope.get("questions", []),
            "authorized_scope": scope,
            "source_ids": sorted({ev.evidence_id for ev in evidence_items}),
            "evidence_ids": sorted({ev.evidence_id for ev in evidence_items}),
            "chain_of_custody": {ev.evidence_id: ev.chain_of_custody_state.name for ev in evidence_items},
            "integrity_states": {ev.evidence_id: ev.integrity_state.name for ev in evidence_items},
            "disk_images": [asdict(ev) for ev in evidence_items if ev.evidence_type.upper() in {"DISK_IMAGE", "E01", "EWF", "RAW_IMAGE", "VHD", "VHDX", "VMDK", "AFF"}],
            "memory_images": [asdict(ev) for ev in evidence_items if "MEMORY" in ev.evidence_type.upper()],
            "mobile_extractions": [asdict(ev) for ev in evidence_items if "MOBILE" in ev.evidence_type.upper()],
            "cloud_exports": [asdict(ev) for ev in evidence_items if "CLOUD" in ev.evidence_type.upper()],
            "devices": [asdict(d) for d in devices.values()],
            "volumes": [],
            "filesystems": sorted({a.artifact_type for a in artifacts if a.artifact_type in {"NTFS", "FAT", "EXFAT", "EXT", "APFS", "HFSPLUS", "FILESYSTEM_FILE", "MFT", "USN_JOURNAL"}}),
            "files": sorted({str(e.file.get("path")) for e in events if e.file.get("path")}),
            "deleted_files": sorted({str(e.file.get("path")) for e in events if e.event_type == "FILE_DELETED" and e.file.get("path")}),
            "carved_artifacts": [asdict(a) for a in artifacts if a.artifact_type == "CARVED_FILE"],
            "registry_artifacts": [asdict(a) for a in artifacts if a.artifact_type.startswith("REGISTRY")],
            "event_logs": [asdict(a) for a in artifacts if a.artifact_type == "EVENT_LOG"],
            "browser_artifacts": [asdict(a) for a in artifacts if a.artifact_type.startswith("BROWSER")],
            "email_artifacts": [asdict(a) for a in artifacts if a.artifact_type == "EMAIL"],
            "application_artifacts": [asdict(a) for a in artifacts if a.artifact_type not in {"EVENT_LOG", "BROWSER_HISTORY", "BROWSER_DOWNLOAD", "EMAIL", "MFT", "USN_JOURNAL", "FILESYSTEM_FILE", "PREFETCH", "AMCACHE", "SHIMCACHE", "MEMORY_PROCESS", "EDR_PROCESS", "USBSTOR", "REMOVABLE_MEDIA", "SERVICE", "SCHEDULED_TASK", "NETWORK_CONNECTION", "DNS", "FLOW", "RANSOM_NOTE", "CARVED_FILE", "REGISTRY_RUN", "STARTUP", "LAUNCH_AGENT", "CRON"}],
            "processes": sorted({str(e.process.get("name") or e.process.get("path")) for e in events if e.process.get("name") or e.process.get("path")}),
            "process_trees": [
                {
                    "pid": e.process.get("pid"),
                    "parent_pid": e.process.get("parent_pid"),
                    "name": e.process.get("name"),
                    "path": e.process.get("path"),
                    "event_id": e.event_id,
                }
                for e in events
                if e.process.get("pid")
            ],
            "services": [p for p in persistence if p["type"] == "SERVICE_INSTALLED"],
            "scheduled_tasks": [p for p in persistence if p["type"] == "SCHEDULED_TASK_CONFIGURED"],
            "persistence_artifacts": persistence,
            "accounts": sorted({str(e.account) for e in events if e.account}),
            "sessions": [
                {
                    "event_id": e.event_id,
                    "account": e.account,
                    "session": e.details.get("session") or e.details.get("logon_id"),
                    "timestamp": e.timestamp.raw_value,
                }
                for e in events
                if e.event_type in {"LOGIN_SUCCESS", "LOGIN_FAILURE", "REMOTE_SESSION", "PROCESS_START"}
            ],
            "usb_devices": usb,
            "removable_media": usb,
            "network_connections": network_records,
            "dns_artifacts": [n for n in network_records if n["type"] == "DNS_QUERY"],
            "malware_artifact_context": [
                {
                    "event_id": e.event_id,
                    "type": e.event_type,
                    "timestamp": e.timestamp.raw_value,
                    "limitations": ["Malware file presence does not prove execution; execution does not prove full incident scope."],
                }
                for e in events
                if e.event_type in {"RANSOM_NOTE_PRESENT", "MALWARE_ARTIFACT_CONTEXT"}
            ],
            "cloud_events": [asdict(ev) for ev in evidence_items if "CLOUD" in ev.evidence_type.upper()],
            "container_events": [asdict(ev) for ev in evidence_items if "CONTAINER" in ev.evidence_type.upper()],
            "authentication_events": [
                {
                    "event_id": e.event_id,
                    "type": e.event_type,
                    "account": e.account,
                    "source_host": e.details.get("source_host"),
                    "logon_type": e.details.get("logon_type"),
                    "timestamp": e.timestamp.raw_value,
                }
                for e in events
                if e.event_type in {"LOGIN_SUCCESS", "LOGIN_FAILURE", "REMOTE_SESSION"}
            ],
            "execution_evidence": {k: asdict(v) for k, v in execution_states.items()},
            "file_activity": [
                {
                    "event_id": e.event_id,
                    "type": e.event_type,
                    "path": e.file.get("path"),
                    "timestamp": e.timestamp.raw_value,
                    "semantics": e.timestamp.semantics.name,
                }
                for e in events
                if e.event_type.startswith("FILE_")
            ],
            "timeline_events": [asdict(e) for e in sorted(events, key=lambda x: x.timestamp.sort_key)],
            "normalized_timeline": [
                {
                    "sort_key": e.timestamp.sort_key,
                    "event_id": e.event_id,
                    "event_type": e.event_type,
                    "device": e.device,
                    "account": e.account,
                    "timestamp_semantics": e.timestamp.semantics.name,
                    "confidence": e.confidence,
                }
                for e in sorted(events, key=lambda x: x.timestamp.sort_key)
            ],
            "timestamp_semantics": {
                e.event_id: {
                    "raw_value": e.timestamp.raw_value,
                    "raw_timezone": e.timestamp.raw_timezone,
                    "utc": e.timestamp.utc,
                    "semantics": e.timestamp.semantics.name,
                    "precision": e.timestamp.precision.name,
                    "confidence": e.timestamp.confidence,
                    "limitations": e.timestamp.limitations,
                }
                for e in events
            },
            "timezone_context": {
                ev.evidence_id: {
                    "source_timezone": ev.source_timezone,
                    "collection_time": ev.collection_time,
                }
                for ev in evidence_items
            },
            "clock_skew_context": [
                {
                    "risk": "Clock skew or timezone conversion may affect ordering.",
                    "affected_event_ids": [e.event_id for e in events if e.timestamp.utc is None or e.timestamp.precision in (TimestampPrecision.APPROXIMATE, TimestampPrecision.UNKNOWN, TimestampPrecision.DATE_ONLY)],
                }
            ],
            "anti_forensic_indicators": anti_forensic,
            "artifact_reliability": {
                a.artifact_id: {
                    "confidence": a.confidence,
                    "parser": a.parser,
                    "parser_version": a.parser_version,
                    "limitations": a.limitations,
                    "parser_disagreement": a.parser_disagreement,
                }
                for a in artifacts
            },
            "parser_results": {
                a.artifact_id: {
                    "parser": a.parser,
                    "parser_version": a.parser_version,
                    "parsed_at": a.parsed_at,
                    "normalized_fields": a.normalized_fields,
                }
                for a in artifacts
            },
            "parser_disagreements": [
                {
                    "artifact_id": a.artifact_id,
                    "disagreement": a.parser_disagreement,
                }
                for a in artifacts
                if a.parser_disagreement
            ],
            "observations": [asdict(o) for o in observations],
            "candidate_facts": [asdict(f) for f in candidate_facts],
            "supported_facts": [asdict(f) for f in supported_facts],
            "partial_facts": [asdict(f) for f in partial_facts],
            "disputed_facts": [asdict(f) for f in disputed_facts],
            "derived_facts": [
                asdict(f) for f in facts if f.claim_type in (ClaimType.DERIVED_FACT, ClaimType.CORRELATED_FACT)
            ],
            "analytical_inferences": [
                asdict(f) for f in facts if f.claim_type == ClaimType.ANALYTICAL_INFERENCE
            ],
            "source_reliability": {
                ev.evidence_id: {
                    "integrity_state": ev.integrity_state.name,
                    "chain_of_custody_state": ev.chain_of_custody_state.name,
                    "acquisition_tool": ev.acquisition_tool,
                    "acquisition_tool_version": ev.acquisition_tool_version,
                    "collector": ev.collector,
                }
                for ev in evidence_items
            },
            "source_dependencies": {
                ex.process_key: source_dependency_for_events(ex.event_ids, {e.event_id: e for e in events}).name
                for ex in execution_states.values()
            },
            "contradictions": contradictions,
            "hypotheses": [asdict(h) for h in hypotheses],
            "ach_matrix": {
                "note": "ACH is represented through hypotheses and falsification criteria. Consequential attribution requires human review.",
                "hypotheses": [asdict(h) for h in hypotheses],
            },
            "falsification_results": {
                "questions": [
                    "Could artifact reflect installation instead of execution?",
                    "Could account be service account?",
                    "Could timestamps be skewed?",
                    "Could process be legitimate software?",
                    "Could USB connection lack file transfer?",
                    "Could network connection be benign?",
                    "Could log gap be retention?",
                    "Could event have been generated automatically?",
                ],
                "skeptic_review": skeptic,
            },
            "privacy_flags": privacy_flags,
            "legal_flags": legal_flags,
            "unknowns": [
                "Real-person operator identity remains unresolved.",
                "Intent remains unresolved.",
                "Maliciousness remains unresolved unless separately established by authorized MALINT/INCIDENTINT context.",
                "Exfiltration remains unresolved without file-transfer/network-payload evidence.",
                "Initial access remains unresolved; earliest observed activity is not automatically initial access.",
            ],
            "knowledge_gaps": gaps,
            "recommended_next_actions": recommended_next_actions,
            "specialist_handoffs": specialist_handoffs,
            "limitations": [
                "FORENSICINT analyzes supplied authorized evidence representations only.",
                "It does not access devices, bypass authentication, use credentials, crack passwords, modify evidence, or execute malware.",
                "Artifact presence does not prove execution.",
                "Execution does not prove user intent, maliciousness, or real-person attribution.",
                "USB connection does not prove file copy.",
                "File copy does not prove exfiltration.",
                "Network connection does not prove C2.",
                "Log clearing does not prove attacker cover-up.",
                "Parser output is not automatically ground truth.",
            ],
            "analyst_summary": analyst_summary,
            "graphical_memory": graph,
            "replay_manifest": {
                "case_id": case_id,
                "task_id": task_id,
                "model_mode": self.model_mode,
                "generated_at": now.isoformat(),
                "evidence_ids": sorted({ev.evidence_id for ev in evidence_items}),
                "artifact_ids": sorted({a.artifact_id for a in artifacts}),
                "event_ids": sorted({e.event_id for e in events}),
                "tool_parser_versions": {
                    a.artifact_id: {
                        "parser": a.parser,
                        "parser_version": a.parser_version,
                        "parsed_at": a.parsed_at,
                    }
                    for a in artifacts
                },
                "hashes": {ev.evidence_id: ev.hashes for ev in evidence_items},
                "chain_of_custody_events": {
                    ev.evidence_id: [asdict(c) for c in ev.custody_events]
                    for ev in evidence_items
                },
                "normalization_logic": {
                    "timezone": "UTC internally; original timezone preserved; no silent local assumption",
                    "credentials": "redacted; not used",
                    "execution_ladder": "FILE_PRESENT -> EXECUTION_CANDIDATE -> EXECUTION_SUPPORTED -> EXECUTION_STRONGLY_SUPPORTED -> EXECUTION_VERIFIED_BY_MULTIPLE_ARTIFACTS",
                },
                "fact_gate": [asdict(f) for f in facts],
                "contradictions": contradictions,
                "hypotheses": [asdict(h) for h in hypotheses],
                "skeptic_review": skeptic,
            },
        }

        logger.info(
            "FORENSICINT case completed. evidence=%s artifacts=%s events=%s executions=%s",
            len(evidence_items),
            len(artifacts),
            len(events),
            len(execution_states),
        )

        return result


# ==============================================================================
# EXAMPLE EXECUTION
# ==============================================================================

if __name__ == "__main__":
    analyst = ForensicIntEmployee(model_mode="LOCAL_ONLY")

    case_id = "CASE_FORENSIC_001"
    task_id = "TASK_WORKSTATION_EXFIL_CONTEXT_001"

    objective = (
        "Analyze authorized forensic evidence from workstation DEV_WS01 to reconstruct execution, "
        "file activity, USB context, network context, and anti-forensic indicators. "
        "Do not use credentials, do not access unauthorized devices, do not modify evidence, "
        "and do not attribute a real person without independent authorized evidence and human review."
    )

    scope = {
        "mode": "AUTHORIZED_READONLY",
        "read_only": True,
        "questions": [
            "Which evidence items are integrity-verified?",
            "Which processes have execution support?",
            "Which files were created or modified?",
            "Was USB/removable media connected?",
            "Was network activity observed?",
            "Are anti-forensic indicators present?",
            "What remains unresolved?",
        ],
        "allow_device_intrusion": False,
        "allow_authentication_bypass": False,
        "allow_credential_use": False,
        "allow_password_cracking": False,
        "allow_anti_forensic_instructions": False,
        "allow_evidence_modification": False,
    }

    evidence_input = [
        {
            "evidence_id": "E01_DISK_WS01",
            "case_id": case_id,
            "source_device_id": "DEV_WS01",
            "device_type": "Workstation",
            "hostname": "WS01",
            "evidence_type": "DISK_IMAGE",
            "artifact_type": "E01",
            "original_name": "ws01.E01",
            "original_path": "/evidence/ws01.E01",
            "size": 1099511627776,
            "hashes": {
                "sha256": "a3f5b9c8d1e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4"
            },
            "expected_sha256": "a3f5b9c8d1e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4",
            "hash_verified": True,
            "acquisition_method": "hardware_write_blocker",
            "acquisition_tool": "FTK Imager",
            "acquisition_tool_version": "4.5.0",
            "collector": "ACME_DFIR_ANALYST_01",
            "collection_time": "2026-10-08T22:00:00Z",
            "source_timezone": "UTC",
            "chain_of_custody_state": "COMPLETE",
            "custody_events": [
                {
                    "event_id": "CUST_001",
                    "action": "acquisition",
                    "actor": "ACME_DFIR_ANALYST_01",
                    "timestamp": "2026-10-08T22:00:00Z",
                    "location": "Lab A",
                    "tool": "FTK Imager 4.5.0",
                },
                {
                    "event_id": "CUST_002",
                    "action": "transfer",
                    "actor": "ACME_DFIR_ANALYST_01",
                    "timestamp": "2026-10-08T22:30:00Z",
                    "location": "Secure storage",
                    "tool": "encrypted transfer",
                },
                {
                    "event_id": "CUST_003",
                    "action": "storage",
                    "actor": "ACME_EVIDENCE_MANAGER",
                    "timestamp": "2026-10-08T23:00:00Z",
                    "location": "Evidence vault",
                    "tool": None,
                },
                {
                    "event_id": "CUST_004",
                    "action": "processing",
                    "actor": "FORENSICINT_AI",
                    "timestamp": "2026-10-09T00:00:00Z",
                    "location": "Read-only analysis environment",
                    "tool": "TRACEATLAS FORENSICINT",
                },
            ],
            "authorization_context": "AUTHORIZED_INCIDENT_RESPONSE_SCOPE",
            "artifacts": [
                {
                    "artifact_id": "ART_MFT_ARCHIVE",
                    "artifact_type": "FILESYSTEM_FILE",
                    "source_path": "$MFT:1234",
                    "parser": "mft_parser",
                    "parser_version": "1.2.0",
                    "parsed_at": "2026-10-09T00:10:00Z",
                    "raw_reference": "MFT record 1234",
                    "normalized_fields": {
                        "path": "C:\\Users\\U\\Downloads\\archive.zip",
                        "name": "archive.zip",
                        "size": 52428800,
                        "allocation_state": "allocated",
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T10:15:00Z",
                            "semantics": "FILE_CREATED",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "U",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.90,
                },
                {
                    "artifact_id": "ART_PREFETCH_PROGRAM",
                    "artifact_type": "PREFETCH",
                    "source_path": "C:\\Windows\\Prefetch\\PROGRAM.EXE-1234.pf",
                    "parser": "prefetch_parser",
                    "parser_version": "2.0.1",
                    "parsed_at": "2026-10-09T00:12:00Z",
                    "raw_reference": "Prefetch file",
                    "normalized_fields": {
                        "process_name": "program.exe",
                        "process_path": "C:\\Users\\U\\Downloads\\program.exe",
                        "execution_count": 1,
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T10:16:00Z",
                            "semantics": "PROCESS_START",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "U",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.88,
                },
                {
                    "artifact_id": "ART_EVT_4688",
                    "artifact_type": "EVENT_LOG",
                    "source_path": "Security.evtx",
                    "parser": "evt_parser",
                    "parser_version": "3.1.0",
                    "parsed_at": "2026-10-09T00:13:00Z",
                    "raw_reference": "Event record 99123",
                    "normalized_fields": {
                        "event_id": 4688,
                        "event_type": "PROCESS_START",
                        "process_name": "program.exe",
                        "process_path": "C:\\Users\\U\\Downloads\\program.exe",
                        "account": "U",
                        "logon_id": "0x3E7",
                        "command_line": "C:\\Users\\U\\Downloads\\program.exe --sync password=SuperSecret123",
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T10:16:05Z",
                            "semantics": "PROCESS_START",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "U",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.92,
                },
                {
                    "artifact_id": "ART_USBSTOR",
                    "artifact_type": "USBSTOR",
                    "source_path": "SYSTEM hive USBSTOR key",
                    "parser": "registry_parser",
                    "parser_version": "1.8.0",
                    "parsed_at": "2026-10-09T00:14:00Z",
                    "raw_reference": "Registry key",
                    "normalized_fields": {
                        "device_serial": "USB123456789",
                        "vendor": "Acme",
                        "product": "FlashDrive",
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T10:20:00Z",
                            "semantics": "USB_FIRST_SEEN",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "U",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.85,
                },
                {
                    "artifact_id": "ART_EVT_LOGCLEAR",
                    "artifact_type": "EVENT_LOG",
                    "source_path": "Security.evtx",
                    "parser": "evt_parser",
                    "parser_version": "3.1.0",
                    "parsed_at": "2026-10-09T00:15:00Z",
                    "raw_reference": "Event record 99500",
                    "normalized_fields": {
                        "event_id": 1102,
                        "event_type": "LOG_CLEARING_OBSERVED",
                        "account": "SYSTEM",
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T11:00:00Z",
                            "semantics": "EVENT_LOG_TIME",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "SYSTEM",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.90,
                },
                {
                    "artifact_id": "ART_NET_CONN",
                    "artifact_type": "NETWORK_CONNECTION",
                    "source_path": "Firewall/export.json",
                    "parser": "net_parser",
                    "parser_version": "1.0.0",
                    "parsed_at": "2026-10-09T00:16:00Z",
                    "raw_reference": "Connection record",
                    "normalized_fields": {
                        "remote_ip": "203.0.113.10",
                        "remote_port": 443,
                        "protocol": "TCP",
                        "bytes_sent": 60000000,
                        "bytes_received": 1200,
                        "process_name": "program.exe",
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T10:25:00Z",
                            "semantics": "NETWORK_CONNECTION_TIME",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "U",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.82,
                },
            ],
        },
        {
            "evidence_id": "E02_MEMORY_WS01",
            "case_id": case_id,
            "source_device_id": "DEV_WS01",
            "device_type": "Workstation",
            "evidence_type": "MEMORY_IMAGE",
            "artifact_type": "RAW_MEMORY",
            "original_name": "ws01.mem",
            "size": 17179869184,
            "hashes": {
                "sha256": "b4e6c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8"
            },
            "hash_verified": True,
            "acquisition_method": "authorized_memory_capture",
            "acquisition_tool": "WinPmem",
            "acquisition_tool_version": "3.0",
            "collector": "ACME_DFIR_ANALYST_01",
            "collection_time": "2026-10-08T22:10:00Z",
            "source_timezone": "UTC",
            "chain_of_custody_state": "SUBSTANTIALLY_COMPLETE",
            "custody_events": [
                {
                    "event_id": "CUST_MEM_001",
                    "action": "acquisition",
                    "actor": "ACME_DFIR_ANALYST_01",
                    "timestamp": "2026-10-08T22:10:00Z",
                    "location": "Lab A",
                    "tool": "WinPmem 3.0",
                },
                {
                    "event_id": "CUST_MEM_002",
                    "action": "transfer",
                    "actor": "ACME_DFIR_ANALYST_01",
                    "timestamp": "2026-10-08T22:20:00Z",
                    "location": "Secure storage",
                    "tool": "encrypted transfer",
                },
                {
                    "event_id": "CUST_MEM_003",
                    "action": "processing",
                    "actor": "FORENSICINT_AI",
                    "timestamp": "2026-10-09T00:05:00Z",
                    "location": "Read-only analysis environment",
                    "tool": "TRACEATLAS FORENSICINT",
                },
            ],
            "authorization_context": "AUTHORIZED_INCIDENT_RESPONSE_SCOPE",
            "artifacts": [
                {
                    "artifact_id": "ART_MEM_PROCESS",
                    "artifact_type": "MEMORY_PROCESS",
                    "source_path": "memory image process list",
                    "parser": "volatility_like_parser",
                    "parser_version": "0.9.0",
                    "parsed_at": "2026-10-09T00:07:00Z",
                    "raw_reference": "Process list entry",
                    "normalized_fields": {
                        "pid": 4321,
                        "process_name": "program.exe",
                        "process_path": "C:\\Users\\U\\Downloads\\program.exe",
                        "parent_pid": 1234,
                        "session": 1,
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T22:10:00Z",
                            "semantics": "PROCESS_START",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "U",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.86,
                }
            ],
        },
        {
            "evidence_id": "E03_EDR_WS01",
            "case_id": case_id,
            "source_device_id": "DEV_WS01",
            "device_type": "Workstation",
            "evidence_type": "EDR_EXPORT",
            "artifact_type": "JSON",
            "original_name": "edr_export.json",
            "hashes": {
                "sha256": "c5f7d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9"
            },
            "hash_verified": True,
            "acquisition_method": "api_export",
            "acquisition_tool": "EDR API Exporter",
            "acquisition_tool_version": "2.4",
            "collector": "ACME_SOC_ANALYST_02",
            "collection_time": "2026-10-08T22:15:00Z",
            "source_timezone": "UTC",
            "chain_of_custody_state": "COMPLETE",
            "custody_events": [
                {
                    "event_id": "CUST_EDR_001",
                    "action": "acquisition",
                    "actor": "ACME_SOC_ANALYST_02",
                    "timestamp": "2026-10-08T22:15:00Z",
                    "location": "SOC",
                    "tool": "EDR API Exporter 2.4",
                },
                {
                    "event_id": "CUST_EDR_002",
                    "action": "transfer",
                    "actor": "ACME_SOC_ANALYST_02",
                    "timestamp": "2026-10-08T22:16:00Z",
                    "location": "Secure storage",
                    "tool": "encrypted transfer",
                },
                {
                    "event_id": "CUST_EDR_003",
                    "action": "storage",
                    "actor": "ACME_EVIDENCE_MANAGER",
                    "timestamp": "2026-10-08T22:17:00Z",
                    "location": "Evidence vault",
                    "tool": None,
                },
                {
                    "event_id": "CUST_EDR_004",
                    "action": "processing",
                    "actor": "FORENSICINT_AI",
                    "timestamp": "2026-10-09T00:06:00Z",
                    "location": "Read-only analysis environment",
                    "tool": "TRACEATLAS FORENSICINT",
                },
            ],
            "authorization_context": "AUTHORIZED_INCIDENT_RESPONSE_SCOPE",
            "artifacts": [
                {
                    "artifact_id": "ART_EDR_PROCESS",
                    "artifact_type": "EDR_PROCESS",
                    "source_path": "edr_export.json",
                    "parser": "edr_json_parser",
                    "parser_version": "1.0.0",
                    "parsed_at": "2026-10-09T00:08:00Z",
                    "raw_reference": "EDR process event",
                    "normalized_fields": {
                        "pid": 4321,
                        "process_name": "program.exe",
                        "process_path": "C:\\Users\\U\\Downloads\\program.exe",
                        "parent_process": "explorer.exe",
                        "account": "U",
                        "command_line": "C:\\Users\\U\\Downloads\\program.exe --sync",
                    },
                    "timestamps": [
                        {
                            "value": "2026-10-08T10:16:03Z",
                            "semantics": "PROCESS_START",
                            "precision": "SECOND",
                        }
                    ],
                    "owner_candidate": "U",
                    "device_candidate": "DEV_WS01",
                    "confidence": 0.91,
                }
            ],
        },
    ]

    known_facts = {
        "authorized_scope": "Incident response on DEV_WS01",
        "credential_use_prohibited": True,
        "real_person_attribution_requires_human_review": True,
    }

    report = analyst.process_case(
        case_id=case_id,
        task_id=task_id,
        objective=objective,
        scope=scope,
        evidence_input=evidence_input,
        known_facts=known_facts,
    )

    print("\n" + "=" * 100)
    print("TRACEATLAS / FORENSICINT DEFENSIVE REPORT")
    print("=" * 100)
    print(report.get("analyst_summary", ""))

    print("\n" + "=" * 100)
    print("FULL JSON RESULT")
    print("=" * 100)
    print(json.dumps(report, indent=2, default=json_serial))
