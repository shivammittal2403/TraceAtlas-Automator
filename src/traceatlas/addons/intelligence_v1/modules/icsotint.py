#!/usr/bin/env python3
"""
TRACEATLAS / ICSOTINT — Local defensive, passive-by-default ICS/OT intelligence pipeline.

IMPORTANT SAFETY / POLICY NOTES:
- This is a local demo implementation.
- It does NOT access live OT networks, PLCs, RTUs, IEDs, HMIs, SCADA systems, DCS, SIS,
  engineering workstations, historians, firewalls, sensors, or vendor remote-access systems.
- It does NOT perform active scanning, probing, fingerprinting, protocol command transmission,
  register/coil/tag writes, setpoint changes, valve/motor/relay control, PLC logic modification,
  firmware modification, reboots, disconnections, alarm/interlock/SIS bypass, sabotage,
  process disruption, grid disruption, wireless jamming/spoofing, credential testing,
  or malware execution.
- It separates cyber events, process events, and physical impact.
- It treats vulnerability applicability, asset identity, firmware/version, and impact as
  evidence-bound and often inconclusive.
- Consequential OT control, containment, shutdown, isolation, patching, or recovery actions
  require authorized humans, site engineers, operators, vendors, and safety governance.
- Sample data is synthetic and passive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


PIPELINE_VERSION = "0.1.0-icsotint-passive-defensive-demo"
DEFAULT_AS_OF = "2026-10-09T00:00:00Z"


# =====================================================================
# ENUMS
# =====================================================================

class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ASSET_UNRESOLVED = "ASSET_UNRESOLVED"
    VERSION_UNRESOLVED = "VERSION_UNRESOLVED"
    PROTOCOL_UNRESOLVED = "PROTOCOL_UNRESOLVED"
    PROCESS_ROLE_UNRESOLVED = "PROCESS_ROLE_UNRESOLVED"
    VULNERABILITY_UNRESOLVED = "VULNERABILITY_UNRESOLVED"
    IMPACT_UNRESOLVED = "IMPACT_UNRESOLVED"
    PASSIVE_VISIBILITY_LIMIT = "PASSIVE_VISIBILITY_LIMIT"
    SAFETY_REVIEW_REQUIRED = "SAFETY_REVIEW_REQUIRED"
    ACTIVE_VALIDATION_NOT_ALLOWED = "ACTIVE_VALIDATION_NOT_ALLOWED"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_PERMISSION = "BLOCKED_PERMISSION"
    BLOCKED_SAFETY = "BLOCKED_SAFETY"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class SourceType(str, Enum):
    ASSET_INVENTORY = "ASSET_INVENTORY"
    CMDB = "CMDB"
    ENGINEERING_EXPORT = "ENGINEERING_EXPORT"
    CONFIG_BACKUP = "CONFIG_BACKUP"
    PASSIVE_NDR = "PASSIVE_NDR"
    PCAP = "PCAP"
    NETFLOW = "NETFLOW"
    FIREWALL_LOG = "FIREWALL_LOG"
    IDS_ALERT = "IDS_ALERT"
    VENDOR_ADVISORY = "VENDOR_ADVISORY"
    CISA_ADVISORY = "CISA_ADVISORY"
    NVD = "NVD"
    KEV = "KEV"
    ATTCK_ICS = "ATTCK_ICS"
    CHANGE_TICKET = "CHANGE_TICKET"
    MAINTENANCE_LOG = "MAINTENANCE_LOG"
    OPERATOR_STATEMENT = "OPERATOR_STATEMENT"
    PUBLIC_INDEX = "PUBLIC_INDEX"
    INCIDENT_REPORT = "INCIDENT_REPORT"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class ZoneType(str, Enum):
    ENTERPRISE_IT = "ENTERPRISE_IT"
    IT_OT_BOUNDARY = "IT_OT_BOUNDARY"
    INDUSTRIAL_DMZ = "INDUSTRIAL_DMZ"
    SITE_OPERATIONS = "SITE_OPERATIONS"
    SUPERVISORY_CONTROL = "SUPERVISORY_CONTROL"
    CONTROL = "CONTROL"
    FIELD_CONTROL = "FIELD_CONTROL"
    FIELD_DEVICES = "FIELD_DEVICES"
    SAFETY_SYSTEMS = "SAFETY_SYSTEMS"
    UNKNOWN = "UNKNOWN"


class AssetRole(str, Enum):
    PLC = "PLC"
    PAC = "PAC"
    RTU = "RTU"
    IED = "IED"
    HMI = "HMI"
    SCADA_SERVER = "SCADA_SERVER"
    DCS_CONTROLLER = "DCS_CONTROLLER"
    DCS_SERVER = "DCS_SERVER"
    ENGINEERING_WORKSTATION = "ENGINEERING_WORKSTATION"
    HISTORIAN = "HISTORIAN"
    OPC_SERVER = "OPC_SERVER"
    OPC_GATEWAY = "OPC_GATEWAY"
    INDUSTRIAL_GATEWAY = "INDUSTRIAL_GATEWAY"
    PROTOCOL_CONVERTER = "PROTOCOL_CONVERTER"
    REMOTE_IO = "REMOTE_IO"
    FIELD_IO = "FIELD_IO"
    VFD = "VFD"
    MOTOR_CONTROLLER = "MOTOR_CONTROLLER"
    PROTECTIVE_RELAY = "PROTECTIVE_RELAY"
    SIS_CONTROLLER = "SIS_CONTROLLER"
    SAFETY_PLC = "SAFETY_PLC"
    INDUSTRIAL_SWITCH = "INDUSTRIAL_SWITCH"
    INDUSTRIAL_ROUTER = "INDUSTRIAL_ROUTER"
    INDUSTRIAL_FIREWALL = "INDUSTRIAL_FIREWALL"
    JUMP_HOST = "JUMP_HOST"
    REMOTE_ACCESS_GATEWAY = "REMOTE_ACCESS_GATEWAY"
    EDGE_GATEWAY = "EDGE_GATEWAY"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class IdentityState(str, Enum):
    VERIFIED = "VERIFIED"
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"
    DISPUTED = "DISPUTED"


class Protocol(str, Enum):
    MODBUS_TCP = "MODBUS_TCP"
    DNP3 = "DNP3"
    OPC_UA = "OPC_UA"
    ETHERNET_IP = "ETHERNET_IP"
    PROFINET = "PROFINET"
    S7COMM = "S7COMM"
    IEC_61850 = "IEC_61850"
    BACNET = "BACNET"
    MQTT = "MQTT"
    HTTPS = "HTTPS"
    SSH = "SSH"
    RDP = "RDP"
    UNKNOWN = "UNKNOWN"


class FunctionCategory(str, Enum):
    READ_LIKE = "READ_LIKE"
    WRITE_LIKE = "WRITE_LIKE"
    CONTROL_LIKE = "CONTROL_LIKE"
    DIAGNOSTIC = "DIAGNOSTIC"
    ENGINEERING = "ENGINEERING"
    MONITORING = "MONITORING"
    CONFIGURATION = "CONFIGURATION"
    UNKNOWN = "UNKNOWN"


class AnomalyState(str, Enum):
    NORMAL_FOR_BASELINE = "NORMAL_FOR_BASELINE"
    NEW_COMMUNICATION = "NEW_COMMUNICATION"
    NEW_PROTOCOL = "NEW_PROTOCOL"
    NEW_PEER = "NEW_PEER"
    FREQUENCY_CHANGE = "FREQUENCY_CHANGE"
    DIRECTION_CHANGE = "DIRECTION_CHANGE"
    FUNCTION_CHANGE = "FUNCTION_CHANGE"
    ZONE_VIOLATION_CANDIDATE = "ZONE_VIOLATION_CANDIDATE"
    UNKNOWN = "UNKNOWN"


class ApplicabilityState(str, Enum):
    CONFIRMED_APPLICABLE = "CONFIRMED_APPLICABLE"
    LIKELY_APPLICABLE = "LIKELY_APPLICABLE"
    POSSIBLE = "POSSIBLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNKNOWN = "UNKNOWN"


class ExposureState(str, Enum):
    POTENTIALLY_INTERNET_EXPOSED = "POTENTIALLY_INTERNET_EXPOSED"
    PARTIALLY_EXPOSED = "PARTIALLY_EXPOSED"
    SEGMENTED = "SEGMENTED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNKNOWN = "UNKNOWN"


class SafetyRelevance(str, Enum):
    DIRECT_SAFETY_FUNCTION = "DIRECT_SAFETY_FUNCTION"
    SAFETY_SUPPORTING = "SAFETY_SUPPORTING"
    PROCESS_CONTROL = "PROCESS_CONTROL"
    MONITORING_ONLY = "MONITORING_ONLY"
    NO_KNOWN_SAFETY_ROLE = "NO_KNOWN_SAFETY_ROLE"
    UNKNOWN = "UNKNOWN"


class Criticality(str, Enum):
    SAFETY_CRITICAL = "SAFETY_CRITICAL"
    MISSION_CRITICAL = "MISSION_CRITICAL"
    PRODUCTION_CRITICAL = "PRODUCTION_CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class PhysicalImpactState(str, Enum):
    NO_OBSERVED_IMPACT = "NO_OBSERVED_IMPACT"
    POTENTIAL_IMPACT = "POTENTIAL_IMPACT"
    PROCESS_DEGRADATION = "PROCESS_DEGRADATION"
    PRODUCTION_IMPACT = "PRODUCTION_IMPACT"
    SAFETY_IMPACT_REPORTED = "SAFETY_IMPACT_REPORTED"
    SAFETY_IMPACT_SUPPORTED = "SAFETY_IMPACT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


class VerificationState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CANDIDATE = "CANDIDATE"
    OBSERVED = "OBSERVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    DISPUTED = "DISPUTED"
    UNSUPPORTED = "UNSUPPORTED"


class FindingType(str, Enum):
    ASSET_IDENTITY_SUPPORTED = "ASSET_IDENTITY_SUPPORTED"
    ASSET_IDENTITY_DISPUTED = "ASSET_IDENTITY_DISPUTED"
    VERSION_DISPUTED = "VERSION_DISPUTED"
    ZONE_MAPPED = "ZONE_MAPPED"
    SAFETY_ASSET_IDENTIFIED = "SAFETY_ASSET_IDENTIFIED"
    COMMUNICATION_OBSERVED = "COMMUNICATION_OBSERVED"
    ANOMALY_CANDIDATE = "ANOMALY_CANDIDATE"
    APPROVED_CHANGE_CANDIDATE = "APPROVED_CHANGE_CANDIDATE"
    CHANGE_AUTHORIZATION_UNKNOWN = "CHANGE_AUTHORIZATION_UNKNOWN"
    VULNERABILITY_APPLICABILITY = "VULNERABILITY_APPLICABILITY"
    PROCESS_NO_OBSERVED_IMPACT = "PROCESS_NO_OBSERVED_IMPACT"
    PROCESS_POTENTIAL_IMPACT = "PROCESS_POTENTIAL_IMPACT"
    CYBER_PROCESS_SEPARATION = "CYBER_PROCESS_SEPARATION"
    INTERNET_EXPOSURE_CANDIDATE = "INTERNET_EXPOSURE_CANDIDATE"
    HONEYPOT_CANDIDATE = "HONEYPOT_CANDIDATE"
    REMOTE_ACCESS_CONFIGURED = "REMOTE_ACCESS_CONFIGURED"
    BACKUP_RECOVERY_CONTEXT = "BACKUP_RECOVERY_CONTEXT"
    SOURCE_DEPENDENCY = "SOURCE_DEPENDENCY"
    CONTRADICTION_OBSERVED = "CONTRADICTION_OBSERVED"
    NO_ACTIVE_PROBING = "NO_ACTIVE_PROBING"
    NO_CONTROL_WRITES = "NO_CONTROL_WRITES"
    NO_SAFETY_BYPASS = "NO_SAFETY_BYPASS"
    NO_SABOTAGE = "NO_SABOTAGE"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    LOCAL_ONLY_RECOMMENDED = "LOCAL_ONLY_RECOMMENDED"


class GapType(str, Enum):
    ASSET_IDENTITY_UNKNOWN = "ASSET_IDENTITY_UNKNOWN"
    FIRMWARE_UNVERIFIED = "FIRMWARE_UNVERIFIED"
    VULNERABILITY_APPLICABILITY_UNRESOLVED = "VULNERABILITY_APPLICABILITY_UNRESOLVED"
    PROCESS_IMPACT_UNKNOWN = "PROCESS_IMPACT_UNKNOWN"
    SAFETY_REVIEW_REQUIRED = "SAFETY_REVIEW_REQUIRED"
    ACTIVE_VALIDATION_NOT_ALLOWED = "ACTIVE_VALIDATION_NOT_ALLOWED"
    CONFIG_BASELINE_UNAVAILABLE = "CONFIG_BASELINE_UNAVAILABLE"
    CHANGE_AUTHORIZATION_UNKNOWN = "CHANGE_AUTHORIZATION_UNKNOWN"
    BACKUP_FRESHNESS_UNKNOWN = "BACKUP_FRESHNESS_UNKNOWN"
    INVENTORY_STALENESS = "INVENTORY_STALENESS"
    SENSOR_BLIND_SPOT = "SENSOR_BLIND_SPOT"


class SafetyFlag(str, Enum):
    NO_ACTIVE_PROBING = "NO_ACTIVE_PROBING"
    NO_CONTROL_WRITES = "NO_CONTROL_WRITES"
    NO_SETPOINT_CHANGES = "NO_SETPOINT_CHANGES"
    NO_SIS_MODIFICATION = "NO_SIS_MODIFICATION"
    NO_SABOTAGE = "NO_SABOTAGE"
    NO_PROCESS_DISRUPTION = "NO_PROCESS_DISRUPTION"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    LOCAL_ONLY_RECOMMENDED = "LOCAL_ONLY_RECOMMENDED"


class PrivacyFlag(str, Enum):
    CASE_SCOPED = "CASE_SCOPED"
    PLANT_CONFIDENTIAL = "PLANT_CONFIDENTIAL"
    NO_CREDENTIAL_USE = "NO_CREDENTIAL_USE"
    LOCAL_ONLY_DEFAULT = "LOCAL_ONLY_DEFAULT"
    PURPOSE_LIMITATION = "PURPOSE_LIMITATION"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


# =====================================================================
# CONSTANTS
# =====================================================================

SOURCE_FACTOR: Dict[SourceType, float] = {
    SourceType.ASSET_INVENTORY: 0.88,
    SourceType.CMDB: 0.88,
    SourceType.ENGINEERING_EXPORT: 0.90,
    SourceType.CONFIG_BACKUP: 0.86,
    SourceType.PASSIVE_NDR: 0.88,
    SourceType.PCAP: 0.88,
    SourceType.NETFLOW: 0.84,
    SourceType.FIREWALL_LOG: 0.86,
    SourceType.IDS_ALERT: 0.82,
    SourceType.VENDOR_ADVISORY: 0.90,
    SourceType.CISA_ADVISORY: 0.92,
    SourceType.NVD: 0.86,
    SourceType.KEV: 0.90,
    SourceType.ATTCK_ICS: 0.84,
    SourceType.CHANGE_TICKET: 0.88,
    SourceType.MAINTENANCE_LOG: 0.86,
    SourceType.OPERATOR_STATEMENT: 0.70,
    SourceType.PUBLIC_INDEX: 0.55,
    SourceType.INCIDENT_REPORT: 0.80,
    SourceType.OTHER: 0.65,
    SourceType.UNKNOWN: 0.50,
}

NEGATIVE_CONTEXT_WORDS = [
    "no ",
    "not ",
    "without ",
    "avoid ",
    "prevent ",
    "do not",
    "don't",
    "never",
    "blocked",
    "prohibited",
    "must not",
    "shall not",
]

PROHIBITED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "ACTIVE_PROBING_OR_SCANNING",
        re.compile(
            r"\b(scan|probe|fingerprint|connect\s+to|send\s+to|interrogate|enumerate)\b[^.]{0,60}"
            r"\b(plc|ot|ics|controller|device|asset|hmi|rtu|ied|modbus|dnp3|opc|scada|dcs|sis)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CONTROL_WRITE_OR_SETPOINT_CHANGE",
        re.compile(
            r"\b(write|change|modify|alter|set|toggle)\s+"
            r"(register|coil|tag|setpoint|valve|motor|relay|output|recipe|alarm\s+limit)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "LOGIC_OR_FIRMWARE_MODIFICATION",
        re.compile(
            r"\b(modify|download|upload|change|flash|replace)\s+"
            r"(plc\s+logic|ladder|function\s+block|structured\s+text|firmware|controller\s+program|project\s+file)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SAFETY_SYSTEM_BYPASS",
        re.compile(
            r"\b(bypass|disable|defeat|override)\s+"
            r"(sis|safety|interlock|alarm|trip|protective\s+relay|emergency\s+shutdown|esd)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SABOTAGE_OR_PROCESS_DISRUPTION",
        re.compile(
            r"\b(sabotage|shut\s+down\s+(the\s+)?plant|stop\s+process|disrupt\s+(power|water|telecom|process)|"
            r"overpressure|overtemperature|chemical\s+release|physical\s+destruction)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "WIRELESS_ATTACK",
        re.compile(
            r"\b(jam|deauth|spoof)\s+(wireless|wifi|wi-fi|radio|industrial)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CREDENTIAL_ABUSE",
        re.compile(
            r"\b(use|test|guess|brute[- ]force)\s+(credential|password|token|vendor\s+account)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "MALWARE_OR_EXPLOIT_EXECUTION",
        re.compile(
            r"\b(execute|run|deploy)\s+(malware|payload|exploit)\b",
            re.IGNORECASE,
        ),
    ),
]


# =====================================================================
# UTILITIES
# =====================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str, seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}{h}"


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_short(text: str) -> str:
    return stable_hash(text)[:16]


def jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: jsonable(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, (list, tuple, set)):
        return [jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): jsonable(v) for k, v in obj.items()}
    return obj


def normalize_text(value: str) -> str:
    s = unicodedata.normalize("NFKC", value or "")
    s = s.lower().strip()
    s = re.sub(r"[^\w\s\-'.:/@]", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def dt_or_min(value: Optional[str]) -> datetime:
    dt = parse_dt(value)
    return dt if dt else datetime.min.replace(tzinfo=timezone.utc)


def intervals_overlap(
    a_start: Optional[str],
    a_end: Optional[str],
    b_start: Optional[str],
    b_end: Optional[str],
) -> bool:
    if not (a_start and a_end and b_start and b_end):
        return False
    return dt_or_min(a_start) <= dt_or_min(b_end) and dt_or_min(b_start) <= dt_or_min(a_end)


def policy_guard(text: str) -> List[Dict[str, str]]:
    violations: List[Dict[str, str]] = []
    lowered = (text or "").lower()
    for rule, rx in PROHIBITED_PATTERNS:
        for m in rx.finditer(text or ""):
            start = max(0, m.start() - 60)
            ctx = lowered[start:m.end()].strip()
            if any(neg in ctx for neg in NEGATIVE_CONTEXT_WORDS):
                continue
            violations.append({"rule": rule, "matched": m.group(0)})
    return violations


# =====================================================================
# DATACLASSES
# =====================================================================

@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: [
        "authorized_passive_defensive_ics_ot_intelligence",
        "safety_first",
        "evidence_first",
        "no_active_probing",
        "no_control_writes",
        "no_safety_bypass",
        "no_sabotage",
    ])
    authorization: str = "demo_authorized_passive_ics_ot_intelligence"
    sites: List[str] = field(default_factory=list)
    facilities: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    as_of: str = DEFAULT_AS_OF
    sample: bool = False


@dataclass
class Source:
    id: str
    title: str
    url: str
    source_type: SourceType
    independence_group: str = "UNKNOWN"
    reliability: float = 0.5
    derived_from: Optional[str] = None
    published_at: Optional[str] = None
    retrieved_at: Optional[str] = None
    notes: str = ""


@dataclass
class Evidence:
    id: str
    source_id: str
    artifact_type: str
    excerpt: str
    observed_at: Optional[str] = None
    content_hash: str = ""
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Site:
    id: str
    name: str = ""
    facility_type: str = ""
    location_context: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Zone:
    id: str
    site_id: str = ""
    name: str = ""
    zone_type: ZoneType = ZoneType.UNKNOWN
    criticality: Criticality = Criticality.UNKNOWN
    security_controls: List[str] = field(default_factory=list)
    allowed_connections: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Asset:
    id: str
    site_id: str = ""
    name: str = ""
    role: AssetRole = AssetRole.UNKNOWN
    vendor: str = ""
    product: str = ""
    model: str = ""
    hardware_revision: str = ""
    firmware_version: str = ""
    passive_firmware_candidate: str = ""
    software_version: str = ""
    ips: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    zone_id: str = ""
    criticality: Criticality = Criticality.UNKNOWN
    safety_relevance: SafetyRelevance = SafetyRelevance.UNKNOWN
    process_function: str = ""
    identity_state: IdentityState = IdentityState.UNKNOWN
    version_state: IdentityState = IdentityState.UNKNOWN
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Communication:
    id: str
    source_asset_id: str
    destination_asset_id: str
    protocol: Protocol = Protocol.UNKNOWN
    function_category: FunctionCategory = FunctionCategory.UNKNOWN
    direction: str = "SOURCE_TO_DEST"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    frequency: str = ""
    zone_crossing: str = "UNKNOWN"
    baseline_state: str = "UNKNOWN"
    anomaly_state: AnomalyState = AnomalyState.UNKNOWN
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    id: str
    cve: str = ""
    advisory: str = ""
    vendor: str = ""
    product_family: str = ""
    affected_versions: List[str] = field(default_factory=list)
    description: str = ""
    mitigations: List[str] = field(default_factory=list)
    severity: str = ""
    kev: bool = False
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Applicability:
    id: str
    vulnerability_id: str
    asset_id: str
    state: ApplicabilityState = ApplicabilityState.UNKNOWN
    confidence: float = 0.0
    rationale: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Configuration:
    id: str
    asset_id: str
    version: str = ""
    content_hash: str = ""
    effective_at: Optional[str] = None
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class ChangeTicket:
    id: str
    title: str = ""
    asset_ids: List[str] = field(default_factory=list)
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    requester: str = ""
    engineer: str = ""
    vendor: str = ""
    scope: str = ""
    status: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class ProcessEvent:
    id: str
    process_area: str = ""
    event_type: str = ""
    time: Optional[str] = None
    severity: str = "UNKNOWN"
    summary: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Incident:
    id: str
    summary: str = ""
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    affected_asset_ids: List[str] = field(default_factory=list)
    cyber_event_ids: List[str] = field(default_factory=list)
    process_event_ids: List[str] = field(default_factory=list)
    physical_impact: PhysicalImpactState = PhysicalImpactState.UNKNOWN
    recovery_status: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    finding_type: FindingType
    subject_id: str
    statement: str
    verification_state: VerificationState = VerificationState.INCONCLUSIVE
    confidence: float = 0.0
    asset_id: Optional[str] = None
    zone_id: Optional[str] = None
    safety_relevance: Optional[str] = None
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    safety_flags: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    specialist_handoff: Optional[str] = None


@dataclass
class Hypothesis:
    id: str
    statement: str
    kind: str
    supporting_finding_ids: List[str] = field(default_factory=list)
    contradicting_finding_ids: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    predictions: List[str] = field(default_factory=list)
    falsification_conditions: List[str] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.UNRESOLVED
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class Contradiction:
    id: str
    contradiction_type: str
    description: str
    subject_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    status: str = "OPEN"
    recommended_resolution: str = ""


@dataclass
class KnowledgeGap:
    id: str
    gap_type: GapType
    description: str
    about_subject_ids: List[str] = field(default_factory=list)
    about_finding_ids: List[str] = field(default_factory=list)
    importance: str = "MEDIUM"
    safety_relevance: str = "UNKNOWN"
    recommended_source: str = ""
    specialist: Optional[str] = None
    expected_information_value: float = 0.0


@dataclass
class NextAction:
    id: str
    description: str
    priority: int = 1
    safety_impact: str = "PROTECTIVE"
    expected_gain: float = 0.0
    specialist: Optional[str] = None
    requires_human_approval: bool = False


@dataclass
class Recommendation:
    id: str
    category: str
    action: str
    target: str
    rationale: str
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    approval: str = "HUMAN_REVIEW_REQUIRED"
    limitations: List[str] = field(default_factory=list)


# =====================================================================
# ICSOTINT ENGINE
# =====================================================================

class IcsOtInt:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.as_of = case.as_of or DEFAULT_AS_OF

        self.sources: Dict[str, Source] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.sites: Dict[str, Site] = {}
        self.zones: Dict[str, Zone] = {}
        self.assets: Dict[str, Asset] = {}
        self.communications: Dict[str, Communication] = {}
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.applicabilities: Dict[str, Applicability] = {}
        self.configurations: Dict[str, Configuration] = {}
        self.change_tickets: Dict[str, ChangeTicket] = {}
        self.process_events: List[ProcessEvent] = []
        self.incidents: List[Incident] = []

        self.findings: Dict[str, Finding] = {}
        self.contradictions: List[Contradiction] = []
        self.hypotheses: List[Hypothesis] = []
        self.gaps: List[KnowledgeGap] = []
        self.actions: List[NextAction] = []
        self.recommendations: List[Recommendation] = []
        self.handoffs: List[Dict[str, str]] = []

        self.internet_exposure: List[Dict[str, Any]] = []
        self.backup_recovery_context: List[Dict[str, Any]] = []
        self.supply_chain_context: List[Dict[str, Any]] = []
        self.compensating_controls: List[Dict[str, Any]] = []
        self.segmentation_context: List[Dict[str, Any]] = []
        self.malware_context: List[Dict[str, Any]] = []
        self.attack_mappings: List[Dict[str, Any]] = []
        self.firmware_changes: List[Dict[str, Any]] = []

        self.physical_impact: PhysicalImpactState = PhysicalImpactState.UNKNOWN
        self.safety_flags: List[str] = []
        self.privacy_flags: List[str] = [
            PrivacyFlag.CASE_SCOPED.value,
            PrivacyFlag.PLANT_CONFIDENTIAL.value,
            PrivacyFlag.NO_CREDENTIAL_USE.value,
            PrivacyFlag.LOCAL_ONLY_DEFAULT.value,
            PrivacyFlag.PURPOSE_LIMITATION.value,
        ]
        self.validation_errors: List[str] = []
        self.dual: Dict[str, Any] = {}
        self.summary: str = ""

    # -----------------------------------------------------------------
    # Adders
    # -----------------------------------------------------------------

    def add_source(self, source: Source) -> Source:
        self.sources[source.id] = source
        return source

    def add_evidence(self, evidence: Evidence) -> Evidence:
        if not evidence.content_hash:
            evidence.content_hash = stable_hash("|".join([
                evidence.source_id,
                evidence.artifact_type,
                evidence.excerpt,
            ]))
        self.evidence[evidence.id] = evidence
        return evidence

    def add_site(self, site: Site) -> Site:
        self.sites[site.id] = site
        return site

    def add_zone(self, zone: Zone) -> Zone:
        self.zones[zone.id] = zone
        return zone

    def add_asset(self, asset: Asset) -> Asset:
        self.assets[asset.id] = asset
        return asset

    def add_communication(self, comm: Communication) -> Communication:
        self.communications[comm.id] = comm
        return comm

    def add_vulnerability(self, vuln: Vulnerability) -> Vulnerability:
        self.vulnerabilities[vuln.id] = vuln
        return vuln

    def add_applicability(self, app: Applicability) -> Applicability:
        self.applicabilities[app.id] = app
        return app

    def add_configuration(self, config: Configuration) -> Configuration:
        self.configurations[config.id] = config
        return config

    def add_change_ticket(self, ticket: ChangeTicket) -> ChangeTicket:
        self.change_tickets[ticket.id] = ticket
        return ticket

    def add_process_event(self, event: ProcessEvent) -> ProcessEvent:
        self.process_events.append(event)
        return event

    def add_incident(self, incident: Incident) -> Incident:
        self.incidents.append(incident)
        return incident

    def add_finding(self, finding: Finding) -> Finding:
        if finding.id in self.findings:
            return self.findings[finding.id]
        self.findings[finding.id] = finding
        return finding

    def add_contradiction(self, contradiction: Contradiction) -> Contradiction:
        if any(c.description == contradiction.description for c in self.contradictions):
            return self.contradictions[0]
        self.contradictions.append(contradiction)
        return contradiction

    def add_gap(self, gap: KnowledgeGap) -> KnowledgeGap:
        if any(g.description == gap.description for g in self.gaps):
            return self.gaps[0]
        self.gaps.append(gap)
        return gap

    def add_safety_flag(self, flag: str) -> None:
        if flag not in self.safety_flags:
            self.safety_flags.append(flag)

    # -----------------------------------------------------------------
    # Source lineage / independence
    # -----------------------------------------------------------------

    def get_source_family(self, source_id: str) -> Optional[str]:
        src = self.sources.get(source_id)
        if not src:
            return None
        seen: Set[str] = set()
        cur = src
        while (
            cur
            and cur.derived_from
            and cur.derived_from in self.sources
            and cur.id not in seen
        ):
            seen.add(cur.id)
            cur = self.sources[cur.derived_from]
        if cur and cur.independence_group and cur.independence_group != "UNKNOWN":
            return cur.independence_group
        return cur.id if cur else source_id

    def source_families(self, source_ids: List[str]) -> Set[str]:
        families: Set[str] = set()
        for sid in source_ids:
            fam = self.get_source_family(sid)
            families.add(fam or sid)
        return families

    def independence_state(self, source_ids: List[str]) -> str:
        if not source_ids:
            return "UNKNOWN"
        families = self.source_families(source_ids)
        if len(source_ids) == 1:
            return "SINGLE_SOURCE"
        if len(families) == 1:
            return "DEPENDENT"
        if len(families) == len(source_ids):
            return "INDEPENDENT"
        return "PARTIALLY_DEPENDENT"

    # -----------------------------------------------------------------
    # Analysis stages
    # -----------------------------------------------------------------

    def resolve_assets(self) -> None:
        inventory_like = {
            SourceType.ASSET_INVENTORY,
            SourceType.CMDB,
            SourceType.ENGINEERING_EXPORT,
            SourceType.CONFIG_BACKUP,
        }
        passive_like = {
            SourceType.PASSIVE_NDR,
            SourceType.PCAP,
            SourceType.NETFLOW,
            SourceType.FIREWALL_LOG,
            SourceType.IDS_ALERT,
        }

        for a in self.assets.values():
            stypes = {self.sources[sid].source_type for sid in a.source_ids if sid in self.sources}
            has_inventory = bool(stypes & inventory_like)
            has_passive = bool(stypes & passive_like)
            public_only = bool(stypes) and not (has_inventory or has_passive)

            if a.identity_state == IdentityState.UNKNOWN:
                if has_inventory and has_passive:
                    a.identity_state = IdentityState.SUPPORTED
                elif has_inventory:
                    a.identity_state = IdentityState.PROBABLE
                elif public_only:
                    a.identity_state = IdentityState.POSSIBLE
                    a.limitations.append(
                        "Public index entry is not evidence of live production ICS; may be stale, lab, simulator, honeypot, gateway, or NAT."
                    )
                else:
                    a.identity_state = IdentityState.UNKNOWN

            if a.passive_firmware_candidate and a.firmware_version and a.passive_firmware_candidate != a.firmware_version:
                a.version_state = IdentityState.DISPUTED
                desc = (
                    f"Firmware conflict for asset {a.id}: inventory/config reports {a.firmware_version}; "
                    f"passive candidate suggests {a.passive_firmware_candidate}."
                )
                fid = new_id("FIND-VER-", a.id)
                self.add_finding(Finding(
                    id=fid,
                    finding_type=FindingType.VERSION_DISPUTED,
                    subject_id=a.id,
                    asset_id=a.id,
                    statement=desc,
                    verification_state=VerificationState.DISPUTED,
                    source_ids=a.source_ids,
                    evidence_ids=a.evidence_ids,
                    limitations=[
                        "Do not silently choose one firmware version.",
                        "Firmware difference may reflect patch, regional build, hardware revision, stale inventory, or parsing issue.",
                        "No firmware modification is performed.",
                    ],
                ))
                self.add_contradiction(Contradiction(
                    id=new_id("CON-VER-", desc),
                    contradiction_type="FIRMWARE_CONFLICT",
                    description=desc,
                    subject_ids=[a.id],
                    finding_ids=[fid],
                    evidence_ids=a.evidence_ids,
                    source_ids=a.source_ids,
                    severity="MEDIUM",
                    status="OPEN",
                    recommended_resolution="Verify through authorized engineering records, vendor tool export, or maintenance-window approved passive inspection only.",
                ))
                self.firmware_changes.append({
                    "asset_id": a.id,
                    "observed_inventory_version": a.firmware_version,
                    "observed_passive_candidate": a.passive_firmware_candidate,
                    "state": "DISPUTED",
                    "limitations": ["Not evidence of compromise.", "No firmware change is performed."],
                })
            elif a.version_state == IdentityState.UNKNOWN:
                if a.firmware_version and has_inventory:
                    a.version_state = IdentityState.SUPPORTED
                    a.limitations.append("Firmware version is inventory/config-reported; not independently runtime-verified by passive telemetry alone.")
                elif a.firmware_version:
                    a.version_state = IdentityState.POSSIBLE
                else:
                    a.version_state = IdentityState.UNKNOWN

            if a.identity_state in {IdentityState.SUPPORTED, IdentityState.PROBABLE}:
                self.add_finding(Finding(
                    id=new_id("FIND-ID-", a.id),
                    finding_type=FindingType.ASSET_IDENTITY_SUPPORTED,
                    subject_id=a.id,
                    asset_id=a.id,
                    statement=(
                        f"Asset {a.id} identity is {a.identity_state.value} as role {a.role.value}; "
                        "IP/hostname/banner alone are not treated as exact identity."
                    ),
                    verification_state=VerificationState.SUPPORTED if a.identity_state == IdentityState.SUPPORTED else VerificationState.PARTIALLY_SUPPORTED,
                    source_ids=a.source_ids,
                    evidence_ids=a.evidence_ids,
                    limitations=[
                        "Asset identity is time-bound.",
                        "Do not force exact model/version from protocol fingerprint alone.",
                    ],
                ))
            elif a.identity_state == IdentityState.POSSIBLE:
                self.add_finding(Finding(
                    id=new_id("FIND-IDP-", a.id),
                    finding_type=FindingType.ASSET_IDENTITY_SUPPORTED,
                    subject_id=a.id,
                    asset_id=a.id,
                    statement=f"Asset {a.id} identity is only possible and requires corroboration.",
                    verification_state=VerificationState.CANDIDATE,
                    source_ids=a.source_ids,
                    evidence_ids=a.evidence_ids,
                    limitations=["Public index or weak evidence is not live production ICS."],
                ))
            else:
                self.add_finding(Finding(
                    id=new_id("FIND-IDU-", a.id),
                    finding_type=FindingType.ASSET_IDENTITY_DISPUTED,
                    subject_id=a.id,
                    asset_id=a.id,
                    statement=f"Asset {a.id} identity is unresolved.",
                    verification_state=VerificationState.INCONCLUSIVE,
                    source_ids=a.source_ids,
                    evidence_ids=a.evidence_ids,
                    limitations=["Do not invent asset role, vendor, model, firmware, or process function."],
                ))

    def map_zones(self) -> None:
        for a in self.assets.values():
            zone = self.zones.get(a.zone_id)
            if zone:
                self.add_finding(Finding(
                    id=new_id("FIND-ZONE-", a.id),
                    finding_type=FindingType.ZONE_MAPPED,
                    subject_id=a.id,
                    asset_id=a.id,
                    zone_id=zone.id,
                    statement=f"Asset {a.id} is mapped to zone {zone.id} ({zone.zone_type.value}).",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=a.source_ids + zone.source_ids,
                    evidence_ids=a.evidence_ids + zone.evidence_ids,
                    limitations=[
                        "Zone mapping is conceptual and site-specific.",
                        "Purdue model is not universal truth; modern OT may be hybrid/cloud/edge/flat.",
                    ],
                ))
                if zone.zone_type == ZoneType.SAFETY_SYSTEMS:
                    self.add_safety_flag(SafetyFlag.HUMAN_REVIEW_REQUIRED.value)

            if (
                a.safety_relevance in {SafetyRelevance.DIRECT_SAFETY_FUNCTION, SafetyRelevance.SAFETY_SUPPORTING}
                or a.role in {AssetRole.SIS_CONTROLLER, AssetRole.SAFETY_PLC, AssetRole.PROTECTIVE_RELAY}
            ):
                self.add_finding(Finding(
                    id=new_id("FIND-SAFETY-", a.id),
                    finding_type=FindingType.SAFETY_ASSET_IDENTIFIED,
                    subject_id=a.id,
                    asset_id=a.id,
                    safety_relevance=a.safety_relevance.value,
                    statement=(
                        f"Asset {a.id} has safety-relevant role/relevance: {a.role.value}/{a.safety_relevance.value}. "
                        "Only passive architecture/inventory context is analyzed; no settings, trip logic, or safety bypass is touched."
                    ),
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=a.source_ids,
                    evidence_ids=a.evidence_ids,
                    safety_flags=[SafetyFlag.NO_SIS_MODIFICATION.value, SafetyFlag.HUMAN_REVIEW_REQUIRED.value],
                    limitations=[
                        "Safety relevance is not safety impact.",
                        "Protective relay/SIS configuration is highly sensitive.",
                        "No trip defeat, protection bypass, or relay-setting change is provided.",
                    ],
                    specialist_handoff="SITE_ENGINEER / SAFETY_AUTHORITY / HUMAN_REVIEW",
                ))
                self.add_safety_flag(SafetyFlag.NO_SIS_MODIFICATION.value)
                self.add_safety_flag(SafetyFlag.HUMAN_REVIEW_REQUIRED.value)

    def analyze_communications(self) -> None:
        high_criticality = {
            Criticality.SAFETY_CRITICAL,
            Criticality.MISSION_CRITICAL,
            Criticality.PRODUCTION_CRITICAL,
            Criticality.HIGH,
        }
        sensitive_functions = {
            FunctionCategory.WRITE_LIKE,
            FunctionCategory.CONTROL_LIKE,
            FunctionCategory.ENGINEERING,
            FunctionCategory.CONFIGURATION,
        }

        for c in self.communications.values():
            self.add_finding(Finding(
                id=new_id("FIND-COMM-", c.id),
                finding_type=FindingType.COMMUNICATION_OBSERVED,
                subject_id=c.id,
                statement=(
                    f"Passive communication observed: {c.source_asset_id} -> {c.destination_asset_id} "
                    f"protocol={c.protocol.value}, function={c.function_category.value}, baseline={c.baseline_state}."
                ),
                verification_state=VerificationState.OBSERVED,
                source_ids=c.source_ids,
                evidence_ids=c.evidence_ids,
                limitations=[
                    "Observed connection is not proof of authorization.",
                    "Protocol observation alone does not prove exact device role.",
                    "No active probing or command transmission is performed.",
                ],
            ))

            if c.anomaly_state != AnomalyState.NORMAL_FOR_BASELINE:
                fid = new_id("FIND-ANOM-", c.id)
                self.add_finding(Finding(
                    id=fid,
                    finding_type=FindingType.ANOMALY_CANDIDATE,
                    subject_id=c.id,
                    statement=(
                        f"Communication anomaly candidate {c.id}: state={c.anomaly_state.value}; "
                        "possible causes include maintenance, commissioning, failover, vendor support, "
                        "network reconfiguration, stale inventory, telemetry misclassification, or cyber incident."
                    ),
                    verification_state=VerificationState.CANDIDATE,
                    source_ids=c.source_ids,
                    evidence_ids=c.evidence_ids,
                    limitations=[
                        "Anomaly is not attack.",
                        "Do not equate new communication with malicious control activity.",
                    ],
                ))

                correlated_tickets = [
                    t for t in self.change_tickets.values()
                    if intervals_overlap(c.first_seen, c.last_seen, t.window_start, t.window_end)
                    and (c.source_asset_id in t.asset_ids or c.destination_asset_id in t.asset_ids)
                ]
                if correlated_tickets:
                    self.add_finding(Finding(
                        id=new_id("FIND-CHG-", c.id),
                        finding_type=FindingType.APPROVED_CHANGE_CANDIDATE,
                        subject_id=c.id,
                        statement=(
                            f"Anomalous communication {c.id} temporally overlaps approved change ticket(s): "
                            f"{[t.id for t in correlated_tickets]}. This supports maintenance/commissioning hypothesis, not attack."
                        ),
                        verification_state=VerificationState.PARTIALLY_SUPPORTED,
                        source_ids=c.source_ids + [t.id for t in correlated_tickets for t in [t]],
                        evidence_ids=c.evidence_ids,
                        limitations=[
                            "Approved change is not automatically safe change.",
                            "Confirm with site engineer and change record.",
                        ],
                    ))
                else:
                    self.add_finding(Finding(
                        id=new_id("FIND-CHGU-", c.id),
                        finding_type=FindingType.CHANGE_AUTHORIZATION_UNKNOWN,
                        subject_id=c.id,
                        statement=(
                            f"No approved change record currently correlates with communication {c.id}. "
                            "Authorization remains unknown; this is not proof of malicious activity."
                        ),
                        verification_state=VerificationState.INCONCLUSIVE,
                        source_ids=c.source_ids,
                        evidence_ids=c.evidence_ids,
                        limitations=[
                            "Unapproved/unknown change is not malicious.",
                            "Could be documentation gap, emergency maintenance, human error, failover, or sensor blindness.",
                        ],
                    ))

                src = self.assets.get(c.source_asset_id)
                dst = self.assets.get(c.destination_asset_id)
                if c.function_category in sensitive_functions:
                    if (src and (src.criticality in high_criticality or src.safety_relevance in {
                        SafetyRelevance.DIRECT_SAFETY_FUNCTION, SafetyRelevance.SAFETY_SUPPORTING
                    })) or (dst and (dst.criticality in high_criticality or dst.safety_relevance in {
                        SafetyRelevance.DIRECT_SAFETY_FUNCTION, SafetyRelevance.SAFETY_SUPPORTING
                    })):
                        self.add_safety_flag(SafetyFlag.HUMAN_REVIEW_REQUIRED.value)
                        self.add_safety_flag(SafetyFlag.NO_CONTROL_WRITES.value)

    def _vendor_product_match(self, vuln: Vulnerability, asset: Asset) -> bool:
        v = normalize_text(vuln.vendor)
        p = normalize_text(vuln.product_family)
        av = normalize_text(asset.vendor)
        ap = normalize_text(asset.product)
        vendor_ok = (not v) or (v in av) or (av in v)
        product_ok = (not p) or (p in ap) or (ap in p)
        return vendor_ok and product_ok

    def correlate_vulnerabilities(self) -> None:
        for v in self.vulnerabilities.values():
            for a in self.assets.values():
                if not self._vendor_product_match(v, a):
                    continue
                if any(
                    app.asset_id == a.id and app.vulnerability_id == v.id
                    for app in self.applicabilities.values()
                ):
                    continue

                if a.firmware_version and a.firmware_version in v.affected_versions:
                    state = ApplicabilityState.LIKELY_APPLICABLE
                    rationale = (
                        "Inventory/config-reported firmware matches advisory-affected version; "
                        "runtime configuration and exact component applicability are not independently verified."
                    )
                elif a.version_state == IdentityState.DISPUTED:
                    state = ApplicabilityState.INCONCLUSIVE
                    rationale = "Firmware/version evidence is disputed; applicability cannot be resolved passively."
                elif not a.firmware_version:
                    state = ApplicabilityState.INCONCLUSIVE
                    rationale = "Exact firmware/version is unknown; advisory applicability unresolved."
                else:
                    state = ApplicabilityState.POSSIBLE
                    rationale = "Product-family match only; exact version/configuration/component unresolved."

                app = Applicability(
                    id=new_id("APP-", v.id + a.id),
                    vulnerability_id=v.id,
                    asset_id=a.id,
                    state=state,
                    rationale=rationale,
                    evidence_ids=a.evidence_ids + v.evidence_ids,
                    limitations=[
                        "CVE/advisory product match is not proof that this asset is vulnerable.",
                        "Vulnerable is not exploitable.",
                        "Exploitable is not exploited.",
                        "CVSS is not OT safety/business risk.",
                        "No exploit validation or active testing is performed.",
                    ],
                )
                self.add_applicability(app)

    def assess_applicabilities(self) -> None:
        for app in self.applicabilities.values():
            a = self.assets.get(app.asset_id)
            v = self.vulnerabilities.get(app.vulnerability_id)
            if not a or not v:
                continue

            self.add_finding(Finding(
                id=new_id("FIND-APP-", app.id),
                finding_type=FindingType.VULNERABILITY_APPLICABILITY,
                subject_id=app.id,
                asset_id=a.id,
                statement=(
                    f"Vulnerability applicability for {app.vulnerability_id} on asset {a.id}: {app.state.value}. "
                    f"Rationale: {app.rationale}"
                ),
                verification_state=(
                    VerificationState.PARTIALLY_SUPPORTED
                    if app.state in {ApplicabilityState.LIKELY_APPLICABLE, ApplicabilityState.CONFIRMED_APPLICABLE}
                    else VerificationState.INCONCLUSIVE
                ),
                source_ids=a.source_ids + v.source_ids,
                evidence_ids=app.evidence_ids,
                limitations=app.limitations + [
                    "Remediation requires vendor validation, maintenance window, testing, rollback plan, and human approval.",
                    "No autonomous patching or exploitability testing is performed.",
                ],
                specialist_handoff="VULNINT / SITE_ENGINEER / CHANGE_MANAGEMENT",
            ))

            if app.state in {ApplicabilityState.LIKELY_APPLICABLE, ApplicabilityState.CONFIRMED_APPLICABLE}:
                if (
                    a.safety_relevance in {SafetyRelevance.DIRECT_SAFETY_FUNCTION, SafetyRelevance.SAFETY_SUPPORTING}
                    or a.role in {AssetRole.SIS_CONTROLLER, AssetRole.SAFETY_PLC, AssetRole.PROTECTIVE_RELAY}
                    or a.criticality in {Criticality.SAFETY_CRITICAL, Criticality.MISSION_CRITICAL, Criticality.PRODUCTION_CRITICAL}
                ):
                    self.add_safety_flag(SafetyFlag.HUMAN_REVIEW_REQUIRED.value)

    def assess_process_impact(self) -> None:
        anomalies = [c for c in self.communications.values() if c.anomaly_state != AnomalyState.NORMAL_FOR_BASELINE]

        if not anomalies:
            self.physical_impact = PhysicalImpactState.NO_OBSERVED_IMPACT
            self.add_finding(Finding(
                id="FIND-PROC-NONE",
                finding_type=FindingType.PROCESS_NO_OBSERVED_IMPACT,
                subject_id="PROCESS",
                statement="No material communication anomaly is present; no process/physical impact is asserted.",
                verification_state=VerificationState.OBSERVED,
                limitations=["Absence in limited telemetry is not proof of absence.", "Sensor blind spots may exist."],
            ))
            return

        nearby_events = []
        for p in self.process_events:
            for c in anomalies:
                if intervals_overlap(p.time, p.time, c.first_seen, c.last_seen):
                    nearby_events.append((p, c))

        if nearby_events:
            self.physical_impact = PhysicalImpactState.POTENTIAL_IMPACT
            for p, c in nearby_events:
                self.add_finding(Finding(
                    id=new_id("FIND-PROCPOT-", p.id + c.id),
                    finding_type=FindingType.PROCESS_POTENTIAL_IMPACT,
                    subject_id=p.id,
                    statement=(
                        f"Process event {p.id} is temporally near communication anomaly {c.id}. "
                        "This supports correlation investigation only, not cyber causation."
                    ),
                    verification_state=VerificationState.CANDIDATE,
                    source_ids=p.source_ids + c.source_ids,
                    evidence_ids=p.evidence_ids + c.evidence_ids,
                    limitations=[
                        "Process anomaly is not cyberattack.",
                        "Possible causes include sensor failure, mechanical fault, operator action, process upset, maintenance, network failure, or cyber event.",
                        "No malicious setpoint or process manipulation is generated.",
                    ],
                    specialist_handoff="SITE_ENGINEER / INCIDENTINT / PROCESS_SAFETY",
                ))
        else:
            self.physical_impact = PhysicalImpactState.NO_OBSERVED_IMPACT
            self.add_finding(Finding(
                id="FIND-PROC-NOIMPACT",
                finding_type=FindingType.PROCESS_NO_OBSERVED_IMPACT,
                subject_id="PROCESS",
                statement=(
                    "Communication anomalies exist, but no independent process/physical impact evidence is currently correlated. "
                    "Cyber event is separated from process event and physical impact."
                ),
                verification_state=VerificationState.OBSERVED,
                source_ids=sorted({sid for c in anomalies for sid in c.source_ids}),
                evidence_ids=sorted({eid for c in anomalies for eid in c.evidence_ids}),
                limitations=[
                    "No observed impact is not no impact.",
                    "Telemetry coverage and clock synchronization may be limited.",
                ],
            ))

        self.add_finding(Finding(
            id="FIND-CYBERPROCSEP",
            finding_type=FindingType.CYBER_PROCESS_SEPARATION,
            subject_id="GOVERNANCE",
            statement=(
                "ICSOTINT maintains separate layers: CYBER_EVENT, PROCESS_EVENT, PHYSICAL_IMPACT. "
                "Command observation is not physical effect; HMI loss is not loss of process control; "
                "safety-relevant device presence is not safety impact."
            ),
            verification_state=VerificationState.SUPPORTED,
            confidence=0.99,
            limitations=["High evidentiary threshold required for safety-impact claims."],
        ))

    def assess_internet_exposure(self) -> None:
        for item in self.internet_exposure:
            self.add_finding(Finding(
                id=new_id("FIND-EXP-", item.get("id", "EXP")),
                finding_type=FindingType.INTERNET_EXPOSURE_CANDIDATE,
                subject_id=item.get("id", "EXP"),
                statement=(
                    f"Internet exposure context: {item.get('indicator', 'UNKNOWN')} state={item.get('state', 'UNKNOWN')}. "
                    "This is passive index metadata, not live production ICS confirmation."
                ),
                verification_state=VerificationState.CANDIDATE,
                source_ids=item.get("source_ids", []),
                evidence_ids=item.get("evidence_ids", []),
                limitations=[
                    "Do not actively probe, authenticate, enumerate, or send protocol requests.",
                    "Public index may be stale, NATed, gateway, honeypot, lab, simulator, or research system.",
                ],
                specialist_handoff="NETINT / INFRAINT / HUMAN_AUTHORIZED_VALIDATION",
            ))
            if item.get("honeypot_candidate"):
                self.add_finding(Finding(
                    id=new_id("FIND-HONEY-", item.get("id", "EXP")),
                    finding_type=FindingType.HONEYPOT_CANDIDATE,
                    subject_id=item.get("id", "EXP"),
                    statement="Discovered industrial-like service may be honeypot/decoy/training/lab infrastructure.",
                    verification_state=VerificationState.CANDIDATE,
                    source_ids=item.get("source_ids", []),
                    evidence_ids=item.get("evidence_ids", []),
                    limitations=["Do not classify as production solely from ICS protocol presence."],
                ))

    def assess_remote_access(self) -> None:
        for a in self.assets.values():
            if a.role in {AssetRole.JUMP_HOST, AssetRole.REMOTE_ACCESS_GATEWAY}:
                self.add_finding(Finding(
                    id=new_id("FIND-RAT-", a.id),
                    finding_type=FindingType.REMOTE_ACCESS_CONFIGURED,
                    subject_id=a.id,
                    asset_id=a.id,
                    statement=(
                        f"Remote-access-related asset {a.id} is configured/identified. "
                        "Configured access path is not evidence of active session."
                    ),
                    verification_state=VerificationState.OBSERVED,
                    source_ids=a.source_ids,
                    evidence_ids=a.evidence_ids,
                    limitations=[
                        "No login attempts, credential testing, or session interception.",
                        "Correlate VPN/jump-host/session logs through authorized sources.",
                    ],
                    specialist_handoff="NETINT / CREDINT / INCIDENTINT",
                ))

    def assess_backup_recovery(self) -> None:
        for item in self.backup_recovery_context:
            self.add_finding(Finding(
                id=new_id("FIND-BACKUP-", item.get("asset_id", "BK")),
                finding_type=FindingType.BACKUP_RECOVERY_CONTEXT,
                subject_id=item.get("asset_id", "BK"),
                asset_id=item.get("asset_id"),
                statement=(
                    f"Backup/recovery context for {item.get('asset_id', 'UNKNOWN')}: "
                    f"backup={item.get('backup_state', 'UNKNOWN')}, restore_test={item.get('restore_test_state', 'UNKNOWN')}."
                ),
                verification_state=VerificationState.OBSERVED,
                source_ids=item.get("source_ids", []),
                evidence_ids=item.get("evidence_ids", []),
                limitations=item.get("limitations", []) + [
                    "Backup reported is not verified recovery.",
                    "No autonomous restoration, reboot, or startup sequence is issued.",
                ],
                specialist_handoff="SITE_ENGINEER / INCIDENTINT / BUSINESS_CONTINUITY",
            ))

    def detect_source_dependencies(self) -> None:
        for src in self.sources.values():
            if src.derived_from and src.derived_from in self.sources:
                self.add_finding(Finding(
                    id=new_id("FIND-SRCDEP-", src.id),
                    finding_type=FindingType.SOURCE_DEPENDENCY,
                    subject_id=src.id,
                    statement=(
                        f"Source {src.id} derives from {src.derived_from}; downstream copies are not independent corroboration."
                    ),
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=[src.id, src.derived_from],
                    limitations=[
                        "Vendor advisory -> CTI provider -> vulnerability platform is one pedigree.",
                        "Do not count dependent reports as multiple independent confirmations.",
                    ],
                ))

    def add_governance_findings(self) -> None:
        governance = [
            (
                "FIND-GOV-NOACTIVE",
                FindingType.NO_ACTIVE_PROBING,
                "No active scanning, probing, fingerprinting, protocol command transmission, authentication, enumeration, or live OT interaction is performed by default.",
            ),
            (
                "FIND-GOV-NOWRITE",
                FindingType.NO_CONTROL_WRITES,
                "No register/coil/tag writes, setpoint changes, valve/motor/relay control, recipe changes, alarm changes, PLC logic modification, firmware modification, reboot, or disconnection is performed.",
            ),
            (
                "FIND-GOV-NOSAFETY",
                FindingType.NO_SAFETY_BYPASS,
                "No SIS, ESD, interlock, alarm, trip, protective-relay, or safety-system bypass/defeat/modification is performed or instructed.",
            ),
            (
                "FIND-GOV-NOSABOTAGE",
                FindingType.NO_SABOTAGE,
                "No sabotage, process disruption, power/water/telecom disruption, grid manipulation, chemical release, overpressure/overtemperature guidance, or physical destruction planning is produced.",
            ),
            (
                "FIND-GOV-HUMAN",
                FindingType.HUMAN_REVIEW_REQUIRED,
                "Consequential OT control, containment, shutdown, isolation, patching, recovery, safety-impact, or attack-attribution decisions require authorized humans, site engineers, operators, and safety governance.",
            ),
            (
                "FIND-GOV-LOCAL",
                FindingType.LOCAL_ONLY_RECOMMENDED,
                "Sensitive OT configurations, PLC projects, process tags, safety-system data, plant topology, credentials, and production telemetry should default to LOCAL_ONLY restricted handling.",
            ),
        ]
        for fid, ftype, stmt in governance:
            self.add_finding(Finding(
                id=fid,
                finding_type=ftype,
                subject_id="GOVERNANCE",
                statement=stmt,
                verification_state=VerificationState.SUPPORTED,
                confidence=0.99,
                safety_flags=[
                    SafetyFlag.NO_ACTIVE_PROBING.value,
                    SafetyFlag.NO_CONTROL_WRITES.value,
                    SafetyFlag.NO_SIS_MODIFICATION.value,
                    SafetyFlag.NO_SABOTAGE.value,
                    SafetyFlag.HUMAN_REVIEW_REQUIRED.value,
                    SafetyFlag.LOCAL_ONLY_RECOMMENDED.value,
                ],
                limitations=["Defensive passive ICS/OT intelligence boundary."],
            ))
            self.add_safety_flag(SafetyFlag.NO_ACTIVE_PROBING.value)
            self.add_safety_flag(SafetyFlag.NO_CONTROL_WRITES.value)
            self.add_safety_flag(SafetyFlag.NO_SIS_MODIFICATION.value)
            self.add_safety_flag(SafetyFlag.NO_SABOTAGE.value)
            self.add_safety_flag(SafetyFlag.HUMAN_REVIEW_REQUIRED.value)
            self.add_safety_flag(SafetyFlag.LOCAL_ONLY_RECOMMENDED.value)

    def fact_gate_findings(self) -> None:
        policy_types = {
            FindingType.NO_ACTIVE_PROBING,
            FindingType.NO_CONTROL_WRITES,
            FindingType.NO_SAFETY_BYPASS,
            FindingType.NO_SABOTAGE,
            FindingType.HUMAN_REVIEW_REQUIRED,
            FindingType.LOCAL_ONLY_RECOMMENDED,
            FindingType.CYBER_PROCESS_SEPARATION,
        }

        for f in self.findings.values():
            if f.finding_type in policy_types:
                f.verification_state = VerificationState.SUPPORTED
                f.confidence = 0.99
                continue

            srcs = [self.sources[sid] for sid in f.source_ids if sid in self.sources]
            if not srcs:
                f.confidence = 0.0
                if f.verification_state == VerificationState.OBSERVED:
                    f.verification_state = VerificationState.INCONCLUSIVE
                f.limitations.append("No mapped source for fact gate.")
                continue

            families = self.source_families(f.source_ids)
            max_rel = max((s.reliability for s in srcs), default=0.5)
            base = max_rel

            if len(families) >= 2:
                base = min(0.99, base * 1.05)
            elif len(families) == 1 and len(f.source_ids) > 1:
                base *= 0.90
                f.limitations.append("Multiple sources share one upstream source family.")

            ft = f.finding_type
            if ft == FindingType.ASSET_IDENTITY_SUPPORTED:
                f.verification_state = VerificationState.SUPPORTED if base >= 0.75 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.append("Asset identity is time-bound and source-bound.")

            elif ft == FindingType.ASSET_IDENTITY_DISPUTED:
                f.verification_state = VerificationState.INCONCLUSIVE
                base = min(base, 0.65)

            elif ft == FindingType.VERSION_DISPUTED:
                f.verification_state = VerificationState.DISPUTED
                base = min(base, 0.80)
                f.limitations.append("Do not silently resolve firmware conflict.")

            elif ft == FindingType.ZONE_MAPPED:
                f.verification_state = VerificationState.OBSERVED
                base = min(base, 0.84)

            elif ft == FindingType.SAFETY_ASSET_IDENTIFIED:
                f.verification_state = VerificationState.SUPPORTED
                base = min(base, 0.90)
                f.limitations.append("Safety relevance is not safety impact.")

            elif ft == FindingType.COMMUNICATION_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                base = min(base, 0.86)
                f.limitations.append("Observed connection is not authorized connection.")

            elif ft == FindingType.ANOMALY_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.72)
                f.limitations.append("Anomaly is not attack.")

            elif ft == FindingType.APPROVED_CHANGE_CANDIDATE:
                f.verification_state = VerificationState.PARTIALLY_SUPPORTED
                base = min(base, 0.78)
                f.limitations.append("Approved change is not automatically safe change.")

            elif ft == FindingType.CHANGE_AUTHORIZATION_UNKNOWN:
                f.verification_state = VerificationState.INCONCLUSIVE
                base = min(base, 0.65)
                f.limitations.append("Unknown authorization is not malicious activity.")

            elif ft == FindingType.VULNERABILITY_APPLICABILITY:
                f.verification_state = VerificationState.PARTIALLY_SUPPORTED if base >= 0.70 else VerificationState.INCONCLUSIVE
                base = min(base, 0.78)
                f.limitations.extend([
                    "CVE/advisory match is not asset compromise.",
                    "No exploit validation is performed.",
                ])

            elif ft in {
                FindingType.PROCESS_NO_OBSERVED_IMPACT,
                FindingType.PROCESS_POTENTIAL_IMPACT,
            }:
                f.verification_state = VerificationState.OBSERVED if ft == FindingType.PROCESS_NO_OBSERVED_IMPACT else VerificationState.CANDIDATE
                base = min(base, 0.80)
                f.limitations.append("Cyber event, process event, and physical impact remain separate.")

            elif ft == FindingType.INTERNET_EXPOSURE_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.60)
                f.limitations.append("Public index entry is not live production ICS.")

            elif ft == FindingType.HONEYPOT_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.60)

            elif ft == FindingType.REMOTE_ACCESS_CONFIGURED:
                f.verification_state = VerificationState.OBSERVED
                base = min(base, 0.80)
                f.limitations.append("Configured access is not active session.")

            elif ft == FindingType.BACKUP_RECOVERY_CONTEXT:
                f.verification_state = VerificationState.OBSERVED
                base = min(base, 0.78)
                f.limitations.append("Backup reported is not tested recovery.")

            elif ft == FindingType.SOURCE_DEPENDENCY:
                f.verification_state = VerificationState.SUPPORTED
                base = 0.90

            elif ft == FindingType.CONTRADICTION_OBSERVED:
                f.verification_state = VerificationState.DISPUTED
                base = min(base, 0.82)

            else:
                if base >= 0.75:
                    f.verification_state = VerificationState.SUPPORTED
                elif base >= 0.60:
                    f.verification_state = VerificationState.PARTIALLY_SUPPORTED
                elif base >= 0.40:
                    f.verification_state = VerificationState.INCONCLUSIVE
                else:
                    f.verification_state = VerificationState.UNSUPPORTED

            f.confidence = round(max(0.0, min(0.99, base)), 3)

    def build_hypotheses(self) -> None:
        anomalies = [c for c in self.communications.values() if c.anomaly_state != AnomalyState.NORMAL_FOR_BASELINE]
        if not anomalies:
            self.hypotheses = [
                Hypothesis(
                    id="H-STABLE-BASELINE",
                    statement="Observed communications remain within passive baseline for the available corpus.",
                    kind="BASELINE",
                    assumptions=["Telemetry coverage is sufficient and clocks are reasonably synchronized."],
                    falsification_conditions=[
                        "Additional passive sources reveal unbaselined communications.",
                        "Sensor blind spots or clock drift invalidate baseline.",
                    ],
                    status=HypothesisStatus.POSSIBLE,
                    confidence=0.55,
                    limitations=["Absence in limited telemetry is not absence of activity."],
                )
            ]
            return

        c = anomalies[0]
        correlated_tickets = [
            t for t in self.change_tickets.values()
            if intervals_overlap(c.first_seen, c.last_seen, t.window_start, t.window_end)
            and (c.source_asset_id in t.asset_ids or c.destination_asset_id in t.asset_ids)
        ]
        anomaly_finding_ids = [f.id for f in self.findings.values() if f.subject_id == c.id and f.finding_type == FindingType.ANOMALY_CANDIDATE]
        change_finding_ids = [f.id for f in self.findings.values() if f.subject_id == c.id and f.finding_type in {
            FindingType.APPROVED_CHANGE_CANDIDATE, FindingType.CHANGE_AUTHORIZATION_UNKNOWN
        }]

        self.hypotheses = [
            Hypothesis(
                id="H-APPROVED-MAINTENANCE",
                statement=f"Anomalous communication {c.id} reflects approved maintenance/commissioning activity.",
                kind="OPERATIONAL_CHANGE",
                supporting_finding_ids=change_finding_ids if correlated_tickets else [],
                assumptions=["Change ticket is accurate and session matches authorized scope."],
                predictions=["Session logs, engineer identity, and work order would align."],
                falsification_conditions=[
                    "No authorized ticket exists.",
                    "Session originates from unexpected asset/account.",
                    "Function category exceeds approved scope.",
                ],
                status=HypothesisStatus.PROBABLE if correlated_tickets else HypothesisStatus.UNRESOLVED,
                confidence=0.70 if correlated_tickets else 0.35,
                limitations=["Approved change is not automatically safe change."],
            ),
            Hypothesis(
                id="H-FAILOVER-REDUNDANCY",
                statement=f"Anomalous communication {c.id} reflects failover, redundancy, or normal operational reconfiguration.",
                kind="RESILIENCE_BEHAVIOR",
                assumptions=["Site has redundant paths/controllers not fully represented in inventory."],
                predictions=["Architecture records or vendor documentation would explain the peer/path."],
                falsification_conditions=[
                    "No redundancy design exists.",
                    "Traffic pattern is inconsistent with failover behavior.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.45,
                limitations=["Do not assume redundancy without evidence."],
            ),
            Hypothesis(
                id="H-STALE-INVENTORY",
                statement=f"Anomalous communication {c.id} arises from stale asset inventory or obsolete topology.",
                kind="SOURCE_QUALITY",
                supporting_finding_ids=[f.id for f in self.findings.values() if f.finding_type == FindingType.VERSION_DISPUTED],
                assumptions=["Inventory is older than observed network state."],
                predictions=["Current engineering export or authorized CMDB would resolve asset/zone mismatch."],
                falsification_conditions=[
                    "Inventory is verified current.",
                    "Communication is confirmed against known asset and policy.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.50,
                limitations=["Stale inventory is not compromise."],
            ),
            Hypothesis(
                id="H-UNAUTHORIZED-ENGINEERING",
                statement=f"Anomalous communication {c.id} may reflect unauthorized engineering or configuration activity.",
                kind="SECURITY_INCIDENT_CANDIDATE",
                supporting_finding_ids=anomaly_finding_ids,
                contradicting_finding_ids=change_finding_ids if correlated_tickets else [],
                assumptions=["No valid maintenance window or authorized account explains the session."],
                predictions=["Session logs, EDR, jump-host logs, and change records would show unauthorized access."],
                falsification_conditions=[
                    "Approved ticket and authorized account explain activity.",
                    "Activity is failover/redundancy.",
                    "Telemetry misclassified protocol/asset.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.35 if correlated_tickets else 0.50,
                limitations=[
                    "This is a candidate only.",
                    "No active validation, credential testing, or containment action is performed autonomously.",
                ],
            ),
            Hypothesis(
                id="H-TELEMETRY-MISCLASSIFICATION",
                statement=f"Anomalous communication {c.id} is caused by parser/sensor misclassification or clock drift.",
                kind="DATA_QUALITY",
                assumptions=["Passive sensors may have limited visibility, packet loss, or time sync issues."],
                predictions=["Independent PCAP/NDR/firewall correlation would resolve classification."],
                falsification_conditions=[
                    "Multiple independent passive sources agree.",
                    "Engineering records confirm the behavior.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.40,
                limitations=["Do not hide sensor blind spots or clock drift."],
            ),
        ]

    def build_gaps(self) -> None:
        for a in self.assets.values():
            if a.identity_state in {IdentityState.UNKNOWN, IdentityState.POSSIBLE}:
                self.add_gap(KnowledgeGap(
                    id=new_id("GAP-ID-", a.id),
                    gap_type=GapType.ASSET_IDENTITY_UNKNOWN,
                    description=f"Asset identity for {a.id} is unresolved or only possible.",
                    about_subject_ids=[a.id],
                    importance="HIGH",
                    safety_relevance=a.safety_relevance.value,
                    recommended_source="Authorized asset inventory, engineering export, CMDB, or passive NDR corroboration.",
                    specialist="ICSOTINT / TECHINT / ORGINT",
                    expected_information_value=0.85,
                ))
            if a.version_state in {IdentityState.UNKNOWN, IdentityState.DISPUTED, IdentityState.POSSIBLE}:
                self.add_gap(KnowledgeGap(
                    id=new_id("GAP-VER-", a.id),
                    gap_type=GapType.FIRMWARE_UNVERIFIED,
                    description=f"Firmware/software version for {a.id} is unverified or disputed.",
                    about_subject_ids=[a.id],
                    importance="HIGH",
                    safety_relevance=a.safety_relevance.value,
                    recommended_source="Authorized vendor tool export, configuration backup, maintenance record, or approved passive inspection.",
                    specialist="ICSOTINT / VULNINT / SITE_ENGINEER",
                    expected_information_value=0.85,
                ))

        for app in self.applicabilities.values():
            if app.state in {ApplicabilityState.INCONCLUSIVE, ApplicabilityState.POSSIBLE, ApplicabilityState.UNKNOWN}:
                self.add_gap(KnowledgeGap(
                    id=new_id("GAP-APP-", app.id),
                    gap_type=GapType.VULNERABILITY_APPLICABILITY_UNRESOLVED,
                    description=f"Vulnerability applicability {app.id} is unresolved for asset {app.asset_id}.",
                    about_subject_ids=[app.id, app.asset_id, app.vulnerability_id],
                    importance="HIGH",
                    recommended_source="Authorized version/configuration evidence, vendor advisory applicability matrix, VULNINT review.",
                    specialist="VULNINT / ICSOTINT",
                    expected_information_value=0.80,
                ))

        if self.physical_impact in {PhysicalImpactState.UNKNOWN, PhysicalImpactState.POTENTIAL_IMPACT}:
            self.add_gap(KnowledgeGap(
                id="GAP-PROC-IMPACT",
                gap_type=GapType.PROCESS_IMPACT_UNKNOWN,
                description="Process/physical impact is unknown or only potentially correlated; cyber causation is not established.",
                about_subject_ids=[c.id for c in self.communications.values() if c.anomaly_state != AnomalyState.NORMAL_FOR_BASELINE],
                importance="HIGH",
                safety_relevance="POSSIBLE",
                recommended_source="Authorized historian/alarm/operator records, process telemetry, site engineer review.",
                specialist="ICSOTINT / INCIDENTINT / SITE_ENGINEER",
                expected_information_value=0.90,
            ))

        if self.safety_flags:
            self.add_gap(KnowledgeGap(
                id="GAP-SAFETY",
                gap_type=GapType.SAFETY_REVIEW_REQUIRED,
                description="Safety-relevant assets, anomalies, or vulnerability applicability require human/site-engineer review.",
                about_subject_ids=[a.id for a in self.assets.values() if a.safety_relevance in {
                    SafetyRelevance.DIRECT_SAFETY_FUNCTION, SafetyRelevance.SAFETY_SUPPORTING
                }],
                importance="HIGH",
                safety_relevance="HIGH",
                recommended_source="Authorized safety engineering, operations, vendor guidance, and site incident commander.",
                specialist="SITE_ENGINEER / SAFETY_AUTHORITY / HUMAN_REVIEW",
                expected_information_value=0.95,
            ))

        self.add_gap(KnowledgeGap(
            id="GAP-ACTIVE",
            gap_type=GapType.ACTIVE_VALIDATION_NOT_ALLOWED,
            description="Active validation is not allowed in default passive mode; any future validation requires explicit written authorization, safety approval, maintenance window, vendor procedure, rollback plan, and human supervision.",
            importance="HIGH",
            safety_relevance="HIGH",
            recommended_source="Authorized change management and site safety governance.",
            specialist="HUMAN_REVIEW",
            expected_information_value=0.0,
        ))

    def build_next_actions(self) -> None:
        self.actions = [
            NextAction(
                id="ACT-NO-ACTIVE-PROBE",
                description="Do not actively probe, scan, connect to, authenticate to, enumerate, or send protocol commands to live OT equipment.",
                priority=99,
                safety_impact="PROTECTIVE",
                expected_gain=0.0,
                specialist=None,
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-REVIEW-INVENTORY",
                description="Review existing authorized asset inventory, CMDB, engineering exports, and configuration backups for asset identity and zone consistency.",
                priority=1,
                safety_impact="LOW",
                expected_gain=0.85,
                specialist="ICSOTINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-CONFIRM-CHANGE",
                description="Confirm anomalous engineering/maintenance sessions against approved change tickets, engineer identity, vendor support records, and session logs.",
                priority=2,
                safety_impact="LOW",
                expected_gain=0.90,
                specialist="ICSOTINT / CHANGE_MANAGEMENT / SITE_ENGINEER",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-VERIFY-FIRMWARE",
                description="Verify firmware/software through authorized vendor tool exports or configuration records; do not flash, download, upload, or modify firmware.",
                priority=3,
                safety_impact="MEDIUM_IF_AUTHORIZED",
                expected_gain=0.85,
                specialist="ICSOTINT / VULNINT / SITE_ENGINEER",
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-HANDOFF-VULN",
                description="Hand vulnerability applicability deep analysis to VULNINT with asset, version, exposure, compensating controls, and safety context.",
                priority=4,
                safety_impact="LOW",
                expected_gain=0.85,
                specialist="VULNINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-PROCESS-CORRELATION",
                description="Correlate cyber anomalies with authorized historian/alarm/operator records before asserting process or physical impact.",
                priority=5,
                safety_impact="LOW",
                expected_gain=0.90,
                specialist="ICSOTINT / INCIDENTINT / SITE_ENGINEER",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-SAFETY-HUMAN-REVIEW",
                description="Route safety-relevant findings, SIS/protective-relay context, and potential physical impact to qualified human safety/engineering review.",
                priority=6,
                safety_impact="PROTECTIVE",
                expected_gain=0.95,
                specialist="SITE_ENGINEER / SAFETY_AUTHORITY",
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-LOCAL-ONLY",
                description="Keep PLC projects, controller configs, process tags, safety-system data, plant topology, credentials, and sensitive telemetry in LOCAL_ONLY restricted handling.",
                priority=7,
                safety_impact="PROTECTIVE",
                expected_gain=0.80,
                specialist="SECURITY_OPERATIONS / LEGALINT / PRIVACY",
                requires_human_approval=False,
            ),
        ]

    def build_recommendations(self) -> None:
        self.recommendations = [
            Recommendation(
                id="REC-PASSIVE-ONLY",
                category="SAFETY",
                action="Remain passive-by-default; do not validate vulnerabilities or asset identity through active OT interaction without separate authorization.",
                target="All OT assets",
                rationale="Active interaction can have physical process consequences.",
                approval="AUTONOMOUS_ANALYTIC",
                limitations=["Inconclusive is preferable to unsafe validation."],
            ),
            Recommendation(
                id="REC-NO-BLIND-CONTAINMENT",
                category="INCIDENT_RESPONSE",
                action="Do not autonomously isolate, shutdown, reboot, disconnect, block control traffic, disable switch ports, or revoke critical service accounts.",
                target="Potential incidents",
                rationale="OT containment actions can affect safety, availability, and process state.",
                approval="HUMAN_REVIEW_REQUIRED",
                limitations=["Site incident commander and process safety govern containment."],
            ),
            Recommendation(
                id="REC-CHANGE-VERIFICATION",
                category="CHANGE_MANAGEMENT",
                action="Verify engineering sessions against approved work orders, maintenance windows, vendor support records, and session logs.",
                target="Anomalous communications",
                rationale="Many anomalies are maintenance, commissioning, failover, or documentation gaps.",
                approval="AUTONOMOUS_ANALYTIC",
                limitations=["Approved change is not automatically safe change."],
            ),
            Recommendation(
                id="REC-VULN-APPLICABILITY",
                category="VULNERABILITY",
                action="Treat CVE/advisory matches as applicability candidates until version/configuration/exposure/controls are verified through authorized records.",
                target="Vulnerability findings",
                rationale="CVE match is not asset vulnerability; vulnerable is not exploitable; exploitable is not exploited.",
                approval="AUTONOMOUS_ANALYTIC",
                limitations=["No exploit validation is performed."],
            ),
            Recommendation(
                id="REC-LOCAL-ONLY",
                category="PRIVACY",
                action="Default sensitive OT engineering data to LOCAL_ONLY and sanitize/redact before any cloud routing.",
                target="PLC projects, configs, tags, topology, credentials",
                rationale="Plant configuration and process data are highly sensitive.",
                approval="HUMAN_APPROVAL_REQUIRED",
                limitations=["Never silently upload plant configuration."],
            ),
        ]

    def build_handoffs(self) -> None:
        self.handoffs = [
            {"specialist": "NETINT", "reason": "General network telemetry, paths, and communication context without OT control actions."},
            {"specialist": "INFRAINT", "reason": "Internet-facing infrastructure context; no exploitation."},
            {"specialist": "VULNINT", "reason": "Deep vulnerability applicability, exposure, compensating controls, and remediation context."},
            {"specialist": "MALINT", "reason": "Malware family/capability analysis; no execution in OT."},
            {"specialist": "INCIDENTINT", "reason": "Incident reconstruction, containment governance, and recovery sequencing."},
            {"specialist": "LOGINT", "reason": "Log normalization, session correlation, and audit trails."},
            {"specialist": "TECHINT", "reason": "Exact hardware/product/model technical identity."},
            {"specialist": "SUPPLYCHAININT", "reason": "Vendor, integrator, OEM, cloud, remote-support dependencies."},
            {"specialist": "CORPINT", "reason": "Legal entity/vendor/integrator identity."},
            {"specialist": "CREDINT", "reason": "Credential exposure handling; never use tested credentials."},
            {"specialist": "CTI / THREATACTORINT", "reason": "Actor/campaign attribution; ATT&CK mapping is not attribution."},
            {"specialist": "DOCINT / MALINT", "reason": "Safe ingestion of vendor docs, project files, configs, logs; no macro/script execution."},
            {"specialist": "SITE_ENGINEER / SAFETY_AUTHORITY", "reason": "Process safety, control actions, containment, recovery, and consequential decisions."},
        ]

    def dual_ai_review(self) -> Dict[str, Any]:
        issues: List[str] = []

        if any(g.gap_type == GapType.ASSET_IDENTITY_UNKNOWN for g in self.gaps):
            issues.append("Asset identity remains unresolved or only possible for some assets.")

        if any(g.gap_type == GapType.FIRMWARE_UNVERIFIED for g in self.gaps):
            issues.append("Firmware/version evidence is unverified or disputed; vulnerability applicability is constrained.")

        if any(g.gap_type == GapType.VULNERABILITY_APPLICABILITY_UNRESOLVED for g in self.gaps):
            issues.append("Vulnerability applicability is unresolved; no exploitability or exploitation claim is made.")

        if any(c.anomaly_state != AnomalyState.NORMAL_FOR_BASELINE for c in self.communications.values()):
            issues.append("Communication anomalies exist but are not attacks without correlation.")

        if self.contradictions:
            issues.append(f"{len(self.contradictions)} contradiction(s) remain open.")

        if self.safety_flags:
            issues.append("Safety-relevant context requires human/site-engineer governance.")

        if any(item.get("honeypot_candidate") for item in self.internet_exposure):
            issues.append("Public internet-index exposure may be honeypot/lab/stale; do not probe.")

        if not issues:
            verdict = "AGREE"
        elif len(issues) <= 5:
            verdict = "PARTIAL_AGREEMENT"
        else:
            verdict = "INSUFFICIENT_EVIDENCE"

        return {
            "primary_ot_analyst": (
                "Synthetic passive corpus supports partial OT architecture understanding: "
                "PLC/HMI/EWS/historian/OPC/firewall/RTU/protective-relay context is identified with varying confidence. "
                "A new engineering-like session overlaps an approved maintenance ticket, so unauthorized control activity is not established. "
                "Vulnerability applicability is likely/inconclusive due firmware dispute and lacks runtime verification. "
                "No process or physical impact is currently supported. Active validation is not permitted."
            ),
            "independent_ot_safety_skeptic_issues": issues,
            "verdict": verdict,
            "adversarial_checks": [
                "Is active probing performed? No.",
                "Are control writes performed? No.",
                "Is safety system modified or bypassed? No.",
                "Is CVE match treated as asset compromise? No.",
                "Is new communication treated as attack? No.",
                "Is engineering activity treated as malicious? No.",
                "Is public index treated as live production ICS? No.",
                "Is cyber event separated from process event and physical impact? Yes.",
                "Are source dependencies and firmware conflicts preserved? Yes.",
            ],
            "note": "AI agreement is analytical agreement, not engineering verification or OT corroboration.",
        }

    def analyst_summary(self, dual: Dict[str, Any]) -> str:
        if not self.assets:
            return (
                "ICSOTINT UNRESOLVED: No configured authorized passive OT corpus. "
                "No PLC, HMI, RTU, IED, firmware, protocol, tag, vulnerability, incident, process impact, "
                "control action, sabotage plan, or physical consequence was fabricated."
            )

        first_asset = next(iter(self.assets.values()))
        anomalies = [c for c in self.communications.values() if c.anomaly_state != AnomalyState.NORMAL_FOR_BASELINE]
        apps = list(self.applicabilities.values())
        likely_apps = [a for a in apps if a.state in {ApplicabilityState.LIKELY_APPLICABLE, ApplicabilityState.CONFIRMED_APPLICABLE}]
        inconclusive_apps = [a for a in apps if a.state in {ApplicabilityState.INCONCLUSIVE, ApplicabilityState.POSSIBLE}]

        lines = [
            f"SITE / FACILITY: {first_asset.site_id or 'UNKNOWN'}",
            "OT ARCHITECTURE: Passive inventory/NDR/firewall/change/advisory corpus only; no active validation.",
            f"CRITICAL ASSETS: {', '.join(a.id for a in self.assets.values() if a.criticality in {Criticality.SAFETY_CRITICAL, Criticality.MISSION_CRITICAL, Criticality.PRODUCTION_CRITICAL, Criticality.HIGH}) or 'UNKNOWN'}",
            f"SAFETY-RELEVANT ASSETS: {', '.join(a.id for a in self.assets.values() if a.safety_relevance in {SafetyRelevance.DIRECT_SAFETY_FUNCTION, SafetyRelevance.SAFETY_SUPPORTING} or a.role in {AssetRole.SIS_CONTROLLER, AssetRole.SAFETY_PLC, AssetRole.PROTECTIVE_RELAY}) or 'NONE_IDENTIFIED'}",
            f"ASSET IDENTITY CONFIDENCE: {', '.join(f'{a.id}={a.identity_state.value}' for a in list(self.assets.values())[:5])}",
            f"COMMUNICATION ANOMALIES: {len(anomalies)} candidate anomalies; not attacks without correlation.",
            f"CHANGE CORRELATION: {'Approved maintenance ticket overlaps anomalous engineering session.' if anomalies and self.change_tickets else 'No material anomaly or no correlated ticket.'}",
            f"VULNERABILITY APPLICABILITY: likely={len(likely_apps)}, inconclusive/possible={len(inconclusive_apps)}; no exploit validation.",
            f"PROCESS / PHYSICAL IMPACT: {self.physical_impact.value}; cyber/process/physical layers kept separate.",
            f"INTERNET EXPOSURE CONTEXT: {len(self.internet_exposure)} passive index candidates; honeypot/stale/lab possible.",
            f"BACKUP / RECOVERY: {len(self.backup_recovery_context)} contexts; backup reported is not tested recovery.",
            "",
            "ASSESSMENT:",
            "- UNAUTHORIZED_CONTROL_ACTIVITY = NOT ESTABLISHED.",
            "- VULNERABILITY_APPLICABILITY = INCONCLUSIVE/LIKELY_ONLY where noted.",
            "- PHYSICAL_IMPACT = NOT SUPPORTED by current passive corpus.",
            "- ACTIVE_VALIDATION = NOT ALLOWED by default.",
            "- SAFETY_GOVERNANCE = HUMAN_REVIEW_REQUIRED.",
            "",
            f"DUAL-AI REVIEW: {dual['verdict']}.",
            "NEXT SAFE ACTION: Verify firmware/configuration through existing authorized engineering records, confirm maintenance activity with site engineer, hand vulnerability applicability to VULNINT, and do not actively query, alter, reboot, disconnect, patch, or bypass safety systems.",
        ]
        return "\n".join(lines)

    def prepare(self) -> None:
        self.resolve_assets()
        self.map_zones()
        self.analyze_communications()
        self.correlate_vulnerabilities()
        self.assess_applicabilities()
        self.assess_process_impact()
        self.assess_internet_exposure()
        self.assess_remote_access()
        self.assess_backup_recovery()
        self.detect_source_dependencies()
        self.add_governance_findings()
        self.fact_gate_findings()
        self.build_hypotheses()
        self.build_gaps()
        self.build_next_actions()
        self.build_recommendations()
        self.build_handoffs()


# =====================================================================
# SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-ICSOTINT-001",
        task_id="TASK-ICSOTINT-001",
        objective=(
            "Authorized passive defensive ICS/OT intelligence review for Synthetic Northbridge Process Facility. "
            "Resolve OT asset identity/role/zone from inventory and passive telemetry, analyze communications and change correlation, "
            "assess vulnerability applicability without exploit validation, separate cyber/process/physical impact, and recommend safe human-governed actions."
        ),
        questions=[
            "Which OT assets are identified and with what confidence?",
            "What industrial communications are observed and which are anomalous relative to baseline?",
            "Does an anomalous engineering session correlate with approved change management?",
            "Which vulnerability advisories are possibly/likely applicable, and what remains unresolved?",
            "Is there evidence of process or physical impact?",
            "What safety boundaries and human-review requirements apply?",
            "What safe next actions are appropriate without active OT interaction?",
        ],
        scope=[
            "authorized_passive_defensive_ics_ot_intelligence",
            "safety_first",
            "evidence_first",
            "no_active_probing",
            "no_control_writes",
            "no_safety_bypass",
            "no_sabotage",
            "local_only_recommended",
        ],
        authorization="demo_authorized_passive_ics_ot_intelligence",
        sites=["SITE-PLANT-1"],
        facilities=["Synthetic Northbridge Process Facility"],
        assets=["A-PLC-01", "A-HMI-01", "A-EWS-01", "A-HIST-01", "A-OPC-01", "A-FW-01", "A-RTU-01", "A-IED-01"],
        vendors=["Synthetic Automation", "Synthetic Protection"],
        products=["Family P", "Relay X"],
        time_range="2026-10-01/2026-10-09",
        as_of=DEFAULT_AS_OF,
        sample=True,
    )


def build_sample_icsotint() -> IcsOtInt:
    h = IcsOtInt(sample_case())
    retrieved = now_iso()

    # Sources
    h.add_source(Source(
        id="SRC-INVENTORY",
        title="Synthetic authorized OT asset inventory",
        url="https://cmdb.example/ot/inventory",
        source_type=SourceType.ASSET_INVENTORY,
        independence_group="INVENTORY_ROOT",
        reliability=0.88,
        published_at="2026-09-15T00:00:00Z",
        retrieved_at=retrieved,
        notes="Authorized inventory; may be stale relative to runtime changes.",
    ))
    h.add_source(Source(
        id="SRC-NDR",
        title="Synthetic passive OT NDR telemetry summary",
        url="https://ndr.example/ot/passive-summary",
        source_type=SourceType.PASSIVE_NDR,
        independence_group="NDR_ROOT",
        reliability=0.88,
        published_at="2026-10-08T23:59:00Z",
        retrieved_at=retrieved,
        notes="Passive observations only; no active probing.",
    ))
    h.add_source(Source(
        id="SRC-FW",
        title="Synthetic industrial firewall log summary",
        url="https://fw.example/ot/logs",
        source_type=SourceType.FIREWALL_LOG,
        independence_group="FW_ROOT",
        reliability=0.86,
        published_at="2026-10-08T23:59:00Z",
        retrieved_at=retrieved,
        notes="Allowed/denied context; log coverage may be incomplete.",
    ))
    h.add_source(Source(
        id="SRC-ADVISORY",
        title="Synthetic CISA/ICS-style advisory",
        url="https://advisory.example/syn-adv-2026-01",
        source_type=SourceType.CISA_ADVISORY,
        independence_group="ADVISORY_ROOT",
        reliability=0.92,
        published_at="2026-09-20T00:00:00Z",
        retrieved_at=retrieved,
        notes="Advisory context; applicability requires asset version/configuration validation.",
    ))
    h.add_source(Source(
        id="SRC-VENDOR",
        title="Synthetic vendor advisory summary",
        url="https://vendor.example/advisory/syn-2026-01",
        source_type=SourceType.VENDOR_ADVISORY,
        independence_group="ADVISORY_ROOT",
        reliability=0.90,
        derived_from="SRC-ADVISORY",
        published_at="2026-09-21T00:00:00Z",
        retrieved_at=retrieved,
        notes="Vendor summary may depend on same advisory root.",
    ))
    h.add_source(Source(
        id="SRC-CHANGE",
        title="Synthetic approved maintenance change ticket",
        url="https://change.example/ticket/CHG-2026-1008",
        source_type=SourceType.CHANGE_TICKET,
        independence_group="CHANGE_ROOT",
        reliability=0.88,
        published_at="2026-10-07T00:00:00Z",
        retrieved_at=retrieved,
        notes="Approved window and scope; approved is not automatically safe.",
    ))
    h.add_source(Source(
        id="SRC-CONFIG",
        title="Synthetic configuration backup metadata",
        url="https://config.example/backups/plc-01",
        source_type=SourceType.CONFIG_BACKUP,
        independence_group="CONFIG_ROOT",
        reliability=0.86,
        published_at="2026-09-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Backup may be old/test/pre-maintenance.",
    ))
    h.add_source(Source(
        id="SRC-OPS",
        title="Synthetic operator statement",
        url="https://ops.example/shift-note",
        source_type=SourceType.OPERATOR_STATEMENT,
        independence_group="OPS_ROOT",
        reliability=0.70,
        published_at="2026-10-08T15:30:00Z",
        retrieved_at=retrieved,
        notes="Operator perspective; not engineering verification.",
    ))
    h.add_source(Source(
        id="SRC-PUBLIC",
        title="Synthetic public internet-index observation",
        url="https://index.example/observation/203.0.113.10",
        source_type=SourceType.PUBLIC_INDEX,
        independence_group="PUBLIC_ROOT",
        reliability=0.55,
        published_at="2026-10-07T00:00:00Z",
        retrieved_at=retrieved,
        notes="Passive index metadata only; do not probe.",
    ))

    # Evidence
    h.add_evidence(Evidence(
        id="EV-NDR-EWS-PLC",
        source_id="SRC-NDR",
        artifact_type="passive_session_summary",
        excerpt="Passive NDR observed EWS A-EWS-01 initiating engineering-like session to PLC A-PLC-01 at 2026-10-08T14:05-14:28Z.",
        observed_at="2026-10-08T14:28:00Z",
        parsed_fields={"source": "A-EWS-01", "destination": "A-PLC-01", "function": "ENGINEERING"},
        limitations=["Protocol classification passive; exact device role requires corroboration.", "No active validation."],
    ))
    h.add_evidence(Evidence(
        id="EV-CHANGE-TICKET",
        source_id="SRC-CHANGE",
        artifact_type="change_record",
        excerpt="Approved maintenance ticket CHG-2026-1008 covers A-EWS-01 and A-PLC-01 from 13:00 to 15:00 for read-only diagnostic review and configuration backup verification.",
        observed_at="2026-10-07T00:00:00Z",
    ))
    h.add_evidence(Evidence(
        id="EV-ADVISORY-PLC",
        source_id="SRC-ADVISORY",
        artifact_type="advisory",
        excerpt="Advisory references engineering-interface issues in Synthetic Automation Family P firmware versions 4.1 and 4.2; mitigation requires vendor-approved patching in controlled window.",
        observed_at="2026-09-20T00:00:00Z",
        limitations=["Advisory match is not asset compromise.", "No exploit details retained."],
    ))
    h.add_evidence(Evidence(
        id="EV-CONFIG-PLC",
        source_id="SRC-CONFIG",
        artifact_type="config_metadata",
        excerpt="Configuration backup metadata for A-PLC-01 reports firmware 4.2 effective 2026-09-01.",
        observed_at="2026-09-01T00:00:00Z",
        limitations=["Backup may not equal deployed runtime state."],
    ))
    h.add_evidence(Evidence(
        id="EV-PUBLIC-INDEX",
        source_id="SRC-PUBLIC",
        artifact_type="index_banner",
        excerpt="Public index observed banner resembling industrial service on 203.0.113.10; historical and certificate metadata ambiguous.",
        observed_at="2026-10-07T00:00:00Z",
        limitations=["Do not connect, authenticate, enumerate, or send protocol requests.", "May be honeypot/lab/stale/NAT/gateway."],
    ))

    # Site / zones
    h.add_site(Site(
        id="SITE-PLANT-1",
        name="Synthetic Northbridge Process Facility",
        facility_type="process_manufacturing",
        location_context="Region-level synthetic facility; no precise private-person location.",
        source_ids=["SRC-INVENTORY"],
        evidence_ids=[],
        limitations=["Facility context is high-level and defensive."],
    ))
    h.add_zone(Zone(
        id="Z-IT",
        site_id="SITE-PLANT-1",
        name="Enterprise IT",
        zone_type=ZoneType.ENTERPRISE_IT,
        criticality=Criticality.MEDIUM,
        source_ids=["SRC-INVENTORY"],
        limitations=["Zone model is conceptual."],
    ))
    h.add_zone(Zone(
        id="Z-BOUNDARY",
        site_id="SITE-PLANT-1",
        name="IT/OT Boundary",
        zone_type=ZoneType.IT_OT_BOUNDARY,
        criticality=Criticality.HIGH,
        security_controls=["industrial_firewall", "segmentation_policy"],
        source_ids=["SRC-INVENTORY", "SRC-FW"],
        limitations=["Observed connectivity is not permission."],
    ))
    h.add_zone(Zone(
        id="Z-DMZ",
        site_id="SITE-PLANT-1",
        name="Industrial DMZ",
        zone_type=ZoneType.INDUSTRIAL_DMZ,
        criticality=Criticality.HIGH,
        source_ids=["SRC-INVENTORY"],
    ))
    h.add_zone(Zone(
        id="Z-SITEOPS",
        site_id="SITE-PLANT-1",
        name="Site Operations",
        zone_type=ZoneType.SITE_OPERATIONS,
        criticality=Criticality.HIGH,
        source_ids=["SRC-INVENTORY"],
    ))
    h.add_zone(Zone(
        id="Z-SUPV",
        site_id="SITE-PLANT-1",
        name="Supervisory Control",
        zone_type=ZoneType.SUPERVISORY_CONTROL,
        criticality=Criticality.PRODUCTION_CRITICAL,
        source_ids=["SRC-INVENTORY"],
    ))
    h.add_zone(Zone(
        id="Z-CONTROL",
        site_id="SITE-PLANT-1",
        name="Control",
        zone_type=ZoneType.CONTROL,
        criticality=Criticality.PRODUCTION_CRITICAL,
        source_ids=["SRC-INVENTORY"],
        limitations=["No control actions."],
    ))
    h.add_zone(Zone(
        id="Z-FIELD",
        site_id="SITE-PLANT-1",
        name="Field Control",
        zone_type=ZoneType.FIELD_CONTROL,
        criticality=Criticality.MEDIUM,
        source_ids=["SRC-NDR"],
    ))
    h.add_zone(Zone(
        id="Z-SAFETY",
        site_id="SITE-PLANT-1",
        name="Safety Systems",
        zone_type=ZoneType.SAFETY_SYSTEMS,
        criticality=Criticality.SAFETY_CRITICAL,
        source_ids=["SRC-INVENTORY"],
        limitations=["Highly sensitive; passive architecture context only."],
    ))

    # Assets
    h.add_asset(Asset(
        id="A-PLC-01",
        site_id="SITE-PLANT-1",
        name="PLC-01",
        role=AssetRole.PLC,
        vendor="Synthetic Automation",
        product="Family P",
        model="P-300",
        hardware_revision="rev-C",
        firmware_version="4.2",
        passive_firmware_candidate="4.1",
        software_version="",
        ips=["10.20.30.11"],
        macs=["02:aa:bb:cc:00:01"],
        zone_id="Z-CONTROL",
        criticality=Criticality.PRODUCTION_CRITICAL,
        safety_relevance=SafetyRelevance.PROCESS_CONTROL,
        process_function="pump control area",
        first_seen="2026-09-01T00:00:00Z",
        last_seen="2026-10-08T23:00:00Z",
        source_ids=["SRC-INVENTORY", "SRC-NDR", "SRC-CONFIG"],
        evidence_ids=["EV-NDR-EWS-PLC", "EV-CONFIG-PLC"],
        limitations=[
            "Firmware conflict unresolved.",
            "No PLC logic access/upload/download.",
            "No setpoint/register/coil changes.",
        ],
    ))
    h.add_asset(Asset(
        id="A-HMI-01",
        site_id="SITE-PLANT-1",
        name="HMI-01",
        role=AssetRole.HMI,
        vendor="Synthetic Visualization",
        product="HMI Suite",
        model="H-20",
        firmware_version="",
        software_version="7.4",
        ips=["10.20.20.21"],
        macs=["02:aa:bb:cc:00:02"],
        zone_id="Z-SUPV",
        criticality=Criticality.HIGH,
        safety_relevance=SafetyRelevance.MONITORING_ONLY,
        process_function="operator visualization",
        source_ids=["SRC-INVENTORY", "SRC-NDR"],
        evidence_ids=[],
        limitations=["HMI loss is not loss of process control."],
    ))
    h.add_asset(Asset(
        id="A-EWS-01",
        site_id="SITE-PLANT-1",
        name="EWS-01",
        role=AssetRole.ENGINEERING_WORKSTATION,
        vendor="Synthetic Computing",
        product="Engineering Station",
        model="EW-5",
        firmware_version="",
        software_version="Automation Studio 2025",
        ips=["10.20.10.31"],
        macs=["02:aa:bb:cc:00:03"],
        zone_id="Z-SITEOPS",
        criticality=Criticality.HIGH,
        safety_relevance=SafetyRelevance.NO_KNOWN_SAFETY_ROLE,
        process_function="engineering/configuration workstation",
        source_ids=["SRC-INVENTORY", "SRC-NDR", "SRC-CHANGE"],
        evidence_ids=["EV-NDR-EWS-PLC", "EV-CHANGE-TICKET"],
        limitations=["Engineering activity is not automatically malicious.", "No autonomous logic modification."],
    ))
    h.add_asset(Asset(
        id="A-HIST-01",
        site_id="SITE-PLANT-1",
        name="HIST-01",
        role=AssetRole.HISTORIAN,
        vendor="Synthetic Data Systems",
        product="Historian",
        model="HD-100",
        firmware_version="",
        software_version="5.1",
        ips=["10.30.10.41"],
        macs=["02:aa:bb:cc:00:04"],
        zone_id="Z-DMZ",
        criticality=Criticality.MEDIUM,
        safety_relevance=SafetyRelevance.MONITORING_ONLY,
        process_function="process data historian",
        source_ids=["SRC-INVENTORY"],
        evidence_ids=[],
        limitations=["Historian traffic is not process control by default."],
    ))
    h.add_asset(Asset(
        id="A-OPC-01",
        site_id="SITE-PLANT-1",
        name="OPC-01",
        role=AssetRole.OPC_GATEWAY,
        vendor="Synthetic Interop",
        product="OPC Gateway",
        model="OG-2",
        firmware_version="2.8",
        software_version="",
        ips=["10.30.10.42"],
        macs=["02:aa:bb:cc:00:05"],
        zone_id="Z-DMZ",
        criticality=Criticality.HIGH,
        safety_relevance=SafetyRelevance.PROCESS_CONTROL,
        process_function="data aggregation / protocol gateway",
        source_ids=["SRC-INVENTORY", "SRC-NDR"],
        evidence_ids=[],
        limitations=["Centrality is not attack priority.", "No gateway configuration changes."],
    ))
    h.add_asset(Asset(
        id="A-FW-01",
        site_id="SITE-PLANT-1",
        name="OT-FW-01",
        role=AssetRole.INDUSTRIAL_FIREWALL,
        vendor="Synthetic Secure Networks",
        product="Industrial Firewall",
        model="IF-9",
        firmware_version="6.2",
        software_version="",
        ips=["10.10.10.1"],
        macs=["02:aa:bb:cc:00:06"],
        zone_id="Z-BOUNDARY",
        criticality=Criticality.HIGH,
        safety_relevance=SafetyRelevance.SAFETY_SUPPORTING,
        process_function="IT/OT segmentation enforcement",
        source_ids=["SRC-INVENTORY", "SRC-FW"],
        evidence_ids=[],
        limitations=["No firewall rule changes.", "Presence of control is not proven effectiveness."],
    ))
    h.add_asset(Asset(
        id="A-RTU-01",
        site_id="SITE-PLANT-1",
        name="RTU-01",
        role=AssetRole.RTU,
        vendor="Synthetic Field Systems",
        product="RTU Family",
        model="R-44",
        firmware_version="",
        software_version="",
        ips=["10.40.10.51"],
        macs=["02:aa:bb:cc:00:07"],
        zone_id="Z-FIELD",
        criticality=Criticality.MEDIUM,
        safety_relevance=SafetyRelevance.PROCESS_CONTROL,
        process_function="remote telemetry",
        source_ids=["SRC-NDR"],
        evidence_ids=[],
        limitations=["Remote location does not mean Internet exposure.", "Identity only passive-probable."],
    ))
    h.add_asset(Asset(
        id="A-IED-01",
        site_id="SITE-PLANT-1",
        name="PROT-RLY-01",
        role=AssetRole.PROTECTIVE_RELAY,
        vendor="Synthetic Protection",
        product="Relay X",
        model="RX-100",
        firmware_version="",
        passive_firmware_candidate="",
        software_version="",
        ips=["10.50.10.61"],
        macs=["02:aa:bb:cc:00:08"],
        zone_id="Z-SAFETY",
        criticality=Criticality.SAFETY_CRITICAL,
        safety_relevance=SafetyRelevance.DIRECT_SAFETY_FUNCTION,
        process_function="electrical protection context",
        source_ids=["SRC-INVENTORY", "SRC-NDR"],
        evidence_ids=[],
        limitations=[
            "Highly sensitive safety asset.",
            "No relay settings, trip logic, protection bypass, or actuation.",
            "Passive inventory/context only.",
        ],
    ))

    # Communications
    h.add_communication(Communication(
        id="C-HMI-PLC-NORMAL",
        source_asset_id="A-HMI-01",
        destination_asset_id="A-PLC-01",
        protocol=Protocol.MODBUS_TCP,
        function_category=FunctionCategory.READ_LIKE,
        direction="HMI_TO_PLC",
        first_seen="2026-10-08T00:00:00Z",
        last_seen="2026-10-08T23:00:00Z",
        frequency="continuous_polling",
        zone_crossing="Z-SUPV_TO_Z-CONTROL",
        baseline_state="NORMAL",
        anomaly_state=AnomalyState.NORMAL_FOR_BASELINE,
        source_ids=["SRC-NDR", "SRC-FW"],
        evidence_ids=[],
        limitations=["Read-like monitoring context only.", "No command generation."],
    ))
    h.add_communication(Communication(
        id="C-EWS-PLC-ENG",
        source_asset_id="A-EWS-01",
        destination_asset_id="A-PLC-01",
        protocol=Protocol.S7COMM,
        function_category=FunctionCategory.ENGINEERING,
        direction="EWS_TO_PLC",
        first_seen="2026-10-08T14:05:00Z",
        last_seen="2026-10-08T14:28:00Z",
        frequency="session",
        zone_crossing="Z-SITEOPS_TO_Z-CONTROL",
        baseline_state="NOT_PREVIOUSLY_OBSERVED_IN_WINDOW",
        anomaly_state=AnomalyState.NEW_COMMUNICATION,
        source_ids=["SRC-NDR", "SRC-FW", "SRC-CHANGE"],
        evidence_ids=["EV-NDR-EWS-PLC", "EV-CHANGE-TICKET"],
        limitations=[
            "Engineering-like session observed passively.",
            "Overlaps approved maintenance ticket.",
            "No active validation or control write.",
        ],
    ))
    h.add_communication(Communication(
        id="C-OPC-HIST",
        source_asset_id="A-OPC-01",
        destination_asset_id="A-HIST-01",
        protocol=Protocol.OPC_UA,
        function_category=FunctionCategory.MONITORING,
        direction="OPC_TO_HISTORIAN",
        first_seen="2026-10-08T00:00:00Z",
        last_seen="2026-10-08T23:00:00Z",
        frequency="periodic",
        zone_crossing="Z-DMZ_INTERNAL",
        baseline_state="NORMAL",
        anomaly_state=AnomalyState.NORMAL_FOR_BASELINE,
        source_ids=["SRC-NDR"],
        evidence_ids=[],
        limitations=["Historian monitoring is not process control."],
    ))

    # Vulnerabilities
    h.add_vulnerability(Vulnerability(
        id="VULN-SYN-PLC-ENG",
        cve="CVE-SYN-2026-0001",
        advisory="SYN-ADV-2026-01",
        vendor="Synthetic Automation",
        product_family="Family P",
        affected_versions=["4.1", "4.2"],
        description="Synthetic advisory indicates engineering-interface weakness in certain Family P firmware releases.",
        mitigations=[
            "Verify exact firmware/version through authorized records.",
            "Restrict engineering access through approved jump-host/change process.",
            "Apply vendor-approved update only in controlled maintenance window with rollback plan.",
            "Monitor passive telemetry for unexpected engineering sessions.",
        ],
        severity="HIGH",
        kev=False,
        source_ids=["SRC-ADVISORY", "SRC-VENDOR"],
        evidence_ids=["EV-ADVISORY-PLC"],
        limitations=[
            "No exploit details retained.",
            "Advisory match is not asset compromise.",
            "Remediation requires human/vendor/change governance.",
        ],
    ))
    h.add_vulnerability(Vulnerability(
        id="VULN-SYN-RELAY",
        cve="CVE-SYN-2026-0002",
        advisory="SYN-ADV-2026-02",
        vendor="Synthetic Protection",
        product_family="Relay X",
        affected_versions=["all reported versions pending vendor matrix"],
        description="Synthetic advisory references protection-device configuration management weakness.",
        mitigations=[
            "Verify device firmware/configuration through authorized safety engineering records.",
            "Do not modify trip logic, relay settings, or protection functions analytically.",
            "Route to safety authority and vendor.",
        ],
        severity="CRITICAL_SAFETY_CONTEXT",
        kev=False,
        source_ids=["SRC-ADVISORY"],
        evidence_ids=[],
        limitations=[
            "Safety-critical context.",
            "No bypass, defeat, or setting change.",
            "Applicability unresolved due unknown firmware.",
        ],
    ))

    # Change ticket
    h.add_change_ticket(ChangeTicket(
        id="CHG-2026-1008",
        title="Read-only diagnostic review and configuration backup verification",
        asset_ids=["A-EWS-01", "A-PLC-01"],
        window_start="2026-10-08T13:00:00Z",
        window_end="2026-10-08T15:00:00Z",
        requester="Operations",
        engineer="E. Maintainer",
        vendor="Synthetic Automation Services",
        scope="Passive/diagnostic review; no process control changes authorized in summary.",
        status="APPROVED",
        source_ids=["SRC-CHANGE"],
        evidence_ids=["EV-CHANGE-TICKET"],
        limitations=["Approved change is not automatically safe change.", "Scope must be verified against logs and records."],
    ))

    # Configuration
    h.add_configuration(Configuration(
        id="CFG-PLC-2026-09",
        asset_id="A-PLC-01",
        version="2026-09-01",
        content_hash="sha256:placeholder-config-hash",
        effective_at="2026-09-01T00:00:00Z",
        source_ids=["SRC-CONFIG"],
        evidence_ids=["EV-CONFIG-PLC"],
        limitations=["Configuration backup may differ from deployed runtime state."],
    ))

    # Internet exposure context
    h.internet_exposure.append({
        "id": "EXP-PUBLIC-203-0-113-10",
        "observed_at": "2026-10-07T00:00:00Z",
        "indicator": "Public index banner resembling industrial service on 203.0.113.10",
        "state": ExposureState.POTENTIALLY_INTERNET_EXPOSED.value,
        "honeypot_candidate": True,
        "source_ids": ["SRC-PUBLIC"],
        "evidence_ids": ["EV-PUBLIC-INDEX"],
        "limitations": [
            "Do not probe, authenticate, enumerate, or send protocol requests.",
            "May be stale, NAT, gateway, honeypot, lab, simulator, or research system.",
        ],
    })

    # Backup/recovery context
    h.backup_recovery_context.append({
        "asset_id": "A-PLC-01",
        "backup_state": "BACKUP_REPORTED",
        "restore_test_state": "UNKNOWN",
        "source_ids": ["SRC-CONFIG", "SRC-INVENTORY"],
        "evidence_ids": ["EV-CONFIG-PLC"],
        "limitations": [
            "Backup reported is not verified recovery.",
            "No autonomous restoration or startup sequence.",
        ],
    })

    # Supply chain context
    h.supply_chain_context.extend([
        {
            "type": "oem_vendor",
            "name": "Synthetic Automation",
            "relationship": "PLC vendor",
            "limitations": ["Vendor relationship is not compromise."],
        },
        {
            "type": "system_integrator",
            "name": "Northbridge Automation Integrators",
            "relationship": "engineering/integration context",
            "limitations": ["Integrator access must be governed by change management."],
        },
        {
            "type": "vendor_remote_access",
            "name": "SynthSupport",
            "relationship": "configured remote-support pathway",
            "state": "CONFIGURED_NOT_ACTIVE_SESSION_EVIDENCED",
            "limitations": ["Configured access is not active use.", "No credential testing."],
        },
    ])

    # Compensating controls
    h.compensating_controls.extend([
        {
            "control_id": "CTRL-FW-BOUNDARY",
            "type": "segmentation",
            "description": "Industrial firewall at IT/OT boundary",
            "asset_id": "A-FW-01",
            "effectiveness_state": "DOCUMENTED_NOT_VERIFIED",
            "limitations": ["Presence is not proven effectiveness."],
        },
        {
            "control_id": "CTRL-NDR-PASSIVE",
            "type": "monitoring",
            "description": "Passive OT NDR telemetry",
            "effectiveness_state": "OBSERVED_COVERAGE_LIMITED",
            "limitations": ["Sensor blind spots and packet loss may exist."],
        },
        {
            "control_id": "CTRL-CHANGE-MGMT",
            "type": "change_management",
            "description": "Approved maintenance ticket process",
            "effectiveness_state": "DOCUMENTED",
            "limitations": ["Approved change is not automatically safe change."],
        },
    ])

    # Segmentation context
    h.segmentation_context.append({
        "id": "SEG-ITOT",
        "description": "Intended IT/OT boundary via industrial firewall; observed EWS->PLC engineering session within site operations/control context.",
        "states": ["INTENDED_SEGMENTATION", "OBSERVED_CROSS_ZONE_SESSION", "APPROVED_WINDOW_OVERLAP"],
        "limitations": [
            "Observed connection is not permission.",
            "No firewall rule changes are performed.",
        ],
    })

    # ATT&CK mapping placeholder
    h.attack_mappings.append({
        "id": "ATT-CAND-ENG-SESSION",
        "behavior": "Engineering workstation initiated engineering-like session to PLC during maintenance window.",
        "attack_version": "MITRE ATT&CK for ICS version not independently verified in local demo",
        "technique": "UNMAPPED_PENDING_AUTHORIZED_TAXONOMY",
        "subtechnique": "",
        "evidence_ids": ["EV-NDR-EWS-PLC", "EV-CHANGE-TICKET"],
        "confidence": 0.35,
        "limitations": [
            "Technique overlap is not attribution.",
            "Mapping requires verified behavior taxonomy and human review.",
        ],
    })

    h.prepare()
    return h


# =====================================================================
# RESULT BUILDERS
# =====================================================================

def graph_version_hash(h: IcsOtInt) -> str:
    seed_obj = {
        "assets": sorted(
            (a.id, a.role.value, a.identity_state.value, a.version_state.value, a.zone_id, a.criticality.value, a.safety_relevance.value)
            for a in h.assets.values()
        ),
        "communications": sorted(
            (c.id, c.source_asset_id, c.destination_asset_id, c.protocol.value, c.function_category.value, c.anomaly_state.value)
            for c in h.communications.values()
        ),
        "applicabilities": sorted((a.id, a.vulnerability_id, a.asset_id, a.state.value) for a in h.applicabilities.values()),
        "findings": sorted(
            (f.id, f.finding_type.value, f.subject_id, f.verification_state.value, round(float(f.confidence), 3))
            for f in h.findings.values()
        ),
        "physical_impact": h.physical_impact.value,
    }
    return sha256_short(json.dumps(jsonable(seed_obj), sort_keys=True))


def build_source_graph(h: IcsOtInt) -> Dict[str, Any]:
    edges = []
    for src in h.sources.values():
        if src.derived_from:
            edges.append({"source": src.derived_from, "target": src.id, "relationship_type": "DERIVED_FROM"})
    return {"nodes": [s.id for s in h.sources.values()], "edges": edges}


def build_source_dependency_graph(h: IcsOtInt) -> Dict[str, List[str]]:
    families: Dict[str, List[str]] = defaultdict(list)
    for sid in h.sources:
        fam = h.get_source_family(sid) or "UNKNOWN"
        families[fam].append(sid)
    return {k: sorted(v) for k, v in families.items()}


def build_ot_graph(h: IcsOtInt) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for site in h.sites.values():
        nodes.append({"id": site.id, "type": "Site", "name": site.name, "facility_type": site.facility_type})

    for zone in h.zones.values():
        nodes.append({
            "id": zone.id,
            "type": "Zone",
            "name": zone.name,
            "zone_type": zone.zone_type.value,
            "criticality": zone.criticality.value,
        })
        edges.append({"source": zone.id, "target": zone.site_id, "relationship_type": "PART_OF_SITE"})

    for asset in h.assets.values():
        nodes.append({
            "id": asset.id,
            "type": "OTAsset",
            "role": asset.role.value,
            "vendor": asset.vendor,
            "product": asset.product,
            "identity_state": asset.identity_state.value,
            "version_state": asset.version_state.value,
            "criticality": asset.criticality.value,
            "safety_relevance": asset.safety_relevance.value,
        })
        if asset.zone_id:
            edges.append({"source": asset.id, "target": asset.zone_id, "relationship_type": "PART_OF_ZONE"})
        if asset.vendor:
            edges.append({"source": asset.id, "target": f"VENDOR-{asset.vendor}", "relationship_type": "SUPPORTED_BY_VENDOR"})
            nodes.append({"id": f"VENDOR-{asset.vendor}", "type": "Vendor", "name": asset.vendor})

    for c in h.communications.values():
        edges.append({
            "source": c.source_asset_id,
            "target": c.destination_asset_id,
            "relationship_type": "COMMUNICATES_WITH",
            "protocol": c.protocol.value,
            "function_category": c.function_category.value,
            "anomaly_state": c.anomaly_state.value,
            "confidence": c.confidence,
            "evidence_ids": c.evidence_ids,
        })

    for app in h.applicabilities.values():
        nodes.append({"id": app.vulnerability_id, "type": "Vulnerability", "state": app.state.value})
        edges.append({
            "source": app.asset_id,
            "target": app.vulnerability_id,
            "relationship_type": "AFFECTED_BY_CANDIDATE",
            "applicability_state": app.state.value,
            "limitations": app.limitations,
        })

    for ticket in h.change_tickets.values():
        nodes.append({"id": ticket.id, "type": "ChangeTicket", "status": ticket.status, "scope": ticket.scope})
        for aid in ticket.asset_ids:
            edges.append({"source": ticket.id, "target": aid, "relationship_type": "COVERS_ASSET"})

    for event in h.process_events:
        nodes.append({"id": event.id, "type": "ProcessEvent", "event_type": event.event_type, "severity": event.severity})

    return {
        "nodes": nodes,
        "edges": edges,
        "guardrails": [
            "CONTROLS_CANDIDATE is not asserted from traffic alone.",
            "Communication edges are passive observations, not authorized paths.",
            "Vulnerability edges are applicability candidates, not exploitation claims.",
            "No tactical attack path, bypass sequence, or control-command edge is represented.",
        ],
    }


def build_timeline(h: IcsOtInt) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for c in h.communications.values():
        if c.first_seen:
            events.append({
                "time": c.first_seen,
                "type": "COMMUNICATION_FIRST_SEEN",
                "subject_id": c.id,
                "description": f"{c.source_asset_id} -> {c.destination_asset_id} {c.protocol.value} {c.function_category.value} anomaly={c.anomaly_state.value}.",
                "source_ids": c.source_ids,
                "evidence_ids": c.evidence_ids,
            })

    for t in h.change_tickets.values():
        if t.window_start:
            events.append({
                "time": t.window_start,
                "type": "CHANGE_WINDOW_START",
                "subject_id": t.id,
                "description": f"Change ticket {t.id}: {t.scope}; status={t.status}.",
                "source_ids": t.source_ids,
                "evidence_ids": t.evidence_ids,
            })

    for p in h.process_events:
        if p.time:
            events.append({
                "time": p.time,
                "type": "PROCESS_EVENT",
                "subject_id": p.id,
                "description": f"{p.event_type} in {p.process_area}: {p.summary}",
                "source_ids": p.source_ids,
                "evidence_ids": p.evidence_ids,
            })

    for inc in h.incidents:
        if inc.started_at:
            events.append({
                "time": inc.started_at,
                "type": "INCIDENT",
                "subject_id": inc.id,
                "description": inc.summary,
                "source_ids": inc.source_ids,
                "evidence_ids": inc.evidence_ids,
            })

    for item in h.internet_exposure:
        if item.get("observed_at"):
            events.append({
                "time": item["observed_at"],
                "type": "INTERNET_EXPOSURE_OBSERVATION",
                "subject_id": item.get("id", "EXP"),
                "description": item.get("indicator", ""),
                "source_ids": item.get("source_ids", []),
                "evidence_ids": item.get("evidence_ids", []),
            })

    return sorted(events, key=lambda e: dt_or_min(e.get("time")))


def build_facts_by_state(h: IcsOtInt) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = defaultdict(list)
    for f in h.findings.values():
        out[f.verification_state.value].append(f)
    return {k: v for k, v in out.items()}


def assets_by_role(h: IcsOtInt, roles: Set[AssetRole]) -> List[Asset]:
    return [a for a in h.assets.values() if a.role in roles]


def build_result(h: IcsOtInt, status: Status) -> Dict[str, Any]:
    dual = h.dual if h.dual else h.dual_ai_review()
    summary = h.summary if h.summary else h.analyst_summary(dual)
    source_families = build_source_dependency_graph(h)
    facts_by_state = build_facts_by_state(h)

    finding_independence = {
        fid: h.independence_state(f.source_ids)
        for fid, f in h.findings.items()
    }

    supported_facts = facts_by_state.get(VerificationState.SUPPORTED.value, [])
    partial_facts = facts_by_state.get(VerificationState.PARTIALLY_SUPPORTED.value, [])
    candidate_facts = facts_by_state.get(VerificationState.CANDIDATE.value, [])
    disputed_facts = facts_by_state.get(VerificationState.DISPUTED.value, [])
    observed_facts = facts_by_state.get(VerificationState.OBSERVED.value, [])

    anomalies = [c for c in h.communications.values() if c.anomaly_state != AnomalyState.NORMAL_FOR_BASELINE]
    likely_apps = [a for a in h.applicabilities.values() if a.state in {ApplicabilityState.LIKELY_APPLICABLE, ApplicabilityState.CONFIRMED_APPLICABLE}]
    inconclusive_apps = [a for a in h.applicabilities.values() if a.state in {ApplicabilityState.INCONCLUSIVE, ApplicabilityState.POSSIBLE, ApplicabilityState.UNKNOWN}]

    conduit_map: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for c in h.communications.values():
        s = h.assets.get(c.source_asset_id)
        d = h.assets.get(c.destination_asset_id)
        if s and d and s.zone_id and d.zone_id and s.zone_id != d.zone_id:
            conduit_map[(s.zone_id, d.zone_id)].append(c.protocol.value)

    conduits = [
        {
            "source_zone": k[0],
            "destination_zone": k[1],
            "protocols": sorted(set(v)),
            "note": "Observed zone-crossing communication paths; not authorized policy unless corroborated by firewall/configuration records.",
        }
        for k, v in conduit_map.items()
    ]

    control_relationships = [
        {
            "communication_id": c.id,
            "source_asset_id": c.source_asset_id,
            "destination_asset_id": c.destination_asset_id,
            "relationship_state": "CANDIDATE",
            "function_category": c.function_category.value,
            "limitations": [
                "Traffic alone does not prove control relationship.",
                "CONTROLS_CANDIDATE becomes CONTROLS only with engineering/process evidence.",
            ],
        }
        for c in h.communications.values()
        if c.function_category in {FunctionCategory.CONTROL_LIKE, FunctionCategory.WRITE_LIKE, FunctionCategory.ENGINEERING}
    ]

    limitations = [
        "Local synthetic demo; no live OT access.",
        "Passive-by-default defensive ICS/OT intelligence only.",
        "No active scanning, probing, fingerprinting, protocol command transmission, authentication, or enumeration.",
        "No register/coil/tag writes, setpoint changes, valve/motor/relay control, PLC logic modification, firmware modification, reboot, or disconnection.",
        "No SIS, ESD, interlock, alarm, trip, protective-relay, or safety-system bypass/defeat/modification.",
        "No sabotage, process disruption, grid disruption, chemical release, overpressure/overtemperature guidance, or physical destruction planning.",
        "Asset identity, firmware/version, vulnerability applicability, and impact are evidence-bound and often inconclusive.",
        "Cyber event, process event, and physical impact are kept separate.",
        "Consequential OT control, containment, shutdown, isolation, patching, or recovery actions require authorized humans and site engineers.",
    ] + h.validation_errors

    replay_manifest = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "graph_version": graph_version_hash(h),
        "core_principle": (
            "SAFETY -> AUTHORIZATION -> PASSIVE EVIDENCE -> ASSET RESOLUTION -> ARCHITECTURE -> "
            "COMMUNICATION RELATIONSHIPS -> VERSION / CONFIGURATION CONTEXT -> VULNERABILITY APPLICABILITY -> "
            "PROCESS CONTEXT -> INCIDENT CORRELATION -> FACT GATE -> DEFENSIVE RESPONSE"
        ),
        "as_of": h.as_of,
        "passive_rule": "No active probing/scanning/command transmission by default.",
        "identity_rule": "IP, hostname, banner, port, and protocol alone do not prove exact asset identity or role.",
        "version_rule": "Firmware/software version evidence method is tracked; banner/inventory is not runtime verification.",
        "communication_rule": "Observed connection is not authorized connection; baseline is not policy.",
        "anomaly_rule": "Anomaly is not attack; alternatives include maintenance, failover, stale inventory, misclassification, or cyber event.",
        "vulnerability_rule": "CVE match is not asset vulnerable; vulnerable is not exploitable; exploitable is not exploited.",
        "process_rule": "Cyber event, process event, and physical impact are separate layers.",
        "safety_rule": "Safety-relevant assets and potential impacts require human/site-engineer governance.",
        "privacy_rule": "Plant configuration, PLC projects, tags, topology, credentials, and sensitive telemetry default to LOCAL_ONLY.",
        "policy_exclusions": [
            "No control-system exploitation.",
            "No process manipulation.",
            "No physical disruption.",
            "No safety bypass.",
            "No credential use/testing.",
            "No malware execution.",
            "No autonomous containment/shutdown/reboot/patching.",
        ],
        "source_lineage": source_families,
        "finding_independence": finding_independence,
    }

    return {
        "case_id": h.case.case_id,
        "task_id": h.case.task_id,
        "objective": h.case.objective,
        "questions": h.case.questions,
        "scope": h.case.scope,
        "authorization": h.case.authorization,
        "status": status.value,
        "as_of": h.as_of,

        "source_ids": sorted(h.sources.keys()),
        "evidence_ids": sorted(h.evidence.keys()),

        "sites": list(h.sites.values()),
        "facilities": [
            {
                "site_id": s.id,
                "name": s.name,
                "facility_type": s.facility_type,
                "location_context": s.location_context,
                "limitations": s.limitations,
            }
            for s in h.sites.values()
        ],
        "zones": list(h.zones.values()),
        "conduits": conduits,

        "assets": list(h.assets.values()),
        "asset_roles": {a.id: a.role.value for a in h.assets.values()},
        "vendors": sorted({a.vendor for a in h.assets.values() if a.vendor}),
        "products": sorted({a.product for a in h.assets.values() if a.product}),
        "models": sorted({a.model for a in h.assets.values() if a.model}),
        "hardware_revisions": sorted({a.hardware_revision for a in h.assets.values() if a.hardware_revision}),
        "firmware_versions": sorted({a.firmware_version for a in h.assets.values() if a.firmware_version}),
        "software_versions": sorted({a.software_version for a in h.assets.values() if a.software_version}),
        "ip_addresses": sorted({ip for a in h.assets.values() for ip in a.ips}),

        "network_relationships": list(h.communications.values()),
        "industrial_protocols": sorted({c.protocol.value for c in h.communications.values()}),
        "communication_relationships": list(h.communications.values()),
        "communication_baselines": [
            {
                "communication_id": c.id,
                "baseline_state": c.baseline_state,
                "anomaly_state": c.anomaly_state.value,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "frequency": c.frequency,
                "zone_crossing": c.zone_crossing,
                "limitations": c.limitations,
            }
            for c in h.communications.values()
        ],
        "network_anomalies": anomalies,

        "engineering_workstations": assets_by_role(h, {AssetRole.ENGINEERING_WORKSTATION}),
        "plcs": assets_by_role(h, {AssetRole.PLC, AssetRole.PAC}),
        "rtus": assets_by_role(h, {AssetRole.RTU}),
        "ieds": assets_by_role(h, {AssetRole.IED, AssetRole.PROTECTIVE_RELAY}),
        "hmis": assets_by_role(h, {AssetRole.HMI}),
        "scada_servers": assets_by_role(h, {AssetRole.SCADA_SERVER}),
        "dcs_context": assets_by_role(h, {AssetRole.DCS_CONTROLLER, AssetRole.DCS_SERVER}),
        "historians": assets_by_role(h, {AssetRole.HISTORIAN}),
        "opc_context": assets_by_role(h, {AssetRole.OPC_SERVER, AssetRole.OPC_GATEWAY}),
        "gateways": assets_by_role(h, {
            AssetRole.INDUSTRIAL_GATEWAY,
            AssetRole.PROTOCOL_CONVERTER,
            AssetRole.EDGE_GATEWAY,
            AssetRole.OPC_GATEWAY,
        }),
        "sis_context": assets_by_role(h, {AssetRole.SIS_CONTROLLER, AssetRole.SAFETY_PLC}),
        "field_devices": assets_by_role(h, {
            AssetRole.FIELD_IO,
            AssetRole.REMOTE_IO,
            AssetRole.VFD,
            AssetRole.MOTOR_CONTROLLER,
            AssetRole.RTU,
        }),
        "protective_relays": assets_by_role(h, {AssetRole.PROTECTIVE_RELAY}),

        "remote_access": assets_by_role(h, {AssetRole.JUMP_HOST, AssetRole.REMOTE_ACCESS_GATEWAY}),
                "vendor_access": [x for x in h.supply_chain_context if x.get("type") == "vendor_remote_access"],
        "internet_exposure_context": h.internet_exposure,
        "honeypot_candidates": [x for x in h.internet_exposure if x.get("honeypot_candidate")],

        "process_functions": sorted({a.process_function for a in h.assets.values() if a.process_function}),
        "process_anomalies": h.process_events,
        "control_relationships": control_relationships,

        "safety_relevance": {a.id: a.safety_relevance.value for a in h.assets.values()},
        "criticality": {a.id: a.criticality.value for a in h.assets.values()},

        "configurations": list(h.configurations.values()),
        "configuration_changes": [
            {
                "asset_id": fc.get("asset_id"),
                "change_type": "FIRMWARE_VERSION_DISPUTED",
                "old_state": fc.get("observed_inventory_version"),
                "new_state": fc.get("observed_passive_candidate"),
                "state": fc.get("state"),
                "limitations": fc.get("limitations", []),
            }
            for fc in h.firmware_changes
        ],
        "firmware_changes": h.firmware_changes,
        "change_management_context": list(h.change_tickets.values()),

        "vulnerabilities": list(h.vulnerabilities.values()),
        "advisories": [
            {
                "id": v.advisory,
                "vulnerability_id": v.id,
                "cve": v.cve,
                "vendor": v.vendor,
                "product_family": v.product_family,
                "affected_versions": v.affected_versions,
                "description": v.description,
                "mitigations": v.mitigations,
                "severity": v.severity,
                "kev": v.kev,
                "source_ids": v.source_ids,
                "evidence_ids": v.evidence_ids,
                "limitations": v.limitations,
            }
            for v in h.vulnerabilities.values()
            if v.advisory
        ],
        "applicability_states": {a.id: a.state.value for a in h.applicabilities.values()},
        "exposure_states": {
            "internet_exposure_candidates": [x.get("state") for x in h.internet_exposure],
            "note": "No active validation; public-index candidates only.",
        },
        "compensating_controls": h.compensating_controls,
        "segmentation_context": h.segmentation_context,
        "malware_context": h.malware_context or [
            {
                "state": "NOT_CONFIGURED_IN_SAMPLE",
                "limitations": [
                    "No malware sample executed.",
                    "MALINT handles malware family details.",
                    "ICSOTINT only evaluates OT relevance defensively.",
                ],
            }
        ],
        "incident_context": h.incidents,
        "ATTACK_ICS_mapping": h.attack_mappings,
        "physical_impact_states": {
            "overall": h.physical_impact.value,
            "cyber_anomaly_ids": [c.id for c in anomalies],
            "process_event_ids": [p.id for p in h.process_events],
            "note": "Cyber event, process event, and physical impact are kept separate.",
        },
        "backup_recovery_context": h.backup_recovery_context,
        "supply_chain_context": h.supply_chain_context,

        "timeline_updates": build_timeline(h),
        "observations": list(h.evidence.values()),

        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "observed_facts": observed_facts,

        "source_reliability": {sid: src.reliability for sid, src in h.sources.items()},
        "source_bias": {sid: src.notes for sid, src in h.sources.items()},
        "source_limitations": {
            sid: [src.notes]
            for sid, src in h.sources.items()
            if src.notes
        },
        "source_pedigree": {
            sid: h.get_source_family(sid)
            for sid in h.sources
        },
        "source_independence": {
            "source_families": source_families,
            "finding_independence": finding_independence,
            "communication_independence": {
                c.id: h.independence_state(c.source_ids)
                for c in h.communications.values()
            },
            "applicability_independence": {
                a.id: h.independence_state(
                    (
                        h.assets[a.asset_id].source_ids
                        if a.asset_id in h.assets
                        else []
                    )
                    + (
                        h.vulnerabilities[a.vulnerability_id].source_ids
                        if a.vulnerability_id in h.vulnerabilities
                        else []
                    )
                )
                for a in h.applicabilities.values()
            },
        },

        "contradictions": h.contradictions,
        "hypotheses": h.hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": hy.id,
                "statement": hy.statement,
                "kind": hy.kind,
                "status": hy.status.value,
                "confidence": hy.confidence,
                "supporting_finding_ids": hy.supporting_finding_ids,
                "contradicting_finding_ids": hy.contradicting_finding_ids,
                "assumptions": hy.assumptions,
                "predictions": hy.predictions,
                "falsification_conditions": hy.falsification_conditions,
                "limitations": hy.limitations,
            }
            for hy in h.hypotheses
        ],

        "safety_flags": h.safety_flags,
        "privacy_flags": h.privacy_flags,

        "unknowns": sorted(set(
            [g.description for g in h.gaps]
            + [
                hy.statement
                for hy in h.hypotheses
                if hy.status in {
                    HypothesisStatus.UNRESOLVED,
                    HypothesisStatus.DISPUTED,
                }
            ]
        )),
        "knowledge_gaps": h.gaps,
        "recommended_next_actions": h.actions,
        "specialist_handoffs": h.handoffs,
        "limitations": limitations,

        "analyst_summary": summary,
        "dual_ai_review": dual,

        "ot_graph": build_ot_graph(h),
        "source_graph": build_source_graph(h),
        "source_dependency_graph": source_families,
        "replay_manifest": replay_manifest,
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline() -> Dict[str, Any]:
    h = build_sample_icsotint()
    return build_result(h, Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    h = IcsOtInt(case)

    h.add_gap(KnowledgeGap(
        id="GAP-NO-OT-EVIDENCE",
        gap_type=GapType.CONFIG_BASELINE_UNAVAILABLE,
        description=(
            "No configured authorized passive OT corpus is available. "
            "No OT asset, PLC, RTU, IED, HMI, SCADA, DCS, engineering workstation, historian, "
            "OPC gateway, firmware version, industrial protocol, communication baseline, anomaly, "
            "vulnerability applicability, process impact, incident, backup state, or safety conclusion can be resolved."
        ),
        importance="HIGH",
        safety_relevance="HIGH",
        recommended_source=(
            "Provide authorized asset inventory, CMDB, engineering exports, configuration backups, "
            "passive NDR/PCAP/NetFlow summaries, firewall logs, change tickets, vendor advisories, "
            "CISA/ICS advisory metadata, operator statements, and incident records."
        ),
        specialist="ICSOTINT / VULNINT / INCIDENTINT / SITE_ENGINEER",
        expected_information_value=0.95,
    ))

    h.actions = [
        NextAction(
            id="ACT-CONFIGURE-PASSIVE-OT-EVIDENCE",
            description=(
                "Configure lawful authorized passive OT evidence or sanitized local corpus. "
                "Do not actively probe, scan, connect to, authenticate to, enumerate, send protocol commands, "
                "write registers/coils/tags, change setpoints, modify PLC logic/firmware, bypass safety systems, "
                "sabotage processes, or execute malware in OT."
            ),
            priority=1,
            safety_impact="PROTECTIVE",
            expected_gain=0.95,
            specialist=None,
            requires_human_approval=False,
        ),
        NextAction(
            id="ACT-NO-ACTIVE-PROBE",
            description="Remain passive-by-default. Inconclusive is preferable to unsafe validation.",
            priority=99,
            safety_impact="PROTECTIVE",
            expected_gain=0.0,
            specialist=None,
            requires_human_approval=False,
        ),
    ]

    h.recommendations = [
        Recommendation(
            id="REC-PASSIVE-ONLY",
            category="SAFETY",
            action="Do not perform active OT validation without separate written authorization, safety approval, maintenance window, vendor procedure, rollback plan, and human supervision.",
            target="All OT assets",
            rationale="Active interaction with live control systems can have physical process consequences.",
            approval="AUTONOMOUS_ANALYTIC",
            limitations=["ICSOTINT analyzes and recommends only; site engineers/operators govern control actions."],
        ),
        Recommendation(
            id="REC-LOCAL-ONLY",
            category="PRIVACY",
            action="Default PLC projects, controller configs, process tags, safety-system data, plant topology, credentials, and sensitive telemetry to LOCAL_ONLY restricted handling.",
            target="Sensitive OT engineering data",
            rationale="Plant configuration and process data are highly sensitive and confidentiality-bearing.",
            approval="HUMAN_APPROVAL_REQUIRED",
            limitations=["Never silently upload plant configuration to external cloud models."],
        ),
    ]

    h.handoffs = [
        {"specialist": "VULNINT", "reason": "Deep vulnerability applicability once authorized asset/version evidence exists."},
        {"specialist": "INCIDENTINT", "reason": "Incident reconstruction if authorized passive evidence indicates an event."},
        {"specialist": "NETINT", "reason": "General network telemetry and path context without OT control actions."},
        {"specialist": "MALINT", "reason": "Malware family/capability analysis; no execution in OT."},
        {"specialist": "SITE_ENGINEER / SAFETY_AUTHORITY", "reason": "Process safety, control actions, containment, recovery, and consequential decisions."},
    ]

    h.hypotheses = []
    h.contradictions = []
    h.safety_flags = [
        SafetyFlag.NO_ACTIVE_PROBING.value,
        SafetyFlag.NO_CONTROL_WRITES.value,
        SafetyFlag.NO_SETPOINT_CHANGES.value,
        SafetyFlag.NO_SIS_MODIFICATION.value,
        SafetyFlag.NO_SABOTAGE.value,
        SafetyFlag.NO_PROCESS_DISRUPTION.value,
        SafetyFlag.HUMAN_REVIEW_REQUIRED.value,
        SafetyFlag.LOCAL_ONLY_RECOMMENDED.value,
    ]

    h.dual = {
        "primary_ot_analyst": "No authorized passive OT evidence available.",
        "independent_ot_safety_skeptic_issues": [
            "No OT asset inventory or passive telemetry configured.",
            "No asset identity, role, zone, firmware, protocol, or communication baseline can be resolved.",
            "No vulnerability applicability can be assessed.",
            "No process or physical impact can be inferred.",
            "No active probing or control-system validation is permitted.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "AI agreement is not engineering verification or OT corroboration.",
    }

    h.summary = (
        "ICSOTINT UNRESOLVED: No configured authorized passive OT corpus. "
        "No PLC, RTU, IED, HMI, SCADA, DCS, engineering workstation, historian, OPC gateway, firmware, "
        "protocol, tag, communication, vulnerability, incident, process impact, safety impact, control action, "
        "sabotage plan, or physical consequence was fabricated. "
        "Provide lawful passive evidence or run sample mode."
    )

    return build_result(h, Status.BLOCKED_CONFIGURATION)


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "questions": case.questions,
        "scope": case.scope,
        "authorization": case.authorization,
        "status": Status.BLOCKED_POLICY.value,
        "as_of": case.as_of,

        "policy_violations": violations,
        "message": (
            "Prohibited ICS/OT intelligence request detected. ICSOTINT supports lawful, authorized, defensive, "
            "safety-first, passive-by-default, evidence-first OT/ICS intelligence only. It does not actively probe, "
            "scan, connect to, authenticate to, enumerate, or send protocol commands to live OT equipment; "
            "does not write registers/coils/tags, change setpoints, control valves/motors/relays, modify PLC logic, "
            "modify firmware, reboot/disconnect controllers, bypass SIS/ESD/interlocks/alarms/protective relays, "
            "sabotage processes, disrupt power/water/telecom/grid, provide unsafe chemical/process parameters, "
            "jam/spoof industrial wireless, test/use credentials, or execute malware in OT."
        ),

        "lawful_alternatives": [
            "Analyze authorized passive asset inventories, CMDB exports, engineering metadata, and configuration backups.",
            "Parse existing PCAP/NetFlow/IPFIX/NDR/firewall/IDS logs without active interaction.",
            "Resolve asset identity/role/zone with evidence-bound confidence states.",
            "Baseline observed communications and separate observed-normal from approved policy.",
            "Correlate anomalies with change tickets, maintenance logs, vendor support records, and session logs.",
            "Assess vulnerability applicability using vendor/CISA advisories and authorized version evidence only.",
            "Separate cyber event, process event, and physical impact.",
            "Route safety-relevant findings, containment, shutdown, isolation, patching, and recovery to humans/site engineers.",
            "Hand malware family analysis to MALINT, vulnerability depth to VULNINT, incident reconstruction to INCIDENTINT.",
            "Keep sensitive OT engineering data LOCAL_ONLY and sanitize before any cloud routing.",
        ],

        "safety_flags": [
            SafetyFlag.NO_ACTIVE_PROBING.value,
            SafetyFlag.NO_CONTROL_WRITES.value,
            SafetyFlag.NO_SETPOINT_CHANGES.value,
            SafetyFlag.NO_SIS_MODIFICATION.value,
            SafetyFlag.NO_SABOTAGE.value,
            SafetyFlag.NO_PROCESS_DISRUPTION.value,
            SafetyFlag.HUMAN_REVIEW_REQUIRED.value,
            SafetyFlag.LOCAL_ONLY_RECOMMENDED.value,
        ],

        "privacy_flags": [
            PrivacyFlag.CASE_SCOPED.value,
            PrivacyFlag.PLANT_CONFIDENTIAL.value,
            PrivacyFlag.NO_CREDENTIAL_USE.value,
            PrivacyFlag.LOCAL_ONLY_DEFAULT.value,
            PrivacyFlag.PURPOSE_LIMITATION.value,
        ],

        "unknowns": [
            "No ICS/OT analysis was performed because the request violated lawful defensive safety boundaries.",
            "No OT asset, firmware, protocol, communication, vulnerability, incident, process impact, or safety impact was fabricated.",
        ],

        "knowledge_gaps": [
            {
                "id": "GAP-POLICY-BLOCK",
                "gap_type": GapType.ACTIVE_VALIDATION_NOT_ALLOWED.value,
                "description": "Request blocked due to prohibited active OT interaction, control-system manipulation, safety bypass, sabotage, or process-disruption intent.",
                "about_subject_ids": [],
                "about_finding_ids": [],
                "importance": "HIGH",
                "safety_relevance": "HIGH",
                "recommended_source": "Lawful authorized passive OT evidence and human safety governance only.",
                "specialist": "ICSOTINT / HUMAN_REVIEW",
                "expected_information_value": 0.0,
            }
        ],

        "recommended_next_actions": [
            {
                "id": "ACT-LAWFUL-OT-SCOPE",
                "description": "Restate the objective as lawful passive defensive OT/ICS intelligence: asset context, architecture, vulnerability applicability, incident correlation, resilience, and safety-reviewed recommendations.",
                "priority": 1,
                "safety_impact": "PROTECTIVE",
                "expected_gain": 0.90,
                "specialist": "ICSOTINT",
                "requires_human_approval": False,
            },
            {
                "id": "ACT-NO-ACTIVE-PROBE",
                "description": "Do not probe, scan, connect, authenticate, enumerate, write, modify, reboot, disconnect, bypass, sabotage, or execute malware in OT.",
                "priority": 99,
                "safety_impact": "PROTECTIVE",
                "expected_gain": 0.0,
                "specialist": None,
                "requires_human_approval": False,
            },
        ],

        "specialist_handoffs": [
            {"specialist": "SITE_ENGINEER / SAFETY_AUTHORITY", "reason": "Any consequential OT control, containment, shutdown, isolation, patching, or recovery decision."},
            {"specialist": "VULNINT", "reason": "Authorized vulnerability applicability analysis without exploit validation."},
            {"specialist": "INCIDENTINT", "reason": "Authorized passive incident reconstruction and response governance."},
            {"specialist": "LEGALINT / COMPLIANCE", "reason": "Authorization, contractual, regulatory, and safety-governance review where needed."},
        ],

        "limitations": [
            "No ICS/OT analysis performed.",
            "No OT asset, PLC, RTU, IED, HMI, firmware, protocol, tag, communication, vulnerability, incident, process impact, or safety impact fabricated.",
            "No active scanning, probing, protocol command transmission, control write, logic/firmware modification, safety bypass, sabotage, process disruption, credential use, or malware execution performed.",
            "No tactical attack path, disruption sequence, or exploitation guidance produced.",
        ],

        "analyst_summary": (
            "ICSOTINT POLICY BLOCKED: Request involved prohibited active OT interaction, control-system manipulation, "
            "safety bypass, sabotage, process disruption, credential abuse, or malware execution intent. "
            "Safe lawful defensive passive OT intelligence remains available: asset identity, architecture, "
            "communication baselining, change correlation, vulnerability applicability, incident evidence review, "
            "process/physical impact separation, resilience, and human-governed safety recommendations."
        ),

        "dual_ai_review": {
            "primary_ot_analyst": "Request blocked by safety/policy guard.",
            "independent_ot_safety_skeptic_issues": [
                "No lawful passive OT analysis can proceed under prohibited active/manipulative intent.",
                "No control-system command, register/coil/tag write, setpoint change, logic/firmware modification, or safety bypass may be produced.",
                "No process disruption, sabotage, grid disruption, chemical release, or physical destruction guidance may be produced.",
                "No credential testing/use or malware execution may be performed.",
            ],
            "verdict": "BLOCKED_POLICY",
            "note": "AI agreement is irrelevant when the request violates safety-first defensive boundaries.",
        },

        "replay_manifest": {
            "generated_at": now_iso(),
            "pipeline_version": PIPELINE_VERSION,
            "core_principle": (
                "SAFETY-FIRST PASSIVE ICS/OT INTELLIGENCE ONLY: resolve asset identity passively, map zones/conduits, "
                "baseline communications, correlate changes, assess vulnerability applicability without exploit validation, "
                "separate cyber/process/physical impact, withhold control actions, and route consequential decisions to humans."
            ),
            "as_of": case.as_of,
            "policy_exclusions": [
                "No active probing/scanning/connecting/authenticating/enumerating live OT.",
                "No register/coil/tag/setpoint/valve/motor/relay writes.",
                "No PLC logic/firmware modification.",
                "No reboot/disconnect/containment automation.",
                "No SIS/ESD/interlock/alarm/protective-relay bypass.",
                "No sabotage/process/grid/chemical/physical disruption guidance.",
                "No credential testing/use.",
                "No malware execution in OT.",
            ],
        },
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.questions,
            *case.sites,
            *case.facilities,
            *case.assets,
            *case.vendors,
            *case.products,
            case.time_range or "",
            case.authorization or "",
            " ".join(case.scope),
        ]
    )

    violations = policy_guard(text)
    if violations:
        return blocked_policy_result(case, violations)

    if case.sample:
        return run_sample_pipeline()

    return run_unconfigured_pipeline(case)


# =====================================================================
# CLI
# =====================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "TRACEATLAS ICSOTINT local defensive passive-by-default ICS/OT intelligence pipeline. "
            "Sample mode uses synthetic authorized passive inventory/NDR/firewall/change/advisory metadata."
        )
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic ICSOTINT sample.")
    parser.add_argument("--objective", help="Authorized passive defensive ICS/OT objective.")
    parser.add_argument("--question", action="append", default=[], help="Analytic question. Repeatable.")
    parser.add_argument("--site", action="append", default=[], help="Site ID/name. Repeatable.")
    parser.add_argument("--facility", action="append", default=[], help="Facility name. Repeatable.")
    parser.add_argument("--asset", action="append", default=[], help="Asset ID/name. Repeatable.")
    parser.add_argument("--vendor", action="append", default=[], help="Vendor name. Repeatable.")
    parser.add_argument("--product", action="append", default=[], help="Product/family name. Repeatable.")
    parser.add_argument("--time-range", help="Time range hint.")
    parser.add_argument("--as-of", default=DEFAULT_AS_OF, help="Analysis as-of timestamp.")

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            questions=args.question,
            sites=args.site,
            facilities=args.facility,
            assets=args.asset,
            vendors=args.vendor,
            products=args.product,
            time_range=args.time_range,
            as_of=args.as_of,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()