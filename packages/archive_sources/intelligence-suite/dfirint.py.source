#!/usr/bin/env python3
"""
TRACEATLAS / DFIRINT — Local defensive digital forensics & incident response intelligence pipeline.

IMPORTANT SAFETY / POLICY NOTES:
- This is a local demo implementation.
- It does NOT access live systems, disks, memory, PCAPs, EDR, SIEM, cloud tenants, or private accounts.
- It does NOT exploit systems, deploy malware/ransomware, install persistence, steal/use credentials,
  bypass MFA, replay tokens/cookies, disable security tools, delete logs, tamper with evidence,
  or teach anti-forensics.
- It supports authorized, defensive, evidence-first DFIR reasoning only.
- Sample data is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


PIPELINE_VERSION = "0.1.0-dfirint-defensive-safe-demo"


# =====================================================================
# ENUMS
# =====================================================================

class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INCIDENT_CANDIDATE = "INCIDENT_CANDIDATE"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    CHAIN_OF_CUSTODY_ISSUE = "CHAIN_OF_CUSTODY_ISSUE"
    SENSOR_GAP = "SENSOR_GAP"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class SourceType(str, Enum):
    EDR = "EDR"
    SIEM = "SIEM"
    WINDOWS_EVENT_LOG = "WINDOWS_EVENT_LOG"
    SYSMON = "SYSMON"
    IDENTITY_LOG = "IDENTITY_LOG"
    NETWORK_TELEMETRY = "NETWORK_TELEMETRY"
    DNS_LOG = "DNS_LOG"
    FIREWALL_LOG = "FIREWALL_LOG"
    PROXY_LOG = "PROXY_LOG"
    VPN_LOG = "VPN_LOG"
    FILE_METADATA = "FILE_METADATA"
    DISK_IMAGE_METADATA = "DISK_IMAGE_METADATA"
    MEMORY_IMAGE_METADATA = "MEMORY_IMAGE_METADATA"
    PCAP_METADATA = "PCAP_METADATA"
    MALWARE_REPORT = "MALWARE_REPORT"
    CLOUD_AUDIT = "CLOUD_AUDIT"
    SAAS_AUDIT = "SAAS_AUDIT"
    EMAIL_HEADER = "EMAIL_HEADER"
    BROWSER_ARTIFACT = "BROWSER_ARTIFACT"
    USER_REPORT = "USER_REPORT"
    TICKET = "TICKET"
    OTHER = "OTHER"


class EvidenceClassification(str, Enum):
    ORIGINAL_EVIDENCE = "ORIGINAL_EVIDENCE"
    FORENSIC_WORKING_COPY = "FORENSIC_WORKING_COPY"
    PARSED_DERIVATIVE = "PARSED_DERIVATIVE"
    ANALYST_OUTPUT = "ANALYST_OUTPUT"


class AcquisitionType(str, Enum):
    AUTHORIZED_ENDPOINT_COLLECTION = "AUTHORIZED_ENDPOINT_COLLECTION"
    AUTHORIZED_DISK_IMAGE = "AUTHORIZED_DISK_IMAGE"
    AUTHORIZED_MEMORY_IMAGE = "AUTHORIZED_MEMORY_IMAGE"
    AUTHORIZED_NETWORK_CAPTURE = "AUTHORIZED_NETWORK_CAPTURE"
    AUTHORIZED_LOG_EXPORT = "AUTHORIZED_LOG_EXPORT"
    AUTHORIZED_CLOUD_AUDIT_EXPORT = "AUTHORIZED_CLOUD_AUDIT_EXPORT"
    AUTHORIZED_SAAS_AUDIT_EXPORT = "AUTHORIZED_SAAS_AUDIT_EXPORT"
    SYNTHETIC_DEMO_RECORD = "SYNTHETIC_DEMO_RECORD"
    UNKNOWN = "UNKNOWN"


class VerificationState(str, Enum):
    REPORTED = "REPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    SUPPORTED = "SUPPORTED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    RETRACTED = "RETRACTED"


class IncidentState(str, Enum):
    ALERT_ONLY = "ALERT_ONLY"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    INCIDENT_CANDIDATE = "INCIDENT_CANDIDATE"
    INCIDENT_SUPPORTED = "INCIDENT_SUPPORTED"
    INCIDENT_CONFIRMED_BY_AUTHORIZED_EVIDENCE = "INCIDENT_CONFIRMED_BY_AUTHORIZED_EVIDENCE"
    BENIGN_EXPLANATION_SUPPORTED = "BENIGN_EXPLANATION_SUPPORTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class TemporalPrecision(str, Enum):
    EXACT = "EXACT"
    SECOND = "SECOND"
    MINUTE = "MINUTE"
    HOUR = "HOUR"
    DAY = "DAY"
    APPROXIMATE = "APPROXIMATE"
    RELATIVE = "RELATIVE"
    UNKNOWN = "UNKNOWN"


class IOCType(str, Enum):
    FILE_HASH = "FILE_HASH"
    DOMAIN = "DOMAIN"
    IP = "IP"
    URL = "URL"
    FILE_PATH = "FILE_PATH"
    PROCESS_ID = "PROCESS_ID"
    CERTIFICATE = "CERTIFICATE"
    REGISTRY_KEY = "REGISTRY_KEY"
    MUTEX = "MUTEX"
    OTHER = "OTHER"


class HypothesisKind(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    ROOT_CAUSE = "ROOT_CAUSE"
    EXECUTION = "EXECUTION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION = "EXFILTRATION"
    MALICIOUSNESS = "MALICIOUSNESS"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_ADMINISTRATION = "BENIGN_ADMINISTRATION"
    OTHER = "OTHER"


class HypothesisStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNRESOLVED = "UNRESOLVED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


class GapType(str, Enum):
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    CHAIN_OF_CUSTODY_GAP = "CHAIN_OF_CUSTODY_GAP"
    SENSOR_GAP = "SENSOR_GAP"
    LOG_RETENTION_GAP = "LOG_RETENTION_GAP"
    CLOCK_SKEW_GAP = "CLOCK_SKEW_GAP"
    TIMEZONE_GAP = "TIMEZONE_GAP"
    PARSER_GAP = "PARSER_GAP"
    EXECUTION_GAP = "EXECUTION_GAP"
    PERSISTENCE_GAP = "PERSISTENCE_GAP"
    CREDENTIAL_ACCESS_GAP = "CREDENTIAL_ACCESS_GAP"
    LATERAL_MOVEMENT_GAP = "LATERAL_MOVEMENT_GAP"
    DATA_ACCESS_GAP = "DATA_ACCESS_GAP"
    EXFILTRATION_GAP = "EXFILTRATION_GAP"
    INITIAL_ACCESS_GAP = "INITIAL_ACCESS_GAP"
    ROOT_CAUSE_GAP = "ROOT_CAUSE_GAP"
    SOURCE_INDEPENDENCE_GAP = "SOURCE_INDEPENDENCE_GAP"
    PRIVACY_SCOPE_GAP = "PRIVACY_SCOPE_GAP"


class PrivacyFlag(str, Enum):
    CASE_SCOPED = "CASE_SCOPED"
    AUTHORIZED_SCOPE_ONLY = "AUTHORIZED_SCOPE_ONLY"
    NO_RAW_EVIDENCE_EXPORT = "NO_RAW_EVIDENCE_EXPORT"
    NO_PRIVATE_CONTENT_INSPECTION = "NO_PRIVATE_CONTENT_INSPECTION"
    NO_CREDENTIAL_REUSE = "NO_CREDENTIAL_REUSE"
    NO_TOKEN_REPLAY = "NO_TOKEN_REPLAY"
    NO_ANTI_FORENSICS_GUIDANCE = "NO_ANTI_FORENSICS_GUIDANCE"
    NO_OFFENSIVE_ACTION = "NO_OFFENSIVE_ACTION"


class PolicyFlag(str, Enum):
    NONE = "NONE"
    BLOCKED_REQUEST = "BLOCKED_REQUEST"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    DEFENSIVE_ONLY = "DEFENSIVE_ONLY"


class RecommendationApproval(str, Enum):
    AUTONOMOUS_ANALYTIC = "AUTONOMOUS_ANALYTIC"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    OPERATIONAL_CHANGE_APPROVAL_REQUIRED = "OPERATIONAL_CHANGE_APPROVAL_REQUIRED"


# =====================================================================
# CONSTANTS
# =====================================================================

DIRECT_SOURCE_FACTOR: Dict[SourceType, float] = {
    SourceType.EDR: 0.95,
    SourceType.WINDOWS_EVENT_LOG: 0.95,
    SourceType.SYSMON: 0.92,
    SourceType.IDENTITY_LOG: 0.95,
    SourceType.NETWORK_TELEMETRY: 0.92,
    SourceType.DNS_LOG: 0.78,
    SourceType.FIREWALL_LOG: 0.85,
    SourceType.PROXY_LOG: 0.82,
    SourceType.VPN_LOG: 0.85,
    SourceType.FILE_METADATA: 0.72,
    SourceType.DISK_IMAGE_METADATA: 0.80,
    SourceType.MEMORY_IMAGE_METADATA: 0.82,
    SourceType.PCAP_METADATA: 0.82,
    SourceType.CLOUD_AUDIT: 0.90,
    SourceType.SAAS_AUDIT: 0.86,
    SourceType.EMAIL_HEADER: 0.78,
    SourceType.BROWSER_ARTIFACT: 0.70,
    SourceType.MALWARE_REPORT: 0.70,
    SourceType.SIEM: 0.65,
    SourceType.USER_REPORT: 0.50,
    SourceType.TICKET: 0.55,
    SourceType.OTHER: 0.65,
}

TEMPORAL_FACTOR: Dict[TemporalPrecision, float] = {
    TemporalPrecision.EXACT: 1.00,
    TemporalPrecision.SECOND: 1.00,
    TemporalPrecision.MINUTE: 0.98,
    TemporalPrecision.HOUR: 0.90,
    TemporalPrecision.DAY: 0.75,
    TemporalPrecision.APPROXIMATE: 0.65,
    TemporalPrecision.RELATIVE: 0.50,
    TemporalPrecision.UNKNOWN: 0.30,
}

EXECUTION_CAPABLE_SOURCE_TYPES = {
    SourceType.EDR,
    SourceType.SYSMON,
    SourceType.WINDOWS_EVENT_LOG,
    SourceType.MEMORY_IMAGE_METADATA,
}

FILE_PRESENCE_SOURCE_TYPES = {
    SourceType.FILE_METADATA,
    SourceType.DISK_IMAGE_METADATA,
    SourceType.EDR,
}

PROHIBITED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "OFFENSIVE_EXPLOITATION",
        re.compile(
            r"\b(exploit|deploy malware|deploy ransomware|install persistence|backdoor|"
            r"payload delivery|weaponize|attack system|compromise system)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CREDENTIAL_ABUSE",
        re.compile(
            r"\b(steal credentials|password spray|credential stuff|brute force|bypass mfa|"
            r"use recovered credential|replay token|replay cookie|session hijack|harvest credential)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ANTI_FORENSICS_INSTRUCTION",
        re.compile(
            r"\b(teach|explain|show me how|instructions?|guide).{0,60}"
            r"(anti[- ]forensics|delete logs|clear event log|timestomp|timestamp manipulation|"
            r"log evasion|disable edr|disable logging|wipe disk|destroy evidence)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "EVIDENCE_DESTRUCTION",
        re.compile(
            r"\b(delete|destroy|wipe|clear|tamper with|modify|alter) "
            r"(logs|event logs|audit trail|forensic artifacts|evidence|memory image|disk image)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "UNAUTHORIZED_ACCESS",
        re.compile(
            r"\b(hack|bypass authentication|access private account|stolen credential|"
            r"unauthorized scan|unauthorized access)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "ATTACKER_INTERACTION",
        re.compile(
            r"\b(interact with c2|command malware|trigger ransomware|contact attacker|"
            r"send beacon|receive tasking)\b",
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
    return f"{prefix}{h}" if prefix else h


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


def coerce_precision(value: Any) -> Optional[TemporalPrecision]:
    if value is None:
        return None
    if isinstance(value, TemporalPrecision):
        return value
    try:
        return TemporalPrecision(str(value).upper())
    except Exception:
        return TemporalPrecision.UNKNOWN


@dataclass
class TimeValue:
    original: str = ""
    utc: Optional[str] = None
    local: Optional[str] = None
    timezone: Optional[str] = None
    precision: TemporalPrecision = TemporalPrecision.UNKNOWN
    inferred_timezone: bool = False
    notes: str = ""


def parse_time(
    raw: Any,
    precision: Any = None,
    tz_hint: str = "UTC",
    notes: str = "",
) -> TimeValue:
    original = str(raw or "").strip()
    if not original:
        return TimeValue(original="", precision=TemporalPrecision.UNKNOWN, notes=notes)

    s = original.replace("Z", "+00:00")
    approximate = bool(re.match(r"^(around|approx(?:imately)?|circa|~)\s+", s, re.IGNORECASE))
    if approximate:
        s = re.sub(r"^(around|approx(?:imately)?|circa|~)\s+", "", s, flags=re.IGNORECASE).strip()

    dt: Optional[datetime] = None
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        for fmt in [
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M%z",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
        ]:
            try:
                dt = datetime.strptime(s, fmt)
                break
            except Exception:
                continue

    if dt is None:
        return TimeValue(original=original, precision=TemporalPrecision.UNKNOWN, notes=notes)

    inferred = False
    if dt.tzinfo is None:
        if tz_hint.upper() == "UTC":
            dt = dt.replace(tzinfo=timezone.utc)
            inferred = True
        else:
            try:
                m = re.match(r"^([+-])(\d{2}):(\d{2})$", tz_hint)
                if m:
                    sign = 1 if m.group(1) == "+" else -1
                    dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))))
                    inferred = True
                else:
                    dt = dt.replace(tzinfo=timezone.utc)
                    inferred = True
            except Exception:
                dt = dt.replace(tzinfo=timezone.utc)
                inferred = True

    utc = dt.astimezone(timezone.utc).isoformat()
    local = dt.isoformat()
    tz_name = dt.tzinfo.tzname(dt) if dt.tzinfo else tz_hint

    p = coerce_precision(precision)
    if p:
        prec = p
    elif approximate:
        prec = TemporalPrecision.APPROXIMATE
    elif re.search(r"\d{2}:\d{2}:\d{2}", original):
        prec = TemporalPrecision.SECOND
    elif re.search(r"\d{2}:\d{2}", original):
        prec = TemporalPrecision.MINUTE
    elif re.search(r"T\d{2}\b", original):
        prec = TemporalPrecision.HOUR
    elif re.match(r"^\d{4}-\d{2}-\d{2}$", original):
        prec = TemporalPrecision.DAY
    else:
        prec = TemporalPrecision.UNKNOWN

    return TimeValue(
        original=original,
        utc=utc,
        local=local,
        timezone=tz_name,
        precision=prec,
        inferred_timezone=inferred,
        notes=notes,
    )


def utc_datetime(tv: Optional[TimeValue]) -> datetime:
    if not tv or not tv.utc:
        return datetime.max.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(tv.utc.replace("Z", "+00:00"))
    except Exception:
        return datetime.max.replace(tzinfo=timezone.utc)


def policy_guard(text: str) -> List[Dict[str, str]]:
    violations: List[Dict[str, str]] = []
    for rule, rx in PROHIBITED_PATTERNS:
        m = rx.search(text or "")
        if m:
            violations.append({"rule": rule, "matched": m.group(0)})
    return violations


# =====================================================================
# DATACLASSES
# =====================================================================

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
class ChainOfCustodyEntry:
    custodian: str
    action: str
    at: str
    method: str = ""
    tool: str = ""
    tool_version: str = ""
    hash_after: str = ""
    storage_reference: str = ""
    notes: str = ""


@dataclass
class Evidence:
    id: str
    source_id: str
    artifact_type: str
    classification: EvidenceClassification = EvidenceClassification.ORIGINAL_EVIDENCE
    acquisition_type: AcquisitionType = AcquisitionType.SYNTHETIC_DEMO_RECORD
    original_filename: str = ""
    logical_path: str = ""
    host_identifier: str = ""
    account_identifier: str = ""
    device_identifier: str = ""
    created_at: Optional[str] = None
    modified_at: Optional[str] = None
    accessed_at: Optional[str] = None
    acquired_at: Optional[str] = None
    hash_sha256: str = ""
    size: Optional[int] = None
    tool: str = ""
    tool_version: str = ""
    collector: str = ""
    authorization_context: str = "authorized_demo_scope"
    storage_reference: str = "case-scoped-secure-storage"
    chain_of_custody: List[ChainOfCustodyEntry] = field(default_factory=list)
    parser_version: str = "synthetic-parser-0.1"
    excerpt: str = ""
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Observation:
    id: str
    evidence_id: str
    source_id: str
    statement: str
    observed_at: TimeValue = field(default_factory=TimeValue)
    entities: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Claim:
    id: str
    source_id: str
    statement: str
    asserted_at: TimeValue = field(default_factory=TimeValue)
    status: str = "SOURCE_CLAIM_ONLY"
    confidence: float = 0.5
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    id: str
    case_id: str
    event_type: str
    subtype: Optional[str] = None
    title: str = ""
    description: str = ""
    time: TimeValue = field(default_factory=TimeValue)
    host_identifier: str = ""
    account_identifier: str = ""
    process_identifier: str = ""
    file_identifier: str = ""
    network_identifier: str = ""
    dns_identifier: str = ""
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    observation_ids: List[str] = field(default_factory=list)
    claim_ids: List[str] = field(default_factory=list)
    parsed_fields: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    verification_state: VerificationState = VerificationState.REPORTED
    limitations: List[str] = field(default_factory=list)
    requires_human_review: bool = False


@dataclass
class IOC:
    id: str
    ioc_type: IOCType
    value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: float = 0.0
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    temporal_note: str = "IOCs are temporal; ownership/use may change."
    limitations: List[str] = field(default_factory=list)


@dataclass
class TTPMapping:
    id: str
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    mitre_version: str = "ATT&CK v17"
    behavior_summary: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    attribution_caution: str = "TTP mapping is not actor attribution."


@dataclass
class Hypothesis:
    id: str
    kind: HypothesisKind
    statement: str
    supporting_event_ids: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
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
    event_ids: List[str] = field(default_factory=list)
    claim_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    status: str = "OPEN"
    recommended_resolution: str = ""


@dataclass
class KnowledgeGap:
    id: str
    gap_type: GapType
    description: str
    about_event_ids: List[str] = field(default_factory=list)
    about_evidence_ids: List[str] = field(default_factory=list)
    importance: str = "MEDIUM"
    recommended_source: str = ""
    specialist: Optional[str] = None
    expected_information_value: float = 0.0


@dataclass
class NextAction:
    id: str
    description: str
    priority: int = 1
    privacy_impact: str = "LOW_IF_AUTHORIZED"
    expected_gain: float = 0.0
    specialist: Optional[str] = None
    requires_human_approval: bool = False


@dataclass
class Recommendation:
    id: str
    phase: str
    action: str
    target: str
    rationale: str
    evidence_ids: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    approval: RecommendationApproval = RecommendationApproval.HUMAN_APPROVAL_REQUIRED
    business_impact: str = "REQUIRES_OPERATIONAL_REVIEW"
    reversibility: str = "REQUIRES_VALIDATION"
    evidence_preservation_note: str = "Do not perform action if it destroys required evidence without preservation plan."
    limitations: List[str] = field(default_factory=list)


@dataclass
class Incident:
    id: str
    case_id: str
    title: str
    state: IncidentState
    severity: str
    first_observed: Optional[str] = None
    earliest_supported_activity: Optional[str] = None
    detection_time: Optional[str] = None
    containment_time: Optional[str] = None
    recovery_time: Optional[str] = None
    affected_assets: List[str] = field(default_factory=list)
    potentially_affected_assets: List[str] = field(default_factory=list)
    affected_accounts: List[str] = field(default_factory=list)
    affected_data: str = "UNKNOWN"
    initial_access_state: str = "INITIAL_ACCESS_UNKNOWN"
    root_cause_state: str = "ROOT_CAUSE_UNKNOWN"
    incident_type: str = "SUSPICIOUS_ENDPOINT_ACTIVITY"
    evidence_ids: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: ["authorized_defensive_dfir", "case_scoped"])
    authorization: str = "demo_authorized_incident_response"
    incident_id: str = ""
    hosts: List[str] = field(default_factory=list)
    accounts: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    sample: bool = False
    budget: Optional[str] = None
    deadline: Optional[str] = None


# =====================================================================
# DFIRINT ENGINE
# =====================================================================

class DfirInt:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.sources: Dict[str, Source] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.observations: Dict[str, Observation] = {}
        self.claims: Dict[str, Claim] = {}
        self.events: Dict[str, Event] = {}
        self.iocs: Dict[str, IOC] = {}
        self.ttps: List[TTPMapping] = []
        self.hypotheses: List[Hypothesis] = []
        self.contradictions: List[Contradiction] = []
        self.gaps: List[KnowledgeGap] = []
        self.actions: List[NextAction] = []
        self.containment: List[Recommendation] = []
        self.eradication: List[Recommendation] = []
        self.recovery: List[Recommendation] = []
        self.handoffs: List[Dict[str, str]] = []
        self.incident: Optional[Incident] = None
        self.timeline: List[Event] = []
        self.validation_errors: List[str] = []

    # -----------------------------------------------------------------
    # Adders
    # -----------------------------------------------------------------

    def add_source(self, source: Source) -> Source:
        self.sources[source.id] = source
        return source

    def add_evidence(self, evidence: Evidence) -> Evidence:
        if not evidence.hash_sha256:
            seed = "|".join([
                evidence.source_id,
                evidence.artifact_type,
                evidence.logical_path,
                evidence.excerpt,
            ])
            evidence.hash_sha256 = stable_hash(seed)
        if not evidence.acquired_at:
            evidence.acquired_at = now_iso()
        if not evidence.collector:
            evidence.collector = "authorized-demo-collector"
        if not evidence.tool:
            evidence.tool = "synthetic-safe-ingestor"
        if not evidence.tool_version:
            evidence.tool_version = PIPELINE_VERSION
        if not evidence.chain_of_custody:
            evidence.chain_of_custody.append(
                ChainOfCustodyEntry(
                    custodian=evidence.collector,
                    action="acquired_and_hashed",
                    at=evidence.acquired_at or now_iso(),
                    method=evidence.acquisition_type.value,
                    tool=evidence.tool,
                    tool_version=evidence.tool_version,
                    hash_after=evidence.hash_sha256,
                    storage_reference=evidence.storage_reference,
                    notes="Synthetic demo custody entry; no live acquisition performed.",
                )
            )
        self.evidence[evidence.id] = evidence
        return evidence

    def add_observation(self, observation: Observation) -> Observation:
        self.observations[observation.id] = observation
        return observation

    def add_claim(self, claim: Claim) -> Claim:
        self.claims[claim.id] = claim
        return claim

    def add_event(self, event: Event) -> Event:
        self.events[event.id] = event
        return event

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
    # Chain of custody / coverage validation
    # -----------------------------------------------------------------

    def validate_chain_of_custody(self) -> None:
        required_fields = [
            ("hash_sha256", "evidence hash"),
            ("acquired_at", "acquisition time"),
            ("collector", "collector"),
            ("tool", "acquisition/processing tool"),
            ("tool_version", "tool version"),
        ]
        for ev in self.evidence.values():
            missing = [label for attr, label in required_fields if not getattr(ev, attr)]
            if missing:
                self.gaps.append(KnowledgeGap(
                    id=new_id("GAP-COC-", ev.id + "".join(missing)),
                    gap_type=GapType.CHAIN_OF_CUSTODY_GAP,
                    description=f"Evidence {ev.id} missing chain-of-custody fields: {', '.join(missing)}.",
                    about_evidence_ids=[ev.id],
                    importance="HIGH",
                    recommended_source="Authorized acquisition record / custody log",
                    specialist="DFIRINT / EVIDENCEHANDLING",
                    expected_information_value=0.80,
                ))
            if not ev.chain_of_custody:
                self.gaps.append(KnowledgeGap(
                    id=new_id("GAP-COC-EMPTY-", ev.id),
                    gap_type=GapType.CHAIN_OF_CUSTODY_GAP,
                    description=f"Evidence {ev.id} has no chain-of-custody entries.",
                    about_evidence_ids=[ev.id],
                    importance="HIGH",
                    recommended_source="Custody transfer log",
                    specialist="DFIRINT / EVIDENCEHANDLING",
                    expected_information_value=0.75,
                ))
            for entry in ev.chain_of_custody:
                if not entry.custodian or not entry.action or not entry.at:
                    self.validation_errors.append(
                        f"Evidence {ev.id} custody entry incomplete: custodian/action/at required."
                    )

    def validate_sensor_coverage(self) -> None:
        source_types = {self.sources[sid].source_type for sid in self.sources if sid in self.sources}
        coverage_notes = []
        if SourceType.MEMORY_IMAGE_METADATA not in source_types:
            coverage_notes.append("Memory evidence not available in current corpus.")
        if SourceType.DISK_IMAGE_METADATA not in source_types:
            coverage_notes.append("Full disk image metadata not available in current corpus.")
        if SourceType.PCAP_METADATA not in source_types:
            coverage_notes.append("Full PCAP not available; only telemetry/log derivatives represented.")
        if coverage_notes:
            self.gaps.append(KnowledgeGap(
                id=new_id("GAP-COVERAGE-", "".join(coverage_notes)),
                gap_type=GapType.SENSOR_GAP,
                description="Evidence coverage limitations: " + " ".join(coverage_notes),
                importance="MEDIUM",
                recommended_source="Authorized volatile/dead-box acquisition if operationally justified",
                specialist="DFIRINT / LOGINT / NETINT",
                expected_information_value=0.70,
            ))

    # -----------------------------------------------------------------
    # Fact gate
    # -----------------------------------------------------------------

    def fact_gate_events(self) -> None:
        contradiction_event_ids = {eid for c in self.contradictions for eid in c.event_ids if c.severity == "MATERIAL"}

        for ev in self.events.values():
            srcs = [self.sources[sid] for sid in ev.source_ids if sid in self.sources]
            if not srcs:
                ev.confidence = 0.0
                ev.verification_state = VerificationState.UNSUPPORTED
                ev.limitations.append("No mapped source.")
                continue

            families = self.source_families(ev.source_ids)
            max_rel = max((s.reliability for s in srcs), default=0.5)
            direct = max((DIRECT_SOURCE_FACTOR.get(s.source_type, 0.65) for s in srcs), default=0.65)
            temporal = TEMPORAL_FACTOR.get(ev.time.precision, 0.35)

            confidence = max_rel * direct * temporal
            if len(families) >= 2:
                confidence = min(0.99, confidence * 1.08)
            elif len(families) == 1 and len(ev.source_ids) > 1:
                confidence *= 0.90
                ev.limitations.append("Multiple sources share one upstream source family.")

            # Semantic guards
            if ev.event_type == "FILE_PRESENT":
                ev.limitations.append("File presence does not establish execution.")
                if confidence >= 0.65:
                    state = VerificationState.PARTIALLY_SUPPORTED
                else:
                    state = VerificationState.INCONCLUSIVE
            elif ev.event_type == "PROCESS_CREATION":
                has_execution_capable = any(s.source_type in EXECUTION_CAPABLE_SOURCE_TYPES for s in srcs)
                if not has_execution_capable:
                    ev.limitations.append("No execution-capable telemetry supports process creation.")
                    state = VerificationState.INCONCLUSIVE
                elif confidence >= 0.78 and len(families) >= 2:
                    state = VerificationState.SUPPORTED
                elif confidence >= 0.65:
                    state = VerificationState.PARTIALLY_SUPPORTED
                else:
                    state = VerificationState.INCONCLUSIVE
            elif ev.event_type == "NETWORK_CONNECTION":
                has_network = any(s.source_type in {SourceType.NETWORK_TELEMETRY, SourceType.PCAP_METADATA, SourceType.FIREWALL_LOG, SourceType.PROXY_LOG} for s in srcs)
                if not has_network:
                    state = VerificationState.INCONCLUSIVE
                    ev.limitations.append("No network telemetry supports connection.")
                elif confidence >= 0.75:
                    state = VerificationState.SUPPORTED
                else:
                    state = VerificationState.PARTIALLY_SUPPORTED
                ev.limitations.append("Network connection does not establish malicious C2 or exfiltration.")
            elif ev.event_type == "DNS_QUERY":
                state = VerificationState.PARTIALLY_SUPPORTED if confidence >= 0.60 else VerificationState.INCONCLUSIVE
                ev.limitations.append("DNS query does not establish user intent or website visit.")
            elif ev.event_type == "AUTHENTICATION":
                state = VerificationState.SUPPORTED if confidence >= 0.75 else VerificationState.PARTIALLY_SUPPORTED
                ev.limitations.append("Authentication does not establish human operator identity.")
            elif ev.event_type == "ALERT":
                state = VerificationState.SUPPORTED if confidence >= 0.70 else VerificationState.PARTIALLY_SUPPORTED
                ev.limitations.append("Alert is not incident confirmation.")
            elif ev.event_type == "SIEM_INGEST":
                state = VerificationState.SUPPORTED if confidence >= 0.60 else VerificationState.PARTIALLY_SUPPORTED
                ev.limitations.append("SIEM ingest is derivative telemetry, not independent source corroboration.")
            elif ev.event_type == "USER_REPORT":
                state = VerificationState.PARTIALLY_SUPPORTED if confidence >= 0.55 else VerificationState.REPORTED
                ev.limitations.append("Human report requires basis-of-knowledge review.")
            else:
                if confidence >= 0.78 and len(families) >= 2:
                    state = VerificationState.SUPPORTED
                elif confidence >= 0.65:
                    state = VerificationState.PARTIALLY_SUPPORTED
                elif confidence >= 0.45:
                    state = VerificationState.INCONCLUSIVE
                else:
                    state = VerificationState.UNSUPPORTED

            if ev.id in contradiction_event_ids:
                state = VerificationState.DISPUTED
                ev.limitations.append("Material contradiction affects this event.")

            ev.confidence = round(confidence, 3)
            ev.verification_state = state
            ev.requires_human_review = (
                state in {VerificationState.DISPUTED, VerificationState.INCONCLUSIVE}
                or ev.event_type in {"PROCESS_CREATION", "NETWORK_CONNECTION", "AUTHENTICATION"}
            )

    # -----------------------------------------------------------------
    # Contradictions
    # -----------------------------------------------------------------

    def detect_contradictions(self) -> None:
        for claim in self.claims.values():
            event_id = claim.attributes.get("event_id")
            if not event_id or event_id not in self.events:
                continue
            ev = self.events[event_id]
            if not claim.asserted_at.utc or not ev.time.utc:
                continue
            try:
                c_dt = datetime.fromisoformat(claim.asserted_at.utc.replace("Z", "+00:00"))
                e_dt = datetime.fromisoformat(ev.time.utc.replace("Z", "+00:00"))
                delta = abs((c_dt - e_dt).total_seconds())
            except Exception:
                continue

            if delta > 900 and claim.asserted_at.precision in {
                TemporalPrecision.SECOND,
                TemporalPrecision.MINUTE,
                TemporalPrecision.HOUR,
            } and ev.time.precision in {
                TemporalPrecision.SECOND,
                TemporalPrecision.MINUTE,
                TemporalPrecision.HOUR,
            }:
                desc = (
                    f"Claim {claim.id} asserts event {event_id} around {claim.asserted_at.original}, "
                    f"but normalized evidence places it at {ev.time.utc}. Delta exceeds 15 minutes."
                )
                self.contradictions.append(Contradiction(
                    id=new_id("CON-", desc),
                    contradiction_type="TEMPORAL",
                    description=desc,
                    event_ids=[event_id],
                    claim_ids=[claim.id],
                    source_ids=sorted({claim.source_id, *ev.source_ids}),
                    severity="LOW",
                    status="OPEN",
                    recommended_resolution=(
                        "Verify human report timezone/memory, primary log timestamps, clock skew, "
                        "and whether claim refers to a different but related event."
                    ),
                ))

    # -----------------------------------------------------------------
    # Timeline
    # -----------------------------------------------------------------

    def build_timeline(self) -> None:
        self.timeline = sorted(self.events.values(), key=lambda e: utc_datetime(e.time))

    # -----------------------------------------------------------------
    # IOC extraction
    # -----------------------------------------------------------------

    def add_or_update_ioc(self, ioc_type: IOCType, value: str, evidence_ids: List[str], source_ids: List[str], time_utc: Optional[str], confidence: float) -> None:
        if not value:
            return
        key = f"{ioc_type.value}:{normalize_text(value)}"
        if key in self.iocs:
            ioc = self.iocs[key]
            ioc.evidence_ids = sorted(set(ioc.evidence_ids + evidence_ids))
            ioc.source_ids = sorted(set(ioc.source_ids + source_ids))
            ioc.confidence = max(ioc.confidence, confidence)
            if time_utc:
                if not ioc.first_seen or time_utc < (ioc.first_seen or ""):
                    ioc.first_seen = time_utc
                if not ioc.last_seen or time_utc > (ioc.last_seen or ""):
                    ioc.last_seen = time_utc
            return

        self.iocs[key] = IOC(
            id=new_id("IOC-", key),
            ioc_type=ioc_type,
            value=value,
            first_seen=time_utc,
            last_seen=time_utc,
            confidence=round(confidence, 3),
            evidence_ids=sorted(set(evidence_ids)),
            source_ids=sorted(set(source_ids)),
            limitations=[
                "IOC is temporal; ownership/use may change.",
                "IOC presence does not establish actor attribution.",
            ],
        )

    def build_iocs(self) -> None:
        for ev in self.events.values():
            pf = ev.parsed_fields or {}
            conf = ev.confidence
            if pf.get("file_hash"):
                self.add_or_update_ioc(IOCType.FILE_HASH, pf["file_hash"], ev.evidence_ids, ev.source_ids, ev.time.utc, conf)
            if pf.get("file_path"):
                self.add_or_update_ioc(IOCType.FILE_PATH, pf["file_path"], ev.evidence_ids, ev.source_ids, ev.time.utc, conf * 0.8)
            if pf.get("process_identifier"):
                self.add_or_update_ioc(IOCType.PROCESS_ID, pf["process_identifier"], ev.evidence_ids, ev.source_ids, ev.time.utc, conf * 0.7)
            if pf.get("domain"):
                self.add_or_update_ioc(IOCType.DOMAIN, pf["domain"], ev.evidence_ids, ev.source_ids, ev.time.utc, conf)
            if pf.get("ip"):
                self.add_or_update_ioc(IOCType.IP, pf["ip"], ev.evidence_ids, ev.source_ids, ev.time.utc, conf * 0.85)
            if pf.get("url"):
                self.add_or_update_ioc(IOCType.URL, pf["url"], ev.evidence_ids, ev.source_ids, ev.time.utc, conf)

        # Also extract from evidence parsed fields.
        for evid in self.evidence.values():
            pf = evid.parsed_fields or {}
            time_utc = evid.acquired_at
            if pf.get("file_hash"):
                self.add_or_update_ioc(IOCType.FILE_HASH, pf["file_hash"], [evid.id], [evid.source_id], time_utc, 0.70)
            if pf.get("domain"):
                self.add_or_update_ioc(IOCType.DOMAIN, pf["domain"], [evid.id], [evid.source_id], time_utc, 0.70)

    # -----------------------------------------------------------------
    # TTP mapping
    # -----------------------------------------------------------------

    def build_ttps(self) -> None:
        proc_events = [e for e in self.events.values() if e.event_type == "PROCESS_CREATION" and e.verification_state in {VerificationState.SUPPORTED, VerificationState.PARTIALLY_SUPPORTED}]
        net_events = [e for e in self.events.values() if e.event_type == "NETWORK_CONNECTION" and e.verification_state in {VerificationState.SUPPORTED, VerificationState.PARTIALLY_SUPPORTED}]

        if proc_events:
            ev = max(proc_events, key=lambda x: x.confidence)
            self.ttps.append(TTPMapping(
                id=new_id("TTP-", "execution-" + ev.id),
                tactic="Execution",
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                behavior_summary="Observed process creation consistent with interpreter/script execution on endpoint.",
                evidence_ids=ev.evidence_ids,
                event_ids=[ev.id],
                confidence=round(ev.confidence * 0.85, 3),
                attribution_caution="TTP mapping is not actor attribution; administrators, pentesters, and benign software can exhibit similar behavior.",
            ))

        if net_events:
            ev = max(net_events, key=lambda x: x.confidence)
            self.ttps.append(TTPMapping(
                id=new_id("TTP-", "c2-" + ev.id),
                tactic="Command and Control",
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                subtechnique_id="T1071.001",
                subtechnique_name="Web Protocols",
                behavior_summary="Observed outbound network connection using common application protocol; C2 remains hypothesis only.",
                evidence_ids=ev.evidence_ids,
                event_ids=[ev.id],
                confidence=round(ev.confidence * 0.65, 3),
                attribution_caution="Connection to external service does not establish C2, actor, campaign, or malicious intent.",
            ))

    # -----------------------------------------------------------------
    # Hypotheses / ACH-lite
    # -----------------------------------------------------------------

    def build_hypotheses(self) -> None:
        auth_events = [e for e in self.events.values() if e.event_type == "AUTHENTICATION"]
        proc_events = [e for e in self.events.values() if e.event_type == "PROCESS_CREATION"]
        net_events = [e for e in self.events.values() if e.event_type == "NETWORK_CONNECTION"]
        alert_events = [e for e in self.events.values() if e.event_type == "ALERT"]

        all_support_ev = sorted({eid for e in self.events.values() for eid in e.evidence_ids})

        if proc_events and auth_events:
            self.hypotheses.append(Hypothesis(
                id="HYP-ACCOUNT-COMPROMISE",
                kind=HypothesisKind.INITIAL_ACCESS,
                statement="Account activity may reflect compromised or misused identity leading to endpoint process execution.",
                supporting_event_ids=[e.id for e in auth_events + proc_events],
                supporting_evidence_ids=all_support_ev,
                assumptions=["Authentication preceded process creation.", "Account may not represent human operator."],
                predictions=["Identity telemetry would show unusual source/device/MFA/session pattern.", "Credential-access artifacts may exist if memory/LSASS evidence is collected."],
                falsification_conditions=[
                    "Activity is explained by legitimate service automation.",
                    "Authentication source/device is known-administrator approved workflow.",
                    "Process is signed/benign and connection is known updater.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.45,
                limitations=[
                    "No credential-access evidence in current corpus.",
                    "Account identity is not person attribution.",
                ],
            ))

        self.hypotheses.append(Hypothesis(
            id="HYP-BENIGN-ADMIN",
            kind=HypothesisKind.BENIGN_ADMINISTRATION,
            statement="Observed activity may be legitimate administrative, backup, monitoring, or software-update behavior.",
            supporting_event_ids=[e.id for e in auth_events + proc_events + net_events],
            supporting_evidence_ids=all_support_ev,
            assumptions=["Account may be privileged/service account.", "External connection may be benign cloud/service traffic."],
            predictions=["Change tickets, admin schedules, service catalogs, or known-good baselines would explain activity."],
            falsification_conditions=[
                "Process/file hash is known malicious and executed.",
                "Connection destination is threat-linked and unrelated to approved service.",
                "Persistence/credential-access/lateral-movement artifacts are found.",
            ],
            status=HypothesisStatus.POSSIBLE,
            confidence=0.40,
            limitations=["Benign explanation is not confirmed without operational context."],
        ))

        self.hypotheses.append(Hypothesis(
            id="HYP-FALSE-POSITIVE",
            kind=HypothesisKind.FALSE_POSITIVE,
            statement="EDR/SIEM alert may be false positive or low-fidelity detection.",
            supporting_event_ids=[e.id for e in alert_events],
            supporting_evidence_ids=all_support_ev,
            assumptions=["Detection logic may be broad.", "Telemetry normalization may lose context."],
            predictions=["Raw artifact review and vendor detection semantics would show benign process/tree."],
            falsification_conditions=[
                "Independent execution and network artifacts support unexpected behavior.",
                "Malware report/hash intelligence supports malicious file.",
            ],
            status=HypothesisStatus.POSSIBLE,
            confidence=0.30,
            limitations=["False positive cannot be declared solely because alert stopped."],
        ))

        if net_events:
            self.hypotheses.append(Hypothesis(
                id="HYP-EXFIL-CANDIDATE",
                kind=HypothesisKind.EXFILTRATION,
                statement="Outbound connection may represent data transfer candidate, but exfiltration is not supported by current evidence.",
                supporting_event_ids=[e.id for e in net_events],
                supporting_evidence_ids=sorted({eid for e in net_events for eid in e.evidence_ids}),
                assumptions=["Network flow metadata may indicate transfer volume/destination."],
                predictions=["DLP, proxy, cloud audit, file access, and packet metadata would show data movement."],
                falsification_conditions=[
                    "Transfer is known backup/update/telemetry.",
                    "No data access/staging evidence exists.",
                    "Volume/destination is benign and expected.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.25,
                limitations=[
                    "Connection is not exfiltration.",
                    "Large transfer is not theft without data context.",
                ],
            ))

        self.hypotheses.append(Hypothesis(
            id="HYP-ROOT-CAUSE-UNKNOWN",
            kind=HypothesisKind.ROOT_CAUSE,
            statement="Root cause remains unresolved; initial access may involve valid account misuse, phishing, public-facing application, third party, malware delivery, or benign administration.",
            supporting_event_ids=[],
            supporting_evidence_ids=all_support_ev,
            assumptions=["Current corpus lacks email, browser, cloud, memory, and full endpoint artifacts."],
            predictions=["Additional artifacts would narrow or eliminate initial-access hypotheses."],
            falsification_conditions=["Any single initial-access hypothesis becomes strongly supported by independent evidence."],
            status=HypothesisStatus.UNRESOLVED,
            confidence=0.20,
            limitations=["Do not select common initial access solely because it is frequent."],
        ))

    def build_ach_matrix(self) -> List[Dict[str, Any]]:
        matrix = []
        evidence_ids = sorted({eid for e in self.events.values() for eid in e.evidence_ids})
        for hyp in self.hypotheses:
            row = {
                "hypothesis_id": hyp.id,
                "statement": hyp.statement,
                "evidence_assessments": [],
            }
            for evid_id in evidence_ids:
                if evid_id in hyp.supporting_evidence_ids:
                    assessment = "CONSISTENT"
                elif evid_id in hyp.contradicting_evidence_ids:
                    assessment = "INCONSISTENT"
                else:
                    assessment = "NEUTRAL"
                row["evidence_assessments"].append({
                    "evidence_id": evid_id,
                    "assessment": assessment,
                })
            row["diagnostic_note"] = (
                "Simplified ACH-lite. Full ACH requires weighted diagnostic evidence and human review."
            )
            matrix.append(row)
        return matrix

    # -----------------------------------------------------------------
    # Scope / blast radius / incident state
    # -----------------------------------------------------------------

    def build_incident(self) -> None:
        supported = [e for e in self.events.values() if e.verification_state == VerificationState.SUPPORTED]
        partial = [e for e in self.events.values() if e.verification_state == VerificationState.PARTIALLY_SUPPORTED]

        proc_supported = [e for e in supported if e.event_type == "PROCESS_CREATION"]
        alert_supported = [e for e in supported if e.event_type == "ALERT"]
        net_partial_or_supported = [e for e in supported + partial if e.event_type == "NETWORK_CONNECTION"]

        if proc_supported and alert_supported:
            state = IncidentState.INCIDENT_SUPPORTED
        elif proc_supported or net_partial_or_supported:
            state = IncidentState.INCIDENT_CANDIDATE
        elif alert_supported or partial:
            state = IncidentState.SUSPICIOUS_ACTIVITY
        else:
            state = IncidentState.ALERT_ONLY

        confirmed_hosts = sorted({
            e.host_identifier for e in supported
            if e.host_identifier and e.event_type in {"PROCESS_CREATION", "NETWORK_CONNECTION", "FILE_PRESENT"}
        })
        potential_hosts = sorted({
            e.host_identifier for e in self.events.values()
            if e.host_identifier and e.host_identifier not in confirmed_hosts
            and e.verification_state in {VerificationState.PARTIALLY_SUPPORTED, VerificationState.SUPPORTED}
            and e.event_type in {"AUTHENTICATION", "DNS_QUERY", "ALERT", "USER_REPORT"}
        })
        affected_accounts = sorted({e.account_identifier for e in self.events.values() if e.account_identifier})

        first_observed = min((e.time.utc for e in self.events.values() if e.time.utc), default=None)
        earliest_supported = min((e.time.utc for e in supported if e.time.utc), default=None)
        detection = None
        for e in self.timeline:
            if e.event_type == "ALERT" and e.verification_state in {VerificationState.SUPPORTED, VerificationState.PARTIALLY_SUPPORTED}:
                detection = e.time.utc
                break

        severity = "MEDIUM"
        if proc_supported and net_partial_or_supported:
            severity = "MEDIUM_HIGH"
        if any(e.parsed_fields.get("account_type") == "PRIVILEGED" for e in self.events.values()):
            severity = "HIGH_PENDING_VALIDATION"

        self.incident = Incident(
            id=self.case.incident_id or new_id("INC-", self.case.case_id),
            case_id=self.case.case_id,
            title="Suspicious endpoint process execution with outbound connection candidate",
            state=state,
            severity=severity,
            first_observed=first_observed,
            earliest_supported_activity=earliest_supported,
            detection_time=detection,
            affected_assets=confirmed_hosts,
            potentially_affected_assets=potential_hosts,
            affected_accounts=affected_accounts,
            affected_data="UNKNOWN_NO_DIRECT_DATA_ACCESS_EVIDENCE",
            initial_access_state="CANDIDATE_MULTIPLE_HYPOTHESES",
            root_cause_state="ROOT_CAUSE_UNKNOWN",
            evidence_ids=sorted(self.evidence.keys()),
            findings=[
                "Process creation is supported by endpoint telemetry." if proc_supported else "Process creation is not fully supported.",
                "Outbound network connection is observed but malicious C2/exfiltration is not established." if net_partial_or_supported else "No supported outbound connection event.",
                "Authentication activity is observed but does not establish human operator identity.",
            ],
            unknowns=[
                "Initial access vector unresolved.",
                "Credential access unresolved due absent memory/credential-artifact evidence.",
                "Persistence unresolved due absent scheduled-task/service/startup artifact review.",
                "Data impact unresolved.",
                "Exfiltration unresolved.",
                "Real-person attribution not performed.",
            ],
            confidence=round(max((e.confidence for e in supported), default=0.0), 3),
        )

    # -----------------------------------------------------------------
    # Recommendations
    # -----------------------------------------------------------------

    def build_recommendations(self) -> None:
        if not self.incident:
            return

        confirmed = self.incident.affected_assets
        accounts = self.incident.affected_accounts
        proc_event_ids = [e.id for e in self.events.values() if e.event_type == "PROCESS_CREATION"]
        net_event_ids = [e.id for e in self.events.values() if e.event_type == "NETWORK_CONNECTION"]
        auth_event_ids = [e.id for e in self.events.values() if e.event_type == "AUTHENTICATION"]

        for host in confirmed:
            self.containment.append(Recommendation(
                id=new_id("REC-CONTAIN-", host),
                phase="CONTAINMENT",
                action="Isolate or restrict network access for affected endpoint after preserving volatile evidence.",
                target=host,
                rationale="Supported process execution and/or outbound connection evidence exists on this asset.",
                event_ids=proc_event_ids + net_event_ids,
                evidence_ids=sorted({eid for eid in (
                    [e.evidence_ids for e in self.events.values() if e.host_identifier == host]
                ) for x in eid}) if False else sorted({eid for e in self.events.values() if e.host_identifier == host for eid in e.evidence_ids}),
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                business_impact="May interrupt legitimate work; requires operations approval.",
                reversibility="Reversible after validation, but isolation may alter evidence state.",
                evidence_preservation_note="Preserve memory/process/network state before disruptive containment when authorized.",
                limitations=["Containment recommendation is not autonomous execution."],
            ))

        for account in accounts:
            self.containment.append(Recommendation(
                id=new_id("REC-ACCOUNT-", account),
                phase="CONTAINMENT",
                action="Review and conditionally disable/suspend account or revoke active sessions if compromise is supported and business impact accepted.",
                target=account,
                rationale="Account appears in authentication/execution timeline; identity misuse is a hypothesis, not established.",
                event_ids=auth_event_ids + proc_event_ids,
                evidence_ids=sorted({eid for e in self.events.values() if e.account_identifier == account for eid in e.evidence_ids}),
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                business_impact="May affect service automation or user productivity.",
                reversibility="Typically reversible with identity governance workflow.",
                evidence_preservation_note="Capture identity/session telemetry before revocation where feasible.",
                limitations=["Do not use recovered credentials.", "Do not equate account with person."],
            ))

        domain_iocs = [ioc for ioc in self.iocs.values() if ioc.ioc_type == IOCType.DOMAIN]
        for ioc in domain_iocs:
            self.containment.append(Recommendation(
                id=new_id("REC-BLOCK-", ioc.id),
                phase="CONTAINMENT",
                action="Consider blocking or sinkholing indicator only after CTI/validation and business-impact review.",
                target=ioc.value,
                rationale="Domain appeared in observed network/DNS telemetry; maliciousness is not independently confirmed.",
                evidence_ids=ioc.evidence_ids,
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                business_impact="May disrupt benign services sharing infrastructure.",
                reversibility="Usually reversible.",
                evidence_preservation_note="Preserve DNS/proxy/firewall logs before blocking.",
                limitations=["Do not interact with attacker infrastructure.", "Blocking is not attribution."],
            ))

        self.eradication.extend([
            Recommendation(
                id="REC-ERAD-PERSISTENCE",
                phase="ERADICATION",
                action="After evidence collection, review and remove unauthorized persistence artifacts if found.",
                target="Affected endpoints/accounts/cloud identities",
                rationale="Persistence not assessed in current corpus; remediation requires artifact evidence.",
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                limitations=["Do not remove artifacts before preservation if forensic value exists."],
            ),
            Recommendation(
                id="REC-ERAD-CREDENTIALS",
                phase="ERADICATION",
                action="Rotate credentials/secrets only where compromise or exposure is supported by evidence.",
                target="Affected accounts/service principals",
                rationale="Credential access is unresolved; proportional rotation requires validation.",
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                limitations=["Do not use recovered credentials.", "Avoid blanket rotation without impact review."],
            ),
            Recommendation(
                id="REC-ERAD-VULN",
                phase="ERADICATION",
                action="Patch or mitigate confirmed vulnerable component only after root-cause evidence supports it.",
                target="Affected software/services",
                rationale="Root cause unknown; patching without evidence may miss actual vector.",
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                limitations=["Root cause ≠ first alert."],
            ),
        ])

        self.recovery.extend([
            Recommendation(
                id="REC-REC-VALIDATE",
                phase="RECOVERY",
                action="Restore affected assets to known-good state and validate integrity before returning to production.",
                target=", ".join(confirmed) or "affected assets",
                rationale="Recovery requires validation, not merely alert cessation.",
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                limitations=["Do not declare clean solely because alert stopped."],
            ),
            Recommendation(
                id="REC-REC-MONITOR",
                phase="RECOVERY",
                action="Increase targeted monitoring for recurrence across endpoint, identity, network, cloud, and SaaS telemetry.",
                target="Affected assets/accounts/domains",
                rationale="Recurrence may indicate incomplete eradication or new activity.",
                approval=RecommendationApproval.AUTONOMOUS_ANALYTIC,
                limitations=["Monitoring recommendations must respect privacy and authorization."],
            ),
            Recommendation(
                id="REC-REC-BACKUP",
                phase="RECOVERY",
                action="Validate backup integrity and restoration path before relying on backups.",
                target="Backup systems for affected assets",
                rationale="Backup impact is unresolved in current corpus.",
                approval=RecommendationApproval.OPERATIONAL_CHANGE_APPROVAL_REQUIRED,
                limitations=["Do not test destructive restoration autonomously."],
            ),
        ])

    def build_next_actions(self) -> None:
        self.actions = [
            NextAction(
                id="ACT-VOLATILE",
                description="If authorized and operationally safe, preserve volatile evidence: memory, process state, network connections, logged-on sessions, container state.",
                priority=1,
                privacy_impact="MEDIUM_IF_AUTHORIZED",
                expected_gain=0.90,
                specialist="DFIRINT / VOLATILE_COLLECTION",
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-ENDPOINT-ARTIFACTS",
                description="Collect authorized endpoint artifacts for persistence, execution, scheduled tasks, services, startup items, registry/config equivalents, and file metadata.",
                priority=2,
                privacy_impact="LOW_IF_AUTHORIZED",
                expected_gain=0.85,
                specialist="DFIRINT / ENDPOINTFORENSICS",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-IDENTITY",
                description="Retrieve identity provider logs, MFA events, session metadata, token usage metadata, and conditional access signals for affected accounts.",
                priority=3,
                privacy_impact="MEDIUM_IF_AUTHORIZED",
                expected_gain=0.85,
                specialist="IDENTITYINT / DFIRINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-NETWORK",
                description="Review network telemetry, DNS, proxy, firewall, VPN, and cloud flow logs for destination context, volume, and repeated beacon-like patterns without assuming C2.",
                priority=4,
                privacy_impact="LOW_IF_AUTHORIZED",
                expected_gain=0.80,
                specialist="NETINT / DFIRINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-CLOUD-SAAS",
                description="Collect cloud audit and SaaS admin logs for affected principals, OAuth grants, sharing events, and configuration changes.",
                priority=5,
                privacy_impact="MEDIUM_IF_AUTHORIZED",
                expected_gain=0.75,
                specialist="CLOUDINT / SAASINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-MALWARE-SAFE",
                description="Route suspected malware artifacts to authorized MALINT workflow; hash, quarantine, and analyze safely without execution on investigator systems.",
                priority=6,
                privacy_impact="LOW",
                expected_gain=0.70,
                specialist="MALINT",
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-HUMAN-REVIEW",
                description="Require human review before containment, credential rotation, account disablement, blocking, reimaging, or public attribution.",
                priority=7,
                privacy_impact="PROTECTIVE",
                expected_gain=0.80,
                specialist=None,
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-NO-OFFENSE",
                description="Do not exploit systems, deploy malware, install persistence, use credentials, replay tokens, interact with C2, delete logs, or perform anti-forensics.",
                priority=99,
                privacy_impact="PROTECTIVE",
                expected_gain=0.0,
                specialist=None,
                requires_human_approval=False,
            ),
        ]

    def build_handoffs(self) -> None:
        self.handoffs = [
            {"specialist": "MALINT", "reason": "Safe malware metadata, sandbox-report ingestion, family context without execution."},
            {"specialist": "IOCINT", "reason": "IOC lifecycle, temporal validity, sharing/deduplication."},
            {"specialist": "TTPINT / CTI", "reason": "TTP enrichment and campaign context; not actor attribution from TTP alone."},
            {"specialist": "CREDINT", "reason": "Credential exposure handling; DFIRINT must not use recovered credentials."},
            {"specialist": "NETINT / DNSINT / PROXYINT", "reason": "Network forensic depth and destination reputation context."},
            {"specialist": "CLOUDINT / SAASINT", "reason": "Cloud/SaaS principal, audit log, OAuth, and resource context."},
            {"specialist": "LOGINT", "reason": "High-volume log normalization, retention, and correlation."},
            {"specialist": "FRAUDINT", "reason": "If payment/BEC/fraud patterns emerge from email/transaction evidence."},
            {"specialist": "LEGALINT / PRIVACY", "reason": "Breach notification, evidence handling, employee investigation boundaries."},
        ]

    # -----------------------------------------------------------------
    # Dual-AI review / summary
    # -----------------------------------------------------------------

    def dual_ai_review(self) -> Dict[str, Any]:
        issues: List[str] = []

        if self.validation_errors:
            issues.append("Chain-of-custody/tool validation warnings exist.")

        dependent_events = [
            e for e in self.events.values()
            if self.independence_state(e.source_ids) in {"DEPENDENT", "SINGLE_SOURCE"}
            and e.event_type in {"PROCESS_CREATION", "NETWORK_CONNECTION", "ALERT"}
        ]
        if dependent_events:
            issues.append("Some material events rely on single-source or dependent source families.")

        if not any(e.event_type == "PERSISTENCE_OBSERVED" for e in self.events.values()):
            issues.append("Persistence not assessed due absent artifacts; absence is not evidence of no persistence.")

        if not any(e.event_type == "CREDENTIAL_ACCESS_OBSERVED" for e in self.events.values()):
            issues.append("Credential access unresolved due absent memory/credential-artifact evidence.")

        if self.contradictions:
            issues.append(f"{len(self.contradictions)} temporal/source contradiction(s) remain open.")

        if any(h.status == HypothesisStatus.UNRESOLVED for h in self.hypotheses):
            issues.append("Root cause and initial access remain unresolved hypotheses.")

        if any(e.account_identifier for e in self.events.values()):
            issues.append("Account activity is not real-person attribution.")

        if not issues:
            verdict = "AGREE"
        elif len(issues) <= 5:
            verdict = "PARTIAL_AGREEMENT"
        else:
            verdict = "INSUFFICIENT_EVIDENCE"

        return {
            "primary_dfir_analyst": (
                "Endpoint telemetry supports suspicious process execution on HOST-01 and an outbound network connection candidate. "
                "Alerting and SIEM propagation are observed, but SIEM is derivative of EDR and not independent corroboration. "
                "Credential access, persistence, data impact, exfiltration, initial access, and root cause remain unresolved."
            ),
            "independent_forensic_skeptic_issues": issues,
            "verdict": verdict,
            "adversarial_checks": [
                "Is alert being treated as incident? No; incident state is evidence-gated.",
                "Is file presence treated as execution? No; separate events and limitations.",
                "Is account login treated as human operator? No; person attribution withheld.",
                "Is network connection treated as C2/exfil? No; hypothesis only.",
                "Are EDR/SIEM/SOAR copies treated as independent? No; source families tracked.",
                "Is absence of logs treated as absence of activity? No; coverage gaps recorded.",
                "Are containment actions autonomous? No; human/operational approval required.",
            ],
            "note": "AI agreement is analytical agreement, not independent forensic evidence.",
        }

    def analyst_summary(self, dual: Dict[str, Any]) -> str:
        inc = self.incident
        if not inc:
            return "No incident object built."

        lines = [
            f"INCIDENT STATUS: {inc.state.value}.",
            f"SEVERITY: {inc.severity}.",
            f"EARLIEST SUPPORTED ACTIVITY: {inc.earliest_supported_activity or 'UNKNOWN'}.",
            f"DETECTION TIME: {inc.detection_time or 'UNKNOWN'}.",
            f"AFFECTED HOSTS: {', '.join(inc.affected_assets) or 'NONE_CONFIRMED'}.",
            f"POTENTIALLY AFFECTED HOSTS: {', '.join(inc.potentially_affected_assets) or 'NONE'}.",
            f"AFFECTED ACCOUNTS: {', '.join(inc.affected_accounts) or 'NONE'}.",
            "INITIAL ACCESS: CANDIDATE_MULTIPLE_HYPOTHESES; not established.",
            "EXECUTION: Supported by endpoint telemetry for process creation on affected host.",
            "PERSISTENCE: Not assessed in current corpus; absence is not evidence.",
            "CREDENTIAL ACCESS: Unresolved; memory/credential artifacts unavailable.",
            "LATERAL MOVEMENT: Candidate only from account activity; not supported as malicious lateral movement.",
            "NETWORK ACTIVITY: Outbound connection observed; C2 not established.",
            "MALWARE CONTEXT: File/hash intelligence suggests suspicion; family/actor unresolved.",
            "DATA IMPACT: Unknown; no direct data-access evidence in current corpus.",
            "EXFILTRATION: Not supported; transfer candidate only.",
            "ROOT CAUSE: Unknown.",
            f"CONTAINMENT RECOMMENDATIONS: {len(self.containment)}; all operational changes require approval.",
            f"ERADICATION RECOMMENDATIONS: {len(self.eradication)}.",
            f"RECOVERY RECOMMENDATIONS: {len(self.recovery)}.",
            f"DUAL-AI REVIEW: {dual['verdict']}.",
            "PRIVACY/POLICY: Defensive authorized DFIR only. No exploitation, credential reuse, token replay, anti-forensics, evidence destruction, or autonomous production changes.",
            "NEXT ACTION: Preserve volatile evidence, collect identity/network/cloud artifacts, and require human review before containment/eradication.",
        ]
        return "\n".join(lines)

    # -----------------------------------------------------------------
    # Prepare
    # -----------------------------------------------------------------

    def prepare(self) -> None:
        self.validate_chain_of_custody()
        self.validate_sensor_coverage()
        self.detect_contradictions()
        self.fact_gate_events()
        self.build_timeline()
        self.build_iocs()
        self.build_ttps()
        self.build_hypotheses()
        self.build_incident()
        self.build_recommendations()
        self.build_next_actions()
        self.build_handoffs()


# =====================================================================
# SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-DFIRINT-001",
        task_id="TASK-DFIRINT-001",
        objective=(
            "Authorized defensive triage for suspicious endpoint alert on HOST-01 involving ACCOUNT-A, "
            "process execution, outbound connection candidate, and potential scope expansion to HOST-02."
        ),
        questions=[
            "Is an incident supported?",
            "What execution evidence exists?",
            "Does file presence prove execution?",
            "Does account authentication prove human operator?",
            "Is lateral movement supported?",
            "Is exfiltration supported?",
            "What evidence gaps remain?",
            "What containment actions are justified and what requires human approval?",
        ],
        scope=["authorized_defensive_dfir", "case_scoped", "no_offensive_action"],
        authorization="demo_authorized_incident_response",
        incident_id="INC-777",
        hosts=["HOST-01", "HOST-02"],
        accounts=["ACCOUNT-A"],
        time_range="2026-10-08",
        sample=True,
    )


def build_sample_dfir() -> DfirInt:
    d = DfirInt(sample_case())
    retrieved = now_iso()

    # Sources
    d.add_source(Source(
        id="SRC-EDR-ALERT",
        title="Authorized EDR detection: suspicious process tree",
        url="https://edr.example/detections/DET-777",
        source_type=SourceType.EDR,
        independence_group="EDR_ROOT",
        reliability=0.92,
        published_at="2026-10-08T14:06:00Z",
        retrieved_at=retrieved,
        notes="Primary endpoint detection telemetry.",
    ))
    d.add_source(Source(
        id="SRC-SIEM-ALERT",
        title="SIEM normalized alert derived from EDR",
        url="https://siem.example/alerts/ALT-777",
        source_type=SourceType.SIEM,
        independence_group="SIEM_DERIVED_EDR",
        reliability=0.65,
        derived_from="SRC-EDR-ALERT",
        published_at="2026-10-08T14:08:00Z",
        retrieved_at=retrieved,
        notes="Derivative alert pipeline; not independent corroboration of EDR event.",
    ))
    d.add_source(Source(
        id="SRC-WINDOWS-EVT",
        title="Authorized Windows event log export: process creation",
        url="https://logs.example/windows/HOST-01",
        source_type=SourceType.WINDOWS_EVENT_LOG,
        independence_group="WINDOWS_EVT_ROOT",
        reliability=0.94,
        published_at="2026-10-08T14:03:10Z",
        retrieved_at=retrieved,
        notes="Native OS event log; parser/version must be preserved.",
    ))
    d.add_source(Source(
        id="SRC-SYSMON",
        title="Authorized Sysmon-like process telemetry",
        url="https://sysmon.example/HOST-01",
        source_type=SourceType.SYSMON,
        independence_group="SYSMON_ROOT",
        reliability=0.90,
        published_at="2026-10-08T14:03:08Z",
        retrieved_at=retrieved,
        notes="Endpoint telemetry from separate collection pipeline.",
    ))
    d.add_source(Source(
        id="SRC-IDENTITY",
        title="Authorized identity provider authentication log",
        url="https://idp.example/logs/ACCOUNT-A",
        source_type=SourceType.IDENTITY_LOG,
        independence_group="IDP_ROOT",
        reliability=0.95,
        published_at="2026-10-08T14:01:00Z",
        retrieved_at=retrieved,
        notes="Authentication event; does not establish human operator.",
    ))
    d.add_source(Source(
        id="SRC-NET",
        title="Authorized network telemetry flow record",
        url="https://net.example/flows/FLOW-777",
        source_type=SourceType.NETWORK_TELEMETRY,
        independence_group="NET_ROOT",
        reliability=0.88,
        published_at="2026-10-08T14:07:00Z",
        retrieved_at=retrieved,
        notes="Connection metadata; content/exfiltration not established.",
    ))
    d.add_source(Source(
        id="SRC-DNS",
        title="Authorized DNS resolver log",
        url="https://dns.example/queries/external.example",
        source_type=SourceType.DNS_LOG,
        independence_group="DNS_ROOT",
        reliability=0.80,
        published_at="2026-10-08T14:04:00Z",
        retrieved_at=retrieved,
        notes="DNS query; not user intent or website visit.",
    ))
    d.add_source(Source(
        id="SRC-FILE",
        title="Authorized file metadata artifact",
        url="https://endpoint.example/files/F-777",
        source_type=SourceType.FILE_METADATA,
        independence_group="FILE_ROOT",
        reliability=0.72,
        published_at="2026-10-08T13:55:00Z",
        retrieved_at=retrieved,
        notes="File presence/metadata; presence alone is not execution.",
    ))
    d.add_source(Source(
        id="SRC-MALWARE-REPORT",
        title="Authorized malware reference report for file hash",
        url="https://malware.example/reports/HASH-777",
        source_type=SourceType.MALWARE_REPORT,
        independence_group="MALWARE_REPORT_ROOT",
        reliability=0.70,
        published_at="2026-10-08T14:20:00Z",
        retrieved_at=retrieved,
        notes="Hash/classification context; family/actor unresolved.",
    ))
    d.add_source(Source(
        id="SRC-USER-REPORT",
        title="Authorized user report",
        url="https://ticket.example/reports/USR-777",
        source_type=SourceType.USER_REPORT,
        independence_group="USER_ROOT",
        reliability=0.50,
        published_at="2026-10-08T14:25:00Z",
        retrieved_at=retrieved,
        notes="Human report; basis-of-knowledge and timezone uncertainty possible.",
    ))

    # Evidence
    d.add_evidence(Evidence(
        id="EV-EDR-ALERT",
        source_id="SRC-EDR-ALERT",
        artifact_type="edr_detection",
        classification=EvidenceClassification.PARSED_DERIVATIVE,
        acquisition_type=AcquisitionType.AUTHORIZED_ENDPOINT_COLLECTION,
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        acquired_at="2026-10-08T14:06:00Z",
        excerpt="EDR detected suspicious process P-4321 spawned by parent process P-111 on HOST-01 under ACCOUNT-A.",
        parsed_fields={
            "process_identifier": "P-4321",
            "parent_process_identifier": "P-111",
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
            "file_path": "C:\\ProgramData\\Example\\runner.dat",
            "domain": "external.example",
        },
        limitations=["EDR detection semantics must be read; detection does not always equal execution."],
    ))
    d.add_evidence(Evidence(
        id="EV-SIEM-ALERT",
        source_id="SRC-SIEM-ALERT",
        artifact_type="siem_alert",
        classification=EvidenceClassification.PARSED_DERIVATIVE,
        acquisition_type=AcquisitionType.AUTHORIZED_LOG_EXPORT,
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        acquired_at="2026-10-08T14:08:00Z",
        excerpt="SIEM ingested and normalized EDR detection DET-777.",
        parsed_fields={"upstream_evidence_id": "EV-EDR-ALERT"},
        limitations=["Derivative of EDR; not independent source."],
    ))
    d.add_evidence(Evidence(
        id="EV-WINDOWS-EVT",
        source_id="SRC-WINDOWS-EVT",
        artifact_type="windows_event_log",
        classification=EvidenceClassification.ORIGINAL_EVIDENCE,
        acquisition_type=AcquisitionType.AUTHORIZED_LOG_EXPORT,
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        acquired_at="2026-10-08T14:03:10Z",
        excerpt="Windows process-creation event observed for process P-4321 under ACCOUNT-A on HOST-01.",
        parsed_fields={
            "process_identifier": "P-4321",
            "parent_process_identifier": "P-111",
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        },
        limitations=["Event-log interpretation requires provider/host/account/session correlation."],
    ))
    d.add_evidence(Evidence(
        id="EV-SYSMON",
        source_id="SRC-SYSMON",
        artifact_type="endpoint_process_telemetry",
        classification=EvidenceClassification.ORIGINAL_EVIDENCE,
        acquisition_type=AcquisitionType.AUTHORIZED_ENDPOINT_COLLECTION,
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        acquired_at="2026-10-08T14:03:08Z",
        excerpt="Endpoint telemetry observed creation of process P-4321 with image path C:\\ProgramData\\Example\\runner.dat.",
        parsed_fields={
            "process_identifier": "P-4321",
            "file_path": "C:\\ProgramData\\Example\\runner.dat",
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        },
    ))
    d.add_evidence(Evidence(
        id="EV-IDENTITY",
        source_id="SRC-IDENTITY",
        artifact_type="identity_authentication_log",
        classification=EvidenceClassification.ORIGINAL_EVIDENCE,
        acquisition_type=AcquisitionType.AUTHORIZED_LOG_EXPORT,
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        acquired_at="2026-10-08T14:01:00Z",
        excerpt="ACCOUNT-A authenticated to HOST-01 from source 203.0.113.50; MFA result recorded as satisfied by policy.",
        parsed_fields={
            "source_ip": "203.0.113.50",
            "mfa": "SATISFIED_BY_POLICY",
            "account_type": "STANDARD_OR_SERVICE_UNRESOLVED",
        },
        limitations=["Authentication does not establish human operator."],
    ))
    d.add_evidence(Evidence(
        id="EV-IDENTITY-HOST2",
        source_id="SRC-IDENTITY",
        artifact_type="identity_authentication_log",
        classification=EvidenceClassification.ORIGINAL_EVIDENCE,
        acquisition_type=AcquisitionType.AUTHORIZED_LOG_EXPORT,
        host_identifier="HOST-02",
        account_identifier="ACCOUNT-A",
        acquired_at="2026-10-08T14:12:00Z",
        excerpt="ACCOUNT-A authenticated to HOST-02 after HOST-01 activity.",
        parsed_fields={"source_ip": "10.20.30.40"},
        limitations=["Account authentication to another host is not malicious lateral movement without process/admin evidence."],
    ))
    d.add_evidence(Evidence(
        id="EV-NET",
        source_id="SRC-NET",
        artifact_type="network_flow_record",
        classification=EvidenceClassification.ORIGINAL_EVIDENCE,
        acquisition_type=AcquisitionType.AUTHORIZED_NETWORK_CAPTURE,
        host_identifier="HOST-01",
        acquired_at="2026-10-08T14:07:00Z",
        excerpt="Outbound connection from HOST-01 process P-4321 to external.example:443 observed; bytes transferred modest.",
        parsed_fields={
            "process_identifier": "P-4321",
            "domain": "external.example",
            "ip": "198.51.100.77",
            "bytes_out": 18432,
        },
        limitations=["Connection metadata does not establish C2, exfiltration, or data content."],
    ))
    d.add_evidence(Evidence(
        id="EV-DNS",
        source_id="SRC-DNS",
        artifact_type="dns_query_log",
        classification=EvidenceClassification.ORIGINAL_EVIDENCE,
        acquisition_type=AcquisitionType.AUTHORIZED_LOG_EXPORT,
        host_identifier="HOST-01",
        acquired_at="2026-10-08T14:04:00Z",
        excerpt="DNS query for external.example resolved to 198.51.100.77.",
        parsed_fields={"domain": "external.example", "ip": "198.51.100.77"},
        limitations=["DNS query does not establish user intent or website visit."],
    ))
    d.add_evidence(Evidence(
        id="EV-FILE",
        source_id="SRC-FILE",
        artifact_type="file_metadata",
        classification=EvidenceClassification.ORIGINAL_EVIDENCE,
        acquisition_type=AcquisitionType.AUTHORIZED_ENDPOINT_COLLECTION,
        host_identifier="HOST-01",
        acquired_at="2026-10-08T13:55:00Z",
        excerpt="File runner.dat present at C:\\ProgramData\\Example\\runner.dat with hash and timestamps.",
        parsed_fields={
            "file_path": "C:\\ProgramData\\Example\\runner.dat",
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        },
        limitations=["File presence does not establish execution."],
    ))
    d.add_evidence(Evidence(
        id="EV-MALWARE-REPORT",
        source_id="SRC-MALWARE-REPORT",
        artifact_type="malware_reference_report",
        classification=EvidenceClassification.ANALYST_OUTPUT,
        acquisition_type=AcquisitionType.AUTHORIZED_LOG_EXPORT,
        acquired_at="2026-10-08T14:20:00Z",
        excerpt="Reference report associates file hash with generic malicious classification; family and actor unresolved.",
        parsed_fields={
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
            "classification": "GENERIC_SUSPICIOUS",
        },
        limitations=["Malware family is not actor attribution."],
    ))
    d.add_evidence(Evidence(
        id="EV-USER-REPORT",
        source_id="SRC-USER-REPORT",
        artifact_type="user_report",
        classification=EvidenceClassification.ANALYST_OUTPUT,
        acquisition_type=AcquisitionType.AUTHORIZED_LOG_EXPORT,
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        acquired_at="2026-10-08T14:25:00Z",
        excerpt="User reports noticing unusual activity around 2026-10-08T19:40:00+05:30 and recalls process start around 14:20 UTC.",
        parsed_fields={},
        limitations=["Human memory/timezone uncertainty possible."],
    ))

    # Observations
    d.add_observation(Observation(
        id="OBS-EDR-PROC",
        evidence_id="EV-EDR-ALERT",
        source_id="SRC-EDR-ALERT",
        statement="EDR observed suspicious process P-4321 on HOST-01 under ACCOUNT-A.",
        observed_at=parse_time("2026-10-08T14:03:00Z"),
        entities=["HOST-01", "ACCOUNT-A", "P-4321"],
    ))
    d.add_observation(Observation(
        id="OBS-WINEVT-PROC",
        evidence_id="EV-WINDOWS-EVT",
        source_id="SRC-WINDOWS-EVT",
        statement="Windows event log observed process creation for P-4321.",
        observed_at=parse_time("2026-10-08T14:03:10Z"),
        entities=["HOST-01", "ACCOUNT-A", "P-4321"],
    ))
    d.add_observation(Observation(
        id="OBS-SYSMON-PROC",
        evidence_id="EV-SYSMON",
        source_id="SRC-SYSMON",
        statement="Endpoint telemetry observed process P-4321 with file path/hash.",
        observed_at=parse_time("2026-10-08T14:03:08Z"),
        entities=["HOST-01", "P-4321"],
    ))

    # Claims
    d.add_claim(Claim(
        id="CLM-USER-TIME",
        source_id="SRC-USER-REPORT",
        statement="User recalls process start around 2026-10-08T14:20:00Z.",
        asserted_at=parse_time("around 2026-10-08T14:20:00Z"),
        status="SOURCE_CLAIM_ONLY",
        confidence=0.45,
        attributes={"event_id": "EVT-PROC-CREATE"},
    ))

    # Events
    d.add_event(Event(
        id="EVT-FILE-PRESENT",
        case_id=d.case.case_id,
        event_type="FILE_PRESENT",
        subtype="SUSPICIOUS_FILE_METADATA",
        title="File present on HOST-01",
        description="File metadata shows runner.dat present before process creation.",
        time=parse_time("2026-10-08T13:55:00Z"),
        host_identifier="HOST-01",
        file_identifier="F-777",
        source_ids=["SRC-FILE"],
        evidence_ids=["EV-FILE"],
        parsed_fields={
            "file_path": "C:\\ProgramData\\Example\\runner.dat",
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        },
        limitations=["Presence only; execution not established by this event."],
    ))
    d.add_event(Event(
        id="EVT-AUTH-HOST1",
        case_id=d.case.case_id,
        event_type="AUTHENTICATION",
        subtype="ACCOUNT_LOGIN",
        title="ACCOUNT-A authenticated to HOST-01",
        description="Identity log shows authentication before process creation.",
        time=parse_time("2026-10-08T14:01:00Z"),
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        source_ids=["SRC-IDENTITY"],
        evidence_ids=["EV-IDENTITY"],
        parsed_fields={"source_ip": "203.0.113.50", "mfa": "SATISFIED_BY_POLICY"},
        limitations=["Authentication does not establish human operator."],
    ))
    d.add_event(Event(
        id="EVT-PROC-CREATE",
        case_id=d.case.case_id,
        event_type="PROCESS_CREATION",
        subtype="SUSPICIOUS_PROCESS",
        title="Process P-4321 created on HOST-01",
        description="EDR, Windows event log, and endpoint telemetry support process creation.",
        time=parse_time("2026-10-08T14:03:00Z"),
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        process_identifier="P-4321",
        file_identifier="F-777",
        source_ids=["SRC-EDR-ALERT", "SRC-WINDOWS-EVT", "SRC-SYSMON"],
        evidence_ids=["EV-EDR-ALERT", "EV-WINDOWS-EVT", "EV-SYSMON"],
        observation_ids=["OBS-EDR-PROC", "OBS-WINEVT-PROC", "OBS-SYSMON-PROC"],
        claim_ids=["CLM-USER-TIME"],
        parsed_fields={
            "process_identifier": "P-4321",
            "parent_process_identifier": "P-111",
            "file_hash": "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
            "file_path": "C:\\ProgramData\\Example\\runner.dat",
        },
        limitations=["Execution evidence supports process creation, not intent or actor attribution."],
    ))
    d.add_event(Event(
        id="EVT-DNS-QUERY",
        case_id=d.case.case_id,
        event_type="DNS_QUERY",
        subtype="DOMAIN_RESOLUTION",
        title="DNS query for external.example",
        description="Resolver log shows query for external.example.",
        time=parse_time("2026-10-08T14:04:00Z"),
        host_identifier="HOST-01",
        dns_identifier="DNS-777",
        source_ids=["SRC-DNS"],
        evidence_ids=["EV-DNS"],
        parsed_fields={"domain": "external.example", "ip": "198.51.100.77"},
        limitations=["DNS query does not establish user intent or malicious infrastructure."],
    ))
    d.add_event(Event(
        id="EVT-NET-CONN",
        case_id=d.case.case_id,
        event_type="NETWORK_CONNECTION",
        subtype="OUTBOUND_TLS",
        title="Outbound connection from HOST-01 to external.example",
        description="Network telemetry shows process P-4321 connecting to external.example:443.",
        time=parse_time("2026-10-08T14:05:30Z"),
        host_identifier="HOST-01",
        process_identifier="P-4321",
        network_identifier="FLOW-777",
        source_ids=["SRC-NET", "SRC-DNS"],
        evidence_ids=["EV-NET", "EV-DNS"],
        parsed_fields={
            "process_identifier": "P-4321",
            "domain": "external.example",
            "ip": "198.51.100.77",
            "bytes_out": 18432,
        },
        limitations=["Connection is not C2. Modest bytes do not establish exfiltration."],
    ))
    d.add_event(Event(
        id="EVT-EDR-ALERT",
        case_id=d.case.case_id,
        event_type="ALERT",
        subtype="EDR_DETECTION",
        title="EDR alert generated",
        description="EDR generated detection for suspicious process tree.",
        time=parse_time("2026-10-08T14:06:00Z"),
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        source_ids=["SRC-EDR-ALERT"],
        evidence_ids=["EV-EDR-ALERT"],
        parsed_fields={"detection_id": "DET-777"},
        limitations=["Alert is not incident confirmation."],
    ))
    d.add_event(Event(
        id="EVT-SIEM-INGEST",
        case_id=d.case.case_id,
        event_type="SIEM_INGEST",
        subtype="ALERT_NORMALIZATION",
        title="SIEM ingested EDR alert",
        description="SIEM normalized and alerted on upstream EDR detection.",
        time=parse_time("2026-10-08T14:08:00Z"),
        host_identifier="HOST-01",
        source_ids=["SRC-SIEM-ALERT"],
        evidence_ids=["EV-SIEM-ALERT"],
        parsed_fields={"upstream_detection_id": "DET-777"},
        limitations=["Derivative source; not independent corroboration."],
    ))
    d.add_event(Event(
        id="EVT-AUTH-HOST2",
        case_id=d.case.case_id,
        event_type="AUTHENTICATION",
        subtype="ACCOUNT_LOGIN",
        title="ACCOUNT-A authenticated to HOST-02",
        description="Identity log shows subsequent authentication to another host.",
        time=parse_time("2026-10-08T14:12:00Z"),
        host_identifier="HOST-02",
        account_identifier="ACCOUNT-A",
        source_ids=["SRC-IDENTITY"],
        evidence_ids=["EV-IDENTITY-HOST2"],
        parsed_fields={"source_ip": "10.20.30.40"},
        limitations=["Authentication alone is not malicious lateral movement."],
    ))
    d.add_event(Event(
        id="EVT-USER-REPORT",
        case_id=d.case.case_id,
        event_type="USER_REPORT",
        subtype="HUMAN_OBSERVATION",
        title="User reported unusual activity",
        description="User reported unusual activity; local timezone preserved and normalized to UTC.",
        time=parse_time("2026-10-08T19:40:00+05:30", notes="Original local time preserved."),
        host_identifier="HOST-01",
        account_identifier="ACCOUNT-A",
        source_ids=["SRC-USER-REPORT"],
        evidence_ids=["EV-USER-REPORT"],
        claim_ids=["CLM-USER-TIME"],
        limitations=["Human report; memory/timezone uncertainty possible."],
    ))

    d.prepare()
    return d


# =====================================================================
# RESULT BUILDER
# =====================================================================

def graph_version_hash(d: DfirInt) -> str:
    seed_obj = {
        "evidence": sorted((eid, e.hash_sha256, e.source_id) for eid, e in d.evidence.items()),
        "events": sorted((eid, e.event_type, e.verification_state.value, round(float(e.confidence), 3)) for eid, e in d.events.items()),
        "incident": d.incident.state.value if d.incident else "NONE",
    }
    return sha256_short(json.dumps(jsonable(seed_obj), sort_keys=True))


def build_source_graph(d: DfirInt) -> Dict[str, Any]:
    edges = []
    for src in d.sources.values():
        if src.derived_from:
            edges.append({
                "source": src.derived_from,
                "target": src.id,
                "relationship_type": "DERIVED_FROM",
            })
    return {
        "nodes": [s.id for s in d.sources.values()],
        "edges": edges,
    }


def build_source_dependency_graph(d: DfirInt) -> Dict[str, List[str]]:
    families: Dict[str, List[str]] = defaultdict(list)
    for sid in d.sources:
        fam = d.get_source_family(sid) or "UNKNOWN"
        families[fam].append(sid)
    return {k: sorted(v) for k, v in families.items()}


def build_evidence_inventory(d: DfirInt) -> List[Dict[str, Any]]:
    out = []
    for ev in d.evidence.values():
        out.append({
            "evidence_id": ev.id,
            "source_id": ev.source_id,
            "artifact_type": ev.artifact_type,
            "classification": ev.classification.value,
            "acquisition_type": ev.acquisition_type.value,
            "host_identifier": ev.host_identifier,
            "account_identifier": ev.account_identifier,
            "acquired_at": ev.acquired_at,
            "hash_sha256": ev.hash_sha256,
            "tool": ev.tool,
            "tool_version": ev.tool_version,
            "collector": ev.collector,
            "chain_of_custody_entries": len(ev.chain_of_custody),
            "parser_version": ev.parser_version,
            "limitations": ev.limitations,
        })
    return out


def build_chain_of_custody_status(d: DfirInt) -> Dict[str, Any]:
    ok = []
    warn = []
    for ev in d.evidence.values():
        missing = []
        if not ev.hash_sha256:
            missing.append("hash")
        if not ev.acquired_at:
            missing.append("acquired_at")
        if not ev.collector:
            missing.append("collector")
        if not ev.tool:
            missing.append("tool")
        if not ev.tool_version:
            missing.append("tool_version")
        if not ev.chain_of_custody:
            missing.append("custody_entries")
        if missing:
            warn.append({"evidence_id": ev.id, "missing": missing})
        else:
            ok.append(ev.id)
    return {
        "complete_evidence_ids": sorted(ok),
        "warnings": warn,
        "note": "Hash proves stored artifact integrity, not authenticity, truth, maliciousness, or ownership.",
    }


def build_timeline_payload(d: DfirInt) -> List[Dict[str, Any]]:
    out = []
    for ev in d.timeline:
        out.append({
            "event_id": ev.id,
            "utc_time": ev.time.utc,
            "original_time": ev.time.original,
            "timezone": ev.time.timezone,
            "precision": ev.time.precision.value,
            "event_type": ev.event_type,
            "subtype": ev.subtype,
            "host": ev.host_identifier,
            "account": ev.account_identifier,
            "process": ev.process_identifier,
            "verification_state": ev.verification_state.value,
            "confidence": ev.confidence,
            "source_ids": ev.source_ids,
            "evidence_ids": ev.evidence_ids,
            "limitations": ev.limitations,
        })
    return out


def build_business_impact(d: DfirInt) -> Dict[str, str]:
    return {
        "confidentiality": "UNKNOWN_NO_DIRECT_DATA_ACCESS_EVIDENCE",
        "integrity": "POTENTIAL_ENDPOINT_INTEGRITY_RISK_PENDING_VALIDATION",
        "availability": "NO_SUPPORTED_AVAILABILITY_IMPACT",
        "identity": "ACCOUNT_ACTIVITY_OBSERVED_OPERATOR_IDENTITY_UNRESOLVED",
        "financial": "UNKNOWN",
        "operational": "CONTAINMENT_MAY_REQUIRE_OPERATIONAL_REVIEW",
        "regulatory": "LEGAL_REVIEW_REQUIRED_IF_PERSONAL_DATA_OR_BREACH_ISOLATED",
        "customer": "UNKNOWN",
        "reputation": "UNKNOWN",
    }


def build_result(d: DfirInt, status: Status) -> Dict[str, Any]:
    dual = d.dual_ai_review()
    summary = d.analyst_summary(dual)
    ach = d.build_ach_matrix()

    source_families = build_source_dependency_graph(d)
    event_independence = {eid: d.independence_state(ev.source_ids) for eid, ev in d.events.items()}

    supported_facts = [
        {
            "fact_id": f"FACT-{ev.id}",
            "statement": (
                f"Event {ev.id} ({ev.subtype or ev.event_type}) is {ev.verification_state.value} "
                f"at {ev.time.utc or ev.time.original} with confidence {ev.confidence}."
            ),
            "event_id": ev.id,
            "source_ids": ev.source_ids,
            "evidence_ids": ev.evidence_ids,
            "confidence": ev.confidence,
            "verification_state": ev.verification_state.value,
            "limitations": ev.limitations,
        }
        for ev in d.events.values()
        if ev.verification_state in {VerificationState.SUPPORTED, VerificationState.PARTIALLY_SUPPORTED}
    ]

    replay_manifest = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "graph_version": graph_version_hash(d),
        "evidence_ladder": "RAW_ARTIFACT -> PARSED_ARTIFACT -> OBSERVATION -> CORRELATED_EVENT -> SUPPORTED_FACT -> INCIDENT_FINDING -> ROOT_CAUSE_HYPOTHESIS -> VERIFIED_INCIDENT_ASSESSMENT",
        "original_vs_working_copy": {
            "original_evidence_ids": [eid for eid, ev in d.evidence.items() if ev.classification == EvidenceClassification.ORIGINAL_EVIDENCE],
            "working_copy_ids": [eid for eid, ev in d.evidence.items() if ev.classification == EvidenceClassification.FORENSIC_WORKING_COPY],
            "parsed_derivative_ids": [eid for eid, ev in d.evidence.items() if ev.classification == EvidenceClassification.PARSED_DERIVATIVE],
            "analyst_output_ids": [eid for eid, ev in d.evidence.items() if ev.classification == EvidenceClassification.ANALYST_OUTPUT],
        },
        "hashing_note": "SHA-256 hashes are computed over synthetic demo representations. In real DFIR, hash original acquired artifacts and verify working copies.",
        "source_lineage": source_families,
        "event_independence": event_independence,
        "causal_guard": "Timeline ordering is not causation. Causal/incident conclusions require mechanism and independent evidence.",
        "policy_exclusions": [
            "No exploitation.",
            "No malware deployment.",
            "No persistence installation.",
            "No credential use/replay.",
            "No anti-forensics instruction.",
            "No evidence destruction.",
            "No autonomous production containment.",
        ],
    }

    return {
        "case_id": d.case.case_id,
        "task_id": d.case.task_id,
        "incident_id": d.incident.id if d.incident else d.case.incident_id,
        "objective": d.case.objective,
        "questions": d.case.questions,
        "scope": d.case.scope,
        "authorization": d.case.authorization,
        "status": status.value,
        "incident_state": d.incident.state.value if d.incident else IncidentState.INCONCLUSIVE.value,
        "severity": d.incident.severity if d.incident else "UNKNOWN",
        "source_ids": sorted(d.sources.keys()),
        "evidence_ids": sorted(d.evidence.keys()),
        "chain_of_custody_status": build_chain_of_custody_status(d),
        "evidence_inventory": build_evidence_inventory(d),
        "source_graph": build_source_graph(d),
        "source_dependency_graph": source_families,
        "hosts": sorted({ev.host_identifier for ev in d.events.values() if ev.host_identifier}),
        "devices": sorted({ev.device_identifier for ev in d.evidence.values() if ev.device_identifier}),
        "accounts": sorted({ev.account_identifier for ev in d.events.values() if ev.account_identifier}),
        "identities": sorted({ev.account_identifier for ev in d.events.values() if ev.account_identifier}),
        "cloud_resources": [],
        "saas_accounts": [],
        "containers": [],
        "files": sorted({ev.file_identifier for ev in d.events.values() if ev.file_identifier} | {
            pf.get("file_path", "") for ev in d.evidence.values() for pf in [ev.parsed_fields] if pf.get("file_path")
        }),
        "hashes": sorted({ioc.value for ioc in d.iocs.values() if ioc.ioc_type == IOCType.FILE_HASH}),
        "processes": sorted({ev.process_identifier for ev in d.events.values() if ev.process_identifier}),
        "process_trees": [
            {
                "event_id": ev.id,
                "process_identifier": ev.process_identifier,
                "parent_process_identifier": ev.parsed_fields.get("parent_process_identifier"),
                "host_identifier": ev.host_identifier,
                "evidence_ids": ev.evidence_ids,
            }
            for ev in d.events.values()
            if ev.event_type == "PROCESS_CREATION"
        ],
        "services": [],
        "scheduled_tasks": [],
        "persistence_artifacts": [],
        "authentication_events": [ev.id for ev in d.events.values() if ev.event_type == "AUTHENTICATION"],
        "network_connections": [ev.id for ev in d.events.values() if ev.event_type == "NETWORK_CONNECTION"],
        "dns_events": [ev.id for ev in d.events.values() if ev.event_type == "DNS_QUERY"],
        "email_events": [],
        "browser_artifacts": [],
        "cloud_events": [],
        "identity_events": [ev.id for ev in d.events.values() if ev.event_type == "AUTHENTICATION"],
        "ioc_sightings": list(d.iocs.values()),
        "malware_context": [
            {
                "evidence_id": "EV-MALWARE-REPORT",
                "classification": "GENERIC_SUSPICIOUS",
                "family": "UNRESOLVED",
                "actor": "NOT_ATTRIBUED",
                "caution": "Malware family is not threat actor attribution.",
            }
        ],
        "ransomware_context": [],
        "ttp_observations": d.ttps,
        "attack_mappings": d.ttps,
        "execution_evidence": [ev.id for ev in d.events.values() if ev.event_type == "PROCESS_CREATION"],
        "credential_access_evidence": [],
        "lateral_movement_evidence": [
            {
                "status": "LATERAL_MOVEMENT_CANDIDATE_NOT_SUPPORTED",
                "basis_event_ids": ["EVT-AUTH-HOST2"],
                "limitation": "Account authentication to another host is not malicious lateral movement without remote admin/process evidence.",
            }
        ],
        "remote_access_evidence": [],
        "data_staging_evidence": [],
        "exfiltration_evidence": [
            {
                "status": "INCONCLUSIVE_TRANSFER_CANDIDATE_ONLY",
                "event_ids": ["EVT-NET-CONN"],
                "limitation": "Outbound connection does not establish exfiltration.",
            }
        ],
        "initial_access_hypotheses": [h for h in d.hypotheses if h.kind == HypothesisKind.INITIAL_ACCESS],
        "root_cause_hypotheses": [h for h in d.hypotheses if h.kind == HypothesisKind.ROOT_CAUSE],
        "affected_assets": d.incident.affected_assets if d.incident else [],
        "potentially_affected_assets": d.incident.potentially_affected_assets if d.incident else [],
        "affected_accounts": d.incident.affected_accounts if d.incident else [],
        "data_impact": d.incident.affected_data if d.incident else "UNKNOWN",
        "blast_radius": {
            "confirmed_assets": d.incident.affected_assets if d.incident else [],
            "potential_assets": d.incident.potentially_affected_assets if d.incident else [],
            "note": "Blast radius is evidence-based scope for response, not offensive targeting.",
        },
        "business_impact": build_business_impact(d),
        "timeline": build_timeline_payload(d),
        "sensor_coverage": {
            "available_source_types": sorted({s.source_type.value for s in d.sources.values()}),
            "source_families": source_families,
            "known_gaps": [g.description for g in d.gaps],
        },
        "logging_gaps": [g.description for g in d.gaps if g.gap_type in {GapType.SENSOR_GAP, GapType.LOG_RETENTION_GAP, GapType.CHAIN_OF_CUSTODY_GAP}],
        "observations": list(d.observations.values()),
        "claims": list(d.claims.values()),
        "candidate_facts": [
            {
                "event_id": ev.id,
                "statement": ev.title,
                "verification_state": ev.verification_state.value,
                "confidence": ev.confidence,
            }
            for ev in d.events.values()
        ],
        "supported_facts": [f for f in supported_facts if f["verification_state"] == VerificationState.SUPPORTED.value],
        "partial_facts": [f for f in supported_facts if f["verification_state"] == VerificationState.PARTIALLY_SUPPORTED.value],
        "disputed_facts": [
            {
                "event_id": ev.id,
                "statement": ev.title,
                "verification_state": ev.verification_state.value,
                "contradictions": [c.id for c in d.contradictions if ev.id in c.event_ids],
            }
            for ev in d.events.values()
            if ev.verification_state == VerificationState.DISPUTED
        ],
        "source_reliability": {sid: s.reliability for sid, s in d.sources.items()},
        "source_bias": {sid: s.notes for sid, s in d.sources.items()},
        "source_limitations": {sid: [s.notes] for sid, s in d.sources.items() if s.notes},
        "source_pedigree": {sid: d.get_source_family(sid) for sid in d.sources},
        "source_independence": {
            "event_independence": event_independence,
            "source_families": source_families,
        },
        "contradictions": d.contradictions,
        "hypotheses": d.hypotheses,
        "ach_matrix": ach,
        "falsification_results": [
            {
                "hypothesis_id": h.id,
                "status": h.status.value,
                "falsification_conditions": h.falsification_conditions,
                "limitations": h.limitations,
            }
            for h in d.hypotheses
        ],
        "containment_recommendations": d.containment,
        "eradication_recommendations": d.eradication,
        "recovery_recommendations": d.recovery,
        "privacy_flags": [
            PrivacyFlag.CASE_SCOPED.value,
            PrivacyFlag.AUTHORIZED_SCOPE_ONLY.value,
            PrivacyFlag.NO_RAW_EVIDENCE_EXPORT.value,
            PrivacyFlag.NO_PRIVATE_CONTENT_INSPECTION.value,
            PrivacyFlag.NO_CREDENTIAL_REUSE.value,
            PrivacyFlag.NO_TOKEN_REPLAY.value,
            PrivacyFlag.NO_ANTI_FORENSICS_GUIDANCE.value,
            PrivacyFlag.NO_OFFENSIVE_ACTION.value,
        ],
        "legal_flags": [
            "Human/legal review required before breach notification, employee misconduct attribution, or law-enforcement engagement."
        ],
        "unknowns": (d.incident.unknowns if d.incident else []) + [h.statement for h in d.hypotheses if h.status == HypothesisStatus.UNRESOLVED],
        "knowledge_gaps": d.gaps,
        "recommended_next_actions": d.actions,
        "specialist_handoffs": d.handoffs,
        "limitations": [
            "Local synthetic demo; no live forensic acquisition.",
            "Defensive DFIR reasoning only; no offensive action.",
            "Account activity is not real-person attribution.",
            "File presence is not execution.",
            "Alert is not incident confirmation.",
            "Connection is not C2 or exfiltration.",
            "Absence of logs is not absence of activity.",
            "Containment/eradication/recovery require human/operational approval.",
        ] + d.validation_errors,
        "analyst_summary": summary,
        "dual_ai_review": dual,
        "replay_manifest": replay_manifest,
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline() -> Dict[str, Any]:
    d = build_sample_dfir()
    return build_result(d, Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    d = DfirInt(case)

    d.gaps.append(KnowledgeGap(
        id="GAP-NO-EVIDENCE",
        gap_type=GapType.MISSING_EVIDENCE,
        description="No authorized evidence corpus, logs, EDR/SIEM exports, disk/memory/pcap metadata, or cloud/SaaS audit records are configured.",
        importance="HIGH",
        recommended_source="Connect authorized DFIR evidence sources or provide local sanitized JSON evidence corpus.",
        specialist="DFIRINT / EVIDENCEHANDLING",
        expected_information_value=0.95,
    ))

    d.actions = [NextAction(
        id="ACT-CONFIGURE-EVIDENCE",
        description=(
            "Configure authorized evidence connectors or supply sanitized local evidence. "
            "Do not exploit systems, use credentials, replay tokens, delete logs, or perform anti-forensics."
        ),
        priority=1,
        privacy_impact="LOW",
        expected_gain=0.95,
        specialist=None,
        requires_human_approval=False,
    )]

    d.handoffs = []
    d.incident = Incident(
        id=case.incident_id or "INC-UNRESOLVED",
        case_id=case.case_id,
        title="Unresolved DFIR triage",
        state=IncidentState.INCONCLUSIVE,
        severity="UNKNOWN",
        unknowns=["No evidence configured."],
        confidence=0.0,
    )

    dual = {
        "primary_dfir_analyst": "No evidence available.",
        "independent_forensic_skeptic_issues": [
            "No sources configured.",
            "No chain of custody available.",
            "No events can be validated.",
            "No incident conclusion is possible.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "AI agreement is not independent forensic evidence.",
    }

    summary = (
        "DFIR UNRESOLVED: No configured evidence corpus. "
        "No hosts, processes, malware, events, timestamps, or causes were fabricated. "
        "Provide authorized evidence or run sample mode."
    )

    result = build_result(d, Status.BLOCKED_CONFIGURATION)
    result["analyst_summary"] = summary
    result["dual_ai_review"] = dual
    return result


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "incident_id": case.incident_id,
        "objective": case.objective,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited DFIR request detected. DFIRINT supports authorized defensive forensics and incident response only. "
            "It does not exploit systems, deploy malware, install persistence, use credentials, replay tokens, "
            "bypass MFA, disable security tools, delete logs, tamper with evidence, or teach anti-forensics."
        ),
        "lawful_alternatives": [
            "Preserve and hash authorized evidence.",
            "Analyze authorized logs/telemetry for execution, persistence, identity, network, cloud, and data impact.",
            "Generate defensive containment/eradication/recovery recommendations requiring human approval.",
            "Route malware analysis to authorized MALINT workflow without execution on investigator systems.",
            "Use CTI for threat-actor context; do not attribute from TTP or IOC alone.",
        ],
        "privacy_flags": [
            PrivacyFlag.NO_OFFENSIVE_ACTION.value,
            PrivacyFlag.NO_CREDENTIAL_REUSE.value,
            PrivacyFlag.NO_TOKEN_REPLAY.value,
            PrivacyFlag.NO_ANTI_FORENSICS_GUIDANCE.value,
        ],
        "limitations": [
            "No forensic analysis performed.",
            "No evidence fabricated.",
            "No private data accessed.",
        ],
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.questions,
            *case.hosts,
            *case.accounts,
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
            "TRACEATLAS DFIRINT local defensive evidence-first digital forensics and incident response pipeline. "
            "Sample mode uses synthetic authorized-record-style data."
        )
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic DFIRINT sample.")
    parser.add_argument("--objective", help="Defensive DFIR objective.")
    parser.add_argument("--question", action="append", default=[], help="Analytic question. Repeatable.")
    parser.add_argument("--host", action="append", default=[], help="Host identifier. Repeatable.")
    parser.add_argument("--account", action="append", default=[], help="Account identifier. Repeatable.")
    parser.add_argument("--incident-id", help="Incident ID.")
    parser.add_argument("--time-range", help="Time range hint, e.g. 2026-10-08.")

    args = parser.parse_args()

    if args.sample or not args.objective:
        case = sample_case()
    else:
        case = Case(
            case_id=new_id("CASE-", args.objective),
            task_id=new_id("TASK-", args.objective),
            objective=args.objective,
            questions=args.question,
            hosts=args.host,
            accounts=args.account,
            incident_id=args.incident_id or "",
            time_range=args.time_range,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()