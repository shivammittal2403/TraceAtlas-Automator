#!/usr/bin/env python3
"""
TRACEATLAS / SBOMINT — Local defensive software bill-of-materials intelligence pipeline.

IMPORTANT SAFETY / POLICY NOTES:
- This is a local demo implementation.
- It does NOT access live package registries, artifact registries, CI systems, container registries,
  runtime environments, private repositories, or production systems.
- It does NOT download, install, execute, or run scripts from packages.
- It does NOT publish malicious packages, poison dependencies, perform dependency confusion,
  typosquat, compromise registries/repositories/CI/CD, tamper with SBOMs, forge attestations/signatures,
  use signing keys, exploit vulnerable components, use credentials found in build artifacts,
  disable security controls, or help evade software-integrity verification.
- It supports authorized, defensive, evidence-first SBOM/software-component intelligence only.
- Sample data is synthetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


PIPELINE_VERSION = "0.1.0-sbomint-defensive-safe-demo"
DEFAULT_AS_OF = "2026-10-09T00:00:00Z"


# =====================================================================
# ENUMS
# =====================================================================

class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SBOM_INVALID = "SBOM_INVALID"
    SBOM_STALE = "SBOM_STALE"
    COMPONENT_UNRESOLVED = "COMPONENT_UNRESOLVED"
    VERSION_UNRESOLVED = "VERSION_UNRESOLVED"
    DEPENDENCY_UNRESOLVED = "DEPENDENCY_UNRESOLVED"
    PURL_UNRESOLVED = "PURL_UNRESOLVED"
    CPE_AMBIGUOUS = "CPE_AMBIGUOUS"
    RUNTIME_STATE_UNKNOWN = "RUNTIME_STATE_UNKNOWN"
    VEX_UNRESOLVED = "VEX_UNRESOLVED"
    BLOCKED_CONFIGURATION = "BLOCKED_CONFIGURATION"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class SourceType(str, Enum):
    CYCLONEDX_SBOM = "CYCLONEDX_SBOM"
    SPDX_SBOM = "SPDX_SBOM"
    SWID = "SWID"
    PACKAGE_MANIFEST = "PACKAGE_MANIFEST"
    LOCKFILE = "LOCKFILE"
    CONTAINER_SBOM = "CONTAINER_SBOM"
    CONTAINER_METADATA = "CONTAINER_METADATA"
    OS_PACKAGE_INVENTORY = "OS_PACKAGE_INVENTORY"
    FIRMWARE_SBOM = "FIRMWARE_SBOM"
    RUNTIME_INVENTORY = "RUNTIME_INVENTORY"
    VEX = "VEX"
    ATTESTATION = "ATTESTATION"
    SIGNATURE = "SIGNATURE"
    VULNERABILITY_DATA = "VULNERABILITY_DATA"
    LICENSE_DATABASE = "LICENSE_DATABASE"
    EOL_DATABASE = "EOL_DATABASE"
    PACKAGE_REGISTRY = "PACKAGE_REGISTRY"
    REPOSITORY_METADATA = "REPOSITORY_METADATA"
    BUILD_METADATA = "BUILD_METADATA"
    ARTIFACT_REGISTRY = "ARTIFACT_REGISTRY"
    SCA_EXPORT = "SCA_EXPORT"
    CMDB = "CMDB"
    OTHER = "OTHER"


class SBOMFormat(str, Enum):
    CYCLONEDX = "CYCLONEDX"
    SPDX = "SPDX"
    SWID = "SWID"
    MANIFEST = "MANIFEST"
    LOCKFILE = "LOCKFILE"
    CONTAINER_SBOM = "CONTAINER_SBOM"
    OS_PACKAGES = "OS_PACKAGES"
    FIRMWARE_SBOM = "FIRMWARE_SBOM"
    UNKNOWN = "UNKNOWN"


class FreshnessState(str, Enum):
    CURRENT = "CURRENT"
    RECENT = "RECENT"
    AGING = "AGING"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class ComponentType(str, Enum):
    APPLICATION = "APPLICATION"
    LIBRARY = "LIBRARY"
    FRAMEWORK = "FRAMEWORK"
    PACKAGE = "PACKAGE"
    MODULE = "MODULE"
    PLUGIN = "PLUGIN"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"
    FIRMWARE = "FIRMWARE"
    DEVICE_COMPONENT = "DEVICE_COMPONENT"
    FILE = "FILE"
    CONTAINER = "CONTAINER"
    IMAGE = "IMAGE"
    SERVICE = "SERVICE"
    MIDDLEWARE = "MIDDLEWARE"
    DRIVER = "DRIVER"
    RUNTIME = "RUNTIME"
    TOOL = "TOOL"
    OTHER = "OTHER"


class Scope(str, Enum):
    RUNTIME = "RUNTIME"
    BUILD = "BUILD"
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    OPTIONAL = "OPTIONAL"
    PROVIDED = "PROVIDED"
    REQUIRED = "REQUIRED"
    UNKNOWN = "UNKNOWN"


class ProvenanceState(str, Enum):
    STRONG = "STRONG"
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    SELF_REPORTED = "SELF_REPORTED"
    UNKNOWN = "UNKNOWN"
    CONTRADICTED = "CONTRADICTED"


class SigningState(str, Enum):
    SIGNED_VERIFIED = "SIGNED_VERIFIED"
    SIGNED_UNVERIFIED = "SIGNED_UNVERIFIED"
    UNSIGNED = "UNSIGNED"
    UNKNOWN = "UNKNOWN"


class VexStatus(str, Enum):
    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    FIXED = "FIXED"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    UNKNOWN = "UNKNOWN"


class VulnMatchState(str, Enum):
    EXACT_COMPONENT_VERSION_MATCH = "EXACT_COMPONENT_VERSION_MATCH"
    RANGE_MATCH = "RANGE_MATCH"
    CPE_ONLY_MATCH = "CPE_ONLY_MATCH"
    NAME_ONLY_MATCH = "NAME_ONLY_MATCH"
    AMBIGUOUS = "AMBIGUOUS"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


class VerificationState(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    CANDIDATE = "CANDIDATE"
    OBSERVED = "OBSERVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    DISPUTED = "DISPUTED"
    UNSUPPORTED = "UNSUPPORTED"
    RETRACTED = "RETRACTED"


class FindingType(str, Enum):
    COMPONENT_PRESENT = "COMPONENT_PRESENT"
    VERSION_DECLARED = "VERSION_DECLARED"
    VERSION_RESOLVED = "VERSION_RESOLVED"
    VERSION_CONFLICT = "VERSION_CONFLICT"
    DEPENDENCY_EDGE_OBSERVED = "DEPENDENCY_EDGE_OBSERVED"
    DIRECT_DEPENDENCY = "DIRECT_DEPENDENCY"
    TRANSITIVE_DEPENDENCY = "TRANSITIVE_DEPENDENCY"
    RUNTIME_DEPENDENCY = "RUNTIME_DEPENDENCY"
    BUILD_DEPENDENCY = "BUILD_DEPENDENCY"
    DEV_DEPENDENCY = "DEV_DEPENDENCY"
    OPTIONAL_DEPENDENCY = "OPTIONAL_DEPENDENCY"
    PURL_RESOLVED = "PURL_RESOLVED"
    PURL_MISSING = "PURL_MISSING"
    CPE_AMBIGUOUS = "CPE_AMBIGUOUS"
    HASH_OBSERVED = "HASH_OBSERVED"
    HASH_MISSING = "HASH_MISSING"
    LICENSE_OBSERVED = "LICENSE_OBSERVED"
    LICENSE_MISSING = "LICENSE_MISSING"
    LICENSE_CONFLICT_CANDIDATE = "LICENSE_CONFLICT_CANDIDATE"
    SUPPLIER_OBSERVED = "SUPPLIER_OBSERVED"
    SUPPLIER_MISSING = "SUPPLIER_MISSING"
    REPOSITORY_OBSERVED = "REPOSITORY_OBSERVED"
    REGISTRY_OBSERVED = "REGISTRY_OBSERVED"
    PROVENANCE_PARTIAL = "PROVENANCE_PARTIAL"
    ATTESTATION_OBSERVED = "ATTESTATION_OBSERVED"
    SIGNATURE_OBSERVED = "SIGNATURE_OBSERVED"
    VEX_OBSERVED = "VEX_OBSERVED"
    VEX_CONFLICT_CANDIDATE = "VEX_CONFLICT_CANDIDATE"
    VULNERABILITY_CANDIDATE = "VULNERABILITY_CANDIDATE"
    EOL_OBSERVED = "EOL_OBSERVED"
    SBOM_STALE = "SBOM_STALE"
    SBOM_DRIFT = "SBOM_DRIFT"
    UNEXPECTED_COMPONENT_CANDIDATE = "UNEXPECTED_COMPONENT_CANDIDATE"
    ORPHAN_COMPONENT = "ORPHAN_COMPONENT"
    BROKEN_REFERENCE = "BROKEN_REFERENCE"
    RUNTIME_CONFLICT = "RUNTIME_CONFLICT"
    COMPONENT_ABSENT_IN_RUNTIME = "COMPONENT_ABSENT_IN_RUNTIME"
    COMPONENT_LOADED_IN_RUNTIME = "COMPONENT_LOADED_IN_RUNTIME"
    COMMON_COMPONENT_OBSERVED = "COMMON_COMPONENT_OBSERVED"
    SBOM_QUALITY_LOW = "SBOM_QUALITY_LOW"
    SBOM_QUALITY_MEDIUM = "SBOM_QUALITY_MEDIUM"
    SBOM_QUALITY_HIGH = "SBOM_QUALITY_HIGH"


class GapType(str, Enum):
    COMPONENT_IDENTITY_UNRESOLVED = "COMPONENT_IDENTITY_UNRESOLVED"
    VERSION_UNRESOLVED = "VERSION_UNRESOLVED"
    PURL_MISSING = "PURL_MISSING"
    CPE_AMBIGUOUS = "CPE_AMBIGUOUS"
    DEPENDENCY_EDGE_MISSING = "DEPENDENCY_EDGE_MISSING"
    RUNTIME_PRESENCE_UNKNOWN = "RUNTIME_PRESENCE_UNKNOWN"
    REACHABILITY_UNKNOWN = "REACHABILITY_UNKNOWN"
    SBOM_STALE = "SBOM_STALE"
    SBOM_INCOMPLETE = "SBOM_INCOMPLETE"
    SUPPLIER_UNKNOWN = "SUPPLIER_UNKNOWN"
    REPOSITORY_UNKNOWN = "REPOSITORY_UNKNOWN"
    LICENSE_UNKNOWN = "LICENSE_UNKNOWN"
    PROVENANCE_INCOMPLETE = "PROVENANCE_INCOMPLETE"
    VEX_MISSING = "VEX_MISSING"
    VEX_CONFLICT = "VEX_CONFLICT"
    DEPLOYED_ARTIFACT_UNKNOWN = "DEPLOYED_ARTIFACT_UNKNOWN"
    BUILD_ID_UNKNOWN = "BUILD_ID_UNKNOWN"
    VULNERABILITY_APPLICABILITY_UNKNOWN = "VULNERABILITY_APPLICABILITY_UNKNOWN"
    SOURCE_INDEPENDENCE_GAP = "SOURCE_INDEPENDENCE_GAP"


class PrivacyFlag(str, Enum):
    CASE_SCOPED = "CASE_SCOPED"
    AUTHORIZED_SBOM_ONLY = "AUTHORIZED_SBOM_ONLY"
    NO_PACKAGE_EXECUTION = "NO_PACKAGE_EXECUTION"
    NO_INSTALL_SCRIPT_EXECUTION = "NO_INSTALL_SCRIPT_EXECUTION"
    NO_DEPENDENCY_ATTACK_ENABLEMENT = "NO_DEPENDENCY_ATTACK_ENABLEMENT"
    NO_SBOM_TAMPERING = "NO_SBOM_TAMPERING"
    NO_ATTESTATION_FORGERY = "NO_ATTESTATION_FORGERY"
    NO_SIGNATURE_FORGERY = "NO_SIGNATURE_FORGERY"
    NO_SIGNING_KEY_USE = "NO_SIGNING_KEY_USE"
    NO_CREDENTIAL_USE = "NO_CREDENTIAL_USE"
    LOCAL_ONLY_DEFAULT = "LOCAL_ONLY_DEFAULT"


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
    SourceType.CYCLONEDX_SBOM: 0.92,
    SourceType.SPDX_SBOM: 0.92,
    SourceType.SWID: 0.82,
    SourceType.PACKAGE_MANIFEST: 0.88,
    SourceType.LOCKFILE: 0.94,
    SourceType.CONTAINER_SBOM: 0.90,
    SourceType.CONTAINER_METADATA: 0.88,
    SourceType.OS_PACKAGE_INVENTORY: 0.90,
    SourceType.FIRMWARE_SBOM: 0.85,
    SourceType.RUNTIME_INVENTORY: 0.93,
    SourceType.VEX: 0.82,
    SourceType.ATTESTATION: 0.86,
    SourceType.SIGNATURE: 0.86,
    SourceType.VULNERABILITY_DATA: 0.84,
    SourceType.LICENSE_DATABASE: 0.78,
    SourceType.EOL_DATABASE: 0.82,
    SourceType.PACKAGE_REGISTRY: 0.88,
    SourceType.REPOSITORY_METADATA: 0.86,
    SourceType.BUILD_METADATA: 0.88,
    SourceType.ARTIFACT_REGISTRY: 0.88,
    SourceType.SCA_EXPORT: 0.72,
    SourceType.CMDB: 0.70,
    SourceType.OTHER: 0.65,
}

PROHIBITED_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "MALICIOUS_PACKAGE_OR_DEPENDENCY_ATTACK",
        re.compile(
            r"\b(publish|create|submit|inject|poison)\s+(malicious\s+)?(package|dependency)|"
            r"\bdependency[- ]confus\w*|\btyposquat\w*|\bpoison\w*\s+dependenc\w+\b",
            re.IGNORECASE,
        ),
    ),
    (
        "COMPROMISE_REGISTRY_REPO_CI",
        re.compile(
            r"\b(compromise|tamper with|attack)\s+(package registry|artifact registry|repository|repo|ci/cd|ci|build pipeline)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SBOM_ATTESTATION_SIGNATURE_TAMPERING",
        re.compile(
            r"\b(tamper with|forge|modify maliciously)\s+(sbom|attestation|signature|provenance)\b|"
            r"\buse signing key\b|\bsteal signing key\b",
            re.IGNORECASE,
        ),
    ),
    (
        "UNTRUSTED_PACKAGE_EXECUTION",
        re.compile(
            r"\b(download and execute|execute|run|install)\s+(untrusted|suspicious|unknown)\s+(package|dependency|artifact|binary|script)\b|"
            r"\brun install scripts\b",
            re.IGNORECASE,
        ),
    ),
    (
        "EXPLOIT_VULNERABLE_COMPONENT",
        re.compile(
            r"\b(exploit|weaponize|attack)\s+(vulnerable\s+)?(component|dependency|package|library|cve)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "CREDENTIAL_USE_FROM_ARTIFACT",
        re.compile(
            r"\b(use|test|redeem|authenticate with)\s+(credential|token|api key|secret|password|repository token)\s+(found in|from)?\s*(build|artifact|sbom|metadata)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SECURITY_EVASION",
        re.compile(
            r"\b(disable security control|evade software-integrity verification|bypass integrity check|tamper with signature)\b",
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


def days_between(a: Optional[str], b: Optional[str]) -> Optional[int]:
    da = parse_dt(a)
    db = parse_dt(b)
    if not da or not db:
        return None
    return abs((db - da).days)


def purl_base(purl: Optional[str]) -> Optional[str]:
    if not purl:
        return None
    return purl.split("@", 1)[0]


def purl_version(purl: Optional[str]) -> Optional[str]:
    if not purl or "@" not in purl:
        return None
    return purl.split("@", 1)[1]


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
class SBOM:
    id: str
    format: SBOMFormat = SBOMFormat.UNKNOWN
    format_version: str = ""
    document_name: str = ""
    serial_number: str = ""
    namespace: str = ""
    creation_time: Optional[str] = None
    generator: str = ""
    generator_version: str = ""
    subject_component_id: Optional[str] = None
    components: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    licenses: List[str] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)
    signatures: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    quality_score: Optional[float] = None
    freshness_state: FreshnessState = FreshnessState.UNKNOWN
    limitations: List[str] = field(default_factory=list)


@dataclass
class Component:
    id: str
    sbom_id: str
    component_type: ComponentType = ComponentType.LIBRARY
    name: str = ""
    namespace: Optional[str] = None
    group: Optional[str] = None
    version: Optional[str] = None
    declared_version: Optional[str] = None
    resolved_version: Optional[str] = None
    installed_version: Optional[str] = None
    runtime_version: Optional[str] = None
    qualifiers: Dict[str, str] = field(default_factory=dict)
    subpath: Optional[str] = None
    purl: Optional[str] = None
    cpe_candidates: List[str] = field(default_factory=list)
    cpe_state: str = "UNKNOWN"
    swid: Optional[str] = None
    supplier: Optional[str] = None
    manufacturer_candidate: Optional[str] = None
    publisher: Optional[str] = None
    licenses: List[str] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)
    repository: Optional[str] = None
    registry: Optional[str] = None
    scope: Scope = Scope.UNKNOWN
    dependency_depth: Optional[int] = None
    runtime_context: str = "UNKNOWN"
    build_context: str = "UNKNOWN"
    provenance_state: ProvenanceState = ProvenanceState.UNKNOWN
    signing_state: SigningState = SigningState.UNKNOWN
    evidence_ids: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class DependencyEdge:
    id: str
    sbom_id: str
    from_component_id: str
    to_component_id: str
    relationship_type: str = "DEPENDS_ON"
    derived_relationship: Optional[str] = None
    depth: Optional[int] = None
    path: List[str] = field(default_factory=list)
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = field(default_factory=list)


@dataclass
class VEXStatement:
    id: str
    component_id: str
    sbom_id: Optional[str] = None
    vex_status: VexStatus = VexStatus.UNKNOWN
    justification: str = ""
    vendor: str = ""
    statement_time: Optional[str] = None
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityContext:
    id: str
    component_id: str
    advisory_id: str = ""
    cve: Optional[str] = None
    match_state: VulnMatchState = VulnMatchState.UNKNOWN
    affected_versions: Optional[str] = None
    fixed_versions: Optional[str] = None
    kev: bool = False
    epss: Optional[float] = None
    severity: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Attestation:
    id: str
    subject_component_id: Optional[str] = None
    subject_artifact: Optional[str] = None
    predicate_type: str = ""
    subject_digest: Optional[str] = None
    issuer: str = ""
    builder: str = ""
    attested_at: Optional[str] = None
    verification_state: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Signature:
    id: str
    subject_component_id: Optional[str] = None
    subject_artifact: Optional[str] = None
    signer: str = ""
    certificate: str = ""
    timestamp: Optional[str] = None
    verification_state: str = "UNKNOWN"
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class EOLRecord:
    id: str
    component_id: str
    status: str = "UNKNOWN"
    end_of_life: Optional[str] = None
    end_of_support: Optional[str] = None
    deprecated: bool = False
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class RuntimeInventory:
    id: str
    component_id: str
    present: Optional[bool] = None
    loaded: Optional[bool] = None
    version: Optional[str] = None
    observed_at: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
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
    source_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    specialist_handoff: Optional[str] = None


@dataclass
class Hypothesis:
    id: str
    statement: str
    kind: str
    supporting_finding_ids: List[str] = field(default_factory=list)
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
    category: str
    action: str
    target: str
    rationale: str
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    approval: str = "HUMAN_APPROVAL_REQUIRED"
    business_impact: str = "REQUIRES_ENGINEERING_REVIEW"
    reversibility: str = "REQUIRES_VALIDATION"
    limitations: List[str] = field(default_factory=list)


@dataclass
class Case:
    case_id: str
    task_id: str
    objective: str
    questions: List[str] = field(default_factory=list)
    scope: List[str] = field(default_factory=lambda: ["authorized_defensive_sbom", "evidence_first", "case_scoped"])
    authorization: str = "demo_authorized_sbom_intelligence"
    applications: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    releases: List[str] = field(default_factory=list)
    builds: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    sboms: List[str] = field(default_factory=list)
    time_range: Optional[str] = None
    as_of: str = DEFAULT_AS_OF
    sample: bool = False
    budget: Optional[str] = None
    deadline: Optional[str] = None


# =====================================================================
# SBOMINT ENGINE
# =====================================================================

class SbomInt:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.as_of = case.as_of or DEFAULT_AS_OF

        self.sources: Dict[str, Source] = {}
        self.evidence: Dict[str, Evidence] = {}
        self.sboms: Dict[str, SBOM] = {}
        self.components: Dict[str, Component] = {}
        self.edges: Dict[str, DependencyEdge] = {}
        self.vex_statements: Dict[str, VEXStatement] = {}
        self.vulnerability_contexts: Dict[str, VulnerabilityContext] = {}
        self.attestations: Dict[str, Attestation] = {}
        self.signatures: Dict[str, Signature] = {}
        self.eol_records: Dict[str, EOLRecord] = {}
        self.runtime_inventories: Dict[str, RuntimeInventory] = {}
        self.findings: Dict[str, Finding] = {}
        self.hypotheses: List[Hypothesis] = []
        self.contradictions: List[Contradiction] = []
        self.gaps: List[KnowledgeGap] = []
        self.actions: List[NextAction] = []
        self.recommendations: List[Recommendation] = []
        self.handoffs: List[Dict[str, str]] = []
        self.quality: Dict[str, Any] = {}
        self.drift: List[Dict[str, Any]] = []
        self.common_components: List[Dict[str, Any]] = []
        self.component_paths: Dict[str, List[List[str]]] = defaultdict(list)
        self.validation_errors: List[str] = []

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

    def add_sbom(self, sbom: SBOM) -> SBOM:
        self.sboms[sbom.id] = sbom
        return sbom

    def add_component(self, component: Component) -> Component:
        self.components[component.id] = component
        if component.sbom_id in self.sboms:
            if component.id not in self.sboms[component.sbom_id].components:
                self.sboms[component.sbom_id].components.append(component.id)
        return component

    def add_edge(self, edge: DependencyEdge) -> DependencyEdge:
        self.edges[edge.id] = edge
        if edge.sbom_id in self.sboms:
            if edge.id not in self.sboms[edge.sbom_id].dependencies:
                self.sboms[edge.sbom_id].dependencies.append(edge.id)
        return edge

    def add_vex(self, vex: VEXStatement) -> VEXStatement:
        self.vex_statements[vex.id] = vex
        return vex

    def add_vulnerability_context(self, ctx: VulnerabilityContext) -> VulnerabilityContext:
        self.vulnerability_contexts[ctx.id] = ctx
        return ctx

    def add_attestation(self, att: Attestation) -> Attestation:
        self.attestations[att.id] = att
        return att

    def add_signature(self, sig: Signature) -> Signature:
        self.signatures[sig.id] = sig
        return sig

    def add_eol(self, eol: EOLRecord) -> EOLRecord:
        self.eol_records[eol.id] = eol
        return eol

    def add_runtime_inventory(self, rt: RuntimeInventory) -> RuntimeInventory:
        self.runtime_inventories[rt.id] = rt
        return rt

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
    # Graph / version / identity analysis
    # -----------------------------------------------------------------

    def build_dependency_graph(self) -> None:
        self.component_paths = defaultdict(list)

        for sbom in self.sboms.values():
            root = sbom.subject_component_id
            if not root or root not in self.components:
                self.validation_errors.append(f"SBOM {sbom.id} has no resolvable subject/root component.")
                continue

            adj: Dict[str, List[str]] = defaultdict(list)
            for edge in self.edges.values():
                if edge.sbom_id == sbom.id:
                    adj[edge.from_component_id].append(edge.to_component_id)

            visited: Set[str] = set()
            q = deque([(root, 0, [root])])

            while q:
                node, depth, path = q.popleft()
                if len(path) > 20:
                    continue

                if node in visited:
                    self.component_paths[node].append(path)
                    continue

                visited.add(node)
                self.component_paths[node].append(path)

                comp = self.components.get(node)
                if comp:
                    if comp.dependency_depth is None or depth < comp.dependency_depth:
                        comp.dependency_depth = depth

                for nxt in adj.get(node, []):
                    if nxt not in visited:
                        q.append((nxt, depth + 1, path + [nxt]))
                    else:
                        self.component_paths[nxt].append(path + [nxt])

            for edge in self.edges.values():
                if edge.sbom_id != sbom.id:
                    continue
                from_comp = self.components.get(edge.from_component_id)
                if from_comp and from_comp.dependency_depth is not None:
                    edge.depth = from_comp.dependency_depth + 1

                if edge.depth == 1:
                    edge.derived_relationship = "DIRECT_DEPENDS_ON"
                elif edge.depth and edge.depth > 1:
                    edge.derived_relationship = "TRANSITIVELY_DEPENDS_ON"
                else:
                    edge.derived_relationship = edge.relationship_type

                paths = self.component_paths.get(edge.to_component_id, [])
                if paths:
                    edge.path = min(paths, key=len)

            # Detect orphan components in this SBOM.
            for comp_id in sbom.components:
                if comp_id == root:
                    continue
                if not self.component_paths.get(comp_id):
                    comp = self.components.get(comp_id)
                    if comp:
                        self.add_finding(Finding(
                            id=new_id("FIND-ORPHAN-", comp_id),
                            finding_type=FindingType.ORPHAN_COMPONENT,
                            subject_id=comp_id,
                            statement=f"Component {comp_id} appears in SBOM {sbom.id} without a resolved dependency path from the subject/root component.",
                            verification_state=VerificationState.OBSERVED,
                            source_ids=comp.source_ids,
                            evidence_ids=comp.evidence_ids,
                            limitations=[
                                "Orphan may be root-level, optional plugin, missing dependency edge, or SBOM incompleteness.",
                                "Orphan does not prove unused component.",
                            ],
                        ))

            # Broken references.
            for edge in self.edges.values():
                if edge.sbom_id != sbom.id:
                    continue
                if edge.to_component_id not in self.components:
                    self.add_finding(Finding(
                        id=new_id("FIND-BROKEN-", edge.id),
                        finding_type=FindingType.BROKEN_REFERENCE,
                        subject_id=edge.id,
                        statement=f"Dependency edge {edge.id} references unknown component {edge.to_component_id}.",
                        verification_state=VerificationState.OBSERVED,
                        source_ids=edge.source_ids,
                        evidence_ids=edge.evidence_ids,
                        limitations=["Broken reference may indicate incomplete SBOM or parser normalization issue."],
                    ))

    def resolve_versions(self) -> None:
        for comp in self.components.values():
            if comp.declared_version and comp.resolved_version and comp.declared_version != comp.resolved_version:
                comp.limitations.append(
                    f"Declared version range '{comp.declared_version}' differs from resolved version '{comp.resolved_version}'; both preserved."
                )
                self.add_finding(Finding(
                    id=new_id("FIND-VERDECL-", comp.id),
                    finding_type=FindingType.VERSION_DECLARED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} has declared version range {comp.declared_version}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Declared range is not resolved version."],
                ))
                self.add_finding(Finding(
                    id=new_id("FIND-VERRES-", comp.id),
                    finding_type=FindingType.VERSION_RESOLVED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} has resolved version {comp.resolved_version}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Resolved version is not automatically deployed/production version."],
                ))

            if comp.runtime_version and comp.resolved_version and comp.runtime_version != comp.resolved_version:
                desc = (
                    f"Component {comp.id} resolved version {comp.resolved_version} conflicts with "
                    f"runtime inventory version {comp.runtime_version}."
                )
                self.add_contradiction(Contradiction(
                    id=new_id("CON-VER-", desc),
                    contradiction_type="RESOLVED_VS_RUNTIME_VERSION",
                    description=desc,
                    subject_ids=[comp.id, comp.sbom_id],
                    evidence_ids=comp.evidence_ids,
                    source_ids=comp.source_ids,
                    severity="HIGH",
                    status="OPEN",
                    recommended_resolution=(
                        "Use runtime/deployment evidence for deployed-state claims; preserve build/lockfile evidence separately."
                    ),
                ))
                self.add_finding(Finding(
                    id=new_id("FIND-VERCONFLICT-", comp.id),
                    finding_type=FindingType.VERSION_CONFLICT,
                    subject_id=comp.id,
                    statement=desc,
                    verification_state=VerificationState.DISPUTED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Do not silently choose one version; preserve both evidence states."],
                ))

    def analyze_identity_coverage(self) -> None:
        for comp in self.components.values():
            if comp.purl and comp.purl.startswith("pkg:"):
                self.add_finding(Finding(
                    id=new_id("FIND-PURL-", comp.id),
                    finding_type=FindingType.PURL_RESOLVED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} has PURL {comp.purl}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["PURL identifies package coordinates; it does not prove deployment, loading, or reachability."],
                ))
            else:
                self.add_finding(Finding(
                    id=new_id("FIND-PURLMISS-", comp.id),
                    finding_type=FindingType.PURL_MISSING,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} lacks a resolved PURL.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Missing PURL reduces identity confidence and vulnerability matching reliability."],
                ))

            if comp.cpe_candidates:
                state = comp.cpe_state or "CANDIDATE"
                if state in {"AMBIGUOUS", "UNKNOWN", "CANDIDATE"}:
                    self.add_finding(Finding(
                        id=new_id("FIND-CPE-", comp.id),
                        finding_type=FindingType.CPE_AMBIGUOUS,
                        subject_id=comp.id,
                        statement=f"Component {comp.id} has CPE candidate(s) {comp.cpe_candidates} with state {state}.",
                        verification_state=VerificationState.CANDIDATE,
                        source_ids=comp.source_ids,
                        evidence_ids=comp.evidence_ids,
                        limitations=[
                            "CPE vocabularies may be coarse/incomplete.",
                            "Incorrect CPE can cause vulnerability false positives.",
                            "CPE match is not verified product match.",
                        ],
                    ))

            if comp.hashes:
                self.add_finding(Finding(
                    id=new_id("FIND-HASH-", comp.id),
                    finding_type=FindingType.HASH_OBSERVED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} has hash metadata: {list(comp.hashes.keys())}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=[
                        "Hash equality supports byte-identical artifact.",
                        "Hash does not prove benignness, safety, or authentic authorship.",
                    ],
                ))
            else:
                self.add_finding(Finding(
                    id=new_id("FIND-HASHMISS-", comp.id),
                    finding_type=FindingType.HASH_MISSING,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} lacks cryptographic hash metadata.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Missing hash reduces integrity/provenance traceability."],
                ))

            if comp.licenses:
                self.add_finding(Finding(
                    id=new_id("FIND-LIC-", comp.id),
                    finding_type=FindingType.LICENSE_OBSERVED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} declares licenses {comp.licenses}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=[
                        "Declared license is not verified license.",
                        "Final legal interpretation requires LEGALINT/counsel.",
                    ],
                ))
            else:
                self.add_finding(Finding(
                    id=new_id("FIND-LICMISS-", comp.id),
                    finding_type=FindingType.LICENSE_MISSING,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} lacks license metadata.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Missing license metadata is a governance/legal-review signal, not automatic violation."],
                ))

            if comp.supplier:
                self.add_finding(Finding(
                    id=new_id("FIND-SUP-", comp.id),
                    finding_type=FindingType.SUPPLIER_OBSERVED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} supplier metadata: {comp.supplier}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=[
                        "Supplier metadata may be organization, individual, foundation, vendor, or unknown.",
                        "Maintainer is not automatically legal owner.",
                    ],
                ))
            else:
                self.add_finding(Finding(
                    id=new_id("FIND-SUPMISS-", comp.id),
                    finding_type=FindingType.SUPPLIER_MISSING,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} lacks supplier metadata.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Missing supplier reduces supply-chain context."],
                ))

            if comp.repository:
                self.add_finding(Finding(
                    id=new_id("FIND-REPO-", comp.id),
                    finding_type=FindingType.REPOSITORY_OBSERVED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} source repository candidate: {comp.repository}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Registry is not source repository. Repository reference requires REPOINT for deeper source context."],
                ))

            if comp.registry:
                self.add_finding(Finding(
                    id=new_id("FIND-REG-", comp.id),
                    finding_type=FindingType.REGISTRY_OBSERVED,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} registry context: {comp.registry}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Registry distributes artifact; it does not prove source ownership or deployment."],
                ))

    def analyze_runtime(self) -> None:
        for rt in self.runtime_inventories.values():
            comp = self.components.get(rt.component_id)
            if not comp:
                continue

            if rt.present is True:
                comp.runtime_context = "PRESENT_OBSERVED"
                self.add_finding(Finding(
                    id=new_id("FIND-RTPRESENT-", rt.id),
                    finding_type=FindingType.COMPONENT_PRESENT,
                    subject_id=comp.id,
                    statement=f"Runtime inventory indicates component {comp.id} is present.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=rt.source_ids,
                    evidence_ids=rt.evidence_ids,
                    limitations=["Runtime presence is not loaded, reachable, vulnerable, or exploited."],
                ))
            elif rt.present is False:
                comp.runtime_context = "ABSENT_IN_RUNTIME"
                desc = f"Component {comp.id} appears in SBOM/build evidence but runtime inventory reports absent."
                self.add_contradiction(Contradiction(
                    id=new_id("CON-RTABSENT-", desc),
                    contradiction_type="SBOM_VS_RUNTIME_PRESENCE",
                    description=desc,
                    subject_ids=[comp.id, comp.sbom_id, rt.id],
                    evidence_ids=sorted(set(comp.evidence_ids + rt.evidence_ids)),
                    source_ids=sorted(set(comp.source_ids + rt.source_ids)),
                    severity="MEDIUM",
                    status="OPEN",
                    recommended_resolution=(
                        "Determine whether SBOM is build-specific, stale, optional feature disabled, or runtime inventory scope mismatch."
                    ),
                ))
                self.add_finding(Finding(
                    id=new_id("FIND-RTABSENT-", rt.id),
                    finding_type=FindingType.COMPONENT_ABSENT_IN_RUNTIME,
                    subject_id=comp.id,
                    statement=desc,
                    verification_state=VerificationState.DISPUTED,
                    source_ids=rt.source_ids,
                    evidence_ids=rt.evidence_ids,
                    limitations=["Absent in sampled runtime does not prove globally absent."],
                ))

            if rt.loaded is True:
                comp.runtime_context = "LOADED_OBSERVED"
                self.add_finding(Finding(
                    id=new_id("FIND-RTLOADED-", rt.id),
                    finding_type=FindingType.COMPONENT_LOADED_IN_RUNTIME,
                    subject_id=comp.id,
                    statement=f"Runtime inventory indicates component {comp.id} is loaded.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=rt.source_ids,
                    evidence_ids=rt.evidence_ids,
                    limitations=["Loaded component is not reachable or vulnerable without application/VULNINT analysis."],
                ))

            if rt.version and comp.resolved_version and rt.version != comp.resolved_version:
                comp.runtime_context = "RUNTIME_VERSION_CONFLICT"
                self.add_finding(Finding(
                    id=new_id("FIND-RTVER-", rt.id),
                    finding_type=FindingType.RUNTIME_CONFLICT,
                    subject_id=comp.id,
                    statement=f"Runtime version {rt.version} conflicts with resolved/build version {comp.resolved_version} for component {comp.id}.",
                    verification_state=VerificationState.DISPUTED,
                    source_ids=rt.source_ids,
                    evidence_ids=rt.evidence_ids,
                    limitations=["Preserve both build and runtime states; do not silently overwrite."],
                ))

    def analyze_sbom_freshness(self) -> None:
        for sbom in self.sboms.values():
            age = days_between(sbom.creation_time, self.as_of)
            if age is None:
                sbom.freshness_state = FreshnessState.UNKNOWN
                continue

            # Runtime conflicts can force stale classification.
            runtime_conflict = any(
                c.contradiction_type in {"RESOLVED_VS_RUNTIME_VERSION", "SBOM_VS_RUNTIME_PRESENCE"}
                and sbom.id in c.subject_ids
                for c in self.contradictions
            )

            if runtime_conflict or age > 180:
                sbom.freshness_state = FreshnessState.STALE
            elif age <= 30:
                sbom.freshness_state = FreshnessState.CURRENT
            elif age <= 90:
                sbom.freshness_state = FreshnessState.RECENT
            else:
                sbom.freshness_state = FreshnessState.AGING

            if sbom.freshness_state == FreshnessState.STALE:
                self.add_finding(Finding(
                    id=new_id("FIND-STALE-", sbom.id),
                    finding_type=FindingType.SBOM_STALE,
                    subject_id=sbom.id,
                    statement=f"SBOM {sbom.id} is stale relative to as-of time {self.as_of} and/or runtime conflicts.",
                    verification_state=VerificationState.SUPPORTED,
                    source_ids=sbom.source_ids,
                    evidence_ids=sbom.evidence_ids,
                    limitations=[
                        "Stale SBOM does not invalidate historical build evidence.",
                        "Use SBOM generation/build/release time separately.",
                    ],
                ))

    def analyze_sbom_drift(self) -> None:
        ordered = sorted(self.sboms.values(), key=lambda s: dt_or_min(s.creation_time))
        if len(ordered) < 2:
            return

        old = ordered[0]
        new = ordered[-1]

        def key_for(comp: Component) -> str:
            base = purl_base(comp.purl)
            if base:
                return base
            return f"{comp.namespace or ''}/{comp.name}".strip("/")

        old_map = {key_for(self.components[c]): self.components[c] for c in old.components if c in self.components}
        new_map = {key_for(self.components[c]): self.components[c] for c in new.components if c in self.components}

        added = sorted(set(new_map) - set(old_map))
        removed = sorted(set(old_map) - set(new_map))
        common = sorted(set(old_map) & set(new_map))

        changes: List[Dict[str, Any]] = []

        for k in added:
            comp = new_map[k]
            changes.append({
                "type": "COMPONENT_ADDED",
                "key": k,
                "component_id": comp.id,
                "version": comp.version or comp.resolved_version,
                "scope": comp.scope.value,
            })
            self.add_finding(Finding(
                id=new_id("FIND-DRIFTADD-", old.id + new.id + k),
                finding_type=FindingType.UNEXPECTED_COMPONENT_CANDIDATE,
                subject_id=comp.id,
                statement=f"Component {k} appears in newer SBOM {new.id} but not older SBOM {old.id}.",
                verification_state=VerificationState.CANDIDATE,
                source_ids=comp.source_ids,
                evidence_ids=comp.evidence_ids,
                limitations=[
                    "Addition may be new feature, transitive update, build tooling, packaging change, or malicious component.",
                    "Do not jump to compromise without provenance/runtime/security evidence.",
                ],
                specialist_handoff="MALINT / PACKAGEINT if suspicious",
            ))

        for k in removed:
            comp = old_map[k]
            changes.append({
                "type": "COMPONENT_REMOVED",
                "key": k,
                "component_id": comp.id,
                "version": comp.version or comp.resolved_version,
            })

        for k in common:
            o = old_map[k]
            n = new_map[k]
            ov = o.version or o.resolved_version or purl_version(o.purl)
            nv = n.version or n.resolved_version or purl_version(n.purl)
            if ov != nv:
                changes.append({
                    "type": "VERSION_CHANGED",
                    "key": k,
                    "old_component_id": o.id,
                    "new_component_id": n.id,
                    "old_version": ov,
                    "new_version": nv,
                    "note": "Ecosystem-aware upgrade/downgrade comparator unavailable; version change preserved without semantic ranking.",
                })
            if o.hashes != n.hashes and o.hashes and n.hashes:
                changes.append({
                    "type": "HASH_CHANGED",
                    "key": k,
                    "old_component_id": o.id,
                    "new_component_id": n.id,
                })
            if o.licenses != n.licenses:
                changes.append({
                    "type": "LICENSE_CHANGED",
                    "key": k,
                    "old_component_id": o.id,
                    "new_component_id": n.id,
                    "old_licenses": o.licenses,
                    "new_licenses": n.licenses,
                })

        self.drift = [{
            "old_sbom_id": old.id,
            "new_sbom_id": new.id,
            "added": added,
            "removed": removed,
            "changes": changes,
            "guardrails": [
                "SBOM drift is not incident evidence.",
                "Dependency changes may be intentional releases or build variants.",
                "Version changed labels avoid naive lexical upgrade/downgrade claims.",
            ],
        }]

        for ch in changes:
            self.add_finding(Finding(
                id=new_id("FIND-DRIFT-", old.id + new.id + json.dumps(ch, sort_keys=True)),
                finding_type=FindingType.SBOM_DRIFT,
                subject_id=new.id,
                statement=f"SBOM drift {ch['type']} between {old.id} and {new.id}: {ch.get('key')}.",
                verification_state=VerificationState.OBSERVED,
                source_ids=sorted(set(old.source_ids + new.source_ids)),
                evidence_ids=sorted(set(old.evidence_ids + new.evidence_ids)),
                limitations=["Drift requires release/change context before operational interpretation."],
            ))

        # Common components across SBOMs.
        for k in common:
            o = old_map[k]
            n = new_map[k]
            self.common_components.append({
                "component_key": k,
                "old_component_id": o.id,
                "new_component_id": n.id,
                "old_version": o.version or o.resolved_version,
                "new_version": n.version or n.resolved_version,
                "note": "Shared component across releases; common presence is not shared compromise.",
            })
            self.add_finding(Finding(
                id=new_id("FIND-COMMON-", k + old.id + new.id),
                finding_type=FindingType.COMMON_COMPONENT_OBSERVED,
                subject_id=n.id,
                statement=f"Component {k} is common across SBOMs {old.id} and {new.id}.",
                verification_state=VerificationState.OBSERVED,
                source_ids=sorted(set(o.source_ids + n.source_ids)),
                evidence_ids=sorted(set(o.evidence_ids + n.evidence_ids)),
                limitations=["Common component supports systemic exposure/patch planning, not compromise inference."],
            ))

    def analyze_vex_vulnerability(self) -> None:
        runtime_feature_evidence_available = any(
            rt.extra.get("feature_f_enabled") in {True, False}
            for rt in self.runtime_inventories.values()
        )

        for ctx in self.vulnerability_contexts.values():
            comp = self.components.get(ctx.component_id)
            if not comp:
                continue

            if ctx.match_state in {
                VulnMatchState.EXACT_COMPONENT_VERSION_MATCH,
                VulnMatchState.RANGE_MATCH,
            }:
                self.add_finding(Finding(
                    id=new_id("FIND-VULN-", ctx.id),
                    finding_type=FindingType.VULNERABILITY_CANDIDATE,
                    subject_id=comp.id,
                    statement=(
                        f"Advisory {ctx.advisory_id or ctx.cve} matches component {comp.id} "
                        f"version {comp.resolved_version or comp.version} with match_state {ctx.match_state.value}."
                    ),
                    verification_state=VerificationState.CANDIDATE,
                    source_ids=ctx.source_ids,
                    evidence_ids=ctx.evidence_ids,
                    limitations=[
                        "Component presence creates vulnerability candidate, not applicable vulnerability.",
                        "Reachability, configuration, backports, forks, and exposure require VULNINT.",
                        "KEV/EPSS are context, not proof this environment was exploited.",
                    ],
                    specialist_handoff="VULNINT",
                ))

            elif ctx.match_state in {VulnMatchState.CPE_ONLY_MATCH, VulnMatchState.NAME_ONLY_MATCH, VulnMatchState.AMBIGUOUS}:
                self.add_finding(Finding(
                    id=new_id("FIND-VULNWEAK-", ctx.id),
                    finding_type=FindingType.VULNERABILITY_CANDIDATE,
                    subject_id=comp.id,
                    statement=(
                        f"Advisory {ctx.advisory_id or ctx.cve} weakly matches component {comp.id} "
                        f"with match_state {ctx.match_state.value}."
                    ),
                    verification_state=VerificationState.INCONCLUSIVE,
                    source_ids=ctx.source_ids,
                    evidence_ids=ctx.evidence_ids,
                    limitations=[
                        "Name-only or CPE-only matching is weak.",
                        "Do not promote to vulnerable application without component/version/reachability evidence.",
                    ],
                    specialist_handoff="VULNINT",
                ))

        for vex in self.vex_statements.values():
            comp = self.components.get(vex.component_id)
            if not comp:
                continue

            self.add_finding(Finding(
                id=new_id("FIND-VEX-", vex.id),
                finding_type=FindingType.VEX_OBSERVED,
                subject_id=comp.id,
                statement=f"VEX statement {vex.id} reports {vex.vex_status.value} for component {comp.id}; justification: {vex.justification}.",
                verification_state=VerificationState.OBSERVED,
                source_ids=vex.source_ids,
                evidence_ids=vex.evidence_ids,
                limitations=[
                    "VEX is assertion evidence, not unquestionable fact.",
                    "Vendor/product-owner justification must be evaluated against configuration, version, and reachability.",
                ],
            ))

            matching_vulns = [
                ctx for ctx in self.vulnerability_contexts.values()
                if ctx.component_id == comp.id
                and ctx.match_state in {VulnMatchState.EXACT_COMPONENT_VERSION_MATCH, VulnMatchState.RANGE_MATCH}
            ]

            if vex.vex_status == VexStatus.NOT_AFFECTED and matching_vulns:
                if not runtime_feature_evidence_available:
                    desc = (
                        f"VEX {vex.id} states NOT_AFFECTED for {comp.id}, but external vulnerability context "
                        f"{matching_vex_ids(matching_vulns)} indicates affected version and runtime/configuration evidence "
                        "for the cited mitigation is unavailable."
                    )
                    self.add_contradiction(Contradiction(
                        id=new_id("CON-VEX-", desc),
                        contradiction_type="VEX_VS_EXTERNAL_APPLICABILITY",
                        description=desc,
                        subject_ids=[comp.id, vex.id] + [v.id for v in matching_vulns],
                        evidence_ids=sorted(set(vex.evidence_ids + [eid for v in matching_vulns for eid in v.evidence_ids])),
                        source_ids=sorted(set(vex.source_ids + [sid for v in matching_vulns for sid in v.source_ids])),
                        severity="HIGH",
                        status="OPEN",
                        recommended_resolution=(
                            "Obtain authorized runtime/configuration evidence for the VEX justification and hand applicability/reachability to VULNINT."
                        ),
                    ))
                    self.add_finding(Finding(
                        id=new_id("FIND-VEXCONF-", vex.id),
                        finding_type=FindingType.VEX_CONFLICT_CANDIDATE,
                        subject_id=comp.id,
                        statement=desc,
                        verification_state=VerificationState.DISPUTED,
                        source_ids=vex.source_ids,
                        evidence_ids=vex.evidence_ids,
                        limitations=[
                            "Do not silently trust vendor VEX or external scanner.",
                            "Preserve both statements until validated.",
                        ],
                        specialist_handoff="VULNINT",
                    ))

    def analyze_licenses(self) -> None:
        # Example: root application declared Proprietary, dependency GPL-3.0-only.
        for comp in self.components.values():
            if comp.component_type == ComponentType.APPLICATION and "Proprietary" in comp.licenses:
                dep_gpl = [
                    d for d in self.components.values()
                    if d.sbom_id == comp.sbom_id
                    and d.id != comp.id
                    and any("GPL" in lic for lic in d.licenses)
                ]
                for d in dep_gpl:
                    desc = (
                        f"Application {comp.id} declares Proprietary license while dependency {d.id} "
                        f"declares {d.licenses}; license compatibility review candidate."
                    )
                    self.add_finding(Finding(
                        id=new_id("FIND-LICCONF-", comp.id + d.id),
                        finding_type=FindingType.LICENSE_CONFLICT_CANDIDATE,
                        subject_id=d.id,
                        statement=desc,
                        verification_state=VerificationState.CANDIDATE,
                        source_ids=sorted(set(comp.source_ids + d.source_ids)),
                        evidence_ids=sorted(set(comp.evidence_ids + d.evidence_ids)),
                        limitations=[
                            "SBOMINT does not make final legal conclusions.",
                            "License expression semantics and distribution model require LEGALINT/counsel.",
                        ],
                        specialist_handoff="LEGALINT",
                    ))

    def analyze_provenance_signatures(self) -> None:
        for att in self.attestations.values():
            comp = self.components.get(att.subject_component_id or "")
            if comp:
                comp.provenance_state = ProvenanceState.PARTIAL if att.verification_state != "VERIFIED" else ProvenanceState.SUPPORTED
            self.add_finding(Finding(
                id=new_id("FIND-ATT-", att.id),
                finding_type=FindingType.ATTESTATION_OBSERVED,
                subject_id=att.subject_component_id or att.subject_artifact or att.id,
                statement=f"Attestation {att.id} observed: predicate={att.predicate_type}, issuer={att.issuer}, verification={att.verification_state}.",
                verification_state=VerificationState.OBSERVED,
                source_ids=att.source_ids,
                evidence_ids=att.evidence_ids,
                limitations=[
                    "Attestation quality depends on issuer trust, build environment, signing controls, and provenance chain.",
                    "Attestation is not absolute truth.",
                ],
            ))

        for sig in self.signatures.values():
            comp = self.components.get(sig.subject_component_id or "")
            if comp:
                comp.signing_state = SigningState.SIGNED_VERIFIED if sig.verification_state == "VERIFIED" else SigningState.SIGNED_UNVERIFIED
            self.add_finding(Finding(
                id=new_id("FIND-SIG-", sig.id),
                finding_type=FindingType.SIGNATURE_OBSERVED,
                subject_id=sig.subject_component_id or sig.subject_artifact or sig.id,
                statement=f"Signature metadata {sig.id} observed: signer={sig.signer}, verification={sig.verification_state}.",
                verification_state=VerificationState.OBSERVED,
                source_ids=sig.source_ids,
                evidence_ids=sig.evidence_ids,
                limitations=[
                    "Signed does not mean safe.",
                    "Unsigned does not mean malicious.",
                    "Signature indicates integrity/authorship context, not benignness.",
                ],
            ))

        for comp in self.components.values():
            if comp.provenance_state in {ProvenanceState.PARTIAL, ProvenanceState.SELF_REPORTED, ProvenanceState.UNKNOWN}:
                self.add_finding(Finding(
                    id=new_id("FIND-PROV-", comp.id),
                    finding_type=FindingType.PROVENANCE_PARTIAL,
                    subject_id=comp.id,
                    statement=f"Component {comp.id} provenance state is {comp.provenance_state.value}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=comp.source_ids,
                    evidence_ids=comp.evidence_ids,
                    limitations=["Partial provenance is common; absence is not automatically maliciousness."],
                ))

    def analyze_eol(self) -> None:
        for eol in self.eol_records.values():
            comp = self.components.get(eol.component_id)
            if not comp:
                continue
            self.add_finding(Finding(
                id=new_id("FIND-EOL-", eol.id),
                finding_type=FindingType.EOL_OBSERVED,
                subject_id=comp.id,
                statement=(
                    f"Component {comp.id} lifecycle: status={eol.status}, "
                    f"end_of_support={eol.end_of_support}, deprecated={eol.deprecated}."
                ),
                verification_state=VerificationState.OBSERVED,
                source_ids=eol.source_ids,
                evidence_ids=eol.evidence_ids,
                limitations=[
                    "EOL/EOS elevates maintenance risk; it does not prove current exploitation.",
                    "Deprecated does not mean removed.",
                ],
            ))

    def analyze_dependencies(self) -> None:
        for edge in self.edges.values():
            to_comp = self.components.get(edge.to_component_id)
            if not to_comp:
                continue

            if edge.derived_relationship == "DIRECT_DEPENDS_ON":
                self.add_finding(Finding(
                    id=new_id("FIND-DIRECT-", edge.id),
                    finding_type=FindingType.DIRECT_DEPENDENCY,
                    subject_id=to_comp.id,
                    statement=f"Component {to_comp.id} is a direct dependency via edge {edge.id}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=edge.source_ids,
                    evidence_ids=edge.evidence_ids,
                    limitations=["Direct dependency is not automatically runtime reachable."],
                ))
            elif edge.derived_relationship == "TRANSITIVELY_DEPENDS_ON":
                self.add_finding(Finding(
                    id=new_id("FIND-TRANS-", edge.id),
                    finding_type=FindingType.TRANSITIVE_DEPENDENCY,
                    subject_id=to_comp.id,
                    statement=f"Component {to_comp.id} is transitive dependency at depth {edge.depth} via path {edge.path}.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=edge.source_ids,
                    evidence_ids=edge.evidence_ids,
                    limitations=["Transitive presence may be build/dev/optional; preserve scope."],
                ))

            if to_comp.scope == Scope.RUNTIME:
                self.add_finding(Finding(
                    id=new_id("FIND-RUNTIME-", edge.id),
                    finding_type=FindingType.RUNTIME_DEPENDENCY,
                    subject_id=to_comp.id,
                    statement=f"Component {to_comp.id} is classified as runtime dependency.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=edge.source_ids,
                    evidence_ids=edge.evidence_ids,
                    limitations=["Runtime listing is not vulnerable code path use."],
                ))
            elif to_comp.scope == Scope.BUILD:
                self.add_finding(Finding(
                    id=new_id("FIND-BUILD-", edge.id),
                    finding_type=FindingType.BUILD_DEPENDENCY,
                    subject_id=to_comp.id,
                    statement=f"Component {to_comp.id} is classified as build dependency.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=edge.source_ids,
                    evidence_ids=edge.evidence_ids,
                    limitations=["Build dependency may not ship into production."],
                ))
            elif to_comp.scope == Scope.DEVELOPMENT:
                self.add_finding(Finding(
                    id=new_id("FIND-DEV-", edge.id),
                    finding_type=FindingType.DEV_DEPENDENCY,
                    subject_id=to_comp.id,
                    statement=f"Component {to_comp.id} is classified as development dependency.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=edge.source_ids,
                    evidence_ids=edge.evidence_ids,
                    limitations=["Development dependency may not be deployed."],
                ))
            elif to_comp.scope == Scope.OPTIONAL:
                self.add_finding(Finding(
                    id=new_id("FIND-OPT-", edge.id),
                    finding_type=FindingType.OPTIONAL_DEPENDENCY,
                    subject_id=to_comp.id,
                    statement=f"Component {to_comp.id} is classified as optional dependency.",
                    verification_state=VerificationState.OBSERVED,
                    source_ids=edge.source_ids,
                    evidence_ids=edge.evidence_ids,
                    limitations=["Optional dependency requires feature/configuration evidence before treating as active."],
                ))

    # -----------------------------------------------------------------
    # Quality / fact gate / hypotheses / outputs
    # -----------------------------------------------------------------

    def build_quality(self) -> None:
        total = len(self.components)
        if total == 0:
            self.quality = {"status": "NO_COMPONENTS"}
            return

        purl_cov = sum(1 for c in self.components.values() if c.purl and c.purl.startswith("pkg:")) / total
        ver_cov = sum(1 for c in self.components.values() if c.resolved_version or c.version) / total
        hash_cov = sum(1 for c in self.components.values() if c.hashes) / total
        lic_cov = sum(1 for c in self.components.values() if c.licenses) / total
        sup_cov = sum(1 for c in self.components.values() if c.supplier) / total
        prov_cov = sum(1 for c in self.components.values() if c.provenance_state in {ProvenanceState.STRONG, ProvenanceState.SUPPORTED, ProvenanceState.PARTIAL}) / total
        dep_edges = len(self.edges)
        dep_cov = min(1.0, dep_edges / max(1, total - len(self.sboms)))
        reachable = sum(1 for c in self.components.values() if self.component_paths.get(c.id))
        reach_cov = reachable / total
        trace_cov = sum(1 for c in self.components.values() if c.evidence_ids) / total

        freshness_scores = {
            FreshnessState.CURRENT: 1.0,
            FreshnessState.RECENT: 0.9,
            FreshnessState.AGING: 0.7,
            FreshnessState.STALE: 0.35,
            FreshnessState.UNKNOWN: 0.5,
        }
        fresh_cov = sum(freshness_scores.get(sb.freshness_state, 0.5) for sb in self.sboms.values()) / max(1, len(self.sboms))

        consistency_penalty = min(0.35, 0.05 * len(self.contradictions))
        consistency = max(0.0, 1.0 - consistency_penalty)

        dims = {
            "FORMAT_VALIDITY": 1.0 if self.sboms else 0.0,
            "IDENTITY_COMPLETENESS": round(purl_cov, 3),
            "VERSION_COMPLETENESS": round(ver_cov, 3),
            "DEPENDENCY_COMPLETENESS": round(dep_cov, 3),
            "HASH_COVERAGE": round(hash_cov, 3),
            "LICENSE_COVERAGE": round(lic_cov, 3),
            "SUPPLIER_COVERAGE": round(sup_cov, 3),
            "PROVENANCE_COVERAGE": round(prov_cov, 3),
            "FRESHNESS": round(fresh_cov, 3),
            "CONSISTENCY": round(consistency, 3),
            "TRACEABILITY": round(trace_cov, 3),
            "REACHABILITY_FROM_ROOT_COVERAGE": round(reach_cov, 3),
        }

        weights = {
            "FORMAT_VALIDITY": 0.10,
            "IDENTITY_COMPLETENESS": 0.15,
            "VERSION_COMPLETENESS": 0.12,
            "DEPENDENCY_COMPLETENESS": 0.12,
            "HASH_COVERAGE": 0.08,
            "LICENSE_COVERAGE": 0.07,
            "SUPPLIER_COVERAGE": 0.05,
            "PROVENANCE_COVERAGE": 0.08,
            "FRESHNESS": 0.08,
            "CONSISTENCY": 0.08,
            "TRACEABILITY": 0.04,
            "REACHABILITY_FROM_ROOT_COVERAGE": 0.03,
        }

        score = round(sum(dims[k] * weights[k] for k in dims), 3)
        state = "SBOM_QUALITY_HIGH" if score >= 0.85 else "SBOM_QUALITY_MEDIUM" if score >= 0.65 else "SBOM_QUALITY_LOW"

        self.quality = {
            "as_of": self.as_of,
            "component_count": total,
            "sbom_count": len(self.sboms),
            "edge_count": len(self.edges),
            "contradiction_count": len(self.contradictions),
            "dimensions": dims,
            "weights": weights,
            "score": score,
            "state": state,
            "guardrails": [
                "Quality score is transparent and dimension-weighted, not a mysterious badge.",
                "Large component count does not equal high quality.",
                "SBOM quality does not equal deployed/runtime truth.",
            ],
        }

        self.add_finding(Finding(
            id="FIND-SBOMQUALITY",
            finding_type=FindingType[state],
            subject_id=self.case.case_id,
            statement=f"Aggregate SBOM quality score {score} with state {state}.",
            verification_state=VerificationState.OBSERVED,
            limitations=["Score reflects available metadata coverage and consistency, not security assurance."],
        ))

    def fact_gate_findings(self) -> None:
        for f in self.findings.values():
            srcs = [self.sources[sid] for sid in f.source_ids if sid in self.sources]
            if not srcs:
                f.confidence = 0.0
                if f.verification_state == VerificationState.OBSERVED:
                    f.verification_state = VerificationState.INCONCLUSIVE
                f.limitations.append("No mapped source for fact gate.")
                continue

            families = self.source_families(f.source_ids)
            max_rel = max((s.reliability for s in srcs), default=0.5)
            direct = max((SOURCE_FACTOR.get(s.source_type, 0.65) for s in srcs), default=0.65)
            base = max_rel * direct

            if len(families) >= 2:
                base = min(0.99, base * 1.05)
            elif len(families) == 1 and len(f.source_ids) > 1:
                base *= 0.90
                f.limitations.append("Multiple sources share one upstream source family.")

            # Semantic guards.
            if f.finding_type == FindingType.COMPONENT_PRESENT:
                f.verification_state = VerificationState.SUPPORTED if base >= 0.70 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.append("Component presence is not deployed, loaded, reachable, vulnerable, or exploited.")

            elif f.finding_type == FindingType.VERSION_RESOLVED:
                f.verification_state = VerificationState.SUPPORTED if base >= 0.75 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.append("Resolved version is not automatically production/deployed version.")

            elif f.finding_type == FindingType.VERSION_DECLARED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Declared range is weaker evidence than resolved lockfile/build version.")

            elif f.finding_type == FindingType.VERSION_CONFLICT:
                f.verification_state = VerificationState.DISPUTED
                base = min(base, 0.85)
                f.limitations.append("Conflict preserved; no silent source preference.")

            elif f.finding_type in {
                FindingType.DIRECT_DEPENDENCY,
                FindingType.TRANSITIVE_DEPENDENCY,
                FindingType.RUNTIME_DEPENDENCY,
                FindingType.BUILD_DEPENDENCY,
                FindingType.DEV_DEPENDENCY,
                FindingType.OPTIONAL_DEPENDENCY,
            }:
                f.verification_state = VerificationState.OBSERVED if base >= 0.65 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.append("Dependency classification is build/SBOM evidence, not runtime reachability proof.")

            elif f.finding_type == FindingType.PURL_RESOLVED:
                f.verification_state = VerificationState.SUPPORTED if base >= 0.75 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.append("PURL is coordinate identity, not installed/deployed instance proof.")

            elif f.finding_type == FindingType.CPE_AMBIGUOUS:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.60)
                f.limitations.append("Ambiguous CPE must not be used for confident vulnerability matching.")

            elif f.finding_type == FindingType.HASH_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Hash supports byte identity/integrity context, not benignness.")

            elif f.finding_type == FindingType.LICENSE_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Declared license is not verified license.")

            elif f.finding_type == FindingType.LICENSE_CONFLICT_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.70)
                f.limitations.append("Legal interpretation requires LEGALINT/counsel.")

            elif f.finding_type == FindingType.PROVENANCE_PARTIAL:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Partial provenance is not contradiction or compromise.")

            elif f.finding_type == FindingType.ATTESTATION_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Attestation trust depends on issuer/build environment; not absolute truth.")

            elif f.finding_type == FindingType.SIGNATURE_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Signed != safe; unsigned != malicious.")

            elif f.finding_type == FindingType.VEX_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("VEX is assertion evidence, not unquestionable fact.")

            elif f.finding_type == FindingType.VEX_CONFLICT_CANDIDATE:
                f.verification_state = VerificationState.DISPUTED
                base = min(base, 0.80)
                f.limitations.append("Preserve VEX and external applicability until validated by VULNINT/configuration evidence.")

            elif f.finding_type == FindingType.VULNERABILITY_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.70)
                f.limitations.extend([
                    "Presence + advisory match is vulnerability candidate, not applicable vulnerability.",
                    "Reachability/exploitability/exploitation require VULNINT/incident evidence.",
                ])
                f.specialist_handoff = f.specialist_handoff or "VULNINT"

            elif f.finding_type == FindingType.EOL_OBSERVED:
                f.verification_state = VerificationState.SUPPORTED if base >= 0.70 else VerificationState.PARTIALLY_SUPPORTED
                f.limitations.append("EOL/EOS is maintenance-risk context, not current exploitation.")

            elif f.finding_type == FindingType.SBOM_STALE:
                f.verification_state = VerificationState.SUPPORTED
                f.limitations.append("Stale SBOM remains historical build evidence.")

            elif f.finding_type == FindingType.SBOM_DRIFT:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Drift is not incident; requires release/change context.")

            elif f.finding_type == FindingType.UNEXPECTED_COMPONENT_CANDIDATE:
                f.verification_state = VerificationState.CANDIDATE
                base = min(base, 0.65)
                f.limitations.append("Unexpected component may be benign feature/build/packaging change or malicious; do not jump to compromise.")

            elif f.finding_type in {FindingType.ORPHAN_COMPONENT, FindingType.BROKEN_REFERENCE}:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("May indicate SBOM incompleteness or normalization issue.")

            elif f.finding_type in {FindingType.RUNTIME_CONFLICT, FindingType.COMPONENT_ABSENT_IN_RUNTIME}:
                f.verification_state = VerificationState.DISPUTED
                f.limitations.append("Preserve build/SBOM and runtime evidence separately.")

            elif f.finding_type == FindingType.COMPONENT_LOADED_IN_RUNTIME:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Loaded is not reachable or vulnerable.")

            elif f.finding_type == FindingType.COMMON_COMPONENT_OBSERVED:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Common component supports systemic patch planning, not compromise inference.")

            elif f.finding_type in {
                FindingType.SBOM_QUALITY_LOW,
                FindingType.SBOM_QUALITY_MEDIUM,
                FindingType.SBOM_QUALITY_HIGH,
            }:
                f.verification_state = VerificationState.OBSERVED
                f.limitations.append("Quality score is metadata coverage/consistency, not security assurance.")

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
        hyps: List[Hypothesis] = []

        stale_findings = [f.id for f in self.findings.values() if f.finding_type == FindingType.SBOM_STALE]
        runtime_conflicts = [f.id for f in self.findings.values() if f.finding_type in {FindingType.RUNTIME_CONFLICT, FindingType.COMPONENT_ABSENT_IN_RUNTIME}]
        if stale_findings or runtime_conflicts:
            hyps.append(Hypothesis(
                id="H-SBOM-STALE",
                statement="One or more SBOMs are stale relative to current runtime/deployment state.",
                kind="SBOM_FRESHNESS",
                supporting_finding_ids=stale_findings + runtime_conflicts,
                assumptions=["Runtime inventory scope matches the analyzed deployment."],
                predictions=["Newer build-generated SBOM or deployment artifact digest would align with runtime inventory."],
                falsification_conditions=[
                    "Runtime inventory is from different environment/build.",
                    "SBOM represents an intentionally different build variant.",
                    "Component is optional/disabled in runtime.",
                ],
                status=HypothesisStatus.PROBABLE if stale_findings else HypothesisStatus.POSSIBLE,
                confidence=0.70,
                limitations=["Stale SBOM does not invalidate historical build evidence."],
            ))

        build_deps = [f.id for f in self.findings.values() if f.finding_type == FindingType.BUILD_DEPENDENCY]
        if build_deps:
            hyps.append(Hypothesis(
                id="H-BUILD-ONLY",
                statement="Some components are build-only and may not be present in production runtime.",
                kind="DEPENDENCY_SCOPE",
                supporting_finding_ids=build_deps,
                assumptions=["Build classification from SBOM/manifest is accurate."],
                predictions=["Final container/image/runtime inventory would omit build-only components."],
                falsification_conditions=[
                    "Build tool is bundled into runtime image.",
                    "Multi-stage build leaks artifact.",
                    "Runtime inventory scope is incomplete.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.60,
                limitations=["Build-only classification is not proof of absence without runtime/deployment evidence."],
            ))

        vuln_findings = [f.id for f in self.findings.values() if f.finding_type == FindingType.VULNERABILITY_CANDIDATE]
        vex_conflicts = [f.id for f in self.findings.values() if f.finding_type == FindingType.VEX_CONFLICT_CANDIDATE]
        if vuln_findings:
            hyps.append(Hypothesis(
                id="H-VULN-NOT-REACHABLE",
                statement="A matched vulnerable component may be present but not reachable/exploitable in the deployed configuration.",
                kind="VULNERABILITY_APPLICABILITY",
                supporting_finding_ids=vuln_findings + vex_conflicts,
                assumptions=["Advisory version range is accurate but reachability/configuration unknown."],
                predictions=["VULNINT reachability analysis and runtime configuration evidence would confirm or deny applicability."],
                falsification_conditions=[
                    "Component code path is reachable with attacker-controlled input.",
                    "Feature cited in VEX is enabled.",
                    "Backport/fork status invalidates naive range match.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.50,
                limitations=["SBOMINT does not determine exploitability or reachability."],
            ))

        unexpected = [f.id for f in self.findings.values() if f.finding_type == FindingType.UNEXPECTED_COMPONENT_CANDIDATE]
        if unexpected:
            hyps.append(Hypothesis(
                id="H-UNEXPECTED-BENIGN",
                statement="Unexpected component addition may be benign release/build/packaging change.",
                kind="SUPPLY_CHAIN_ANOMALY",
                supporting_finding_ids=unexpected,
                assumptions=["Release notes/change management may explain addition."],
                predictions=["Provenance, release diff, and package registry/repository metadata would explain origin."],
                falsification_conditions=[
                    "Component lacks provenance and appears in suspicious release window.",
                    "Package registry/repository metadata indicates takeover/typosquat/anomaly.",
                    "Runtime behavior or MALINT evidence suggests maliciousness.",
                ],
                status=HypothesisStatus.POSSIBLE,
                confidence=0.55,
                limitations=[
                    "Do not jump to compromise.",
                    "Malicious suspicion requires MALINT/PACKAGEINT/SUPPLYCHAININT evidence.",
                ],
            ))

        license_conflicts = [f.id for f in self.findings.values() if f.finding_type == FindingType.LICENSE_CONFLICT_CANDIDATE]
        if license_conflicts:
            hyps.append(Hypothesis(
                id="H-LICENSE-COMPAT",
                statement="License conflict candidate may require legal review depending on distribution/linking model.",
                kind="LICENSE",
                supporting_finding_ids=license_conflicts,
                assumptions=["Declared licenses may be incomplete or incorrect."],
                predictions=["Legal review would assess SPDX expressions, exceptions, distribution model, and obligations."],
                falsification_conditions=[
                    "Dependency license is incorrectly declared.",
                    "Distribution model avoids copyleft trigger.",
                    "Exception applies.",
                ],
                status=HypothesisStatus.UNRESOLVED,
                confidence=0.45,
                limitations=["SBOMINT does not make final legal conclusions."],
            ))

        self.hypotheses = hyps

    def build_knowledge_gaps(self) -> None:
        existing = {g.description for g in self.gaps}

        for comp in self.components.values():
            if not comp.purl:
                desc = f"Component {comp.id} lacks PURL identity."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-PURL-", comp.id),
                        gap_type=GapType.PURL_MISSING,
                        description=desc,
                        about_subject_ids=[comp.id],
                        importance="MEDIUM",
                        recommended_source="Lockfile, package registry metadata, build-generated SBOM",
                        specialist="PACKAGEINT",
                        expected_information_value=0.70,
                    ))
                    existing.add(desc)

            if comp.cpe_state in {"AMBIGUOUS", "UNKNOWN", "CANDIDATE"} and comp.cpe_candidates:
                desc = f"CPE mapping for component {comp.id} is ambiguous."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-CPE-", comp.id),
                        gap_type=GapType.CPE_AMBIGUOUS,
                        description=desc,
                        about_subject_ids=[comp.id],
                        importance="MEDIUM",
                        recommended_source="Authoritative CPE dictionary/vendor mapping",
                        specialist="VULNINT",
                        expected_information_value=0.65,
                    ))
                    existing.add(desc)

            if not comp.evidence_ids:
                desc = f"Component {comp.id} lacks evidence traceability."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-TRACE-", comp.id),
                        gap_type=GapType.COMPONENT_IDENTITY_UNRESOLVED,
                        description=desc,
                        about_subject_ids=[comp.id],
                        importance="MEDIUM",
                        recommended_source="Original SBOM/lockfile/runtime record",
                        specialist="SBOMINT",
                        expected_information_value=0.60,
                    ))
                    existing.add(desc)

        for f in self.findings.values():
            if f.finding_type == FindingType.VULNERABILITY_CANDIDATE:
                desc = f"Vulnerability applicability/reachability unresolved for finding {f.id}."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-VULN-", f.id),
                        gap_type=GapType.VULNERABILITY_APPLICABILITY_UNKNOWN,
                        description=desc,
                        about_subject_ids=[f.subject_id],
                        about_finding_ids=[f.id],
                        importance="HIGH",
                        recommended_source="VULNINT affected-version/reachability/configuration analysis",
                        specialist="VULNINT",
                        expected_information_value=0.90,
                    ))
                    existing.add(desc)

            if f.finding_type == FindingType.VEX_CONFLICT_CANDIDATE:
                desc = f"VEX conflict requires runtime/configuration validation for {f.subject_id}."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-VEX-", f.id),
                        gap_type=GapType.VEX_CONFLICT,
                        description=desc,
                        about_subject_ids=[f.subject_id],
                        about_finding_ids=[f.id],
                        importance="HIGH",
                        recommended_source="Authorized runtime configuration evidence and VULNINT analysis",
                        specialist="VULNINT",
                        expected_information_value=0.85,
                    ))
                    existing.add(desc)

        for sbom in self.sboms.values():
            if sbom.freshness_state in {FreshnessState.STALE, FreshnessState.UNKNOWN}:
                desc = f"SBOM {sbom.id} freshness is {sbom.freshness_state.value}."
                if desc not in existing:
                    self.gaps.append(KnowledgeGap(
                        id=new_id("GAP-FRESH-", sbom.id),
                        gap_type=GapType.SBOM_STALE,
                        description=desc,
                        about_subject_ids=[sbom.id],
                        importance="HIGH" if sbom.freshness_state == FreshnessState.STALE else "MEDIUM",
                        recommended_source="Current build-generated SBOM, deployment artifact digest, runtime inventory",
                        specialist="SBOMINT / CLOUDINT / DEPLOYMENTINT",
                        expected_information_value=0.80,
                    ))
                    existing.add(desc)

        if not self.runtime_inventories:
            desc = "No runtime inventory available; deployed/loaded component state unknown."
            if desc not in existing:
                self.gaps.append(KnowledgeGap(
                    id="GAP-RUNTIME",
                    gap_type=GapType.RUNTIME_PRESENCE_UNKNOWN,
                    description=desc,
                    about_subject_ids=list(self.components.keys()),
                    importance="HIGH",
                    recommended_source="Authorized runtime inventory/container filesystem/process inventory",
                    specialist="SBOMINT / CLOUDINT / DFIRINT",
                    expected_information_value=0.90,
                ))
                existing.add(desc)

    def build_next_actions(self) -> None:
        self.actions = [
            NextAction(
                id="ACT-LOCKFILE-SBOM",
                description="Retrieve current lockfile and build-generated SBOM for the exact release/build; preserve declared vs resolved versions separately.",
                priority=1,
                privacy_impact="LOW_IF_AUTHORIZED",
                expected_gain=0.90,
                specialist="SBOMINT / PACKAGEINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-RUNTIME-INVENTORY",
                description="Obtain authorized runtime/container inventory for deployed artifact to distinguish present/loaded/deployed components from build metadata.",
                priority=2,
                privacy_impact="MEDIUM_IF_AUTHORIZED",
                expected_gain=0.90,
                specialist="SBOMINT / CLOUDINT / DFIRINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-ARTIFACT-DIGEST",
                description="Verify artifact/image digest and map SBOM to exact build/release/artifact.",
                priority=3,
                privacy_impact="LOW",
                expected_gain=0.85,
                specialist="SBOMINT / SUPPLYCHAININT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-VULNINT-HANDOFF",
                description="Hand vulnerability candidate and VEX conflict components to VULNINT for applicability, reachability, backport, and configuration analysis.",
                priority=4,
                privacy_impact="LOW",
                expected_gain=0.90,
                specialist="VULNINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-PROVENANCE",
                description="Retrieve build provenance, attestations, signatures, and source repository references for unexpected or critical components.",
                priority=5,
                privacy_impact="LOW",
                expected_gain=0.80,
                specialist="SUPPLYCHAININT / PACKAGEINT / REPOINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-LICENSE-LEGAL",
                description="Route license conflict candidates to LEGALINT; SBOMINT does not make final legal determinations.",
                priority=6,
                privacy_impact="LOW",
                expected_gain=0.65,
                specialist="LEGALINT",
                requires_human_approval=False,
            ),
            NextAction(
                id="ACT-EOL-PLAN",
                description="Plan replacement/upgrade for EOL/EOS components through authorized change management; EOL is not automatic exploitation.",
                priority=7,
                privacy_impact="LOW",
                expected_gain=0.70,
                specialist="PACKAGEINT / SUPPLYCHAININT",
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-HUMAN-REVIEW",
                description="Require human review before production patching, package removal/replacement, consequential vulnerability promotion, or supply-chain compromise attribution.",
                priority=8,
                privacy_impact="PROTECTIVE",
                expected_gain=0.85,
                specialist=None,
                requires_human_approval=True,
            ),
            NextAction(
                id="ACT-NO-EXECUTION",
                description="Do not download/execute packages, run install scripts, exploit components, tamper with SBOMs, forge attestations/signatures, or enable dependency attacks.",
                priority=99,
                privacy_impact="PROTECTIVE",
                expected_gain=0.0,
                specialist=None,
                requires_human_approval=False,
            ),
        ]

    def build_recommendations(self) -> None:
        recs: List[Recommendation] = []

        for f in self.findings.values():
            if f.finding_type == FindingType.VULNERABILITY_CANDIDATE:
                recs.append(Recommendation(
                    id=new_id("REC-VULN-", f.id),
                    category="VULNERABILITY_CONTEXT",
                    action="Hand component/version/configuration evidence to VULNINT before promoting to applicable vulnerability.",
                    target=f.subject_id,
                    rationale="Component presence and advisory match create candidate, not verified application vulnerability.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval="HUMAN_APPROVAL_REQUIRED",
                    limitations=["Do not exploit component.", "Do not execute package to verify."],
                ))

            elif f.finding_type == FindingType.VEX_CONFLICT_CANDIDATE:
                recs.append(Recommendation(
                    id=new_id("REC-VEX-", f.id),
                    category="VEX_VALIDATION",
                    action="Obtain authorized runtime/configuration evidence for VEX justification and preserve conflict until validated.",
                    target=f.subject_id,
                    rationale="Vendor VEX NOT_AFFECTED conflicts with external applicability context and lacks configuration evidence.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval="HUMAN_APPROVAL_REQUIRED",
                    limitations=["Do not silently trust vendor or scanner."],
                ))

            elif f.finding_type == FindingType.SBOM_STALE:
                recs.append(Recommendation(
                    id=new_id("REC-STALE-", f.id),
                    category="SBOM_HYGIENE",
                    action="Regenerate SBOM from current build/deployment artifact and map it to release/build ID.",
                    target=f.subject_id,
                    rationale="SBOM is stale or conflicts with runtime evidence.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval="AUTONOMOUS_ANALYTIC",
                    limitations=["Preserve historical SBOM; do not overwrite."],
                ))

            elif f.finding_type == FindingType.LICENSE_CONFLICT_CANDIDATE:
                recs.append(Recommendation(
                    id=new_id("REC-LIC-", f.id),
                    category="LICENSE_REVIEW",
                    action="Route license conflict candidate to LEGALINT with SPDX expressions, dependency graph, and distribution model.",
                    target=f.subject_id,
                    rationale="Declared license metadata suggests possible compatibility/obligation question.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval="HUMAN_APPROVAL_REQUIRED",
                    limitations=["SBOMINT does not make legal conclusions."],
                ))

            elif f.finding_type == FindingType.UNEXPECTED_COMPONENT_CANDIDATE:
                recs.append(Recommendation(
                    id=new_id("REC-UNEXPECTED-", f.id),
                    category="SUPPLY_CHAIN_REVIEW",
                    action="Review provenance, release notes, registry metadata, and build diff before treating unexpected component as anomalous.",
                    target=f.subject_id,
                    rationale="Component appeared unexpectedly between SBOMs; benign and malicious explanations remain possible.",
                    finding_ids=[f.id],
                    evidence_ids=f.evidence_ids,
                    approval="HUMAN_APPROVAL_REQUIRED",
                    limitations=["Do not execute or install package for validation."],
                ))

        self.recommendations = recs

    def build_handoffs(self) -> None:
        self.handoffs = [
            {"specialist": "VULNINT", "reason": "Vulnerability applicability, affected ranges, backports, reachability, exploitability, remediation priority."},
            {"specialist": "PACKAGEINT", "reason": "Package identity, registry metadata, versions, maintainers, package health, typosquat defense."},
            {"specialist": "REPOINT", "reason": "Source repository, commits, releases, fork/lineage context."},
            {"specialist": "SUPPLYCHAININT", "reason": "Vendor/supplier/dependency propagation, build provenance, systemic risk."},
            {"specialist": "MALINT", "reason": "If component/package is suspected malicious; SBOMINT does not execute samples."},
            {"specialist": "CLOUDINT", "reason": "Deployed container/image/runtime cloud context."},
            {"specialist": "CERTINT", "reason": "Deep certificate/signature analysis."},
            {"specialist": "CREDINT", "reason": "If credentials/tokens appear in build metadata; SBOMINT does not use them."},
            {"specialist": "LEGALINT", "reason": "License interpretation and legal obligations."},
            {"specialist": "INCIDENTINT", "reason": "If component evidence connects to active incident/compromise."},
        ]

    def dual_ai_review(self) -> Dict[str, Any]:
        issues: List[str] = []

        if any(f.finding_type == FindingType.VULNERABILITY_CANDIDATE for f in self.findings.values()):
            issues.append("Vulnerability applicability/reachability remains unresolved; VULNINT handoff required.")

        if any(f.finding_type == FindingType.VEX_CONFLICT_CANDIDATE for f in self.findings.values()):
            issues.append("VEX conflicts remain open due absent runtime/configuration evidence.")

        if any(f.finding_type == FindingType.SBOM_STALE for f in self.findings.values()):
            issues.append("One or more SBOMs are stale relative to runtime/as-of evidence.")

        if any(f.finding_type == FindingType.RUNTIME_CONFLICT for f in self.findings.values()):
            issues.append("Runtime inventory conflicts with build/lockfile version evidence.")

        if any(f.finding_type == FindingType.LICENSE_CONFLICT_CANDIDATE for f in self.findings.values()):
            issues.append("License conflict candidate requires LEGALINT review.")

        if any(f.finding_type == FindingType.UNEXPECTED_COMPONENT_CANDIDATE for f in self.findings.values()):
            issues.append("Unexpected component addition requires provenance/release review.")

        if self.quality.get("state") == "SBOM_QUALITY_LOW":
            issues.append("SBOM quality is low for consequential decisions.")

        if self.contradictions:
            issues.append(f"{len(self.contradictions)} contradiction(s) remain open.")

        if not issues:
            verdict = "AGREE"
        elif len(issues) <= 5:
            verdict = "PARTIAL_AGREEMENT"
        else:
            verdict = "INSUFFICIENT_EVIDENCE"

        return {
            "primary_sbom_analyst": (
                "Build-generated SBOM and lockfile support component presence/resolved versions for the analyzed release. "
                "A transitive runtime component has an advisory range match, but applicability/reachability are unresolved. "
                "Vendor VEX NOT_AFFECTED conflicts due missing runtime configuration evidence. SBOM drift and an unexpected optional component require provenance review. "
                "Runtime inventory partially confirms deployed state."
            ),
            "independent_sbom_skeptic_issues": issues,
            "verdict": verdict,
            "adversarial_checks": [
                "Is SBOM component treated as deployed component? No; runtime evidence separated.",
                "Is deployed component treated as loaded/reachable? No.",
                "Is manifest range treated as resolved version? No.",
                "Is resolved version treated as production version? No.",
                "Is CVE range match treated as application vulnerability? No.",
                "Is VEX NOT_AFFECTED treated as unquestionable fact? No.",
                "Is signed treated as safe? No.",
                "Is hash equality treated as benignness? No.",
                "Were packages executed or install scripts run? No.",
                "Was any credential used? No.",
            ],
            "note": "AI agreement is analytical agreement, not independent component evidence.",
        }

    def analyst_summary(self, dual: Dict[str, Any]) -> str:
        app_comp = next((c for c in self.components.values() if c.component_type == ComponentType.APPLICATION), None)
        lib_b = self.components.get("COMP-LIB-B-110")
        sbom_new = self.sboms.get("SBOM-APP-1.1.0")

        lines = [
            f"PRODUCT / APPLICATION: {app_comp.name if app_comp else 'UNKNOWN'}",
            f"RELEASE / BUILD: {sbom_new.properties.get('release', 'UNKNOWN') if sbom_new else 'UNKNOWN'} / {sbom_new.properties.get('build', 'UNKNOWN') if sbom_new else 'UNKNOWN'}",
            f"SBOM FORMAT: {sbom_new.format.value if sbom_new else 'UNKNOWN'}",
            f"SBOM GENERATOR: {sbom_new.generator if sbom_new else 'UNKNOWN'} {sbom_new.generator_version if sbom_new else ''}",
            f"SBOM FRESHNESS: {sbom_new.freshness_state.value if sbom_new else 'UNKNOWN'}",
            f"SBOM QUALITY: {self.quality.get('score', 'UNKNOWN')} ({self.quality.get('state', 'UNKNOWN')})",
            f"COMPONENT COUNT: {len(self.components)}",
            f"DEPENDENCY EDGES: {len(self.edges)}",
            "",
            "COMPONENT FINDING:",
        ]

        if lib_b:
            lines.append(
                f"- {lib_b.name} {lib_b.resolved_version or lib_b.version} is present as transitive runtime dependency "
                f"in SBOM {lib_b.sbom_id}; PURL={lib_b.purl}; CPE state={lib_b.cpe_state}."
            )
            lines.append("- Advisory range match creates VULNERABILITY_CANDIDATE, not verified application vulnerability.")
            lines.append("- Vendor VEX NOT_AFFECTED conflicts because runtime/configuration evidence for cited mitigation is unavailable.")
        else:
            lines.append("- Target component not found in sample corpus.")

        lines.extend([
            "",
            "RUNTIME:",
            "- Runtime inventory partially confirms presence/loading for selected components.",
            "- Runtime presence is not reachability or exploitation.",
            "",
            "DRIFT:",
            f"- SBOM drift entries: {len(self.drift[0]['changes']) if self.drift else 0}.",
            "- Drift is not incident; requires release/change context.",
            "",
            "LICENSE / EOL / PROVENANCE:",
            "- License conflict candidate requires LEGALINT review.",
            "- EOL component observed; maintenance risk context only.",
            "- Provenance/attestation/signature context is partial.",
            "",
            f"DUAL-AI REVIEW: {dual['verdict']}.",
            "PRIVACY/POLICY: Defensive authorized SBOM intelligence only. No package execution, install-script execution, dependency poisoning, SBOM tampering, attestation/signature forgery, credential use, or exploitation.",
            "NEXT ACTION: Obtain current build/runtime artifact mapping, hand vulnerability candidate and VEX conflict to VULNINT, retrieve provenance for unexpected component, route license conflict to LEGALINT.",
        ])
        return "\n".join(lines)

    def prepare(self) -> None:
        self.build_dependency_graph()
        self.resolve_versions()
        self.analyze_identity_coverage()
        self.analyze_dependencies()
        self.analyze_runtime()
        self.analyze_sbom_freshness()
        self.analyze_sbom_drift()
        self.analyze_vex_vulnerability()
        self.analyze_licenses()
        self.analyze_provenance_signatures()
        self.analyze_eol()
        self.fact_gate_findings()
        self.build_quality()
        self.build_hypotheses()
        self.build_knowledge_gaps()
        self.build_next_actions()
        self.build_recommendations()
        self.build_handoffs()


def matching_vex_ids(vulns: List[VulnerabilityContext]) -> str:
    return ", ".join(v.id for v in vulns)


# =====================================================================
# SAMPLE DATA
# =====================================================================

def sample_case() -> Case:
    return Case(
        case_id="SAMPLE-SBOMINT-001",
        task_id="TASK-SBOMINT-001",
        objective=(
            "Authorized defensive SBOM and software component inventory analysis for payments-app releases, "
            "including dependency graph, PURL/version resolution, provenance, VEX correlation, runtime conflicts, "
            "license context, EOL context, SBOM quality, and vulnerability-context handoff."
        ),
        questions=[
            "Which components are declared/resolved in the SBOM?",
            "Which are direct/transitive/runtime/build/dev/optional?",
            "Does SBOM component presence prove deployed component?",
            "Is resolved version equal to runtime version?",
            "What vulnerability context applies and what remains candidate-only?",
            "Does VEX NOT_AFFECTED resolve the vulnerability question?",
            "What SBOM drift occurred between releases?",
            "What provenance/attestation/signature context exists?",
            "What license/EOL gaps require specialist handoff?",
            "What defensive next actions are justified?",
        ],
        scope=["authorized_defensive_sbom", "evidence_first", "case_scoped", "no_package_execution", "no_dependency_attack_enablement"],
        authorization="demo_authorized_sbom_intelligence",
        applications=["APP-PAYMENTS"],
        releases=["REL-1.0.0", "REL-1.1.0"],
        builds=["BUILD-100", "BUILD-110"],
        artifacts=["ART-PAYMENTS-1.1.0"],
        sboms=["SBOM-APP-1.0.0", "SBOM-APP-1.1.0"],
        time_range="2026-08-01/2026-10-09",
        as_of=DEFAULT_AS_OF,
        sample=True,
    )


def build_sample_sbomint() -> SbomInt:
    s = SbomInt(sample_case())
    retrieved = now_iso()

    # Sources
    s.add_source(Source(
        id="SRC-SBOM-110",
        title="Build-generated CycloneDX SBOM for payments-app 1.1.0",
        url="https://build.example/payments-app/sbom-1.1.0.cdx.json",
        source_type=SourceType.CYCLONEDX_SBOM,
        independence_group="BUILD_SBOM_ROOT",
        reliability=0.92,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Build-generated SBOM; represents build artifact, not automatically deployed runtime.",
    ))
    s.add_source(Source(
        id="SRC-SBOM-100",
        title="Build-generated CycloneDX SBOM for payments-app 1.0.0",
        url="https://build.example/payments-app/sbom-1.0.0.cdx.json",
        source_type=SourceType.CYCLONEDX_SBOM,
        independence_group="BUILD_SBOM_ROOT",
        reliability=0.92,
        derived_from="SRC-SBOM-110",
        published_at="2026-08-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Prior release SBOM included for drift analysis; derivative grouping kept conservative.",
    ))
    s.add_source(Source(
        id="SRC-MANIFEST",
        title="Package manifest for payments-app",
        url="https://repo.example/payments-app/pyproject.toml",
        source_type=SourceType.PACKAGE_MANIFEST,
        independence_group="MANIFEST_ROOT",
        reliability=0.88,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Manifest declares version ranges, not resolved versions.",
    ))
    s.add_source(Source(
        id="SRC-LOCK",
        title="Lockfile for payments-app 1.1.0",
        url="https://repo.example/payments-app/poetry.lock",
        source_type=SourceType.LOCKFILE,
        independence_group="LOCK_ROOT",
        reliability=0.94,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="Lockfile provides resolved versions and integrity hashes.",
    ))
    s.add_source(Source(
        id="SRC-CONTAINER",
        title="Container image SBOM/metadata for payments-app 1.1.0",
        url="https://registry.example/payments-app:1.1.0",
        source_type=SourceType.CONTAINER_SBOM,
        independence_group="CONTAINER_ROOT",
        reliability=0.90,
        published_at="2026-10-01T01:00:00Z",
        retrieved_at=retrieved,
        notes="Container SBOM represents image contents, not running container.",
    ))
    s.add_source(Source(
        id="SRC-RUNTIME",
        title="Authorized runtime inventory for deployed payments-app",
        url="https://runtime.example/payments-app/inventory",
        source_type=SourceType.RUNTIME_INVENTORY,
        independence_group="RUNTIME_ROOT",
        reliability=0.93,
        published_at="2026-10-08T00:00:00Z",
        retrieved_at=retrieved,
        notes="Runtime inventory stronger for deployed/loaded state than build SBOM.",
    ))
    s.add_source(Source(
        id="SRC-VEX",
        title="Vendor VEX document for payments-app 1.1.0",
        url="https://vendor.example/vex/payments-app-1.1.0",
        source_type=SourceType.VEX,
        independence_group="VENDOR_VEX_ROOT",
        reliability=0.82,
        published_at="2026-10-02T00:00:00Z",
        retrieved_at=retrieved,
        notes="VEX assertion; requires configuration/reachability validation.",
    ))
    s.add_source(Source(
        id="SRC-ADVISORY",
        title="External vulnerability advisory for lib-b",
        url="https://advisory.example/lib-b-cve-2026-9999",
        source_type=SourceType.VULNERABILITY_DATA,
        independence_group="ADVISORY_ROOT",
        reliability=0.84,
        published_at="2026-09-20T00:00:00Z",
        retrieved_at=retrieved,
        notes="Advisory affects lib-b range; applicability requires VULNINT.",
    ))
    s.add_source(Source(
        id="SRC-ATTEST",
        title="Build attestation for lib-b artifact",
        url="https://attest.example/lib-b-2.4.1.intoto.jsonl",
        source_type=SourceType.ATTESTATION,
        independence_group="ATTESTATION_ROOT",
        reliability=0.86,
        published_at="2026-09-25T00:00:00Z",
        retrieved_at=retrieved,
        notes="Attestation supports provenance context, not absolute truth.",
    ))
    s.add_source(Source(
        id="SRC-SIG",
        title="Release signature metadata for payments-app artifact",
        url="https://release.example/payments-app-1.1.0.sig",
        source_type=SourceType.SIGNATURE,
        independence_group="SIGNATURE_ROOT",
        reliability=0.86,
        published_at="2026-10-01T02:00:00Z",
        retrieved_at=retrieved,
        notes="Signature metadata; signed does not mean safe.",
    ))
    s.add_source(Source(
        id="SRC-EOL",
        title="OS package lifecycle database",
        url="https://lifecycle.example/os-packages",
        source_type=SourceType.EOL_DATABASE,
        independence_group="EOL_ROOT",
        reliability=0.82,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="EOL/EOS lifecycle context.",
    ))
    s.add_source(Source(
        id="SRC-LICENSE",
        title="License database / SPDX metadata",
        url="https://license.example/spdx",
        source_type=SourceType.LICENSE_DATABASE,
        independence_group="LICENSE_ROOT",
        reliability=0.78,
        published_at="2026-10-01T00:00:00Z",
        retrieved_at=retrieved,
        notes="License metadata; legal interpretation requires LEGALINT.",
    ))

    # Evidence
    s.add_evidence(Evidence(
        id="EV-SBOM-110",
        source_id="SRC-SBOM-110",
        artifact_type="cyclonedx_sbom",
        excerpt="CycloneDX SBOM for payments-app 1.1.0 generated during BUILD-110. Subject APP-110. Components include lib-a 3.2.0, lib-b 2.4.1, build-tool 1.0.0, optional-plugin 0.9.0, os-legacy 1.2.3-1, base-image digest.",
        observed_at="2026-10-01T00:00:00Z",
        parsed_fields={
            "format": "CycloneDX",
            "format_version": "1.5",
            "serial_number": "urn:uuid:payments-app-110",
            "release": "REL-1.1.0",
            "build": "BUILD-110",
        },
    ))
    s.add_evidence(Evidence(
        id="EV-SBOM-100",
        source_id="SRC-SBOM-100",
        artifact_type="cyclonedx_sbom",
        excerpt="CycloneDX SBOM for payments-app 1.0.0 generated during BUILD-100. Subject APP-100. Components include lib-a 3.1.0, lib-b 2.4.0, build-tool 1.0.0, os-legacy 1.2.3-1.",
        observed_at="2026-08-01T00:00:00Z",
        parsed_fields={
            "format": "CycloneDX",
            "format_version": "1.5",
            "serial_number": "urn:uuid:payments-app-100",
            "release": "REL-1.0.0",
            "build": "BUILD-100",
        },
    ))
    s.add_evidence(Evidence(
        id="EV-MANIFEST",
        source_id="SRC-MANIFEST",
        artifact_type="pyproject_manifest",
        excerpt="Manifest declares lib-a ^3.1, lib-b ^2.4, build-tool ^1.0, optional-plugin ^0.9 optional.",
        observed_at="2026-10-01T00:00:00Z",
        parsed_fields={
            "declared": {
                "lib-a": "^3.1",
                "lib-b": "^2.4",
                "build-tool": "^1.0",
                "optional-plugin": "^0.9",
            }
        },
    ))
    s.add_evidence(Evidence(
        id="EV-LOCK",
        source_id="SRC-LOCK",
        artifact_type="poetry_lock",
        excerpt="Lockfile resolves lib-a 3.2.0, lib-b 2.4.1, build-tool 1.0.0, optional-plugin 0.9.0 with sha256 hashes.",
        observed_at="2026-10-01T00:00:00Z",
        parsed_fields={
            "resolved": {
                "lib-a": "3.2.0",
                "lib-b": "2.4.1",
                "build-tool": "1.0.0",
                "optional-plugin": "0.9.0",
            }
        },
    ))
    s.add_evidence(Evidence(
        id="EV-CONTAINER",
        source_id="SRC-CONTAINER",
        artifact_type="container_sbom",
        excerpt="Container image payments-app:1.1.0 digest sha256:image110 includes base image digest sha256:base123 and final-stage packages.",
        observed_at="2026-10-01T01:00:00Z",
        parsed_fields={
            "image_digest": "sha256:image110",
            "base_image_digest": "sha256:base123",
            "multi_stage": True,
        },
    ))
    s.add_evidence(Evidence(
        id="EV-RUNTIME",
        source_id="SRC-RUNTIME",
        artifact_type="runtime_inventory",
        excerpt="Runtime inventory confirms lib-b 2.4.1 present and loaded in deployed payments-app. Feature F configuration is not captured. Optional plugin not observed in sampled runtime.",
        observed_at="2026-10-08T00:00:00Z",
        parsed_fields={
            "lib-b": {"present": True, "loaded": True, "version": "2.4.1"},
            "optional-plugin": {"present": False, "loaded": False, "version": None},
            "feature_f_enabled": None,
        },
    ))
    s.add_evidence(Evidence(
        id="EV-VEX",
        source_id="SRC-VEX",
        artifact_type="vex_document",
        excerpt="Vendor VEX states lib-b is NOT_AFFECTED in payments-app 1.1.0 because feature F is disabled by default.",
        observed_at="2026-10-02T00:00:00Z",
        parsed_fields={
            "status": "NOT_AFFECTED",
            "justification": "feature_f_disabled_by_default",
        },
    ))
    s.add_evidence(Evidence(
        id="EV-ADVISORY",
        source_id="SRC-ADVISORY",
        artifact_type="advisory",
        excerpt="Advisory CVE-2026-9999 affects lib-b >=2.4.0,<2.5.0. Fixed in 2.5.0. KEV false. EPSS 0.22.",
        observed_at="2026-09-20T00:00:00Z",
        parsed_fields={
            "cve": "CVE-2026-9999",
            "affected": ">=2.4.0,<2.5.0",
            "fixed": "2.5.0",
            "kev": False,
            "epss": 0.22,
        },
    ))
    s.add_evidence(Evidence(
        id="EV-ATTEST",
        source_id="SRC-ATTEST",
        artifact_type="attestation",
        excerpt="Build attestation for lib-b 2.4.1 subject digest sha256:libb241, issuer build-service, predicate SLSA provenance, verification PARTIAL.",
        observed_at="2026-09-25T00:00:00Z",
    ))
    s.add_evidence(Evidence(
        id="EV-SIG",
        source_id="SRC-SIG",
        artifact_type="signature_metadata",
        excerpt="Release artifact payments-app 1.1.0 signature verified by platform for signer payments-release-key.",
        observed_at="2026-10-01T02:00:00Z",
    ))
    s.add_evidence(Evidence(
        id="EV-EOL",
        source_id="SRC-EOL",
        artifact_type="eol_record",
        excerpt="OS package os-legacy 1.2.3-1 end of support 2025-12-31; deprecated true.",
        observed_at="2026-10-01T00:00:00Z",
    ))
    s.add_evidence(Evidence(
        id="EV-LICENSE",
        source_id="SRC-LICENSE",
        artifact_type="license_metadata",
        excerpt="License metadata: payments-app Proprietary, lib-a MIT, lib-b Apache-2.0, gpl-helper GPL-3.0-only.",
        observed_at="2026-10-01T00:00:00Z",
    ))

    # SBOM 1.0.0
    s.add_sbom(SBOM(
        id="SBOM-APP-1.0.0",
        format=SBOMFormat.CYCLONEDX,
        format_version="1.5",
        document_name="payments-app-1.0.0.cdx.json",
        serial_number="urn:uuid:payments-app-100",
        namespace="https://build.example/payments-app/1.0.0",
        creation_time="2026-08-01T00:00:00Z",
        generator="synthetic-cyclonedx-generator",
        generator_version="1.8.0",
        subject_component_id="COMP-APP-100",
        source_ids=["SRC-SBOM-100"],
        evidence_ids=["EV-SBOM-100"],
        confidence=0.90,
        properties={"release": "REL-1.0.0", "build": "BUILD-100"},
        limitations=["Build-generated SBOM; not automatically deployed runtime truth."],
    ))

    # SBOM 1.1.0
    s.add_sbom(SBOM(
        id="SBOM-APP-1.1.0",
        format=SBOMFormat.CYCLONEDX,
        format_version="1.5",
        document_name="payments-app-1.1.0.cdx.json",
        serial_number="urn:uuid:payments-app-110",
        namespace="https://build.example/payments-app/1.1.0",
        creation_time="2026-10-01T00:00:00Z",
        generator="synthetic-cyclonedx-generator",
        generator_version="1.9.0",
        subject_component_id="COMP-APP-110",
        source_ids=["SRC-SBOM-110", "SRC-LOCK", "SRC-CONTAINER"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK", "EV-CONTAINER"],
        confidence=0.93,
        properties={"release": "REL-1.1.0", "build": "BUILD-110", "image_digest": "sha256:image110"},
        limitations=["Build-generated SBOM; runtime inventory required for deployed-state claims."],
    ))

    # Components SBOM 1.0.0
    s.add_component(Component(
        id="COMP-APP-100",
        sbom_id="SBOM-APP-1.0.0",
        component_type=ComponentType.APPLICATION,
        name="payments-app",
        version="1.0.0",
        resolved_version="1.0.0",
        purl="pkg:generic/payments-app@1.0.0",
        licenses=["Proprietary"],
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-100"],
        evidence_ids=["EV-SBOM-100"],
        confidence=0.92,
    ))
    s.add_component(Component(
        id="COMP-LIB-A-100",
        sbom_id="SBOM-APP-1.0.0",
        component_type=ComponentType.LIBRARY,
        name="lib-a",
        version="3.1.0",
        declared_version="^3.1",
        resolved_version="3.1.0",
        purl="pkg:pypi/lib-a@3.1.0",
        licenses=["MIT"],
        hashes={"SHA-256": "sha256:liba310"},
        supplier="Acme Library Team",
        registry="PyPI",
        repository="https://repo.example/lib-a",
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-100", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-100", "EV-LOCK"],
        confidence=0.91,
    ))
    s.add_component(Component(
        id="COMP-LIB-B-100",
        sbom_id="SBOM-APP-1.0.0",
        component_type=ComponentType.LIBRARY,
        name="lib-b",
        version="2.4.0",
        declared_version="^2.4",
        resolved_version="2.4.0",
        purl="pkg:pypi/lib-b@2.4.0",
        cpe_candidates=["cpe:2.3:a:lib-b:lib-b:2.4.0:*:*:*:*:*:*:*"],
        cpe_state="CANDIDATE",
        licenses=["Apache-2.0"],
        hashes={"SHA-256": "sha256:libb240"},
        supplier="LibB Project",
        registry="PyPI",
        repository="https://repo.example/lib-b",
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-100", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-100", "EV-LOCK"],
        confidence=0.90,
    ))
    s.add_component(Component(
        id="COMP-BUILD-C-100",
        sbom_id="SBOM-APP-1.0.0",
        component_type=ComponentType.TOOL,
        name="build-tool",
        version="1.0.0",
        resolved_version="1.0.0",
        purl="pkg:npm/build-tool@1.0.0",
        licenses=["MIT"],
        hashes={"SHA-256": "sha256:buildtool100"},
        scope=Scope.BUILD,
        source_ids=["SRC-SBOM-100", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-100", "EV-LOCK"],
        confidence=0.88,
    ))
    s.add_component(Component(
        id="COMP-OS-E-100",
        sbom_id="SBOM-APP-1.0.0",
        component_type=ComponentType.OPERATING_SYSTEM,
        name="os-legacy",
        version="1.2.3-1",
        resolved_version="1.2.3-1",
        purl="pkg:deb/debian/os-legacy@1.2.3-1",
        licenses=["GPL-2.0-only"],
        hashes={"SHA-256": "sha256:oslegacy1231"},
        supplier="Debian-like OS Maintainers",
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-100", "SRC-CONTAINER"],
        evidence_ids=["EV-SBOM-100", "EV-CONTAINER"],
        confidence=0.88,
    ))

    # Components SBOM 1.1.0
    s.add_component(Component(
        id="COMP-APP-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.APPLICATION,
        name="payments-app",
        version="1.1.0",
        resolved_version="1.1.0",
        purl="pkg:generic/payments-app@1.1.0",
        licenses=["Proprietary"],
        hashes={"SHA-256": "sha256:app110"},
        signing_state=SigningState.SIGNED_VERIFIED,
        provenance_state=ProvenanceState.PARTIAL,
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-110", "SRC-SIG", "SRC-CONTAINER"],
        evidence_ids=["EV-SBOM-110", "EV-SIG", "EV-CONTAINER"],
        confidence=0.94,
    ))
    s.add_component(Component(
        id="COMP-LIB-A-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.LIBRARY,
        name="lib-a",
        version="3.2.0",
        declared_version="^3.1",
        resolved_version="3.2.0",
        purl="pkg:pypi/lib-a@3.2.0",
        licenses=["MIT"],
        hashes={"SHA-256": "sha256:liba320"},
        supplier="Acme Library Team",
        registry="PyPI",
        repository="https://repo.example/lib-a",
        provenance_state=ProvenanceState.SELF_REPORTED,
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-110", "SRC-LOCK", "SRC-LICENSE"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK", "EV-LICENSE"],
        confidence=0.93,
    ))
    s.add_component(Component(
        id="COMP-LIB-B-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.LIBRARY,
        name="lib-b",
        version="2.4.1",
        declared_version="^2.4",
        resolved_version="2.4.1",
        runtime_version="2.4.1",
        purl="pkg:pypi/lib-b@2.4.1",
        cpe_candidates=["cpe:2.3:a:lib-b:lib-b:2.4.1:*:*:*:*:*:*:*"],
        cpe_state="AMBIGUOUS",
        licenses=["Apache-2.0"],
        hashes={"SHA-256": "sha256:libb241"},
        supplier="LibB Project",
        registry="PyPI",
        repository="https://repo.example/lib-b",
        provenance_state=ProvenanceState.PARTIAL,
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-110", "SRC-LOCK", "SRC-ATTEST", "SRC-ADVISORY", "SRC-RUNTIME"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK", "EV-ATTEST", "EV-ADVISORY", "EV-RUNTIME"],
        confidence=0.94,
        limitations=["Advisory range match creates candidate; reachability/configuration unresolved."],
    ))
    s.add_component(Component(
        id="COMP-BUILD-C-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.TOOL,
        name="build-tool",
        version="1.0.0",
        resolved_version="1.0.0",
        purl="pkg:npm/build-tool@1.0.0",
        licenses=["MIT"],
        hashes={"SHA-256": "sha256:buildtool100"},
        scope=Scope.BUILD,
        source_ids=["SRC-SBOM-110", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK"],
        confidence=0.88,
    ))
    s.add_component(Component(
        id="COMP-PLUGIN-D-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.PLUGIN,
        name="optional-plugin",
        version="0.9.0",
        declared_version="^0.9",
        resolved_version="0.9.0",
        purl="pkg:pypi/optional-plugin@0.9.0",
        licenses=["BSD-3-Clause"],
        hashes={"SHA-256": "sha256:optplugin090"},
        supplier="Community Plugin Maintainers",
        scope=Scope.OPTIONAL,
        source_ids=["SRC-SBOM-110", "SRC-LOCK", "SRC-RUNTIME"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK", "EV-RUNTIME"],
        confidence=0.82,
        limitations=["Optional component; runtime inventory sampled did not observe it."],
    ))
    s.add_component(Component(
        id="COMP-OS-E-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.OPERATING_SYSTEM,
        name="os-legacy",
        version="1.2.3-1",
        resolved_version="1.2.3-1",
        purl="pkg:deb/debian/os-legacy@1.2.3-1",
        licenses=["GPL-2.0-only"],
        hashes={"SHA-256": "sha256:oslegacy1231"},
        supplier="Debian-like OS Maintainers",
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-110", "SRC-CONTAINER", "SRC-EOL"],
        evidence_ids=["EV-SBOM-110", "EV-CONTAINER", "EV-EOL"],
        confidence=0.88,
    ))
    s.add_component(Component(
        id="COMP-BASE-F-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.CONTAINER,
        name="base-image",
        version="sha256:base123",
        resolved_version="sha256:base123",
        purl="pkg:oci/base-image@sha256:base123",
        licenses=["UNKNOWN"],
        hashes={"SHA-256": "sha256:base123"},
        registry="registry.example",
        scope=Scope.RUNTIME,
        source_ids=["SRC-CONTAINER"],
        evidence_ids=["EV-CONTAINER"],
        confidence=0.88,
        limitations=["Base image digest stronger identity than mutable tag."],
    ))
    s.add_component(Component(
        id="COMP-GPL-HELPER-110",
        sbom_id="SBOM-APP-1.1.0",
        component_type=ComponentType.LIBRARY,
        name="gpl-helper",
        version="1.4.0",
        resolved_version="1.4.0",
        purl="pkg:pypi/gpl-helper@1.4.0",
        licenses=["GPL-3.0-only"],
        hashes={"SHA-256": "sha256:gplhelper140"},
        supplier="GPL Helper Project",
        registry="PyPI",
        scope=Scope.RUNTIME,
        source_ids=["SRC-SBOM-110", "SRC-LOCK", "SRC-LICENSE"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK", "EV-LICENSE"],
        confidence=0.88,
    ))

    # Edges SBOM 1.0.0
    s.add_edge(DependencyEdge(
        id="EDGE-100-APP-A",
        sbom_id="SBOM-APP-1.0.0",
        from_component_id="COMP-APP-100",
        to_component_id="COMP-LIB-A-100",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-SBOM-100"],
        evidence_ids=["EV-SBOM-100"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-100-A-B",
        sbom_id="SBOM-APP-1.0.0",
        from_component_id="COMP-LIB-A-100",
        to_component_id="COMP-LIB-B-100",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-SBOM-100", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-100", "EV-LOCK"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-100-APP-C",
        sbom_id="SBOM-APP-1.0.0",
        from_component_id="COMP-APP-100",
        to_component_id="COMP-BUILD-C-100",
        relationship_type="BUILD_DEPENDS_ON",
        source_ids=["SRC-SBOM-100"],
        evidence_ids=["EV-SBOM-100"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-100-APP-OS",
        sbom_id="SBOM-APP-1.0.0",
        from_component_id="COMP-APP-100",
        to_component_id="COMP-OS-E-100",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-SBOM-100", "SRC-CONTAINER"],
        evidence_ids=["EV-SBOM-100", "EV-CONTAINER"],
    ))

    # Edges SBOM 1.1.0
    s.add_edge(DependencyEdge(
        id="EDGE-110-APP-A",
        sbom_id="SBOM-APP-1.1.0",
        from_component_id="COMP-APP-110",
        to_component_id="COMP-LIB-A-110",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-SBOM-110"],
        evidence_ids=["EV-SBOM-110"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-110-A-B",
        sbom_id="SBOM-APP-1.1.0",
        from_component_id="COMP-LIB-A-110",
        to_component_id="COMP-LIB-B-110",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-SBOM-110", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-110-A-GPL",
        sbom_id="SBOM-APP-1.1.0",
        from_component_id="COMP-LIB-A-110",
        to_component_id="COMP-GPL-HELPER-110",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-SBOM-110", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-110-APP-C",
        sbom_id="SBOM-APP-1.1.0",
        from_component_id="COMP-APP-110",
        to_component_id="COMP-BUILD-C-110",
        relationship_type="BUILD_DEPENDS_ON",
        source_ids=["SRC-SBOM-110"],
        evidence_ids=["EV-SBOM-110"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-110-APP-D",
        sbom_id="SBOM-APP-1.1.0",
        from_component_id="COMP-APP-110",
        to_component_id="COMP-PLUGIN-D-110",
        relationship_type="OPTIONALLY_DEPENDS_ON",
        source_ids=["SRC-SBOM-110", "SRC-LOCK"],
        evidence_ids=["EV-SBOM-110", "EV-LOCK"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-110-APP-OS",
        sbom_id="SBOM-APP-1.1.0",
        from_component_id="COMP-APP-110",
        to_component_id="COMP-OS-E-110",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-SBOM-110", "SRC-CONTAINER"],
        evidence_ids=["EV-SBOM-110", "EV-CONTAINER"],
    ))
    s.add_edge(DependencyEdge(
        id="EDGE-110-APP-BASE",
        sbom_id="SBOM-APP-1.1.0",
        from_component_id="COMP-APP-110",
        to_component_id="COMP-BASE-F-110",
        relationship_type="RUNTIME_DEPENDS_ON",
        source_ids=["SRC-CONTAINER"],
        evidence_ids=["EV-CONTAINER"],
    ))

    # VEX
    s.add_vex(VEXStatement(
        id="VEX-LIBB-NOT_AFFECTED",
        component_id="COMP-LIB-B-110",
        sbom_id="SBOM-APP-1.1.0",
        vex_status=VexStatus.NOT_AFFECTED,
        justification="feature_f_disabled_by_default",
        vendor="Payments Inc.",
        statement_time="2026-10-02T00:00:00Z",
        source_ids=["SRC-VEX"],
        evidence_ids=["EV-VEX"],
        limitations=["Vendor assertion requires configuration/reachability validation."],
    ))

    # Vulnerability context
    s.add_vulnerability_context(VulnerabilityContext(
        id="VC-CVE-2026-9999-LIBB",
        component_id="COMP-LIB-B-110",
        advisory_id="GHSA-like-2026-9999",
        cve="CVE-2026-9999",
        match_state=VulnMatchState.RANGE_MATCH,
        affected_versions=">=2.4.0,<2.5.0",
        fixed_versions="2.5.0",
        kev=False,
        epss=0.22,
        severity="HIGH",
        source_ids=["SRC-ADVISORY"],
        evidence_ids=["EV-ADVISORY"],
        limitations=["Range match is not application vulnerability proof."],
    ))

    # Attestation / Signature
    s.add_attestation(Attestation(
        id="ATT-LIBB-241",
        subject_component_id="COMP-LIB-B-110",
        subject_artifact="sha256:libb241",
        predicate_type="https://slsa.dev/provenance/v0.2",
        subject_digest="sha256:libb241",
        issuer="build-service.example",
        builder="synthetic-builder-01",
        attested_at="2026-09-25T00:00:00Z",
        verification_state="PARTIAL",
        source_ids=["SRC-ATTEST"],
        evidence_ids=["EV-ATTEST"],
        limitations=["Attestation verification partial; issuer/build environment trust unresolved."],
    ))
    s.add_signature(Signature(
        id="SIG-APP-110",
        subject_component_id="COMP-APP-110",
        subject_artifact="sha256:app110",
        signer="payments-release-key",
        certificate="cert-placeholder",
        timestamp="2026-10-01T02:00:00Z",
        verification_state="VERIFIED",
        source_ids=["SRC-SIG"],
        evidence_ids=["EV-SIG"],
        limitations=["Signed release supports provenance/integrity context, not absence of vulnerabilities."],
    ))

    # EOL
    s.add_eol(EOLRecord(
        id="EOL-OS-LEGACY",
        component_id="COMP-OS-E-110",
        status="END_OF_SUPPORT",
        end_of_support="2025-12-31T00:00:00Z",
        deprecated=True,
        source_ids=["SRC-EOL"],
        evidence_ids=["EV-EOL"],
        limitations=["EOL/EOS is maintenance risk context, not current exploitation."],
    ))

    # Runtime inventory
    s.add_runtime_inventory(RuntimeInventory(
        id="RT-LIBB-110",
        component_id="COMP-LIB-B-110",
        present=True,
        loaded=True,
        version="2.4.1",
        observed_at="2026-10-08T00:00:00Z",
        extra={"feature_f_enabled": None},
        source_ids=["SRC-RUNTIME"],
        evidence_ids=["EV-RUNTIME"],
        limitations=["Runtime inventory sampled; feature configuration not captured."],
    ))
    s.add_runtime_inventory(RuntimeInventory(
        id="RT-PLUGIN-D-110",
        component_id="COMP-PLUGIN-D-110",
        present=False,
        loaded=False,
        version=None,
        observed_at="2026-10-08T00:00:00Z",
        extra={},
        source_ids=["SRC-RUNTIME"],
        evidence_ids=["EV-RUNTIME"],
        limitations=["Sampled runtime did not observe optional plugin; does not prove global absence."],
    ))

    s.prepare()
    return s


# =====================================================================
# RESULT BUILDER
# =====================================================================

def graph_version_hash(s: SbomInt) -> str:
    seed_obj = {
        "sboms": sorted((sid, sb.format.value, sb.creation_time or "", sb.freshness_state.value) for sid, sb in s.sboms.items()),
        "components": sorted((cid, c.sbom_id, c.name, c.version or "", c.purl or "", c.scope.value) for cid, c in s.components.items()),
        "edges": sorted((eid, e.sbom_id, e.from_component_id, e.to_component_id, e.derived_relationship or e.relationship_type) for eid, e in s.edges.items()),
        "findings": sorted((fid, f.finding_type.value, f.subject_id, f.verification_state.value, round(float(f.confidence), 3)) for fid, f in s.findings.items()),
    }
    return sha256_short(json.dumps(jsonable(seed_obj), sort_keys=True))


def build_source_graph(s: SbomInt) -> Dict[str, Any]:
    edges = []
    for src in s.sources.values():
        if src.derived_from:
            edges.append({
                "source": src.derived_from,
                "target": src.id,
                "relationship_type": "DERIVED_FROM",
            })
    return {
        "nodes": [x.id for x in s.sources.values()],
        "edges": edges,
    }


def build_source_dependency_graph(s: SbomInt) -> Dict[str, List[str]]:
    families: Dict[str, List[str]] = defaultdict(list)
    for sid in s.sources:
        fam = s.get_source_family(sid) or "UNKNOWN"
        families[fam].append(sid)
    return {k: sorted(v) for k, v in families.items()}


def build_dependency_graph_payload(s: SbomInt) -> Dict[str, Any]:
    nodes = []
    edges = []

    for comp in s.components.values():
        nodes.append({
            "id": comp.id,
            "type": "Component",
            "sbom_id": comp.sbom_id,
            "name": comp.name,
            "version": comp.version or comp.resolved_version,
            "purl": comp.purl,
            "scope": comp.scope.value,
            "dependency_depth": comp.dependency_depth,
            "runtime_context": comp.runtime_context,
        })

    for edge in s.edges.values():
        edges.append({
            "id": edge.id,
            "sbom_id": edge.sbom_id,
            "from": edge.from_component_id,
            "to": edge.to_component_id,
            "relationship_type": edge.relationship_type,
            "derived_relationship": edge.derived_relationship,
            "depth": edge.depth,
            "path": edge.path,
            "source_ids": edge.source_ids,
            "evidence_ids": edge.evidence_ids,
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "paths": {k: v for k, v in s.component_paths.items()},
        "guardrails": [
            "Dependency graph is build/SBOM evidence, not runtime reachability proof.",
            "Multiple paths preserved where available.",
            "Cycle-safe traversal used; dynamic loading may remain unknown.",
        ],
    }


def build_result(s: SbomInt, status: Status) -> Dict[str, Any]:
    dual = s.dual_ai_review()
    summary = s.analyst_summary(dual)
    source_families = build_source_dependency_graph(s)

    finding_independence = {
        fid: s.independence_state(f.source_ids)
        for fid, f in s.findings.items()
    }

    supported_facts = [f for f in s.findings.values() if f.verification_state == VerificationState.SUPPORTED]
    partial_facts = [f for f in s.findings.values() if f.verification_state == VerificationState.PARTIALLY_SUPPORTED]
    candidate_facts = [f for f in s.findings.values() if f.verification_state == VerificationState.CANDIDATE]
    disputed_facts = [f for f in s.findings.values() if f.verification_state == VerificationState.DISPUTED]
    observed_facts = [f for f in s.findings.values() if f.verification_state == VerificationState.OBSERVED]

    replay_manifest = {
        "generated_at": now_iso(),
        "pipeline_version": PIPELINE_VERSION,
        "graph_version": graph_version_hash(s),
        "core_principle": (
            "SBOM / MANIFEST / INVENTORY -> PRESERVE ORIGINAL -> FORMAT DETECTION -> PARSE -> NORMALIZE -> "
            "COMPONENT IDENTITY -> VERSION RESOLUTION -> DEPENDENCY GRAPH -> COMPONENT ROLE -> PROVENANCE -> "
            "HASH / INTEGRITY METADATA -> LICENSE CONTEXT -> VEX CONTEXT -> VULNERABILITY CONTEXT -> "
            "TEMPORAL VALIDATION -> SOURCE RELIABILITY -> SOURCE INDEPENDENCE -> FACT GATE -> SUPPLY-CHAIN ASSESSMENT"
        ),
        "as_of": s.as_of,
        "temporal_rule": "SBOM generation time, build time, release time, deployment time, and runtime inventory time preserved separately.",
        "component_rule": "SBOM component != deployed component != loaded component != reachable component != vulnerable component != exploited component.",
        "version_rule": "Declared range != resolved version != installed version != runtime version != production version.",
        "vex_rule": "VEX is assertion evidence, not unquestionable fact; conflicts preserved.",
        "vulnerability_rule": "CVE/advisory match creates candidate; applicability/reachability/exploitability belongs to VULNINT.",
        "source_rule": "Multiple dashboards/tools parsing same SBOM are not independent evidence.",
        "policy_exclusions": [
            "No package download/execution/install-script execution.",
            "No malicious package publication.",
            "No dependency poisoning/confusion/typosquatting.",
            "No registry/repository/CI/CD compromise.",
            "No SBOM tampering.",
            "No attestation/signature forgery.",
            "No signing-key use.",
            "No exploitation of vulnerable components.",
            "No credential use from build artifacts.",
            "No security-control disabling or integrity evasion.",
        ],
        "source_lineage": source_families,
        "finding_independence": finding_independence,
    }

    return {
        "case_id": s.case.case_id,
        "task_id": s.case.task_id,
        "objective": s.case.objective,
        "questions": s.case.questions,
        "scope": s.case.scope,
        "authorization": s.case.authorization,
        "status": status.value,
        "as_of": s.as_of,

        "source_ids": sorted(s.sources.keys()),
        "evidence_ids": sorted(s.evidence.keys()),

        "applications": s.case.applications,
        "products": s.case.products,
        "releases": s.case.releases,
        "builds": s.case.builds,
        "artifacts": s.case.artifacts,

        "sboms": list(s.sboms.values()),
        "sbom_formats": sorted({sb.format.value for sb in s.sboms.values()}),
        "sbom_versions": {sid: sb.format_version for sid, sb in s.sboms.items()},
        "generator_tools": {sid: f"{sb.generator}:{sb.generator_version}" for sid, sb in s.sboms.items()},

        "components": list(s.components.values()),
        "component_types": sorted({c.component_type.value for c in s.components.values()}),
        "component_aliases": [
            {
                "component_id": c.id,
                "name": c.name,
                "namespace": c.namespace,
                "purl": c.purl,
                "swid": c.swid,
                "cpe_candidates": c.cpe_candidates,
            }
            for c in s.components.values()
        ],
        "packages": [c for c in s.components.values() if c.component_type in {ComponentType.PACKAGE, ComponentType.LIBRARY, ComponentType.FRAMEWORK, ComponentType.PLUGIN, ComponentType.MODULE}],
        "versions": {
            c.id: {
                "declared": c.declared_version,
                "resolved": c.resolved_version,
                "installed": c.installed_version,
                "runtime": c.runtime_version,
                "version": c.version,
            }
            for c in s.components.values()
        },
        "purls": {c.id: c.purl for c in s.components.values() if c.purl},
        "cpe_candidates": {c.id: c.cpe_candidates for c in s.components.values() if c.cpe_candidates},
        "swids": {c.id: c.swid for c in s.components.values() if c.swid},
        "hashes": {c.id: c.hashes for c in s.components.values() if c.hashes},
        "licenses": {c.id: c.licenses for c in s.components.values() if c.licenses},
        "suppliers": {c.id: c.supplier for c in s.components.values() if c.supplier},
        "manufacturers": {c.id: c.manufacturer_candidate for c in s.components.values() if c.manufacturer_candidate},
        "maintainers": {},
        "registries": {c.id: c.registry for c in s.components.values() if c.registry},
        "repositories": {c.id: c.repository for c in s.components.values() if c.repository},
        "artifacts_registries": [
            {
                "sbom_id": sb.id,
                "image_digest": sb.properties.get("image_digest"),
                "base_image_digest": s.components.get("COMP-BASE-F-110").hashes.get("SHA-256") if s.components.get("COMP-BASE-F-110") else None,
            }
            for sb in s.sboms.values()
        ],

        "dependency_graph": build_dependency_graph_payload(s),
        "direct_dependencies": [c.id for c in s.components.values() if c.dependency_depth == 1],
        "transitive_dependencies": [c.id for c in s.components.values() if c.dependency_depth and c.dependency_depth > 1],
        "runtime_dependencies": [c.id for c in s.components.values() if c.scope == Scope.RUNTIME],
        "build_dependencies": [c.id for c in s.components.values() if c.scope == Scope.BUILD],
        "development_dependencies": [c.id for c in s.components.values() if c.scope == Scope.DEVELOPMENT],
        "optional_dependencies": [c.id for c in s.components.values() if c.scope == Scope.OPTIONAL],
        "dependency_depth": {c.id: c.dependency_depth for c in s.components.values()},
        "multiple_versions": [
            {
                "component_key": purl_base(c.purl) or c.name,
                "component_ids": [x.id for x in s.components.values() if (purl_base(x.purl) or x.name) == (purl_base(c.purl) or c.name)],
                "versions": sorted({x.version or x.resolved_version for x in s.components.values() if (purl_base(x.purl) or x.name) == (purl_base(c.purl) or c.name)}),
            }
            for c in s.components.values()
        ],
        "duplicate_components": [],
        "orphan_components": [f.subject_id for f in s.findings.values() if f.finding_type == FindingType.ORPHAN_COMPONENT],
        "broken_references": [f.subject_id for f in s.findings.values() if f.finding_type == FindingType.BROKEN_REFERENCE],

        "containers": [
            {
                "component_id": c.id,
                "name": c.name,
                "digest": c.resolved_version,
                "registry": c.registry,
            }
            for c in s.components.values()
            if c.component_type == ComponentType.CONTAINER
        ],
        "base_images": [
            {
                "component_id": "COMP-BASE-F-110",
                "digest": "sha256:base123",
                "note": "Digest preferred over mutable tag."
            }
        ],
        "os_packages": [c.id for c in s.components.values() if c.component_type == ComponentType.OPERATING_SYSTEM],
        "firmware_components": [c.id for c in s.components.values() if c.component_type == ComponentType.FIRMWARE],

        "component_provenance": {c.id: c.provenance_state.value for c in s.components.values()},
        "build_provenance": [
            {
                "sbom_id": sb.id,
                "build": sb.properties.get("build"),
                "release": sb.properties.get("release"),
                "image_digest": sb.properties.get("image_digest"),
            }
            for sb in s.sboms.values()
        ],
        "attestations": list(s.attestations.values()),
        "signatures": list(s.signatures.values()),

        "vex_records": list(s.vex_statements.values()),
        "vulnerability_context": list(s.vulnerability_contexts.values()),
        "eol_eos_context": list(s.eol_records.values()),

        "sbom_quality": s.quality,
        "sbom_completeness": {
            "component_count": len(s.components),
            "edge_count": len(s.edges),
            "purl_coverage": s.quality.get("dimensions", {}).get("IDENTITY_COMPLETENESS"),
            "version_coverage": s.quality.get("dimensions", {}).get("VERSION_COMPLETENESS"),
            "dependency_coverage": s.quality.get("dimensions", {}).get("DEPENDENCY_COMPLETENESS"),
            "hash_coverage": s.quality.get("dimensions", {}).get("HASH_COVERAGE"),
            "license_coverage": s.quality.get("dimensions", {}).get("LICENSE_COVERAGE"),
            "supplier_coverage": s.quality.get("dimensions", {}).get("SUPPLIER_COVERAGE"),
            "provenance_coverage": s.quality.get("dimensions", {}).get("PROVENANCE_COVERAGE"),
        },
        "sbom_freshness": {sb.id: sb.freshness_state.value for sb in s.sboms.values()},
        "sbom_drift": s.drift,
        "release_diffs": s.drift,
        "runtime_conflicts": [f for f in s.findings.values() if f.finding_type in {FindingType.RUNTIME_CONFLICT, FindingType.COMPONENT_ABSENT_IN_RUNTIME, FindingType.VERSION_CONFLICT}],
        "common_components": s.common_components,

        "timeline_updates": [
            {
                "time": "2026-08-01T00:00:00Z",
                "event": "SBOM-APP-1.0.0 generated for BUILD-100 / REL-1.0.0.",
                "source_ids": ["SRC-SBOM-100"],
            },
            {
                "time": "2026-09-20T00:00:00Z",
                "event": "Advisory CVE-2026-9999 published affecting lib-b >=2.4.0,<2.5.0.",
                "source_ids": ["SRC-ADVISORY"],
            },
            {
                "time": "2026-09-25T00:00:00Z",
                "event": "Partial build attestation observed for lib-b 2.4.1.",
                "source_ids": ["SRC-ATTEST"],
            },
            {
                "time": "2026-10-01T00:00:00Z",
                "event": "SBOM-APP-1.1.0 generated for BUILD-110 / REL-1.1.0.",
                "source_ids": ["SRC-SBOM-110", "SRC-LOCK"],
            },
            {
                "time": "2026-10-02T00:00:00Z",
                "event": "Vendor VEX NOT_AFFECTED statement published for lib-b.",
                "source_ids": ["SRC-VEX"],
            },
            {
                "time": "2026-10-08T00:00:00Z",
                "event": "Runtime inventory confirms lib-b 2.4.1 present/loaded; feature F configuration not captured.",
                "source_ids": ["SRC-RUNTIME"],
            },
        ],

        "observations": list(s.evidence.values()),
        "candidate_facts": candidate_facts,
        "supported_facts": supported_facts,
        "partial_facts": partial_facts,
        "disputed_facts": disputed_facts,
        "observed_facts": observed_facts,

        "source_reliability": {sid: src.reliability for sid, src in s.sources.items()},
        "source_bias": {sid: src.notes for sid, src in s.sources.items()},
        "source_limitations": {sid: [src.notes] for sid, src in s.sources.items() if src.notes},
        "source_pedigree": {sid: s.get_source_family(sid) for sid in s.sources},
        "source_independence": {
            "source_families": source_families,
            "finding_independence": finding_independence,
        },

        "contradictions": s.contradictions,
        "hypotheses": s.hypotheses,
        "falsification_results": [
            {
                "hypothesis_id": h.id,
                "statement": h.statement,
                "kind": h.kind,
                "status": h.status.value,
                "confidence": h.confidence,
                "assumptions": h.assumptions,
                "predictions": h.predictions,
                "falsification_conditions": h.falsification_conditions,
                "limitations": h.limitations,
            }
            for h in s.hypotheses
        ],

        "privacy_flags": [
            PrivacyFlag.CASE_SCOPED.value,
            PrivacyFlag.AUTHORIZED_SBOM_ONLY.value,
            PrivacyFlag.NO_PACKAGE_EXECUTION.value,
            PrivacyFlag.NO_INSTALL_SCRIPT_EXECUTION.value,
            PrivacyFlag.NO_DEPENDENCY_ATTACK_ENABLEMENT.value,
            PrivacyFlag.NO_SBOM_TAMPERING.value,
            PrivacyFlag.NO_ATTESTATION_FORGERY.value,
            PrivacyFlag.NO_SIGNATURE_FORGERY.value,
            PrivacyFlag.NO_SIGNING_KEY_USE.value,
            PrivacyFlag.NO_CREDENTIAL_USE.value,
            PrivacyFlag.LOCAL_ONLY_DEFAULT.value,
        ],
        "legal_flags": [
            "License conflict candidates require LEGALINT/counsel.",
            "Consequential production patch/removal/replacement decisions require human/engineering approval.",
            "Supply-chain compromise attribution requires incident/provenance/security evidence and human review.",
        ],

        "unknowns": sorted(set(
            [g.description for g in s.gaps]
            + [h.statement for h in s.hypotheses if h.status in {HypothesisStatus.UNRESOLVED, HypothesisStatus.DISPUTED}]
        )),
        "knowledge_gaps": s.gaps,
        "recommended_next_actions": s.actions,
        "recommendations": s.recommendations,
        "specialist_handoffs": s.handoffs,

        "limitations": [
            "Local synthetic demo; no live registry/artifact/runtime access.",
            "Defensive SBOM intelligence only; no package execution or dependency attack enablement.",
            "SBOM component presence is not deployed component presence.",
            "Resolved version is not production version.",
            "Advisory range match is not application vulnerability.",
            "VEX statements are assertions requiring validation.",
            "Runtime inventory may be sampled and scope-limited.",
            "Provenance/attestation/signature context is not absolute trust.",
        ] + s.validation_errors,

        "analyst_summary": summary,
        "dual_ai_review": dual,
        "replay_manifest": replay_manifest,
        "source_graph": build_source_graph(s),
        "source_dependency_graph": source_families,
    }


# =====================================================================
# PIPELINES
# =====================================================================

def run_sample_pipeline() -> Dict[str, Any]:
    s = build_sample_sbomint()
    return build_result(s, Status.PARTIAL)


def run_unconfigured_pipeline(case: Case) -> Dict[str, Any]:
    s = SbomInt(case)

    s.gaps.append(KnowledgeGap(
        id="GAP-NO-SBOM-EVIDENCE",
        gap_type=GapType.COMPONENT_IDENTITY_UNRESOLVED,
        description=(
            "No authorized SBOM, manifest, lockfile, container inventory, runtime inventory, VEX, "
            "advisory, provenance, license, or EOL corpus is configured."
        ),
        importance="HIGH",
        recommended_source="Provide authorized build-generated SBOM, lockfile, container/runtime inventory, VEX, and vulnerability-context corpus.",
        specialist="SBOMINT / PACKAGEINT / VULNINT",
        expected_information_value=0.95,
    ))

    s.actions = [NextAction(
        id="ACT-CONFIGURE-SBOM-EVIDENCE",
        description=(
            "Configure authorized SBOM/component evidence or supply sanitized local corpus. "
            "Do not download/execute packages, run install scripts, poison dependencies, tamper with SBOMs, "
            "forge attestations/signatures, use credentials, or exploit components."
        ),
        priority=1,
        privacy_impact="LOW",
        expected_gain=0.95,
        specialist=None,
        requires_human_approval=False,
    )]

    s.handoffs = []
    s.recommendations = []
    s.hypotheses = []
    s.quality = {
        "as_of": s.as_of,
        "component_count": 0,
        "sbom_count": 0,
        "edge_count": 0,
        "contradiction_count": 0,
        "dimensions": {},
        "weights": {},
        "score": 0.0,
        "state": "SBOM_QUALITY_LOW",
        "guardrails": ["No SBOM evidence configured."],
    }

    dual = {
        "primary_sbom_analyst": "No evidence available.",
        "independent_sbom_skeptic_issues": [
            "No SBOM/source corpus configured.",
            "No component identity can be resolved.",
            "No dependency graph can be constructed.",
            "No vulnerability/VEX/provenance conclusion possible.",
        ],
        "verdict": "INSUFFICIENT_EVIDENCE",
        "note": "AI agreement is not independent component evidence.",
    }

    summary = (
        "SBOM UNRESOLVED: No configured evidence corpus. "
        "No components, versions, dependencies, hashes, licenses, provenance, VEX, vulnerabilities, or deployments were fabricated. "
        "Provide authorized SBOM evidence or run sample mode."
    )

    result = build_result(s, Status.BLOCKED_CONFIGURATION)
    result["analyst_summary"] = summary
    result["dual_ai_review"] = dual
    return result


def blocked_policy_result(case: Case, violations: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "task_id": case.task_id,
        "objective": case.objective,
        "status": Status.BLOCKED_POLICY.value,
        "policy_violations": violations,
        "message": (
            "Prohibited SBOM/software-component intelligence request detected. SBOMINT supports authorized defensive, "
            "evidence-first SBOM intelligence only. It does not download/execute packages, run install scripts, "
            "publish malicious packages, poison dependencies, perform dependency confusion/typosquatting, "
            "compromise registries/repositories/CI/CD, tamper with SBOMs, forge attestations/signatures, "
            "use signing keys, exploit vulnerable components, use credentials from artifacts, or evade integrity verification."
        ),
        "lawful_alternatives": [
            "Parse authorized SBOMs/manifests/lockfiles statically.",
            "Resolve component identity, versions, PURLs, hashes, licenses, suppliers, and dependency edges.",
            "Correlate VEX and advisory context as candidates, then hand applicability to VULNINT.",
            "Retrieve provenance/attestation/signature metadata defensively.",
            "Compare SBOMs for drift and common components.",
            "Require human approval for production remediation or consequential legal/security actions.",
        ],
        "privacy_flags": [
            PrivacyFlag.NO_PACKAGE_EXECUTION.value,
            PrivacyFlag.NO_INSTALL_SCRIPT_EXECUTION.value,
            PrivacyFlag.NO_DEPENDENCY_ATTACK_ENABLEMENT.value,
            PrivacyFlag.NO_SBOM_TAMPERING.value,
            PrivacyFlag.NO_ATTESTATION_FORGERY.value,
            PrivacyFlag.NO_SIGNATURE_FORGERY.value,
            PrivacyFlag.NO_SIGNING_KEY_USE.value,
            PrivacyFlag.NO_CREDENTIAL_USE.value,
        ],
        "limitations": [
            "No SBOM analysis performed.",
            "No components, versions, dependencies, or findings fabricated.",
            "No packages executed or credentials used.",
        ],
    }


def run_pipeline(case: Case) -> Dict[str, Any]:
    text = " ".join(
        [
            case.objective,
            *case.questions,
            *case.applications,
            *case.products,
            *case.releases,
            *case.builds,
            *case.artifacts,
            *case.sboms,
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
            "TRACEATLAS SBOMINT local defensive software bill-of-materials intelligence pipeline. "
            "Sample mode uses synthetic authorized SBOM/lockfile/runtime/VEX/advisory data."
        )
    )
    parser.add_argument("--sample", action="store_true", help="Run built-in synthetic SBOMINT sample.")
    parser.add_argument("--objective", help="Defensive SBOM intelligence objective.")
    parser.add_argument("--question", action="append", default=[], help="Analytic question. Repeatable.")
    parser.add_argument("--application", action="append", default=[], help="Application ID/name. Repeatable.")
    parser.add_argument("--product", action="append", default=[], help="Product ID/name. Repeatable.")
    parser.add_argument("--release", action="append", default=[], help="Release ID/version. Repeatable.")
    parser.add_argument("--build", action="append", default=[], help="Build ID. Repeatable.")
    parser.add_argument("--artifact", action="append", default=[], help="Artifact ID/digest. Repeatable.")
    parser.add_argument("--sbom", action="append", default=[], help="SBOM ID. Repeatable.")
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
            applications=args.application,
            products=args.product,
            releases=args.release,
            builds=args.build,
            artifacts=args.artifact,
            sboms=args.sbom,
            time_range=args.time_range,
            as_of=args.as_of,
            sample=False,
        )

    result = run_pipeline(case)
    print(json.dumps(jsonable(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
