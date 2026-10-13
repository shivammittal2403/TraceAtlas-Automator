from __future__ import annotations

import json
import logging
import re
import unicodedata
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple

# ==============================================================================
# TRACEATLAS — USERNAMEINT
# USERNAME / HANDLE / ALIAS CORRELATION INTELLIGENCE AI EMPLOYEE
# MODE: PUBLIC / AUTHORIZED / EVIDENCE-FIRST / PRIVACY-AWARE
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("TRACEATLAS.USERNAMEINT")


# ==============================================================================
# SECTION 19: HARD RESTRICTIONS / POLICY ENGINE
# ==============================================================================

class PolicyViolation(Exception):
    pass


PROHIBITED_SCOPE_FLAGS = (
    "allow_private_access",
    "allow_authentication_bypass",
    "allow_captcha_bypass",
    "allow_rate_limit_abuse",
    "allow_stolen_cookies",
    "allow_stolen_tokens",
    "allow_stolen_sessions",
    "allow_leaked_credentials",
    "allow_password_spray",
    "allow_credential_stuffing",
    "allow_brute_force",
    "allow_account_recovery_probing",
    "allow_security_question_guessing",
    "allow_deceptive_contact",
    "allow_impersonation",
    "allow_fake_account_infiltration",
    "allow_private_group_infiltration",
    "allow_private_scraping",
    "allow_credential_harvesting",
    "allow_secret_harvesting",
    "allow_doxing",
    "allow_home_address_exposure",
    "allow_precise_private_location_tracking",
    "allow_stalking",
    "allow_face_identification",
    "allow_voice_identification",
    "allow_sensitive_trait_inference",
    "allow_criminality_inference_from_username",
    "allow_nationality_inference_from_username_alone",
)

PROHIBITED_OBJECTIVE_KEYWORDS = (
    "dox",
    "doxxing",
    "stalk",
    "stalking",
    "private account access",
    "bypass login",
    "bypass captcha",
    "password spray",
    "credential stuff",
    "brute force",
    "stolen cookie",
    "stolen token",
    "leaked password",
    "account recovery probe",
    "security question",
    "impersonate user",
    "fake account infiltration",
    "join private group deceptively",
    "contact target deceptively",
    "harvest credential",
    "harvest secret",
    "home address",
    "real-time location",
    "precise private location",
    "face recognition",
    "facial embedding",
    "voice identification",
    "biometric identity",
    "infer religion",
    "infer ethnicity",
    "infer sexual orientation",
    "infer medical status",
    "infer political ideology",
    "infer criminality",
)


def enforce_policy(objective: str, scope: Dict[str, Any]) -> None:
    """
    Enforces USERNAMEINT hard restrictions.
    Defensive/public/authorized analysis only.
    """
    if not isinstance(scope, dict):
        raise PolicyViolation("POLICY_BLOCKED: scope must be a dictionary.")

    # Default public-only posture.
    if scope.get("mode", "PUBLIC_ONLY").upper() != "PUBLIC_ONLY":
        if not scope.get("authorized_authenticated", False):
            raise PolicyViolation(
                "POLICY_BLOCKED: authenticated collection requires explicit authorization."
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

class AccountType(Enum):
    PERSONAL_CLAIM = auto()
    ORGANIZATION = auto()
    BRAND = auto()
    PROJECT = auto()
    BOT = auto()
    AUTOMATION = auto()
    SERVICE_ACCOUNT = auto()
    TEAM_ACCOUNT = auto()
    COMMUNITY_ACCOUNT = auto()
    PARODY = auto()
    FAN_ACCOUNT = auto()
    IMPERSONATION_CANDIDATE = auto()
    UNKNOWN = auto()


class HandleUniqueness(Enum):
    COMMON = auto()
    MODERATELY_DISTINCTIVE = auto()
    HIGHLY_DISTINCTIVE = auto()
    UNKNOWN = auto()


class CollisionRisk(Enum):
    LOW = auto()
    MODERATE = auto()
    HIGH = auto()
    UNKNOWN = auto()


class CorrelationState(Enum):
    VERIFIED_ASSOCIATION = auto()
    STRONGLY_SUPPORTED = auto()
    SUPPORTED = auto()
    PROBABLE = auto()
    POSSIBLE = auto()
    WEAK_CANDIDATE = auto()
    DISPUTED = auto()
    DISTINCT = auto()
    INCONCLUSIVE = auto()


class IdentityState(Enum):
    ACCOUNT_ONLY = auto()
    ACCOUNT_CLUSTER = auto()
    ENTITY_ASSOCIATION_CANDIDATE = auto()
    ENTITY_ASSOCIATION_SUPPORTED = auto()
    ENTITY_ASSOCIATION_VERIFIED = auto()
    DISPUTED = auto()
    DISTINCT = auto()
    INCONCLUSIVE = auto()


class SourceIndependenceState(Enum):
    INDEPENDENT = auto()
    PARTIALLY_DEPENDENT = auto()
    DEPENDENT = auto()
    UNKNOWN = auto()


class HypothesisStatus(Enum):
    ACTIVE = auto()
    REJECTED = auto()
    CONFIRMED = auto()
    CANDIDATE = auto()
    INCONCLUSIVE = auto()


# ==============================================================================
# DATA OBJECTS
# ==============================================================================

@dataclass
class EvidenceObject:
    evidence_id: str
    case_id: str
    source_id: str
    source_type: str
    upstream_source_id: str
    platform: Optional[str]
    account_id: Optional[str]
    handle: Optional[str]
    kind: str
    payload: Dict[str, Any]
    observed_at: datetime
    reliability: float
    limitations: List[str] = field(default_factory=list)


@dataclass
class HandleObject:
    handle_id: str
    raw_handle: str
    normalized_handle: str
    confusable_handle: str
    platform: str
    namespace: str
    first_seen: datetime
    last_seen: datetime
    current_status: str
    account_id: str
    source_id: str
    confidence: float


@dataclass
class HandleEra:
    era_id: str
    account_id: str
    platform: str
    platform_account_id: Optional[str]
    raw_handle: str
    normalized_handle: str
    valid_from: Optional[datetime]
    valid_to: Optional[datetime]
    source_id: str
    state: str
    evidence_id: Optional[str] = None


@dataclass
class AccountObject:
    account_id: str
    platform: str
    platform_account_id: Optional[str]
    current_handle: str
    normalized_handle: str
    confusable_handle: str
    display_name: Optional[str]
    account_type: AccountType
    account_type_basis: str
    account_type_confidence: float
    profile_url: Optional[str]
    created_at_if_public: Optional[datetime]
    first_seen: datetime
    last_seen: datetime
    status: str
    public_self_claims: Dict[str, Any]
    public_links: List[Dict[str, Any]]
    organization_claim: Optional[str]
    location_claim: Optional[str]
    source_ids: List[str]
    evidence_ids: List[str]
    source_upstream_id: Optional[str]
    bio: Optional[str]
    avatar_hash: Optional[str]
    project_references: List[str]
    confidence: float
    limitations: List[str] = field(default_factory=list)


@dataclass
class PublicSelfLink:
    link_id: str
    source_account_id: str
    target_platform: Optional[str]
    target_account_id: Optional[str]
    target_handle: Optional[str]
    link_type: str
    evidence_id: str
    confidence: float
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthoritativeWebsite:
    website_id: str
    url: str
    official_for: Optional[str]
    linked_account_ids: List[str]
    evidence_id: str
    source_id: str
    upstream_source_id: str
    verified: bool
    reliability: float


@dataclass
class CorrelationFeature:
    name: str
    value: Any
    weight: float
    evidence_ids: List[str]
    origin_group: str
    interpretation: str


@dataclass
class PairAssessment:
    pair_id: str
    account_id_a: str
    account_id_b: str
    features: List[CorrelationFeature]
    score: float
    state: CorrelationState
    independent_roots: int
    contradictions: List[str]
    notes: List[str]
    evidence_ids: List[str]


@dataclass
class IdentityClusterCandidate:
    cluster_id: str
    account_ids: List[str]
    handles: List[str]
    historical_handles: List[str]
    pair_assessments: List[PairAssessment]
    contradictions: List[str]
    confidence: float
    state: IdentityState
    entity_association_state: IdentityState
    real_person_state: IdentityState
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
    "platform_native_profile": 1.00,
    "official_website": 0.95,
    "verified_organization_directory": 0.92,
    "public_repository_metadata": 0.85,
    "package_metadata": 0.80,
    "public_forum_profile": 0.75,
    "public_marketplace_profile": 0.70,
    "public_messaging_channel": 0.68,
    "web_archive_snapshot": 0.65,
    "search_result_snippet": 0.35,
    "third_party_aggregator": 0.30,
    "profile_scraper_mirror": 0.25,
    "commercial_osint_provider": 0.45,
    "unknown": 0.20,
}

PLATFORM_RULES = {
    "github": {"case_insensitive": True},
    "gitlab": {"case_insensitive": True},
    "twitter_like": {"case_insensitive": True},
    "x": {"case_insensitive": True},
    "instagram": {"case_insensitive": True},
    "telegram": {"case_insensitive": True},
    "discord": {"case_insensitive": True},
    "reddit": {"case_insensitive": True},
    "youtube": {"case_insensitive": True},
    "facebook": {"case_insensitive": True},
    "forum": {"case_insensitive": True},
    "marketplace": {"case_insensitive": True},
}

DEFAULT_PLATFORM_RULES = {"case_insensitive": True}

COMMON_HANDLES = {
    "admin",
    "administrator",
    "user",
    "test",
    "demo",
    "support",
    "help",
    "info",
    "contact",
    "sales",
    "marketing",
    "john",
    "jane",
    "alex",
    "sam",
    "chris",
    "king",
    "queen",
    "coder",
    "dev",
    "developer",
    "hacker",
    "security",
    "shivam",
    "rahul",
    "aman",
    "rohit",
    "priya",
    "neha",
}

LOOKALIKE_REPLACEMENTS = {
    "1": "l",
    "0": "o",
    "5": "s",
    "7": "t",
    "3": "e",
    "@": "a",
    "$": "s",
    "!": "i",
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
        return None


def normalize_handle(raw: str, platform: str = "default") -> str:
    """
    Preserves semantics while producing a comparison-safe normalized form.
    Original raw handle must always be preserved elsewhere.
    """
    if raw is None:
        return ""

    s = str(raw).strip()
    s = unicodedata.normalize("NFKC", s)

    # Remove format-control characters such as zero-width joiners.
    s = "".join(ch for ch in s if unicodedata.category(ch) != "Cf")

    rules = PLATFORM_RULES.get(platform, DEFAULT_PLATFORM_RULES)
    if rules.get("case_insensitive", True):
        s = s.casefold()

    return s


def confusable_fold(handle: str) -> str:
    """
    Defensive lookalike detection only.
    Does not generate abuse handles.
    """
    s = unicodedata.normalize("NFKD", handle or "")
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.encode("ascii", "ignore").decode("ascii")

    for bad, good in LOOKALIKE_REPLACEMENTS.items():
        s = s.replace(bad, good)

    return s.casefold()


def generate_handle_variants(raw: str, platform: str = "default", max_variants: int = 20) -> List[str]:
    """
    Bounded safe search candidates.
    No combinatorial explosion. No credential probing. No abusive enumeration.
    """
    variants: Set[str] = set()

    def add(value: Optional[str]) -> None:
        if value:
            variants.add(value)

    add(raw)
    add(raw.strip())
    add(normalize_handle(raw, platform))

    lower = (raw or "").casefold().strip()
    add(lower)

    add(re.sub(r"[\._\-]+", "_", lower))
    add(re.sub(r"[\._\-]+", ".", lower))
    add(re.sub(r"[\._\-]+", "-", lower))
    add(re.sub(r"[\._\-]+", "", lower))

    match = re.match(r"^(.*?)(\d{1,3})$", lower)
    if match:
        add(match.group(1))

    return sorted(variants)[:max_variants]


def assess_handle_uniqueness(handle: str) -> Tuple[HandleUniqueness, CollisionRisk, float]:
    """
    Deterministic heuristic for collision risk.
    Rare handle != verified identity.
    """
    h = normalize_handle(handle, "default")
    base = re.sub(r"\d+$", "", h)

    if h in COMMON_HANDLES or base in COMMON_HANDLES:
        return HandleUniqueness.COMMON, CollisionRisk.HIGH, 0.10

    if len(h) <= 5 and h.isalpha():
        return HandleUniqueness.COMMON, CollisionRisk.HIGH, 0.20

    has_digit = any(ch.isdigit() for ch in h)
    has_separator = any(ch in h for ch in "._-")

    if len(h) >= 12 and (has_digit or has_separator):
        return HandleUniqueness.HIGHLY_DISTINCTIVE, CollisionRisk.LOW, 0.90

    if len(h) >= 8:
        return HandleUniqueness.MODERATELY_DISTINCTIVE, CollisionRisk.MODERATE, 0.60

    return HandleUniqueness.MODERATELY_DISTINCTIVE, CollisionRisk.MODERATE, 0.40


def token_set(text: Optional[str]) -> Set[str]:
    if not text:
        return set()
    return set(re.findall(r"[a-z0-9]+", text.casefold()))


def jaccard_similarity(a: Optional[str], b: Optional[str]) -> float:
    sa = token_set(a)
    sb = token_set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def classify_account_type(account_payload: Dict[str, Any]) -> Tuple[AccountType, str, float]:
    """
    Account type is evidence-informed but self-declared claims remain claims.
    """
    claim = str(account_payload.get("account_type_claim", "")).upper()
    bio = str(account_payload.get("bio", "")).lower()
    labels = [str(x).lower() for x in account_payload.get("labels", [])]

    if any("parody" in label for label in labels) or "parody" in bio:
        return AccountType.PARODY, "Explicit parody label or parody language in public bio.", 0.80

    if "fan account" in bio or "not official" in bio or "unofficial" in bio:
        return AccountType.FAN_ACCOUNT, "Fan/unofficial language in public bio.", 0.70

    if claim == "BOT" or any(label in ("bot", "automated") for label in labels):
        return AccountType.BOT, "Self-declared bot/service identity.", 0.65

    if claim == "AUTOMATION":
        return AccountType.AUTOMATION, "Self-declared automation identity.", 0.60

    if claim == "SERVICE_ACCOUNT":
        return AccountType.SERVICE_ACCOUNT, "Self-declared service account.", 0.60

    if claim == "TEAM_ACCOUNT":
        return AccountType.TEAM_ACCOUNT, "Self-declared team account.", 0.55

    if claim == "COMMUNITY_ACCOUNT":
        return AccountType.COMMUNITY_ACCOUNT, "Self-declared community account.", 0.55

    if claim == "ORGANIZATION":
        return AccountType.ORGANIZATION, "Self-declared organization account; requires authoritative verification.", 0.45

    if claim == "BRAND":
        return AccountType.BRAND, "Self-declared brand account; requires authoritative verification.", 0.45

    if claim == "PROJECT":
        return AccountType.PROJECT, "Self-declared project account.", 0.50

    if "official" in bio and account_payload.get("organization_claim"):
        return AccountType.ORGANIZATION, "'Official' language plus organization claim; unverified.", 0.35

    if claim == "PERSONAL_CLAIM":
        return AccountType.PERSONAL_CLAIM, "Self-declared personal account.", 0.40

    return AccountType.UNKNOWN, "No reliable account-type indicator available.", 0.20


def account_interval(account: AccountObject, now: datetime) -> Tuple[datetime, datetime]:
    start = account.created_at_if_public or account.first_seen or now
    end = account.last_seen or now
    if end < start:
        end = start
    return start, end


def intervals_overlap(a: AccountObject, b: AccountObject, now: datetime) -> bool:
    a_start, a_end = account_interval(a, now)
    b_start, b_end = account_interval(b, now)
    return a_start <= b_end and b_start <= a_end


# ==============================================================================
# USERNAMEINT AI EMPLOYEE
# ==============================================================================

class UsernameIntEmployee:
    """
    Defensive USERNAMEINT employee.

    Consumes already-collected public/authorized evidence.
    Does not perform network collection, login probing, credential testing,
    private access, biometric identification, or doxxing.
    """

    def __init__(self, model_mode: str = "LOCAL_ONLY"):
        self.model_mode = model_mode.upper()
        self.graph_nodes: Dict[str, GraphNode] = {}
        self.graph_edges: List[GraphEdge] = []
        logger.info("USERNAMEINT employee initialized in mode=%s", self.model_mode)

    # --------------------------------------------------------------------------
    # MAIN ENTRYPOINT
    # --------------------------------------------------------------------------

    def process_case(
        self,
        case_id: str,
        task_id: str,
        objective: str,
        scope: Dict[str, Any],
        seed_handles: List[str],
        public_evidence: Dict[str, Any],
        existing_facts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        existing_facts = existing_facts or {}
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
                    "PUBLIC_ONLY_DEFAULT",
                    "NO_PRIVATE_ACCESS",
                    "NO_CREDENTIAL_ATTACK",
                    "NO_BIOMETRIC_IDENTIFICATION",
                    "NO_SENSITIVE_TRAIT_INFERENCE",
                ],
            }

        logger.info("Starting USERNAMEINT case=%s task=%s", case_id, task_id)

        # ----------------------------------------------------------------------
        # 1. SEED HANDLE NORMALIZATION / COLLISION / VARIANTS
        # ----------------------------------------------------------------------

        seeds: List[Dict[str, Any]] = []
        for raw in seed_handles:
            normalized = normalize_handle(raw, "default")
            confusable = confusable_fold(normalized)
            uniqueness, collision, uniqueness_score = assess_handle_uniqueness(normalized)
            variants = generate_handle_variants(raw, "default")

            seeds.append(
                {
                    "raw_handle": raw,
                    "normalized_handle": normalized,
                    "confusable_handle": confusable,
                    "uniqueness": uniqueness.name,
                    "collision_risk": collision.name,
                    "uniqueness_score": uniqueness_score,
                    "variants": variants,
                }
            )

        # ----------------------------------------------------------------------
        # 2. INGEST PUBLIC/AUTHORIZED ACCOUNT EVIDENCE
        # ----------------------------------------------------------------------

        accounts: Dict[str, AccountObject] = {}
        evidences: List[EvidenceObject] = []
        evidence_by_id: Dict[str, EvidenceObject] = {}
        handles: List[HandleObject] = []
        eras: List[HandleEra] = []
        self_links: List[PublicSelfLink] = []
        websites: List[AuthoritativeWebsite] = []
        org_memberships: Dict[str, List[str]] = defaultdict(list)
        project_refs: Dict[str, List[str]] = defaultdict(list)
        gaps: List[Dict[str, Any]] = []

        def add_gap(
            description: str,
            importance: str,
            recommended_source: str,
            specialist: str,
            expected_information_value: str,
        ) -> None:
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

        for idx, acc in enumerate(public_evidence.get("accounts", [])):
            platform = str(acc.get("platform", "unknown"))
            platform_account_id = acc.get("platform_account_id")
            account_id = (
                f"{platform}:{platform_account_id}"
                if platform_account_id
                else f"{platform}:no_stable_id:{idx}"
            )

            raw_handle = str(acc.get("current_handle", ""))
            normalized_handle = normalize_handle(raw_handle, platform)
            confusable_handle = confusable_fold(normalized_handle)

            source_type = str(acc.get("source_type", "platform_native_profile"))
            source_id = str(acc.get("source_id", f"SRC_ACC_{idx}"))
            upstream_source_id = str(acc.get("upstream_source_id", source_id))
            reliability = float(acc.get("reliability", SOURCE_RELIABILITY.get(source_type, 0.20)))

            first_seen = parse_dt(acc.get("first_seen")) or now
            last_seen = parse_dt(acc.get("last_seen")) or now
            created_at = parse_dt(acc.get("created_at"))

            evidence_id = f"EVID_ACC_{idx}"
            ev = EvidenceObject(
                evidence_id=evidence_id,
                case_id=case_id,
                source_id=source_id,
                source_type=source_type,
                upstream_source_id=upstream_source_id,
                platform=platform,
                account_id=account_id,
                handle=raw_handle,
                kind="account_observation",
                payload=acc,
                observed_at=parse_dt(acc.get("observed_at")) or now,
                reliability=reliability,
                limitations=[
                    "Profile claims are self-reported unless independently verified.",
                    "Search snippets or mirrors are not primary account evidence.",
                ],
            )
            evidences.append(ev)
            evidence_by_id[evidence_id] = ev

            account_type, account_type_basis, account_type_confidence = classify_account_type(acc)

            public_self_claims = {
                "display_name": acc.get("display_name"),
                "bio": acc.get("bio"),
                "organization_claim": acc.get("organization_claim"),
                "location_claim": acc.get("location_claim"),
                "account_type_claim": acc.get("account_type_claim"),
                "website_claim": acc.get("website_claim"),
            }

            account = AccountObject(
                account_id=account_id,
                platform=platform,
                platform_account_id=platform_account_id,
                current_handle=raw_handle,
                normalized_handle=normalized_handle,
                confusable_handle=confusable_handle,
                display_name=acc.get("display_name"),
                account_type=account_type,
                account_type_basis=account_type_basis,
                account_type_confidence=account_type_confidence,
                profile_url=acc.get("profile_url"),
                created_at_if_public=created_at,
                first_seen=first_seen,
                last_seen=last_seen,
                status=str(acc.get("status", "ACTIVE_PUBLIC")),
                public_self_claims=public_self_claims,
                public_links=acc.get("public_links", []),
                organization_claim=acc.get("organization_claim"),
                location_claim=acc.get("location_claim"),
                source_ids=[source_id],
                evidence_ids=[evidence_id],
                source_upstream_id=upstream_source_id,
                bio=acc.get("bio"),
                avatar_hash=acc.get("avatar_hash"),
                project_references=list(acc.get("project_references", [])),
                confidence=reliability,
                limitations=[
                    "Account existence does not prove account ownership.",
                    "Same handle does not prove same human.",
                    "Stable account ID proves platform-account continuity, not lifetime operator continuity.",
                ],
            )
            accounts[account_id] = account

            handles.append(
                HandleObject(
                    handle_id=new_id("HANDLE"),
                    raw_handle=raw_handle,
                    normalized_handle=normalized_handle,
                    confusable_handle=confusable_handle,
                    platform=platform,
                    namespace=platform,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    current_status=account.status,
                    account_id=account_id,
                    source_id=source_id,
                    confidence=reliability,
                )
            )

            if not platform_account_id:
                add_gap(
                    f"Stable platform account ID unavailable for {platform}/{raw_handle}.",
                    "HIGH",
                    "platform_native_profile",
                    "USERNAMEINT",
                    "Enables handle-era and reuse resolution.",
                )

            if not created_at:
                add_gap(
                    f"Account creation date unavailable for {account_id}.",
                    "MEDIUM",
                    "platform_native_profile or archive",
                    "ARCHIVEINT",
                    "Improves temporal correlation and recycle detection.",
                )

            # Current observed handle era.
            eras.append(
                HandleEra(
                    era_id=new_id("ERA"),
                    account_id=account_id,
                    platform=platform,
                    platform_account_id=platform_account_id,
                    raw_handle=raw_handle,
                    normalized_handle=normalized_handle,
                    valid_from=created_at or first_seen,
                    valid_to=last_seen,
                    source_id=source_id,
                    state="CURRENT_OBSERVED",
                    evidence_id=evidence_id,
                )
            )

            # Historical handle eras, if publicly/authorized observed.
            for h_idx, hist in enumerate(acc.get("handle_history", [])):
                hist_raw = str(hist.get("handle", ""))
                hist_norm = normalize_handle(hist_raw, platform)
                hist_from = parse_dt(hist.get("valid_from"))
                hist_to = parse_dt(hist.get("valid_to"))
                hist_source = str(hist.get("source_id", f"{source_id}_H{h_idx}"))
                hist_upstream = str(hist.get("upstream_source_id", hist_source))
                hist_evidence_id = f"{evidence_id}_H{h_idx}"

                hist_ev = EvidenceObject(
                    evidence_id=hist_evidence_id,
                    case_id=case_id,
                    source_id=hist_source,
                    source_type=str(hist.get("source_type", "platform_metadata")),
                    upstream_source_id=hist_upstream,
                    platform=platform,
                    account_id=account_id,
                    handle=hist_raw,
                    kind="historical_handle_observation",
                    payload=hist,
                    observed_at=parse_dt(hist.get("observed_at")) or now,
                    reliability=float(hist.get("reliability", reliability)),
                    limitations=["Historical handle does not prove current owner."],
                )
                evidences.append(hist_ev)
                evidence_by_id[hist_evidence_id] = hist_ev

                eras.append(
                    HandleEra(
                        era_id=new_id("ERA"),
                        account_id=account_id,
                        platform=platform,
                        platform_account_id=platform_account_id,
                        raw_handle=hist_raw,
                        normalized_handle=hist_norm,
                        valid_from=hist_from,
                        valid_to=hist_to,
                        source_id=hist_source,
                        state="HISTORICAL",
                        evidence_id=hist_evidence_id,
                    )
                )

            for proj in account.project_references:
                project_refs[proj].append(account_id)

        # Build resolution indexes.
        by_platform_pid: Dict[Tuple[str, str], str] = {}
        by_platform_norm_handle: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        by_norm_handle_all: Dict[str, List[str]] = defaultdict(list)
        by_confusable_all: Dict[str, List[str]] = defaultdict(list)

        for aid, acc in accounts.items():
            if acc.platform_account_id:
                by_platform_pid[(acc.platform, acc.platform_account_id)] = aid
            by_platform_norm_handle[(acc.platform, acc.normalized_handle)].append(aid)
            by_norm_handle_all[acc.normalized_handle].append(aid)
            by_confusable_all[acc.confusable_handle].append(aid)

        def resolve_account_id(
            platform: Optional[str],
            platform_account_id: Optional[str],
            handle: Optional[str],
        ) -> Optional[str]:
            if platform and platform_account_id:
                return by_platform_pid.get((platform, str(platform_account_id)))

            if platform and handle:
                norm = normalize_handle(str(handle), platform)
                matches = by_platform_norm_handle.get((platform, norm), [])
                if len(matches) == 1:
                    return matches[0]

            return None

        # Post-process public self-links.
        for idx, link in enumerate(listAccountsPublicLinks := [l for a in accounts.values() for l in a.public_links]):
            source_account_id = None
            for aid, acc in accounts.items():
                if link in acc.public_links:
                    source_account_id = aid
                    break

            if not source_account_id:
                continue

            target_platform = link.get("target_platform")
            target_account_id = link.get("target_account_id") or link.get("target_platform_account_id")
            target_handle = link.get("target_handle")
            resolved_target = resolve_account_id(target_platform, target_account_id, target_handle)

            self_links.append(
                PublicSelfLink(
                    link_id=new_id("LINK"),
                    source_account_id=source_account_id,
                    target_platform=target_platform,
                    target_account_id=resolved_target,
                    target_handle=target_handle,
                    link_type=str(link.get("link_type", "public_profile_link")),
                    evidence_id=accounts[source_account_id].evidence_ids[0],
                    confidence=accounts[source_account_id].confidence,
                    raw=link,
                )
            )

            if target_platform and not resolved_target:
                add_gap(
                    f"Public self-link target unresolved: {source_account_id} -> {target_platform}/{target_handle or target_account_id}.",
                    "MEDIUM",
                    "platform_native_profile",
                    "USERNAMEINT",
                    "Confirms cross-account association.",
                )

        # ----------------------------------------------------------------------
        # 3. WEBSITE / ORGANIZATION / ARCHIVE EVIDENCE
        # ----------------------------------------------------------------------

        for idx, site in enumerate(public_evidence.get("websites", [])):
            url = str(site.get("url", ""))
            official_for = site.get("official_for")
            source_type = str(site.get("source_type", "official_website"))
            source_id = str(site.get("source_id", f"SRC_WEB_{idx}"))
            upstream_source_id = str(site.get("upstream_source_id", source_id))
            reliability = float(site.get("reliability", SOURCE_RELIABILITY.get(source_type, 0.20)))
            evidence_id = f"EVID_WEB_{idx}"

            ev = EvidenceObject(
                evidence_id=evidence_id,
                case_id=case_id,
                source_id=source_id,
                source_type=source_type,
                upstream_source_id=upstream_source_id,
                platform="web",
                account_id=None,
                handle=None,
                kind="authoritative_website_link",
                payload=site,
                observed_at=parse_dt(site.get("observed_at")) or now,
                reliability=reliability,
                limitations=["Website link proves association to website, not automatically real-person identity."],
            )
            evidences.append(ev)
            evidence_by_id[evidence_id] = ev

            linked_ids: List[str] = []
            for link in site.get("links_to_accounts", []):
                resolved = resolve_account_id(
                    link.get("platform"),
                    link.get("platform_account_id") or link.get("account_id"),
                    link.get("handle"),
                )
                if resolved:
                    linked_ids.append(resolved)
                else:
                    add_gap(
                        f"Website {url} links to unresolved account {link}.",
                        "MEDIUM",
                        "platform_native_profile",
                        "WEBINT / USERNAMEINT",
                        "Strengthens authoritative association.",
                    )

            verified = bool(existing_facts.get(f"website:{url} owner:{official_for}"))

            websites.append(
                AuthoritativeWebsite(
                    website_id=new_id("WEB"),
                    url=url,
                    official_for=official_for,
                    linked_account_ids=sorted(set(linked_ids)),
                    evidence_id=evidence_id,
                    source_id=source_id,
                    upstream_source_id=upstream_source_id,
                    verified=verified,
                    reliability=reliability,
                )
            )

        for idx, org in enumerate(public_evidence.get("organizations", [])):
            org_id = str(org.get("organization_id") or org.get("name") or f"ORG_{idx}")
            source_type = str(org.get("source_type", "verified_organization_directory"))
            source_id = str(org.get("source_id", f"SRC_ORG_{idx}"))
            upstream_source_id = str(org.get("upstream_source_id", source_id))
            reliability = float(org.get("reliability", SOURCE_RELIABILITY.get(source_type, 0.20)))
            evidence_id = f"EVID_ORG_{idx}"

            ev = EvidenceObject(
                evidence_id=evidence_id,
                case_id=case_id,
                source_id=source_id,
                source_type=source_type,
                upstream_source_id=upstream_source_id,
                platform="organization",
                account_id=None,
                handle=None,
                kind="organization_membership",
                payload=org,
                observed_at=parse_dt(org.get("observed_at")) or now,
                reliability=reliability,
                limitations=["Organization membership does not automatically prove employment."],
            )
            evidences.append(ev)
            evidence_by_id[evidence_id] = ev

            for member in org.get("verified_accounts", []):
                resolved = resolve_account_id(
                    member.get("platform"),
                    member.get("platform_account_id") or member.get("account_id"),
                    member.get("handle"),
                )
                if resolved:
                    org_memberships[org_id].append(resolved)
                else:
                    add_gap(
                        f"Organization {org_id} membership target unresolved: {member}.",
                        "MEDIUM",
                        "verified_organization_directory",
                        "ORGINT / CORPINT",
                        "Supports entity association.",
                    )

        for idx, arch in enumerate(public_evidence.get("archives", [])):
            platform = str(arch.get("platform", "unknown"))
            platform_account_id = arch.get("platform_account_id")
            handle = str(arch.get("handle", ""))
            resolved = resolve_account_id(platform, platform_account_id, handle)
            source_id = str(arch.get("source_id", f"SRC_ARCH_{idx}"))
            upstream_source_id = str(arch.get("upstream_source_id", source_id))
            reliability = float(arch.get("reliability", SOURCE_RELIABILITY["web_archive_snapshot"]))
            evidence_id = f"EVID_ARCH_{idx}"

            ev = EvidenceObject(
                evidence_id=evidence_id,
                case_id=case_id,
                source_id=source_id,
                source_type="web_archive_snapshot",
                upstream_source_id=upstream_source_id,
                platform=platform,
                account_id=resolved,
                handle=handle,
                kind="archive_snapshot",
                payload=arch,
                observed_at=parse_dt(arch.get("snapshot_at")) or now,
                reliability=reliability,
                limitations=["Archive timestamp is snapshot time, not original creation time."],
            )
            evidences.append(ev)
            evidence_by_id[evidence_id] = ev

            if resolved:
                eras.append(
                    HandleEra(
                        era_id=new_id("ERA"),
                        account_id=resolved,
                        platform=platform,
                        platform_account_id=platform_account_id,
                        raw_handle=handle,
                        normalized_handle=normalize_handle(handle, platform),
                        valid_from=parse_dt(arch.get("valid_from")) or parse_dt(arch.get("snapshot_at")),
                        valid_to=parse_dt(arch.get("valid_to")) or parse_dt(arch.get("snapshot_at")),
                        source_id=source_id,
                        state="ARCHIVED_HISTORICAL",
                        evidence_id=evidence_id,
                    )
                )
            else:
                add_gap(
                    f"Archive snapshot could not be resolved to known account: {platform}/{handle}.",
                    "MEDIUM",
                    "web archive",
                    "ARCHIVEINT",
                    "May reveal historical handle era or deleted public profile.",
                )

        # ----------------------------------------------------------------------
        # 4. HANDLE REUSE / REASSIGNMENT / RENAME CONTEXT
        # ----------------------------------------------------------------------

        reuse_context: List[Dict[str, Any]] = []

        for (platform, norm), aids in by_platform_norm_handle.items():
            unique_aids = sorted(set(aids))
            if len(unique_aids) <= 1:
                continue

            pids = {accounts[aid].platform_account_id for aid in unique_aids}
            if len(pids) <= 1:
                continue

            overlap = False
            for a1, a2 in combinations(unique_aids, 2):
                if intervals_overlap(accounts[a1], accounts[a2], now):
                    overlap = True
                    break

            state = "HANDLE_REUSE_CANDIDATE" if overlap else "HANDLE_REASSIGNED_CANDIDATE"
            reuse_context.append(
                {
                    "platform": platform,
                    "normalized_handle": norm,
                    "account_ids": unique_aids,
                    "state": state,
                    "interpretation": (
                        "Same platform namespace appears to contain multiple stable account IDs for the same handle. "
                        "Do not merge accounts based on handle alone."
                    ),
                }
            )

        eras_by_account: Dict[str, List[HandleEra]] = defaultdict(list)
        for era in eras:
            eras_by_account[era.account_id].append(era)

        for aid, era_list in eras_by_account.items():
            unique_handles = sorted({e.normalized_handle for e in era_list if e.normalized_handle})
            if len(unique_handles) > 1:
                reuse_context.append(
                    {
                        "account_id": aid,
                        "state": "SAME_ACCOUNT_RENAME",
                        "handles": unique_handles,
                        "interpretation": "Stable platform account ID appears to have multiple observed handle eras.",
                    }
                )

        # ----------------------------------------------------------------------
        # 5. IMPERSONATION / PARODY / FAN CONTEXT
        # ----------------------------------------------------------------------

        impersonation_context: List[Dict[str, Any]] = []

        for acc in accounts.values():
            for seed in seeds:
                if acc.confusable_handle == seed["confusable_handle"] and acc.normalized_handle != seed["normalized_handle"]:
                    official_claim = bool(acc.organization_claim) or "official" in (acc.bio or "").lower()
                    verified_official = any(acc.account_id in members for members in org_memberships.values())

                    if acc.account_type == AccountType.PARODY:
                        typ = "PARODY"
                    elif acc.account_type == AccountType.FAN_ACCOUNT:
                        typ = "FAN_ACCOUNT"
                    elif official_claim and not verified_official:
                        typ = "IMPERSONATION_CANDIDATE"
                    else:
                        typ = "LOOKALIKE_CANDIDATE"

                    impersonation_context.append(
                        {
                            "account_id": acc.account_id,
                            "platform": acc.platform,
                            "handle": acc.current_handle,
                            "target_seed_handle": seed["raw_handle"],
                            "type": typ,
                            "evidence_ids": acc.evidence_ids,
                            "interpretation": (
                                "Lookalike/homoglyph context detected. This is defensive impersonation analysis, "
                                "not proof of common operator."
                            ),
                        }
                    )

        # ----------------------------------------------------------------------
        # 6. CANDIDATE PAIRS
        # ----------------------------------------------------------------------

        candidate_pairs: Set[Tuple[str, str]] = set()

        def add_pair(a: str, b: str) -> None:
            if a == b:
                return
            candidate_pairs.add(tuple(sorted((a, b))))

        # Same normalized handle across platforms.
        for aids in by_norm_handle_all.values():
            unique = sorted(set(aids))
            if 2 <= len(unique) <= 25:
                for a, b in combinations(unique, 2):
                    add_pair(a, b)

        # Seed-confusable matches.
        for seed in seeds:
            aids = sorted({aid for aid, acc in accounts.items() if acc.confusable_handle == seed["confusable_handle"]})
            if 2 <= len(aids) <= 25:
                for a, b in combinations(aids, 2):
                    add_pair(a, b)

        # Direct self-links.
        for link in self_links:
            if link.target_account_id:
                add_pair(link.source_account_id, link.target_account_id)

        # Authoritative websites linking multiple accounts.
        for site in websites:
            aids = sorted(set(site.linked_account_ids))
            if 2 <= len(aids) <= 25:
                for a, b in combinations(aids, 2):
                    add_pair(a, b)

        # Verified organization memberships.
        for members in org_memberships.values():
            aids = sorted(set(members))
            if 2 <= len(aids) <= 25:
                for a, b in combinations(aids, 2):
                    add_pair(a, b)

        # Distinctive project references.
        for members in project_refs.values():
            aids = sorted(set(members))
            if 2 <= len(aids) <= 25:
                for a, b in combinations(aids, 2):
                    add_pair(a, b)

        # Safety bound: avoid accidental combinatorial explosion.
        candidate_pairs = set(list(candidate_pairs)[:1000])

        # ----------------------------------------------------------------------
        # 7. PAIR CORRELATION ASSESSMENT
        # ----------------------------------------------------------------------

        pair_assessments: List[PairAssessment] = []

        def assess_pair(aid_a: str, aid_b: str) -> PairAssessment:
            a = accounts[aid_a]
            b = accounts[aid_b]

            features: List[CorrelationFeature] = []
            contradictions: List[str] = []
            notes: List[str] = []
            evidence_ids: Set[str] = set(a.evidence_ids) | set(b.evidence_ids)

            # Exact normalized handle match.
            if a.normalized_handle == b.normalized_handle:
                uniqueness, collision, _ = assess_handle_uniqueness(a.normalized_handle)
                weight_map = {
                    HandleUniqueness.HIGHLY_DISTINCTIVE: 0.35,
                    HandleUniqueness.MODERATELY_DISTINCTIVE: 0.20,
                    HandleUniqueness.COMMON: 0.05,
                    HandleUniqueness.UNKNOWN: 0.05,
                }
                weight = weight_map[uniqueness]
                features.append(
                    CorrelationFeature(
                        name="exact_normalized_handle_match",
                        value=a.normalized_handle,
                        weight=weight,
                        evidence_ids=sorted(evidence_ids),
                        origin_group="handle_match",
                        interpretation=(
                            f"Handle uniqueness={uniqueness.name}, collision risk={collision.name}. "
                            "Same handle alone is weak identity evidence."
                        ),
                    )
                )

            # Confusable/lookalike handle.
            if a.confusable_handle == b.confusable_handle and a.normalized_handle != b.normalized_handle:
                features.append(
                    CorrelationFeature(
                        name="confusable_handle_match",
                        value=a.confusable_handle,
                        weight=0.15,
                        evidence_ids=sorted(evidence_ids),
                        origin_group="confusable_handle",
                        interpretation="Lookalike/homoglyph context. Defensive impersonation signal only.",
                    )
                )

            # Direct / reciprocal public self-links.
            links_ab = [l for l in self_links if l.source_account_id == aid_a and l.target_account_id == aid_b]
            links_ba = [l for l in self_links if l.source_account_id == aid_b and l.target_account_id == aid_a]
            link_evidence = sorted({l.evidence_id for l in links_ab + links_ba})

            if links_ab and links_ba:
                features.append(
                    CorrelationFeature(
                        name="reciprocal_public_self_link",
                        value=[l.raw for l in links_ab + links_ba],
                        weight=0.90,
                        evidence_ids=link_evidence,
                        origin_group="self_link",
                        interpretation="Reciprocal public self-link is strong account-association evidence.",
                    )
                )
            elif links_ab or links_ba:
                features.append(
                    CorrelationFeature(
                        name="one_way_public_self_link",
                        value=[l.raw for l in links_ab + links_ba],
                        weight=0.70,
                        evidence_ids=link_evidence,
                        origin_group="self_link",
                        interpretation="One-way public self-link is strong but less conclusive than reciprocal linking.",
                    )
                )

            # Authoritative website linking both accounts.
            common_sites = [s for s in websites if aid_a in s.linked_account_ids and aid_b in s.linked_account_ids]
            if common_sites:
                site_evidence = sorted({s.evidence_id for s in common_sites})
                verified_any = any(s.verified for s in common_sites)
                base_weight = 0.75 if verified_any else 0.45
                weight = min(0.85, base_weight + 0.05 * (len(common_sites) - 1))
                features.append(
                    CorrelationFeature(
                        name="authoritative_website_links_both_accounts",
                        value=[{"url": s.url, "verified": s.verified} for s in common_sites],
                        weight=weight,
                        evidence_ids=site_evidence,
                        origin_group="authoritative_website",
                        interpretation=(
                            "Website linking both accounts supports account-cluster association. "
                            "It does not automatically prove real-person identity."
                        ),
                    )
                )

            # Verified organization membership.
            common_orgs = [org for org, members in org_memberships.items() if aid_a in members and aid_b in members]
            if common_orgs:
                org_evidence = sorted(
                    {
                        evidence_id
                        for ev in evidences
                        if ev.kind == "organization_membership"
                        and any(aid in ev.payload.get("verified_accounts", []) for aid in (aid_a, aid_b))
                    }
                )
                features.append(
                    CorrelationFeature(
                        name="verified_common_organization_membership",
                        value=common_orgs,
                        weight=0.60,
                        evidence_ids=org_evidence,
                        origin_group="organization_verified",
                        interpretation="Common verified organization membership supports entity association, not employment or person identity.",
                    )
                )
            elif a.organization_claim and a.organization_claim == b.organization_claim:
                features.append(
                    CorrelationFeature(
                        name="self_reported_common_organization_claim",
                        value=a.organization_claim,
                        weight=0.15,
                        evidence_ids=sorted(evidence_ids),
                        origin_group="organization_self_claim",
                        interpretation="Shared self-reported organization claim is weak until verified by authoritative source.",
                    )
                )

            # Distinctive project overlap.
            common_projects = [p for p, members in project_refs.items() if aid_a in members and aid_b in members]
            if common_projects:
                features.append(
                    CorrelationFeature(
                        name="distinctive_project_reference_overlap",
                        value=common_projects,
                        weight=0.45,
                        evidence_ids=sorted(evidence_ids),
                        origin_group="project_overlap",
                        interpretation="Shared distinctive project references can support association if independently sourced.",
                    )
                )

            # Temporal consistency.
            if intervals_overlap(a, b, now):
                features.append(
                    CorrelationFeature(
                        name="temporal_activity_overlap",
                        value="overlap",
                        weight=0.10,
                        evidence_ids=sorted(evidence_ids),
                        origin_group="temporal",
                        interpretation="Overlapping activity is weak supporting evidence only.",
                    )
                )

            # Avatar similarity.
            if a.avatar_hash and b.avatar_hash and a.avatar_hash == b.avatar_hash:
                features.append(
                    CorrelationFeature(
                        name="exact_avatar_hash_match",
                        value=a.avatar_hash,
                        weight=0.15,
                        evidence_ids=sorted(evidence_ids),
                        origin_group="avatar",
                        interpretation="Avatar match is supporting evidence only; images can be copied, generic, or reused.",
                    )
                )

            # Bio similarity.
            bio_sim = jaccard_similarity(a.bio, b.bio)
            if bio_sim >= 0.70:
                dependent = a.source_upstream_id == b.source_upstream_id
                weight = 0.0 if dependent else 0.10
                if dependent:
                    notes.append("Bio similarity suppressed because both observations appear to share the same upstream source family.")
                features.append(
                    CorrelationFeature(
                        name="bio_similarity",
                        value=bio_sim,
                        weight=weight,
                        evidence_ids=sorted(evidence_ids),
                        origin_group="bio",
                        interpretation="Bio similarity is weak and highly susceptible to copying or dependent sourcing.",
                    )
                )

            # Contradictions.
            if (
                a.platform == b.platform
                and a.platform_account_id
                and b.platform_account_id
                and a.platform_account_id != b.platform_account_id
                and a.normalized_handle == b.normalized_handle
            ):
                if intervals_overlap(a, b, now):
                    contradictions.append(
                        "Same platform, same normalized handle, different stable account IDs during overlapping period. "
                        "Treat as distinct or data-quality conflict until resolved."
                    )
                else:
                    notes.append(
                        "Same platform, same normalized handle, different stable account IDs in non-overlapping periods. "
                        "Possible handle reassignment/recycling."
                    )

            for imp in impersonation_context:
                if imp["account_id"] in (aid_a, aid_b) and imp["type"] == "IMPERSONATION_CANDIDATE":
                    contradictions.append(
                        f"Impersonation candidate context involving {imp['account_id']} relative to seed handle {imp['target_seed_handle']}."
                    )

            # Verified fact gate.
            verified = False
            for key in (
                f"account_association:{aid_a}|{aid_b}",
                f"account_association:{aid_b}|{aid_a}",
            ):
                if existing_facts.get(key):
                    verified = True
                    break

            # Transparent score aggregation with origin de-duplication.
            origin_weights: Dict[str, float] = defaultdict(float)
            for feature in features:
                origin_weights[feature.origin_group] = max(origin_weights[feature.origin_group], feature.weight)

            score = sum(origin_weights.values())

            roots: Set[str] = set()
            for aid in (aid_a, aid_b):
                for eid in accounts[aid].evidence_ids:
                    roots.add(evidence_by_id[eid].upstream_source_id)

            for feature in features:
                for eid in feature.evidence_ids:
                    if eid in evidence_by_id:
                        roots.add(evidence_by_id[eid].upstream_source_id)

            independent_roots = len(roots)

            if independent_roots <= 1:
                score *= 0.60
                notes.append("Score reduced because evidence appears to come from a single upstream source family.")

            if contradictions:
                score = max(0.0, score - 0.25)

            score = max(0.0, min(1.0, score))

            # State assignment.
            if verified:
                state = CorrelationState.VERIFIED_ASSOCIATION
            elif (
                a.platform == b.platform
                and a.platform_account_id
                and b.platform_account_id
                and a.platform_account_id != b.platform_account_id
                and a.normalized_handle == b.normalized_handle
                and intervals_overlap(a, b, now)
            ):
                state = CorrelationState.DISTINCT
            elif contradictions and score < 0.45:
                state = CorrelationState.DISPUTED
            elif score >= 0.85 and independent_roots >= 2:
                state = CorrelationState.STRONGLY_SUPPORTED
            elif score >= 0.65 and independent_roots >= 2:
                state = CorrelationState.SUPPORTED
            elif score >= 0.50:
                state = CorrelationState.PROBABLE
            elif score >= 0.35:
                state = CorrelationState.POSSIBLE
            elif score > 0:
                state = CorrelationState.WEAK_CANDIDATE
            else:
                state = CorrelationState.INCONCLUSIVE

            return PairAssessment(
                pair_id=new_id("PAIR"),
                account_id_a=aid_a,
                account_id_b=aid_b,
                features=features,
                score=round(score, 4),
                state=state,
                independent_roots=independent_roots,
                contradictions=contradictions,
                notes=notes,
                evidence_ids=sorted(evidence_ids),
            )

        for aid_a, aid_b in sorted(candidate_pairs):
            pair_assessments.append(assess_pair(aid_a, aid_b))

        # ----------------------------------------------------------------------
        # 8. IDENTITY CLUSTERS
        # ----------------------------------------------------------------------

        parent: Dict[str, str] = {aid: aid for aid in accounts}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: str, y: str) -> None:
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[ry] = rx

        for pair in pair_assessments:
            if pair.state in (
                CorrelationState.VERIFIED_ASSOCIATION,
                CorrelationState.STRONGLY_SUPPORTED,
                CorrelationState.SUPPORTED,
            ):
                union(pair.account_id_a, pair.account_id_b)
            elif pair.score >= 0.65 and pair.independent_roots >= 2:
                union(pair.account_id_a, pair.account_id_b)

        cluster_map: Dict[str, List[str]] = defaultdict(list)
        for aid in accounts:
            cluster_map[find(aid)].append(aid)

        identity_clusters: List[IdentityClusterCandidate] = []

        for root, aids in cluster_map.items():
            if len(aids) < 2:
                continue

            aids = sorted(aids)
            cluster_pairs = [
                p for p in pair_assessments
                if p.account_id_a in aids and p.account_id_b in aids
            ]

            if not cluster_pairs:
                continue

            avg_score = sum(p.score for p in cluster_pairs) / len(cluster_pairs)
            all_contradictions = sorted({c for p in cluster_pairs for c in p.contradictions})

            if any(p.state == CorrelationState.VERIFIED_ASSOCIATION for p in cluster_pairs):
                cluster_state = IdentityState.ENTITY_ASSOCIATION_VERIFIED
            elif all(p.state in (CorrelationState.STRONGLY_SUPPORTED, CorrelationState.VERIFIED_ASSOCIATION) for p in cluster_pairs):
                cluster_state = IdentityState.ACCOUNT_CLUSTER
            elif any(p.state in (CorrelationState.SUPPORTED, CorrelationState.STRONGLY_SUPPORTED, CorrelationState.VERIFIED_ASSOCIATION) for p in cluster_pairs):
                cluster_state = IdentityState.ACCOUNT_CLUSTER
            elif all_contradictions:
                cluster_state = IdentityState.DISPUTED
            else:
                cluster_state = IdentityState.INCONCLUSIVE

            common_orgs = [org for org, members in org_memberships.items() if all(aid in members for aid in aids)]
            common_verified_sites = [
                s for s in websites
                if s.verified and all(aid in s.linked_account_ids for aid in aids)
            ]
            common_any_sites = [
                s for s in websites
                if all(aid in s.linked_account_ids for aid in aids)
            ]

            if common_orgs or common_verified_sites:
                entity_state = IdentityState.ENTITY_ASSOCIATION_SUPPORTED
            elif any(accounts[aid].organization_claim for aid in aids) or common_any_sites:
                entity_state = IdentityState.ENTITY_ASSOCIATION_CANDIDATE
            else:
                entity_state = IdentityState.ACCOUNT_CLUSTER

            # Default privacy boundary: do not resolve real person from handle correlation alone.
            real_person_state = IdentityState.INCONCLUSIVE
            if existing_facts.get(f"person_association:{root}"):
                real_person_state = IdentityState.ENTITY_ASSOCIATION_VERIFIED

            current_handles = sorted({accounts[aid].current_handle for aid in aids})
            historical_handles = sorted(
                {
                    era.raw_handle
                    for era in eras
                    if era.account_id in aids and era.state != "CURRENT_OBSERVED"
                }
            )

            identity_clusters.append(
                IdentityClusterCandidate(
                    cluster_id=root,
                    account_ids=aids,
                    handles=current_handles,
                    historical_handles=historical_handles,
                    pair_assessments=cluster_pairs,
                    contradictions=all_contradictions,
                    confidence=round(avg_score, 4),
                    state=cluster_state,
                    entity_association_state=entity_state,
                    real_person_state=real_person_state,
                    limitations=[
                        "Cluster represents account association evidence, not automatic real-person identity.",
                        "Team-managed, brand, bot, parody, fan, recycled, or compromised accounts remain possible.",
                        "Historical handle eras must not be contaminated into current ownership claims.",
                    ],
                )
            )

        # ----------------------------------------------------------------------
        # 9. HYPOTHESES / FALSIFICATION / DUAL-AI SKEPTIC
        # ----------------------------------------------------------------------

        hypotheses: List[Hypothesis] = []
        top_cluster = max(identity_clusters, key=lambda c: c.confidence) if identity_clusters else None

        if top_cluster:
            strong_features = [
                f.name
                for p in top_cluster.pair_assessments
                for f in p.features
                if f.weight >= 0.40
            ]
            opposition = []
            if top_cluster.contradictions:
                opposition.extend(top_cluster.contradictions)
            if any(accounts[aid].account_type in (AccountType.PARODY, AccountType.FAN_ACCOUNT, AccountType.IMPERSONATION_CANDIDATE) for aid in top_cluster.account_ids):
                opposition.append("Parody/fan/impersonation context present.")
            if any(rc.get("state") in ("HANDLE_REUSE_CANDIDATE", "HANDLE_REASSIGNED_CANDIDATE") for rc in reuse_context):
                opposition.append("Handle reuse/reassignment context present.")

            hypotheses.append(
                Hypothesis(
                    id="H1",
                    description="Accounts in the cluster are associated as one account/entity cluster.",
                    support_evidence=sorted(set(strong_features)),
                    opposition_evidence=sorted(set(opposition)),
                    unknowns=["Real-world person identity", "Single operator vs team/organization control"],
                    falsification_criteria="Reject or downgrade if independent stable IDs, incompatible timelines, deceptive impersonation, or dependent-source artifacts dominate.",
                    status=HypothesisStatus.ACTIVE if top_cluster.state in (IdentityState.ACCOUNT_CLUSTER, IdentityState.ENTITY_ASSOCIATION_SUPPORTED, IdentityState.ENTITY_ASSOCIATION_VERIFIED) else HypothesisStatus.CANDIDATE,
                )
            )

            hypotheses.append(
                Hypothesis(
                    id="H2",
                    description="Accounts are distinct entities using same or similar handles.",
                    support_evidence=[
                        "Handle collision risk" if any(s["collision_risk"] == CollisionRisk.HIGH.name for s in seeds) else "No strong link evidence",
                    ],
                    opposition_evidence=sorted(set(strong_features)),
                    unknowns=["Whether handle was recycled", "Whether profiles copied each other"],
                    falsification_criteria="Reject if reciprocal self-links, authoritative website links, or verified organization membership connect accounts.",
                    status=HypothesisStatus.CANDIDATE if not strong_features else HypothesisStatus.REJECTED,
                )
            )

            hypotheses.append(
                Hypothesis(
                    id="H3",
                    description="One account impersonates or mimics another identity/brand.",
                    support_evidence=[imp["type"] for imp in impersonation_context if imp["type"] == "IMPERSONATION_CANDIDATE"],
                    opposition_evidence=["Parody/fan labels" if any(accounts[aid].account_type in (AccountType.PARODY, AccountType.FAN_ACCOUNT) for aid in top_cluster.account_ids) else "No explicit parody/fan label"],
                    unknowns=["Operator identity", "Campaign linkage"],
                    falsification_criteria="Reject if account is explicitly parody/fan or verified as official by authoritative source.",
                    status=HypothesisStatus.CANDIDATE if any(i["type"] == "IMPERSONATION_CANDIDATE" for i in impersonation_context) else HypothesisStatus.REJECTED,
                )
            )

            hypotheses.append(
                Hypothesis(
                    id="H4",
                    description="Handle was renamed, reassigned, or recycled across account eras.",
                    support_evidence=[rc["state"] for rc in reuse_context],
                    opposition_evidence=["Stable account ID continuity" if any(rc["state"] == "SAME_ACCOUNT_RENAME" for rc in reuse_context) else "No reuse context"],
                    unknowns=["Previous operator", "Platform release policy"],
                    falsification_criteria="Reject if stable platform account ID and continuous handle era prove same account.",
                    status=HypothesisStatus.CANDIDATE if reuse_context else HypothesisStatus.INCONCLUSIVE,
                )
            )

            hypotheses.append(
                Hypothesis(
                    id="H5",
                    description="Accounts are organization-, brand-, team-, or project-managed rather than single-person accounts.",
                    support_evidence=[
                        "verified organization membership" if top_cluster.entity_association_state == IdentityState.ENTITY_ASSOCIATION_SUPPORTED else "self-reported organization claim",
                    ],
                    opposition_evidence=["Personal self-claims" if any(accounts[aid].account_type == AccountType.PERSONAL_CLAIM for aid in top_cluster.account_ids) else "No personal self-claim"],
                    unknowns=["Employment", "Individual operator identity"],
                    falsification_criteria="Reject if independent evidence shows single personal operator and no organizational control.",
                    status=HypothesisStatus.ACTIVE if top_cluster.entity_association_state in (IdentityState.ENTITY_ASSOCIATION_CANDIDATE, IdentityState.ENTITY_ASSOCIATION_SUPPORTED, IdentityState.ENTITY_ASSOCIATION_VERIFIED) else HypothesisStatus.CANDIDATE,
                )
            )
        else:
            hypotheses.append(
                Hypothesis(
                    id="H1",
                    description="No sufficiently supported account cluster was identified.",
                    support_evidence=["No pair reached supported correlation threshold"],
                    opposition_evidence=[],
                    unknowns=["Whether additional public/authorized evidence exists"],
                    falsification_criteria="Upgrade if reciprocal self-links, authoritative website links, or verified organization membership appear.",
                    status=HypothesisStatus.INCONCLUSIVE,
                )
            )

        def skeptic_review() -> Dict[str, Any]:
            alternatives: List[str] = []
            flags: List[str] = []
            questions: List[str] = []

            if any(s["collision_risk"] == CollisionRisk.HIGH.name for s in seeds):
                alternatives.append("High-collision handle may belong to unrelated people, teams, brands, or recycled accounts.")
                flags.append("INCREASE_EVIDENCE_THRESHOLD_FOR_COMMON_HANDLE")

            if not top_cluster:
                alternatives.append("Same or similar handle alone is not identity evidence.")
                flags.append("DO_NOT_MERGE_ON_HANDLE_ALONE")

            if any(rc.get("state") in ("HANDLE_REUSE_CANDIDATE", "HANDLE_REASSIGNED_CANDIDATE") for rc in reuse_context):
                alternatives.append("Handle may have been renamed, released, reassigned, or recycled.")
                flags.append("PRESERVE_HANDLE_ERAS")

            if any(i["type"] in ("IMPERSONATION_CANDIDATE", "LOOKALIKE_CANDIDATE") for i in impersonation_context):
                alternatives.append("Lookalike account may be impersonation, parody, fan account, or unrelated coincidence.")
                flags.append("SEPARATE_PARODY_FAN_IMPERSONATION")

            if any(acc.account_type in (AccountType.ORGANIZATION, AccountType.BRAND, AccountType.TEAM_ACCOUNT, AccountType.SERVICE_ACCOUNT, AccountType.BOT) for acc in accounts.values()):
                alternatives.append("Account may be organization-, brand-, team-, service-, or bot-managed rather than one human operator.")
                flags.append("ACCOUNT_CLUSTER_BEFORE_PERSON")

            if len({ev.upstream_source_id for ev in evidences}) < len(evidences):
                alternatives.append("Some evidence may be dependent on the same upstream profile, website, archive, or aggregator.")
                flags.append("COUNT_INDEPENDENT_SOURCE_FAMILIES")

            questions.extend(
                [
                    "Is the handle sufficiently distinctive?",
                    "Could the account be parody or fan content?",
                    "Could the account be organization-managed?",
                    "Could the handle have been recycled?",
                    "Are self-reported bios independently corroborated?",
                    "Are sources actually independent or mirror/aggregator copies?",
                    "What evidence would establish accounts as distinct?",
                    "Do we have account-level association or unsupported real-person attribution?",
                ]
            )

            return {
                "alternative_explanations": alternatives,
                "flags": flags,
                "diagnostic_questions": questions,
                "identity_boundary": "Default to ACCOUNT_CLUSTER. Do not resolve real person without strong, authorized, consequential-evidence review.",
            }

        falsification_results = skeptic_review()

        # ----------------------------------------------------------------------
        # 10. GRAPHICAL MEMORY
        # ----------------------------------------------------------------------

        self.graph_nodes = {}
        self.graph_edges = []

        def add_node(node_id: str, node_type: str, attributes: Dict[str, Any]) -> None:
            self.graph_nodes[node_id] = GraphNode(node_id=node_id, type=node_type, attributes=attributes)

        def add_edge(source: str, target: str, relation: str, confidence: float, evidence_ids: List[str]) -> None:
            self.graph_edges.append(
                GraphEdge(
                    edge_id=new_id("EDGE"),
                    source_node_id=source,
                    target_node_id=target,
                    relation=relation,
                    confidence=confidence,
                    evidence_ids=evidence_ids,
                )
            )

        for seed in seeds:
            node_id = f"N_HANDLE_{seed['normalized_handle']}"
            add_node(
                node_id,
                "Handle",
                {
                    "raw": seed["raw_handle"],
                    "normalized": seed["normalized_handle"],
                    "confusable": seed["confusable_handle"],
                    "uniqueness": seed["uniqueness"],
                    "collision_risk": seed["collision_risk"],
                },
            )

        for aid, acc in accounts.items():
            acc_node = f"N_ACCOUNT_{aid}"
            handle_node = f"N_HANDLE_{acc.normalized_handle}"
            platform_node = f"N_PLATFORM_{acc.platform}"

            add_node(
                acc_node,
                "Account",
                {
                    "platform": acc.platform,
                    "platform_account_id": acc.platform_account_id,
                    "current_handle": acc.current_handle,
                    "display_name": acc.display_name,
                    "account_type": acc.account_type.name,
                    "status": acc.status,
                    "confidence": acc.confidence,
                },
            )

            add_node(platform_node, "Platform", {"platform": acc.platform})

            if handle_node not in self.graph_nodes:
                add_node(
                    handle_node,
                    "Handle",
                    {
                        "raw": acc.current_handle,
                        "normalized": acc.normalized_handle,
                        "confusable": acc.confusable_handle,
                    },
                )

            add_edge(acc_node, handle_node, "USES_HANDLE", acc.confidence, acc.evidence_ids)
            add_edge(acc_node, platform_node, "ACCOUNT_ON_PLATFORM", acc.confidence, acc.evidence_ids)

        for link in self_links:
            if link.target_account_id:
                add_edge(
                    f"N_ACCOUNT_{link.source_account_id}",
                    f"N_ACCOUNT_{link.target_account_id}",
                    "SELF_LINKS_TO",
                    link.confidence,
                    [link.evidence_id],
                )

        for site in websites:
            site_node = f"N_WEBSITE_{site.website_id}"
            add_node(
                site_node,
                "Website",
                {
                    "url": site.url,
                    "official_for": site.official_for,
                    "verified": site.verified,
                    "reliability": site.reliability,
                },
            )
            for aid in site.linked_account_ids:
                add_edge(site_node, f"N_ACCOUNT_{aid}", "LINKED_FROM", site.reliability, [site.evidence_id])

        for org, members in org_memberships.items():
            org_node = f"N_ORG_{org}"
            add_node(org_node, "Organization", {"organization": org})
            for aid in members:
                add_edge(f"N_ACCOUNT_{aid}", org_node, "ASSOCIATED_WITH_ORGANIZATION", 0.85, [])

        for cluster in identity_clusters:
            cluster_node = f"N_CLUSTER_{cluster.cluster_id}"
            add_node(
                cluster_node,
                "IdentityClusterCandidate",
                {
                    "account_ids": cluster.account_ids,
                    "state": cluster.state.name,
                    "entity_association_state": cluster.entity_association_state.name,
                    "real_person_state": cluster.real_person_state.name,
                    "confidence": cluster.confidence,
                },
            )
            for aid in cluster.account_ids:
                add_edge(cluster_node, f"N_ACCOUNT_{aid}", "MEMBER_OF_ACCOUNT_CLUSTER", cluster.confidence, [])

        # ----------------------------------------------------------------------
        # 11. SOURCE INDEPENDENCE / PEDIGREE / RELIABILITY
        # ----------------------------------------------------------------------

        upstream_groups: Dict[str, List[str]] = defaultdict(list)
        for ev in evidences:
            upstream_groups[ev.upstream_source_id].append(ev.evidence_id)

        source_independence = {
            "unique_upstream_families": len(upstream_groups),
            "total_evidence_items": len(evidences),
            "groups": {
                root: {
                    "evidence_ids": sorted(eids),
                    "state": SourceIndependenceState.DEPENDENT.name if len(eids) > 1 else SourceIndependenceState.INDEPENDENT.name,
                }
                for root, eids in upstream_groups.items()
            },
        }

        source_reliability = {
            ev.source_id: {
                "source_type": ev.source_type,
                "reliability": ev.reliability,
                "upstream_source_id": ev.upstream_source_id,
            }
            for ev in evidences
        }

        source_pedigree = {
            ev.evidence_id: {
                "source_id": ev.source_id,
                "source_type": ev.source_type,
                "upstream_source_id": ev.upstream_source_id,
                "observed_at": ev.observed_at,
            }
            for ev in evidences
        }

        # ----------------------------------------------------------------------
        # 12. NEXT BEST ACTIONS / HANDOFFS
        # ----------------------------------------------------------------------

        recommended_next_actions: List[Dict[str, Any]] = []

        if any(not acc.platform_account_id for acc in accounts.values()):
            recommended_next_actions.append(
                {
                    "action": "Retrieve platform-native public profile to resolve stable account ID.",
                    "reason": "Stable account ID is required for handle-era and reuse resolution.",
                    "specialist": "USERNAMEINT",
                    "privacy": "PUBLIC_ONLY",
                }
            )

        if websites and not any(site.verified for site in websites):
            recommended_next_actions.append(
                {
                    "action": "Verify official website ownership through authoritative corporate/org source.",
                    "reason": "Website links are strong only if website authority is verified.",
                    "specialist": "WEBINT / ORGINT / CORPINT",
                    "privacy": "PUBLIC_ONLY",
                }
            )

        if impersonation_context:
            recommended_next_actions.append(
                {
                    "action": "Separate parody, fan, lookalike, and impersonation candidates before any operator conclusion.",
                    "reason": "Lookalike handles may be benign, parody, fan, or deceptive.",
                    "specialist": "USERNAMEINT / FRAUDINT if lawful context requires",
                    "privacy": "PUBLIC_ONLY",
                }
            )

        if reuse_context:
            recommended_next_actions.append(
                {
                    "action": "Resolve handle eras using stable IDs, archives, and platform metadata.",
                    "reason": "Historical handle must not contaminate current owner claims.",
                    "specialist": "USERNAMEINT / ARCHIVEINT",
                    "privacy": "PUBLIC_ONLY",
                }
            )

        if top_cluster and top_cluster.real_person_state == IdentityState.INCONCLUSIVE:
            recommended_next_actions.append(
                {
                    "action": "Do not proceed to real-person attribution without independent, authorized, consequential-evidence review.",
                    "reason": "Handle correlation resolves accounts/entities first, not private persons.",
                    "specialist": "HUMAN_REVIEW",
                    "privacy": "PRIVACY_BOUNDARY",
                }
            )

        specialist_handoffs = [
            {"specialist": "SOCMINT", "reason": "Deep public social-content behavior is outside USERNAMEINT core scope."},
            {"specialist": "WEBINT", "reason": "Website ownership/content verification."},
            {"specialist": "ARCHIVEINT", "reason": "Historical public profiles and deleted pages."},
            {"specialist": "ORGINT / CORPINT", "reason": "Organization/brand verification."},
            {"specialist": "REPOINT", "reason": "Developer repository/package identity context."},
            {"specialist": "CREDINT", "reason": "If public code/profile exposes secrets, defensive exposure handling only."},
            {"specialist": "FRAUDINT", "reason": "If scam/fraud context emerges, handle resolution only; no guilt determination."},
            {"specialist": "THREATACTORINT / CTI", "reason": "If threat-actor alias context emerges, maintain alias/account uncertainty."},
        ]

        # ----------------------------------------------------------------------
        # 13. ANALYST SUMMARY
        # ----------------------------------------------------------------------

        def build_analyst_summary() -> str:
            lines: List[str] = []
            lines.append("=== USERNAMEINT REQUIRED ANALYST SUMMARY ===")

            for seed in seeds:
                lines.append(f"SEED HANDLE: {seed['raw_handle']}")
                lines.append(f"NORMALIZED HANDLE: {seed['normalized_handle']}")
                lines.append(f"HANDLE UNIQUENESS: {seed['uniqueness']}")
                lines.append(f"HANDLE COLLISION RISK: {seed['collision_risk']}")

            platforms = sorted({acc.platform for acc in accounts.values()})
            lines.append(f"PLATFORM PRESENCE: {', '.join(platforms) if platforms else 'none'}")

            current_accounts = [f"{acc.platform}/{acc.current_handle} ({acc.account_id})" for acc in accounts.values()]
            lines.append(f"CURRENT ACCOUNTS OBSERVED: {len(current_accounts)}")

            historical_accounts = [era for era in eras if era.state != "CURRENT_OBSERVED"]
            lines.append(f"HISTORICAL/ARCHIVED HANDLE ERAS: {len(historical_accounts)}")

            stable_ids = sorted({acc.platform_account_id for acc in accounts.values() if acc.platform_account_id})
            lines.append(f"STABLE ACCOUNT IDs: {', '.join(stable_ids) if stable_ids else 'none resolved'}")

            account_types = sorted({acc.account_type.name for acc in accounts.values()})
            lines.append(f"ACCOUNT TYPES: {', '.join(account_types) if account_types else 'none'}")

            lines.append(f"PUBLIC SELF-LINKS: {len(self_links)}")
            lines.append(f"AUTHORITATIVE WEBSITE LINK FAMILIES: {len(websites)}")
            lines.append(f"VERIFIED ORGANIZATION MEMBERSHIP FAMILIES: {len(org_memberships)}")

            if top_cluster:
                lines.append(f"TOP IDENTITY CLUSTER: {top_cluster.cluster_id}")
                lines.append(f"CLUSTER ACCOUNTS: {', '.join(top_cluster.account_ids)}")
                lines.append(f"CLUSTER STATE: {top_cluster.state.name}")
                lines.append(f"ENTITY ASSOCIATION STATE: {top_cluster.entity_association_state.name}")
                lines.append(f"REAL-PERSON ASSOCIATION: {top_cluster.real_person_state.name}")
                lines.append(f"CLUSTER CONFIDENCE: {top_cluster.confidence}")

                evidence_names = sorted({f.name for p in top_cluster.pair_assessments for f in p.features if f.weight > 0})
                lines.append(f"CORRELATION EVIDENCE: {', '.join(evidence_names) if evidence_names else 'none'}")
            else:
                lines.append("IDENTITY CLUSTER: no supported cluster")
                lines.append("REAL-PERSON ASSOCIATION: INCONCLUSIVE")

            lines.append(f"HANDLE REUSE / REASSIGNMENT CONTEXT: {len(reuse_context)}")
            lines.append(f"IMPERSONATION / PARODY CONTEXT ITEMS: {len(impersonation_context)}")
            lines.append(f"CONTRADICTIONS: {len({c for p in pair_assessments for c in p.contradictions})}")
            lines.append(f"SOURCE UPSTREAM FAMILIES: {source_independence['unique_upstream_families']}")
            lines.append("PRIVACY BOUNDARY: account cluster first; real-person attribution last; no private access.")
            lines.append("NEXT ACTION: resolve stable IDs, authoritative website/org ownership, and handle eras before any identity escalation.")

            return "\n".join(lines)

        analyst_summary = build_analyst_summary()

        # ----------------------------------------------------------------------
        # 14. RESULT OBJECT
        # ----------------------------------------------------------------------

        all_contradictions = sorted({c for p in pair_assessments for c in p.contradictions})

        result: Dict[str, Any] = {
            "case_id": case_id,
            "task_id": task_id,
            "objective": objective,
            "status": "COMPLETED",
            "model_mode": self.model_mode,
            "questions": scope.get("questions", []),
            "authorized_scope": scope,
            "source_ids": sorted({ev.source_id for ev in evidences}),
            "evidence_ids": sorted({ev.evidence_id for ev in evidences}),
            "seed_handles": seeds,
            "normalized_handles": sorted({s["normalized_handle"] for s in seeds}),
            "handle_variants": {s["raw_handle"]: s["variants"] for s in seeds},
            "platforms": sorted({acc.platform for acc in accounts.values()}),
            "accounts": [asdict(acc) for acc in accounts.values()],
            "platform_account_ids": sorted({acc.platform_account_id for acc in accounts.values() if acc.platform_account_id}),
            "current_handles": sorted({acc.current_handle for acc in accounts.values()}),
            "historical_handles": sorted({era.raw_handle for era in eras if era.state != "CURRENT_OBSERVED"}),
            "handle_eras": [asdict(era) for era in eras],
            "display_names": sorted({acc.display_name for acc in accounts.values() if acc.display_name}),
            "account_types": {acc.account_id: acc.account_type.name for acc in accounts.values()},
            "account_states": {acc.account_id: acc.status for acc in accounts.values()},
            "creation_dates": {acc.account_id: acc.created_at_if_public for acc in accounts.values()},
            "first_seen": {acc.account_id: acc.first_seen for acc in accounts.values()},
            "last_seen": {acc.account_id: acc.last_seen for acc in accounts.values()},
            "public_self_claims": {acc.account_id: acc.public_self_claims for acc in accounts.values()},
            "public_self_links": [asdict(link) for link in self_links],
            "authoritative_links": [asdict(site) for site in websites],
            "organization_associations": {org: sorted(set(members)) for org, members in org_memberships.items()},
            "brand_associations": {
                site.official_for: site.linked_account_ids
                for site in websites
                if site.official_for
            },
            "project_associations": {proj: sorted(set(members)) for proj, members in project_refs.items()},
            "developer_context": {
                acc.account_id: acc.platform
                for acc in accounts.values()
                if acc.platform in {"github", "gitlab", "bitbucket", "repo", "package"}
            },
            "forum_context": {
                acc.account_id: acc.platform
                for acc in accounts.values()
                if "forum" in acc.platform.lower()
            },
            "social_context": {
                acc.account_id: acc.platform
                for acc in accounts.values()
                if acc.platform in {"twitter_like", "x", "instagram", "facebook", "reddit", "youtube"}
            },
            "messaging_context": {
                acc.account_id: acc.platform
                for acc in accounts.values()
                if acc.platform in {"telegram", "discord", "signal", "whatsapp"}
            },
            "marketplace_context": {
                acc.account_id: acc.platform
                for acc in accounts.values()
                if "marketplace" in acc.platform.lower()
            },
            "bot_context": {
                acc.account_id: acc.account_type.name
                for acc in accounts.values()
                if acc.account_type in (AccountType.BOT, AccountType.AUTOMATION, AccountType.SERVICE_ACCOUNT)
            },
            "parody_context": [imp for imp in impersonation_context if imp["type"] == "PARODY"],
            "fan_account_context": [imp for imp in impersonation_context if imp["type"] == "FAN_ACCOUNT"],
            "impersonation_context": [imp for imp in impersonation_context if imp["type"] in ("IMPERSONATION_CANDIDATE", "LOOKALIKE_CANDIDATE")],
            "identity_clusters": [asdict(cluster) for cluster in identity_clusters],
            "correlation_features": {
                pair.pair_id: [asdict(feature) for feature in pair.features]
                for pair in pair_assessments
            },
            "correlation_states": {pair.pair_id: pair.state.name for pair in pair_assessments},
            "correlation_confidence": {pair.pair_id: pair.score for pair in pair_assessments},
            "collision_risk": {s["raw_handle"]: s["collision_risk"] for s in seeds},
            "reuse_context": reuse_context,
            "timeline_updates": sorted(
                [asdict(era) for era in eras],
                key=lambda x: x.get("valid_from") or datetime.min.replace(tzinfo=timezone.utc),
            ),
            "observations": [asdict(ev) for ev in evidences],
            "candidate_facts": [
                {
                    "fact": f"Handle '{acc.current_handle}' observed on platform '{acc.platform}'.",
                    "evidence_ids": acc.evidence_ids,
                    "confidence": acc.confidence,
                }
                for acc in accounts.values()
            ],
            "supported_facts": [
                {
                    "fact": f"Website '{site.url}' links accounts {site.linked_account_ids}.",
                    "evidence_ids": [site.evidence_id],
                    "confidence": site.reliability,
                    "verified": site.verified,
                }
                for site in websites
            ],
            "partial_facts": [
                {
                    "fact": f"Account '{acc.account_id}' self-claims organization '{acc.organization_claim}'.",
                    "evidence_ids": acc.evidence_ids,
                    "confidence": 0.35,
                    "limitation": "Self-reported organization claim is not verified identity evidence.",
                }
                for acc in accounts.values()
                if acc.organization_claim
            ],
            "disputed_facts": all_contradictions,
            "source_reliability": source_reliability,
            "source_bias": [
                "Platform visibility limits may hide accounts.",
                "Search indexes and aggregators may be stale or dependent.",
                "Self-presented bios may be inaccurate, parody, promotional, or team-authored.",
                "Archive snapshots preserve historical states but do not prove current ownership.",
            ],
            "source_limitations": [
                "No private account access.",
                "No authentication bypass.",
                "No credential testing.",
                "No biometric identification.",
                "No sensitive-trait inference.",
            ],
            "source_pedigree": source_pedigree,
            "source_independence": source_independence,
            "contradictions": all_contradictions,
            "hypotheses": [asdict(h) for h in hypotheses],
            "falsification_results": falsification_results,
            "privacy_flags": [
                "PUBLIC_ONLY_DEFAULT",
                "NO_PRIVATE_ACCESS",
                "NO_CREDENTIAL_ATTACK",
                "NO_DOXXING",
                "NO_STALKING",
                "NO_FACE_IDENTIFICATION",
                "NO_VOICE_IDENTIFICATION",
                "NO_SENSITIVE_TRAIT_INFERENCE",
                "ACCOUNT_CLUSTER_BEFORE_PERSON",
            ],
            "unknowns": [
                "Real-world person identity remains unresolved by default.",
                "Single-operator versus team/organization control remains unresolved unless verified.",
                "Historical owner of recycled handles remains unresolved unless archived/authorized evidence exists.",
            ],
            "knowledge_gaps": gaps,
            "recommended_next_actions": recommended_next_actions,
            "specialist_handoffs": specialist_handoffs,
            "limitations": [
                "USERNAMEINT resolves handles/accounts/entities, not legal identity.",
                "Same handle is weak evidence.",
                "Display name similarity is very weak evidence.",
                "Avatar similarity is supporting evidence only.",
                "Bio similarity may be copied or dependent.",
                "Organization membership does not automatically prove employment.",
                "Account transfer/compromise remains possible.",
            ],
            "analyst_summary": analyst_summary,
            "graphical_memory": {
                "nodes": [asdict(node) for node in self.graph_nodes.values()],
                "edges": [asdict(edge) for edge in self.graph_edges],
            },
            "replay_manifest": {
                "seed_handles": seeds,
                "normalization_rules": {
                    "unicode_form": "NFKC",
                    "case_folding": "platform-rule-dependent",
                    "confusable_fold": "defensive_lookalike_detection_only",
                },
                "evidence_ids": sorted({ev.evidence_id for ev in evidences}),
                "pair_assessments": [asdict(p) for p in pair_assessments],
                "identity_clusters": [asdict(c) for c in identity_clusters],
                "source_upstream_families": sorted(upstream_groups.keys()),
                "model_mode": self.model_mode,
                "generated_at": now,
            },
        }

        logger.info("USERNAMEINT case completed. clusters=%s pairs=%s accounts=%s", len(identity_clusters), len(pair_assessments), len(accounts))
        return result


# ==============================================================================
# EXAMPLE EXECUTION
# ==============================================================================

if __name__ == "__main__":
    analyst = UsernameIntEmployee(model_mode="LOCAL_ONLY")

    case_id = "CASE_USERNAME_001"
    task_id = "TASK_HANDLE_CORRELATION_001"

    objective = (
        "Correlate public/authorized observations for the handle nightfalcon27 across platforms, "
        "resolve account clusters, collision risk, handle reuse, and impersonation/parody context. "
        "Do not infer real-person identity."
    )

    scope = {
        "mode": "PUBLIC_ONLY",
        "authorized_authenticated": False,
        "questions": [
            "Which observed accounts use the seed handle or close variants?",
            "Which accounts are linked by public self-links or authoritative websites?",
            "Is the handle common or distinctive?",
            "Is there handle reuse/reassignment?",
            "Is there parody/fan/impersonation context?",
            "What remains unresolved?",
        ],
        "allow_private_access": False,
        "allow_authentication_bypass": False,
        "allow_credential_attack": False,
        "allow_doxing": False,
        "allow_stalking": False,
        "allow_face_identification": False,
        "allow_voice_identification": False,
        "allow_sensitive_trait_inference": False,
    }

    seed_handles = ["nightfalcon27"]

    public_evidence = {
        "accounts": [
            {
                "platform": "github",
                "platform_account_id": "GH-111",
                "current_handle": "nightfalcon27",
                "display_name": "Night Falcon",
                "account_type_claim": "PERSONAL_CLAIM",
                "profile_url": "https://github.example/nightfalcon27",
                "created_at": "2021-05-01T00:00:00Z",
                "first_seen": "2026-10-01T00:00:00Z",
                "last_seen": "2026-10-09T00:00:00Z",
                "status": "ACTIVE_PUBLIC",
                "bio": "Security researcher. Website: https://nightfalcon.example",
                "organization_claim": None,
                "location_claim": None,
                "public_links": [
                    {
                        "target_platform": "website",
                        "target_url": "https://nightfalcon.example",
                        "link_type": "bio_website",
                    }
                ],
                "project_references": [
                    "https://github.example/nightfalcon27/toolkit"
                ],
                "avatar_hash": "AVATAR_9F2C",
                "source_type": "platform_native_profile",
                "source_id": "SRC_GH_111",
                "upstream_source_id": "PROFILE_GH_111",
            },
            {
                "platform": "twitter_like",
                "platform_account_id": "TW-222",
                "current_handle": "nightfalcon27",
                "display_name": "Night Falcon",
                "account_type_claim": "PERSONAL_CLAIM",
                "profile_url": "https://x.example/nightfalcon27",
                "created_at": "2021-06-15T00:00:00Z",
                "first_seen": "2026-10-02T00:00:00Z",
                "last_seen": "2026-10-09T00:00:00Z",
                "status": "ACTIVE_PUBLIC",
                "bio": "Security research. Site: https://nightfalcon.example",
                "organization_claim": None,
                "location_claim": None,
                "public_links": [
                    {
                        "target_platform": "website",
                        "target_url": "https://nightfalcon.example",
                        "link_type": "bio_website",
                    }
                ],
                "project_references": [
                    "https://github.example/nightfalcon27/toolkit"
                ],
                "avatar_hash": "AVATAR_9F2C",
                "source_type": "platform_native_profile",
                "source_id": "SRC_TW_222",
                "upstream_source_id": "PROFILE_TW_222",
            },
            {
                "platform": "forum",
                "platform_account_id": "FR-333",
                "current_handle": "nightfalcon27",
                "display_name": "NF",
                "account_type_claim": "PERSONAL_CLAIM",
                "profile_url": "https://forum.example/user/333",
                "created_at": "2025-01-10T00:00:00Z",
                "first_seen": "2026-10-03T00:00:00Z",
                "last_seen": "2026-10-09T00:00:00Z",
                "status": "ACTIVE_PUBLIC",
                "bio": "Just a fan of security topics.",
                "organization_claim": None,
                "location_claim": None,
                "public_links": [],
                "project_references": [],
                "avatar_hash": "AVATAR_GENERIC",
                "source_type": "public_forum_profile",
                "source_id": "SRC_FR_333",
                "upstream_source_id": "PROFILE_FR_333",
            },
            {
                "platform": "instagram",
                "platform_account_id": "IG-999",
                "current_handle": "nightfa1con27",
                "display_name": "Night Falcon Official",
                "account_type_claim": "ORGANIZATION",
                "profile_url": "https://instagram.example/nightfa1con27",
                "created_at": "2026-09-01T00:00:00Z",
                "first_seen": "2026-10-05T00:00:00Z",
                "last_seen": "2026-10-09T00:00:00Z",
                "status": "ACTIVE_PUBLIC",
                "bio": "Official account. Contact for promos.",
                "organization_claim": "Night Falcon Media",
                "location_claim": None,
                "public_links": [],
                "project_references": [],
                "avatar_hash": "AVATAR_9F2C",
                "source_type": "platform_native_profile",
                "source_id": "SRC_IG_999",
                "upstream_source_id": "PROFILE_IG_999",
            },
        ],
        "websites": [
            {
                "url": "https://nightfalcon.example",
                "official_for": "Night Falcon Projects",
                "links_to_accounts": [
                    {
                        "platform": "github",
                        "platform_account_id": "GH-111",
                    },
                    {
                        "platform": "twitter_like",
                        "platform_account_id": "TW-222",
                    },
                ],
                "source_type": "official_website",
                "source_id": "SRC_WEB_1",
                "upstream_source_id": "WEB_NIGHTFALCON",
            }
        ],
        "organizations": [
            {
                "organization_id": "ORG_NIGHTFALCON_PROJECTS",
                "name": "Night Falcon Projects",
                "verified_accounts": [
                    {
                        "platform": "github",
                        "platform_account_id": "GH-111",
                    }
                ],
                "source_type": "verified_organization_directory",
                "source_id": "SRC_ORG_1",
                "upstream_source_id": "ORG_DIR_1",
            }
        ],
        "archives": [
            {
                "platform": "github",
                "platform_account_id": "GH-111",
                "handle": "nightfalcon_old",
                "snapshot_at": "2020-01-01T00:00:00Z",
                "valid_from": "2019-01-01T00:00:00Z",
                "valid_to": "2021-04-30T00:00:00Z",
                "source_type": "web_archive_snapshot",
                "source_id": "SRC_ARCH_1",
                "upstream_source_id": "ARCH_GH_111",
            }
        ],
    }

    existing_facts = {
        "website:https://nightfalcon.example owner:Night Falcon Projects": True,
        "organization:ORG_NIGHTFALCON_PROJECTS account:github/GH-111": True,
    }

    report = analyst.process_case(
        case_id=case_id,
        task_id=task_id,
        objective=objective,
        scope=scope,
        seed_handles=seed_handles,
        public_evidence=public_evidence,
        existing_facts=existing_facts,
    )

    print("\n" + "=" * 100)
    print("TRACEATLAS / USERNAMEINT DEFENSIVE REPORT")
    print("=" * 100)
    print(report.get("analyst_summary", ""))
    print("\n" + "=" * 100)
    print("FULL JSON RESULT")
    print("=" * 100)
    print(json.dumps(report, indent=2, default=json_serial))