# TRACEATLAS — SCAMNETINT + HYPOTHESISINT + ACADEMICINT
# Single-file defensive Python core.
#
# SCAMNETINT:
#   - Maps scam infrastructure/entity relationships from authorized/public supplied evidence.
#   - Does NOT hack, scan, exploit, seize, sinkhole, contact scammers, make test payments,
#     use credentials, dox real persons, or identify private people from weak clues.
#
# HYPOTHESISINT:
#   - Generates/tests competing hypotheses, predictions, falsifiers, ACH-style evidence matrix.
#   - Does NOT fabricate certainty, hide contradictions, or treat AI output as evidence.
#
# ACADEMICINT:
#   - Analyzes supplied papers, authors, institutions, citations, versions, retractions.
#   - Does NOT fabricate papers/DOIs/citations/authors, plagiarize, manipulate citations,
#     harass researchers, or present preprints as peer-reviewed.

from __future__ import annotations

import difflib
import hashlib
import json
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


TOOL_VERSION = "TRACEATLAS-SHA-0.1"
MAX_DT = datetime.max.replace(tzinfo=timezone.utc)


# ======================================================================
# Common enums / status
# ======================================================================

class Mode(str, Enum):
    LOCAL_ONLY = "LOCAL_ONLY"
    HYBRID = "HYBRID"
    CLOUD = "CLOUD"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class Status(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    BLOCKED_AUTHORIZATION = "BLOCKED_AUTHORIZATION"


# ======================================================================
# Common utilities
# ======================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(x)))


def mean(values: list[float], default: float = 0.0) -> float:
    if not values:
        return default
    return sum(values) / len(values)


def sha256_12(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8", errors="ignore")).hexdigest()[:12]


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        dt = None
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d %b %Y", "%b %d, %Y", "%d-%m-%Y"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def norm_text(text: Any) -> str:
    text = unicodedata.normalize("NFKC", str(text or ""))
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def text_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def normalize_domain(value: Any) -> str:
    s = str(value or "").strip().lower().rstrip(".")
    if "://" in s:
        parsed = urlparse(s)
        s = parsed.netloc or parsed.path
    s = s.split("/")[0].strip(".")
    return s


def normalize_url(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s
    parsed = urlparse(s)
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    query_pairs: list[tuple[str, str]] = []
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        lk = k.lower()
        if lk.startswith("utm_") or lk in {"ref", "fbclid", "gclid", "mc_cid", "mc_eid"}:
            continue
        query_pairs.append((k, v))
    query = urlencode(query_pairs, doseq=True)
    return urlunparse((parsed.scheme or "https", netloc, path, "", query, ""))


def normalize_email(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s


def normalize_phone(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def normalize_handle(value: Any) -> str:
    return str(value or "").strip().lower().lstrip("@")


def mask_secret(value: Any, keep_start: int = 3, keep_end: int = 3) -> str:
    s = str(value or "")
    if not s:
        return ""
    if len(s) <= keep_start + keep_end:
        return "***"
    return s[:keep_start] + "***" + s[-keep_end:]


def mask_email(value: Any) -> str:
    s = normalize_email(value)
    if not s or "@" not in s:
        return mask_secret(s, 1, 1)
    local, domain = s.rsplit("@", 1)
    if len(local) <= 2:
        lm = "***"
    else:
        lm = local[0] + "***" + local[-1]
    return f"{lm}@{domain}"


def mask_phone(value: Any) -> str:
    digits = normalize_phone(value)
    if not digits:
        return ""
    if len(digits) <= 5:
        return "***"
    return digits[:3] + "***" + digits[-2:]


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, x: str) -> None:
        self.parent.setdefault(x, x)

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: str, b: str) -> str:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        if ra < rb:
            self.parent[rb] = ra
            return ra
        self.parent[ra] = rb
        return rb


def interval_overlap(
    start_a: Optional[str],
    end_a: Optional[str],
    start_b: Optional[str],
    end_b: Optional[str],
) -> tuple[bool, bool]:
    """
    Returns (overlap_ok, temporal_known).
    If any explicit interval conflict => False.
    If no explicit intervals => True but temporal_known=False.
    """
    sa = parse_dt(start_a)
    ea = parse_dt(end_a)
    sb = parse_dt(start_b)
    eb = parse_dt(end_b)

    known = any(x is not None for x in (sa, ea, sb, eb))

    if ea and sb and ea < sb:
        return False, known
    if eb and sa and eb < sa:
        return False, known

    return True, known


# ======================================================================
# SCAMNETINT
# ======================================================================

SCAM_NODE_TYPES = {
    "PERSONA",
    "PERSON_CANDIDATE",
    "ORGANIZATION",
    "COMPANY",
    "BRAND",
    "MERCHANT",
    "VENDOR",
    "DOMAIN",
    "SUBDOMAIN",
    "URL",
    "WEBSITE",
    "IP_ADDRESS",
    "ASN",
    "CERTIFICATE",
    "EMAIL",
    "PHONE",
    "HANDLE",
    "SOCIAL_ACCOUNT",
    "MARKETPLACE_ACCOUNT",
    "PAYMENT_ACCOUNT",
    "BANK_ACCOUNT_REFERENCE",
    "PAYMENT_INSTRUMENT",
    "CRYPTO_ADDRESS",
    "WALLET",
    "INVOICE",
    "TRANSACTION",
    "COMPLAINT",
    "VICTIM_REPORT",
    "INFRASTRUCTURE_CLUSTER",
    "EVIDENCE",
    "OBSERVATION",
    "FACT",
    "HYPOTHESIS",
    "CONTRADICTION",
    "GAP",
}

SCAM_WEAK_EDGE_TYPES = {
    "USES_ASN",
    "SHARES_REGISTRAR",
    "SHARES_CDN",
    "SHARES_NAMESERVER",
    "SHARES_CMS",
    "SAME_COUNTRY",
    "SHARES_GENERIC_TEMPLATE",
}

SCAM_MEDIUM_EDGE_TYPES = {
    "USES_DOMAIN",
    "USES_URL",
    "USES_EMAIL",
    "USES_PHONE",
    "USES_HANDLE",
    "USES_SOCIAL_ACCOUNT",
    "USES_MARKETPLACE_ACCOUNT",
    "HOSTED_ON",
    "RESOLVES_TO",
    "USES_IP_ADDRESS",
    "USES_CERTIFICATE",
    "SHARES_TEMPLATE_WITH",
    "SHARES_CONTENT_WITH",
    "SHARES_INFRASTRUCTURE_WITH",
    "IMPERSONATES",
    "REDIRECTS_TO",
    "CONTACTED",
    "OBSERVED_WITH",
}

SCAM_STRONG_EDGE_TYPES = {
    "USES_PAYMENT_ACCOUNT",
    "USES_WALLET",
    "USES_CRYPTO_ADDRESS",
    "REQUESTED_PAYMENT_TO",
    "TRANSFERRED_TO",
    "USES_UNIQUE_TRACKING_ID",
    "SHARES_UNIQUE_ARTIFACT",
}

SCAM_EDGE_STATES = {
    "OBSERVED",
    "SUPPORTED",
    "PROBABLE",
    "POSSIBLE",
    "DISPUTED",
    "REJECTED",
    "HISTORICAL",
    "UNKNOWN",
}

SCAMNET_BLOCK_PHRASES = [
    "hack scam",
    "attack infrastructure",
    "exploit domain",
    "exploit server",
    "take over domain",
    "seize domain",
    "sinkhole",
    "change dns",
    "modify dns",
    "contact scammer",
    "contact suspected scammer",
    "impersonate victim",
    "test payment",
    "make test payment",
    "purchase illicit",
    "buy illicit",
    "plant tracking malware",
    "deploy malware",
    "dox",
    "home address",
    "identify real person",
    "real person attribution",
    "harass suspect",
    "vigilante",
    "use credentials",
    "stolen credentials",
    "replay session",
    "access private account",
    "unauthorized sinkholing",
]


@dataclass
class ScamNode:
    node_id: str
    node_type: str
    value: str
    first_seen: str = ""
    last_seen: str = ""
    valid_from: str = ""
    valid_to: str = ""
    source_id: str = ""
    upstream_source: str = ""
    evidence_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScamEdge:
    edge_id: str
    from_node: str
    to_node: str
    edge_type: str
    state: str = "PROBABLE"
    confidence: float = 0.5
    source_id: str = ""
    upstream_source: str = ""
    evidence_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    valid_from: str = ""
    valid_to: str = ""
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScamComplaint:
    complaint_id: str
    reporter_pseudonym: str = ""
    domain: str = ""
    url: str = ""
    email: str = ""
    phone: str = ""
    payment_ref: str = ""
    wallet: str = ""
    amount: float = 0.0
    currency: str = ""
    time: str = ""
    source_id: str = ""
    upstream_source: str = ""
    evidence_id: str = ""
    text: str = ""


@dataclass
class ScamNetRequest:
    case_id: str
    objective: str
    authorization: dict[str, Any] = field(default_factory=dict)
    nodes: list[ScamNode] = field(default_factory=list)
    edges: list[ScamEdge] = field(default_factory=list)
    complaints: list[ScamComplaint] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)
    time_range: dict[str, str] = field(default_factory=dict)


@dataclass
class ScamNetResult:
    case_id: str
    status: str
    policy_decision: str
    summary: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    clusters: list[dict[str, Any]]
    personas: list[dict[str, Any]]
    complaints: list[dict[str, Any]]
    raw_complaint_count: int
    unique_complaint_families: int
    source_independence: dict[str, Any]
    contradictions: list[dict[str, Any]]
    falsification: list[dict[str, Any]]
    unknowns: list[str]
    knowledge_gaps: list[str]
    recommended_next_actions: list[str]
    specialist_handoffs: list[str]
    privacy_flags: list[str]
    limitations: list[str]
    replay_manifest: dict[str, Any]
    created_at: str


class ScamNetIntAgent:
    """
    Defensive SCAMNETINT core.

    Uses only supplied nodes/edges/complaints.
    Does not invent links, contact scammers, attack infrastructure, or dox persons.
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    def policy_check(self, req: ScamNetRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        if req.authorization.get("authorized") is not True:
            return (
                PolicyDecision.BLOCK,
                "BLOCKED_AUTHORIZATION",
                "SCAMNETINT requires explicit authorized defensive scope.",
            )

        for phrase in SCAMNET_BLOCK_PHRASES:
            if phrase in blob:
                return (
                    PolicyDecision.BLOCK,
                    "BLOCKED_POLICY",
                    f"Prohibited scam-network action requested: {phrase}",
                )

        return PolicyDecision.ALLOW, "", ""

    def blocked_result(self, req: ScamNetRequest, code: str, reason: str) -> ScamNetResult:
        return ScamNetResult(
            case_id=req.case_id,
            status=code,
            policy_decision=PolicyDecision.BLOCK.value,
            summary=f"POLICY_BLOCKED: {reason}",
            nodes=[],
            edges=[],
            clusters=[],
            personas=[],
            complaints=[],
            raw_complaint_count=0,
            unique_complaint_families=0,
            source_independence={},
            contradictions=[],
            falsification=[],
            unknowns=["Request outside defensive SCAMNETINT boundary."],
            knowledge_gaps=["No network analysis performed."],
            recommended_next_actions=[
                "Reframe as passive, authorized, privacy-aware scam-network correlation."
            ],
            specialist_handoffs=[],
            privacy_flags=[reason],
            limitations=[reason],
            replay_manifest={},
            created_at=now_iso(),
        )

    def _normalize_node(self, node: ScamNode) -> dict[str, Any]:
        ntype = node.node_type.upper()
        value = node.value

        if ntype in {"DOMAIN", "SUBDOMAIN"}:
            norm = normalize_domain(value)
            display = norm
        elif ntype in {"URL", "WEBSITE"}:
            norm = normalize_url(value)
            display = norm
        elif ntype == "EMAIL":
            norm = normalize_email(value)
            display = mask_email(norm)
        elif ntype == "PHONE":
            norm = normalize_phone(value)
            display = mask_phone(norm)
        elif ntype in {"HANDLE", "SOCIAL_ACCOUNT", "MARKETPLACE_ACCOUNT"}:
            norm = normalize_handle(value)
            display = norm
        elif ntype in {"PAYMENT_ACCOUNT", "BANK_ACCOUNT_REFERENCE", "CRYPTO_ADDRESS", "WALLET"}:
            norm = str(value).strip()
            display = mask_secret(norm, 4, 4)
        elif ntype == "IP_ADDRESS":
            norm = str(value).strip()
            display = norm
        else:
            norm = norm_text(value)
            display = str(value)

        return {
            "node_id": node.node_id,
            "node_type": ntype,
            "value": display,
            "normalized_value": norm,
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
            "valid_from": node.valid_from,
            "valid_to": node.valid_to,
            "source_id": node.source_id,
            "upstream_source": node.upstream_source,
            "evidence_id": node.evidence_id,
            "metadata": node.metadata,
            "privacy_note": (
                "Email/phone/payment/wallet values are masked in output."
                if ntype in {"EMAIL", "PHONE", "PAYMENT_ACCOUNT", "BANK_ACCOUNT_REFERENCE", "CRYPTO_ADDRESS", "WALLET"}
                else ""
            ),
        }

    def _temporal_check(self, edge: dict[str, Any], node_map: dict[str, dict[str, Any]]) -> tuple[bool, float, list[str]]:
        notes: list[str] = []
        ok = True
        factor = 1.0

        e_start = edge.get("valid_from") or edge.get("first_seen")
        e_end = edge.get("valid_to") or edge.get("last_seen")

        for nid in (edge["from_node"], edge["to_node"]):
            node = node_map.get(nid)
            if not node:
                notes.append(f"{edge['edge_id']}: node {nid} unresolved")
                factor *= 0.85
                continue

            n_ok, n_known = interval_overlap(e_start, e_end, node.get("valid_from"), node.get("valid_to"))
            if not n_ok:
                ok = False
                notes.append(f"{edge['edge_id']}: temporal conflict with node {nid}")
                factor = 0.05
            elif not n_known:
                factor *= 0.92
                notes.append(f"{edge['edge_id']}: temporal coverage incomplete for node {nid}")

        if not any([e_start, e_end, edge.get("first_seen"), edge.get("last_seen")]):
            factor *= 0.90
            notes.append(f"{edge['edge_id']}: edge time unknown")

        return ok, clamp(factor), notes

    def _adjust_edge(
        self,
        edge: ScamEdge,
        node_map: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        e = asdict(edge)
        e["edge_type"] = edge.edge_type.upper()
        e["state"] = edge.state.upper() if edge.state.upper() in SCAM_EDGE_STATES else "UNKNOWN"

        tags: list[str] = []
        conf = clamp(edge.confidence)
        etype = e["edge_type"]
        meta = e.get("metadata") or {}

        if etype in SCAM_WEAK_EDGE_TYPES:
            conf *= 0.35
            tags.append("WEAK_SHARED_SERVICE")

        if etype in {"HOSTED_ON", "RESOLVES_TO", "USES_IP_ADDRESS"}:
            if meta.get("shared_hosting") or meta.get("cdn") or meta.get("reverse_proxy"):
                conf *= 0.35
                tags.append("SHARED_INFRA_CONTEXT")

        if etype in SCAM_STRONG_EDGE_TYPES:
            conf = min(1.0, conf * 1.10)
            tags.append("POTENTIALLY_STRONG_LINK")

        temporal_ok, temporal_factor, temporal_notes = self._temporal_check(e, node_map)
        tags.extend(temporal_notes)

        if not temporal_ok:
            conf = 0.05
            e["state"] = "REJECTED"
            tags.append("TEMPORAL_IMPOSSIBLE")
        else:
            conf *= temporal_factor

        if e["state"] == "REJECTED":
            conf = min(conf, 0.10)
        elif e["state"] == "DISPUTED":
            conf *= 0.50

        if e["state"] not in {"REJECTED", "DISPUTED"}:
            if conf >= 0.80:
                e["state"] = "SUPPORTED"
            elif conf >= 0.60:
                e["state"] = "PROBABLE"
            elif conf >= 0.35:
                e["state"] = "POSSIBLE"
            elif conf > 0.05:
                e["state"] = "UNKNOWN"
            else:
                e["state"] = "REJECTED"

        # Historical if valid_to is clearly in past and confidence remains usable.
        vt = parse_dt(e.get("valid_to"))
        if vt and vt < datetime.now(timezone.utc) and conf >= 0.50 and e["state"] in {"SUPPORTED", "PROBABLE"}:
            e["state"] = "HISTORICAL"
            tags.append("HISTORICAL_CONTROL_OR_USAGE_ERAS")

        e["final_confidence"] = round(clamp(conf), 3)
        e["tags"] = sorted(set(tags))
        e["edge_kind"] = (
            "WEAK"
            if etype in SCAM_WEAK_EDGE_TYPES
            else "STRONG"
            if etype in SCAM_STRONG_EDGE_TYPES
            else "MEDIUM"
        )
        return e

    def _dedup_complaints(self, complaints: list[ScamComplaint]) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
        processed: list[dict[str, Any]] = []
        for c in complaints:
            domain = normalize_domain(c.domain)
            url = normalize_url(c.url)
            email = normalize_email(c.email)
            phone = normalize_phone(c.phone)
            payment = norm_text(c.payment_ref)
            wallet = str(c.wallet or "").strip()
            text = norm_text(c.text)

            key_parts = [x for x in (domain, url, email, phone, payment, wallet) if x]
            key = tuple(sorted(key_parts))

            processed.append(
                {
                    "complaint_id": c.complaint_id,
                    "reporter_pseudonym": c.reporter_pseudonym or "ANON",
                    "domain": domain,
                    "url": url,
                    "email_masked": mask_email(email) if email else "",
                    "phone_masked": mask_phone(phone) if phone else "",
                    "payment_ref_masked": mask_secret(payment, 4, 4) if payment else "",
                    "wallet_masked": mask_secret(wallet, 4, 4) if wallet else "",
                    "amount": c.amount,
                    "currency": c.currency,
                    "time": c.time,
                    "source_id": c.source_id,
                    "upstream_source": c.upstream_source,
                    "evidence_id": c.evidence_id,
                    "text_preview": text[:180],
                    "_key": key,
                    "_text": text,
                }
            )

        uf = UnionFind()
        for p in processed:
            uf.add(p["complaint_id"])

        # Exact key duplicates.
        by_key: dict[tuple[str, ...], list[str]] = defaultdict(list)
        for p in processed:
            if p["_key"]:
                by_key[p["_key"]].append(p["complaint_id"])
        for ids in by_key.values():
            for x in ids[1:]:
                uf.union(ids[0], x)

        # Near-duplicate text with overlapping strong identifiers.
        for i in range(len(processed)):
            for j in range(i + 1, len(processed)):
                a, b = processed[i], processed[j]
                shared = set(a["_key"]) & set(b["_key"])
                strong_shared = any(
                    x for x in shared if x and (x.startswith("pay") or "@" in x or x.isdigit() or "." in x)
                )
                if strong_shared and text_similarity(a["_text"], b["_text"]) >= 0.90:
                    uf.union(a["complaint_id"], b["complaint_id"])

        families: dict[str, list[str]] = defaultdict(list)
        for p in processed:
            families[uf.find(p["complaint_id"])].append(p["complaint_id"])

        for p in processed:
            p.pop("_key", None)
            p.pop("_text", None)

        return processed, dict(families)

    def analyze(self, req: ScamNetRequest) -> ScamNetResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self.blocked_result(req, code, reason)
            self.memory.append(asdict(result))
            return result

        node_map = {n.node_id: self._normalize_node(n) for n in req.nodes}
        processed_edges = [self._adjust_edge(e, node_map) for e in req.edges]

        # Validate edge endpoints.
        valid_edges: list[dict[str, Any]] = []
        unknowns: set[str] = set()
        gaps: set[str] = set()

        for e in processed_edges:
            if e["from_node"] not in node_map:
                unknowns.add(f"Edge {e['edge_id']} from_node unresolved: {e['from_node']}")
                gaps.add(f"Resolve node {e['from_node']}")
                continue
            if e["to_node"] not in node_map:
                unknowns.add(f"Edge {e['edge_id']} to_node unresolved: {e['to_node']}")
                gaps.add(f"Resolve node {e['to_node']}")
                continue
            valid_edges.append(e)

        # Clustering.
        uf = UnionFind()
        for nid in node_map:
            uf.add(nid)

        for e in valid_edges:
            if e["final_confidence"] >= 0.60 and e["state"] != "REJECTED":
                uf.union(e["from_node"], e["to_node"])

        cluster_edges: dict[str, list[dict[str, Any]]] = defaultdict(list)
        cluster_nodes: dict[str, set[str]] = defaultdict(set)

        for e in valid_edges:
            if e["final_confidence"] >= 0.60 and e["state"] != "REJECTED":
                root = uf.find(e["from_node"])
                cluster_edges[root].append(e)
                cluster_nodes[root].add(e["from_node"])
                cluster_nodes[root].add(e["to_node"])

        clusters: list[dict[str, Any]] = []
        personas: list[dict[str, Any]] = []

        for root, edges_in_cluster in cluster_edges.items():
            node_ids = sorted(cluster_nodes[root])
            edge_types = {e["edge_type"] for e in edges_in_cluster}
            strong = [e for e in edges_in_cluster if e["edge_kind"] == "STRONG" and e["final_confidence"] >= 0.70]
            medium = [e for e in edges_in_cluster if e["edge_kind"] == "MEDIUM" and e["final_confidence"] >= 0.60]
            weak_only = all(e["edge_kind"] == "WEAK" for e in edges_in_cluster)

            source_keys = {e.get("upstream_source") or e.get("source_id") or "UNKNOWN" for e in edges_in_cluster}
            independent_source_count = len({x for x in source_keys if x != "UNKNOWN"})

            if weak_only:
                state = "WEAK_CLUSTER"
            elif strong and independent_source_count >= 2:
                state = "SUPPORTED_NETWORK"
            elif strong:
                state = "PROBABLE_NETWORK"
            elif len(medium) >= 2 and independent_source_count >= 2:
                state = "PROBABLE_NETWORK"
            elif medium:
                state = "POSSIBLE_CLUSTER"
            else:
                state = "WEAK_CLUSTER"

            cluster_id = f"CLUSTER-{sha256_12(root)}"

            cluster_personas = []
            for nid in node_ids:
                nd = node_map[nid]
                if nd["node_type"] in {"PERSONA", "PERSON_CANDIDATE", "HANDLE", "EMAIL", "PHONE", "SOCIAL_ACCOUNT", "MARKETPLACE_ACCOUNT"}:
                    cluster_personas.append(
                        {
                            "cluster_id": cluster_id,
                            "node_id": nid,
                            "node_type": nd["node_type"],
                            "display_value": nd["value"],
                            "persona_not_real_person": True,
                            "note": "Persona/identifier cluster only. Do not infer real-person identity from this graph alone.",
                        }
                    )
            personas.extend(cluster_personas)

            clusters.append(
                {
                    "cluster_id": cluster_id,
                    "state": state,
                    "nodes": node_ids,
                    "edge_ids": [e["edge_id"] for e in edges_in_cluster],
                    "edge_types": sorted(edge_types),
                    "strong_edge_count": len(strong),
                    "medium_edge_count": len(medium),
                    "weak_only": weak_only,
                    "independent_source_count": independent_source_count,
                    "source_keys": sorted(source_keys),
                    "temporal_caution": any("TEMPORAL" in tag for e in edges_in_cluster for tag in e["tags"]),
                }
            )

        # Complaint dedup.
        complaint_rows, complaint_families = self._dedup_complaints(req.complaints)
        raw_complaint_count = len(req.complaints)
        unique_complaint_families = len(complaint_families)

        # Source independence summary.
        edge_source_groups: dict[str, list[str]] = defaultdict(list)
        for e in valid_edges:
            key = e.get("upstream_source") or e.get("source_id") or "UNKNOWN"
            edge_source_groups[key].append(e["edge_id"])

        complaint_source_groups: dict[str, list[str]] = defaultdict(list)
        for c in complaint_rows:
            key = c.get("upstream_source") or c.get("source_id") or "UNKNOWN"
            complaint_source_groups[key].append(c["complaint_id"])

        source_independence = {
            "edge_source_groups": {k: sorted(v) for k, v in edge_source_groups.items()},
            "complaint_source_groups": {k: sorted(v) for k, v in complaint_source_groups.items()},
            "independent_edge_source_count": len({k for k in edge_source_groups if k != "UNKNOWN"}),
            "independent_complaint_source_count": len({k for k in complaint_source_groups if k != "UNKNOWN"}),
            "warning": "Multiple URLs/complaints may derive from one upstream victim report or feed.",
        }

        # Contradictions.
        contradictions: list[dict[str, Any]] = []
        pair_states: dict[tuple[str, str], set[str]] = defaultdict(set)
        for e in valid_edges:
            pair = tuple(sorted([e["from_node"], e["to_node"]]))
            pair_states[pair].add(e["state"])

        for pair, states in pair_states.items():
            if "REJECTED" in states and ({"SUPPORTED", "OBSERVED", "PROBABLE"} & states):
                contradictions.append(
                    {
                        "type": "EDGE_STATE_CONTRADICTION",
                        "nodes": list(pair),
                        "states": sorted(states),
                        "possible_explanations": [
                            "different time eras",
                            "different entity resolution",
                            "one edge disputed/low quality",
                            "infrastructure reassignment",
                        ],
                    }
                )

        # Falsification prompts per cluster.
        falsification: list[dict[str, Any]] = []
        for cl in clusters:
            falsification.append(
                {
                    "cluster_id": cl["cluster_id"],
                    "questions": [
                        "Could shared hosting, CDN, reverse proxy, registrar, nameserver, or CMS explain the links?",
                        "Could the website template be commercially available and reused by unrelated operators?",
                        "Could email/phone/domain/IP/payment account have changed control during the time window?",
                        "Could complaints be duplicates, reposts, or derived from one upstream victim report?",
                        "Could a payment identifier belong to a processor, mule candidate, or compromised merchant?",
                        "Could a wallet/address be exchange-controlled rather than operator-controlled?",
                        "Could persona/handle reuse reflect platform naming coincidence rather than same operator?",
                    ],
                    "required_discriminating_evidence": [
                        "unique payment beneficiary with temporal control evidence",
                        "independent primary complaint/source not derived from same upstream",
                        "historical DNS/WHOIS/IP usage era",
                        "native website/archive evidence rather than screenshot",
                        "crypto wallet clustering from CRYPTOINT with exchange/mule context",
                    ],
                }
            )

        # Next actions / handoffs.
        next_actions: set[str] = {
            "Do not contact suspected scammers.",
            "Do not attack, seize, sinkhole, or alter scam infrastructure.",
            "Do not make test payments or use credentials.",
            "Do not infer real-person identity from network graph alone.",
            "Preserve temporal control/usage eras for domains, IPs, accounts, and payment identifiers.",
            "Deduplicate complaints before estimating victim/network size.",
        }

        handoffs: set[str] = set()

        for cl in clusters:
            if cl["state"] in {"WEAK_CLUSTER", "POSSIBLE_CLUSTER"}:
                next_actions.add(f"Seek independent strong identifier for {cl['cluster_id']} before upgrading cluster state.")
            if cl["temporal_caution"]:
                next_actions.add(f"Retrieve historical DNS/WHOIS/IP/account-era evidence for {cl['cluster_id']}.")

        for e in valid_edges:
            if e["edge_type"] in {"USES_PAYMENT_ACCOUNT", "REQUESTED_PAYMENT_TO", "TRANSFERRED_TO"}:
                handoffs.update({"FININT", "PAYMENTINT"})
                next_actions.add("Resolve payment account holder/processor/mule context via FININT/PAYMENTINT, not operator attribution.")
            if e["edge_type"] in {"USES_WALLET", "USES_CRYPTO_ADDRESS"}:
                handoffs.add("CRYPTOINT")
                next_actions.add("Hand off wallet/address clustering to CRYPTOINT with exchange/mule/temporal context.")
            if e["edge_type"] in {"USES_DOMAIN", "RESOLVES_TO", "HOSTED_ON", "USES_IP_ADDRESS"}:
                handoffs.update({"DOMAININT", "DNSINT", "IPINT", "INFRAINT"})
            if e["edge_type"] == "IMPERSONATES":
                handoffs.add("CORPINT")
                next_actions.add("Resolve impersonated legal entity via CORPINT; do not equate impersonation with operation.")
            if e["edge_type"] in {"USES_SOCIAL_ACCOUNT", "USES_MARKETPLACE_ACCOUNT", "USES_HANDLE"}:
                handoffs.add("SOCMINT")

        if complaint_rows:
            handoffs.add("FRAUDINT")
            next_actions.add("Hand off fraud truth/loss validation to FRAUDINT; SCAMNETINT only maps linkage.")

        privacy_flags = [
            "Email/phone/payment/wallet identifiers are masked in output.",
            "Persona nodes are not real-person identifications.",
            "No doxxing, home-address exposure, or private-person deanonymization is performed.",
            "Complaint reporter data is kept pseudonymous where supplied.",
        ]

        limitations = [
            "Rule-based local SCAMNETINT skeleton; not a live OSINT collector.",
            "Does not fetch domains, scan infrastructure, contact accounts, or access private data.",
            "Clusters are analytical candidates, not legal or factual proof of common operation.",
            "Shared IP/ASN/registrar/CDN/template are weak linkage signals.",
            "Real-person attribution requires substantially stronger evidence and authorized human/legal process.",
        ]

        if not req.nodes and not req.edges:
            status = Status.INCONCLUSIVE.value
            summary = "No scam-network nodes or edges supplied."
        elif clusters and any(c["state"] in {"SUPPORTED_NETWORK", "PROBABLE_NETWORK"} for c in clusters):
            status = Status.PARTIAL.value
            summary = (
                f"Defensive scam-network correlation produced {len(clusters)} candidate cluster(s). "
                "No infrastructure attack, scammer contact, doxxing, or real-person attribution performed."
            )
        else:
            status = Status.PARTIAL.value if req.edges else Status.INCONCLUSIVE.value
            summary = (
                f"Defensive scam-network correlation assessed {len(valid_edges)} edge(s) and "
                f"{len(clusters)} weak/possible cluster(s). Linkage remains conservative."
            )

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "case_id": req.case_id,
            "created_at": now_iso(),
            "node_ids": sorted(node_map),
            "edge_ids": [e["edge_id"] for e in valid_edges],
            "cluster_ids": [c["cluster_id"] for c in clusters],
            "complaint_families": complaint_families,
            "source_independence": source_independence,
        }

        result = ScamNetResult(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            summary=summary,
            nodes=[node_map[nid] for nid in sorted(node_map)],
            edges=valid_edges,
            clusters=clusters,
            personas=personas,
            complaints=complaint_rows,
            raw_complaint_count=raw_complaint_count,
            unique_complaint_families=unique_complaint_families,
            source_independence=source_independence,
            contradictions=contradictions,
            falsification=falsification,
            unknowns=sorted(unknowns),
            knowledge_gaps=sorted(gaps),
            recommended_next_actions=sorted(next_actions),
            specialist_handoffs=sorted(handoffs),
            privacy_flags=privacy_flags,
            limitations=limitations,
            replay_manifest=replay_manifest,
            created_at=now_iso(),
        )

        self.memory.append(asdict(result))
        return result


# ======================================================================
# HYPOTHESISINT
# ======================================================================

HYP_REL_WEIGHTS = {
    "STRONGLY_SUPPORTS": 1.00,
    "SUPPORTS": 0.60,
    "SLIGHTLY_SUPPORTS": 0.25,
    "NEUTRAL": 0.00,
    "SLIGHTLY_CONTRADICTS": -0.25,
    "CONTRADICTS": -0.70,
    "STRONGLY_CONTRADICTS": -1.20,
    "NOT_APPLICABLE": 0.00,
    "UNKNOWN": 0.00,
}

HYP_IMPORTANCE_WEIGHTS = {
    "LOW": 0.5,
    "MEDIUM": 1.0,
    "HIGH": 1.5,
    "CRITICAL": 2.0,
}

HYP_BLOCK_PHRASES = [
    "fabricate certainty",
    "ignore evidence",
    "only confirm",
    "assume true",
    "skip falsification",
    "do not test alternatives",
    "attribute without evidence",
    "hide contradictions",
    "delete falsified",
    "force winner",
]


@dataclass
class EvidenceItem:
    evidence_id: str
    statement: str
    source_id: str = ""
    upstream_source: str = ""
    reliability: float = 0.5
    independence_group: str = ""
    time: str = ""
    entity_ids: list[str] = field(default_factory=list)
    claim_ids: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    diagnosticity: float = 0.5


@dataclass
class Hypothesis:
    hypothesis_id: str
    statement: str
    hypothesis_type: str = "DESCRIPTIVE"
    status: str = "PROPOSED"
    created_by: str = "USER"
    assumption_statements: list[str] = field(default_factory=list)
    prediction_ids: list[str] = field(default_factory=list)
    falsifier_ids: list[str] = field(default_factory=list)
    alternative_ids: list[str] = field(default_factory=list)
    mutually_exclusive_with: list[str] = field(default_factory=list)
    compatible_with: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class Assumption:
    assumption_id: str
    statement: str
    hypothesis_ids: list[str] = field(default_factory=list)
    criticality: str = "IMPORTANT"
    evidence_status: str = "UNKNOWN"
    confidence: float = 0.5
    falsification_condition: str = ""


@dataclass
class Prediction:
    prediction_id: str
    hypothesis_id: str
    expected_observation: str
    time_window: str = ""
    source_type: str = ""
    importance: str = "MEDIUM"
    observed_state: str = "NOT_TESTED"
    result: str = ""


@dataclass
class Falsifier:
    falsifier_id: str
    hypothesis_id: str
    condition: str
    observed_state: str = "NOT_TESTED"


@dataclass
class EvidenceHypothesisLink:
    evidence_id: str
    hypothesis_id: str
    relation: str = "UNKNOWN"
    locator: str = ""
    notes: str = ""


@dataclass
class HypothesisRequest:
    case_id: str
    objective: str
    question: str
    authorization: dict[str, Any] = field(default_factory=dict)
    facts: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    claims: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    links: list[EvidenceHypothesisLink] = field(default_factory=list)
    assumptions: list[Assumption] = field(default_factory=list)
    predictions: list[Prediction] = field(default_factory=list)
    falsifiers: list[Falsifier] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)


@dataclass
class HypothesisResult:
    case_id: str
    status: str
    policy_decision: str
    question: str
    summary: str
    hypotheses: list[dict[str, Any]]
    evidence_matrix: list[dict[str, Any]]
    ach_matrix: list[dict[str, Any]]
    diagnostic_evidence: list[dict[str, Any]]
    contradictions: list[dict[str, Any]]
    assumptions: list[dict[str, Any]]
    predictions: list[dict[str, Any]]
    falsifiers: list[dict[str, Any]]
    ranking: list[dict[str, Any]]
    confidence: dict[str, str]
    verification_state: dict[str, str]
    unknowns: list[str]
    knowledge_gaps: list[str]
    next_best_evidence: list[str]
    recommended_next_actions: list[str]
    what_would_change_assessment: list[str]
    human_review_flags: list[str]
    limitations: list[str]
    replay_manifest: dict[str, Any]
    created_at: str


class HypothesisIntAgent:
    """
    Defensive HYPOTHESISINT core.

    Generates/tests competing hypotheses from supplied evidence.
    Does not fabricate evidence, hide contradictions, or assign fake probabilities.
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    def policy_check(self, req: HypothesisRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                req.question,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        if req.authorization.get("authorized") is False:
            return PolicyDecision.BLOCK, "BLOCKED_AUTHORIZATION", "Authorization denied."

        for phrase in HYP_BLOCK_PHRASES:
            if phrase in blob:
                return PolicyDecision.BLOCK, "BLOCKED_POLICY", f"Prohibited reasoning action requested: {phrase}"

        return PolicyDecision.ALLOW, "", ""

    def blocked_result(self, req: HypothesisRequest, code: str, reason: str) -> HypothesisResult:
        return HypothesisResult(
            case_id=req.case_id,
            status=code,
            policy_decision=PolicyDecision.BLOCK.value,
            question=req.question,
            summary=f"POLICY_BLOCKED: {reason}",
            hypotheses=[],
            evidence_matrix=[],
            ach_matrix=[],
            diagnostic_evidence=[],
            contradictions=[],
            assumptions=[],
            predictions=[],
            falsifiers=[],
            ranking=[],
            confidence={},
            verification_state={},
            unknowns=["Request outside defensive HYPOTHESISINT boundary."],
            knowledge_gaps=["No hypothesis testing performed."],
            next_best_evidence=["Reframe as evidence-first competing-hypothesis analysis."],
            recommended_next_actions=[],
            what_would_change_assessment=[],
            human_review_flags=[],
            limitations=[reason],
            replay_manifest={},
            created_at=now_iso(),
        )

    def _default_hypotheses(self, req: HypothesisRequest) -> list[Hypothesis]:
        q = (req.question + " " + req.objective).lower()
        hyps: list[Hypothesis] = []

        if any(k in q for k in ["scam", "fraud", "malware", "attack", "campaign", "actor", "compromise", "phishing", "network"]):
            hyps.append(
                Hypothesis(
                    hypothesis_id="H-CAMPAIGN",
                    statement="Observed indicators reflect a coordinated campaign or common operator/control path.",
                    hypothesis_type="CAMPAIGN",
                    created_by="HYPOTHESISINT_DEFAULT",
                    assumption_statements=["Shared identifiers are not merely common-provider artifacts."],
                )
            )

        hyps.append(
            Hypothesis(
                hypothesis_id="H-SHARED-PROVIDER",
                statement="Observed similarities reflect shared commercial provider, template, CDN, registrar, hosting, or platform artifact.",
                hypothesis_type="ORIGIN",
                created_by="HYPOTHESISINT_DEFAULT",
                assumption_statements=["Shared infrastructure/content can occur without common operation."],
            )
        )

        hyps.append(
            Hypothesis(
                hypothesis_id="H-DATA-ERROR",
                statement="Observed linkage is caused by data error, duplicate reporting, stale records, or entity-resolution mistake.",
                hypothesis_type="MECHANISM",
                created_by="HYPOTHESISINT_DEFAULT",
                assumption_statements=["Source records may be duplicated, delayed, or incorrectly normalized."],
            )
        )

        if any(k in q for k in ["account", "domain", "email", "phone", "wallet", "payment", "ip", "handle"]):
            hyps.append(
                Hypothesis(
                    hypothesis_id="H-REUSE-COMPROMISE",
                    statement="Identifier was reused, recycled, reassigned, compromised, or operated by a different party during part of the time window.",
                    hypothesis_type="IDENTITY",
                    created_by="HYPOTHESISINT_DEFAULT",
                    assumption_statements=["Entity control/usage eras must be time-bound."],
                )
            )

        hyps.append(
            Hypothesis(
                hypothesis_id="H-UNKNOWN",
                statement="Evidence is insufficient to distinguish among explanations.",
                hypothesis_type="OTHER",
                created_by="HYPOTHESISINT_DEFAULT",
            )
        )

        return hyps

    def _ensure_hypotheses(self, req: HypothesisRequest) -> list[Hypothesis]:
        hyps = list(req.hypotheses)
        if not hyps:
            return self._default_hypotheses(req)

        existing_text = " ".join(h.statement.lower() for h in hyps)
        defaults = self._default_hypotheses(req)

        # Ensure at least benign/null alternatives are visible unless user explicitly supplied them.
        for d in defaults:
            if d.hypothesis_id in {h.hypothesis_id for h in hyps}:
                continue
            if "shared" in d.statement.lower() and "shared" not in existing_text:
                hyps.append(d)
            elif "error" in d.statement.lower() and "error" not in existing_text:
                hyps.append(d)
            elif "unknown" in d.statement.lower() and "insufficient" not in existing_text:
                hyps.append(d)

        return hyps

    def analyze(self, req: HypothesisRequest) -> HypothesisResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self.blocked_result(req, code, reason)
            self.memory.append(asdict(result))
            return result

        hypotheses = self._ensure_hypotheses(req)
        hyp_map = {h.hypothesis_id: h for h in hypotheses}
        evidence_map = {e.evidence_id: e for e in req.evidence}

        scores: dict[str, float] = defaultdict(float)
        contradictions: dict[str, int] = defaultdict(int)
        used_groups: dict[str, set[str]] = defaultdict(set)
        linked_evidence: dict[str, set[str]] = defaultdict(set)
        matrix: dict[str, dict[str, str]] = defaultdict(dict)
        unknowns: set[str] = set()
        gaps: set[str] = set()

        # Evidence links.
        for link in req.links:
            if link.evidence_id not in evidence_map:
                unknowns.add(f"Link references missing evidence {link.evidence_id}.")
                gaps.add(f"Preserve or replace evidence {link.evidence_id}.")
                continue
            if link.hypothesis_id not in hyp_map:
                unknowns.add(f"Link references missing hypothesis {link.hypothesis_id}.")
                continue

            ev = evidence_map[link.evidence_id]
            rel = (link.relation or "UNKNOWN").upper()
            w = HYP_REL_WEIGHTS.get(rel, 0.0)

            indep_key = ev.independence_group or ev.upstream_source or ev.source_id or ev.evidence_id
            indep_factor = 0.25 if indep_key in used_groups[link.hypothesis_id] else 1.0
            used_groups[link.hypothesis_id].add(indep_key)

            quality = clamp(ev.reliability) * clamp(ev.diagnosticity if ev.diagnosticity > 0 else 0.5)
            contrib = w * quality * indep_factor

            scores[link.hypothesis_id] += contrib
            linked_evidence[link.hypothesis_id].add(link.evidence_id)
            matrix[link.hypothesis_id][link.evidence_id] = rel

            if w < 0:
                contradictions[link.hypothesis_id] += 1

        # Assumptions.
        assumption_rows = [asdict(a) for a in req.assumptions]
        for a in req.assumptions:
            for hid in a.hypothesis_ids:
                if hid not in hyp_map:
                    continue
                penalty = 0.0
                if a.criticality.upper() == "FOUNDATIONAL" and a.evidence_status.upper() in {"UNKNOWN", "UNSUPPORTED"}:
                    penalty = 0.15
                elif a.criticality.upper() == "IMPORTANT" and a.evidence_status.upper() in {"UNKNOWN", "UNSUPPORTED"}:
                    penalty = 0.07
                scores[hid] -= penalty

        for h in hypotheses:
            # Lightweight penalty for stated assumptions.
            scores[h.hypothesis_id] -= min(0.15, 0.03 * len(h.assumption_statements))

        # Predictions.
        prediction_rows = [asdict(p) for p in req.predictions]
        for p in req.predictions:
            if p.hypothesis_id not in hyp_map:
                continue
            imp = HYP_IMPORTANCE_WEIGHTS.get(p.importance.upper(), 1.0)
            state = p.observed_state.upper()
            if state == "OBSERVED":
                scores[p.hypothesis_id] += 0.10 * imp
            elif state == "NOT_OBSERVED_WITH_GOOD_COVERAGE":
                scores[p.hypothesis_id] -= 0.20 * imp
                contradictions[p.hypothesis_id] += 1
            elif state == "NOT_OBSERVED_WITH_POOR_COVERAGE":
                scores[p.hypothesis_id] -= 0.05 * imp

        # Falsifiers.
        falsifier_rows = [asdict(f) for f in req.falsifiers]
        for f in req.falsifiers:
            if f.hypothesis_id not in hyp_map:
                continue
            if f.observed_state.upper() == "OBSERVED":
                scores[f.hypothesis_id] -= 0.50
                contradictions[f.hypothesis_id] += 1

        # Build evidence/ACH matrices.
        evidence_matrix: list[dict[str, Any]] = []
        ach_matrix: list[dict[str, Any]] = []
        diagnostic_evidence: list[dict[str, Any]] = []

        for eid, ev in evidence_map.items():
            row = {"evidence_id": eid, "statement": ev.statement, "hypotheses": {}}
            weights: list[float] = []
            for hid in hyp_map:
                rel = matrix.get(hid, {}).get(eid, "NOT_APPLICABLE")
                w = HYP_REL_WEIGHTS.get(rel, 0.0)
                quality = clamp(ev.reliability) * clamp(ev.diagnosticity if ev.diagnosticity > 0 else 0.5)
                weighted = w * quality
                row["hypotheses"][hid] = {"relation": rel, "weighted_score": round(weighted, 3)}
                weights.append(weighted)

            evidence_matrix.append(row)
            ach_matrix.append(
                {
                    "evidence_id": eid,
                    "cells": {hid: row["hypotheses"][hid]["relation"] for hid in hyp_map},
                }
            )

            if weights:
                rng = max(weights) - min(weights)
                if rng >= 0.35 and max(abs(x) for x in weights) >= 0.15:
                    diagnostic_evidence.append(
                        {
                            "evidence_id": eid,
                            "range": round(rng, 3),
                            "max_abs_weight": round(max(abs(x) for x in weights), 3),
                            "note": "Evidence discriminates among hypotheses better than generic consistency.",
                        }
                    )

        # Ranking / states.
        ranking: list[dict[str, Any]] = []
        confidence: dict[str, str] = {}
        verification_state: dict[str, str] = {}

        for h in hypotheses:
            hid = h.hypothesis_id
            score = round(scores.get(hid, 0.0), 3)
            contra = contradictions.get(hid, 0)
            indep_count = len(used_groups.get(hid, set()))
            ev_count = len(linked_evidence.get(hid, set()))

            avg_rel = mean([evidence_map[eid].reliability for eid in linked_evidence.get(hid, set())], 0.0)
            coverage = min(1.0, ev_count / 3.0)
            indep = min(1.0, indep_count / 2.0)
            conf_raw = clamp(0.20 + 0.35 * avg_rel + 0.20 * coverage + 0.25 * indep - min(0.40, contra * 0.15))

            if conf_raw >= 0.80:
                conf_label = "HIGH"
            elif conf_raw >= 0.60:
                conf_label = "MODERATE"
            elif conf_raw >= 0.40:
                conf_label = "LOW"
            else:
                conf_label = "VERY_LOW"

            if score >= 0.80 and contra == 0 and indep_count >= 2:
                state = "STRONGLY_SUPPORTED"
                h.status = "STRONGLY_SUPPORTED"
            elif score >= 0.45 and contra == 0:
                state = "SUPPORTED"
                h.status = "SUPPORTED"
            elif score > 0.10 and contra <= 1:
                state = "PARTIALLY_SUPPORTED"
                h.status = "ACTIVE"
            elif score < -0.20 or contra >= 2:
                state = "WEAKENED"
                h.status = "WEAKENED"
            else:
                state = "INCONCLUSIVE"
                h.status = "INCONCLUSIVE"

            confidence[hid] = conf_label
            verification_state[hid] = state

            ranking.append(
                {
                    "hypothesis_id": hid,
                    "statement": h.statement,
                    "score": score,
                    "contradiction_count": contra,
                    "independent_evidence_groups": indep_count,
                    "linked_evidence_count": ev_count,
                    "verification_state": state,
                    "confidence": conf_label,
                }
            )

        ranking.sort(key=lambda x: (x["score"], -x["contradiction_count"], x["independent_evidence_groups"]), reverse=True)

        # Contradiction register.
        contradiction_rows: list[dict[str, Any]] = []
        for link in req.links:
            rel = (link.relation or "").upper()
            if rel in {"CONTRADICTS", "STRONGLY_CONTRADICTS", "SLIGHTLY_CONTRADICTS"}:
                contradiction_rows.append(
                    {
                        "evidence_id": link.evidence_id,
                        "hypothesis_id": link.hypothesis_id,
                        "relation": rel,
                        "locator": link.locator,
                        "notes": link.notes,
                        "materiality": "HIGH" if rel == "STRONGLY_CONTRADICTS" else "MEDIUM" if rel == "CONTRADICTS" else "LOW",
                    }
                )

        # Next best evidence.
        next_best: set[str] = set()
        what_would_change: set[str] = set()

        top_ids = [r["hypothesis_id"] for r in ranking[:2] if r["score"] > 0]
        for hid in top_ids:
            h = hyp_map[hid]
            for p in req.predictions:
                if p.hypothesis_id == hid and p.observed_state.upper() == "NOT_TESTED":
                    next_best.add(f"Test prediction {p.prediction_id} for {hid}: {p.expected_observation}")
                    what_would_change.add(f"Observation of {p.expected_observation} would strengthen {hid}.")
            for f in req.falsifiers:
                if f.hypothesis_id == hid and f.observed_state.upper() == "NOT_TESTED":
                    next_best.add(f"Search for falsifier {f.falsifier_id} for {hid}: {f.condition}")
                    what_would_change.add(f"Evidence of {f.condition} would weaken or falsify {hid}.")

        for r in ranking:
            if r["independent_evidence_groups"] < 2 and r["score"] > 0:
                next_best.add(f"Obtain an independent evidence family for {r['hypothesis_id']}.")
            if r["contradiction_count"] > 0:
                next_best.add(f"Adjudicate contradictions affecting {r['hypothesis_id']} using primary records.")

        if not req.evidence:
            next_best.add("Supply at least one preserved evidence item; hypothesis ranking without evidence is inconclusive.")
        if not req.links:
            next_best.add("Map existing evidence to hypotheses explicitly; do not infer support silently.")

        human_review_flags: list[str] = []
        blob = (req.question + " " + req.objective).lower()
        if any(k in blob for k in ["real person", "individual", "employee", "director", "suspect", "accuse"]):
            human_review_flags.append("Real-person attribution requires authorized human/legal review.")
        if any(k in blob for k in ["legal", "law enforcement", "court", "arrest", "employment"]):
            human_review_flags.append("Consequential action requires human review.")

        recommended_actions = sorted(
            {
                "Preserve falsified/weakened hypotheses in history; do not delete them.",
                "Count independent evidence families, not repeated sources.",
                "Prefer diagnostic evidence over merely consistent evidence.",
                "Return INCONCLUSIVE when evidence cannot discriminate.",
                "Do not treat AI agreement as corroboration.",
            }
        ) | next_best

        limitations = [
            "Rule-based HYPOTHESISINT skeleton; scores are relative analytical rankings, not calibrated probabilities.",
            "Does not collect evidence by itself; consumes supplied evidence/links only.",
            "Does not hide contradictions or delete falsified hypotheses.",
            "Does not recommend unauthorized action merely because it is informative.",
        ]

        if not hypotheses or not req.evidence:
            status = Status.INCONCLUSIVE.value
        elif ranking and ranking[0]["verification_state"] in {"STRONGLY_SUPPORTED", "SUPPORTED"}:
            status = Status.PARTIAL.value
        else:
            status = Status.PARTIAL.value

        summary = (
            f"Competing-hypothesis analysis for question: {req.question}. "
            f"Hypotheses: {len(hypotheses)}. Evidence items: {len(req.evidence)}. "
            "Leading assessment remains evidentiary and revisable."
        )

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "case_id": req.case_id,
            "created_at": now_iso(),
            "question": req.question,
            "hypothesis_ids": [h.hypothesis_id for h in hypotheses],
            "evidence_ids": sorted(evidence_map),
            "link_count": len(req.links),
            "ranking": ranking,
        }

        result = HypothesisResult(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            question=req.question,
            summary=summary,
            hypotheses=[asdict(h) for h in hypotheses],
            evidence_matrix=evidence_matrix,
            ach_matrix=ach_matrix,
            diagnostic_evidence=diagnostic_evidence,
            contradictions=contradiction_rows,
            assumptions=assumption_rows,
            predictions=prediction_rows,
            falsifiers=falsifier_rows,
            ranking=ranking,
            confidence=confidence,
            verification_state=verification_state,
            unknowns=sorted(unknowns),
            knowledge_gaps=sorted(gaps),
            next_best_evidence=sorted(next_best),
            recommended_next_actions=sorted(recommended_actions),
            what_would_change_assessment=sorted(what_would_change),
            human_review_flags=human_review_flags,
            limitations=limitations,
            replay_manifest=replay_manifest,
            created_at=now_iso(),
        )

        self.memory.append(asdict(result))
        return result


# ======================================================================
# ACADEMICINT
# ======================================================================

ACADEMIC_BLOCK_PHRASES = [
    "fabricate paper",
    "fake paper",
    "fabricate doi",
    "fake doi",
    "fabricate citation",
    "fake citation",
    "fabricate author",
    "fake author",
    "generate fake research",
    "fake peer review",
    "submit manuscript",
    "impersonate researcher",
    "harass researcher",
    "dox researcher",
    "plagiarize",
    "manipulate citation",
    "citation cartel",
    "manufacture fake dataset",
    "alter research record",
    "hide retraction",
]

PEER_REVIEWED_STATES = {
    "PEER_REVIEWED_ARTICLE",
    "REVIEW_ARTICLE",
    "SYSTEMATIC_REVIEW",
    "META_ANALYSIS",
    "CONFERENCE_PAPER",
    "BOOK_CHAPTER",
}

HIGH_WEIGHT_STATES = {"SYSTEMATIC_REVIEW", "META_ANALYSIS"}


@dataclass
class AuthorAffiliation:
    institution_id: str
    department: str = ""
    lab: str = ""
    valid_from: str = ""
    valid_to: str = ""
    publication_context: str = ""


@dataclass
class Author:
    author_id: str
    name: str
    orcid: str = ""
    name_variants: list[str] = field(default_factory=list)
    affiliations: list[AuthorAffiliation] = field(default_factory=list)
    topics: list[str] = field(default_factory=list)
    confidence: float = 0.5


@dataclass
class Institution:
    institution_id: str
    name: str
    institution_type: str = "UNIVERSITY"
    departments: list[str] = field(default_factory=list)
    labs: list[str] = field(default_factory=list)


@dataclass
class PaperClaim:
    claim_id: str
    statement: str
    claim_type: str = "PRIMARY"
    support_state: str = "REPORTED"  # REPORTED / SUPPORTED_BY_METHOD / CONTESTED / RETRACTED


@dataclass
class Paper:
    paper_id: str
    doi: str = ""
    title: str = ""
    authors: list[str] = field(default_factory=list)
    institutions: list[str] = field(default_factory=list)
    venue: str = ""
    year: int = 0
    publication_state: str = "UNKNOWN"
    preprint_id: str = ""
    version_of: str = ""
    supersedes: list[str] = field(default_factory=list)
    corrected_by: list[str] = field(default_factory=list)
    retracted_by: list[str] = field(default_factory=list)
    expression_of_concern: bool = False
    claims: list[PaperClaim] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    datasets: list[str] = field(default_factory=list)
    benchmarks: list[str] = field(default_factory=list)
    results: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    funding: list[str] = field(default_factory=list)
    coi: list[str] = field(default_factory=list)
    repository: str = ""
    code_available: bool = False
    data_available: bool = False
    replication_status: str = "UNKNOWN"
    keywords: list[str] = field(default_factory=list)
    source_id: str = ""
    upstream_source: str = ""
    source_reliability: float = 0.75


@dataclass
class Citation:
    citing_paper_id: str
    cited_paper_id: str
    context: str = ""
    relationship: str = "UNKNOWN"
    source_id: str = ""


@dataclass
class Dataset:
    dataset_id: str
    name: str
    creator: str = ""
    version: str = ""
    license: str = ""
    sample_size: int = 0
    coverage: str = ""
    limitations: list[str] = field(default_factory=list)


@dataclass
class Grant:
    grant_id: str
    funder: str
    recipient: str
    project: str = ""
    amount_if_public: str = ""
    period: str = ""


@dataclass
class Patent:
    patent_id: str
    title: str
    inventors: list[str] = field(default_factory=list)
    assignee: str = ""
    related_paper_ids: list[str] = field(default_factory=list)


@dataclass
class AcademicRequest:
    case_id: str
    objective: str
    research_question: str
    authorization: dict[str, Any] = field(default_factory=dict)
    papers: list[Paper] = field(default_factory=list)
    authors: list[Author] = field(default_factory=list)
    institutions: list[Institution] = field(default_factory=list)
    citations: list[Citation] = field(default_factory=list)
    datasets: list[Dataset] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    patents: list[Patent] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)


@dataclass
class AcademicResult:
    case_id: str
    status: str
    policy_decision: str
    research_question: str
    summary: str
    papers: list[dict[str, Any]]
    authors: list[dict[str, Any]]
    institutions: list[dict[str, Any]]
    citation_graph: list[dict[str, Any]]
    version_groups: dict[str, list[str]]
    retractions: list[dict[str, Any]]
    corrections: list[dict[str, Any]]
    claim_assessments: list[dict[str, Any]]
    replication_status: dict[str, str]
    source_independence: dict[str, Any]
    research_gaps: list[dict[str, Any]]
    trends: dict[str, Any]
    consensus_state: str
    contradictions: list[dict[str, Any]]
    unknowns: list[str]
    knowledge_gaps: list[str]
    recommended_next_actions: list[str]
    specialist_handoffs: list[str]
    limitations: list[str]
    replay_manifest: dict[str, Any]
    created_at: str


class AcademicIntAgent:
    """
    Defensive ACADEMICINT core.

    Analyzes only supplied papers/authors/citations.
    Does not fabricate bibliographic records or citations.
    """

    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    def policy_check(self, req: AcademicRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                req.research_question,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        if req.authorization.get("authorized") is False:
            return PolicyDecision.BLOCK, "BLOCKED_AUTHORIZATION", "Authorization denied."

        for phrase in ACADEMIC_BLOCK_PHRASES:
            if phrase in blob:
                return PolicyDecision.BLOCK, "BLOCKED_POLICY", f"Prohibited academic-intelligence action requested: {phrase}"

        return PolicyDecision.ALLOW, "", ""

    def blocked_result(self, req: AcademicRequest, code: str, reason: str) -> AcademicResult:
        return AcademicResult(
            case_id=req.case_id,
            status=code,
            policy_decision=PolicyDecision.BLOCK.value,
            research_question=req.research_question,
            summary=f"POLICY_BLOCKED: {reason}",
            papers=[],
            authors=[],
            institutions=[],
            citation_graph=[],
            version_groups={},
            retractions=[],
            corrections=[],
            claim_assessments=[],
            replication_status={},
            source_independence={},
            research_gaps=[],
            trends={},
            consensus_state="INSUFFICIENT_EVIDENCE",
            contradictions=[],
            unknowns=["Request outside defensive ACADEMICINT boundary."],
            knowledge_gaps=["No literature analysis performed."],
            recommended_next_actions=["Reframe as authorized, citation-aware research synthesis."],
            specialist_handoffs=[],
            limitations=[reason],
            replay_manifest={},
            created_at=now_iso(),
        )

    def _paper_status(self, p: Paper) -> str:
        if p.retracted_by:
            return "RETRACTED"
        if p.expression_of_concern:
            return "EXPRESSION_OF_CONCERN"
        if p.corrected_by:
            return "CORRECTED"
        return p.publication_state.upper()

    def _is_peer_reviewed(self, p: Paper, version_roots: dict[str, list[str]], paper_map: dict[str, Paper]) -> bool:
        state = p.publication_state.upper()
        if state in PEER_REVIEWED_STATES:
            return True

        # If a peer-reviewed version exists in same version group, mark work as having peer-reviewed version,
        # but this specific artifact may still be preprint.
        root = version_roots.get(p.paper_id, [p.paper_id])
        for pid in root:
            other = paper_map.get(pid)
            if other and other.publication_state.upper() in PEER_REVIEWED_STATES:
                return True
        return False

    def _paper_weight(self, p: Paper, peer_reviewed: bool) -> float:
        status = self._paper_status(p)
        if status == "RETRACTED":
            return 0.0
        if status == "EXPRESSION_OF_CONCERN":
            return 0.25
        if p.publication_state.upper() in HIGH_WEIGHT_STATES:
            return 1.30
        if peer_reviewed:
            return 1.00
        if p.publication_state.upper() == "PREPRINT":
            return 0.45
        return 0.60

    def _author_overlap(self, a: Paper, b: Paper, author_map: dict[str, Author]) -> bool:
        set_a = set(a.authors)
        set_b = set(b.authors)
        if set_a & set_b:
            return True

        # ORCID-level overlap.
        orcids_a = set()
        orcids_b = set()
        for aid in set_a:
            auth = author_map.get(aid)
            if auth and auth.orcid:
                orcids_a.add(auth.orcid.lower())
        for aid in set_b:
            auth = author_map.get(aid)
            if auth and auth.orcid:
                orcids_b.add(auth.orcid.lower())
        return bool(orcids_a & orcids_b)

    def analyze(self, req: AcademicRequest) -> AcademicResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self.blocked_result(req, code, reason)
            self.memory.append(asdict(result))
            return result

        paper_map = {p.paper_id: p for p in req.papers}
        author_map = {a.author_id: a for a in req.authors}
        institution_map = {i.institution_id: i for i in req.institutions}

        unknowns: set[str] = set()
        gaps: set[str] = set()

        # Version groups by explicit version_of/supersedes/DOI.
        uf = UnionFind()
        for pid in paper_map:
            uf.add(pid)

        doi_groups: dict[str, list[str]] = defaultdict(list)
        for p in req.papers:
            if p.doi:
                doi_groups[p.doi.lower()].append(p.paper_id)
        for ids in doi_groups.values():
            for x in ids[1:]:
                uf.union(ids[0], x)

        for p in req.papers:
            if p.version_of and p.version_of in paper_map:
                uf.union(p.paper_id, p.version_of)
            for s in p.supersedes:
                if s in paper_map:
                    uf.union(p.paper_id, s)

        version_roots: dict[str, list[str]] = defaultdict(list)
        for pid in paper_map:
            version_roots[uf.find(pid)].append(pid)
        version_groups = {k: sorted(v) for k, v in version_roots.items()}

        # Author name collision flags.
        name_to_authors: dict[str, list[str]] = defaultdict(list)
        for a in req.authors:
            name_to_authors[norm_text(a.name)].append(a.author_id)
        author_collision_flags = [
            {"normalized_name": name, "author_ids": sorted(ids)}
            for name, ids in name_to_authors.items()
            if len(ids) > 1
        ]

        # Citation graph validation.
        citation_rows: list[dict[str, Any]] = []
        for c in req.citations:
            if c.citing_paper_id not in paper_map:
                unknowns.add(f"Citation citing paper unresolved: {c.citing_paper_id}")
                continue
            if c.cited_paper_id not in paper_map:
                unknowns.add(f"Citation cited paper unresolved: {c.cited_paper_id}")
                continue
            citation_rows.append(asdict(c))

        # Retractions/corrections.
        retractions: list[dict[str, Any]] = []
        corrections: list[dict[str, Any]] = []
        for p in req.papers:
            status = self._paper_status(p)
            if status == "RETRACTED":
                retractions.append(
                    {
                        "paper_id": p.paper_id,
                        "title": p.title,
                        "retracted_by": p.retracted_by,
                        "note": "Retraction materially changes evidentiary weight; preserve original claim history.",
                    }
                )
                gaps.add(f"Propagate retraction impact for {p.paper_id} to dependent conclusions.")
            if p.corrected_by:
                corrections.append(
                    {
                        "paper_id": p.paper_id,
                        "title": p.title,
                        "corrected_by": p.corrected_by,
                        "note": "Use corrected version for current claims; preserve original version.",
                    }
                )

        # Claim assessments.
        claim_groups: dict[str, list[tuple[Paper, PaperClaim]]] = defaultdict(list)
        for p in req.papers:
            for c in p.claims:
                key = c.claim_id or norm_text(c.statement)
                claim_groups[key].append((p, c))

        claim_assessments: list[dict[str, Any]] = []
        global_contradictions: list[dict[str, Any]] = []

        for key, items in claim_groups.items():
            papers_in_group = [p for p, _ in items]
            selected: list[Paper] = []
            selected_roots: set[str] = set()
            selected_sources: set[str] = set()

            # Sort by weight desc.
            weighted = []
            for p in papers_in_group:
                peer = self._is_peer_reviewed(p, {pid: version_roots[uf.find(pid)] for pid in paper_map}, paper_map)
                weighted.append((self._paper_weight(p, peer), p, peer))
            weighted.sort(key=lambda x: x[0], reverse=True)

            for weight, p, peer in weighted:
                root = uf.find(p.paper_id)
                source_key = p.upstream_source or p.source_id or p.paper_id
                if root in selected_roots:
                    continue
                if source_key in selected_sources:
                    continue
                if any(self._author_overlap(p, s, author_map) for s in selected):
                    continue
                selected.append(p)
                selected_roots.add(root)
                selected_sources.add(source_key)

            independent_count = len(selected)
            peer_reviewed_independent = sum(
                1
                for p in selected
                if self._is_peer_reviewed(p, {pid: version_roots[uf.find(pid)] for pid in paper_map}, paper_map)
            )
            systematic_independent = sum(1 for p in selected if p.publication_state.upper() in HIGH_WEIGHT_STATES)

            contested = sum(1 for _, c in items if c.support_state.upper() == "CONTESTED")
            retracted = sum(1 for p, _ in items if self._paper_status(p) == "RETRACTED")
            failed_replication = sum(1 for p, _ in items if p.replication_status.upper() == "FAILED_REPRODUCTION")
            success_replication = sum(
                1
                for p, _ in items
                if p.replication_status.upper() in {"REPRODUCED_INDEPENDENTLY", "PARTIALLY_REPRODUCED"}
            )

            if retracted and independent_count == 0:
                consensus = "INSUFFICIENT_EVIDENCE"
            elif contested or failed_replication:
                consensus = "MIXED" if independent_count >= 1 else "CONTESTED"
            elif systematic_independent >= 1 and independent_count >= 1:
                consensus = "STRONG_CONSENSUS"
            elif independent_count >= 2 and peer_reviewed_independent >= 2 and success_replication >= 1:
                consensus = "MODERATE_CONSENSUS"
            elif independent_count >= 2 and peer_reviewed_independent >= 2:
                consensus = "MODERATE_CONSENSUS"
            else:
                consensus = "INSUFFICIENT_EVIDENCE"

            if contested or failed_replication:
                global_contradictions.append(
                    {
                        "claim_key": key,
                        "contested_claims": contested,
                        "failed_replications": failed_replication,
                        "note": "Preserve contradictory evidence; do not flatten nuance.",
                    }
                )

            claim_assessments.append(
                {
                    "claim_key": key,
                    "statements": sorted({c.statement for _, c in items}),
                    "paper_ids": sorted({p.paper_id for p, _ in items}),
                    "independent_paper_count": independent_count,
                    "peer_reviewed_independent_count": peer_reviewed_independent,
                    "systematic_or_meta_independent_count": systematic_independent,
                    "retracted_paper_count": retracted,
                    "contested_claim_count": contested,
                    "failed_replication_count": failed_replication,
                    "successful_replication_count": success_replication,
                    "consensus_state": consensus,
                    "caution": "Author-reported claim is not verified fact; consensus depends on independent replication and method quality.",
                }
            )

        overall_consensus = "INSUFFICIENT_EVIDENCE"
        if claim_assessments:
            states = [c["consensus_state"] for c in claim_assessments]
            if all(s == "STRONG_CONSENSUS" for s in states):
                overall_consensus = "STRONG_CONSENSUS"
            elif any(s == "CONTESTED" for s in states):
                overall_consensus = "CONTESTED"
            elif any(s == "MIXED" for s in states):
                overall_consensus = "MIXED"
            elif any(s == "MODERATE_CONSENSUS" for s in states):
                overall_consensus = "MODERATE_CONSENSUS"

        # Research gaps.
        research_gaps: list[dict[str, Any]] = []
        gap_keywords = {
            "SAMPLE_SIZE_GAP": ["sample", "small", "n=", "participants"],
            "GEOGRAPHIC_GAP": ["geograph", "region", "country", "locale"],
            "TEMPORAL_GAP": ["time", "year", "longitudinal", "temporal"],
            "REPLICATION_GAP": ["replicat", "reproduc", "confirm"],
            "DATASET_GAP": ["dataset", "data availability", "benchmark"],
            "METHOD_GAP": ["method", "measurement", "instrument"],
            "EXTERNAL_VALIDITY_GAP": ["external validity", "generaliz", "generalis"],
            "CAUSAL_GAP": ["causal", "correlation", "mechanism"],
        }

        for p in req.papers:
            lims = " ".join(p.limitations).lower()
            for gap_type, kws in gap_keywords.items():
                if any(k in lims for k in kws):
                    research_gaps.append(
                        {
                            "gap_type": gap_type,
                            "paper_id": p.paper_id,
                            "source_limitation": " ".join(p.limitations)[:200],
                            "recommended_action": f"Seek independent evidence addressing {gap_type.lower().replace('_', ' ')}.",
                        }
                    )

        for ca in claim_assessments:
            if ca["independent_paper_count"] < 2:
                research_gaps.append(
                    {
                        "gap_type": "INDEPENDENT_REPLICATION_GAP",
                        "claim_key": ca["claim_key"],
                        "recommended_action": "Locate independent replication or primary dataset/code review.",
                    }
                )

        # Trends.
        by_year = Counter(p.year for p in req.papers if p.year)
        by_state = Counter(self._paper_status(p) for p in req.papers)
        keyword_counter: Counter[str] = Counter()
        for p in req.papers:
            for k in p.keywords:
                keyword_counter[norm_text(k)] += 1
        for a in req.authors:
            for t in a.topics:
                keyword_counter[norm_text(t)] += 1

        trends = {
            "papers_by_year": {str(k): v for k, v in sorted(by_year.items())},
            "papers_by_status": dict(by_state),
            "top_keywords": keyword_counter.most_common(10),
            "warning": "Trend/popularity is not scientific consensus.",
        }

        # Source independence summary.
        upstream_groups: dict[str, list[str]] = defaultdict(list)
        for p in req.papers:
            key = p.upstream_source or p.source_id or "UNKNOWN"
            upstream_groups[key].append(p.paper_id)

        source_independence = {
            "version_groups": version_groups,
            "upstream_source_groups": {k: sorted(v) for k, v in upstream_groups.items()},
            "author_collision_flags": author_collision_flags,
            "warning": "Same authors/dataset/upstream source may reduce independence; citation count is not quality.",
        }

        replication_status = {
            p.paper_id: p.replication_status.upper()
            for p in req.papers
        }

        recommended_actions = sorted(
            {
                "Do not present preprint as peer-reviewed unless peer-reviewed version is resolved.",
                "Preserve retraction/correction history; do not hide retractions.",
                "Evaluate paper-level method/claim quality, not journal prestige alone.",
                "Count independent research groups, not duplicate versions.",
                "Verify DOI/citation metadata from supplied authoritative records only.",
            }
        )

        handoffs: set[str] = set()
        if any(p.repository for p in req.papers):
            handoffs.add("REPOINT")
        if req.datasets:
            handoffs.add("DATASETINT")
        if req.grants:
            handoffs.add("FININT")
        if req.patents:
            handoffs.update({"TECHINT", "CORPINT"})
        if any("company" in i.institution_type.lower() or "corp" in i.institution_type.lower() for i in req.institutions):
            handoffs.add("CORPINT")

        limitations = [
            "Rule-based local ACADEMICINT skeleton; does not query live publisher/Crossref/OpenAlex/arXiv services.",
            "Does not fabricate papers, DOIs, authors, citations, datasets, or results.",
            "Peer review is quality control, not proof of truth.",
            "Citation count and journal prestige are not paper-quality oracles.",
            "Consensus assessment is conservative and depends on supplied independent studies/replications.",
        ]

        if not req.papers:
            status = Status.INCONCLUSIVE.value
            summary = "No papers supplied."
        else:
            status = Status.PARTIAL.value
            summary = (
                f"Academic research synthesis for {len(req.papers)} paper(s), "
                f"{len(citation_rows)} citation edge(s), and {len(claim_assessments)} claim group(s). "
                "No bibliographic records were fabricated."
            )

        paper_rows: list[dict[str, Any]] = []
        for p in req.papers:
            peer = self._is_peer_reviewed(p, {pid: version_roots[uf.find(pid)] for pid in paper_map}, paper_map)
            paper_rows.append(
                {
                    "paper_id": p.paper_id,
                    "doi": p.doi,
                    "title": p.title,
                    "venue": p.venue,
                    "year": p.year,
                    "publication_state": p.publication_state.upper(),
                    "status": self._paper_status(p),
                    "peer_reviewed_or_has_peer_version": peer,
                    "authors": p.authors,
                    "institutions": p.institutions,
                    "datasets": p.datasets,
                    "benchmarks": p.benchmarks,
                    "repository": p.repository,
                    "code_available": p.code_available,
                    "data_available": p.data_available,
                    "replication_status": p.replication_status.upper(),
                    "limitations": p.limitations,
                    "funding": p.funding,
                    "coi": p.coi,
                    "claims": [asdict(c) for c in p.claims],
                    "version_root": uf.find(p.paper_id),
                }
            )

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "case_id": req.case_id,
            "created_at": now_iso(),
            "paper_ids": sorted(paper_map),
            "citation_edges": citation_rows,
            "version_groups": version_groups,
            "claim_groups": {k: sorted({p.paper_id for p, _ in v}) for k, v in claim_groups.items()},
        }

        result = AcademicResult(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            research_question=req.research_question,
            summary=summary,
            papers=paper_rows,
            authors=[asdict(a) for a in req.authors],
            institutions=[asdict(i) for i in req.institutions],
            citation_graph=citation_rows,
            version_groups=version_groups,
            retractions=retractions,
            corrections=corrections,
            claim_assessments=claim_assessments,
            replication_status=replication_status,
            source_independence=source_independence,
            research_gaps=research_gaps,
            trends=trends,
            consensus_state=overall_consensus,
            contradictions=global_contradictions,
            unknowns=sorted(unknowns),
            knowledge_gaps=sorted(gaps),
            recommended_next_actions=recommended_actions,
            specialist_handoffs=sorted(handoffs),
            limitations=limitations,
            replay_manifest=replay_manifest,
            created_at=now_iso(),
        )

        self.memory.append(asdict(result))
        return result


# ======================================================================
# Demo / main
# ======================================================================

def demo_scamnet() -> None:
    agent = ScamNetIntAgent(mode=Mode.LOCAL_ONLY)

    nodes = [
        ScamNode("N-DOMAIN-1", "DOMAIN", "shop-example.test", valid_from="2026-09-01", valid_to="2026-09-20", source_id="SRC-DNS", upstream_source="UP-DNS-1"),
        ScamNode("N-DOMAIN-2", "DOMAIN", "secure-shop.example.test", valid_from="2026-09-10", valid_to="2026-09-25", source_id="SRC-DNS", upstream_source="UP-DNS-1"),
        ScamNode("N-EMAIL-1", "EMAIL", "payments@example.test", source_id="SRC-WEB", upstream_source="UP-WEB-1"),
        ScamNode("N-PAY-1", "PAYMENT_ACCOUNT", "PAY-99887766", source_id="SRC-COMPLAINT", upstream_source="UP-VICTIM-1"),
        ScamNode("N-TEMPLATE-1", "WEBSITE", "commercial-template-A", source_id="SRC-WEB", upstream_source="UP-WEB-1"),
    ]

    edges = [
        ScamEdge("E-EMAIL-1", "N-DOMAIN-1", "N-EMAIL-1", "USES_EMAIL", confidence=0.80, source_id="SRC-WEB", upstream_source="UP-WEB-1", evidence_id="EV-WEB-1"),
        ScamEdge("E-EMAIL-2", "N-DOMAIN-2", "N-EMAIL-1", "USES_EMAIL", confidence=0.75, source_id="SRC-WEB", upstream_source="UP-WEB-1", evidence_id="EV-WEB-2"),
        ScamEdge("E-PAY-1", "N-EMAIL-1", "N-PAY-1", "USES_PAYMENT_ACCOUNT", confidence=0.85, source_id="SRC-COMPLAINT", upstream_source="UP-VICTIM-1", evidence_id="EV-COMP-1"),
        ScamEdge("E-TMPL-1", "N-DOMAIN-1", "N-TEMPLATE-1", "SHARES_TEMPLATE_WITH", confidence=0.65, source_id="SRC-WEB", upstream_source="UP-WEB-1", metadata={"template": "commercial"}),
        ScamEdge("E-TMPL-2", "N-DOMAIN-2", "N-TEMPLATE-1", "SHARES_TEMPLATE_WITH", confidence=0.65, source_id="SRC-WEB", upstream_source="UP-WEB-1", metadata={"template": "commercial"}),
    ]

    complaints = [
        ScamComplaint(
            complaint_id="C-1",
            reporter_pseudonym="VICTIM-A",
            domain="shop-example.test",
            email="payments@example.test",
            payment_ref="PAY-99887766",
            time="2026-09-15",
            source_id="SRC-COMPLAINT",
            upstream_source="UP-VICTIM-1",
            text="Unauthorized charge after fake shop purchase.",
        ),
        ScamComplaint(
            complaint_id="C-2",
            reporter_pseudonym="VICTIM-A",
            domain="shop-example.test",
            email="payments@example.test",
            payment_ref="PAY-99887766",
            time="2026-09-16",
            source_id="SRC-FEED",
            upstream_source="UP-VICTIM-1",
            text="Unauthorized charge after fake shop purchase.",
        ),
    ]

    req = ScamNetRequest(
        case_id="SCAM-001",
        objective="Defensively correlate supplied scam infrastructure indicators and identify candidate clusters without attacking or contacting anyone.",
        authorization={"authorized": True, "purpose": "defensive_fraud_network_mapping"},
        nodes=nodes,
        edges=edges,
        complaints=complaints,
        scope={"time_range": "2026-09-01 to 2026-09-30"},
    )

    res = agent.analyze(req)

    print("=== SCAMNETINT ===")
    print(res.summary)
    print("Clusters:")
    for c in res.clusters:
        print(f"  {c['cluster_id']}: {c['state']}, nodes={c['nodes']}, strong={c['strong_edge_count']}, independent_sources={c['independent_source_count']}")
    print(f"Raw complaints: {res.raw_complaint_count}; unique complaint families: {res.unique_complaint_families}")
    print("Privacy flags:", res.privacy_flags[:2])
    print()


def demo_hypothesis() -> None:
    agent = HypothesisIntAgent(mode=Mode.LOCAL_ONLY)

    evidence = [
        EvidenceItem(
            evidence_id="EV-EMAIL",
            statement="Both domains displayed the same contact email in archived page captures.",
            source_id="SRC-WEB",
            upstream_source="UP-WEB-1",
            reliability=0.80,
            independence_group="UP-WEB-1",
            diagnosticity=0.70,
        ),
        EvidenceItem(
            evidence_id="EV-PAYMENT",
            statement="Victim complaint references the same payment identifier used by both domains.",
            source_id="SRC-COMPLAINT",
            upstream_source="UP-VICTIM-1",
            reliability=0.75,
            independence_group="UP-VICTIM-1",
            diagnosticity=0.85,
        ),
        EvidenceItem(
            evidence_id="EV-TEMPLATE",
            statement="Both sites use a commercially available website template.",
            source_id="SRC-WEB",
            upstream_source="UP-WEB-1",
            reliability=0.60,
            independence_group="UP-WEB-1",
            diagnosticity=0.15,
        ),
    ]

    hypotheses = [
        Hypothesis(
            hypothesis_id="H-CAMPAIGN",
            statement="The domains are part of the same scam campaign or common operator/control path.",
            hypothesis_type="CAMPAIGN",
        ),
        Hypothesis(
            hypothesis_id="H-SHARED-PROVIDER",
            statement="The similarities reflect shared template/hosting/provider rather than common operation.",
            hypothesis_type="ORIGIN",
        ),
        Hypothesis(
            hypothesis_id="H-DATA-ERROR",
            statement="The linkage reflects duplicate reporting or data normalization error.",
            hypothesis_type="MECHANISM",
        ),
    ]

    links = [
        EvidenceHypothesisLink("EV-EMAIL", "H-CAMPAIGN", "SUPPORTS", locator="archive capture"),
        EvidenceHypothesisLink("EV-PAYMENT", "H-CAMPAIGN", "STRONGLY_SUPPORTS", locator="payment ref"),
        EvidenceHypothesisLink("EV-TEMPLATE", "H-CAMPAIGN", "SLIGHTLY_SUPPORTS", locator="template hash"),

        EvidenceHypothesisLink("EV-TEMPLATE", "H-SHARED-PROVIDER", "SUPPORTS", locator="commercial template"),
        EvidenceHypothesisLink("EV-PAYMENT", "H-SHARED-PROVIDER", "CONTRADICTS", locator="unique payment identifier"),
        EvidenceHypothesisLink("EV-EMAIL", "H-SHARED-PROVIDER", "SLIGHTLY_CONTRADICTS", locator="contact email not generic provider address"),

        EvidenceHypothesisLink("EV-PAYMENT", "H-DATA-ERROR", "CONTRADICTS", locator="independent complaint field"),
        EvidenceHypothesisLink("EV-EMAIL", "H-DATA-ERROR", "SLIGHTLY_CONTRADICTS", locator="two archive captures"),
    ]

    predictions = [
        Prediction(
            prediction_id="P-1",
            hypothesis_id="H-CAMPAIGN",
            expected_observation="Additional independent complaints reference same payment/email with overlapping time window.",
            importance="HIGH",
            observed_state="NOT_TESTED",
        ),
        Prediction(
            prediction_id="P-2",
            hypothesis_id="H-SHARED-PROVIDER",
            expected_observation="Template and infrastructure identifiers appear across many unrelated sites.",
            importance="MEDIUM",
            observed_state="NOT_TESTED",
        ),
    ]

    falsifiers = [
        Falsifier(
            falsifier_id="F-1",
            hypothesis_id="H-CAMPAIGN",
            condition="Payment identifier is shown to belong to a shared payment processor used by unrelated merchants.",
            observed_state="NOT_TESTED",
        ),
        Falsifier(
            falsifier_id="F-2",
            hypothesis_id="H-SHARED-PROVIDER",
            condition="Unique payment/email linkage persists after controlling for template and hosting.",
            observed_state="NOT_TESTED",
        ),
    ]

    req = HypothesisRequest(
        case_id="HYP-001",
        objective="Test competing explanations for observed scam-domain linkage.",
        question="Are Domain-1 and Domain-2 linked by common campaign operation, shared provider artifacts, or data error?",
        authorization={"authorized": True, "purpose": "defensive_hypothesis_testing"},
        evidence=evidence,
        hypotheses=hypotheses,
        links=links,
        predictions=predictions,
        falsifiers=falsifiers,
    )

    res = agent.analyze(req)

    print("=== HYPOTHESISINT ===")
    print(res.summary)
    print("Ranking:")
    for r in res.ranking:
        print(
            f"  {r['hypothesis_id']}: score={r['score']}, state={r['verification_state']}, "
            f"confidence={r['confidence']}, contradictions={r['contradiction_count']}"
        )
    print("Diagnostic evidence:", [d["evidence_id"] for d in res.diagnostic_evidence])
    print("Next best evidence (first 3):")
    for x in res.next_best_evidence[:3]:
        print("  -", x)
    print()


def demo_academic() -> None:
    agent = AcademicIntAgent(mode=Mode.LOCAL_ONLY)

    authors = [
        Author(author_id="A-1", name="Researcher One", orcid="0000-0001-1111-1111", topics=["fraud detection"], affiliations=[AuthorAffiliation("I-1", valid_from="2024", valid_to="2026")]),
        Author(author_id="A-2", name="Researcher Two", orcid="0000-0002-2222-2222", topics=["network security"], affiliations=[AuthorAffiliation("I-2", valid_from="2025")]),
        Author(author_id="A-3", name="Researcher Three", orcid="0000-0003-3333-3333", topics=["applied ML"], affiliations=[AuthorAffiliation("I-3", valid_from="2025")]),
    ]

    institutions = [
        Institution("I-1", "University Alpha", "UNIVERSITY"),
        Institution("I-2", "Institute Beta", "RESEARCH_INSTITUTE"),
        Institution("I-3", "Lab Gamma", "LABORATORY"),
    ]

    papers = [
        Paper(
            paper_id="P-1",
            doi="10.1234/example.preprint.001",
            title="Template reuse in fraudulent websites",
            authors=["A-1"],
            institutions=["I-1"],
            venue="arXiv-like",
            year=2026,
            publication_state="PREPRINT",
            claims=[PaperClaim("CLM-1", "Commercial templates reduce the discriminative value of template similarity for operator linkage.", support_state="REPORTED")],
            methods=["content fingerprinting"],
            datasets=["D-1"],
            limitations=["Small sample; single region; no independent replication."],
            keywords=["fraud", "templates", "web"],
            replication_status="NOT_REPRODUCED",
            source_id="SRC-ARXIV",
            upstream_source="UP-ARXIV-1",
        ),
        Paper(
            paper_id="P-2",
            doi="10.5678/example.journal.002",
            title="Independent evaluation of template reuse in fraud linkage",
            authors=["A-2"],
            institutions=["I-2"],
            venue="Journal Example",
            year=2026,
            publication_state="PEER_REVIEWED_ARTICLE",
            claims=[PaperClaim("CLM-1", "Commercial templates reduce the discriminative value of template similarity for operator linkage.", support_state="SUPPORTED_BY_METHOD")],
            methods=["controlled comparison", "independent dataset"],
            datasets=["D-2"],
            limitations=["Limited geographic coverage."],
            keywords=["fraud", "templates", "replication"],
            replication_status="REPRODUCED_INDEPENDENTLY",
            source_id="SRC-JOURNAL",
            upstream_source="UP-JOURNAL-1",
        ),
        Paper(
            paper_id="P-3",
            doi="10.9012/example.journal.003",
            title="Another independent replication on template reuse",
            authors=["A-3"],
            institutions=["I-3"],
            venue="Conference Example",
            year=2026,
            publication_state="CONFERENCE_PAPER",
            claims=[PaperClaim("CLM-1", "Commercial templates reduce the discriminative value of template similarity for operator linkage.", support_state="SUPPORTED_BY_METHOD")],
            methods=["cross-region replication"],
            datasets=["D-3"],
            limitations=["Conference page limits; code availability partial."],
            keywords=["fraud", "replication"],
            replication_status="PARTIALLY_REPRODUCED",
            source_id="SRC-CONF",
            upstream_source="UP-CONF-1",
        ),
    ]

    citations = [
        Citation(citing_paper_id="P-2", cited_paper_id="P-1", relationship="REPLICATES", context="independent dataset"),
        Citation(citing_paper_id="P-3", cited_paper_id="P-1", relationship="REPLICATES", context="cross-region"),
        Citation(citing_paper_id="P-3", cited_paper_id="P-2", relationship="EXTENDS", context="additional geography"),
    ]

    datasets = [
        Dataset("D-1", "Fraud Web Sample A", creator="University Alpha", sample_size=120, limitations=["single region"]),
        Dataset("D-2", "Fraud Web Sample B", creator="Institute Beta", sample_size=340, limitations=["limited labels"]),
        Dataset("D-3", "Fraud Web Sample C", creator="Lab Gamma", sample_size=210, limitations=["partial code"]),
    ]

    req = AcademicRequest(
        case_id="ACAD-001",
        objective="Synthesize supplied research on template reuse and fraud-network linkage without fabricating citations.",
        research_question="Does commercial template reuse reduce the evidentiary value of template similarity for scam-operator linkage?",
        authorization={"authorized": True, "purpose": "defensive_research_synthesis"},
        papers=papers,
        authors=authors,
        institutions=institutions,
        citations=citations,
        datasets=datasets,
    )

    res = agent.analyze(req)

    print("=== ACADEMICINT ===")
    print(res.summary)
    print("Overall consensus:", res.consensus_state)
    print("Claim assessments:")
    for ca in res.claim_assessments:
        print(
            f"  {ca['claim_key']}: independent={ca['independent_paper_count']}, "
            f"peer_independent={ca['peer_reviewed_independent_count']}, "
            f"replications={ca['successful_replication_count']}, consensus={ca['consensus_state']}"
        )
    print("Research gaps (first 3):")
    for g in res.research_gaps[:3]:
        print("  -", g["gap_type"], g.get("paper_id") or g.get("claim_key"))
    print()


def main() -> None:
    demo_scamnet()
    demo_hypothesis()
    demo_academic()

    print("=== ALL DEMOS COMPLETE ===")
    print("Defensive boundaries enforced:")
    print("  - SCAMNETINT: no attack/contact/doxxing/test-payment behavior.")
    print("  - HYPOTHESISINT: no fabricated certainty; contradictions preserved.")
    print("  - ACADEMICINT: no fabricated papers/DOIs/citations; preprint/peer-review separated.")


if __name__ == "__main__":
    main()