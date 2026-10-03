"""Temporal, provenance-rich analytical graph kept separate from identity truth."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


NODE_TYPES = frozenset({
    "Case", "Task", "Employee", "Person", "Organization", "Company", "Account", "Domain", "IP",
    "Email", "Phone", "Username", "Device", "Document", "Location", "Event", "Asset", "Supplier",
    "Facility", "Software", "Hardware", "AIModel", "ThreatActor", "Campaign", "Indicator",
    "Transaction", "Evidence", "Observation", "Claim", "Hypothesis", "Source", "Acquisition",
    "URL", "ASN", "Certificate", "Hash", "Malware", "Vulnerability", "TTP", "Dataset",
})
IDENTITY_STATES = frozenset({"MATCH", "LIKELY_MATCH", "POSSIBLE_MATCH", "CONFLICT", "NO_MATCH"})


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("graph timestamps require timezone")
    return parsed


@dataclass(frozen=True, slots=True)
class GraphNode:
    node_id: str
    case_id: str
    node_type: str
    label: str
    evidence_ids: tuple[str, ...]
    observation_ids: tuple[str, ...]
    valid_from: str
    valid_to: str | None
    proposed_by: str
    reviewed_by: str | None = None
    decision_state: str = "PROPOSED"

    def __post_init__(self) -> None:
        if self.node_type not in NODE_TYPES or not self.node_id or not self.case_id or not self.label.strip():
            raise ValueError("invalid temporal graph node")
        start = _time(self.valid_from)
        if self.valid_to is not None and _time(self.valid_to) < start:
            raise ValueError("valid_to cannot precede valid_from")
        if self.decision_state not in {"PROPOSED", "ACCEPTED", "REJECTED", "RETRACTED", "SUPERSEDED"}:
            raise ValueError("invalid graph decision state")


@dataclass(frozen=True, slots=True)
class GraphEdge:
    edge_id: str
    case_id: str
    source_node_id: str
    target_node_id: str
    edge_type: str
    evidence_ids: tuple[str, ...]
    observation_ids: tuple[str, ...]
    lineage_groups: tuple[str, ...]
    valid_from: str
    valid_to: str | None
    confidence_basis: str
    uncertainty: str
    proposed_by: str
    reviewed_by: str | None = None
    decision_state: str = "PROPOSED"
    supersedes_edge_id: str | None = None
    retracted_by_edge_id: str | None = None

    def __post_init__(self) -> None:
        if not self.edge_id or not self.case_id or self.source_node_id == self.target_node_id:
            raise ValueError("invalid temporal graph edge")
        if not self.edge_type or not self.observation_ids or not self.evidence_ids:
            raise ValueError("material graph edges require provenance")
        start = _time(self.valid_from)
        if self.valid_to is not None and _time(self.valid_to) < start:
            raise ValueError("valid_to cannot precede valid_from")
        if self.decision_state not in {"PROPOSED", "ACCEPTED", "REJECTED", "RETRACTED", "SUPERSEDED"}:
            raise ValueError("invalid graph decision state")


class TemporalClaimGraph:
    """Deterministic graph gate; proposals never silently become identity merges."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}

    def add_node(self, node: GraphNode) -> None:
        if node.case_id != self.case_id or node.node_id in self.nodes:
            raise ValueError("graph node case mismatch or duplicate")
        self.nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.case_id != self.case_id or edge.edge_id in self.edges:
            raise ValueError("graph edge case mismatch or duplicate")
        if edge.source_node_id not in self.nodes or edge.target_node_id not in self.nodes:
            raise ValueError("graph edge references an unknown node")
        if edge.edge_type.casefold() in {"caused", "same_as", "identity_merge"} and edge.decision_state != "ACCEPTED":
            raise ValueError("causation and identity edges require explicit human acceptance")
        self.edges[edge.edge_id] = edge

    @staticmethod
    def identity_candidate(state: str, reasons: tuple[str, ...], *, human_accepted: bool = False) -> dict:
        if state not in IDENTITY_STATES or not reasons:
            raise ValueError("identity candidates require a supported state and reasons")
        return {"state": state, "reasons": list(reasons), "canonical_merge": state == "MATCH" and human_accepted,
                "human_review_required": True}

    def snapshot(self) -> dict:
        return {
            "case_id": self.case_id,
            "nodes": [node.__dict__ if hasattr(node, "__dict__") else {field: getattr(node, field) for field in node.__dataclass_fields__}
                      for node in self.nodes.values()],
            "edges": [edge.__dict__ if hasattr(edge, "__dict__") else {field: getattr(edge, field) for field in edge.__dataclass_fields__}
                      for edge in self.edges.values()],
        }
