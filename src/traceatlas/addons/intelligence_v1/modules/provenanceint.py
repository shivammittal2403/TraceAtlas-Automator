# TRACEATLAS — PROVENANCEINT AI EMPLOYEE
# Single-file defensive Python core for provenance / lineage / chain-of-custody analysis.
# Does NOT forge metadata, timestamps, signatures, custody logs, or provenance.

from __future__ import annotations

import difflib
import hashlib
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


TOOL_VERSION = "PROVENANCEINT-PY-0.1"
MAX_DT = datetime.max.replace(tzinfo=timezone.utc)


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


BLOCK_PHRASES = [
    "forge metadata",
    "fake metadata",
    "fabricate provenance",
    "fabricate custody",
    "backdate artifact",
    "backdate file",
    "alter chain-of-custody",
    "modify evidence history",
    "forge signature",
    "fake signature",
    "spoof timestamp",
    "tamper with evidence",
    "erase contradictory",
    "delete evidence",
    "launder provenance",
    "hide origin",
]


@dataclass
class CustodyEvent:
    event_id: str
    artifact_id: str
    action: str
    timestamp: str
    custodian_from: str = ""
    custodian_to: str = ""
    hash_before: str = ""
    hash_after: str = ""
    operator: str = ""
    tool: str = ""
    reason: str = ""


@dataclass
class Transformation:
    transformation_id: str
    input_artifact_ids: list[str]
    output_artifact_id: str
    operation: str
    tool: str = ""
    tool_version: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    lossy: bool = False
    reversible: bool = False


@dataclass
class Artifact:
    artifact_id: str
    artifact_type: str = "DOCUMENT"
    filename: str = ""
    content: bytes | str | None = None
    source_id: str = ""
    collector: str = ""
    collection_time: str = ""
    creation_time_claimed: str = ""
    publication_time: str = ""
    first_seen: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: dict[str, Any] = field(default_factory=dict)
    timestamps: dict[str, str] = field(default_factory=dict)
    upstream_ids: list[str] = field(default_factory=list)
    custody_events: list[CustodyEvent] = field(default_factory=list)
    transformations: list[Transformation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ProvenanceRequest:
    case_id: str
    objective: str
    authorization: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceResult:
    case_id: str
    status: str
    policy_decision: str
    summary: str
    artifacts: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    integrity_status: dict[str, str]
    authenticity_status: dict[str, str]
    provenance_status: dict[str, str]
    tampering_status: dict[str, str]
    custody_status: dict[str, str]
    gaps: list[str]
    contradictions: list[str]
    next_actions: list[str]
    handoffs: list[str]
    limitations: list[str]
    replay_manifest: dict[str, Any]
    created_at: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def to_bytes(content: bytes | str | dict | list | None) -> Optional[bytes]:
    if content is None:
        return None
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8", errors="ignore")
    return json.dumps(content, default=str, sort_keys=True).encode("utf-8")


def norm_text(content: bytes | str | dict | list | None) -> str:
    b = to_bytes(content)
    if not b:
        return ""
    try:
        s = b.decode("utf-8", errors="ignore")
    except Exception:
        s = repr(b)
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"<[^>]+>", " ", s)
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


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
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d %b %Y", "%b %d, %Y"):
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


def earliest_dt(rec: dict[str, Any]) -> datetime:
    art: Artifact = rec["artifact"]
    for val in (art.first_seen, art.publication_time, art.collection_time, art.creation_time_claimed):
        dt = parse_dt(val)
        if dt:
            return dt
    return MAX_DT


class ProvenanceAgent:
    def __init__(self, mode: Mode = Mode.LOCAL_ONLY) -> None:
        self.mode = mode
        self.memory: list[dict[str, Any]] = []

    def policy_check(self, req: ProvenanceRequest) -> tuple[PolicyDecision, str, str]:
        blob = " ".join(
            [
                req.objective,
                json.dumps(req.scope, default=str),
                json.dumps(req.authorization, default=str),
            ]
        ).lower()

        if req.authorization.get("authorized") is not True:
            return PolicyDecision.BLOCK, "BLOCKED_AUTHORIZATION", "Explicit authorization is required."

        for phrase in BLOCK_PHRASES:
            if phrase in blob:
                return PolicyDecision.BLOCK, "BLOCKED_POLICY", f"Prohibited provenance action requested: {phrase}"

        return PolicyDecision.ALLOW, "", ""

    def blocked_result(self, req: ProvenanceRequest, code: str, reason: str) -> ProvenanceResult:
        return ProvenanceResult(
            case_id=req.case_id,
            status=code,
            policy_decision=PolicyDecision.BLOCK.value,
            summary=f"POLICY_BLOCKED: {reason}",
            artifacts=[],
            edges=[],
            hypotheses=[],
            integrity_status={},
            authenticity_status={},
            provenance_status={},
            tampering_status={},
            custody_status={},
            gaps=["Request outside defensive provenance boundary."],
            contradictions=[],
            next_actions=["Reframe as authorized, passive, tamper-evident provenance reconstruction."],
            handoffs=[],
            limitations=[reason],
            replay_manifest={},
            created_at=now_iso(),
        )

    def analyze(self, req: ProvenanceRequest) -> ProvenanceResult:
        decision, code, reason = self.policy_check(req)
        if decision == PolicyDecision.BLOCK:
            result = self.blocked_result(req, code, reason)
            self.memory.append(asdict(result))
            return result

        records: dict[str, dict[str, Any]] = {}
        for art in req.artifacts:
            b = to_bytes(art.content)
            raw_hash = sha256_hex(b) if b else ""
            text = norm_text(b)
            records[art.artifact_id] = {
                "artifact": art,
                "raw_hash": raw_hash,
                "text": text,
                "preview": text[:160],
            }

        edges: list[dict[str, Any]] = []

        # Declared upstream / transformation lineage
        for art_id, rec in records.items():
            art: Artifact = rec["artifact"]

            for up in art.upstream_ids:
                relation = "DERIVED_FROM" if up in records else "DECLARED_UPSTREAM_UNRESOLVED"
                confidence = 0.80 if up in records else 0.40
                edges.append(
                    {
                        "from": art_id,
                        "to": up,
                        "relation": relation,
                        "confidence": confidence,
                        "evidence": "declared upstream reference",
                    }
                )

            for tr in art.transformations:
                for inp in tr.input_artifact_ids:
                    edges.append(
                        {
                            "from": inp,
                            "to": art_id,
                            "relation": tr.operation or "TRANSFORMED_TO",
                            "confidence": 0.90,
                            "evidence": f"transformation {tr.transformation_id} by {tr.tool or 'unknown'}",
                        }
                    )

        # Exact / near duplicate detection
        ids = list(records.keys())
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                id1, id2 = ids[i], ids[j]
                r1, r2 = records[id1], records[id2]

                if r1["raw_hash"] and r1["raw_hash"] == r2["raw_hash"]:
                    earlier, later = (id1, id2) if earliest_dt(r1) <= earliest_dt(r2) else (id2, id1)
                    edges.append(
                        {
                            "from": later,
                            "to": earlier,
                            "relation": "EXACT_COPY_OF",
                            "confidence": 1.0,
                            "evidence": "identical SHA-256",
                        }
                    )
                elif r1["text"] and r2["text"]:
                    ratio = difflib.SequenceMatcher(None, r1["text"], r2["text"]).ratio()
                    if ratio >= 0.86:
                        earlier, later = (id1, id2) if earliest_dt(r1) <= earliest_dt(r2) else (id2, id1)
                        edges.append(
                            {
                                "from": later,
                                "to": earlier,
                                "relation": "NEAR_DUPLICATE_OF",
                                "confidence": round(ratio, 3),
                                "evidence": f"text similarity {ratio:.3f}",
                            }
                        )

        integrity: dict[str, str] = {}
        authenticity: dict[str, str] = {}
        provenance: dict[str, str] = {}
        tampering: dict[str, str] = {}
        custody: dict[str, str] = {}

        gaps: list[str] = []
        contradictions: list[str] = []
        next_actions: set[str] = set()
        handoffs: set[str] = set()

        transfer_like = {"TRANSFERRED", "RECEIVED", "COPIED", "VERIFIED", "SEALED"}
        transform_like = {
            "PARSED",
            "EXTRACTED",
            "TRANSCODED",
            "REDACTED",
            "NORMALIZED",
            "OCR",
            "ASR",
            "CONVERT",
            "EXPORTED",
        }

        for art_id, rec in records.items():
            art: Artifact = rec["artifact"]
            art_contradictions: list[str] = []
            unexplained_hash_changes: list[str] = []
            expected_hash_changes: list[str] = []
            custody_issues: list[str] = []

            events = sorted(art.custody_events, key=lambda e: parse_dt(e.timestamp) or MAX_DT)
            collection_dt = parse_dt(art.collection_time)

            for ev in events:
                ev_dt = parse_dt(ev.timestamp)

                if ev_dt and collection_dt and ev_dt < collection_dt:
                    art_contradictions.append(f"{art_id}: custody event {ev.event_id} before collection time")

                action = ev.action.upper()

                if action in transfer_like:
                    if ev.hash_before and ev.hash_after and ev.hash_before != ev.hash_after:
                        unexplained_hash_changes.append(ev.event_id)

                if action in transform_like:
                    if ev.hash_before and ev.hash_after and ev.hash_before != ev.hash_after:
                        expected_hash_changes.append(ev.event_id)

                if not ev.hash_after:
                    custody_issues.append(f"{ev.event_id}: missing hash_after")
                if action != "COLLECTED" and not ev.hash_before:
                    custody_issues.append(f"{ev.event_id}: missing hash_before")
                if action in {"TRANSFERRED", "RECEIVED"} and not ev.custodian_to:
                    custody_issues.append(f"{ev.event_id}: missing receiving custodian")

            # Integrity
            if not rec["raw_hash"]:
                integrity[art_id] = "INTEGRITY_UNVERIFIED"
                gaps.append(f"{art_id}: content/hash unavailable")
                next_actions.add(f"Obtain native {art_id} and compute SHA-256")
            elif unexplained_hash_changes:
                integrity[art_id] = "INTEGRITY_CHANGED_UNEXPLAINED"
                tampering[art_id] = "TAMPERING_CANDIDATE"
                contradictions.extend(art_contradictions)
                contradictions.append(
                    f"{art_id}: unexplained hash change in custody events {unexplained_hash_changes}"
                )
                next_actions.add(
                    f"Investigate unexplained hash change for {art_id}; compare original bytes and tool normalization"
                )
            elif expected_hash_changes:
                integrity[art_id] = "INTEGRITY_CHANGED_EXPECTED"
                tampering[art_id] = "EXPECTED_TRANSFORMATION"
            else:
                integrity[art_id] = "INTEGRITY_VERIFIED"
                tampering[art_id] = "NO_TAMPERING_EVIDENCE"

            # Custody
            if not events:
                custody[art_id] = "UNVERIFIED_CHAIN"
                gaps.append(f"{art_id}: no chain-of-custody events supplied")
                next_actions.add(f"Retrieve custody log for {art_id}")
            elif art_contradictions or custody_issues:
                custody[art_id] = "CHAIN_WITH_GAPS"
                gaps.extend(f"{art_id}: {issue}" for issue in custody_issues)
            else:
                custody[art_id] = "SUBSTANTIALLY_DOCUMENTED"

            # Authenticity
            sig = art.signature or {}
            sig_state = str(sig.get("state", "UNKNOWN")).upper()
            meta_author = art.metadata.get("author")
            signer = sig.get("signer")

            if sig_state.startswith("VALID"):
                authenticity[art_id] = "AUTHENTICITY_SUPPORTED"
                if signer and meta_author and str(signer).strip() != str(meta_author).strip():
                    contradictions.append(
                        f"{art_id}: signature signer '{signer}' differs from metadata author '{meta_author}'"
                    )
                next_actions.add(
                    f"Record that valid signature supports signer/integrity, not factual truth for {art_id}"
                )
            elif sig_state in {
                "INVALID_SIGNATURE",
                "REVOKED_CERTIFICATE_CONTEXT",
                "EXPIRED_CERTIFICATE_CONTEXT",
                "SIGNER_UNRESOLVED",
            }:
                authenticity[art_id] = "AUTHENTICITY_DISPUTED"
                tampering[art_id] = "TAMPERING_CANDIDATE"
                gaps.append(f"{art_id}: signature state {sig_state}")
            elif meta_author:
                authenticity[art_id] = "AUTHENTICITY_PARTIALLY_SUPPORTED"
                gaps.append(f"{art_id}: metadata author is unverified claim")
            else:
                authenticity[art_id] = "AUTHENTICITY_UNRESOLVED"
                gaps.append(f"{art_id}: no authenticity evidence supplied")

            # Provenance
            has_upstream = (
                bool(art.upstream_ids)
                or bool(art.transformations)
                or any(
                    e["from"] == art_id and e["relation"] in {"DERIVED_FROM", "EXACT_COPY_OF", "NEAR_DUPLICATE_OF"}
                    for e in edges
                )
            )

            if art_contradictions or any(c.startswith(art_id) for c in contradictions):
                provenance[art_id] = "CONTRADICTED"
            elif (
                has_upstream
                and integrity[art_id] in {"INTEGRITY_VERIFIED", "INTEGRITY_CHANGED_EXPECTED"}
                and custody[art_id] != "UNVERIFIED_CHAIN"
            ):
                provenance[art_id] = "STRONGLY_SUPPORTED_LINEAGE"
            elif has_upstream:
                provenance[art_id] = "PARTIALLY_SUPPORTED_LINEAGE"
            elif art.first_seen or art.publication_time:
                provenance[art_id] = "ORIGIN_CANDIDATE"
            else:
                provenance[art_id] = "UNRESOLVED"

            if custody[art_id] == "CHAIN_WITH_GAPS" and provenance[art_id] != "CONTRADICTED":
                provenance[art_id] = "LINEAGE_GAPPED"

            # Basic gaps / actions
            if not art.source_id:
                gaps.append(f"{art_id}: source/host unresolved")
                next_actions.add(f"Resolve hosting source vs creation source for {art_id}")

            if not art.collection_time:
                gaps.append(f"{art_id}: collection time unknown")

            if sig_state == "UNKNOWN":
                next_actions.add(f"Validate signature/attestation for {art_id} if available")

            # Specialist handoffs
            t = art.artifact_type.upper()
            if any(k in t for k in ["DOC", "PDF", "EMAIL", "MESSAGE"]):
                handoffs.update({"DOCINT", "METADATAINT"})
            if any(k in t for k in ["IMAGE", "PHOTO", "SCREENSHOT"]):
                handoffs.add("IMINT")
            if "VIDEO" in t:
                handoffs.add("VIDINT")
            if any(k in t for k in ["AUDIO", "TRANSCRIPT"]):
                handoffs.add("AUDINT")
            if any(k in t for k in ["SOFTWARE", "PACKAGE", "CONTAINER", "SBOM", "REPO", "BUILD"]):
                handoffs.update({"PACKAGEINT", "SUPPLYCHAININT"})
            if any(k in t for k in ["DATASET", "RECORD"]):
                handoffs.add("SOURCEINT")
            if "LOG" in t:
                handoffs.add("LOGINT")

        hypotheses = [
            {
                "id": "H1",
                "statement": "Earliest observed artifact may be an original candidate.",
                "support": "No earlier supplied copy found in this case set.",
                "opposition": "Earliest observed does not prove original creation.",
                "status": "CANDIDATE",
            },
            {
                "id": "H2",
                "statement": "Later artifacts are derivatives, copies, or syndicated versions.",
                "support": "Hash equality, text similarity, declared upstream, or transformation edges exist.",
                "opposition": "Independent convergence or common upstream source is possible.",
                "status": "CONDITIONAL",
            },
            {
                "id": "H3",
                "statement": "Metadata author equals real creator.",
                "support": "Metadata field may name an author.",
                "opposition": "Metadata can be defaulted, copied, stripped, edited, or spoofed.",
                "status": "UNRESOLVED",
            },
            {
                "id": "H4",
                "statement": "Hash change indicates tampering.",
                "support": "Unexplained hash mismatch during transfer-like custody event.",
                "opposition": "Documented lossy transformation, container change, or normalization may explain it.",
                "status": "CONDITIONAL",
            },
        ]

        next_actions.update(
            {
                "Preserve original bytes and analyze only working copies.",
                "Record every transformation with tool, version, parameters, timestamp, and before/after hashes.",
                "If origin remains unknown, label UNKNOWN rather than fabricating lineage.",
                "Separate integrity, authenticity, provenance, and veracity in final reporting.",
            }
        )

        limitations = [
            "Rule-based local PROVENANCEINT skeleton; not a full forensic platform.",
            "Does not fetch live sources, execute files, decrypt evidence, or verify cryptographic signatures unless state is supplied.",
            "Near-duplicate detection is heuristic and must be supplemented with archival/native-source review.",
            "Provenance supports origin/lineage assessment; it does not prove factual truth of content.",
            "No metadata forging, timestamp spoofing, signature fabrication, custody falsification, or evidence tampering is performed.",
        ]

        if not records:
            status = Status.INCONCLUSIVE.value
        elif (
            not contradictions
            and all(v in {"STRONGLY_SUPPORTED_LINEAGE", "PARTIALLY_SUPPORTED_LINEAGE", "ORIGIN_CANDIDATE"} for v in provenance.values())
            and all(v != "INTEGRITY_UNVERIFIED" for v in integrity.values())
        ):
            status = Status.SUCCEEDED.value
        else:
            status = Status.PARTIAL.value

        summary = (
            f"Defensive provenance analysis for {len(records)} artifacts. "
            f"Integrity verified/expected: {sum(1 for v in integrity.values() if v.startswith('INTEGRITY_VERIFIED') or v == 'INTEGRITY_CHANGED_EXPECTED')}. "
            f"Contradictions: {len(contradictions)}. "
            "No provenance fabrication, metadata spoofing, or evidence tampering performed."
        )

        artifact_rows = []
        for art_id, rec in records.items():
            art: Artifact = rec["artifact"]
            artifact_rows.append(
                {
                    "artifact_id": art_id,
                    "artifact_type": art.artifact_type,
                    "filename": art.filename,
                    "source_id": art.source_id,
                    "collector": art.collector,
                    "collection_time": art.collection_time,
                    "first_seen": art.first_seen,
                    "publication_time": art.publication_time,
                    "raw_sha256": rec["raw_hash"],
                    "content_preview": rec["preview"],
                    "upstream_ids": art.upstream_ids,
                    "transformation_count": len(art.transformations),
                    "custody_event_count": len(art.custody_events),
                    "metadata_keys": sorted(art.metadata.keys()),
                    "signature_state": str((art.signature or {}).get("state", "UNKNOWN")),
                }
            )

        replay_manifest = {
            "tool_version": TOOL_VERSION,
            "case_id": req.case_id,
            "created_at": now_iso(),
            "artifact_hashes": {aid: rec["raw_hash"] for aid, rec in records.items()},
            "edges": edges,
            "integrity_status": integrity,
            "authenticity_status": authenticity,
            "provenance_status": provenance,
            "custody_status": custody,
            "tampering_status": tampering,
        }

        result = ProvenanceResult(
            case_id=req.case_id,
            status=status,
            policy_decision=PolicyDecision.ALLOW.value,
            summary=summary,
            artifacts=artifact_rows,
            edges=edges,
            hypotheses=hypotheses,
            integrity_status=integrity,
            authenticity_status=authenticity,
            provenance_status=provenance,
            tampering_status=tampering,
            custody_status=custody,
            gaps=sorted(set(gaps)),
            contradictions=sorted(set(contradictions)),
            next_actions=sorted(next_actions),
            handoffs=sorted(handoffs),
            limitations=limitations,
            replay_manifest=replay_manifest,
            created_at=now_iso(),
        )

        self.memory.append(asdict(result))
        return result


def main() -> None:
    agent = ProvenanceAgent(mode=Mode.LOCAL_ONLY)

    original_content = b"Annual safety report. Section 1. Signed by OEM."
    ocr_text = "Annual safety report. Section 1. Signed by OEM"
    edited_content = b"Annual safety report. Section 1. Edited."

    original = Artifact(
        artifact_id="ART-001",
        artifact_type="DOCUMENT",
        filename="report.pdf",
        content=original_content,
        source_id="SRC-OEM-PORTAL",
        collector="CASE-SYSTEM",
        collection_time="2026-10-01T10:00:00Z",
        publication_time="2026-10-01T08:00:00Z",
        first_seen="2026-10-01T09:00:00Z",
        metadata={"author": "OEM Compliance"},
        signature={"state": "VALID_SIGNATURE", "signer": "OEM Compliance"},
        custody_events=[
            CustodyEvent(
                event_id="CE-1",
                artifact_id="ART-001",
                action="COLLECTED",
                timestamp="2026-10-01T10:00:00Z",
                custodian_to="CASE-SYSTEM",
                hash_before=sha256_hex(original_content),
                hash_after=sha256_hex(original_content),
                operator="analyst",
                tool="secure-download",
            ),
            CustodyEvent(
                event_id="CE-2",
                artifact_id="ART-001",
                action="SEALED",
                timestamp="2026-10-01T10:05:00Z",
                custodian_to="EVIDENCE-VAULT",
                hash_before=sha256_hex(original_content),
                hash_after=sha256_hex(original_content),
                operator="system",
                tool="vault-seal",
            ),
        ],
    )

    mirror_copy = Artifact(
        artifact_id="ART-002",
        artifact_type="DOCUMENT",
        filename="report_mirror.pdf",
        content=original_content,
        source_id="SRC-MIRROR",
        first_seen="2026-10-01T11:00:00Z",
        upstream_ids=["ART-001"],
    )

    ocr_derivative = Artifact(
        artifact_id="ART-003",
        artifact_type="TEXT_EXTRACTION",
        filename="report_ocr.txt",
        content=ocr_text,
        source_id="SRC-NEWS",
        first_seen="2026-10-02T09:00:00Z",
        upstream_ids=["ART-002"],
        transformations=[
            Transformation(
                transformation_id="TR-1",
                input_artifact_ids=["ART-002"],
                output_artifact_id="ART-003",
                operation="OCR",
                tool="tesseract",
                tool_version="5.3",
                timestamp="2026-10-02T08:00:00Z",
                lossy=True,
            )
        ],
    )

    suspicious = Artifact(
        artifact_id="ART-004",
        artifact_type="DOCUMENT",
        filename="report_suspicious.pdf",
        content=edited_content,
        source_id="SRC-UNKNOWN",
        first_seen="2026-10-02T12:00:00Z",
        custody_events=[
            CustodyEvent(
                event_id="CE-9",
                artifact_id="ART-004",
                action="TRANSFERRED",
                timestamp="2026-10-02T12:10:00Z",
                custodian_from="ANALYST-A",
                custodian_to="ANALYST-B",
                hash_before=sha256_hex(original_content),
                hash_after=sha256_hex(edited_content),
                operator="unknown",
                tool="scp",
            )
        ],
    )

    request = ProvenanceRequest(
        case_id="PROV-001",
        objective="Reconstruct lineage, duplicates, custody, integrity, and authenticity support for supplied artifacts.",
        authorization={"authorized": True, "purpose": "defensive_provenance_analysis"},
        artifacts=[original, mirror_copy, ocr_derivative, suspicious],
        scope={"time_range": "2026-10-01 to 2026-10-02"},
    )

    result = agent.analyze(request)
    print("=== PROVENANCEINT RESULT ===")
    print(json.dumps(asdict(result), indent=2, default=str))

    blocked = agent.analyze(
        ProvenanceRequest(
            case_id="PROV-002",
            objective="Forge metadata and backdate artifact to hide origin.",
            authorization={"authorized": False},
            artifacts=[],
        )
    )

    print("\n=== BLOCKED EXAMPLE ===")
    print("Status:", blocked.status)
    print("Summary:", blocked.summary)


if __name__ == "__main__":
    main()