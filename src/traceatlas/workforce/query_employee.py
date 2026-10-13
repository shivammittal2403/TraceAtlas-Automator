"""Fact-first, read-only query-planning AI employee for the canonical workforce.

Query -> bounded departmental work orders -> imported typed source documents
-> existing deterministic provenance/independence/contradiction rules -> review.

This module NEVER acquires new authority, calls providers, runs a model, merges
identities, or promotes a source assertion into a canonical approved fact.
For actual collection use the existing WorkforceService + InvestigationPipeline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contradictions import contradicts
from .documents import SourceDocument, StructuredFact, normalize_seed
from .lineage import SourceIndependenceEngine, SourceRecord

VERSION = "query-employee/v1"
MAX_QUERY = 2000
MAX_TASKS = 8
MAX_RESULTS = 32
MAX_DOCUMENTS = 64
MAX_DOCUMENT_TOTAL_BYTES = 4 * 1024 * 1024

# These are PLANNING disciplines, not a list of working or licensed connectors.
DOMAINS = {
    "OSINT": ("open source", "osint", "public record", "public information", "research"),
    "FININT": ("finint", "finmint", "financial", "finance", "transaction", "funding", "revenue", "money", "payment"),
    "GEOINT": ("geoint", "geomint", "geospatial", "coordinates", "geolocation", "satellite", "map", "location", "geography"),
    "CORPINT": ("corpint", "company", "corporation", "filings", "ownership", "subsidiary", "director", "business"),
    "CTI": ("cti", "threat intelligence", "cve", "vulnerability", "malware", "ioc", "ransomware"),
    "WEBINT": ("webint", "website", "webpage", "domain", "dns", "url", "internet"),
    "DOCINT": ("docint", "document", "pdf", "filing", "report", "publication"),
    "CODEINT": ("codeint", "repository", "github", "source code", "software", "dependency", "package"),
    "SOCMINT": ("socmint", "social media", "public profile", "social account", "post"),
    "PROCINT": ("procint", "procurement", "tender", "contract", "bid"),
    "BLOCKINT": ("blockint", "blockchain", "crypto", "wallet", "bitcoin", "onchain"),
}
DEFAULT_DOMAIN = {
    "domain": "WEBINT", "ip": "CTI", "cve": "CTI",
    "vulnerability": "CTI", "company": "CORPINT", "package": "CODEINT",
    "person": "OSINT", "location": "GEOINT", "account": "SOCMINT",
    "crypto_address": "BLOCKINT",
}
CANONICAL_TARGETS = frozenset(("domain", "ip", "person", "company", "cve", "vulnerability", "package"))
SENSITIVE_TARGETS = frozenset(("person", "account", "location", "crypto_address"))
VALID_RESULT_STATES = frozenset(("completed", "partial", "failed", "blocked", "unavailable"))
SUSPICIOUS = re.compile(
    r"(?i)(ignore\s+(all\s+)?previous\s+instructions|you\s+are\s+now\s+"
    r"(a|the)\s+system|system\s*prompt|reveal\s+(your\s+)?secrets|"
    r"disable\s+(the\s+)?safety|execute\s+(this\s+)?command)"
)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _bounded_text(value: Any, name: str, maximum: int, minimum: int = 1) -> str:
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValueError(f"{name} requires {minimum}-{maximum} characters")
    if any(ord(ch) < 32 and ch not in "\n\t" for ch in value):
        raise ValueError(f"{name} contains control characters")
    return value.strip()


def _valid_case(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,63}", value):
        raise ValueError("case_id must be a stable 2-64 character identifier")
    return value


def _words(text: str, phrase: str) -> bool:
    return bool(re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text))


def _target(target_type: str, target: str) -> str:
    if target_type not in DEFAULT_DOMAIN:
        raise ValueError("unknown target type")
    target = _bounded_text(target, "target", 160)
    if target_type in CANONICAL_TARGETS:
        return normalize_seed(target_type, target)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@/ -]{0,159}", target):
        raise ValueError("unsupported untrusted target identifier")
    return target


def create_plan(case_id: str, query: str, target_type: str, target: str, *,
                max_domains: int = 5) -> dict[str, Any]:
    """Create a purely advisory plan. No source/model/network operation occurs."""
    case_id = _valid_case(case_id)
    query = _bounded_text(query, "query", MAX_QUERY, 8)
    target = _target(target_type, target)
    if type(max_domains) is not int or not 1 <= max_domains <= MAX_TASKS:
        raise ValueError("max_domains must be 1-8")
    normalized = query.casefold()
    if SUSPICIOUS.search(query):
        # User query can be studied but not turned into executable instructions.
        raise ValueError("instruction-like input needs an analyst rewrite")
    scored = []
    for domain, phrases in DOMAINS.items():
        matched = [phrase for phrase in phrases if _words(normalized, phrase)]
        if matched:
            scored.append((domain, len(matched), matched))
    default = DEFAULT_DOMAIN[target_type]
    if not any(domain == default for domain, _, _ in scored):
        scored.append((default, 0, ["typed_target"]))
    scored.sort(key=lambda item: (-item[1], item[0]))
    selected = scored[:max_domains]
    # Never append generic OSINT at the expense of a specifically requested discipline.
    tasks = []
    seed = target_type + ":" + target
    for ordinal, (domain, score, signals) in enumerate(selected):
        subquery = f"Within authorized records for {seed}, investigate {domain}: {query}"
        task_id = "query-task-" + _hash([case_id, seed, domain, query])[:16]
        tasks.append({
            "task_id": task_id, "department": domain, "team_lead": domain.lower() + "_lead",
            "query": subquery, "target_entity": seed,
            "routing_signals": signals, "routing_score": score,
            "stage": "PLANNED", "execution": "NOT_EXECUTED",
            "required_evidence": ["source_id", "source_uri", "retrieved_at",
                                  "content", "original_source_id", "ownership_group", "typed_facts"],
            "authorization_required": True, "approved_connector_ids": [],
        })
    plan = {
        "schema": VERSION, "case_id": case_id, "query": query,
        "target_type": target_type, "target": target,
        "seed": seed, "tasks": tasks,
        "policy": {
            "live_collection": False, "automatic_pivots": False,
            "automatic_identity_merge": False, "autonomous_decisions": False,
            "minimum_independent_source_groups": 2,
            "human_review_before_release": True,
        },
        "handoff": {
            "canonical_service": "traceatlas.workforce.service.WorkforceService",
            "canonical_collector": "traceatlas.workforce.pipeline.InvestigationPipeline",
            "approval": "existing workforce authorization and immutable approved task",
            "capability_discovery": "traceatlas.workforce.source_router.SourceRouter",
            "note": "Domain labels are advisory; only existing approved connectors may execute.",
        },
        "limitations": (["Sensitive target: analyst/legal review required; no personal tracking."] if
                        target_type in SENSITIVE_TARGETS else []),
    }
    plan["plan_digest"] = _hash(plan)
    return plan


def _check_plan(plan: Any) -> None:
    if not isinstance(plan, dict) or plan.get("schema") != VERSION:
        raise ValueError("unsupported query plan")
    supplied_hash = plan.get("plan_digest")
    unsigned = {k: v for k, v in plan.items() if k != "plan_digest"}
    if supplied_hash != _hash(unsigned):
        raise ValueError("plan digest mismatch")
    if len(plan.get("tasks", [])) > MAX_TASKS or not plan["tasks"]:
        raise ValueError("invalid task inventory")
    if len({t["task_id"] for t in plan["tasks"]}) != len(plan["tasks"]):
        raise ValueError("duplicate task ID")
    if plan["policy"].get("live_collection") is not False:
        raise ValueError("live collection cannot be enabled by query plan")


def _decode_results(plan: dict[str, Any], results: Any):
    if not isinstance(results, list) or len(results) > MAX_RESULTS:
        raise ValueError("results must be a bounded array of at most 32 envelopes")
    allowed = {t["task_id"] for t in plan["tasks"]}
    seen_tasks = set()
    docs: dict[str, SourceDocument] = {}
    outcomes = []
    withheld = []
    total_bytes = 0
    for envelope in results:
        if not isinstance(envelope, dict) or set(envelope) != {"task_id", "case_id", "status", "documents"}:
            raise ValueError("invalid specialist result envelope")
        task_id = envelope["task_id"]
        if task_id not in allowed or task_id in seen_tasks or envelope["case_id"] != plan["case_id"]:
            raise ValueError("cross-case, duplicate or unknown specialist result")
        seen_tasks.add(task_id)
        state = envelope["status"]
        if state not in VALID_RESULT_STATES:
            raise ValueError("unknown employee status")
        raw_documents = envelope["documents"]
        if not isinstance(raw_documents, list) or len(raw_documents) > 8:
            raise ValueError("specialist returned an invalid document list")
        if state in {"blocked", "failed", "unavailable"} and raw_documents:
            raise ValueError("failed or blocked task cannot claim new evidence")
        outcomes.append({"task_id": task_id, "status": state, "documents": len(raw_documents)})
        for raw in raw_documents:
            doc = SourceDocument.from_dict(raw)
            total_bytes += len(doc.content.encode("utf-8"))
            if total_bytes > MAX_DOCUMENT_TOTAL_BYTES or len(docs) >= MAX_DOCUMENTS and doc.source_id not in docs:
                raise ValueError("source evidence exceeds case bounds")
            old = docs.get(doc.source_id)
            if old is not None and _hash(old.to_dict()) != _hash(doc.to_dict()):
                raise ValueError("same source ID contains conflicting source documents")
            docs[doc.source_id] = doc
    return docs, outcomes, withheld


def _grounded(doc: SourceDocument, fact: StructuredFact) -> bool:
    """Reuse canonical source-document serialization rather than substring truth tests."""
    try:
        payload = json.loads(doc.content)
    except (ValueError, TypeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema") == "traceatlas-structured-source/v1"
        and isinstance(payload.get("facts"), list)
        and len(payload["facts"]) <= 100
        and fact.to_dict() in payload["facts"]
    )


def fuse(plan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Cross-check submitted specialist results; outputs candidates, NEVER approved facts."""
    _check_plan(plan)
    documents, outcomes, withheld = _decode_results(plan, results)
    lineage = SourceIndependenceEngine().group([
        SourceRecord(source_id=d.source_id, uri=d.source_uri, content=d.content,
                     original_source_id=d.original_source_id, ownership_group=d.ownership_group)
        for d in documents.values()
    ])
    groups = {line.source_id: line.independence_group for line in lineage}
    seed = plan["seed"]
    rows = []
    for doc in documents.values():
        for fact in doc.facts:
            if fact.subject != seed:
                withheld.append({"source_id": doc.source_id, "reason": "out_of_scope_subject"})
                continue
            if SUSPICIOUS.search(fact.value) or SUSPICIOUS.search(doc.content):
                withheld.append({"source_id": doc.source_id, "reason": "instruction_like_source_content"})
                continue
            if not _grounded(doc, fact):
                withheld.append({"source_id": doc.source_id, "reason": "unvalidated_semantic_extraction"})
                continue
            rows.append({
                "fact": fact, "source_id": doc.source_id,
                "source_group": groups[doc.source_id],
                "evidence_id": "evidence-" + _hash([doc.source_id, doc.content])[:24],
                "content_sha256": hashlib.sha256(doc.content.encode("utf-8")).hexdigest(),
                "source_uri": doc.source_uri, "retrieved_at": doc.retrieved_at,
            })
    # The canonical contradiction predicate is intentionally narrow and temporal.
    conflicts: dict[int, set[int]] = defaultdict(set)
    for i, left in enumerate(rows):
        for j in range(i + 1, len(rows)):
            right = rows[j]
            if contradicts(left["fact"], right["fact"]):
                conflicts[i].add(j)
                conflicts[j].add(i)
    grouped: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for i, row in enumerate(rows):
        fact = row["fact"]
        grouped[(fact.subject, fact.predicate, fact.value)].append(i)
    candidates = []
    for key, indices in sorted(grouped.items()):
        supporting = [rows[i] for i in indices]
        independent = sorted({r["source_group"] for r in supporting})
        contradicting = sorted({rows[j]["evidence_id"] for i in indices for j in conflicts.get(i, ())})
        evidence = sorted({r["evidence_id"] for r in supporting})
        candidate_status = ("DISPUTED" if contradicting else
                            "CORROBORATED_CANDIDATE" if len(independent) >= 2 else
                            "SINGLE_SOURCE_CANDIDATE")
        candidates.append({
            "claim_id": "claim-" + _hash(key)[:24],
            "subject": key[0], "predicate": key[1], "value": key[2],
            "status": candidate_status,
            "source_ids": sorted({r["source_id"] for r in supporting}),
            "independent_source_groups": independent,
            "evidence_ids": evidence, "contradicting_evidence_ids": contradicting,
            "validity_intervals": sorted({(r["fact"].valid_from, r["fact"].valid_to or "") for r in supporting}),
            "review_required": True,
            "limitations": ["Provenance/corroboration is not independent proof of real-world truth.",
                            "Canonical approval requires the existing EvidenceStore and VerificationEngine."],
        })
    completed = {o["task_id"] for o in outcomes if o["status"] == "completed"}
    pending = [task["department"] for task in plan["tasks"] if task["task_id"] not in completed]
    return {
        "schema": "query-fusion/v1", "case_id": plan["case_id"],
        "plan_digest": plan["plan_digest"], "mode": "OFFLINE_SOURCE_ASSERTION_REVIEW",
        "employee_outcomes": outcomes, "candidate_claims": candidates,
        "approved_facts": [], "human_review_required": True,
        "withheld": withheld, "unresolved_departments": pending,
        "summary": {
            "submitted_sources": len(documents), "grounded_observations": len(rows),
            "corroborated_candidates": sum(c["status"] == "CORROBORATED_CANDIDATE" for c in candidates),
            "disputed_candidates": sum(c["status"] == "DISPUTED" for c in candidates),
            "verified_facts": 0,
        },
        "next_actions": [
            "Verify raw evidence bytes and acquisition IDs using canonical EvidenceStore.",
            "Apply canonical VerificationEngine to any material candidate before promotion.",
            "Adjudicate contradictions and source dependence with a human analyst.",
            "Do not represent missing or unavailable source results as negative findings.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TraceAtlas offline fact-first query employee (no network)")
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("plan", help="Route a query into nonexecuting, evidence-bounded work orders")
    p.add_argument("--case", required=True)
    p.add_argument("--query", required=True)
    p.add_argument("--target-type", required=True, choices=sorted(DEFAULT_DOMAIN))
    p.add_argument("--target", required=True)
    p.add_argument("--max-domains", type=int, default=5)
    f = sub.add_parser("fuse", help="Review existing typed specialist documents offline")
    f.add_argument("--input", type=Path, required=True, help="JSON containing plan and results")
    args = parser.parse_args(argv)
    try:
        if args.action == "plan":
            data = create_plan(args.case, args.query, args.target_type, args.target, max_domains=args.max_domains)
        else:
            path = args.input
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DOCUMENT_TOTAL_BYTES + 256 * 1024:
                raise ValueError("fusion input must be a bounded regular JSON file")
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or set(payload) != {"plan", "results"}:
                raise ValueError("fusion input requires exactly plan and results")
            data = fuse(payload["plan"], payload["results"])
        print(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"Query employee blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
