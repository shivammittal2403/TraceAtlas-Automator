"""Evidence-first investigation slice using existing policy, bytes and transport owners.

One bounded collection cycle is followed by deterministic analysis and a human
review stop. No model, external action, identity merge or network pivot is hidden
inside analysis or replay.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from ..evidence import EvidenceStore
from ..intelligence.ai import detect_instruction_injection
from ..intelligence.hub import ConnectorNotConfigured
from ..intelligence.provider import ProviderError, ResilientJSONClient, _validate_shape
from ..intelligence.transport import request, request_loopback_search
from ..intelligence.rdap import lookup as rdap_lookup, validate_response as validate_rdap_response
from .contracts import Claim, CostRecord, EvidenceObject, Observation, ResultEnvelope, SemanticClass, TraceSpan
from .documents import DOCUMENT_SCHEMA, MAX_DOCUMENTS, SourceDocument, StructuredFact
from .contradictions import SINGLE_VALUE_PREDICATES as SINGLE_VALUES, contradicts
from .graph import GraphEdge, GraphNode, TemporalClaimGraph
from .lineage import SourceIndependenceEngine, SourceRecord
from .service import WorkforceService
from .verification import VerificationEngine
from .live_sources import SOURCE_TOOLS, SEARCH_SOURCES, select_sources, request_spec
from .normalization import live_facts as _live_facts

WORKFLOW_VERSION = "evidence-investigation/1.3.0"
PARSER_VERSION = "structured-fact/4"
POLICY_VERSION = "bounded-readonly/1"


from .source_sdk import CollectionStopped
from .source_state import SourceState
from .source_gateway import SourceGateway


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(prefix, value):
    return prefix + "-" + digest(value)[:24]


def _overlap(a, b):
    return a.valid_from <= (b.valid_to or "9999") and b.valid_from <= (a.valid_to or "9999")


def _grounded(document, fact):
    """Check extraction against a deterministic schema, never a substring match."""
    try:
        payload = json.loads(document.content)
        if document.source_id in SOURCE_TOOLS:
            extracted = _live_facts(document.source_id, fact.subject, payload, document.retrieved_at)
            return fact in extracted
        if isinstance(payload, dict) and payload.get("schema") == "traceatlas-structured-source/v1":
            rows = payload.get("facts")
            return isinstance(rows, list) and len(rows) <= 100 and fact.to_dict() in rows
    except (ValueError, KeyError, TypeError, ProviderError):
        pass
    return False


def plan_sources(task, *, live=False):
    kind, value = task.target_entities[0].split(":", 1)
    bound = tuple(row.split(":", 1)[1] for row in task.constraints if row.startswith("live-source:"))
    # Legacy approvals never acquire newly added sources or environment-based search.
    legacy = ["dns", "rdap", "wayback"] if kind == "domain" else ["rdap", "internetdb"] if kind == "ip" else []
    if kind == "ip" and ipaddress.ip_address(value).version == 6:
        legacy.remove("internetdb")
    sources = list(select_sources(kind, value, bound)) if bound else [] if any(c.startswith("source-plan:") for c in task.constraints) else legacy
    search = next((source for source in sources if source in SEARCH_SOURCES), None)
    return {"workflow_version": WORKFLOW_VERSION, "seed": task.target_entities[0],
            "mode": "live" if live else "approved-records", "sources": sources if live else [],
            "selection_basis": "typed seed and implemented fixed-host connector contracts",
            "maximum_documents": min(MAX_DOCUMENTS, task.budget.tool_calls),
            "query_intents": [{"category": "public-web-leads", "query": '"' + value + '"',
                               "state": "planned" if live and search else "not-executed",
                               "provider": search if live else None,
                               "reason": "approved-source-selection" if live and search else "no-approved-search-provider-bound"}],
            "automatic_pivots": False}




class InvestigationPipeline:
    def __init__(self, service: WorkforceService, workspace: Path, *, requester=request, search_requester=request_loopback_search):
        self.service = service
        self.store = service.store
        self.workspace = workspace
        self.requester = requester
        self.search_requester = search_requester

    def run(self, task_id, *, documents=(), live=False, authorized=False):
        if live and documents:
            raise ValueError("choose live collection or approved records")
        supplied = tuple(documents)
        if len(supplied) > MAX_DOCUMENTS or any(not isinstance(d, SourceDocument) for d in supplied):
            raise ValueError("collection requires at most eight typed source documents")
        if len({d.source_id for d in supplied}) != len(supplied):
            raise ValueError("collection source IDs must be unique")
        row = self.store.task(task_id)
        if row["status"] == "completed":
            if not authorized or not self.service._enabled():
                raise ValueError("execution requires explicit enabled authorization")
            return self.store.product(task_id)
        task = row["envelope"]
        if any(f.subject not in task.target_entities for doc in supplied for f in doc.facts):
            raise ValueError("source document contains an out-of-scope subject")
        product = None

        def runner(task, employee):
            nonlocal product
            started = time.monotonic()
            context = self.store.authorization(task.authorization_context_id)
            plan = plan_sources(task, live=live)
            source_state = SourceState(self.store)
            capability_plan = source_state.plan(task)
            if capability_plan is not None:
                plan['capability_plan'] = capability_plan
                plan['selection_basis'] = 'approved capability routing with explicit alternatives and rejection reasons'
            gateway_result = None
            collected, outcomes, spans, tools = [], [], [], []
            network_attempts = 0
            def check(tool):
                try:
                    self.service._check_authority(context, task)
                except ValueError as exc:
                    raise CollectionStopped("collection authority is no longer valid") from exc
                if not self.service._enabled():
                    raise CollectionStopped("workforce kill switch stopped collection")
                if tool not in context.allowed_tools or tool not in employee.allowed_tools:
                    raise ValueError("collection tool is outside effective authority")
                if "request_collection" not in context.allowed_actions or "request_collection" not in employee.allowed_actions:
                    raise ValueError("collection action is outside effective authority")
                # Reserve bounded time for evidence capture, analysis and the final transaction.
                reserve = min(5.0, task.budget.runtime_seconds * 0.1)
                return min(30.0, task.budget.runtime_seconds - reserve - (time.monotonic() - started),
                           (datetime.fromisoformat(task.deadline) - datetime.now(timezone.utc)).total_seconds())
            if not live:
                if supplied and check("evidence.retrieve") <= 0:
                    raise ValueError("collection runtime budget exhausted")
                if supplied and task.budget.tool_calls < 1:
                    raise ValueError("collection tool-call budget exhausted")
                if supplied:
                    tools.append("evidence.retrieve")
                collected.extend(supplied)
                outcomes.extend({"source_id": d.source_id, "status": "captured", "mode": "approved-records", "attempts": 0} for d in supplied)
            else:
                gateway_plan = capability_plan or {'sources': plan['sources']}
                gateway_result = SourceGateway(source_state, self.requester, self.search_requester, PARSER_VERSION).collect(
                    task, employee, gateway_plan, check, capture=lambda doc: self.store.capture_document(task, doc, self.workspace))
                collected.extend(gateway_result['documents'])
                outcomes.extend(gateway_result['outcomes'])
                network_attempts = gateway_result['network_attempts']
                tools.extend(gateway_result['tools'])
                for outcome in outcomes:
                    for intent in plan['query_intents']:
                        if intent.get('provider') == outcome['source_id']:
                            intent.update(state='executed' if outcome['status'] == 'captured' else outcome['status'],
                                          result_count=outcome.get('observations', 0))
                            if outcome.get('reason'): intent['reason'] = outcome['reason']
                    if outcome.get('started_at'):
                        spans.append(TraceSpan(identifier('span', [task.task_id, outcome['source_id']]), task.trace_id, None,
                            SOURCE_TOOLS[outcome['source_id']], outcome['status'], outcome['started_at'], now(), outcome['latency_ms'], ()))
            evidence = gateway_result['evidence'] if gateway_result else tuple(self.store.capture_document(task, doc, self.workspace) for doc in collected)
            if gateway_result:
                for result_row in gateway_result['results']:
                    item = next((e for e in evidence if e.source_id == result_row['source_id']), None)
                    result_row['raw_evidence_id'] = item.evidence_id if item else None
                    if item and result_row['source_metadata']['state'] == 'captured':
                        source_state.cache(task, result_row['source_id'], PARSER_VERSION, evidence)
            analysis = self.analyze(task, tuple(collected), evidence, outcomes)
            if gateway_result:
                for result_row in gateway_result['results']:
                    evidence_id = result_row['raw_evidence_id']
                    result_row['observations'] = [o for o in analysis['observations'] if o['evidence_id'] == evidence_id]
                    result_row['candidate_entities'] = [n for n in analysis['graph']['nodes'] if evidence_id in n['evidence_ids']]
                    result_row['candidate_relationships'] = [e for e in analysis['graph']['edges'] if evidence_id in e['evidence_ids']]
            for observation in analysis["observations"]:
                self.store.record_observation(task.case_id, Observation.from_dict(observation))
            for lineage in analysis["source_lineage"]:
                from .contracts import SourceLineage
                # Snapshot is canonical; this table is a current derived index.
                self.store.record_lineage(task.case_id, SourceLineage.from_dict(lineage))
            for decision in analysis["verification"]:
                from .contracts import VerificationDecision
                self.store.record_verification(task.case_id, VerificationDecision.from_dict({**decision, "decided_at": now()}))
            failed = any(r["status"] not in {"captured", "not_needed"} for r in outcomes)
            stop = "source_exhausted" if not collected else "human_review_required"
            result = ResultEnvelope(
                schema_version="1.0", task_id=task.task_id, employee_id=employee.employee_id,
                observations=tuple(Observation.from_dict(r) for r in analysis["observations"]),
                evidence_ids=tuple(e.evidence_id for e in evidence), entities=tuple(r["node_id"] for r in analysis["graph"]["nodes"]),
                relationships=tuple(r["edge_id"] for r in analysis["graph"]["edges"]),
                claims=tuple(Claim.from_dict(r) for r in analysis["claims"]), hypotheses=(),
                contradictions=tuple(r["claim_id"] for r in analysis["verification"] if r["status"] == "DISPUTED"),
                uncertainties=("structured_assertions_not_identity_or_causation",), confidence_basis=("deterministic-evidence-verification",),
                source_independence=tuple(sorted({r["independence_group"] for r in analysis["source_lineage"]})),
                information_gaps=tuple(analysis["information_gaps"]), recommended_next_actions=tuple(r["action_id"] for r in analysis["next_actions"]),
                cost=CostRecord("traceatlas", "deterministic-no-model", 0, 0, gateway_result["estimated_cost"] if gateway_result else 0, None if live else 0, "USD" if live else "NONE"),
                latency_ms=int((time.monotonic()-started)*1000), model_used="deterministic-no-model",
                tool_calls=tuple(tools), execution_trace=tuple(spans), stop_reason=stop, completed_at=now())
            product = {"schema": "traceatlas-investigation-product/v1", "task_id": task.task_id, "case_id": task.case_id,
                       "objective": task.objective, "authorization": context.to_dict(), "plan": plan,
                       "state": "PARTIAL" if failed or not analysis["claims"] else "HUMAN_REVIEW",
                       "phase_history": ["AUTHORIZED", "PLANNING", "COLLECTING", "NORMALIZING", "RESOLVING", "ANALYZING", "VERIFYING", "GAP_ANALYSIS", "HUMAN_REVIEW"],
                       "analysis": analysis, "result": result.to_dict(),
                       "replay_manifest": {"schema": "traceatlas-replay/v1", "workflow_version": WORKFLOW_VERSION,
                           "parser_version": PARSER_VERSION, "policy_version": POLICY_VERSION,
                           "worker_version": employee.version, "envelope_digest": row["envelope_digest"],
                           "connector_versions": {d.source_id: 2 if d.source_id == "rdap" else 1 for d in collected},
                           "source_timestamps": {d.source_id: d.retrieved_at for d in collected},
                           "dataset_versions": {}, "trace_id": task.trace_id,
                           "execution_parameters": {"seed": task.target_entities[0], "budget": task.budget.to_dict()},
                           "model": "deterministic-no-model", "prompt_version": None,
                           "source_outcomes": outcomes, "evidence": [e.to_dict() for e in evidence],
                           "analysis_digest": digest(analysis), "requires_network": False},
                       "report_status": "DRAFT_REQUIRES_HUMAN_RELEASE", "network_attempts": network_attempts,
                       "source_costs": {"status": "not-measured" if live else "no-network-calls", "actual_cost": None if live else 0,
                                        "limitation": "Request count is bounded; provider billing and entitlements require operator qualification."}}
            if gateway_result:
                product['source_results'] = gateway_result['results']
                product['source_costs'].update(estimated_cost=gateway_result['estimated_cost'], currency='USD',
                    remaining_estimated_budget=round(task.budget.amount - gateway_result['estimated_cost'], 8))
                product['collection_limits'] = gateway_result['concurrency']
            product["report_markdown"] = self.render_report(product)
            product = json.loads(canonical(product))
            # Store only after service-level result checks succeed.
            return result
        self.service.execute(task_id, runner, authorized=authorized, product_factory=lambda: product)
        return product

    def analyze(self, task, documents, evidence, outcomes):
        if len(documents) != len(evidence) or any(e.case_id != task.case_id for e in evidence):
            raise ValueError("analysis input evidence case mismatch")
        observations, fact_rows, gaps = [], [], {"human-report-release-required"}
        capability_plan = SourceState(self.store).plan(task)
        if capability_plan:
            gaps.update('unavailable-capability-' + cap for cap in capability_plan['information_gaps'])
        kind = task.target_entities[0].split(":", 1)[0]
        if kind in {"domain", "ip", "company"} and not any(d.source_id in SEARCH_SOURCES for d in documents):
            gaps.add("no-captured-web-search")
        lineage = SourceIndependenceEngine().group([SourceRecord(d.source_id, d.source_uri, d.content, d.original_source_id, d.ownership_group) for d in documents])
        lineage_index = {r.source_id: r.independence_group for r in lineage}
        injection_sources = set()
        for doc, item in zip(documents, evidence):
            if doc.source_id != item.source_id:
                raise ValueError("source/evidence binding mismatch")
            if detect_instruction_injection(doc.content)["instruction_like_patterns"]:
                injection_sources.add(doc.source_id)
                gaps.add("untrusted-instruction-content")
            for index, fact in enumerate(doc.facts):
                if len(fact_rows) >= 200:
                    gaps.add("structured-fact-limit-reached")
                    continue
                if fact.subject not in task.target_entities:
                    raise ValueError("fact subject outside task scope")
                observation = Observation(identifier("observation", [task.task_id, item.evidence_id, index]), item.evidence_id,
                    item.acquisition_id, f"{fact.subject} {fact.predicate} {fact.value}", SemanticClass.OBSERVATION, fact.valid_from)
                observations.append(observation)
                fact_rows.append((fact, observation, doc))
        grouped = {}
        for fact, observation, doc in fact_rows:
            grouped.setdefault((fact.subject, fact.predicate, fact.value), []).append((fact, observation, doc))
        claims, decisions, timeline, conflicts = [], [], [], []
        graph = TemporalClaimGraph(task.case_id)
        kind, seed = task.target_entities[0].split(":", 1)
        seed_node = identifier("entity", [task.case_id, task.target_entities[0]])
        graph.add_node(GraphNode(seed_node, task.case_id, {"domain":"Domain", "ip":"IP", "person":"Person", "company":"Company",
                                "cve":"Vulnerability", "vulnerability":"Vulnerability", "package":"Software"}[kind], seed,
                                tuple(e.evidence_id for e in evidence), tuple(o.observation_id for o in observations), task.created_at, None, "deterministic-planner"))
        for doc, item in zip(documents, evidence):
            refs = tuple(o.observation_id for o in observations if o.evidence_id == item.evidence_id)
            source_node = identifier("source", [task.task_id, doc.source_id])
            graph.add_node(GraphNode(source_node, task.case_id, "Source", doc.source_uri,
                                     (item.evidence_id,), refs, doc.retrieved_at, None, "source-capture"))
            graph.add_node(GraphNode(item.evidence_id, task.case_id, "Evidence", item.evidence_id,
                                     (item.evidence_id,), refs, doc.retrieved_at, None, "source-capture"))
        for fact, observation, doc in fact_rows:
            graph.add_node(GraphNode(observation.observation_id, task.case_id, "Observation", observation.statement,
                                     (observation.evidence_id,), (observation.observation_id,), fact.valid_from,
                                     fact.valid_to, "structured-fact-parser"))
            for source_node, target_node, relationship in (
                (observation.observation_id, observation.evidence_id, "DERIVED_FROM"),
                (observation.evidence_id, identifier("source", [task.task_id, doc.source_id]), "ACQUIRED_FROM")):
                edge_id = identifier("provenance", [task.task_id, source_node, target_node])
                if edge_id not in graph.edges:
                    graph.add_edge(GraphEdge(edge_id, task.case_id, source_node, target_node, relationship,
                        (observation.evidence_id,), (observation.observation_id,), (lineage_index[doc.source_id],),
                        fact.valid_from, fact.valid_to, "captured-input-provenance", "INCONCLUSIVE", "source-capture"))
        for key, rows in sorted(grouped.items()):
            subject, predicate, value = key
            claim = Claim(identifier("claim", [task.task_id, key]), f"Sources record {subject} {predicate} {value}", SemanticClass.CLAIM,
                          tuple(o.observation_id for _, o, _ in rows), True, None)
            contrary = [(f, o, d) for f, o, d in fact_rows
                        if any(contradicts(f, support_fact) for support_fact, _, _ in rows)]
            adversarial = []
            if predicate == "search_result_url":
                adversarial.append("search_listing_not_content_verification")
            if predicate == "approximate_country":
                adversarial.append("ip_geolocation_not_person_location")
            if any(d.source_id in injection_sources for _, _, d in rows):
                adversarial.append("untrusted_instruction_content")
            if any(f.value not in d.content for f, _, d in rows):
                adversarial.append("structured_value_absent_from_source")
            if any(not _grounded(d, f) for f, _, d in rows):
                adversarial.append("unverified_semantic_extraction")
            # Corroboration has to cover the same time, not two historical versions.
            if len(rows) > 1 and not all(_overlap(a[0], b[0]) for a in rows for b in rows):
                adversarial.append("nonoverlapping_support_times")
            decision = VerificationEngine().verify(claim, tuple(observations), evidence, lineage,
                contradicting_observation_ids=tuple(o.observation_id for _, o, _ in contrary),
                adversarial_gaps=tuple(adversarial), evidence_validator=self.store.verify_evidence)
            decision_dict = decision.to_dict()
            decision_dict.pop("decided_at")  # A replay compares substantive decisions, not wall clocks.
            claims.append(claim.to_dict())
            decisions.append(decision_dict)
            graph.add_node(GraphNode(claim.claim_id, task.case_id, "Claim", claim.statement,
                tuple(dict.fromkeys(o.evidence_id for _, o, _ in rows)), claim.observation_ids,
                min(f.valid_from for f, _, _ in rows), None, "deterministic-claim-builder"))
            gaps.update(decision.information_gaps)
            if contrary:
                conflicts.append({"claim_id": claim.claim_id, "predicate": predicate,
                                  "contrary_observation_ids": [o.observation_id for _, o, _ in contrary]})
            target_id = identifier("entity", [task.case_id, predicate, value])
            node_type = ("IP" if predicate in {"resolves_to", "scan_observed_ip"}
                         else "URL" if predicate in {"archived_url", "indexed_url", "search_result_url"}
                         else "Vulnerability" if predicate in {"vulnerability_id", "vulnerability_alias"}
                         else "Software" if predicate in {"affected_package", "package_version"} else "Document")
            eids = tuple(dict.fromkeys(o.evidence_id for _, o, _ in rows))
            oids = tuple(o.observation_id for _, o, _ in rows)
            if target_id not in graph.nodes:
                graph.add_node(GraphNode(target_id, task.case_id, node_type, value, eids, oids,
                                        min(f.valid_from for f, _, _ in rows), None, "structured-fact-parser"))
            for fact, observation, doc in rows:
                graph.add_edge(GraphEdge(identifier("support", [claim.claim_id, observation.observation_id]),
                    task.case_id, claim.claim_id, observation.observation_id, "CITES",
                    (observation.evidence_id,), (observation.observation_id,), (lineage_index[doc.source_id],),
                    fact.valid_from, fact.valid_to, "structured-source-assertion", decision.status.value,
                    "deterministic-claim-builder"))
                graph.add_edge(GraphEdge(identifier("relationship", [task.task_id, observation.observation_id]),
                    task.case_id, seed_node, target_id, predicate, (observation.evidence_id,),
                    (observation.observation_id,), (lineage_index[doc.source_id],), fact.valid_from, fact.valid_to,
                    "structured-source-assertion", decision.status.value, "structured-fact-parser"))
                timeline.append({"observed_at": fact.valid_from, "valid_to": fact.valid_to,
                                 "retrieved_at": doc.retrieved_at, "observation_id": observation.observation_id,
                                 "evidence_id": observation.evidence_id, "source_id": doc.source_id,
                                 "statement": observation.statement, "verification_status": decision.status.value})
        for outcome in outcomes:
            if outcome["status"] not in {"captured", "not_needed"}:
                gaps.add("source-" + outcome["source_id"] + "-" + outcome.get("reason", "unavailable"))
        if not observations:
            gaps.add("no-source-observations")
        if kind in {"person", "company"}:
            gaps.add("identity-resolution-needs-human-review")
        next_actions = []
        if conflicts:
            next_actions.append({"action_id": "review-contradictions", "priority": 1, "basis": "overlapping conflicting single-valued records", "automatic_execution": False})
        if any(r["status"] != "SUPPORTED" for r in decisions):
            next_actions.append({"action_id": "seek-independent-corroboration", "priority": 2, "basis": "verification gaps", "automatic_execution": False})
        predicates = {fact.predicate for fact, _, _ in fact_rows}
        if kind == "cve":
            if "vulnerability_score" not in predicates:
                next_actions.append({"action_id": "obtain-vulnerability-severity", "priority": 2, "basis": "no normalized severity score was captured", "automatic_execution": False})
            if "exploitation_probability" not in predicates:
                next_actions.append({"action_id": "obtain-exploitation-probability", "priority": 2, "basis": "no dated exploitation probability was captured", "automatic_execution": False})
            next_actions.append({"action_id": "review-authorized-asset-applicability", "priority": 3, "basis": "a public advisory does not prove an authorized asset is affected", "automatic_execution": False})
        elif kind == "vulnerability":
            next_actions.append({"action_id": "review-affected-package-applicability", "priority": 3, "basis": "advisory package metadata requires comparison with authorized inventory", "automatic_execution": False})
        elif kind == "package":
            next_actions.append({"action_id": "compare-version-with-authorized-inventory", "priority": 3, "basis": "registry metadata does not establish an installed version", "automatic_execution": False})
        next_actions.append({"action_id": "human-review-draft", "priority": 4, "basis": "material findings require human release", "automatic_execution": False})
        snapshot = graph.snapshot()
        evidence_sources = {e.evidence_id: e.source_id for e in evidence}
        for edge in snapshot["edges"]:
            edge["source_ids"] = sorted({evidence_sources[eid] for eid in edge["evidence_ids"]})
            edge["verification_status"] = edge["uncertainty"]
            edge["confidence"] = None
        return {"observations": [o.to_dict() for o in observations], "claims": claims, "verification": decisions,
                "source_lineage": [r.to_dict() for r in lineage], "contradictions": conflicts,
                "timeline": sorted(timeline, key=lambda r:(r["observed_at"], r["observation_id"])),
                "graph": snapshot, "information_gaps": sorted(gaps), "next_actions": next_actions,
                "identity_candidates": ([{"seed_id": seed_node, "state": "POSSIBLE_MATCH", "canonical_merge": False,
                    "reason": "case-local seed association does not establish identity"}] if kind in {"person", "company"} else []),
                "metrics": {"claims": len(claims), "observations": len(observations),
                    "citation_coverage": 1.0 if claims else None,
                    "supported_claims": sum(r["status"] == "SUPPORTED" for r in decisions),
                    "released_material_claims": 0, "unsupported_material_claims_released": 0,
                    "independence_groups": len({r.independence_group for r in lineage})},
                "limitations": ["Verification corroborates structured source assertions, not authorship, intent, identity or causation.",
                    "Source ownership and declared lineage may be incomplete; distinct groups do not prove independence.",
                    "Next-action priorities are rules, not a calibrated information-gain score."]}

    @staticmethod
    def render_report(product):
        analysis = product["analysis"]
        esc = html.escape
        lines = ["# TraceAtlas investigation draft", "", "Status: DRAFT — human release required", "",
                 "## Objective", esc(product["objective"]), "", "## Scope and authorization",
                 esc(product["plan"]["seed"]), "Purpose: " + esc(product["authorization"]["lawful_purpose"]), "",
                 "## Methodology", "Bounded capture, typed observations, conservative source lineage, integrity/corroboration review.", "",
                 "## Findings"]
        index = {c["claim_id"]: c for c in analysis["claims"]}
        for d in analysis["verification"]:
            claim = index[d["claim_id"]]
            lines.append(f"- {d['status']}: {esc(claim['statement'])}; observations: {', '.join(claim['observation_ids'])}")
        lines += ["", "## Source collection"]
        for outcome in product["replay_manifest"]["source_outcomes"]:
            lines.append(f"- {outcome['source_id']}: {outcome['status']}; attempts {outcome['attempts']}"
                         + ("; " + outcome["reason"] if "reason" in outcome else ""))
        lines += ["", "## Provider costs", esc(product["source_costs"]["limitation"])]
        lines += ["", "## Evidence"]
        for e in product["replay_manifest"]["evidence"]:
            lines.append(f"- {e['evidence_id']}: {esc(e['source_uri'])}; SHA-256 {e['content_hash']}")
        lines += ["", "## Timeline"]
        lines += [f"- {r['observed_at']}: {esc(r['statement'])}; {r['evidence_id']}" for r in analysis["timeline"]]
        lines += ["", "## Contradictions", canonical(analysis["contradictions"]), "", "## Unknowns and information gaps"]
        lines += ["- " + g for g in analysis["information_gaps"]]
        lines += ["", "## Technical appendix and replay", "Workflow: " + WORKFLOW_VERSION,
                  "Analysis SHA-256: " + product["replay_manifest"]["analysis_digest"],
                  "Model: deterministic-no-model; no prompt or model chain-of-thought exists.", "",
                  "## Limitations", *analysis["limitations"]]
        return "\n".join(lines) + "\n"

    def replay(self, task_id):
        product = self.store.product(task_id)
        manifest = product["replay_manifest"]
        if manifest["workflow_version"] != WORKFLOW_VERSION or manifest["parser_version"] != PARSER_VERSION or manifest["policy_version"] != POLICY_VERSION:
            raise ValueError("replay version is not supported by this runtime")
        task = self.store.task(task_id)
        if manifest["envelope_digest"] != task["envelope_digest"]:
            raise ValueError("replay task binding mismatch")
        valid, _ = EvidenceStore(self.workspace, self.store.db, task["envelope"].case_id).verify_ledger()
        if not valid:
            raise ValueError("replay custody ledger failed integrity validation")
        evidence = tuple(EvidenceObject.from_dict(r) for r in manifest["evidence"])
        documents = []
        for item in evidence:
            if not self.store.verify_evidence(item):
                raise ValueError("replay captured evidence failed integrity validation")
            captured = json.loads(Path(item.raw_artifact_pointer).read_text(encoding="utf-8"))
            if captured["task_id"] != task_id or captured["case_id"] != task["envelope"].case_id or captured["acquisition_id"] != item.acquisition_id:
                raise ValueError("replay acquisition binding mismatch")
            documents.append(SourceDocument.from_dict(captured["document"]))
        analysis = self.analyze(task["envelope"], tuple(documents), evidence, manifest["source_outcomes"])
        if digest(analysis) != manifest["analysis_digest"]:
            raise ValueError("replay analysis digest mismatch")
        return {"task_id": task_id, "verified": True, "requires_network": False,
                "analysis_digest": digest(analysis), "analysis": analysis}
