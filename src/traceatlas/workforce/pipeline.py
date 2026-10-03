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
from .graph import GraphEdge, GraphNode, TemporalClaimGraph
from .lineage import SourceIndependenceEngine, SourceRecord
from .service import WorkforceService
from .verification import VerificationEngine
from .live_sources import SOURCE_TOOLS, SEARCH_SOURCES, select_sources, request_spec

WORKFLOW_VERSION = "evidence-investigation/1.1.0"
PARSER_VERSION = "structured-fact/2"
POLICY_VERSION = "bounded-readonly/1"
SINGLE_VALUES = frozenset({"registry_handle", "registered_name", "registered_country"})


class CollectionStopped(ValueError):
    """Authority/kill changes stop execution, rather than becoming source errors."""


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
    sources = list(select_sources(kind, value, bound)) if bound else legacy
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


def _live_facts(source, seed, data, stamp):
    _validate_shape(source, data)
    facts = []
    def add(predicate, value, at=stamp):
        if isinstance(value, (str, int)) and str(value).strip():
            facts.append(StructuredFact(seed, predicate, str(value), at, at))
    kind, target = seed.split(":", 1)
    if source == "dns":
        questions = data.get("Question", [])
        if not any(isinstance(q, dict) and str(q.get("name", "")).rstrip(".").casefold() == target for q in questions):
            raise ProviderError("provider_target_mismatch")
        if data["Status"] == 0:
            for row in data.get("Answer", [])[:100]:
                if isinstance(row, dict) and row.get("type") in {1, 28} and str(row.get("name", "")).rstrip(".").casefold() == target:
                    add("resolves_to", row.get("data"))
    elif source == "rdap":
        validate_rdap_response(kind, target, data)
        add("registry_handle", data.get("handle"))
        add("registered_name", data.get("ldhName") if kind == "domain" else data.get("name"))
        if kind == "ip":
            add("registered_country", data.get("country"))
        for status in data.get("status", [])[:20]:
            add("registration_status", status)
    elif source == "internetdb":
        if ipaddress.ip_address(data["ip"]) != ipaddress.ip_address(target):
            raise ProviderError("provider_target_mismatch")
        for port in data.get("ports", [])[:100]:
            add("observed_port", port)
    elif source in {"ipwhois", "ipdata", "greynoise"}:
        if ipaddress.ip_address(data["ip"]) != ipaddress.ip_address(target):
            raise ProviderError("provider_target_mismatch")
        if source == "greynoise":
            add("provider_classification", data.get("classification"))
            add("provider_last_seen", data.get("last_seen"))
        else:
            add("approximate_country", data.get("country_code"))
            network = data.get("connection", {}) if source == "ipwhois" else data.get("asn", {})
            if isinstance(network, dict):
                add("network_asn", network.get("asn"))
                add("network_isp", network.get("isp") if source == "ipwhois" else network.get("name"))
    elif source in SEARCH_SOURCES:
        query = data["query"]["original"] if source == "brave" else data["query"]
        if query != '"' + target + '"':
            raise ProviderError("provider_target_mismatch")
        rows = data.get("web", {}).get("results", []) if source == "brave" else data["results"]
        for row in rows[:10]:
            if not isinstance(row, dict):
                raise ProviderError("provider_schema_mismatch")
            url = _public_result_url(row.get("url"))
            if url:
                add("search_result_url", url)
    elif source == "urlscan":
        for row in data["results"]:
            if not isinstance(row, dict):
                raise ProviderError("provider_schema_mismatch")
            page, task = row.get("page", {}), row.get("task", {})
            if not isinstance(page, dict) or not isinstance(task, dict):
                raise ProviderError("provider_schema_mismatch")
            # Missing optional fields yield no assertions; different targets fail closed.
            if kind == "domain" and page.get("domain") is not None:
                if str(page["domain"]).rstrip(".").lower() != target:
                    raise ProviderError("provider_target_mismatch")
            elif kind == "ip" and page.get("ip") is not None:
                if ipaddress.ip_address(page["ip"]) != ipaddress.ip_address(target):
                    raise ProviderError("provider_target_mismatch")
            else:
                continue
            at = task.get("time")
            if not isinstance(at, str):
                continue
            parsed_time = datetime.fromisoformat(at.replace("Z", "+00:00"))
            if parsed_time.tzinfo is None:
                raise ProviderError("provider_schema_mismatch")
            at = parsed_time.astimezone(timezone.utc).isoformat()
            url = _public_result_url(page.get("url"))
            if url and (kind == "ip" or (urlsplit(url).hostname or "").lower() == target):
                add("indexed_url", url, at)
            if page.get("ip"):
                add("scan_observed_ip", str(ipaddress.ip_address(page["ip"])), at)
    elif source == "wayback":
        if not data:
            return ()
        header = data[0]
        if "original" not in header or "timestamp" not in header:
            raise ProviderError("provider_schema_mismatch")
        for row in data[1:101]:
            if not isinstance(row, list) or len(row) != len(header):
                raise ProviderError("provider_schema_mismatch")
            record = dict(zip(header, row))
            host = (urlsplit(record["original"]).hostname or "").lower()
            if host != target and not host.endswith("." + target):
                raise ProviderError("provider_target_mismatch")
            try:
                at = datetime.strptime(record["timestamp"], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
                add("archived_url", record["original"], at)
            except (ValueError, TypeError):
                raise ProviderError("provider_schema_mismatch") from None
    return tuple(facts)


def _public_result_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 500 or any(ord(c) < 33 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
            return None
        try:
            if not ipaddress.ip_address(parsed.hostname).is_global:
                return None
        except ValueError:
            pass
    except ValueError:
        return None
    return value


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
            if live and not plan["sources"]:
                raise ValueError("person/company slices accept approved records; live discovery is not implemented")
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
                unhealthy = {r["source"] for r in self.store.db.connector_health() if r["consecutive_failures"] >= 3}
                kind, value = task.target_entities[0].split(":", 1)
                for source in plan["sources"]:
                    if source not in employee.allowed_sources:
                        raise ValueError("collection source is outside employee authority")
                    tool = SOURCE_TOOLS[source]
                    remaining = check(tool)
                    span_stamp, call_started = now(), time.monotonic()
                    if source in unhealthy or remaining <= 0 or network_attempts >= task.budget.tool_calls:
                        outcomes.append({"source_id": source, "status": "skipped", "reason": "circuit_open" if source in unhealthy else "budget_exhausted", "attempts": 0})
                        for intent in plan["query_intents"]:
                            if intent.get("provider") == source:
                                intent.update(state="skipped", reason=outcomes[-1]["reason"])
                        continue
                    if tool not in tools:
                        tools.append(tool)
                    captured = {}
                    bootstrap_attempts = 0
                    def governed_request(url, headers, timeout):
                        nonlocal network_attempts
                        remaining = check(tool)
                        if network_attempts >= task.budget.tool_calls or remaining <= 0:
                            raise ProviderError("provider_deadline_exceeded")
                        network_attempts += 1
                        dispatch = self.search_requester if source == "searxng" else self.requester
                        status, raw = dispatch(url, headers, min(timeout, remaining))
                        if status == 200:
                            captured[url] = raw
                        return status, raw
                    # Without Retry-After metadata, surface 429 instead of guessing a reset.
                    client = ResilientJSONClient(governed_request, max_body_bytes=400 * 1024, retry_rate_limits=False)
                    attempts_before = network_attempts
                    try:
                        if source == "rdap":
                            def preserve_bootstrap(bootstrap_uri, response):
                                nonlocal bootstrap_attempts
                                bootstrap_attempts = response.attempts
                                collected.append(SourceDocument(DOCUMENT_SCHEMA, "rdap_bootstrap", bootstrap_uri,
                                    now(), captured[bootstrap_uri].decode("utf-8"), (), None, "iana"))
                                outcomes.append({"source_id": "rdap_bootstrap", "status": "captured", "mode": "live", "attempts": response.attempts})
                            url, response = rdap_lookup(client, kind, value, remaining, on_bootstrap=preserve_bootstrap)
                        else:
                            url, headers = request_spec(source, kind, value)
                            response = client.get(source, url, headers, remaining)
                        stamp = now()
                        facts = _live_facts(source, task.target_entities[0], response.data, stamp)
                        # Queries and headers are omitted; captured body bytes remain in content.
                        uri = "urn:traceatlas:provider:searxng:search" if source == "searxng" else url.split("?", 1)[0]
                        doc = SourceDocument(DOCUMENT_SCHEMA, source, uri, stamp,
                                             captured[url].decode("utf-8"), facts, None, source)
                        collected.append(doc)
                        outcomes.append({"source_id": source, "status": "captured", "mode": "live", "attempts": network_attempts-attempts_before-bootstrap_attempts})
                        for intent in plan["query_intents"]:
                            if intent.get("provider") == source:
                                intent["state"] = "executed"
                                intent["result_count"] = len(facts)
                        self.store.db.record_connector_result(source, True)
                    except CollectionStopped:
                        raise
                    except (ProviderError, OSError, ValueError, KeyError, TypeError) as exc:
                        # Stable codes only. Never serialize URL/header/body or exception messages.
                        reason = exc.code if isinstance(exc, (ProviderError, ConnectorNotConfigured)) else "connector_contract_failure"
                        status = "skipped" if isinstance(exc, ConnectorNotConfigured) else "failed"
                        outcomes.append({"source_id": source, "status": status, "reason": reason, "attempts": network_attempts-attempts_before-bootstrap_attempts})
                        for intent in plan["query_intents"]:
                            if intent.get("provider") == source:
                                intent["state"] = status
                                intent["reason"] = reason
                        if status == "failed":
                            self.store.db.record_connector_result(source, False, reason)
                    spans.append(TraceSpan(identifier("span", [task.task_id, source]), task.trace_id, None,
                                           tool, outcomes[-1]["status"], span_stamp, now(),
                                           int((time.monotonic()-call_started)*1000), ()))
            evidence = tuple(self.store.capture_document(task, doc, self.workspace) for doc in collected)
            analysis = self.analyze(task, tuple(collected), evidence, outcomes)
            for observation in analysis["observations"]:
                self.store.record_observation(task.case_id, Observation.from_dict(observation))
            for lineage in analysis["source_lineage"]:
                from .contracts import SourceLineage
                # Snapshot is canonical; this table is a current derived index.
                self.store.record_lineage(task.case_id, SourceLineage.from_dict(lineage))
            for decision in analysis["verification"]:
                from .contracts import VerificationDecision
                self.store.record_verification(task.case_id, VerificationDecision.from_dict({**decision, "decided_at": now()}))
            failed = any(r["status"] != "captured" for r in outcomes)
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
                cost=CostRecord("traceatlas", "deterministic-no-model", 0, 0, 0, None if live else 0, "NONE"),
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
        if not any(d.source_id in SEARCH_SOURCES for d in documents):
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
        graph.add_node(GraphNode(seed_node, task.case_id, {"domain":"Domain", "ip":"IP", "person":"Person", "company":"Company"}[kind], seed,
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
            contrary = [(f, o, d) for f, o, d in fact_rows if f.subject == subject and f.predicate == predicate
                        and f.value != value and predicate in SINGLE_VALUES and any(_overlap(f, r[0]) for r in rows)]
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
            node_type = "IP" if predicate in {"resolves_to", "scan_observed_ip"} else "URL" if predicate in {"archived_url", "indexed_url", "search_result_url"} else "Document"
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
            if outcome["status"] != "captured":
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
        next_actions.append({"action_id": "human-review-draft", "priority": 3, "basis": "material findings require human release", "automatic_execution": False})
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
