"""Bounded local source scheduling; policy and evidence remain owned by workforce."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone

from ..intelligence.provider import ProviderError
from .source_sdk import CollectionStopped, SourceBatch, SourceConnector, SourceResult
from .source_registry import SourceRegistry
from .source_state import stable_digest
from .source_limits import REQUEST_LIMITER

_GLOBAL = threading.BoundedSemaphore(4)
_PROVIDER_LOCK = threading.Lock()
_PROVIDERS = {}


class SourceGateway:
    def __init__(self, state, requester, search_requester, parser_version):
        self.state, self.requester, self.search_requester = state, requester, search_requester
        self.parser_version, self.registry = parser_version, SourceRegistry()

    def collect(self, task, employee, plan, check, capture=None):
        sources = plan['sources']
        if not set(sources).issubset(employee.allowed_sources):
            raise ValueError('collection source is outside employee authority')
        kind, target = task.target_entities[0].split(':', 1)
        entries = {r['source_id']: r for r in plan.get('tasks', [])}
        limits = plan.get('price_ceilings', {})
        lock = threading.Lock()
        attempts, estimated = 0, 0.0
        case_slots = threading.BoundedSemaphore(2)
        outcomes, documents, results, tools, completed, evidence = [], [], [], [], {}, []
        old_unhealthy = {r['source'] for r in self.state.store.db.connector_health() if r['consecutive_failures'] >= 3}

        def execute(source, cached):
            nonlocal attempts, estimated
            connector = SourceConnector(source, registry=self.registry)
            tool = connector.manifest.tool
            check(tool)
            count, spent = 0, 0.0
            stamp, started = datetime.now(timezone.utc).isoformat(), time.monotonic()
            if cached:
                return SourceBatch(cached, 'captured'), {'source_id': source, 'status': 'captured', 'mode': 'cache',
                    'attempts': 0, 'cache_hit': True, 'latency_ms': 0, 'estimated_cost': 0, 'actual_cost': 0, 'started_at': stamp}
            price = limits.get(source, connector.manifest.estimated_request_cost)
            with _PROVIDER_LOCK:
                slot = _PROVIDERS.setdefault(connector.manifest.provider, threading.BoundedSemaphore(connector.manifest.provider_concurrency))

            def request(url, headers, timeout):
                nonlocal attempts, estimated, count, spent
                acquired = []
                try:
                    for semaphore in (case_slots, _GLOBAL, slot):
                        remaining = min(timeout, check(tool))
                        if remaining <= 0 or not semaphore.acquire(timeout=remaining):
                            raise ProviderError('provider_deadline_exceeded')
                        acquired.append(semaphore)
                    remaining = min(timeout, check(tool))
                    with lock:
                        if remaining <= 0 or attempts >= task.budget.tool_calls:
                            raise ProviderError('provider_deadline_exceeded')
                        if price is None:
                            raise ProviderError('source_price_unknown')
                        if estimated + price > task.budget.amount + 1e-12:
                            raise ProviderError('source_cost_boundary')
                        if not REQUEST_LIMITER.reserve(connector.manifest.provider, source):
                            raise ProviderError('provider_local_rate_limited')
                        attempts += 1; count += 1; estimated += price; spent += price
                    dispatch = self.search_requester if source == 'searxng' else self.requester
                    return dispatch(url, headers, remaining)
                finally:
                    for semaphore in reversed(acquired):
                        semaphore.release()
            batch = connector.fetch(kind, target, request, min(30.0, max(0.0, check(tool))))
            outcome = {'source_id': source, 'status': batch.status, 'mode': 'live', 'attempts': count,
                'cache_hit': False, 'latency_ms': int((time.monotonic() - started) * 1000),
                'estimated_cost': spent, 'actual_cost': None if count else 0, 'started_at': stamp}
            if batch.reason: outcome['reason'] = batch.reason
            connector.close()
            return batch, outcome

        cancelled = None
        for wave in (1, 2):
            work = []
            for source in sources:
                entry = entries.get(source, {})
                if entry.get('wave', 1) != wave: continue
                tool = self.registry.get(source).tool
                check(tool)
                prerequisite = entry.get('fallback_for')
                if prerequisite and completed.get(prerequisite) == 'captured':
                    outcomes.append({'source_id': source, 'status': 'not_needed', 'reason': 'primary_succeeded', 'attempts': 0})
                    continue
                health = self.state.health(source)
                if not plan.get('health_probe') and (source in old_unhealthy or health['state'] in {'DOWN', 'AUTH_FAILURE', 'SCHEMA_CHANGED', 'RATE_LIMITED', 'DISABLED'}):
                    outcomes.append({'source_id': source, 'status': 'skipped', 'reason': 'circuit_open', 'attempts': 0})
                    continue
                cached = None if plan.get('health_probe') else self.state.cached(task, source, self.parser_version, self.registry.get(source).cache_ttl_seconds)
                work.append((source, cached))
            # SQLite and evidence writes stay on the caller thread. Workers receive
            # immutable authority and bounded network callbacks, never a DB handle.
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix='traceatlas-source') as pool:
                futures = [(source, pool.submit(execute, source, cached)) for source, cached in work]
                for source, future in futures:
                    try:
                        batch, outcome = future.result()
                    except CollectionStopped as exc:
                        cancelled = exc
                        if capture:
                            evidence.extend(capture(d) for d in getattr(exc, 'documents', ()))
                        continue
                    completed[source] = batch.status
                    documents.extend(batch.documents)
                    if capture:
                        evidence.extend(capture(d) for d in batch.documents)
                    primary = next((d for d in batch.documents if d.source_id == source), None)
                    if any(d.source_id == 'rdap_bootstrap' for d in batch.documents):
                        boot_attempts = 0 if outcome['cache_hit'] else batch.bootstrap_attempts
                        outcome['attempts'] -= boot_attempts
                        outcomes.append({'source_id': 'rdap_bootstrap', 'status': 'captured', 'mode': outcome['mode'], 'attempts': boot_attempts})
                    outcome['observations'] = len(primary.facts) if primary else 0
                    outcomes.append(outcome)
                    tool = self.registry.get(source).tool
                    if tool not in tools: tools.append(tool)
                    result = SourceResult(source, stable_digest([task.task_id, source, task.target_entities]),
                        retrieval_time=primary.retrieved_at if primary else None,
                        observations=[f.to_dict() for f in primary.facts] if primary else [],
                        timestamps=sorted({f.valid_from for f in primary.facts}) if primary else [],
                        source_metadata={'state': outcome['status'], 'cache_hit': outcome['cache_hit'], 'connector_version': self.registry.get(source).contract_version},
                        provenance={'case_id': task.case_id, 'task_id': task.task_id, 'trace_id': task.trace_id,
                                    'authorization_context_id': task.authorization_context_id, 'upstream_group': self.registry.get(source).upstream_group},
                        cost={'estimated': outcome['estimated_cost'], 'actual': outcome['actual_cost'], 'currency': 'USD'},
                        latency_ms=outcome['latency_ms'], errors=[batch.reason] if batch.reason else [])
                    results.append(asdict(result))
                    self.state.record(task, source, outcome)
                    if outcome['attempts'] or source == 'rdap' and batch.documents:
                        self.state.store.db.record_connector_result(source, batch.status == 'captured', batch.reason)
            if cancelled:
                raise cancelled
        return {'documents': tuple(documents), 'outcomes': outcomes, 'results': results,
                'evidence': tuple(evidence),
                'tools': tools, 'network_attempts': attempts, 'estimated_cost': round(estimated, 8),
                'concurrency': {'global': 4, 'case': 2, 'provider': 1, 'scope': 'this-process'}}
