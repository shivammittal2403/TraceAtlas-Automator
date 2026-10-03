"""Case-scoped cache references and source telemetry, backed by canonical SQLite."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .contracts import EvidenceObject
from .documents import SourceDocument

SCHEMA = """
CREATE TABLE IF NOT EXISTS source_fabric_events (
 id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 task_id TEXT NOT NULL, source_id TEXT NOT NULL, created_at TEXT NOT NULL, event_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS source_fabric_events_source ON source_fabric_events(source_id,id);
CREATE TABLE IF NOT EXISTS source_fabric_cache (
 cache_key TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 source_id TEXT NOT NULL, retrieved_at TEXT NOT NULL, evidence_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_fabric_plans (
 task_id TEXT PRIMARY KEY REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
 plan_json TEXT NOT NULL, plan_digest TEXT NOT NULL
);
"""


def stable_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class SourceState:
    def __init__(self, store):
        self.store = store
        self.conn = store.db.conn
        self.conn.executescript(SCHEMA)

    def save_plan(self, task, plan):
        digest = stable_digest(plan)
        if 'source-plan:' + digest not in task.constraints:
            raise ValueError('source plan is not bound into task authority')
        with self.conn:
            self.conn.execute('INSERT INTO source_fabric_plans VALUES (?,?,?)',
                              (task.task_id, json.dumps(plan, sort_keys=True), digest))

    def plan(self, task):
        row = self.conn.execute('SELECT plan_json, plan_digest FROM source_fabric_plans WHERE task_id=?', (task.task_id,)).fetchone()
        if not row:
            if any(c.startswith('source-plan:') for c in task.constraints):
                raise ValueError('bound source plan is missing')
            return None
        plan = json.loads(row[0])
        if stable_digest(plan) != row[1] or 'source-plan:' + row[1] not in task.constraints:
            raise ValueError('bound source plan was altered')
        return plan

    @staticmethod
    def cache_key(task, source_id, parser_version):
        return stable_digest([task.case_id, task.authorization_context_id, task.policy_digest,
                              source_id, task.target_entities, parser_version])

    def cached(self, task, source_id, parser_version, ttl_seconds):
        try:
            return self._cached(task, source_id, parser_version, ttl_seconds)
        except (ValueError, KeyError, TypeError, OSError):
            # This derived index has no evidentiary authority. Corruption is a
            # cache miss; a new acquisition still requires current authorization.
            return None

    def _cached(self, task, source_id, parser_version, ttl_seconds):
        if not ttl_seconds:
            return None
        key = self.cache_key(task, source_id, parser_version)
        row = self.conn.execute('SELECT case_id,retrieved_at,evidence_json FROM source_fabric_cache WHERE cache_key=?', (key,)).fetchone()
        if not row or row[0] != task.case_id:
            return None
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(row[1])).total_seconds()
        if not 0 <= age <= ttl_seconds:
            return None
        references = json.loads(row[2])
        if not isinstance(references, list) or not 1 <= len(references) <= 2:
            return None
        items = tuple(EvidenceObject.from_dict(r) for r in references)
        documents = []
        for item in items:
            if item.case_id != task.case_id or not self.store.verify_evidence(item):
                return None
            payload = json.loads(Path(item.raw_artifact_pointer).read_text(encoding='utf-8'))
            if payload['case_id'] != task.case_id:
                return None
            documents.append(SourceDocument.from_dict(payload['document']))
        allowed_sources = {source_id, 'rdap_bootstrap'} if source_id == 'rdap' else {source_id}
        if any(d.source_id not in allowed_sources or any(f.subject not in task.target_entities for f in d.facts) for d in documents):
            return None
        if not any(d.source_id == source_id for d in documents):
            return None
        return tuple(documents)

    def cache(self, task, source_id, parser_version, evidence):
        items = tuple(e for e in evidence if e.source_id == source_id or (source_id == 'rdap' and e.source_id == 'rdap_bootstrap'))
        if not items or not any(e.source_id == source_id for e in items):
            return
        key = self.cache_key(task, source_id, parser_version)
        with self.conn:
            self.conn.execute('INSERT OR REPLACE INTO source_fabric_cache VALUES (?,?,?,?,?)',
                (key, task.case_id, source_id, min(e.retrieved_at for e in items), json.dumps([e.to_dict() for e in items])))
            # Bounded derived index; deleting cache references never deletes evidence.
            self.conn.execute('DELETE FROM source_fabric_cache WHERE case_id=? AND cache_key NOT IN '
                '(SELECT cache_key FROM source_fabric_cache WHERE case_id=? ORDER BY retrieved_at DESC LIMIT 32)',
                (task.case_id, task.case_id))

    def record(self, task, source, outcome):
        allowed = {'status', 'reason', 'attempts', 'latency_ms', 'cache_hit', 'observations', 'estimated_cost', 'actual_cost'}
        safe = {k: v for k, v in outcome.items() if k in allowed}
        with self.conn:
            self.conn.execute('INSERT INTO source_fabric_events(case_id,task_id,source_id,created_at,event_json) VALUES (?,?,?,?,?)',
                (task.case_id, task.task_id, source, datetime.now(timezone.utc).isoformat(), json.dumps(safe, allow_nan=False)))

    def health(self, source):
        rows = self.conn.execute('SELECT created_at,event_json FROM source_fabric_events WHERE source_id=? ORDER BY id DESC LIMIT 100', (source,)).fetchall()
        events = [(r[0], json.loads(r[1])) for r in rows]
        requests = [(at, e) for at, e in events if e.get('attempts', 0) > 0]
        state, last_success, last_failure, failures = 'UNKNOWN', None, None, 0
        for at, e in requests:
            if e['status'] == 'captured':
                last_success = last_success or at
            else:
                last_failure = last_failure or at
        for at, e in requests:
            if e['status'] == 'captured':
                break
            failures += 1
        if requests:
            reason = requests[0][1].get('reason', '')
            state = 'HEALTHY' if requests[0][1]['status'] == 'captured' else (
                'RATE_LIMITED' if reason == 'provider_rate_limited' else
                'AUTH_FAILURE' if reason == 'provider_authentication_rejected' else
                'SCHEMA_CHANGED' if reason in {'provider_schema_mismatch', 'provider_invalid_json', 'provider_target_mismatch'} else
                'DOWN' if failures >= 3 else 'DEGRADED')
        samples = len(requests)
        latencies = sorted(e.get('latency_ms', 0) for _, e in requests)
        return {'state': state, 'samples': samples, 'last_success': last_success, 'last_failure': last_failure,
                'consecutive_failures': failures, 'success_rate': sum(e['status'] == 'captured' for _, e in requests) / samples if samples else None,
                'mean_latency_ms': sum(e.get('latency_ms', 0) for _, e in requests) / samples if samples else None,
                'cache_hits': sum(e.get('cache_hit', False) for _, e in events),
                'p95_latency_ms': latencies[max(0, (95 * samples + 99) // 100 - 1)] if samples else None,
                'error_rate': sum(e['status'] != 'captured' for _, e in requests) / samples if samples else None,
                'rate_limit_incidents': sum(e.get('reason') in {'provider_rate_limited', 'provider_local_rate_limited'} for _, e in events),
                'estimated_cost_usd': round(sum(e.get('estimated_cost', 0) for _, e in events), 8),
                'actual_cost_usd': None if requests else 0, 'cost_variance': None,
                'sample_window': 'latest-100-local-events-not-production-qualification',
                'schema_errors': sum(e.get('reason') in {'provider_schema_mismatch', 'provider_invalid_json'} for _, e in requests)}
