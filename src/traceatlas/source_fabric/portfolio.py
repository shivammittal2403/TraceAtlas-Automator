"""Governed source research, independence and honest portfolio acceptance.

Metadata never grants collection authority. Execution remains in the reviewed
fixed-origin gateways; qualification remains in FabricStore and EvidenceStore.
"""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..policy import PolicyError
from .registry import SOURCES, manifest
from .store import FabricStore

FAMILY_TARGETS = {
    'SOCMINT': 80, 'WEBINT': 65, 'INFRA': 70, 'CTI': 65, 'CORPINT': 55,
    'GEOINT': 50, 'DARKINT': 35, 'IMINT': 35, 'VIDINT': 20, 'AUDINT': 15,
    'DOCINT': 30, 'CODEINT': 30, 'FININT': 35, 'GOVERNMENT': 35, 'SPECIALIZED': 25,
}
TARGETS = {'registered': 650, 'governed': 650, 'capability_mapped': 600, 'implemented': 450,
           'integration_tested': 300, 'live_verified': 200, 'production_qualified': 125}
FIELDS = tuple('source_id provider_name official_name official_documentation official_api_documentation '
               'base_api source_family intelligence_domain capabilities entity_types supported_queries '
               'authentication_type API_key_required OAuth_required free_tier paid_tier pricing_model '
               'rate_limits concurrency_limits countries languages historical_depth freshness pagination '
               'streaming_support webhook_support bulk_export license terms_of_service redistribution_rules '
               'commercial_use_rules PII_risk jurisdiction data_residency source_authority source_independence '
               'reliability expected_information_gain fallback_sources connector_status test_status live_status '
               'qualification_status'.split())
EXTRA_FIELDS = {'dataset_id', 'upstream_datasets', 'publisher', 'aliases', 'unique_value',
                'redundancy_justification', 'documentation_evidence', 'blocked_reason',
                'blocked_evidence', 'quality_factors', 'estimated_cost', 'estimated_latency_ms'}
LIST_FIELDS = {'capabilities', 'entity_types', 'supported_queries', 'countries', 'languages',
               'fallback_sources', 'upstream_datasets', 'aliases'}
URL_FIELDS = {'official_documentation', 'official_api_documentation', 'base_api', 'terms_of_service'}
BOOLEAN_FIELDS = {'API_key_required', 'OAuth_required', 'streaming_support', 'webhook_support', 'bulk_export'}
FACTORS = ('authority', 'reliability', 'freshness', 'independence', 'relevance',
           'historical_depth', 'jurisdiction_fit', 'availability')
PENALTIES = ('cost', 'latency', 'privacy_risk', 'failure_rate', 'duplication')
HEALTH_STATES = {'HEALTHY', 'DEGRADED', 'RATE_LIMITED', 'AUTH_REQUIRED',
                 'SCHEMA_CHANGED', 'OUTAGE', 'DISABLED', 'UNKNOWN'}


def _number(value, name, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise PolicyError('Invalid ' + name)
    if maximum is not None and value > maximum:
        raise PolicyError('Invalid ' + name)
    return value


def validate_record(value):
    """Bound and validate research metadata; unknown fields remain null."""
    if not isinstance(value, dict) or set(value) - set(FIELDS) - EXTRA_FIELDS:
        raise PolicyError('Unknown governed source fields')
    row = {key: None for key in FIELDS}
    row.update(value)
    sid = row['source_id']
    if not isinstance(sid, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,99}', sid):
        raise PolicyError('Invalid source identity')
    for key in ('provider_name', 'official_name'):
        if not isinstance(row[key], str) or not 2 <= len(row[key].strip()) <= 200:
            raise PolicyError('Provider and official source name required')
    if row['source_family'] is not None and (not isinstance(row['source_family'], str) or row['source_family'] not in FAMILY_TARGETS):
        raise PolicyError('Invalid primary source family')
    for key in LIST_FIELDS:
        items = row.get(key)
        if items is not None and (not isinstance(items, list) or len(items) > 200 or
                                 any(not isinstance(item, str) or not 1 <= len(item) <= 300 for item in items) or
                                 len(set(items)) != len(items)):
            raise PolicyError('Invalid list: ' + key)
    for key in BOOLEAN_FIELDS:
        if row[key] is not None and type(row[key]) is not bool:
            raise PolicyError('Invalid boolean: ' + key)
    for key in URL_FIELDS:
        if row[key] is None:
            continue
        if not isinstance(row[key], str) or len(row[key]) > 2000:
            raise PolicyError('Invalid URL: ' + key)
        parsed = urlsplit(row[key])
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise PolicyError('Documentation and API URLs must be HTTPS without credentials')
        if parsed.query:
            raise PolicyError('Source base/documentation URLs must not contain query credentials')
    for key in ('estimated_cost', 'estimated_latency_ms'):
        if row.get(key) is not None:
            _number(row[key], key)
    factors = row.get('quality_factors')
    if factors is not None:
        if not isinstance(factors, dict) or set(factors) - set(FACTORS + PENALTIES):
            raise PolicyError('Unknown quality factor')
        for name, factor in factors.items():
            if factor is not None:
                _number(factor, name, 1)
    for key in ('dataset_id', 'publisher', 'unique_value', 'redundancy_justification', 'blocked_reason'):
        if row.get(key) is not None and (not isinstance(row[key], str) or not 1 <= len(row[key]) <= 4000):
            raise PolicyError('Invalid research text: ' + key)
    for key in ('documentation_evidence', 'blocked_evidence'):
        ref = row.get(key)
        if ref is not None and (not isinstance(ref, dict) or set(ref) != {'case_id', 'sha256'} or
                                not isinstance(ref['case_id'], str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,100}', ref['case_id']) or
                                not isinstance(ref['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', ref['sha256'])):
            raise PolicyError('Invalid canonical evidence reference: ' + key)
    encoded = json.dumps(row, allow_nan=False)
    if len(encoded.encode()) > 64000:
        raise PolicyError('Source record exceeds 64 KiB')
    for key, item in row.items():
        if isinstance(item, str) and (len(item) > 4000 or any(ord(c) < 32 for c in item)):
            raise PolicyError('Unbounded source metadata: ' + key)
    # Research imports can never self-assert implementation or maturity.
    for key in ('connector_status', 'test_status', 'live_status', 'qualification_status'):
        row[key] = 'UNVERIFIED'
    return row


def source_score(factors):
    """Multiplicative heuristic; incomplete research never gets an invented score."""
    if not isinstance(factors, dict) or set(factors) - set(FACTORS + PENALTIES):
        raise PolicyError('Unknown quality factor')
    for key, value in factors.items():
        if value is not None:
            _number(value, key, 1)
    missing = [key for key in FACTORS + PENALTIES if factors.get(key) is None]
    if missing:
        return {'score': None, 'missing_factors': missing, 'calibration': 'UNVALIDATED_HEURISTIC'}
    score = math.prod(factors[key] for key in FACTORS)
    score /= 1 + sum(factors[key] for key in PENALTIES)
    return {'score': score, 'missing_factors': [], 'calibration': 'UNVALIDATED_HEURISTIC'}


def independence_graph(rows):
    """Dataset ancestry is transitive; unknown ancestry shares one conservative group."""
    rows = list(rows)
    parents, edges = {}, []
    def find(node):
        parents.setdefault(node, node)
        if parents[node] != node:
            parents[node] = find(parents[node])
        return parents[node]
    def join(left, right):
        a, b = find(left), find(right)
        if a != b:
            parents[max(a, b)] = min(a, b)
    for row in rows:
        source = 'source:' + row['source_id']
        dataset = 'dataset:' + (row.get('dataset_id') or 'UNKNOWN')
        join(source, dataset)
        edges.append({'from': source, 'to': dataset, 'relationship': 'USES_DATASET'})
        for upstream in row.get('upstream_datasets') or []:
            target = 'dataset:' + upstream
            join(dataset, target)
            edges.append({'from': dataset, 'to': target, 'relationship': 'DERIVED_FROM'})
        edges.append({'from': 'provider:' + row['provider_name'], 'to': dataset, 'relationship': 'PROVIDES'})
        if row.get('publisher'):
            edges.append({'from': dataset, 'to': 'publisher:' + row['publisher'], 'relationship': 'PUBLISHED_BY'})
        if row.get('base_api'):
            edges.append({'from': dataset, 'to': 'api:' + row['base_api'], 'relationship': 'EXPOSED_BY'})
    groups = {}
    for row in rows:
        group = find('source:' + row['source_id'])
        groups.setdefault(group, []).append(row['source_id'])
    return {'edges': edges, 'groups': {k: sorted(v) for k, v in sorted(groups.items())},
            'limitation': 'Groups are conservative metadata clusters, not proof of independent reporting.'}


class Portfolio:
    """Research metadata in the existing case database; no executable plugin imports."""
    def __init__(self, db):
        self.db = db
        self.fabric = FabricStore(db)
        db.conn.execute('''CREATE TABLE IF NOT EXISTS fabric_source_research (
            source_id TEXT PRIMARY KEY, record_json TEXT NOT NULL, updated_at TEXT NOT NULL)''')
        db.conn.commit()

    def import_records(self, values):
        if not isinstance(values, list) or len(values) > 1000:
            raise PolicyError('Research import requires at most 1000 source records')
        rows = [validate_record(value) for value in values]
        if len({r['source_id'] for r in rows}) != len(rows):
            raise PolicyError('Duplicate source IDs in research import')
        # Validate the entire batch before writing; aliases do not inflate counts.
        all_rows = {r['source_id']: r for r in self.research()}
        all_rows.update({r['source_id']: r for r in rows})
        if len(all_rows) > 10000:
            raise PolicyError('Research portfolio exceeds 10000 records')
        identities = {}
        for row in all_rows.values():
            key = (row['provider_name'].casefold().strip(), row['official_name'].casefold().strip())
            if key in identities and identities[key] != row['source_id']:
                raise PolicyError('Duplicate provider/source identity; use aliases')
            identities[key] = row['source_id']
        now = datetime.now(timezone.utc).isoformat()
        with self.db.conn:
            self.db.conn.executemany('''INSERT INTO fabric_source_research VALUES(?,?,?)
                ON CONFLICT(source_id) DO UPDATE SET record_json=excluded.record_json, updated_at=excluded.updated_at''',
                [(r['source_id'], json.dumps(r, allow_nan=False), now) for r in rows])
        return {'research_records_saved': len(rows), 'execution_granted': False, 'maturity_promoted': False}

    def research(self):
        return [json.loads(row[0]) for row in self.db.conn.execute(
            'SELECT record_json FROM fabric_source_research ORDER BY source_id')]

    def records(self):
        research = {r['source_id']: r for r in self.research()}
        states = self.fabric.states()
        rows = []
        for sid in sorted(set(SOURCES) | set(research)):
            existing = manifest(sid) if sid in SOURCES else None
            row = {key: None for key in FIELDS}
            if existing:
                row.update(source_id=sid, provider_name=existing['provider'], official_name=existing['name'],
                           official_documentation=existing['documentation_url'], capabilities=existing['capabilities'],
                           entity_types=existing['entity_types'], authentication_type=existing['auth_type'])
            row.update(research.get(sid, {}))
            row['registered'] = existing is not None
            row['connector_status'] = 'CODED' if existing and existing['execution_path'] else 'NOT_IMPLEMENTED'
            row['qualification_status'] = states.get(sid, existing['maturity_state'] if existing else 'DISCOVERED')
            row['test_status'] = 'UNKNOWN'  # Never infer per-source integration tests from general unit tests.
            row['live_status'] = row['qualification_status'] if sid in states else 'UNVERIFIED'
            row['documentation_verified'] = self._documentation_verified(row)
            row['governed'] = bool(existing and row['documentation_verified'] and row.get('source_family') and
                                   row.get('dataset_id') and (row.get('unique_value') or row.get('redundancy_justification')) and
                                   {'manifest', 'terms', 'license', 'privacy'}.issubset(self.fabric._resolved_checks(sid)))
            rows.append(row)
        return rows

    def _documentation_verified(self, row):
        ref = row.get('documentation_evidence')
        if not isinstance(ref, dict) or set(ref) != {'case_id', 'sha256'}:
            return False
        if not row.get('official_documentation') or not isinstance(ref['sha256'], str):
            return False
        # A metadata claim must resolve to the canonical source review and case artifact.
        reviewed = self.db.conn.execute('''SELECT 1 FROM fabric_reviews WHERE source=? AND check_name='documentation'
            AND case_id=? AND evidence_hash=?''', (row['source_id'], ref['case_id'], ref['sha256'])).fetchone()
        return bool(reviewed and any(e['sha256'] == ref['sha256'] for e in self.db.evidence(ref['case_id'])))

    def report(self):
        rows = self.records()
        registered = [r for r in rows if r['registered']]
        counts = {'registered': len(registered),
                  'governed': sum(r['governed'] for r in registered),
                  'documented': sum(r['documentation_verified'] for r in registered),
                  'capability_mapped': sum(bool(r['capabilities']) for r in registered),
                  'implemented': sum(r['connector_status'] == 'CODED' for r in registered),
                  'integration_tested': None,
                  'live_tested': len({r[0] for r in self.db.conn.execute("SELECT source FROM fabric_executions WHERE mode='live' AND cache_hit=0") if r[0] in SOURCES}),
                  'live_verified': sum(r['qualification_status'] in {'LIVE_VERIFIED', 'PRODUCTION_QUALIFIED'} for r in registered),
                  'production_qualified': sum(r['qualification_status'] == 'PRODUCTION_QUALIFIED' for r in registered),
                  'degraded': sum(r['qualification_status'] == 'DEGRADED' for r in registered),
                  'failed': len({r[0] for r in self.db.conn.execute("SELECT source FROM fabric_executions WHERE mode='live' AND status='failed'")}),
                  'research_only': len(rows) - len(registered)}
        families = {key: sum(r['source_family'] == key and r['governed'] for r in registered)
                    for key in FAMILY_TARGETS}
        gates = {key: {'actual': counts[key], 'target': target,
                      'passed': counts[key] is not None and counts[key] >= target}
                 for key, target in TARGETS.items()}
        return {'schema': 'traceatlas-source-portfolio/v1', 'counts': counts, 'acceptance': gates,
                'family_coverage': {key: {'reviewed': families[key], 'target': target,
                                        'gap': max(0, target-families[key])} for key, target in FAMILY_TARGETS.items()},
                'family_minimum_total': sum(FAMILY_TARGETS.values()),
                'targets_satisfied': all(g['passed'] for g in gates.values()) and all(families[k] >= t for k, t in FAMILY_TARGETS.items()),
                'blocked_integrations': [{'source_id': r['source_id'], 'reason': r['blocked_reason'],
                                          'evidence': r.get('blocked_evidence')} for r in rows if r.get('blocked_reason')],
                'independence': independence_graph(rows),
                'notes': ['Family minima sum to 645; at least five further unique sources are needed for the 650-source portfolio.',
                          'Research imports, aliases, mocks and upstream packages do not increase implementation counts.',
                          'Integration-tested totals remain unknown until source-specific runtime evidence is recorded.']}

    def health_report(self):
        """Measured operational health is independent of qualification maturity."""
        outcomes = {}
        for row in self.db.conn.execute("""SELECT * FROM (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY source ORDER BY started_at DESC) AS position
                FROM fabric_executions WHERE mode='live' AND cache_hit=0)
                WHERE position<=100 ORDER BY started_at DESC"""):
            outcomes.setdefault(row['source'], []).append(dict(row))
        result = []
        states = self.fabric.states()
        for source in sorted(SOURCES):
            calls = outcomes.get(source, [])[:100]
            latest = calls[0] if calls else None
            state = 'UNKNOWN'
            if states.get(source) == 'DISABLED':
                state = 'DISABLED'
            elif latest:
                error = latest['error_code']
                if latest['drift'] or error == 'provider_schema_mismatch': state = 'SCHEMA_CHANGED'
                elif error == 'provider_rate_limited': state = 'RATE_LIMITED'
                elif error in {'provider_authentication_rejected', 'connector_not_configured'}: state = 'AUTH_REQUIRED'
                elif latest['status'] == 'completed': state = 'HEALTHY'
                elif error in {'provider_unavailable', 'provider_transport_failure', 'provider_deadline_exceeded'}: state = 'OUTAGE'
                else: state = 'DEGRADED'
                try:
                    stamp = datetime.fromisoformat(latest['started_at'])
                    if stamp.tzinfo is None:
                        stamp = stamp.replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc)-stamp).total_seconds()
                    if not 0 <= age <= 7*86400:
                        state = 'UNKNOWN'
                except (ValueError, TypeError):
                    state = 'UNKNOWN'
            failures = sum(c['status'] == 'failed' for c in calls)
            result.append({'source_id': source, 'health': state,
                           'maturity': states.get(source, manifest(source)['maturity_state']),
                           'observed_calls': len(calls), 'failure_rate': failures/len(calls) if calls else None,
                           'rate_limit_events': sum(c['error_code'] == 'provider_rate_limited' for c in calls),
                           'schema_changes': sum(bool(c['drift']) for c in calls),
                           'authentication_failures': sum(c['error_code'] == 'provider_authentication_rejected' for c in calls),
                           'average_latency_ms': sum(c['duration_ms'] for c in calls)/len(calls) if calls else None,
                           'last_observed_at': latest['started_at'] if latest else None,
                           'quota_remaining': None, 'evidence_capture_failures': None, 'replay_failures': None})
        return {'schema': 'traceatlas-source-health/v1', 'sources': result,
                'states': {state: sum(r['health'] == state for r in result) for state in sorted(HEALTH_STATES)},
                'window': 'last 100 non-cache live executions per source', 'network_probes': 0}

    def rank(self, capabilities, *, country=None, language=None, max_sources=8, budget=0):
        """Non-executing four-wave plan. Unknown prices and constraints fail closed."""
        if not isinstance(capabilities, list) or not capabilities or len(capabilities) > 30 or any(not isinstance(c, str) for c in capabilities):
            raise PolicyError('Bounded capability requirements required')
        if type(max_sources) is not int or not 1 <= max_sources <= 100:
            raise PolicyError('Invalid source limit')
        _number(budget, 'budget')
        graph = independence_graph(self.records())
        group_by_source = {sid: group for group, ids in graph['groups'].items() for sid in ids}
        candidates, rejected = [], []
        for row in self.records():
            match = set(capabilities) & set(row['capabilities'] or [])
            if not match:
                continue
            reason = []
            if row['connector_status'] != 'CODED': reason.append('not_implemented')
            if row['qualification_status'] in {'DEGRADED', 'DISABLED', 'DEPRECATED'}: reason.append('unavailable')
            if not row['documentation_verified']: reason.append('documentation_unverified')
            if not {'terms', 'license', 'privacy'}.issubset(self.fabric._resolved_checks(row['source_id'])):
                reason.append('terms_license_privacy_unverified')
            if row.get('blocked_reason'): reason.append('recorded_access_obstacle')
            if country and country not in (row['countries'] or []): reason.append('jurisdiction_unverified')
            if language and language not in (row['languages'] or []): reason.append('language_unverified')
            if row.get('PII_risk') not in {'NONE', 'LOW'}: reason.append('privacy_review_required')
            cost = row.get('estimated_cost')
            if cost is None: reason.append('cost_unknown')
            quality = source_score(row.get('quality_factors') or {})
            if reason:
                rejected.append({'source_id': row['source_id'], 'reasons': reason})
                continue
            candidates.append({'source_id': row['source_id'], 'capabilities': sorted(match),
                               'cost': cost, 'latency_ms': row.get('estimated_latency_ms'),
                               'quality': quality, 'independence_group': group_by_source[row['source_id']]})
        selected, covered, groups, spent = [], set(), set(), 0
        for row in sorted(candidates, key=lambda r: (r['cost'], -(r['quality']['score'] or 0), r['source_id'])):
            if len(selected) >= max_sources or spent + row['cost'] > budget:
                continue
            new = set(row['capabilities']) - covered
            expensive = row['cost'] > 0 or row['latency_ms'] is None or row['latency_ms'] > 5000
            if expensive: wave = 4
            elif new and not selected: wave = 1
            elif new: wave = 3
            elif row['independence_group'] not in groups: wave = 2
            else: continue
            selected.append({**row, 'wave': wave, 'condition': 'information_gap_remains' if wave >= 3 else 'corroboration' if wave == 2 else 'initial'})
            covered.update(row['capabilities']); groups.add(row['independence_group']); spent += row['cost']
        return {'schema': 'traceatlas-portfolio-plan/v1', 'waves': [
                    {'wave': n, 'sources': [r for r in selected if r['wave'] == n]} for n in (1, 2, 3, 4)],
                'rejected': rejected, 'estimated_cost': spent, 'information_gaps': sorted(set(capabilities)-covered),
                'execution_granted': False, 'authorization': 'Dispatch through canonical gateway after case authorization.',
                'calibration': 'UNVALIDATED_HEURISTIC'}
