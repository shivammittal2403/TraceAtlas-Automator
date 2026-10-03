from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.employee.autonomous import AutonomousInvestigator
from traceatlas.employee.autonomous_analysis import verify_replay
from traceatlas.intelligence.hub import IntelligenceHub
from traceatlas.intelligence.provider import ProviderError, _validate_shape
from traceatlas.source_fabric.registry import audit, candidates, manifest
from traceatlas.source_fabric.router import SourceRouter
from traceatlas.source_fabric.sdk import HubConnector
from traceatlas.source_fabric.store import FabricStore
from traceatlas.policy import PolicyError
"""Controlled Source Fabric investigations; no fixture establishes live readiness."""
import json
import os
import tempfile
import threading
import time
import unittest
import asyncio
from importlib.util import find_spec
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from traceatlas.db import CaseDB
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.pipeline import InvestigationPipeline
from traceatlas.workforce.service import WorkforceService
from traceatlas.workforce.source_registry import SourceRegistry, SourceManifest, P0_IDS
from traceatlas.workforce.source_router import ObjectiveSpec, SourceRouter
from traceatlas.workforce.source_state import SourceState
from traceatlas.workforce.source_sdk import SourceConnector
from traceatlas.workforce.source_discovery import candidate_catalog

LEI = '5493001KJTIIGC8Y1R12'
BOOT = {'version': '1.0', 'services': [[['org'], ['https://rdap.publicinterestregistry.org/rdap/']]]}
FIXTURES = {
    'dns': ('domain', 'example.org', {'Status': 0, 'Question': [{'name': 'example.org'}], 'Answer': [{'name': 'example.org', 'type': 1, 'data': '8.8.8.8'}]}),
    'cloudflare_dns': ('domain', 'example.org', {'Status': 0, 'Question': [{'name': 'example.org'}], 'Answer': [{'name': 'example.org', 'type': 1, 'data': '8.8.8.8'}]}),
    'rdap': ('domain', 'example.org', {'objectClassName': 'domain', 'ldhName': 'example.org', 'handle': 'fixture-org'}),
    'crtsh': ('domain', 'example.org', [{'id': 7, 'name_value': 'example.org', 'entry_timestamp': '2025-01-01T00:00:00'}]),
    'ripestat': ('ip', '8.8.8.8', {'status': 'ok', 'query_id': 'fixture', 'data': {'prefix': '8.8.8.0/24', 'asns': ['15169']}}),
    'urlscan': ('domain', 'example.org', {'results': [{'page': {'domain': 'example.org', 'ip': '8.8.8.8', 'url': 'https://example.org/'}, 'task': {'time': '2025-01-01T00:00:00Z'}}]}),
    'wayback': ('domain', 'example.org', [['timestamp', 'original'], ['20250101000000', 'https://example.org/']]),
    'internetdb': ('ip', '8.8.8.8', {'ip': '8.8.8.8', 'ports': [53]}),
    'ipwhois': ('ip', '8.8.8.8', {'ip': '8.8.8.8', 'success': True, 'country_code': 'US'}),
    'ipdata': ('ip', '8.8.8.8', {'ip': '8.8.8.8', 'country_code': 'US'}),
    'greynoise': ('ip', '8.8.8.8', {'ip': '8.8.8.8', 'noise': False, 'riot': True, 'classification': 'benign'}),
    'brave': ('domain', 'example.org', {'query': {'original': '"example.org"'}, 'web': {'results': [{'url': 'https://example.org/'}]}}),
    'searxng': ('domain', 'example.org', {'query': '"example.org"', 'results': [{'url': 'https://example.org/'}]}),
    'gleif': ('company', 'lei:' + LEI, {'data': {'id': LEI, 'attributes': {'lei': LEI, 'entity': {'legalName': {'name': 'Fixture Company'}, 'legalAddress': {'country': 'US'}, 'status': 'ACTIVE'}}}}),
    'companieshouse': ('company', 'gb:00000001', {'company_number': '00000001', 'company_name': 'Fixture Company', 'company_status': 'active'}),
    'sec': ('company', 'cik:1', {'cik': '1', 'name': 'Fixture Company', 'filings': {'recent': {'accessionNumber': ['0000000001-25-000001'], 'filingDate': ['2025-01-01']}}}),
    'opencorporates': ('company', 'gb:00000001', {'results': {'company': {'company_number': '00000001', 'jurisdiction_code': 'gb', 'name': 'Fixture Company', 'current_status': 'active', 'retrieved_at': '2025-01-01T00:00:00Z'}}}),
    'github': ('company', 'github:fixture-org', {'login': 'fixture-org', 'type': 'Organization', 'name': 'Fixture Organization', 'public_repos': 3, 'html_url': 'https://github.com/fixture-org'}),
    'shodan': ('ip', '8.8.8.8', {'ip_str': '8.8.8.8', 'ports': [53]}),
    'virustotal': ('ip', '8.8.8.8', {'data': {'id': '8.8.8.8', 'attributes': {'last_analysis_stats': {'malicious': 0}}}}),
}


class SourceFabricTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root/'case.db')
        self.addCleanup(self.db.close)
        self.db.create_case('case-a', 'Fixture', 'Authorized synthetic source fabric research')
        self.calls = []
        self.hub = IntelligenceHub(self.db, self.root, requester=self.request, sleeper=lambda _: None)
        self.employee = AutonomousInvestigator(self.db, self.root, hub=self.hub, enabled=True)

    def request(self, url, headers, timeout):
        self.calls.append(url)
        if 'dns.google' in url:
            data = {'Status': 0, 'Answer': [{'type': 1, 'data': '1.1.1.1'}]}
        elif 'web.archive.org' in url:
            data = [['timestamp', 'original', 'statuscode'], ['20200101000000', 'https://example.org/', '200']]
        elif 'rdap.org' in url:
            data = {'objectClassName': 'domain', 'country': 'US'}
        elif 'api.gleif.org' in url:
            data = {'data': [{'id': '5493001KJTIIGC8Y1R12', 'attributes': {'entity': {'legalName': {'name': 'Fixture Company'}}}}]}
        elif 'stat.ripe.net' in url:
            data = {'status': 'ok', 'data': {'asns': [13335], 'prefix': '1.1.1.0/24'}}
        elif 'api.first.org' in url:
            data = {'status': 'OK', 'data': [{'cve': 'CVE-2021-44228', 'epss': '0.8', 'date': '2026-10-03'}]}
        elif 'api.osv.dev' in url:
            data = {'id': 'GHSA-jfh8-c2jp-5v3q', 'modified': '2026-10-03T00:00:00Z', 'affected': []}
        elif 'api.github.com' in url:
            data = {'login': 'fixture'}
        elif 'gitlab.com' in url:
            data = [{'username': 'fixture'}]
        else:
            self.fail('Unexpected source destination')
        return 200, json.dumps(data).encode()

    def create(self, objective='Review DNS and archive history', seeds=None, **kwargs):
        options = dict(actor='analyst-1', authorized=True, source_fabric=True,
                       attestations={'owned_asset': True, 'public_record_basis': True})
        options.update(kwargs)
        return self.employee.create('case-a', objective, seeds or [{'type': 'domain', 'value': 'example.org'}], **options)

    def run_case(self, current):
        return self.employee.run('case-a', current['id'], actor='analyst-1', authorized=True)

    def test_counts_separate_candidates_aliases_implementation_and_live(self):
        summary = audit(self.db)
        self.assertEqual(summary['candidate_slots'], 400)
        self.assertEqual(summary['duplicate_candidate_slots'], 39)
        self.assertEqual(summary['implemented_api_connectors'], 27)
        self.assertEqual(summary['source_records'], 41)
        self.assertEqual(summary['live_verified'], 0)
        self.assertEqual(summary['production_qualified'], 0)
        self.assertEqual(len(candidates()), 400)
        self.assertIsNone(manifest('gleif')['estimated_cost']['amount'])

    def test_router_selects_small_capability_set_and_keeps_uncovered_gaps(self):
        current = self.create('Review DNS and sanctions exposure')
        plan = current['manifest']['routing_plans'][0]
        self.assertIn('sanctions', plan['uncovered_capabilities'])
        self.assertEqual([a['source'] for a in plan['actions']], ['dns'])
        self.assertEqual(self.calls, [])

    def test_parallel_transport_serial_custody_and_raw_replay(self):
        barrier = threading.Barrier(2)
        original = self.request
        def parallel_request(*args):
            barrier.wait(timeout=5)
            return original(*args)
        self.employee.fabric_requester = parallel_request
        result = self.run_case(self.create())
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(result['report']['raw_evidence']), 2)
        self.assertTrue(EvidenceStore(self.root, self.db, 'case-a').verify_ledger()[0])
        for raw in result['report']['raw_evidence']:
            self.assertEqual(hashlib.sha256(Path(raw['raw_artifact_pointer']).read_bytes()).hexdigest(), raw['content_hash'])
        exported = self.employee.export('case-a', result['id'], self.root/'reports')
        self.assertEqual(verify_replay(Path(exported['directory']))['status'], 'verified')
        self.assertEqual(audit(self.db)['live_verified'], 0)  # Fixture success never counts as live.
        self.assertGreater(result['elapsed'], 0)

    def test_same_case_cache_reuses_preserved_evidence(self):
        first = self.run_case(self.create())
        count = len(self.calls)
        second = self.run_case(self.create())
        self.assertEqual(len(self.calls), count)
        self.assertTrue(all(a['outcome']['cache_hit'] for a in second['actions']))
        self.assertEqual(first['report']['evidence'][0]['content_hash'], second['report']['evidence'][0]['content_hash'])
        self.assertEqual(FabricStore(self.db).metrics()['source_actions'], 0)

    def test_fallback_only_after_failure_and_stops_when_gap_is_filled(self):
        original = self.request
        def fail_github(url, *args):
            if 'api.github.com' in url:
                self.calls.append(url)
                return 403, b''
            return original(url, *args)
        self.employee.fabric_requester = fail_github
        result = self.run_case(self.create('Review public profile metadata', [{'type': 'username', 'value': 'fixture'}], attestations={'subject_consent': True}))
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(any(a['state'] == 'failed' for a in result['actions']))
        self.assertTrue(any(a['outcome'].get('reason') == 'sufficient_capability_coverage' for a in result['actions']))
        self.assertEqual(result['report']['raw_evidence'], [])  # Personal-source raw bytes withheld.

    def test_company_candidates_have_citations_not_identity_merge(self):
        result = self.run_case(self.create('Review company LEI records', [{'type': 'company', 'value': 'Fixture Company'}]))
        self.assertEqual(len(self.calls), 1)
        self.assertIn('candidate_lei', {e['edge_type'] for e in result['report']['graph']['edges']})
        self.assertNotIn('same_as', {e['edge_type'] for e in result['report']['graph']['edges']})
        self.assertIn('subject_identifier_associations_require_human_review', str(result['report']['unknowns']))

    def test_new_connector_contracts_and_target_mismatch(self):
        samples = [('ripestat', 'ip', '1.1.1.1'), ('gleif', 'company', 'Fixture Company'),
                   ('epss', 'cve', 'CVE-2021-44228'), ('osv', 'vulnerability', 'GHSA-jfh8-c2jp-5v3q')]
        for source, kind, target in samples:
            connector = HubConnector(source, requester=self.request)
            response = connector.fetch(kind, target)
            self.assertTrue(connector.normalize(kind, target, response))
            with self.assertRaises(ProviderError):
                _validate_shape(source, {'unexpected': True})
        with self.assertRaises(ProviderError):
            IntelligenceHub._validated_records('epss', 'cve', 'CVE-2020-1234', {'data': [{'cve': 'CVE-2021-44228'}]})

    def test_no_authority_no_collection_and_no_automatic_production(self):
        with self.assertRaises(PolicyError):
            self.create(attestations={})
        with self.assertRaises(PolicyError):
            SourceRouter(self.db).plan('Read public profile', 'username', 'fixture', {})
        self.run_case(self.create())
        with self.assertRaisesRegex(PolicyError, 'canary'):
            FabricStore(self.db).promote('dns', 'analyst-1', self.root, authorized=True)

    def test_configured_credentials_are_excluded_from_automatic_routing(self):
        with patch.dict('os.environ', {'GITHUB_TOKEN': 'fixture'}):
            current = self.create('Review developer profile', [{'type': 'username', 'value': 'fixture'}], attestations={'subject_consent': True})
        self.assertNotIn('github', {a['source'] for a in current['manifest']['actions']})

    def test_known_broken_rdap_is_excluded_with_coverage_gap(self):
        plan = SourceRouter(self.db).plan('Review registration', 'domain', 'example.org', {'owned_asset': True, 'public_record_basis': True})
        self.assertEqual(plan['actions'], [])
        self.assertIn('registration', plan['uncovered_capabilities'])
        self.assertIn('rdap', audit(self.db)['broken'])

    def test_shared_workspace_concurrency_leases(self):
        store = FabricStore(self.db)
        store.acquire_slot('one', 'provider-a', 'case-a', 5)
        with self.assertRaises(PolicyError):
            store.acquire_slot('two', 'provider-a', 'case-b', 5)
        store.acquire_slot('two', 'provider-b', 'case-a', 5)
        store.acquire_slot('three', 'provider-c', 'case-a', 5)
        with self.assertRaises(PolicyError):
            store.acquire_slot('four', 'provider-d', 'case-a', 5)
        store.release_slot('one')
        store.acquire_slot('four', 'provider-a', 'case-a', 5)

    def test_gateway_rejects_forged_scope_and_cancelled_authority(self):
        from traceatlas.source_fabric.gateway import SourceGateway
        current = self.create('Review DNS')
        gateway = SourceGateway(self.db, self.root, requester=self.request)
        manifest = current['manifest']
        from traceatlas.employee.brief import digest
        arguments = ('case-a', manifest['actions'], manifest['attestations'], digest(manifest))
        with self.assertRaises(PolicyError):
            gateway.collect_batch(*arguments)
        self.db.conn.execute("UPDATE autonomous_investigations SET status='running' WHERE id=?", (current['id'],))
        self.db.conn.commit()
        with self.assertRaises(PolicyError):
            gateway.collect_batch('case-a', [{**manifest['actions'][0], 'target':'other.org'}], manifest['attestations'], digest(manifest))
        self.db.conn.execute("UPDATE autonomous_investigations SET cancel_requested=1 WHERE id=?", (current['id'],))
        self.db.conn.commit()
        with self.assertRaises(PolicyError):
            gateway.collect_batch(*arguments)
        self.assertEqual(self.calls, [])

    def test_cache_is_case_scoped(self):
        self.run_case(self.create('Review DNS'))
        before = len(self.calls)
        self.db.create_case('case-b', 'Other case', 'Separate authorized fixture research')
        current = self.employee.create('case-b', 'Review DNS', [{'type':'domain','value':'example.org'}], actor='analyst-1', authorized=True, source_fabric=True, attestations={'owned_asset':True})
        self.employee.run('case-b', current['id'], actor='analyst-1', authorized=True)
        self.assertEqual(len(self.calls), before+1)

    def test_schema_drift_and_secret_raw_withholding(self):
        self.run_case(self.create('Review DNS'))
        self.db.conn.execute("UPDATE fabric_executions SET started_at='2000-01-01T00:00:00+00:00'")
        self.db.conn.commit()
        def changed(url, headers, timeout):
            return 200, json.dumps({'Status':0, 'Answer':[{'type':1,'data':'1.1.1.1'}], 'api_key':'sensitive-fixture'}).encode()
        self.employee.fabric_requester = changed
        result = self.run_case(self.create('Review DNS'))
        self.assertTrue(result['actions'][0]['outcome']['schema_drift'])
        self.assertEqual(result['report']['raw_evidence'], [])
        self.assertEqual(audit(self.db)['live_verified'], 0)


if __name__ == '__main__':
    unittest.main()
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / 'case.db'); self.db.create_case('fabric-case', 'Controlled source tests', 'Synthetic fixtures')
        self.service = WorkforceService(self.db, enabled=True); self.sequence = 0
        env = {key: 'fixture-credential-value' for item in SourceRegistry().list() for key in item.credential_refs}
        env.update(SEC_USER_AGENT='Fixture tester contact@example.org', SEARXNG_URL='http://127.0.0.1:8123',
                   TRACEATLAS_WORKFORCE_KILL_SWITCH='', TRACEATLAS_SEARCH_PROVIDER='')
        self.env = patch.dict(os.environ, env); self.env.start()

    def tearDown(self):
        self.env.stop(); self.db.close(); self.temp.cleanup()

    def context(self, kind, target):
        self.sequence += 1; stamp = datetime.now(timezone.utc)
        ctx = AuthorizationContext('1.0', 'fabric-auth-' + str(self.sequence), 'fabric-case', 'analyst', 'Controlled fixture validation',
            (kind + ':' + target,), ('request_collection', 'propose_observation', 'propose_claim'),
            ('dns.lookup', 'rdap.lookup', 'archive.lookup', 'ip.lookup', 'search.execute', 'registry.lookup', 'evidence.retrieve'),
            'IN', 'test-only', stamp.isoformat(), (stamp + timedelta(hours=1)).isoformat(), 'a' * 64)
        self.service.register_authorization(ctx); return ctx

    def task(self, kind, target, sources=None, *, context=None, prices=None, capabilities=None):
        ctx = context or self.context(kind, target)
        plan = self.service.create_investigation_task(ctx.context_id, kind, target, 'Inspect source evidence and contradictions',
            sources=sources, source_prices=prices, capabilities=capabilities)
        self.service.approve(plan['task']['task_id'], actor_id='analyst', rationale='Approved exact controlled source plan',
                             envelope_digest=plan['envelope_digest'], authorized=True)
        return plan['task']['task_id']

    def test_twenty_adapters_sixty_controlled_capture_failure_and_drift_investigations(self):
        self.assertEqual(set(FIXTURES), P0_IDS)
        for source, (kind, target, payload) in FIXTURES.items():
            for scenario in ('success', 'authentication_failure', 'schema_drift'):
                with self.subTest(source=source, scenario=scenario):
                    task = self.task(kind, target, [source], prices={source: 0})
                    def request(url, *_):
                        if scenario == 'authentication_failure': return 401, b''
                        if scenario == 'schema_drift': return 200, b'{"changed_api":true}'
                        return 200, json.dumps(BOOT if urlsplit(url).hostname == 'data.iana.org' else payload).encode()
                    # Independent test scopes must not inherit a previous scenario's breaker.
                    self.db.conn.execute('DELETE FROM source_fabric_events'); self.db.conn.execute('DELETE FROM connector_health'); self.db.conn.commit()
                    pipeline = InvestigationPipeline(self.service, self.root, requester=request, search_requester=request)
                    result = pipeline.run(task, live=True, authorized=True)
                    if scenario == 'success':
                        self.assertGreater(len(result['analysis']['observations']), 0)
                        self.assertTrue(all(r['status'] == 'captured' for r in result['replay_manifest']['source_outcomes']))
                        self.assertIsNotNone(result['source_results'][0]['raw_evidence_id'])
                    else:
                        self.assertFalse(result['analysis']['observations'])
                        self.assertEqual(result['state'], 'PARTIAL')
                    self.assertTrue(pipeline.replay(task)['verified'])

    def test_registry_accepts_401_definitions_without_execution_permissions(self):
        registry = SourceRegistry([SourceManifest('candidate-' + str(i), 'test', 'Test', 'test', ('test.read',), ('domain',)) for i in range(401)])
        self.assertEqual(len(registry.capabilities()['test.read']), 401)
        self.assertFalse(registry.supports('candidate-1', 'domain', 'example.org'))
        with self.assertRaises(ValueError): SourceRegistry([registry.get('candidate-1')] * 2)

    def test_discovery_deduplicates_without_claiming_400_implemented(self):
        data = candidate_catalog()
        self.assertEqual(data['candidate_entries'], 400)
        self.assertLess(data['deduplicated_review_rows'], 400)
        self.assertEqual(data['additional_implemented_connectors'], 0)
        self.assertTrue(all(not r['execution_enabled'] for r in data['sources']))

    def test_case_and_authority_scoped_cache_reuses_verified_bytes(self):
        ctx = self.context('domain', 'example.org'); calls = []
        def request(url, *_):
            calls.append(url); return 200, json.dumps(FIXTURES['dns'][2]).encode()
        pipeline = InvestigationPipeline(self.service, self.root, requester=request)
        one = pipeline.run(self.task('domain', 'example.org', ['dns'], context=ctx), live=True, authorized=True)
        two = pipeline.run(self.task('domain', 'example.org', ['dns'], context=ctx), live=True, authorized=True)
        self.assertEqual(len(calls), 1); self.assertEqual(two['network_attempts'], 0)
        self.assertTrue(two['source_results'][0]['source_metadata']['cache_hit'])
        self.assertEqual(one['source_results'][0]['retrieval_time'], two['source_results'][0]['retrieval_time'])
        pipeline.run(self.task('domain', 'example.org', ['dns']), live=True, authorized=True)
        self.assertEqual(len(calls), 2)

    def test_concurrent_sources_respect_case_limit(self):
        active = 0; highest = 0; lock = threading.Lock(); overlap = threading.Event()
        def request(url, *_):
            nonlocal active, highest
            with lock:
                active += 1; highest = max(highest, active)
                if active == 2: overlap.set()
            overlap.wait(1)
            with lock: active -= 1
            source = 'dns' if 'dns' in url else 'urlscan'
            return 200, json.dumps(FIXTURES[source][2]).encode()
        task = self.task('domain', 'example.org', ['dns', 'urlscan'])
        result = InvestigationPipeline(self.service, self.root, requester=request).run(task, live=True, authorized=True)
        self.assertEqual(highest, 2); self.assertEqual(result['network_attempts'], 2)

    def test_plan_tampering_fails_before_network(self):
        task = self.task('domain', 'example.org', ['dns'])
        self.db.conn.execute("UPDATE source_fabric_plans SET plan_json='{}' WHERE task_id=?", (task,)); self.db.conn.commit()
        with self.assertRaisesRegex(ValueError, 'altered'):
            InvestigationPipeline(self.service, self.root, requester=lambda *_: self.fail('no network')).run(task, live=True, authorized=True)

    def test_unknown_price_blocks_paid_call_and_records_gap(self):
        task = self.task('domain', 'example.org', ['brave'])
        result = InvestigationPipeline(self.service, self.root, requester=lambda *_: self.fail('unpriced request')).run(task, live=True, authorized=True)
        self.assertEqual(result['network_attempts'], 0)
        self.assertIn('source-brave-source_price_unknown', result['analysis']['information_gaps'])

    def test_secret_echo_is_not_preserved(self):
        task = self.task('domain', 'example.org', ['brave'], prices={'brave': 0})
        result = InvestigationPipeline(self.service, self.root, requester=lambda *_: (200, b'{"secret":"fixture-credential-value"}')).run(task, live=True, authorized=True)
        self.assertFalse(result['replay_manifest']['evidence'])
        self.assertNotIn('fixture-credential-value', json.dumps(result))

    def test_company_name_does_not_match_a_registry_identifier(self):
        registry = SourceRegistry()
        self.assertFalse(registry.supports('gleif', 'company', 'ACME'))
        self.assertFalse(registry.supports('companieshouse', 'company', 'ACME'))
        connector = SourceConnector('companieshouse')
        with self.assertRaises(ValueError): connector.validate_input('company', 'gb:../secret')
        with self.assertRaises(Exception): connector.normalize('company', 'gb:00000001', {**FIXTURES['companieshouse'][2], 'company_number': '00000002'}, datetime.now(timezone.utc).isoformat())

    def test_fallback_runs_only_after_primary_failure(self):
        task = self.task('domain', 'example.org', capabilities=['domain.dns'])
        plan = SourceState(self.service.store).plan(self.service.store.task(task)['envelope'])
        self.assertEqual(len(plan['tasks']), 2)
        primary = plan['tasks'][0]['source_id']
        def request(url, *_):
            source = 'cloudflare_dns' if 'cloudflare' in url else 'dns'
            return (401, b'') if source == primary else (200, json.dumps(FIXTURES[source][2]).encode())
        result = InvestigationPipeline(self.service, self.root, requester=request).run(task, live=True, authorized=True)
        self.assertEqual(result['network_attempts'], 2)
        self.assertTrue(result['analysis']['observations'])
        self.assertTrue(any(o['status'] == 'failed' for o in result['replay_manifest']['source_outcomes']))

    def test_schema_breaker_requires_an_approved_fresh_canary(self):
        task = self.task('domain', 'example.org', ['dns'])
        runner = InvestigationPipeline(self.service, self.root, requester=lambda *_: (200, b'{"drift":true}'))
        runner.run(task, live=True, authorized=True)
        self.assertEqual(SourceState(self.service.store).health('dns')['state'], 'SCHEMA_CHANGED')
        result = runner.run(self.task('domain', 'example.org', ['dns']), live=True, authorized=True)
        self.assertEqual(result['network_attempts'], 0)
        ctx = self.context('domain', 'example.org')
        plan = self.service.create_investigation_task(ctx.context_id, 'domain', 'example.org', 'Verify repaired source schema', sources=['dns'], health_probe=True)
        canary = plan['task']['task_id']
        repaired = InvestigationPipeline(self.service, self.root, requester=lambda *_: (200, json.dumps(FIXTURES['dns'][2]).encode()))
        with self.assertRaises(ValueError): repaired.run(canary, live=True, authorized=True)
        self.service.approve(canary, actor_id='analyst', rationale='Review one source canary', envelope_digest=plan['envelope_digest'], authorized=True)
        self.assertEqual(repaired.run(canary, live=True, authorized=True)['network_attempts'], 1)
        self.assertEqual(SourceState(self.service.store).health('dns')['state'], 'HEALTHY')

    def test_rate_limits_are_atomic_and_recover_after_window(self):
        from traceatlas.workforce.source_limits import SourceRateLimiter
        from concurrent.futures import ThreadPoolExecutor
        clock = [0.0]; limiter = SourceRateLimiter(lambda: clock[0])
        with ThreadPoolExecutor(max_workers=8) as pool:
            allowed = list(pool.map(lambda _: limiter.reserve('virustotal', 'virustotal'), range(20)))
        self.assertEqual(sum(allowed), 4)
        clock[0] = 60.0
        self.assertTrue(limiter.reserve('virustotal', 'virustotal'))

    def test_cache_corruption_never_becomes_evidence(self):
        ctx = self.context('domain', 'example.org'); calls = []
        def request(url, *_):
            calls.append(url); return 200, json.dumps(FIXTURES['dns'][2]).encode()
        runner = InvestigationPipeline(self.service, self.root, requester=request)
        runner.run(self.task('domain', 'example.org', ['dns'], context=ctx), live=True, authorized=True)
        self.db.conn.execute("UPDATE source_fabric_cache SET evidence_json='not-json'"); self.db.conn.commit()
        result = runner.run(self.task('domain', 'example.org', ['dns'], context=ctx), live=True, authorized=True)
        self.assertEqual(len(calls), 2)
        self.assertTrue(runner.replay(result['task_id'])['verified'])

    def test_mcp_reopens_store_in_worker_and_rejects_scope_injection(self):
        from concurrent.futures import ThreadPoolExecutor
        from traceatlas.workforce.source_mcp import SourceCapabilities
        task = self.task('domain', 'example.org', ['dns'])
        envelope = self.service.store.task(task)['envelope']
        arguments = {key: getattr(envelope, key) for key in ('case_id', 'task_id', 'authorization_context_id', 'trace_id')}
        arguments['scope'] = list(envelope.scope)
        facade = SourceCapabilities(self.service, self.root)
        with ThreadPoolExecutor(max_workers=1) as pool:
            value = pool.submit(facade.call_in_worker, 'sources.estimate_cost', arguments).result()
        self.assertEqual(value['result']['estimated_cost'], 0)
        for bad in ({**arguments, 'scope': ['domain:other.example']}, {**arguments, 'url': 'https://other.example/'}, {**arguments, 'task_id': 1}):
            with self.assertRaises(ValueError): facade.call('sources.search', bad)

    @unittest.skipUnless(find_spec('mcp'), 'optional MCP SDK; exercised by the bundled runtime CI gate')
    def test_mcp_wire_lists_tools_and_uses_worker_bound_authority(self):
        import anyio
        from mcp import ClientSession
        from mcp.shared.memory import create_client_server_memory_streams
        from traceatlas.workforce.source_mcp import SourceCapabilities, build_server, OPERATIONS
        task = self.task('domain', 'example.org', ['dns'])
        envelope = self.service.store.task(task)['envelope']
        arguments = {key: getattr(envelope, key) for key in ('case_id', 'task_id', 'authorization_context_id', 'trace_id')}
        arguments['scope'] = list(envelope.scope)
        server = build_server(SourceCapabilities(self.service, self.root))
        async def exercise():
            async with create_client_server_memory_streams() as (client_streams, server_streams):
                async with anyio.create_task_group() as group:
                    group.start_soon(server.run, *server_streams, server.create_initialization_options())
                    async with ClientSession(*client_streams) as client:
                        await client.initialize()
                        listing = await client.list_tools()
                        self.assertEqual({t.name for t in listing.tools}, set(OPERATIONS))
                        value = await client.call_tool('sources.estimate_cost', arguments)
                        self.assertFalse(value.is_error)
                        self.assertEqual(json.loads(value.content[0].text)['task_id'], task)
                        rejected = await client.call_tool('sources.search', {**arguments, 'scope': ['domain:other.example']})
                        self.assertTrue(rejected.is_error)
                    group.cancel_scope.cancel()
        asyncio.run(exercise())
