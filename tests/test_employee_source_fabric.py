from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

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
        parsed = urlparse(url)
        host = (parsed.hostname or '').lower()
        path = parsed.path or ''
        if host == 'dns.google':
            data = {'Status': 0, 'Answer': [{'type': 1, 'data': '1.1.1.1'}]}
        elif host == 'data.iana.org' and path == '/rdap/dns.json':
            data = {'version': '1.0', 'services': [[['org'], ['https://rdap.publicinterestregistry.org/rdap/']]]}
        elif host == 'rdap.publicinterestregistry.org':
            data = {'objectClassName': 'domain', 'ldhName': 'EXAMPLE.ORG', 'country': 'US'}
        elif host == 'web.archive.org':
            data = [['timestamp', 'original', 'statuscode'], ['20200101000000', 'https://example.org/', '200']]
        elif host == 'rdap.org':
            data = {'objectClassName': 'domain', 'country': 'US'}
        elif host == 'api.gleif.org':
            data = {'data': {'id': '5493001KJTIIGC8Y1R12', 'attributes': {'entity': {'legalName': {'name': 'Fixture Company'}}}}}
        elif host == 'stat.ripe.net':
            data = {'status': 'ok', 'query_id': 'fixture', 'data': {'asns': [13335], 'prefix': '1.1.1.0/24'}}
        elif host == 'api.first.org':
            data = {'status': 'OK', 'data': [{'cve': 'CVE-2021-44228', 'epss': '0.8', 'date': '2026-10-03'}]}
        elif host == 'api.osv.dev':
            data = {'id': 'GHSA-jfh8-c2jp-5v3q', 'modified': '2026-10-03T00:00:00Z', 'affected': []}
        elif host == 'api.github.com':
            data = {'login': 'fixture'}
        elif host == 'gitlab.com':
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
        self.assertEqual(summary['implemented_api_connectors'], 37)
        self.assertEqual(summary['source_records'], 51)
        self.assertEqual(summary['live_verified'], 0)
        self.assertEqual(summary['production_qualified'], 0)
        self.assertEqual(len(candidates()), 400)
        self.assertIsNone(manifest('gleif')['estimated_cost']['amount'])

    def test_router_selects_small_capability_set_and_keeps_uncovered_gaps(self):
        current = self.create('Review DNS and sanctions exposure')
        plan = current['manifest']['routing_plans'][0]
        self.assertIn('sanctions', plan['uncovered_capabilities'])
        self.assertEqual([a['source'] for a in plan['actions']], ['dns', 'cloudflare_dns'])
        self.assertEqual([a['wave'] for a in plan['actions']], [1, 2])
        self.assertEqual(self.calls, [])

    def test_parallel_transport_serial_custody_and_raw_replay(self):
        from traceatlas.source_fabric.review_receipts import implementation_digest, execution_runtime_id
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
        for action in result['actions']:
            if action['state'] == 'completed':
                self.assertEqual(action['outcome']['implementation_sha256'], implementation_digest(action['outcome']['source']))
                self.assertEqual(action['outcome']['runtime_id'], execution_runtime_id())

    def test_same_case_cache_reuses_preserved_evidence(self):
        first = self.run_case(self.create())
        count = len(self.calls)
        second = self.run_case(self.create())
        self.assertEqual(len(self.calls), count)
        self.assertTrue(all(a['outcome']['cache_hit'] for a in second['actions'] if a['state'] == 'completed'))
        self.assertTrue(all(a['outcome']['reason'] == 'sufficient_capability_coverage'
                            for a in second['actions'] if a['state'] == 'skipped'))
        self.assertEqual(first['report']['evidence'][0]['content_hash'], second['report']['evidence'][0]['content_hash'])
        self.assertEqual(FabricStore(self.db).metrics()['source_actions'], 0)

    def test_runtime_change_invalidates_cache_and_is_recorded(self):
        with patch.dict('os.environ', {'TRACEATLAS_RUNTIME_ID': 'synthetic-first'}):
            self.run_case(self.create('Review DNS'))
        count = len(self.calls)
        with patch.dict('os.environ', {'TRACEATLAS_RUNTIME_ID': 'synthetic-second'}):
            result = self.run_case(self.create('Review DNS'))
        self.assertGreater(len(self.calls), count)
        self.assertTrue(all(a['outcome']['runtime_id'] == 'synthetic-second'
                            for a in result['actions'] if a['state'] == 'completed'))

    def test_runtime_change_during_transport_blocks_evidence_promotion(self):
        import os
        def change_runtime(*args):
            response = self.request(*args)
            os.environ['TRACEATLAS_RUNTIME_ID'] = 'synthetic-changed'
            return response
        self.employee.fabric_requester = change_runtime
        with patch.dict('os.environ', {'TRACEATLAS_RUNTIME_ID': 'synthetic-start'}):
            result = self.run_case(self.create('Review DNS', max_actions=1))
        self.assertEqual(result['actions'][0]['state'], 'failed')
        self.assertEqual(result['report']['raw_evidence'], [])

    def test_fallback_only_after_failure_and_stops_when_gap_is_filled(self):
        original = self.request
        def fail_github(url, *args):
            host = (urlparse(url).hostname or '').lower()
            if host == 'api.github.com':
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
        result = self.run_case(self.create('Review company LEI records', [{'type': 'company', 'value': 'lei:5493001KJTIIGC8Y1R12'}]))
        self.assertEqual(len(self.calls), 1)
        self.assertIn('candidate_lei', {e['edge_type'] for e in result['report']['graph']['edges']})
        self.assertNotIn('same_as', {e['edge_type'] for e in result['report']['graph']['edges']})
        self.assertIn('subject_identifier_associations_require_human_review', str(result['report']['unknowns']))

    def test_new_connector_contracts_and_target_mismatch(self):
        samples = [('rdap', 'domain', 'example.org'), ('ripestat', 'ip', '1.1.1.1'),
                   ('gleif', 'company', 'lei:5493001KJTIIGC8Y1R12'),
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

    def test_rdap_uses_reviewed_iana_bootstrap(self):
        plan = SourceRouter(self.db).plan('Review registration', 'domain', 'example.org', {'owned_asset': True, 'public_record_basis': True})
        self.assertEqual([a['source'] for a in plan['actions']], ['rdap'])
        self.assertNotIn('rdap', audit(self.db)['broken'])
        ct_plan = SourceRouter(self.db).plan('Review certificate transparency', 'domain', 'example.org', {'owned_asset': True, 'public_record_basis': True})
        self.assertEqual([a['source'] for a in ct_plan['actions']], ['crtsh'])

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
