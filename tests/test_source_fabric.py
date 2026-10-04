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
from traceatlas.intelligence.hub import IntelligenceHub

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
    'cveorg': ('cve', 'CVE-2024-12345', {'dataType': 'CVE_RECORD', 'dataVersion': '5.1',
        'cveMetadata': {'cveId': 'CVE-2024-12345', 'state': 'PUBLISHED', 'datePublished': '2025-01-01T00:00:00Z', 'dateUpdated': '2025-01-02T00:00:00Z'},
        'containers': {'cna': {'title': 'Fixture vulnerability record', 'descriptions': [{'lang': 'en', 'value': 'Synthetic CVE Program fixture.'}],
            'affected': [{'vendor': 'Fixture Vendor', 'product': 'Fixture Product'}]}}}),
    'cisa_kev': ('cve', 'CVE-2024-12345', {'title': 'Known Exploited Vulnerabilities Catalog',
        'catalogVersion': '2026.10.04', 'dateReleased': '2026-10-04T00:00:00.000Z', 'count': 1,
        'vulnerabilities': [{'cveID': 'CVE-2024-12345', 'vendorProject': 'Fixture Vendor',
            'product': 'Fixture Product', 'vulnerabilityName': 'Fixture KEV record',
            'dateAdded': '2025-01-02', 'shortDescription': 'Synthetic controlled fixture.',
            'requiredAction': 'Apply vendor mitigations', 'dueDate': '2025-01-31'}]}),
    'nvd': ('cve', 'CVE-2024-12345', {'resultsPerPage': 1, 'startIndex': 0, 'totalResults': 1,
        'format': 'NVD_CVE', 'version': '2.0', 'timestamp': '2025-01-02T00:00:00.000Z',
        'vulnerabilities': [{'cve': {'id': 'CVE-2024-12345', 'published': '2025-01-01T00:00:00.000Z',
            'lastModified': '2025-01-02T00:00:00.000Z', 'vulnStatus': 'Analyzed',
            'cisaExploitAdd': '2025-01-02', 'cisaActionDue': '2025-01-31',
            'cisaRequiredAction': 'Apply vendor mitigations', 'cisaVulnerabilityName': 'Fixture KEV record',
            'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}}]}}}]}),
    'epss': ('cve', 'CVE-2024-12345', {'status': 'OK', 'status-code': 200, 'version': '1.0',
        'access': 'public', 'total': 1, 'offset': 0, 'limit': 1,
        'data': [{'cve': 'CVE-2024-12345', 'epss': '0.812340000', 'percentile': '0.987650000', 'date': '2025-01-02'}]}),
    'osv': ('vulnerability', 'GHSA-1234-5678-9ABC', {'id': 'GHSA-1234-5678-9ABC',
        'modified': '2025-01-02T00:00:00Z', 'aliases': ['CVE-2024-12345'],
        'affected': [{'package': {'ecosystem': 'npm', 'name': 'fixture-package'}, 'versions': ['1.0.0']}]}),
    'npm': ('package', 'fixture-package', {'name': 'fixture-package', 'version': '1.2.3', 'license': 'MIT'}),
}


class SourceFabricTests(unittest.TestCase):
    def setUp(self):
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
            ('dns.lookup', 'rdap.lookup', 'archive.lookup', 'ip.lookup', 'search.execute', 'registry.lookup',
             'vulnerability.lookup', 'package.lookup', 'evidence.retrieve'),
            'IN', 'test-only', stamp.isoformat(), (stamp + timedelta(hours=1)).isoformat(), 'a' * 64)
        self.service.register_authorization(ctx); return ctx

    def task(self, kind, target, sources=None, *, context=None, prices=None, capabilities=None):
        ctx = context or self.context(kind, target)
        plan = self.service.create_investigation_task(ctx.context_id, kind, target, 'Inspect source evidence and contradictions',
            sources=sources, source_prices=prices, capabilities=capabilities)
        self.service.approve(plan['task']['task_id'], actor_id='analyst', rationale='Approved exact controlled source plan',
                             envelope_digest=plan['envelope_digest'], authorized=True)
        return plan['task']['task_id']

    def test_twenty_six_adapters_seventy_eight_controlled_capture_failure_and_drift_investigations(self):
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
                        self.assertGreater(len(result['analysis']['observations']), 0, json.dumps(result['replay_manifest']['source_outcomes']))
                        self.assertTrue(all(r['status'] == 'captured' for r in result['replay_manifest']['source_outcomes']))
                        self.assertIsNotNone(result['source_results'][0]['raw_evidence_id'])
                    else:
                        self.assertFalse(result['analysis']['observations'])
                        self.assertEqual(result['state'], 'PARTIAL')
                    self.assertTrue(pipeline.replay(task)['verified'])

    def test_vulnerability_and_package_defaults_route_typed_sources(self):
        cases = (
            ('cve', 'CVE-2024-12345', {'nvd', 'epss', 'cveorg', 'cisa_kev'}),
            ('vulnerability', 'GHSA-1234-5678-9ABC', {'osv'}),
            ('package', '@scope/fixture-package', {'npm'}),
        )
        for kind, target, expected in cases:
            with self.subTest(kind=kind):
                ctx = self.context(kind, target)
                plan = self.service.create_investigation_task(ctx.context_id, kind, target, 'Inspect exact public security metadata')
                self.assertEqual(set(plan['source_plan']['sources']), expected)

    def test_cve_collection_normalizes_advisory_probability_and_next_action(self):
        task = self.task('cve', 'CVE-2024-12345', ['nvd', 'cveorg', 'epss'])
        def request(url, *_):
            host = urlsplit(url).hostname
            source = 'nvd' if host == 'services.nvd.nist.gov' else 'cveorg' if host == 'cveawg.mitre.org' else 'epss'
            return 200, json.dumps(FIXTURES[source][2]).encode()
        product = InvestigationPipeline(self.service, self.root, requester=request).run(task, live=True, authorized=True)
        predicates = {row['statement'].split()[1] for row in product['analysis']['observations']}
        self.assertTrue({'vulnerability_id', 'vulnerability_score', 'exploitation_probability',
                         'cisa_kev_listed', 'cisa_kev_added_date', 'cisa_kev_due_date',
                         'cisa_kev_required_action', 'cisa_kev_vulnerability_name',
                         'vulnerability_name', 'affected_product'}.issubset(predicates))
        self.assertIn('review-authorized-asset-applicability', product['result']['recommended_next_actions'])
        self.assertNotIn('no-captured-web-search', product['analysis']['information_gaps'])
        self.assertEqual(product['analysis']['graph']['nodes'][0]['node_type'], 'Vulnerability')

    def test_new_exact_identifier_sources_reject_wrong_targets(self):
        stamp = datetime.now(timezone.utc).isoformat()
        for source, (kind, target, payload) in {key: FIXTURES[key] for key in ('nvd', 'cveorg', 'epss', 'osv', 'npm')}.items():
            if source == 'npm':
                wrong = {**payload, 'name': 'other-package'}
            elif source == 'osv':
                wrong = {**payload, 'id': 'GHSA-0000-0000-0000'}
            elif source == 'epss':
                wrong = {**payload, 'data': [{**payload['data'][0], 'cve': 'CVE-2024-99999'}]}
            elif source == 'cveorg':
                wrong = {**payload, 'cveMetadata': {**payload['cveMetadata'], 'cveId': 'CVE-2024-99999'}}
            else:
                wrong = {**payload, 'vulnerabilities': [{'cve': {**payload['vulnerabilities'][0]['cve'], 'id': 'CVE-2024-99999'}}]}
            with self.subTest(source=source), self.assertRaises(Exception):
                SourceConnector(source).normalize(kind, target, wrong, stamp)
            with self.subTest(source=source + '-intelligence-hub'), self.assertRaises(Exception):
                IntelligenceHub._validated_records(source, kind, target, wrong)

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
