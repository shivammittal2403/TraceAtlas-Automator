"""Exercise the canonical threaded factory boundary; fixtures never count as live."""
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.employee.autonomous import AutonomousInvestigator
from traceatlas.intelligence.hub import IntelligenceHub
from traceatlas.policy import PolicyError
from traceatlas.source_fabric.gateway import SourceGateway


class GatewayAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / 'case.db')
        self.addCleanup(self.db.close)
        self.db.create_case('case-a', 'Controlled gateway', 'Synthetic authorized public test')
        self.calls = []
        self.environment = patch.dict(os.environ, {'TRACEATLAS_WORKFORCE_KILL_SWITCH': ''})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.response_hook = lambda: None

    def request(self, url, headers, timeout):
        self.calls.append(url)
        self.response_hook()
        if 'data.iana.org' in url:
            data = {'version': '1.0', 'services': [[['org'], ['https://rdap.publicinterestregistry.org/rdap/']]]}
        elif 'rdap.publicinterestregistry.org' in url:
            data = {'objectClassName': 'domain', 'ldhName': 'example.org'}
        else:
            data = {'Status': 0, 'Answer': [{'name': 'example.org.', 'type': 1, 'data': '8.8.8.8'}]}
        return 200, json.dumps(data).encode()

    def authorize(self, source='dns'):
        service = AutonomousInvestigator(self.db, self.root,
            hub=IntelligenceHub(self.db, self.root, requester=self.request), enabled=True)
        current = service.create('case-a', 'Investigate DNS registration of a controlled example',
            [{'type': 'domain', 'value': 'example.org'}], actor='analyst-1', authorized=True,
            attestations={'public_record_basis': True, 'owned_asset': True}, source_fabric=True)
        self.db.conn.execute("UPDATE autonomous_investigations SET status='running' WHERE id=?", (current['id'],))
        self.db.conn.commit()
        action = next(a for a in current['manifest']['actions'] if a['source'] == source)
        self.current, self.action = current, action
        return SourceGateway(self.db, self.root, requester=self.request)

    def collect(self, gateway):
        return gateway.collect_batch('case-a', [self.action], self.current['manifest']['attestations'],
                                     self.current['manifest_hash'], timeout=5)

    def revoke(self):
        # This callback runs in a transport thread and uses its own connection.
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute('UPDATE autonomous_investigations SET cancel_requested=1 WHERE id=?',
                         (self.current['id'],))
            conn.commit()

    def test_canonical_gateway_uses_factory_and_preserves_fixture_mode(self):
        gateway = self.authorize()
        result = self.collect(gateway)[0]
        self.assertEqual(result['state'], 'completed')
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(result['outcome']['provider']['primitive'], 'DNS_JSON')
        self.assertTrue(result['outcome']['provider']['fixture'])
        self.assertEqual(self.db.conn.execute('SELECT mode FROM fabric_executions').fetchone()[0], 'fixture')

    def test_revocation_during_request_prevents_evidence_promotion(self):
        gateway = self.authorize()
        self.response_hook = self.revoke
        result = self.collect(gateway)[0]
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.db.evidence('case-a'), [])
        self.assertEqual(self.db.conn.execute('SELECT count(*) FROM fabric_slots').fetchone()[0], 0)

    def test_revocation_between_rdap_bootstrap_and_provider_blocks_second_request(self):
        gateway = self.authorize('rdap')
        self.response_hook = self.revoke
        self.assertEqual(self.collect(gateway)[0]['state'], 'failed')
        self.assertEqual(len(self.calls), 1)
        self.assertIn('data.iana.org', self.calls[0])

    def test_revocation_before_retry_blocks_retry(self):
        gateway = self.authorize()
        def retryable(url, headers, timeout):
            self.calls.append(url)
            self.revoke()
            return 503, b'{}'
        gateway.requester = retryable
        with patch('traceatlas.intelligence.provider.time.sleep', lambda _: None):
            self.assertEqual(self.collect(gateway)[0]['state'], 'failed')
        self.assertEqual(len(self.calls), 1)

    def test_kill_switch_blocks_cache_hit_and_network(self):
        gateway = self.authorize()
        self.assertEqual(self.collect(gateway)[0]['state'], 'completed')
        count = len(self.calls)
        with patch.dict(os.environ, {'TRACEATLAS_WORKFORCE_KILL_SWITCH': 'true'}):
            with self.assertRaises(PolicyError):
                self.collect(gateway)
        self.assertEqual(len(self.calls), count)

    def test_changed_manifest_is_rejected_before_transport(self):
        gateway = self.authorize()
        manifest = self.current['manifest']
        manifest['expires_at'] = '2099-01-01T00:00:00+00:00'
        self.db.conn.execute('UPDATE autonomous_investigations SET manifest_json=? WHERE id=?',
                             (json.dumps(manifest), self.current['id']))
        self.db.conn.commit()
        with self.assertRaises(PolicyError):
            self.collect(gateway)
        self.assertEqual(self.calls, [])

    def test_changed_executable_contract_is_rejected_before_transport(self):
        gateway = self.authorize()
        with patch('traceatlas.employee.autonomous.skill_contract_digest', return_value='changed'):
            with self.assertRaises(PolicyError):
                self.collect(gateway)
        self.assertEqual(self.calls, [])

    def test_contract_change_during_request_prevents_evidence_promotion(self):
        gateway = self.authorize()
        changed = patch('traceatlas.employee.autonomous.skill_contract_digest', return_value='changed')
        self.addCleanup(changed.stop)
        self.response_hook = changed.start
        self.assertEqual(self.collect(gateway)[0]['state'], 'failed')
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.db.evidence('case-a'), [])


if __name__ == '__main__':
    unittest.main()
