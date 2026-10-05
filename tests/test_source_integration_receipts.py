"""Synthetic receipt validation; these tests make no live-source claim."""
import json
import unittest
from unittest.mock import patch

import test_fabric_gateway_authority as fixtures
from traceatlas.policy import PolicyError
from traceatlas.source_fabric.integration import IntegrationReceipts
from traceatlas.source_fabric.portfolio import Portfolio


class IntegrationReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GatewayAuthorityTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.gateway = self.fixture.authorize()
        result = self.fixture.collect(self.gateway)[0]
        self.execution_id = result['outcome']['execution_id']
        self.receipts = IntegrationReceipts(self.fixture.db, self.fixture.root)

    def synthetic_live_row(self):
        # Controlled database injection exercises validation, never external verification.
        outcome = json.loads(self.fixture.db.conn.execute('SELECT evidence_json FROM fabric_executions WHERE id=?',
                                                          (self.execution_id,)).fetchone()[0])
        outcome['provider']['fixture'] = False
        self.fixture.db.conn.execute("UPDATE fabric_executions SET mode='live',evidence_json=? WHERE id=?",
                                      (json.dumps(outcome), self.execution_id))
        self.fixture.db.conn.commit()

    def record(self, authorized=True):
        return self.receipts.record('dns', self.execution_id, 'case-a', 'analyst-1', authorized=authorized)

    def test_fixtures_and_missing_authority_never_count(self):
        with self.assertRaises(PolicyError):
            self.record(False)
        with self.assertRaisesRegex(PolicyError, 'non-fixture'):
            self.record()
        self.assertEqual(self.receipts.verified(), [])

    def test_receipt_resolves_to_current_execution_and_case_custody(self):
        self.synthetic_live_row()
        receipt = self.record()
        self.assertFalse(receipt['maturity_promoted'])
        self.assertFalse(receipt['live_verified'])
        self.assertFalse(receipt['raw_replay_verified'])
        self.assertEqual(len(self.receipts.verified()), 1)
        self.assertEqual(Portfolio(self.fixture.db).report()['counts']['integration_tested'], 1)
        self.assertEqual(Portfolio(self.fixture.db).report()['counts']['live_verified'], 0)

    def test_cache_failure_and_schema_drift_are_rejected(self):
        self.synthetic_live_row()
        for column, value in [('cache_hit', 1), ('drift', 1), ('status', 'failed')]:
            with self.subTest(column=column):
                self.fixture.db.conn.execute('UPDATE fabric_executions SET ' + column + '=? WHERE id=?',
                                             (value, self.execution_id))
                self.fixture.db.conn.commit()
                with self.assertRaises(PolicyError):
                    self.record()
                self.fixture.db.conn.execute("UPDATE fabric_executions SET cache_hit=0,drift=0,status='completed' WHERE id=?",
                                             (self.execution_id,))
                self.fixture.db.conn.commit()

    def test_current_code_change_invalidates_old_receipt(self):
        self.synthetic_live_row()
        self.record()
        with patch('traceatlas.source_fabric.integration.implementation_digest', return_value='f'*64):
            self.assertEqual(self.receipts.verified(), [])

    def test_execution_change_invalidates_receipt(self):
        self.synthetic_live_row()
        self.record()
        self.fixture.db.conn.execute('UPDATE fabric_executions SET bytes=bytes+1 WHERE id=?', (self.execution_id,))
        self.fixture.db.conn.commit()
        self.assertEqual(self.receipts.verified(), [])

    def test_unresolved_or_wrong_case_evidence_is_rejected(self):
        self.synthetic_live_row()
        with self.assertRaises(PolicyError):
            self.receipts.record('dns', self.execution_id, 'another-case', 'analyst-1', authorized=True)
        self.fixture.db.conn.execute('DELETE FROM evidence WHERE case_id=?', ('case-a',))
        self.fixture.db.conn.commit()
        with self.assertRaises(PolicyError):
            self.record()


if __name__ == '__main__':
    unittest.main()
