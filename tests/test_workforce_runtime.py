"""Two-connection and crash-boundary fixtures; no provider network calls."""
import json
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.pipeline import InvestigationPipeline
from traceatlas.workforce.runtime import ExecutionRuntime, ExecutionStopped, micros
from traceatlas.workforce.service import WorkforceService


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / 'case.db')
        self.addCleanup(self.db.close)
        self.db.create_case('case-runtime', 'Runtime fixture', 'Isolated synthetic tests')
        self.service = WorkforceService(self.db, enabled=True)
        self.now = time.time()
        stamp = datetime.now(timezone.utc)
        self.context = AuthorizationContext('1.0', 'auth-runtime', 'case-runtime', 'analyst-runtime',
            'Controlled synthetic domain investigation', ('domain:example.org',),
            ('request_collection', 'propose_observation', 'propose_claim'),
            ('dns.lookup', 'evidence.retrieve'), 'IN', 'fixture-only',
            (stamp - timedelta(seconds=10)).isoformat(), (stamp + timedelta(days=1)).isoformat(), 'a' * 64)
        self.service.register_authorization(self.context)
        self.plan = self.service.create_investigation_task('auth-runtime', 'domain', 'example.org',
            'Review the authorized domain DNS record', sources=['dns'])
        self.task_id = self.plan['task']['task_id']
        self.service.approve(self.task_id, actor_id='analyst-runtime', rationale='Approve isolated synthetic fixture',
                             envelope_digest=self.plan['envelope_digest'], authorized=True)
        self.runtime = self.service.store.runtime
        self.runtime.clock = lambda: self.now
        self.runtime.lease_seconds = 10

    def result(self):
        return self.service.deterministic_no_model_result(self.task_id)

    def request(self, *_):
        return 200, json.dumps({'Status': 0, 'Question': [{'name': 'example.org', 'type': 1}],
            'Answer': [{'name': 'example.org', 'type': 1, 'TTL': 60, 'data': '93.184.216.34'}]}).encode()

    def pipeline(self, requester=None):
        return InvestigationPipeline(self.service, self.root, requester=requester or self.request)

    def test_two_sessions_only_one_claim_wins(self):
        def claim(_):
            try:
                return ExecutionRuntime(self.db.path).claim(self.task_id)
            except ExecutionStopped:
                return None
        with ThreadPoolExecutor(2) as pool:
            values = list(pool.map(claim, range(2)))
        self.assertEqual(sum(v is not None for v in values), 1)

    def test_stale_worker_cannot_dispatch_finalize_or_fail_replacement(self):
        old = self.runtime.claim(self.task_id)
        self.now += 11
        self.runtime.recover(self.task_id)
        new = self.runtime.claim(self.task_id)
        with self.assertRaises(ExecutionStopped):
            self.runtime.reserve(self.task_id, old, 'dns', 0)
        with self.assertRaises(ExecutionStopped):
            self.service.store.finish(self.task_id, self.result(), token=old)
        self.service.store.fail(self.task_id, token=old)
        self.assertEqual(self.service.describe(self.task_id)['status'], 'running')
        self.service.store.finish(self.task_id, self.result(), token=new)

    def test_recovery_preserves_time_budget_and_requires_expired_lease(self):
        self.runtime.claim(self.task_id)
        with self.assertRaises(ExecutionStopped):
            self.runtime.recover(self.task_id)
        self.now += 121
        with self.assertRaisesRegex(ExecutionStopped, 'exhausted'):
            self.runtime.recover(self.task_id)

    def test_cancel_checks_owner_and_fences_all_execution(self):
        token = self.runtime.claim(self.task_id)
        with self.assertRaises(ValueError):
            self.service.cancel(self.task_id, actor_id='another-user', authorized=True)
        self.service.cancel(self.task_id, actor_id='analyst-runtime', authorized=True)
        for call in (lambda: self.runtime.check(self.task_id, token),
                     lambda: self.runtime.reserve(self.task_id, token, 'dns', 0),
                     lambda: self.service.store.finish(self.task_id, self.result(), token=token)):
            with self.assertRaises(ExecutionStopped):
                call()
        self.service.store.fail(self.task_id, token=token)
        self.assertEqual(self.service.describe(self.task_id)['status'], 'cancelled')
        with self.assertRaises(ExecutionStopped):
            self.service.recover(self.task_id, actor_id='analyst-runtime', authorized=True)

    def test_paid_ambiguous_charge_stays_reserved_across_recovery(self):
        token = self.runtime.claim(self.task_id)
        request_id = self.runtime.reserve(self.task_id, token, 'fixture-paid', .75)
        self.runtime.settle(self.task_id, token, request_id)
        self.service.store.fail(self.task_id, token=token)
        self.service.recover(self.task_id, actor_id='analyst-runtime', authorized=True)
        new = self.runtime.claim(self.task_id)
        with self.assertRaisesRegex(ExecutionStopped, 'budget'):
            self.runtime.reserve(self.task_id, new, 'fixture-paid', .3)
        self.assertEqual(self.runtime.snapshot(self.task_id)['accounted_usd'], .75)
        self.runtime.settle(self.task_id, token, request_id, actual=.5)
        self.runtime.reserve(self.task_id, new, 'fixture-paid', .5)
        with self.assertRaises(ValueError):
            self.runtime.settle(self.task_id, token, request_id, actual=0)

    def test_concurrent_reservations_cannot_overspend(self):
        token = self.runtime.claim(self.task_id)
        def reserve(_):
            try:
                return self.runtime.reserve(self.task_id, token, 'fixture-paid', .6)
            except ExecutionStopped:
                return None
        with ThreadPoolExecutor(2) as pool:
            outcomes = list(pool.map(reserve, range(2)))
        self.assertEqual(sum(v is not None for v in outcomes), 1)

    def test_request_limit_survives_restart_even_when_free(self):
        token = self.runtime.claim(self.task_id)
        for _ in range(8):
            self.runtime.reserve(self.task_id, token, 'dns', 0)
        self.service.store.fail(self.task_id, token=token)
        self.runtime.recover(self.task_id)
        new = self.runtime.claim(self.task_id)
        with self.assertRaises(ExecutionStopped):
            self.runtime.reserve(self.task_id, new, 'dns', 0)

    def test_completion_idempotent_but_conflicting_result_rejected(self):
        token = self.runtime.claim(self.task_id)
        result = self.result()
        self.service.store.finish(self.task_id, result, token=token)
        self.service.store.finish(self.task_id, result, token=token)
        with self.assertRaises(ValueError):
            self.service.store.finish(self.task_id, replace(result, latency_ms=4), token=token)
        self.assertEqual(len(self.runtime.snapshot(self.task_id)['outbox']), 1)

    def test_completion_rolls_back_at_every_canonical_write_boundary(self):
        tables = ('workforce_products', 'observations_v2', 'source_lineage_v2',
                  'verification_decisions_v2', 'workforce_results', 'workforce_outbox')
        for table in tables:
            with self.subTest(table=table):
                self.db.conn.execute(f"CREATE TEMP TRIGGER crash BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'synthetic crash'); END")
                with self.assertRaises(sqlite3.IntegrityError):
                    self.pipeline().run(self.task_id, live=True, authorized=True)
                for output in tables:
                    self.assertEqual(self.db.conn.execute(f'SELECT COUNT(*) FROM {output}').fetchone()[0], 0)
                self.db.conn.execute('DROP TRIGGER crash')
                self.db.conn.commit()
                self.service.recover(self.task_id, actor_id='analyst-runtime', authorized=True)
        self.pipeline().run(self.task_id, live=True, authorized=True)
        self.assertEqual(self.service.describe(self.task_id)['status'], 'completed')

    def test_failed_finalization_resumes_capture_without_network(self):
        pipeline = self.pipeline()
        with patch.object(self.service.store, 'finish', side_effect=RuntimeError('synthetic crash')):
            with self.assertRaises(RuntimeError):
                pipeline.run(self.task_id, live=True, authorized=True)
        before = self.runtime.snapshot(self.task_id)
        self.assertTrue(before['checkpoints'])
        self.service.recover(self.task_id, actor_id='analyst-runtime', authorized=True)
        product = self.pipeline(lambda *_: self.fail('recovery repeated captured request')).run(self.task_id, live=True, authorized=True)
        self.assertEqual(self.runtime.snapshot(self.task_id)['request_attempts'], before['request_attempts'])
        self.assertTrue(pipeline.replay(self.task_id)['verified'])
        self.assertTrue(product['analysis']['observations'])

    def test_cancel_during_provider_response_never_commits_a_result(self):
        def request(*args):
            self.runtime.stop(self.task_id, cancel=True)
            return self.request(*args)
        with self.assertRaises(ExecutionStopped):
            self.pipeline(request).run(self.task_id, live=True, authorized=True)
        self.assertEqual(self.service.describe(self.task_id)['status'], 'cancelled')
        self.assertEqual(self.db.conn.execute('SELECT COUNT(*) FROM workforce_results').fetchone()[0], 0)

    def test_checkpoint_tamper_and_conflicting_rewrite_fail_closed(self):
        token = self.runtime.claim(self.task_id)
        self.runtime.checkpoint(self.task_id, token, 'capture:fixture', {'evidence_id': 'fixture'})
        with self.assertRaises(ValueError):
            self.runtime.checkpoint(self.task_id, token, 'capture:fixture', {'evidence_id': 'other'})
        self.db.conn.execute("UPDATE workforce_checkpoints SET payload_json='{}'")
        self.db.conn.commit()
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.runtime.snapshot(self.task_id)

    def test_capture_reuse_rejects_tampered_bytes(self):
        self.pipeline().run(self.task_id, live=True, authorized=True)
        task = self.service.store.task(self.task_id)['envelope']
        _, item = self.service.store.captured_document(task, 'dns')
        Path(item.raw_artifact_pointer).write_bytes(b'tampered controlled fixture')
        with self.assertRaisesRegex(ValueError, 'integrity'):
            self.service.store.captured_document(task, 'dns')

    def test_existing_database_schema_upgrade_is_additive(self):
        before = self.db.conn.execute('SELECT envelope_digest FROM workforce_tasks').fetchone()[0]
        WorkforceService(self.db, enabled=True)
        self.assertEqual(self.db.conn.execute('SELECT envelope_digest FROM workforce_tasks').fetchone()[0], before)

    def test_prices_reject_nan_negative_bool_and_round_up(self):
        for value in (float('nan'), float('inf'), -1, True, None, 'not-a-price'):
            with self.assertRaises(ValueError):
                micros(value)
        self.assertEqual(micros(.0000001), 1)

    def test_product_case_mismatch_rolls_back(self):
        token = self.runtime.claim(self.task_id)
        with self.assertRaises(ValueError):
            self.service.store.finish(self.task_id, self.result(), token=token,
                                      product={'task_id': self.task_id, 'case_id': 'another-case'})
        self.assertEqual(self.db.conn.execute('SELECT COUNT(*) FROM workforce_results').fetchone()[0], 0)

    def test_terminal_state_write_failure_rolls_back_result_and_outbox(self):
        token = self.runtime.claim(self.task_id)
        self.db.conn.execute("CREATE TEMP TRIGGER crash_state BEFORE UPDATE OF status ON workforce_tasks "
                             "WHEN NEW.status='completed' BEGIN SELECT RAISE(ABORT,'state write failed'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.service.store.finish(self.task_id, self.result(), token=token)
        self.assertEqual(self.service.describe(self.task_id)['status'], 'running')
        for table in ('workforce_results', 'workforce_outbox'):
            self.assertEqual(self.db.conn.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0], 0)

    def test_request_settlement_cannot_cross_task_or_attempt(self):
        token = self.runtime.claim(self.task_id)
        reservation = self.runtime.reserve(self.task_id, token, 'fixture-paid', .5)
        for task, attempt in ((self.task_id, 'wrong-token'), ('other-task', token)):
            with self.assertRaises(ExecutionStopped):
                self.runtime.settle(task, attempt, reservation, actual=0)
        self.assertEqual(self.runtime.snapshot(self.task_id)['accounted_usd'], .5)
