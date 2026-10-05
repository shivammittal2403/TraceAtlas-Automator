"""Adversarial qualification contracts, with synthetic rows and no network IO."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from qualification_fixtures import make_receipt, make_execution, preserve
from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.policy import PolicyError
from traceatlas.source_fabric.store import FabricStore, QUALIFICATION_CHECKS
from traceatlas.source_fabric.review_receipts import review_template


class QualificationReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / 'traceatlas.db')
        self.db.create_case('case', 'Synthetic source reviews', 'Contract evaluation only')
        self.store = FabricStore(self.db)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def review(self, gate='terms', **changes):
        evidence_hash, receipt = make_receipt(self.root, self.db, 'dns', gate, 'case', **changes)
        self.store.review('dns', gate, 'case', evidence_hash, 'analyst', self.root, authorized=True)
        return evidence_hash, receipt

    def reject(self, gate='terms', **changes):
        evidence_hash, _ = make_receipt(self.root, self.db, 'dns', gate, 'case', **changes)
        with self.assertRaises(PolicyError):
            self.store.review('dns', gate, 'case', evidence_hash, 'analyst', self.root, authorized=True)

    def complete(self, omit=()):
        for gate in sorted(QUALIFICATION_CHECKS - set(omit)):
            self.review(gate)

    def test_unrelated_artifact_cannot_satisfy_any_of_26_checks(self):
        artifact = preserve(self.root, self.db, 'case', {'unrelated': True})
        for gate in QUALIFICATION_CHECKS:
            with self.subTest(gate=gate), self.assertRaisesRegex(PolicyError, 'typed JSON'):
                self.store.review('dns', gate, 'case', artifact, 'analyst', self.root, authorized=True)
        self.assertEqual(self.db.conn.execute('SELECT COUNT(*) FROM fabric_reviews').fetchone()[0], 0)

    def test_template_cannot_grant_a_review(self):
        form = review_template('dns', 'terms', 'case', 'analyst', 'runtime')
        self.assertEqual(form['outcome'], 'UNREVIEWED')
        self.assertEqual(form['supporting_evidence_hashes'], [])
        artifact = preserve(self.root, self.db, 'case', form)
        with self.assertRaises(PolicyError):
            self.store.review('dns', 'terms', 'case', artifact, 'analyst', self.root, authorized=True)

    def test_receipt_is_bound_to_source_case_check_and_actor(self):
        for changes in ({'source_id': 'cloudflare_dns'}, {'case_id': 'another'},
                        {'check_name': 'privacy'}, {'actor': 'someone else'}):
            with self.subTest(changes=changes):
                # actor is a fixture parameter, so alter preserved JSON directly.
                _, receipt = make_receipt(self.root, self.db, 'dns', 'terms', 'case')
                receipt.update(changes)
                evidence_hash = preserve(self.root, self.db, 'case', receipt)
                with self.assertRaisesRegex(PolicyError, 'binding mismatch'):
                    self.store.review('dns', 'terms', 'case', evidence_hash, 'analyst', self.root, authorized=True)

    def test_check_requirement_and_schema_are_strict(self):
        for changes in ({'requirement': 'anything'}, {'outcome': True}, {'outcome': []}, {'outcome': {}}, {'outcome': 'UNREVIEWED'},
                        {'schema': 'invented/v1'}, {'extra_field': 'ignored?'}):
            with self.subTest(changes=changes):
                self.reject(**changes)

    def test_timestamps_expiry_future_and_timezone_fail_closed(self):
        now = datetime.now(timezone.utc)
        for changes in (
            {'expires_at': (now - timedelta(seconds=1)).isoformat()},
            {'reviewed_at': (now + timedelta(hours=1)).isoformat()},
            {'reviewed_at': (now - timedelta(days=31)).isoformat()},
            {'expires_at': (now + timedelta(days=31)).isoformat()},
            {'reviewed_at': now.replace(tzinfo=None).isoformat()}, {'reviewed_at': 'invalid'}):
            with self.subTest(changes=changes):
                self.reject(**changes)

    def test_supporting_artifacts_must_be_same_case_and_resolve(self):
        self.db.create_case('other', 'Other', 'Synthetic isolation check')
        cross_case = preserve(self.root, self.db, 'other', {'other_case_only': True})
        for supporting in ([], ['f' * 64], [cross_case], ['not-a-hash'], [{'nested': True}]):
            with self.subTest(supporting=supporting):
                self.reject(supporting=supporting)
        valid = preserve(self.root, self.db, 'case', {'support': True})
        self.reject(supporting=[valid, valid])

    def test_duplicate_json_fields_and_oversized_receipt_are_rejected(self):
        _, receipt = make_receipt(self.root, self.db, 'dns', 'terms', 'case')
        for content in ('{"schema":"forged",' + json.dumps(receipt)[1:], 'x' * 65537):
            path = self.root / 'invalid.json'
            path.write_text(content, encoding='utf-8')
            artifact = EvidenceStore(self.root, self.db, 'case').preserve_file(path, 'synthetic:invalid')['sha256']
            with self.assertRaises(PolicyError):
                self.store.review('dns', 'terms', 'case', artifact, 'analyst', self.root, authorized=True)

    def test_runtime_reviews_reject_fixture_cache_failure_drift_and_zero_attempts(self):
        for column, value in (('mode', 'fixture'), ('cache_hit', 1), ('status', 'failed'),
                              ('drift', 1), ('attempts', 0), ('source', 'cloudflare_dns')):
            with self.subTest(column=column):
                execution = make_execution(self.root, self.db, 'dns', 'case', 'synthetic-' + column)
                self.db.conn.execute('UPDATE fabric_executions SET ' + column + '=? WHERE id=?', (value, execution[0]))
                self.db.conn.commit()
                self.reject('live_request', execution=execution)

    def test_runtime_reviews_bind_raw_bytes_provider_and_time(self):
        for mutation in ('fixture', 'hash', 'source', 'size', 'missing_raw', 'future', 'stale', 'code', 'runtime'):
            with self.subTest(mutation=mutation):
                execution = make_execution(self.root, self.db, 'dns', 'case', 'raw-' + mutation)
                row = self.db.conn.execute('SELECT * FROM fabric_executions WHERE id=?', (execution[0],)).fetchone()
                outcome = json.loads(row['evidence_json'])
                if mutation in ('fixture', 'hash', 'source', 'size', 'missing_raw', 'code', 'runtime'):
                    if mutation == 'fixture': outcome['provider']['fixture'] = True
                    if mutation == 'hash': outcome['provider']['response_sha256'] = 'e' * 64
                    if mutation == 'source': outcome['provider']['source'] = 'cloudflare_dns'
                    if mutation == 'size': outcome['provider']['response_bytes'] = row['bytes'] + 1
                    if mutation == 'missing_raw': outcome['raw_evidence_refs'] = []
                    if mutation == 'code': outcome['implementation_sha256'] = 'e' * 64
                    if mutation == 'runtime': outcome['runtime_id'] = 'different-runtime'
                    self.db.conn.execute('UPDATE fabric_executions SET evidence_json=? WHERE id=?', (json.dumps(outcome), execution[0]))
                else:
                    delta = timedelta(hours=1) if mutation == 'future' else -timedelta(days=8)
                    self.db.conn.execute('UPDATE fabric_executions SET started_at=? WHERE id=?',
                                         ((datetime.now(timezone.utc) + delta).isoformat(), execution[0]))
                self.db.conn.commit()
                self.reject('live_request', execution=execution)

    def test_expired_or_failed_latest_review_never_falls_back_to_old_pass(self):
        self.review()
        self.assertIn('terms', self.store._resolved_checks('dns'))
        self.review(outcome='FAIL')
        self.assertNotIn('terms', self.store._resolved_checks('dns'))
        self.review()
        row = self.db.conn.execute('SELECT id FROM fabric_reviews ORDER BY id DESC LIMIT 1').fetchone()
        self.db.conn.execute('UPDATE fabric_reviews SET at=? WHERE id=?',
                             ((datetime.now(timezone.utc) - timedelta(days=31)).isoformat(), row[0]))
        self.db.conn.commit()
        self.assertNotIn('terms', self.store._resolved_checks('dns'))

    def test_failed_runtime_review_can_revoke_a_pass_without_response_bytes(self):
        self.review('live_request')
        execution = make_execution(self.root, self.db, 'dns', 'case', 'failed-network')
        self.db.conn.execute("UPDATE fabric_executions SET status='failed',evidence_json='{}' WHERE id=?", (execution[0],))
        self.db.conn.commit()
        self.review('live_request', outcome='FAIL', execution=execution)
        self.assertNotIn('live_request', self.store._resolved_checks('dns'))

    def test_implementation_changes_invalidate_prior_reviews(self):
        self.review()
        with patch('traceatlas.source_fabric.store.implementation_digest', return_value='e' * 64):
            self.assertNotIn('terms', self.store._resolved_checks('dns'))

    def test_supporting_tamper_invalidates_reported_checks(self):
        _, receipt = self.review()
        support = next(r for r in self.db.evidence('case') if r['sha256'] == receipt['supporting_evidence_hashes'][0])
        Path(support['path']).write_text('modified', encoding='utf-8')
        self.assertEqual(self.store._resolved_checks('dns'), set())

    def test_qualification_is_explicit_and_bound_to_exact_review_set(self):
        self.complete()
        self.assertEqual(self.store.states()['dns'], 'LIVE_VERIFIED')
        with self.assertRaises(PolicyError):
            self.store.promote('dns', 'analyst', self.root)
        self.store.promote('dns', 'analyst', self.root, authorized=True)
        self.assertEqual(self.store.states()['dns'], 'PRODUCTION_QUALIFIED')
        self.review(method='Revised synthetic attestation requires a new promotion.')
        self.assertEqual(self.store.states()['dns'], 'LIVE_VERIFIED')
        self.store.promote('dns', 'analyst', self.root, authorized=True)
        self.assertEqual(self.store.states()['dns'], 'PRODUCTION_QUALIFIED')
        self.review(outcome='FAIL')
        self.assertEqual(self.store.states()['dns'], 'LIVE_TESTED')

    def test_mixed_runtime_reviews_do_not_create_qualification(self):
        self.complete(omit={'terms'})
        self.review(runtime='different-runtime')
        self.assertEqual(self.store.states()['dns'], 'LIVE_TESTED')
        with self.assertRaises(PolicyError):
            self.store.promote('dns', 'analyst', self.root, authorized=True)

    def test_stale_projection_cannot_bypass_receipt_validation_at_promotion(self):
        make_execution(self.root, self.db, 'dns', 'case')
        with patch.object(self.store, 'states', return_value={'dns': 'LIVE_VERIFIED'}):
            with self.assertRaisesRegex(PolicyError, 'receipts do not resolve'):
                self.store.promote('dns', 'analyst', self.root, authorized=True)

    def test_authority_requires_true_boolean_and_canonical_workspace(self):
        artifact, _ = make_receipt(self.root, self.db, 'dns', 'terms', 'case')
        for authorized in ('yes', 1, None):
            with self.subTest(authorized=authorized), self.assertRaises(PolicyError):
                self.store.review('dns', 'terms', 'case', artifact, 'analyst', self.root, authorized=authorized)
        with self.assertRaisesRegex(PolicyError, 'canonical case database'):
            self.store.review('dns', 'terms', 'case', artifact, 'analyst', self.root / 'elsewhere', authorized=True)

    def test_old_promotion_schema_migrates_without_trusting_legacy_status(self):
        self.db.conn.execute('DROP TABLE fabric_promotions')
        self.db.conn.execute('CREATE TABLE fabric_promotions(source TEXT PRIMARY KEY,state TEXT,actor TEXT,at TEXT)')
        self.db.conn.execute("INSERT INTO fabric_promotions VALUES('dns','PRODUCTION_QUALIFIED','analyst',?)",
                             (datetime.now(timezone.utc).isoformat(),))
        self.db.conn.commit()
        store = FabricStore(self.db)
        self.complete()
        self.assertEqual(store.states()['dns'], 'LIVE_VERIFIED')
        self.assertEqual(self.db.conn.execute('SELECT runtime_id,review_digest FROM fabric_promotions').fetchone()[0], None)

    def test_cli_preserves_receipt_then_records_review_and_requires_authority(self):
        from types import SimpleNamespace
        from traceatlas.cli import parser
        from traceatlas.source_fabric.cli import run_fabric
        _, receipt = make_receipt(self.root, self.db, 'dns', 'terms', 'case')
        submitted = self.root / 'submitted-review.json'
        submitted.write_text(json.dumps(receipt), encoding='utf-8')
        argv = ['source-fabric', 'review', '--source', 'dns', '--check', 'terms',
                '--case', 'case', '--actor', 'analyst', '--receipt', str(submitted)]
        engine = SimpleNamespace(db=self.db, workspace=self.root)
        before = len(self.db.evidence('case'))
        with self.assertRaises(PolicyError):
            run_fabric(parser().parse_args(argv), engine)
        self.assertEqual(len(self.db.evidence('case')), before)
        result = run_fabric(parser().parse_args(argv + ['--authorized']), engine)
        self.assertFalse(result['production_promoted'])
        self.assertIn('terms', self.store._resolved_checks('dns'))


if __name__ == '__main__':
    unittest.main()
