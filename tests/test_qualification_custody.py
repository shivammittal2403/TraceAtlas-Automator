"""Synthetic lifecycle projections must recheck current canonical custody."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.policy import PolicyError
from traceatlas.source_fabric.store import FabricStore, utc
from traceatlas.source_maturity import SOURCE_QUALIFICATION_GATES
from qualification_fixtures import make_receipt


class QualificationCustodyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.db = CaseDB(self.root / 'traceatlas.db')
        self.addCleanup(self.db.close)
        self.db.create_case('canary', 'Canary', 'Synthetic regression; no network')
        self.db.create_case('review', 'Review', 'Synthetic review attestation')
        self.store = FabricStore(self.db, self.root)
        self.canary = self.preserve('canary')
        self.review = self.preserve('review')
        # Controlled database injection exercises the projection, not provider authenticity.
        self.db.conn.execute("INSERT INTO fabric_executions"
            "(id,source,case_id,request_hash,authority_hash,status,mode,started_at) "
            "VALUES('synthetic','dns','canary','a','b','completed','live',?)", (utc(),))
        self.db.conn.commit()
        for gate in sorted(SOURCE_QUALIFICATION_GATES):
            evidence_hash, _ = make_receipt(self.root, self.db, 'dns', gate, 'review',
                actor='test-operator', supporting=[self.review['sha256']]) if gate not in {
                    'live_request', 'canary', 'intended_runtime'} else make_receipt(
                        self.root, self.db, 'dns', gate, 'review', actor='test-operator')
            self.store.review('dns', gate, 'review', evidence_hash,
                              'test-operator', self.root, authorized=True)
        # The latest canary is a distinct case from the reviewed execution;
        # corruption in either trust boundary must revoke the projection.
        self.db.conn.execute("UPDATE fabric_executions SET started_at=? WHERE id='synthetic'", (utc(),))
        self.db.conn.commit()
        self.store.promote('dns', 'test-operator', self.root, authorized=True)

    def preserve(self, case):
        path = self.root / (case + '.json')
        path.write_text('{"synthetic":"' + case + '"}', encoding='utf-8')
        return EvidenceStore(self.root, self.db, case).preserve_file(path, 'test:qualification')

    def test_intact_qualification_is_preserved(self):
        self.assertEqual(self.store.states()['dns'], 'PRODUCTION_QUALIFIED')

    def test_review_bytes_changed_after_promotion_revoke_projection(self):
        Path(self.review['path']).write_text('tampered', encoding='utf-8')
        self.assertFalse(EvidenceStore(self.root, self.db, 'review').verify_ledger()[0])
        self.assertEqual(self.store.states()['dns'], 'LIVE_TESTED')
        with self.assertRaises(PolicyError):
            self.store.promote('dns', 'test-operator', self.root, authorized=True)

    def test_deleted_review_artifact_revokes_projection(self):
        Path(self.review['path']).unlink()
        self.assertEqual(self.store.states()['dns'], 'LIVE_TESTED')

    def test_review_ledger_corruption_revokes_projection(self):
        ledger = EvidenceStore(self.root, self.db, 'review').ledger
        ledger.write_text('not-json\n', encoding='utf-8')
        self.assertEqual(self.store.states()['dns'], 'LIVE_TESTED')

    def test_canary_custody_corruption_degrades_source(self):
        Path(self.canary['path']).write_text('tampered', encoding='utf-8')
        self.assertEqual(self.store.states()['dns'], 'DEGRADED')

    def test_custody_checks_are_repeated_between_reads_and_cached_within_read(self):
        original = EvidenceStore.verify_ledger
        checked = []
        def verify(store):
            checked.append(store.case_id)
            return original(store)
        with patch.object(EvidenceStore, 'verify_ledger', verify):
            self.assertEqual(self.store.states()['dns'], 'PRODUCTION_QUALIFIED')
            self.assertCountEqual(checked, ['canary', 'review'])
            Path(self.review['path']).write_text('changed', encoding='utf-8')
            self.assertEqual(self.store.states()['dns'], 'LIVE_TESTED')
        self.assertEqual(checked.count('review'), 2)

    def test_configured_anchor_failure_cannot_keep_qualification(self):
        with patch.object(EvidenceStore, 'verify_ledger', return_value=(False, ['anchor unavailable'])):
            self.assertEqual(self.store.states()['dns'], 'DEGRADED')

    def test_constructor_failure_fails_closed(self):
        with patch('traceatlas.source_fabric.store.EvidenceStore', side_effect=ValueError('invalid anchor')):
            self.assertEqual(self.store.states()['dns'], 'DEGRADED')

    def test_explicit_workspace_is_used_when_database_is_elsewhere(self):
        self.store.workspace = self.root / 'wrong-root'
        self.assertEqual(self.store.states(workspace=self.root)['dns'], 'PRODUCTION_QUALIFIED')
        self.assertEqual(self.store.promote('dns', 'test-operator', self.root, authorized=True)['state'],
                         'PRODUCTION_QUALIFIED')
