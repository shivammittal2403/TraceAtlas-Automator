import hashlib
import json
import tempfile
import sqlite3
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.intelligence.hub import IntelligenceHub
from traceatlas.intelligence.provider import ProviderError


class EvidenceBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / 'cases.db')
        self.db.create_case('case-a', 'Fixture', 'Authorized synthetic evidence')
        self.store = EvidenceStore(self.root, self.db, 'case-a')

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_connector_response_envelope_export_and_tamper_rejection(self):
        raw = b'{"ip":"8.8.8.8","ports":[443],"vulns":[]}'
        hub = IntelligenceHub(self.db, self.root, requester=lambda *_: (200, raw))
        result = hub.collect('case-a', 'internetdb', 'ip', '8.8.8.8', authorized=True, owned_asset=True)
        rows = {e['sha256']: e for e in self.db.evidence('case-a')}
        envelope = json.loads(Path(rows[result['evidence_envelope_ref']]['path']).read_text())
        self.assertEqual(envelope['response_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(envelope['normalized_evidence_refs'], result['evidence_refs'])
        bundle = self.root / 'evidence.zip'
        self.store.export_bundle(bundle)
        self.assertTrue(EvidenceStore.verify_bundle(bundle))
        with self.assertRaises(FileExistsError):
            self.store.export_bundle(bundle)
        tampered = self.root / 'tampered.zip'
        with zipfile.ZipFile(bundle) as original, zipfile.ZipFile(tampered, 'w') as changed:
            for name in original.namelist():
                changed.writestr(name, b'changed' if name.startswith('evidence/') else original.read(name))
        self.assertFalse(EvidenceStore.verify_bundle(tampered))
        Path(rows[result['evidence_refs'][0]]['path']).write_text('tampered')
        self.assertFalse(self.store.verify_ledger()[0])
        with self.assertRaisesRegex(ValueError, 'verification failed'):
            self.store.export_bundle(self.root / 'rejected.zip')

    def test_missing_ledger_with_indexed_evidence_is_not_valid(self):
        source = self.root / 'source.txt'
        source.write_text('fixture')
        self.store.preserve_file(source, 'fixture')
        self.store.ledger.unlink()
        self.assertEqual(self.store.verify_ledger(), (False, 0))

    def test_wrong_target_never_becomes_evidence(self):
        hub = IntelligenceHub(self.db, self.root, requester=lambda *_: (200, b'{"ip":"1.1.1.1"}'))
        with self.assertRaisesRegex(ProviderError, 'target_mismatch'):
            hub.collect('case-a', 'internetdb', 'ip', '8.8.8.8', authorized=True, owned_asset=True)
        self.assertEqual(self.db.evidence('case-a'), [])
        self.assertEqual(self.db.source_runs('case-a')[0]['failure_code'], 'provider_target_mismatch')

    def test_missing_entitlement_is_durable_not_configured_without_fallback(self):
        requester = Mock()
        hub = IntelligenceHub(self.db, self.root, requester=requester)
        with patch.dict('os.environ', {'IPDATA_API_KEY': ''}):
            with self.assertRaisesRegex(ValueError, 'IPDATA_API_KEY'):
                hub.collect('case-a', 'ipdata', 'ip', '8.8.8.8', authorized=True, owned_asset=True)
        requester.assert_not_called()
        self.assertEqual(self.db.evidence('case-a'), [])
        self.assertEqual(self.db.source_runs('case-a')[0]['failure_code'], 'not_configured')

    def test_invalid_ledger_returns_failure_and_unknown_case_is_rejected(self):
        self.store.ledger.write_text('{broken')
        self.assertEqual(self.store.verify_ledger(), (False, 0))
        with self.assertRaises(ValueError):
            EvidenceStore(self.root, self.db, 'not-a-case')

    def test_identical_content_is_indexed_in_each_case(self):
        self.db.create_case('case-b', 'Second case', 'Another authorized fixture')
        source = self.root / 'shared.txt'
        source.write_text('same synthetic observation')
        self.store.preserve_file(source, 'fixture')
        EvidenceStore(self.root, self.db, 'case-b').preserve_file(source, 'fixture')
        self.assertEqual(len(self.db.evidence('case-a')), 1)
        self.assertEqual(len(self.db.evidence('case-b')), 1)
        self.assertNotEqual(self.db.evidence('case-a')[0]['path'], self.db.evidence('case-b')[0]['path'])

    def test_legacy_evidence_index_upgrade_preserves_rows_and_is_repeatable(self):
        path = self.root / 'legacy.db'
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE evidence (sha256 TEXT PRIMARY KEY, case_id TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL, captured_at TEXT NOT NULL, size INTEGER NOT NULL, media_type TEXT)')
        row = ('a'*64, 'case-a', 'fixture-path', 'fixture', '2026-09-29', 10, 'text/plain')
        conn.execute('INSERT INTO evidence VALUES (?,?,?,?,?,?,?)', row)
        conn.commit()
        conn.close()
        for _ in range(2):
            migrated = CaseDB(path)
            try:
                self.assertEqual(migrated.evidence('case-a')[0]['sha256'], row[0])
                self.assertEqual(migrated.conn.execute('SELECT count(*) FROM evidence_legacy_v1').fetchone()[0], 1)
                migrated.add_evidence('case-b', row[0], 'other-path', 'fixture', 10, 'text/plain')
                self.assertEqual(len(migrated.evidence('case-b')), 1)
            finally:
                migrated.close()


if __name__ == '__main__':
    unittest.main()
