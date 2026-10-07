"""Archive filesystem regressions using isolated, synthetic local stores."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from traceatlas.filesystem import child_path, path_component
from traceatlas.addons.cute_v1.evidence.store import EvidenceStore as CuteStore
from traceatlas.addons.cute_v1.investigation.manager import CaseWorkspace
from traceatlas.addons.cute_v1.reporting.report_manager import ReportManager
from traceatlas.addons.osint_v1.evidence.store import EvidenceStore as OsintStore
from traceatlas.addons.osint_v1.exceptions import EvidenceError


class ArchiveFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_case_identifiers_cannot_escape_on_either_platform(self):
        for value in ('../outside', 'a/b', '..\\outside', '/tmp', 'C:\\temp', '.', '..', '',
                      'a\0b', 'a\nb', 'case.', 'case ', 'CON', 'LPT1.txt'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                CaseWorkspace(self.root, value)
        self.assertEqual(list(self.root.iterdir()), [])
        # Existing human-chosen local labels and generated UUIDs stay usable.
        self.assertEqual(path_component('case 1'), 'case 1')
        ws = CaseWorkspace(self.root, 'fixture-case')
        self.assertEqual(ws.root, self.root / 'fixture-case')

    def test_symlinked_case_is_rejected_without_writing_outside(self):
        other = self.root / 'other'
        other.mkdir()
        (self.root / 'case').symlink_to(other, target_is_directory=True)
        with self.assertRaises(ValueError):
            CaseWorkspace(self.root, 'case')
        self.assertEqual(list(other.iterdir()), [])

    def test_cute_store_reads_only_the_digest_bound_blob(self):
        store = CuteStore(self.root / 'store')
        ev = store.put_bytes(b'synthetic evidence', 'fixture:submitted', case_id='case')
        self.assertEqual(store.read_bytes(ev.evidence_id), b'synthetic evidence')
        for key in ('../../outside', '/tmp/file', 'blobs/aa/wrong'):
            store._index[ev.evidence_id] = replace(ev, storage_key=key)
            with self.subTest(key=key), self.assertRaises(ValueError):
                store.read_bytes(ev.evidence_id)

    def test_cute_blob_tampering_and_symlinks_are_rejected(self):
        store = CuteStore(self.root / 'store')
        ev = store.put_bytes(b'synthetic evidence', 'fixture:submitted')
        blob = self.root / 'store' / ev.storage_key
        blob.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            store.read_bytes(ev.evidence_id)
        blob.unlink()
        outside = self.root / 'outside'
        outside.write_bytes(b'synthetic evidence')
        blob.symlink_to(outside)
        with self.assertRaises(ValueError):
            store.read_bytes(ev.evidence_id)

    def test_osint_store_rejects_case_and_digest_traversal(self):
        store = OsintStore(self.root / 'store')
        digest = store.put('case', b'fixture')
        self.assertEqual(store.get('case', digest), b'fixture')
        for case in ('../outside', '/absolute', '..\\outside'):
            with self.subTest(case=case), self.assertRaises(ValueError):
                store.put(case, b'fixture')
        for bad in ('../outside', '/absolute', 'not-a-digest'):
            with self.subTest(digest=bad), self.assertRaises(EvidenceError):
                store.get('case', bad)
            with self.assertRaises(EvidenceError):
                store.exists('case', bad)

    def test_report_state_symlink_cannot_read_a_foreign_record(self):
        ws = CaseWorkspace(self.root, 'case')
        outside = self.root / 'outside.json'
        outside.write_text(json.dumps({'objective': 'FOREIGN RECORD'}))
        ws.state_path.symlink_to(outside)
        with self.assertRaises(ValueError):
            ReportManager().build(ws.root)
        self.assertFalse((ws.root / 'report.md').exists())

    def test_report_output_symlink_cannot_overwrite_a_foreign_file(self):
        ws = CaseWorkspace(self.root, 'case')
        ws.state_path.write_text(json.dumps({'case_id': 'case', 'objective': 'Fixture'}))
        outside = self.root / 'outside.txt'
        outside.write_text('UNCHANGED')
        (ws.root / 'report.md').symlink_to(outside)
        with self.assertRaises(ValueError):
            ReportManager().build(ws.root)
        self.assertEqual(outside.read_text(), 'UNCHANGED')

    def test_readable_reference_code_is_inert_and_hash_mapped(self):
        repo = Path(__file__).resolve().parents[1]
        manifest = json.loads((repo / 'docs/archive_merge_manifest.json').read_text())
        self.assertEqual(sum(len(a['files']) for a in manifest['archives']), 1863)
        for archive in manifest['archives']:
            for row in archive['files']:
                if row['state'] == 'PRESERVED_INERT_REFERENCE':
                    self.assertTrue(row['preserved_path'].endswith('.source'))
        self.assertEqual(list((repo / 'public/academy/js').glob('*.js')), [])


if __name__ == '__main__':
    unittest.main()
