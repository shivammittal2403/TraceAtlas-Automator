import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.evidence_anchor import HmacFileLedgerAnchor, configured_ledger_anchor


class EvidenceAnchorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.db = CaseDB(self.workspace / "cases.sqlite3")
        self.db.create_case("case-a", "Synthetic anchor test", "Controlled fixture")
        self.key = b"synthetic-test-key-not-for-production-0001"
        self.anchor = HmacFileLedgerAnchor(
            self.root / "external-anchor", self.workspace, lambda: self.key, key_id="test-key-v1",
        )
        self.source = self.workspace / "source.txt"
        self.source.write_bytes(b"synthetic evidence\n")

    def tearDown(self):
        self.db.close()
        self.temporary.cleanup()

    def store(self, *, anchor=True, required=True):
        return EvidenceStore(
            self.workspace, self.db, "case-a",
            anchor=self.anchor if anchor else None, require_anchor=required,
        )

    def test_required_anchor_rejects_missing_or_in_workspace_anchor(self):
        with self.assertRaisesRegex(ValueError, "required"):
            self.store(anchor=False)
        with self.assertRaisesRegex(ValueError, "outside"):
            HmacFileLedgerAnchor(
                self.workspace / "anchor", self.workspace, lambda: self.key, key_id="test-key-v1",
            )

    def test_signed_external_receipt_detects_full_local_reanchoring(self):
        store = self.store()
        store.preserve_file(self.source, "fixture")
        self.assertEqual(store.verify_ledger(), (True, 1))

        row = self.db.evidence("case-a")[0]
        captured_path = Path(row["path"])
        replacement = b"attacker replacement bytes\n"
        captured_path.write_bytes(replacement)
        new_digest = hashlib.sha256(replacement).hexdigest()
        self.db.conn.execute(
            "UPDATE evidence SET sha256=?,size=? WHERE case_id=? AND sha256=?",
            (new_digest, len(replacement), "case-a", row["sha256"]),
        )
        self.db.conn.commit()
        entry = json.loads(store.ledger.read_text(encoding="utf-8").splitlines()[0])
        entry["sha256"] = new_digest
        entry.pop("entry_hash")
        entry["entry_hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        store.ledger.write_text(json.dumps(entry, sort_keys=True) + "\n", encoding="utf-8")

        self.assertEqual(store.verify_ledger(), (False, 1))

    def test_anchored_bundle_requires_verifier_and_carries_receipt(self):
        store = self.store()
        store.preserve_file(self.source, "fixture")
        bundle = self.root / "anchored.zip"
        store.export_bundle(bundle)
        self.assertTrue(EvidenceStore.verify_bundle(bundle, anchor=self.anchor, require_anchor=True))
        self.assertFalse(EvidenceStore.verify_bundle(bundle))
        self.assertFalse(EvidenceStore.verify_bundle(bundle, require_anchor=True))

    def test_anchor_cannot_move_backwards_or_replace_same_sequence(self):
        first = self.anchor.publish("case-a", 2, "a" * 64)
        self.assertTrue(self.anchor.verify("case-a", 2, "a" * 64, first))
        with self.assertRaisesRegex(ValueError, "backwards"):
            self.anchor.publish("case-a", 1, "0" * 64)
        with self.assertRaisesRegex(ValueError, "same sequence"):
            self.anchor.publish("case-a", 2, "b" * 64)

    def test_environment_configuration_anchors_application_stores_and_exports(self):
        values = {
            "TRACEATLAS_EVIDENCE_ANCHOR_DIR": str(self.root / "environment-anchor"),
            "TRACEATLAS_EVIDENCE_ANCHOR_KEY_HEX": self.key.hex(),
            "TRACEATLAS_EVIDENCE_ANCHOR_KEY_ID": "environment-key-v1",
            "TRACEATLAS_EVIDENCE_ANCHOR_REQUIRED": "1",
        }
        with patch.dict(os.environ, values):
            store = EvidenceStore(self.workspace, self.db, "case-a")
            store.preserve_file(self.source, "fixture")
            self.assertEqual(store.verify_ledger(), (True, 1))
            bundle = self.root / "environment-anchored.zip"
            store.export_bundle(bundle)
            verifier, required = configured_ledger_anchor(self.workspace)
            self.assertTrue(required)
            self.assertTrue(EvidenceStore.verify_bundle(bundle, anchor=verifier, require_anchor=required))

    def test_environment_required_without_key_fails_closed(self):
        values = {
            "TRACEATLAS_EVIDENCE_ANCHOR_DIR": str(self.root / "environment-anchor"),
            "TRACEATLAS_EVIDENCE_ANCHOR_KEY_HEX": "",
            "TRACEATLAS_EVIDENCE_ANCHOR_REQUIRED": "0",
        }
        with patch.dict(os.environ, values):
            with self.assertRaisesRegex(ValueError, "without an operator key"):
                EvidenceStore(self.workspace, self.db, "case-a")

    def test_reviewed_bootstrap_migrates_an_existing_verified_case(self):
        legacy = EvidenceStore(self.workspace, self.db, "case-a", use_environment_anchor=False)
        legacy.preserve_file(self.source, "fixture")
        anchored = EvidenceStore(self.workspace, self.db, "case-a", anchor=self.anchor, require_anchor=True)
        self.assertEqual(anchored.verify_ledger(), (False, 1))
        with self.assertRaisesRegex(ValueError, "review reference"):
            anchored.bootstrap_anchor_after_review("")
        receipt = anchored.bootstrap_anchor_after_review("change-control-42")
        self.assertTrue(self.anchor.verify("case-a", 2, receipt["ledger_head"], receipt))
        self.assertEqual(anchored.verify_ledger(), (True, 2))
        entries = [json.loads(line) for line in anchored.ledger.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(entries[-1]["action"], "anchor_bootstrap")
        self.assertEqual(entries[-1]["review_id"], "change-control-42")


if __name__ == "__main__":
    unittest.main()

