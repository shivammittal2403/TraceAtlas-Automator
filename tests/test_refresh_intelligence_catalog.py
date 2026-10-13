"""Catalog maintenance must never rewrite source provenance or accept unknown IDs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "refresh_intelligence_catalog",
    Path(__file__).resolve().parents[1] / "scripts/refresh_intelligence_catalog.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CatalogRefreshTests(unittest.TestCase):
    def fixture(self, root):
        (root / "modules").mkdir()
        source = b"value = 42\r\n"
        (root / "modules/example.py").write_bytes(source)
        catalog = {"modules": [{"id": "example", "file_sha256": "old",
                                "original_sha256": "original", "stored_source_sha256": "stored",
                                "version": "1.0.0", "live_verified": False}],
                   "archive_sha256": "archive"}
        (root / "catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
        return catalog, source

    def test_only_maintained_hash_changes_and_second_run_is_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected, source = self.fixture(root)
            self.assertEqual(MODULE.refresh(root, ["example"]), ["example"])
            expected["modules"][0]["file_sha256"] = hashlib.sha256(source).hexdigest()
            self.assertEqual(json.loads((root / "catalog.json").read_text()), expected)
            before = (root / "catalog.json").read_bytes()
            self.assertEqual(MODULE.refresh(root, ["example"]), [])
            self.assertEqual((root / "catalog.json").read_bytes(), before)

    def test_unknown_id_and_invalid_python_leave_catalog_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            before = (root / "catalog.json").read_bytes()
            with self.assertRaises(ValueError):
                MODULE.refresh(root, ["example", "../unexpected"])
            self.assertEqual((root / "catalog.json").read_bytes(), before)
            (root / "modules/example.py").write_text("def broken(", encoding="utf-8")
            with self.assertRaises(SyntaxError):
                MODULE.refresh(root, ["example"])
            self.assertEqual((root / "catalog.json").read_bytes(), before)
