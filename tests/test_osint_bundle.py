"""Verify the delivered ZIP as a portable executable source bundle."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("osint_bundle_builder", REPOSITORY / "scripts/build_osint_bundle.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class OSINTBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.archive = cls.directory / "TraceAtlas-OSINT.zip"
        cls.report = BUILDER.build_bundle(REPOSITORY, cls.archive)
        cls.extracted = cls.directory / "extracted"
        with zipfile.ZipFile(cls.archive) as archive:
            archive.extractall(cls.extracted)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.unrelated = Path(self.work.name)

    def launch(self, *arguments):
        result = subprocess.run([sys.executable, "-I", "-S", str(self.extracted / "OSINT PYTHON.py"), *arguments],
                                cwd=self.unrelated, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stderr, b"")
        return json.loads(result.stdout)

    def test_extracted_source_runs_without_installed_packages_or_repository_cwd(self):
        check = self.launch("check")
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(check["requested_disciplines"], 140)
        self.assertEqual(check["canonical_modules"], 135)
        self.assertFalse(check["live_verified"])
        output = self.unrelated / "academic-result.json"
        result = self.launch("run", "ACADEMICINT", "--input",
                             str(self.extracted / "examples/osint140/academic.json"), "--output", str(output))
        self.assertEqual(result["canonical_id"], "accadmicint")
        self.assertEqual(result["draft"]["bibliometrics"]["publication_count"], 2)
        self.assertEqual({row["publication_id"] for row in result["draft"]["publications"]}, {"P1", "P2"})
        self.assertEqual(set(result["draft"]["source_ids"]), {"S1", "S2"})
        self.assertEqual(result["network_calls"], 0)
        self.assertFalse(result["live_verified"])
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), result)
        self.assertEqual(self.report["status"], "CREATED")
        self.assertGreater(self.report["file_count"], 135)

    def test_existing_output_and_missing_required_source_leave_artifacts_untouched(self):
        output = self.unrelated / "existing.zip"
        output.write_bytes(b"existing user artifact")
        with self.assertRaises(FileExistsError):
            BUILDER.build_bundle(self.extracted, output)
        self.assertEqual(output.read_bytes(), b"existing user artifact")
        required = self.extracted / "LICENSE"
        original = required.read_bytes()
        required.unlink()
        missing_output = self.unrelated / "missing-source.zip"
        try:
            with self.assertRaises(FileNotFoundError):
                BUILDER.build_bundle(self.extracted, missing_output)
            self.assertFalse(missing_output.exists())
        finally:
            required.write_bytes(original)

    def test_corrupted_module_or_catalog_is_not_published_as_a_bundle(self):
        module = self.extracted / "src/traceatlas/addons/intelligence_v1/modules/accadmicint.py"
        original = module.read_bytes()
        output = self.unrelated / "changed-module.zip"
        try:
            module.write_bytes(original + b"\n# synthetic changed source\n")
            with self.assertRaisesRegex(ValueError, "differs from its catalog"):
                BUILDER.build_bundle(self.extracted, output)
            self.assertFalse(output.exists())
        finally:
            module.write_bytes(original)
        catalog = self.extracted / "src/traceatlas/addons/intelligence_v1/catalog.json"
        original = catalog.read_bytes()
        output = self.unrelated / "malformed-catalog.zip"
        try:
            value = json.loads(original)
            value["support_files_sha256"] = []
            catalog.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                BUILDER.build_bundle(self.extracted, output)
            self.assertFalse(output.exists())
        finally:
            catalog.write_bytes(original)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
