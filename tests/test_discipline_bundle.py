"""Exercise the employee source ZIP without installed packages or repository cwd."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPOSITORY = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "employee_bundle_builder", REPOSITORY / "scripts/build_employee_bundle.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class DisciplineBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.archive = cls.directory / "TraceAtlas-Employees.zip"
        cls.report = BUILDER.build_bundle(REPOSITORY, cls.archive)
        cls.extracted = cls.directory / "extracted"
        with zipfile.ZipFile(cls.archive) as archive:
            archive.extractall(cls.extracted)

    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.unrelated = Path(self.work.name)

    def python_json(self, relative, *arguments):
        completed = subprocess.run(
            [sys.executable, "-I", "-S", str(self.extracted / relative), *arguments],
            cwd=self.unrelated, capture_output=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        self.assertEqual(completed.stderr, b"")
        return json.loads(completed.stdout)

    def test_extracted_all140_team_preserves_assignment_evidence_and_output(self):
        catalog = self.python_json("EMPLOYEES PYTHON.py", "catalog")
        original_entry = self.python_json("OSINT PYTHON.py", "employees", "catalog")
        self.assertEqual(original_entry["implemented"], 140)
        self.assertEqual(catalog["requested"], 140)
        self.assertEqual(catalog["implemented"], 140)
        self.assertEqual(catalog["remaining"], 0)
        labels = {row["discipline"] for row in catalog["employees"]}
        self.assertEqual(len(labels), 140)
        recipe = self.extracted / "examples/employees/all140.json"
        source = json.loads(recipe.read_text(encoding="utf-8"))
        assignments = {row["discipline"]: row for row in source["assignments"]}
        output = self.unrelated / "all140-review.json"
        team = self.python_json("EMPLOYEES PYTHON.py", "team",
                                "--input", str(recipe), "--output", str(output))
        self.assertEqual(team["schema"], "traceatlas.discipline.team.v1")
        self.assertEqual(team["employees_executed"], 140)
        self.assertEqual(len(team["drafts"]), 140)
        self.assertEqual({row["discipline"] for row in team["drafts"]}, labels)
        self.assertEqual(set(assignments), labels)
        self.assertEqual(team["network_calls"], 0)
        self.assertEqual(team["model_calls"], 0)
        self.assertFalse(team["source_authenticity_verified"])
        self.assertFalse(team["factual_entailment_verified"])
        for draft in team["drafts"]:
            with self.subTest(discipline=draft["discipline"]):
                self.assertIn(draft["status"], {"ANALYSIS_COMPLETE", "PARTIAL"})
                self.assertEqual(draft["network_calls"], 0)
                self.assertEqual(draft["model_calls"], 0)
                self.assertTrue(draft["findings"])
                records = {row["record_id"]: row for row in assignments[draft["discipline"]]["records"]}
                for finding in draft["findings"]:
                    refs = set(finding["record_ids"])
                    self.assertTrue(refs)
                    self.assertLessEqual(refs, set(records))
                    self.assertEqual(set(finding["source_ids"]),
                                     {records[identifier]["source_id"] for identifier in refs})
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), team)
        self.assertFalse((self.unrelated / ".traceatlas").exists())

    def test_extracted_dns_recipe_and_legacy_pins_run_from_unrelated_directory(self):
        dns = self.python_json("EMPLOYEES PYTHON.py", "analyze", "DNSINT", "--input",
                               str(self.extracted / "examples/employees/recipes/DNSINT.json"))
        self.assertEqual(dns["discipline"], "DNSINT")
        self.assertEqual(dns["metrics"]["cname_cycles"], 1)
        self.assertEqual(dns["metrics"]["cname_conflicts"], 1)
        self.assertTrue(any(row["kind"] == "dns_cname_cycle" for row in dns["findings"]))
        check = self.python_json("OSINT PYTHON.py", "check")
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(check["canonical_modules"], 135)
        self.assertEqual(check["requested_disciplines"], 140)

    def test_delivered_source_rebuilds_byte_identical_bundle(self):
        output = self.unrelated / "rebuilt.zip"
        rebuilt = self.python_json("scripts/build_employee_bundle.py", "--output", str(output))
        self.assertEqual(rebuilt["status"], "CREATED")
        self.assertEqual(rebuilt["file_count"], self.report["file_count"])
        self.assertEqual(rebuilt["sha256"], self.report["sha256"])
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), self.report["sha256"])
        self.assertEqual(output.read_bytes(), self.archive.read_bytes())

    def test_existing_output_and_missing_employee_document_are_preserved(self):
        existing = self.unrelated / "existing.zip"
        existing.write_bytes(b"existing user artifact")
        with self.assertRaises(FileExistsError):
            BUILDER.build_bundle(self.extracted, existing)
        self.assertEqual(existing.read_bytes(), b"existing user artifact")
        required = self.extracted / "EMPLOYEES_README.md"
        original = required.read_bytes()
        missing = self.unrelated / "missing-source.zip"
        required.unlink()
        try:
            with self.assertRaisesRegex(FileNotFoundError, "EMPLOYEES_README"):
                BUILDER.build_bundle(self.extracted, missing)
            self.assertFalse(missing.exists())
        finally:
            required.write_bytes(original)

    def test_example_symlink_is_refused_before_output_creation(self):
        link = self.extracted / "examples/employees/synthetic-link.json"
        try:
            link.symlink_to(self.extracted / "examples/employees/all140.json")
        except (OSError, NotImplementedError):
            self.skipTest("This system does not allow creating test symlinks")
        self.addCleanup(link.unlink)
        output = self.unrelated / "symlink-source.zip"
        with self.assertRaisesRegex(ValueError, "symlinks"):
            BUILDER.build_bundle(self.extracted, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
