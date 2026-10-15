"""Cross-platform worker restrictions and finite result contracts."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from traceatlas.addons.intelligence_v1.registry import ROOT
from traceatlas.policy import PolicyError
from traceatlas.workforce.intelligence import run_offline


class PortableWorkerTests(unittest.TestCase):
    def child(self, statement, resource_absent=False):
        code = (
            "import sys,socket,sqlite3,subprocess;"
            "sys.path.insert(0," + repr(str(ROOT.parents[2])) + ");"
            "from traceatlas.addons.intelligence_v1.worker import restrict_process;"
            + ("sys.modules['resource']=None;" if resource_absent else "")
            + "restrict_process();" + statement
        )
        return subprocess.run([sys.executable, "-I", "-B", "-c", code],
                              capture_output=True, timeout=10)

    def test_worker_runs_when_posix_resource_is_unavailable(self):
        result = self.child("print('ready')", resource_absent=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout.strip(), b"ready")

    def test_missing_resource_preserves_network_database_and_process_denials(self):
        for statement in ("socket.socket()", "sqlite3.connect(':memory:')",
                          "subprocess.run([sys.executable, '-c', 'pass'])"):
            with self.subTest(statement=statement):
                result = self.child(statement, resource_absent=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"PermissionError", result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_external_reads_and_writes_are_denied_on_each_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "private.txt"
            source.write_text("synthetic private fixture", encoding="utf-8")
            output = Path(directory) / "must-not-exist.txt"
            for statement in ("open(" + repr(str(source)) + ").read()",
                              "open(" + repr(str(output)) + ", 'w').write('x')"):
                with self.subTest(statement=statement):
                    result = self.child(statement, resource_absent=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b"PermissionError", result.stderr)
                    self.assertEqual(result.stdout, b"")
            self.assertFalse(output.exists())

    def test_nonempty_supplied_metadata_review_in_a_real_worker(self):
        data = {"case_id": "portable-case", "research_records": [
            {"record_id": "R-PORTABLE", "record_type": "PUBLIC_RESEARCH",
             "source_id": "SYNTHETIC-LOCAL", "publication_date": "2026-01-01",
             "method": "Synthetic metadata fixture", "limitations": ["Synthetic test input"]}
        ]}
        item, result = run_offline("bioint", data)
        self.assertEqual(item["id"], "bioint")
        self.assertEqual(result["status"], "ANALYSIS_DRAFT")
        self.assertTrue(result["observations"][0]["metadata_complete"])
        self.assertEqual(result["observations"][0]["record_id"], "R-PORTABLE")
        self.assertEqual(result["knowledge_gaps"], [])
        self.assertEqual(result["network_calls"], 0)
        self.assertFalse(result["source_authenticity_verified"])

    def test_unicode_result_uses_utf8_under_ascii_child_stdio(self):
        original_run = subprocess.run

        def force_ascii(*args, **kwargs):
            kwargs["env"] = {**kwargs["env"], "PYTHONIOENCODING": "ascii"}
            return original_run(*args, **kwargs)

        data = {"case_id": "portable-case", "research_records": [
            {"record_id": "R-研究-हिन्दी", "record_type": "PUBLIC_RESEARCH",
             "source_id": "SYNTHETIC-LOCAL", "publication_date": "2026-01-01",
             "method": "Synthetic fixture", "limitations": ["Synthetic test input"]}
        ]}
        with patch("traceatlas.workforce.intelligence.subprocess.run", side_effect=force_ascii):
            _, result = run_offline("bioint", data)
        self.assertEqual(result["observations"][0]["record_id"], "R-研究-हिन्दी")


class FiniteResultTests(unittest.TestCase):
    def output(self, body):
        return patch("traceatlas.workforce.intelligence.subprocess.run",
                     return_value=subprocess.CompletedProcess([], 0, stdout=body, stderr=b""))

    def test_nonfinite_constants_and_numeric_overflow_are_rejected(self):
        for number in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"):
            with self.subTest(number=number), self.output(b'{"nested":[{"number":' + number + b'}]}'):
                with self.assertRaises(PolicyError):
                    run_offline("bioint", {})

    def test_json_scalar_is_not_a_module_result(self):
        for body in (b"null", b"true", b"42", b'"text"'):
            with self.subTest(body=body), self.output(body):
                with self.assertRaises(PolicyError):
                    run_offline("bioint", {})

    def test_finite_numbers_preserve_valid_json(self):
        body = b'{"integer":2,"decimal":1.25,"small":1e-10,"large":1e308}'
        with self.output(body):
            _, result = run_offline("bioint", {})
        self.assertEqual(result, json.loads(body))
        json.dumps(result, allow_nan=False)

    def test_process_start_failure_is_a_sanitized_contract_error(self):
        with patch("traceatlas.workforce.intelligence.subprocess.run",
                   side_effect=OSError("synthetic-private-path")):
            with self.assertRaises(PolicyError) as error:
                run_offline("bioint", {})
        self.assertNotIn("synthetic-private-path", str(error.exception))


if __name__ == "__main__":
    unittest.main()
