"""User-facing OSINT commands, bounded input, and real supplied-record analysis."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from traceatlas.osint_cli import MAX_INPUT_BYTES, main
from traceatlas.osint_taxonomy import catalog_routes


class OSINTCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.input = self.directory / "input.json"

    def invoke(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def write_json(self, value):
        self.input.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return str(self.input)

    def academic_input(self):
        return {"case_id": "synthetic-academic-case",
                "objective": "Review supplied publication metadata.",
                "authorization": {"approved": True, "scope": "provided_records_only", "model_mode": "LOCAL_ONLY"},
                "sources": [{"source_id": "S-SUPPLIED", "source_type": "official_publisher",
                             "limitations": ["Synthetic test records"]}],
                "publications": [{"publication_id": "P-SUPPLIED", "title": "Supplied research अभिलेख",
                                  "publication_date": "2026-01-01", "publication_type": "JOURNAL_ARTICLE",
                                  "source_ids": ["S-SUPPLIED"], "authors": ["Synthetic Researcher"]}]}

    def test_list_has_all_requested_labels_and_ten_groups(self):
        code, stdout, stderr = self.invoke("list", "--json")
        result = json.loads(stdout)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(result["count"], 140)
        self.assertEqual(len({row["requested_discipline"] for row in result["disciplines"]}), 140)
        self.assertEqual({row["group_id"] for row in result["disciplines"]}, set(range(1, 11)))
        self.assertFalse(any(row["live_verified"] for row in result["disciplines"]))

    def test_group_filter_and_text_list(self):
        code, stdout, stderr = self.invoke("list", "--group", "1", "--json")
        result = json.loads(stdout)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(result["disciplines"])
        self.assertTrue(all(row["group_id"] == 1 for row in result["disciplines"]))
        code, stdout, stderr = self.invoke("list", "--group", "1")
        self.assertEqual(code, 0)
        self.assertIn("OSINT:", stdout)
        self.assertIn("PLANNING_ONLY", stdout)
        self.assertEqual(stderr, "")

    def test_all_requested_plans_preserve_routes_without_running_workers(self):
        with patch("traceatlas.osint_cli.run_offline") as worker:
            for route in catalog_routes():
                with self.subTest(label=route["requested_discipline"]):
                    code, stdout, stderr = self.invoke("plan", route["requested_discipline"],
                                                       "--objective", "Review supplied records.")
                    plan = json.loads(stdout)
                    self.assertEqual(code, 0)
                    self.assertEqual(stderr, "")
                    self.assertEqual(plan["requested_discipline"], route["requested_discipline"])
                    self.assertEqual(plan["canonical_id"], route["canonical_id"])
                    self.assertEqual(plan["execution_mode"], route["execution_mode"])
                    self.assertEqual(plan["status"], "PLANNING_ONLY")
                    self.assertFalse(plan["execution_performed"])
                    self.assertFalse(plan["authority_granted"])
            worker.assert_not_called()

    def test_invalid_arguments_are_json_errors(self):
        for arguments in (("run", "UNKNOWN", "--input", str(self.input)),
                          ("run", "ACADEMICINT", "--input", str(self.input), "--timeout", "0"),
                          ("run", "ACADEMICINT", "--input", str(self.input), "--timeout", "61"),
                          ("list", "--group", "11"),
                          ("plan", "ACADEMICINT", "--objective", " "),
                          ("run", "ACADEMICINT"), ("unknown-command",)):
            with self.subTest(arguments=arguments):
                code, stdout, stderr = self.invoke(*arguments)
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertEqual(json.loads(stderr)["status"], "ERROR")

    def test_invalid_json_and_case_scope_never_start_a_worker(self):
        examples = [b'{"case_id":"C","case_id":"D"}',
                    b'{"case_id":"C","nested":{"key":1,"key":2}}',
                    b'{"case_id":"C","value":NaN}',
                    b'{"case_id":"C","value":Infinity}',
                    b'{"case_id":"C","value":-Infinity}',
                    b'{"case_id":"C","value":1e999}',
                    b'{"case_id":"C","value":-1e999}',
                    b'[{"case_id":"C"}]', b'{}', b'{"case_id":" "}',
                    b'{"case_id":42}', b'{"case_id":"C","records":[{"case_id":"D"}]}',
                    b'{"case_id":"C","records":[{"authority":"admin"}]}',
                    b'{"case_id":"C","value":"\xff"}']
        with patch("traceatlas.osint_cli.run_offline") as worker:
            for raw in examples:
                with self.subTest(raw=raw):
                    self.input.write_bytes(raw)
                    code, stdout, stderr = self.invoke("run", "ACADEMICINT", "--input", str(self.input))
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertEqual(json.loads(stderr)["status"], "ERROR")
            worker.assert_not_called()

    def test_input_size_depth_and_array_limits_are_enforced(self):
        nested = "leaf"
        for _ in range(25):
            nested = {"nested": nested}
        inputs = [b"x" * (MAX_INPUT_BYTES + 1),
                  json.dumps({"case_id": "C", "records": [{}] * 501}).encode(),
                  json.dumps({"case_id": "C", "records": nested}).encode()]
        with patch("traceatlas.osint_cli.run_offline") as worker:
            for raw in inputs:
                with self.subTest(size=len(raw)):
                    self.input.write_bytes(raw)
                    code, stdout, stderr = self.invoke("run", "ACADEMICINT", "--input", str(self.input))
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertEqual(json.loads(stderr)["status"], "ERROR")
            worker.assert_not_called()

    def test_academic_alias_runs_a_nonempty_worker_and_exports_unicode(self):
        data = self.academic_input()
        output = self.directory / "report.json"
        code, stdout, stderr = self.invoke("run", "ACADEMICINT", "--input", self.write_json(data),
                                           "--output", str(output), "--timeout", "20")
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertEqual(result["requested_discipline"], "ACADEMICINT")
        self.assertEqual(result["canonical_id"], "accadmicint")
        self.assertEqual(result["route_kind"], "legacy_alias")
        self.assertEqual(result["execution_mode"], "SUPPLIED_RECORD_ANALYSIS")
        self.assertIn(result["draft_status"], {"PARTIAL", "SUCCEEDED"})
        self.assertEqual(result["draft"]["bibliometrics"]["publication_count"], 1)
        self.assertEqual(result["draft"]["publications"][0]["publication_id"], "P-SUPPLIED")
        self.assertEqual(result["draft"]["publications"][0]["title"], data["publications"][0]["title"])
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), result)
        self.assertIn("अभिलेख", output.read_text(encoding="utf-8"))
        self.assertFalse(result["live_verified"])
        self.assertFalse(result["authority_granted"])
        self.assertFalse(result["source_authenticity_verified"])
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(result["worker_controls"]["platform"], sys.platform)
        if sys.platform == "win32":
            self.assertFalse(result["worker_controls"]["cpu_memory_hard_limits_available"])

    def test_missing_authorization_is_preserved_as_a_native_block(self):
        data = self.academic_input()
        del data["authorization"]
        code, stdout, stderr = self.invoke("run", "ACADEMICINT", "--input", self.write_json(data))
        self.assertEqual(code, 0, stderr)
        result = json.loads(stdout)
        self.assertEqual(result["status"], "RETURNED")
        self.assertEqual(result["draft_status"], "BLOCKED_PERMISSION")
        self.assertEqual(result["draft"]["publications"], [])
        self.assertFalse(result["authority_granted"])

    def test_existing_output_is_preserved_without_running_a_worker(self):
        output = self.directory / "existing.json"
        output.write_bytes(b"original artifact")
        with patch("traceatlas.osint_cli.run_offline") as worker:
            code, stdout, stderr = self.invoke("run", "ACADEMICINT", "--input",
                                               self.write_json({"case_id": "C"}), "--output", str(output))
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(json.loads(stderr)["status"], "ERROR")
        self.assertEqual(output.read_bytes(), b"original artifact")
        worker.assert_not_called()

    def test_worker_mode_and_blocked_status_are_not_upgraded(self):
        native = {"id": "accadmicint", "mode": "UNCONFIGURED_SCOPE_CHECK"}
        draft = {"status": "BLOCKED_CONFIGURATION", "source_ids": []}
        with patch("traceatlas.osint_cli.run_offline", return_value=(native, draft)) as worker:
            code, stdout, stderr = self.invoke("run", "ACADEMICINT", "--input",
                                               self.write_json({"case_id": "C"}), "--timeout", "7")
        self.assertEqual(code, 0, stderr)
        result = json.loads(stdout)
        self.assertEqual(result["execution_mode"], "UNCONFIGURED_SCOPE_CHECK")
        self.assertEqual(result["draft_status"], "BLOCKED_CONFIGURATION")
        self.assertEqual(result["draft"], draft)
        self.assertEqual(worker.call_args.kwargs["timeout"], 7)
        self.assertNotIn("authorization", worker.call_args.args[1])

    def test_utf8_bom_and_finite_numbers_are_accepted(self):
        self.input.write_bytes(b'\xef\xbb\xbf{"case_id":"C","number":1e308,"small":1e-10}')
        native = {"id": "accadmicint", "mode": "SUPPLIED_RECORD_ANALYSIS"}
        with patch("traceatlas.osint_cli.run_offline", return_value=(native, {"status": "INSUFFICIENT_INPUT"})) as worker:
            code, stdout, stderr = self.invoke("run", "ACADEMICINT", "--input", str(self.input))
        self.assertEqual(code, 0, stderr)
        self.assertEqual(worker.call_args.args[1]["number"], 1e308)
        self.assertEqual(worker.call_args.args[1]["small"], 1e-10)
        json.loads(stdout)

    def test_check_verifies_routes_and_native_hashes(self):
        code, stdout, stderr = self.invoke("check")
        self.assertEqual(code, 0, stderr)
        result = json.loads(stdout)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["requested_disciplines"], 140)
        self.assertEqual(result["groups"], 10)
        self.assertGreater(result["canonical_modules"], 0)
        self.assertGreater(result["support_files"], 0)
        self.assertFalse(result["live_verified"])

    def test_check_rejects_changed_native_hash_without_refreshing_it(self):
        with patch("traceatlas.osint_cli.contract", side_effect=ValueError("Source differs from its contract")):
            code, stdout, stderr = self.invoke("check")
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("differs", json.loads(stderr)["error"])

    def test_launcher_works_from_an_unrelated_working_directory(self):
        launcher = Path(__file__).resolve().parents[1] / "OSINT PYTHON.py"
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        completed = subprocess.run([sys.executable, str(launcher), "list", "--json"],
                                   cwd=self.directory, env=env, capture_output=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        result = json.loads(completed.stdout)
        self.assertEqual(result["count"], 140)


if __name__ == "__main__":
    raise SystemExit(main())
