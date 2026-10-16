"""CLI regression through the real standalone employee dispatcher."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from traceatlas.workforce.discipline_cli import main


class DisciplineCLITests(unittest.TestCase):
    def call(self, args):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = main(args)
        return code, json.loads((output.getvalue() or error.getvalue()).strip())

    def test_original_osint_entrypoint_exposes_all140_employee_catalog(self):
        from traceatlas.osint_cli import main as osint_main
        output = io.StringIO()
        with redirect_stdout(output):
            code = osint_main(["employees", "catalog"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["implemented"], 140)

    def test_catalog_has_truthful_inventory(self):
        code, result = self.call(["catalog"])
        self.assertEqual(code, 0)
        self.assertEqual(result["requested"], 140)
        self.assertGreaterEqual(result["implemented"], 40)

    def test_nonempty_analysis_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "input.json", root / "output.json"
            source.write_text(json.dumps({
                "case_id": "case-cli", "task_id": "task-cli", "discipline": "DNSINT",
                "objective": "Review supplied DNS records", "as_of": "2026-10-15T00:00:00Z",
                "sources": [{"source_id": "s", "uri": "urn:fixture:s"}],
                "records": [{"record_id": "r", "source_id": "s", "data": {
                    "name": "example.org", "type": "A", "value": "192.0.2.1"}}]}), encoding="utf-8")
            args = ["analyze", "DNSINT", "--input", str(source), "--output", str(destination)]
            code, result = self.call(args)
            self.assertEqual(code, 0)
            self.assertEqual(result["artifacts"]["records"][0]["value"], "192.0.2.1")
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), result)
            before = destination.read_bytes()
            code, _ = self.call(args)
            self.assertEqual(code, 2)
            self.assertEqual(destination.read_bytes(), before)

    def test_canonical_hypotheses_are_available_through_cli_and_read_only_replay(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
                "os.environ", {"TRACEATLAS_WORKFORCE_ENABLED": "1", "TRACEATLAS_WORKFORCE_KILL_SWITCH": "0"}):
            root = Path(directory)
            prefix = ["--workspace", str(root)]
            code, _ = self.call(prefix + ["case", "--case", "cli-review", "--title", "Synthetic review",
                "--purpose", "Controlled synthetic hypothesis review"])
            self.assertEqual(code, 0)
            code, authority = self.call(prefix + ["authorize", "--case", "cli-review",
                "--actor", "cli-analyst", "--purpose", "Controlled synthetic hypothesis review",
                "--jurisdiction", "IN", "--authorized"])
            self.assertEqual(code, 0)
            source = root / "hypotheses.json"
            source.write_text(json.dumps({"case_id": "cli-review", "discipline": "HYPOTHESISINT",
                "objective": "Review synthetic alternative propositions", "as_of": "2026-01-01T00:00:00Z",
                "sources": [{"source_id": "s", "uri": "urn:fixture:cli"}],
                "records": [{"record_id": "matrix", "source_id": "s", "data": {
                    "hypotheses": [{"id": "a", "statement": "First submitted explanation"},
                                   {"id": "b", "statement": "Alternative submitted explanation"}],
                    "evidence": []}}]}), encoding="utf-8")
            code, planned = self.call(prefix + ["plan", "HYPOTHESISINT",
                "--context", authority["authorization"]["context_id"], "--input", str(source)])
            self.assertEqual(code, 0)
            task_id = planned["task"]["task_id"]
            code, _ = self.call(prefix + ["approve", "--task", task_id, "--actor", "cli-analyst",
                "--envelope-digest", planned["envelope_digest"],
                "--rationale", "Approve exact controlled synthetic hypotheses", "--authorized"])
            self.assertEqual(code, 0)
            code, product = self.call(prefix + ["run", "--task", task_id, "--authorized"])
            self.assertEqual(code, 0)
            self.assertEqual(len(product["result"]["hypotheses"]), 2)
            with patch.dict("os.environ", {"TRACEATLAS_WORKFORCE_ENABLED": "0"}):
                code, replay = self.call(prefix + ["replay", "--task", task_id])
            self.assertEqual(code, 0)
            self.assertEqual(replay["status"], "VERIFIED_NATIVE_REVIEW")
            self.assertTrue(replay["semantic_recomputed"])
            self.assertFalse(replay["source_authenticity_verified"])

    def test_json_duplicate_fields_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            source.write_text('{"case_id":"a","case_id":"b"}', encoding="utf-8")
            code, result = self.call(["analyze", "DNSINT", "--input", str(source)])
            self.assertEqual(code, 2)
            self.assertIn("Duplicate", result["error"])


if __name__ == "__main__":
    unittest.main()
