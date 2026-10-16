"""CLI regression through the real standalone employee dispatcher."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from traceatlas.workforce.discipline_cli import main


class DisciplineCLITests(unittest.TestCase):
    def call(self, args):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = main(args)
        return code, json.loads((output.getvalue() or error.getvalue()).strip())

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

    def test_json_duplicate_fields_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            source.write_text('{"case_id":"a","case_id":"b"}', encoding="utf-8")
            code, result = self.call(["analyze", "DNSINT", "--input", str(source)])
            self.assertEqual(code, 2)
            self.assertIn("Duplicate", result["error"])


if __name__ == "__main__":
    unittest.main()
