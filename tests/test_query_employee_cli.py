"""Canonical CLI integration: query-plan and query-fuse remain offline."""
import argparse
import json
import tempfile
import unittest
from pathlib import Path
from traceatlas.workforce.cli import add_workforce_parser, run_workforce


class QueryEmployeeCliTests(unittest.TestCase):
    def parser(self, *items):
        ap = argparse.ArgumentParser()
        add_workforce_parser(ap.add_subparsers(dest="command", required=True))
        return ap.parse_args(["workforce", *items])

    def test_query_plan_uses_existing_workforce_cli(self):
        args = self.parser("query-plan", "--case", "case-001",
                           "--query", "Check company financial ownership and geolocation",
                           "--target-type", "company", "--target", "ACME")
        data = run_workforce(args, None)
        self.assertEqual(data["schema"], "query-employee/v1")
        self.assertFalse(data["policy"]["live_collection"])
        self.assertIn("FININT", [t["department"] for t in data["tasks"]])

    def test_fuse_cli_reads_only_supplied_file(self):
        plan_args = self.parser("query-plan", "--case", "case-001",
                                "--query", "Check public company ownership details",
                                "--target-type", "company", "--target", "ACME")
        plan = run_workforce(plan_args, None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source.json"
            path.write_text(json.dumps({"plan": plan, "results": []}))
            result = run_workforce(self.parser("query-fuse", "--input", str(path)), None)
        self.assertEqual(result["approved_facts"], [])
        self.assertTrue(result["unresolved_departments"])

    def test_cli_rejects_invalid_json_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.json"
            path.write_text(json.dumps({"evil": "run"}))
            with self.assertRaisesRegex(ValueError, "exactly plan"):
                run_workforce(self.parser("query-fuse", "--input", str(path)), None)


if __name__ == "__main__":
    unittest.main()
