"""Shared employee contracts and actual-engine canonical case lifecycle."""
import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from traceatlas.db import CaseDB
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.discipline_engines import invoke_employee, registered_handlers, engine_identity
from traceatlas.workforce.discipline_engines.common import make_context, text
from traceatlas.workforce.discipline_registry import employee_catalog, build_employee_definitions
from traceatlas.workforce.discipline_runtime import create_runtime
from traceatlas.workforce.registry import EmployeeRegistry


def fixture():
    return {"case_id": "case-test", "task_id": "task-test", "discipline": "DNSINT",
            "objective": "Review supplied DNS evidence", "as_of": "2026-10-15T00:00:00Z",
            "sources": [{"source_id": "s1", "uri": "urn:fixture:s1"}],
            "records": [{"record_id": "r1", "source_id": "s1",
                         "data": {"name": "example.org", "type": "A", "value": "192.0.2.1"}}]}


class DisciplineContractTests(unittest.TestCase):
    def test_catalog_separates_requested_and_actual_implementation(self):
        catalog, handlers = employee_catalog(), registered_handlers()
        self.assertEqual(catalog["requested"], 140)
        self.assertEqual(catalog["implemented"], len(handlers))
        self.assertEqual(catalog["remaining"], 140 - len(handlers))
        self.assertEqual(len(EmployeeRegistry().list()), 5)
        self.assertEqual({item.domain for item in build_employee_definitions()}, set(handlers))
        self.assertEqual(len({id(handler) for handler in handlers.values()}), len(handlers))
        for row in catalog["employees"]:
            self.assertEqual(row["implemented"], row["discipline"] in handlers)
            if row["implemented"]:
                self.assertRegex(row["engine_sha256"], r"^[0-9a-f]{64}$")

    def test_canonical_output_is_deterministic_and_evidence_bound(self):
        data = fixture()
        result = invoke_employee(data, evidence_ids=("evidence-input",))
        self.assertEqual(result, invoke_employee(copy.deepcopy(data), evidence_ids=("evidence-input",)))
        self.assertEqual(result["status"], "ANALYSIS_COMPLETE")
        self.assertEqual(result["findings"][0]["canonical_evidence_ids"], ["evidence-input"])
        self.assertEqual(result["findings"][0]["source_ids"], ["s1"])
        self.assertEqual(result["engine_sha256"], engine_identity("DNSINT"))
        self.assertFalse(result["factual_entailment_verified"])

    def test_empty_records_report_insufficient_data(self):
        data = fixture()
        data["records"] = []
        result = invoke_employee(data)
        self.assertEqual(result["status"], "INSUFFICIENT_DATA")
        self.assertEqual(result["findings"], [])

    def test_input_ids_sources_and_json_are_strict(self):
        mutations = [
            lambda d: d.update(unexpected=True),
            lambda d: d["sources"][0].update(content_sha256=int("1" * 64)),
            lambda d: d["sources"][0].update(uri="https://@example.org"),
            lambda d: d["sources"].append(copy.deepcopy(d["sources"][0])),
            lambda d: d["records"].append(copy.deepcopy(d["records"][0])),
            lambda d: d["records"][0].update(source_id="foreign"),
            lambda d: d.update(as_of="2026-10-15T00:00:00"),
            lambda d: d.update(parameters=[]),
            lambda d: d["records"][0]["data"].update(value=float("nan")),
            lambda d: d["records"][0]["data"].update(value=float("inf")),
            lambda d: d["records"][0]["data"].update(value="\ud800"),
            lambda d: d["sources"][0].update(uri="https://user:secret@example.org"),
            lambda d: d["sources"][0].update(uri="https://example.org/path with spaces"),
        ]
        for mutation in mutations:
            data = fixture()
            mutation(data)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                make_context(data)

    def test_nested_budgets_and_foreign_finding_refs(self):
        for value in (list(range(501)), "x" * 262145):
            data = fixture()
            data["records"][0]["data"]["oversized"] = value
            with self.assertRaises(ValueError):
                make_context(data)
        context = make_context(fixture())
        with self.assertRaises(ValueError):
            context.finding("test", "Foreign record refused.", ["foreign"])
        with self.assertRaises(ValueError):
            context.issue("foreign", "test", "Foreign issue refused.")
        with self.assertRaises(ValueError):
            make_context(fixture(), evidence_ids="evidence-input")

    def test_context_snapshot_and_deduplication(self):
        data = fixture()
        context = make_context(data)
        data["records"][0]["data"]["value"] = "203.0.113.2"
        self.assertEqual(context.records[0].data["value"], "192.0.2.1")
        for _ in range(2):
            context.finding("test", "One assertion.", ["r1"], {"valid": True})
        self.assertEqual(len(context.findings), 1)

    def test_text_helper_rejects_decoded_unpaired_surrogate(self):
        with self.assertRaises(ValueError):
            text("\ud800", "parsed value")

    def test_issue_and_finding_budgets_return_explicit_partial_output(self):
        context = make_context(fixture())
        for index in range(600):
            context.issue("r1", "issue_" + str(index), "Synthetic bounded issue")
            context.finding("finding_" + str(index), "Synthetic bounded finding", ["r1"])
        output = context.output()
        self.assertEqual(len(output["issues"]), 500)
        self.assertEqual(output["issues"][-1]["code"], "issues_truncated")
        self.assertEqual(len(output["findings"]), 500)
        self.assertEqual(output["metrics"]["finding_reports_suppressed"], 100)
        self.assertGreater(output["metrics"]["issue_reports_suppressed"], 0)

    def test_amplified_output_retains_bounded_evidence_linked_partial_result(self):
        context = make_context(fixture(), evidence_ids=("evidence-input",))
        for index in range(30):
            context.finding("large_" + str(index), "Large submitted derived field.", ["r1"],
                            {"text": "x" * 100000})
        result = context.output(artifacts={"large": ["y" * 100000 for _ in range(30)]})
        self.assertLess(len(__import__("json").dumps(result).encode()), 2 * 1024 * 1024)
        self.assertTrue(result["metrics"]["output_budget"]["artifact_fields_omitted"])
        self.assertGreater(result["metrics"]["output_budget"]["findings_omitted"], 0)
        self.assertIn("output_budget_exhausted", {issue["code"] for issue in result["issues"]})
        for finding in result["findings"]:
            self.assertEqual(finding["canonical_evidence_ids"], ["evidence-input"])
            self.assertEqual(finding["record_ids"], ["r1"])

    def test_derived_arrays_are_clipped_with_explicit_budget_metadata(self):
        context = make_context(fixture())
        context.finding("large_array", "Large derived row set.", ["r1"], {"rows": list(range(750))})
        result = context.output()
        self.assertEqual(len(result["findings"][0]["data"]["rows"]), 500)
        self.assertGreater(result["metrics"]["output_budget"]["structures_truncated"], 0)
        self.assertIn("derived_data_truncated", {issue["code"] for issue in result["issues"]})

    def test_actual_dns_engine_completes_canonical_case_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = CaseDB(root / "traceatlas.db")
            try:
                db.create_case("case-test", "Actual DNS analyzer", "Synthetic regression")
                runtime = create_runtime(db, root, enabled=True)
                now = datetime.now(timezone.utc)
                authority = AuthorizationContext(
                    "1.0", "auth-test", "case-test", "fixture-analyst",
                    "Analyze supplied synthetic records", ("provided_records:case-test",),
                    ("propose_observation",), ("discipline.analyze",), "IN", "fixture",
                    (now - timedelta(seconds=1)).isoformat(), (now + timedelta(hours=1)).isoformat(), "a" * 64)
                runtime.service.register_authorization(authority)
                data = fixture()
                del data["task_id"]
                plan = runtime.plan(authority.context_id, "DNSINT", data)
                task = plan["task"]["task_id"]
                runtime.service.approve(task, actor_id=authority.actor_id,
                    rationale="Approve exact supplied bytes", envelope_digest=plan["envelope_digest"], authorized=True)
                result = runtime.run(task, authorized=True)
                self.assertEqual(result["draft"]["status"], "ANALYSIS_COMPLETE")
                self.assertEqual(result["draft"]["artifacts"]["records"][0]["value"], "192.0.2.1")
                self.assertEqual(len(result["result"]["observations"]), 1)
                self.assertEqual(result["draft"]["findings"][0]["canonical_evidence_ids"], [plan["input_evidence_id"]])
                self.assertEqual(result["result"]["model_used"], "deterministic-no-model")
                self.assertEqual(runtime.run(task, authorized=True), result)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
