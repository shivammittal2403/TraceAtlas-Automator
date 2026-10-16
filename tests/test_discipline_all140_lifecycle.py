"""Every requested employee executes through the real canonical case lifecycle."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from traceatlas.db import CaseDB
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.discipline_engines import supported_disciplines
from traceatlas.workforce.discipline_runtime import create_runtime

ROOT = Path(__file__).resolve().parents[1]


class CompleteWorkforceTests(unittest.TestCase):
    def test_all140_actual_employees_approve_execute_and_preserve_custody(self):
        labels = supported_disciplines()
        self.assertEqual(len(labels), 140)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            db = CaseDB(workspace / "traceatlas.db")
            try:
                db.create_case("case-all140", "All dedicated employees", "Synthetic complete workforce regression")
                runtime = create_runtime(db, workspace, enabled=True)
                now = datetime.now(timezone.utc)
                context = AuthorizationContext(
                    "1.0", "auth-all140", "case-all140", "fixture-analyst",
                    "Analyze supplied synthetic records", ("provided_records:case-all140",),
                    ("propose_observation",), ("discipline.analyze",), "IN", "fixture",
                    (now - timedelta(seconds=1)).isoformat(), (now + timedelta(hours=1)).isoformat(), "a" * 64)
                runtime.service.register_authorization(context)
                completed, evidence_ids = set(), set()
                for label in labels:
                    with self.subTest(discipline=label):
                        data = json.loads((ROOT / "examples/employees/recipes" / (label + ".json")).read_text(encoding="utf-8"))
                        data["case_id"] = context.case_id
                        data.pop("task_id")
                        self.assertTrue(data["records"])
                        plan = runtime.plan(context.context_id, label, data)
                        task_id = plan["task"]["task_id"]
                        with self.assertRaises(ValueError):
                            runtime.run(task_id, authorized=True)
                        runtime.service.approve(task_id, actor_id=context.actor_id,
                            rationale="Approve these exact synthetic records",
                            envelope_digest=plan["envelope_digest"], authorized=True)
                        product = runtime.run(task_id, authorized=True)
                        self.assertIn(product["draft"]["status"], {"ANALYSIS_COMPLETE", "PARTIAL"})
                        self.assertEqual(product["employee_id"], "discipline-" + label.lower())
                        self.assertTrue(product["result"]["observations"])
                        self.assertEqual(product["result"]["model_used"], "deterministic-no-model")
                        self.assertFalse(product["source_authenticity_verified"])
                        self.assertFalse(product["factual_entailment_verified"])
                        self.assertEqual(runtime.service.describe(task_id)["status"], "completed")
                        for finding in product["draft"]["findings"]:
                            self.assertEqual(finding["canonical_evidence_ids"], [plan["input_evidence_id"]])
                        evidence_ids.add(plan["input_evidence_id"])
                        completed.add(product["discipline"])
                self.assertEqual(completed, set(labels))
                self.assertEqual(len(evidence_ids), 140)
                self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM workforce_results").fetchone()[0], 140)
                self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM workforce_outbox").fetchone()[0], 140)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
