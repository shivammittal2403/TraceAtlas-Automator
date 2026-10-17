"""Exercise persisted coordination through JSON CLI calls and real native DNS processing."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceatlas.workforce.discipline_cli import main


class CoordinationCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = ["--workspace", str(self.root)]
        self.environment = patch.dict("os.environ", {
            "TRACEATLAS_WORKFORCE_ENABLED": "1",
            "TRACEATLAS_WORKFORCE_KILL_SWITCH": "0"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.ok(["case", "--case", "coordination-cli", "--title", "Synthetic coordination",
                 "--purpose", "Controlled supplied-record CLI regression"])
        self.source = self.root / "coordination.json"
        self.payload = {
            "objective": "Review a supplied DNS assertion through individually approved roles",
            "as_of": "2026-10-16T00:00:00Z",
            "sources": [{"source_id": "shared", "uri": "urn:fixture:coordination-cli"}],
            "assignments": [{"discipline": "DNSINT", "records": [{
                "record_id": "dns", "source_id": "shared",
                "data": {"name": "example.org", "type": "A", "value": "192.0.2.1"}}]}],
            "budget": {"max_tasks": 5, "max_employees": 1, "max_tool_calls": 5,
                       "max_runtime_seconds": 600, "model_calls": 0, "max_cost": 0}}
        self.source.write_text(json.dumps(self.payload), encoding="utf-8")

    def call(self, args):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = main(self.prefix + args)
        rendered = (output.getvalue() or error.getvalue()).strip()
        self.assertTrue(rendered)
        value = json.loads(rendered)
        self.assertIsInstance(value, dict)
        if code == 0:
            self.assertEqual(error.getvalue(), "")
        else:
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(value["status"], "ERROR")
        return code, value

    def ok(self, args):
        code, value = self.call(args)
        self.assertEqual(code, 0, value)
        return value

    def fails(self, args):
        code, value = self.call(args)
        self.assertEqual(code, 2, value)
        self.assertTrue(value["error"])
        return value

    def authorize(self, coordination=True):
        args = ["authorize", "--case", "coordination-cli", "--actor", "cli-analyst",
                "--purpose", "Controlled supplied-record CLI regression",
                "--jurisdiction", "IN", "--authorized"]
        if coordination:
            args.append("--coordination")
        return self.ok(args)["authorization"]

    def plan(self, context):
        return self.ok(["coordinate-plan", "--context", context["context_id"],
                        "--input", str(self.source)])

    def approve_and_run(self, descriptor):
        task_id = descriptor["task"]["task_id"]
        self.fails(["run", "--task", task_id, "--authorized"])
        self.fails(["approve", "--task", task_id, "--actor", "foreign-actor",
                    "--envelope-digest", descriptor["envelope_digest"],
                    "--rationale", "Approve exact synthetic task envelope", "--authorized"])
        self.ok(["approve", "--task", task_id, "--actor", "cli-analyst",
                 "--envelope-digest", descriptor["envelope_digest"],
                 "--rationale", "Approve exact synthetic task envelope", "--authorized"])
        self.fails(["run", "--task", task_id])
        return self.ok(["run", "--task", task_id, "--authorized"])

    def test_capabilities_reports_native_analysis_without_execution_receipts(self):
        catalog = self.ok(["capabilities"])
        self.assertEqual(catalog["schema"], "traceatlas.discipline.capabilities.v1")
        self.assertEqual(catalog["discipline_count"], 139)
        self.assertEqual(catalog["umbrella_count"], 1)
        self.assertEqual(catalog["registered_handler_count"], 140)
        dns = next(row for row in catalog["employees"] if row["discipline"] == "DNSINT")
        self.assertEqual(dns["native_execution"]["mode"], "SUPPLIED_RECORD_ANALYSIS")
        self.assertIsNone(dns["native_execution"]["execution_receipt"])
        self.assertFalse(dns["evidence_support"]["source_authenticity_verified"])

    def test_installed_role_guides_are_readable_without_execution_authority(self):
        with patch.dict("os.environ", {"TRACEATLAS_WORKFORCE_ENABLED": "0"}):
            inventory = self.ok(["coordinate-skills"])
            self.assertEqual(inventory["count"], 11)
            self.assertFalse(inventory["grants_authority"])
            guide = self.ok(["coordinate-skill", "coordination-lead-4"])
            self.assertEqual(guide["metadata"]["domain_group"], "4")
            self.assertIn("DNSINT", guide["markdown"])
            self.assertFalse(guide["live_verified"])
            self.fails(["coordinate-skill", "../manager"])

    def test_coordination_authority_is_explicit_and_old_grants_are_unchanged(self):
        ordinary = self.authorize(False)
        self.assertEqual(ordinary["allowed_actions"],
                         ["propose_observation", "propose_claim", "propose_plan", "route_task"])
        self.assertEqual(ordinary["allowed_tools"], ["discipline.analyze", "investigation.plan"])
        error = self.fails(["coordinate-plan", "--context", ordinary["context_id"],
                           "--input", str(self.source)])
        self.assertIn("authority", error["error"].lower())
        coordinated = self.authorize(True)
        self.assertIn("propose_synthesis", coordinated["allowed_actions"])
        self.assertIn("coordination.plan", coordinated["allowed_tools"])
        self.assertIn("coordination.synthesize", coordinated["allowed_tools"])
        manager = self.plan(coordinated)
        state = self.ok(["coordinate-show", "--coordination", manager["coordination_id"]])
        self.assertEqual(state["pending_approval_task_ids"], [manager["task"]["task_id"]])
        self.assertEqual(len(state["tasks"]), 1)

    def test_five_individually_approved_cli_phases_preserve_real_dns_and_replay_offline(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("Supplied-record coordination called network or a model")
        with patch("traceatlas.intelligence.transport.request", side_effect=forbidden), \
             patch("traceatlas.workforce.model_fabric.ModelRouter.generate", side_effect=forbidden):
            manager = self.plan(self.authorize())
            manager_id, coordination_id = manager["task"]["task_id"], manager["coordination_id"]
            self.fails(["coordinate-expand", "--task", manager_id])
            self.fails(["coordinate-synthesize", "--task", manager_id])
            self.approve_and_run(manager)
            leads = self.ok(["coordinate-expand", "--task", manager_id])["children"]
            self.assertEqual(len(leads), 1)
            lead = leads[0]
            self.approve_and_run(lead)
            leaves = self.ok(["coordinate-expand", "--task", lead["task"]["task_id"]])["children"]
            self.assertEqual(len(leaves), 1)
            self.assertEqual(leaves[0]["discipline"], "DNSINT")
            self.fails(["coordinate-synthesize", "--task", lead["task"]["task_id"]])
            native = self.approve_and_run(leaves[0])
            self.assertEqual(native["draft"]["artifacts"]["records"][0]["value"], "192.0.2.1")
            self.assertEqual(len(native["result"]["evidence_ids"]), 1)
            self.assertFalse(native["source_authenticity_verified"])
            lead_summary = self.ok(["coordinate-synthesize", "--task", lead["task"]["task_id"]])
            self.assertEqual(lead_summary["phase"], "lead-synthesis")
            self.approve_and_run(lead_summary)
            final = self.ok(["coordinate-synthesize", "--task", manager_id])
            self.assertEqual(final["phase"], "manager-synthesis")
            product = self.approve_and_run(final)
            self.assertEqual(product["report_status"], "DRAFT_REQUIRES_HUMAN_RELEASE")
            self.assertFalse(product["coordination"]["source_independence_verified"])
            self.assertGreater(product["coordination"]["findings_count"], 0)
            state = self.ok(["coordinate-show", "--coordination", coordination_id])
            self.assertEqual(state["status"], "COMPLETE_DRAFT_REQUIRES_HUMAN_RELEASE")
            self.assertEqual(len(state["tasks"]), 5)
            self.assertEqual(state["pending_approval_task_ids"], [])
            with patch.dict("os.environ", {"TRACEATLAS_WORKFORCE_ENABLED": "0"}):
                receipt = self.ok(["coordinate-replay", "--coordination", coordination_id])
            self.assertTrue(receipt["verified"])
            self.assertEqual(receipt["tasks_verified"], 5)
            self.assertFalse(receipt["requires_network"])
            self.assertFalse(receipt["source_authenticity_verified"])
            self.assertFalse(receipt["factual_entailment_verified"])

    def test_cli_cancel_requires_owner_authority_and_stops_dispatch(self):
        manager = self.plan(self.authorize())
        coordination_id = manager["coordination_id"]
        self.fails(["coordinate-cancel", "--coordination", coordination_id, "--actor", "cli-analyst"])
        self.fails(["coordinate-cancel", "--coordination", coordination_id,
                    "--actor", "foreign-actor", "--authorized"])
        state = self.ok(["coordinate-cancel", "--coordination", coordination_id,
                         "--actor", "cli-analyst", "--authorized"])
        self.assertEqual(state["status"], "CANCELLED")
        self.fails(["run", "--task", manager["task"]["task_id"], "--authorized"])
        self.fails(["coordinate-replay", "--coordination", coordination_id])

    def test_coordinate_json_duplicate_keys_and_unknown_fields_fail_closed(self):
        context = self.authorize()
        self.source.write_text('{"objective":"a","objective":"b"}', encoding="utf-8")
        error = self.fails(["coordinate-plan", "--context", context["context_id"],
                           "--input", str(self.source)])
        self.assertIn("Duplicate", error["error"])
        invalid = dict(self.payload, execute=True)
        self.source.write_text(json.dumps(invalid), encoding="utf-8")
        self.fails(["coordinate-plan", "--context", context["context_id"], "--input", str(self.source)])
        self.source.write_text(json.dumps(self.payload), encoding="utf-8")
        manager = self.plan(context)
        state = self.ok(["coordinate-show", "--coordination", manager["coordination_id"]])
        self.assertEqual(len(state["tasks"]), 1)
        self.assertEqual(state["pending_approval_task_ids"], [manager["task"]["task_id"]])


if __name__ == "__main__":
    unittest.main()
