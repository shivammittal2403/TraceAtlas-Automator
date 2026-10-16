"""Lifecycle and custody fences using isolated synthetic analyzer fixtures."""
import copy
import json
import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.discipline_runtime import (
    ENGINE_PREFIX, INPUT_PREFIX, SOURCE_PREFIX, canonical, create_runtime, digest)
from traceatlas.workforce.registry import EmployeeRegistry


class DisciplineLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "case.db")
        self.addCleanup(self.db.close)
        self.db.create_case("case-discipline", "Discipline fixture", "Synthetic lifecycle regression")
        self.calls, self.on_call, self.on_result = [], None, None
        self.runtime = create_runtime(self.db, self.root, enabled=True, invoker=self.invoke)
        self.service = self.runtime.service
        stamp = datetime.now(timezone.utc)
        self.context = AuthorizationContext(
            "1.0", "auth-discipline", "case-discipline", "analyst-fixture",
            "Authorized supplied-record lifecycle regression", ("domain:example.org",),
            ("propose_observation", "propose_claim", "propose_plan", "route_task"),
            ("discipline.analyze", "investigation.plan"), "IN", "fixture-only",
            (stamp - timedelta(seconds=10)).isoformat(),
            (stamp + timedelta(days=1)).isoformat(), "a" * 64)
        self.service.register_authorization(self.context)

    def payload(self):
        return {"case_id": self.context.case_id, "discipline": "DNSINT",
                "objective": "Review supplied synthetic DNS records",
                "as_of": "2026-01-01T00:00:00+00:00",
                "sources": [{"source_id": "S1", "uri": "https://fixture.example/dns"}],
                "records": [{"record_id": "R1", "source_id": "S1",
                             "observed_at": "2026-01-01T00:00:00+00:00",
                             "data": {"name": "example.org", "type": "A", "value": "93.184.216.34"}}]}

    def invoke(self, payload, *, evidence_ids=()):
        self.calls.append((copy.deepcopy(payload), tuple(evidence_ids)))
        if self.on_call:
            self.on_call(payload)
        result = {"schema": "traceatlas.discipline.analysis.v1",
                  "employee_id": "discipline-dnsint", "discipline": "DNSINT",
                  "case_id": payload["case_id"], "task_id": payload["task_id"],
                  "status": "ANALYSIS_COMPLETE", "input_sha256": digest(payload), "engine_version": "1.0.0",
                  "findings": [{"finding_id": "F1", "kind": "DNS_RECORD",
                                "summary": "Supplied A record links example.org to 93.184.216.34",
                                "record_ids": ["R1"], "source_ids": ["S1"],
                                "canonical_evidence_ids": list(evidence_ids),
                                "data": copy.deepcopy(payload["records"][0]["data"])}],
                  "issues": [], "metrics": {"records": 1}, "artifacts": {}, "limitations": ["Synthetic fixture"],
                  "source_authenticity_verified": False, "requires_human_review": True}
        if self.on_result:
            self.on_result(result)
        return result

    def plan(self, payload=None):
        return self.runtime.plan(self.context.context_id, "DNSINT", self.payload() if payload is None else payload)

    def approve(self, plan):
        self.service.approve(plan["task"]["task_id"], actor_id=self.context.actor_id,
                             rationale="Approve exact immutable synthetic records",
                             envelope_digest=plan["envelope_digest"], authorized=True)

    def count(self, table):
        # Only fixed table names from this test module reach this helper.
        return self.db.conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]

    def captured(self, plan):
        task = self.service.store.task(plan["task"]["task_id"])["envelope"]
        source_id = next(value[len(SOURCE_PREFIX):] for value in task.constraints if value.startswith(SOURCE_PREFIX))
        return self.service.store.captured_document(task, source_id)

    def test_default_registry_stays_five_and_specialists_are_opt_in(self):
        self.assertEqual(len(EmployeeRegistry().list()), 5)
        self.assertEqual(self.service.registry.get("discipline-dnsint").domain, "DNSINT")

    def test_approved_task_persists_custody_observations_result_and_outbox(self):
        plan = self.plan()
        task_id = plan["task"]["task_id"]
        document, evidence = self.captured(plan)
        self.assertTrue(self.service.store.verify_evidence(evidence))
        self.assertEqual(plan["task"]["evidence_context_ids"], [evidence.evidence_id])
        self.assertEqual(json.loads(document.content)["task_id"], task_id)
        with self.assertRaises(ValueError):
            self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.calls, [])
        self.approve(plan)
        product = self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.service.describe(task_id)["status"], "completed")
        self.assertEqual(product["employee_id"], "discipline-dnsint")
        self.assertEqual(product["input_evidence_id"], evidence.evidence_id)
        self.assertEqual(product["result"]["observations"][0]["evidence_id"], evidence.evidence_id)
        self.assertEqual(product["result"]["claims"], [])
        self.assertFalse(product["source_authenticity_verified"])
        self.assertEqual(self.calls[0][1], (evidence.evidence_id,))
        self.assertEqual(self.count("observations_v2"), 1)
        self.assertEqual(self.count("workforce_results"), 1)
        self.assertEqual(self.count("workforce_outbox"), 1)
        self.assertTrue(EvidenceStore(self.root, self.db, self.context.case_id).verify_ledger()[0])
        snapshot = self.service.describe(task_id)["execution"]
        self.assertEqual(snapshot["request_attempts"], 1)
        self.assertEqual({row["step_id"] for row in snapshot["checkpoints"]}, {"discipline-input", "discipline-result"})
        before = self.count("evidence_objects_v2")
        self.assertEqual(self.runtime.run(task_id, authorized=True), product)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.count("evidence_objects_v2"), before)
        self.assertEqual(self.count("workforce_outbox"), 1)

    def test_caller_mutation_cannot_replace_approved_input(self):
        payload = self.payload()
        plan = self.plan(payload)
        payload["records"][0]["data"]["value"] = "203.0.113.99"
        self.approve(plan)
        product = self.runtime.run(plan["task"]["task_id"], authorized=True)
        self.assertEqual(self.calls[0][0]["records"][0]["data"]["value"], "93.184.216.34")
        self.assertEqual(product["input_sha256"], plan["input_sha256"])

    def test_bad_source_references_fail_before_any_capture_or_task(self):
        payload = self.payload()
        payload["records"][0]["source_id"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            self.plan(payload)
        self.assertEqual(self.count("workforce_tasks"), 0)
        self.assertEqual(self.count("evidence_objects_v2"), 0)

    def test_cross_case_and_user_canonical_evidence_are_rejected_before_capture(self):
        for payload in ({**self.payload(), "case_id": "other-case"},
                        {**self.payload(), "canonical_evidence_ids": ["evidence-foreign"]},
                        {**self.payload(), "parameters": {"canonical_evidence_ids": ["evidence-foreign"]}}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.plan(payload)
        self.assertEqual(self.count("workforce_tasks"), 0)
        self.assertEqual(self.count("evidence_objects_v2"), 0)

    def test_changed_preserved_bytes_never_reach_the_analyzer(self):
        plan = self.plan()
        self.approve(plan)
        _, evidence = self.captured(plan)
        Path(evidence.raw_artifact_pointer).write_bytes(b"{}")
        with self.assertRaises(ValueError):
            self.runtime.run(plan["task"]["task_id"], authorized=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.count("workforce_results"), 0)

    def test_input_digest_mismatch_is_detected_with_valid_envelope_encoding(self):
        plan = self.plan()
        self.approve(plan)
        task_id = plan["task"]["task_id"]
        task = self.service.store.task(task_id)["envelope"].to_dict()
        task["constraints"] = [INPUT_PREFIX + "0" * 64 if row.startswith(INPUT_PREFIX) else row
                               for row in task["constraints"]]
        encoded = canonical(task)
        self.db.conn.execute("UPDATE workforce_tasks SET envelope_json=?,envelope_digest=? WHERE task_id=?",
                             (encoded, digest(task), task_id))
        self.db.conn.commit()
        with self.assertRaisesRegex(ValueError, "input digest mismatch"):
            self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.count("workforce_results"), 0)

    def test_changed_engine_identity_cannot_execute_an_approved_task(self):
        plan = self.plan()
        self.approve(plan)
        self.assertTrue(any(row.startswith(ENGINE_PREFIX) for row in plan["task"]["constraints"]))
        with patch("traceatlas.workforce.discipline_runtime._identity", return_value="0" * 64):
            with self.assertRaisesRegex(ValueError, "engine changed"):
                self.runtime.run(plan["task"]["task_id"], authorized=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.count("workforce_results"), 0)

    def test_callback_cannot_write_foreign_evidence_or_case_results(self):
        mutations = [lambda result: result.update(case_id="other-case"),
                     lambda result: result["findings"][0].update(canonical_evidence_ids=["evidence-foreign"]),
                     lambda result: result["findings"][0].update(record_ids=["UNKNOWN"]),
                     lambda result: result["findings"][0].update(source_ids=["UNKNOWN"]),
                     lambda result: result.update(source_authenticity_verified=True),
                     lambda result: result.update(input_sha256="0" * 64)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                plan = self.plan()
                self.approve(plan)
                self.on_result = mutation
                with self.assertRaises(ValueError):
                    self.runtime.run(plan["task"]["task_id"], authorized=True)
                self.assertEqual(self.service.describe(plan["task"]["task_id"])["status"], "failed")
        self.assertEqual(self.count("workforce_results"), 0)
        self.assertEqual(self.count("observations_v2"), 0)
        self.assertEqual(self.count("workforce_outbox"), 0)

    def test_cancel_before_or_during_analysis_prevents_canonical_completion(self):
        plan = self.plan()
        self.approve(plan)
        task_id = plan["task"]["task_id"]
        self.service.cancel(task_id, actor_id=self.context.actor_id, authorized=True)
        with self.assertRaises(ValueError):
            self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.calls, [])
        second = self.plan()
        self.approve(second)
        second_id = second["task"]["task_id"]
        self.on_call = lambda _: self.service.cancel(second_id, actor_id=self.context.actor_id, authorized=True)
        with self.assertRaises(ValueError):
            self.runtime.run(second_id, authorized=True)
        self.assertEqual(self.service.describe(second_id)["status"], "cancelled")
        self.assertEqual(self.count("workforce_results"), 0)
        self.assertEqual(self.count("workforce_outbox"), 0)

    def test_kill_switch_before_or_during_analysis_prevents_completion(self):
        plan = self.plan()
        self.approve(plan)
        task_id = plan["task"]["task_id"]
        with patch.dict(os.environ, {"TRACEATLAS_WORKFORCE_KILL_SWITCH": "1"}):
            with self.assertRaises(ValueError):
                self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.calls, [])
        self.on_call = lambda _: os.environ.__setitem__("TRACEATLAS_WORKFORCE_KILL_SWITCH", "1")
        with patch.dict(os.environ, {}):
            with self.assertRaisesRegex(ValueError, "kill switch"):
                self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.service.describe(task_id)["status"], "failed")
        self.assertEqual(self.count("workforce_results"), 0)
        self.assertEqual(self.count("workforce_outbox"), 0)

    def test_expired_attempt_cannot_finalize_and_recovery_reuses_input(self):
        plan = self.plan()
        self.approve(plan)
        task_id = plan["task"]["task_id"]
        clock = [time.time()]
        self.service.store.runtime.clock = lambda: clock[0]
        self.service.store.runtime.lease_seconds = 1
        self.on_call = lambda _: clock.__setitem__(0, clock[0] + 2)
        with self.assertRaises(ValueError):
            self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.count("workforce_results"), 0)
        self.assertEqual(self.service.describe(task_id)["status"], "failed")
        before = self.count("evidence_objects_v2")
        self.on_call = None
        self.service.recover(task_id, actor_id=self.context.actor_id, authorized=True)
        self.runtime.run(task_id, authorized=True)
        self.assertEqual(self.service.describe(task_id)["status"], "completed")
        self.assertEqual(self.count("evidence_objects_v2"), before)
        self.assertEqual(self.service.describe(task_id)["execution"]["request_attempts"], 2)
        self.assertEqual(self.count("workforce_outbox"), 1)

    def test_canonical_write_failure_rolls_back_all_completion_rows(self):
        plan = self.plan()
        self.approve(plan)
        task_id = plan["task"]["task_id"]
        self.db.conn.executescript("CREATE TRIGGER reject_discipline_observation BEFORE INSERT ON observations_v2 "
                                   "BEGIN SELECT RAISE(ABORT,'synthetic observation write failure'); END;")
        self.db.conn.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.runtime.run(task_id, authorized=True)
        for table in ("workforce_products", "observations_v2", "workforce_results", "workforce_outbox"):
            self.assertEqual(self.count(table), 0, table)
        self.assertEqual(self.service.describe(task_id)["status"], "failed")
        self.db.conn.execute("DROP TRIGGER reject_discipline_observation")
        self.db.conn.commit()
        self.service.recover(task_id, actor_id=self.context.actor_id, authorized=True)
        self.runtime.run(task_id, authorized=True)
        for table in ("workforce_products", "observations_v2", "workforce_results", "workforce_outbox"):
            self.assertEqual(self.count(table), 1, table)

    def test_callback_custody_mutation_cannot_be_committed(self):
        plan = self.plan()
        self.approve(plan)
        _, evidence = self.captured(plan)
        self.on_call = lambda _: Path(evidence.raw_artifact_pointer).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "evidence changed"):
            self.runtime.run(plan["task"]["task_id"], authorized=True)
        self.assertEqual(self.service.describe(plan["task"]["task_id"])["status"], "failed")
        for table in ("workforce_products", "observations_v2", "workforce_results", "workforce_outbox"):
            self.assertEqual(self.count(table), 0, table)

    def test_manager_rejects_malformed_source_bindings_before_capture(self):
        payload = self.payload()
        del payload["discipline"]
        payload["records"][0]["source_id"] = "UNKNOWN"
        with self.assertRaises(ValueError):
            self.runtime.plan_manager(self.context.context_id, payload, ["DNSINT"])
        self.assertEqual(self.count("workforce_tasks"), 0)
        self.assertEqual(self.count("evidence_objects_v2"), 0)

    def test_manager_plan_does_not_run_or_approve_specialists(self):
        payload = self.payload()
        del payload["discipline"]
        manager = self.runtime.plan_manager(self.context.context_id, payload, ["DNSINT"])
        self.approve(manager)
        product = self.runtime.run(manager["task"]["task_id"], authorized=True)
        self.assertEqual(product["employee_id"], "case-manager")
        self.assertEqual(product["draft"]["status"], "PLANNING_ONLY")
        assignment = product["draft"]["artifacts"]["assignments"][0]
        self.assertEqual(assignment["employee_id"], "discipline-dnsint")
        self.assertEqual(assignment["status"], "PLANNED_REQUIRES_SEPARATE_APPROVAL")
        self.assertEqual(self.calls, [])
        child = self.runtime.plan(self.context.context_id, "DNSINT", self.payload(),
                                  parent_task_id=manager["task"]["task_id"])
        self.assertEqual(child["task"]["parent_task_id"], manager["task"]["task_id"])
        self.assertEqual(self.service.describe(child["task"]["task_id"])["status"], "planned")
        with self.assertRaises(ValueError):
            self.runtime.run(child["task"]["task_id"], authorized=True)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
