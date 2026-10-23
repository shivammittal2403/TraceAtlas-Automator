"""Real persisted coordination stages retain approvals, native drafts and provenance."""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.coordination import CoordinationService
from traceatlas.workforce.coordination_registry import build_coordination_definitions
from traceatlas.workforce.discipline_engines import invoke_employee
from traceatlas.workforce.discipline_runtime import create_runtime, canonical, digest, SOURCE_PREFIX
from traceatlas.workforce.registry import EmployeeRegistry


def fixture():
    return {
        "objective": "Review supplied infrastructure and software assertions",
        "as_of": "2026-10-16T00:00:00Z",
        "sources": [{"source_id": "shared", "uri": "urn:fixture:coordination"}],
        "assignments": [
            {"discipline": "DNSINT", "records": [{"record_id": "dns", "source_id": "shared",
                "data": {"name": "example.org", "type": "A", "value": "192.0.2.1"}}]},
            {"discipline": "IPINT", "records": [{"record_id": "ip", "source_id": "shared",
                "data": {"ip": "192.0.2.1", "prefixes": ["192.0.2.0/24"]}}]},
            {"discipline": "CODEINT", "records": [{"record_id": "code", "source_id": "shared",
                "data": {"path": "fixture.py", "content": "answer = 42\n"}}]},
        ],
        "budget": {"max_tasks": 20, "max_employees": 3, "max_tool_calls": 20,
                   "max_runtime_seconds": 2400, "model_calls": 0, "max_cost": 0},
    }


class CoordinationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "cases.db")
        self.addCleanup(self.db.close)
        self.db.create_case("coordination-case", "Coordination fixture", "Authorized synthetic supplied records")
        self.calls, self.on_call = [], None
        def invoker(payload, *, evidence_ids):
            self.calls.append(payload["discipline"])
            if self.on_call is not None:
                self.on_call(payload)
            return invoke_employee(payload, evidence_ids=evidence_ids)
        self.runtime = create_runtime(self.db, self.root, enabled=True, invoker=invoker)
        self.service = self.runtime.service
        self.coordinator = CoordinationService(self.runtime)
        now = datetime.now(timezone.utc)
        self.authority = AuthorizationContext(
            "1.0", "coordination-auth", "coordination-case", "coordination-analyst",
            "Authorized synthetic supplied-data coordination", ("provided_records:coordination-case",),
            ("propose_plan", "route_task", "propose_observation", "propose_claim", "propose_synthesis"),
            ("coordination.plan", "coordination.synthesize", "discipline.analyze", "investigation.plan"),
            "IN", "fixture-only", (now - timedelta(seconds=10)).isoformat(),
            (now + timedelta(hours=1)).isoformat(), "a" * 64,
        )
        self.service.register_authorization(self.authority)

    def task_id(self, descriptor):
        return descriptor["task"]["task_id"]

    def approve(self, descriptor):
        self.service.approve(
            self.task_id(descriptor), actor_id=self.authority.actor_id,
            rationale="Approve this exact bounded synthetic coordination stage",
            envelope_digest=descriptor["envelope_digest"], authorized=True,
        )

    def execute(self, descriptor):
        self.approve(descriptor)
        return self.coordinator.run(self.task_id(descriptor), authorized=True)

    def counts(self):
        return tuple(self.db.conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                     for table in ("workforce_tasks", "evidence_objects_v2",
                                   "workforce_products", "workforce_results", "workforce_outbox"))

    def prepare_leaves(self, payload=None):
        manager = self.coordinator.plan(self.authority.context_id, fixture() if payload is None else payload)
        self.execute(manager)
        leads = self.coordinator.materialize_children(self.task_id(manager))["children"]
        employees = []
        for lead in leads:
            self.execute(lead)
            employees.extend(self.coordinator.materialize_children(self.task_id(lead))["children"])
        return manager, leads, employees

    def complete(self, payload=None):
        manager, leads, employees = self.prepare_leaves(payload)
        for employee in employees:
            self.execute(employee)
        syntheses = []
        for lead in leads:
            synthesis = self.coordinator.plan_synthesis(self.task_id(lead))
            self.execute(synthesis)
            syntheses.append(synthesis)
        final = self.coordinator.plan_synthesis(self.task_id(manager))
        final_product = self.execute(final)
        return manager, leads, employees, syntheses, final, final_product

    def rewrite_product(self, task_id, product):
        encoded = canonical(product)
        self.db.conn.execute(
            "UPDATE workforce_products SET product_json=?,product_digest=? WHERE task_id=?",
            (encoded, hashlib.sha256(encoded.encode()).hexdigest(), task_id))
        self.db.conn.commit()

    def test_opt_in_registry_preserves_five_default_roles(self):
        self.assertEqual(len(EmployeeRegistry().list()), 5)
        added = build_coordination_definitions()
        self.assertEqual({item.employee_id for item in added},
                         {"coordination-manager"} | {"coordination-lead-" + str(i) for i in range(1, 11)})
        self.assertEqual(self.service.registry.get("discipline-dnsint").domain, "DNSINT")

    def test_plan_preserves_caller_input_and_only_creates_the_manager_stage(self):
        payload = fixture()
        original = copy.deepcopy(payload)
        planned = self.coordinator.plan(self.authority.context_id, payload)
        self.assertEqual(payload, original)
        self.assertEqual(planned["phase"], "manager-plan")
        self.assertIsNone(planned["task"]["parent_task_id"])
        described = self.coordinator.describe(planned["coordination_id"])
        self.assertEqual(len(described["tasks"]), 1)
        self.assertIn(self.task_id(planned), described["pending_approval_task_ids"])
        payload["assignments"][0]["records"][0]["data"]["value"] = "203.0.113.99"
        self.execute(planned)
        self.assertEqual(self.calls, [])

    def test_invalid_assignments_and_budgets_fail_before_capture(self):
        mutations = (
            lambda p: p["assignments"].append(copy.deepcopy(p["assignments"][0])),
            lambda p: p["assignments"][0].update(discipline="UNKNOWNINT"),
            lambda p: p["assignments"][0]["records"][0].update(source_id="foreign"),
            lambda p: p["assignments"][0].update(parameters={"canonical_evidence_ids": ["forged"]}),
            lambda p: p["budget"].update(max_tasks=1),
            lambda p: p["budget"].update(max_employees=2),
            lambda p: p["budget"].update(model_calls=1),
            lambda p: p.update(case_id="foreign-case"),
        )
        before = self.counts()
        for mutate in mutations:
            payload = fixture()
            mutate(payload)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.coordinator.plan(self.authority.context_id, payload)
            self.assertEqual(self.counts(), before)

    def test_materialization_retry_reuses_a_captured_frozen_child_after_planner_failure(self):
        manager = self.coordinator.plan(self.authority.context_id, fixture())
        self.execute(manager)
        original = self.coordinator._control_plan
        crashed = []
        def fail_after_capture(*args, **kwargs):
            planned = original(*args, **kwargs)
            if not crashed:
                crashed.append(True)
                raise RuntimeError("Synthetic interruption after the child planner committed")
            return planned
        with patch.object(self.coordinator, "_control_plan", side_effect=fail_after_capture):
            with self.assertRaisesRegex(RuntimeError, "Synthetic interruption"):
                self.coordinator.materialize_children(self.task_id(manager))
        self.assertEqual(self.counts()[:2], (2, 2))
        children = self.coordinator.materialize_children(self.task_id(manager))["children"]
        self.assertEqual(len(children), 2)
        self.assertEqual(self.counts()[:2], (3, 3))
        before = self.counts()
        retried = self.coordinator.materialize_children(self.task_id(manager))["children"]
        self.assertEqual({self.task_id(row) for row in retried}, {self.task_id(row) for row in children})
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.calls, [])

    def test_manager_and_employees_require_their_own_approvals(self):
        manager = self.coordinator.plan(self.authority.context_id, fixture())
        with self.assertRaises(ValueError):
            self.coordinator.run(self.task_id(manager), authorized=True)
        with self.assertRaises(ValueError):
            self.coordinator.materialize_children(self.task_id(manager))
        self.assertEqual(self.calls, [])
        self.execute(manager)
        lead = self.coordinator.materialize_children(self.task_id(manager))["children"][0]
        self.execute(lead)
        employees = self.coordinator.materialize_children(self.task_id(lead))["children"]
        before = self.counts()[2:]
        with self.assertRaises(ValueError):
            self.coordinator.run(self.task_id(employees[0]), authorized=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.counts()[2:], before)

    def test_complete_real_hierarchy_is_offline_idempotent_and_replayable(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("Coordination dispatched a network request or model call")
        with patch("traceatlas.intelligence.transport.request", side_effect=forbidden), \
             patch("traceatlas.workforce.model_fabric.ModelRouter.generate", side_effect=forbidden):
            manager, leads, employees, syntheses, final, product = self.complete()
            self.assertEqual(len(leads), 2)
            self.assertEqual({lead["group_id"] for lead in leads}, {4, 5})
            self.assertEqual({employee["discipline"] for employee in employees}, {"DNSINT", "IPINT", "CODEINT"})
            self.assertEqual(sorted(self.calls), ["CODEINT", "DNSINT", "IPINT"])
            all_stages = [manager, *leads, *employees, *syntheses, final]
            self.assertEqual(len({self.task_id(stage) for stage in all_stages}), 9)
            described = self.coordinator.describe(manager["coordination_id"])
            self.assertEqual(described["status"], "COMPLETE_DRAFT_REQUIRES_HUMAN_RELEASE")
            self.assertEqual(described["pending_approval_task_ids"], [])
            self.assertTrue(all(row["task_status"] == "completed" for row in described["tasks"]))
            receipt = self.coordinator.replay(manager["coordination_id"])
            self.assertTrue(receipt["verified"])
            self.assertFalse(receipt["requires_network"])
            self.assertFalse(receipt["source_authenticity_verified"])
            self.assertFalse(receipt["factual_entailment_verified"])
            self.assertEqual(receipt["tasks_verified"], 9)
            before = self.counts()
            self.assertEqual(self.coordinator.run(self.task_id(final), authorized=True), product)
            again = self.coordinator.materialize_children(self.task_id(manager))["children"]
            self.assertEqual({self.task_id(row) for row in again}, {self.task_id(row) for row in leads})
            self.assertEqual(self.task_id(self.coordinator.plan_synthesis(self.task_id(manager))), self.task_id(final))
            self.assertEqual(self.counts(), before)
            self.assertEqual(self.counts()[2:], (9, 9, 9))

    def test_missing_approval_receipt_cannot_be_replaced_by_an_approved_status(self):
        manager = self.coordinator.plan(self.authority.context_id, fixture())
        self.approve(manager)
        self.db.conn.execute("DELETE FROM workforce_approvals WHERE task_id=?", (self.task_id(manager),))
        self.db.conn.commit()
        with self.assertRaises(ValueError):
            self.coordinator.run(self.task_id(manager), authorized=True)
        self.assertEqual(self.counts()[2:], (0, 0, 0))

    def test_rehashed_leaf_parent_cannot_change_the_approved_assignment_tree(self):
        manager, leads, employees = self.prepare_leaves()
        employee = employees[0]
        self.approve(employee)
        task_id = self.task_id(employee)
        envelope = self.runtime.store.task(task_id)["envelope"].to_dict()
        envelope["parent_task_id"] = self.task_id(manager)  # Wrong level, same case and authority.
        encoded = canonical(envelope)
        checksum = digest(envelope)
        self.db.conn.execute("UPDATE workforce_tasks SET envelope_json=?,envelope_digest=? WHERE task_id=?",
                             (encoded, checksum, task_id))
        self.db.conn.execute("UPDATE workforce_approvals SET envelope_digest=? WHERE task_id=?", (checksum, task_id))
        self.db.conn.commit()
        before = self.counts()[2:]
        with self.assertRaises(ValueError):
            self.coordinator.run(task_id, authorized=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.counts()[2:], before)

    def test_coordination_cancellation_before_or_during_leaf_prevents_completion(self):
        for during in (False, True):
            with self.subTest(during=during):
                payload = fixture()
                payload["objective"] += " during callback" if during else " before dispatch"
                manager, _, employees = self.prepare_leaves(payload)
                employee = employees[0]
                self.approve(employee)
                coordination_id = manager["coordination_id"]
                before = self.counts()[2:]
                if during:
                    self.on_call = lambda _: self.coordinator.cancel(
                        coordination_id, actor_id=self.authority.actor_id, authorized=True)
                else:
                    with self.assertRaises(ValueError):
                        self.coordinator.cancel(coordination_id, actor_id="foreign-analyst", authorized=True)
                    self.coordinator.cancel(coordination_id, actor_id=self.authority.actor_id, authorized=True)
                with self.assertRaises(ValueError):
                    self.coordinator.run(self.task_id(employee), authorized=True)
                self.on_call = None
                self.assertEqual(self.counts()[2:], before)

    def test_callback_fabricated_metrics_cannot_enter_synthesis(self):
        payload = fixture()
        payload["assignments"] = payload["assignments"][:1]
        manager, leads, employees = self.prepare_leaves(payload)
        def forged(data, *, evidence_ids):
            draft = invoke_employee(data, evidence_ids=evidence_ids)
            draft["metrics"]["fabricated_agreement"] = 999
            return draft
        self.runtime.invoker = forged
        self.execute(employees[0])
        before_products = self.counts()[2]
        with self.assertRaises(ValueError):
            synthesis = self.coordinator.plan_synthesis(self.task_id(leads[0]))
            self.execute(synthesis)
        self.assertEqual(self.counts()[2], before_products)

    def test_rehashed_completed_leaf_cannot_change_a_final_receipt(self):
        manager, _, employees, _, _, _ = self.complete()
        employee = next(row for row in employees if row["discipline"] == "DNSINT")
        task_id = self.task_id(employee)
        product = self.runtime.store.product(task_id)
        product["draft"]["metrics"]["fabricated_agreement"] = 999
        self.rewrite_product(task_id, product)
        with self.assertRaises(ValueError):
            self.coordinator.replay(manager["coordination_id"])

    def test_damaged_preserved_leaf_bytes_prevent_verified_replay(self):
        manager, _, employees, _, _, _ = self.complete()
        task = self.runtime.store.task(self.task_id(employees[0]))["envelope"]
        source = next(value[len(SOURCE_PREFIX):] for value in task.constraints if value.startswith(SOURCE_PREFIX))
        _, evidence = self.runtime.store.captured_document(task, source)
        Path(evidence.raw_artifact_pointer).write_bytes(b"{}")
        with self.assertRaises(ValueError):
            self.coordinator.replay(manager["coordination_id"])

    def test_changed_or_expired_registered_context_blocks_child_creation(self):
        manager = self.coordinator.plan(self.authority.context_id, fixture())
        self.execute(manager)
        context = self.authority.to_dict()
        context["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        self.db.conn.execute("UPDATE workforce_authorizations SET context_json=? WHERE context_id=?",
                             (canonical(context), self.authority.context_id))
        self.db.conn.commit()
        before = self.counts()
        with self.assertRaises(ValueError):
            self.coordinator.materialize_children(self.task_id(manager))
        self.assertEqual(self.counts(), before)

    def test_rehashed_leaf_scope_cannot_expand_root_authority(self):
        _, _, employees = self.prepare_leaves()
        employee = employees[0]
        self.approve(employee)
        task_id = self.task_id(employee)
        envelope = self.runtime.store.task(task_id)["envelope"].to_dict()
        envelope["scope"].append("provided_records:foreign-case")
        encoded, checksum = canonical(envelope), digest(envelope)
        self.db.conn.execute("UPDATE workforce_tasks SET envelope_json=?,envelope_digest=? WHERE task_id=?",
                             (encoded, checksum, task_id))
        self.db.conn.execute("UPDATE workforce_approvals SET envelope_digest=? WHERE task_id=?",
                             (checksum, task_id))
        self.db.conn.commit()
        before = self.counts()[2:]
        with self.assertRaises(ValueError):
            self.coordinator.run(task_id, authorized=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.counts()[2:], before)

    def test_failed_native_employee_blocks_synthesis_and_stays_visible(self):
        payload = fixture()
        payload["assignments"] = payload["assignments"][:1]
        manager, leads, employees = self.prepare_leaves(payload)
        def failed(*args, **kwargs):
            raise ValueError("Synthetic native employee failure")
        self.runtime.invoker = failed
        self.approve(employees[0])
        with self.assertRaisesRegex(ValueError, "Synthetic native employee failure"):
            self.coordinator.run(self.task_id(employees[0]), authorized=True)
        state = self.coordinator.describe(manager["coordination_id"])
        self.assertEqual(state["status"], "BLOCKED_CHILD_FAILED")
        self.assertTrue(any(row["task_id"] == self.task_id(employees[0]) and row["task_status"] == "failed"
                            for row in state["tasks"]))
        with self.assertRaises(ValueError):
            self.coordinator.plan_synthesis(self.task_id(leads[0]))

    def test_synthesis_bounds_previews_and_preserves_all_native_findings(self):
        payload = fixture()
        payload["assignments"] = payload["assignments"][:1]
        payload["assignments"][0]["records"] = [{
            "record_id": "dns-" + str(index), "source_id": "shared",
            "data": {"name": "host" + str(index) + ".example.org", "type": "A",
                     "value": "192.0.2." + str(index + 1)}} for index in range(12)]
        manager, leads, employees = self.prepare_leaves(payload)
        native = self.execute(employees[0])
        original = copy.deepcopy(native)
        findings = native["draft"]["findings"]
        self.assertEqual(len(findings), 12)
        synthesis = self.coordinator.plan_synthesis(self.task_id(leads[0]))
        summarized = self.execute(synthesis)
        summary = summarized["coordination"]
        receipt = summary["dependencies"][0]
        self.assertEqual(summary["findings_count"], len(findings))
        self.assertEqual(len(receipt["preview_findings"]), 5)
        self.assertEqual(receipt["findings_omitted"], 7)
        self.assertEqual(summary["findings_omitted_from_previews"], 7)
        self.assertEqual(receipt["source_artifact_count"], 1)
        self.assertFalse(summary["source_independence_verified"])
        self.assertEqual(self.runtime.store.product(self.task_id(employees[0])), original)
        self.assertEqual(len(native["result"]["evidence_ids"]), 1)
        self.assertEqual(len(summarized["result"]["evidence_ids"]), 2)

    def test_hypothesis_omissions_propagate_to_manager_synthesis(self):
        payload = fixture()
        payload["assignments"] = [{
            "discipline": "HYPOTHESISINT",
            "records": [{
                "record_id": "hypothesis-matrix", "source_id": "shared",
                "data": {
                    "hypotheses": [
                        {"id": "hypothesis-" + str(index), "statement": "Synthetic candidate " + str(index)}
                        for index in range(101)],
                    "evidence": [],
                },
            }],
        }]
        payload["budget"]["max_employees"] = 1
        manager, leads, employees = self.prepare_leaves(payload)
        employee = self.execute(employees[0])
        self.assertEqual(len(employee["result"]["hypotheses"]), 101)

        lead_task = self.coordinator.plan_synthesis(self.task_id(leads[0]))
        lead_product = self.execute(lead_task)
        self.assertEqual(lead_product["coordination"]["canonical_hypotheses_omitted"], 1)
        self.assertEqual(len(lead_product["result"]["hypotheses"]), 100)

        manager_task = self.coordinator.plan_synthesis(self.task_id(manager))
        manager_product = self.execute(manager_task)
        self.assertEqual(manager_product["coordination"]["canonical_hypotheses_omitted"], 1)
        self.assertEqual(len(manager_product["result"]["hypotheses"]), 100)
        self.assertIn("coordination-hypotheses-omitted", manager_product["result"].information_gaps)

    def test_native_materialization_retry_reuses_frozen_ids_and_capture(self):
        payload = fixture()
        payload["assignments"] = payload["assignments"][:2]
        manager = self.coordinator.plan(self.authority.context_id, payload)
        self.execute(manager)
        leads = self.coordinator.materialize_children(self.task_id(manager))["children"]
        self.assertEqual(len(leads), 1)
        self.execute(leads[0])
        original = self.runtime._plan
        crashed = []
        def fail_after_native_capture(*args, **kwargs):
            planned = original(*args, **kwargs)
            if not crashed:
                crashed.append(True)
                raise RuntimeError("Synthetic interruption after native child capture")
            return planned
        with patch.object(self.runtime, "_plan", side_effect=fail_after_native_capture):
            with self.assertRaisesRegex(RuntimeError, "Synthetic interruption"):
                self.coordinator.materialize_children(self.task_id(leads[0]))
        self.assertEqual(self.counts()[:2], (3, 3))
        children = self.coordinator.materialize_children(self.task_id(leads[0]))["children"]
        self.assertEqual(len(children), 2)
        self.assertEqual(self.counts()[:2], (4, 4))
        self.assertEqual(self.calls, [])

    def test_existing_coordination_cannot_capture_children_in_a_different_workspace(self):
        manager = self.coordinator.plan(self.authority.context_id, fixture())
        self.execute(manager)
        moved = create_runtime(self.db, self.root / "other-workspace", enabled=True)
        alternative = CoordinationService(moved)
        before = self.counts()
        with self.assertRaisesRegex(ValueError, "workspace"):
            alternative.materialize_children(self.task_id(manager))
        with self.assertRaisesRegex(ValueError, "workspace"):
            alternative.replay(manager["coordination_id"])
        self.assertEqual(self.counts(), before)
        self.assertFalse((self.root / "other-workspace").exists())

    def test_rehashed_native_result_cannot_add_unowned_typed_state_or_remove_execution(self):
        for field, value in (
                ("contradictions", ["invented-contradiction-without-owned-evidence"]),
                ("source_independence", ["asserted-independent-source-corroboration"]),
                ("execution_trace", [])):
            with self.subTest(field=field):
                payload = fixture()
                payload["objective"] += " altered " + field
                payload["assignments"] = payload["assignments"][:1]
                _, leads, employees = self.prepare_leaves(payload)
                native = self.execute(employees[0])
                task_id = self.task_id(employees[0])
                native["result"][field] = value
                result_encoded = canonical(native["result"])
                self.db.conn.execute(
                    "UPDATE workforce_results SET result_json=?,result_digest=? WHERE task_id=?",
                    (result_encoded, hashlib.sha256(result_encoded.encode()).hexdigest(), task_id))
                self.rewrite_product(task_id, native)
                before = self.counts()[2:]
                with self.assertRaises(ValueError):
                    self.coordinator.plan_synthesis(self.task_id(leads[0]))
                self.assertEqual(self.counts()[2:], before)


if __name__ == "__main__":
    unittest.main()
