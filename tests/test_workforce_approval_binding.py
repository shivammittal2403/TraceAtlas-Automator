"""Approval receipts remain bound to task identity before dispatch and completion."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from traceatlas.db import CaseDB
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.service import WorkforceService


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def checksum(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


class ApprovalBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "cases.db")
        self.addCleanup(self.db.close)
        self.db.create_case("case-approval", "Approval fixture", "Authorized synthetic execution")
        self.db.create_case("case-foreign", "Foreign case", "Separate controlled synthetic case")
        self.service = WorkforceService(self.db, enabled=True)
        now = datetime.now(timezone.utc)
        self.context = AuthorizationContext(
            "1.0", "auth-approval", "case-approval", "analyst-approval",
            "Authorized synthetic execution with exact immutable approval", ("domain:example.org",),
            ("request_collection", "propose_observation", "propose_claim"),
            ("dns.lookup", "evidence.retrieve"), "IN", "fixture-only",
            (now - timedelta(seconds=10)).isoformat(), (now + timedelta(hours=1)).isoformat(),
            "a" * 64,
        )
        self.service.register_authorization(self.context)

    def approved(self):
        plan = self.service.create_investigation_task(
            self.context.context_id, "domain", "example.org",
            "Review isolated synthetic execution approval bindings", sources=["dns"],
        )
        task_id = plan["task"]["task_id"]
        self.service.approve(
            task_id, actor_id=self.context.actor_id,
            rationale="Approve this exact immutable synthetic investigation",
            envelope_digest=plan["envelope_digest"], authorized=True,
        )
        return task_id

    def product(self, task_id):
        return {
            "schema": "traceatlas-approval-fixture/v1", "task_id": task_id, "case_id": self.context.case_id,
            "analysis": {"observations": [], "source_lineage": [], "verification": []},
        }

    def assert_no_completion(self, task_id):
        for table in ("workforce_products", "workforce_results", "workforce_outbox", "observations_v2"):
            with self.subTest(table=table):
                if table == "observations_v2":
                    count = self.db.conn.execute(
                        "SELECT COUNT(*) FROM observations_v2 WHERE case_id=?", (self.context.case_id,)).fetchone()[0]
                else:
                    count = self.db.conn.execute(
                        "SELECT COUNT(*) FROM " + table + " WHERE task_id=?", (task_id,)).fetchone()[0]
                self.assertEqual(count, 0)

    def change_receipt(self, task_id, field, value):
        if field not in {"decision", "actor_id", "envelope_digest"}:
            raise AssertionError("Test receipt field is not allowed")
        self.db.conn.execute(
            "UPDATE workforce_approvals SET " + field + "=? WHERE task_id=?", (value, task_id))
        self.db.conn.commit()

    def delete_receipt(self, task_id):
        self.db.conn.execute("DELETE FROM workforce_approvals WHERE task_id=?", (task_id,))
        self.db.conn.commit()

    def change_context(self, field, value):
        data = self.context.to_dict()
        data[field] = value
        self.db.conn.execute(
            "UPDATE workforce_authorizations SET context_json=?,policy_digest=? WHERE context_id=?",
            (encode(data), data["policy_digest"], self.context.context_id))
        self.db.conn.commit()

    def restore_context(self):
        self.db.conn.execute(
            "UPDATE workforce_authorizations SET context_json=?,policy_digest=? WHERE context_id=?",
            (encode(self.context.to_dict()), self.context.policy_digest, self.context.context_id))
        self.db.conn.commit()

    def change_sql_case(self, task_id):
        self.db.conn.execute("UPDATE workforce_tasks SET case_id=? WHERE task_id=?", ("case-foreign", task_id))
        self.db.conn.commit()

    def change_envelope_task_id(self, task_id):
        data = self.service.store.task(task_id)["envelope"].to_dict()
        data["task_id"] = "task-foreign-envelope"
        self.db.conn.execute(
            "UPDATE workforce_tasks SET envelope_json=?,envelope_digest=? WHERE task_id=?",
            (encode(data), checksum(data), task_id))
        # A matching rehashed receipt must still not authorize a foreign envelope identity.
        self.db.conn.execute(
            "UPDATE workforce_approvals SET envelope_digest=? WHERE task_id=?", (checksum(data), task_id))
        self.db.conn.commit()

    def test_valid_receipt_returns_registered_context_and_completes_normally(self):
        task_id = self.approved()
        self.assertEqual(self.service.store.verify_task_approval(self.service.store.task(task_id)), self.context)
        completed = self.service.execute(
            task_id, lambda *_: self.service.deterministic_no_model_result(task_id),
            authorized=True, product_factory=lambda: self.product(task_id),
        )
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(self.service.store.product(task_id), self.product(task_id))
        for table in ("workforce_products", "workforce_results", "workforce_outbox"):
            self.assertEqual(self.db.conn.execute(
                "SELECT COUNT(*) FROM " + table + " WHERE task_id=?", (task_id,)).fetchone()[0], 1)

    def test_approved_status_without_an_exact_owner_receipt_cannot_dispatch(self):
        mutations = (
            lambda task: self.delete_receipt(task),
            lambda task: self.change_receipt(task, "decision", "rejected"),
            lambda task: self.change_receipt(task, "actor_id", "foreign-analyst"),
            lambda task: self.change_receipt(task, "envelope_digest", "0" * 64),
            self.change_sql_case,
            self.change_envelope_task_id,
        )
        for mutation in mutations:
            task_id = self.approved()
            mutation(task_id)
            calls = []
            def runner(*args):
                calls.append(True)
                return self.service.deterministic_no_model_result(task_id)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.service.execute(task_id, runner, authorized=True)
            self.assertEqual(calls, [])
            self.assert_no_completion(task_id)
            self.assertEqual(self.db.conn.execute(
                "SELECT COUNT(*) FROM workforce_attempts WHERE task_id=?", (task_id,)).fetchone()[0], 0)

    def test_receipt_tampering_after_runner_begins_rolls_back_completion(self):
        mutations = (
            lambda task: self.delete_receipt(task),
            lambda task: self.change_receipt(task, "decision", "rejected"),
            lambda task: self.change_receipt(task, "actor_id", "foreign-analyst"),
            lambda task: self.change_receipt(task, "envelope_digest", "0" * 64),
            self.change_sql_case,
            self.change_envelope_task_id,
        )
        for mutation in mutations:
            task_id = self.approved()
            calls = []
            def runner(*args):
                value = self.service.deterministic_no_model_result(task_id)
                calls.append(True)
                mutation(task_id)
                return value
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.service.execute(task_id, runner, authorized=True,
                                     product_factory=lambda: self.product(task_id))
            self.assertEqual(calls, [True])
            self.assert_no_completion(task_id)

    def test_context_owner_or_policy_tampering_after_runner_begins_cannot_finalize(self):
        for field, value in (("actor_id", "foreign-analyst"), ("policy_digest", "0" * 64)):
            task_id = self.approved()
            calls = []
            def runner(*args):
                result = self.service.deterministic_no_model_result(task_id)
                calls.append(True)
                self.change_context(field, value)
                return result
            try:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.service.execute(task_id, runner, authorized=True,
                                         product_factory=lambda: self.product(task_id))
                self.assertEqual(calls, [True])
                self.assert_no_completion(task_id)
            finally:
                self.restore_context()


if __name__ == "__main__":
    unittest.main()
