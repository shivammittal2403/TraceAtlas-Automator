"""Result contracts reject fabricated provenance and ambiguous identities."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.workforce.contracts import (
    AuthorizationContext, Claim, CostRecord, Hypothesis, Observation, ResultEnvelope,
    SCHEMA_VERSION, SemanticClass, TraceSpan,
)
from traceatlas.workforce.service import WorkforceService

STAMP = "2026-10-16T00:00:00+00:00"


def result():
    return ResultEnvelope(
        schema_version=SCHEMA_VERSION, task_id="task-fixture", employee_id="report-analyst",
        observations=(), evidence_ids=(), entities=(), relationships=(), claims=(),
        hypotheses=(), contradictions=(), uncertainties=(), confidence_basis=(),
        source_independence=(), information_gaps=(), recommended_next_actions=(),
        cost=CostRecord("traceatlas", "deterministic-no-model", 0, 0, 0, 0, "NONE"),
        latency_ms=0, model_used="deterministic-no-model", tool_calls=(), execution_trace=(),
        stop_reason="source_exhausted", completed_at=STAMP,
    )


def cited_result():
    observation = Observation("observation-a", "evidence-a", "acquisition-a",
                              "Fixture source returned a record", SemanticClass.OBSERVATION, STAMP)
    claim = Claim("claim-a", "A fixture record was returned", SemanticClass.CLAIM,
                  ("observation-a",), True, None)
    hypothesis = Hypothesis("hypothesis-a", "The fixture assertion may hold", ("evidence-a",), ("check-origin",))
    span = TraceSpan("span-a", "trace-a", None, "evidence.review", "completed",
                     STAMP, STAMP, 0, ("evidence-a",))
    return replace(result(), observations=(observation,), evidence_ids=("evidence-a",),
                   claims=(claim,), hypotheses=(hypothesis,), execution_trace=(span,))


class ResultIntegrityTests(unittest.TestCase):
    def test_empty_deterministic_and_fully_cited_results_round_trip(self):
        for value in (result(), cited_result()):
            with self.subTest(evidence_ids=value.evidence_ids):
                self.assertEqual(ResultEnvelope.from_dict(value.to_dict()), value)

    def test_hypothesis_cannot_cite_unlisted_evidence(self):
        value = cited_result().to_dict()
        value["hypotheses"][0]["evidence_ids"] = ["evidence-a", "evidence-foreign"]
        with self.assertRaisesRegex(ValueError, "hypothesis cites unknown evidence"):
            ResultEnvelope.from_dict(value)

    def test_trace_cannot_cite_unlisted_evidence(self):
        value = cited_result().to_dict()
        value["execution_trace"][0]["evidence_ids"] = ["evidence-a", "evidence-foreign"]
        with self.assertRaisesRegex(ValueError, "execution trace cites unknown evidence"):
            ResultEnvelope.from_dict(value)

    def test_duplicate_nested_identities_are_rejected(self):
        base = cited_result()
        changes = {"observations": {"statement": "A conflicting fixture observation"},
                   "claims": {"statement": "A conflicting fixture claim"},
                   "hypotheses": {"statement": "An alternative fixture hypothesis"},
                   "execution_trace": {"status": "failed"}}
        for field, changed in changes.items():
            rows = getattr(base, field)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "duplicate"):
                replace(base, **{field: rows + (replace(rows[0], **changed),)})


class CanonicalResultIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "cases.db")
        self.addCleanup(self.db.close)
        self.db.create_case("case-a", "Result integrity", "Controlled synthetic domain investigation")
        self.service = WorkforceService(self.db, enabled=True)
        stamp = datetime.now(timezone.utc)
        context = AuthorizationContext(
            SCHEMA_VERSION, "auth-results", "case-a", "analyst-results",
            "Controlled synthetic domain investigation", ("domain:example.org",),
            ("request_collection", "propose_observation", "propose_claim"),
            ("dns.lookup", "evidence.retrieve"), "IN", "fixture-only",
            (stamp - timedelta(seconds=10)).isoformat(),
            (stamp + timedelta(days=1)).isoformat(), "a" * 64,
        )
        self.service.register_authorization(context)
        self.plan = self.service.create_investigation_task(
            "auth-results", "domain", "example.org", "Review the authorized domain DNS record", sources=["dns"])
        self.task_id = self.plan["task"]["task_id"]
        self.service.approve(self.task_id, actor_id="analyst-results",
            rationale="Approve isolated synthetic result integrity fixture",
            envelope_digest=self.plan["envelope_digest"], authorized=True)

    def capture(self, case_id="case-a"):
        source = self.root / (case_id + ".json")
        source.write_text('{"fixture_case":"' + case_id + '"}', encoding="utf-8")
        preserved = EvidenceStore(self.root, self.db, case_id).preserve_file(source, "fixture-" + case_id)
        return self.service.store.import_v1_evidence(case_id, preserved["sha256"])

    def cited(self, item):
        stamp = item.retrieved_at
        observation = Observation("observation-a", item.evidence_id, item.acquisition_id,
            "A controlled fixture record was preserved", SemanticClass.OBSERVATION, stamp)
        hypothesis = Hypothesis("hypothesis-a", "The supplied assertion may hold",
            (item.evidence_id,), ("review-origin",))
        span = TraceSpan("span-a", self.plan["task"]["trace_id"], None, "evidence.review", "completed",
            stamp, stamp, 0, (item.evidence_id,))
        return replace(self.service.deterministic_no_model_result(self.task_id),
            observations=(observation,), evidence_ids=(item.evidence_id,),
            hypotheses=(hypothesis,), execution_trace=(span,))

    def assert_rejected_without_completion(self, value, message):
        # product=None exercises the former generic runner bypass directly.
        with self.assertRaisesRegex(ValueError, message):
            self.service.execute(self.task_id, lambda *_: value, authorized=True)
        self.assertEqual(self.service.describe(self.task_id)["status"], "failed")
        for table in ("workforce_results", "workforce_products", "workforce_outbox"):
            with self.subTest(table=table):
                count = self.db.conn.execute(
                    "SELECT COUNT(*) FROM " + table + " WHERE task_id=?", (self.task_id,)).fetchone()[0]
                self.assertEqual(count, 0)

    def test_listed_but_nonexistent_evidence_is_rejected_atomically(self):
        value = replace(self.service.deterministic_no_model_result(self.task_id),
            evidence_ids=("evidence-fabricated",),
            hypotheses=(Hypothesis("hypothesis-a", "This may hold", ("evidence-fabricated",), ("check-origin",)),))
        self.assert_rejected_without_completion(value, "outside its case")

    def test_listed_evidence_from_another_case_is_rejected_atomically(self):
        self.db.create_case("case-b", "Foreign case", "A separate controlled synthetic case")
        item = self.capture("case-b")
        self.assertTrue(self.service.store.verify_evidence(item))
        self.assert_rejected_without_completion(self.cited(item), "outside its case")

    def test_altered_preserved_bytes_are_rejected_atomically(self):
        item = self.capture()
        value = self.cited(item)
        Path(item.raw_artifact_pointer).write_text("tampered", encoding="utf-8")
        self.assert_rejected_without_completion(value, "failed integrity")

    def test_wrong_observation_acquisition_is_rejected_atomically(self):
        value = self.cited(self.capture())
        value = replace(value, observations=(replace(value.observations[0], acquisition_id="acquisition-foreign"),))
        self.assert_rejected_without_completion(value, "acquisition mismatch")

    def test_foreign_task_trace_is_rejected_atomically(self):
        value = self.cited(self.capture())
        value = replace(value, execution_trace=(replace(value.execution_trace[0], trace_id="trace-foreign"),))
        self.assert_rejected_without_completion(value, "trace belongs to another task")

    def test_canonical_row_cannot_alias_a_different_valid_evidence_id(self):
        first = self.capture()
        source = self.root / "second.json"
        source.write_text('{"fixture":"second distinct capture"}', encoding="utf-8")
        preserved = EvidenceStore(self.root, self.db, "case-a").preserve_file(source, "fixture-second")
        second = self.service.store.import_v1_evidence("case-a", preserved["sha256"])
        self.assertNotEqual(first.evidence_id, second.evidence_id)
        encoded = json.dumps(second.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        # Keep the original digest: the former verifier followed parsed JSON keys
        # to the second valid row instead of checking the row selected for this ID.
        self.db.conn.execute(
            "UPDATE evidence_objects_v2 SET object_json=? WHERE case_id=? AND evidence_id=?",
            (encoded, "case-a", first.evidence_id))
        self.db.conn.commit()
        self.assertTrue(self.service.store.verify_evidence(second))
        value = replace(self.service.deterministic_no_model_result(self.task_id),
            evidence_ids=(first.evidence_id,),
            hypotheses=(Hypothesis("hypothesis-alias", "The supplied assertion may hold",
                (first.evidence_id,), ("review-origin",)),))
        self.assert_rejected_without_completion(value, "failed integrity")

    def test_missing_canonical_acquisition_is_rejected_atomically(self):
        item = self.capture()
        value = self.cited(item)
        self.db.conn.execute("DELETE FROM acquisitions_v2 WHERE acquisition_id=?", (item.acquisition_id,))
        self.db.conn.commit()
        self.assert_rejected_without_completion(value, "acquisition metadata mismatch")

    def test_changed_canonical_acquisition_metadata_is_rejected_atomically(self):
        item = self.capture()
        value = self.cited(item)
        self.db.conn.execute("UPDATE acquisitions_v2 SET source_id=? WHERE acquisition_id=?",
                            ("source-foreign", item.acquisition_id))
        self.db.conn.commit()
        self.assert_rejected_without_completion(value, "acquisition metadata mismatch")

    def test_same_case_cited_completion_preserves_valid_provenance(self):
        item = self.capture()
        value = self.cited(item)
        completed = self.service.execute(self.task_id, lambda *_: value, authorized=True)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(ResultEnvelope.from_dict(completed["result"]), value)
        self.assertTrue(self.service.store.verify_evidence(item))
        for table in ("workforce_results", "workforce_outbox"):
            self.assertEqual(self.db.conn.execute(
                "SELECT COUNT(*) FROM " + table + " WHERE task_id=?", (self.task_id,)).fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
