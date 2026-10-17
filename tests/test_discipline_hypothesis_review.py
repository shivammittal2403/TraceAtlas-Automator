"""Canonical native hypothesis review lifecycle, provenance and adversarial replay."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.discipline_engines import invoke_employee
from traceatlas.workforce.discipline_runtime import create_runtime, canonical


class DisciplineHypothesisReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / "case.db")
        self.addCleanup(self.db.close)
        self.db.create_case("review-case", "Native review", "Synthetic canonical hypothesis regression")
        self.runtime = create_runtime(self.db, self.root, enabled=True)
        now = datetime.now(timezone.utc)
        self.context = AuthorizationContext(
            "1.0", "review-auth", "review-case", "fixture-analyst",
            "Review synthetic supplied hypotheses", ("provided_records:review-case",),
            ("propose_observation",), ("discipline.analyze",), "IN", "fixture",
            (now - timedelta(seconds=1)).isoformat(), (now + timedelta(hours=1)).isoformat(), "a" * 64)
        self.runtime.service.register_authorization(self.context)

    def payload(self, label="HYPOTHESISINT"):
        return {"case_id": "review-case", "discipline": label,
                "objective": "Review synthetic competing explanations",
                "as_of": "2026-01-01T00:00:00Z",
                "sources": [
                    {"source_id": "S0", "uri": "urn:fixture:matrix"},
                    {"source_id": "S1", "uri": "urn:fixture:first", "original_source_id": "origin-a"},
                    {"source_id": "S2", "uri": "urn:fixture:copy", "original_source_id": "origin-a"},
                    {"source_id": "S3", "uri": "urn:fixture:contrary", "original_source_id": "origin-b"},
                    {"source_id": "S4", "uri": "urn:fixture:unknown"}],
                "records": [
                    {"record_id": "M", "source_id": "S0", "data": {
                        "hypotheses": [{"id": "h1", "statement": "Primary explanation"},
                                       {"id": "h2", "statement": "Benign alternative"}],
                        "evidence": [
                            {"record_id": "R1", "weight": 0.8, "assessments": {"h1": "supports", "h2": "refutes"}},
                            {"record_id": "R2", "weight": 0.6, "assessments": {"h1": "supports", "h2": "neutral"}},
                            {"record_id": "R3", "weight": 0.5, "assessments": {"h1": "refutes", "h2": "supports"}},
                            {"record_id": "R4", "weight": 0.2, "assessments": {"h1": "unknown", "h2": "unknown"}},
                            {"record_id": "R1", "weight": 1, "assessments": {"h1": "refutes"}},
                            {"record_id": "Missing", "assessments": {"h1": "supports"}}]}},
                    {"record_id": "R1", "source_id": "S1", "data": {"observation": "First assertion"}},
                    {"record_id": "R2", "source_id": "S2", "data": {"observation": "Copied assertion"}},
                    {"record_id": "R3", "source_id": "S3", "data": {"observation": "Contrary assertion"}},
                    {"record_id": "R4", "source_id": "S4", "data": {"observation": "Unresolved assertion"}}]}

    def run_payload(self, payload):
        plan = self.runtime.plan(self.context.context_id, payload["discipline"], payload)
        task_id = plan["task"]["task_id"]
        self.runtime.service.approve(
            task_id, actor_id=self.context.actor_id, rationale="Approve exact synthetic review records",
            envelope_digest=plan["envelope_digest"], authorized=True)
        return plan, self.runtime.run(task_id, authorized=True)

    def rewrite_product(self, task_id, mutation):
        product = self.runtime.store.product(task_id)
        mutation(product)
        encoded = canonical(product)
        self.db.conn.execute(
            "UPDATE workforce_products SET product_json=?,product_digest=? WHERE task_id=?",
            (encoded, hashlib.sha256(encoded.encode()).hexdigest(), task_id))
        self.db.conn.commit()

    def count(self, table):
        return self.db.conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]

    def legacy_identity(self, label, runtime_hash):
        from traceatlas.workforce.discipline_engines import engine_identity
        from traceatlas.workforce import discipline_review
        from traceatlas.workforce.discipline_runtime import digest
        return digest({"processors": engine_identity(label), "runtime": runtime_hash,
                       "canonical_review": hashlib.sha256(Path(discipline_review.__file__).read_bytes()).hexdigest()})

    def test_replay_adapter_accepts_only_exact_pinned_runtime_with_current_processor_and_review(self):
        from traceatlas.workforce.discipline_runtime import (
            LEGACY_REVIEW_RUNTIME_SHA256, _review_replay_adapter, _identity)
        for label in ("HYPOTHESISINT", "FALSIFICATIONINT"):
            with self.subTest(label=label):
                self.assertEqual(_review_replay_adapter(label, _identity(label)), "current-runtime")
                for old_runtime in LEGACY_REVIEW_RUNTIME_SHA256:
                    old_identity = self.legacy_identity(label, old_runtime)
                    self.assertEqual(_review_replay_adapter(label, old_identity), "pinned-runtime-8a322870")
                    with patch("traceatlas.workforce.discipline_engines.engine_identity", return_value="changed-processor"):
                        with self.assertRaisesRegex(ValueError, "engine changed"):
                            _review_replay_adapter(label, old_identity)
                with self.assertRaisesRegex(ValueError, "engine changed"):
                    _review_replay_adapter(label, self.legacy_identity(label, "0" * 64))

    def test_pinned_replay_compatibility_never_authorizes_an_old_pending_engine(self):
        from traceatlas.workforce.discipline_runtime import LEGACY_REVIEW_RUNTIME_SHA256
        old_identity = self.legacy_identity("HYPOTHESISINT", LEGACY_REVIEW_RUNTIME_SHA256[0])
        with patch("traceatlas.workforce.discipline_runtime._identity", return_value=old_identity):
            plan = self.runtime.plan(self.context.context_id, "HYPOTHESISINT", self.payload())
            self.runtime.service.approve(
                plan["task"]["task_id"], actor_id=self.context.actor_id,
                rationale="Approve an old engine before its simulated runtime upgrade",
                envelope_digest=plan["envelope_digest"], authorized=True)
        with self.assertRaisesRegex(ValueError, "engine changed"):
            self.runtime.run(plan["task"]["task_id"], authorized=True)
        self.assertEqual(self.runtime.store.task(plan["task"]["task_id"])["status"], "approved")
        self.assertEqual(self.count("workforce_results"), 0)
        self.assertEqual(self.count("workforce_products"), 0)

    def test_native_stance_provenance_and_copied_origins_survive_canonical_lifecycle(self):
        plan, product = self.run_payload(self.payload())
        self.assertEqual(product["schema"], "traceatlas-discipline-product/v2")
        self.assertEqual({row["statement"] for row in product["result"]["hypotheses"]},
                         {"Primary explanation", "Benign alternative"})
        self.assertEqual(product["analysis"]["hypotheses"], product["result"]["hypotheses"])
        review = product["analysis"]["hypothesis_review"]
        self.assertTrue(review["recomputed_from_preserved_input"])
        self.assertFalse(review["origin_group_independence_verified"])
        matrix = review["native_artifacts"]["hypotheses"][0]
        h1 = next(row for row in matrix["ranking"] if row["hypothesis_id"] == "h1")
        self.assertAlmostEqual(h1["support_weight"], 0.8)
        self.assertAlmostEqual(h1["refute_weight"], 0.5)
        self.assertEqual(h1["unknown_assessments"], 1)
        self.assertEqual({row["record_id"]: row["stance"] for row in h1["assessments"]},
                         {"R1": "supports", "R2": "supports", "R3": "refutes", "R4": "unknown"})
        h2 = next(row for row in matrix["ranking"] if row["hypothesis_id"] == "h2")
        self.assertEqual(next(row["stance"] for row in h2["assessments"] if row["record_id"] == "R2"), "neutral")
        origin = {row["record_id"]: row["asserted_origin_group"] for row in h1["assessments"]}
        self.assertEqual(origin["R1"], origin["R2"])
        self.assertNotEqual(origin["R1"], origin["R3"])
        codes = {row["code"] for row in review["native_issues"]}
        self.assertIn("duplicate_hypothesis_evidence", codes)
        self.assertIn("unknown_hypothesis_evidence", codes)
        provenance = {row["record_id"]: row for row in review["record_provenance"]}
        _, evidence = self.runtime._input(self.runtime.store.task(plan["task"]["task_id"])["envelope"])
        for index, record in enumerate(self.payload()["records"]):
            self.assertEqual(provenance[record["record_id"]]["input_pointer"], "/records/" + str(index))
            self.assertEqual(provenance[record["record_id"]]["asserted_source_id"], record["source_id"])
            self.assertEqual(provenance[record["record_id"]]["evidence_id"], plan["input_evidence_id"])
            self.assertEqual(provenance[record["record_id"]]["acquisition_id"], evidence.acquisition_id)
        for hypothesis in product["result"]["hypotheses"]:
            self.assertEqual(hypothesis["evidence_ids"], [plan["input_evidence_id"]])
            self.assertEqual(len(hypothesis["next_checks"]), 3)
        self.assertEqual(len({row["hypothesis_id"] for row in product["result"]["hypotheses"]}), 2)

    def test_callback_artifacts_cannot_promote_forged_hypotheses_or_scores(self):
        calls = []
        def forged(payload, *, evidence_ids):
            calls.append(payload["task_id"])
            native = invoke_employee(payload, evidence_ids=evidence_ids)
            native["artifacts"] = {"hypotheses": [{"hypothesis_id": "FORGED",
                "statement": "Forged proposition", "support_weight": 999,
                "evidence_ids": ["foreign-evidence"]}]}
            return native
        self.runtime.invoker = forged
        _, product = self.run_payload(self.payload())
        self.assertEqual(len(calls), 1)
        self.assertEqual(product["draft"]["artifacts"]["hypotheses"][0]["hypothesis_id"], "FORGED")
        self.assertNotIn("Forged proposition", {row["statement"] for row in product["result"]["hypotheses"]})
        review = product["analysis"]["hypothesis_review"]
        self.assertNotIn("FORGED", canonical(review))
        self.assertNotIn("foreign-evidence", canonical(review))
        h1 = review["native_artifacts"]["hypotheses"][0]["ranking"][0]
        self.assertAlmostEqual(h1["support_weight"], 0.8)

    def test_falsification_preserves_counterexamples_unknowns_and_pending_scope(self):
        payload = self.payload("FALSIFICATIONINT")
        payload["records"] = [
            {"record_id": "P", "source_id": "S0", "data": {"hypothesis_id": "all-cool",
                "tests": [{"test_id": "bound", "field": "temperature", "operator": "lte",
                           "expected_value": 10, "record_ids": ["A", "B", "C", "Missing"]},
                          {"test_id": "exists", "field": "temperature", "operator": "eq",
                           "expected_value": 0, "record_ids": ["A"], "claim_kind": "existential",
                           "coverage_complete": False}]}},
            {"record_id": "A", "source_id": "S1", "data": {"temperature": 9}},
            {"record_id": "B", "source_id": "S2", "data": {"temperature": 12}},
            {"record_id": "C", "source_id": "S3", "data": {"other": 1}}]
        plan, product = self.run_payload(payload)
        self.assertEqual(product["result"]["hypotheses"], [])
        review = product["analysis"]["hypothesis_review"]
        protocol = review["native_artifacts"]["falsification"][0]
        self.assertEqual(protocol["hypothesis_id"], "all-cool")
        self.assertFalse(protocol["hypothesis_proven_true"])
        tests = {row["test_id"]: row for row in protocol["tests"]}
        self.assertEqual(tests["bound"]["state"], "COUNTEREXAMPLE_IN_SUPPLIED_RECORDS")
        self.assertEqual(tests["bound"]["passing_record_ids"], ["A"])
        self.assertEqual(tests["bound"]["counterexample_record_ids"], ["B"])
        self.assertEqual(tests["bound"]["unknown_record_ids"], ["C", "Missing"])
        self.assertEqual(tests["exists"]["state"], "INCONCLUSIVE")
        self.assertEqual(review["input_evidence_id"], plan["input_evidence_id"])

    def test_malformed_matrices_and_protocols_remain_issues_without_invented_hypotheses(self):
        for label, data, expected in (
            ("HYPOTHESISINT", {"hypotheses": [{"id": "h", "statement": "First"},
                {"id": "h", "statement": "Duplicate"}], "evidence": []}, "ambiguous_hypothesis_ids"),
            ("FALSIFICATIONINT", {"hypothesis_id": "h", "tests": "invalid"}, "invalid_falsification_protocol")):
            with self.subTest(label=label):
                payload = self.payload(label)
                payload["records"] = [{"record_id": "M", "source_id": "S0", "data": data}]
                _, product = self.run_payload(payload)
                self.assertEqual(product["result"]["hypotheses"], [])
                review = product["analysis"]["hypothesis_review"]
                self.assertIn(expected, {row["code"] for row in review["native_issues"]})

    def test_projection_bound_and_overlong_proposition_are_explicit_omissions(self):
        payload = self.payload()
        payload["records"][0]["data"] = {"hypotheses": [
            {"id": "h" + str(index), "statement": "Supplied explanation " + str(index)}
            for index in range(101)], "evidence": []}
        _, product = self.run_payload(payload)
        self.assertEqual(len(product["result"]["hypotheses"]), 100)
        review = product["analysis"]["hypothesis_review"]
        self.assertEqual(len(review["native_artifacts"]["hypotheses"][0]["ranking"]), 101)
        self.assertEqual(review["hypotheses_omitted"]["canonical_limit"], 1)
        self.assertIn("discipline-review-canonical-limit", product["result"]["information_gaps"])
        long_payload = self.payload()
        long_payload["records"][0]["data"] = {"hypotheses": [
            {"id": "long", "statement": "x" * 4001}], "evidence": []}
        _, long_product = self.run_payload(long_payload)
        self.assertEqual(long_product["result"]["hypotheses"], [])
        self.assertEqual(long_product["analysis"]["hypothesis_review"]["hypotheses_omitted"]["invalid_statement"], 1)
        self.assertIn("discipline-review-invalid-statement", long_product["result"]["information_gaps"])

    def test_unapproved_task_and_review_budget_failure_never_finalize(self):
        plan = self.runtime.plan(self.context.context_id, "HYPOTHESISINT", self.payload())
        task_id = plan["task"]["task_id"]
        with patch("traceatlas.workforce.discipline_runtime.project_discipline_review",
                   side_effect=AssertionError("Unapproved projection executed")):
            with self.assertRaises(ValueError):
                self.runtime.run(task_id, authorized=True)
        self.runtime.service.approve(
            task_id, actor_id=self.context.actor_id, rationale="Approve bounded synthetic review",
            envelope_digest=plan["envelope_digest"], authorized=True)
        with patch("traceatlas.workforce.discipline_review.MAX_REVIEW_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "bounded output"):
                self.runtime.run(task_id, authorized=True)
        for table in ("workforce_products", "workforce_results", "workforce_outbox", "observations_v2"):
            self.assertEqual(self.count(table), 0)
        self.assertEqual(self.count("evidence_objects_v2"), 1)

    def test_completed_run_is_idempotent_and_offline_replay_recomputes_trusted_review(self):
        plan, product = self.run_payload(self.payload())
        task_id = plan["task"]["task_id"]
        with patch("traceatlas.workforce.discipline_runtime.project_discipline_review",
                   side_effect=AssertionError("Completed run must return its stored product")):
            self.assertEqual(self.runtime.run(task_id, authorized=True), product)
        fresh = create_runtime(self.db, self.root, enabled=True)
        self.assertEqual(fresh.run(task_id, authorized=True), product)
        fresh.invoker = lambda *args, **kwargs: self.fail("Replay cannot call the employee callback")
        receipt = fresh.replay(task_id)
        self.assertEqual(receipt["status"], "VERIFIED_NATIVE_REVIEW")
        self.assertTrue(receipt["semantic_recomputed"])
        self.assertEqual(receipt["hypotheses_verified"], 2)
        self.assertFalse(receipt["factual_entailment_verified"])
        self.assertEqual(fresh.store.product(task_id), product)
        for table in ("workforce_products", "workforce_results", "workforce_outbox"):
            self.assertEqual(self.count(table), 1)
        self.assertTrue(EvidenceStore(self.root, self.db, "review-case").verify_ledger()[0])

    def test_rehashed_sidecar_and_projection_tampering_fail_semantic_replay(self):
        mutations = (
            lambda product: product["analysis"]["hypothesis_review"]["native_artifacts"]["hypotheses"][0]["ranking"][0].update(support_weight=999),
            lambda product: product["analysis"]["hypotheses"][0].update(statement="Forged projection"),
            lambda product: product["analysis"]["hypothesis_review"]["record_provenance"][0].update(evidence_id="foreign-evidence"))
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                plan, _ = self.run_payload(self.payload())
                task_id = plan["task"]["task_id"]
                self.rewrite_product(task_id, mutation)
                with self.assertRaisesRegex(ValueError, "replay mismatch"):
                    self.runtime.replay(task_id)

    def test_consistently_rehashed_product_and_result_cannot_change_canonical_hypothesis(self):
        plan, _ = self.run_payload(self.payload())
        task_id = plan["task"]["task_id"]
        product = self.runtime.store.product(task_id)
        product["result"]["hypotheses"][0]["statement"] = "Forged canonical proposition"
        result_encoded = canonical(product["result"])
        product_encoded = canonical(product)
        self.db.conn.execute(
            "UPDATE workforce_results SET result_json=?,result_digest=? WHERE task_id=?",
            (result_encoded, hashlib.sha256(result_encoded.encode()).hexdigest(), task_id))
        self.db.conn.execute(
            "UPDATE workforce_products SET product_json=?,product_digest=? WHERE task_id=?",
            (product_encoded, hashlib.sha256(product_encoded.encode()).hexdigest(), task_id))
        self.db.conn.commit()
        with self.assertRaisesRegex(ValueError, "replay mismatch"):
            self.runtime.replay(task_id)

    def test_rehashed_reviewed_product_cannot_downgrade_to_legacy_schema(self):
        plan, product = self.run_payload(self.payload())
        task_id = plan["task"]["task_id"]
        product["schema"] = "traceatlas-discipline-product/v1"
        product["result"]["hypotheses"] = []
        product["analysis"].pop("hypotheses")
        product["analysis"].pop("hypothesis_review")
        result_encoded = canonical(product["result"])
        product_encoded = canonical(product)
        self.db.conn.execute(
            "UPDATE workforce_results SET result_json=?,result_digest=? WHERE task_id=?",
            (result_encoded, hashlib.sha256(result_encoded.encode()).hexdigest(), task_id))
        self.db.conn.execute(
            "UPDATE workforce_products SET product_json=?,product_digest=? WHERE task_id=?",
            (product_encoded, hashlib.sha256(product_encoded.encode()).hexdigest(), task_id))
        self.db.conn.commit()
        with self.assertRaises(ValueError):
            self.runtime.replay(task_id)

    def test_unknown_rehashed_review_product_schema_fails_closed(self):
        plan, _ = self.run_payload(self.payload())
        task_id = plan["task"]["task_id"]
        self.rewrite_product(task_id, lambda product: product.update(
            schema="traceatlas-discipline-product/v999"))
        with self.assertRaises(ValueError):
            self.runtime.replay(task_id)

    def test_engine_and_acquisition_changes_prevent_verified_replay(self):
        plan, _ = self.run_payload(self.payload())
        task_id = plan["task"]["task_id"]
        with patch("traceatlas.workforce.discipline_runtime._identity", return_value="0" * 64):
            with self.assertRaisesRegex(ValueError, "engine changed"):
                self.runtime.replay(task_id)
        self.db.conn.execute("UPDATE acquisitions_v2 SET method='forged' WHERE case_id=?", ("review-case",))
        self.db.conn.commit()
        with self.assertRaisesRegex(ValueError, "acquisition metadata"):
            self.runtime.replay(task_id)

    def test_replay_rejects_damaged_custody_ledger(self):
        plan, _ = self.run_payload(self.payload())
        ledger = EvidenceStore(self.root, self.db, "review-case").ledger
        ledger.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "custody ledger"):
            self.runtime.replay(plan["task"]["task_id"])

    def test_replay_rejects_modified_preserved_input_bytes(self):
        plan, _ = self.run_payload(self.payload())
        task = self.runtime.store.task(plan["task"]["task_id"])["envelope"]
        _, evidence = self.runtime._input(task)
        Path(evidence.raw_artifact_pointer).write_bytes(b"{}")
        with self.assertRaises(ValueError):
            self.runtime.replay(plan["task"]["task_id"])

    def test_legacy_products_keep_integrity_only_replay_and_unchanged_shape(self):
        payload = self.payload("DNSINT")
        payload["records"] = [{"record_id": "D", "source_id": "S0", "data": {
            "name": "example.org", "type": "A", "value": "192.0.2.1"}}]
        plan, product = self.run_payload(payload)
        self.assertEqual(product["schema"], "traceatlas-discipline-product/v1")
        self.assertNotIn("hypothesis_review", product["analysis"])
        self.assertNotIn("hypotheses", product["analysis"])
        receipt = self.runtime.replay(plan["task"]["task_id"])
        self.assertEqual(receipt["status"], "LEGACY_INTEGRITY_ONLY")
        self.assertFalse(receipt["semantic_recomputed"])
        self.assertEqual(self.runtime.store.product(plan["task"]["task_id"]), product)


if __name__ == "__main__":
    unittest.main()
