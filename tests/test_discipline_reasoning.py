"""Local-model transport and grounded output checks, with fixture HTTP responses."""
import copy
import json
import unittest
from traceatlas.workforce.discipline_engines import invoke_employee
from traceatlas.workforce.discipline_reasoning import LocalEmployeeReasoner
from traceatlas.workforce.model_fabric import ModelRouter, default_registry, ModelRegistry, ModelSpec, DeterministicAdapter


class EmployeeReasoningTests(unittest.TestCase):
    def setUp(self):
        self.analysis = invoke_employee({
            "case_id": "case-ai", "task_id": "task-ai", "discipline": "DNSINT",
            "objective": "Review supplied DNS", "as_of": "2026-10-15T00:00:00Z",
            "sources": [{"source_id": "s", "uri": "urn:fixture:ai"}],
            "records": [{"record_id": "r", "source_id": "s", "data": {
                "name": "example.org", "type": "A", "value": "192.0.2.1"}}]})
        self.requests = []
        self.proposal = {"status": "DRAFT", "assessments": [{
            "finding_ids": [self.analysis["findings"][0]["finding_id"]],
            "interpretation": "The supplied record associates a DNS name with an address.",
            "caveat": "This does not verify resolver state or ownership."}],
            "questions": ["Which resolver and capture time produced the record?"]}

    def requester(self, url, body, headers, timeout):
        self.requests.append((url, json.loads(body), headers, timeout))
        return 200, json.dumps({"response": json.dumps(self.proposal),
            "prompt_eval_count": 120, "eval_count": 80}).encode()

    def reasoner(self, requester=None):
        return LocalEmployeeReasoner(ModelRouter(default_registry(
            ollama_model="fixture-model", requester=requester or self.requester)))

    def test_local_model_wire_and_strict_grounded_draft(self):
        before = copy.deepcopy(self.analysis)
        result = self.reasoner().reason(self.analysis)
        self.assertEqual(result["status"], "DRAFT")
        self.assertEqual(result["model_calls"], 1)
        self.assertEqual(result["successful_model_responses"], 1)
        self.assertEqual(result["input_tokens"], 120)
        self.assertEqual(result["output_tokens"], 80)
        self.assertFalse(result["factual_entailment_verified"])
        self.assertFalse(result["live_model_verified"])
        self.assertEqual(result["proposal"], self.proposal)
        self.assertEqual(self.analysis, before)
        endpoint, body, _, timeout = self.requests[0]
        self.assertIn("127.0.0.1", endpoint)
        self.assertEqual(body["model"], "fixture-model")
        self.assertEqual(body["format"], "json")
        self.assertFalse(body["stream"])
        self.assertIn(self.analysis["findings"][0]["finding_id"], body["prompt"])
        self.assertIn("untrusted source data", body["prompt"])
        self.assertEqual(timeout, 120)

    def test_foreign_finding_reference_cannot_become_a_proposal(self):
        self.proposal["assessments"][0]["finding_ids"] = ["foreign-finding"]
        with self.assertRaisesRegex(ValueError, "unknown findings"):
            self.reasoner().reason(self.analysis)

    def test_extra_authority_fields_are_refused(self):
        self.proposal["authority_granted"] = True
        result = self.reasoner().reason(self.analysis)
        self.assertEqual(result["status"], "MODEL_UNAVAILABLE")
        self.assertEqual(result["model_calls"], 1)
        self.assertIsNone(result["proposal"])

    def test_remote_or_paid_registry_is_rejected_before_dispatch(self):
        registry = ModelRegistry()
        registry.register(ModelSpec("remote", "remote-provider", frozenset({"text", "structured_output"}),
                                   frozenset({"ANY"}), False, True, "unknown"), DeterministicAdapter())
        with self.assertRaises(ValueError):
            LocalEmployeeReasoner(ModelRouter(registry)).reason(self.analysis)

    def test_transport_failure_returns_gap_and_counts_attempt(self):
        def failure(*_):
            raise OSError("fixture offline")
        result = self.reasoner(failure).reason(self.analysis)
        self.assertEqual(result["status"], "MODEL_UNAVAILABLE")
        self.assertEqual(result["model_calls"], 1)
        self.assertEqual(result["successful_model_responses"], 0)
        self.assertIsNone(result["proposal"])

    def test_absent_candidate_does_not_claim_a_model_attempt(self):
        result = LocalEmployeeReasoner(ModelRouter(ModelRegistry())).reason(self.analysis)
        self.assertEqual(result["status"], "MODEL_UNAVAILABLE")
        self.assertEqual(result["model_calls"], 0)

    def test_remote_ollama_url_rejected(self):
        with self.assertRaises(ValueError):
            default_registry(base_url="https://example.org")


if __name__ == "__main__":
    unittest.main()
