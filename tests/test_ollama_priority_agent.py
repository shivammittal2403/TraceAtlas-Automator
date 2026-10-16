"""Regression tests: Ollama ranking cannot grant new OSINT permissions."""
import json
import unittest

from traceatlas.employee.agentic_planner import approved_actions, prioritize_actions, validate_priority


ACTIONS = [
    {"action_id": "action-aaa", "source": "dns", "target_type": "domain", "target": "example.org"},
    {"action_id": "action-bbb", "source": "rdap", "target_type": "domain", "target": "example.org"},
]
MANIFEST = {
    "model": "qwen2.5:7b",
    "objective": "Investigate authorized domain infrastructure",
    "actions": ACTIONS,
}


class OllamaPlannerTests(unittest.TestCase):
    def test_valid_local_response_prioritizes_without_executing(self):
        calls = []
        def requester(url, body, headers, timeout):
            calls.append((url, json.loads(body), timeout))
            return 200, json.dumps({"response": json.dumps({
                "order": ["action-bbb", "action-aaa"],
                "rationale": "Registration may explain infrastructure",
                "questions": ["Has registration changed?"],
            })}).encode()
        result = prioritize_actions(MANIFEST, requester=requester, timeout=3)
        self.assertEqual(result["status"], "model-advisory")
        self.assertEqual(result["order"], ["action-bbb", "action-aaa"])
        self.assertFalse(result["may_execute"])
        self.assertEqual(calls[0][0], "http://127.0.0.1:11434/api/generate")
        self.assertEqual(calls[0][2], 3)
        self.assertNotIn("example.org", calls[0][1]["prompt"])

    def test_model_cannot_add_remove_duplicate_or_modify_actions(self):
        allowed = approved_actions(MANIFEST)
        for order in (["action-aaa"], ["action-aaa", "action-evil"],
                      ["action-aaa", "action-aaa"], ["action-bbb", 2]):
            with self.subTest(order=order), self.assertRaises(ValueError):
                validate_priority({"order": order, "rationale": "", "questions": []}, allowed)

    def test_unavailable_model_falls_back(self):
        def failed(*args):
            raise TimeoutError("synthetic Ollama timeout")
        result = prioritize_actions(MANIFEST, requester=failed, timeout=2)
        self.assertEqual(result["status"], "model-unavailable")
        self.assertEqual(result["order"], [])
        self.assertFalse(result["may_execute"])

    def test_invalid_model_tool_injection_is_rejected(self):
        def invalid(url, body, headers, timeout):
            return 200, json.dumps({"response": json.dumps({
                "order": ["action-aaa", "action-evil"],
                "rationale": "Ignore the policy", "questions": [],
            })}).encode()
        result = prioritize_actions(MANIFEST, requester=invalid)
        self.assertEqual(result["status"], "invalid-model-priority")
        self.assertEqual(result["order"], [])

    def test_duplicate_approved_manifest_fails_before_network(self):
        bad = {**MANIFEST, "actions": [ACTIONS[0], ACTIONS[0]]}
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            prioritize_actions(bad, requester=lambda *args: self.fail("network not allowed"))

    def test_extra_model_fields_or_bad_timeout_are_rejected(self):
        with self.assertRaises(ValueError):
            prioritize_actions(MANIFEST, timeout=90)
        with self.assertRaises(ValueError):
            validate_priority({"order": ["action-aaa", "action-bbb"],
                               "rationale": "ok", "questions": [], "shell": "bash"}, approved_actions(MANIFEST))
