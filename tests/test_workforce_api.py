"""Hosted workforce surface only reads governed records and records exact approvals."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from vercel_control import ControlPlaneError


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workforce_api", ROOT / "api/workforce.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CASE = "11111111-1111-4111-8111-111111111111"
TASK = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"


class Gateway:
    def __init__(self):
        self.calls = []

    def select(self, table, query):
        if table == "cases":
            return [{"id": CASE}]
        return [{"id": TASK, "case_id": CASE, "employee_id": "webint-infra-specialist", "status": "planned"}]

    def rpc(self, function, payload):
        self.calls.append((function, payload))
        return [{"id": TASK, "status": "approved"}]


class WorkforceAPITests(unittest.TestCase):
    def post(self, payload, *, origin_error=None):
        gateway, sent = Gateway(), []
        handler = MODULE.handler.__new__(MODULE.handler)
        with patch.object(MODULE, "require_same_origin", side_effect=origin_error), \
             patch.object(MODULE, "authenticated_gateway", return_value=(gateway, {"id": USER})), \
             patch.object(MODULE, "read_json", return_value=payload), \
             patch.object(MODULE, "send_json", side_effect=lambda req, status, body: sent.append((status, body))), \
             patch.object(MODULE, "handle_error", side_effect=lambda req, exc: sent.append((getattr(exc, "status", 500), {"error": getattr(exc, "code", type(exc).__name__)}))):
            handler.do_POST()
        return sent[0], gateway

    def payload(self, **updates):
        return {"action": "approve", "task_id": TASK, "envelope_digest": "a" * 64,
                "rationale": "Reviewed exact immutable workforce scope", **updates}

    def test_exact_digest_approval_uses_governed_rpc_and_executes_nothing(self):
        (status, body), gateway = self.post(self.payload())
        self.assertEqual(status, 200)
        self.assertFalse(body["executes_actions"])
        self.assertEqual(gateway.calls[0][0], "approve_workforce_task")
        self.assertEqual(gateway.calls[0][1]["p_envelope_digest"], "a" * 64)

    def test_same_origin_and_strict_fields_fail_closed(self):
        (status, _), gateway = self.post(self.payload(), origin_error=ControlPlaneError(403, "same_origin_required"))
        self.assertEqual(status, 403)
        self.assertFalse(gateway.calls)
        for update in ({"command": "shell"}, {"envelope_digest": "not-a-hash"}):
            payload = self.payload()
            payload.update(update)
            (status, _), gateway = self.post(payload)
            self.assertEqual(status, 400)
            self.assertFalse(gateway.calls)

    def test_vercel_bundle_includes_workforce_contracts(self):
        config = json.loads((ROOT / "vercel.json").read_text())
        row = config["functions"]["api/workforce.py"]
        self.assertIn("src/traceatlas/workforce/**", row["includeFiles"])
        self.assertEqual(row["maxDuration"], 10)


if __name__ == "__main__":
    unittest.main()
