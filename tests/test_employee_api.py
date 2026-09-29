"""Hosted employee uses authenticated stored evidence and existing review RLS."""
import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from vercel_control import ControlPlaneError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("employee_api", ROOT / "api/employee.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CASE = "11111111-1111-4111-8111-111111111111"
ORG = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"


class Gateway:
    def __init__(self, *, visible=True):
        self.visible = visible
        self.inserts = []
        self.evidence = [{"id": "44444444-4444-4444-8444-444444444444", "source": "fixture-provider",
                          "classification": "observed", "payload": {"ports": [443]},
                          "content_hash": "a" * 64, "created_at": "2026-09-29T00:00:00Z"}]

    def select(self, table, params):
        if table == "cases":
            assert params["id"] == "eq." + CASE
            return [{"id": CASE, "organisation_id": ORG}] if self.visible else []
        assert params["case_id"] == "eq." + CASE
        if table == "evidence_items":
            return self.evidence
        return []

    def insert(self, table, payload):
        self.inserts.append((table, payload))
        return [{"id": "55555555-5555-4555-8555-555555555555", **payload}]


class EmployeeAPITests(unittest.TestCase):
    def request(self, payload, gateway=None, *, auth_error=None, origin_error=None):
        gateway = gateway or Gateway()
        handler = MODULE.handler.__new__(MODULE.handler)
        handler.path = "/api/employee"
        sent = []
        with patch.object(MODULE, "require_same_origin", side_effect=origin_error), \
             patch.object(MODULE, "authenticated_gateway", return_value=(gateway, {"id": USER}), side_effect=auth_error), \
             patch.object(MODULE, "read_json", return_value=payload), \
             patch.object(MODULE, "send_json", side_effect=lambda req, status, body: sent.append((status, body))), \
             patch.object(MODULE, "handle_error", side_effect=lambda req, exc: sent.append((getattr(exc, "status", 500), {"error": getattr(exc, "code", type(exc).__name__)}))):
            handler.do_POST()
        return sent[0], gateway

    def payload(self, **updates):
        return {"action": "brief", "case_id": CASE, "objective": "Review service exposure evidence", "mode": "pt", **updates}

    def test_authentication_same_origin_and_case_visibility(self):
        for kwargs, code in (({"auth_error": ControlPlaneError(401, "authentication_required")}, 401),
                             ({"origin_error": ControlPlaneError(403, "same_origin_required")}, 403),
                             ({"gateway": Gateway(visible=False)}, 404)):
            (status, _), gateway = self.request(self.payload(), **kwargs)
            self.assertEqual(status, code)
            self.assertFalse(gateway.inserts)

    def test_brief_uses_stored_records_and_does_not_write_or_execute(self):
        (status, body), gateway = self.request(self.payload())
        self.assertEqual(status, 200)
        self.assertEqual(body["brief"]["summary"]["observations"], 1)
        self.assertEqual(body["brief"]["scenarios"][0]["id"], "exposure")
        self.assertFalse(gateway.inserts)

    def test_client_cannot_supply_evidence_commands_or_model_endpoints(self):
        for key in ("evidence", "observations", "command", "model_url", "target"):
            (status, _), gateway = self.request(self.payload(**{key: "untrusted"}))
            self.assertEqual(status, 400)
            self.assertFalse(gateway.inserts)

    def test_changed_evidence_blocks_review_submission(self):
        (status, body), gateway = self.request(self.payload())
        expected = body["brief"]["evidence_digest"]
        gateway.evidence[0]["payload"] = {"ports": [22]}
        (status, body), _ = self.request(self.payload(action="queue-review", expected_evidence_digest=expected), gateway)
        self.assertEqual(status, 409)
        self.assertFalse(gateway.inserts)

    def test_review_is_owned_by_user_and_contains_server_derived_snapshot(self):
        (_, body), gateway = self.request(self.payload())
        (status, _), _ = self.request(self.payload(action="queue-review", expected_evidence_digest=body["brief"]["evidence_digest"]), gateway)
        self.assertEqual(status, 201)
        table, item = gateway.inserts[0]
        self.assertEqual(table, "review_tasks")
        self.assertEqual(item["created_by"], USER)
        self.assertEqual(item["organisation_id"], ORG)
        self.assertEqual(item["context"]["decision_owner"], "human")
        self.assertFalse(item["context"]["auto_execute"])
        self.assertLess(len(json.dumps(item["context"]).encode()), 16384)

    def test_worker_observation_locator_and_truncation_are_explicit(self):
        gateway = Gateway()
        gateway.evidence[0]["payload"] = {"observations": [{"type": "SERVICE", "value": {"ports": [443]}} for _ in range(205)]}
        (status, body), _ = self.request(self.payload(), gateway)
        self.assertEqual(status, 200)
        self.assertEqual(body["brief"]["summary"]["observations"], 200)
        self.assertTrue(body["brief"]["summary"]["truncated"])
        self.assertTrue(body["brief"]["facts"][0]["id"].endswith("/observations/0"))

    def test_worker_model_output_not_promoted_to_fact(self):
        gateway = Gateway()
        gateway.evidence[0]["payload"] = {"observations": [{"type": "SUMMARY", "value": "claim", "tags": ["model-output"]}]}
        (status, body), _ = self.request(self.payload(), gateway)
        self.assertEqual(status, 200)
        self.assertFalse(body["brief"]["facts"])

    def test_review_snapshot_bounded_for_many_unicode_citations(self):
        from traceatlas.employee.brief import build_brief
        rows = [{"id": "e" + str(i), "source": "测试" * 100, "classification": "observed", "data": {"ports": [443], "text": "说明" * 500}}
                for i in range(40)]
        brief = build_brief(CASE, "Compare service observations", rows)
        snapshot = MODULE.review_snapshot(brief)
        self.assertLessEqual(len(json.dumps(snapshot, ensure_ascii=False).encode()), 14000)

    def test_vercel_bundle_includes_shared_core_and_keeps_existing_limits(self):
        config = json.loads((ROOT / "vercel.json").read_text())
        self.assertEqual(next(iter(config["functions"])), "api/employee.py")
        employee = config["functions"]["api/employee.py"]
        self.assertEqual(employee["maxDuration"], 30)
        self.assertNotIn(",src/**,", employee["excludeFiles"])
        self.assertEqual(config["functions"]["api/*.py"]["maxDuration"], 10)


if __name__ == "__main__":
    unittest.main()
