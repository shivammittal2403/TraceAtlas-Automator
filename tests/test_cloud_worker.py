from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traceatlas.cloud_worker import CloudWorker, WorkerError, _redact, _require_public_target, worker_id


JOB_ID = "11111111-1111-4111-8111-111111111111"
CASE_ID = "22222222-2222-4222-8222-222222222222"
ASSET_ID = "33333333-3333-4333-8333-333333333333"
ORG_ID = "44444444-4444-4444-8444-444444444444"


class FakeGateway:
    def __init__(self):
        self.claimed = False
        self.inserted = []
        self.completed = None

    def rpc(self, name, payload=None):
        if name == "recover_stale_investigation_jobs": return 0
        if name == "claim_next_investigation_job":
            if self.claimed: return []
            self.claimed = True
            return [{"id": JOB_ID, "case_id": CASE_ID, "asset_id": ASSET_ID,
                     "organisation_id": ORG_ID, "kind": "url_metadata", "status": "running"}]
        if name == "complete_investigation_job":
            self.completed = payload
            return True
        raise AssertionError(name)

    def select_one(self, table, _row_id, _columns):
        if table == "assets":
            return {"id": ASSET_ID, "organisation_id": ORG_ID, "target_type": "url",
                    "target_value": "https://example.com/about", "target_fingerprint": "a" * 64,
                    "ownership_basis": "owned_asset", "label": "Example website"}
        return {"id": CASE_ID, "organisation_id": ORG_ID, "title": "Authorised example",
                "purpose": "Test an explicitly owned public website", "status": "open"}

    def insert(self, table, payload):
        self.inserted.append((table, payload))
        return [{"id": "55555555-5555-4555-8555-555555555555"}] if table == "evidence_items" else []

    def upsert(self, table, payload, conflict):
        self.inserted.append((table, payload))
        self.upsert_conflict = conflict
        return [{"id": "66666666-6666-4666-8666-666666666666"}]


class CloudWorkerTests(unittest.TestCase):
    def test_worker_id_and_redaction(self):
        self.assertEqual(worker_id("worker-01"), "worker-01")
        with self.assertRaises(WorkerError): worker_id("bad worker id")
        self.assertNotIn("secret.example", str(_redact({"value": "secret.example"}, "secret.example")))

    def test_worker_processes_allowlisted_job_and_records_evidence(self):
        gateway = FakeGateway()
        with tempfile.TemporaryDirectory() as tmp:
            worker = CloudWorker(Path(tmp), gateway=gateway, identity="worker-01")
            with patch("traceatlas.cloud_worker.socket.getaddrinfo", return_value=[
                (2, 1, 6, "", ("93.184.216.34", 0)),
            ]): self.assertTrue(worker.run_once())
            self.assertFalse(worker.run_once())
        tables = [table for table, _ in gateway.inserted]
        for table in ("source_runs", "evidence_items", "graph_entities", "job_events", "review_tasks"):
            self.assertIn(table, tables)
        self.assertEqual(gateway.upsert_conflict, "case_id,fingerprint")
        self.assertEqual(gateway.completed["p_status"], "completed")
        self.assertNotIn("example.com", str(gateway.completed))

    def test_cloud_network_preflight_rejects_private_dns(self):
        with patch("traceatlas.cloud_worker.socket.getaddrinfo", return_value=[
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]), self.assertRaisesRegex(WorkerError, "non-public"):
            _require_public_target("url", "https://public-looking.example/path")

    def test_claim_validation_rejects_arbitrary_workflow(self):
        with self.assertRaises(WorkerError):
            CloudWorker._validate_job({"id": JOB_ID, "case_id": CASE_ID, "asset_id": ASSET_ID,
                                       "organisation_id": ORG_ID, "kind": "run_shell", "status": "running"})


if __name__ == "__main__":
    unittest.main()
