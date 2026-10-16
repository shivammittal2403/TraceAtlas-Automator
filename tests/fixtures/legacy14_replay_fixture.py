"""Generate a real pinned 1.4.0 case, then verify it in a separate new-runtime process.

The producer must import TraceAtlas from commit b8fe5e3d94ab797c9fac3630447def09c1f74503.
The verifier must import the current source tree. Expected report bytes and hashes
are written only by the producer, never by the current report renderer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.documents import DOCUMENT_SCHEMA, SourceDocument, StructuredFact
from traceatlas.workforce.pipeline import InvestigationPipeline, WORKFLOW_VERSION, digest
from traceatlas.workforce.service import WorkforceService


BASELINE_COMMIT = "b8fe5e3d94ab797c9fac3630447def09c1f74503"
LEGACY_VERSION = "evidence-investigation/1.4.0"
CURRENT_VERSION = "evidence-investigation/1.5.0"
RECEIPT_SCHEMA = "traceatlas-legacy14-ci-receipt/v1"
STAMP = "2024-06-01T00:00:00+00:00"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def reject_external(*args, **kwargs):
    raise AssertionError("Legacy replay fixture must not dispatch network or model calls")


def report_path(receipt_path):
    return receipt_path.with_suffix(receipt_path.suffix + ".report.md")


def documents():
    rows = []
    for source, country, context in (
        ("registry-a", "IN", "Primary administrative registry allocation and jurisdiction filing"),
        ("gazette-b", "GB", "Separate overseas gazette conflicting public administrative assertion"),
    ):
        fact = StructuredFact("domain:example.org", "registered_country", country, STAMP, None)
        content = json.dumps({
            "schema": "traceatlas-structured-source/v1",
            "facts": [fact.to_dict()],
            "source_context": context,
        }, sort_keys=True, ensure_ascii=False)
        rows.append(SourceDocument(
            DOCUMENT_SCHEMA, source, "https://" + source + ".example/record",
            STAMP, content, (fact,), None, None,
        ))
    return tuple(rows)


def create(workspace, receipt_path):
    require(WORKFLOW_VERSION == LEGACY_VERSION, "Producer did not import the pinned legacy runtime")
    expected_report = report_path(receipt_path)
    require(not receipt_path.exists() and not expected_report.exists(), "Refuse to overwrite legacy expectations")
    require(not workspace.exists() or not any(workspace.iterdir()), "Producer requires a fresh case workspace")
    workspace.mkdir(parents=True, exist_ok=True)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    db = CaseDB(workspace / "cases.db")
    try:
        db.create_case("case-legacy14", "Pinned legacy replay fixture", "Controlled synthetic supplied records")
        service = WorkforceService(db, enabled=True)
        stamp = datetime.now(timezone.utc)
        authority = AuthorizationContext(
            "1.0", "auth-legacy14", "case-legacy14", "analyst-legacy14",
            "Controlled synthetic supplied registration assertions", ("domain:example.org",),
            ("request_collection", "propose_observation", "propose_claim"),
            ("evidence.retrieve",), "IN", "fixture-only",
            (stamp - timedelta(seconds=10)).isoformat(),
            (stamp + timedelta(hours=1)).isoformat(), "a" * 64,
        )
        service.register_authorization(authority)
        planned = service.create_investigation_task(
            authority.context_id, "domain", "example.org",
            "Review the conflicting supplied registration-country assertions",
        )
        task_id = planned["task"]["task_id"]
        require(not any(row.startswith("workflow-version:") for row in planned["task"]["constraints"]),
                "Baseline unexpectedly bound a new workflow version")
        service.approve(
            task_id, actor_id=authority.actor_id,
            rationale="Approve only the exact synthetic supplied records",
            envelope_digest=planned["envelope_digest"], authorized=True,
        )
        pipeline = InvestigationPipeline(
            service, workspace, requester=reject_external, search_requester=reject_external,
        )
        with patch("traceatlas.workforce.model_fabric.ModelRouter.generate", side_effect=reject_external):
            product = pipeline.run(task_id, documents=documents(), authorized=True)
            replay = pipeline.replay(task_id)
        analysis = product["analysis"]
        require(product["replay_manifest"]["workflow_version"] == LEGACY_VERSION, "Wrong legacy manifest version")
        require(replay["verified"], "Pinned producer failed its own offline replay")
        require(len(analysis["claims"]) == 2 and len(analysis["contradictions"]) == 2,
                "Fixture failed to capture two contradictory assertions")
        require(all(row["status"] == "DISPUTED" for row in analysis["verification"]), "Fixture assertions were not disputed")
        require("hypothesis_review" not in analysis and product["result"]["hypotheses"] == [],
                "Producer did not retain genuine legacy hypothesis semantics")
        require(product["network_attempts"] == 0, "Fixture unexpectedly dispatched collection")
        report_bytes = product["report_markdown"].encode("utf-8")
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "baseline_commit": BASELINE_COMMIT,
            "case_id": "case-legacy14",
            "task_id": task_id,
            "workflow_version": LEGACY_VERSION,
            "analysis_digest": product["replay_manifest"]["analysis_digest"],
            "product_digest": digest(product),
            "result_digest": digest(product["result"]),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        }
        with expected_report.open("xb") as handle:
            handle.write(report_bytes)
        with receipt_path.open("x", encoding="utf-8") as handle:
            json.dump(receipt, handle, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
        print(json.dumps({"mode": "create", "workflow_version": LEGACY_VERSION, "verified": True}))
    finally:
        db.close()


def verify(workspace, receipt_path):
    require(WORKFLOW_VERSION == CURRENT_VERSION, "Verifier did not import the current runtime")
    require((workspace / "cases.db").is_file(), "Legacy producer case database is missing")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    require(receipt["schema"] == RECEIPT_SCHEMA and receipt["baseline_commit"] == BASELINE_COMMIT,
            "Unexpected legacy expectation receipt")
    require(receipt["workflow_version"] == LEGACY_VERSION, "Unexpected legacy receipt workflow")
    expected_report = report_path(receipt_path).read_bytes()
    require(hashlib.sha256(expected_report).hexdigest() == receipt["report_sha256"], "Legacy report expectation was changed")
    db = CaseDB(workspace / "cases.db")
    try:
        service = WorkforceService(db, enabled=True)
        task_id = receipt["task_id"]
        task = service.store.task(task_id)
        require(task["envelope"].case_id == receipt["case_id"], "Legacy case binding changed")
        require(not any(row.startswith("workflow-version:") for row in task["envelope"].constraints),
                "Legacy task approval was rewritten with new semantics")
        product = service.store.product(task_id)
        require(digest(product) == receipt["product_digest"], "Stored legacy product changed")
        require(digest(task["result"].to_dict()) == receipt["result_digest"], "Stored legacy result changed")
        require(product["report_markdown"].encode("utf-8") == expected_report, "Stored legacy report bytes changed")
        require("hypothesis_review" not in product["analysis"] and task["result"].hypotheses == (),
                "New hypothesis semantics were added to the legacy product")
        pipeline = InvestigationPipeline(
            service, workspace, requester=reject_external, search_requester=reject_external,
        )
        with patch("traceatlas.workforce.model_fabric.ModelRouter.generate", side_effect=reject_external):
            replay = pipeline.replay(task_id)
        require(replay["verified"] and replay["requires_network"] is False, "Current runtime rejected offline legacy replay")
        require(replay["analysis_digest"] == receipt["analysis_digest"], "Legacy analysis digest changed")
        require(replay["analysis"] == product["analysis"], "Recomputed legacy analysis changed")
        require(digest(service.store.product(task_id)) == receipt["product_digest"], "Replay rewrote the legacy product")
        print(json.dumps({"mode": "verify", "workflow_version": LEGACY_VERSION, "verified": True}))
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    receipt = args.receipt.resolve()
    {"create": create, "verify": verify}[args.mode](workspace, receipt)


if __name__ == "__main__":
    main()
