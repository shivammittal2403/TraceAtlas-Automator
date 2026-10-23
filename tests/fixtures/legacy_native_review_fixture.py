"""Generate real pinned native-review products, then replay them with a newer runtime.

Create imports TraceAtlas from commit 8a3228703747777623db876826d3d5921030ace8.
Verify imports the current source tree using the same Python interpreter.
Expected product/result bytes, hashes and replay fields are written only by
the independently hash-checked producer.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.workforce.contracts import AuthorizationContext
from traceatlas.workforce.discipline_engines import engine_identity
from traceatlas.workforce import discipline_review, discipline_runtime


BASELINE_COMMIT = "8a3228703747777623db876826d3d5921030ace8"
PINNED_RUNTIME_RAW_HASHES = {
    "01b877ff05ee8deacf5f26031233dfb518db7e0a76d57a2758b8d93ae7fff565": "LF",
    "451195bfc63583a00e9632b6e785121a2d5a973b3233edeec034d93b79d32b35": "CRLF",
}
RECEIPT_SCHEMA = "traceatlas-legacy-native-review-ci-receipt/v1"
CASE_ID = "case-pinned-native-review"
LABELS = ("HYPOTHESISINT", "FALSIFICATIONINT")
STAMP = "2024-06-01T00:00:00+00:00"
REVIEW_SCHEMA = "traceatlas-discipline-product/v2"
REPLAY_FIELDS = (
    "schema", "task_id", "case_id", "product_schema", "input_evidence_id", "input_sha256",
    "custody_verified", "source_authenticity_verified", "factual_entailment_verified",
    "requires_human_review", "status", "semantic_recomputed", "hypotheses_verified",
    "semantics_verified_scope", "callback_draft_semantics_verified",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def text_hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_hash():
    return file_hash(Path(discipline_runtime.__file__).resolve())


def reject_external(*args, **kwargs):
    raise AssertionError("Pinned native review fixture attempted external collection or model execution")


@contextmanager
def offline_only():
    with ExitStack() as stack:
        for target in ("urllib.request.urlopen", "subprocess.run",
                       "traceatlas.workforce.model_fabric.ModelRouter.generate",
                       "socket.create_connection", "socket.socket.connect", "socket.socket.connect_ex",
                       "socket.socket.sendto"):
            stack.enter_context(patch(target, side_effect=reject_external))
        yield


def payload(label):
    sources = [
        {"source_id": "S0", "uri": "urn:fixture:pinned:protocol"},
        {"source_id": "S1", "uri": "urn:fixture:pinned:first", "original_source_id": "origin-a"},
        {"source_id": "S2", "uri": "urn:fixture:pinned:copy", "original_source_id": "origin-a"},
        {"source_id": "S3", "uri": "urn:fixture:pinned:contrary", "original_source_id": "origin-b"},
    ]
    if label == "HYPOTHESISINT":
        records = [
            {"record_id": "M", "source_id": "S0", "data": {
                "hypotheses": [{"id": "primary", "statement": "First supplied synthetic explanation"},
                               {"id": "benign", "statement": "Benign supplied synthetic alternative"}],
                "evidence": [
                    {"record_id": "R1", "weight": 0.8,
                     "assessments": {"primary": "supports", "benign": "refutes"}},
                    {"record_id": "R2", "weight": 0.6,
                     "assessments": {"primary": "supports", "benign": "neutral"}},
                    {"record_id": "R3", "weight": 0.5,
                     "assessments": {"primary": "refutes", "benign": "supports"}}]}},
            {"record_id": "R1", "source_id": "S1", "data": {"observation": "First supplied assertion"}},
            {"record_id": "R2", "source_id": "S2", "data": {"observation": "Copied supplied assertion"}},
            {"record_id": "R3", "source_id": "S3", "data": {"observation": "Contrary supplied assertion"}},
        ]
    else:
        records = [
            {"record_id": "P", "source_id": "S0", "data": {
                "hypothesis_id": "supplied-temperature-bound",
                "tests": [
                    {"test_id": "necessary-bound", "field": "temperature", "operator": "lte",
                     "expected_value": 10, "record_ids": ["A", "B", "C"]},
                    {"test_id": "incomplete-existence", "field": "temperature", "operator": "eq",
                     "expected_value": 0, "record_ids": ["A"], "claim_kind": "existential",
                     "coverage_complete": False}]}},
            {"record_id": "A", "source_id": "S1", "data": {"temperature": 9}},
            {"record_id": "B", "source_id": "S2", "data": {"temperature": 12}},
            {"record_id": "C", "source_id": "S3", "data": {"unmeasured": True}},
        ]
    return {"case_id": CASE_ID, "discipline": label,
            "objective": "Review controlled synthetic native hypotheses and tests",
            "as_of": STAMP, "sources": sources, "records": records}


def quoted_identifier(value):
    return '"' + value.replace('"', '""') + '"'


def table_snapshots(db, names=None):
    if names is None:
        names = [row[0] for row in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    result = {}
    for name in names:
        rows = [dict(row) for row in db.conn.execute(
            "SELECT * FROM " + quoted_identifier(name) + " ORDER BY rowid")]
        result[name] = {"rows": len(rows), "sha256": text_hash(wire(rows))}
    return result


def file_snapshots(workspace, db):
    store = EvidenceStore(workspace, db, CASE_ID)
    require(store.verify_ledger()[0], "Pinned native custody ledger failed")
    paths = {Path(row["path"]).resolve() for row in db.evidence(CASE_ID)}
    paths.add(store.ledger.resolve())
    result = {}
    for path in sorted(paths):
        require(path.is_relative_to(workspace), "Fixture artifact escapes its workspace")
        result[path.relative_to(workspace).as_posix()] = {
            "bytes": path.stat().st_size, "sha256": file_hash(path)}
    return result


def stored_snapshot(db, runtime, task_id):
    task = runtime.store.task(task_id)
    product = runtime.store.product(task_id)
    require(task["status"] == "completed" and task["result"] is not None, "Producer task is not completed")
    stored = db.conn.execute(
        "SELECT p.product_json,p.product_digest,r.result_json,r.result_digest "
        "FROM workforce_products p JOIN workforce_results r ON r.task_id=p.task_id "
        "WHERE p.task_id=?", (task_id,)).fetchone()
    require(stored is not None, "Native product/result bytes are missing")
    require(text_hash(stored["product_json"]) == stored["product_digest"], "Stored product integrity failed")
    require(text_hash(stored["result_json"]) == stored["result_digest"], "Stored result integrity failed")
    return task, product, {
        "product_json_sha256": text_hash(stored["product_json"]),
        "product_json_bytes": len(stored["product_json"].encode("utf-8")),
        "result_json_sha256": text_hash(stored["result_json"]),
        "result_json_bytes": len(stored["result_json"].encode("utf-8")),
        "canonical_hypotheses_sha256": text_hash(wire(product["result"]["hypotheses"])),
        "native_review_sha256": text_hash(wire(product["analysis"]["hypothesis_review"])),
    }


def approved_unexecuted_snapshot(db, runtime, task_id):
    """Read exact old approval/input state without asking the runtime to execute it."""
    task = runtime.store.task(task_id)
    require(task["status"] == "approved" and task["result"] is None,
            "Pinned pending native task did not retain approved/unexecuted state")
    raw = dict(db.conn.execute(
        "SELECT * FROM workforce_tasks WHERE task_id=?", (task_id,)).fetchone())
    require(text_hash(raw["envelope_json"]) == raw["envelope_digest"],
            "Pinned pending task envelope bytes fail their digest")
    approval = db.conn.execute(
        "SELECT * FROM workforce_approvals WHERE task_id=?", (task_id,)).fetchone()
    require(approval is not None, "Pinned pending task lacks its real persisted approval")
    approval = dict(approval)
    require(approval["decision"] == "approved" and approval["envelope_digest"] == raw["envelope_digest"],
            "Pinned pending approval does not bind its exact envelope")
    data, evidence = runtime._input(task["envelope"])
    require(data["discipline"] == "HYPOTHESISINT" and evidence.case_id == CASE_ID,
            "Pinned pending task lost its supplied HYPOTHESISINT input")
    engine = discipline_runtime._bound(task["envelope"], discipline_runtime.ENGINE_PREFIX)
    review = [item[len(discipline_runtime.REVIEW_PREFIX):] for item in task["envelope"].constraints
              if item.startswith(discipline_runtime.REVIEW_PREFIX)]
    require(review == [REVIEW_SCHEMA], "Pinned pending native review approval binding is missing")
    tables = ("workforce_attempts", "workforce_request_budget", "workforce_checkpoints",
              "workforce_products", "workforce_results", "workforce_outbox")
    execution_rows = {name: db.conn.execute(
        "SELECT COUNT(*) FROM " + quoted_identifier(name) + " WHERE task_id=?", (task_id,)).fetchone()[0]
        for name in tables}
    require(not any(execution_rows.values()), "Pinned pending task acquired execution/output state")
    return {
        "task_id": task_id, "task_row": raw, "approval_row": approval,
        "envelope_json_sha256": text_hash(raw["envelope_json"]),
        "engine_binding": engine, "review_binding": review,
        "native_engine_sha256": engine_identity("HYPOTHESISINT"),
        "input_payload": data, "input_sha256": discipline_runtime.digest(data),
        "input_evidence_id": evidence.evidence_id, "input_content_hash": evidence.content_hash,
        "input_acquisition_id": evidence.acquisition_id, "execution_rows": execution_rows,
        "expected_rejection": "discipline engine changed after task approval",
    }


def assert_semantics(label, product):
    require(product["schema"] == REVIEW_SCHEMA, "Expected a genuine producer native v2 product")
    require(product["draft"]["network_calls"] == 0 and product["draft"]["model_calls"] == 0,
            "Producer dispatched external collection or model calls")
    review = product["analysis"]["hypothesis_review"]
    require(review["recomputed_from_preserved_input"] and not review["source_authenticity_verified"],
            "Native review provenance flags changed")
    if label == "HYPOTHESISINT":
        require(len(product["result"]["hypotheses"]) == 2, "Producer did not project both supplied hypotheses")
        ranking = review["native_artifacts"]["hypotheses"][0]["ranking"]
        primary = next(row for row in ranking if row["hypothesis_id"] == "primary")
        require(primary["support_weight"] == 0.8 and primary["refute_weight"] == 0.5,
                "Producer did not preserve copied-origin support and contrary evidence")
        require({row["stance"] for row in primary["assessments"]} == {"supports", "refutes"},
                "Producer stance provenance is incomplete")
    else:
        require(product["result"]["hypotheses"] == [], "Falsification invented an absent proposition")
        protocol = review["native_artifacts"]["falsification"][0]
        tests = {row["test_id"]: row for row in protocol["tests"]}
        require(tests["necessary-bound"]["state"] == "COUNTEREXAMPLE_IN_SUPPLIED_RECORDS",
                "Producer lost the supplied counterexample")
        require(tests["necessary-bound"]["unknown_record_ids"] == ["C"],
                "Producer lost missing-measurement uncertainty")
        require(tests["incomplete-existence"]["state"] == "INCONCLUSIVE" and not protocol["hypothesis_proven_true"],
                "Producer upgraded an incomplete test to proof")


def replay_fields(replay):
    require(replay["status"] == "VERIFIED_NATIVE_REVIEW" and replay["semantic_recomputed"] is True,
            "Replay did not verify the native canonical review")
    require(replay["semantics_verified_scope"] == "canonical_hypothesis_review"
            and replay["callback_draft_semantics_verified"] is False,
            "Replay silently changed its verification scope")
    return {key: replay[key] for key in REPLAY_FIELDS}


def create(workspace, receipt_path):
    producer_hash = runtime_hash()
    require(producer_hash in PINNED_RUNTIME_RAW_HASHES,
            "Producer runtime raw bytes do not match pinned commit 8a322870 (LF or CRLF)")
    require(not receipt_path.exists(), "Refuse to overwrite old-producer expectations")
    require(not workspace.exists() or not any(workspace.iterdir()), "Producer requires a fresh workspace")
    workspace.mkdir(parents=True, exist_ok=True)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    db = CaseDB(workspace / "cases.db")
    try:
        db.create_case(CASE_ID, "Pinned native replay fixture", "Controlled supplied-record compatibility regression")
        runtime = discipline_runtime.create_runtime(db, workspace, enabled=True)
        now = datetime.now(timezone.utc)
        authority = AuthorizationContext(
            "1.0", "auth-pinned-native-review", CASE_ID, "analyst-pinned-native",
            "Review controlled synthetic native hypotheses", ("provided_records:" + CASE_ID,),
            ("propose_observation",), ("discipline.analyze",), "IN", "fixture-only",
            (now - timedelta(seconds=10)).isoformat(), (now + timedelta(hours=1)).isoformat(), "a" * 64)
        runtime.service.register_authorization(authority)
        tasks = {}
        with offline_only():
            for label in LABELS:
                planned = runtime.plan(authority.context_id, label, payload(label))
                task_id = planned["task"]["task_id"]
                runtime.service.approve(
                    task_id, actor_id=authority.actor_id,
                    rationale="Approve exact pinned synthetic native review records",
                    envelope_digest=planned["envelope_digest"], authorized=True)
                runtime.run(task_id, authorized=True)
                task, product, snapshot = stored_snapshot(db, runtime, task_id)
                assert_semantics(label, product)
                bindings = [value[len(discipline_runtime.REVIEW_PREFIX):]
                            for value in task["envelope"].constraints
                            if value.startswith(discipline_runtime.REVIEW_PREFIX)]
                require(bindings == [REVIEW_SCHEMA], "Producer did not bind native review semantics at approval")
                engine_binding = next(value[len(discipline_runtime.ENGINE_PREFIX):]
                                      for value in task["envelope"].constraints
                                      if value.startswith(discipline_runtime.ENGINE_PREFIX))
                require(engine_binding == discipline_runtime._identity(label), "Producer source binding is inconsistent")
                tasks[label] = {
                    "task_id": task_id, "review_binding": bindings, "engine_binding": engine_binding,
                    "native_engine_sha256": engine_identity(label),
                    "envelope_digest": task["envelope_digest"],
                    "expected_replay": replay_fields(runtime.replay(task_id)), **snapshot}
            pending_payload = payload("HYPOTHESISINT")
            pending_payload["objective"] = "Leave this genuine old-approved native task unexecuted"
            planned = runtime.plan(authority.context_id, "HYPOTHESISINT", pending_payload)
            pending_id = planned["task"]["task_id"]
            runtime.service.approve(
                pending_id, actor_id=authority.actor_id,
                rationale="Approve exact old native input but retain it unexecuted for the version gate",
                envelope_digest=planned["envelope_digest"], authorized=True)
            pending = approved_unexecuted_snapshot(db, runtime, pending_id)
            require(pending["engine_binding"] == discipline_runtime._identity("HYPOTHESISINT"),
                    "Producer pending task did not bind its genuine old runtime engine")
        receipt = {
            "schema": RECEIPT_SCHEMA, "baseline_commit": BASELINE_COMMIT, "case_id": CASE_ID,
            "producer_runtime_raw_sha256": producer_hash,
            "producer_newline_variant": PINNED_RUNTIME_RAW_HASHES[producer_hash],
            "producer_review_raw_sha256": file_hash(Path(discipline_review.__file__).resolve()),
            "producer_python_version": list(sys.version_info[:3]),
            "producer_python_implementation": sys.implementation.name,
            "producer_python_executable": str(Path(sys.executable).resolve()),
            "tasks": tasks, "approved_unexecuted": pending, "legacy_tables": table_snapshots(db),
            "preserved_files": file_snapshots(workspace, db),
        }
        with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(receipt, handle, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
        print(json.dumps({"mode": "create", "verified": True, "producer_runtime_raw_sha256": producer_hash,
                          "native_review_products": len(tasks), "approved_unexecuted_tasks": 1}))
    finally:
        db.close()


def verify(workspace, receipt_path):
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    require(receipt["schema"] == RECEIPT_SCHEMA and receipt["baseline_commit"] == BASELINE_COMMIT,
            "Unexpected native old-producer receipt")
    require(receipt["producer_runtime_raw_sha256"] in PINNED_RUNTIME_RAW_HASHES,
            "Receipt does not identify a pinned native producer runtime")
    require(runtime_hash() not in PINNED_RUNTIME_RAW_HASHES, "Verifier imported the old producer instead of a new runtime")
    require(receipt["producer_python_version"] == list(sys.version_info[:3])
            and receipt["producer_python_implementation"] == sys.implementation.name
            and Path(receipt["producer_python_executable"]).resolve() == Path(sys.executable).resolve(),
            "Native engine identity requires the same interpreter and Python patch version")
    require(file_hash(Path(discipline_review.__file__).resolve()) == receipt["producer_review_raw_sha256"],
            "Native review helper changed; this fixture cannot claim identical semantic replay")
    require(set(receipt["tasks"]) == set(LABELS), "Receipt is missing native review cases")
    require(isinstance(receipt.get("approved_unexecuted"), dict),
            "Receipt lacks the genuine old-approved unexecuted native task")
    require((workspace / "cases.db").is_file(), "Old producer database is missing")
    db = CaseDB(workspace / "cases.db")
    try:
        runtime = discipline_runtime.create_runtime(db, workspace, enabled=True)
        require(table_snapshots(db, receipt["legacy_tables"]) == receipt["legacy_tables"],
                "Old producer table rows changed before replay")
        require(file_snapshots(workspace, db) == receipt["preserved_files"], "Old producer preserved bytes changed")
        changes_before = db.conn.total_changes
        with offline_only():
            pending = receipt["approved_unexecuted"]
            pending_id = pending["task_id"]
            require(approved_unexecuted_snapshot(db, runtime, pending_id) == pending,
                    "Old-approved task/envelope/approval/input state changed before dispatch")
            require(discipline_runtime._identity("HYPOTHESISINT") != pending["engine_binding"],
                    "Current runtime unexpectedly retained the old pending task engine identity")
            for label in LABELS:
                expected = receipt["tasks"][label]
                task_id = expected["task_id"]
                task, product, snapshot = stored_snapshot(db, runtime, task_id)
                require(task["envelope"].case_id == CASE_ID and task["envelope_digest"] == expected["envelope_digest"],
                        "Old approved native task changed")
                bindings = [value[len(discipline_runtime.REVIEW_PREFIX):]
                            for value in task["envelope"].constraints
                            if value.startswith(discipline_runtime.REVIEW_PREFIX)]
                require(bindings == expected["review_binding"] == [REVIEW_SCHEMA], "Native review approval binding changed")
                engine_bindings = [value[len(discipline_runtime.ENGINE_PREFIX):]
                                   for value in task["envelope"].constraints
                                   if value.startswith(discipline_runtime.ENGINE_PREFIX)]
                require(engine_bindings == [expected["engine_binding"]], "Old producer engine binding changed")
                require(engine_identity(label) == expected["native_engine_sha256"], "Native processor identity changed")
                require(snapshot == {key: expected[key] for key in snapshot}, "Old product/result bytes or review projection changed")
                assert_semantics(label, product)
                require(runtime.run(task_id, authorized=True) == product, "Completed run did not retain its old product")
                replay = runtime.replay(task_id)
                require(replay_fields(replay) == expected["expected_replay"], "Current replay differs from old canonical expectations")
                _, _, after = stored_snapshot(db, runtime, task_id)
                require(after == snapshot, "Current replay rewrote old product/result bytes")
            before_rejection = table_snapshots(db, receipt["legacy_tables"])
            before_files = file_snapshots(workspace, db)
            try:
                runtime.run(pending_id, authorized=True)
            except ValueError as error:
                require(str(error) == pending["expected_rejection"],
                        "Old pending native task was rejected for a different reason")
            else:
                raise ValueError("Current runtime dispatched a genuine old-approved pending task")
            require(approved_unexecuted_snapshot(db, runtime, pending_id) == pending,
                    "Engine rejection changed approved task/input state or created execution/output rows")
            require(table_snapshots(db, receipt["legacy_tables"]) == before_rejection,
                    "Engine rejection mutated an old producer database row")
            require(file_snapshots(workspace, db) == before_files,
                    "Engine rejection changed preserved artifacts or custody bytes")
        require(db.conn.total_changes == changes_before, "Read-only native replay performed a database write")
        require(table_snapshots(db, receipt["legacy_tables"]) == receipt["legacy_tables"],
                "Current replay changed old-producer table rows")
        require(file_snapshots(workspace, db) == receipt["preserved_files"], "Current replay changed preserved artifact or ledger bytes")
        print(json.dumps({"mode": "verify", "verified": True, "native_review_products": len(LABELS),
                          "semantics_verified_scope": "canonical_hypothesis_review",
                          "old_product_result_bytes_preserved": True,
                          "old_approved_task_rejected_before_dispatch": True}))
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    {"create": create, "verify": verify}[args.mode](args.workspace.resolve(), args.receipt.resolve())


if __name__ == "__main__":
    main()
