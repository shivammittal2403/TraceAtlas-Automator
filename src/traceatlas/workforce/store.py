"""Append-only local persistence and Evidence Fabric v2 compatibility adapter."""
from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..evidence import sha256_file
from ..employee.brief import digest
from .contracts import (
    AuthorizationContext, EvidenceObject, Observation, ResultEnvelope, SourceLineage,
    TaskEnvelope, VerificationDecision,
)
from .runtime import ExecutionRuntime, SCHEMA as RUNTIME_SCHEMA


SCHEMA = """
CREATE TABLE IF NOT EXISTS workforce_authorizations (
  context_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  context_json TEXT NOT NULL, policy_digest TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workforce_tasks (
  task_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  employee_id TEXT NOT NULL, envelope_json TEXT NOT NULL, envelope_digest TEXT NOT NULL,
  definition_digest TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT NOT NULL, approved_at TEXT, completed_at TEXT
);
CREATE TABLE IF NOT EXISTS workforce_approvals (
  approval_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL, decision TEXT NOT NULL, rationale TEXT NOT NULL,
  envelope_digest TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(task_id)
);
CREATE TABLE IF NOT EXISTS workforce_results (
  task_id TEXT PRIMARY KEY REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
  result_json TEXT NOT NULL, result_digest TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS acquisitions_v2 (
  acquisition_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  source_id TEXT NOT NULL, method TEXT NOT NULL, retrieved_at TEXT NOT NULL,
  trace_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_objects_v2 (
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL, version INTEGER NOT NULL, content_hash TEXT NOT NULL,
  object_json TEXT NOT NULL, object_digest TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(case_id,evidence_id,version), UNIQUE(case_id,object_digest)
);
CREATE TABLE IF NOT EXISTS observations_v2 (
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  observation_id TEXT NOT NULL, evidence_id TEXT NOT NULL, observation_json TEXT NOT NULL,
  created_at TEXT NOT NULL, PRIMARY KEY(case_id,observation_id)
);
CREATE TABLE IF NOT EXISTS source_lineage_v2 (
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  lineage_id TEXT NOT NULL, lineage_json TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(case_id,lineage_id)
);
CREATE TABLE IF NOT EXISTS verification_decisions_v2 (
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  claim_id TEXT NOT NULL, decision_json TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(case_id,claim_id)
);
CREATE INDEX IF NOT EXISTS workforce_tasks_case_idx ON workforce_tasks(case_id,created_at);
CREATE INDEX IF NOT EXISTS evidence_objects_v2_hash_idx ON evidence_objects_v2(case_id,content_hash);
CREATE INDEX IF NOT EXISTS observations_v2_evidence_idx ON observations_v2(case_id,evidence_id);
CREATE TABLE IF NOT EXISTS workforce_products (
  task_id TEXT PRIMARY KEY REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
  product_json TEXT NOT NULL, product_digest TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class WorkforceStore:
    def __init__(self, db):
        self.db = db
        self.db.conn.executescript(SCHEMA)
        self.db.conn.executescript(RUNTIME_SCHEMA)
        self.db.conn.commit()
        self.runtime = ExecutionRuntime(self.db.path)

    def register_authorization(self, context: AuthorizationContext) -> None:
        if not self.db.get_case(context.case_id):
            raise ValueError("authorization references an unknown case")
        encoded = _json(context.to_dict())
        existing = self.db.conn.execute(
            "SELECT context_json FROM workforce_authorizations WHERE context_id=?", (context.context_id,)
        ).fetchone()
        if existing and existing["context_json"] != encoded:
            raise ValueError("authorization context is immutable")
        self.db.conn.execute(
            "INSERT OR IGNORE INTO workforce_authorizations VALUES(?,?,?,?,?)",
            (context.context_id, context.case_id, encoded, context.policy_digest, _now()),
        )
        self.db.conn.commit()

    def authorization(self, context_id: str) -> AuthorizationContext:
        row = self.db.conn.execute(
            "SELECT context_json FROM workforce_authorizations WHERE context_id=?", (context_id,)
        ).fetchone()
        if not row:
            raise ValueError("authorization context is not registered server-side")
        return AuthorizationContext.from_dict(json.loads(row["context_json"]))

    def create_task(self, task: TaskEnvelope, employee_id: str, definition_digest: str) -> str:
        encoded = _json(task.to_dict())
        envelope_digest = hashlib.sha256(encoded.encode()).hexdigest()
        try:
            self.db.conn.execute(
                "INSERT INTO workforce_tasks VALUES(?,?,?,?,?,?,?,?,?,?)",
                (task.task_id, task.case_id, employee_id, encoded, envelope_digest, definition_digest,
                 "planned", task.created_at, None, None),
            )
            self.db.conn.commit()
        except Exception:
            self.db.conn.rollback()
            row = self.db.conn.execute("SELECT envelope_digest FROM workforce_tasks WHERE task_id=?", (task.task_id,)).fetchone()
            if not row or row["envelope_digest"] != envelope_digest:
                raise ValueError("task ID replay conflicts with existing task")
        return envelope_digest

    def task(self, task_id: str) -> dict[str, Any]:
        row = self.db.conn.execute("SELECT * FROM workforce_tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            raise ValueError("unknown workforce task")
        result = dict(row)
        result["envelope"] = TaskEnvelope.from_dict(json.loads(result.pop("envelope_json")))
        if digest(result["envelope"].to_dict()) != result["envelope_digest"]:
            raise ValueError("stored task digest mismatch")
        stored = self.db.conn.execute("SELECT result_json,result_digest FROM workforce_results WHERE task_id=?", (task_id,)).fetchone()
        if stored and hashlib.sha256(stored["result_json"].encode()).hexdigest() != stored["result_digest"]:
            raise ValueError("stored result digest mismatch")
        result["result"] = ResultEnvelope.from_dict(json.loads(stored["result_json"])) if stored else None
        return result

    def approve(self, task_id: str, actor_id: str, rationale: str, envelope_digest: str, approval_id: str) -> None:
        task = self.task(task_id)
        if task["envelope_digest"] != envelope_digest:
            raise ValueError("approval digest does not match the immutable task")
        if not 10 <= len(rationale.strip()) <= 2000:
            raise ValueError("approval rationale must be 10-2000 characters")
        existing = self.db.conn.execute("SELECT * FROM workforce_approvals WHERE task_id=?", (task_id,)).fetchone()
        if existing:
            if existing["actor_id"] == actor_id and existing["rationale"] == rationale.strip() and existing["envelope_digest"] == envelope_digest:
                return
            raise ValueError("approval conflicts with an existing decision")
        with self.db.conn:
            changed = self.db.conn.execute(
                "UPDATE workforce_tasks SET status='approved',approved_at=? WHERE task_id=? AND status='planned'",
                (_now(), task_id),
            )
            if changed.rowcount != 1:
                raise ValueError("task is not pending approval")
            self.db.conn.execute(
                "INSERT INTO workforce_approvals VALUES(?,?,?,?,?,?,?)",
                (approval_id, task_id, actor_id, "approved", rationale.strip(), envelope_digest, _now()),
            )

    def claim(self, task_id: str) -> str:
        return self.runtime.claim(task_id)

    def finish(self, task_id: str, result: ResultEnvelope, *, token: str, product: dict | None = None) -> None:
        encoded = _json(result.to_dict())
        with self.db.conn:
            self.db.conn.execute('BEGIN IMMEDIATE')
            current = self.task(task_id)
            if result.task_id != task_id or result.employee_id != current['employee_id']:
                raise ValueError('result does not belong to task')
            winner = self.db.conn.execute('SELECT token FROM workforce_attempts WHERE task_id=?', (task_id,)).fetchone()
            if current['status'] == 'completed':
                existing = self.db.conn.execute('SELECT product_json FROM workforce_products WHERE task_id=?', (task_id,)).fetchone()
                if (not winner or winner[0] != token or current['result'] != result
                        or (existing[0] if existing else None) != (_json(product) if product is not None else None)):
                    raise ValueError('conflicting duplicate completion')
                return
            self.runtime.assert_current(self.db.conn, task_id, token)
            if product is not None:
                if product.get('task_id') != task_id or product.get('case_id') != current['case_id']:
                    raise ValueError('product does not belong to task and case')
                self.db.conn.execute("INSERT INTO workforce_products VALUES(?,?,?,?)",
                    (task_id, _json(product), hashlib.sha256(_json(product).encode()).hexdigest(), _now()))
                for entry in product['analysis']['observations']:
                    observation = Observation.from_dict(entry)
                    reference = self.db.conn.execute('SELECT object_json FROM evidence_objects_v2 '
                        'WHERE case_id=? AND evidence_id=? ORDER BY version DESC LIMIT 1',
                        (current['case_id'], observation.evidence_id)).fetchone()
                    if not reference or json.loads(reference[0])['acquisition_id'] != observation.acquisition_id:
                        raise ValueError('observation references unknown evidence')
                    old = self.db.conn.execute('SELECT observation_json FROM observations_v2 WHERE case_id=? AND observation_id=?',
                                              (current['case_id'], observation.observation_id)).fetchone()
                    if old and old[0] != _json(entry):
                        raise ValueError('observation ID conflicts with existing evidence')
                    self.db.conn.execute('INSERT OR IGNORE INTO observations_v2 VALUES(?,?,?,?,?)',
                        (current['case_id'], observation.observation_id, observation.evidence_id, _json(entry), _now()))
                for entry in product['analysis']['source_lineage']:
                    lineage = SourceLineage.from_dict(entry)
                    self.db.conn.execute('INSERT OR REPLACE INTO source_lineage_v2 VALUES(?,?,?,?)',
                        (current['case_id'], lineage.lineage_id, _json(entry), _now()))
                for entry in product['analysis']['verification']:
                    decision = VerificationDecision.from_dict({**entry, 'decided_at': _now()})
                    self.db.conn.execute('INSERT OR REPLACE INTO verification_decisions_v2 VALUES(?,?,?,?)',
                        (current['case_id'], decision.claim_id, _json(decision.to_dict()), _now()))
            self.db.conn.execute(
                "INSERT INTO workforce_results VALUES(?,?,?,?)",
                (task_id, encoded, hashlib.sha256(encoded.encode()).hexdigest(), _now()),
            )
            changed = self.db.conn.execute(
                "UPDATE workforce_tasks SET status='completed',completed_at=? WHERE task_id=? AND status='running'",
                (_now(), task_id),
            )
            if changed.rowcount != 1:
                raise ValueError("task no longer owns the running completion state")
            self.db.conn.execute("UPDATE workforce_request_budget SET state='uncertain' WHERE task_id=? AND state='reserved'", (task_id,))
            self.db.conn.execute('INSERT INTO workforce_outbox VALUES(?,?,?,?,?,NULL)',
                ('completed-' + task_id, task_id, 'task.completed',
                 _json({'task_id': task_id, 'case_id': current['case_id'],
                        'result_digest': hashlib.sha256(encoded.encode()).hexdigest()}), self.runtime.clock()))

    def fail(self, task_id: str, *, token: str) -> None:
        self.runtime.stop(task_id, token=token)

    def captured_document(self, task, source_id):
        """Resume immutable task captures without another provider request."""
        from .documents import SourceDocument
        acquisition_id = 'acquisition-' + hashlib.sha256((task.task_id + source_id).encode()).hexdigest()[:24]
        row = self.db.conn.execute('SELECT e.object_json FROM evidence_objects_v2 e JOIN acquisitions_v2 a '
            "ON json_extract(e.object_json,'$.acquisition_id')=a.acquisition_id "
            'WHERE e.case_id=? AND a.acquisition_id=? ORDER BY e.version DESC LIMIT 1',
            (task.case_id, acquisition_id)).fetchone()
        if not row:
            return None
        evidence = EvidenceObject.from_dict(json.loads(row[0]))
        if not self.verify_evidence(evidence):
            raise ValueError('captured checkpoint evidence failed integrity validation')
        body = json.loads(Path(evidence.raw_artifact_pointer).read_text(encoding='utf-8'))
        if body['task_id'] != task.task_id or body['case_id'] != task.case_id:
            raise ValueError('captured checkpoint belongs to another task')
        document = SourceDocument.from_dict(body['document'])
        if document.source_id != source_id or any(f.subject not in task.target_entities for f in document.facts):
            raise ValueError('captured checkpoint scope mismatch')
        return document, evidence

    def import_v1_evidence(self, case_id: str, sha256: str, *, source_uri: str | None = None,
                           parser: str = "legacy", parser_version: str = "1",
                           extractor: str = "legacy", extractor_version: str = "1") -> EvidenceObject:
        row = next((item for item in self.db.evidence(case_id) if item["sha256"] == sha256), None)
        if not row:
            raise ValueError("v1 evidence does not exist in this case")
        path = Path(row["path"])
        if not path.is_file() or sha256_file(path) != sha256:
            raise ValueError("v1 evidence bytes fail integrity validation")
        created = _now()
        source_id = "source-" + hashlib.sha256(row["source"].encode()).hexdigest()[:16]
        acquisition_id = "acquisition-" + hashlib.sha256((case_id + sha256 + row["captured_at"]).encode()).hexdigest()[:20]
        evidence_id = "evidence-" + sha256[:24]
        self.db.conn.execute(
            "INSERT OR IGNORE INTO acquisitions_v2 VALUES(?,?,?,?,?,?,?)",
            (acquisition_id, case_id, source_id, "v1-compatibility-import", row["captured_at"], "trace-legacy", created),
        )
        item = EvidenceObject(
            schema_version="1.0", evidence_id=evidence_id, version=1, prior_version_id=None,
            case_id=case_id, source_id=source_id, source_uri=source_uri or "urn:traceatlas:legacy:" + source_id,
            acquisition_id=acquisition_id, acquisition_method="v1-compatibility-import",
            retrieved_at=row["captured_at"], content_hash=sha256, mime_type=row.get("media_type") or "application/octet-stream",
            raw_artifact_pointer=str(path), parser=parser, parser_version=parser_version,
            extractor=extractor, extractor_version=extractor_version, observation_ids=(),
            chain_of_custody=("legacy-preserve", "v2-import"), access_policy="case-members",
            retention_policy="inherit-case-policy", classification="unclassified", created_at=created,
        )
        encoded = _json(item.to_dict())
        self.db.conn.execute(
            "INSERT OR IGNORE INTO evidence_objects_v2 VALUES(?,?,?,?,?,?,?)",
            (case_id, evidence_id, 1, sha256, encoded, hashlib.sha256(encoded.encode()).hexdigest(), created),
        )
        self.db.conn.commit()
        return item

    def append_evidence_version(self, previous: EvidenceObject, *, parser: str, parser_version: str,
                                extractor: str, extractor_version: str, observation_ids: tuple[str, ...]) -> EvidenceObject:
        if not self.verify_evidence(previous):
            raise ValueError("previous evidence version failed integrity validation")
        created = _now()
        item = EvidenceObject(
            **{**previous.to_dict(), "version": previous.version + 1,
               "prior_version_id": f"{previous.evidence_id}-v{previous.version}",
               "parser": parser, "parser_version": parser_version, "extractor": extractor,
               "extractor_version": extractor_version, "observation_ids": list(observation_ids),
               "chain_of_custody": [*previous.chain_of_custody, "metadata-version"], "created_at": created}
        )
        encoded = _json(item.to_dict())
        self.db.conn.execute(
            "INSERT INTO evidence_objects_v2 VALUES(?,?,?,?,?,?,?)",
            (item.case_id, item.evidence_id, item.version, item.content_hash, encoded,
             hashlib.sha256(encoded.encode()).hexdigest(), created),
        )
        self.db.conn.commit()
        return item

    def verify_evidence(self, item: EvidenceObject) -> bool:
        try:
            path = Path(item.raw_artifact_pointer)
            stored = self.db.conn.execute(
                "SELECT object_json,object_digest FROM evidence_objects_v2 WHERE case_id=? AND evidence_id=? AND version=?",
                (item.case_id, item.evidence_id, item.version),
            ).fetchone()
            return bool(stored and _json(item.to_dict()) == stored["object_json"]
                        and hashlib.sha256(stored["object_json"].encode()).hexdigest() == stored["object_digest"]) and path.is_file() and not path.is_symlink() and sha256_file(path) == item.content_hash and any(
                row["sha256"] == item.content_hash and Path(row["path"]).resolve() == path.resolve()
                for row in self.db.evidence(item.case_id)
            )
        except OSError:
            return False

    def record_observation(self, case_id: str, observation: Observation) -> None:
        row = self.db.conn.execute(
            "SELECT object_json FROM evidence_objects_v2 WHERE case_id=? AND evidence_id=? ORDER BY version DESC LIMIT 1",
            (case_id, observation.evidence_id),
        ).fetchone()
        if not row or json.loads(row["object_json"])["acquisition_id"] != observation.acquisition_id:
            raise ValueError("observation references unknown evidence")
        self.db.conn.execute(
            "INSERT INTO observations_v2 VALUES(?,?,?,?,?)",
            (case_id, observation.observation_id, observation.evidence_id, _json(observation.to_dict()), _now()),
        )
        self.db.conn.commit()

    def capture_document(self, task: TaskEnvelope, document, workspace: Path) -> EvidenceObject:
        from ..evidence import EvidenceStore
        prior = self.captured_document(task, document.source_id)
        if prior:
            if prior[0] != document:
                raise ValueError('source capture is immutable within a task')
            return prior[1]
        acquisition_id = "acquisition-" + hashlib.sha256((task.task_id + document.source_id).encode()).hexdigest()[:24]
        body = {"task_id": task.task_id, "case_id": task.case_id, "trace_id": task.trace_id,
                "acquisition_id": acquisition_id, "document": document.to_dict()}
        with tempfile.TemporaryDirectory(prefix="traceatlas-source-") as temp:
            path = Path(temp) / "source-document.json"
            path.write_text(_json(body), encoding="utf-8")
            preserved = EvidenceStore(workspace, self.db, task.case_id).preserve_file(path, "workforce:" + document.source_id)
        item = EvidenceObject(
            schema_version="1.0", evidence_id="evidence-" + preserved["sha256"][:24], version=1,
            prior_version_id=None, case_id=task.case_id, source_id=document.source_id,
            source_uri=document.source_uri, acquisition_id=acquisition_id,
            acquisition_method="source-document-capture", retrieved_at=document.retrieved_at,
            content_hash=preserved["sha256"], mime_type="application/json",
            raw_artifact_pointer=preserved["path"], parser="source-document", parser_version="1",
            extractor="structured-fact", extractor_version="1", observation_ids=(),
            chain_of_custody=("source-capture", "sha256-preserve"), access_policy="case-members",
            retention_policy=self.authorization(task.authorization_context_id).retention_policy,
            classification="untrusted-source", created_at=_now(),
        )
        with self.db.conn:
            self.db.conn.execute("INSERT INTO acquisitions_v2 VALUES(?,?,?,?,?,?,?)",
                (acquisition_id, task.case_id, document.source_id, item.acquisition_method,
                 item.retrieved_at, task.trace_id, item.created_at))
            encoded = _json(item.to_dict())
            self.db.conn.execute("INSERT INTO evidence_objects_v2 VALUES(?,?,?,?,?,?,?)",
                (task.case_id, item.evidence_id, 1, item.content_hash, encoded,
                 hashlib.sha256(encoded.encode()).hexdigest(), item.created_at))
        return item

    def save_product(self, task_id: str, value: dict) -> None:
        encoded = _json(value)
        with self.db.conn:
            self.db.conn.execute("INSERT INTO workforce_products VALUES(?,?,?,?)",
                (task_id, encoded, hashlib.sha256(encoded.encode()).hexdigest(), _now()))

    def product(self, task_id: str) -> dict:
        self.task(task_id)
        row = self.db.conn.execute("SELECT product_json,product_digest FROM workforce_products WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            raise ValueError("task has no investigation product")
        if hashlib.sha256(row["product_json"].encode()).hexdigest() != row["product_digest"]:
            raise ValueError("stored investigation product digest mismatch")
        return json.loads(row["product_json"])

    def record_lineage(self, case_id: str, item: SourceLineage) -> None:
        self.db.conn.execute(
            "INSERT OR REPLACE INTO source_lineage_v2 VALUES(?,?,?,?)",
            (case_id, item.lineage_id, _json(item.to_dict()), _now()),
        )
        self.db.conn.commit()

    def record_verification(self, case_id: str, item: VerificationDecision) -> None:
        self.db.conn.execute(
            "INSERT OR REPLACE INTO verification_decisions_v2 VALUES(?,?,?,?)",
            (case_id, item.claim_id, _json(item.to_dict()), _now()),
        )
        self.db.conn.commit()
