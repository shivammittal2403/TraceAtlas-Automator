"""Opt-in discipline employees on the canonical approved workforce lifecycle."""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .contracts import (Budget, CostRecord, Observation, ResultEnvelope,
                        SemanticClass, TaskEnvelope, TraceSpan)
from .discipline_engines.common import make_context
from .discipline_review import project_discipline_review, REVIEWED_DISCIPLINES, REVIEWED_PRODUCT_SCHEMA
from .documents import DOCUMENT_SCHEMA, MAX_DOCUMENT_BYTES, SourceDocument
from .intelligence import validate_case_input
from .registry import EmployeeRegistry, INITIAL_EMPLOYEES
from .service import WorkforceService, _digest as definition_digest
from .tools import ToolContract, ToolFacade

INPUT_PREFIX = "discipline-input-sha256:"
SOURCE_PREFIX = "discipline-input-source:"
LABEL_PREFIX = "discipline-label:"
ENGINE_PREFIX = "discipline-engine-sha256:"
REVIEW_PREFIX = "discipline-review-version:"
MAX_OUTPUT_BYTES = 2 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _identity(label):
    if label != "MANAGER":
        from .discipline_engines import engine_identity
        from . import discipline_review
        return digest({"processors": engine_identity(label),
                       "runtime": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "canonical_review": hashlib.sha256(Path(discipline_review.__file__).read_bytes()).hexdigest()})
    from . import discipline_registry
    return digest({name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                   for name, path in (("runtime", __file__),
                                      ("registry", discipline_registry.__file__))})


def _stamp():
    return datetime.now(timezone.utc).isoformat()


def _bound(task, prefix):
    values = [item[len(prefix):] for item in task.constraints if item.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise ValueError("discipline task is missing an immutable binding")
    return values[0]


def _reject_evidence_authority(value):
    if isinstance(value, dict):
        if "canonical_evidence_ids" in value:
            raise ValueError("canonical evidence references are assigned by the lifecycle")
        for item in value.values():
            _reject_evidence_authority(item)
    elif isinstance(value, list):
        for item in value:
            _reject_evidence_authority(item)


def create_runtime(db, workspace, *, enabled=None, invoker=None):
    """Leave the five default roles untouched; extend only this service instance."""
    from .discipline_registry import build_employee_definitions
    definitions = tuple(INITIAL_EMPLOYEES) + tuple(build_employee_definitions(implemented_only=True))
    service = WorkforceService(db, registry=EmployeeRegistry(definitions), enabled=enabled)
    return DisciplineRuntime(service, workspace, invoker=invoker)


class DisciplineRuntime:
    def __init__(self, service, workspace, *, invoker=None):
        self.service, self.store = service, service.store
        self.workspace = Path(workspace)
        self.invoker = invoker

    def _employee(self, label):
        if not isinstance(label, str) or not label.strip():
            raise ValueError("discipline must be a registered label")
        label = label.strip().upper()
        employee = self.service.registry.get("discipline-" + label.lower())
        if employee.domain != label or employee.required_capabilities != ("discipline:" + label,):
            raise ValueError("employee definition does not implement the requested discipline")
        return label, employee

    def plan(self, context_id, label, payload, *, objective=None, parent_task_id=None):
        label, employee = self._employee(label)
        return self._plan(context_id, label, employee, payload, objective=objective,
                          parent_task_id=parent_task_id, tool="discipline.analyze",
                          action="propose_observation")

    def plan_manager(self, context_id, payload, disciplines, *, objective=None):
        if not isinstance(disciplines, (list, tuple)) or not 1 <= len(disciplines) <= 140:
            raise ValueError("manager requires one to 140 implemented disciplines")
        labels = [self._employee(label)[0] for label in disciplines]
        if len(set(labels)) != len(labels):
            raise ValueError("manager disciplines must be unique")
        if not isinstance(payload, dict):
            raise ValueError("discipline input must be an object")
        data = {**payload, "requested_disciplines": labels}
        return self._plan(context_id, "MANAGER", self.service.registry.get("case-manager"), data,
                          objective=objective, parent_task_id=None,
                          tool="investigation.plan", action="propose_plan")

    def _plan(self, context_id, label, employee, payload, *, objective, parent_task_id, tool, action):
        if not self.service._enabled():
            raise ValueError("discipline execution is disabled")
        if not isinstance(payload, dict):
            raise ValueError("discipline input must be an object")
        context = self.store.authorization(context_id)
        self.service._check_authority(context)
        if not context.scope:
            raise ValueError("discipline tasks require registered case scope")
        if tool not in context.allowed_tools or tool not in employee.allowed_tools:
            raise ValueError("discipline tool is outside effective authority")
        if action not in context.allowed_actions or action not in employee.allowed_actions:
            raise ValueError("discipline action is outside effective authority")
        if payload.get("case_id", context.case_id) != context.case_id:
            raise ValueError("discipline input belongs to another case")
        if payload.get("task_id") not in (None, ""):
            raise ValueError("task_id is assigned by the lifecycle")
        if payload.get("discipline", label) != label:
            raise ValueError("input discipline differs from the requested employee")
        validate_case_input(payload, context.case_id)
        _reject_evidence_authority(payload)
        if parent_task_id is not None:
            parent = self.store.task(parent_task_id)["envelope"]
            if parent.case_id != context.case_id or parent.authorization_context_id != context_id:
                raise ValueError("parent task belongs to another authority context")
        objective = objective if objective is not None else payload.get("objective")
        task_id = "task-" + uuid4().hex
        now = datetime.now(timezone.utc)
        as_of = payload.get("as_of", now.isoformat())
        if not isinstance(as_of, str):
            raise ValueError("as_of requires an ISO timestamp")
        parsed = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("as_of requires an explicit timezone")
        data = json.loads(canonical({**payload, "case_id": context.case_id, "task_id": task_id,
                                    "discipline": label, "objective": objective,
                                    "as_of": parsed.astimezone(timezone.utc).isoformat()}))
        make_context({key: value for key, value in data.items()
                      if key != "requested_disciplines"} if label == "MANAGER" else data)
        encoded = canonical(data)
        if len(encoded.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ValueError("discipline input exceeds the preserved-document limit")
        input_sha = digest(data)
        source_id = "discipline-input-" + uuid4().hex
        limit = employee.budget_limit
        if limit.tool_calls < 1 or limit.runtime_seconds < 1:
            raise ValueError("employee has no execution budget")
        task = TaskEnvelope(
            schema_version="1.0", task_id=task_id, case_id=context.case_id,
            parent_task_id=parent_task_id, trace_id="trace-" + uuid4().hex,
            objective=objective, scope=context.scope, authorization_context_id=context_id,
            policy_digest=context.policy_digest, target_entities=context.scope,
            required_capabilities=employee.required_capabilities, evidence_context_ids=(),
            constraints=("provided_records_only", "no_external_collection", "human_release_required",
                         LABEL_PREFIX + label, INPUT_PREFIX + input_sha, SOURCE_PREFIX + source_id,
                         ENGINE_PREFIX + _identity(label)) + (
                             (REVIEW_PREFIX + REVIEWED_PRODUCT_SCHEMA,) if label in REVIEWED_DISCIPLINES else ()),
            budget=Budget("USD", min(1.0, limit.amount), min(120, limit.runtime_seconds),
                          min(8, limit.tool_calls), 0),
            deadline=min(now + timedelta(minutes=15), datetime.fromisoformat(context.expires_at)).isoformat(),
            stop_conditions=("deadline_reached", "budget_exhausted", "human_review_required"),
            created_by=context.actor_id, created_at=now.isoformat())
        document = SourceDocument(DOCUMENT_SCHEMA, source_id,
                                  "urn:traceatlas:discipline-input:" + task_id,
                                  now.isoformat(), encoded, (), None, None)
        captured = self.store.capture_document(task, document, self.workspace)
        task = replace(task, evidence_context_ids=(captured.evidence_id,))
        envelope_sha = self.store.create_task(task, employee.employee_id, definition_digest(employee.to_dict()))
        return {"task": task.to_dict(), "employee": employee.to_dict(),
                "envelope_digest": envelope_sha, "input_sha256": input_sha,
                "input_evidence_id": captured.evidence_id, "status": "planned"}

    def _input(self, task):
        label = _bound(task, LABEL_PREFIX)
        source_id = _bound(task, SOURCE_PREFIX)
        captured = self.store.captured_document(task, source_id)
        if captured is None:
            raise ValueError("discipline input evidence is missing")
        document, evidence = captured
        if task.evidence_context_ids != (evidence.evidence_id,):
            raise ValueError("task evidence binding differs from its captured input")
        data = json.loads(document.content)
        if not isinstance(data, dict) or digest(data) != _bound(task, INPUT_PREFIX):
            raise ValueError("discipline input digest mismatch")
        if (data.get("case_id") != task.case_id or data.get("task_id") != task.task_id
                or data.get("discipline") != label):
            raise ValueError("captured discipline input belongs to another task")
        validate_case_input(data, task.case_id)
        _reject_evidence_authority(data)
        return data, evidence

    def _manager(self, payload, evidence_ids):
        assignments = [{"discipline": label, "employee_id": self._employee(label)[1].employee_id,
                        "status": "PLANNED_REQUIRES_SEPARATE_APPROVAL"}
                       for label in payload["requested_disciplines"]]
        return {"schema": "traceatlas.discipline.manager.v1", "employee_id": "case-manager",
                "discipline": "MANAGER", "case_id": payload["case_id"], "task_id": payload["task_id"],
                "status": "PLANNING_ONLY", "findings": [], "issues": [],
                "metrics": {"assignments": len(assignments)}, "artifacts": {"assignments": assignments},
                "limitations": ["Assignments do not create or approve specialist execution.",
                                "Submitted sources share one canonical input artifact."],
                "source_authenticity_verified": False, "requires_human_review": True,
                "input_sha256": digest(payload), "engine_version": "1.0.0"}

    def _validate_output(self, result, payload, employee, evidence):
        if not isinstance(result, dict):
            raise ValueError("discipline callback must return an object")
        if len(canonical(result).encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("discipline output exceeds its contract")
        if any(result.get(key) != expected for key, expected in (
                ("employee_id", employee.employee_id), ("case_id", payload["case_id"]),
                ("task_id", payload["task_id"]), ("discipline", payload["discipline"]),
                ("input_sha256", digest(payload)))):
            raise ValueError("discipline output has a foreign identity or input digest")
        if result.get("source_authenticity_verified") is not False or result.get("requires_human_review") is not True:
            raise ValueError("discipline draft cannot assert source verification or release authority")
        if not isinstance(result.get("status"), str) or not result["status"]:
            raise ValueError("discipline output requires its native status")
        if not isinstance(result.get("engine_version"), str) or not result["engine_version"]:
            raise ValueError("discipline output requires an engine version")
        for key, types in (("findings", (list,)), ("issues", (list,)),
                           ("metrics", (dict,)), ("artifacts", (dict, list)), ("limitations", (list,))):
            if not isinstance(result.get(key), types):
                raise ValueError("discipline output has an invalid " + key)
        if len(result["findings"]) > 500:
            raise ValueError("discipline output contains too many findings")
        records = {row["record_id"]: row for row in payload.get("records", [])}
        known_sources = {row["source_id"] for row in payload.get("sources", [])}
        seen = set()
        for finding in result["findings"]:
            if not isinstance(finding, dict):
                raise ValueError("finding must be an object")
            finding_id = finding.get("finding_id")
            if not isinstance(finding_id, str) or not finding_id or finding_id in seen:
                raise ValueError("finding IDs must be nonempty and unique")
            seen.add(finding_id)
            if not isinstance(finding.get("kind"), str) or not 1 <= len(finding["kind"]) <= 128:
                raise ValueError("finding requires a bounded kind")
            if not isinstance(finding.get("summary"), str) or not 1 <= len(finding["summary"].strip()) <= 3500:
                raise ValueError("finding requires a bounded summary")
            if not isinstance(finding.get("data"), dict):
                raise ValueError("finding data must be an object")
            for key in ("record_ids", "source_ids", "canonical_evidence_ids"):
                refs = finding.get(key)
                if (not isinstance(refs, list) or len(refs) > 500
                        or any(not isinstance(ref, str) for ref in refs) or len(set(refs)) != len(refs)):
                    raise ValueError("finding references must be bounded unique string arrays")
            record_ids = set(finding["record_ids"])
            source_ids = set(finding["source_ids"])
            if not record_ids or not record_ids.issubset(records):
                raise ValueError("finding cites unknown or absent input records")
            if not source_ids.issubset(known_sources) or source_ids != {records[key]["source_id"] for key in record_ids}:
                raise ValueError("finding sources do not match the cited records")
            if finding["canonical_evidence_ids"] != [evidence.evidence_id]:
                raise ValueError("finding cites foreign canonical evidence")
        return json.loads(canonical(result))

    def run(self, task_id, *, authorized=False):
        if not authorized or not self.service._enabled():
            raise ValueError("discipline execution requires enabled explicit authorization")
        row = self.store.task(task_id)
        task = row["envelope"]
        data, evidence = self._input(task)
        if row["status"] == "completed":
            return self.store.product(task_id)
        label = _bound(task, LABEL_PREFIX)
        manager = label == "MANAGER"
        if _identity(label) != _bound(task, ENGINE_PREFIX):
            raise ValueError("discipline engine changed after task approval")
        tool = "investigation.plan" if manager else "discipline.analyze"
        action = "propose_plan" if manager else "propose_observation"
        product = None

        def runner(task, employee):
            nonlocal product
            token = self.service.execution_token(task.task_id)
            runtime = self.store.runtime
            context = self.store.authorization(task.authorization_context_id)
            runtime.check(task.task_id, token)
            if _identity(label) != _bound(task, ENGINE_PREFIX):
                raise ValueError("discipline engine changed after task approval")
            runtime.checkpoint(task.task_id, token, "discipline-input",
                               {"input_sha256": digest(data), "evidence_id": evidence.evidence_id,
                                "engine_sha256": _bound(task, ENGINE_PREFIX)})
            facade = ToolFacade()

            def invoke(arguments):
                if manager:
                    return self._manager(arguments, (evidence.evidence_id,))
                if self.invoker is None:
                    from .discipline_engines import invoke_employee
                    return invoke_employee(arguments, evidence_ids=(evidence.evidence_id,))
                return self.invoker(arguments, evidence_ids=(evidence.evidence_id,))

            facade.register(ToolContract(tool, action, MAX_DOCUMENT_BYTES, MAX_OUTPUT_BYTES), invoke)
            started_at, started = _stamp(), time.monotonic()
            reservation = runtime.reserve(task.task_id, token, tool, 0)
            try:
                wrapped = facade.call(tool, json.loads(canonical(data)), task=task,
                                      authorization=context, employee=employee)
            finally:
                runtime.settle(task.task_id, token, reservation, actual=0)
            runtime.check(task.task_id, token)
            if not self.store.verify_evidence(evidence):
                raise ValueError("discipline input evidence changed during analysis")
            draft = self._validate_output(wrapped["result"], data, employee, evidence)
            hypotheses, hypothesis_review, review_gaps = project_discipline_review(
                json.loads(canonical(data)), evidence.evidence_id, evidence.acquisition_id)
            runtime.check(task.task_id, token)
            if _identity(label) != _bound(task, ENGINE_PREFIX):
                raise ValueError("discipline engine changed during analysis")
            runtime.checkpoint(task.task_id, token, "discipline-result",
                               {"output_sha256": digest(draft),
                                "finding_ids": [finding["finding_id"] for finding in draft["findings"]]})
            observations = tuple(
                Observation("observation-" + digest([task.task_id, finding["finding_id"]])[:24],
                            evidence.evidence_id, evidence.acquisition_id,
                            "Analyzer " + label + " records " + finding["kind"] + ": " + finding["summary"],
                            SemanticClass.OBSERVATION, data["as_of"])
                for finding in draft["findings"])
            gaps = ("source-authenticity-unverified", "human-review-required") + tuple(
                "issue-" + digest(issue)[:24] for issue in draft["issues"])
            gaps = tuple(dict.fromkeys(gaps + review_gaps))
            completed_at = _stamp()
            elapsed = int((time.monotonic() - started) * 1000)
            result = ResultEnvelope(
                schema_version="1.0", task_id=task.task_id, employee_id=employee.employee_id,
                observations=observations, evidence_ids=(evidence.evidence_id,), entities=(),
                relationships=(), claims=(), hypotheses=hypotheses, contradictions=(),
                uncertainties=("submitted-source-assertions",),
                confidence_basis=("deterministic-supplied-record-analysis",),
                source_independence=("single-canonical-input-artifact",), information_gaps=gaps,
                recommended_next_actions=("review-discipline-draft",),
                cost=CostRecord("traceatlas", "deterministic-no-model", 0, 0, 0, 0, "NONE"),
                latency_ms=elapsed, model_used="deterministic-no-model", tool_calls=(tool,),
                execution_trace=(TraceSpan("span-" + digest([task.task_id, tool])[:24], task.trace_id,
                                          None, tool, draft["status"], started_at, completed_at,
                                          elapsed, (evidence.evidence_id,)),),
                stop_reason="human_review_required" if manager or observations else "source_exhausted",
                completed_at=completed_at)
            product = {"schema": "traceatlas-discipline-product/v1", "task_id": task.task_id,
                       "case_id": task.case_id, "employee_id": employee.employee_id,
                       "discipline": label, "input_sha256": digest(data),
                       "input_evidence_id": evidence.evidence_id, "draft": draft,
                       "engine_sha256": _bound(task, ENGINE_PREFIX),
                       "analysis": {"observations": [item.to_dict() for item in observations],
                                    "source_lineage": [], "verification": [], "claims": [],
                                    "graph": {"nodes": [], "edges": []}, "timeline": [],
                                    "information_gaps": list(gaps), "next_actions": []},
                       "result": result.to_dict(), "source_authenticity_verified": False,
                       "factual_entailment_verified": False, "requires_human_review": True,
                       "source_record_ids_are_canonical_evidence": False,
                       "report_status": "DRAFT_REQUIRES_HUMAN_RELEASE",
                       "source_independence_note": "Submitted source IDs and URIs are assertions inside one preserved artifact."}
            if hypothesis_review is not None:
                product["schema"] = REVIEWED_PRODUCT_SCHEMA
                product["analysis"]["hypotheses"] = [item.to_dict() for item in hypotheses]
                product["analysis"]["hypothesis_review"] = hypothesis_review
            return result

        def finalize_product():
            if _identity(label) != _bound(task, ENGINE_PREFIX):
                raise ValueError("discipline engine changed before completion")
            if not self.store.verify_evidence(evidence):
                raise ValueError("discipline input evidence changed before completion")
            return product

        self.service.execute(task_id, runner, authorized=authorized, product_factory=finalize_product)
        return self.store.product(task_id)

    def replay(self, task_id):
        """Verify stored custody and recompute v2 reviews without callback or provider calls."""
        from ..evidence import EvidenceStore

        row = self.store.task(task_id)
        if row["status"] != "completed" or row["result"] is None:
            raise ValueError("discipline replay requires a completed stored result")
        task = row["envelope"]
        product = self.store.product(task_id)
        data, evidence = self._input(task)
        if not EvidenceStore(self.workspace, self.store.db, task.case_id).verify_ledger()[0]:
            raise ValueError("discipline replay custody ledger failed")
        acquisition = self.store.db.conn.execute(
            "SELECT source_id,method,retrieved_at,trace_id FROM acquisitions_v2 "
            "WHERE case_id=? AND acquisition_id=?", (task.case_id, evidence.acquisition_id)
        ).fetchone()
        if (not acquisition or acquisition["source_id"] != evidence.source_id
                or acquisition["method"] != evidence.acquisition_method
                or acquisition["retrieved_at"] != evidence.retrieved_at
                or acquisition["trace_id"] != task.trace_id):
            raise ValueError("discipline replay acquisition metadata mismatch")
        if (product.get("task_id") != task.task_id or product.get("case_id") != task.case_id
                or product.get("employee_id") != row["employee_id"]
                or product.get("discipline") != data["discipline"]
                or product.get("input_sha256") != digest(data)
                or product.get("input_evidence_id") != evidence.evidence_id
                or product.get("result") != row["result"].to_dict()
                or row["result"].evidence_ids != (evidence.evidence_id,)
                or any(item.evidence_id != evidence.evidence_id
                       or item.acquisition_id != evidence.acquisition_id
                       for item in row["result"].observations)):
            raise ValueError("discipline replay product/result binding mismatch")
        receipt = {"schema": "traceatlas.discipline.replay.v1", "task_id": task.task_id,
                   "case_id": task.case_id, "product_schema": product.get("schema"),
                   "input_evidence_id": evidence.evidence_id, "input_sha256": digest(data),
                   "custody_verified": True, "source_authenticity_verified": False,
                   "factual_entailment_verified": False, "requires_human_review": True}
        versions = [value[len(REVIEW_PREFIX):] for value in task.constraints
                    if value.startswith(REVIEW_PREFIX)]
        if not versions:
            if product.get("schema") != "traceatlas-discipline-product/v1":
                raise ValueError("discipline replay review schema lacks its approved version binding")
            return {**receipt, "status": "LEGACY_INTEGRITY_ONLY", "semantic_recomputed": False,
                    "semantics_verified_scope": "none", "callback_draft_semantics_verified": False}
        label = _bound(task, LABEL_PREFIX)
        if (versions != [REVIEWED_PRODUCT_SCHEMA] or product.get("schema") != REVIEWED_PRODUCT_SCHEMA
                or label not in REVIEWED_DISCIPLINES):
            raise ValueError("unsupported discipline review product schema or version binding")
        if (_identity(label) != _bound(task, ENGINE_PREFIX)
                or product.get("engine_sha256") != _bound(task, ENGINE_PREFIX)):
            raise ValueError("discipline review engine changed since approval")
        hypotheses, review, review_gaps = project_discipline_review(
            json.loads(canonical(data)), evidence.evidence_id, evidence.acquisition_id)
        if _identity(label) != _bound(task, ENGINE_PREFIX):
            raise ValueError("discipline review engine changed during replay")
        projected = [item.to_dict() for item in hypotheses]
        analysis = product.get("analysis")
        if (not isinstance(analysis, dict) or analysis.get("hypothesis_review") != review
                or analysis.get("hypotheses") != projected
                or product["result"]["hypotheses"] != projected
                or not set(review_gaps).issubset(row["result"].information_gaps)
                or analysis.get("information_gaps") != product["result"]["information_gaps"]):
            raise ValueError("canonical discipline hypothesis review replay mismatch")
        return {**receipt, "status": "VERIFIED_NATIVE_REVIEW", "semantic_recomputed": True,
                "hypotheses_verified": len(hypotheses),
                "semantics_verified_scope": "canonical_hypothesis_review",
                "callback_draft_semantics_verified": False}
