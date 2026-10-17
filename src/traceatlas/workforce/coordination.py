"""Canonical supplied-record Manager -> Team Lead -> Employee coordination.

Every phase is an immutable, separately approved workforce task. Plans never
approve children; local routing creates planned tasks only. Synthesis reads
canonical receipts and independently recomputes native processor drafts.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from uuid import uuid4

from .contracts import Budget, CostRecord, Observation, ResultEnvelope, SemanticClass, TaskEnvelope, TraceSpan
from .discipline_capabilities import discipline_group
from .discipline_engines import invoke_employee
from .discipline_engines.common import _json, make_context
from .discipline_runtime import (
    ENGINE_PREFIX, INPUT_PREFIX, LABEL_PREFIX, SOURCE_PREFIX,
    _bound, _identity, _reject_evidence_authority,
)
from .discipline_review import REVIEWED_DISCIPLINES, project_discipline_review
from .documents import DOCUMENT_SCHEMA, MAX_DOCUMENT_BYTES, SourceDocument
from .intelligence import validate_case_input
from .service import _digest as definition_digest
from .tools import ToolContract, ToolFacade

VERSION = "traceatlas-coordination/1"
PRODUCT_SCHEMA = "traceatlas-coordination-product/v1"
PREFIXES = {
    "id": "coordination-id:", "slot": "coordination-slot:",
    "descriptor": "coordination-descriptor-sha256:", "code": "coordination-code-sha256:",
}
CREATION_LEASE_SECONDS = 120
PREVIEW_FINDINGS = 5
SCHEMA = """
CREATE TABLE IF NOT EXISTS workforce_coordinations (
 coordination_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, context_id TEXT NOT NULL,
 manifest_json TEXT NOT NULL, manifest_digest TEXT NOT NULL, cancelled_at TEXT
);
CREATE TABLE IF NOT EXISTS workforce_coordination_slots (
 coordination_id TEXT NOT NULL, slot TEXT NOT NULL, task_id TEXT NOT NULL UNIQUE,
 descriptor_json TEXT NOT NULL, descriptor_digest TEXT NOT NULL,
 materialized INTEGER NOT NULL DEFAULT 0, lease_owner TEXT, lease_until REAL,
 PRIMARY KEY(coordination_id,slot)
);
CREATE TABLE IF NOT EXISTS workforce_coordination_events (
 event_id TEXT PRIMARY KEY, coordination_id TEXT NOT NULL, action TEXT NOT NULL,
 actor_id TEXT NOT NULL, created_at TEXT NOT NULL
);
"""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def stamp():
    return datetime.now(timezone.utc).isoformat()


def source_identity():
    from . import coordination_registry, discipline_capabilities
    from .. import osint_taxonomy
    return digest({name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for name, path in (("coordinator", __file__), ("registry", coordination_registry.__file__),
                           ("taxonomy", osint_taxonomy.__file__),
                           ("capabilities", discipline_capabilities.__file__))})


def _one(task, prefix):
    matches = [value[len(prefix):] for value in task.constraints if value.startswith(prefix)]
    if len(matches) != 1 or not matches[0]:
        raise ValueError("missing or ambiguous coordination binding")
    return matches[0]


def _load_root(store, coordination_id):
    row = store.db.conn.execute(
        "SELECT * FROM workforce_coordinations WHERE coordination_id=?", (coordination_id,)).fetchone()
    if not row:
        raise ValueError("unknown coordination")
    root = json.loads(row["manifest_json"])
    if (digest(root) != row["manifest_digest"] or root["coordination_id"] != coordination_id
            or root["case_id"] != row["case_id"] or root["context_id"] != row["context_id"]):
        raise ValueError("coordination manifest integrity or case binding mismatch")
    return root, row["cancelled_at"]


def _context(store, root, *, active):
    context = store.authorization(root["context_id"])
    if (context.case_id != root["case_id"] or context.actor_id != root["actor_id"]
            or context.policy_digest != root["policy_digest"] or list(context.scope) != root["scope"]
            or digest(context.to_dict()) != root["authorization_digest"]):
        raise ValueError("coordination authority binding changed")
    if active:
        current = datetime.now(timezone.utc)
        if not datetime.fromisoformat(context.issued_at) <= current < datetime.fromisoformat(context.expires_at):
            raise ValueError("coordination authority expired or not yet valid")
        if os.environ.get("TRACEATLAS_WORKFORCE_KILL_SWITCH", "").casefold() in {"1", "true", "yes"}:
            raise ValueError("coordination kill switch stopped execution")
    return context


def _load_slot(store, coordination_id, slot):
    row = store.db.conn.execute(
        "SELECT * FROM workforce_coordination_slots WHERE coordination_id=? AND slot=?",
        (coordination_id, slot)).fetchone()
    if not row:
        raise ValueError("coordination dependency has not been planned")
    descriptor = json.loads(row["descriptor_json"])
    if (digest(descriptor) != row["descriptor_digest"] or descriptor["slot"] != slot
            or descriptor["coordination_id"] != coordination_id
            or descriptor["frozen"]["task_id"] != row["task_id"]):
        raise ValueError("coordination slot descriptor integrity mismatch")
    return descriptor, row


def _spec(root, slot):
    assignments = root["payload"]["assignments"]
    groups = sorted({item["group_id"] for item in assignments})
    if slot == "manager-plan":
        return "manager-plan", None, None, None, []
    if slot == "manager-synthesis":
        return "manager-synthesis", None, None, "manager-plan", ["lead-synthesis:" + str(g) for g in groups]
    for group in groups:
        if slot == "lead-plan:" + str(group):
            return "lead-plan", group, None, "manager-plan", []
        if slot == "lead-synthesis:" + str(group):
            return ("lead-synthesis", group, None, "lead-plan:" + str(group),
                    ["employee:" + item["discipline"] for item in assignments if item["group_id"] == group])
    for item in assignments:
        if slot == "employee:" + item["discipline"]:
            return "employee", item["group_id"], item["discipline"], "lead-plan:" + str(item["group_id"]), []
    raise ValueError("task is not an approved coordination assignment")


def _bindings(descriptor):
    return tuple(PREFIXES[key] + value for key, value in (
        ("id", descriptor["coordination_id"]), ("slot", descriptor["slot"]),
        ("descriptor", digest(descriptor)), ("code", descriptor["code_sha256"])))


def _employee_id(phase, group, label):
    if phase == "employee":
        return "discipline-" + label.lower()
    return "coordination-manager" if group is None else "coordination-lead-" + str(group)


def _task_exists(store, task_id):
    return store.db.conn.execute("SELECT 1 FROM workforce_tasks WHERE task_id=?", (task_id,)).fetchone() is not None


def _native_input(store, task, descriptor):
    source_id = descriptor["frozen"]["source_id"]
    captured = store.captured_document(task, source_id)
    if captured is None:
        raise ValueError("coordination task input evidence is missing")
    document, evidence = captured
    root, _ = _load_root(store, descriptor["coordination_id"])
    if not Path(evidence.raw_artifact_pointer).resolve().is_relative_to(Path(root["workspace"]).resolve()):
        raise ValueError("coordination evidence lies outside its pinned workspace")
    body = json.loads(Path(evidence.raw_artifact_pointer).read_text(encoding="utf-8"))
    acquisition = store.db.conn.execute(
        "SELECT source_id,method,retrieved_at,trace_id FROM acquisitions_v2 "
        "WHERE case_id=? AND acquisition_id=?", (task.case_id, evidence.acquisition_id)).fetchone()
    expected_uri = ("urn:traceatlas:discipline-input:" if descriptor["phase"] == "employee"
                    else "urn:traceatlas:coordination-input:") + task.task_id
    if (not isinstance(body, dict) or body.get("task_id") != task.task_id
            or body.get("case_id") != task.case_id or body.get("trace_id") != task.trace_id
            or body.get("acquisition_id") != evidence.acquisition_id
            or not acquisition or acquisition["source_id"] != evidence.source_id
            or acquisition["method"] != evidence.acquisition_method
            or acquisition["retrieved_at"] != evidence.retrieved_at
            or acquisition["trace_id"] != task.trace_id
            or evidence.source_id != source_id or evidence.source_uri != expected_uri
            or document.source_uri != expected_uri or evidence.acquisition_method != "source-document-capture"
            or evidence.retrieved_at != descriptor["frozen"]["created_at"]):
        raise ValueError("coordination input acquisition, source or trace metadata mismatch")
    expected = _expected_data(descriptor, task.case_id)
    if (json.loads(document.content) != expected
            or document.source_id != source_id
            or document.retrieved_at != descriptor["frozen"]["created_at"]
            or evidence.case_id != task.case_id):
        raise ValueError("coordination captured input differs from its frozen assignment")
    return expected, evidence


def _phase_data(root, slot, dependencies):
    phase, group, label, _, _ = _spec(root, slot)
    assignments = [item for item in root["payload"]["assignments"]
                   if group is None or item["group_id"] == group]
    if phase == "employee":
        assignment = next(item for item in assignments if item["discipline"] == label)
        return {"discipline": label, "objective": root["payload"]["objective"],
            "as_of": root["payload"]["as_of"], "sources": deepcopy(root["payload"]["sources"]),
            "records": deepcopy(assignment["records"]), "parameters": deepcopy(assignment["parameters"])}
    return {"coordination_id": root["coordination_id"], "phase": phase, "group_id": group,
        "objective": root["payload"]["objective"], "as_of": root["payload"]["as_of"],
        "assignment_disciplines": [item["discipline"] for item in assignments],
        "manifest_digest": digest(root), "dependencies": dependencies,
        "sources": deepcopy(root["payload"]["sources"]) if phase.endswith("plan") else [],
        "assignments": deepcopy(assignments) if phase.endswith("plan") else []}


def _expected_data(descriptor, case_id):
    data = deepcopy(descriptor["data"])
    data.update(case_id=case_id, task_id=descriptor["frozen"]["task_id"])
    if descriptor["phase"] == "employee":
        data["discipline"] = descriptor["discipline"]
    return data


def _basic_receipt(store, descriptor):
    task_id = descriptor["frozen"]["task_id"]
    row = store.task(task_id)
    if row["status"] != "completed" or row["result"] is None:
        raise ValueError("coordination blocked: dependency is not completed")
    store.verify_task_approval(row)
    product = store.product(task_id)
    if (product.get("result") != row["result"].to_dict()
            or product.get("task_id") != task_id or product.get("case_id") != row["envelope"].case_id
            or product.get("employee_id") != row["employee_id"]
            or row["result"].task_id != task_id or row["result"].employee_id != row["employee_id"]
            or product.get("source_authenticity_verified") is not False
            or product.get("factual_entailment_verified") is not False
            or product.get("requires_human_review") is not True
            or product.get("report_status") != "DRAFT_REQUIRES_HUMAN_RELEASE"):
        raise ValueError("coordination dependency product/result/case binding mismatch")
    if descriptor["phase"] != "employee" and (
            product.get("schema") != PRODUCT_SCHEMA
            or product.get("coordination_id") != descriptor["coordination_id"]
            or product.get("phase") != descriptor["phase"] or product.get("group_id") != descriptor["group_id"]):
        raise ValueError("coordination control product role/phase binding mismatch")
    return {
        "task_id": task_id, "slot": descriptor["slot"], "phase": descriptor["phase"],
        "group_id": descriptor["group_id"], "discipline": descriptor["discipline"],
        "employee_id": row["employee_id"], "envelope_digest": row["envelope_digest"],
        "result_digest": digest(row["result"].to_dict()), "product_digest": digest(product),
        "trace_id": row["envelope"].trace_id,
        "evidence_ids": list(row["result"].evidence_ids),
    }


def _verify_execution(result, task, tool, status, evidence_ids):
    """Check governed execution metadata without claiming to recompute elapsed time."""
    expected_cost = CostRecord("traceatlas", "deterministic-no-model", 0, 0, 0, 0, "NONE")
    if (result.cost != expected_cost or result.model_used != "deterministic-no-model"
            or result.tool_calls != (tool,) or len(result.execution_trace) != 1):
        raise ValueError("coordination execution must contain one local zero-model tool span")
    span = result.execution_trace[0]
    if (span.span_id != "span-" + digest([task.task_id, tool])[:24]
            or span.trace_id != task.trace_id or span.parent_span_id is not None
            or span.operation != tool or span.status != status or span.evidence_ids != evidence_ids
            or span.completed_at != result.completed_at or span.latency_ms != result.latency_ms
            or datetime.fromisoformat(span.started_at) > datetime.fromisoformat(span.completed_at)):
        raise ValueError("coordination execution span metadata changed")


def _verify_native(store, root, descriptor):
    row = store.task(descriptor["frozen"]["task_id"])
    task = row["envelope"]
    data, evidence = _native_input(store, task, descriptor)
    label = descriptor["discipline"]
    if _identity(label) != _bound(task, ENGINE_PREFIX):
        raise ValueError("native coordination processor changed since approval")
    native = invoke_employee(data, evidence_ids=(evidence.evidence_id,))
    product = store.product(task.task_id)
    result = row["result"]
    observations = tuple(Observation(
        "observation-" + digest([task.task_id, finding["finding_id"]])[:24],
        evidence.evidence_id, evidence.acquisition_id,
        "Analyzer " + label + " records " + finding["kind"] + ": " + finding["summary"],
        SemanticClass.OBSERVATION, data["as_of"]) for finding in native["findings"])
    hypotheses, review, review_gaps = (), None, ()
    if label in REVIEWED_DISCIPLINES:
        hypotheses, review, review_gaps = project_discipline_review(
            data, evidence.evidence_id, evidence.acquisition_id)
    gaps = ("source-authenticity-unverified", "human-review-required") + tuple(
        "issue-" + digest(issue)[:24] for issue in native["issues"])
    gaps = tuple(dict.fromkeys(gaps + review_gaps))
    analysis = {"observations": [item.to_dict() for item in observations],
        "source_lineage": [], "verification": [], "claims": [],
        "graph": {"nodes": [], "edges": []}, "timeline": [],
        "information_gaps": list(gaps), "next_actions": []}
    from .discipline_review import REVIEWED_PRODUCT_SCHEMA
    expected_schema = REVIEWED_PRODUCT_SCHEMA if label in REVIEWED_DISCIPLINES else "traceatlas-discipline-product/v1"
    if review is not None:
        analysis["hypotheses"] = [item.to_dict() for item in hypotheses]
        analysis["hypothesis_review"] = review
    if (product.get("schema") != expected_schema or product.get("discipline") != label
            or product.get("draft") != native or product.get("input_sha256") != digest(data)
            or product.get("input_evidence_id") != evidence.evidence_id
            or product.get("engine_sha256") != _bound(task, ENGINE_PREFIX)
            or product.get("analysis") != analysis
            or product.get("source_record_ids_are_canonical_evidence") is not False
            or product.get("source_independence_note") !=
                "Submitted source IDs and URIs are assertions inside one preserved artifact."
            or result.observations != observations or result.hypotheses != hypotheses
            or result.evidence_ids != (evidence.evidence_id,)
            or result.claims or result.relationships or result.entities or result.contradictions
            or result.uncertainties != ("submitted-source-assertions",)
            or result.confidence_basis != ("deterministic-supplied-record-analysis",)
            or result.source_independence != ("single-canonical-input-artifact",)
            or result.information_gaps != gaps
            or result.recommended_next_actions != ("review-discipline-draft",)
            or result.stop_reason != ("human_review_required" if observations else "source_exhausted")):
        raise ValueError("native coordination result does not match registered processor recomputation")
    _verify_execution(result, task, "discipline.analyze", native["status"], (evidence.evidence_id,))
    return product


def _control_gaps(summary):
    gaps = ("source-authenticity-unverified", "factual-entailment-unverified", "human-review-required")
    if summary["analysis_status"] == "PARTIAL":
        gaps += ("partial-child-analysis",)
    if summary["canonical_hypotheses_omitted"]:
        gaps += ("coordination-hypotheses-omitted",)
    return gaps


def _control_analysis(observations, gaps):
    return {"observations": [item.to_dict() for item in observations],
        "source_lineage": [], "verification": [], "claims": [],
        "information_gaps": list(gaps), "next_actions": []}


def _verified_dependency(store, root, descriptor, stack=()):
    task_id = descriptor["frozen"]["task_id"]
    if task_id in stack or len(stack) > 12:
        raise ValueError("coordination dependency cycle")
    row = store.task(task_id)
    _validate(store, row["envelope"], "replay", stack + (task_id,))
    receipt = _basic_receipt(store, descriptor)
    if descriptor["phase"] == "employee":
        product = _verify_native(store, root, descriptor)
    else:
        product = store.product(task_id)
        expected, observations, hypotheses, evidence_ids = _derive_control(
            store, root, descriptor, stack + (task_id,))
        result = row["result"]
        if (product.get("coordination") != expected or product.get("descriptor_sha256") != digest(descriptor)
                or result.observations != observations or result.hypotheses != hypotheses
                or product.get("input_sha256") != digest(_expected_data(descriptor, root["case_id"]))
                or product.get("analysis") != _control_analysis(observations, _control_gaps(expected))
                or result.evidence_ids != evidence_ids or result.claims or result.entities or result.relationships
                or result.contradictions or result.uncertainties != ("supplied-source-assertions",)
                or result.confidence_basis != ("registered-native-processor-recomputation", "canonical-child-receipts")
                or result.source_independence != ("derived-receipts-not-independent-sources",)
                or result.information_gaps != _control_gaps(expected)
                or result.recommended_next_actions != ("review-coordination-draft",)
                or result.stop_reason != "human_review_required"):
            raise ValueError("coordination control synthesis derivation mismatch")
        tool = "coordination.plan" if descriptor["phase"].endswith("plan") else "coordination.synthesize"
        _verify_execution(result, row["envelope"], tool, expected["analysis_status"], evidence_ids)
    if descriptor["phase"] == "employee":
        draft = product["draft"]
        findings = draft["findings"]
        receipt.update(analysis_status=draft["status"], findings_count=len(findings),
            preview_findings=[{
                "finding_id": item["finding_id"], "kind": item["kind"],
                "summary": item["summary"][:200], "summary_truncated": len(item["summary"]) > 200,
                "record_ids": item["record_ids"][:5], "record_ids_omitted": max(0, len(item["record_ids"]) - 5),
            } for item in findings[:PREVIEW_FINDINGS]],
            findings_omitted=max(0, len(findings) - PREVIEW_FINDINGS),
            issues_count=len(draft["issues"]), source_artifact_count=1,
            native_draft_recomputed=True, factual_entailment_verified=False)
    else:
        summary = product["coordination"]
        receipt.update(analysis_status=summary["analysis_status"], findings_count=summary["findings_count"],
            preview_findings=[], findings_omitted=summary["findings_count"],
            issues_count=summary["issues_count"], source_artifact_count=len(row["result"].evidence_ids),
            native_draft_recomputed=True, factual_entailment_verified=False)
    return receipt


def _validate(store, task, stage, stack=()):
    has_binding = any(item.startswith("coordination-") for item in task.constraints)
    if not has_binding:
        if task.parent_task_id is not None:
            parent = store.task(task.parent_task_id)["envelope"]
            if any(item.startswith("coordination-") for item in parent.constraints):
                raise ValueError("child of a coordinated task lacks immutable coordination bindings")
        return
    coordination_id = _one(task, PREFIXES["id"])
    slot = _one(task, PREFIXES["slot"])
    root, cancelled = _load_root(store, coordination_id)
    if cancelled:
        raise ValueError("coordination is cancelled")
    if root["code_sha256"] != source_identity():
        raise ValueError("coordination implementation or taxonomy changed since planning")
    context = _context(store, root, active=stage != "replay")
    descriptor, _ = _load_slot(store, coordination_id, slot)
    phase, group, label, parent_slot, dependency_slots = _spec(root, slot)
    if (descriptor["phase"], descriptor["group_id"], descriptor["discipline"]) != (phase, group, label):
        raise ValueError("coordination phase/group/assignment binding mismatch")
    if (descriptor["code_sha256"] != root["code_sha256"]
            or _one(task, PREFIXES["descriptor"]) != digest(descriptor)
            or _one(task, PREFIXES["code"]) != root["code_sha256"]
            or not set(_bindings(descriptor)).issubset(task.constraints)):
        raise ValueError("coordination task descriptor binding changed")
    assigned_labels = [item["discipline"] for item in root["payload"]["assignments"]
                       if group is None or item["group_id"] == group]
    if (descriptor["assignment_disciplines"] != assigned_labels
            or descriptor["data"] != _phase_data(root, slot, descriptor["dependencies"])):
        raise ValueError("coordination input differs from the approved root assignment")
    expected_caps = ("discipline:" + label,) if phase == "employee" else (
        ("coordination:manager",) if group is None else ("coordination:group-" + str(group),))
    allocation = Budget("NONE", 0,
        min(120, root["payload"]["budget"]["max_runtime_seconds"] // root["expected_tasks"]),
        min(8, root["payload"]["budget"]["max_tool_calls"] // root["expected_tasks"]), 0)
    if descriptor["frozen"]["budget"] != allocation.to_dict():
        raise ValueError("coordination task enlarged its globally reserved allocation")
    frozen = descriptor["frozen"]
    if (task.objective != root["payload"]["objective"] or task.required_capabilities != expected_caps
            or task.task_id != frozen["task_id"] or task.trace_id != frozen["trace_id"]
            or task.created_at != frozen["created_at"] or task.deadline != frozen["deadline"]
            or task.budget.to_dict() != frozen["budget"] or task.case_id != root["case_id"]
            or task.authorization_context_id != root["context_id"] or task.created_by != root["actor_id"]
            or task.policy_digest != root["policy_digest"] or list(task.scope) != root["scope"]
            or list(task.target_entities) != root["scope"]):
        raise ValueError("coordination frozen task authority, budget or metadata changed")
    if descriptor["employee_id"] != _employee_id(phase, group, label):
        raise ValueError("coordination employee assignment changed")
    stored = store.db.conn.execute("SELECT employee_id FROM workforce_tasks WHERE task_id=?", (task.task_id,)).fetchone()
    if stored and stored["employee_id"] != descriptor["employee_id"]:
        raise ValueError("coordination task was assigned to a different employee")
    if stage != "planning":
        store.verify_task_approval(store.task(task.task_id))
    if parent_slot is None:
        if (task.parent_task_id is not None or descriptor["parent_task_id"] is not None
                or descriptor["parent_receipt"] is not None):
            raise ValueError("coordination manager plan has an unexpected parent")
    else:
        parent, _ = _load_slot(store, coordination_id, parent_slot)
        if (task.parent_task_id != parent["frozen"]["task_id"]
                or descriptor["parent_task_id"] != task.parent_task_id):
            raise ValueError("coordination parent does not implement the approved hierarchy")
        actual = _verified_dependency(store, root, parent, stack)
        if actual != descriptor["parent_receipt"]:
            raise ValueError("coordination parent receipt changed")
    if [item["slot"] for item in descriptor["dependencies"]] != dependency_slots:
        raise ValueError("coordination synthesis dependencies differ from the approved assignment set")
    for saved in descriptor["dependencies"]:
        dependency, _ = _load_slot(store, coordination_id, saved["slot"])
        if _verified_dependency(store, root, dependency, stack) != saved:
            raise ValueError("coordination dependency receipt changed")
    expected = _expected_data(descriptor, root["case_id"])
    if phase == "employee":
        if (_bound(task, LABEL_PREFIX) != label or _bound(task, SOURCE_PREFIX) != frozen["source_id"]
                or _bound(task, INPUT_PREFIX) != digest(expected)
                or _bound(task, ENGINE_PREFIX) != _identity(label)):
            raise ValueError("coordinated native processor input/identity binding mismatch")
    else:
        for tool, action in (("coordination.plan", "propose_plan"),) if phase.endswith("plan") else (
                ("coordination.synthesize", "propose_synthesis"),):
            if tool not in context.allowed_tools or action not in context.allowed_actions:
                raise ValueError("coordination tool/action is outside explicit authority")
        if "route_task" not in context.allowed_actions:
            raise ValueError("coordination routing lacks explicit authority")
        if _one(task, INPUT_PREFIX) != digest(expected):
            raise ValueError("coordination control input digest changed")
    if stage != "planning" or task.evidence_context_ids:
        _, evidence = _native_input(store, task, descriptor)
        references = sorted({ref for item in descriptor["dependencies"] for ref in item["evidence_ids"]})
        expected_ids = (evidence.evidence_id,) if phase == "employee" else tuple(dict.fromkeys([evidence.evidence_id] + references))
        if task.evidence_context_ids != expected_ids:
            raise ValueError("coordination canonical input evidence binding changed")


def validate_coordination_task(store, task, stage):
    """Read-only guard; safe inside the canonical completion transaction."""
    if stage not in {"planning", "dispatch", "finish", "replay"}:
        raise ValueError("unsupported coordination validation stage")
    _validate(store, task, stage)


def _derive_control(store, root, descriptor, stack=()):
    task = store.task(descriptor["frozen"]["task_id"])["envelope"]
    _, evidence = _native_input(store, task, descriptor)
    dependencies = []
    for saved in descriptor["dependencies"]:
        dep, _ = _load_slot(store, root["coordination_id"], saved["slot"])
        actual = _verified_dependency(store, root, dep, stack)
        if actual != saved:
            raise ValueError("coordination dependency snapshot changed")
        dependencies.append(actual)
    issues = sum(item["issues_count"] for item in dependencies)
    partial = any(item["analysis_status"] not in {"ANALYSIS_COMPLETE", "PLAN_VALIDATED"} for item in dependencies)
    phase = descriptor["phase"]
    summary = {
        "schema": VERSION, "coordination_id": root["coordination_id"], "slot": descriptor["slot"],
        "phase": phase, "group_id": descriptor["group_id"],
        "assignment_disciplines": descriptor["assignment_disciplines"],
        "parent_receipt": descriptor["parent_receipt"], "dependencies": dependencies,
        "analysis_status": "PLAN_VALIDATED" if phase.endswith("plan") else "PARTIAL" if partial else "ANALYSIS_COMPLETE",
        "findings_count": sum(item["findings_count"] for item in dependencies), "issues_count": issues,
        "preview_limit_per_child": PREVIEW_FINDINGS,
        "findings_omitted_from_previews": sum(item["findings_omitted"] for item in dependencies),
        "original_products_preserved": True, "native_drafts_recomputed": True,
        "source_authenticity_verified": False, "factual_entailment_verified": False,
        "source_independence_verified": False, "requires_human_review": True,
        "network_calls": 0, "model_calls": 0,
        "limitations": [
            "Separate employee tasks and agreement do not establish independent source origins.",
            "Previews are bounded; complete original findings remain in the named immutable child products.",
            "Recomputation verifies deterministic processor output, not source authenticity or factual entailment.",
            "Task completion and data adequacy are reported separately; report release requires human review."]}
    observations = tuple(Observation(
        "observation-" + digest([task.task_id, item["task_id"]])[:24],
        evidence.evidence_id, evidence.acquisition_id,
        "Approved " + item["employee_id"] + " task " + item["task_id"] + " reported "
        + str(item["findings_count"]) + " findings; analysis status " + item["analysis_status"],
        SemanticClass.OBSERVATION, evidence.retrieved_at) for item in dependencies)
    hypotheses = {}
    for item in dependencies:
        result = store.task(item["task_id"])["result"]
        for hypothesis in result.hypotheses:
            previous = hypotheses.get(hypothesis.hypothesis_id)
            if previous is not None and previous != hypothesis:
                raise ValueError("coordination hypotheses share an ambiguous identity")
            hypotheses[hypothesis.hypothesis_id] = hypothesis
    selected = tuple(hypotheses[key] for key in sorted(hypotheses)[:100])
    summary["canonical_hypotheses_omitted"] = max(0, len(hypotheses) - len(selected))
    references = sorted({ref for item in dependencies for ref in item["evidence_ids"]})
    evidence_ids = tuple(dict.fromkeys([evidence.evidence_id] + references))
    return summary, observations, selected, evidence_ids


def run_control_task(runtime, task_id, authorized=False):
    """Execute one separately approved local plan/synthesis phase."""
    coordinator = CoordinationService(runtime)
    store, service = runtime.store, runtime.service
    current = store.task(task_id)
    task = current["envelope"]
    root, _ = coordinator._root(_one(task, PREFIXES["id"]))
    descriptor, _ = _load_slot(store, root["coordination_id"], _one(task, PREFIXES["slot"]))
    if descriptor["phase"] == "employee":
        raise ValueError("native employee tasks use the discipline runtime")
    if not authorized or not service._enabled():
        raise ValueError("coordination execution requires enabled explicit authorization")
    if current["status"] == "completed":
        _verified_dependency(store, root, descriptor)
        return store.product(task_id)
    product = None

    def runner(active, employee):
        nonlocal product
        validate_coordination_task(store, active, "dispatch")
        token = service.execution_token(task_id)
        execution = store.runtime
        execution.check(task_id, token)
        phase = descriptor["phase"]
        tool = "coordination.plan" if phase.endswith("plan") else "coordination.synthesize"
        action = "propose_plan" if phase.endswith("plan") else "propose_synthesis"
        facade = ToolFacade()
        facade.register(ToolContract(tool, action, MAX_DOCUMENT_BYTES, 2 * 1024 * 1024),
                        lambda _: _derive_control(store, root, descriptor)[0])
        before, started = stamp(), time.monotonic()
        reservation = execution.reserve(task_id, token, tool, 0)
        try:
            wrapped = facade.call(tool, _expected_data(descriptor, active.case_id),
                task=active, authorization=store.authorization(active.authorization_context_id), employee=employee)
        finally:
            execution.settle(task_id, token, reservation, actual=0)
        summary, observations, hypotheses, evidence_ids = _derive_control(store, root, descriptor)
        if wrapped["result"] != summary:
            raise ValueError("coordination changed during governed derivation")
        execution.check(task_id, token)
        elapsed, completed = int((time.monotonic() - started) * 1000), stamp()
        gaps = _control_gaps(summary)
        result = ResultEnvelope(
            schema_version="1.0", task_id=task_id, employee_id=employee.employee_id,
            observations=observations, evidence_ids=evidence_ids, entities=(), relationships=(), claims=(),
            hypotheses=hypotheses, contradictions=(), uncertainties=("supplied-source-assertions",),
            confidence_basis=("registered-native-processor-recomputation", "canonical-child-receipts"),
            source_independence=("derived-receipts-not-independent-sources",), information_gaps=gaps,
            recommended_next_actions=("review-coordination-draft",),
            cost=CostRecord("traceatlas", "deterministic-no-model", 0, 0, 0, 0, "NONE"),
            latency_ms=elapsed, model_used="deterministic-no-model", tool_calls=(tool,),
            execution_trace=(TraceSpan("span-" + digest([task_id, tool])[:24], active.trace_id, None,
                tool, summary["analysis_status"], before, completed, elapsed, evidence_ids),),
            stop_reason="human_review_required", completed_at=completed)
        product = {
            "schema": PRODUCT_SCHEMA, "coordination_id": root["coordination_id"], "task_id": task_id,
            "case_id": active.case_id, "employee_id": employee.employee_id, "phase": phase,
            "group_id": descriptor["group_id"], "descriptor_sha256": digest(descriptor),
            "input_sha256": digest(_expected_data(descriptor, active.case_id)),
            "coordination": summary, "result": result.to_dict(),
            "analysis": _control_analysis(observations, gaps),
            "source_authenticity_verified": False, "factual_entailment_verified": False,
            "requires_human_review": True, "report_status": "DRAFT_REQUIRES_HUMAN_RELEASE"}
        return result

    service.execute(task_id, runner, authorized=authorized, product_factory=lambda: product)
    return store.product(task_id)


class CoordinationService:
    def __init__(self, runtime):
        self.runtime, self.store, self.service = runtime, runtime.store, runtime.service
        self.workspace = Path(runtime.workspace).resolve()
        from .coordination_registry import build_coordination_definitions
        from .registry import EmployeeRegistry
        existing = {item.employee_id: item for item in self.service.registry.list()}
        for definition in build_coordination_definitions():
            if definition.employee_id in existing and existing[definition.employee_id] != definition:
                raise ValueError("coordination role collides with an existing employee definition")
            existing[definition.employee_id] = definition
        self.service.registry = EmployeeRegistry(tuple(existing.values()))
        self.store.db.conn.executescript(SCHEMA)
        self.store.db.conn.commit()

    def _root(self, coordination_id):
        root, cancelled = _load_root(self.store, coordination_id)
        if Path(root["workspace"]).resolve() != self.workspace:
            raise ValueError("coordination runtime workspace differs from its pinned manifest")
        return root, cancelled

    def _payload(self, context, supplied):
        _json(supplied)
        if not isinstance(supplied, dict) or set(supplied) - {
                "case_id", "objective", "as_of", "sources", "assignments", "budget"} or not {
                "objective", "as_of", "sources", "assignments", "budget"}.issubset(supplied):
            raise ValueError("coordination requires explicit objective/as_of/sources/assignments/budget")
        if supplied.get("case_id", context.case_id) != context.case_id:
            raise ValueError("coordination input belongs to another case")
        _reject_evidence_authority(supplied)
        validate_case_input(supplied, context.case_id)
        assignments = supplied["assignments"]
        if not isinstance(assignments, list) or not 1 <= len(assignments) <= 140:
            raise ValueError("coordination requires one to 140 explicit assignments")
        normalized, labels, records = [], set(), {}
        for item in assignments:
            if not isinstance(item, dict) or set(item) - {"discipline", "records", "parameters"} or not {
                    "discipline", "records"}.issubset(item):
                raise ValueError("coordination assignment has missing or unknown fields")
            label, _ = self.runtime._employee(item["discipline"])
            if label in labels:
                raise ValueError("coordination disciplines must be unique")
            labels.add(label)
            group = discipline_group(label)
            data = {
                "case_id": context.case_id, "task_id": "task-coordination-validation",
                "discipline": label, "objective": supplied["objective"], "as_of": supplied["as_of"],
                "sources": supplied["sources"], "records": item["records"],
                "parameters": item.get("parameters", {})}
            ctx = make_context(data)
            for record in item["records"]:
                encoded = canonical(record)
                previous = records.get(record["record_id"])
                if previous is not None and previous != encoded:
                    raise ValueError("one shared record identity cannot denote different evidence")
                records[record["record_id"]] = encoded
            normalized.append({"discipline": label, "group_id": group["group_id"],
                "records": deepcopy(item["records"]), "parameters": deepcopy(item.get("parameters", {}))})
        normalized.sort(key=lambda item: (item["group_id"], item["discipline"]))
        budget = supplied["budget"]
        keys = {"max_tasks", "max_employees", "max_tool_calls", "max_runtime_seconds", "model_calls", "max_cost"}
        if not isinstance(budget, dict) or set(budget) != keys:
            raise ValueError("coordination requires an exact declared global budget")
        for key, maximum in (("max_tasks", 512), ("max_employees", 140), ("max_tool_calls", 4096),
                             ("max_runtime_seconds", 86400)):
            if type(budget[key]) is not int or not 1 <= budget[key] <= maximum:
                raise ValueError("coordination global budget is invalid")
        if type(budget["model_calls"]) is not int or budget["model_calls"] != 0 or (
                type(budget["max_cost"]) not in (int, float) or budget["max_cost"] != 0):
            raise ValueError("coordination permits zero model calls and zero provider cost only")
        expected = len(normalized) + 2 * len({item["group_id"] for item in normalized}) + 2
        if (budget["max_tasks"] < expected or budget["max_employees"] < len(normalized)
                or budget["max_tool_calls"] < expected or budget["max_runtime_seconds"] < expected):
            raise ValueError("coordination declared budget cannot cover the required hierarchy")
        payload = {"objective": supplied["objective"], "as_of": ctx.as_of.isoformat(),
            "sources": deepcopy(supplied["sources"]), "assignments": normalized, "budget": deepcopy(budget)}
        if len(canonical(payload).encode("utf-8")) > 224 * 1024:
            raise ValueError("coordination supplied manifest exceeds the preserved input bound")
        return payload, expected

    def plan(self, context_id, payload):
        if not self.service._enabled():
            raise ValueError("coordination execution is disabled")
        context = self.store.authorization(context_id)
        self.service._check_authority(context)
        if context.scope != ("provided_records:" + context.case_id,):
            raise ValueError("coordination requires exact supplied-record case scope")
        required_tools = {"coordination.plan", "coordination.synthesize", "discipline.analyze"}
        required_actions = {"propose_plan", "propose_synthesis", "route_task", "propose_observation"}
        if not required_tools.issubset(context.allowed_tools) or not required_actions.issubset(context.allowed_actions):
            raise ValueError("coordination requires explicit local planning, synthesis and routing authority")
        prepared, expected = self._payload(context, payload)
        coordination_id = "coordination-" + digest([context_id, prepared])[:32]
        root = {
            "schema": VERSION, "coordination_id": coordination_id, "case_id": context.case_id,
            "context_id": context_id, "actor_id": context.actor_id, "policy_digest": context.policy_digest,
            "scope": list(context.scope), "authorization_digest": digest(context.to_dict()),
            "workspace": str(self.workspace), "payload": prepared,
            "expected_tasks": expected, "code_sha256": source_identity()}
        with self.store.db.conn:
            self.store.db.conn.execute(
                "INSERT OR IGNORE INTO workforce_coordinations VALUES(?,?,?,?,?,NULL)",
                (coordination_id, context.case_id, context_id, canonical(root), digest(root)))
        existing, cancelled = self._root(coordination_id)
        if existing != root or cancelled:
            raise ValueError("coordination replay conflicts with an existing immutable or cancelled plan")
        descriptor = self._reserve(root, "manager-plan")
        return self._materialize(root, descriptor)

    def _reserve(self, root, slot):
        phase, group, label, parent_slot, dependency_slots = _spec(root, slot)
        _context(self.store, root, active=True)
        found = self.store.db.conn.execute(
            "SELECT 1 FROM workforce_coordination_slots WHERE coordination_id=? AND slot=?",
            (root["coordination_id"], slot)).fetchone()
        if found:
            return _load_slot(self.store, root["coordination_id"], slot)[0]
        context = _context(self.store, root, active=True)
        parent_receipt, parent_task_id = None, None
        if parent_slot is not None:
            parent, _ = _load_slot(self.store, root["coordination_id"], parent_slot)
            parent_receipt = _verified_dependency(self.store, root, parent)
            parent_task_id = parent["frozen"]["task_id"]
        dependencies = []
        for dep_slot in dependency_slots:
            dep, _ = _load_slot(self.store, root["coordination_id"], dep_slot)
            dependencies.append(_verified_dependency(self.store, root, dep))
        assignments = [item for item in root["payload"]["assignments"] if group is None or item["group_id"] == group]
        employee_id = _employee_id(phase, group, label)
        employee = self.service.registry.get(employee_id)
        required = root["expected_tasks"]
        budget = Budget("NONE", 0, min(120, employee.budget_limit.runtime_seconds,
            root["payload"]["budget"]["max_runtime_seconds"] // required),
            min(8, employee.budget_limit.tool_calls, root["payload"]["budget"]["max_tool_calls"] // required), 0)
        now = datetime.now(timezone.utc)
        frozen = {
            "task_id": "task-" + uuid4().hex, "source_id": "coordination-input-" + uuid4().hex,
            "trace_id": "trace-" + uuid4().hex, "created_at": now.isoformat(),
            "deadline": min(now + timedelta(minutes=15), datetime.fromisoformat(context.expires_at)).isoformat(),
            "budget": budget.to_dict()}
        data = _phase_data(root, slot, dependencies)
        descriptor = {
            "coordination_id": root["coordination_id"], "slot": slot, "phase": phase,
            "group_id": group, "discipline": label, "employee_id": employee_id,
            "assignment_disciplines": [item["discipline"] for item in assignments],
            "parent_task_id": parent_task_id, "parent_receipt": parent_receipt,
            "dependencies": dependencies, "data": data, "frozen": frozen,
            "code_sha256": root["code_sha256"]}
        # Reserve immutable descriptors and their full task budget before any planner/capture side effect.
        with self.store.db.conn:
            self.store.db.conn.execute("BEGIN IMMEDIATE")
            rows = self.store.db.conn.execute(
                "SELECT descriptor_json FROM workforce_coordination_slots WHERE coordination_id=?",
                (root["coordination_id"],)).fetchall()
            allocations = [json.loads(row[0])["frozen"]["budget"] for row in rows]
            limit = root["payload"]["budget"]
            if (len(rows) + 1 > limit["max_tasks"]
                    or sum(item["tool_calls"] for item in allocations) + budget.tool_calls > limit["max_tool_calls"]
                    or sum(item["runtime_seconds"] for item in allocations) + budget.runtime_seconds > limit["max_runtime_seconds"]):
                raise ValueError("coordination global conservative reservations exhausted")
            self.store.db.conn.execute(
                "INSERT OR IGNORE INTO workforce_coordination_slots VALUES(?,?,?,?,?,0,NULL,NULL)",
                (root["coordination_id"], slot, frozen["task_id"], canonical(descriptor), digest(descriptor)))
        return _load_slot(self.store, root["coordination_id"], slot)[0]

    def _control_plan(self, root, descriptor):
        context = _context(self.store, root, active=True)
        frozen = descriptor["frozen"]
        data = _expected_data(descriptor, root["case_id"])
        employee = self.service.registry.get(descriptor["employee_id"])
        tool = "coordination.plan" if descriptor["phase"].endswith("plan") else "coordination.synthesize"
        if tool not in employee.allowed_tools:
            raise ValueError("coordination employee does not implement its local phase tool")
        task = TaskEnvelope(
            schema_version="1.0", task_id=frozen["task_id"], case_id=root["case_id"],
            parent_task_id=descriptor["parent_task_id"], trace_id=frozen["trace_id"],
            objective=root["payload"]["objective"], scope=tuple(root["scope"]), authorization_context_id=root["context_id"],
            policy_digest=root["policy_digest"], target_entities=tuple(root["scope"]),
            required_capabilities=employee.required_capabilities, evidence_context_ids=(),
            constraints=("provided_records_only", "no_external_collection", "human_release_required",
                INPUT_PREFIX + digest(data), *_bindings(descriptor)),
            budget=Budget.from_dict(frozen["budget"]), deadline=frozen["deadline"],
            stop_conditions=("deadline_reached", "budget_exhausted", "human_review_required"),
            created_by=context.actor_id, created_at=frozen["created_at"])
        validate_coordination_task(self.store, task, "planning")
        if _task_exists(self.store, task.task_id):
            existing = self.store.task(task.task_id)
            captured = self.store.captured_document(existing["envelope"], frozen["source_id"])
            if not captured:
                raise ValueError("existing control task has no immutable captured input")
            references = sorted({ref for item in descriptor["dependencies"] for ref in item["evidence_ids"]})
            expected = replace(task, evidence_context_ids=tuple(dict.fromkeys([captured[1].evidence_id] + references)))
            if existing["envelope"] != expected or existing["employee_id"] != employee.employee_id:
                raise ValueError("existing control task differs from its frozen descriptor")
            return
        document = SourceDocument(DOCUMENT_SCHEMA, frozen["source_id"],
            "urn:traceatlas:coordination-input:" + task.task_id, frozen["created_at"], canonical(data), (), None, None)
        evidence = self.store.capture_document(task, document, self.workspace)
        references = sorted({ref for item in descriptor["dependencies"] for ref in item["evidence_ids"]})
        task = replace(task, evidence_context_ids=tuple(dict.fromkeys([evidence.evidence_id] + references)))
        self.store.create_task(task, employee.employee_id, definition_digest(employee.to_dict()))

    def _materialize(self, root, descriptor):
        owner = uuid4().hex
        with self.store.db.conn:
            self.store.db.conn.execute("BEGIN IMMEDIATE")
            slot = self.store.db.conn.execute(
                "SELECT lease_owner,lease_until FROM workforce_coordination_slots WHERE coordination_id=? AND slot=?",
                (root["coordination_id"], descriptor["slot"])).fetchone()
            if slot["lease_owner"] and slot["lease_until"] > time.time():
                raise ValueError("coordination task creation is already in progress")
            self.store.db.conn.execute(
                "UPDATE workforce_coordination_slots SET lease_owner=?,lease_until=? WHERE coordination_id=? AND slot=?",
                (owner, time.time() + CREATION_LEASE_SECONDS, root["coordination_id"], descriptor["slot"]))
        try:
            if descriptor["phase"] == "employee":
                self.runtime._plan(root["context_id"], descriptor["discipline"],
                    self.service.registry.get(descriptor["employee_id"]), deepcopy(descriptor["data"]),
                    objective=root["payload"]["objective"], parent_task_id=descriptor["parent_task_id"],
                    tool="discipline.analyze", action="propose_observation",
                    frozen=deepcopy(descriptor["frozen"]), extra_constraints=_bindings(descriptor))
            else:
                self._control_plan(root, descriptor)
            with self.store.db.conn:
                changed = self.store.db.conn.execute(
                    "UPDATE workforce_coordination_slots SET materialized=1 WHERE coordination_id=? AND slot=? AND lease_owner=?",
                    (root["coordination_id"], descriptor["slot"], owner))
                if changed.rowcount != 1:
                    raise ValueError("coordination task creation lease was superseded")
        finally:
            with self.store.db.conn:
                self.store.db.conn.execute(
                    "UPDATE workforce_coordination_slots SET lease_owner=NULL,lease_until=NULL "
                    "WHERE coordination_id=? AND slot=? AND lease_owner=?",
                    (root["coordination_id"], descriptor["slot"], owner))
        row = self.store.task(descriptor["frozen"]["task_id"])
        return {
            "coordination_id": root["coordination_id"], "slot": descriptor["slot"],
            "phase": descriptor["phase"], "group_id": descriptor["group_id"], "discipline": descriptor["discipline"],
            "task": row["envelope"].to_dict(), "employee": self.service.registry.get(row["employee_id"]).to_dict(),
            "envelope_digest": row["envelope_digest"], "status": row["status"]}

    def _parent(self, parent_task_id):
        if not self.service._enabled():
            raise ValueError("coordination execution is disabled")
        row = self.store.task(parent_task_id)
        coordination_id = _one(row["envelope"], PREFIXES["id"])
        root, cancelled = self._root(coordination_id)
        if cancelled:
            raise ValueError("coordination is cancelled")
        _context(self.store, root, active=True)
        descriptor, _ = _load_slot(self.store, coordination_id, _one(row["envelope"], PREFIXES["slot"]))
        _verified_dependency(self.store, root, descriptor)
        if descriptor["phase"] not in {"manager-plan", "lead-plan"}:
            raise ValueError("coordination routing requires a completed manager or lead plan")
        return root, descriptor

    def materialize_children(self, parent_task_id):
        root, parent = self._parent(parent_task_id)
        if parent["phase"] == "manager-plan":
            slots = ["lead-plan:" + str(group) for group in sorted({
                item["group_id"] for item in root["payload"]["assignments"]})]
        else:
            slots = ["employee:" + item["discipline"] for item in root["payload"]["assignments"]
                     if item["group_id"] == parent["group_id"]]
        children = [self._materialize(root, self._reserve(root, slot)) for slot in slots]
        return {"coordination_id": root["coordination_id"], "parent_task_id": parent_task_id, "children": children}

    def plan_synthesis(self, parent_task_id):
        root, parent = self._parent(parent_task_id)
        slot = "manager-synthesis" if parent["phase"] == "manager-plan" else "lead-synthesis:" + str(parent["group_id"])
        return self._materialize(root, self._reserve(root, slot))

    def run(self, task_id, authorized=False):
        task = self.store.task(task_id)["envelope"]
        coordination_id = _one(task, PREFIXES["id"])
        root, cancelled = self._root(coordination_id)
        if cancelled:
            raise ValueError("coordination is cancelled")
        descriptor, _ = _load_slot(self.store, coordination_id, _one(task, PREFIXES["slot"]))
        if descriptor["phase"] == "employee":
            return self.runtime.run(task_id, authorized=authorized)
        return run_control_task(self.runtime, task_id, authorized=authorized)

    def describe(self, coordination_id):
        root, cancelled = self._root(coordination_id)
        _context(self.store, root, active=False)
        tasks, reservations = [], {"tasks": 0, "tool_calls": 0, "runtime_seconds": 0, "model_calls": 0, "provider_cost": 0}
        slots = self.store.db.conn.execute(
            "SELECT slot FROM workforce_coordination_slots WHERE coordination_id=? ORDER BY slot", (coordination_id,)).fetchall()
        for saved in slots:
            descriptor, _ = _load_slot(self.store, coordination_id, saved["slot"])
            frozen = descriptor["frozen"]
            reservations["tasks"] += 1
            reservations["tool_calls"] += frozen["budget"]["tool_calls"]
            reservations["runtime_seconds"] += frozen["budget"]["runtime_seconds"]
            row = self.store.task(frozen["task_id"]) if _task_exists(self.store, frozen["task_id"]) else None
            quality = None
            if row and row["status"] == "completed":
                product = self.store.product(frozen["task_id"])
                quality = product["draft"]["status"] if descriptor["phase"] == "employee" else product["coordination"]["analysis_status"]
            tasks.append({"task_id": frozen["task_id"], "slot": descriptor["slot"], "phase": descriptor["phase"],
                "group_id": descriptor["group_id"], "discipline": descriptor["discipline"],
                "task_status": row["status"] if row else "reserved", "analysis_status": quality})
        pending = [item["task_id"] for item in tasks if item["task_status"] == "planned"]
        failed = [item["task_id"] for item in tasks if item["task_status"] in {"failed", "cancelled"}]
        final = next((item for item in tasks if item["slot"] == "manager-synthesis"), None)
        reasons = []
        if cancelled:
            status = "CANCELLED"
        elif failed:
            status, reasons = "BLOCKED_CHILD_FAILED", failed
        elif final and final["task_status"] == "completed":
            status = "PARTIAL_DRAFT" if final["analysis_status"] == "PARTIAL" else "COMPLETE_DRAFT_REQUIRES_HUMAN_RELEASE"
        elif pending:
            status = "BLOCKED_REQUIRES_APPROVAL"
        elif any(item["task_status"] in {"running", "approved"} for item in tasks):
            status = "RUNNING"
        else:
            status, reasons = "PLANNED", ["next-stage-routing-or-synthesis-required"]
        return {"coordination_id": coordination_id, "status": status, "tasks": tasks,
            "pending_approval_task_ids": pending, "blocked_reasons": reasons,
            "budget": root["payload"]["budget"], "reservations": reservations,
            "expected_tasks": root["expected_tasks"], "requires_human_review": True,
            "source_authenticity_verified": False, "factual_entailment_verified": False}

    def replay(self, coordination_id):
        root, cancelled = self._root(coordination_id)
        if cancelled:
            raise ValueError("coordination is cancelled")
        final, _ = _load_slot(self.store, coordination_id, "manager-synthesis")
        _verified_dependency(self.store, root, final)
        from ..evidence import EvidenceStore
        if not EvidenceStore(self.workspace, self.store.db, root["case_id"]).verify_ledger()[0]:
            raise ValueError("coordination custody ledger failed")
        described = self.describe(coordination_id)
        if len(described["tasks"]) != root["expected_tasks"] or any(item["task_status"] != "completed" for item in described["tasks"]):
            raise ValueError("coordination replay requires every approved workflow stage")
        for item in described["tasks"]:
            descriptor, _ = _load_slot(self.store, coordination_id, item["slot"])
            _verified_dependency(self.store, root, descriptor)
        return {"coordination_id": coordination_id, "verified": True, "requires_network": False,
            "tasks_verified": len(described["tasks"]), "native_drafts_recomputed": True,
            "source_authenticity_verified": False, "factual_entailment_verified": False,
            "semantics_verified_scope": "registered_processor_outputs_and_coordination_receipts",
            "requires_human_review": True}

    def cancel(self, coordination_id, actor_id, authorized=False):
        root, cancelled = self._root(coordination_id)
        context = _context(self.store, root, active=False)
        if not authorized or actor_id != context.actor_id:
            raise ValueError("coordination cancellation requires its authorization owner")
        if not cancelled:
            with self.store.db.conn:
                self.store.db.conn.execute(
                    "UPDATE workforce_coordinations SET cancelled_at=? WHERE coordination_id=? AND cancelled_at IS NULL",
                    (stamp(), coordination_id))
                self.store.db.conn.execute("INSERT INTO workforce_coordination_events VALUES(?,?,?,?,?)",
                    ("event-" + uuid4().hex, coordination_id, "cancel", actor_id, stamp()))
        for item in self.describe(coordination_id)["tasks"]:
            if item["task_status"] in {"planned", "approved", "running", "failed"}:
                self.service.cancel(item["task_id"], actor_id=actor_id, authorized=True)
        return self.describe(coordination_id)
