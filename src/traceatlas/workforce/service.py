"""Bounded scheduler and the first owned-domain workforce vertical slice."""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from .contracts import (
    AuthorizationContext, Budget, CostRecord, ResultEnvelope, SCHEMA_VERSION,
    TaskEnvelope,
)
from .registry import EmployeeRegistry
from .store import WorkforceStore


Runner = Callable[[TaskEnvelope, object], ResultEnvelope]


def _digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def workforce_enabled() -> bool:
    enabled = os.environ.get("TRACEATLAS_WORKFORCE_ENABLED", "").casefold() in {"1", "true", "yes"}
    killed = os.environ.get("TRACEATLAS_WORKFORCE_KILL_SWITCH", "").casefold() in {"1", "true", "yes"}
    return enabled and not killed


class WorkforceService:
    def __init__(self, db, *, registry: EmployeeRegistry | None = None, enabled: bool | None = None):
        self.store = WorkforceStore(db)
        self.registry = registry or EmployeeRegistry()
        self.enabled = workforce_enabled() if enabled is None else enabled

    def register_authorization(self, context: AuthorizationContext) -> None:
        self.store.register_authorization(context)

    def _enabled(self) -> bool:
        return self.enabled and os.environ.get("TRACEATLAS_WORKFORCE_KILL_SWITCH", "").casefold() not in {"1", "true", "yes"}

    @staticmethod
    def _check_authority(context, task=None) -> None:
        now = datetime.now(timezone.utc)
        if not datetime.fromisoformat(context.issued_at) <= now < datetime.fromisoformat(context.expires_at):
            raise ValueError("authorization context expired or not yet valid")
        if task is not None:
            if datetime.fromisoformat(task.deadline) <= now:
                raise ValueError("task deadline reached")
            if (task.policy_digest != context.policy_digest or task.case_id != context.case_id
                    or task.created_by != context.actor_id or not set(task.scope).issubset(context.scope)
                    or not set(task.target_entities).issubset(task.scope)):
                raise ValueError("task authority binding is invalid")

    def create_owned_domain_task(self, context_id: str, domain: str, objective: str) -> dict:
        return self.create_investigation_task(context_id, "domain", domain, objective)

    def create_investigation_task(self, context_id: str, target_type: str, target: str, objective: str, *, sources=None, capabilities=None, source_prices=None, health_probe=False) -> dict:
        from .documents import normalize_seed
        from .live_sources import select_sources, SOURCE_TOOLS
        if not self._enabled():
            raise ValueError("AI workforce execution is disabled by the server-side feature flag")
        target = normalize_seed(target_type, target)
        context = self.store.authorization(context_id)
        now = datetime.now(timezone.utc)
        seed = f"{target_type}:{target}"
        if seed not in context.scope:
            raise ValueError("target is outside the immutable authorization scope")
        self._check_authority(context)
        from .source_router import ObjectiveSpec, SourceRouter
        from .source_state import SourceState, stable_digest
        state = SourceState(self.store)
        objective_spec = ObjectiveSpec(context.case_id, objective, (seed,), (), (context.jurisdiction,),
            (target_type,), ('no_contact', 'no_identity_merge', 'no_active_probe'), ('report', 'graph', 'timeline', 'replay'), context.context_id)
        source_plan = SourceRouter(health=state.health).plan(objective_spec, allowed_tools=context.allowed_tools,
            capabilities=capabilities, prices=source_prices, explicit_sources=sources, health_probe=health_probe)
        selected = tuple(source_plan['sources'])
        required_tools = {"evidence.retrieve"} | {SOURCE_TOOLS[source] for source in selected}
        required_actions = {"request_collection", "propose_observation", "propose_claim"}
        if not required_tools.issubset(context.allowed_tools) or not required_actions.issubset(context.allowed_actions):
            raise ValueError("authorization does not permit the typed investigation")
        task = TaskEnvelope(
            schema_version=SCHEMA_VERSION, task_id="task-" + uuid4().hex, case_id=context.case_id,
            parent_task_id=None, trace_id="trace-" + uuid4().hex,
            objective=objective, scope=(seed,), authorization_context_id=context.context_id,
            policy_digest=context.policy_digest, target_entities=(seed,),
            required_capabilities=(target_type, "webint"), evidence_context_ids=(),
            constraints=("passive_only", "no_contact", "no_identity_merge", "human_release_required",
                         'source-plan:' + stable_digest(source_plan), *("live-source:" + source for source in selected)),
            budget=Budget("USD", 1.0, 120, 8, 2),
            deadline=(now + timedelta(minutes=15)).isoformat(),
            stop_conditions=("budget_exhausted", "deadline_reached", "source_exhausted", "human_review_required"),
            created_by=context.actor_id, created_at=now.isoformat(),
        )
        employee = self.registry.select(task, set(context.allowed_tools), set(context.allowed_actions))
        if not set(selected).issubset(employee.allowed_sources):
            raise ValueError("employee does not permit the selected sources")
        definition_digest = _digest(employee.to_dict())
        envelope_digest = self.store.create_task(task, employee.employee_id, definition_digest)
        state.save_plan(task, source_plan)
        return {"task": task.to_dict(), "employee": employee.to_dict(), "envelope_digest": envelope_digest,
                "status": "planned", "execution_enabled": self.enabled, "source_plan": source_plan}

    def approve(self, task_id: str, *, actor_id: str, rationale: str, envelope_digest: str,
                authorized: bool = False) -> dict:
        if not authorized:
            raise ValueError("explicit human authorization is required")
        task = self.store.task(task_id)
        context = self.store.authorization(task["envelope"].authorization_context_id)
        if actor_id != context.actor_id:
            raise ValueError("approval actor does not own the authorization context")
        self._check_authority(context, task["envelope"])
        self.store.approve(task_id, actor_id, rationale, envelope_digest, "approval-" + uuid4().hex)
        return self.describe(task_id)

    def execute(self, task_id: str, runner: Runner, *, authorized: bool = False, product_factory=None) -> dict:
        if not self._enabled() or not authorized:
            raise ValueError("workforce execution requires enabled feature flag and explicit authorization")
        current = self.store.task(task_id)
        if current["status"] == "completed":
            return self.describe(task_id)
        if current["status"] != "approved":
            raise ValueError("only an approved task can execute")
        task = current["envelope"]
        context = self.store.authorization(task.authorization_context_id)
        self._check_authority(context, task)
        employee = self.registry.get(current["employee_id"])
        if _digest(employee.to_dict()) != current["definition_digest"]:
            raise ValueError("employee definition changed after task creation")
        self.store.claim(task_id)
        started = time.monotonic()
        try:
            result = runner(task, employee)
            if not isinstance(result, ResultEnvelope) or result.task_id != task.task_id or result.employee_id != employee.employee_id:
                raise ValueError("runner returned a result for the wrong task or employee")
            if not set(result.tool_calls).issubset(employee.allowed_tools) or not set(result.tool_calls).issubset(context.allowed_tools):
                raise ValueError("result contains an unapproved tool call")
            if len(result.tool_calls) > task.budget.tool_calls:
                raise ValueError("result exceeds the tool-call budget")
            model_calls = sum(span.operation == "model.generate" for span in result.execution_trace)
            if model_calls > task.budget.model_calls or (result.model_used != "deterministic-no-model" and task.budget.model_calls == 0):
                raise ValueError("result exceeds the model-call budget")
            if result.cost.estimated_cost > task.budget.amount or (result.cost.actual_cost or 0) > task.budget.amount:
                raise ValueError("result exceeds the cost budget")
            if time.monotonic() - started > task.budget.runtime_seconds:
                raise ValueError("result exceeded the runtime budget")
            self._check_authority(context, task)
            if not self._enabled():
                raise ValueError("workforce kill switch stopped completion")
            self.store.finish(task_id, result, product=product_factory() if product_factory else None)
        except BaseException:
            self.store.fail(task_id)
            raise
        return self.describe(task_id)

    def deterministic_no_model_result(self, task_id: str) -> ResultEnvelope:
        current = self.store.task(task_id)
        task, employee_id = current["envelope"], current["employee_id"]
        return ResultEnvelope(
            schema_version=SCHEMA_VERSION, task_id=task.task_id, employee_id=employee_id,
            observations=(), evidence_ids=(), entities=(), relationships=(), claims=(), hypotheses=(), contradictions=(),
            uncertainties=("model_assistance_unavailable",), confidence_basis=("no_model_advisory",),
            source_independence=(), information_gaps=("collection_not_supplied",),
            recommended_next_actions=("collect_approved_domain_sources",),
            cost=CostRecord("traceatlas", "deterministic-no-model", 0, 0, 0, 0, "NONE"),
            latency_ms=0, model_used="deterministic-no-model", tool_calls=(), execution_trace=(),
            stop_reason="source_exhausted", completed_at=datetime.now(timezone.utc).isoformat(),
        )

    def describe(self, task_id: str) -> dict:
        row = self.store.task(task_id)
        return {
            "task": row["envelope"].to_dict(), "employee_id": row["employee_id"], "status": row["status"],
            "envelope_digest": row["envelope_digest"],
            "result": row["result"].to_dict() if row["result"] else None,
        }
