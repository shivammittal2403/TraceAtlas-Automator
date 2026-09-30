"""Bounded scheduler and the first owned-domain workforce vertical slice."""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from ..policy import validate_target
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

    def create_owned_domain_task(self, context_id: str, domain: str, objective: str) -> dict:
        if not self.enabled:
            raise ValueError("AI workforce execution is disabled by the server-side feature flag")
        target = validate_target("domain", domain).value.lower()
        context = self.store.authorization(context_id)
        now = datetime.now(timezone.utc)
        if datetime.fromisoformat(context.expires_at) <= now:
            raise ValueError("authorization context expired")
        if f"domain:{target}" not in context.scope:
            raise ValueError("domain is outside the immutable authorization scope")
        required_tools = {"dns.lookup", "rdap.lookup", "archive.lookup", "search.execute", "evidence.retrieve"}
        required_actions = {"request_collection", "propose_observation", "propose_claim"}
        if not required_tools.issubset(context.allowed_tools) or not required_actions.issubset(context.allowed_actions):
            raise ValueError("authorization does not permit the domain vertical slice")
        task = TaskEnvelope(
            schema_version=SCHEMA_VERSION, task_id="task-" + uuid4().hex, case_id=context.case_id,
            parent_task_id=None, trace_id="trace-" + uuid4().hex,
            objective=objective, scope=(f"domain:{target}",), authorization_context_id=context.context_id,
            policy_digest=context.policy_digest, target_entities=(f"domain:{target}",),
            required_capabilities=("domain", "webint", "infraint"), evidence_context_ids=(),
            constraints=("passive_only", "no_contact", "no_identity_merge", "human_release_required"),
            budget=Budget("USD", 1.0, 120, 8, 2),
            deadline=(now + timedelta(minutes=15)).isoformat(),
            stop_conditions=("budget_exhausted", "deadline_reached", "source_exhausted", "human_review_required"),
            created_by=context.actor_id, created_at=now.isoformat(),
        )
        employee = self.registry.select(task, set(context.allowed_tools), set(context.allowed_actions))
        definition_digest = _digest(employee.to_dict())
        envelope_digest = self.store.create_task(task, employee.employee_id, definition_digest)
        return {"task": task.to_dict(), "employee": employee.to_dict(), "envelope_digest": envelope_digest,
                "status": "planned", "execution_enabled": self.enabled}

    def approve(self, task_id: str, *, actor_id: str, rationale: str, envelope_digest: str,
                authorized: bool = False) -> dict:
        if not authorized:
            raise ValueError("explicit human authorization is required")
        task = self.store.task(task_id)
        context = self.store.authorization(task["envelope"].authorization_context_id)
        if actor_id != context.actor_id:
            raise ValueError("approval actor does not own the authorization context")
        self.store.approve(task_id, actor_id, rationale, envelope_digest, "approval-" + uuid4().hex)
        return self.describe(task_id)

    def execute(self, task_id: str, runner: Runner, *, authorized: bool = False) -> dict:
        if not self.enabled or not authorized:
            raise ValueError("workforce execution requires enabled feature flag and explicit authorization")
        current = self.store.task(task_id)
        if current["status"] == "completed":
            return self.describe(task_id)
        if current["status"] != "approved":
            raise ValueError("only an approved task can execute")
        task = current["envelope"]
        context = self.store.authorization(task.authorization_context_id)
        if task.policy_digest != context.policy_digest or task.case_id != context.case_id:
            raise ValueError("task authority binding is invalid")
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
            if result.cost.estimated_cost > task.budget.amount or (result.cost.actual_cost or 0) > task.budget.amount:
                raise ValueError("result exceeds the cost budget")
            if time.monotonic() - started > task.budget.runtime_seconds:
                raise ValueError("result exceeded the runtime budget")
            self.store.finish(task_id, result)
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
