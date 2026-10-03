"""Transport-neutral tool facade used by direct calls and future MCP handlers."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any, Callable

from .contracts import AuthorizationContext, EmployeeDefinition, TaskEnvelope


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]
SECRET_KEYS = frozenset({"password", "secret", "token", "api_key", "authorization", "cookie"})


def _has_secret(value, depth=0):
    if depth > 12:
        raise ValueError("tool arguments exceed nesting limit")
    if isinstance(value, dict):
        return any(str(key).casefold() in SECRET_KEYS or _has_secret(item, depth + 1) for key, item in value.items())
    if isinstance(value, list):
        return any(_has_secret(item, depth + 1) for item in value)
    return False


@dataclass(frozen=True, slots=True)
class ToolContract:
    tool_id: str
    action: str
    maximum_input_bytes: int = 16_384
    maximum_output_bytes: int = 2 * 1024 * 1024


class ToolFacade:
    def __init__(self):
        self._tools: dict[str, tuple[ToolContract, ToolHandler]] = {}

    def register(self, contract: ToolContract, handler: ToolHandler) -> None:
        if contract.tool_id in self._tools or not 1 <= contract.maximum_input_bytes <= 1_048_576:
            raise ValueError("invalid or duplicate tool contract")
        self._tools[contract.tool_id] = (contract, handler)

    def call(self, tool_id: str, arguments: dict[str, Any], *, task: TaskEnvelope,
             authorization: AuthorizationContext, employee: EmployeeDefinition) -> dict[str, Any]:
        if tool_id not in self._tools:
            raise ValueError("unknown governed tool")
        contract, handler = self._tools[tool_id]
        if task.case_id != authorization.case_id or task.authorization_context_id != authorization.context_id:
            raise ValueError("tool call authority binding is invalid")
        if task.policy_digest != authorization.policy_digest:
            raise ValueError("tool call policy digest changed")
        stamp = datetime.now(timezone.utc)
        if not datetime.fromisoformat(authorization.issued_at) <= stamp < datetime.fromisoformat(authorization.expires_at):
            raise ValueError("tool authority expired or not yet valid")
        if datetime.fromisoformat(task.deadline) <= stamp:
            raise ValueError("tool task deadline reached")
        if not set(task.scope).issubset(authorization.scope) or not set(task.target_entities).issubset(task.scope):
            raise ValueError("tool task scope is outside registered authority")
        if tool_id not in authorization.allowed_tools or tool_id not in employee.allowed_tools:
            raise ValueError("tool is outside the effective permission intersection")
        if contract.action not in authorization.allowed_actions or contract.action not in employee.allowed_actions:
            raise ValueError("tool action is outside the effective permission intersection")
        if not isinstance(arguments, dict) or _has_secret(arguments):
            raise ValueError("tool arguments contain a forbidden secret field")
        scoped_values = set(task.target_entities) | {v.split(":", 1)[-1] for v in task.target_entities}
        if any(arguments[key] not in scoped_values for key in ("domain", "ip", "subject", "target") if key in arguments and isinstance(arguments[key], str)):
            raise ValueError("tool argument target is outside task scope")
        encoded = json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode()
        if len(encoded) > contract.maximum_input_bytes:
            raise ValueError("tool input exceeds its contract")
        result = handler(arguments)
        if not isinstance(result, dict):
            raise ValueError("tool output must be an object")
        rendered = json.dumps(result, ensure_ascii=False, allow_nan=False).encode()
        if len(rendered) > contract.maximum_output_bytes:
            raise ValueError("tool output exceeds its contract")
        return {"tool_id": tool_id, "action": contract.action, "case_id": task.case_id,
                "trace_id": task.trace_id, "instruction_authority": "none", "result": result}
