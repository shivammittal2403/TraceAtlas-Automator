"""Transport-neutral tool facade used by direct calls and future MCP handlers."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from .contracts import AuthorizationContext, EmployeeDefinition, TaskEnvelope


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]
SECRET_KEYS = frozenset({"password", "secret", "token", "api_key", "authorization", "cookie"})


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
        if tool_id not in authorization.allowed_tools or tool_id not in employee.allowed_tools:
            raise ValueError("tool is outside the effective permission intersection")
        if contract.action not in authorization.allowed_actions or contract.action not in employee.allowed_actions:
            raise ValueError("tool action is outside the effective permission intersection")
        if not isinstance(arguments, dict) or any(str(key).casefold() in SECRET_KEYS for key in arguments):
            raise ValueError("tool arguments contain a forbidden secret field")
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
