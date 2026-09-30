"""Provider-neutral, policy-first model selection with deterministic fallback."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from ..intelligence.ai import _local_ollama_url, _request
from .contracts import CostRecord


@dataclass(frozen=True, slots=True)
class ModelSpec:
    model_id: str
    provider: str
    capabilities: frozenset[str]
    jurisdictions: frozenset[str]
    local_only: bool
    structured_output: bool
    retention: str
    input_cost_per_million: float = 0.0
    output_cost_per_million: float = 0.0


@dataclass(frozen=True, slots=True)
class ModelRequest:
    task_id: str
    required_capabilities: frozenset[str]
    jurisdiction: str
    maximum_cost: float
    prompt: str
    output_keys: frozenset[str]


@dataclass(frozen=True, slots=True)
class ModelResponse:
    model_id: str
    provider: str
    value: dict[str, Any]
    input_tokens: int
    output_tokens: int
    latency_ms: int
    fallback: bool

    def cost_record(self, spec: ModelSpec) -> CostRecord:
        estimated = (self.input_tokens * spec.input_cost_per_million + self.output_tokens * spec.output_cost_per_million) / 1_000_000
        return CostRecord(self.provider, self.model_id, self.input_tokens, self.output_tokens, estimated, None, "USD")


class ModelAdapter(Protocol):
    def generate(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse: ...


class DeterministicAdapter:
    """Zero-provider fallback: returns an explicit gap, never fabricated analysis."""

    def generate(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        value = {key: [] for key in request.output_keys}
        if "status" in value:
            value["status"] = "model-unavailable"
        return ModelResponse(spec.model_id, spec.provider, value, 0, 0, 0, True)


class OllamaAdapter:
    def __init__(self, base_url: str = "http://127.0.0.1:11434", requester: Callable = _request):
        self.endpoint = _local_ollama_url(base_url)
        self.requester = requester

    def generate(self, spec: ModelSpec, request: ModelRequest) -> ModelResponse:
        started = time.monotonic()
        body = json.dumps({"model": spec.model_id, "prompt": request.prompt, "stream": False, "format": "json"}).encode()
        status, raw = self.requester(self.endpoint, body, {"Content-Type": "application/json"}, 120)
        if status != 200 or len(raw) > 2 * 1024 * 1024:
            raise ValueError("local model transport failed")
        outer = json.loads(raw)
        value = json.loads(outer["response"])
        if not isinstance(value, dict) or set(value) != set(request.output_keys):
            raise ValueError("model output failed strict schema validation")
        input_tokens = int(outer.get("prompt_eval_count", 0))
        output_tokens = int(outer.get("eval_count", 0))
        return ModelResponse(spec.model_id, spec.provider, value, max(0, input_tokens), max(0, output_tokens),
                             int((time.monotonic() - started) * 1000), False)


class ModelRegistry:
    def __init__(self):
        self._specs: dict[str, ModelSpec] = {}
        self._adapters: dict[str, ModelAdapter] = {}

    def register(self, spec: ModelSpec, adapter: ModelAdapter) -> None:
        if spec.model_id in self._specs:
            raise ValueError("model is already registered")
        if not spec.structured_output:
            raise ValueError("workforce models must support structured output")
        self._specs[spec.model_id], self._adapters[spec.model_id] = spec, adapter

    def spec(self, model_id: str) -> ModelSpec:
        return self._specs[model_id]

    def adapter(self, model_id: str) -> ModelAdapter:
        return self._adapters[model_id]

    def list(self) -> tuple[ModelSpec, ...]:
        return tuple(self._specs[key] for key in sorted(self._specs))


class ModelRouter:
    def __init__(self, registry: ModelRegistry, *, failure_threshold: int = 3):
        self.registry = registry
        self.failure_threshold = failure_threshold
        self.failures: dict[str, int] = {}

    def candidates(self, request: ModelRequest) -> tuple[ModelSpec, ...]:
        rows = []
        for spec in self.registry.list():
            if self.failures.get(spec.model_id, 0) >= self.failure_threshold:
                continue
            if request.jurisdiction not in spec.jurisdictions and "ANY" not in spec.jurisdictions:
                continue
            if not request.required_capabilities.issubset(spec.capabilities):
                continue
            estimated = len(request.prompt) / 4 * spec.input_cost_per_million / 1_000_000
            if estimated > request.maximum_cost:
                continue
            rows.append(spec)
        return tuple(sorted(rows, key=lambda row: (not row.local_only, row.input_cost_per_million, row.model_id)))

    def generate(self, request: ModelRequest) -> tuple[ModelResponse, CostRecord]:
        for spec in self.candidates(request):
            try:
                response = self.registry.adapter(spec.model_id).generate(spec, request)
                self.failures[spec.model_id] = 0
                return response, response.cost_record(spec)
            except (OSError, TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                self.failures[spec.model_id] = self.failures.get(spec.model_id, 0) + 1
        fallback = ModelSpec("deterministic-no-model", "traceatlas", frozenset(), frozenset({"ANY"}), True, True, "none")
        response = DeterministicAdapter().generate(fallback, request)
        return response, response.cost_record(fallback)


def default_registry(*, ollama_model: str = "qwen2.5:7b", base_url: str = "http://127.0.0.1:11434",
                     requester: Callable = _request) -> ModelRegistry:
    registry = ModelRegistry()
    registry.register(ModelSpec(ollama_model, "local-ollama", frozenset({"text", "structured_output"}),
                                frozenset({"ANY"}), True, True, "local-process"),
                      OllamaAdapter(base_url, requester))
    return registry
