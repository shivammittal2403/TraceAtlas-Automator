"""Executable, evidence-bound domain processors for specialist employees."""
from __future__ import annotations

import hashlib
import importlib
import sys
from pathlib import Path

from ...osint_taxonomy import GROUP_TERMS
from .common import ENGINE_VERSION, MAX_BYTES, _json, canonical, digest, make_context

FAMILIES = ("network", "software", "discovery", "economic", "social", "cyber", "media", "evidence", "fraud", "research")


def registered_handlers():
    expected = {label for terms in GROUP_TERMS.values() for label in terms.split()}
    result = {}
    for family in FAMILIES:
        module = importlib.import_module(__name__ + "." + family)
        for label, handler in module.HANDLERS.items():
            if label not in expected or label in result or not callable(handler):
                raise ValueError("Invalid or duplicate discipline handler: " + str(label))
            result[label] = handler
    return result


def supported_disciplines():
    return tuple(sorted(registered_handlers()))


def engine_identity(label):
    handlers = registered_handlers()
    label = str(label).strip().upper()
    if label not in handlers:
        raise ValueError("Discipline processor is not implemented: " + label)
    paths = {"kernel": Path(__file__), "contract": Path(__file__).with_name("common.py")}
    # Some families share temporal, measurement and graph algorithms. Bind the
    # full processor set rather than omitting imported sibling dependencies.
    paths.update({family: Path(__file__).with_name(family + ".py") for family in FAMILIES})
    identity = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in sorted(paths.items())}
    identity["python_version"] = list(sys.version_info[:3])
    identity["discipline"] = label
    return digest(identity)


def invoke_employee(payload, *, evidence_ids=()):
    ctx = make_context(payload, evidence_ids=evidence_ids)
    handlers = registered_handlers()
    if ctx.discipline not in handlers:
        raise ValueError("Discipline processor is not implemented: " + ctx.discipline)
    if ctx.records:
        result = handlers[ctx.discipline](ctx)
        if not isinstance(result, dict) or set(result) != {"findings", "issues", "metrics", "artifacts", "limitations"}:
            raise ValueError("Discipline processor returned an invalid result contract")
        if result["findings"] != ctx.findings or result["issues"] != ctx.issues:
            raise ValueError("Processor findings must use the evidence-bound context")
    else:
        result = ctx.output(
            metrics={"records_received": 0}, limitations=("No supplied records were available for analysis.",))
    # Reapply budgets after family-added artifact fields.
    result = ctx.output(metrics=result["metrics"], artifacts=result["artifacts"],
                        limitations=result["limitations"])
    if not ctx.records:
        status = "INSUFFICIENT_DATA"
    elif ctx.issues and not ctx.findings:
        status = "INVALID_DATA"
    elif ctx.issues:
        status = "PARTIAL"
    else:
        status = "ANALYSIS_COMPLETE"
    result = {
        "schema": "traceatlas.discipline.analysis.v1",
        "employee_id": "discipline-" + ctx.discipline.lower(),
        "discipline": ctx.discipline, "case_id": ctx.case_id, "task_id": ctx.task_id,
        "objective": ctx.objective, "as_of": ctx.as_of.isoformat(),
        "status": status, "engine_version": ENGINE_VERSION,
        "engine_sha256": engine_identity(ctx.discipline),
        "input_sha256": ctx.input_sha256, **result,
        "source_authenticity_verified": False, "factual_entailment_verified": False,
        "requires_human_review": True, "network_calls": 0, "model_calls": 0,
        "source_independence": "Submitted source metadata is asserted; canonical evidence links identify the preserved input artifact.",
    }
    _json(result)
    if len(canonical(result).encode("utf-8")) > MAX_BYTES:
        raise ValueError("Employee output exceeds 2 MiB")
    return result
