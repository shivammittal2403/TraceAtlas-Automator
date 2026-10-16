"""Dedicated employee definitions, separate from the five initial workforce roles."""
from __future__ import annotations

from ..osint_taxonomy import GROUP_NAMES, GROUP_TERMS
from .discipline_engines import registered_handlers, engine_identity
from .registry import _employee


def supported_disciplines():
    return tuple(sorted(registered_handlers()))


def build_employee_definitions(*, implemented_only=True):
    handlers = registered_handlers()
    expected = {label for terms in GROUP_TERMS.values() for label in terms.split()}
    if not implemented_only and set(handlers) != expected:
        raise ValueError("Some discipline processors are not yet implemented")
    result = []
    for label, handler in sorted(handlers.items()):
        objective = (handler.__doc__ or ("Analyze supplied " + label + " records")).strip().splitlines()[0]
        result.append(_employee(
            "discipline-" + label.lower(), label + " Specialist", "specialist", label,
            objective, ("discipline.analyze",), ("provided_records",),
            ("propose_observation", "propose_claim"), ("discipline:" + label,),
            version="1.0.0"))
    return tuple(result)


def employee_catalog():
    handlers = registered_handlers()
    definitions = {item.domain: item for item in build_employee_definitions()}
    rows = []
    for group_id, terms in GROUP_TERMS.items():
        for label in terms.split():
            item = definitions.get(label)
            rows.append({
                "discipline": label, "group_id": group_id, "group_name": GROUP_NAMES[group_id],
                "implemented": item is not None,
                "employee": item.to_dict() if item is not None else None,
                "engine_sha256": engine_identity(label) if item is not None else None,
                "analysis_method": (handlers[label].__doc__ or "").strip() if label in handlers else None,
                "collection_mode": "provided_records" if item is not None else "not_implemented",
                "live_verified": False,
            })
    return {"schema": "traceatlas.discipline.catalog.v1", "requested": len(rows),
            "implemented": len(handlers), "remaining": len(rows) - len(handlers), "employees": rows}
