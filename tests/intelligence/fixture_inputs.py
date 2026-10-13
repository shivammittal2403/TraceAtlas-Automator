"""Explicitly synthetic contract smoke inputs; never live-source proof."""
import importlib
import inspect
from dataclasses import fields, MISSING
from typing import get_type_hints, get_origin


def fixture(item):
    module = importlib.import_module("traceatlas.addons.intelligence_v1.modules." + item["id"])
    base = {"case_id": "suite-fixture", "task_id": "suite-fixture-job",
            "objective": "Review supplied synthetic records for a defensive offline fixture.",
            "question": "What do the supplied records establish?",
            "questions": ["What do the supplied records establish?"],
            "scope": {"authorized_only": True, "public_or_authorized_sources_only": True,
                      "defensive_only": True, "mode": "AUTHORIZED_ONLY",
                      "no_private_person_tracking": True},
            "authorization": {"approved": True, "scope": "provided_records_only",
                              "model_mode": "LOCAL_ONLY", "context": "SYNTHETIC_TEST_INPUT"},
            "model_mode": "LOCAL_ONLY", "mode": "LOCAL_ONLY", "sources": [], "evidence": [],
            "authorization_context": "SYNTHETIC_PROVIDED_RECORDS_ONLY"}
    adapter = item["adapter"]
    if adapter in {"request", "pipeline"}:
        cls = getattr(module, item["request"])
        hints = get_type_hints(cls)
        data = {field.name: base[field.name] for field in fields(cls) if field.name in base}
        for field in fields(cls):
            if field.name in data and get_origin(hints.get(field.name)) is list and not isinstance(data[field.name], list):
                data[field.name] = ["provided_records_only"]
            if field.name in data and hints.get(field.name) is str and not isinstance(data[field.name], str):
                data[field.name] = "provided_records_only"
            if field.name not in data and field.default is MISSING and field.default_factory is MISSING:
                if hints.get(field.name) is str:
                    data[field.name] = "SYNTHETIC_TEST_INPUT"
                else:
                    raise ValueError("Add an explicit fixture for " + item["id"] + ":" + field.name)
        return data
    if adapter == "employee" and item["method"] == "process_case":
        method = getattr(getattr(module, item["entry"])(), item["method"])
        defaults = {**base, "authorized_scope": base["scope"], "evidence_input": {},
                    "observations_input": [], "raw_inputs": [], "public_evidence": {},
                    "seed_handles": [], "known_facts": {}, "existing_facts": {}}
        if item["id"] == "forensicint":
            defaults["evidence_input"] = []
        return {name: defaults[name] for name in inspect.signature(method).parameters}
    if adapter == "journal":
        return {"case_id": base["case_id"], "objective": base["objective"],
                "scope": "provided_records_only", "records": {}}
    return base
