"""Opt-in local coordination roles derived from the authoritative discipline taxonomy."""
from __future__ import annotations

from dataclasses import replace

from .contracts import Budget
from .discipline_capabilities import domain_groups
from .registry import _employee


def build_coordination_definitions():
    """Leave the initial five roles and every native specialist unchanged."""
    definitions = [_employee(
        "coordination-manager", "Coordination Manager", "manager", "COORDINATION",
        "Validate exact supplied assignments and synthesize approved domain lead receipts",
        ("coordination.plan", "coordination.synthesize"), ("provided_records",),
        ("propose_plan", "propose_synthesis", "route_task"), ("coordination:manager",))]
    for group in domain_groups():
        identity = str(group["group_id"])
        definitions.append(_employee(
            "coordination-lead-" + identity, group["group_name"] + " Team Lead",
            "team_lead", "GROUP-" + identity,
            "Validate assigned native employees and synthesize their evidence-bound results",
            ("coordination.plan", "coordination.synthesize"), ("provided_records",),
            ("propose_plan", "propose_synthesis", "route_task"),
            ("coordination:group-" + identity,)))
    return tuple(replace(item, budget_limit=Budget("NONE", 0, 120, 8, 0))
                 for item in definitions)
