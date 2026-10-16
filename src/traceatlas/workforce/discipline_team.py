"""Deterministic case coordinator for explicit, bounded employee assignments."""
from __future__ import annotations

from copy import deepcopy
from .discipline_engines import invoke_employee, supported_disciplines
from .discipline_engines.common import _json, canonical, digest, identifier, instant, text, MAX_BYTES


def run_team(payload):
    """Execute each supplied discipline assignment and retain evidence-specific drafts.

    The coordinator never invents records, selects new subjects, grants authority
    or dispatches external tools. Persistent case tasks use DisciplineRuntime.
    """
    _json(payload)
    fields = {"case_id", "task_id", "objective", "as_of", "sources", "assignments"}
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError("Team input requires exactly case_id/task_id/objective/as_of/sources/assignments")
    if len(canonical(payload).encode("utf-8")) > MAX_BYTES:
        raise ValueError("Team input exceeds 2 MiB")
    case_id, team_id = identifier(payload["case_id"], "case_id"), identifier(payload["task_id"], "task_id")
    objective, stamp = text(payload["objective"], "objective", maximum=4000), instant(payload["as_of"])
    assignments = payload["assignments"]
    if not isinstance(assignments, list) or not 1 <= len(assignments) <= 140:
        raise ValueError("Team requires between 1 and 140 explicit assignments")
    allowed, prepared, identities, record_values = set(supported_disciplines()), [], set(), {}
    for assignment in assignments:
        if not isinstance(assignment, dict) or set(assignment) - {"discipline", "records", "parameters"} or (
            {"discipline", "records"} - set(assignment)
        ):
            raise ValueError("Assignment requires discipline/records and optional parameters")
        label = identifier(assignment["discipline"], "discipline").upper()
        if label not in allowed or label in identities:
            raise ValueError("Assignments require unique implemented disciplines")
        identities.add(label)
        records = assignment["records"]
        if not isinstance(records, list):
            raise ValueError("Assignment records require an array")
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("record_id"), str):
                raise ValueError("Team record identity is missing")
            previous = record_values.get(record["record_id"])
            value = canonical(record)
            if previous is not None and previous != value:
                raise ValueError("A record_id cannot denote different evidence across assignments")
            record_values[record["record_id"]] = value
        prepared.append({
            "case_id": case_id, "task_id": "task-" + digest([team_id, label])[:32],
            "objective": objective, "as_of": stamp.isoformat(), "discipline": label,
            "sources": deepcopy(payload["sources"]), "records": deepcopy(records),
            "parameters": deepcopy(assignment.get("parameters", {}))})
    # Validate every shared source/reference contract before executing any handler.
    from .discipline_engines.common import make_context
    for assignment in prepared:
        make_context(assignment)
    results, gaps = [], []
    for assignment in prepared:
        draft = invoke_employee(assignment)
        results.append(draft)
        if draft["status"] != "ANALYSIS_COMPLETE":
            gaps.append({"discipline": draft["discipline"], "status": draft["status"],
                         "issues": len(draft["issues"])})
    counts = {}
    for draft in results:
        counts[draft["status"]] = counts.get(draft["status"], 0) + 1
    output = {"schema": "traceatlas.discipline.team.v1", "case_id": case_id, "task_id": team_id,
              "objective": objective, "as_of": stamp.isoformat(),
              "status": "PARTIAL" if gaps else "ANALYSIS_COMPLETE",
              "input_sha256": digest(payload), "employees_executed": len(results),
              "unique_supplied_records": len(record_values), "status_counts": counts,
              "drafts": results, "information_gaps": gaps,
              "network_calls": 0, "model_calls": 0, "requires_human_review": True,
              "source_authenticity_verified": False, "factual_entailment_verified": False,
              "limitations": ["Cross-discipline agreement does not establish source independence.",
                              "This standalone coordinator does not persist or approve canonical case tasks.",
                              "Every assignment uses explicit supplied evidence; no discovery is inferred from absent inputs."]}
    _json(output)
    if len(canonical(output).encode("utf-8")) > MAX_BYTES:
        raise ValueError("Team output exceeds 2 MiB; split the submitted assignments")
    return output
