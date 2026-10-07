"""Resumability helpers: snapshot current run state into a Checkpoint."""

from __future__ import annotations

from traceatlas.addons.osint_v1.investigation.checkpoints import Checkpoint
from traceatlas.addons.osint_v1.investigation.context import InvestigationContext
from traceatlas.addons.osint_v1.core.task import Task


def build_checkpoint(investigation_id: str, ctx: InvestigationContext,
                     tasks: list[Task], wave: int, notes: dict | None = None) -> Checkpoint:
    return Checkpoint(
        investigation_id=investigation_id,
        case_id=ctx.case_id,
        wave=wave,
        task_states={t.id: t.status.value for t in tasks},
        entity_keys=sorted(ctx.entities),
        evidence_ids=sorted(ctx.evidence),
        completed_task_kinds=list(ctx.completed_task_kinds),
        cost_units_spent=ctx.cost_units_spent,
        notes=notes or {},
    )
