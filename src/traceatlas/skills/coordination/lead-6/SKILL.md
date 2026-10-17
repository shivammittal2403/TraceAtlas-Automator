---
id: coordination-lead-6
employee_id: coordination-lead-6
version: 1.0.0
role: team_lead
execution_mode: supplied_record_coordination
live_verified: false
domain_group: 6
---

# MEDIA / EVIDENCE / VERIFICATION Team Lead

## Purpose and Selection

Serve as `coordination-lead-6` for authoritative taxonomy group 6,
MEDIA / EVIDENCE / VERIFICATION. Validate the supplied assignments delegated by the coordination
manager and synthesize the exact approved employees for this group. The processor
is deterministic; this Markdown guides operation and review without granting
execution or model authority.

Assigned taxonomy labels:

- `MASINT`
- `GEOINT`
- `IMINT`
- `VIDINT`
- `AUDINT`
- `DOCINT`
- `METADATAINT`
- `TRUSTINT`
- `SOURCEINT`
- `PROVENANCEINT`
- `CORROBORATIONINT`
- `CONTRADICTIONINT`
- `VERIFICATIONINT`
- `HYPOTHESISINT`
- `FALSIFICATIONINT`

Select only labels explicitly present in this coordination's immutable root
manifest. This taxonomy group, rather than a native implementation-file family,
defines the lead's assignment boundary.

## Inputs and Preconditions

Require a completed, separately approved `manager-plan`, its verified receipt,
the immutable root manifest, matching case/authorization owner and policy,
objective and timezone-aware `as_of`, declared sources, and this group's exact
assignments. Each assignment has a unique registered discipline, supplied
`records`, and optional `parameters`.

Sources require `source_id` and `uri`; records require `record_id`,
`source_id`, object `data`, and optional `observed_at`. Referenced sources
must exist, and a record ID reused across assignments must identify identical
content. Use the selected discipline's native procedure and recipe for its actual
data fields. Shared-envelope validation alone does not establish adequate data.

## Scope and Permissions

Use only `coordination.plan` and `coordination.synthesize`, with the role
actions `propose_plan`, `propose_synthesis`, and `route_task`. The exact
authorization scope is `provided_records:<case_id>`. The broader case context
must explicitly permit native `discipline.analyze` and
`propose_observation` for the separately approved employee tasks; these are not
additional tools or actions granted to the lead itself.

Every plan, employee, and synthesis task needs its own human
`runtime.service.approve(...)`. Parent approval, task materialization, this
guide, and `run(..., authorized=True)` cannot replace the child's persisted
approval. Keep network calls, local/hosted model calls, and provider cost at zero.
Do not fetch a source URI or broaden the supplied-record scope.

## Procedure

1. Obtain this group's `lead-plan:6` through
   `materialize_children(manager_plan_task_id)`. Verify its parent is that
   exact completed manager plan, its group is 6, its employee ID is
   `coordination-lead-6`, and its assignments match only this group's root subset.
   Review code, context, source/input, assignment and parent-receipt bindings,
   then obtain a separate approval and run the lead plan.
2. After the lead plan completes, use
   `materialize_children(lead_plan_task_id)` to create each selected
   `employee:<LABEL>`. The exact parent is this lead plan; each task has this
   group and one preserved discipline assignment. Inspect the native input
   contract, then have each employee separately approved and run.
3. Review all employee statuses, issues, limitations, contradictions, and full
   native products. These are the domain review concerns for the human reviewer:

   Review supplied media/document manifests, measurements, geospatial assertions, hashes, source/lineage records, contradictions, hypothesis matrices, and falsification protocols. Retain record-level support, refutation, uninformative assessments, asserted origins, counterexamples, unknown outcomes, pending tests, and data-quality issues.

   HYPOTHESISINT canonical review recomputes accepted assessments and preserves native ranking/provenance with bounded typed hypotheses and explicit omissions. FALSIFICATIONINT preserves protocol_id and protocol outcomes without inventing a proposition. Measurements, metadata, source scores, and agreement do not establish authenticity or independent origins.
4. Once every required employee has completed, use
   `plan_synthesis(lead_plan_task_id)` for `lead-synthesis:6`. It retains
   this group's lead plan as parent and every selected employee in this group
   as a dependency. Obtain its own approval and run it. Do not omit a failed
   dependency or replace a missing product with a summary.
5. Provide the resulting receipt to the manager's `manager-synthesis`
   dependency set. Preserve the five persisted phases:
   manager-plan -> lead-plan -> employee -> lead-synthesis -> manager-synthesis.
   Do not take over another group's tasks or add an unplanned label.

The root global budget has exact keys `max_tasks`, `max_employees`,
`max_tool_calls`, `max_runtime_seconds`, `model_calls`, and `max_cost`.
E selected employees across G selected groups require E + 2G + 2 tasks. Every
stage consumes its own reserved allocation, bounded by the root totals and the
role cap of 8 tool calls and 120 seconds. Model calls and provider cost remain
zero. Do not enlarge allocations, add automatic retries, or reinterpret an
expired authorization as permission. A newly created child can have its own
fresh deadline within the active authorization without changing its parent.

## Evidence and Provenance

Retain the supplied-input artifact and its hash/acquisition/custody records,
record/source IDs, immutable canonical results and products, exact parent and
dependency receipts, and all omission counts. Synthesis recomputes full
registered native outputs from preserved input; callback artifacts, prose
previews, or claimed approvals cannot replace the trusted derivation.

Each employee receipt previews at most five findings, with explicit truncated
summary/reference indicators and omitted-finding counts. Inspect original
products before substantive review. Propagated canonical hypotheses are bounded
to 100 with explicit omissions; the manager preserves dependency receipts even
when its summary has no finding previews. Only the native HYPOTHESISINT review
projects supplied propositions into canonical hypotheses. FALSIFICATIONINT
protocol outcomes do not create an unsupplied statement.

Agreement by separate employees does not establish independent evidence.
Supplied publisher/origin groups remain assertions; custody hashes establish
preserved bytes, not source authenticity or factual entailment. Do not present
native recomputation as external verification, live collection, or a confidence
upgrade. Preserve unknowns, refutations and unresolved conflicts for the manager.

## Failure and Escalation

Use `describe(coordination_id)` to distinguish incomplete routing,
`BLOCKED_REQUIRES_APPROVAL`, running tasks, `BLOCKED_CHILD_FAILED`, and
`PARTIAL_DRAFT`. A completed employee may still have inadequate data or a
partial analysis. Report those limitations instead of converting completion into
a substantive success claim.

Stop when group/assignment/code/context bindings, parent receipts, custody,
dependency completeness, or budgets fail validation. Escalate to the manager
and human authorization owner; changed records or assignments require a new
plan. Preserve failed inputs and existing products. Do not edit receipts or
reassign another group's evidence to bypass a failure.

Only the authorization owner may call
`cancel(coordination_id, actor_id, authorized=True)`. Cancellation blocks
further coordinated work and cancels unfinished tasks while preserving completed
evidence. The lead cannot approve itself or silently resume a cancelled plan.

## Output and Review

Return the exact group/assignment IDs, phase/task statuses, pending approvals,
reserved-budget status, dependency/product receipts, findings and issue totals,
omission counts, unresolved contradictions, data limitations, and proposed human
follow-up. Keep supplied evidence and review inferences distinct.

The manager can call `replay(coordination_id)` after every stage completes.
Replay verifies `registered_processor_outputs_and_coordination_receipts`
offline, including native draft recomputation and preserved bindings. It does
not authenticate sources or certify independence. Successful replay and
`COMPLETE_DRAFT_REQUIRES_HUMAN_RELEASE` still require human review before any
report release. This lead has no publication or collection authority.
