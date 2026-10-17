---
id: coordination-manager
employee_id: coordination-manager
version: 1.0.0
role: manager
execution_mode: supplied_record_coordination
live_verified: false
domain_group: ALL
---

# Coordination Manager

## Purpose and Selection

Coordinate the explicit supplied-record assignments in one authorized case through
`CoordinationService`. This role validates a declared investigation workflow and
derives evidence-bound summaries. The current processor is deterministic: this
Markdown is an operational guide, not executable authority or a model-generated
investigation plan.

Delegate by the ten groups in `traceatlas.osint_taxonomy`, not by the eleven
native implementation files:

- Group 1: DISCOVERY / OSINT; lead `coordination-lead-1`.
- Group 2: HUMAN / SOCIAL / INFORMATION; lead `coordination-lead-2`.
- Group 3: CYBER / THREAT; lead `coordination-lead-3`.
- Group 4: NETWORK / INFRASTRUCTURE; lead `coordination-lead-4`.
- Group 5: SOFTWARE / ENGINEERING; lead `coordination-lead-5`.
- Group 6: MEDIA / EVIDENCE / VERIFICATION; lead `coordination-lead-6`.
- Group 7: CORPORATE / ECONOMIC; lead `coordination-lead-7`.
- Group 8: FRAUD / EXPOSURE; lead `coordination-lead-8`.
- Group 9: SUPPLY CHAIN / TRANSPORT; lead `coordination-lead-9`.
- Group 10: RESEARCH / GOVERNMENT / POLICY; lead `coordination-lead-10`.

Only explicitly selected disciplines are assigned. The taxonomy contains 139
disciplines plus the umbrella OSINT label; this workflow does not create new
collectors or establish compliance with an unread external specification.

## Inputs and Preconditions

Require a current authorization context, matching case and owner, enabled
workforce execution, and an explicit `objective`, timezone-aware `as_of`,
`sources`, `assignments`, and `budget`. Optional `case_id` must match the
authorization. Each assignment names one unique registered discipline, its
`records`, and optional `parameters`; group membership is derived by the code.

Sources require `source_id` and `uri`. Records require `record_id`,
`source_id`, and object `data`, with optional `observed_at`. Every record
references a declared source. Reusing a record ID across assignments requires
identical record content. Consult each native procedure and recipe for the
discipline-specific data fields; a valid shared envelope alone does not establish
adequate domain data. Canonical evidence and approval authority are runtime-owned.

## Scope and Permissions

Require the exact scope `provided_records:<case_id>`. The context must explicitly
permit `coordination.plan`, `coordination.synthesize`, and
`discipline.analyze`, and the actions `propose_plan`, `propose_synthesis`,
`route_task`, and `propose_observation`. The manager's own registry authority is
only the first two tools and `propose_plan`, `propose_synthesis`, and
`route_task`; native analysis belongs to separately approved employee tasks.

Do not browse, probe, fetch source URLs, run external commands, contact people,
or call a local or hosted model through this role. Model calls and provider cost
are zero. Neither this guide nor a completed parent plan grants child execution
authority. Every task requires its own human `runtime.service.approve(...)`;
`run(..., authorized=True)` also requires that persisted approval.

## Procedure

1. Use `plan(context_id, payload)` to preserve the immutable root and materialize
   the `manager-plan` task. Inspect its manifest, sources, exact assignments,
   policy, code identity, and global budget. Obtain its separate approval, then
   run that task. `PLAN_VALIDATED` records validation of supplied assignments.
2. After the manager plan completes, use `materialize_children(manager_task_id)`
   to create the selected `lead-plan:<group>` tasks. Each has the manager plan
   as parent and the exact group assignment. Approve and run each lead plan.
3. Use `materialize_children(lead_plan_task_id)` for that group's employee
   tasks. Each `employee:<LABEL>` has its own lead plan as parent and exactly
   one preserved assignment. Approve and run every employee separately.
4. After a group's employees complete, call
   `plan_synthesis(lead_plan_task_id)`. Its `lead-synthesis:<group>` retains
   the lead plan as parent and all of that group's employee receipts as
   dependencies. Obtain a new approval and run it.
5. After every selected lead synthesis completes, call
   `plan_synthesis(manager_plan_task_id)`. The `manager-synthesis` task retains
   the manager plan as parent and all selected lead synthesis receipts as
   dependencies. Approve it separately, run it, and inspect `describe(id)`.
6. Treat the five persisted phases as distinct tasks:
   manager-plan -> lead-plan -> employee -> lead-synthesis -> manager-synthesis.
   Preserve the case, context-owner/policy, code, root, input, group, assignment,
   parent receipt, and dependency digests. Changed inputs require a new plan.

Declare the global keys `max_tasks`, `max_employees`, `max_tool_calls`,
`max_runtime_seconds`, `model_calls`, and `max_cost`. For E selected
employees and G selected groups, reserve E + 2G + 2 tasks, covering every phase.
Per-task allocations remain within the declared global reservations and the
registry cap of 8 tool calls and 120 seconds. Do not enlarge a task allocation,
add unplanned employees, or retry outside the ledger. A new child may receive a
fresh deadline within the active authorization; this does not extend its parent.

## Evidence and Provenance

Keep the preserved input artifacts, acquisition and custody records, source and
record IDs, immutable child products, canonical results, and exact receipts.
Synthesis independently recomputes registered native drafts from preserved
inputs, including canonical review for HYPOTHESISINT and FALSIFICATIONINT.
Callback-produced artifacts cannot substitute for that recomputation.

Inspect full child products when evaluating support, contradictions, unknowns,
and missing tests. Each employee receipt previews at most five findings with
explicit truncation and omission counts; manager summaries can carry no finding
previews while preserving their original product receipts. Propagated canonical
hypotheses are capped at 100 with an omission count. FALSIFICATIONINT protocol
outcomes alone do not supply a new proposition.

Distinct employee outputs and repeated agreement do not prove independent
sources. Supplied origin/publisher assertions, source authenticity, factual
entailment, and source independence remain unverified. Replay establishes
registered processor outputs and coordination receipt consistency; it cannot
establish that supplied assertions describe the world accurately.

## Failure and Escalation

Use `describe(id)` to distinguish missing approvals, routing still required,
running work, failed/cancelled children, and partial analysis. Stop synthesis
when required dependencies or bindings fail. Keep inadequate or malformed input,
unknown protocol outcomes, contradictions, and omission counts visible; task
completion does not mean the data were sufficient.

Report `BLOCKED_REQUIRES_APPROVAL`, `BLOCKED_CHILD_FAILED`, or
`PARTIAL_DRAFT` as applicable. Escalate policy, code identity, custody,
assignment, budget, or receipt mismatches for human review. Do not edit stored
products to make a failed comparison pass. Only the authorization owner can use
`cancel(id, actor_id, authorized=True)`; cancellation blocks further work and
preserves completed evidence.

## Output and Review

Return the coordination ID, task and phase statuses, pending approval IDs,
reservations, receipt references, findings/issues totals, omitted content, data
limitations, and recommended human follow-up. Carry competing supplied
hypotheses and counterevidence through their canonical IDs without inventing
statements, source independence, or confidence.

For a fully completed workflow use `replay(id)` and inspect its semantic scope
`registered_processor_outputs_and_coordination_receipts`. Review full native
products and source assertions before release. Even
`COMPLETE_DRAFT_REQUIRES_HUMAN_RELEASE` and successful offline replay remain
draft outcomes requiring human review; this role has no publishing authority.
