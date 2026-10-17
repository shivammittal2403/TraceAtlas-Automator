# Approved supplied-record coordination

The opt-in coordinator uses the existing workforce task, approval, execution,
evidence and product stores. It adds one coordination manager and ten team leads
from the native taxonomy. The five default workforce roles and 140 native
processors retain their existing definitions. These roles execute deterministic
local planning and synthesis; they do not call a model or collect live sources.

## Persisted phases and authority

A coordination input names an objective, an explicit `as_of`, shared supplied
sources, unique discipline assignments with actual native records, and a global
budget. The manager validates that manifest. Running its approved plan permits
creation of planned domain lead tasks. Each approved lead plan permits creation
of its assigned native employee tasks. Completed employee products feed a
separately approved lead synthesis, then a separately approved manager synthesis.

Every stage has its own immutable task digest and owner approval. Planning a
child never approves it. The coordinator does not run a workflow unattended:
the operator approves each stage and explicitly executes it. Existing offline
`team` and planning-only `manager` commands remain available with their prior
contracts.

The context must explicitly permit `coordination.plan`,
`coordination.synthesize` and `discipline.analyze`, plus `propose_plan`,
`propose_synthesis`, `route_task` and `propose_observation`. The dedicated
`authorize --coordination` option grants these local capabilities in a new
registered context. It does not change an existing context or grant external
source authority.

The hierarchy is bound to the complete registered context, scope, policy, owner,
taxonomy/source identity, root assignment manifest, frozen task IDs, budgets,
parent receipts and exact dependency set. Supplied input cannot create its own
canonical evidence IDs. Unbound children of a coordinated parent fail closed.
The generic workforce lifecycle also checks the actual owner approval receipt
before dispatch and again inside the final completion transaction, reading the
current authorization rather than trusting a mutable approved status.

## Global budgets and recovery

The expected task count is `employees + 2 * participating_groups + 2`.
Global input fields are `max_tasks`, `max_employees`, `max_tool_calls`,
`max_runtime_seconds`, `model_calls` and `max_cost`. Model calls and provider
cost must both be zero. Each task conservatively reserves its full fixed tool
and runtime allocation before materialization. Total reservations cannot exceed
the approved global limits. Existing attempt and request reservations continue
to govern retries; a recovery does not replenish a task budget.

Slots and their immutable creation descriptors are durable before capture.
A bounded creation lease serializes retries. The same task, source, trace,
capture timestamp and envelope are reused after an interrupted creation; a
conflicting descriptor or capture is rejected. An active creation lease must
expire before another process can recover an abandoned creation. A failed
execution remains visible and uses the existing owner-authorized `recover`
flow. Cancellation marks the whole coordination and stops pending execution.
Completion rechecks parent/coordination state inside the canonical transaction.

Completed parent task deadlines need not remain current for later stages.
The registered authorization and each stage's own active deadline still apply.

## Evidence and synthesis

Native products preserve full draft findings, input records and their captured
artifact. Synthesis independently invokes the registered native dispatcher from
those preserved inputs and compares the draft and typed observations.
HYPOTHESISINT/FALSIFICATIONINT canonical review projections are recomputed too.
Control summaries are deterministically derived from exact dependency receipts;
a matching rewritten product hash alone cannot establish verified semantics.

Summaries retain task/product/result hashes, child traces and bounded finding
previews with explicit omitted counts. They preserve full original child
products rather than copying every finding into each parent. Parent observations
describe what a child reported and cite the preserved receipt input. Any carried
canonical hypotheses retain their original evidence references; their 100-entry
bound has an explicit omission count.

Shared source IDs, copied records, separate tasks and agreeing employees do not
establish independent origins or source authenticity. Synthesis does not grant
factual entailment, identity attribution or report-release authority. Native
partial/invalid analysis remains distinguishable from execution completion.
A final partial summary is labelled `PARTIAL_DRAFT`; a complete workflow
remains `COMPLETE_DRAFT_REQUIRES_HUMAN_RELEASE`.

## Installed role procedures

Each coordinator role has a separate packaged Markdown procedure under
`src/traceatlas/skills/coordination/`. `coordinate-skills` validates all eleven
role/scope metadata records, and `coordinate-skill coordination-lead-4` displays
one inert guide. The guides name the native taxonomy disciplines and actual
approved phases. Reading a guide grants no execution authority.

## Commands

Create a case, then register a new context with explicit coordination authority:

```text
traceatlas-employees --workspace PATH case --case CASE --title TITLE --purpose PURPOSE
traceatlas-employees --workspace PATH authorize --case CASE --actor ACTOR --purpose PURPOSE --jurisdiction IN --coordination --authorized
traceatlas-employees --workspace PATH coordinate-plan --context CONTEXT --input INPUT.json
```

For each returned task, inspect its envelope and approve its exact digest using
the existing `approve --task TASK --actor ACTOR --envelope-digest DIGEST
--rationale TEXT --authorized` command. Then execute `run --task TASK
--authorized`. Coordinated tasks are routed to their corresponding local
control or native runtime.

After a manager or lead plan completes, `coordinate-expand --task PLAN_TASK`
returns its separately approved child tasks. Once the assigned dependencies
complete, `coordinate-synthesize --task PLAN_TASK` creates that plan's
separately approved synthesis task. Use the original manager plan for the final
manager synthesis after all lead syntheses complete.

```text
traceatlas-employees --workspace PATH coordinate-show --coordination COORDINATION
traceatlas-employees --workspace PATH coordinate-replay --coordination COORDINATION
traceatlas-employees --workspace PATH coordinate-cancel --coordination COORDINATION --actor ACTOR --authorized
```

Replay requires every workflow stage to be completed and checks custody,
acquisition/trace bindings, approved descriptors, deterministic native outputs
and derived control receipts without external calls. Its verification scope is
registered processor output and coordination receipts, not real-world truth.

## Earlier native-review compatibility

Completed native v2 reviews from pinned commit
`8a3228703747777623db876826d3d5921030ace8` retain their exact stored products.
An explicit adapter accepts only that runtime's LF/CRLF source hashes, combined
with the unchanged current native processor and review-helper identities.
Dispatch always requires current source identity; replay compatibility never
authorizes an old pending engine. The native identity also binds the Python
patch version, so this adapter is not general interpreter portability.

CI creates genuine HYPOTHESISINT and FALSIFICATIONINT products using the pinned
old runtime in a separate process, then verifies canonical reviews with the
current runtime while checking unchanged database rows, product/result JSON,
artifacts and custody ledger bytes. Existing genuine pipeline 1.4 compatibility
checks remain.

Local execution is unavailable while Windows sandbox startup fails. Hosted
checks on the proposed exact head provide execution evidence. The external
master prompt/catalog remain unread; exact minimum-requirement compliance,
live-provider qualification, representative evaluation and security triage
remain open.
