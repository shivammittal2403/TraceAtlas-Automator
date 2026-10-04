# Local workforce execution runtime v1

Developed against main `9d025c27a6d9d92294384df85dcbc3f479dae2ec` on 2026-10-04.
Reuses the canonical workforce, existing case SQLite DB and EvidenceStore.

## Operations

The authorize → plan → approve → run → report/replay flow is preserved.
`workforce show --task TASK` includes attempt generation/lease, cumulative
requests, accounted USD, unsettled charges, checkpoints and completion events.
Internal attempt tokens are not exposed in the response.

```sh
traceatlas workforce cancel --task TASK --actor OWNER --authorized
traceatlas workforce recover --task TASK --actor OWNER --authorized
traceatlas workforce run --task TASK --live --authorized
```

Cancellation requires the registered authorization owner. It stops new dispatch
and canonical completion; an already sent request cannot be retracted. Explicit
recovery accepts only failed or expired-lease tasks, rechecks authority and keeps
the original budget, request count and absolute runtime deadline. An expired
runtime requires a new approved task. Cancelled/completed tasks cannot recover.

## Guarantees and boundaries

* Claim is atomic and issues a unique attempt token. Dispatch and finalization
  require the current lease; stale failure cannot fail a replacement worker.
* Request slots and micro-USD ceilings reserve atomically before transport.
  Timeouts and paid responses without billing receipts remain uncertain and
  retain their ceiling. Free successful responses settle at zero. The internal
  settlement API accepts trusted receipts; no automatic provider reconciliation
  or model-call reservation is implemented.
* Immutable checkpoints cite captured evidence. Recovery validates task, case,
  source, target and byte integrity before reusing a capture without another
  network request. Captured empty results also remain historical records;
  refreshing them requires a new task.
* Product, result, observations, lineage/verification indexes, terminal state
  and local completion outbox event commit together. Exact winning-attempt
  retransmission is idempotent; conflicting duplicate completion is rejected.
* Filesystem capture/custody precedes completion. Crashes can leave preserved
  artifacts without a completed product. These are retained for audit. Neither
  filesystem capture nor remote API execution is exactly-once. Health/cache
  telemetry is auxiliary, not a canonical completed result.
* The outbox records completion locally; no external publisher is enabled.
  Distributed quotas, hosted tenant isolation, delivery workers, real billing,
  hosted restoration and independent operational qualification remain open.

## Schema compatibility

Four additive tables initialize idempotently: `workforce_attempts`,
`workforce_request_budget`, `workforce_checkpoints`, `workforce_outbox`.
No existing evidence or task schema is removed; no hosted migration is applied.
Back up the case database and evidence before upgrade. Completed legacy products
remain readable. Legacy running jobs without attempt metadata cannot recover
through this protocol: inspect them and create a fresh approved task.

Before downgrade, stop scheduling and drain/cancel in-flight tasks. Preserve
new tables and evidence; deleting reservations is not a safe rollback. Older
executables do not enforce the new fences.

## Local verification

18 runtime tests exercise real isolated SQLite connections, claim/spend races,
stale attempts, cancellation, deadline exhaustion, ambiguous charges, retries,
exact/conflicting finalization, each final insert and terminal-state failure,
capture recovery/replay, evidence/checkpoint tampering and schema initialization.
Provider responses are synthetic; these tests do not qualify a live source.

The fresh main baseline also contained malformed merged statements in workforce
source registry, qualification store and its test. Those import blockers are
repaired while preserving same-case evidence requirements. The negative test
now checks both unresolved terms (blocks LIVE_VERIFIED) and unresolved operational
owner (blocks PRODUCTION_QUALIFIED), instead of expecting an invalid terms
receipt to qualify.

Exact local results: `docs/verification/workforce-runtime-2026-10-04.json`.
The 650-source target, broader media/social/planning work and enterprise parity
remain incomplete. No maturity score or live/production promotion is awarded.
