# Active work

## Current repair checkpoint — 2026-10-04

The previous 329-test pass came from an unsynchronized local checkout and was
incorrectly attributed to merged commit `e2f39d3`; that attribution is withdrawn.
PR #54 merged while a repair was underway. Continued from exact main snapshot
`9d025c27a6d9d92294384df85dcbc3f479dae2ec`: all 678 tracked file contents matched.
This snapshot had duplicate merge fragments in the source registry, FabricStore,
qualification policy and source tests. The repair preserves the new 26-gate
qualification policy, same-case evidence validation and stricter LIVE_TESTED
versus LIVE_VERIFIED distinction. Negative tests cover missing prerequisites,
unresolved reviews, and promotion rejection despite a stale state projection.

Fresh result on that snapshot plus the four repair blobs: 354 tests run,
351 passed, 3 skipped, zero failures; compilation and secret scan pass.
Grouping remains TP=7/FP=0/TN=5/FN=0 on 12 synthetic pairs; temporal contradiction
remains TP=3/FP=0/TN=5/FN=0 on 8 synthetic pairs. These do not measure field accuracy.
Baseline, changed blob IDs and verification metadata are recorded in
`docs/verification/source-registry-merge-repair-2026-10-04.json`.
Branch: `codex/repair-qualification-20261004`. Hosted repair CI/CodeQL pending.
The Enterprise 8/10 objective and representative/live acceptance gates remain open.

# Active work

## Durable execution delivery — 2026-10-04

Branch `codex/durable-workforce-runtime`, baseline `9d025c27a6d9d92294384df85dcbc3f479dae2ec`.
Canonical leases/fences, cancel/recover, durable request accounting, immutable
capture reuse and atomic finalization/outbox are implemented and locally tested.
371 tests run: 370 pass, 1 skip. Browser blocked locally by missing Chromium;
GitHub CI is a separate gate. See `docs/WORKFORCE_EXECUTION.md` and its receipt.
Next: review/CI, model reservations, approved outbox consumer and hosted staging
qualification. Preserve all earlier source/evidence/lineage work below.

## Completed this session: ER-BENCH-001 and ER-SIGNALS-001

- Status: synthetic diagnostic complete; representative identity quality remains OPEN P0.
- Delivered: exact attribute agreement/difference flags; six synthetic company queries and 24 labeled pairs; deterministic evaluator/CLI and saved JSON results; malformed-label, sensitive-field, ranking and denominator tests.
- Measurement: precision 0.80, recall 1.00, F1 0.889, false-positive rate 0.05, recall@1/3 1.00. One namesake candidate was flagged at 0.7258; no merge was attempted.
- Limitation: synthetic data is not representative; the false-merge denominator is zero. Do not use the score as a probability or operational quality estimate.
- Next: ER-EVAL-002 requires an approved privacy-reviewed adjudication set and pre-registered thresholds; it cannot be completed with fabricated or public-person data.

## Current slice: EVIDENCE-004 anchoring path

- Added `src/traceatlas/evidence_anchor.py` with a `LedgerAnchor` contract and an opt-in `HmacFileLedgerAnchor`; `EvidenceStore` can require an external checkpoint, anchor ledger heads, embed receipts in bundles, and verify anchored exports.
- Added `docs/EVIDENCE_ANCHORING.md`, focused tests and expanded the synthetic evaluator from 9 to 14 cases.
- 13/14 expected outcomes match; 8/9 invalid cases reject. The opt-in HMAC adapter blocks the tested full local rewrite while key and receipt stay outside the attacker boundary. The legacy unanchored path still accepts that rewrite, so EVIDENCE-001 stays OPEN and the benchmark status is **FAIL**.
- This file adapter cannot prevent rollback of an old receipt, concurrent writers or operator-key service failures. No key manager, append-only remote service, immutable storage or hosted replay was tested.
- Citation evaluation verifies ID membership only, not semantic support. Next: implement and validate a monotonic remote anchor provider and wire authorized application paths to required anchoring; obtain reviewed citation labels before claiming citation accuracy.

## Session rules

Read `.ai/CURRENT_STATE.md`, `.ai/TASKS.md`, `.ai/KNOWN_ISSUES.md`, and the
active `docs/program/` ledger before extending this slice. Update current state,
tasks, gap register, evaluation results and implementation ledger after changes.



## Current slice: LINEAGE-005 synthetic diagnostic

- Added a deterministic 12-pair synthetic evaluator for source-origin grouping, covering declared upstreams, reviewed ownership, copies, canonical URLs and independent sources sharing one hostname.
- The benchmark exposed that hostname equality could merge separate tenants. Removed hostname-only merging; publisher grouping now requires explicit ownership metadata. Updated the same-publisher regression case to provide reviewed ownership.
- Evaluator tests 3/3; grouping benchmark 12 pairs TP=7/FP=0/TN=5/FN=0; temporal contradiction benchmark 8 pairs TP=3/FP=0/TN=5/FN=0. Pipeline tests 28 run, 27 pass, 1 skip; AI workforce tests 13/13.
- Full Python suite: 329 run, 323 pass, 3 skip, 3 fail (all known OpenCTI checkout failures); loopback-console tests passed in the full run. Secret scan, compileall and `git diff --check` passed.
- LINEAGE-005 remains OPEN: synthetic metrics do not estimate representative lineage quality or contradiction recall. Next: obtain approved curated labels and resolve the OpenCTI checkout prerequisite.

- Remote code commit: `e9d1745790a2c4f42dedd08ffbf1dc0429690686` pushed to `codex/source-maturity-taxonomy`; current state/ledger follow-up is being recorded.
## Work item TA-P0-001 — repair source maturity merge regression

- Baseline: `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`
- Severity: P0; baseline CI cannot compile the application.
- Cause: malformed `SourceManifest.to_dict`, duplicate keyword arguments,
  duplicate registry constants, and unreachable conflicting qualification code.
- Change: restore a single canonical lifecycle vocabulary and shared 23-gate
  policy; require bounded, printable evidence references; keep proposed
  transitions non-persistent and keep actual qualification in FabricStore.
- Focused check: `python -m unittest discover -s tests -p test_source_fabric.py -q`
  — 26 run, 25 pass, 1 optional MCP SDK test skipped.
- Local CI-equivalent compile, full Python suite, secret scan, Node graph,
  database, browser, research integrity, benchmark, 78-case fixture golden,
  local restore drill and pinned OpenCTI snapshot verification pass. Docker is
  unavailable locally. Final diff review is complete. PR #49 code/test head
  `1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI `37184302223` and
  CodeQL `37184302217`, including hosted worker-image verification.

## Work item TA-003 — resolve qualification review evidence references

- PR #49 source maturity repair and program ledgers passed hosted CI and CodeQL.
- Tightened Source Fabric state calculation and promotion so every review hash
  resolves to evidence recorded in the same case; promotion also verifies that
  case's custody ledger. Legacy/direct database rows with unresolved hashes no
  longer qualify.
- Added tests for explicit authorization, missing refs, cross-case refs,
  valid refs, and unresolved legacy rows at promotion.
- Local result: 28 Source Fabric tests pass (one optional SDK skip); full Python
  suite 315 tests pass with three skips; secret scan clean.
- Published as PR #50, stacked on PR #49. Hosted CI `37185114010` and CodeQL
  `37185114003` both passed, including worker-image and locked MCP checks.
- Do not merge either PR without the user's request.

After TA-003 is reviewed, move to semantic evidence replay. Do not start broad
SOCMINT connector expansion until source terms, access permission, evidence
flow and testable API contracts are established.

## Latest validation checkpoint — 2026-10-04

- Full Python suite passed: 329 run, 326 passed, 3 skipped, 0 failures. OpenCTI-focused tests passed 7/7 against the pinned connector checkout.
- Next high-value unblocked work remains evidence integrity with a rollback-safe independent anchor and representative authorized evaluation labels. Do not claim 8/10 until the scorecard and mandatory gates have measured evidence.


## Verified merge repair follow-up — 2026-10-05

PR #56 was merged as `5ad16f01d4e3916dc6f40591c8fcbef2c14c88b8`. Its tree
`ed5a421db97250eadea5e32910c299b871035ac7` equals the downloaded `03fdfd84`
snapshot. A subsequent merge had reintroduced duplicate registry gate definitions,
a malformed conditional and duplicate test fragments. The follow-up changes only
`src/traceatlas/workforce/source_registry.py` and `tests/test_source_fabric.py`
in executable code. Durable workforce runtime and all 26 qualification gates remain.
Negative tests retain unresolved terms, unresolved operational-owner evidence and
stale-state promotion checks.

Full local suite: **372 run, 369 passed, 3 skipped, zero failures** (88.957 seconds).
Compilation of src/tests/api/scripts/vercel_control.py passes; secret scan is clean.
Exact baseline, changed Git blob hashes and test-output hash are recorded in
`docs/verification/source-qualification-followup-2026-10-05.json`.
Earlier 329-test attribution to merged code remains withdrawn. The previous
synthetic benchmark record remains 12 lineage pairs (TP7/FP0/TN5/FN0) and 8
temporal pairs (TP3/FP0/TN5/FN0); these are not field-accuracy measurements.
Hosted checks are pending publication of this follow-up. Enterprise 8/10,
representative evaluation and live-source qualification remain open.
