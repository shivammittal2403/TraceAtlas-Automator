# Implementation ledger

## Qualification receipt and merge repair — 2026-10-05

Current checked base: `f30ba40a6dd51978c2072391081b8d159c16014a`; branch `codex/qualification-receipts-20261005`; version `1.11.0`.
CODED and locally TESTED: typed source/check/case/actor/runtime review receipts,
supporting-artifact and custody resolution, expiry/code binding, captured dispatch
code/runtime identity, cache partitioning, failed-review supersession and explicit
promotion bound to the exact receipt set. Unrelated artifact acceptance: 26/26
before, 0/26 after; synthetic false production promotion now rejects.

Current main integration had three registry copies, three shadowing source-test
classes and overlapping gateway authority/fetch code. Consolidated them while
preserving every distinct test, shared 26-gate policy, ConnectorFactory, request
revocation/retry/RDAP checks, semantic replay and custody anchoring. Added a
regression that detects duplicate critical definitions and hidden tests.

Actual final local verification: 439 Python run / 436 pass / 3 optional skips;
Node graph/target 25/25; PGlite 1/1; browser fixture flow, compileall, secret scan
and diff checks PASS. Controlled packs: core 12/12, source 78/78, enterprise
112/112 (105 drafts/replays, seven scope rejects). These are synthetic contracts,
not representative field accuracy. No live source/model request or source
promotion; 0 live-verified / 0 production-qualified in this clean audit workspace.
51 registered metadata sources / 37 coded shared API adapters; neither is a
qualified integration count. Enterprise category/weighted scores NOT ESTABLISHED.
Hosted CI/CodeQL on this proposed branch are a separate pending gate.

The full employee/platform objective remains active. Next: raw-to-normalized
replay; independently governed reviewers/source-specific assertions; IAM and
retention; representative ER/SOCMINT/multilingual evaluation; official India
source research and qualification. Staging, entitlements, approved expert labels
and independent security review need actual operator inputs. Other engineering
is OPEN, not bulk-blocked. See `docs/SOURCE_REVIEW_RECEIPTS.md`,
`docs/program/SESSION_REPORT_2026-10-05_RECEIPTS.md` and the hash-bound receipt
`docs/verification/source-review-receipts-2026-10-05.json`.

Earlier checkpoints below are historical and do not certify the current tree.

## Semantic employee integration — 2026-10-05

Base: `5ad16f01d4e3916dc6f40591c8fcbef2c14c88b8`; branch:
`codex/semantic-employee-integration`. This integration preserves the latest
source portfolio, 26-gate qualification policy, external HMAC anchor option,
entity/lineage/contradiction diagnostics and durable workforce execution.

CODED: captured provider/structured fact recomputation; normalized-record
employee semantic replay; request-level Fabric revocation and kill checks;
evidence-linked knowledge states and human review priorities; bounded console
framing; idempotent evidence import; 112 synthetic investigation contracts.
Durable leases, cumulative reservations, immutable capture recovery and atomic
completion/outbox are preserved, with semantic replay applied to recovery.

Merged registry/test fragments are repaired without weakening source authority.
TESTED locally: Python 388 run / 385 passed / 3 skipped (173.397 seconds);
112/112 contracts, 105 draft replays and seven pre-capture scope rejects;
Node graph/PGlite 26/26, browser flow, compilation and secret scan PASS. Proposed-head CI/CodeQL
remain a separate required gate. See
`docs/program/SESSION_REPORT_2026-10-04.md` and `docs/REPLAY.md`.

No live provider/model request, source promotion, main merge or deployment was
performed. Production-qualified sources: 0. Enterprise score: NOT ESTABLISHED.
Remaining engineering is OPEN: receipt semantics, raw-to-redacted replay,
representative identity/SOCMINT/multilingual coverage, IAM/retention, distributed
quotas and observability. Source rights/entitlements, authorized expert labels,
independent security review and staging access require actual operator inputs.
The unanchored full-local-rewrite weakness remains open; optional file HMAC
anchoring is not an independently operated, rollback-safe anchor.

Historical checkpoints below retain their original scope and limitations.



## Runtime development — 2026-10-04

Baseline `9d025c27a6d9d92294384df85dcbc3f479dae2ec`; branch
`codex/durable-workforce-runtime`. Implements canonical local attempt leases,
fenced finalization, cancellation/recovery, cumulative request/spend reservations,
capture resume and transactional completion outbox. Repairs baseline merge syntax
regressions without relaxing qualification evidence. Local tests: 371 run,
370 passed, 1 skip; runtime 18/18; graph 25/25; PGlite 1/1; source fixtures 78/78;
golden pipeline, compilation, secret scan and wheel build pass. Browser launch
blocked by absent Chromium. No new live-source/hosted proof or 10/10 claim.
Details: `../WORKFORCE_EXECUTION.md`, `../verification/workforce-runtime-2026-10-04.json`.

| Date | Commit / state | Work | Verification | Outcome / remaining gap |
|---|---|---|---|---|
| 2026-10-04 | GitHub program branch `83f13df9a8f043f7e4a2536d7d0a26ae674bcc30`; local equivalent tree at `9a20b7f16980049380722602c0868f7958d86e4e` | Unified source maturity vocabulary, conservative qualification gates, deterministic target-bound investigation plan. | Prior session: focused Source Fabric, employee Source Fabric, Node graph/target, compile, secret and whitespace checks. Full suite had OpenCTI checkout failures. | CODED and locally tested; not live-source-qualified; remote branch CI not rechecked here. |
| 2026-10-04 | Baseline for ER-BENCH-001 | Read repo rules, current-state, acceptance, audit, gap, security, source maturity, entity resolution and golden investigations. | 310 Python tests (304 pass, 3 skip, 3 OpenCTI prerequisite failures); Node 25/25 after environment fix; compile/secret/diff checks pass. | Establish synthetic ER benchmark next; operational accuracy remains unknown. |
| 2026-10-04 | GitHub commit `50c774ac263ba7cb1ffe4262fd2bc3cbe2ee70fd` on `codex/source-maturity-taxonomy` | Added exact agreement/difference signals; synthetic ER benchmark/evaluator/CLI and JSON report; created persistent enterprise scorecard and ledgers. | 8 focused ER/resolution tests pass; full suite: 317 run, 311 pass, 3 skipped, 3 OpenCTI prerequisite failures; Node graph/target 25/25 when exact Python path is set; PGlite 1/1; employee UI check pass; compile/secret checks pass. | Synthetic pair precision .80 / recall 1.00; one false-positive candidate is visible and remains analyst-reviewed. Operational ER, false-merge rate and overall maturity stay unmeasured. |
| 2026-10-04 | Code/evaluation commit `d0c21249d813c88cffe8b0316067608866a112bc`; current-state repair `bacf5bbdb62036cbb389210dcbe48778d477da87` | Added nine-case synthetic EvidenceStore/bundle/citation guard evaluator, CLI, focused tests and captured JSON result; updated state and gap records. | Focused tests 2/2 pass; full suite 319 run / 313 pass / 3 skip / 3 known OpenCTI prerequisite failures; benchmark exact-outcome 8/9, invalid-case rejection 5/6; compile, secret scan and diff check pass. | A local full-store rewrite is accepted without an independent anchor; EVIDENCE-001 remains OPEN and benchmark status is FAIL. Semantic citation accuracy and external storage/anchor are unverified. |
| 2026-10-04 | GitHub commit `b47c331327ae50679a10b59b870c11df86c6342b` on `codex/source-maturity-taxonomy` | Added HMAC-backed `LedgerAnchor`, external-receipt bundle support, environment wiring across `EvidenceStore` call sites, reviewed migration bootstrap and anchoring runbook; expanded evaluation to 14 cases. | Focused evidence/anchor/bundle tests 16/16 pass; full suite 326 run / 320 pass / 3 skip / 3 known OpenCTI prerequisite failures; evaluator 13/14 exact outcomes, 8/9 invalid cases rejected; compile, secret scan and diff check pass. | HMAC mode blocks the tested rewrite under key/receipt separation; unanchored legacy default still accepts it. File adapter lacks rollback-safe freshness and production key-manager/immutable-store verification; EVIDENCE-001 remains OPEN. |

| 2026-10-04 | GitHub commit `7fa0431c5229ac14dbb2da8b657de6d8a2734749` on `codex/source-maturity-taxonomy` | Removed hostname-only source grouping, retained reviewed ownership grouping, and added a 12-pair synthetic evaluator/report. | Evaluator tests 2/2; pair metrics TP=7/FP=0/TN=5/FN=0; pipeline 28 run / 27 passed / 1 skipped; AI workforce 13/13; full Python suite 328 run / 321 passed / 3 skipped / 4 failed (3 OpenCTI prerequisite failures plus one Windows loopback-console abort); compileall and diff check passed. | Synthetic diagnostic only; representative lineage, contradiction recall and full-suite loopback failure did not reproduce in isolation (2/2 console tests pass); root cause remains unknown. |

| 2026-10-04 | GitHub commit `e9d1745790a2c4f42dedd08ffbf1dc0429690686` on `codex/source-maturity-taxonomy` | Extracted the pipeline's temporal contradiction predicate into a shared helper and added eight labeled synthetic conflict/non-conflict pairs to the lineage report. | Evaluator 3/3; grouping pairs TP=7/FP=0/TN=5/FN=0; contradiction pairs TP=3/FP=0/TN=5/FN=0; pipeline 28 run / 27 passed / 1 skipped; AI workforce 13/13; full suite 329 run / 323 passed / 3 skipped / 3 known OpenCTI prerequisite failures; secret scan, compileall and diff check passed. | Synthetic results do not establish representative lineage or contradiction quality. LINEAGE-005 remains open; the full suite failures are due to the incomplete OpenCTI submodule. |

Add each accepted change with commit SHA, test evidence, actual metrics and known
limitations. Separate CODED, TESTED, LIVE_VERIFIED and DEPLOYED.

| Date | Baseline/change | Work | Verification | State |
|---|---|---|---|---|
| 2026-10-04 | Main `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`; PR #49 code/test head `1767708adc27e9dc05e0384a4682571e3797d6c4` | Repaired source-registry and workforce CLI syntax; unified maturity gates; bounded qualification refs; added persistent program state | Python 313 (310 pass, 3 skip); compile/secret scan; graph 25/25; PGlite 1/1; UI browser pass; golden 78/78; restore and integrity checks; hosted CI `37184302223` and CodeQL `37184302217` pass | P0 repair verified; PR open; overall release remains NOT READY |
| 2026-10-04 | PR #50 head `d9c7965e98ba3e26e123fe33c266c97be7b591b8`, stacked on PR #49 | TA-003: resolve qualification-review hashes to immutable same-case EvidenceStore records during state reporting and promotion; reject unresolved legacy/direct DB rows | Focused Source Fabric 28 (27 pass, 1 optional skip); full Python 315 (312 pass, 3 skip); compileall and secret scan pass; hosted CI `37185114010` and CodeQL `37185114003` pass | PR open; TA-003 checks verified |

Update this ledger with final PR SHA and CI run before closing TA-001/TA-002.
| 2026-10-04 | Earlier unsynchronized checkout; merged-revision attribution withdrawn | Restored the pinned OpenCTI submodule's 15 deep-path test files from their exact Git blobs using Windows extended paths; left the superproject gitlink unchanged. | OpenCTI-focused tests 7/7; full Python suite 329 run / 326 pass / 3 skip / 0 failures. Two sampled restored file hashes equal their pinned blob IDs. | Local Git for Windows cannot enumerate the two deep directories and may show false deletions. Maturity score and release gates remain open. |

## Exact-snapshot merge repair

| Date | Baseline / changes | Verification | Remaining |
|---|---|---|---|
| 2026-10-04 | Main 9d025c snapshot plus four repair blobs in verification JSON | 354 run / 351 pass / 3 skip; compileall and secret scan pass; lineage 12 pairs and contradictions 8 pairs pass | Hosted repair CI/CodeQL pending; enterprise gates open |


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


## EVIDENCE-005: bundle binding and erased-history rejection — 2026-10-05

Baseline: PR #57 `46cdafdfb3264117edafa2f6df6a38b3f855182b`; its CI and
CodeQL passed. New master objective read from the 2026-10-05 attachment;
source-volume targets are targets only.

Three reproduced P0 integrity gaps: payload and provenance could be rewritten
in an anchored export while reusing its signed head; deleting both local ledger
and index bypassed the external checkpoint check. Bundle v2 now replays the
custody chain and binds exact digests/observations to the signed head. Empty
local histories consult the external anchor and fail closed on outage. Legacy
unanchored v1 is readable; anchored v1 requires re-export.

Expanded identical 18-case synthetic corpus: baseline 14/18, repair 17/18.
Invalid-case rejection improves from 9/13 to 12/13. The unanchored full-rewrite
case still fails, intentionally disclosed; EVIDENCE-001 remains OPEN. Full
suite before two additional compatibility tests: 376 run, 373 pass, 3 skip;
compilation and secret scan pass. Final exact-head hosted checks are separate.
Report: `docs/verification/evidence-integrity-2026-10-05.json`.

Remaining external dependencies: independently protected monotonic anchor,
operator-owned staging, source credentials/terms, representative reviewed labels.
No live source was contacted and no source was promoted. Overall 8/10 remains
NOT ESTABLISHED. Continue next with governed representative-evaluation intake
and metric denominators, rather than claiming fixture performance as field quality.
