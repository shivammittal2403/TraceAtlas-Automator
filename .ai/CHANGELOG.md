# Program changelog

## 2026-10-04 — Temporal contradiction diagnostic

- Extracted registered single-value, same-subject, differing-value, overlapping-valid-time logic into `workforce/contradictions.py` and reused it from the investigation pipeline.
- Added eight synthetic temporal conflict/non-conflict pairs to the source lineage report: TP=3, FP=0, TN=5, FN=0. This is a unit-level diagnostic, not representative recall.
- Focused evaluator tests pass 3/3; pipeline tests pass 27 with 1 skipped; full suite runs 329 with 323 passing, 3 skipped and 3 OpenCTI submodule failures.


## 2026-10-04 — Source independence diagnostic

- Added a 12-pair synthetic source grouping benchmark and JSON report. The initial hostname heuristic caused a false merge for separate tenants sharing one host.
- Removed hostname equality as an automatic grouping signal. Explicit reviewed ownership metadata still groups separate records from one publisher.
- Focused evaluator: 2/2 pass; synthetic pair metrics: TP=7, FP=0, TN=5, FN=0 (precision/recall/specificity/F1=1.0). Pipeline tests 27 pass/1 skip; AI workforce 13/13. Full suite 328 run: 321 pass, 3 skip, 4 fail (three OpenCTI checkout failures and one Windows loopback-console abort). Representative contradiction recall remains open.


## 2026-10-04 — Session baseline

- Read repository engineering guidance, current state, acceptance gates, current completion audit, gap analysis, security review, entity-resolution notes and golden-suite documentation.
- Verified local source-maturity branch tree against its GitHub branch tip; branch is one commit ahead of main at the start of this program.
- Ran 310 Python tests: 304 passed, 3 skipped, and 3 OpenCTI-submodule failures. Ran Node graph/target tests after selecting the bundled Python runtime: 25/25 passed. Python compilation, secret scan and whitespace check passed.
- PGlite database tests are blocked because the pinned package is not installed. No new live source or browser test was performed.
- Selected ER-BENCH-001 as the first program task: quantify current synthetic candidate-ranking behavior without tuning the algorithm or claiming live accuracy.
- Added exact-agreement/differing-field signals to ER comparisons; added a synthetic six-query/24-pair evaluator, CLI, tests and captured result. Observed 0.80 pair precision and one namesake false-positive candidate at score 0.7258; false-merge rate remains undefined because no merge is attempted.
- Installed the pinned JavaScript dev dependencies from the lockfile and verified PGlite 1/1, graph/target 25/25 and the local employee workflow. Visual/hosted browser acceptance remains unverified.

## 2026-10-04 — Evidence integrity diagnostic

- Added a deterministic nine-case evaluator around the actual local EvidenceStore ledger/bundle verifier and AI citation-ID validator, with a CLI, focused tests and saved JSON output.
- Five routine invalid cases were rejected. The synthetic re-anchoring mutation rewrote preserved bytes, the SQLite digest and the local ledger consistently and was accepted. Exact-outcome score: 8/9 (0.8889); invalid-case rejection: 5/6 (0.8333); benchmark status: FAIL.
- Kept EVIDENCE-001 open. The harness establishes a concrete need for an independent trust anchor or immutable store; it does not establish semantic citation correctness, external authorship or deployed replay.
- Focused evaluator tests passed 2/2. Full suite: 319 run, 313 passed, 3 skipped, 3 failed (same OpenCTI prerequisite: source files unavailable and vendor count 72/308). `compileall`, secret scan (clean) and `git diff --check` passed.

## 2026-10-04 — Opt-in evidence ledger anchoring

- Added `LedgerAnchor` and `HmacFileLedgerAnchor`; anchored `EvidenceStore` captures fail closed on invalid/missing checkpoints, and anchored exports carry signed receipts that require the verifier/key provider.
- Added external-path enforcement, HMAC-SHA256 signing from an injected 32-byte-or-stronger key provider, same-sequence conflict/rollback checks, and explicit requirements for `require_anchor=True`.
- Expanded the synthetic benchmark to 14 cases: 13/14 expected outcomes; 8/9 invalid cases rejected. The HMAC mode rejected the tested full local rewrite; unanchored legacy mode still accepts it and drives benchmark status FAIL.
- Focused evidence/anchor/bundle tests passed 16/16. Full suite: 326 run, 320 passed, 3 skipped, 3 failed (same OpenCTI submodule prerequisite; missing source files and vendor count 72/308). `compileall`, secret scan and `git diff --check` pass.
- No production key manager, immutable store or remote monotonic anchor was connected. HMAC-file receipts do not prevent old-receipt rollback; EVIDENCE-001 remains open.

# Engineering program changelog

## 2026-10-04 — source maturity repair and persistent program

- Recorded the baseline main SHA and failed CI evidence.
- Repaired malformed source maturity registry and workforce CLI syntax that
  broke baseline compilation; consolidated qualification around the shared
  23-gate contract and normalized the legacy connector state.
- Added strict evidence-reference bounds and lifecycle regression coverage.
- Local checks: Python suite 313 run, 310 passed, 3 skipped; source compilation
  and secret scan passed; graph/target tests 25/25; PGlite database test 1/1;
  employee UI browser suite passed; source-fabric golden replay 78/78; restore
  drill passed; benchmark evidence contract 8/8. Optional source SDK test was
  skipped where dependency was unavailable.
- OpenCTI submodule checksum verification passed for 8,275 files. The submodule
  checkout is test support and must not be included in the PR diff.
- GitHub PR CI and CodeQL are still pending; Docker, hosted staging, and live
  source qualification were unavailable/not performed.
- No source has been promoted and no live source was contacted by this run.
- PR #49 is open at head `bc6f8dab150fd8bc521ca4b5ecfeafb61bce3aa5`, based on
  main `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`. CI run `37184062835` is
  queued; CodeQL run `37184062839` is in progress.
- The first hosted attempt exposed a truncated test-file blob transfer. The
  UTF-8 source test was re-uploaded in size-verified chunks. Corrected
  code/test head `1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI
  `37184302223` and CodeQL `37184302217`; worker image, both Python versions,
  locked MCP, dependency review and supply-chain checks all passed.
- Implemented TA-003 locally: FabricStore now rejects qualification review rows
  whose evidence hash does not resolve to the same case's immutable EvidenceStore
  records; it also refuses to report a legacy promotion as production-qualified
  when a review reference is unresolved. Full suite: 315 tests, 312 passed,
  3 skipped; focused Source Fabric: 28 tests, 27 passed, 1 skipped; secret scan
  clean. PR #50 head `d9c7965e98ba3e26e123fe33c266c97be7b591b8` passed CI
  `37185114010` and CodeQL `37185114003`.

## 2026-10-04 — Restore pinned OpenCTI test prerequisites

- Revalidated pinned submodule source blobs with Win32 extended paths; focused OpenCTI tests passed 7/7.
- Full Python suite: 329 run, 326 passed, 3 skipped, 0 failures.
- No submodule gitlink change; Git for Windows still cannot enumerate the two deep directories.

## Exact-snapshot merge repair — 2026-10-04

Repaired duplicate merge fragments across registry, FabricStore, qualification policy and tests. Preserved all 26 gates. Exact 9d025c snapshot plus patch: 354 run / 351 pass / 3 skip; compile and secrets pass. Corrected the prior 329-test merged-commit attribution.


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


## ER-EVAL-002 intake implementation and EPSS development evidence — 2026-10-05

Implemented `resolve evaluate` over exact case-preserved corpus/protocol hashes.
Authorization, same-case authority/privacy/label-review artifacts, custody integrity,
2 MiB limits, strict schemas, supported public fields and protocol-before-corpus
capture order are enforced. Reports contain aggregate metrics/denominators and
are preserved as evidence. Null denominators fail thresholds. Passing a diagnostic
never grants enterprise qualification; local capture order does not prove
independent preregistration, reviewer identity or representative sampling.

Focused ER tests: 21/21. Full suite: 392 run, 389 passed, 3 skipped, zero failures
(105.961s); compilation and secret scan passed. No ranker weights were changed.
Representative data quality remains externally dependent on approved adjudicated
records. Input/output contract: `docs/ENTITY_RESOLUTION_EVALUATION.md`.

Also ran the public EPSS connector for CVE-2021-44228 through canonical authority,
plan, digest approval, live capture, graph/claim draft and offline replay. One
real request, two observations, cache miss, no source errors. Replay with socket
connections blocked passes with zero calls. This is local development evidence,
not production-like staging or live qualification. Zero sources promoted.
Summary: `docs/verification/epss-development-canary-2026-10-05.json`; raw artifacts
stay outside the repository in the private development workspace.

Prior evidence repair PR #58 head f434cd7 passed CI 37263783083 and CodeQL
37263783047; final full suite 378 run/375 passed/3 skipped. Separate AI findings
review failed and is not counted as completed review.

Next priorities: qualified monotonic anchoring; prevent engineering checklist
scores from masquerading as Enterprise 8/10; expand measured public-source
canaries and failure handling; semantic planning gaps; representative reviewed
corpora and named staging environment. The full master objective stays OPEN.
