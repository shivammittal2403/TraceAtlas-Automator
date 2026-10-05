# Evaluation results

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


## Source independence and contradiction diagnostics (2026-10-04)

`lineage-and-contradiction-synthetic-v2` runs 12 deterministic source pairs against
the production `SourceIndependenceEngine`: TP=7, FP=0, TN=5, FN=0; precision,
recall, specificity and F1 are 1.0 on this synthetic set. The first run exposed
a false merge when unrelated tenants shared a hostname. The engine no longer
uses hostname equality as proof of common origin; reviewed ownership metadata
still groups distinct pages from one publisher.

The same report includes 8 temporal contradiction pairs evaluated by the
helper used in the production pipeline: TP=3, FP=0, TN=5, FN=0 (synthetic
precision, recall, specificity and F1 are 1.0). Cases cover overlapping and
historical conflicts, partial/open intervals, different subjects/predicates,
same values and multivalued DNS. Evaluator tests passed 3/3,
investigation-pipeline tests 27 passed/1 skipped, AI workforce 13/13, and
`git diff --check` passed. These are unit-level synthetic diagnostics, not
operational accuracy or contradiction recall.

Report: [`source-independence-synthetic-2026-10-04.json`](../verification/source-independence-synthetic-2026-10-04.json).

After the refactor, the full Python suite ran 329 tests: 323 passed, 3 skipped,
and 3 failed. All failures are the known incomplete OpenCTI submodule
prerequisite (two missing-source errors and vendor count 72/308). Console tests
passed in this full run.

Updated: 2026-10-04. Results below are freshly observed in this checkout unless
marked historical. Environment failures are not reported as code passes.

| Evaluation | Result | Scope and limitation |
|---|---|---|
| Python `unittest discover -s tests -q` (latest after lineage/contradiction refactor) | 329 run; 323 passed; 3 skipped; 3 failed (2 errors, 1 failure) | All failures are the OpenCTI submodule prerequisite: pinned source files unavailable and vendor count 72 vs expected 308. Console regression passed in this full run. |
| Node graph/target suite | 25/25 passed | Set `PYTHON` to the bundled Python executable so Node could spawn Python; tests are local synthetic cases. |
| PGlite database/RLS | 1/1 passed | Installed exact project dev dependencies with `pnpm install --frozen-lockfile`; local disposable PGlite/Auth-shim gate only. |
| Python source compilation | Passed | `compileall -q src`. |
| Secret scan | Passed, clean | `scripts/check_secrets.py`. |
| `git diff --check` | Passed for this slice | Whitespace check over tracked implementation/documentation edits; incomplete submodule state is excluded. |
| Employee UI workflow | Passed | `tests/test_employee_ui.cjs`; local workflow check only, not hosted UX acceptance. |
| Live source tests | None | No provider credentials or intended-runtime deployment available. |

## Evidence integrity and citation guard diagnostic

The current deterministic synthetic harness at
[`evidence-integrity-synthetic-2026-10-04.json`](../verification/evidence-integrity-synthetic-2026-10-04.json)
executes 14 cases against `EvidenceStore`, the optional external HMAC checkpoint
and the AI advisory citation-ID validator. It matched 13/14 expected outcomes
(0.9286), with 8/9 invalid cases rejected (0.8889). Ordinary local ledger,
captured-byte and bundle mutations, unknown citation IDs, altered bundle
receipts and missing required receipts reject. Anchored ledger and bundle
fixtures verify. The one expected failure remains the legacy unanchored path:
rewriting captured bytes, SQLite digest and the local hash-chain consistently is
accepted. EVIDENCE-001 therefore stays OPEN.

The opt-in `HmacFileLedgerAnchor` rejected the same rewrite when the key and
receipt remain outside the workspace/attacker trust boundary. It is not a
rollback-safe append-only provider; receipt rollback, concurrent writers, key
manager integration, immutable storage, deployed replay and semantic citation
correctness remain unverified. See [Evidence ledger anchoring](../EVIDENCE_ANCHORING.md).

## Entity-resolution baseline

The existing ranker uses weighted Jaro-Winkler similarities over name,
organization, domain, username and location. It returns a candidate class and a
score described as a heuristic, always requires analyst review and never merges
automatically. Existing G10 only checks a synthetic identifier conflict; it
does not measure population-level precision/recall or false-merge rate.

The first evaluation slice is synthetic and must not be presented as operational
accuracy. The existing 0.72 `possible_candidate` score boundary was retained and
not tuned on this set. Six queries contain 24 labeled pairs (4 positive, 20
negative). Results: TP=4, FP=1, TN=19, FN=0; precision=.80, recall=1.00,
F1=.889, false-positive rate=.05; ranking recall@1=1.00 and @3=1.00 across the
four positive queries. The false positive is the synthetic same-name Meridian
company candidate (score .7258), with differing organization, domain, username
and location. Output now makes exact-agreement/differing fields explicit. It
remains a review candidate, not a merge. Saved result:
[`entity-resolution-synthetic-2026-10-04.json`](../verification/entity-resolution-synthetic-2026-10-04.json).

False-merge rate stays undefined while the automated-merge count denominator is
zero. No representative authorized adjudicated set exists; operational
precision/recall, calibration, candidate-generation recall and false merge/split
rates are still unknown.

No market-parity, 8/10 weighted maturity or production-readiness score is
currently supportable.

## Latest full-suite rerun — 2026-10-04

On the earlier unsynchronized local checkout (not the merged GitHub revision), `python -m unittest discover -s tests -q` completed successfully: 329 run, 326 passed, 3 skipped, 0 failures. The three skips are expected optional checks. OpenCTI-focused tests passed 7/7 after restoring 15 deeply nested source files from the exact pinned submodule blobs; sampled bytes matched Git blob hashes. Git for Windows still warns that those paths exceed its enumeration limit, so `git status` may report false deletions. This result supersedes the earlier full-suite row that reported three OpenCTI prerequisite failures. It does not establish production qualification or close other program gates.


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
