# Program decisions

| Date | Decision | Reason / consequence |
|---|---|---|
| 2026-10-04 | Continue from `codex/source-maturity-taxonomy`; local and GitHub branch trees match, but the SHAs differ. | Preserve the user's pushed work; verify ancestry/ref before the next push. |
| 2026-10-04 | Start with a synthetic entity-resolution benchmark, not a new social connector. | False-merge risk is critical and unmeasured; a provider integration cannot be qualified without terms, entitlement and runtime proof. |
| 2026-10-04 | Leave matching weights/thresholds unchanged during benchmark implementation. | Prevent tuning against a small synthetic suite and keep the benchmark diagnostic rather than a performance claim. |
| 2026-10-04 | Report false-merge rate as undefined when no automatic merge is attempted. | Zero merges means the metric denominator is zero; reporting 0% would imply evidence that does not exist. |
| 2026-10-04 | Keep Enterprise score uncalculated until category scoring is evidence-backed. | Implementation volume and fixture counts do not establish an 8/10 production capability. |
| 2026-10-04 | Do not infer source independence from hostname equality alone. | Shared hosting and CDN domains may contain separate tenants; explicit reviewed ownership is required to group distinct pages from one publisher. |
| 2026-10-04 | Keep temporal contradiction predicate shared between production pipeline and synthetic evaluator. | The diagnostic must exercise the same subject/predicate/value/time-overlap rule; representative real-world contradiction recall remains open. |
# Engineering decisions

## D-001 — Keep scope governed

Use only analyst-provided evidence and explicitly authorized public research.
Do not add account actions, autonomous contact, auth bypass, credential
harvesting, exploitation, malware execution, publication or intrusive scanning.

## D-002 — Preserve existing authorities

The source registry supplies maturity metadata; FabricStore owns persisted
qualification reviews/promotions; EvidenceStore owns case evidence and integrity.
Do not persist qualification proposals as trusted state without artifact checks.

## D-003 — One maturity vocabulary

`src/traceatlas/source_maturity.py` is canonical for lifecycle labels and gates.
Legacy spellings normalize at read/serialization boundaries. Fixture or
configured-source success never counts as live verification.

## D-004 — Level score requires measured evidence

Do not produce numeric category or overall scores until repeatable evaluation
results and a documented rubric exist. Missing measurements are UNKNOWN, not 0
or assumed passing.

## D-005 — PRs are the review boundary

Implementation changes target a new branch and reviewable PR. Never merge into
main from this autonomous engineering loop.

## Keep OpenCTI gitlink pinned during Windows long-path repair — 2026-10-04

Decision: retain the superproject's existing OpenCTI gitlink at `55ca0dfa4129050cb607fdaf6b1a7457e0ae3476`. The 15 deep files are restored from that commit and the tests pass; Git for Windows still reports inaccessible paths. Do not commit submodule churn caused only by local path enumeration.

## Exact-snapshot merge repair — 2026-10-04

Use a new repair branch from main 9d025c after PR #54 merged concurrently. Preserve the 26-gate policy and portfolio additions. Remove duplicate merge fragments; never replace current source with the old local checkout.


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


2026-10-05 SCORE-001: maturity CLI now reports engineering checklist separately
from unestablished enterprise acceptance. Health/configuration cannot qualify
live sources. See docs/MATURITY_ASSESSMENT.md and the current verification JSON.
Next open work: independent anchors, bounded source-runtime verification,
representative reviewed corpora, semantic coverage and operator staging.


2026-10-05 QUAL-CUSTODY-001: revalidate preserved review/canary custody at each
source-maturity read; stale qualification after artifact mutation is repaired.
456 regressions run (453 pass, 3 skip); current verification JSON records scope.
Independent anchoring, representative labels, live qualification and staging
remain open. Next highest unblocked work is source-execution/receipt binding.
