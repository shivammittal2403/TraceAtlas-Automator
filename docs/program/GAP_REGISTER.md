# Enterprise transformation gap register

## Receipt/custody integration repair — 2026-10-06

Base: `5dda70b6b95741227dfc55f51fe1b63fee6c1398`; branch
`codex/qualification-custody-integration-20261006`. PR #65 was integrated and
merged externally as `5dda70b`; its CI failed with a concatenated gateway module
and malformed store promotion branch. Its CodeQL pass does not establish runtime health.

The combined repair retains typed 26-gate receipts, code/runtime/cache binding,
frozen explicit promotion and current canary/review custody revalidation.
Custody is checked once per case within each projection and rechecked on the
next read. Latest invalid/FAIL/expired reviews never fall back to older passes.
Canonical factory, transport revocation, ER evaluation intake and honest maturity
outputs remain. Generic artifacts in custody tests are replaced with typed
synthetic receipts; no actual source is thereby qualified.

Local verification: 479 Python run, 476 pass, three optional skips (238.108s);
Node graph/target/database 26 pass; browser fixture flow, compilation, secret
scan and 214-file Python structure checks PASS. No live provider/model request,
source promotion or deployment by this session. Zero actual LIVE_VERIFIED and
PRODUCTION_QUALIFIED in the clean audit workspace; representative golden cases
0; Enterprise 8/10 score NOT ESTABLISHED. Proposed-head hosted checks are pending.
See `docs/verification/qualification-custody-integration-2026-10-06.json`.

The full employee objective remains active. Next: raw-to-normalized source
replay, governed reviewer IAM, representative evaluation, retention/tenant
isolation and official India source coverage. Earlier records below are
historical and do not certify this tree.

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

## SRC-REVIEW-002 — qualification receipt semantics

- Domain / severity: source integrity and authorization, P0.
- Current / target maturity: CODED and locally TESTED; independent intended-runtime
  validation and substantive source qualification remain OPEN.
- Root cause: a preserved artifact hash established custody membership but did
  not bind the artifact to the source, gate, reviewer, implementation or runtime.
- Investigation / security impact: one unrelated artifact could satisfy all 26
  gates and label a synthetic execution production-qualified.
- Fix / files: typed receipts in source_fabric/review_receipts.py; revalidation and
  frozen promotion in store.py; dispatch/cache binding in gateway.py; CLI and
  portfolio validation. Legacy hash-only rows confer no gate credit.
- Acceptance: reject unrelated, tampered, expired, superseded, cross-case,
  cross-source, wrong-runtime and wrong-code receipts; require preserved live
  execution bytes for runtime checks; require explicit same-runtime promotion.
- Evidence / metric: tests/test_qualification_receipts.py and
  docs/verification/source-review-receipts-2026-10-05.json; 26/26 unrelated
  reviews accepted before, 0/26 after; false promotion rejects; 439 Python tests
  run, 436 pass and three optional skips on the publish tree.
- Status / verification: local acceptance PASS; hosted CI/CodeQL and CODEOWNERS
  review are separate gates. Branch codex/qualification-receipts-20261005.
- Dependency / limitation: trusted local reviewer identity, attestation truth,
  sustained canary coverage, entitlements and raw-withheld replay still need
  substantive proofs. This repair does not qualify any actual source.

Updated: 2026-10-04. Gaps remain open until their acceptance criteria pass.

| ID | Title / domain | Severity | Current state and root cause | Impact | Dependencies | Acceptance criteria / metric | Status |
|---|---|---|---|---|---|---|---|
| ER-BENCH-001 | Synthetic ER evaluation harness | P0 | Previously there was no reproducible ranking metric; added a six-query synthetic company-label set and evaluator. | Makes ranker behavior inspectable but does not estimate deployed identity quality. | None for synthetic diagnostics. | Deterministic 24-pair report; confusion metrics, top-k ranking recall, malformed-label and sensitive-field tests; no automatic merges; limitations disclosed. | COMPLETE: precision 0.80, recall 1.00, F1 0.889, FPR 0.05; one synthetic false-positive candidate. |
| ER-QUALITY-001 | Operational identity quality | P0 | No authorized representative adjudicated dataset; synthetic results cannot establish field accuracy. A same-name synthetic candidate with identifier differences scored 0.7258. | False identity links can harm investigations and subjects; candidate review can be noisy. | Legal/privacy owner, approved cases, adjudication protocol. | Pre-registered thresholds; representative set including collisions and ambiguous cases; measured false merge/split rate with confidence interval. | OPEN / data unavailable; zero auto-merges makes false-merge rate undefined. |
| SRC-PROD-001 | Production source qualification | P0 | 25 coded adapters, zero production-qualified. Terms, entitlements and sustained intended-runtime evidence absent. | No defensible service-level or source coverage claim. | Provider approvals/credentials, source owner, deployed canary. | At least target workflow coverage equivalent to 50 qualified sources; every claimed source passes its evidence gates. | OPEN |
| EVIDENCE-001 | Evidence integrity/citation acceptance | P0 | Added opt-in `LedgerAnchor`, HMAC receipt adapter and environment wiring. 14 synthetic cases match 13/14 expected outcomes; HMAC mode rejects tested local rewrite when key/receipt are outside the workspace, but legacy unanchored mode still accepts it. No rollback-safe remote anchor or semantic citation proof. | Legacy-default cases can be rewritten inside one local trust boundary; citation membership does not prove claim support. | Monotonic external anchor/immutable store; managed key provider; labeled citations and approved adversarial corpus. | Tamper/citation benchmarks pass with no accepted corrupt state across required modes; rollback, immutable storage and replay acceptance verified. | OPEN / opt-in HMAC mode wired; rollback-safe provider and default-required policy absent |
| LINEAGE-001 | Source independence/contradiction evaluation | P0 | 12 synthetic source pairs pass after hostname-only grouping was removed. Added eight labeled pairs around the production temporal contradiction rule (3 conflicts, 5 non-conflicts; all correct). Representative syndication and contradiction recall remain unknown. | Duplicate sources may be overcounted or conflicts missed; conservative host handling can miss common publishers without reviewed ownership metadata. | Curated labeled corpus, source provenance, reviewed publisher ownership. | Predefined pairwise precision/recall thresholds and adversarial duplicate/temporal/contradiction cases pass on approved representative records. | PARTIAL / synthetic diagnostics pass; representative gate OPEN |
| TENANT-001 | Hosted tenant and worker isolation | P0 | RLS/worker contracts exist but no live tenant/Auth/staging test. | Cross-case/tenant leakage cannot be excluded in production. | Disposable staging project and operator credentials. | Cross-tenant read/write, IDOR, evidence/cache/report/AI-context leakage tests all fail closed. | BLOCKED on staging |
| OPS-001 | Production operations and recovery | P0 | No production-like deployment evidence, distributed quota or restore drill in this session. | Availability, budget, cancellation and recovery behavior unknown. | Operator infra, monitoring and backup services. | Deployment, SLO/alert, backup/restore, load and incident runbook gates pass. | BLOCKED on infrastructure |
| SOCMINT-001 | Lawful public social workflows | P1 | No demonstrated multi-family canonical public-social workflow. | Primary program scope cannot yet claim SOCMINT maturity. | Terms, APIs, privacy review, source contracts. | Two or more permitted source families with evidence/replay and collision evaluation; no access-control bypass. | OPEN |
| LANG-IN-001 | Hindi/Romanized Hindi and India country pack | P1 | No validated transliteration/query lineage and operational India pack. | Reduced recall and country-specific workflow utility. | Official source research, allowed-use review, labeled corpus. | Original/native/transliterated queries preserved; official sources tested; no translation replaces original evidence. | OPEN |
| GOLDEN-001 | Representative end-to-end evaluation | P1 | Existing 12 controlled cases are synthetic/fixtures. | Fixture success does not predict investigator outcomes. | Approved realistic dataset and reviewers. | 100+ realistic controlled cases plus adversarial cases; autonomous defensible rate and hard quality metrics reported. | OPEN |

## Closure rule

Keep historical findings. Update status, evidence, test result, metric and commit
in the implementation/evaluation ledgers; do not close a gap when only code or
fixtures exist.

## Exact-snapshot merge repair — 2026-10-04

REGISTRY-MERGE-002 (P0): exact main 9d025c compilation failures repaired; 26-gate requirements and same-case review validation preserved. Local 354-test suite passes; hosted repair verification pending.


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


### SCORE-001 / P1 - misleading maturity output

Root cause: generic health rows and static markers were counted as verified live
operation and a product /10 score. Controlled baseline inflated 6.8 to 8.8 without
a live request. CODED/locally TESTED repair: checklist v2, null enterprise score,
canonical integration-receipt revalidation, explicit denominators and hosted gates
kept unverified. Documentation and consumers/tests migrated. Acceptance: synthetic
health/config injection must not increase acceptance or local verified counts;
fixtures/stale implementation receipts excluded. Full evidence and remaining
limitations: docs/MATURITY_ASSESSMENT.md and verification/maturity-output-2026-10-05.json.
Not DEPLOYED; representative enterprise acceptance remains OPEN.


## QUAL-CUSTODY-001: current custody required for qualification (2026-10-05)

Main parent 6264b935 (tree identical to verified 015ee105). Reproduced a source
still reporting PRODUCTION_QUALIFIED after preserved review bytes were changed
and ledger verification failed. Qualification projections now revalidate same-case
review and canary custody, including any configured anchor, on every read. Checks
are cached only within that projection. Invalid canary custody yields DEGRADED;
invalid reviews cannot grant LIVE_VERIFIED or PRODUCTION_QUALIFIED. Gateway and
promotion propagate the actual workspace instead of assuming the database location.

Measured controlled comparison: intact evidence remains qualified in both versions;
tampered shared canary/review case changes from falsely qualified to DEGRADED.
Nine negative/control regressions pass. Full suite: 456 run, 453 passed, 3 skipped,
zero failures (149.007s). Structure scan 210 files, compilation and secrets pass.
Evidence: docs/verification/qualification-custody-2026-10-05.json. CODED/TESTED;
not DEPLOYED; no live request or actual source promotion in this iteration.
Local attestations still do not prove reviewer identity/review quality; independent
anchor rollback protection and unanchored full rewrite remain OPEN. Enterprise
8/10 is NOT ESTABLISHED. Parent CI 37300581400 and CodeQL 37300581482 passed;
separate AI review failed with confirmed monthly quota/HTTP 402, not a code result.
