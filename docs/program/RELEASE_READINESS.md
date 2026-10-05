# Enterprise release readiness

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



Status: **NOT READY — program baseline only** (updated 2026-10-04).

| Requirement | State | Proof needed |
|---|---|---|
| 50+ production-qualified sources or measured primary-workflow coverage | BLOCKED / 0 qualified | Terms, entitlement and sustained live canaries per source. |
| SOCMINT V2 across lawful public source families | OPEN | Two or more permitted source families, canonical evidence/replay, identity evaluation. |
| Entity resolution thresholds and false-merge controls | OPEN | Representative adjudicated benchmark, confidence intervals, review and reversible decisions. |
| Evidence, independence, contradiction and temporal quality | OPEN / PARTIAL | Opt-in HMAC receipt code is synthetic-tested; unanchored mode still accepts a full local rewrite. Synthetic source grouping (12 pairs) and temporal contradiction rule (8 pairs) pass; need monotonic external anchor, immutable storage, representative citation/lineage/contradiction tests, and staging replay acceptance. |
| Semantic planner, gaps and next-best action | PARTIAL | Calibrated evaluation and bounded end-to-end loop. |
| Multilingual and operational India pack | OPEN | Validated Hindi/Romanized Hindi and official source/legal verification. |
| AI employee and local model | PARTIAL | Local model workflow, contract/failure tests and unsupported-claim KPI. |
| CTI and cross-domain primary workflows | PARTIAL | Independently qualified source families and representative investigation tests. |
| IAM and tenant isolation | BLOCKED on staging | Live OIDC/RBAC/cross-tenant tests and independent review. |
| Operations / observability / backup restore | BLOCKED on infrastructure | Staging run, SLOs, tracing, quota, recovery and incident drills. |
| 100+ realistic golden investigations | OPEN | Approved realistic suite, metrics and adversarial evaluations. |
| Branch CI, CodeQL and release artifacts | NOT VERIFIED this session | Green checks for exact release candidate SHA and signed/verified artifacts. |

The 8/10 score must remain uncalculated until a published, weighted rubric is
populated with reviewed evidence. No critical primary workflow may be below 7.
Open gaps are tracked in [GAP_REGISTER.md](GAP_REGISTER.md), and the formal
acceptance conditions are in [ACCEPTANCE_GATES.md](ACCEPTANCE_GATES.md).

# Release readiness

**State: NOT READY.** Current main baseline fails CI after PR #48. The repair
passes available local checks: Python 313 tests (310 passed, 3 skipped), source
compilation, secret scan, graph/target 25/25, PGlite 1/1, employee UI browser
suite, 78/78 controlled source-fabric replay, and restore/integrity checks.
PR #49 is open. Corrected code/test head
`1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI `37184302223` and CodeQL
`37184302217`, including the hosted worker-image build. Hosted staging evidence
remains unavailable.

Required before release: PR CI and CodeQL green; current-state docs accurate;
source-reference verification; review of auth/evidence/network boundaries;
staging, tenant, backup/restore and operational evidence; no critical golden
regression; reproducible weighted score >=8.0. This PR does not deploy, qualify
sources, assert competitive parity, or merge into main.


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
# Enterprise release readiness

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



Status: **NOT READY — program baseline only** (updated 2026-10-04).

| Requirement | State | Proof needed |
|---|---|---|
| 50+ production-qualified sources or measured primary-workflow coverage | BLOCKED / 0 qualified | Terms, entitlement and sustained live canaries per source. |
| SOCMINT V2 across lawful public source families | OPEN | Two or more permitted source families, canonical evidence/replay, identity evaluation. |
| Entity resolution thresholds and false-merge controls | OPEN | Representative adjudicated benchmark, confidence intervals, review and reversible decisions. |
| Evidence, independence, contradiction and temporal quality | OPEN / PARTIAL | Opt-in HMAC receipt code is synthetic-tested; unanchored mode still accepts a full local rewrite. Synthetic source grouping (12 pairs) and temporal contradiction rule (8 pairs) pass; need monotonic external anchor, immutable storage, representative citation/lineage/contradiction tests, and staging replay acceptance. |
| Semantic planner, gaps and next-best action | PARTIAL | Calibrated evaluation and bounded end-to-end loop. |
| Multilingual and operational India pack | OPEN | Validated Hindi/Romanized Hindi and official source/legal verification. |
| AI employee and local model | PARTIAL | Local model workflow, contract/failure tests and unsupported-claim KPI. |
| CTI and cross-domain primary workflows | PARTIAL | Independently qualified source families and representative investigation tests. |
| IAM and tenant isolation | BLOCKED on staging | Live OIDC/RBAC/cross-tenant tests and independent review. |
| Operations / observability / backup restore | BLOCKED on infrastructure | Staging run, SLOs, tracing, quota, recovery and incident drills. |
| 100+ realistic golden investigations | OPEN | Approved realistic suite, metrics and adversarial evaluations. |
| Branch CI, CodeQL and release artifacts | NOT VERIFIED this session | Green checks for exact release candidate SHA and signed/verified artifacts. |

The 8/10 score must remain uncalculated until a published, weighted rubric is
populated with reviewed evidence. No critical primary workflow may be below 7.
Open gaps are tracked in [GAP_REGISTER.md](GAP_REGISTER.md), and the formal
acceptance conditions are in [ACCEPTANCE_GATES.md](ACCEPTANCE_GATES.md).

# Release readiness

**State: NOT READY.** Current main baseline fails CI after PR #48. The repair
passes available local checks: Python 313 tests (310 passed, 3 skipped), source
compilation, secret scan, graph/target 25/25, PGlite 1/1, employee UI browser
suite, 78/78 controlled source-fabric replay, and restore/integrity checks.
PR #49 is open. Corrected code/test head
`1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI `37184302223` and CodeQL
`37184302217`, including the hosted worker-image build. Hosted staging evidence
remains unavailable.

Required before release: PR CI and CodeQL green; current-state docs accurate;
source-reference verification; review of auth/evidence/network boundaries;
staging, tenant, backup/restore and operational evidence; no critical golden
regression; reproducible weighted score >=8.0. This PR does not deploy, qualify
sources, assert competitive parity, or merge into main.


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


## MERGE-001: canonical gateway and duplicate-definition CI gate (2026-10-05)

Reconciled ER intake commit 1580244 with main f30ba40a. Preserved incoming
source/API/CI changes and remote archive uploads. Main d47769a contained three
concatenated registry/test modules and overlapping gateway implementations.
Registry compilation failed; later classes/methods hid earlier definitions.
Retained latest complete definitions and one ConnectorFactory dispatch per action.
Gateway now consistently rechecks immutable authorization and executable contracts
on transport/retry/evidence promotion, using separate per-thread database reads.
Fixture mode remains fixture. Eight targeted gateway tests pass.

New compile/AST CI gate detects all three affected baseline files (five errors).
The repaired scan passes across 208 files; eight checker regressions were added.
Initial integration suite: 438 run, 435 passed, 3 skipped. Two further contract
mutation tests pass; final suite recorded in
`docs/verification/main-integration-2026-10-05.json`. Compilation/secrets pass.
PR #62's prior head passed CI 37265075218 and CodeQL 37265075236; separate AI
review failed. That PR was externally merged into its stacked base. This repair
targets main and awaits checks on its new commit. No deployment or source promotion.
Enterprise 8/10 remains NOT ESTABLISHED. Next: maturity-score honesty, bounded
public-source verification, independent anchoring and representative/staging gates.


## SCORE-001: engineering checklist is not enterprise acceptance (2026-10-05)

Reproduced baseline ca86a44 assigning 8.8/10 and 51 verified-live sources from
synthetic health/configuration records alone (clean score 6.8; no live requests).
Maturity JSON v2 removes numeric enterprise scoring: overall/maximum null;
enterprise NOT_ESTABLISHED; explicit checklist counts and denominators. Local
integration counts revalidate canonical receipts; generic health cannot qualify.
Hosted readiness cannot be granted by a static configuration response.
Seven new regressions; 24 focused maturity tests pass. Full suite recorded in
`docs/verification/maturity-output-2026-10-05.json`. Migration and limitations:
`docs/MATURITY_ASSESSMENT.md`. Parent ca86a44 passed hosted CI 37299462969 and
CodeQL 37299462901. New-head checks remain separate. No deployment or promotion.


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
