# Master gap register

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



| ID | Priority | Gap | Current proof | Acceptance to close | State |
|---|---|---|---|---|---|
| TA-001 | P0 | Main source-registry syntax/lifecycle regression after PR #48 | CI 37181405185 failed compile and MCP gate; local compile reproduced syntax error; local suite now passes | Full checks pass on a PR based on current main and hosted CI green | IN_PROGRESS |
| TA-002 | P0 | Source-gate vocabulary and evidence-attestation integrity | Main had conflicting duplicated 20/23-gate definitions | One shared 23-gate policy; bounded refs; strict stages; regression tests | IMPLEMENTED LOCALLY; PR PENDING |
| TA-003 | P0 | Qualification evidence reference resolution is incomplete | FabricStore review requires explicit authorization and a case-preserved artifact hash; promotion and reported state re-resolve each ref within the same case | Resolve every ref against case evidence, reverify custody at promotion, reject unresolved legacy rows | PR #50; CI `37185114010` and CodeQL `37185114003` PASS |
| TA-004 | P1 | AI employee remains deterministic for registered target types | Current-state docs explicitly limit semantic hypotheses/multilingual planning | Typed plan, policy-bound tools, resumable bounded loop, evaluated synthetic cases | OPEN |
| TA-005 | P1 | SOCMINT coverage gap | Current state explicitly says no social-platform investigation workflow | Terms-approved public API workflows; provenance/identity uncertainty; lawful test set | OPEN |
| TA-006 | P1 | Enterprise IAM/tenant and hosted operation | Local package only; production/hosted state unverified | Threat model, authz, tenant tests, staging evidence, review, runbooks | OPEN |
| TA-007 | P1 | Source production qualification | 26 canonical adapters; zero production-qualified claims | Receipts and current-runtime canaries meeting every source gate | OPEN |
| TA-008 | P1 | Semantic replay and golden benchmark | Controlled fixtures exist; no 100-case benchmark | Version-aware recomputation and >=100 authorized/de-identified cases | OPEN |
| TA-009 | P2 | Multilingual/country packs and calibrated planner | Existing docs mark them as gaps | Jurisdiction/source coverage, expert-reviewed corpus, calibrated metrics | OPEN |
| TA-010 | P2 | Durable distributed worker budgets and observability | Current docs identify process-local limits and hosted gaps | Cross-worker quotas, tracing, cost data, crash recovery, restore/load evidence | OPEN |
| TA-011 | P2 | Competitor benchmark | Public-feature comparison only | Reproducible workflow benchmark with limitations and no parity inflation | OPEN |
| TA-012 | P2 | Package version drift in current-state heading | `pyproject.toml` and `docs/README.md` specify 1.11.0; stale current-state heading was 1.12.0 | Keep docs aligned to release metadata; change package version only with release evidence | DOC FIXED; POLICY OPEN |

Reprioritize only after inspecting current code and tests. Each closure must link
to commit, checks, artifact and remaining limitations.


# Master gap register

The existing [gap register](GAP_REGISTER.md) remains canonical; do not create
a second set of contradictory statuses. New master objective read 2026-10-05.

## EVIDENCE-005

- Domain/severity: evidence integrity, P0.
- Maturity: locally tested repair; target is independently verified intended-runtime behavior.
- Root cause: exported payload not bound to signed custody head; empty-history early return bypassed anchor.
- User/investigation/security impact: rewritten evidence/provenance or erased history could verify.
- Fix/files: bundle v2 custody replay and external empty-history check in evidence.py; adversarial evaluator and tests.
- Acceptance: rewritten payload/provenance, erased history, stale ledger, malformed/extra evidence fail closed; clean/historical bundles and legacy unanchored imports retain documented behavior.
- Metric/evidence: expanded corpus 14/18 before, 17/18 after; docs/verification/evidence-integrity-2026-10-05.json.
- Status: local contract verified; commit and hosted checks pending publication.
- Dependency/limitation: production monotonic anchor, semantic citation labels and independent staging proof remain absent.

## External blockers

| ID | Task / cause / dependency | Impact | Owner / required action | Workaround / what continues |
|---|---|---|---|---|
| EXT-STAGING | Tenant/IAM/operations: no named disposable staging project | Intended-runtime security and recovery unverified | Operator supplies staging project and approved access | Local and CI failure tests continue |
| EXT-LABELS | ER/claims/lineage: no approved adjudicated records | Field quality remains unknown | Data owner supplies licensed, privacy-reviewed corpus and review protocol | Build governed intake and metric validation |
| EXT-ANCHOR | No independent monotonic checkpoint service | HMAC receipt rollback not prevented | Operator supplies protected anchor/key service | Strengthen local verification and adapters |
| EXT-SOURCES | Terms/entitlements and sustained runtime canaries absent | Zero production-qualified sources | Source owners provide approved access and runtime | Test contracts without live promotion |


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
