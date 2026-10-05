# Program acceptance gates

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



These gates operationalize the transformation brief. They augment, rather than
replace, the repository's existing local and hosted acceptance gates.

| Gate | Pass condition | Current evidence | Status |
|---|---|---|---|
| Source qualification | Every production claim has reviewed terms/entitlement, live canary, parser, evidence/replay, cost/limits, drift/health, owner and runbook. | 25 coded; zero production-qualified. | OPEN |
| Semantic planning | Target/purpose/jurisdiction/language/time/authorization constraints map to questions, evidence and bounded source waves with measured utility. | Deterministic target-bound plan; no free-form or multilingual evaluation. | PARTIAL |
| Entity resolution | Human-review only; representative benchmark meets pre-registered precision/recall and false-merge thresholds. | Synthetic diagnostic: 24 pairs, precision .80, recall 1.00; no auto-merge. No representative evaluation set; false-merge rate undefined. | OPEN |
| Evidence and replay | Immutable bytes, custody, acquisition provenance, tamper detection, offline replay and material citation accuracy pass adversarial evaluation. | 14 synthetic cases: 13/14 exact outcomes; opt-in HMAC checkpoint rejects the tested local rewrite, but legacy unanchored mode accepts it. No rollback-safe external provider or semantic citation labels. | PARTIAL / OPEN |
| Independence/contradiction | Labeled syndication, shared-upstream, temporal and direct-conflict cases meet pre-registered precision/recall. | Synthetic grouping: 12/12 pairs (TP=7, FP=0, TN=5, FN=0). Synthetic temporal contradiction rule: 8 pairs (TP=3, FP=0, TN=5, FN=0); shares production helper and covers temporal/multivalue exclusions. Host-only grouping removed after a tenant false merge. Representative lineage labels and contradiction recall remain unmeasured. | PARTIAL / OPEN |
| SOCMINT | At least two lawful/authorized public source families use canonical evidence/replay and conservative account matching; no bypass. | Not demonstrated. | OPEN |
| Temporal graph | Evidence-linked, time-aware edges and graph operations meet labeled correctness tests and investigator workflow acceptance. | Local graph and temporal primitives; end-to-end quality unknown. | PARTIAL |
| Multilingual/India | English, Hindi and Romanized Hindi query lineage; validated official India sources, identifier formats and local constraints. | Not demonstrated. | OPEN |
| AI employees/local mode | Typed bounded contracts; authority remains server-side; local model mode tested; unsupported material claim rate measured. | Local deterministic workflow; autonomous KPI/local-model acceptance incomplete. | PARTIAL |
| IAM/tenant/security | Live OIDC/RBAC/tenant/case boundary plus explicit leakage, SSRF, injection and secrets gates pass independently. | Local and CI contracts only; staging/independent review missing. | OPEN |
| Deployment/operations | Staging and production-like deployment, observability, quotas, backups/restores, incident drills and SLOs demonstrated. | No environment evidence. | OPEN |
| Evaluation/release score | 100+ realistic investigations; hard metrics; all critical categories >=7, weighted verified score >=8, CI/CodeQL/release evidence current. | 12 controlled cases; no accepted numeric scoring rubric. | OPEN |

The session baseline is recorded in [Evaluation Results](EVALUATION_RESULTS.md).

# Persistent level-8 acceptance gates

| Gate | Pass condition | Evidence required | Current state |
|---|---|---|---|
| Repository health | Clean install, compile, test and security checks | CI/CodeQL on proposed change | BASELINE FAILED; repair underway |
| Authorization | Every collection path rechecks case authority and kill switch | Negative tests for API/CLI/MCP/worker and expiry | Existing controls; full audit open |
| Evidence integrity | Immutable bytes, acquisition metadata, lineage and semantic replay | Tamper/replay tests and receipts | Partial; audit open |
| Source maturity | Shared vocabulary; 23 gates; no fixture promotion | State/gate tests and exact artifact resolution | Repair underway; artifact resolution open |
| Bounded employee | Typed plan/actions, budgets, stop rules, cancellation/resume | End-to-end synthetic cases | Partial deterministic workflow |
| Entity/graph | Evidence-backed relationships; human merge decisions; contradictions | False-merge and graph fixtures/benchmark | Partial; benchmark open |
| Enterprise security | Authn/authz, tenant isolation, retention, secret handling | Threat model and independent test | NOT READY; local only |
| Source qualification | Terms, entitlement, live evidence, health and runbook | Per-source receipts/canaries | 0 production-qualified |
| Operations | Durable jobs, distributed limits, telemetry, backup/restore | CI/staging artifacts | Partial/unverified |
| Golden evaluation | >=100 representative cases, replay, measured error/cost | Versioned benchmark results | NOT ESTABLISHED |
| Release claim | Weighted >=8.0 and every critical primary category >=7.0 | Auditable scorecard and review | NOT ESTABLISHED |

No fixture, mock, catalog count, key presence, or generated model output can
pass a live or production gate.


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
