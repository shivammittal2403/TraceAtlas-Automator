# Archive remote verification checkpoint — 2026-10-07

Code head `56c263af5509de4c3831dbc62f097822afd351ab` fixes the clean-install
archive failure. All six PR CI jobs and the CodeQL gate PASS. Python 3.10 and
3.12 each run 515 tests (513 pass/two explicit optional skips). Locked runtime:
629 pass/28 skips; source-fabric wire 29/29 and optional archive parser 2/2 pass.
Both real Chromium fixture flows pass: 92 directory records, 19 lessons, 207
resource references, zero external requests/errors, CSP/injection/mobile checks.
Installed core-wheel smoke executes all seven archive actions and custody verify.

Fresh Python SARIF records 22 existing protocol/URL-check findings, compared to
76 baseline findings; all 20 archive path findings are absent. This is recorded
scanner evidence, not a vulnerability-free claim. JavaScript/TypeScript findings
and inherited advisories still require review. Optional Copilot AI review is
BLOCKED_EXTERNAL by exhausted monthly quota; no settings/subscription changes.

This documentation update preserves the verified runtime identity. Final main
checks are pending at commit creation; hosted/live operation, independent
outcome/enterprise qualification and deployment remain NOT_VERIFIED. Exact job,
artifact, build and harness identities are in
[the compatibility receipt](verification/archive-compatibility-2026-10-07.json).
Earlier checkpoints below refer to the versions they tested.

# Archive compatibility checkpoint — 2026-10-07

Current baseline `2f662cccbda772ad6264be439e6bc390b6e079db` includes both supplied
archives and parallel TypeScript/dependency/ignore changes. Its core CI is
FAILED: optional PyYAML is imported eagerly through the archive workspace.
Earlier local runs included optional site packages and did not establish a
clean standard-library installation. Historical passes below do not certify
this main build.

CODED / FIXTURE_VERIFIED: defer YAML until an actual optional catalog is parsed;
prove workspace creation/capture/read under Python `-S`; normalize and check
confined child paths before I/O; reuse that boundary for canonical export files.
Restore operator-secret/case-data/build ignore rules removed in PR #71 without
reintroducing removed caches or replacing user changes. The original 1,863
source files remain tracked, byte-identical and hash-mapped; runtime mappings
remain 1,268. Existing CLI, case/evidence/workforce and hosted ownership remain.

Fresh installed core venv: 515 tests run, 513 pass, two explicit optional skips;
31 focused path/export checks pass; Node/PGlite 26/26; compilation, 1,504-file
structure, secret scan, source mapping and shell/JS syntax pass. Remote CI,
locked SDK, browser and scanner results are separate gates, PENDING at commit
creation. No scan alert is declared closed from a local pass. No hosted/live
qualification, deployment, database migration or model/provider collection.
See [the compatibility receipt](verification/archive-compatibility-2026-10-07.json).
Earlier checkpoints below refer to their tested versions.

# Archive security follow-up — 2026-10-07

PR #68 is merged on main as `5cea4fab540ea97271a9b45352f5d4e48d059054`.
Its six repaired CI jobs passed, including the locked MCP runtime and Chromium
flow (92 directory records, 19 lessons, 207 resource references, zero external
requests/browser errors; CSP and injection checks passed). This is CI fixture
proof, not deployment or live-source qualification.

The follow-up preserves all 1,863 original file hashes, makes 1,433 executable
references inert (`.source`), keeps all 1,268 namespaced Python mappings, and
removes nine unused legacy scripts from the public Academy. Active code is still
scanned. Case IDs/artifact paths are confined; archive blobs are digest-bound;
canonical export checks same-case custody even when a report digest is rehashed.
Twelve core negative regressions and two optional parser fixtures are added.
No migrations or existing worker/auth/frontend ownership are replaced.
Refreshed main `8c2e9a2` adds a TypeScript snapshot and locked dependency update;
both are retained. The combined locked SDK suite passes 514/514 with zero skips.
An inherited Dependabot update failed on unresolved transitive advisories; this
is separate from CI/browser and CodeQL qualification, and remains recorded.

Current local tests and remote scanner dispositions are recorded in
[the security receipt](verification/archive-security-followup-2026-10-07.json).
The original 50-alert PR result remains historical evidence until re-scanned;
optional GitHub AI review was blocked by provider quota. No security settings,
subscriptions, secrets, provider collection or deployment are changed.

Earlier checkpoints below describe their tested versions, not the newest tree.

# Remote CI repair checkpoint — 2026-10-07

PR #68 contains the complete hash-verified archive integration. The first remote
attempt exposed an existing MCP SDK 2.x handler mismatch and a browser harness
expectation that incorrectly discarded the distinct SpiderFoot HX listing.
The SDK callbacks/result models and wire rejection coverage are repaired; the
exact locked SDK environment passed 500/500 Python tests with zero skips locally.

CodeQL reported 50 alerts (48 high, two medium); their locations and dispositions
remain OPEN until scanner-backed review. SARIF reporting/artifacts are added
without changing scanner queries, exclusions or gates. The separate GitHub AI
security review exhausted its monthly quota and is BLOCKED_EXTERNAL. No quota,
subscription or security setting is changed. Main merge and hosted qualification
are not certified by a branch push. See verification/archive-ci-repair-2026-10-07.json.

# Archive integration checkpoint — 2026-10-07

Base `b56101237b248922316dc049528e0c83b0f2c774`, branch
`codex/merge-osint-cute-20261007`. CODED/FIXTURE_VERIFIED: two complete
source snapshots, versioned runtime namespaces, seven case-bound offline actions,
CSP-compatible directory/Academy pages, nineteen actual training modules and
207 external resource references. Existing SQLite/EvidenceStore/workforce, CLI,
source qualification, auth and hosted migrations remain canonical.

Actual local regressions: 500 Python run, 499 pass, one optional skip (30.525s);
21 added archive regressions pass; Node graph/target/PGlite 26/26; compilation,
1,500-file structure check, source secret scan, source preservation checks,
launchers/JS syntax and wheel build pass. Controlled workforce source 78/78 and
enterprise 112/112 (105 drafts) pass; these are synthetic contracts.
Local browser verification is BLOCKED by absent Chromium/corrupt CDN downloads;
the required new browser flow is wired into GitHub CI, whose outcome is separate.
No local browser pass, live source collection, model execution, provider
qualification, hosted rollout, migration, identity merge or enterprise score is
claimed. Raw scaffolds/source namespaces are not working integration counts.

Details: [Archive integration](ARCHIVE_INTEGRATION.md),
[hash-bound file mapping](archive_merge_manifest.json),
[verification receipt](verification/archive-merge-2026-10-07.json).
Earlier checkpoints below are historical and do not certify this new tree.

# Current implementation state â€” 2026-10-04 / 1.11.0

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


## Semantic employee integration â€” 2026-10-05

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


## Semantic employee integration â€” 2026-10-05

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
Final integrated Python/benchmark checks are being recorded; Node graph and
PGlite 26/26 and browser flow PASS; compilation PASS. Proposed-head CI/CodeQL
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


## Current repair checkpoint â€” 2026-10-04
# Current implementation state — 2026-10-05 / 1.11.0

## Main CI and release metadata repair — 2026-10-05

Exact refreshed main `5ad16f01d4e3916dc6f40591c8fcbef2c14c88b8` failed compilation
in the source registry and Source Fabric tests. This tranche removes duplicated
merge fragments and overwritten prerequisite definitions, restores canonical
same-case fixture evidence and preserves the 26-gate qualification policy.

Package, Vercel catalog and footer now report 1.11.0. Health/config expose bounded
Git/repository/deployment metadata, keep absent commit IDs unknown, and mark
hosted readiness NOT_VERIFIED. Static production configuration checks cannot
qualify hosted operation; worker deployment is unknown, not asserted from code.

Local verification: 378 Python tests run (377 passed, one optional MCP skip);
the locked MCP SDK separately passes all 29 Source Fabric tests. Graph/target
tests 25/25, local PGlite migration/RLS test 1/1, 78/78 controlled source scenarios,
golden replay and wheel build pass. Exact commands, bundled runtime exclusions,
browser prerequisites and remaining hosted gates are recorded in
[the receipt](verification/release-repair-2026-10-05.json). These results apply to
the receipt's file hashes, not to earlier or concurrently modified main commits.

The inspected Vercel team has no Automator Git project. `trace-atlas-osint` links
to a different repository. [Deployment](DEPLOYMENT.md) records the concrete
dedicated-project proposal and required staging evidence. No resource mutation
or production qualification is claimed. The following sections retain historical
checkpoints rather than extending their test results to this build.

# Historical implementation checkpoint — 2026-10-04 / 1.11.0

## Source Fabric continuation — 2026-10-05

The canonical gateway now uses the connector factory with request-by-request
authority, cancellation, expiry and kill-switch checks. Responses received after
revocation are rejected before evidence promotion. Two exact public metadata
connectors (PyPI and DataCite) bring registration to 51 sources, 37 coded live
API adapters and 35 capability mappings. Explicit live integration receipts bind
current implementation bytes, execution snapshots and same-case preserved
evidence; fixtures and cache hits do not count. Local Windows public sample
checks succeeded for both new sources and passed canonical custody verification.
Their raw responses remain privacy-withheld; replay/production qualification is
not claimed. The 650/600/450/300/200/125 thresholds and family minima remain open.
Inherited duplicate qualification branches and malformed test fragments in base
`5ad16f0` were repaired while preserving canonical prerequisite gates and negative
same-case evidence/promotion tests.

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

# Current implementation state â€” 2026-10-04 / 1.11.0

## Durable local workforce runtime

Attempt fencing, owner cancellation/recovery, persistent request budgets,
capture checkpoints and atomic result/product/derived-record/outbox completion
are implemented in the canonical local workforce. Local verification: 371 Python
tests run, 370 passed, 1 optional skip; 18 runtime negative tests pass. Hosted
execution, distributed quotas and new live-source qualification remain unverified.
See [execution contract](WORKFORCE_EXECUTION.md) and
[test receipt](verification/workforce-runtime-2026-10-04.json).

Source-inventory metrics below were audited against PR #43 baseline
`d698ed519be078ec72092b33dacda9f92ffdb42c`. Main now includes the 2026-10-04
enterprise audit and bounded graph acceptance fix, merged in PR #44 at
`89069097a66899eabc55897114146cf51f81dc45`; its CI and CodeQL checks passed.
See `docs/audit/` for the baseline reports.
Both source briefs are reconciled in `docs/sources/DELIVERY_LEDGER.md`; Phase A is implemented,
later programme phases and production qualification remain incomplete. Exact-CVE
NVD, FIRST EPSS, CVE Program, OSV, npm and CISA KEV records flow through the approved
source gateway, evidence, verification, graph and replay path. The CISA KEV feed is
fixed-host and schema-validated; facts are restricted to the exact CVE match while the bounded raw response is retained for replay.

The canonical local path is typed seed â†’ immutable authority â†’ capability/source
plan â†’ digest approval â†’ bounded gateway â†’ captured bytes â†’ observations â†’ source
lineage â†’ verification â†’ graph/timeline â†’ draft â†’ offline replay. The existing
SQLite/EvidenceStore and five employee roles remain the authorities.

Twenty-six shared workforce adapters cover public DNS, RDAP, CT, passive URL/archive
indexes, IP ownership/ASN/exposure/context, search, company registers, LEI, SEC
filing metadata, public GitHub organizations, exact CVE/advisory records, exploitation
probability, CISA KEV catalog listing and remediation metadata, and npm package
metadata. CISA catalog membership is a source observation, not proof an asset is
affected; it is not independent evidence of exploitation. Company collection requires exact
registered identifiers, never a same-name match. Person investigations still use
approved records. Model-free normalization and report generation remain supported.

| Delivery state | Evidence |
|---|---|
| CODED | Capability registry/router, 26-adapter SDK, bounded parallel gateway, scoped cache, health/canary recovery, cost limits and six MCP tools |
| VERIFIED in CI | Python 3.10 and 3.12: 305 tests each, 303 passed and two optional tests skipped; PGlite and 25 Node UI/target tests pass; 78/78 controlled source scenarios replay successfully; compilation, dependency review, supply-chain evidence, worker image and CodeQL pass |
| Real response parsing/replay | Cloudflare DNS, RIPEstat, GLEIF and GitHub public reference responses through an injected environment-proxy requester; all captured/replayed |
| Direct transport qualification | All five new canaries fail closed on this environment's direct DNS; crt.sh proxy response quarantined for schema mismatch |
| DEPLOYED | Private hosted runner/product view and production rollout remain unverified |
| PRODUCTION_QUALIFIED | Zero source claims; current terms/account entitlement, sustained health and intended-runtime verification outstanding |

Registry counts overlap: 51 workforce metadata entries, 26 canonical approval-driven workforce adapters, and 49 IntelligenceHub entries of which 35 have API implementations. The supplied 400
candidate rows deduplicate to 351 research rows, 41 flagged as generic categories.
A candidate, code path or configured key is never counted as a verified integration.

The router chooses capabilities using explainable heuristics and may preapprove
one fallback wave. Eight request attempts, USD 1 estimated budget and 120 seconds
remain the per-task bounds. Public requests use fixed-host, direct TLS transport;
no proxy fallback was added to the shipped transport. Observed prices are not
billing measurements. Rate/concurrency ceilings are process-local, not a distributed
quota guarantee. All fresh collection rechecks authority and the kill switch.

Paid-source credentials, deployed SearXNG and SEC operator contact are not
established here. Beneficial ownership, sanctions, procurement and public
geospatial coverage remain gaps. Package and vulnerability collection now uses
the canonical authority, source plan, evidence, verification, graph, next-action
and replay path.
Country packs, calibrated information gain, semantic/multilingual planning,
marketplace discovery, distributed workers, model-provider qualification and
hosted operations remain gaps. No contact, active scans, account action, identity
merge or material report release is automated.

The workflow/parser version changed; old evidence stays immutable, and unsupported
historical replay versions fail closed. Retain the previous release to replay its
products. Source health and TTL do not prove the truth of a provider's assertion.

See `docs/sources/SOURCE_FABRIC.md`, `docs/sources/SOURCE_AUDIT_MATRIX.csv`,
`docs/verification/source-fabric-2026-10-03.json`, `docs/LIVE_SOURCES.md` and
`docs/ACCEPTANCE_GATES.md`. The current Markdown/task reconciliation is recorded
in `docs/COMPLETION_AUDIT_2026-10-04.md`. Earlier cycle evidence remains in
`docs/verification/live-sources-2026-10-03.json` and `docs/IMPLEMENTATION_REPORT.md`.

Source manifests now expose the canonical eleven-state maturity vocabulary;
catalogued records, coded connectors, live verification and production
qualification have separate labels and counts. `BROKEN` is normalized to the
`DEGRADED` maturity state, while source health remains a separate field. This
local code change does not qualify any source: the repository still has zero
production-qualified claims until evidence gates and intended-runtime canaries
are completed. See `docs/SOURCE_MATURITY.md`.

The workforce source plan also carries a deterministic, schema-versioned
investigation plan with target-bound questions, evidence checks, candidate sources,
execution waves, verification requirements and stop conditions for registered
target types. It creates no hypotheses and does not claim multilingual or free-form
semantic planning; source scores remain uncalibrated heuristics.

## Employee console integration (PR #26)

Adds `employee serve` and `employee investigate`: local bounded runs, checkpoints,
cancellation, cited graph/report, optional local-model drafting and evidence ZIP.
Shared IntelligenceHub now has 49 records / 35 API implementations with NVD, CVE Program, FIRST EPSS, CISA KEV, OSV and npm. Canonical workforce adapters, MCP, registered company keys and IANA RDAP
remain intact. Employee run telemetry/qualification is separate from canonical
workforce state; do not combine their verification counts. The employee replay
checks bundle integrity, not canonical semantic recomputation.

CODED: console, employee routing and additional connectors. TESTED in this workspace:
305 Python tests run, 304 passed and one optional MCP-SDK test skipped; 25
Node graph/target tests and the PGlite database test pass. See PR #26
verification and docs/SOURCE_FABRIC.md. Three historical direct canaries have
hash receipts, not blanket post-merge qualification. DEPLOYED: local package only;
hosted rollout unverified. PRODUCTION_QUALIFIED: zero. Programme milestones remain
open in the canonical delivery ledger.


## Enterprise audit and graph decision boundary â€” 2026-10-04

Audit baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`. Nine scoped reports
under `docs/audit/` record implementation, test, live and production states
separately. The audit found that the in-memory claim graph accepted caller-created
`ACCEPTED` identity/causation edges without an authorized decision record. The
updated graph now rejects those edge types even when a caller supplies
`decision_state="ACCEPTED"`; human candidate decisions remain in
`ResolutionService`. The graph change is MERGED in PR #44; its CI and CodeQL checks passed.

SOCMINT remains a capability gap: approved public search leads and public GitHub
organization metadata do not constitute a social-platform investigation workflow.
No social account enumeration, private data access, contact, login or bypass is
implemented or claimed. Production qualification remains zero.


## Source lifecycle normalization â€” PR #46

The audit baseline `641f159326d45afe9797ddf5624a5126640fdd19` had only 18
qualification gates and could call a source LIVE_VERIFIED with a live-request
receipt plus a runtime flag, even when normalization, evidence, provenance,
security, health and other gates were missing. The source registry now defines
the ordered lifecycle and requires all 19 non-runbook gates plus intended-runtime
verification for LIVE_VERIFIED; PRODUCTION_QUALIFIED requires all 20 gates.
Catalog output separates `connector_implemented` from lifecycle stage and counts
only LIVE_VERIFIED/PRODUCTION_QUALIFIED sources as live integrations. Evaluated
lifecycle transitions are proposals only; they are not persisted or promoted. The current
catalog has no evidence-backed lifecycle promotion; production-qualified count
remains zero. PR #46 merged as `821c387adc1629baed2e13e7c94aff23ae17a609`; its CI
and CodeQL checks passed. The separate automated code-review job could not run
because the GitHub Copilot monthly quota was exceeded (HTTP 402).

## Entity-resolution evaluation update â€” 2026-10-04

Entity comparisons now preserve exact-agreement and differing-field signals in
the explainable result and analyst review queue. Matching scores and thresholds
were not changed. A new deterministic synthetic company-label benchmark evaluates
24 labeled pairs across six queries at the existing 0.72 candidate threshold:
precision 0.80, recall 1.00, F1 0.889, false-positive rate 0.05, and ranking
recall@1/3 both 1.00 on the four positive queries. One same-name candidate with
conflicting organization/domain signals scored 0.7258 and crossed the candidate
threshold; it remained a review candidate and was not merged. Automated merge
attempts are zero, so false-merge rate is undefined (zero denominator), not zero
percent. This small synthetic suite does not estimate operational identity
accuracy. See `ENTITY_RESOLUTION.md` and `docs/program/` for persistent state
and remaining gates.


## Earlier evidence integrity diagnostic â€” 2026-10-04 (superseded by 14-case run)

The new synthetic nine-case evidence/citation evaluation matches 8/9 expected
outcomes. Five routine invalid cases are rejected. It reproduces an integrity
bypass when a local actor rewrites captured bytes, the SQLite digest and the
unanchored hash-chain entry together. The diagnostic is FAIL (exact-outcome
score 0.8889; invalid-case rejection 5/6). Citation-ID checks do not establish
semantic support. See `docs/program/EVALUATION_RESULTS.md` and
`docs/verification/evidence-integrity-synthetic-2026-10-04.json`. External
anchoring, immutable storage, semantic citation correctness and deployed replay
remain unverified; EVIDENCE-001 stays open.

## Opt-in ledger anchoring update

`EvidenceStore` now accepts an operator-provided `LedgerAnchor`; the included
`HmacFileLedgerAnchor` stores signed checkpoints outside the case workspace and
requires an injected key provider. Anchored capture and bundle-verification
paths are opt-in and fail closed without a matching receipt. The expanded
14-case synthetic benchmark matches 13/14 outcomes (0.9286) and rejects 8/9
invalid scenarios (0.8889). It confirms the HMAC path rejects the tested
coordinated local rewrite while the key and receipt are outside the attack
boundary. The unanchored compatibility path still accepts the rewrite.

The file-backed adapter does not provide rollback-safe freshness, append-only
remote storage, production key management or deployment evidence. Citation-ID
membership still does not establish semantic claim support. EVIDENCE-001 stays
open. See `docs/EVIDENCE_ANCHORING.md`.



## 2026-10-04 source independence update

The deterministic `SourceIndependenceEngine` no longer treats a shared
hostname as proof of common origin. This prevents false corroboration when
separate tenants share hosting. Distinct publisher pages can still be grouped
using explicit reviewed ownership metadata. The 12-pair synthetic benchmark
reports TP=7, FP=0, TN=5, FN=0; these synthetic metrics are not operational
accuracy. Focused lineage tests passed 2/2; investigation pipeline 27 passed,
1 skipped; AI workforce 13/13. Full suite ran 328: 321 passed, 3 skipped, 4
failed (three known OpenCTI submodule issues and one Windows loopback-console
connection abort). Curated lineage and contradiction recall remain unmeasured.


The two loopback-console tests passed on an isolated rerun after the full-suite
connection-aborted error. It did not reproduce in isolation; root cause remains
unknown.


## 2026-10-04 temporal contradiction update

The pipeline now calls the same extracted contradiction rule measured by the
synthetic evaluator. Eight pairs produce TP=3, FP=0, TN=5, FN=0. The cases
include temporal overlap/boundaries and exclude multivalued DNS. This does not
measure real-world recall. Focused evaluator tests pass 3/3 and pipeline tests
27/28 (one skip). Full Python suite: 329 run, 323 pass, 3 skip, 3 fail from
the known incomplete OpenCTI checkout; console tests passed. `LINEAGE-001`
remains open pending approved representative data.


The temporal contradiction helper and eight-case diagnostic were pushed in
code commit `e9d1745790a2c4f42dedd08ffbf1dc0429690686` on `codex/source-maturity-taxonomy`. The synthetic report
matches 3/3 labeled conflict cases; representative contradiction recall remains
unknown.

## Persistent enterprise 8/10 program â€” baseline and active repair

The persistent task checklist and engineering memory now live in `.ai/`; the
scorecard, gap register, source ledger, golden-case plan, security status and
release gates live in `docs/program/`. Scores remain UNKNOWN until benchmarked;
overall 8/10 is not established. The 78 controlled Source Fabric cases remain
fixtures, not 78 golden investigations or live integrations.

Baseline main is `dd3085b8f0658d28f88171b5c8225c0c46cea9a9` (PR #48). Its CI run
`37181405185` failed on Python compile jobs and the locked MCP Source Fabric
check; CodeQL run `37181405183` passed. Local inspection reproduced a syntax
error in `src/traceatlas/workforce/source_registry.py` and found conflicting
qualification definitions. An active repair consolidates the shared 23-gate
vocabulary and lifecycle labels, bounds evidence references, and updates
focused tests. Available local checks now pass: Python 313 tests (310 passed,
three skipped), source compilation, secret scan, graph/target 25/25, PGlite 1/1,
employee UI browser checks, controlled Source Fabric replay 78/78, and restore
integrity drill. PR #49 code/test head
`1767708adc27e9dc05e0384a4682571e3797d6c4` passed hosted CI `37184302223`
and CodeQL `37184302217`, including worker-image verification. The PR is open;
do not treat this repair as merged or released.

No new live source was contacted or production qualification completed for this
repair. Existing 26 adapter and zero production-qualified counts remain in force.

The local TA-003 follow-up also closes a review-reference gap: Source Fabric
review rows now resolve each evidence hash against artifacts in that same case,
and promotion rechecks the ledger and every reference. Invalid legacy/direct
database rows cannot sustain production-qualified state. Focused tests (28) and
the full Python suite (315; 3 skipped) pass locally; hosted checks for this
follow-up pass in PR #50: CI `37185114010` and CodeQL `37185114003`. No source
was promoted.

## Latest local verification â€” 2026-10-04

On the earlier unsynchronized local checkout, the full Python suite passed (329 run, 326 passed, 3 skipped, no failures); OpenCTI-focused tests passed 7/7. Fifteen deep files under the pinned OpenCTI connector commit were restored from Git blobs and sampled hashes match. Git for Windows still warns that these paths exceed its enumeration limit, so its submodule status output is not authoritative here. Enterprise maturity remains unscored; mandatory release gates remain open.
# Current implementation state â€” 2026-10-04 / 1.12.0

The Source Fabric portfolio program adds full governed research fields, atomic
research imports, all 15 family targets, conservative upstream dataset grouping,
an explicitly uncalibrated quality score, a non-executing four-wave planner,
per-source health reporting, and reusable protocol primitives over reviewed
fixed-host connectors. A successful live request is now only LIVE_TESTED until
recent source reviews resolve to same-case evidence; the shared qualification
checklist includes privacy, replay and intended-runtime validation (26 gates).
See [SOURCE_FABRIC_PROGRAM.md](SOURCE_FABRIC_PROGRAM.md) for commands and remaining
acceptance work. The 650/600/450/300/200/125 targets remain unmet; protocol
primitives, candidate rows and parser tests do not establish provider counts.

Source-inventory metrics below were audited against PR #43 baseline
`d698ed519be078ec72092b33dacda9f92ffdb42c`. Main now includes the 2026-10-04
enterprise audit and bounded graph acceptance fix, merged in PR #44 at
`89069097a66899eabc55897114146cf51f81dc45`; its CI and CodeQL checks passed.
See `docs/audit/` for the baseline reports.
Both source briefs are reconciled in `docs/sources/DELIVERY_LEDGER.md`; Phase A is implemented,
later programme phases and production qualification remain incomplete. Exact-CVE
NVD, FIRST EPSS, CVE Program, OSV, npm and CISA KEV records flow through the approved
source gateway, evidence, verification, graph and replay path. The CISA KEV feed is
fixed-host and schema-validated; facts are restricted to the exact CVE match while the bounded raw response is retained for replay.

The canonical local path is typed seed â†’ immutable authority â†’ capability/source
plan â†’ digest approval â†’ bounded gateway â†’ captured bytes â†’ observations â†’ source
lineage â†’ verification â†’ graph/timeline â†’ draft â†’ offline replay. The existing
SQLite/EvidenceStore and five employee roles remain the authorities.

Twenty-six shared workforce adapters cover public DNS, RDAP, CT, passive URL/archive
indexes, IP ownership/ASN/exposure/context, search, company registers, LEI, SEC
filing metadata, public GitHub organizations, exact CVE/advisory records, exploitation
probability, CISA KEV catalog listing and remediation metadata, and npm package
metadata. CISA catalog membership is a source observation, not proof an asset is
affected; it is not independent evidence of exploitation. Company collection requires exact
registered identifiers, never a same-name match. Person investigations still use
approved records. Model-free normalization and report generation remain supported.

| Delivery state | Evidence |
|---|---|
| CODED | Capability registry/router, 26-adapter SDK, bounded parallel gateway, scoped cache, health/canary recovery, cost limits and six MCP tools |
| VERIFIED in CI | Python 3.10 and 3.12: 305 tests each, 303 passed and two optional tests skipped; PGlite and 25 Node UI/target tests pass; 78/78 controlled source scenarios replay successfully; compilation, dependency review, supply-chain evidence, worker image and CodeQL pass |
| Real response parsing/replay | Cloudflare DNS, RIPEstat, GLEIF and GitHub public reference responses through an injected environment-proxy requester; all captured/replayed |
| Direct transport qualification | All five new canaries fail closed on this environment's direct DNS; crt.sh proxy response quarantined for schema mismatch |
| DEPLOYED | Private hosted runner/product view and production rollout remain unverified |
| PRODUCTION_QUALIFIED | Zero source claims; current terms/account entitlement, sustained health and intended-runtime verification outstanding |

Registry counts overlap: 51 workforce metadata entries, 26 canonical approval-driven workforce adapters, and 49 IntelligenceHub entries of which 35 have API implementations. The supplied 400
candidate rows deduplicate to 351 research rows, 41 flagged as generic categories.
A candidate, code path or configured key is never counted as a verified integration.

The router chooses capabilities using explainable heuristics and may preapprove
one fallback wave. Eight request attempts, USD 1 estimated budget and 120 seconds
remain the per-task bounds. Public requests use fixed-host, direct TLS transport;
no proxy fallback was added to the shipped transport. Observed prices are not
billing measurements. Rate/concurrency ceilings are process-local, not a distributed
quota guarantee. All fresh collection rechecks authority and the kill switch.

Paid-source credentials, deployed SearXNG and SEC operator contact are not
established here. Beneficial ownership, sanctions, procurement and public
geospatial coverage remain gaps. Package and vulnerability collection now uses
the canonical authority, source plan, evidence, verification, graph, next-action
and replay path.
Country packs, calibrated information gain, semantic/multilingual planning,
marketplace discovery, distributed workers, model-provider qualification and
hosted operations remain gaps. No contact, active scans, account action, identity
merge or material report release is automated.

The workflow/parser version changed; old evidence stays immutable, and unsupported
historical replay versions fail closed. Retain the previous release to replay its
products. Source health and TTL do not prove the truth of a provider's assertion.

See `docs/sources/SOURCE_FABRIC.md`, `docs/sources/SOURCE_AUDIT_MATRIX.csv`,
`docs/verification/source-fabric-2026-10-03.json`, `docs/LIVE_SOURCES.md` and
`docs/ACCEPTANCE_GATES.md`. The current Markdown/task reconciliation is recorded
in `docs/COMPLETION_AUDIT_2026-10-04.md`. Earlier cycle evidence remains in
`docs/verification/live-sources-2026-10-03.json` and `docs/IMPLEMENTATION_REPORT.md`.

Source manifests now expose the canonical eleven-state maturity vocabulary;
catalogued records, coded connectors, live verification and production
qualification have separate labels and counts. `BROKEN` is normalized to the
`DEGRADED` maturity state, while source health remains a separate field. This
local code change does not qualify any source: the repository still has zero
production-qualified claims until evidence gates and intended-runtime canaries
are completed. See `docs/SOURCE_MATURITY.md`.

The workforce source plan also carries a deterministic, schema-versioned
investigation plan with target-bound questions, evidence checks, candidate sources,
execution waves, verification requirements and stop conditions for registered
target types. It creates no hypotheses and does not claim multilingual or free-form
semantic planning; source scores remain uncalibrated heuristics.

## Employee console integration (PR #26)

Adds `employee serve` and `employee investigate`: local bounded runs, checkpoints,
cancellation, cited graph/report, optional local-model drafting and evidence ZIP.
Shared IntelligenceHub now has 49 records / 35 API implementations with NVD, CVE Program, FIRST EPSS, CISA KEV, OSV and npm. Canonical workforce adapters, MCP, registered company keys and IANA RDAP
remain intact. Employee run telemetry/qualification is separate from canonical
workforce state; do not combine their verification counts. The employee replay
checks bundle integrity, not canonical semantic recomputation.

CODED: console, employee routing and additional connectors. TESTED in this workspace:
305 Python tests run, 304 passed and one optional MCP-SDK test skipped; 25
Node graph/target tests and the PGlite database test pass. See PR #26
verification and docs/SOURCE_FABRIC.md. Three historical direct canaries have
hash receipts, not blanket post-merge qualification. DEPLOYED: local package only;
hosted rollout unverified. PRODUCTION_QUALIFIED: zero. Programme milestones remain
open in the canonical delivery ledger.


## Enterprise audit and graph decision boundary â€” 2026-10-04

Audit baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`. Nine scoped reports
under `docs/audit/` record implementation, test, live and production states
separately. The audit found that the in-memory claim graph accepted caller-created
`ACCEPTED` identity/causation edges without an authorized decision record. The
updated graph now rejects those edge types even when a caller supplies
`decision_state="ACCEPTED"`; human candidate decisions remain in
`ResolutionService`. The graph change is MERGED in PR #44; its CI and CodeQL checks passed.

SOCMINT remains a capability gap: approved public search leads and public GitHub
organization metadata do not constitute a social-platform investigation workflow.
No social account enumeration, private data access, contact, login or bypass is
implemented or claimed. Production qualification remains zero.


## Source lifecycle normalization â€” PR #46

The audit baseline `641f159326d45afe9797ddf5624a5126640fdd19` had only 18
qualification gates and could call a source LIVE_VERIFIED with a live-request
receipt plus a runtime flag, even when normalization, evidence, provenance,
security, health and other gates were missing. The source registry now defines
the ordered lifecycle and requires all 19 non-runbook gates plus intended-runtime
verification for LIVE_VERIFIED; PRODUCTION_QUALIFIED requires all 20 gates.
Catalog output separates `connector_implemented` from lifecycle stage and counts
only LIVE_VERIFIED/PRODUCTION_QUALIFIED sources as live integrations. Evaluated
lifecycle transitions are proposals only; they are not persisted or promoted. The current
catalog has no evidence-backed lifecycle promotion; production-qualified count
remains zero. PR #46 merged as `821c387adc1629baed2e13e7c94aff23ae17a609`; its CI
and CodeQL checks passed. The separate automated code-review job could not run
because the GitHub Copilot monthly quota was exceeded (HTTP 402).
# Current implementation state â€” 2026-10-04 / 1.11.0

Source-inventory metrics below were audited against PR #43 baseline
`d698ed519be078ec72092b33dacda9f92ffdb42c`. Main now includes the 2026-10-04
enterprise audit and bounded graph acceptance fix, merged in PR #44 at
`89069097a66899eabc55897114146cf51f81dc45`; its CI and CodeQL checks passed.
See `docs/audit/` for the baseline reports.
Both source briefs are reconciled in `docs/sources/DELIVERY_LEDGER.md`; Phase A is implemented,
later programme phases and production qualification remain incomplete. Exact-CVE
NVD, FIRST EPSS, CVE Program, OSV, npm and CISA KEV records flow through the approved
source gateway, evidence, verification, graph and replay path. The CISA KEV feed is
fixed-host and schema-validated; facts are restricted to the exact CVE match while the bounded raw response is retained for replay.

The canonical local path is typed seed â†’ immutable authority â†’ capability/source
plan â†’ digest approval â†’ bounded gateway â†’ captured bytes â†’ observations â†’ source
lineage â†’ verification â†’ graph/timeline â†’ draft â†’ offline replay. The existing
SQLite/EvidenceStore and five employee roles remain the authorities.

Twenty-six shared workforce adapters cover public DNS, RDAP, CT, passive URL/archive
indexes, IP ownership/ASN/exposure/context, search, company registers, LEI, SEC
filing metadata, public GitHub organizations, exact CVE/advisory records, exploitation
probability, CISA KEV catalog listing and remediation metadata, and npm package
metadata. CISA catalog membership is a source observation, not proof an asset is
affected; it is not independent evidence of exploitation. Company collection requires exact
registered identifiers, never a same-name match. Person investigations still use
approved records. Model-free normalization and report generation remain supported.

| Delivery state | Evidence |
|---|---|
| CODED | Capability registry/router, 26-adapter SDK, bounded parallel gateway, scoped cache, health/canary recovery, cost limits and six MCP tools |
| VERIFIED in CI | Python 3.10 and 3.12: 305 tests each, 303 passed and two optional tests skipped; PGlite and 25 Node UI/target tests pass; 78/78 controlled source scenarios replay successfully; compilation, dependency review, supply-chain evidence, worker image and CodeQL pass |
| Real response parsing/replay | Cloudflare DNS, RIPEstat, GLEIF and GitHub public reference responses through an injected environment-proxy requester; all captured/replayed |
| Direct transport qualification | All five new canaries fail closed on this environment's direct DNS; crt.sh proxy response quarantined for schema mismatch |
| DEPLOYED | Private hosted runner/product view and production rollout remain unverified |
| PRODUCTION_QUALIFIED | Zero source claims; current terms/account entitlement, sustained health and intended-runtime verification outstanding |

Registry counts overlap: 51 workforce metadata entries, 26 canonical approval-driven workforce adapters, and 49 IntelligenceHub entries of which 35 have API implementations. The supplied 400
candidate rows deduplicate to 351 research rows, 41 flagged as generic categories.
A candidate, code path or configured key is never counted as a verified integration.

The router chooses capabilities using explainable heuristics and may preapprove
one fallback wave. Eight request attempts, USD 1 estimated budget and 120 seconds
remain the per-task bounds. Public requests use fixed-host, direct TLS transport;
no proxy fallback was added to the shipped transport. Observed prices are not
billing measurements. Rate/concurrency ceilings are process-local, not a distributed
quota guarantee. All fresh collection rechecks authority and the kill switch.

Paid-source credentials, deployed SearXNG and SEC operator contact are not
established here. Beneficial ownership, sanctions, procurement and public
geospatial coverage remain gaps. Package and vulnerability collection now uses
the canonical authority, source plan, evidence, verification, graph, next-action
and replay path.
Country packs, calibrated information gain, semantic/multilingual planning,
marketplace discovery, distributed workers, model-provider qualification and
hosted operations remain gaps. No contact, active scans, account action, identity
merge or material report release is automated.

The workflow/parser version changed; old evidence stays immutable, and unsupported
historical replay versions fail closed. Retain the previous release to replay its
products. Source health and TTL do not prove the truth of a provider's assertion.

See `docs/sources/SOURCE_FABRIC.md`, `docs/sources/SOURCE_AUDIT_MATRIX.csv`,
`docs/verification/source-fabric-2026-10-03.json`, `docs/LIVE_SOURCES.md` and
`docs/ACCEPTANCE_GATES.md`. The current Markdown/task reconciliation is recorded
in `docs/COMPLETION_AUDIT_2026-10-04.md`. Earlier cycle evidence remains in
`docs/verification/live-sources-2026-10-03.json` and `docs/IMPLEMENTATION_REPORT.md`.

Source manifests now expose the canonical eleven-state maturity vocabulary;
catalogued records, coded connectors, live verification and production
qualification have separate labels and counts. `BROKEN` is normalized to the
`DEGRADED` maturity state, while source health remains a separate field. This
local code change does not qualify any source: the repository still has zero
production-qualified claims until evidence gates and intended-runtime canaries
are completed. See `docs/SOURCE_MATURITY.md`.

The workforce source plan also carries a deterministic, schema-versioned
investigation plan with target-bound questions, evidence checks, candidate sources,
execution waves, verification requirements and stop conditions for registered
target types. It creates no hypotheses and does not claim multilingual or free-form
semantic planning; source scores remain uncalibrated heuristics.

## Employee console integration (PR #26)

Adds `employee serve` and `employee investigate`: local bounded runs, checkpoints,
cancellation, cited graph/report, optional local-model drafting and evidence ZIP.
Shared IntelligenceHub now has 49 records / 35 API implementations with NVD, CVE Program, FIRST EPSS, CISA KEV, OSV and npm. Canonical workforce adapters, MCP, registered company keys and IANA RDAP
remain intact. Employee run telemetry/qualification is separate from canonical
workforce state; do not combine their verification counts. The employee replay
checks bundle integrity, not canonical semantic recomputation.

CODED: console, employee routing and additional connectors. TESTED in this workspace:
305 Python tests run, 304 passed and one optional MCP-SDK test skipped; 25
Node graph/target tests and the PGlite database test pass. See PR #26
verification and docs/SOURCE_FABRIC.md. Three historical direct canaries have
hash receipts, not blanket post-merge qualification. DEPLOYED: local package only;
hosted rollout unverified. PRODUCTION_QUALIFIED: zero. Programme milestones remain
open in the canonical delivery ledger.


## Enterprise audit and graph decision boundary â€” 2026-10-04

Audit baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`. Nine scoped reports
under `docs/audit/` record implementation, test, live and production states
separately. The audit found that the in-memory claim graph accepted caller-created
`ACCEPTED` identity/causation edges without an authorized decision record. The
updated graph now rejects those edge types even when a caller supplies
`decision_state="ACCEPTED"`; human candidate decisions remain in
`ResolutionService`. The graph change is MERGED in PR #44; its CI and CodeQL checks passed.

SOCMINT remains a capability gap: approved public search leads and public GitHub
organization metadata do not constitute a social-platform investigation workflow.
No social account enumeration, private data access, contact, login or bypass is
implemented or claimed. Production qualification remains zero.


## Source lifecycle normalization â€” PR #46

The audit baseline `641f159326d45afe9797ddf5624a5126640fdd19` had only 18
qualification gates and could call a source LIVE_VERIFIED with a live-request
receipt plus a runtime flag, even when normalization, evidence, provenance,
security, health and other gates were missing. The source registry now defines
the ordered lifecycle and requires all 19 non-runbook gates plus intended-runtime
verification for LIVE_VERIFIED; PRODUCTION_QUALIFIED requires all 20 gates.
Catalog output separates `connector_implemented` from lifecycle stage and counts
only LIVE_VERIFIED/PRODUCTION_QUALIFIED sources as live integrations. Evaluated
lifecycle transitions are proposals only; they are not persisted or promoted. The current
catalog has no evidence-backed lifecycle promotion; production-qualified count
remains zero. PR #46 merged as `821c387adc1629baed2e13e7c94aff23ae17a609`; its CI
and CodeQL checks passed. The separate automated code-review job could not run
because the GitHub Copilot monthly quota was exceeded (HTTP 402).

## Entity-resolution evaluation update â€” 2026-10-04

Entity comparisons now preserve exact-agreement and differing-field signals in
the explainable result and analyst review queue. Matching scores and thresholds
were not changed. A new deterministic synthetic company-label benchmark evaluates
24 labeled pairs across six queries at the existing 0.72 candidate threshold:
precision 0.80, recall 1.00, F1 0.889, false-positive rate 0.05, and ranking
recall@1/3 both 1.00 on the four positive queries. One same-name candidate with
conflicting organization/domain signals scored 0.7258 and crossed the candidate
threshold; it remained a review candidate and was not merged. Automated merge
attempts are zero, so false-merge rate is undefined (zero denominator), not zero
percent. This small synthetic suite does not estimate operational identity
accuracy. See `ENTITY_RESOLUTION.md` and `docs/program/` for persistent state
and remaining gates.


## Earlier evidence integrity diagnostic â€” 2026-10-04 (superseded by 14-case run)

The new synthetic nine-case evidence/citation evaluation matches 8/9 expected
outcomes. Five routine invalid cases are rejected. It reproduces an integrity
bypass when a local actor rewrites captured bytes, the SQLite digest and the
unanchored hash-chain entry together. The diagnostic is FAIL (exact-outcome
score 0.8889; invalid-case rejection 5/6). Citation-ID checks do not establish
semantic support. See `docs/program/EVALUATION_RESULTS.md` and
`docs/verification/evidence-integrity-synthetic-2026-10-04.json`. External
anchoring, immutable storage, semantic citation correctness and deployed replay
remain unverified; EVIDENCE-001 stays open.

## Opt-in ledger anchoring update

`EvidenceStore` now accepts an operator-provided `LedgerAnchor`; the included
`HmacFileLedgerAnchor` stores signed checkpoints outside the case workspace and
requires an injected key provider. Anchored capture and bundle-verification
paths are opt-in and fail closed without a matching receipt. The expanded
14-case synthetic benchmark matches 13/14 outcomes (0.9286) and rejects 8/9
invalid scenarios (0.8889). It confirms the HMAC path rejects the tested
coordinated local rewrite while the key and receipt are outside the attack
boundary. The unanchored compatibility path still accepts the rewrite.

The file-backed adapter does not provide rollback-safe freshness, append-only
remote storage, production key management or deployment evidence. Citation-ID
membership still does not establish semantic claim support. EVIDENCE-001 stays
open. See `docs/EVIDENCE_ANCHORING.md`.



## 2026-10-04 source independence update

The deterministic `SourceIndependenceEngine` no longer treats a shared
hostname as proof of common origin. This prevents false corroboration when
separate tenants share hosting. Distinct publisher pages can still be grouped
using explicit reviewed ownership metadata. The 12-pair synthetic benchmark
reports TP=7, FP=0, TN=5, FN=0; these synthetic metrics are not operational
accuracy. Focused lineage tests passed 2/2; investigation pipeline 27 passed,
1 skipped; AI workforce 13/13. Full suite ran 328: 321 passed, 3 skipped, 4
failed (three known OpenCTI submodule issues and one Windows loopback-console
connection abort). Curated lineage and contradiction recall remain unmeasured.


The two loopback-console tests passed on an isolated rerun after the full-suite
connection-aborted error. It did not reproduce in isolation; root cause remains
unknown.


## 2026-10-04 temporal contradiction update

The pipeline now calls the same extracted contradiction rule measured by the
synthetic evaluator. Eight pairs produce TP=3, FP=0, TN=5, FN=0. The cases
include temporal overlap/boundaries and exclude multivalued DNS. This does not
measure real-world recall. Focused evaluator tests pass 3/3 and pipeline tests
27/28 (one skip). Full Python suite: 329 run, 323 pass, 3 skip, 3 fail from
the known incomplete OpenCTI checkout; console tests passed. `LINEAGE-001`
remains open pending approved representative data.


The temporal contradiction helper and eight-case diagnostic were pushed in
code commit `e9d1745790a2c4f42dedd08ffbf1dc0429690686` on `codex/source-maturity-taxonomy`. The synthetic report
matches 3/3 labeled conflict cases; representative contradiction recall remains
unknown.

## Persistent enterprise 8/10 program â€” baseline and active repair

The persistent task checklist and engineering memory now live in `.ai/`; the
scorecard, gap register, source ledger, golden-case plan, security status and
release gates live in `docs/program/`. Scores remain UNKNOWN until benchmarked;
overall 8/10 is not established. The 78 controlled Source Fabric cases remain
fixtures, not 78 golden investigations or live integrations.

Baseline main is `dd3085b8f0658d28f88171b5c8225c0c46cea9a9` (PR #48). Its CI run
`37181405185` failed on Python compile jobs and the locked MCP Source Fabric
check; CodeQL run `37181405183` passed. Local inspection reproduced a syntax
error in `src/traceatlas/workforce/source_registry.py` and found conflicting
qualification definitions. An active repair consolidates the shared 23-gate
vocabulary and lifecycle labels, bounds evidence references, and updates
focused tests. Available local checks now pass: Python 313 tests (310 passed,
three skipped), source compilation, secret scan, graph/target 25/25, PGlite 1/1,
employee UI browser checks, controlled Source Fabric replay 78/78, and restore
integrity drill. PR #49 code/test head
`1767708adc27e9dc05e0384a4682571e3797d6c4` passed hosted CI `37184302223`
and CodeQL `37184302217`, including worker-image verification. The PR is open;
do not treat this repair as merged or released.

No new live source was contacted or production qualification completed for this
repair. Existing 26 adapter and zero production-qualified counts remain in force.

The local TA-003 follow-up also closes a review-reference gap: Source Fabric
review rows now resolve each evidence hash against artifacts in that same case,
and promotion rechecks the ledger and every reference. Invalid legacy/direct
database rows cannot sustain production-qualified state. Focused tests (28) and
the full Python suite (315; 3 skipped) pass locally; hosted checks for this
follow-up pass in PR #50: CI `37185114010` and CodeQL `37185114003`. No source
was promoted.


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
