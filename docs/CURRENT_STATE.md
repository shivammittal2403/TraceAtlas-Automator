# Current implementation state — 2026-10-04 / 1.11.0

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

# Current implementation state — 2026-10-04 / 1.11.0

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

The canonical local path is typed seed → immutable authority → capability/source
plan → digest approval → bounded gateway → captured bytes → observations → source
lineage → verification → graph/timeline → draft → offline replay. The existing
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


## Enterprise audit and graph decision boundary — 2026-10-04

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


## Source lifecycle normalization — PR #46

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

## Entity-resolution evaluation update — 2026-10-04

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


## Earlier evidence integrity diagnostic — 2026-10-04 (superseded by 14-case run)

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

## Persistent enterprise 8/10 program — baseline and active repair

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

## Latest local verification — 2026-10-04

On the earlier unsynchronized local checkout, the full Python suite passed (329 run, 326 passed, 3 skipped, no failures); OpenCTI-focused tests passed 7/7. Fifteen deep files under the pinned OpenCTI connector commit were restored from Git blobs and sampled hashes match. Git for Windows still warns that these paths exceed its enumeration limit, so its submodule status output is not authoritative here. Enterprise maturity remains unscored; mandatory release gates remain open.
# Current implementation state — 2026-10-04 / 1.12.0

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

The canonical local path is typed seed → immutable authority → capability/source
plan → digest approval → bounded gateway → captured bytes → observations → source
lineage → verification → graph/timeline → draft → offline replay. The existing
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


## Enterprise audit and graph decision boundary — 2026-10-04

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


## Source lifecycle normalization — PR #46

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
# Current implementation state — 2026-10-04 / 1.11.0

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

The canonical local path is typed seed → immutable authority → capability/source
plan → digest approval → bounded gateway → captured bytes → observations → source
lineage → verification → graph/timeline → draft → offline replay. The existing
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


## Enterprise audit and graph decision boundary — 2026-10-04

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


## Source lifecycle normalization — PR #46

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

## Entity-resolution evaluation update — 2026-10-04

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


## Earlier evidence integrity diagnostic — 2026-10-04 (superseded by 14-case run)

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

## Persistent enterprise 8/10 program — baseline and active repair

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
