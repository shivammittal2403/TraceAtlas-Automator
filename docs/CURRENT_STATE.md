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
