# Current implementation state — 2026-10-04 / 1.11.0

The source work from merged PRs #24–#29 and vulnerability-source integration in #32–#35 is included in current `main`. Both source briefs are reconciled in
`docs/sources/DELIVERY_LEDGER.md`; Phase A is implemented, later programme phases
are explicitly incomplete. PR #32 connected exact-CVE NVD, FIRST EPSS, OSV and npm
records to the canonical authority, approval, evidence, verification, graph and replay
path. PR #34 corrected the NVD fixture host and restored the root README; PR #35
preserves CISA KEV fields when NVD supplies them, with NVD retained as the evidence
source and no separate CISA connector claim.

The canonical local path is typed seed → immutable authority → capability/source
plan → digest approval → bounded gateway → captured bytes → observations → source
lineage → verification → graph/timeline → draft → offline replay. The existing
SQLite/EvidenceStore and five employee roles remain the authorities.

Twenty-five shared workforce adapters cover public DNS, RDAP, CT, passive URL/archive
indexes, IP ownership/ASN/exposure/context, search, company registers, LEI, SEC
filing metadata, public GitHub organizations, exact CVE/advisory records, exploitation
probability and npm package metadata. NVD records also preserve CISA KEV listing and
remediation metadata when supplied; those embedded CISA fields are not counted as a
separate CISA connector or independent source. Company collection requires exact
registered identifiers, never a same-name match. Person investigations still use
approved records. Model-free normalization and report generation remain supported.

| Delivery state | Evidence |
|---|---|
| CODED | Capability registry/router, 25-adapter SDK, bounded parallel gateway, scoped cache, health/canary recovery, cost limits and six MCP tools |
| VERIFIED in CI | Python 3.10 and 3.12: 305 tests each, 303 passed and two optional tests skipped; PGlite and 25 Node UI/target tests pass; 75/75 controlled source scenarios replay successfully; compilation, dependency review, supply-chain evidence, worker image and CodeQL pass |
| Real response parsing/replay | Cloudflare DNS, RIPEstat, GLEIF and GitHub public reference responses through an injected environment-proxy requester; all captured/replayed |
| Direct transport qualification | All five new canaries fail closed on this environment's direct DNS; crt.sh proxy response quarantined for schema mismatch |
| DEPLOYED | Private hosted runner/product view and production rollout remain unverified |
| PRODUCTION_QUALIFIED | Zero source claims; current terms/account entitlement, sustained health and intended-runtime verification outstanding |

Registry counts overlap: 50 workforce metadata entries, 25 canonical approval-driven workforce adapters, and 48 IntelligenceHub entries of which 34 have API implementations. The supplied 400
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

## Employee console integration (PR #26)

Adds `employee serve` and `employee investigate`: local bounded runs, checkpoints,
cancellation, cited graph/report, optional local-model drafting and evidence ZIP.
Shared IntelligenceHub now has 48 records / 34 API implementations with NVD, FIRST EPSS, OSV and npm. Canonical workforce adapters, MCP, registered company keys and IANA RDAP
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
