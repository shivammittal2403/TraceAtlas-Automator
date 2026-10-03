# Current implementation state — 2026-10-03 / 1.11.0

Source Fabric baseline is merged PR #24, main
`26dc8b8f41ed901ae65246f5ff91e38aff7fe1b1`. The earlier live-source request is
included there. Both new source briefs are reconciled in
`docs/sources/DELIVERY_LEDGER.md`; Phase A is implemented, later programme phases
are explicitly incomplete.

The canonical local path is typed seed → immutable authority → capability/source
plan → digest approval → bounded gateway → captured bytes → observations → source
lineage → verification → graph/timeline → draft → offline replay. The existing
SQLite/EvidenceStore and five employee roles remain the authorities.

Twenty shared workforce adapters cover public DNS, RDAP, CT, passive URL/archive
indexes, IP ownership/ASN/exposure/context, search, company registers, LEI, SEC
filing metadata and public GitHub organizations. Company collection requires exact
registered identifiers, never a same-name match. Person investigations still use
approved records. Model-free normalization and report generation remain supported.

| Delivery state | Evidence |
|---|---|
| CODED | Capability registry/router, 20-adapter SDK, bounded parallel gateway, scoped cache, health/canary recovery, cost limits and six MCP tools |
| TESTED locally | 271 Python tests run (one optional SDK test skipped in core); 15 tests pass separately with MCP 2.3 including real wire exchange; three Node graph/target/PGlite test files pass; 60/60 controlled source scenarios replay; browser flow and all required CI/CodeQL gates passed on implementation commit c199c799 |
| Real response parsing/replay | Cloudflare DNS, RIPEstat, GLEIF and GitHub public reference responses through an injected environment-proxy requester; all captured/replayed |
| Direct transport qualification | All five new canaries fail closed on this environment's direct DNS; crt.sh proxy response quarantined for schema mismatch |
| DEPLOYED | Private hosted runner/product view and production rollout remain unverified |
| PRODUCTION_QUALIFIED | Zero source claims; current terms/account entitlement, sustained health and intended-runtime verification outstanding |

Registry counts overlap: 47 metadata entries, 20 shared workforce adapters,
45 IntelligenceHub entries of which 31 have API implementations. The supplied 400
candidate rows deduplicate to 351 research rows, 41 flagged as generic categories.
A candidate, code path or configured key is never counted as a verified integration.

The router chooses capabilities using explainable heuristics and may preapprove
one fallback wave. Eight request attempts, USD 1 estimated budget and 120 seconds
remain the per-task bounds. Public requests use fixed-host, direct TLS transport;
no proxy fallback was added to the shipped transport. Observed prices are not
billing measurements. Rate/concurrency ceilings are process-local, not a distributed
quota guarantee. All fresh collection rechecks authority and the kill switch.

Paid-source credentials, deployed SearXNG and SEC operator contact are not
established here. Beneficial ownership, sanctions, procurement, public geospatial,
package and vulnerability company workflows require additional canonical adapters.
Country packs, calibrated information gain, semantic/multilingual planning,
marketplace discovery, distributed workers, model-provider qualification and
hosted operations remain gaps. No contact, active scans, account action, identity
merge or material report release is automated.

The workflow/parser version changed; old evidence stays immutable, and unsupported
historical replay versions fail closed. Retain the previous release to replay its
products. Source health and TTL do not prove the truth of a provider's assertion.

See `docs/sources/SOURCE_FABRIC.md`, `docs/sources/SOURCE_AUDIT_MATRIX.csv`,
`docs/verification/source-fabric-2026-10-03.json`, `docs/LIVE_SOURCES.md` and
`docs/ACCEPTANCE_GATES.md`. Earlier cycle evidence remains in
`docs/verification/live-sources-2026-10-03.json` and `docs/IMPLEMENTATION_REPORT.md`.
