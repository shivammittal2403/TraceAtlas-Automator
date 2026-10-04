# Source gap analysis

Baseline: `641f159326d45afe9797ddf5624a5126640fdd19`, 2026-10-04. References: `docs/sources/SOURCE_FABRIC.md`, `docs/sources/DELIVERY_LEDGER.md`, `docs/sources/SOURCE_AUDIT_MATRIX.csv`.

## Baseline inventory

- 26 canonical approval-driven adapter definitions: coded/fixture-tested, not 26 live integrations.
- 51 workforce metadata definitions, 49 IntelligenceHub entries and 35 IntelligenceHub API implementations: overlapping catalog/runtime counts.
- Selected public responses were captured and replayed through proxy-assisted requests; direct transport canaries failed in the audited environment.
- Production-qualified sources: 0, per current state.
- Source lifecycle lacked TERMS_REVIEWED and LIVE_TESTED; LIVE_VERIFIED could be promoted with only a live-request gate plus a boolean runtime flag.

## Source lifecycle correction in current iteration

`DISCOVERED → CATALOGUED → TERMS_REVIEWED → CONNECTOR_IMPLEMENTED → CONFIGURED
→ LIVE_TESTED → LIVE_VERIFIED → PRODUCTION_QUALIFIED`, with operational
`DEGRADED`, `DISABLED` and `DEPRECATED` states. Code presence is exposed
separately from lifecycle state. LIVE_TESTED requires prior terms, connector and
configuration gates plus a successful live request. LIVE_VERIFIED requires the
non-runbook qualification gates and verified intended runtime. PRODUCTION_QUALIFIED
requires all gates. Counts treat only LIVE_VERIFIED and PRODUCTION_QUALIFIED as
live integrations.

The evaluator checks that references are present but does not resolve artifacts or independently verify attestations. Registry status receipts are not yet stored in a durable qualification ledger. The transition validator and counts are implemented in this iteration; persisted, independently verified lifecycle governance is the next gap. Current live and production-qualified counts remain 0.

## Connector quality gaps

Provider code, manifests, terms, auth, rate limits, licensing and evidence behavior need source-specific review. Per-process concurrency is not a distributed quota; actual billing and sustained SLIs are open. Do not chase source-name targets until 25 sources pass intended-runtime qualification and usefulness review.
