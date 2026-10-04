# Source audit

Baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`, 2026-10-04. See `docs/sources/DELIVERY_LEDGER.md`, `docs/LIVE_SOURCES.md`, `docs/CURRENT_STATE.md` and source audit matrix for inventory details.

## Inventory and evidence levels

- **IMPLEMENTED / TESTED:** 26 approval-driven workforce adapters use the shared bounded source contract; 51 metadata entries and 49 IntelligenceHub records (35 API implementations) are catalog/runtime figures with overlap, not additive unique sources.
- **TESTED:** repository reports 78 controlled source scenarios and CI suites; these are adapter scenarios, not 78 distinct live investigations.
- **LIVE_TESTED:** selected Cloudflare DNS, RIPEstat, GLEIF and public GitHub responses were captured through an injected environment-proxy requester and replayed. This is response parsing/replay evidence, not shipped direct transport qualification.
- **NOT LIVE_QUALIFIED:** five canaries failed closed on direct DNS in the audited environment; a crt.sh proxy response was quarantined for schema mismatch.
- **PRODUCTION_QUALIFIED:** 0 source claims. Real account entitlements, billing, sustained health and intended-runtime verification are open.

## Controls and limits

The canonical gateway applies case authority, fixed-host transport, request/time/cost bounds, cache scoping, evidence capture and replay. Source facts are restricted to supported exact structured predicates; raw captured bytes are retained for replay. A healthy endpoint or hash does not establish the truth of a provider assertion. User-provided catalog rows are candidates, not integrations or licenses.

## Priority actions

Maintain per-source status and freshness receipts. For each provider, capture lawful access basis, terms/entitlement, target scope, schema drift handling, direct transport, rate/billing behavior, failure modes and analyst utility. Keep source outputs as observations with citations; do not merge identities from source matches alone. No new credentials or provider account actions are part of this audit.
