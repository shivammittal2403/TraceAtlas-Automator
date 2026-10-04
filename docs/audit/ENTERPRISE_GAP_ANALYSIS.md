# Enterprise gap analysis

Baseline: main `641f159326d45afe9797ddf5624a5126640fdd19` (2026-10-04).

## Highest-value findings

| Priority | Gap | Baseline evidence | State |
|---|---|---|---|
| P0 release gate | Authenticated multi-tenant production acceptance | Docs report synthetic RLS tests; no live JWT/Auth, tenant recovery, or staging proof | OPEN |
| P0 release gate | Production sources | Current state reports zero production-qualified sources | OPEN |
| P1 | False source qualification | One live-request gate and runtime boolean could yield LIVE_VERIFIED while other gates failed | OPEN at baseline; corrected in this iteration |
| P1 | Source lifecycle/cost/entitlement record | Terms-review and live-tested states absent; no durable qualification ledger | PARTIAL |
| P1 | Semantic planning and bounded iteration | Deterministic typed router exists; calibrated semantic planning/IG and full loop remain | PARTIAL |
| P1 | Entity-resolution metrics | Case-local review exists; no labeled population precision/recall/calibration | OPEN |
| P1 | SOCMINT | No integrated social workflow | NOT_IMPLEMENTED |
| P1 | Operational assurance | Local observability and backup fixture; staging/DR/load/incident evidence incomplete | PARTIAL |
| P2 | Country/multilingual workflows | Primitives and plans exist; integrated India/multilingual packs unqualified | PARTIAL |
| P2 | 100-investigation quality benchmark | Four workforce golden cases plus 78 controlled adapter scenarios are not 100 end-to-end cases | OPEN |

## Root causes

The system has sound bounded foundations, but inventories combine metadata, connectors and evidence without a durable lifecycle. Several docs describe design targets beside coded components, so they must not be read as implementation claims. Runtime source quality and hosted controls are environment-dependent and cannot be inferred from fixtures.

The qualification defect was caused by a shortcut that treated a real-request receipt and a runtime flag as sufficient for LIVE_VERIFIED. This skipped evidence, provenance, security, failure, health and other gates.

## Dependency order

1. Normalize lifecycle and prevent below-LIVE_VERIFIED sources from counting as live.
2. Persist qualification receipts and verify their evidence references.
3. Close remaining source SDK and distributed quota gaps.
4. Qualify initial sources in intended runtime with terms, reliability and usefulness evidence.
5. Implement/evaluate semantic planning, resolution and contradiction workflows.
6. Build social and country verticals only behind scope, source terms and false-attribution tests.
7. Close enterprise IAM, tenant and operations acceptance before production.

This iteration addresses item 1; it does not satisfy the 25-source alpha gate.
