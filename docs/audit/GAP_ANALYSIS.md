# Enterprise gap analysis

Audit baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`, 2026-10-04.

## Ranked findings

| Priority | Finding | Evidence and impact | Status |
|---|---|---|---|
| P0 | Graph decision-state trust | `workforce/graph.py` accepted sensitive edges when caller set `decision_state="ACCEPTED"`; it had no reviewer/authority decision lookup. This could encode an unsupported identity or causal link into an analytical graph. | Fixed in current PR code; awaiting CI |
| P0 release gate | Hosted identity, tenant isolation and operations unverified | Acceptance gates and security docs require live auth/tenant/recovery evidence; none is presented. | OPEN; cannot infer from local tests |
| P0 quality gate | No production-qualified source | Current state reports zero; direct transport canaries failed in this environment and live entitlement/billing/health are open. | OPEN |
| P1 | SOCMINT breadth | No integrated approved social-platform collection and multi-source analysis path; search results and public GitHub org metadata are narrower primitives. | NOT_IMPLEMENTED |
| P1 | Entity-resolution evaluation | Human candidate workflow exists, but labeled evaluation, calibrated thresholds, precision/recall and reversible graph merge/split are absent. | PARTIAL |
| P1 | Semantic planning and model qualification | Deterministic router exists; autonomous semantic planner/provider fabric and quality evaluation remain unqualified. | PARTIAL / PLANNED |
| P1 | Broad source coverage | Catalog candidates exceed working integrations; direct transport, entitlements and intended-runtime qualification remain incomplete. | PARTIAL |
| P2 | Broader multilingual, country, media and CTI workflows | Some primitives exist; integrated, golden-case workflows remain partial or documented only. | PARTIAL |
| P2 | Market-parity assertion | No measured Social Links-class benchmark is present. | NOT ESTABLISHED |

## Root cause

The product has accumulated useful local evidence, source, graph and workforce components, but code presence, fixture success, external response parsing and hosted production qualification are different evidence levels. Some architecture and older gap text are aspirational or historical. The P0 graph flaw arose because an in-memory data object trusted a decision label supplied by its caller instead of requiring a decision from the authorized review owner.

## Remediation order

1. Close graph decision-state trust and keep identity truth under authorized ResolutionService review.
2. Obtain hosted tenant/auth/recovery evidence before deployment claims.
3. Qualify sources in intended runtime with permission, billing, freshness, failure and quality checks.
4. Build a bounded SOCMINT vertical only from approved public sources and explicit case authority.
5. Evaluate entity resolution with appropriately labeled data, abstention, collision tests and analyst decisions.
6. Add semantic planning, source expansion and additional domains only after those gates.

The current PR addresses item 1 only. It does not imply the remaining P0 release gates are complete.
