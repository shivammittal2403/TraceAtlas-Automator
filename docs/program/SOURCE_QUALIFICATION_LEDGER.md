# Source qualification ledger

Updated: 2026-10-04. This ledger counts source maturity, not catalog volume.

| State | Count | Interpretation |
|---|---:|---|
| Coded canonical approval-driven adapters | 25 | Code exists in the canonical workforce. |
| Production-qualified sources | 0 | None has complete current terms, entitlement and intended-runtime evidence. |
| Live source qualifications added this session | 0 | No credentialed or direct live source was exercised. |
| Discovered/candidate catalog | 400 input entries; 351 deduplicated research rows in prior audit | Discovery metadata; not execution-ready sources. |

The 23 evidence gates and state transitions are defined in
[`docs/SOURCE_MATURITY.md`](../SOURCE_MATURITY.md). Per-source records remain in
[`docs/sources/SOURCE_AUDIT_MATRIX.csv`](../sources/SOURCE_AUDIT_MATRIX.csv) and
the source implementation/delivery ledger. Do not infer qualification from a
connector, fixture, configured key, injected response or historical proxy
reference response. Review each source's current terms, licence/access, owner,
runtime credentials, real request, parser, normalized output, captured evidence,
offline replay, costs, rate limits, timeouts, failures, schema drift, canary,
health and runbook before advancing its state.

Targets from the program brief: 25 / 50 / 100+ qualified sources. Current state
is zero; milestone A is not met.
