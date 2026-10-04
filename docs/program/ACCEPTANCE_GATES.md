# Persistent level-8 acceptance gates

| Gate | Pass condition | Evidence required | Current state |
|---|---|---|---|
| Repository health | Clean install, compile, test and security checks | CI/CodeQL on proposed change | BASELINE FAILED; repair underway |
| Authorization | Every collection path rechecks case authority and kill switch | Negative tests for API/CLI/MCP/worker and expiry | Existing controls; full audit open |
| Evidence integrity | Immutable bytes, acquisition metadata, lineage and semantic replay | Tamper/replay tests and receipts | Partial; audit open |
| Source maturity | Shared vocabulary; 23 gates; no fixture promotion | State/gate tests and exact artifact resolution | Repair underway; artifact resolution open |
| Bounded employee | Typed plan/actions, budgets, stop rules, cancellation/resume | End-to-end synthetic cases | Partial deterministic workflow |
| Entity/graph | Evidence-backed relationships; human merge decisions; contradictions | False-merge and graph fixtures/benchmark | Partial; benchmark open |
| Enterprise security | Authn/authz, tenant isolation, retention, secret handling | Threat model and independent test | NOT READY; local only |
| Source qualification | Terms, entitlement, live evidence, health and runbook | Per-source receipts/canaries | 0 production-qualified |
| Operations | Durable jobs, distributed limits, telemetry, backup/restore | CI/staging artifacts | Partial/unverified |
| Golden evaluation | >=100 representative cases, replay, measured error/cost | Versioned benchmark results | NOT ESTABLISHED |
| Release claim | Weighted >=8.0 and every critical primary category >=7.0 | Auditable scorecard and review | NOT ESTABLISHED |

No fixture, mock, catalog count, key presence, or generated model output can
pass a live or production gate.
