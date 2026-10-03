# Operational trace state

Products carry case/task/trace IDs, source outcomes and per-source spans
with operation/status/time/latency. Attempt counts include retries. Result records
zero model tokens/spend for the deterministic path; product network_attempts is
separate from distinct tool identifiers. Stable error codes preserve coverage.

This is correlation-compatible structured telemetry, not an OpenTelemetry exporter,
distributed trace backend or production SLO dashboard. Stored product versions
retain prior trace and evidence contexts. No provider exception message, request
header or query-secret value is included in failure outcomes.
