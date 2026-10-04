# TraceAtlas Workforce Decision Memory

- Audit baseline: `9d64aaf2ce9ec6f75e199be2e428007a384e0436`.
- Canonical implementation is additive under `traceatlas.workforce`; the old
  `modules/` prototypes are not policy, evidence, graph or identity owners.
- Release-one domain scope is passive and requires an immutable owned-domain
  AuthorizationContext.
- Initial roster is fixed at Case Manager, Investigation Planner,
  WEBINT/INFRAINT Specialist, Verification Supervisor and Report Analyst.
- SQLite and hosted Supabase schemas are both supported. Hosted records are
  tenant-RLS protected; authenticated clients receive read access plus a narrow
  approval RPC, never raw insert/update access to workforce execution records.
- Evidence v1 bytes/hashes/ledger remain authoritative. Evidence v2 appends
  acquisition, parser/extractor, custody, retention and access metadata.
- Source corroboration is based on independence groups, not URL/model counts.
- Identity and causal graph edges require explicit human acceptance.
- Loopback Ollama is the only model adapter wired by default. Remote providers
  remain unregistered until a separate deployment review.
- Feature flag default: off. Kill switch always overrides enablement.
- Repository test success is not production deployment evidence.

## 2026-10-03 decisions

- Audited refreshed main fe51ba7; 2a8789e is historical, not the current baseline.
- Wrote docs/GAP_ANALYSIS.md before significant implementation.
- Reused the core stack and workforce rather than adding agents or dependencies.
- Person/company are approved-record modes; domain/IP reuse fixed-host transport.
- Claims verify structured assertions, not real-world identity, intent or guilt.
- Unverified free-text semantics and detected instructions remain INCONCLUSIVE.
- Source lineage uses transitive components; same-source URLs are not corroboration.
- Reports stay drafts; analysis/replay are network-free and use zero model tokens.
- Hosted deployment, provider entitlements and full production gates remain open.
