# Source maturity and qualification

Every source manifest exposes one `maturity_state` from this vocabulary:

| State | Meaning |
|---|---|
| `DISCOVERED` | A source candidate was identified; no catalog or connector claim follows. |
| `CATALOGUED` | Source metadata is recorded. It is not an implemented integration. |
| `TERMS_REVIEWED` | Terms and permitted-use review have evidence recorded. |
| `CONNECTOR_CODED` | A connector implementation exists in the repository. This says nothing about configuration or live success. |
| `CONFIGURED` | Required runtime configuration has been checked. Configuration is not a live test. |
| `LIVE_TESTED` | A real request was attempted and its result recorded. A failed request remains `DEGRADED`. |
| `LIVE_VERIFIED` | A real response passed the connector, evidence, provenance, and target checks in the recorded runtime. |
| `PRODUCTION_QUALIFIED` | All source qualification gates have evidence and a recent live canary is verified. |
| `DEGRADED` | Runtime failure, schema drift, or a legacy `BROKEN` health record is present. |
| `DISABLED` | An operator has disabled the source. |
| `DEPRECATED` | The source is retired from new plans. |

`health` is reported separately from maturity. An old `BROKEN` value is normalized
to `DEGRADED`; it is not a maturity label. Legacy `DOCUMENTED` maps to
`CATALOGUED`, and `CONNECTOR_IMPLEMENTED` maps to `CONNECTOR_CODED`.

The workforce `sources --catalog` output and Source Fabric audit include all
maturity buckets, including zero-valued buckets. Counts for registered source
records, canonical workforce adapters, API implementations, and research
candidates remain separate because their denominators differ. In particular,
`CATALOGUED` is never counted as an integration, and production qualification is
never inferred from a connector, configured credential, fixture, or candidate row.

Both qualification paths use one 26-gate evidence checklist: documentation,
manifest, capabilities, connector, terms, licence, authentication, configured
credentials, live request, normalization, evidence, provenance, failure handling,
fallback behavior, rate limits, cost, security, schema-drift monitoring, tests,
canary, health monitoring, operational owner, runbook, privacy, replay, and
intended runtime. A missing gate prevents
`PRODUCTION_QUALIFIED`; a live request without all live-verification checks is only
`LIVE_TESTED`. Qualification remains scoped to the recorded runtime; it does not
assert that another deployment or jurisdiction is ready.
canary, health monitoring, operational owner, and runbook. A missing gate prevents
`PRODUCTION_QUALIFIED`. `LIVE_VERIFIED` requires the live-verification subset:
all gates except operational owner and runbook, plus a verified intended runtime.
A live request without that full subset is only `LIVE_TESTED`. Qualification
remains scoped to the recorded runtime; it does not assert that another
deployment or jurisdiction is ready. Evidence references must be bounded and
must resolve to authorized case artifacts before an analyst can persist reviews
or promote a source; a string reference alone is not proof.

## Typed review binding — 2026-10-05

Source Fabric now requires source/check/case/reviewer/runtime-bound typed receipts,
revalidated with support/custody/time/code at projection and promotion. Legacy
hash-only rows remain historical and confer no qualification. See
[SOURCE_REVIEW_RECEIPTS.md](SOURCE_REVIEW_RECEIPTS.md) for requirements and limits.

## QUAL-CUSTODY-001: current custody required for qualification (2026-10-05)

Main parent 6264b935 (tree identical to verified 015ee105). Reproduced a source
still reporting PRODUCTION_QUALIFIED after preserved review bytes were changed
and ledger verification failed. Qualification projections now revalidate same-case
review and canary custody, including any configured anchor, on every read. Checks
are cached only within that projection. Invalid canary custody yields DEGRADED;
invalid reviews cannot grant LIVE_VERIFIED or PRODUCTION_QUALIFIED. Gateway and
promotion propagate the actual workspace instead of assuming the database location.

Measured controlled comparison: intact evidence remains qualified in both versions;
tampered shared canary/review case changes from falsely qualified to DEGRADED.
Nine negative/control regressions pass. Full suite: 456 run, 453 passed, 3 skipped,
zero failures (149.007s). Structure scan 210 files, compilation and secrets pass.
Evidence: docs/verification/qualification-custody-2026-10-05.json. CODED/TESTED;
not DEPLOYED; no live request or actual source promotion in this iteration.
Local attestations still do not prove reviewer identity/review quality; independent
anchor rollback protection and unanchored full rewrite remain OPEN. Enterprise
8/10 is NOT ESTABLISHED. Parent CI 37300581400 and CodeQL 37300581482 passed;
separate AI review failed with confirmed monthly quota/HTTP 402, not a code result.
