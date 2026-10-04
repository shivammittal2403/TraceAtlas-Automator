# Source Fabric 1.11

Both supplied 200+ and 400+ briefs are implemented as one staged programme.
This release delivers the Phase A architecture and twenty-four canonical adapters.
It does not claim the later targets of 50 production-qualified or 100 live-verified
sources. The 400 supplied candidate entries become 351 deduplicated review rows,
including 41 entries flagged as generic categories requiring a specific provider.
Unreviewed candidate URLs, prices, licenses and quotas remain unknown.

## Executable architecture

`ObjectiveSpec → SourceRouter → approved source plan → SourceGateway → SourceConnector
→ EvidenceStore → observations → verification → graph/timeline → draft → replay`.

The existing SQLite store, five employee definitions, authorization and evidence
contracts remain canonical. Registry entries do not grant execution permission.
The workforce registry currently describes 49 source definitions (47 IntelligenceHub entries plus Brave/SearXNG); 24 have the canonical approval-driven workforce adapter. The IntelligenceHub has 33 API implementations. These counts overlap and must never be added together.

The planner derives requirements for typed domain, public IP, company, CVE,
vulnerability-advisory or npm-package identifiers.
It returns questions, candidate scores/rejections, a minimum covering set, approved
fallback dependencies, cost ceilings, gaps and stop conditions. Scores are transparent
heuristics, not calibrated information gain. One exact seed, eight network attempts,
USD 1 estimated spend and 120 seconds remain the task limits. No autonomous pivot,
identity merge, contact, scan submission, model call or report release is introduced.

Examples of exact company and security seeds: `lei:5493001KJTIIGC8Y1R12`,
`gb:00000001`, `cik:1`, `github:python`, `CVE-2024-12345`,
`GHSA-1234-5678-9ABC`, `lodash`, or `@scope/package`. These are identifier
syntax examples, not identity matches or installed-software assertions.
A company name alone never silently resolves to a registry record. The operator's
jurisdiction is retained in authority; it is not proof of the entity's jurisdiction.
Cross-register identifier reconciliation and beneficial ownership remain gaps.

## Runbook

```bash
traceatlas workforce sources --catalog
traceatlas workforce sources --capability domain.dns
traceatlas workforce sources --describe gleif
traceatlas workforce sources --candidates
traceatlas workforce golden --source-fabric
```

Register the case and exact authority using `workforce authorize` as documented in
[LIVE_SOURCES](../LIVE_SOURCES.md). Enable the local workforce feature flag. Plan:

```bash
traceatlas workforce plan --context AUTH_ID --target-type domain --target example.org \
  --objective 'Review authorized domain infrastructure and historical exposure'
traceatlas workforce plan --context AUTH_ID --target-type company --target lei:5493001KJTIIGC8Y1R12 \
  --objective 'Verify the public company registration record'
traceatlas workforce plan --context AUTH_ID --target-type cve --target CVE-2024-12345 \
  --objective 'Review advisory severity and exploitation probability'
traceatlas workforce plan --context AUTH_ID --target-type package --target @scope/package \
  --objective 'Capture exact public npm package metadata'
```

Inspect the returned source plan, then approve its exact envelope digest and use
`workforce run --task TASK_ID --live --authorized`. `report` and `replay` verify
stored bytes. Changed plans need new tasks and approval. Explicit `--sources` and
`--capabilities` are optional; normal operation uses the router.

Account-priced sources require environment credentials and an approved per-request
estimate, e.g. `--source-price brave=0.01` **only if supported by your account's plan**.
This reserves estimates for every attempt; actual billing remains unknown. Never
use zero merely to bypass the price gate. Unknown cost prevents dispatch.

Companies House uses `COMPANIES_HOUSE_API_KEY`; OpenCorporates uses
`OPENCORPORATES_API_TOKEN`; SEC uses a truthful `SEC_USER_AGENT` with operator contact.
Shodan and VirusTotal use the existing `SHODAN_API_KEY` and `VIRUSTOTAL_API_KEY`
references. GitHub organization lookup is public and deliberately sends no token.
Operator terms, permitted purpose, privacy, retention, region and account entitlement
must be reviewed before use. VirusTotal's public API is not licensed for commercial
products or commercial lookup workflows; use appropriate licensed access.

## Reliability and security

- Cache references are scoped to case, authorization, policy digest, normalized
  seed, source and parser version. Hits verify canonical evidence bytes and retain
  original timestamps. Corrupt/expired cache is a miss. At most 32 references per
  case are retained; evidence/custody records are never deleted by cache eviction.
- Two concurrent calls per case, four globally, one per provider **in this process**.
  Documented conservative limits for SEC, Companies House, GitHub and VirusTotal
  are enforced before each attempt. Other sources have a local 32/s safety ceiling;
  this is not a claim about provider quota. Multiple processes require a shared
  quota service before production. Provider 429 is never automatically retried.
- Authority, action/tool scope, kill switch, task time and request/cost budgets are
  checked again at dispatch. Fixed-host transport rejects private DNS answers,
  redirects and unexpected content types. Bounded responses are schema/target
  checked. Credential echoes are excluded from capture. Malformed bounded UTF-8
  responses are quarantined with zero observations; oversize data is rejected.
- Primary failures activate only preapproved fallback tasks. Healthy cached results
  avoid network requests. Successful but empty results remain an information gap;
  they do not automatically widen scope or spend more.
- Authentication failures, schema drift, rate limits and repeated failures open a
  circuit. After operator remediation, create a **new**, single-source
  `workforce plan --sources SOURCE --health-probe ...`, review/approve it, then run.
  A canary bypasses cache/circuit state, not authorization, budget or rate limits.
- Health reports the latest 100 local events, success/error rate, p95 latency,
  schema failures, cache hits and estimated costs. No synthetic event promotes a
  source to LIVE_VERIFIED or PRODUCTION_QUALIFIED. Eighteen evidence-backed
  qualification gates must be reviewed against the intended runtime.

## MCP

Install `pip install '.[mcp]'` (Python 3.10+; SDK availability may require a newer
Python runtime). Run `python -m traceatlas.workforce.source_mcp --workspace PATH`.
This optional stdio server exposes `sources.list_capabilities`, `sources.describe`,
`sources.health`, `sources.estimate_cost`, `sources.search` and `sources.fetch`.
Every call binds `case_id`, `task_id`, `authorization_context_id`, `trace_id` and
exact `scope`. Describe/health additionally take a source in the approved plan.
Search/fetch execute the entire approved task once; neither accepts arbitrary URLs
or provider queries. Metadata reads do not approve execution. Result bodies carry
provenance and no instruction authority. Calls reopen SQLite in their worker thread.
The inherited environment is the operator's secret boundary; do not expose stdio
through a public unauthenticated bridge.

## Qualification and remaining work

See [source audit matrix](SOURCE_AUDIT_MATRIX.csv), [delivery ledger](DELIVERY_LEDGER.md)
and [verification record](../verification/source-fabric-2026-10-03.json). Public
Cloudflare/RIPEstat/GLEIF/GitHub responses were parsed, captured and replayed through
an injected environment-proxy requester. The shipped direct transport's DNS was
blocked in this environment. crt.sh returned a schema mismatch and was quarantined.
No direct-runtime production qualification or paid-account entitlement is claimed.

Next phases require current official documentation/terms research for the remaining
candidate queue, real account credentials, sustained canaries and source-specific
adversarial cases. Native sanctions, beneficial ownership, procurement and
geospatial workflows are not delivered by these 24 adapters. Package and
vulnerability collection is now part of the bounded canonical workforce surface
through NVD, EPSS, OSV and npm.
Distributed workers/quotas, automatic source discovery, semantic multilingual
planning and the hosted UI-to-worker flow remain separately unqualified.

Parser version is now `structured-fact/4`, workflow `1.3.0`. Old captures remain
immutable; replay uses its recorded workflow version and fails closed when that
version is unsupported. Keep the previous release available for historical replay;
never relabel old captures or silently reparse them as new evidence.
