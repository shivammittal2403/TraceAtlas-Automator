# Employee console source integration

## Integration with current main

This delivery was reconciled with the canonical workforce pipeline and its 26 source adapters, SourceRegistry, MCP tools, strict registered company identifiers and IANA RDAP bootstrap. See [canonical Source Fabric](sources/SOURCE_FABRIC.md) and [CURRENT_STATE](CURRENT_STATE.md).

The employee console adds a local, single-user objective/seed workflow with checkpoints, cancellation, cited graph/report, optional Ollama draft and evidence ZIP. Its `--source-fabric` adapter path uses shared IntelligenceHub connectors and separate employee run telemetry; it is not a replacement for canonical workforce authorization, semantic replay, health records or hosted approvals. Its replay checks integrity and references, whereas canonical workforce replay reanalyses captured source records. Do not combine the two health databases' verification counts.

Combined IntelligenceHub inventory: **49 records, 35 API implementations, 14 export-only records**. CISA KEV and the CVE Program use the shared integration runner. GLEIF and RIPEstat reuse main's implementations. Company inputs require exact qualified identifiers, e.g. `company:lei:5493001KJTIIGC8Y1R12`; free-name company search is not enabled. RDAP now uses the reviewed IANA bootstrap; the earlier rdap.org redirect incompatibility is resolved by main without enabling arbitrary redirects.

Two historical candidate inventories are preserved. Canonical workforce deduplication produces 351 research rows from 400 supplied slots. The employee catalogue's conservative explicit-alias map produces 361 canonical slots (39 aliases, 31 tool/family slots). These are different grouping policies over candidates, never independent source counts. Neither list demonstrates 400 implemented or legally qualified providers. Prefer the canonical catalogue for programme planning.

## Actual verification

Three direct live canaries succeeded in the employee delivery workspace before main reconciliation: GLEIF, EPSS and OSV. Sanitized hashes/timings are in `source-fabric-live-verification.json`. They do not establish post-merge live qualification of every adapter. Fresh workspaces start at zero locally live-verified sources. **Production-qualified: zero.** Optional credentials, commercial entitlements, hosted rollout and installed Ollama remain unverified.

## Run

```powershell
python -m pip install -e .
$env:TRACEATLAS_WORKFORCE_ENABLED = '1'
traceatlas --workspace ./cases employee serve
```

Open `http://127.0.0.1:8765`. Create a case, supply authorized typed seeds, actor, objective, attestations and budget. The Source Fabric checkbox selects employee capability routing. The server is loopback-only, with Host/Origin checks and CSRF. Analyst IDs are local assertions, not authenticated identities; no remote tenancy is provided.

```text
traceatlas --workspace ./cases source-fabric audit
traceatlas --workspace ./cases source-fabric catalog EPSS
traceatlas --workspace ./cases source-fabric manifest epss
traceatlas --workspace ./cases source-fabric plan --objective "Review company LEI records" --seed company:lei:5493001KJTIIGC8Y1R12 --public-record-basis
traceatlas --workspace ./cases source-fabric metrics
traceatlas --workspace ./cases source-fabric discover --opencti
```

For canonical workforce routing, use the commands in `docs/sources/SOURCE_FABRIC.md`. Discovery here stages bounded candidate metadata only. It never downloads code, enables execution or promotes sources.

## Employee execution limits

- Digest-bound exact seeds, authority expiry, action/runtime budgets, kill switch and cancellation. Source content cannot grant permissions or expand scope.
- Greedy capability coverage and one fallback wave; explicit heuristic scores, not measured information gain. Unknown country/language/cost qualification stays unknown. Credentialed unattended calls are excluded.
- Workspace SQLite concurrency leases: four global calls, three per case, one per provider, plus a process-local interval. Separate workspaces and canonical workforce calls do not share these employee quotas.
- Fixed-host public-address-pinned HTTPS and bounded retries/response size. RDAP destinations intersect IANA data with reviewed registry bases.
- Case-scoped cache rechecks authority and ledger integrity; fixture/live modes are separated. Network calls run concurrently, custody writes serially.
- Schema field changes are flagged. Invalid bodies create failure metadata, not normalized evidence. This is metadata quarantine, not isolated raw-body storage.
- Eligible non-personal JSON retains original bytes; personal sources and recognized secret fields withhold raw bytes. Arbitrary embedded secrets cannot all be detected. Normalized redaction and evidence hashes do not prove claim truth.
- Reports distinguish observations, claims, unknowns and unresolved company associations. Optional local model drafts have no tools. No contact, account actions, publication, bypass or exploitation.
- Qualification requires a recent real canary, intact canary/review ledger and 16 evidence-backed analyst checks. Fixture responses cannot promote sources.
- Telemetry includes bytes, attempts, cache, timing and drift. Parser-only success, actual API/compute cost and causal completion improvement are null when unmeasured. Health percentage is represented as a fraction.

## Remaining programme work

The requested 200 technically qualified / 100 live-verified / 50 production-qualified milestones remain incomplete. Current main supplies CT, public search/registry adapters absent from the initial audit; their entitlement and live-runtime readiness still require qualification. Beneficial ownership, sanctions, procurement, geospatial, distributed quotas, periodic online discovery and calibrated model/source selection remain gaps. See the canonical delivery ledger for progressive releases.

Official research also established [Bing Search API retirement](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement) and [Google Custom Search new-customer restrictions](https://developers.google.com/custom-search/v1/overview). Candidate flags preserve these findings. EPSS is a probability estimate, not proof of exploitation; [EPSS API](https://api.first.org/epss/) and [OSV API](https://google.github.io/osv.dev/get-v1-vulns/) document the new exact-identifier calls.

## Combined regression checkpoint

After reconciliation with current main in this workspace: 302 Python tests ran, 301 passed and one environment-dependent test skipped. The PGlite database test and all 25 Node graph/target tests passed. Source compilation and secret scanning passed. The local browser rerun requires a Playwright Chromium binary that is absent here; repository CI runs the browser gate with its installed browser.
