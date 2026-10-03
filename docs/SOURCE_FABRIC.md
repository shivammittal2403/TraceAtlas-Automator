# Source Fabric: Phase A implementation and qualification status

## Audit and actual counts

Baseline main `fe51ba7b2e085038751a0de1fb546a2ec8453397` had 37 source records, 23 API connector implementations, 14 export-only records, 49 capability adapters and 308 pinned external OpenCTI packages. External packages are not local live sources.

This implementation has **41 source records, 27 API implementations, 14 export-only records**. It adds GLEIF, RIPEstat, FIRST EPSS and OSV. The requested list is preserved as **400 candidate slots, 361 canonical slots, 39 explicit aliases**; 31 slots are tools or dataset families. Canonical slots are not a claim of unique verified providers. Most candidates remain unreviewed; selected official documentation has only partial reviews. Unknown commercial, license, jurisdiction and maintenance fields remain null.

There are 20 prioritized P0 implementations, including credential-gated and unverified connectors. RDAP is a known incompatibility: [rdap.org](https://about.rdap.org/) redirects to authoritative servers, while the pinned transport forbids redirects. Source Fabric excludes it and reports the registration gap. No claim of 20 healthy or production-qualified sources is made.

Three live API canaries succeeded on 2026-10-03: GLEIF, EPSS and OSV. See `source-fabric-live-verification.json`. **Production-qualified: 0.** These measurements belong to the delivery workspace. Fresh installations correctly start with zero locally live-verified sources. Live verification expires after seven days and requires a successful non-fixture call. Production promotion requires a recent live canary, intact canary/review evidence, 16 explicitly recorded analyst checks and local authorization. Local analyst identities are assertions, not authenticated users.

## Implemented flow

1. Exact typed seeds, objective, actor, attestations, expiry and budgets produce a digest-bound immutable manifest.
2. The router derives capabilities and greedily selects a small source set. Scores are documented policy weights, not learned information gain. Country/language fit remains unknown; it does not grant jurisdiction approval.
3. Wave 1 queries selected providers; wave 2 uses alternatives only for unresolved capabilities. Nonempty records indicate retrieval coverage, not proof of a claim. Credentialed providers require an entitlement contract and are excluded from unattended routing.
4. A gateway rechecks case authorization, cancellation and scope, including cache hits. HTTPS destinations are fixed and public DNS addresses pinned. Requests reject redirects and oversized/non-JSON responses.
5. SQLite leases enforce workspace limits: four global calls, three per case, one per provider. A process-local one-second provider interval supplements these leases. Independent workspaces do not share quotas. Network work runs in threads; evidence writes remain serialized. Retries share the bounded deadline.
6. Case-scoped cache reuse verifies custody integrity. Fixture and live responses are separated. Valid schema changes create drift warnings; invalid responses produce failure metadata, never normalized evidence. This is metadata quarantine, not a full isolated body repository.
7. Normalized evidence is hash-preserved. Original response bytes are additionally retained for eligible non-personal JSON; personal sources and recognized sensitive-field responses withhold raw bytes. Hashes establish byte integrity, not truth. The redactor cannot guarantee detection of every secret embedded in arbitrary text.
8. Existing verification, lineage and graph engines produce cited observations, claims, conflicts, unknowns, reports and offline replay. Company LEIs are candidate associations, never automatic identity merges. Optional local Ollama drafting cannot execute tools or alter scope.

## Run

```powershell
python -m pip install -e .
$env:TRACEATLAS_WORKFORCE_ENABLED = '1'
traceatlas --workspace ./cases employee serve
```

Open `http://127.0.0.1:8765`. Source Fabric is selected by default in the local console. The console remains loopback-only with Host/Origin checks and CSRF; it has no remote authentication or tenant isolation.

```text
traceatlas --workspace ./cases source-fabric audit
traceatlas --workspace ./cases source-fabric catalog GLEIF
traceatlas --workspace ./cases source-fabric manifest gleif
traceatlas --workspace ./cases source-fabric plan --objective "Review company LEI records" --seed "company:Example Company" --public-record-basis
traceatlas --workspace ./cases init company-review --title "Company records" --purpose "Authorized public-record research"
traceatlas --workspace ./cases employee investigate --case company-review --objective "Review company LEI records" --seed "company:Example Company" --actor analyst-1 --public-record-basis --authorized --source-fabric --output ./reports
traceatlas --workspace ./cases source-fabric metrics
traceatlas --workspace ./cases source-fabric discover --opencti
```

Replace example scope with real authorized scope. `discover --file candidates.json` accepts bounded candidate name/documentation URL records; discovery only stages candidates. It never downloads code, enables execution, or promotes production status.

## SDK and operations

`source_fabric/sdk.py` defines health, capabilities, input validation, cost estimation, search/fetch, normalization, provenance, evidence metadata, rate status and close. It reuses IntelligenceHub contracts and transport. Manifests expose provider grouping, capabilities, privacy, authentication references, pricing unknowns and implementation status. Credentials themselves are never included.

Execution telemetry records timing, bytes, attempts, errors, cache and schema fingerprints. Retrieval success is end-to-end completion; parser-only success, measured API/compute costs, independent evidence yield and causal completion improvement are currently unknown (null). Health percentage uses recent local state and returns a fraction from 0 to 1. Historical success does not override a later failure.

No automatic source promotion occurs. Use `source-fabric review --help` and `promote --help` for evidence-backed local analyst qualification. Candidate discovery is manually invoked; scheduled online source discovery, full recurring drift probes and centralized distributed quotas are not implemented.

## Research findings and remaining releases

- [Bing Search APIs retired on 2025-08-11](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement). Old Bing candidates are marked deprecated.
- [Google Custom Search](https://developers.google.com/custom-search/v1/overview) is closed to new customers; existing customers must transition by 2027-01-01. It is not treated as a generally available new connector.
- [Brave Search](https://api-dashboard.search.brave.com/api-reference/web/search/get) is a documented candidate, not an implemented provider here.
- New connector contracts reference [GLEIF](https://www.gleif.org/en/lei-data/gleif-api/), [RIPEstat](https://stat.ripe.net/docs/data-api/api-endpoints/network-info), [EPSS](https://api.first.org/epss/) and [OSV](https://google.github.io/osv.dev/get-v1-vulns/). EPSS is a probability estimate, not evidence of exploitation.

The requested 200 technically qualified, 100 live-verified and 50 production-qualified milestones remain future qualification work. Unimplemented coverage includes certificate transparency, official filings, beneficial ownership, procurement, sanctions, web search and geospatial connectors. Waves 3–5, commercial entitlement allocation, automatic source development and blanket 400-provider research completion are not claimed. No autonomous contact, account actions, publication, exploitation or authentication bypass is implemented.

## Verification checkpoint

Full Python regression: 240 tests, 239 passed, one environment-dependent skip on Windows (Bash unavailable). This includes fixture gateway concurrency, same-case cache, cross-case isolation, scope/cancellation rejection, drift, privacy withholding, routing exclusions, report and replay integrity. Wheel packaging succeeded. Browser employee flow was verified with synthetic responses; live provider canaries are separately recorded above.
