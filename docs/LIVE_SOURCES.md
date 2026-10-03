# Live investigation sources

The local CLI integrates these sources into the canonical evidence → observation
→ graph/timeline → draft report → offline replay pipeline. Source selection is
bound into the task before digest approval. All acquisition is read-only; no
scan submission, returned-URL fetch or target pivot is implemented here.

| Source ID | Seed | Selection | Configuration / result meaning |
|---|---|---|---|
| `dns` | Domain | Default | Google DNS JSON; exact question/answer names |
| `rdap` | Domain, public IPv4/IPv6 | Default | IANA bootstrap plus reviewed registry base; registration records |
| `urlscan` | Domain, public IPv4/IPv6 | Default | Existing scan index only; optional `URLSCAN_API_KEY`, limited anonymous quota |
| `wayback` | Domain | Default | CDX index only; archived pages are not fetched |
| `ipwhois` | Public IPv4/IPv6 | Default | IPWHOIS API; approximate network geography and ASN/ISP |
| `internetdb` | Public IPv4 | Default | Passive InternetDB ports; no direct service probes |
| `ipdata` | Public IPv4/IPv6 | Explicit | `IPDATA_API_KEY`; network context |
| `greynoise` | Public IPv4 | Explicit | Optional `GREYNOISE_API_KEY`; community quota/entitlement varies; provider classification |
| `brave` | Domain, public IPv4/IPv6 | Configured or explicit | `BRAVE_SEARCH_API_KEY`; at most ten search-result leads |
| `searxng` | Domain, public IPv4/IPv6 | Configured or explicit | `SEARXNG_URL`; numeric loopback HTTP origin with port; JSON enabled |

`workforce sources` prints configuration status and environment reference names.
It performs no network calls and does not claim provider health. The wider
`intel sources` catalog has 45 governed entries, including 31 API connectors;
only the table above is bound into this investigation runner. Existing social,
package, scholarly and CTI connectors retain their separate `intel collect`
commands and consent/asset/public-record gates. Person/company workforce seeds
still use case-local identifiers and approved records.

## Configure search before creating authority and task

Choose one provider; credentials belong in the private runtime environment.

```bash
export TRACEATLAS_WORKFORCE_ENABLED=1
export TRACEATLAS_SEARCH_PROVIDER=brave
# Set BRAVE_SEARCH_API_KEY through your secret manager/environment.
```

Or use your own SearXNG service with `search.formats` including `json`:

```bash
export TRACEATLAS_WORKFORCE_ENABLED=1
export TRACEATLAS_SEARCH_PROVIDER=searxng
export SEARXNG_URL=http://127.0.0.1:8080
```

This transport accepts numeric loopback only, including IPv6 `[::1]` with a port.
Remote hosts, `localhost`, credentials, base paths, query strings and redirects
are rejected. The local service remains responsible for upstream engine policy,
licensing, availability and privacy. There is no public-instance discovery.

## Execute an approved source plan

Create a case with `init` first. Replace IDs and domain below with your own
registered case and authorized target; example.org is a documentation reference.

```bash
traceatlas workforce sources
traceatlas workforce authorize --case CASE_ID --target-type domain --target example.org \
  --actor analyst-1 --purpose 'Authorized domain investigation' --jurisdiction IN --authorized
traceatlas workforce plan --context AUTH_ID --target-type domain --target example.org \
  --objective 'Review registration and passive public exposure' \
  --sources dns rdap urlscan wayback brave
traceatlas workforce approve --task TASK_ID --actor analyst-1 \
  --envelope-digest DIGEST --rationale 'Reviewed scope, selected sources and provider access' --authorized
traceatlas workforce run --task TASK_ID --live --authorized
traceatlas workforce report --task TASK_ID
traceatlas workforce replay --task TASK_ID
```

Omit `--sources` to bind defaults plus the configured search provider. For IP
investigations use `--target-type ip`; explicitly choose `ipdata` or `greynoise`
if qualified. Select one search provider. To change sources after approval,
create and approve a new task. Existing approvals without source constraints
retain their earlier DNS/RDAP/archive or RDAP/InternetDB selection.

## Evidence and failure behavior

Every successful acquisition preserves response text in immutable source-document
bytes with acquisition/time/hash metadata. RDAP bootstrap is a separate capture
without registration assertions. Routing uses the longest matching IANA domain
suffix or IP allocation, intersected with 18 reviewed HTTPS bases. Unlisted bases
fail with `provider_registry_not_approved`; no RDAP link or redirect expands scope.

Eight actual HTTP attempts, including retries and bootstrap, share the task
budget. The normal 120-second task reserves five seconds for capture/analysis/
commit. HTTP 429 stops that source without guessing a quota reset. Three recorded
provider failures open the health circuit. Missing configuration is skipped and
does not count as provider failure. Other successful evidence is retained when a
source fails. Empty results and failed sources are coverage gaps, not negatives.

Search response URLs remain leads; their listing does not verify linked content.
Historical urlscan timestamps do not describe current DNS or current exposure.
IP geography is approximate network context and never a person's location.
Provider classifications are attributed observations. No report is automatically
released. Source billing is not measured: bounded requests are not a monetary
cost guarantee. Qualify provider terms, pricing, retention and access before use.

## Qualification checkpoint — 2026-10-03

Controlled tests cover target/query mismatches, registry destination injection,
source/permission binding, missing keys, rate limits, IPv6 compatibility,
kill-switch changes between RDAP requests, loopback transport restrictions,
capture/graph/report and offline replay. The loopback HTTP server is a fixture,
not a deployed SearXNG installation. Brave/ipdata/GreyNoise are fixture-tested;
no real credentials or entitlements were available for their qualification.

Public reference runs through this environment's network proxy captured real
DNS, IANA bootstrap, RDAP and urlscan responses for example.org, and RDAP,
IPWHOIS, InternetDB and urlscan for 1.1.1.1. Both captured runs passed offline
replay. Wayback timed out and was recorded as failed. These runs used an injected
proxy requester, not the shipped direct transport. The direct transport was
also attempted and returned `provider_dns_failure` because this environment
blocks direct provider DNS. No unrestricted redirect/proxy fallback was added.

See [verification record](verification/live-sources-2026-10-03.json).
CODED and local TESTED are established. Real response parsing/replay is verified
through the environment proxy. Deployed direct transport, search credentials,
private worker/UI integration and production readiness are not established.

## Source Fabric update (1.11)

New plans use the capability router rather than the older fixed default list above.
The shared runner now has 20 adapters, including exact company registry identifiers.
See [the Source Fabric runbook](sources/SOURCE_FABRIC.md) for the current catalog,
price ceilings, cache, health canaries, MCP interface and remaining qualification gates.
