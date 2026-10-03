# Live-source implementation cycle — 2026-10-03

## 1. Objective

Connect live public sources to the canonical OSINT investigation product.

## 2. Baseline

Main `afec63367ce6500c621d8f3129168949af4addd3`, after the initial evidence pipeline
and concurrent documentation/dependency merges. Existing changes were preserved.

## 3. Existing behavior

The local runner dispatched DNS/RDAP/archive/InternetDB. RDAP's bootstrap server
redirects were rejected by the secure transport. Web search was an unexecuted
intent; other existing enrichment connectors were outside the runner.

## 4. Selected scope

Domain/public-IP passive acquisition, preserving the Python standard-library,
SQLite, EvidenceStore, fixed-host transport and current workforce contracts.
Person/company live discovery and hosted rollout are outside this delivered slice.

## 5. Contracts

Source IDs bind into task constraints before digest approval. RDAP connector v2,
workflow `evidence-investigation/1.1.0`, parser `structured-fact/2`, specialist v1.2.0
and package v1.10.0 record changed behavior. Typed predicates distinguish search
listings, historical index records, network geography and provider classification.

## 6. Source implementation

IANA bootstrap/registry routing, passive urlscan search, IPWHOIS/IPdata/GreyNoise
adapters and configurable Brave/SearXNG search join DNS/Wayback/InternetDB.
`workforce sources` reports ten implemented adapters and secret-safe configuration.

## 7. Evidence

Successful response text feeds immutable SourceDocument capture. Bootstrap is a
separate acquisition even on rejected registry routing. Case/task/acquisition
links, hashes, graph citations, timestamps and source outcomes remain canonical.

## 8. Scope and authority

Exact seed, tool/action/source permissions, deadline and kill state are rechecked
at dispatch. Source changes need a new task/approval. Legacy approvals do not gain
new sources. A kill between bootstrap and registry stops the second request and
completion; it is not hidden as a routine provider failure.

## 9. Network controls

Bootstrap intersects exact reviewed HTTPS bases; all redirects remain blocked.
Public transport retains pinned TLS/public DNS and ignores proxies. SearXNG's
separate numeric-loopback HTTP `/search` transport avoids DNS/proxies and rejects
redirects, credential origins, compression and oversized bodies. No result fetch
or scan submission occurs.

## 10. Failure and budget behavior

Eight actual HTTP attempts include bootstrap/retries. Capture/analysis receive
reserved runtime. HTTP 429 is surfaced without guessed reset retries. Missing
configuration does not poison health. Partial successful evidence is retained.
Provider billing is unmeasured and is recorded as unknown.

## 11. Verification boundaries

Search listings do not verify linked content. Index times remain historical.
Geography does not locate people; classifications remain attributed observations.
No automatic identity merge, model call, consequential action or report release.

## 12. Controlled checks

256 Python regressions, 26 Node/PGlite tests, 12 controlled golden investigations,
source compilation, secret scanning and an actual CLI plan/approval/loopback-
source-run/report/replay smoke passed locally. Loopback is a fixture, not SearXNG
service qualification. CI/CodeQL are publication gates, reported by the PR checks.

## 13. Real response checks

Environment-proxy reference runs captured real DNS/IANA/RDAP/urlscan responses
for example.org and IANA/RDAP/IPWHOIS/InternetDB/urlscan for 1.1.1.1; offline replay
passed. Wayback timed out and remained a source failure. Direct transport returned
DNS failures in this restricted environment. No fallback weakening was added.
See `verification/live-sources-2026-10-03.json` for the aggregate checkpoint.

## 14. Documentation and artifacts

Current state, source strategy/SDK, source schema, workflow/runbook, roadmap,
security review and README are updated. Actual case databases, provider responses,
credentials and temporary qualification products are excluded from git.

## 15. Remaining work

Qualify direct egress and credentialed sources in the target runtime; review
provider pricing/terms/retention; deploy a real SearXNG or configure Brave; connect
the local product to an authenticated private worker/UI; then perform staging and
production acceptance. No deployed readiness or paid-source cost guarantee is claimed.
