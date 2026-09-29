# Supplied source integration status

This status accompanies the 29 September 2026 source-integration plan. It is an
implementation ledger, not a marketing tool count.

## Inventory reconciliation

| Measure | Repository state |
|---|---:|
| Supplied nonblank entries | 196 |
| Canonical candidates after documented aliases | 187 |
| Machine-readable candidates preserved | 187 |
| Versioned TraceAtlas intelligence sources | 37 |
| Sources with implemented API request paths | 23 |
| Newly implemented in this milestone | 3 |

The complete supplied register is packaged at
`src/traceatlas/employee/data/tool_register.json`. Every catalogue result has
`execution_enabled_by_catalog: false`. Discovery lists, external launchers and
unresolved names cannot become executable merely by being imported.

## Current milestone

The connector foundation now exposes a versioned non-secret contract for every
TraceAtlas source. Contracts state the implemented input types, action, auth
mode, credential reference names, target/page/response bounds and capability
state. Live validation is explicitly `deployment-required`; fixture success is
not represented as production proof.

Three source candidates have progressed from catalogue-only to bounded adapters:

| Source | Input | Authentication | Scope and output boundary |
|---|---|---|---|
| IPWHOIS.io | One public IP | None on free endpoint | Owned asset; approximate network/geography context; exact coordinates minimized |
| ipdata | One public IP | `IPDATA_API_KEY` server-side | Owned asset; fixed response fields; subscription-dependent coverage |
| GreyNoise Community | One public IPv4 | Optional `GREYNOISE_API_KEY` | Owned asset; provider classification retained as an observation, never proof |

All three share HTTPS-only fixed provider hosts, public-IP validation, one-target
fan-out, 30-second timeout, 5 MiB response ceiling, stable auth/rate/schema error
classification, privacy sanitization, source-run provenance and connector-health
recording. Keys are never returned in contracts, evidence or failure records.

The AI Employee's default IP plan now uses InternetDB, RDAP, IPWHOIS and
GreyNoise as four separately attributable observations. ipdata remains an
explicit keyed selection so a paid/provider call is not introduced silently.

## Verification evidence

- happy-path fixtures for every new response schema;
- private/reserved target rejection before transport;
- missing ipdata credential rejection;
- GreyNoise schema-drift rejection;
- IPWHOIS application-level negative-result classification;
- contract uniqueness, limits and import-only state tests;
- full repository regression, JavaScript syntax, secret scan and package build
  remain mandatory before release.

No arbitrary IP was queried during development because fixture tests do not
create authority to investigate third-party infrastructure. Deployment owners
must perform a scoped canary against an owned public IP and record provider
entitlement, terms review, quota and observed result before changing live
validation state.

## Still not complete

The remaining candidates include paid APIs, restricted social platforms,
browser tools, hardware/local forensics projects, Tor-dependent research,
datasets, external launchers, duplicate labels and unresolved identities. They
remain catalogue or import candidates until each passes identity, terms,
contract, fixture, configured canary, provenance, privacy, failure and operations
gates. Phone-to-account bots, credential theft, authentication bypass and private
profile scraping are excluded.

The next engineering tranche from the plan is durable connector step state,
deadline/cancellation propagation and usage reservations, followed by approved
archive, CTI, company and social-export workflows. That work requires schema and
worker changes plus deployed Supabase/worker validation; adding more names to a
registry would not complete it.
