# Verified gap analysis — 2026-09-25

This is an evidence-backed review of TraceAtlas 1.2, three supplied archives and
the supplied 30-item problem document. It replaces “feature-count” marketing with
code-level findings. “Implemented” below means code and regression tests exist in
TraceAtlas 1.3; it does not mean an external provider is configured or available.

## Review scope and reproducibility

| Archive | SHA-256 | Static result | Important boundary |
|---|---|---|---|
| `iop-python-main.zip` | `c84bc87b2ceb71e1cb605e407587f04c5cb170038b78bb9ecb89b58598b6f576` | Python compilation and JSON parsing passed | No licence file; code was not copied |
| `IOP-Python-MVP-main (1).zip` | `f36290ef93bc6c13e15df3ea95a2489e4c129dc91e50a4b514065c7f9cbe6a66` | Python/JavaScript compilation and JSON parsing passed | No licence file; code was not copied |
| `OSINT_Tool-main.zip` | `3fbba0ed5987097b026a47c0003f5ed0d28f2d15be3a0f8b6f357044b669e87b` | TypeScript/JSON static inventory passed | Licence says TBD/all rights reserved; code was not copied |

The ZIP paths and symlink metadata were checked before extraction. Archive test
suites were deliberately not executed: they are untrusted supplied code in a
workspace with broad filesystem access. Their test counts are therefore upstream
claims, not independently verified results. TraceAtlas's own suite was executed.

## What the archives actually contain

### `iop-python-main`

- 942 files, about 25,359 Python lines and a large typed FastAPI/SQLAlchemy layout.
- The project's own `FEATURE_STATUS.json` says 660 of 800 entries are
  `GENERIC_ONLY`, 64 are blocked on external dependencies and 76 are partial.
  The 800 count is a registry count, not 800 working collectors.
- Real strengths include case management, content-addressed evidence, hash-chain
  custody, graph operations, deterministic entity resolution, local search and a
  real GitHub connector.
- Critical security defect: `app/dependencies.py` builds tenant, actor and scope
  authorization from caller-controlled `X-Tenant-Id`, `X-Actor-Id` and `X-Scopes`
  headers. `app/auth/service.py` accepts all calls when `IOP_API_KEY` is unset and
  otherwise uses one shared API key. A caller with that key can self-assert another
  tenant and `admin` scope. This is cross-tenant broken access control, not safe
  multi-tenancy.
- Most “agent” paths produce deterministic plans and explicitly report that no
  external action ran. Provider adapters such as OpenAI are blocked stubs.

### `IOP-Python-MVP-main`

- 314 files, but 235 are Mermaid diagrams and only 12 are Python files.
- Its README correctly describes a synthetic demo with no live collection and no
  production-ready features. The 800-feature/38-phase material is a catalog and
  roadmap, not 800 implementations.
- Useful design ideas are the analyst workspace, maturity/status registry and
  custody presentation. The local gateway has no authentication and is appropriate
  only for loopback demo use.

### `OSINT_Tool-main`

- 221 files and about 4,858 TypeScript lines. The web app, connector directory and
  several named services contain no implementation.
- Actual code covers cases, investigations, objectives, evidence and basic entity
  extraction. There is no authentication/authorization middleware or tenant
  isolation in the core Express API; case routes permit global CRUD.
- Evidence routes trust a caller-supplied `x-actor-id`. Docker Compose exposes
  PostgreSQL with `postgres/postgres` defaults. These are release-blocking issues.

## Verification of the supplied 30 problem statements

| ID | Verdict at review time | TraceAtlas 1.3 decision |
|---|---|---|
| 01 | Partly true: built-in pivot generates two URLs, but governed Sherlock and Maigret integrations already exist | Keep built-in non-scraping behavior; use maintained external engines instead of fabricating a 300-site registry |
| 02 | Partly true: five named social platforms are export-only; six sources already have live APIs | No unsupported scraping added; documentation remains explicit about export-only sources |
| 03 | True: only JSON/GEXF graph exports existed | Implemented self-contained offline HTML graph, filters, node details and PNG export |
| 04 | True: correlation had four rules | Implemented a rule registry plus exact shared-IP, certificate reuse, technology overlap and redirect-convergence rules |
| 05 | True: theHarvester fixed two sources | Implemented validated `sources=` option and a broader passive default |
| 06 | True for operational case data; research-pack entity resolution is separate | Deferred: cross-case matching can breach legal/case-isolation boundaries and needs an explicit workspace policy model first |
| 07 | True: FusionBoard required hand-authored JSON | Implemented `fusion auto-rank` from stored case events with existing consent/ownership gates |
| 08 | True: phone playbook is query generation | Deferred: offline metadata is useful, but a mandatory dependency and vendor-specific enrichment were not added without a dependency/policy decision |
| 09 | False/stale: current code already supports gated live Ahmia clear-web search and file import | No direct onion access added |
| 10 | True: no reverse-image provider | Deferred: image upload to a paid third party requires provider selection, DPA/retention review and explicit egress UX |
| 11 | False/stale: authenticated browser UI already enqueues four fixed passive jobs and lists status | No duplicate job system built |
| 12 | True: FIFO and no resume state | Deferred: resumability needs a durable queue schema and compatibility migration; raising limits was rejected |
| 13 | Partly true: Supabase tenant RLS/RBAC exists for the control plane, not every local feature | Full bidirectional case sync deferred pending conflict, retention and sensitive-data policy |
| 14 | True: CTI baseline is regex | Optional context/NER remains a planned enhancement; regex output already requires review |
| 15 | True: no native ledger collector | Deferred pending provider budgets, chain-specific schemas and privacy/threat-model review |
| 16 | Partly true: core has no ASN module, but the governed OSINT MCP capability advertises BGP/GeoIP tools | Native RIPEstat connector remains planned |
| 17 | True at review time: native hub lacked shared retry/schema transport | Implemented in 1.5: bounded retry for 429/5xx/transport failures, response-size limits, provider-specific schema checks and secret-safe failure codes |
| 18 | Partly true: no native hub source, while the preserved OpenOSINT bridge exposes allowlisted paste search | No unverified `psbdmp.ws` dependency added |
| 19 | True: research BM25 did not search cases | Implemented offline case search across findings and spider/intelligence events |
| 20 | True: no behavioral bot scoring | Deferred; a generic score without comparable platform data risks false accusation |
| 21 | Gap is real, proposed mechanics are wrong | X is currently pay-per-usage, not a free tier; Telegram Bot API `getUpdates` is not arbitrary public-channel history search |
| 22 | True: no PDF generator | Deferred optional deliverable; JSON remains canonical and Markdown readability was fixed first |
| 23 | Partly true: STIX exists and ThreatWatch is registered with MISP/TheHive capability, but no native push | Deferred until exact MISP/TheHive versions, destination allowlist and egress approval are specified |
| 24 | True: no Tor/proxy option in core spider | User-Agent rotation/evasion rejected; identifiable default and SSRF protection are deliberate. Controlled proxy egress requires an organisation policy |
| 25 | Partly true: upstream capability/MCP registries exist, but no arbitrary Python plugin loader | Arbitrary in-process plugins deferred because they execute with full analyst privileges; subprocess/MCP isolation is preferred |
| 26 | Not a defect: irreversible target fingerprints are a privacy control | Reversible local decryption/display was rejected; future vault tokenization would require access-control and key-management design |
| 27 | True: Markdown used raw JSON bullets | Implemented risk grouping, scan summary and event humanizers; JSON output remains lossless |
| 28 | True: no persisted live-connector health | Implemented success/failure timestamps, failure streaks and `intel health`; stored errors exclude URLs/keys/bodies |
| 29 | True: spider seeds remain narrow | Deferred until phone/crypto/business collectors have validated contracts; adding labels without real modules would inflate feature counts |
| 30 | True: business registry is export-only | Companies House and SEC are good candidates, but the current one-request connector contract cannot correctly handle officer pagination and SEC fair-access identification yet |

Current official references used to correct unstable claims:

- X API pricing: <https://docs.x.com/x-api/getting-started/pricing>
- Telegram Bot API updates: <https://core.telegram.org/bots/api#getupdates>
- Companies House API: <https://developer.company-information.service.gov.uk/>
- SEC data APIs and fair-access policy: <https://www.sec.gov/search-filings/edgar-application-programming-interfaces> and <https://www.sec.gov/about/developer-resources>

## Implemented in TraceAtlas 1.3

1. Dependency-free BM25 case search: `traceatlas search --case ID "query"`.
2. Automatic, gated evidence fusion: `traceatlas fusion auto-rank`.
3. Modular, explainable correlation rule registry with eight factual rules.
4. Duplicate graph observations preserve additional parent edges, enabling exact
   shared-infrastructure evidence without duplicating nodes.
5. Self-contained offline HTML graph export with filters, node inspection and PNG.
6. Configurable theHarvester passive sources with strict input validation.
7. Connector health history with secret-safe error recording and warnings after
   three consecutive failures.
8. Human-readable, risk-grouped Markdown reports; JSON reports remain unchanged.

## Remaining gap to Maltego/SpiderFoot-class products

TraceAtlas is stronger at explicit authorization, evidence custody, privacy
minimization, deterministic offline research and auditable boundaries. It is weaker
at ecosystem size, live-source breadth, interactive graph manipulation, collaborative
case sync, transform/plugin economics, queue resumability and mature rate-budget
transport. The largest honest gaps are not the number of documented “features”; they
are reliable maintained connectors, safe multi-user operations and analyst UX.

A credible order of work is: native RIPEstat and authoritative company-registry
connectors; resumable priority scans; authenticated
local graph/case UI; optional PDF; then a sandboxed connector SDK. Building hundreds
of URL templates, reversible sensitive-target storage or arbitrary in-process plugins
would increase risk faster than capability and is not recommended.

## Implemented in TraceAtlas 1.5

1. Bounded, secret-safe provider retry and response-contract validation.
2. Persistent non-sensitive entity-resolution proposals and human decisions;
   candidate order is deduplicated and automatic merging remains prohibited.
3. RLS-protected hosted case notes and review tasks with decisions restricted to
   an authorization-checking `SECURITY DEFINER` RPC.
4. Private workers create one analyst review task for every completed evidence job.
5. Installed external binaries can be SHA-256 locked and verified for drift.
6. `traceatlas readiness` separates core, production and competitive readiness
   and exposes unmet operational gates instead of converting catalog counts into claims.
