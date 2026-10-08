# Repository Gap Analysis

## Imported workspace verification gap — 2026-10-08

Canonical main CI passes, but the imported TypeScript workspace had no active
root build/test gate and failed four transitive security updates. A draft
follow-up adds narrow candidate overrides and an isolated root verification
workflow. The initial runner probe passed Prisma compatibility, build/lint,
348 unit and 16 fixture integration tests, and reported no known dependency
vulnerabilities. Its generated lockfile is now committed and its temporary
probe removed; final frozen-install proof remains pending at commit creation.
Six scaffold packages still have zero tests; no deployment or parity claim is made.

## Investigation quality follow-up — 2026-10-08

The radial graph viewport and standalone planning panels have targeted fixes
and regression gates in this change. New-head CI is pending at commit creation;
native Tk, live collection and deployed operation remain unverified. Root panel
presence does not establish integrated SOCMINT or investigation parity.
The unavailable `allint52.zip` remains an open input/completeness gap; the remote
baseline tree alone cannot establish that its files are present or repaired.

## Audit basis

This is a documentation-level audit of the repository's default branch and visible source tree. The project is an existing, active implementation rather than an empty scaffold. The repository contains a Python CLI and SQLite engine, case/evidence/report modules, typed Spider events, adapter registries, CTI and intelligence modules, workforce/verification components, a browser console, API handlers, Supabase schema, and an isolated worker. The README describes a broad set of playbooks, adapters, and test commands. Those declarations are not equivalent to every optional connector being installed, healthy, licensed, or execution-verified.

Relevant implementation locations include `src/traceatlas/{cli,engine,db,evidence,report,policy,spider,cti,workforce}`, `api/{cases,assets,jobs,graph,notes,reviews}.py`, `public/{index.html,employee.js,graph-model.js}`, `supabase/`, and `worker/`.

## Capability status

| Capability | Repository evidence | Status | Remaining work / boundary | Priority |
|---|---|---|---|---|
| Local case lifecycle | `src/traceatlas/cli.py`, `db.py`, `investigation.py`; README quick-start | IMPLEMENTED | Validate each CLI path and preserve clear authority/purpose prompts | P1 |
| Evidence integrity and custody | `evidence.py`, evidence bundle tests, hash-ledger docs | IMPLEMENTED | Authenticity and lawful-acquisition proof require external process | P1 |
| Typed collection and bounded pivots | `collectors.py`, `playbooks.py`, `spider/`, policy/target tests | IMPLEMENTED | Per-adapter runtime/credential/license health still varies | P1 |
| Case graph and visualization | `api/graph.py`, `workforce/graph.py`, `public/graph-model.js` | IMPLEMENTED | Graph edges remain associations; visual/temporal completeness is bounded | P1 |
| AI/workforce and verification | `workforce/{contracts,registry,service,verification,lineage,model_fabric}.py`, golden cases | PARTIAL | Benchmarks do not prove production accuracy; keep humans responsible for material conclusions | P1 |
| Entity resolution | `resolution.py`, review queue, analyst decision API/UI | PARTIAL | Candidates are not automatic identity proof; validate precision/recall and source independence | P1 |
| CTI and IOC workflow | `cti.py`, intelligence modules, connector catalog/docs | IMPLEMENTED | Feed markings, source licensing, freshness, and provider credentials remain operator responsibilities | P1 |
| Malware analysis | File metadata/static/IOC modules and policy gates | PARTIAL | No claim of safe sample execution; isolated sandbox remains separate prerequisite | P0 before any execution feature |
| Authenticated cloud control plane | `api/`, `vercel_control.py`, `supabase/`, `worker/` | IMPLEMENTED | Dedicated project/RLS/worker deployment and production readiness must be verified, not inferred from code | P0 before hosted use |
| Tenant and asset authorization | case/asset/job endpoints, RLS and control-plane tests | PARTIAL | Authorization declarations and ownership attestations are not independent legal verification | P0 |
| Person/cloud investigation | sensitive local policy; cloud asset validator limits types | PARTIAL | Cloud identity target support is intentionally false; keep person work consent-gated/local | P0 |
| Source independence and contradictions | `workforce/lineage.py`, `fusion_board.py`, verification and golden tests | PARTIAL | Coverage and correctness require curated adversarial evaluation; URL count is not corroboration | P1 |
| Replay and reproducibility | run history, schedules, snapshots, ledger, benchmarks | PARTIAL | Re-running external sources cannot reproduce historical responses; add/export a clear replay manifest if required | P2 |
| Documentation contract | extensive architecture, security, integration, and gap docs; missing canonical `docs/WORKFLOW.md` and `docs/USER_FLOW.md` at audit time | PARTIAL | This branch adds those user-facing flow contracts and a consolidated current-state gap summary | P1 |

## What works, can be reused, and remains

**Already implemented:** typed local investigations; SQLite storage; normalized findings; integrity hashes and chained custody events; bounded collectors and event graph; JSON/Markdown reporting; a large adapter/source catalog; CTI/IOC parsing; analyst review queues; and a restricted authenticated cloud plane.

**Reuse:** existing `Target`, `Finding`, method and adapter registries, policy gates, evidence ledger, graph model, review lifecycle, RLS policies, and worker job contracts. Avoid adding a second independent case/evidence database.

**Repair or verify:** keep README capability claims aligned with execution readiness; verify cloud RLS and worker operation against a dedicated disposable project; exercise per-source failure, tenant isolation, cancellation, retry, and retention paths; test adversarial source lineage and identity ambiguity.

**Build next:** produce an explicit replay/export manifest if operational replay is required; improve measurable coverage and citation/source-independence evaluations; document real source coverage and hosted deployment state in generated readiness output.

**Keep deterministic:** authorization decisions, target validation, evidence hashing, normalization, budgets, retention, access control, source allowlists, and report provenance. Models may plan or analyze within policy, but cannot grant scope, mutate evidence, or approve release.
# TraceAtlas implementation gap analysis — 2026-10-03

Audit HEAD: `fe51ba7b2e085038751a0de1fb546a2ec8453397`. Requested historical
baseline `2a8789eb7cc401b327796e32458b9733674ecbc9` is an ancestor; 40 files,
3,709 added lines and 13 deleted lines followed it. Preserve those additions.
GitHub CI and CodeQL for audit HEAD both report success. A clean local checkout
initially ran 209 tests: two date-dependent workforce failures and three missing
OpenCTI-submodule failures. The latter are checkout prerequisites, not broken
connector implementations. This is a pre-implementation audit snapshot.

## Inventory and reconstructed architecture

The root has no AGENTS.md or CURRENT_STATE.md. PRD, RULES, DESIGN, PHASES and
MEMORY exist. The original blueprint documents are summarized by
`docs/BLUEPRINT_DELIVERY.md` and `docs/BLUEPRINT_TASK_LEDGER.csv`; the full original
blueprint is not present in this checkout. Existing architecture, production
architecture, integration, source, graph, employee and workforce documents were
reviewed. Do not replace their historical assessments with release claims.

The canonical runtime is Python 3.10+ standard library, SQLite, plain JavaScript
and a Vercel/Supabase hosted control plane with a separate private worker.
`Engine` owns the local database; `EvidenceStore` owns preserved bytes/custody;
`IntelligenceHub` owns provider policies/normalization; `workforce` owns immutable
authority/task/result contracts. The workforce currently ends at an injected
runner or an empty no-model result. Its lineage, verification and temporal graph
are individually tested but not integrated into the CLI collection path.

## Capability audit

Status applies to the named behavior, not marketing coverage. IMPLEMENTED means
code and a relevant local test exist, PARTIAL means a missing integration/control,
MOCK means fixture-only proof, DOCUMENTED_ONLY means target prose, UNKNOWN means
no runtime evidence, BROKEN means a reproduced failure, MISSING means no owner.

| Capability | Expected behavior | Existing implementation / repository evidence | Status | Architecture gap | Security gap | Testing gap | Integration gap | Dependencies | Priority | Recommended action |
|---|---|---|---|---|---|---|---|---|---|---|
| Case/authority | Immutable case, purpose, actor, scope and expiry | `db.py`; `workforce/contracts.py`, `store.py` | PARTIAL | State distributed across services | Expiry checked at planning only | Expiry-after-approval absent | Runtime dispatch not rebound | Case DB | P0 | Recheck exact authority before work |
| Worker tasks | Bounded plan/approve/execute | `workforce/service.py`, `cli.py` | PARTIAL | No collecting runner | Kill switch cached at construction; model budget not checked | Harness expires 1 October | Collection absent from CLI | Registry, authority | P0 | Integrate bounded runner, repair clock-dependent tests |
| Evidence bytes | Immutable capture and custody validation | `evidence.py`; `test_core.py` | IMPLEMENTED locally | Local filesystem only | No external ledger anchor | Hosted restore unknown | Preserve canonical owner | Case DB | P0 | Reuse; verify before reports/replay |
| Evidence metadata | Acquisition/parser/retention/observations | `workforce/store.py` | PARTIAL | Legacy source digest adapter only | Observation acquisition mismatch accepted | Case/reference adversarial tests missing | No source-document capture path | Evidence store | P0 | Add acquisition-aware capture |
| Connector SDK | Typed fixed-host lookup, retry, health | `intelligence/contracts.py`, `provider.py`, `transport.py` | PARTIAL | RDAP bootstrap redirects fail closed | No unsafe redirect workaround | No new live entitlement proof | Workforce doesn't call it | Source registry | P0 | Reuse transport; make limitations explicit |
| Search/dorks | Generate versioned safe intent queries | OpenOSINT `generate_dorks.py`, local service boundaries | PARTIAL | No workforce search selection | No arbitrary/secret dorks permitted | Live provider unknown | Search optional, cannot invent results | Approved search adapter | P1 | Version safe templates; return search gap |
| Resolution | Explainable reversible candidate decisions | `resolution.py`, `research/analysis.py` | PARTIAL | No canonical merge/split history | Same name never proves identity | Namesake tests exist | Not in new workforce loop | Evidence, observations | P1 | Preserve seed IDs; expose candidates without merging |
| Temporal graph | Evidence-rich nodes/edges with time/state | `workforce/graph.py`, `public/graph-model.js` | PARTIAL | In-memory claim gate, separate event graph | Graph gate trusts caller-supplied ACCEPTED | Contract fixtures only | No report/replay snapshot | Evidence, observations | P0 | Build deterministic snapshot; never accept identity edges |
| Source independence | Transitive origin/owner/copy grouping | `workforce/lineage.py` | PARTIAL | Only first representative compared | Direct upstream IDs and transitive chains missed | Transitive/citation regression absent | Not in collection flow | Source content/lineage | P0 | Connected components, conservative publisher grouping |
| Verification | Integrity → corroboration → adversarial check | `workforce/verification.py` | PARTIAL | Object references mistaken for byte integrity | No scope/case/hash lookup; arbitrary minimum count | Hash and wrong-case tests absent | No claim-specific collection integration | Evidence store, lineage | P0 | Require byte validation in new runner; explicit structured facts |
| Contradictions/timeline | Same-subject temporal conflicts visible | `employee/brief.py`, `research/analysis.py` | PARTIAL | No structured predicate link in loop | Different dates can falsely imply conflict | End-to-end fixture absent | New pipeline integration missing | Fact schema | P0 | Use overlapping validity intervals, preserve contrary evidence |
| Information gaps/NBA | Bounded defensible next check ranking | Employee brief/research plans | PARTIAL | No measured information-gain model | Cannot expand authority | No calibration | No iterative workforce loop | Verification decisions | P1 | Implement transparent heuristic, stop at permitted source exhaustion |
| Reports/replay | Immutable evidence-linked draft and captured-input replay | `report.py`, workforce result storage | PARTIAL | No workflow-version manifest | Stored digests not checked on read | Tamper/replay equivalence absent | No replay CLI | Pipeline, byte store | P0 | Persist hashed draft/manifest, reanalyse captured bytes offline |
| Model fabric | Policy router, fallback, cost | `workforce/model_fabric.py` | PARTIAL | Local adapter only; remote providers disabled | Full spend reservations absent | Synthetic outage test only | Not needed for deterministic slice | Model registry | P1 | Keep no-model path; mark remote adapters missing |
| Investigator UI | Authenticated evidence/graph/timeline/review | `public/`, `api/`, graph JS tests | PARTIAL | New workforce result view absent | RLS/JWT production validation unknown | Existing browser fixture only | Local runner not hosted | Hosted private worker | P1 | Keep current UI; add hosted runner only after staging |
| CTI | IOC/STIX/feed correlation | `cti.py`, tests, governed services | PARTIAL | No new workforce CTI vertical | Provider claims not attribution | Local deterministic tests | Separate services | Core backbone | P1 | Reuse, integrate after domain slice |
| Malware | Quarantine/static/isolated dynamic evidence | Media/hash tools, IntelOwl file-only gates | PARTIAL | No native sandbox lifecycle | File execution deliberately blocked | Isolation/escape proof missing | External sandbox not connected | Dedicated isolation | P2 | Never execute specimens in this delivery |
| DARKINT | Isolated licensed acquisition | `sensitive/`; redacted metadata APIs | PARTIAL | No dedicated onion worker | Licensing and isolation operator controls | Live proof absent | Not new runner scope | Entitlements, isolation | P2 | Keep restricted service boundary |
| Supply chain | BOM/VEX evidence and propagation | CI SBOM, package connectors | PARTIAL | No shared BOM dependency graph | Imports need parser/size limits | Workflow missing | Not in golden production path | Core graph, BOM parsers | P2 | Define future gate, do not claim complete engine |
| Country/dataset packs | Versioned verified sources/licenses | Research corpus, source catalogs | PARTIAL | No country pack registry | Public catalog is not entitlement | Production quality/bias unknown | Country packs missing | Source/license validation | P2 | Reuse corpus; explicitly document future packs |
| Other domains | GEO/IM/VID/AUD/DOC/NEWS/ARCHIVE intelligence | `intelligence/media.py`, capabilities and approved exports | PARTIAL | Specialized workflows not common canonical loop | Consent/egress/runtime controls needed | Model quality unknown | Existing primitives only | Backbone, optional tools | P2 | Integrate only after evidence gates |
| Future domains | MOBILE/IoT/OT/CLOUD/TRANSPORT/ENVIRONMENT | Target architecture only | DOCUMENTED_ONLY | No vertical owner | New scope/isolated tool policy needed | No golden workflow | None | Backbone | P3 | Do not advertise execution |
| Hosted operations | RLS, backup, cancellation, durability | SQL tests, worker and restore drill | UNKNOWN live | No Temporal/NATS/PostGIS/object-store deployment | OIDC/MFA/KMS/tenant operations require staging proof | Multi-session/hosted checks absent | No cloud action authorized here | Operator environment | P0 release gate | Keep production acceptance false |

## Disposition and build order

Reuse DB, EvidenceStore, fixed-host transport, existing worker contracts, graph
gates and source registry. Extend `workforce`; do not create another agent core.
Keep prototypes under `modules/` non-canonical; do not delete reusable history.

1. Repair live policy checks, reference/digest integrity and lineage grouping.
2. Add a strict source-document/fact schema and safe query registry.
3. Capture source responses, observations, graph/timeline and verified claims.
4. Persist immutable draft and replay manifest; implement network-free replay.
5. Prove controlled domain/IP and approved-record person/company paths, including
   contradictions, identity collision, failure and injection cases.
6. Synchronize the requested documentation with exact capability states.
7. Gate hosted execution, remote models and broader domains on staging evidence.

This delivery can prove a local architecture slice. It cannot establish market
parity, live-source quality, fully autonomous semantic research, or production
readiness through fixture counts or documentation volume.


## Live-source follow-up — 2026-10-03

The local connector integration gap is reduced by immutable source selection,
IANA bootstrap/registry routing, passive urlscan search, IP enrichment and
configurable Brave/SearXNG adapters. All successful acquisitions feed the canonical
evidence, graph, report and replay path. The wider catalog retains separate
connectors; person/company live discovery is not claimed. Runtime direct network
access, real search/paid-provider credentials, hosted worker/UI integration and
provider billing qualification remain gaps. Source failures remain explicit.
See [LIVE_SOURCES.md](LIVE_SOURCES.md) for exact coverage and qualification evidence.

## Source Fabric phase A update — 1.11.0

The ten-source runner audited above now uses a twenty-four-source shared SDK and a
capability router/gateway. The new scoped cache, concurrency/cost limits, health
canaries and MCP surface reuse canonical policy and evidence. The deduplicated
candidate queue is discovery data only. The current implementation and remaining
50/100/400-source production objectives are reconciled in
`sources/DELIVERY_LEDGER.md`; this supersedes older source-count snapshots without
rewriting their historical verification results.
