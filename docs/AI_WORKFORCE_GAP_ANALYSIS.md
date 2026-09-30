# AI Workforce Gap Analysis

Audit baseline: commit `9d64aaf2ce9ec6f75e199be2e428007a384e0436`, reviewed 2026-09-30.

Implementation update (2026-09-30): the audit was accepted and the release-one
repository foundation described in `PHASES.md` was subsequently coded and
tested. This document remains the immutable pre-implementation gap snapshot and
does not claim hosted deployment or provider verification.

## Evidence rules and scope

This is an audit artifact, not an implementation claim. Repository code, schemas,
tests and executable verification are stronger evidence than prose. Status terms:

- **IMPLEMENTED**: first-party code and relevant regression tests exist.
- **PARTIALLY_IMPLEMENTED**: useful code exists, but the target contract or end-to-end path is incomplete.
- **MOCKED**: only a fixture/simulated external response proves the path.
- **DOCUMENTED_ONLY**: prose, catalog metadata or a registry entry exists without executable behavior.
- **BROKEN**: repository evidence demonstrates a failing implementation.
- **DUPLICATED**: overlapping implementations exist without one canonical owner.
- **UNKNOWN**: runtime, provider, deployment or legal evidence is unavailable.

No external provider was called and no production system was changed during this
audit. External API versions, commercial access, provider health and deployment
readiness remain **UNKNOWN** until separately verified against official sources.

## A. Executive assessment

TraceAtlas should evolve into a hybrid workforce, but it should not be rewritten
as an agent-first system. Its strongest assets are deterministic: authorization
gates, typed targets, bounded connectors, evidence hashing, a hash-chained ledger,
case isolation, RLS migrations, source-run records, human entity-resolution
decisions, strict AI-output validation and reproducible reports.

The current “Employee” is a bounded collection-plan and briefing workflow. It is
not yet the requested workforce: there is no canonical employee-definition
registry, typed inter-employee envelope, domain router, provider-neutral model
fabric, source-lineage engine, unified claim graph, cost ledger, distributed trace,
or three-layer verification state machine. Optional AI is limited to loopback
Ollama; the platform continues deterministically when it is absent. That is a good
failure posture and should be preserved.

Recommendation: build one domain/IP/company vertical slice on existing services.
Add contracts and lineage before adding specialist agents. Do not create an AI
employee where an existing deterministic service is superior.

## B. Audit facts

| Repository fact | Repository evidence | Status |
|---|---|---|
| 40 investigation methods | `src/traceatlas/playbooks.py` | REPOSITORY VERIFIED |
| 12 built-in deterministic collectors | `src/traceatlas/collectors.py` | REPOSITORY VERIFIED |
| 34 external-tool contracts and 5 profiles | `src/traceatlas/integrations/registry.py` | REPOSITORY VERIFIED; installation varies |
| 37 intelligence sources, 23 marked live | `src/traceatlas/intelligence/sources.py` | Contract presence verified; provider execution is runtime-specific |
| 49 governed upstream capability contracts | `src/traceatlas/capabilities/registry.py` | Registry verified; only 26 are executable by policy and readiness is separate |
| 187 IntelOwl module catalog rows | `src/traceatlas/intelligence/modules.py` | Catalog verified; remote enablement and target compatibility are required |
| 308 pinned OpenCTI connector packages | `src/traceatlas/data/opencti_connectors.json`, `third_party/opencti-connectors` | Integrity/catalog verified; execution disabled |
| 28 analyst procedures | `src/traceatlas/employee/skills.py` | IMPLEMENTED as procedures, not autonomous employees |
| Local evidence ledger and portable bundles | `src/traceatlas/evidence.py` | IMPLEMENTED |
| Local and hosted data stores | `src/traceatlas/db.py`, `supabase/migrations/` | IMPLEMENTED schemas; hosted deployment UNKNOWN |
| Optional AI provider | `src/traceatlas/intelligence/ai.py` | PARTIAL: loopback Ollama only |
| Regression result at audit baseline | 192 Python tests passed, 1 Bash-only test skipped; 26 Node tests passed; 8,275 OpenCTI files verified | TESTED locally |
| Browser fixture | `tests/test_employee_ui.cjs`, CI installs Chromium | Test exists; local browser execution UNKNOWN on this host |
| Production deployment | `src/traceatlas/deployment.py`, `DEPLOYMENT.md` | UNKNOWN; no hosted proof was produced in this audit |

## C. Current-state inventory

| Module | Purpose and location | Status | Inputs / outputs / contract | Tests and controls | Observability, evidence and limitations |
|---|---|---|---|---|---|
| Policy and targets | `policy.py`, `models.py` | IMPLEMENTED | Typed target and authorization flags → validated request | Core, sensitive and integration tests; SSRF/private-target gates | Deterministic; no policy decision trace shared across every subsystem |
| Method engine | `engine.py`, `playbooks.py`, `collectors.py` | IMPLEMENTED | Method + target → `Finding[]` | `test_core.py` | Findings persist to SQLite; `Finding` is smaller than the proposed Observation/Claim model |
| Spider/correlation | `spider/` | IMPLEMENTED | Typed events → bounded event graph | Core and graph tests | Depth/event caps and provenance; not a canonical temporal knowledge graph |
| External tools | `integrations/` | IMPLEMENTED boundary | `ToolSpec` + argv → normalized events | Integration, lock and drift tests | Source health and evidence records; installed/runtime coverage is deployment-specific |
| Intelligence hub | `intelligence/` | IMPLEMENTED/PARTIAL | `SourceSpec` + exact identifier → normalized record | Provider-contract, transport and intelligence tests | Source runs, retry/circuit state and health; source independence is not modeled |
| Capability hub | `capabilities/` | PARTIALLY_IMPLEMENTED | Export/MCP/service/staged-file contracts | Capability and archive-audit tests | 49 contracts; registry readiness can exceed actually verified execution |
| MCP client | `capabilities/mcp.py` | IMPLEMENTED client | MCP stdio request → allowlisted tool result | Real fixture handshake test | Evidence preserved; no TraceAtlas domain MCP server exposing the requested business capabilities |
| OpenCTI suite | `opencti_connectors.py`, data/submodule | IMPLEMENTED catalog, DOCUMENTED_ONLY runtime | Connector ID → non-executing plan | 8,275-file integrity verification and catalog tests | 308 disabled packages; no live OpenCTI execution proof |
| Evidence store | `evidence.py` | IMPLEMENTED | File → content-addressed copy, DB row, chained ledger | Evidence and bundle tests | Strong integrity/replay primitive; lacks full canonical `EvidenceObject` metadata/versioning |
| Local case store | `db.py` | IMPLEMENTED | Cases, runs, findings, evidence, graphs, reviews | Broad unit coverage | SQLite transactional state; employee tables are created inside service code rather than a versioned migration |
| Hosted control plane | `api/`, `vercel_control.py`, Supabase migrations | IMPLEMENTED/PARTIAL | Authenticated/RLS API → tenant data and fixed jobs | Control-plane, API and PGlite tests | Request IDs, audit rows and RLS; hosted operations, backup and tenant isolation are not externally verified |
| Employee workflow | `employee/` | PARTIALLY_IMPLEMENTED | Objective/target → plan → approval → bounded run → brief | Employee and hosted API tests | Immutable plan hash, expiry, review digest; no registry of typed specialist employees |
| AI advisory | `intelligence/ai.py`, `employee/brief.py` | PARTIALLY_IMPLEMENTED | Evidence summary → strict JSON advisory | Benchmark and schema/citation tests | Loopback Ollama only; no router, costs, fallback or evaluation history per model |
| Prototype agent loop | `modules/agent_loop.py` | DUPLICATED / PARTIAL | Injected planner/decider/tools → evidence pool | No first-party test/import found | Separate from Employee and policy/evidence services; tool errors become evidence-like text |
| Entity resolution | `resolution.py`, `research/analysis.py` | IMPLEMENTED/PARTIAL | Two public records → explainable candidate → human decision | Resolution tests | Never auto-merges; no graph merge/split lineage or calibrated probabilistic model |
| Duplicate resolution prototype | `modules/entity_resolution.py` | DUPLICATED | In-memory queue | No integration evidence found | Overlaps persistent `ResolutionService`; should not become a second authority |
| Graph/workspace | `investigation.py`, `public/graph-model.js`, graph APIs | IMPLEMENTED/PARTIAL | Case events/findings/evidence → workspace/graph view | Python, JS and API contract tests | Saved views and collaboration events; claim/evidence/source lineage is not a unified graph ontology |
| Fusion/contradictions | `fusion_board.py`, `employee/brief.py` | IMPLEMENTED/PARTIAL | Signals → ranked candidates, visible contradictions | Capability/employee tests | Discounts model output; URL/source lineage and circular sourcing are not calculated |
| CTI | `cti.py`, IntelOwl/MISP/OpenCTI boundaries | IMPLEMENTED/PARTIAL | Text/feed/service results → IOCs, STIX, trends | Capability and enterprise tests | Regex-first extraction; service execution depends on external deployments |
| Sensitive workflows | `sensitive/` | IMPLEMENTED bounded paths | Explicit attestations → minimized metadata | Sensitive-workflow tests | Hash/minimization and audit; no direct onion access or illicit actions |
| Media intelligence | `intelligence/media.py` | PARTIALLY_IMPLEMENTED | Local file → hashes/metadata/OCR/transcript/advisory | Intelligence tests | Local tools optional; deepfake/speaker model quality is unverified |
| Research/datasets | `research/` | PARTIALLY_IMPLEMENTED | Fixed research pack → BM25/gap results | Research-pack integrity tests | 4,096 audited papers; no general dataset discovery, licensing and bias registry |
| Automation | `automation.py`, worker | IMPLEMENTED/PARTIAL | Fixed schedule/job → bounded execution and alert | Operational and worker tests | Leases, attempts and alerts; no workforce-level budgets/cost ledger |
| Reporting | `report.py`, Employee export | IMPLEMENTED/PARTIAL | Stored facts/events → JSON/Markdown | Core/employee tests | Evidence-linked fields exist; no unified claim-status verification report or signed authorship |
| Security/CI | workflows, CodeQL, secret/SBOM scripts | IMPLEMENTED repository controls | Source → tests, scan and artifacts | CI definitions | Operational incident response, SSO/SCIM, KMS and penetration-test evidence remain external gaps |

## D. Domain coverage

| Domain | Exists | Working | Tested | Evidence-backed | Production-ready | Primary gap | Priority |
|---|---:|---:|---:|---:|---:|---|---|
| OSINT | Yes | Yes, bounded | Yes | Yes | No proof | Fragmented contracts; no workforce orchestration | P0 |
| WEBINT | Yes | Partial | Yes | Yes | No proof | Search-provider breadth, lineage and reproducible capture | P0 |
| SOCMINT | Yes | Partial | Yes | Partial | No | Access/licence constraints and identity ambiguity | P1 |
| PERSONINT | Yes | Partial | Yes | Partial | No | No canonical lawful-purpose/consent context across all paths | P1 |
| CORPINT | Yes | Partial | Yes | Partial | No | Official-registry pagination, identifiers and jurisdiction packs | P1 |
| GEOINT | Yes | Partial | Partial | Partial | No | Coarse-only fusion; external model/source verification | P2 |
| IMINT | Yes | Partial | Partial | Partial | No | Model quality/evaluation and provenance-rich derived artifacts | P2 |
| VIDINT | Yes | Partial | Partial | Partial | No | Frame/time-span evidence contract and runtime tool proof | P2 |
| AUDINT | Yes | Partial | Partial | Partial | No | Speaker/transcript evaluation and consent model | P2 |
| DOCINT | Yes | Partial | Yes at boundary | Partial | No | Parser/extractor version lineage and live MCP proof | P1 |
| FININT | No native engine | No | No | No | No | Authorized transaction schema, rules, explainable risk review | P3 |
| CTI | Yes | Partial | Yes | Yes | No proof | Context extraction, lineage, live external-service operations | P1 |
| DARKINT | Yes, constrained | Partial | Yes | Yes | No proof | Licensed corpus/isolated acquisition operations | P2 |
| INFRAINT | Yes | Yes, bounded | Yes | Yes | No proof | Provider execution depth and source independence | P0 |
| FORENSICINT | Evidence primitives | Partial | Yes | Yes | No | No disk/memory/mobile forensic pipeline | P3 |
| Dataset intelligence | Research pack/catalog only | Partial | Yes | Partial | No | Discovery, licence, bias, quality and suitability contracts | P1 |
| Threat email | Header/basic analysis | Partial | Yes | Partial | No | DKIM/DMARC/ARC verification, attachment sandbox and clustering | P1 |
| Supply chain | SBOM CI + contracts | Partial | Partial | Partial | No | Unified SBOM/HBOM/OBOM/SaaSBOM/AIBOM dependency graph | P2 |
| Country packs | No | No | No | No | No | Verified jurisdiction-specific source registry | P2 |
| Dorking/discovery | Query generation + OpenOSINT boundary | Partial | Partial | Partial | No | Canonical data-driven registry and captured result provenance | P1 |
| Knowledge graph | Event/entity graphs | Partial | Yes | Partial | No | Temporal claim/source/evidence ontology and versioned relationship state | P0 |
| AI orchestration | Single Employee + prototype loop | Partial | Partial | Partial | No | Typed workforce, router, shared trace, budgets and failure isolation | P0 |

“Production-ready” is **No** wherever hosted deployment, real credentials, runtime
SLAs, representative data and operational controls were not demonstrated.

## E. Target-component gaps

### P0 — Canonical investigation contracts

- **Target capability:** EmployeeDefinition, TaskEnvelope, ResultEnvelope, Observation, Claim, Hypothesis and VerificationDecision.
- **Current implementation:** `Method`, `Finding`, `SourceContract`, `ToolSpec`, `CapabilitySpec`, Employee task JSON and several graph/event shapes.
- **Missing components:** one versioned schema package, validators, migrations and compatibility rules.
- **Technical/data gap:** identifiers and semantics do not consistently link task → source run → evidence → observation → claim → report.
- **Model/connector gap:** models and tools do not consume one shared contract.
- **Security/responsible-AI gap:** authority, purpose, jurisdiction, retention and prohibited actions are not one immutable envelope.
- **Testing/observability gap:** no cross-layer contract suite or end-to-end trace assertion.
- **Dependencies:** existing DB, evidence, policy and graph services.
- **Difficulty / action:** High; implement first and version it. Do not add specialist employees before it passes contract tests.

### P0 — Evidence Fabric v2

- **Current implementation:** file hashes, content-addressed storage, chained ledger, portable bundle, DB evidence rows.
- **Missing:** canonical `EvidenceObject`, immutable versions, acquisition/parser/extractor versions, source URI/ID, chain-of-custody events, access/retention policy and derived-artifact links.
- **Gaps:** metadata and observation linkage, tenant-aware retention, provenance query API, trace propagation.
- **Dependencies:** contract package and schema migration.
- **Difficulty / action:** High; extend without rewriting or weakening the existing ledger.

### P0 — Source independence and verification

- **Current implementation:** exact deduplication, source counts, citation validation, contradiction display and a model-output discount.
- **Missing:** source lineage, original-source/citation chain, content similarity, publisher ownership, independence groups and material-claim state machine.
- **Security/RAI gap:** three URLs can still look like three sources; repeated models are not explicitly collapsed to one underlying source.
- **Testing:** no circular-sourcing, syndicated-story or common-origin golden cases.
- **Difficulty / action:** High; deterministic lineage first, optional AI only for proposed links requiring review.

### P0 — Bounded workforce runtime

- **Current implementation:** plan approval and execution in `employee/service.py`; disconnected `modules/agent_loop.py` prototype.
- **Missing:** employee registry, dynamic role selection, typed task/result bus, per-employee least privilege, shared stop policy, trace IDs and supervisor state machine.
- **Model gap:** no provider-neutral model routing.
- **Cost/observability gap:** action/time budgets exist in places, but tokens and monetary cost do not.
- **Difficulty / action:** High; adapt the Employee service and retire/absorb the prototype rather than create a third orchestration path.

### P0 — Temporal claim graph

- **Current implementation:** spider graph, hosted entity/edge tables, JS graph model, workspace timeline and human resolution queue.
- **Missing:** canonical node/edge ontology for Observation, Claim, Evidence, Source and Acquisition; valid-time/transaction-time; supersession; disputed state; merge/split history.
- **Testing:** graph algorithms are tested, but claim-provenance and temporal-conflict semantics are not.
- **Difficulty / action:** High; add schema adapters and migrations, preserving existing graph imports.

### P1 — Model fabric

- **Current implementation:** one strict loopback Ollama adapter with evidence-ID validation.
- **Missing:** `ModelRegistry`, capability registry, router, health, cost tracker, fallback, jurisdiction/privacy rules and evaluation history.
- **Security gap:** provider egress and retention terms are not modeled because remote providers are not implemented.
- **Action:** introduce interfaces and a deterministic null/local adapter first. Add remote providers only after official-doc, privacy and deployment review.

### P1 — MCP domain facade

- **Current implementation:** allowlisted MCP client for external servers.
- **Missing:** a TraceAtlas MCP server exposing stable business capabilities with case, authority, scope, trace and policy context.
- **Action:** wrap existing deterministic services; keep business rules outside MCP handlers.

### P1 — Evaluation and golden investigations

- **Current implementation:** broad unit/contract suite and a small versioned AI advisory benchmark.
- **Missing:** reproducible end-to-end cases and metrics for evidence precision, entity resolution, citation correctness, unsupported claims, contradictions, independence, latency and cost.
- **Action:** create synthetic domain and company investigations before enabling multiple models.

### P1/P2 — Domain data products

- **Current implementation:** mixed live/export/catalog boundaries.
- **Missing:** verified country packs, dataset registry, threat-email workflow and supply-chain ontology; FININT is a later isolated workstream.
- **Action:** add only after canonical contracts. Never invent source URLs or promote a catalog row to executable capability.

## F. Documentation drift, duplicates and dead/mock findings

1. Root `PRD.md`, `RULES.md`, `PHASES.md`, `DESIGN.md` and `MEMORY.md` do not exist, although the requested architecture assumes them. Existing documents cover parts of those responsibilities.
2. `modules/agent_loop.py`, `modules/entity_resolution.py`, `modules/osint_tools.py` and `modules/timeline.py` overlap production services under `src/traceatlas/`. They are not imported by the main package in the reviewed searches. Status: **DUPLICATED / prototype**.
3. The AgentLoop docstring promises citation enforcement, but an injected `llm_brief` can return arbitrary text. Tool exceptions are stored as evidence-like content. Status: **PARTIALLY_IMPLEMENTED**, unsuitable as the workforce core.
4. Capability inventory can report workflow/service contracts as “ready” based on registry mode/configuration before a successful execution. The separate `execution_verified` field is more trustworthy. Status: **documentation/readiness drift**.
5. Tests mock external transports by design. They prove contracts and failure handling, not provider availability, data quality or licence permission. Operational integration remains **UNKNOWN** until a recorded sandbox run succeeds.
6. No currently reproduced first-party regression failure is classified as **BROKEN**. Missing local Chromium is an environment gap, not proof that the browser workflow is broken.
7. No repository evidence identified a formally deprecated module. Deprecation status is **UNKNOWN** unless maintainers designate canonical owners.

## G. AI employee suitability

| Candidate | Reasoning needed? | Unique data/tools? | Independently verifiable? | Decision |
|---|---:|---:|---:|---|
| Case Manager | Yes | Case/policy state | Yes | AI-assisted, deterministic state machine owns transitions |
| Investigation Planner | Yes | Source/tool registry | Yes | AI-assisted plan proposal; deterministic validator approves |
| Domain router | Mostly no | Registry metadata | Yes | Deterministic rules first; model only for ambiguous objectives |
| OSINT/WEBINT/CTI specialist | Yes | Domain tools | Yes | Add dynamically after contracts and golden cases |
| Evidence integrity verifier | No | Evidence ledger | Yes | Deterministic only |
| Entity resolution analyst | Sometimes | Candidate graph | Yes | Deterministic score + optional explanation; human merge decision |
| Source independence analyst | Mostly no | Lineage graph | Yes | Deterministic clustering; AI proposes uncertain lineage only |
| Contradiction analyst | Yes | Claim graph | Yes | Hybrid; deterministic conflicts plus evidence-cited hypotheses |
| Adversarial supervisor | Yes | Complete result envelope | Yes | AI-assisted, cannot authorize actions or change evidence |
| Report analyst | Yes | Verified claim set | Yes | AI-assisted draft; deterministic citations and human sign-off |
| Hashing/parsing/policy/graph traversal | No | Stable services | Yes | Never an AI employee |

## H. Final audit disposition

- **PLANNED:** hybrid workforce, model fabric, source independence, canonical claim/evidence graph, MCP facade and golden investigations.
- **CODED:** existing deterministic platform, bounded Employee workflow and local advisory AI.
- **TESTED:** repository suites listed above; not representative provider/model quality.
- **DEPLOYED:** not established by this audit.
- **VERIFIED:** local regression and integrity checks only; hosted and external-service verification remain open.

Implementation should begin only after review of this document, the target
architecture and migration plan. The first coding phase must be contracts and a
single replayable vertical slice, not a large collection of agents.
