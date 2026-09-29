# TraceAtlas competitive roadmap

## Positioning

TraceAtlas is now a credible open, evidence-first investigation workbench. It
does not yet equal Maltego's mature desktop collaboration ecosystem or Social
Links' claimed 500+ commercial data sources. Pretending otherwise would damage
analyst trust. The defensible path is to win on auditability, local-first AI,
open interoperability, privacy controls and reproducibility.

Official product research shows the competitive baseline: Maltego centres on
typed entities, context-sensitive Transforms and shared graphs, while Social
Links markets full-cycle extraction, visualization, analysis and reporting
across 500+ sources. TraceAtlas therefore treats connector count as only one
axis; evidence quality and governed automation are first-class differentiators.

## Current 1.8 foundation

| Capability | Current state |
|---|---|
| Typed graph and transforms | Spider event graph, 9 modules, 34 tool adapters, MCP contracts |
| Collection breadth | 41 reviewed engines, 37 intelligence sources (23 live), 187 governed IntelOwl modules, OpenOSINT bundle |
| Evidence | SHA-256 ledger, provenance, fact/inference split, citations through document MCPs |
| CTI | IOC/CVE/ATT&CK extraction, feed dedup, STIX 2.1 |
| Media | Metadata, OCR/transcription, perceptual hashes, integrity signals, schema-validated model advisories |
| Correlation | Deterministic Fusion Board with source caps and contradictions |
| Documents | Citra and Docling staged-file MCP integration |
| Public statistics | Data Commons MCP integration |
| Geospatial | GeoAI MCP, coarse GeoJSON, GeoCLIP/Geo-Sleuth export contracts |
| Deployment | One-command local setup, Vercel control plane, Supabase RLS, retention/legal hold and isolated worker |
| Research intelligence | 4,096-paper audited metadata pack, BM25/MMR search, gap planning and temporal review |
| Operations evidence | Durable source runs, connector SLO view, explicit 60-gate maturity scorecard |

## Delivery plan

### Delivered production foundation

- tenant/case/asset/job/evidence/entity/edge schema with RLS;
- same-origin authenticated control API using HttpOnly session cookies;
- atomic fixed-workflow queue claims, worker leases and stale-job recovery;
- case-scoped evidence graph workspace;
- CI, CodeQL, Dependabot, release SBOMs and secret scanning.
- provider response contracts, bounded retries and secret-safe health telemetry;
- persistent human entity-resolution decisions without auto-merge;
- hosted case notes and review tasks protected by tenant RLS;
- binary-integrity lockfiles and evidence-backed release-readiness gates.
- bounded multi-source execution, connector circuit breaking and source-run provenance;
- a unified case timeline/coverage/health/review workspace;
- append-only database audit enforcement and retention/legal-hold policy.
- persistent saved graph views with optimistic revision checks and RLS-scoped
  collaboration events over Supabase Realtime;
- a versioned AI evidence-contract benchmark and CI-exercised local restore drill.

## Evidence-based maturity, not marketing

These scores come from `traceatlas maturity`, which evaluates ten explicit gates
for each area. They describe repository/local-runtime evidence, not licensed-data
breadth or verified hosted operations. The values below were reproduced on
2026-09-26 in the development runtime; optional binaries and live execution
history can change the score.

| Area | Earlier baseline | Verified 1.8 | Blocking acceptance evidence |
|---|---:|---:|---|
| Actual live-source depth | 2.0/10 | 7/10 | 3/10 successful providers and production control plane |
| Social intelligence | 2.0/10 | 6/10 | 2/5 verified sources, run history and production operation |
| Dark-web intelligence | 1.0/10 | 6/10 | Verified/repeated MISP use, licensed corpus authority/SLA and production operation |
| AI/media intelligence | 2.0/10 | 7/10 | Verified local model, representative quality/deepfake benchmark and production monitoring |
| Investigation UX | 3.0/10 | 9/10 | Hosted UX verification |
| Enterprise readiness | 2.5/10 | 7/10 | Source-run history, hosted tenant tests and verified SSO/SCIM lifecycle |
| Overall product maturity | 2.1/10 | 7.0/10 | 18 of 60 explicit gates remain blocked in this clean runtime |

This is not 10/10. The repository now makes that impossible to claim without
the missing evidence. A 10/10 result requires every gate to pass in the target
production environment; adding adapter names or documentation alone cannot
increase operational gates.

The runtime readiness score is intentionally separate and environment-specific.
It remains low until provider calls, external tools and a real Vercel/Supabase/
worker deployment are execution-verified.

### Phase 1 — analyst graph (in progress)

- persistent entity/relationship schema; reviewed candidate decisions are delivered,
  while reversible merge/split history is still pending;
- transform marketplace manifest with signed packages and permissions;
- graph filtering, path finding, timelines and confidence overlays;
- case notes, evidence citations and revision-safe saved graph views are delivered;
- CSV/STIX/MISP/GraphML interchange.

### Phase 2 — team operations

- authenticated multi-tenant backend with strict row isolation;
- analyst roles, approval queues and immutable audit events;
- collaboration event streaming and graph-view conflict resolution are delivered;
- scheduled monitoring, diffs, alert lifecycle and connector health;
- encrypted secret manager references—never browser-stored keys.

### Phase 3 — connector scale

- official APIs and authorised exports before fragile scraping;
- connector SDK, conformance suite, rate budgets and provenance contracts;
- public/business/CTI/geospatial/media/document source packs;
- per-source legal basis, retention and deletion controls;
- quality telemetry: precision sampling, stale-source detection and drift.

### Phase 4 — governed AI

- local retrieval over case evidence with page/region citations;
- prompt-injection labelling and untrusted-content isolation;
- hypothesis generation that cannot execute tools without approval;
- contradiction-first reports and source-independent confidence;
- benchmark corpus for hallucination, entity resolution and link quality.

## Non-negotiable product rules

No private-account access, credential processing, CAPTCHA bypass, bulk person
enumeration, hidden surveillance or automatic criminal attribution. A larger
source count is not strategic advantage if the data cannot be lawfully used,
reproduced or defended in review.

Research references:

- https://docs.maltego.com/en/support/solutions/articles/15000009613-running-transforms
- https://docs.maltego.com/en/support/solutions/articles/15000010791-collaboration
- https://sociallinks.io/products/sl-crimewall
- https://sociallinks.io/
