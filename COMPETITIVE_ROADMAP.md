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

## Current 1.5 foundation

| Capability | Current state |
|---|---|
| Typed graph and transforms | Spider event graph, 9 modules, 34 tool adapters, MCP contracts |
| Collection breadth | 40 reviewed engines, 16 intelligence sources, OpenOSINT bundle |
| Evidence | SHA-256 ledger, provenance, fact/inference split, citations through document MCPs |
| CTI | IOC/CVE/ATT&CK extraction, feed dedup, STIX 2.1 |
| Media | Metadata, OCR/transcription, perceptual hashes, model-advisory path |
| Correlation | Deterministic Fusion Board with source caps and contradictions |
| Documents | Citra and Docling staged-file MCP integration |
| Public statistics | Data Commons MCP integration |
| Geospatial | GeoAI MCP, coarse GeoJSON, GeoCLIP/Geo-Sleuth export contracts |
| Deployment | One-command local setup, Vercel control plane, Supabase RLS and isolated worker |
| Research intelligence | 4,096-paper audited metadata pack, BM25/MMR search, gap planning and temporal review |

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

### Phase 1 — analyst graph (in progress)

- persistent entity/relationship schema; reviewed candidate decisions are delivered,
  while reversible merge/split history is still pending;
- transform marketplace manifest with signed packages and permissions;
- graph filtering, path finding, timelines and confidence overlays;
- case notes and evidence citations are delivered; saved graph views remain pending;
- CSV/STIX/MISP/GraphML interchange.

### Phase 2 — team operations

- authenticated multi-tenant backend with strict row isolation;
- analyst roles, approval queues and immutable audit events;
- collaborative graph changes with conflict resolution;
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
