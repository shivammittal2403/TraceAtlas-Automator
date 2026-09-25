# Upstream capability matrix

TraceAtlas 1.1 includes a governed compatibility layer for all 40 unique supplied and
reviewed upstream projects. The projects are not merged into one unreviewable
dependency tree. Each stays behind an explicit adapter, MCP, service, workflow,
training, export or bundled boundary.

| Engine | Integration | Main capabilities | Execution boundary |
|---|---|---|---|
| Abster Intelligence | Export | Case UI, entity graph, timeline, LLM/MCP | Import approved exports; never persist browser keys |
| Agent Reach | Adapter | Public social/web routing and fallbacks | Consent, public data, no cookie import |
| Claude OSINT | Workflow | Attribution, IdP/SPF, FAIR, monitoring | Organisation-owned/public scope |
| FreeOSINT | Training | Modules, authoring, progress | Non-executing catalogue |
| IOP MVP | Design only | Objectives, DAG, gaps, custody, RBAC | No licence: no code copied or executed |
| OpenOSINT | Bundled | 20 tools, graph, MCP, reports | Isolated runtime and allowlisted bridge |
| Agentic OSINT Agent | Workflow | Bounded ReAct, authority, evaluation | Deterministic authority and evidence gates |
| Apify MCP | MCP | Actors, datasets, tasks, schedules | Actor allowlist; token only from environment |
| Browser Use | Adapter | Browser/CDP, DOM, screenshot, PDF | Isolated profile and domain allowlist |
| Crawl4AI | Adapter | Crawl, fit Markdown, extraction, cache | SSRF guard and rate limits |
| DeerFlow | Workflow | Skills, subagents, memory, sandboxes | Orchestration contract only |
| Exa MCP | MCP | Semantic people/company/code research | Consent and bounded output |
| Firecrawl | Service | Search, scrape, crawl, map, agent | API boundary; AGPL backend not vendored |
| Firecrawl MCP | MCP | 26 tools, monitoring and specialist search | Tool allowlist and bounded output |
| GPT Researcher | Export | Deep research, review, citations, reports | Execution gated pending licence resolution |
| Last30Days | Adapter | Recency, engagement, clustering, transcripts | Public data and rate limits |
| MCP Maigret | MCP | Username candidates, tags, reports | Exact identifier, consent, no bulk enumeration |
| OSINT Agent | Workflow | Multilingual search, translation, satellite | Provenance and fact/inference separation |
| OSINT MCP Server | MCP | 37 DNS/BGP/GeoIP/M365 tools | Tool allowlist, caching and rate limits |
| CTI-to-MITRE NLP | Design only | CTI classification and ATT&CK mapping research | CC BY-SA assets not bundled |
| OSINTIQ | Export | IOC enrichment, ATT&CK/kill-chain reasoning | Missing licence file: no code copied |
| ThreatWatch | Export | Feeds, CVE dedup, trends, alerts | Non-commercial code not copied |
| IntelOwl | Service | Observable/file analysis, plugins and playbooks | External AGPL service only |
| OpenCTI CE | Service/export | STIX graph, connectors, GraphQL/TAXII | Community interoperability only |
| ZettelForge | Adapter | CTI memory, aliases, graph, OCSF audit | Optional local adapter |
| Pharos | Design only | Workspace, graph, search and reports | Proprietary: no code/assets copied |
| CTINexus | Adapter | Entity alignment and link prediction | AI output requires human validation |
| Watcher | Service/export | CERT feeds, leak/domain/CT monitoring | External AGPL service only |
| SearXNG | Service | Private metasearch, categories and filters | Loopback operator instance only |
| MCP SearXNG | MCP | Search, suggestions, info and bounded URL read | Read-only prefix allowlist |
| ScrapeGraphAI | Service | Structured LLM extraction and multi-page graphs | Loopback; generated code blocked |
| Data Commons | MCP | Public indicators, place statistics and time series | Public data, read-only tools |
| Citra | MCP | PDF page/bbox proof, tables, compare, OCR and trust | Staged local files; read-only tools |
| Docling MCP | MCP | Document conversion, OCR, tables, search and RAG | Staged local files; generation blocked |
| SIDA | Design only | Deepfake detection, localization and explanations | No licence: no code/model copied |
| Alethia | Design only | Reverse image, hashes, bias and geo reconciliation | No licence: independent concepts only |
| Geo Sleuth | Export | Terrain/OSM/camera evidence geolocation | Consent/ownership; no live tracking |
| LocateAnything | Export | Local VLM locations and GeoJSON | Custom non-commercial licence |
| GeoAI | MCP | Remote sensing segmentation, classification and change | Owned scope; imagery download blocked |
| GeoCLIP | Adapter | Worldwide visual geolocation and GPS embeddings | External model outputs; coarse retention |

## Commands

```bash
./start.sh capabilities list
./start.sh capabilities doctor --json
./start.sh capabilities show crawl4ai
./start.sh capabilities ingest --case demo-001 --source crawl4ai \
  --file ./approved-export.json --authorized --owned-org
```

Imports accept JSON or JSONL up to 10 MiB. Credentials, tokens, cookies,
passwords, home addresses and government identifiers are never retained.
Imported observations remain explicitly unverified; the normalized record keeps
facts separate from an empty inference section for analyst review.

The planner path remains stateless and processes targets only in the browser.
The optional control plane stores explicitly enrolled organisation-owned
domains, public IPs, public URLs and hashes and requests four fixed passive job
types. Engines run locally or in an isolated worker, never inside Vercel.

## Version 1.1 execution status

- `OpenOSINT` remains fully bundled in its isolated runtime.
- `Apify MCP`, `Exa MCP`, `Firecrawl MCP`, `MCP Maigret` and `OSINT MCP Server`
  use a real MCP stdio client. Only registered read/research tool prefixes are
  exposed; arbitrary Actor execution and destructive tools are blocked.
- `Crawl4AI` uses a loopback-only `/crawl` worker. Runtime code hooks, JavaScript,
  cookies, custom headers, proxies and reusable browser sessions are rejected.
- `Firecrawl` supports bounded search, scrape, map and extract calls to the
  approved HTTPS API endpoint; its AGPL backend is not copied into this project.
- Claude/IOP/Agentic/GPT-Researcher/Last30Days concepts are implemented as a
  deterministic authority-bound research DAG, evidence-gap analysis,
  deduplication and strict fact/inference separation. This is a native TraceAtlas
  implementation, not copied upstream code.
- FreeOSINT-style JSON modules, eight exercise types and local lesson-progress
  tracking are implemented without importing the upstream portal.
- Browser Use, DeerFlow and social-session backends remain external isolated
  workers. TraceAtlas accepts their sanitized exports; it intentionally does not
  import browser cookies or run arbitrary agent prompts inside the core process.
- The native CTI pipeline independently implements IOC/CVE/ATT&CK extraction,
  evidence-labelled co-occurrence graphs, CVE-aware feed deduplication and STIX
  2.1 export. SearXNG and ScrapeGraphAI have bounded loopback service bridges.
- Data Commons, Citra, Docling and GeoAI use the existing real MCP runtime with
  narrowly read-only tool prefixes. Local inputs must pass `stage-file` first.
- The native Fusion Board ranks multi-provider evidence, retains contrary
  signals and discounts inference/model output. Location exports stay coarse.
