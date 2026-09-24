# Upstream capability matrix

TraceAtlas 0.7 adds a governed compatibility layer for all 19 supplied and
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

The public Vercel application remains a stateless command planner. Optional
engines run only on the operator's machine or separately controlled service and
are never invoked by Vercel.
