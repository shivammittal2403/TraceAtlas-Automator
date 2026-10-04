# Supplied repository review — 2026-09

This review covers the 17 archives in the second supplied batch. Five are
byte-identical repeats of archives reviewed for TraceAtlas 0.8, leaving 12 new
projects. Findings were verified against repository READMEs, licence files,
manifests and source layout; feature names are not treated as proof of a safe or
compatible implementation.

| Archive/project | Licence observed | Distinct useful capabilities | TraceAtlas 0.9 result |
|---|---|---|---|
| CTI-to-MITRE with NLP | CC BY-SA 4.0 | CTI classification, ATT&CK dataset/model evaluation | Native operator mapping; assets not copied |
| OSINTIQ | No licence file (README says MIT) | IOC enrichment, ATT&CK, kill-chain and Diamond Model reasoning | Export contract; no source copied |
| ThreatWatch | Non-Commercial 1.0 | Feed pipeline, CVE-aware dedup, clusters, trends and alerts | Native bounded feed/dedup/trends |
| IntelOwl | AGPL 3.0 | Observable/file analyzers, connectors, pivots and playbooks | External service/export boundary |
| OpenCTI | Apache 2.0 Community plus Enterprise files | STIX graph, GraphQL/TAXII and connectors | Native STIX 2.1; no Enterprise files |
| ZettelForge | MIT | CTI memory, aliases, graph retrieval, rules and OCSF audit | Native evidence graph plus adapter |
| Pharos | Proprietary | CTI workspace, graph/search and reporting concepts | Design-only; no code/assets copied |
| CTINexus | MIT | Entity/relation extraction, alignment, link prediction | Adapter; inferred links need review |
| Watcher | AGPL 3.0 | CERT/CVE/ransomware feeds, leak/domain/CT monitoring | External service/export plus feed import |
| SearXNG | AGPL 3.0 | Private metasearch, categories, localization and plugins | Loopback search service |
| MCP SearXNG | MIT | MCP search, suggestions, instance info and URL reading | Read-only stdio MCP allowlist |
| ScrapeGraphAI | MIT | LLM graph extraction across structured inputs | Loopback extraction; code blocked |
| Exa MCP | MIT | Exact repeat of prior archive | Existing integration retained |
| Apify MCP | Apache 2.0 | Exact repeat of prior archive | Existing integration retained |
| Firecrawl MCP | MIT | Exact repeat of prior archive | Existing integration retained |
| Crawl4AI | Apache 2.0 | Exact repeat of prior archive | Existing integration retained |
| Firecrawl | AGPL 3.0 | Exact repeat of prior archive | Existing service retained |

## New native coverage

- deterministic IPv4, domain, URL, email, hash, CVE and ATT&CK extraction;
- evidence-labelled graphs where edges mean co-occurrence, not attribution;
- operator term-to-ATT&CK maps stored as review-required inferences;
- JSON/JSONL/RSS/Atom normalization, CVE-aware dedup and bounded trends;
- STIX 2.1 indicator, vulnerability and attack-pattern bundles;
- SearXNG loopback/MCP and ScrapeGraphAI loopback extraction;
- governed exports for IntelOwl, OpenCTI, Watcher, ZettelForge and CTINexus.

## Intentionally excluded

Credential/session import, private-profile collection, arbitrary model tools,
generated scraper scripts, malware/file execution, remote workers on private
networks, copied upstream feed catalogues, unreviewed actor execution and
automated attribution remain outside the core.
