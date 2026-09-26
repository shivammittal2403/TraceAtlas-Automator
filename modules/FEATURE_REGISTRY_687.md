# TraceAtlas Feature Registry — 687 Unique Features

This file maps every unique non-overlapping feature extracted from the upstream OSINT corpus
into TraceAtlas Automator modules, current status, and planned development priority.

**Source of truth**: Extreme depth extraction from Abster, Firecrawl, Crawl4AI, Browser-Use,
GPT-Researcher, IntelOwl, Agent-Reach, Agentic-OSINT-Agent, Claude-OSINT, Geo*, OSINTIQ,
Pharos, MCP servers, etc.

**Status legend**:
- `implemented` — already present in TraceAtlas 1.6
- `bridged` — available via adapter / MCP / service boundary
- `planned` — high priority next development
- `design` — documented, not yet coded
- `out-of-scope` — intentionally excluded for safety / licence / policy

---

## 1. IntelOwl Analyzers & Connectors (187)

Most are available through the **IntelOwl service boundary** (explicit analyzer list only).

| # | Feature | TraceAtlas Module | Status |
|---|---------|-------------------|--------|
| 1-187 | AbuseIPDB, Abusix, AdGuard, AIL Typosquatting, Androguard, APIVoid, APKiD, Artifacts, Auth0, BBOT, BGP Ranking, BinaryEdge, BitcoinAbuse, Blint, BoxJS, CAPA, CAPE, Censys, CheckDMARC, CheckPhish, CIRCL PDNS/PSSL, ClamAV, Classic DNS, CleanBrowsing, Cloudflare DNS/Malicious, CriminalIP, CrowdSec, crt.sh, CRXcavator, Cuckoo, CVE Exploitability, CyberChef, CyCat, Cymru, Debloat, DetectItEasy, DNS4EU, DNSDB, DNStwist, Doc Info/Guard, Download File, DroidLysis, DShield, ELF Info, EmailRep, Expand URL, Feodo, File Info/Scan, FireHOL, FLOSS, Google DNS/WebRisk/SafeBrowsing, GoReSym, GreedyBear, GreyNoise, GuardDog, Hashlookup, HIBP, HFinger, HoneyDB, HudsonRock, Hunter, InQuest, IntelX, Intezer, IOCExtract/Finder, IP2Location/Whois/API/Info/QS/Query, JA4, JoeSandbox, Knock, Koodous, LeakIX, LNK/MachO Info, Malpedia, MalProb, MaxMind, MalwareBazaar, MISP, MMDB, Mnemonic PDNS, MobSF, Mullvad DNS, MWDB, NERD, Netlas, Nuclei, NVD CVE, OneNote, OnionScan, Onyphe, OpenCTI, ORKL, OTX, PDF/PE/PEFrame Info, Perm Hash, Phishing Army/Extractor/Form/Stats/Tank, PhoneInfoga, PHunter, PolySwarm, Pulsedive, Qiling, Quad9, Quark, RDAP, Robtex, RTF Info, SecurityTrails, Shodan, Signature Info, Slack, Spamhaus, Speakeasy, Spyse, SS API, StalkPhish, Stratosphere, Strings, Sublime, Suricata, Talos, ThreatFox, Tor, Tranco, Triage, URLhaus, UrlScan, VirusTotal, WhoisXML, XForce, YARA, ZoomEye + Connectors (MISP, OpenCTI, Slack, Email, Webhook, ES, TheHive, Mattermost, Teams, Discord, Generic) | `capabilities/intelowl` + service bridge | bridged |

---

## 2. Abster Intelligence Core (92)

| # | Feature Group | TraceAtlas Module | Status |
|---|---------------|-------------------|--------|
| 188-191 | Local-first IndexedDB + LZ-string URL-hash sharing + soft size limit | Case workspace + evidence ledger | planned (local-first browser mode) |
| 192-194 | BYOK multi-LLM + zero-relay + health test | Intelligence Hub + Ollama loopback | implemented (local AI only) |
| 195-211 | Entity types (PERSON…GENERIC) + confidence + exact name matching + relations | Entity graph + resolution queue | implemented |
| 212-220 | D3 physics graph + real-time insertion + geo nodes + polygon + Leaflet + Turf | Entity graph + Fusion Board | implemented / planned map UI |
| 221-231 | Timeline auto-gen from 5 sources + multi-format date parsers | Timeline + case workspace | implemented |
| 232-238 | Native tools /shodan /whois /dns /wayback /hibp + ToolResult + auto-merge | Intel connectors + evidence ledger | implemented |
| 239-242 | Client-side MD/HTML/PDF reports | Report engine | implemented |
| 243-254 | XSS shield, chat cap, panels, deep-link, demos, search, notes, ErrorBoundary | Case workspace + notes | partial |
| 255-278 | Zustand/Zod/date-fns/recharts/Radix/Tailwind/Playwright/Genkit/Next/React/MCP client/Security helpers | Core runtime | partial (Python core) |

---

## 3. Firecrawl (58)

| # | Feature Group | TraceAtlas Module | Status |
|---|---------------|-------------------|--------|
| 279-298 | Search / Scrape (MD/HTML/Screenshot/JSON) / Interact / Actions / Agent / Crawl / Map / Batch / Media parse / only-main-content / Scrape ID | `capabilities/firecrawl` service bridge | bridged |
| 299-336 | Native Rust modules, NAPI, multi-arch, SDKs, credit lock, rate-limit, P95, 96% coverage, MCP | Firecrawl MCP + service | bridged (AGPL backend not vendored) |

---

## 4. Agentic OSINT + OSINT-Agent + Claude-OSINT (74)

| # | Feature Group | TraceAtlas Module | Status |
|---|---------------|-------------------|--------|
| 337-345 | Planner → Decide → Call → Observe → Done loop + budget/termination | Research DAG + authority gates | implemented (deterministic) |
| 346-350 | WHOIS / DNS / Shodan IDB / GitHub Dork / Wayback | Core collectors + adapters | implemented |
| 351-410 | Evidence pool, scratchpad, TUI, eval harness, smoke tests, metrics, ethical policy, Claude skills, backends, citation enforcement | Research engine + eval | partial / planned |

---

## 5. Agent-Reach Channels (48)

| # | Feature Group | TraceAtlas Module | Status |
|---|---------------|-------------------|--------|
| 411-458 | Pluggable channels, SKILL.md, Doctor, dry-run/safe/system, local config 600, Bilibili/Exa/GitHub/LinkedIn/Reddit/Twitter/Facebook/Instagram/Xiaohongshu/V2EX/Boss/RSS/Web + fallbacks + ban-risk warnings | Intelligence Hub + Agent Reach adapter | bridged (public data only, no cookie import) |

---

## 6. GPT-Researcher / Crawl4AI / Browser-Use / Geo / Remaining (228)

| # | Feature Group | TraceAtlas Module | Status |
|---|---------------|-------------------|--------|
| 459-480 | Planner/execution/publisher agents, source tracking, >2000 word reports, image scrape, AI images, PDF/Word export, Claude Skill, memory continuity | Research engine + report | partial |
| 481-486 | Browser-Use agent, OCI, async, Pydantic, typed exceptions | Browser Use adapter | bridged |
| 487-491 | GeoAI / Geo-CLIP / Geo-Sleuth / LocateAnything / Vision | GeoAI MCP + adapters | bridged |
| 492-505 | FreeOSINT training modules (MCQ, fill-blank, matching, ordering, hotspots, T/F, scenario, short-answer, code) + creator UI | Training catalogue | implemented (JSON modules) |
| 506-520 | All MCP servers (Apify, Firecrawl, Exa, Docling, SearXNG, Maigret, OSINT) + Pharos/OSINTIQ/ATT&CK/CTI-NLP | Capability runtime + MCP client | bridged |
| 521-555 | Analyzer/Connector managers, jobs, React frontend patterns, multi-tenant, notifications, plugin architecture, ethical policies, evidence citation, budget termination, soft limits, credential 600, dry-run | Core + capability doctor | implemented |
| 556-687 | Remaining schemas, date parsers, UI components, CI, docs, benchmark corpus, multi-language, deep agents, training JS, hotspot support, validation engines, project cores | Various | mixed (see CAPABILITY_MATRIX.md) |

---

## Development Priority (Next 30 days)

1. **High** — Complete missing entity resolution queue UI + map visualization (Leaflet)
2. **High** — Expand IntelOwl analyzer allowlist with explicit readiness states
3. **Medium** — Local-first browser mode (Abster-style IndexedDB export/import)
4. **Medium** — Additional Claude-OSINT skills as deterministic workflows
5. **Low** — Full TUI for agentic loops (currently CLI + JSON)

---

## How to use this registry

```bash
# See current capability status
./start.sh capabilities doctor --json

# List all registered engines
./start.sh capabilities list

# Show one engine boundary
./start.sh capabilities show intelowl
```

This registry is the single source of truth for mapping the 687 unique upstream features
into governed TraceAtlas modules. No feature is claimed as “implemented” unless it
passes the readiness scorecard and authorization gates.
