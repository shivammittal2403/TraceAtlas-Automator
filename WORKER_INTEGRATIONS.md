# Optional worker and MCP integrations

TraceAtlas keeps third-party engines outside its dependency-free core. This
prevents one compromised browser, crawler, MCP package or model tool from
silently inheriting case-database access.

## MCP servers

Install a server through its official, pinned distribution and ensure its
registered executable is on `PATH`. TraceAtlas does not invoke `npx -y`, moving
Git branches or unpinned container tags.

```bash
./start.sh capabilities mcp-tools --source osint-mcp-server --authorized
./start.sh capabilities mcp-tools --source mcp-maigret --authorized
```

`mcp-call` performs initialize/initialized negotiation, invokes one allowlisted
tool and stores a sanitized JSON result in the case evidence ledger. Responses
are limited to 4 MiB, inputs to 64 KiB and execution to 120 seconds.

## Crawl4AI

Deploy a current patched Crawl4AI worker separately and bind it to loopback.
TraceAtlas calls only `POST /crawl`. The bridge rejects code hooks, JavaScript,
cookies, headers, proxy configuration and persistent session IDs.

```bash
export CRAWL4AI_URL=http://127.0.0.1:11235
./start.sh capabilities service-call --case demo-001 --source crawl4ai \
  --action crawl --target https://example.com --owned-org --authorized
```

## Firecrawl

Set `FIRECRAWL_API_KEY` in the worker environment. Do not place it in a JSON
options file or command line. Only the official HTTPS hostname is accepted.

```bash
export FIRECRAWL_API_KEY='set-in-your-secret-manager'
./start.sh capabilities service-call --case demo-001 --source firecrawl \
  --action search --target 'authorised public topic' --owned-org --authorized
```

## SearXNG and ScrapeGraphAI

Both services must be operator-controlled and bound to loopback. SearXNG
supports search with bounded filters. ScrapeGraphAI exposes only `/extract`.

```bash
export SEARXNG_URL=http://127.0.0.1:8080
./start.sh capabilities service-call --case demo-001 --source searxng \
  --action search --target 'authorised public topic' --owned-org --authorized

export SCRAPEGRAPH_URL=http://127.0.0.1:8001
./start.sh capabilities service-call --case demo-001 --source scrapegraph-ai \
  --action extract --target https://example.com/public-report \
  --options-file extraction-options.json --owned-org --authorized
```

SearXNG accepts pages 1-10 and a small set of documented filters.
ScrapeGraphAI accepts only prompt, schema, model and max-pages. Scripts,
executable code, cookies, headers, credentials, proxies and reusable browser
profiles are rejected before the worker is contacted.

## Research and training

```bash
./start.sh capabilities research-brief --case demo-001 \
  --file approved-evidence.jsonl --authorized

./start.sh capabilities training-validate --file module.json
./start.sh capabilities training-record --module osint-101 --lesson sources --score 85
./start.sh capabilities training-progress
```

The research workflow never performs hidden collection. It creates a dependency
DAG, authority record, evidence standard and stopping conditions. Briefing
deduplicates supplied observations while keeping inferences in a separate array.

## Deliberate exclusions

- Private account access, password-reset testing and bulk username enumeration
- Browser-cookie/profile import and CAPTCHA bypass
- Arbitrary Apify Actor execution
- Crawl hooks or runtime code execution
- ScrapeGraphAI generated scripts, credentials or reusable browser sessions
- Private, loopback, link-local or reserved reconnaissance targets
- Copying the unlicensed IOP code or vendoring the AGPL Firecrawl backend
