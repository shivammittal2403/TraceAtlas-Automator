# TraceAtlas Automator

**RedKross TraceAtlas × OpenOSINT Fusion — version 1.7.0**

TraceAtlas Automator converts 40 OSINT investigation methods into one safe,
repeatable, evidence-first CLI. It automates deterministic collection and keeps
human review where judgment, attribution, privacy or legal authority matters.

## What is included

- All 40 attached methods in a machine-readable playbook registry.
- Case management backed by SQLite.
- DNS, TLS, HTTP, IP, username, email-header, file-metadata, archive, query,
  environment and timeline collectors.
- SHA-256 evidence preservation and a hash-chained custody ledger.
- Finding deduplication, source/provenance, confidence and severity fields.
- JSON and Markdown reports.
- Monitoring snapshots with change detection.
- Durable local schedules with bounded claiming, failure-safe leases, execution
  history and acknowledgeable change/failure alerts.
- Explicit authorization gates for medium/high-risk workflows.
- SpiderFoot-style typed-event engine with bounded recursive pivots.
- Entity graph persistence, explainable correlations and JSON/GEXF export.
- 34 governed external-tool adapters, including Recon-ng, Amass and the
  ProjectDiscovery reconnaissance pipeline.
- Truthful adapter readiness states distinguish registered, installed,
  execution-verified, degraded, unavailable and policy-blocked tools.
- Installed external binaries can be hash-locked and later verified for missing,
  changed or untracked tool drift.
- Installation doctor, multi-tool profiles and recon-directory catalog import.
- Controlled sensitive-workflow automations with hashed targets, explicit
  attestations, redacted evidence and change detection.
- Governed intelligence hub covering 29 social, code, video, community,
  internet-exposure, business, employee, public-record and threat-intelligence
  sources.
- Fourteen live official/public API connectors: GitHub, GitLab, Hacker News,
  NIST NVD, YouTube, Discord invite
  metadata, Shodan, Censys, VirusTotal, RDAP, Google DNS-over-HTTPS, Internet
  Archive CDX metadata, Shodan InternetDB and Bluesky AppView.
- Bounded 1-12-source collection plans enforce a wall-clock budget, isolate
  provider failures and open a circuit after three consecutive failures.
- Live connectors use bounded retries for rate limits/provider outages, strict
  response-size limits, source-specific JSON contract checks and secret-safe
  failure classifications.
- Authorised API/export ingestion for LinkedIn, Instagram, Facebook, TikTok,
  Snapchat, MalwareBazaar, business registries, employee directories,
  sanctions and court records.
- Local image/audio/video metadata, OCR and transcription orchestration with
  optional loopback-only Ollama analysis and coarse EXIF geography.
- The core needs no paid API, JavaScript runtime or cloud account. HIBP, ORCID
  and WiGLE connectors use separately supplied credentials where required.
- The OpenOSINT 2.29.0 MIT package is preserved under `packages/openosint`, with
  all 20 upstream tools available through its isolated runtime and a governed,
  allowlisted TraceAtlas bridge.
- A dual-mode RedKross console: a stateless local command planner plus an
  optional authenticated control plane for organisations, cases, enrolled
  organisation-owned assets, jobs and evidence graphs.
- A Supabase schema with tenant RLS, narrow Data API grants, audit events and
  atomic job claiming, plus a separately deployed non-root worker for four
  fixed passive cloud workflows. Vercel never runs scanners or provider keys.
- A unified capability registry covers all 41 unique reviewed upstream engines with
  licence-aware adapter, MCP, service, workflow, training and export boundaries.
- Approved JSON/JSONL results from those engines can be sanitized, preserved in
  the evidence ledger and kept separate from analyst inferences.
- A dependency-free MCP stdio client performs real handshakes, policy-filtered
  tool discovery and bounded tool calls for installed compatible servers.
- Bounded Crawl4AI and Firecrawl acquisition bridges, deterministic research
  DAGs, evidence-gap briefs and local JSON training progress are included.
- IntelOwl observable analysis is available through a separately deployed,
  host-allowlisted service boundary. Every call requires an explicit analyzer
  list; file execution and runtime analyzer configuration are excluded.
- The complete supplied 187-item IntelOwl inventory is represented as 173
  analyzers, 13 outbound connectors and one extension framework. Observable
  analyzers become selectable only after TraceAtlas discovers the exact enabled
  name and supported target types from the operator's IntelOwl API; 47 file-only
  analyzers, outbound delivery connectors and arbitrary plugin code remain blocked.
- A native CTI engine extracts IOCs, CVEs and explicit ATT&CK references,
  builds non-causal entity graphs, deduplicates JSON/RSS feeds and exports
  STIX 2.1 without requiring a model or paid service.
- SearXNG search and ScrapeGraphAI extraction can run through loopback-only
  workers; MCP SearXNG uses the same read-only tool allowlist as other MCPs.
- A deterministic Fusion Board ranks evidence from independent providers,
  preserves contradictions, discounts model-generated claims and supports
  privacy-reduced GeoJSON for consented or organisation-owned investigations.
- Local image verification now records content signatures plus optional aHash
  and dHash for near-duplicate triage, extension/signature consistency and
  bounded entropy signals. AI advisories must pass a strict JSON schema before
  they can enter the event graph. Citra, Docling, Data Commons and GeoAI
  MCP contracts add document proof, public statistics and geospatial analysis.
- An audited, metadata-only research pack selects 4,096 unique pre-2027 papers
  across all 16 supplied OSINT subtopics, plus 500 patents, 1,000 gap hypotheses
  and 959 fully resolvable prior-art triage links. It powers offline BM25/MMR search,
  gap-driven collection plans, explainable entity comparison and temporal
  conflict analysis without adding a runtime dependency.
- A non-mutating deployment doctor checks required artifacts, version drift,
  non-root worker configuration, public/secret boundaries and production
  environment readiness without deploying or modifying resources.
- A persistent explainable entity-resolution queue records public-label
  candidates, analyst rationales and accept/reject decisions without automatic
  identity merging.
- Local and hosted case notes plus an RLS-protected review-task lifecycle make
  the analyst-in-the-loop requirement operational rather than documentary.
- A unified case workspace exposes coverage, source health, timeline, review
  queue and evidence gaps in both local CLI and authenticated API form.
- The hosted schema now includes source-run provenance, per-case retention and
  legal-hold policy, append-only audit enforcement and request correlation IDs.
- A readiness scorecard refuses to label the system competitive or production
  ready until runtime, provider, external-tool and hosted-control evidence exists.

See [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md), [MEDIA_FUSION.md](MEDIA_FUSION.md) and
[COMPETITIVE_ROADMAP.md](COMPETITIVE_ROADMAP.md) for every engine, capability,
licence boundary and execution gate. [RESEARCH_ENGINE.md](RESEARCH_ENGINE.md)
documents the corpus audit, algorithms, commands and limitations.

## Unified capability runtime

The capability runtime turns the reviewed engine catalogue into an operational boundary.
Optional packages remain separately installed, but TraceAtlas can call their
approved interfaces and preserve normalized output in the case ledger.

```bash
# Inspect readiness and registered contracts
./start.sh capabilities doctor --json

# Discover only policy-allowed tools from an installed MCP server
./start.sh capabilities mcp-tools --source osint-mcp-server --authorized

# Arguments are supplied in a file so credentials never appear in argv
./start.sh capabilities mcp-call --case demo-001 \
  --source osint-mcp-server --tool dns_lookup \
  --arguments-file ./dns-query.json --owned-org --authorized

# Use a separately deployed Crawl4AI worker bound to loopback
export CRAWL4AI_URL=http://127.0.0.1:11235
./start.sh capabilities service-call --case demo-001 \
  --source crawl4ai --action crawl --target https://example.com \
  --owned-org --authorized

# Submit one owned observable to IntelOwl with an explicit bounded analyzer set
cat > intelowl-options.json <<'JSON'
{"observable_classification":"domain","analyzers_requested":["DNSResolver"],"tlp":"AMBER"}
JSON
export INTELOWL_URL=http://127.0.0.1:80
export INTELOWL_API_KEY=YOUR_LOCAL_SERVICE_TOKEN
./start.sh capabilities service-call --case demo-001 \
  --source intelowl --action analyze --target example.com \
  --options-file ./intelowl-options.json --owned-org --authorized

# Inspect all 187 governed modules, reconcile them with the live service, then
# execute only exact remote-verified observable analyzers.
./start.sh intel modules --json
./start.sh intel module-doctor --authorized --json
./start.sh intel module-run --case demo-001 --module abuseipdb \
  --target-type ip --target 8.8.8.8 --tlp AMBER --owned-org --authorized

# Create an auditable research dependency DAG
./start.sh capabilities research-plan \
  --objective "Review organisation-owned public exposure" \
  --scope-type organisation \
  --authority "Approved by the organisation security owner"
```

MCP execution never uses a shell, never downloads packages automatically and
does not accept credentials/cookies inside tool arguments. Arbitrary Apify Actor
execution, deletion/cancellation, CAPTCHA bypass, private-network targets and
browser-session import are excluded. See [WORKER_INTEGRATIONS.md](WORKER_INTEGRATIONS.md).

## Research intelligence pack

The research engine uses 4,096 audited bibliographic records instead of making
unsupported claims about “implementing” thousands of full papers. Metadata is
integrity-checked, deduplicated and balanced across the supplied topics. Long
abstracts and personal review assignments are excluded from the repository.

```bash
./start.sh research status --verify
./start.sh research search "entity resolution provenance" --limit 10
./start.sh research gaps "privacy-preserving cross-platform correlation"
./start.sh research plan --objective "real-time evidence provenance"
./start.sh research prior-art --paper-id RES-NEW-01645
```

Search results retain DOI/URL provenance and matched terms. Gap and patent
matches remain review-only metadata hypotheses, never novelty or legal opinions.
See [RESEARCH_ENGINE.md](RESEARCH_ENGINE.md).

## Fusion architecture

Both engines remain separately auditable. `./start.sh` creates one lightweight
runtime for TraceAtlas and a second optional runtime for OpenOSINT, then checks
both. This avoids dependency conflicts while the bridge enforces case,
authorization, ownership/consent, command allowlisting and output redaction.

```bash
./start.sh openosint doctor --json

./start.sh openosint run --case demo-001 --authorized --owned-asset \
  -- dns example.com
```

See [FUSION.md](FUSION.md) for the component map, allowlisted commands and
public-deployment boundary.

## Automation boundary

| Level | Meaning |
|---|---|
| `high` | Most deterministic collection can run automatically. |
| `partial` | Collection is automated; analyst interpretation remains. |
| `assisted` | The engine prepares evidence and pivots for manual review. |
| `checklist` | The engine audits or generates a controlled procedure. |
| `manual` | Automation is intentionally blocked due to harm/legal risk. |

The engine does **not** claim that two accounts belong to the same person, that
a person committed an act, or that automated scores are proof. Sensitive
workflows are narrowly automated: clear-web dark-web index metadata, authorized
breach summaries, consented professional-profile candidates, k-anonymous
exposure checks and coarse geolocation of an owned BSSID. Every such run needs
two explicit confirmations plus a recorded lawful purpose and workflow-specific
ownership or consent attestation.

Social-platform support does not bypass authentication or scrape private
profiles. Where an official public API is unavailable, TraceAtlas accepts only
an official, authoritative or otherwise approved export supplied by the
operator. Court filings, sanctions entries, AI output and username matches are
leads that require source review; they are never converted into claims of guilt.

## Multi-source intelligence hub

The governed intelligence layer covers social-media, professional,
business, employee, media, geography, community and threat-intelligence data.

```bash
# Inventory sources, credentials and optional local analysis tools
traceatlas intel sources
traceatlas intel doctor --json

# Collect a consenting public GitHub profile through the public API
traceatlas intel collect --case demo-001 --source github \
  --target-type username --target example --subject-consent --authorized

# Execute a bounded multi-source plan (targets are never echoed in the result)
cat > source-plan.json <<'JSON'
{"sources":[
  {"source":"dns","target_type":"domain","target":"example.com"},
  {"source":"wayback","target_type":"domain","target":"example.com"}
]}
JSON
traceatlas intel batch --case demo-001 --plan source-plan.json \
  --budget-seconds 120 --owned-asset --authorized

# Ingest an owned organisation's official LinkedIn/API export
traceatlas intel ingest --case demo-001 --source linkedin \
  --file ./linkedin-export.json --owned-org --authorized

# Ingest authoritative company data
traceatlas intel ingest --case demo-001 --source business_registry \
  --file ./company-record.json --public-record-basis --authorized

# Analyse an authorised image locally; OCR is optional
traceatlas intel media --case demo-001 --file ./evidence.jpg \
  --owned-asset --authorized --ocr

# Add advisory local-AI analysis without sending evidence to a cloud provider
traceatlas intel analyze --case demo-001 --scan SCAN_ID \
  --authorized --ollama --model qwen2.5:7b --output reports/intelligence.json

# Produce a single analyst view of timeline, coverage, health and review gaps
traceatlas casework workspace --case demo-001 --output reports/workspace.json
```

Image metadata uses ExifTool when installed. Audio/video technical metadata uses
FFprobe, OCR uses Tesseract and transcription uses Whisper. AI is off by
default; when enabled, the endpoint must be loopback Ollama. Exact GPS is not
stored—only coordinates rounded to two decimal places. Direct contacts,
credentials, government identifiers and home addresses are redacted or
removed during ingestion.

See [INTELLIGENCE_HUB.md](INTELLIGENCE_HUB.md) for the source matrix, API
variables, result schema and legal/operational boundaries.

## Quick start

Requires Python 3.10+.

### One-command automatic setup

```bash
git clone https://github.com/shivammittal2403/TraceAtlas-Automator.git
cd TraceAtlas-Automator
./start.sh
```

`start.sh` automatically runs the idempotent setup, selects Python 3.10+,
creates an isolated runtime when supported, falls back safely when `venv` is
unavailable, compiles the source, runs the complete regression suite and writes
integration-readiness reports under `.traceatlas/`. Running it again repairs or
revalidates the local runtime when source files change; unchanged verified
installations start immediately. Use `./set.sh` or `./setup.sh` when setup-only
behaviour is preferred. Set `TRACEATLAS_FORCE_SETUP=1` to force a full rebuild
and regression run. The bundled OpenOSINT package is installed into a separate
`.traceatlas/openosint-venv`; set `TRACEATLAS_SKIP_OPENOSINT=1` only when the
optional upstream runtime must be skipped.

Pass CLI arguments directly through the launcher:

```bash
./start.sh --version
./start.sh intel doctor --json
./start.sh init demo-001 --title "Example review" \
  --purpose "Authorised review of organisation-owned assets"
```

### Durable local automation

Schedules store a fixed playbook and validated target, never an arbitrary command.
Only deterministic `high` or `partial` playbooks are eligible; sensitive workflows
and file paths are rejected. Run `automation run-due` from cron/systemd or another
local supervisor. The first run creates a baseline; later evidence changes and
failures create local alerts.

### Human review and release truth

```bash
# Compare only non-sensitive public labels; this creates a pending candidate.
./start.sh resolve propose --case demo-001 --left ./left.json --right ./right.json \
  --source "approved public exports" --authority "Written approval held by owner" --authorized

./start.sh resolve queue --case demo-001
./start.sh resolve decide --candidate CANDIDATE_ID --decision accepted \
  --reviewer analyst-1 --rationale "Independent public attributes agree." --authorized

# Detect external binary drift and score evidence-backed maturity.
./start.sh integrations lock
./start.sh integrations verify-lock
./start.sh readiness --production --json
./start.sh maturity --production --json
```

An accepted resolution remains a documented analyst judgement, not automatic
proof of identity. The readiness command deliberately fails competitive gates
when tools, providers or the hosted deployment are only registered rather than
execution-verified. See [REMEDIATION_STATUS.md](REMEDIATION_STATUS.md).

```bash
./start.sh automation add --case demo-001 --name "Daily domain baseline" \
  --method domain-map --target-type domain --target example.com \
  --every-minutes 1440 --authority "Written approval from the asset owner" --authorized
./start.sh automation run-due
./start.sh automation alerts --case demo-001 --open-only
```

This scheduler is local and pull-based. It does not create a background daemon,
send data to a third party or claim guaranteed delivery.

Optional third-party binaries and commercial API credentials are reported but
are not silently installed or invented. Core TraceAtlas operation is offline
and has no mandatory third-party Python dependency.

### Vercel deployment

The included `vercel.json`, dependency-free Python functions and static
RedKross interface deploy as a local planner and optional authenticated control
plane:

- Canonical source repository: https://github.com/shivammittal2403/TraceAtlas-Automator
- Both the RedKross console and original TraceAtlas directory are included in
  this repository under `public/`.

```bash
vercel
vercel --prod
```

Planner targets stay in the browser. When Supabase is configured, signed-in
members may store only enrolled organisation-owned domains, public IPs, public
URLs and hashes, then queue a fixed passive workflow. Email, username, person
profiling, leaked credentials, private addresses and arbitrary commands are not
accepted by the cloud path. Collection runs in the isolated worker, not Vercel.

No production URL is claimed until a dedicated Vercel project is linked to this
repository and its deployed commit is verified. See [DEPLOYMENT.md](DEPLOYMENT.md)
and [PRODUCTION_ARCHITECTURE.md](PRODUCTION_ARCHITECTURE.md).

Run static readiness checks before any deployment:

```bash
./start.sh deployment doctor --json
./start.sh deployment doctor --production --json
```

### CI, release and security

Pull requests and `main` run tests, compilation, launcher/JavaScript checks and
secret scanning on Python 3.10 and 3.12. CodeQL and Dependabot cover source,
actions and the worker image. Tagged releases build a wheel, CycloneDX SBOM and
SHA-256 checksums. See [SECURITY.md](SECURITY.md).

### Manual setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .

traceatlas methods
traceatlas init demo-001 \
  --title "Example website review" \
  --purpose "Authorized review of an organization-owned domain"

traceatlas run --case demo-001 --method website-legitimacy \
  --target-type url --target https://example.com

traceatlas report --case demo-001 --output reports
traceatlas search --case demo-001 "shared infrastructure" --limit 20
```

## Spider event engine

The `spider` command runs a module pipeline where each module subscribes to
specific event types and can emit new typed events. New events are deduplicated,
linked to their parent and offered to downstream modules until the configured
depth or event limit is reached.

```bash
# Inspect modules and their event contracts
traceatlas spider modules

# Passive public-domain scan (explicit authorization is required)
traceatlas spider scan --case demo-001 \
  --seed-type domain --seed example.com --authorized \
  --max-depth 3 --max-events 250

# Limit execution to selected modules
traceatlas spider scan --case demo-001 \
  --seed-type email --seed security@example.com --authorized \
  --modules email_domain,dns_resolve,tls_certificate

# Use the scan_id returned above
traceatlas spider events --scan SCAN_ID
traceatlas spider export --scan SCAN_ID \
  --format html --output reports/domain-graph.html
```

Built-in modules:

| Module | Consumes | Produces |
|---|---|---|
| `email_domain` | Email | Domain |
| `url_domain` | URL | Domain |
| `domain_url` | Domain | Canonical HTTPS URL |
| `dns_resolve` | Domain/hostname | IP address |
| `reverse_dns` | Public IP | Hostname |
| `tls_certificate` | Domain/hostname | Certificate and SAN names |
| `http_snapshot` | Public URL | Response, technology and redirect events |
| `file_metadata` | Local file | SHA-256 and file metadata |
| `username_pivots` | Username | Unverified account candidates |

The engine is intentionally bounded: `max-depth` is capped at 8 and
`max-events` at 5,000. HTTP/TLS modules reject localhost, private, link-local
and other non-global addresses. The built-in Spider engine remains passive-only
in version 0.4; direct probes
are available solely through separately gated external-tool adapters.

## External tool integrations

TraceAtlas can orchestrate installed OSINT/recon binaries without using a
shell. It does not silently download or install third-party software.

```bash
# Show all adapters and whether each binary is installed
traceatlas integrations doctor
traceatlas integrations list
traceatlas integrations show amass

# Passive Amass enumeration
traceatlas integrations run --case demo-001 --tool amass \
  --target-type domain --target example.com --authorized

# Direct HTTP probing requires a second active-probing confirmation
traceatlas integrations run --case demo-001 --tool httpx \
  --target-type domain --target example.com \
  --authorized --allow-active

# Run every installed compatible passive adapter
traceatlas integrations profile passive-domain \
  --case demo-001 --target-type domain --target example.com --authorized

# End-to-end: passive discovery, then bounded validation of at most 25 assets
traceatlas integrations pipeline --case demo-001 --domain example.com \
  --authorized --verify --allow-active --max-assets 25
```

Every run creates a scan record, preserves allowed raw output as hashed
evidence, normalizes results into typed events and drops domain/URL results that
fall outside the root target. Secret-scanner results are redacted before
evidence storage; only a SHA-256 representation of secret values is retained.

The following profiles are included:

| Profile | Purpose |
|---|---|
| `passive-domain` | Amass, Subfinder, Assetfinder, Findomain, theHarvester, archives and WHOIS |
| `surface-validation` | DNS, HTTP, TLS and technology validation |
| `authorized-web` | Rate-limited crawling and template/web checks |
| `authorized-network` | DNS and conservative common-port discovery |
| `local-file` | Metadata and local repository secret review |

See [INTEGRATIONS.md](INTEGRATIONS.md) for the complete adapter matrix and
installation model.

### Import the Recon Index dataset

The supplied `recon.html` is a frontend; its embedded data array is empty and
it expects a separate `recon-data.json.gz`. Import that dataset when available:

```bash
traceatlas integrations catalog-import --file recon-data.json.gz
traceatlas integrations catalog-search amass
traceatlas integrations catalog-stats
```

JSON, gzip-compressed JSON and HTML with a non-empty embedded `tool-data` array
are supported. Catalog entries remain research links; they are not executed.

For medium or high-risk methods, explicitly confirm authorization:

```bash
traceatlas run --case demo-001 --method domain-map \
  --target-type domain --target example.com --authorized
```

## Controlled sensitive workflows

These commands are suitable only for assets or people you are authorized to
assess. Every command requires `--authorized`, `--allow-sensitive`, a specific
`--lawful-purpose`, and the relevant ownership or consent flag. Targets are
stored as SHA-256 fingerprints. Normalized results and preserved evidence omit
raw emails, account aliases, BSSIDs, password hashes and breach-file rows.

```bash
# Approved Ahmia/provider export; no network or .onion request is made
traceatlas sensitive darkweb-monitor --case demo-001 \
  --domain example.com --owned-domain \
  --index-file ./approved-index.html --authorized-feed \
  --lawful-purpose "Monitor our domain for indexed exposure" \
  --authorized --allow-sensitive

# Public breach catalog metadata for an owned domain
traceatlas sensitive breach-catalog --case demo-001 \
  --domain example.com --owned-domain \
  --lawful-purpose "Review public breach metadata for our domain" \
  --authorized --allow-sensitive

# Consented email k-anonymity check (requires HIBP_API_KEY)
traceatlas sensitive breach-account --case demo-001 \
  --email analyst@example.com --subject-consent \
  --lawful-purpose "Check my work account for known exposure" \
  --authorized --allow-sensitive

# Password exposure check accepts a precomputed SHA-1 only, never plaintext
traceatlas sensitive password-hash --case demo-001 \
  --sha1 0000000000000000000000000000000000000000 --owned-account \
  --lawful-purpose "Check my own password hash for exposure" \
  --authorized --allow-sensitive

# Consented professional records only; no home/family/location enrichment
traceatlas sensitive person-profile --case demo-001 \
  --name "Jane Example" --subject-consent \
  --lawful-purpose "Verify my public professional bibliography" \
  --authorized --allow-sensitive

# Owned exact BSSID only; retains coordinates rounded to two decimals
traceatlas sensitive wifi-locate --case demo-001 \
  --bssid 00:11:22:33:44:55 --owned-asset \
  --lawful-purpose "Inventory the location of our access point" \
  --authorized --allow-sensitive

# Authorized CSV/TSV/JSON: schema summary only, raw rows are never copied
traceatlas sensitive breach-artifact --case demo-001 \
  --file ./authorized.csv --authorized-data \
  --lawful-purpose "Triage an incident artifact we are authorized to hold" \
  --authorized --allow-sensitive
```

Repeated runs return `"changed": true|false`, so the commands can be run from
cron or another approved scheduler. See
[SENSITIVE_WORKFLOWS.md](SENSITIVE_WORKFLOWS.md) for credentials, data-retention
details and the precise automation boundary.

Methods 22, 26, 29, 33 and 34 deliberately refuse the generic `traceatlas run`
path. This prevents sensitive targets from entering the normal unredacted run
table; use the corresponding `traceatlas sensitive` command instead.

## Commands

```text
traceatlas methods [ID|SLUG] [--json]
traceatlas init CASE_ID --title TITLE --purpose PURPOSE
traceatlas run --case ID --method ID_OR_SLUG --target-type TYPE --target VALUE [--authorized]
traceatlas monitor --case ID --method ID_OR_SLUG --target-type TYPE --target VALUE [--authorized]
traceatlas report --case ID [--output DIRECTORY]
traceatlas search --case ID "QUERY" [--limit 20]
traceatlas verify --case ID
traceatlas spider modules [--json]
traceatlas spider scan --case ID --seed-type TYPE --seed VALUE [--modules LIST] [--authorized]
traceatlas spider events --scan SCAN_ID
traceatlas spider export --scan SCAN_ID --format json|gexf|html --output FILE
traceatlas integrations list [--json] [--installed]
traceatlas integrations doctor [--json]
traceatlas integrations show TOOL
traceatlas integrations run --case ID --tool TOOL --target-type TYPE --target VALUE
traceatlas integrations profile PROFILE --case ID --target-type TYPE --target VALUE
traceatlas integrations catalog-import --file FILE
traceatlas integrations catalog-search [QUERY]
traceatlas integrations pipeline --case ID --domain DOMAIN [--verify --allow-active]
traceatlas intel sources [--json]
traceatlas intel doctor [--json]
traceatlas intel health [--json]
traceatlas intel ingest --case ID --source SOURCE --file FILE [ATTESTATION]
traceatlas intel collect --case ID --source SOURCE --target-type TYPE --target VALUE [ATTESTATION]
traceatlas intel media --case ID --file FILE --authorized --owned-asset [--ocr|--transcribe|--ollama]
traceatlas intel analyze --case ID --scan SCAN_ID --authorized [--ollama --output FILE]
traceatlas fusion auto-rank --case ID --scope SCOPE --authorized [ATTESTATION]
traceatlas openosint doctor [--json]
traceatlas openosint run --case ID --authorized --owned-asset -- COMMAND TARGET
traceatlas sensitive darkweb-monitor --case ID --domain DOMAIN --owned-domain ...
traceatlas sensitive breach-catalog --case ID --domain DOMAIN --owned-domain ...
traceatlas sensitive breach-domain --case ID --domain DOMAIN --owned-domain --hibp-domain-verified ...
traceatlas sensitive breach-account --case ID --email EMAIL --subject-consent ...
traceatlas sensitive password-hash --case ID --sha1 HASH --owned-account ...
traceatlas sensitive person-profile --case ID --name NAME --subject-consent ...
traceatlas sensitive wifi-locate --case ID --bssid BSSID --owned-asset ...
traceatlas sensitive breach-artifact --case ID --file FILE --authorized-data ...
```

Use `--workspace /path/to/cases` before the subcommand to choose storage.

## Typical workflows

### Domain infrastructure and website legitimacy

```bash
traceatlas run --case demo-001 --method 4 --target-type domain \
  --target example.com --authorized
traceatlas run --case demo-001 --method 17 --target-type url \
  --target https://example.com
```

### Preserve and inspect a file

```bash
traceatlas run --case demo-001 --method file-metadata \
  --target-type file --target ./photo.jpg
traceatlas verify --case demo-001
```

### Parse an exported email

```bash
traceatlas run --case demo-001 --method email-headers \
  --target-type file --target ./message.eml
```

### Monitor a public page

Run from cron or a systemd timer. The output includes `"changed": true|false`.

```bash
traceatlas monitor --case demo-001 --method osint-monitoring \
  --target-type url --target https://example.com/news --authorized
```

## Data model

Each run stores the method, typed target, timestamps, status and adapter errors.
Each finding stores the source, confidence, severity, observation and a stable
fingerprint for deduplication. File evidence is copied under
`WORKSPACE/evidence/CASE_ID`, hashed and written to `ledger.jsonl`. Every ledger
entry includes the previous entry hash, making later edits detectable.

## Operational safeguards

1. Create one case per lawful purpose and record that purpose precisely.
2. Collect only public data or data you are authorized to access.
3. Do not contact subjects through this tool.
4. Do not treat generated profile URLs as identity matches.
5. Corroborate material claims with two independent sources.
6. Apply retention limits and access control to the workspace.
7. Have an analyst approve any report before external distribution.

## Development

```bash
python -m unittest discover -s tests -v
python -m compileall -q src api vercel_app_data.py
node --check public/app.js
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for extension points and
[METHOD_COVERAGE.md](METHOD_COVERAGE.md) for the complete coverage matrix.
See [SPIDER_ENGINE.md](SPIDER_ENGINE.md) for the event/module contract.
See [INTELLIGENCE_HUB.md](INTELLIGENCE_HUB.md) for social, media, business and
AI-assisted intelligence workflows.
See [FUSION.md](FUSION.md) for the OpenOSINT compatibility and Vercel design.
