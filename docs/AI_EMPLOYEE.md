# TraceAtlas evidence-led AI Employee

## Delivered scope

The Employee turns a research objective into a bounded, reviewable workflow. It
does not claim that every named website in the supplied list is integrated or
safe to automate.

| Capability | Implemented boundary |
|---|---|
| Analyst knowledge | 28 versioned OSINT/PT procedures with official methodology references |
| Supplied source list | 196 raw entries, deduplicated to 187 canonical candidates and packaged in `traceatlas.employee.data` |
| Live collection | Existing TraceAtlas connectors only, selected by target type and policy |
| Active PT | At most one explicitly requested `httpx` probe against an attested owned asset |
| Analysis | Deterministic facts, alternatives, evidence gaps and next checks |
| AI advisory | Optional loopback-only Ollama output; strict schema validation; always an unreviewed draft |
| Hosted mode | Authenticated analysis of stored case evidence; no scanning and no model calls |
| Decisions | Hash-bound approval, immutable decision/review history and no automatic execution |

The catalogue records aliases, likely integration route, verification state,
release gate and next action. Catalogue rows always return
`execution_enabled_by_catalog: false`. A URL appearing in the document is not
evidence of API availability, licence permission, data quality or operational
safety.

## Trust boundary

Source data, webpage text, documents, media metadata and model output are
untrusted data. They cannot add procedures, alter policy, authorize a task or
select a new tool. The execution plan is rebuilt from policy immediately before
running. Stored JSON is never treated as a command.

The Employee also enforces these boundaries:

- facts come only from records classified as observations;
- correlation, inference and model-output records are withheld from the fact set;
- instruction-like source text is withheld rather than followed;
- secrets, contact fields and sensitive identifiers are minimized in briefs;
- scenarios cite evidence IDs and include a benign alternative plus next check;
- explicit source conflicts remain visible;
- approval expires after 24 hours and is tied to the exact plan hash;
- interrupted steps are recorded and are not silently retried;
- human review is bound to the complete evidence digest, preventing stale review;
- no decision causes automatic pivoting, scanning, messaging or remediation.

## Native target routes

| Target | Governed route |
|---|---|
| Domain | DNS, RDAP and Internet Archive metadata |
| IP address | InternetDB, RDAP, IPWHOIS and GreyNoise Community; ipdata is available as an explicit keyed source |
| File hash | VirusTotal when separately configured |
| CVE | NIST NVD and FIRST EPSS through Source Fabric |
| Vulnerability advisory | OSV exact-ID metadata through Source Fabric |
| Username | GitHub, GitLab and Hacker News public endpoints |
| DOI | Crossref |
| npm package | npm registry metadata |

These routes use the existing TraceAtlas integration runners, including response
limits, contract validation, failure isolation and provenance. API keys and
provider readiness remain deployment-specific.

## CLI workflow

```bash
# Procedure and candidate discovery (read-only)
./start.sh employee skills "media verification" --mode osint
./start.sh employee tools "geolocation" --limit 50
./start.sh employee knowledge "entity resolution"

# Create the exact collection plan. Use only attestations that are true.
./start.sh employee assign --case CASE_ID --mode osint \
  --objective "Verify organisation-owned domain exposure" \
  --target-type domain --target example.com \
  --owned-asset --public-record-basis

# The assign response contains TASK_ID and PLAN_HASH. A named reviewer decides
# the same immutable plan; approval by itself executes nothing.
./start.sh employee decide --case CASE_ID --task TASK_ID \
  --decision approved --plan-hash PLAN_HASH --reviewer analyst@example.org \
  --rationale "Scope and sources reviewed" --authorized

# One bounded execution, then inspect its persisted outcomes.
./start.sh employee run --case CASE_ID --task TASK_ID --authorized
./start.sh employee show --case CASE_ID --task TASK_ID

# Analyse already stored evidence without collection.
./start.sh employee brief --case CASE_ID --mode osint \
  --objective "State verified facts, competing explanations and evidence gaps" \
  --output employee-brief.json
```

`employee knowledge --refresh` contacts only a fixed allowlist of public
methodology sources. It pins public IPs, blocks redirects/proxies, bounds
content size and stores responses as untrusted reference material. A failed
refresh preserves the last good content and never changes executable skills.

## Hosted workflow

`POST /api/employee` accepts only `brief` or `queue-review`. It authenticates the
user, checks same-origin requests, resolves the tenant-scoped case through the
existing Supabase gateway and reads at most 200 observations. It cannot call a
collector, active probe or model.

When a reviewer queues a brief, the server rebuilds it and verifies the expected
evidence digest. The compact snapshot enters the existing RLS-protected review
queue. Approval or rejection is a recorded analyst judgment and has no execution
side effect.

## Verification

The repository covers deterministic brief construction, injection resistance,
secret minimization, conflicts, stale evidence, plan approval/expiry, policy
reconstruction, interruption recovery, catalogue counts and hosted API bounds.
`tests/test_employee_ui.cjs` adds an optional real-browser test for untrusted text
rendering, review decisions, stale-response isolation and logout clearing; it
requires a locally installed Playwright Chromium binary.

Run the release checks with:

```bash
python -m unittest discover -s tests -v
node --test tests/test_graph_model.cjs
node --check public/app.js
node --check public/employee.js
python scripts/check_secrets.py
git diff --check
```

## Known limitations

- The 187 candidates are an integration backlog, not 187 live connectors.
- Commercial, authenticated, Tor/dark-web and platform-restricted sources need
  separate legal, licence, credential, retention and connector review.
- Cross-platform identity matches remain hypotheses until a human verifies
  independent evidence; TraceAtlas does not auto-merge identities.
- The Employee does not exploit vulnerabilities, recover credentials, bypass
  authentication, contact subjects or make adverse decisions.
- Production readiness still depends on real provider credentials, Supabase RLS
  deployment, worker operations, logging, backup drills and runtime monitoring.
