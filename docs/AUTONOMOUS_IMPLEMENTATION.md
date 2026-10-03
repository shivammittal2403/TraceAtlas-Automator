# Autonomous investigation delivery

## Audit and architecture decision

Audited main at `fe51ba7b2e085038751a0de1fb546a2ec8453397`. The existing employee service executes a fixed approved source list; the workforce service has strict envelopes but only exposes a no-collection fallback through its CLI. Reuse the IntelligenceHub, source contracts, existing case database and evidence ledger, source lineage, verification engine, temporal graph, analyst skills, and optional local model router.

Build a bounded local investigation coordinator through `employee investigate`: objective plus explicit typed seeds and attestations become an immutable, digest-bound authorization manifest. The coordinator selects eligible source skills, executes within a cumulative action/runtime budget, checkpoints every action, analyzes only evidence from this investigation, then writes a cited report, graph, timeline, and replay manifest. Source results cannot add permissions, commands, destinations, or seeds. Person/company labels require explicit public identifiers; profile candidates never become identity matches.

## Contracts and failure model

Manifest: case, objective, subject label/type, approved seeds, actor, attestations, enabled source skills, expiry, action/runtime limits, optional model. Result: evidence IDs/hashes, observed facts, claim decisions, graph, uncertainty, source failures, budget, trace and stop reason. Each attempted action is reserved before dispatch; resume never repeats an uncertain action. Cancellation/kill switch is checked between bounded calls. Reports are analyst drafts; external release is not an agent capability.

## Start the application

Requires Python 3.10+ and a checkout of this implementation. The Python application
has no third-party runtime dependencies. From the repository root:

```powershell
python -m pip install -e .
$env:TRACEATLAS_WORKFORCE_ENABLED = '1'
traceatlas --workspace ./cases employee serve
```

Open `http://127.0.0.1:8765` (use this exact host). Create a case with its lawful
purpose. Supply the objective, one `type:value` seed per line, the analyst ID,
applicable attestations and a budget. Start the investigation once. The console
shows source activity, observations, claim decisions, source disagreements and
an inspectable graph. Download the evidence/replay ZIP when the run finishes.

For an optional local AI draft, start your independently installed Ollama server
and enter an already available model name such as `qwen2.5:7b`. No model is
downloaded automatically. Model absence or invalid citations produce an explicit
fallback while retaining the deterministic report. The model receives only
bounded evidence excerpts and has no execution tools.

On POSIX shells, enable the feature with `export TRACEATLAS_WORKFORCE_ENABLED=1`.
The existing Vercel/cloud employee and approval routes continue separately; this
change does not expose the local autonomous coordinator through those routes.

## CLI workflow

Create a case once, then run:

```text
traceatlas --workspace ./cases init example-review --title "Domain review" --purpose "Authorized review of our public infrastructure"
traceatlas --workspace ./cases employee investigate --case example-review --objective "Review DNS and registration history" --seed domain:example.org --actor analyst-1 --owned-asset --public-record-basis --authorized --max-actions 8 --runtime-seconds 120 --output ./reports
```

Replace the example identifier and attestations with your actual scope. The CLI
prints the investigation ID before collecting. Add `--plan-only` to save the
manifest without network collection. Subsequent commands use that ID:

```text
traceatlas --workspace ./cases employee investigation-show --case example-review --investigation INVESTIGATION_ID
traceatlas --workspace ./cases employee investigation-cancel --case example-review --investigation INVESTIGATION_ID --actor analyst-1 --authorized
traceatlas --workspace ./cases employee investigation-run --case example-review --investigation INVESTIGATION_ID --actor analyst-1 --authorized --resume
traceatlas --workspace ./cases employee investigation-export --case example-review --investigation INVESTIGATION_ID --output ./reports
traceatlas employee verify-replay --directory ./reports/EXPORTED_DIRECTORY
traceatlas employee executable-skills
```

Person/company investigations use `--subject-type person|company` and an optional
`--subject-label`. Person work requires recorded subject consent. A name alone
does not identify a person or company: supply the exact authorized identifiers.
Associations remain unresolved candidates for human review.

## Actual executable coverage

The registry contains **14 typed source skills across 13 providers**. RDAP accepts
both domain and IP inputs. Skills are selected only for their declared input:

| Seed | Source skills | Autonomous availability |
| --- | --- | --- |
| `domain` | DNS-over-HTTPS, RDAP, Wayback CDX | Bounded public metadata queries |
| `ip` | InternetDB, RDAP, IPWHOIS, GreyNoise Community | Bounded public-IP context; IPv4-only sources omitted for IPv6 |
| `username` | GitHub, GitLab, Hacker News | Exact public username queries with consent/owned-org attestation |
| `cve` | NIST NVD | Published vulnerability metadata |
| `doi` | Crossref | Scholarly publication metadata |
| `package` | npm | Exact package metadata |
| `hash` | VirusTotal | Registered skill; skipped until an unattended provider-entitlement contract exists |

Existing `employee skills` provides analyst procedures. Existing external tools,
OpenCTI packages, imported records and other platform connectors are not silently
promoted into autonomous executable skills. `executable-skills` reports connector
contracts, accepted input types and limitations; a registered skill can still be
skipped because of entitlement, source health or runtime scope.
Credential-required sources and optional-credential sources with a configured
credential are skipped unless their contract explicitly permits unattended calls.
The coordinator never implicitly spends an existing provider credential's quota.

## Execution, recovery and budgets

- Default: 8 attempted source actions and 120 seconds of cumulative collection/
  model-call time. Limits: 12 actions, 900 seconds, 10 seeds, authorization 1–168
  hours. Each provider request receives at most 30 seconds of the remaining budget.
- Actions are ranked by objective keywords and source diversity, within the
  authorized list. This is deterministic prioritization; it is not a learned
  information-gain estimator. Discovered domains/IPs do not authorize new pivots.
- The action count measures connector invocations. A connector's bounded internal
  retries share its request deadline but are not separate source actions. Local
  parsing, hashing and report generation are outside the network/model time meter.
- A source action and its time reservation are persisted before network I/O.
  Successful/failed results replace the reservation with measured time. If a
  process dies, the reservation remains charged and its running action becomes
  `uncertain` on resume; it is never automatically repeated.
- A per-case lease prevents concurrent autonomous writers. After a hard process
  kill, wait for the lease (runtime limit + 60 seconds) to expire before resuming.
  Do not run legacy collectors concurrently against the same local case.
- Cancellation is cooperative between bounded calls. The console cancel button
  persists the request. `TRACEATLAS_WORKFORCE_KILL_SWITCH=1` disables future runs;
  a running process must receive a cancel request or be stopped because changing
  a different shell's environment does not change its environment.
- Failed/empty/skipped sources and exhausted budgets are report gaps. Terminal
  retries return saved results. To recollect uncertain or changed evidence, create
  a new investigation. Authorization or skill-contract changes require a new run.
- `completed` means the planned source workflow finished. Claim confidence is
  separately labeled; it never means a real-world allegation has been proven.

## Evidence and AI semantics

Reports preserve normalized, redacted provider JSON, SHA-256 hashes and the
existing custody ledger. They do not claim to preserve raw HTTP response bytes.
Observations cite evidence; narrowly extracted DNS/IP/CVE/geography relationships
cite observations. No identity merge or causal attribution is automatic. Country
disagreements are surfaced with the caveat that geography semantics and times
may differ. Source grouping estimates independence but cannot prove it.

Instruction-like source text remains evidence and is excluded from the model
brief when detected. Detection is heuristic. Independent containment is provided
by fixed connector hosts, typed authorized seeds and a model with no tools.
Model drafts must include valid observation IDs and a verbatim supporting quote.
They remain human-review assessments even when schema validation succeeds.

Exports contain `report.md`, `report.json`, `graph.json`, normalized evidence
artifacts, `replay.json` and its checksum. Offline replay verifies file hashes,
manifest/report digests and evidence/observation/claim references without a
network request. It does not repeat live searches, authenticate providers or
provide a cryptographic signature against a party able to rewrite the whole bundle.

## Current limits

The loopback console uses Host/Origin checks and a session CSRF token; it is a
single-user local interface, without login, tenancy or remote authorization.
Do not proxy it publicly. Analyst IDs record local assertions, not authenticated
identities. Data is stored in the chosen workspace and uses local filesystem access.

Hosted autonomous execution, cross-model commercial routing, paid provider
entitlements, web-wide search/dork execution, automatic evidence-driven scope
expansion, person identity resolution, registry/court crawling and malware sandbox
execution are not implemented in this coordinator. Existing manual/governed
platform capabilities remain accessible through their original commands. No
autonomous messages, account actions or publication are performed.

## Verification

The full Python suite ran with the pinned OpenCTI source submodule available:
**226 tests, 225 passed, 1 skipped**. The skipped check is the existing
environment-dependent test; no live provider or installed Ollama availability is
claimed. New tests exercise the real IntelligenceHub with fixture HTTP responses,
evidence tamper rejection, scope/actor binding, same-case leases, cancellation,
interrupted resume, cumulative runtime, source failure isolation, IP contradictions,
prompt-injection containment and model fallback. Console HTTP tests cover case
creation through evidence ZIP export, wrong-case access, Host/Origin and CSRF.

Browser verification used a fixture-only server: case creation, start, completed
report, cited graph-node inspection and zero browser console errors. The static
script passes `node --check`. The legacy workforce tests now use their fixed
fixture clock so historical authorization fixtures do not expire with wall time.

```text
git submodule update --init --recursive
python -m unittest discover -s tests -v
```
