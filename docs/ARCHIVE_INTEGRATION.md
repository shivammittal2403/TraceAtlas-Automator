# Two-archive compatibility integration — 2026-10-07

Canonical repository: `shivammittal2403/TraceAtlas-Automator`. Refreshed base:
`b56101237b248922316dc049528e0c83b0f2c774`. The existing standard-library
Python/SQLite/evidence/workforce implementation and hosted Vercel/Supabase
control plane retain ownership. Neither incoming archive replaces the core.

## Complete source preservation

| Supplied archive | SHA-256 | Retained files | Namespaced Python files | Excluded generated/runtime files |
| --- | --- | ---: | ---: | ---: |
| TraceAtlas-OSINT-main.zip | `8d58ea1fdd51e57117b964f23657491fdcca168d4c8d3481450d4402e92a19bd` | 1,066 | 957 | 854 |
| cute-main.zip | `f76cb8af961377a10d57b79481f6ce03819fa931e6508c768f700d12ff3853d8` | 797 | 311 | 1,540 |

Every retained source, test, document, fixture and configuration byte is in
`packages/archive_sources/{osint,cute}`. `docs/archive_merge_manifest.json`
maps each original path/hash to its preserved file and, where applicable, its
adapted runtime path/hash. `python scripts/verify_archive_merge.py` verifies all
of these mappings. It proves byte preservation, not source quality or truth.
Excluded files are Python caches, installed `node_modules`, and the OSINT
archive's sample runtime checkpoint; the uploaded ZIPs remain the original input.

Executable reference files now have a `.source` suffix (1,433 files). Their
bytes and original-path hashes are unchanged. These unreviewed duplicate API,
UI and store implementations are reference material, not an importable or
servable second application. Namespaced runtime Python and the owned public UI
retain ordinary filenames and remain under the normal CodeQL/CI gates. No
scanner query, exclusion or protection is disabled. Secret scanning still
includes all reference bytes. The manifest verifier enforces this boundary.

Both original Python trees use the `traceatlas` name. Runtime imports are
mechanically relocated to `traceatlas.addons.osint_v1` and
`traceatlas.addons.cute_v1`. No `sys.modules` alias, path precedence trick,
replacement console script, new worker or second canonical database is used.
Source presence and importability are not a working integration count.

## Runtime dispositions

| Incoming feature family | Canonical disposition | Execution boundary |
| --- | --- | --- |
| Resource directory, methods, glossary, finder | `/directory/`, linked from the existing workbench | Static reference content; no provider calls |
| Academy curriculum and resources | `/academy/`, training/resources pages, 19 modules and 207 resource references | Static educational material; no credentials or case access |
| Objective parser | `archive analyze --action objective` | Targets/questions are advisory; inferred archive authorization is discarded |
| Dual review | `archive analyze --action dual-review` | Compare supplied drafts; zero model calls; agreement does not prove entailment |
| File ingestion classification | `archive analyze --action detect-file` | Byte signatures/MIME/quarantine flags; never execute or extract archives |
| GEOINT coordinate operations | `archive analyze --action geo` | Supplied coordinate parsing/distance; no person location or biometric identification |
| Scam payment ledger | `archive analyze --action payments` | Exact decimal math, per-currency totals, duplicate suppression, persistent conflict withholding |
| Competing hypotheses / ACH | `archive analyze --action hypotheses` | Explicit submitted support/opposition labels; no token-overlap entailment or calibrated probability |
| ATT&CK/STIX parsing | `archive analyze --action attack-stix` | Supplied versioned bundle; preserve revocation; no feed refresh or actor attribution |
| Archive collection/provider clients | Source retained in the versioned namespaces | Not dispatched by the canonical bridge; existing source contracts/transport/qualification remain authoritative |
| Archive case/graph/evidence databases | Source retained for reference | No migration or writes into these stores from the bridge |
| FastAPI, SQLAlchemy/Alembic, Next.js scaffold, Docker/deployment files | Original snapshot retained under `packages/archive_sources` | Not routed, installed as core dependencies, or deployed |
| AI gateways, remaining domain modules and placeholders | Original and namespaced source retained | Not graduated merely by being present; optional dependencies/implementation gaps remain explicit |

The canonical bridge runs in `src/traceatlas/workforce/archive_bridge.py` and
`archive_actions.py`. The seven actions require an existing local case and
explicit approval to process the submitted file. They share the existing
EvidenceStore and Finding/report pipeline. There is no hosted archive-action
endpoint in this tranche.

## Versioned input/output contracts

All JSON actions accept one finite UTF-8 object, at most 2 MiB, bounded depth
and arrays. Duplicate JSON keys, routine secret fields, embedded authority,
symlinks, devices/FIFOs and unknown action fields are rejected before capture.
Case IDs and citations resolve to the current case. `@input` denotes the exact
submitted bytes; it never constitutes a second independent source.

Outputs use `traceatlas.archive.analysis.v1`: case, action, adapter version,
input SHA-256, canonical evidence references, `ANALYSIS_DRAFT`, review required,
no authority granted and zero network/model calls. The raw validated bytes are
snapshotted before preservation, avoiding input-file substitution races.
Custody is verified before/after capture. Same-case duplicate input reuses
captured evidence and deterministic findings; another case gets its own copy.
This does not introduce a distributed exactly-once or transactional filesystem
claim. A failure after preservation leaves retained bytes for recovery.

### Examples

```bash
traceatlas archive actions
traceatlas --workspace cases init review-case --title "Local archive review" \
  --purpose "Approved evidence analysis and compatibility verification"
traceatlas --workspace cases archive analyze --case review-case --action objective \
  --input objective.json --authorized
traceatlas --workspace cases report --case review-case --output reports
traceatlas --workspace cases verify --case review-case
```

`objective.json`:

```json
{"objective":"Review public infrastructure of example.com; passive only."}
```

Other action inputs:

```json
{"coordinates":["28.7, 77.1","28°36'N 77°12'E"]}
```

```json
{"primary":{"statements":["A service was reported"],"evidence_ids":["@input"]},"secondary":{"statements":["A service was reported"],"evidence_ids":["@input"]}}
```

```json
{"entries":[{"direction":"OUT","amount":"100.10","currency":"INR","status":"COMPLETED","tx_ref":"receipt-label","evidence_ids":["@input"]}]}
```

```json
{"question":"Is this record current?","hypotheses":[{"statement":"It may be stale","opposing_evidence_ids":["@input"]}]}
```

```json
{"type":"bundle","x_traceatlas_attack_version":"18.0","objects":[]}
```

The version in the last example is a fixture label, not a assertion about the
current MITRE release. STIX parsing requires a supplied/detectable version.
Payment totals describe submitted records and stay provisional; no authenticity,
source independence, identity or criminality conclusion is implied.

## Compatibility repairs and verification boundaries

Incoming cute code had a malformed Jarvis return, eagerly imported missing
ATT&CK files, an incorrect decimal-coordinate regex group, implicit coordinate
swapping, an uninitialized file-detector review flag, Decimal values in JSON,
incorrect STIX external ID/revocation keys, and an invalid string escape in
the objective parser. Namespaced repairs are recorded
in the manifest; the original snapshots remain byte-identical. Missing
enterprise/mobile/ICS/timeline implementations stay missing rather than becoming
fake success stubs. The payment bridge withholds conflicting duplicate records
even after a third repeated receipt arrives.

The educational UI uses the existing strict CSP. Directory inline scripts,
styles and handler actions are adapted into same-origin assets/delegated events;
no `eval` or `unsafe-inline` allowance is added. Academy renders an inert,
allowlisted lesson fragment and local quizzes. Remote JS/CSS and automatic
external requests are removed from the active Academy pages. Its index is rebuilt
from the 19 actual files because the supplied 18-row index had missing/mismatched
IDs. Both original UI implementations remain in the source snapshot.

Core dependencies remain empty and Python 3.10+ remains the contract. Only the
graduated, standard-library actions are runtime-qualified by this tranche.
The larger namespaced source tree includes optional Pydantic/FastAPI/SQLAlchemy
code and unresolved scaffold functionality; compilation is not execution proof.

21 new local action/static negative regressions cover case isolation, custody,
repeat imports, scope self-assertion, irrelevant citations, file quarantine,
decimal/currency/duplicate conflicts, explicit hypothesis labels, STIX revocation
and input bounds. Full repository, Node/RLS and browser results are recorded in
`docs/verification/archive-merge-2026-10-07.json` after execution. Local browser
proof is not hosted authentication or production qualification.

No provider collection, database migration, resource/secret change or deployment
is authorized/performed by this integration. User-authorized GitHub publication
is a separate branch/PR/main verification step.

## Security follow-up from merged main

PR #68 merged externally as `5cea4fab540ea97271a9b45352f5d4e48d059054`.
Its repaired CI passed all six jobs, including the locked MCP wire and actual
Chromium Academy/directory flow. The PR's CodeQL aggregate reported 50 new
alerts (48 high, two medium). Analysis job success alone did not close them.

The follow-up confines archive case IDs, rejects separator/control/Windows
device-name aliases and symlinked case/artifact paths, binds archive blob reads
to their digest-derived storage key, verifies blob bytes, and checks report
input/output children. A rehashed canonical report cannot export a foreign or
other-case path: each blob must match this case's verified EvidenceStore
registry before any output is created. Export remains local, explicitly chosen,
bounded to 20 MiB per blob/128 MiB total, and integrity-only.

The loopback console admits only supported public identifier seed kinds; local
file/path seeds remain a legacy CLI capability. The Academy serves the owned
`academy.js`; nine unused legacy JavaScript files are removed from `public`,
with their exact originals retained as inert reference source. The optional DDG
wrapper parser now compares the exact HTTPS hostname and rejects userinfo;
these fixtures do not graduate or execute its external client. The language
tokenizer excludes multiplication/division symbols from its Latin ranges.

Thirteen added core security regressions and two separately run optional parser
fixtures cover these boundaries. There is no hosted alternate-API authorization
claim, no protection against a hostile operating-system user racing filesystem
replacement, and no assertion that the whole repository is vulnerability-free.
Scanner dispositions and exact tests are tracked in
`verification/archive-security-followup-2026-10-07.json`.

## Clean-install compatibility repair

Main `2f662cc` still fails core CI because importing the offline workspace eagerly
imports optional PyYAML. The parser import is now deferred until an actual YAML
catalog file is read. A subprocess using `python -S` proves the workspace can
capture/read synthetic evidence and use built-in registry records without any
optional site package. An existing YAML file still requires its parser; there is
no silent source/model fallback. Original reference bytes remain unchanged and
only the adapted registry's runtime hash is updated.

The child-path helper normalizes and checks a separator-bound root prefix before
I/O, rejects symlinks, and returns the checked resolved path. Canonical export
uses the same helper for artifacts and report/replay children. This does not
claim protection against hostile operating-system races or scanner closure;
fresh remote CodeQL results are required. Current tests and pending gates are
in `verification/archive-compatibility-2026-10-07.json`.

## Attribution

The cute snapshot includes its MIT LICENSE (2026 TraceAtlas Contributors),
preserved in the source snapshot and runtime namespace. The OSINT snapshot has
no root license; no blanket MIT claim is made for it. Its Academy retains the
supplied FreeOSINT MIT LICENSE/ATTRIBUTION. These are user-supplied TraceAtlas
snapshots; no paid dataset, provider entitlement or commercial tool code is
bundled or implied by references to those tools.
