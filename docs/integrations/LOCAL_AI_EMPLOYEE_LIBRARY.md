# TraceAtlas local AI employee: integrated skills, OSINT catalogue and Ollama

## What is actually wired

The existing `traceatlas employee serve` command serves the **same** protected
localhost console on `http://127.0.0.1:8765`. Its new library navigator indexes
all eligible canonical skill documents in
`integrations/traceatlas-agentic-skills-library/skills/*/SKILL.md` and repository
metadata from `integrations/awesome-osint-repos/osint-repositories.csv`.

The import is no longer an inert ZIP alone: operators can **search, inspect and
receive bounded local Ollama recommendations** about these references in the
existing console. The existing autonomous investigation pipeline, source fabric,
manager, employees, target authorization and evidence custody remain the **sole**
authority to execute a source call.

`SKILL.md` is workflow documentation, not executable Python. The bundled
scripts, packages, dependencies, examples and upstream GitHub workflows remain
reference assets until vetted, wrapped in governed adapters, and separately
qualified. A recommendation is not a working third-party connector.

## Start in a Windows PowerShell terminal

```powershell
python -m pip install .
$env:TRACEATLAS_WORKFORCE_ENABLED = "1"
traceatlas --workspace ./cases employee serve
```

Run from the repository checkout so the canonical vendored data directories
can be resolved. When launching a wheel-installed `traceatlas` command from a
different working directory, explicitly set `TRACEATLAS_VENDOR_ROOT` to your
local TraceAtlas repository path:

```powershell
$env:TRACEATLAS_VENDOR_ROOT = "C:\\path\\to\\TraceAtlas-Automator"
```

Visit `http://127.0.0.1:8765`. Search the **Integrated skill and OSINT source
library** panel. The panel and existing investigation actions share the same
session and origin.

To enable optional, local-only Ollama advisory planning:

```powershell
ollama serve
# In a second terminal:
ollama pull qwen2.5:7b
```

Put `qwen2.5:7b` in the local Ollama model input, enable **Use local Ollama for
reference ranking**, enter a lawful objective and click **Prepare advisory
plan**. The UI talks only to the TraceAtlas console origin. TraceAtlas's model
adapter communicates with `127.0.0.1:11434` on the host and does not accept
arbitrary model servers from the browser. Ollama is a separate loopback service,
not a public-facing web endpoint.

When Ollama is stopped or returns an invalid structure, keyword-ranked
references remain accessible. Model-generated ids are constrained to the
deterministic shortlist. Ollama cannot create tools, extend target scopes,
approve a case, call a collector or fabricate evidence. You still authorize
a case and its target identifiers through the existing UI to perform source
collection.

## Local API surface

| Endpoint | Method | Behavior |
|---|---|---|
| `/api/library/status` | GET | Counts and read-only integration state |
| `/api/library/search?q=dns&kind=all&limit=12` | GET | Bounded skill and repo metadata search |
| `/api/library/reference?ref=skill:dns-analysis` | GET | Hash-checked read-only SKILL.md; actual ids vary |
| `/api/ollama/status` | GET | Short loopback-only model availability probe |
| `/api/library/plan` | POST | CSRF-protected deterministic or Ollama-ranked references |

`/api/library/plan` accepts JSON `{"objective":"Investigate owned DNS assets",
"model":"qwen2.5:7b","use_ollama":true}` with the normal console CSRF
header. Library results are explicitly tagged `execution_enabled:false`.

Requests are constrained to the existing loopback host and gateway token
policy. No new network listeners or credentials are created.

## Tests and real boundaries

```bash
PYTHONPATH=src python -m unittest tests/test_vendor_library_runtime.py -v
python -m compileall -q src/traceatlas/employee tests/test_vendor_library_runtime.py
node --check src/traceatlas/employee/static/library.js
PYTHONPATH=src python -m unittest discover -s tests -v
```

Full GitHub CI also checks the existing workforce contract/replay, security,
browser, database, source-fabric and integration regressions.

**Coverage limitations:** 2,705 upstream `SKILL.md` occurrences include nested
copies. The runtime intentionally indexes only canonical immediate folders with
valid safe file paths. Counted skill references do not imply independent
execution, working provider keys, or production-qualified adapters. The OSINT
CSV has 497 linked projects, not 497 installed collectors.


## Every vendor file accounted for

The independent `vendor-file-inventory` CI job enumerates all **26,731**
agentic skill library files and **39** OSINT vendor files tracked by Git. It
calculates SHA-256 for each original file, validates symlink confinement and
classifies its current role (canonical `SKILL.md`, skill attachment,
unqualified helper, plug-in mirror, upstream development tooling, OSINT metadata,
documentation or other preserved reference).

The downloadable `traceatlas-vendor-file-ledger` workflow artifact records a
per-file path, role, length and digest and explicitly reports any count,
missing-file or escaping-symlink errors. A ledger role is an **audit statement**,
not a promise the file is useful or safe to execute. Modules without a
qualified TraceAtlas adapter are deliberately marked unqualified, not silently
registered as employees.

```bash
python scripts/audit_integrated_vendor_files.py --output artifacts/vendor-file-ledger.json
```

## Ongoing per-component integration gate

For each source that needs actual execution: verify license, version and
provenance; classify its permissions and dependencies; build a typed
TraceAtlas-native adapter; restrict target scope; produce acquisition receipts;
add deterministic fixtures, threat-model and abuse tests; and require
analyst-controlled approval. The first-party execution engine remains the only
enforcement point.
