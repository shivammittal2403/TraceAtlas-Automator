# TraceAtlas Local AI Employee: Ollama, RAG and Knowledge Graph

This is a case-scoped agent operating in the existing TraceAtlas localhost console.
It is not an unrestricted machine administrator, and the imported skill libraries
are not automatically granted execution permissions.

## Architecture

- Python local employee selects among six validated read-only tools through Ollama.
- SQLite memory stores analyst-provided documents, SHA-256 chunk citations, sourced
  relationships and persistent run receipts, partitioned by case id.
- Lexical RAG retrieves exact evidence spans. Ollama may summarize cited data,
  with validation that citations originate from returned tool evidence.
- The knowledge graph uses subject / predicate / object edges, each tied to an
  existing original document in the same case.
- A case.reports tool reads bounded summaries and evidence identifiers from existing TraceAtlas autonomous investigations within the same case. It never runs a collector.
- The model can choose a bounded number of read-only tools, never arbitrary
  shell commands, third-party scripts, arbitrary URLs or new provider permissions.
- The existing authorized AutonomousInvestigator remains responsible for any
  real external source collection, target scope validation and evidence custody.
- Native HTML, CSS and JavaScript live under the existing localhost server,
  sharing existing Host/Origin checking and POST CSRF protection.
- Agent profile and capability boundaries are documented in JSON under
  src/traceatlas/employee/data/agent_profile.json.

## Launch on Windows

From your TraceAtlas repository checkout, update and install:

~~~powershell
git pull origin main
python -m pip install .
ollama pull qwen2.5:7b
~~~

Start Ollama in one terminal:

~~~powershell
ollama serve
~~~

Start TraceAtlas in another terminal:

~~~powershell
$env:TRACEATLAS_WORKFORCE_ENABLED = "1"
$env:TRACEATLAS_VENDOR_ROOT = (Get-Location).Path
traceatlas --workspace ./cases employee serve
~~~

Open http://127.0.0.1:8765/agent, linked from the main investigation console.

Create an authorized case first, select your permitted tools, upload evidence
as document text, add sourced graph links, and enter the objective. You must
approve the case and tool scope. If Ollama is offline, the agent returns
attributed local evidence or an explicit gap instead of pretending a model ran.

## Local HTTP endpoints

- GET /agent: native local employee interface
- GET /api/agent/tools: allowed read-only tools
- GET /api/agent/documents?case=...: case-scoped memory index
- GET /api/agent/run?case=...&id=...: persisted case-scoped result
- POST /api/agent/document: analyst-approved evidence ingestion
- POST /api/agent/edge: analyst-approved attributed graph relation
- POST /api/agent/run: bounded local agent loop with selected tools

POST requests require X-TraceAtlas-CSRF from /api/session and authorized=true.
They reject missing cases and invalid scopes. No endpoint accepts remote tool
code, arbitrary executables or external LLM host names.

## Verification

~~~bash
python -m unittest tests/test_local_ai_employee.py -v
python -m compileall -q src/traceatlas/employee
node --check src/traceatlas/employee/static/agent.js
python -m unittest discover -s tests -v
~~~

GitHub additionally runs OSINT platform contracts, security checks, CodeQL,
dedicated employee workflows, wheel packaging, Python 3.10/3.12 regressions.

## Honest capability boundary

The new code includes working local text RAG, a sourced knowledge graph,
Ollama-selected tool calls, vendor-library search, durable receipts, and a GUI.
It does not yet implement semantic vector embeddings, automatic graph discovery
with verified entity resolution, open-ended self-modifying code execution,
or a working execution adapter for every vendored third-party skill. Those
require independent authorization, dependency/security review, and per-adapter
test fixtures. Notes and AI output remain analyst-review material.
