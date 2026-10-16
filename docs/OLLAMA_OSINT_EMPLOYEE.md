# Ollama-guided OSINT AI Employee

TraceAtlas already has a case-scoped autonomous public-source investigator, a permissions layer, evidence preservation, analysis and optional Ollama report drafting. This change adds opt-in **Ollama action prioritization** inside the existing investigator. It does not replace the canonical Manager/Team Lead/AI Employee architecture or claim that every Markdown skill is a working provider integration.

## Local setup

Install Python 3.10+, TraceAtlas and Ollama. Download a model locally:

    ollama pull qwen2.5:7b
    ollama serve

Create an approved case with the existing TraceAtlas CLI. Then run:

    export TRACEATLAS_WORKFORCE_ENABLED=1
    traceatlas --workspace ./cases employee investigate \
      --case CASE_ID \
      --objective "Investigate authorized DNS and registration evidence" \
      --seed domain:example.org \
      --actor analyst-1 --owned-asset --public-record-basis \
      --authorized --model qwen2.5:7b --agentic-ollama

Replace the example domain and case identifier with a case and asset you are actually authorized to investigate.

Ollama receives only the submitted objective plus the approved source/action IDs and target types, not private target identifiers, credentials or raw fetched evidence. It returns a strict permutation of action IDs. The original deterministic investigator executes approved calls and records an "ollama_priority_planned" event. On model failure or invalid schema, the original ordering applies. Model advice cannot grant permissions.

For existing source-fabric parallel execution, use --source-fabric without --agentic-ollama. This Ollama selector is for the sequential bounded collector; the Source Fabric retains its separate deterministic wave router. The --model flag on its own can still generate an advisory report from collected evidence.

## Boundaries and status

- Allowed capabilities: human-approved case scope, fixed-host public collection, local Ollama suggestions, evidence-linked analysis, status and replay exports.
- Forbidden to the model: creating tools or targets, private account access, password collection, shell commands, exploitation, automatic identity merges, independent publication, or changing the investigation's authorization and runtime budgets.
- Replanning: one model decision per investigation, replayed from the event log after interrupted execution. It is not an unrestricted autonomous research loop.
- Readiness: CODED; offline unit tests added, live Ollama/provider end-to-end and hosted deployment are NOT VERIFIED.

Verification:

    PYTHONPATH=src python -m unittest discover -s tests -p 'test_ollama_priority_agent.py' -v
    PYTHONPATH=src python -m unittest discover -s tests -q
    python scripts/check_secrets.py
