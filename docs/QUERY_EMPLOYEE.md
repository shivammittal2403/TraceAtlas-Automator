# TraceAtlas fact-first Query Employee

## Architecture

Query -> read-only planner -> typed domain team leads -> existing authorized
workforce employee dispatcher -> typed source documents -> source-independence
and temporal contradiction checks -> candidate review -> canonical evidence
validation and fact gate -> analyst approval -> source-cited synthesis.

The query employee module is located at:
src/traceatlas/workforce/query_employee.py

It reuses existing traceatlas.workforce.documents.SourceDocument,
StructuredFact, lineage.SourceIndependenceEngine, and contradictions.contradicts.
For actual collection it routes through the EXISTING WorkforceService,
SourceRouter, InvestigationPipeline and explicit human approval steps.
The query employee never starts collection itself.

## Available planning labels

OSINT, FININT (FINMINT), GEOINT (GEOMINT), CORPINT, CTI, WEBINT, DOCINT,
CODEINT, SOCMINT, PROCINT, BLOCKINT. These are advisory routing labels,
not assertions that every named connector or employee is deployed.

## Offline CLI

PYTHONPATH=src python -m traceatlas.workforce.query_employee plan --case case-001 --query "Cross-check finances, ownership and geolocation" --target-type company --target ACME > plan.json

When existing workers have collected authorized, reviewed source documents,
pass a JSON object with exactly the keys plan and results:

{
  "plan": { "schema": "query-employee/v1", "...": "entire generated plan" },
  "results": [
    { "case_id": "case-001", "task_id": "query-task-...",
      "status": "completed", "documents": [
        { "schema_version": "traceatlas-source-document/v1",
          "source_id": "registered-source-1",
          "source_uri": "https://evidence.example/item",
          "retrieved_at": "2026-10-12T00:00:00+00:00",
          "content": "{\"schema\":\"traceatlas-structured-source/v1\",\"facts\":[]}",
          "facts": [], "original_source_id": null, "ownership_group": null }
      ] }
  ]
}

PYTHONPATH=src python -m traceatlas.workforce.query_employee fuse --input results.json > candidate-review.json

## Existing trust boundary

- Source documents are untrusted submissions. A hash binds provided bytes
  but DOES NOT prove a real-world assertion.
- All output claims remain candidate-only. approved_facts is always empty.
- Canonical EvidenceStore acquisition and byte integrity, VerificationEngine,
  human adjudication, source licensing and policy gates cannot be overridden
  by a query prompt or employee result.
- Cross-case/task references, unvalidated extraction and injection-like
  strings are rejected or withheld.
- Independent sources require separate upstream groups; duplicate copies
  are not corroboration. Date-disjoint values do not imply contradiction.
- Missing provider results remain gaps, never silent negative findings.
- All side-effectful operations remain behind existing authorization,
  exact approved task, scope budgets, and kill switch.

## Honest current scope

This increment implements deterministic query decomposition and offline
source-candidate fusion with tests. It does not yet wire automatic
dispatch or streaming into the production manager, create an LLM plan,
run live API calls, or make final factual approval decisions.
Review PR and run full CI before rollout.
