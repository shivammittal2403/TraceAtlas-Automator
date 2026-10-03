# Executable API and CLI contracts

`WorkforceService.create_investigation_task(context_id, target_type, target,
objective)` plans exact-scope work. `approve` binds actor/rationale/envelope digest.
`InvestigationPipeline.run(task_id, documents=..., live=False, authorized=True)`
returns a versioned investigation product. `replay(task_id)` validates custody,
input bytes, versions and substantive analysis digest. `SourceDocument.from_dict`
and `StructuredFact.from_dict` reject unknown fields and invalid types/bounds.

CLI additions: `workforce authorize`, `plan`, `run --documents FILE|--live`,
`report`, `replay`, `golden`. Existing authorize-domain, plan-domain and
run-fallback commands remain available. See RUNBOOK.md.

Existing authenticated `/api/workforce` supports registry/task reads and exact
digest approval. It performs no collection. No new public run endpoint is added.
The source input JSON Schema is `schemas/source-document.schema.json`; Python
validators enforce additional scope, byte, URI and temporal checks.
