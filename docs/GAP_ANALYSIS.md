# Repository Gap Analysis

## Audit basis

This is a documentation-level audit of the repository's default branch and visible source tree. The project is an existing, active implementation rather than an empty scaffold. The repository contains a Python CLI and SQLite engine, case/evidence/report modules, typed Spider events, adapter registries, CTI and intelligence modules, workforce/verification components, a browser console, API handlers, Supabase schema, and an isolated worker. The README describes a broad set of playbooks, adapters, and test commands. Those declarations are not equivalent to every optional connector being installed, healthy, licensed, or execution-verified.

Relevant implementation locations include `src/traceatlas/{cli,engine,db,evidence,report,policy,spider,cti,workforce}`, `api/{cases,assets,jobs,graph,notes,reviews}.py`, `public/{index.html,employee.js,graph-model.js}`, `supabase/`, and `worker/`.

## Capability status

| Capability | Repository evidence | Status | Remaining work / boundary | Priority |
|---|---|---|---|---|
| Local case lifecycle | `src/traceatlas/cli.py`, `db.py`, `investigation.py`; README quick-start | IMPLEMENTED | Validate each CLI path and preserve clear authority/purpose prompts | P1 |
| Evidence integrity and custody | `evidence.py`, evidence bundle tests, hash-ledger docs | IMPLEMENTED | Authenticity and lawful-acquisition proof require external process | P1 |
| Typed collection and bounded pivots | `collectors.py`, `playbooks.py`, `spider/`, policy/target tests | IMPLEMENTED | Per-adapter runtime/credential/license health still varies | P1 |
| Case graph and visualization | `api/graph.py`, `workforce/graph.py`, `public/graph-model.js` | IMPLEMENTED | Graph edges remain associations; visual/temporal completeness is bounded | P1 |
| AI/workforce and verification | `workforce/{contracts,registry,service,verification,lineage,model_fabric}.py`, golden cases | PARTIAL | Benchmarks do not prove production accuracy; keep humans responsible for material conclusions | P1 |
| Entity resolution | `resolution.py`, review queue, analyst decision API/UI | PARTIAL | Candidates are not automatic identity proof; validate precision/recall and source independence | P1 |
| CTI and IOC workflow | `cti.py`, intelligence modules, connector catalog/docs | IMPLEMENTED | Feed markings, source licensing, freshness, and provider credentials remain operator responsibilities | P1 |
| Malware analysis | File metadata/static/IOC modules and policy gates | PARTIAL | No claim of safe sample execution; isolated sandbox remains separate prerequisite | P0 before any execution feature |
| Authenticated cloud control plane | `api/`, `vercel_control.py`, `supabase/`, `worker/` | IMPLEMENTED | Dedicated project/RLS/worker deployment and production readiness must be verified, not inferred from code | P0 before hosted use |
| Tenant and asset authorization | case/asset/job endpoints, RLS and control-plane tests | PARTIAL | Authorization declarations and ownership attestations are not independent legal verification | P0 |
| Person/cloud investigation | sensitive local policy; cloud asset validator limits types | PARTIAL | Cloud identity target support is intentionally false; keep person work consent-gated/local | P0 |
| Source independence and contradictions | `workforce/lineage.py`, `fusion_board.py`, verification and golden tests | PARTIAL | Coverage and correctness require curated adversarial evaluation; URL count is not corroboration | P1 |
| Replay and reproducibility | run history, schedules, snapshots, ledger, benchmarks | PARTIAL | Re-running external sources cannot reproduce historical responses; add/export a clear replay manifest if required | P2 |
| Documentation contract | extensive architecture, security, integration, and gap docs; missing canonical `docs/WORKFLOW.md` and `docs/USER_FLOW.md` at audit time | PARTIAL | This branch adds those user-facing flow contracts and a consolidated current-state gap summary | P1 |

## What works, can be reused, and remains

**Already implemented:** typed local investigations; SQLite storage; normalized findings; integrity hashes and chained custody events; bounded collectors and event graph; JSON/Markdown reporting; a large adapter/source catalog; CTI/IOC parsing; analyst review queues; and a restricted authenticated cloud plane.

**Reuse:** existing `Target`, `Finding`, method and adapter registries, policy gates, evidence ledger, graph model, review lifecycle, RLS policies, and worker job contracts. Avoid adding a second independent case/evidence database.

**Repair or verify:** keep README capability claims aligned with execution readiness; verify cloud RLS and worker operation against a dedicated disposable project; exercise per-source failure, tenant isolation, cancellation, retry, and retention paths; test adversarial source lineage and identity ambiguity.

**Build next:** produce an explicit replay/export manifest if operational replay is required; improve measurable coverage and citation/source-independence evaluations; document real source coverage and hosted deployment state in generated readiness output.

**Keep deterministic:** authorization decisions, target validation, evidence hashing, normalization, budgets, retention, access control, source allowlists, and report provenance. Models may plan or analyze within policy, but cannot grant scope, mutate evidence, or approve release.
