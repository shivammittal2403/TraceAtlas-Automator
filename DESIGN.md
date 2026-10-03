# TraceAtlas Workforce Design

The canonical design is [docs/AI_WORKFORCE_ARCHITECTURE.md](docs/AI_WORKFORCE_ARCHITECTURE.md).

## Implemented package map

| Concern | Canonical implementation |
|---|---|
| Contracts | `src/traceatlas/workforce/contracts.py` |
| Five-role registry/routing | `src/traceatlas/workforce/registry.py` |
| Scheduler and domain slice | `src/traceatlas/workforce/service.py` |
| Local append-only persistence / evidence v2 adapter | `src/traceatlas/workforce/store.py` |
| Model registry/router/fallback | `src/traceatlas/workforce/model_fabric.py` |
| Source independence | `src/traceatlas/workforce/lineage.py` |
| Three-layer verification | `src/traceatlas/workforce/verification.py` |
| Temporal claim graph gates | `src/traceatlas/workforce/graph.py` |
| Direct/MCP capability facade | `src/traceatlas/workforce/tools.py` |
| Local CLI | `src/traceatlas/workforce/cli.py` |
| Hosted read/review endpoint | `api/workforce.py` |
| Hosted schema/RLS | `supabase/migrations/20260930115004_ai_workforce_v1.sql` |

## Trust boundaries

The browser can read tenant-visible workforce state and call the digest-bound
approval RPC. It cannot insert workforce tasks, evidence, claims, results or
traces. A private worker creates and executes tasks. The Python local runtime
uses the same permission intersection and defaults the workforce feature flag to
off. Tool transport never becomes a policy owner.

## Feature controls

- `TRACEATLAS_WORKFORCE_ENABLED=1` enables local workforce planning/execution.
- `TRACEATLAS_WORKFORCE_KILL_SWITCH=1` overrides the enable flag and stops new work.
- Model outage returns a schema-valid deterministic result with explicit gaps.

## Compatibility

Evidence Fabric v2 indexes existing v1 evidence without altering its stored
bytes, hash or ledger. Parser/extractor changes append metadata versions.
Existing Employee, intelligence, graph and evidence services remain canonical
for their current responsibilities.

## Integrated runner and source contracts

- `workforce/documents.py`: strict source/fact records and typed seed validation.
- `workforce/pipeline.py`: bounded capture, graph/timeline, structured verification,
  immutable draft, manifest and network-free replay.
- `workforce_products`: additive local SQLite product persistence; result/product/
  terminal state is atomic while earlier byte/custody capture is retained.
- `workforce/data/pipeline_investigations.json`: controlled G01–G12 fixtures.

Existing hosted API/SQL and browser ownership do not change. See CURRENT_STATE.md
and docs/USER_FLOW.md for the local/hosted boundary and unsupported resume behavior.
