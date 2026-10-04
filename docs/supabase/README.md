# Supabase control plane

Apply every file in `migrations/` in lexical order to a dedicated TraceAtlas
project. Run the pgTAP file in `tests/` against a disposable database before
production. The foreign-key migrations and the workforce migration add
child-side covering indexes for tenant joins, RLS filters and restrict/cascade
checks.

- Vercel: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `TRACEATLAS_ALLOWED_ORIGINS`
- Worker only: `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `TRACEATLAS_WORKER_ID`

Never expose a secret/service-role key to Vercel or browser code. RLS and table
grants are both required: authenticated users read only their organisations and
create organisations, cases and owned assets; job creation is available only
through the validated enqueue RPC. Worker RPCs and evidence writes are
service-role only.

The AI workforce migration follows the same boundary. Authenticated members may
read their tenant's tasks/evidence/verification state and call only the
digest-bound `approve_workforce_task` RPC. Creation of authorization contexts,
tasks, acquisitions, evidence v2, claims, results and traces is private-worker
only. Applying the migration does not enable workforce execution or any model
provider.
