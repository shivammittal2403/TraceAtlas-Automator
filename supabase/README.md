# Supabase control plane

Apply `migrations/20260925000100_traceatlas_control_plane.sql` to a dedicated
TraceAtlas project, then run the pgTAP file in `tests/` against a disposable
database before production.

- Vercel: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `TRACEATLAS_ALLOWED_ORIGINS`
- Worker only: `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `TRACEATLAS_WORKER_ID`

Never expose a secret/service-role key to Vercel or browser code. RLS and table
grants are both required: authenticated users read only their organisations and
create organisations, cases and owned assets; job creation is available only
through the validated enqueue RPC. Worker RPCs and evidence writes are
service-role only.
