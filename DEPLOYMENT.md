# Deployment ownership

`shivammittal2403/TraceAtlas-Automator` is the only source of truth. A Vercel
project is valid only when its Git repository is this repository and the
production deployment SHA matches `main`. Do not deploy this tree into existing
projects that track a different repository.

## Components

| Component | Runtime | Responsibility |
|---|---|---|
| Local CLI | Operator machine | Full authorised collection and local evidence |
| Planner | Browser | Validates targets and fills command templates locally |
| Control API | Vercel Python | Auth, RLS-scoped CRUD and allowlisted job requests |
| Database | Dedicated Supabase project | Tenants, cases, owned assets, jobs, graph and audit |
| Worker | Separate container host | Claims fixed jobs and writes minimised results |

Vercel uses only `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`. The worker alone
receives `SUPABASE_SECRET_KEY`. Never put the worker secret in Vercel or browser
code.

## Required sequence

Before step 1, run `./start.sh deployment doctor --json`. After environment
variables are configured, run `./start.sh deployment doctor --production --json`.
The doctor is static and non-mutating; a passing result does not replace hosted
tenant-isolation, queue, backup or restore tests.

1. Create a dedicated Supabase project in the intended organisation.
2. Apply all migrations in lexical order: control plane, FK indexes, analyst
   workflow, then enterprise controls (`20260926000100_enterprise_controls.sql`).
3. Run `supabase/tests/traceatlas_rls.test.sql` on a disposable database.
4. Create a new Vercel project linked to the canonical GitHub repository.
5. Set only publishable Supabase variables on Vercel.
6. Deploy `worker/Dockerfile` on an isolated container host with the worker-only key.
7. Create the first controlled Auth user, sign in, create an organisation and
   explicitly enrol owned assets.
8. Verify health, auth, tenant isolation, enqueue/claim/complete, source-run
   provenance, legal hold, append-only audit, workspace rendering and that
   production SHA equals `main`.

## Production gates

- CI and CodeQL are green for the exact SHA; Vercel reports `READY`.
- `anon` has no table privileges and authenticated users cannot call worker RPCs.
- Vercel contains no secret/service-role key.
- Cross-tenant writes, private/identity targets, arbitrary job kinds and
  cross-origin mutations fail closed.
- Backups, restore and rollback are tested.

Until these gates pass, this is deployment-ready code—not a verified production service.
