# Deployment boundary

The new runner is local/private Python. Install the existing package or use
`./start.sh`; no new runtime dependency is added. Keep workforce disabled by
default, enable explicitly for authorized local tests and use the kill switch to
stop dispatch. Existing Docker worker/Vercel/Supabase setup remains documented
in root DEPLOYMENT.md and PRODUCTION_ARCHITECTURE.md.

No new hosted migration, provider credential, worker deployment or production
configuration is applied. Before hosted integration add a private worker adapter,
product/evidence authorization and hosted result UI; run real Auth/JWT/RLS/storage,
concurrent failure, egress, backup/restore and golden staging tests. Main's CI and
CodeQL must pass before release/promotion. Production readiness remains false.
