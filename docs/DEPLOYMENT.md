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

## Release identity and configuration checks

`GET /api/health` and `GET /api/config` expose `traceatlas.build/v1`:
package/console version, expected and observed repository, full Git commit SHA,
Vercel deployment ID and environment. Only bounded Vercel system metadata is
read. Missing or malformed values remain null/UNKNOWN; they are never replaced
with a presumed main SHA. These values are metadata, not signed provenance.
Validate them against GitHub main and the Vercel deployment API independently.
See [Vercel system variables](https://vercel.com/docs/environment-variables/system-environment-variables).

The health endpoint's HTTP 200 indicates the handler answered. `configured` and
`configuration_ready` describe environment configuration only. The worker's
presence is unknown (`isolated_worker: null`), `worker_required` is true and
`hosted_readiness` is NOT_VERIFIED. The static deployment doctor similarly reports
`production_configuration_ready` separately and never sets `production_ready`
from file or environment checks. Real hosted authorization, worker, storage,
recovery and investigator-flow receipts are required for release qualification.

## Dedicated Vercel release proposal — 2026-10-05

The inspected team is `team_m5jLCqU5L9Actouh3eGbZ3Lp`. Its Git-linked project
inventory has no `shivammittal2403/TraceAtlas-Automator` link. The existing
`trace-atlas-osint` project belongs to `shivammittal2403/TraceAtlas-OSINT` and
must not be treated as an Automator deployment or silently repointed.

Proposed dedicated project: `traceatlas-automator`, repository
`shivammittal2403/TraceAtlas-Automator`, production branch `main`, repository
root directory, framework Other, and committed `vercel.json`. Verify the team's
plan limits before creating a deployment. No project, alias, secret, database,
worker or deployment is modified by this repair.

After explicit staging authority, use a disposable Supabase project with the
current migration sequence, Vercel's publishable configuration and a separate
private worker. Never transfer another project's worker/service secrets. Keep
workforce dispatch disabled until scope, worker fencing and hosted isolation
are qualified. Verify unauthenticated denial, real JWT/case/tenant revocation,
Storage/Realtime/export, two-session races, cancellation/recovery and restore.
Compare the actual deployment SHA and health metadata with the tested main SHA.
Only then consider a separately authorized production release.
