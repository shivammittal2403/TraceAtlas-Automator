# Known issues and blockers

| ID | State | Impact | Evidence / next action |
|---|---|---|---|
| ENV-OPENCTI-001 | BLOCKED by checkout prerequisite | Three Python tests cannot find the pinned OpenCTI connector source; vendor package count is 72 rather than 308. | `third_party/opencti-connectors` is at a dirty, incomplete commit after the prior interrupted fetch. Restore the exact superproject pin when the Git transport is available, then rerun the suite. Do not include this submodule state in program commits. |
| ENV-PGLITE-001 | RESOLVED for this session | Database migration/RLS gate is locally runnable. | `pnpm install --frozen-lockfile` installed the pinned dependency; PGlite test passed 1/1. Dependencies remain ignored local files. |
| ENV-BROWSER-001 | PARTIAL | Employee workflow harness passed; hosted/visual browser acceptance remains unverified. | `tests/test_employee_ui.cjs` passed. Do not treat this as hosted UX or visual acceptance. |
| ER-QUALITY-001 | OPEN P0 | Entity candidate ranking and false-merge risk lack representative precision/recall measurements. | Synthetic diagnostic exists: 0.80 precision, 1.00 recall on 24 synthetic pairs; one namesake false-positive candidate. Operational accuracy remains unknown until privacy-reviewed adjudicated data exists. |
| SOURCE-PROD-001 | OPEN P0 | Production-qualified source count is zero. | Current terms, account entitlement, intended-runtime live canary, sustained health and operator ownership evidence are absent. |
| HOSTED-OPS-001 | OPEN P0 | Hosted tenant/worker operation, production isolation, backup/restore and distributed controls are not proven. | Requires operator-controlled staging infrastructure and review. |
| GIT-TRANSPORT-001 | BLOCKED | Bundled Git lacks `remote-https`; native push failed. | Use GitHub connector for approved branch commit/ref updates and verify final compare; never report local commit as pushed. |

No real individual data, live provider credentials or live social sources are
available for this engineering session. These constraints do not block synthetic
evaluation or other deterministic local work.
