# Known issues and blockers

| ID | State | Impact | Evidence / next action |
|---|---|---|---|
| ENV-OPENCTI-001 | BLOCKED by checkout prerequisite | Three Python tests cannot find the pinned OpenCTI connector source; vendor package count is 72 rather than 308. | `third_party/opencti-connectors` is at a dirty, incomplete commit after the prior interrupted fetch. Restore the exact superproject pin when the Git transport is available, then rerun the suite. Do not include this submodule state in program commits. |
| ENV-PGLITE-001 | RESOLVED for this session | Database migration/RLS gate is locally runnable. | `pnpm install --frozen-lockfile` installed the pinned dependency; PGlite test passed 1/1. Dependencies remain ignored local files. |
| ENV-BROWSER-001 | PARTIAL | Employee workflow harness passed; hosted/visual browser acceptance remains unverified. | `tests/test_employee_ui.cjs` passed. Do not treat this as hosted UX or visual acceptance. |
| ENV-WINLOOPBACK-001 | NONREPRODUCING / monitor | One full-suite run had a loopback-console connection-aborted error. | Isolated console tests and the next complete Python suite passed. Root cause remains unknown; reopen if it recurs. |
| ER-QUALITY-001 | OPEN P0 | Entity candidate ranking and false-merge risk lack representative precision/recall measurements. | Synthetic diagnostic exists: 0.80 precision, 1.00 recall on 24 synthetic pairs; one namesake false-positive candidate. Operational accuracy remains unknown until privacy-reviewed adjudicated data exists. |
| SOURCE-PROD-001 | OPEN P0 | Production-qualified source count is zero. | Current terms, account entitlement, intended-runtime live canary, sustained health and operator ownership evidence are absent. |
| HOSTED-OPS-001 | OPEN P0 | Hosted tenant/worker operation, production isolation, backup/restore and distributed controls are not proven. | Requires operator-controlled staging infrastructure and review. |
| GIT-TRANSPORT-001 | PARTIAL | Bundled Git lacks `remote-https`, so native fetch/push cannot synchronize this checkout. Remote writes succeeded through the connected GitHub API. | Remote `codex/source-maturity-taxonomy` contains lineage/contradiction implementation commit `e9d1745790a2c4f42dedd08ffbf1dc0429690686`; local `HEAD` remains `52def959113c721ad2ffc5753e8db9c6c36db2ff` and does not contain remote merge ancestry. Keep remote/local state distinct and do not force-update; restore working Git transport before native synchronization. |

No real individual data, live provider credentials or live social sources are
available for this engineering session. These constraints do not block synthetic
evaluation or other deterministic local work.



- LINEAGE-005: source grouping used hostname equality as a positive origin link, which can conflate tenants on shared hosts. Host-only grouping has been removed; explicit reviewed ownership can still group separate publisher pages. Synthetic score is 12/12 only and contradiction recall remains unmeasured.
