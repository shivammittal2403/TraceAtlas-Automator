# Implementation ledger

| Date | Commit / state | Work | Verification | Outcome / remaining gap |
|---|---|---|---|---|
| 2026-10-04 | GitHub program branch `83f13df9a8f043f7e4a2536d7d0a26ae674bcc30`; local equivalent tree at `9a20b7f16980049380722602c0868f7958d86e4e` | Unified source maturity vocabulary, conservative qualification gates, deterministic target-bound investigation plan. | Prior session: focused Source Fabric, employee Source Fabric, Node graph/target, compile, secret and whitespace checks. Full suite had OpenCTI checkout failures. | CODED and locally tested; not live-source-qualified; remote branch CI not rechecked here. |
| 2026-10-04 | Baseline for ER-BENCH-001 | Read repo rules, current-state, acceptance, audit, gap, security, source maturity, entity resolution and golden investigations. | 310 Python tests (304 pass, 3 skip, 3 OpenCTI prerequisite failures); Node 25/25 after environment fix; compile/secret/diff checks pass. | Establish synthetic ER benchmark next; operational accuracy remains unknown. |
| 2026-10-04 | Working tree; commit pending | Added exact agreement/difference signals; synthetic ER benchmark/evaluator/CLI and JSON report; created persistent enterprise scorecard and ledgers. | 8 focused ER/resolution tests pass; full suite: 317 run, 311 pass, 3 skipped, 3 OpenCTI prerequisite failures; Node graph/target 25/25 when exact Python path is set; PGlite 1/1; employee UI check pass; compile/secret checks pass. | Synthetic pair precision .80 / recall 1.00; one false-positive candidate is visible and remains analyst-reviewed. Operational ER, false-merge rate and overall maturity stay unmeasured. |

Add each accepted change with commit SHA, test evidence, actual metrics and known
limitations. Separate CODED, TESTED, LIVE_VERIFIED and DEPLOYED.
