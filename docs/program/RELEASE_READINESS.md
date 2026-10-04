# Release readiness

**State: NOT READY.** Current main baseline fails CI after PR #48. The repair
passes available local checks: Python 313 tests (310 passed, 3 skipped), source
compilation, secret scan, graph/target 25/25, PGlite 1/1, employee UI browser
suite, 78/78 controlled source-fabric replay, and restore/integrity checks.
PR #49 is open. Corrected code/test head
`1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI `37184302223` and CodeQL
`37184302217`, including the hosted worker-image build. Hosted staging evidence
remains unavailable.

Required before release: PR CI and CodeQL green; current-state docs accurate;
source-reference verification; review of auth/evidence/network boundaries;
staging, tenant, backup/restore and operational evidence; no critical golden
regression; reproducible weighted score >=8.0. This PR does not deploy, qualify
sources, assert competitive parity, or merge into main.
