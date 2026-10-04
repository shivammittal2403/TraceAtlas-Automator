# Production readiness

Baseline: `641f159326d45afe9797ddf5624a5126640fdd19`, 2026-10-04. **NOT PRODUCTION_QUALIFIED.**

| Gate | Evidence | Status |
|---|---|---|
| CI regression suite | Main CI run 37180291533 success, including Python 3.10/3.12, Node, PGlite, browser fixtures and golden runs | TESTED |
| Static analysis | CodeQL run 37180291558 success | TESTED |
| Type check / lint | No dedicated type-check or lint step in current CI workflow | NOT EVIDENCED |
| Package/build | Wheel build and worker image smoke test in CI | TESTED |
| Source runtime | Selected proxy-assisted response parsing/replay; direct transport canaries failed in audited environment | LIMITED LIVE_TESTED |
| 25 production-qualified sources | Current repo state says zero | NOT MET |
| Staging and authenticated tenant isolation | No live staging/JWT/tenant acceptance evidence | NOT VERIFIED |
| Operations | CI backup/restore drill only; no production DR, SLO, incident or on-call evidence | PARTIAL |
| Cost / quotas | Estimated per-request costs, process-local limits; actual billing/distributed quota open | PARTIAL |
| AI/SOCMINT quality | No 100 end-to-end golden cases or SOCMINT benchmark | NOT MET |

Enterprise Alpha, Beta and RC acceptance gates are not met. CI success is necessary but does not establish production readiness, provider entitlement or source usefulness.
