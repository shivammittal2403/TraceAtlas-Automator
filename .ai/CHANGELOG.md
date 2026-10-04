# Engineering program changelog

## 2026-10-04 — source maturity repair and persistent program

- Recorded the baseline main SHA and failed CI evidence.
- Repaired malformed source maturity registry and workforce CLI syntax that
  broke baseline compilation; consolidated qualification around the shared
  23-gate contract and normalized the legacy connector state.
- Added strict evidence-reference bounds and lifecycle regression coverage.
- Local checks: Python suite 313 run, 310 passed, 3 skipped; source compilation
  and secret scan passed; graph/target tests 25/25; PGlite database test 1/1;
  employee UI browser suite passed; source-fabric golden replay 78/78; restore
  drill passed; benchmark evidence contract 8/8. Optional source SDK test was
  skipped where dependency was unavailable.
- OpenCTI submodule checksum verification passed for 8,275 files. The submodule
  checkout is test support and must not be included in the PR diff.
- GitHub PR CI and CodeQL are still pending; Docker, hosted staging, and live
  source qualification were unavailable/not performed.
- No source has been promoted and no live source was contacted by this run.
