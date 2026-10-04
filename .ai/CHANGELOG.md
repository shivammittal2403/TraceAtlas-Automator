# Program changelog

## 2026-10-04 — Session baseline

- Read repository engineering guidance, current state, acceptance gates, current completion audit, gap analysis, security review, entity-resolution notes and golden-suite documentation.
- Verified local source-maturity branch tree against its GitHub branch tip; branch is one commit ahead of main at the start of this program.
- Ran 310 Python tests: 304 passed, 3 skipped, and 3 OpenCTI-submodule failures. Ran Node graph/target tests after selecting the bundled Python runtime: 25/25 passed. Python compilation, secret scan and whitespace check passed.
- PGlite database tests are blocked because the pinned package is not installed. No new live source or browser test was performed.
- Selected ER-BENCH-001 as the first program task: quantify current synthetic candidate-ranking behavior without tuning the algorithm or claiming live accuracy.
- Added exact-agreement/differing-field signals to ER comparisons; added a synthetic six-query/24-pair evaluator, CLI, tests and captured result. Observed 0.80 pair precision and one namesake false-positive candidate at score 0.7258; false-merge rate remains undefined because no merge is attempted.
- Installed the pinned JavaScript dev dependencies from the lockfile and verified PGlite 1/1, graph/target 25/25 and the local employee workflow. Visual/hosted browser acceptance remains unverified.
