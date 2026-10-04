# Active work

## Work item TA-P0-001 — repair source maturity merge regression

- Baseline: `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`
- Severity: P0; baseline CI cannot compile the application.
- Cause: malformed `SourceManifest.to_dict`, duplicate keyword arguments,
  duplicate registry constants, and unreachable conflicting qualification code.
- Change: restore a single canonical lifecycle vocabulary and shared 23-gate
  policy; require bounded, printable evidence references; keep proposed
  transitions non-persistent and keep actual qualification in FabricStore.
- Focused check: `python -m unittest discover -s tests -p test_source_fabric.py -q`
  — 26 run, 25 pass, 1 optional MCP SDK test skipped.
- Local CI-equivalent compile, full Python suite, secret scan, Node graph,
  database, browser, research integrity, benchmark, 78-case fixture golden,
  local restore drill and pinned OpenCTI snapshot verification pass. Docker is
  unavailable locally. Final diff review is complete. PR #49 code/test head
  `1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI `37184302223` and
  CodeQL `37184302217`, including hosted worker-image verification.

## Work item TA-003 — resolve qualification review evidence references

- PR #49 source maturity repair and program ledgers passed hosted CI and CodeQL.
- Tightened Source Fabric state calculation and promotion so every review hash
  resolves to evidence recorded in the same case; promotion also verifies that
  case's custody ledger. Legacy/direct database rows with unresolved hashes no
  longer qualify.
- Added tests for explicit authorization, missing refs, cross-case refs,
  valid refs, and unresolved legacy rows at promotion.
- Local result: 28 Source Fabric tests pass (one optional SDK skip); full Python
  suite 315 tests pass with three skips; secret scan clean.
- Remaining: publish as a stacked PR on top of PR #49 and verify hosted CI and
  CodeQL. Do not merge either PR without the user's request.

After TA-003 is reviewed, move to semantic evidence replay. Do not start broad
SOCMINT connector expansion until source terms, access permission, evidence
flow and testable API contracts are established.
