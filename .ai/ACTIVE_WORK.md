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

## Next item

TA-P0-001 is verified on the code/test head. Next take TA-003: resolve every
qualification reference against authorized immutable case artifacts. Do not
start broad SOCMINT connector expansion until source terms, access permission,
evidence flow and testable API contracts are established.
