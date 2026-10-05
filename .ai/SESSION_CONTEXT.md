# Resume checkpoint

1. Inspect `git status`, current branch, and diff. This checkout came from the
   archive for baseline `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`; its local
   root commit is only a scratch baseline and must never be pushed.
2. Read `docs/AGENTS.md`, this directory, and `docs/program/`.
3. Local Python, Node, PGlite, browser, golden replay, secret, restore, and
   source integrity checks have passed as recorded in `.ai/CHANGELOG.md`.
   Docker is unavailable; do not claim worker-image build verification.
4. Review the final diff, exclude `third_party/opencti-connectors` (local
   submodule test material), and update program ledgers with actual outcomes.
5. PR #49 code/test head `1767708adc27e9dc05e0384a4682571e3797d6c4` is based
   on verified main `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`; CI
   `37184302223` and CodeQL `37184302217` passed. Documentation follow-ups may
   advance the branch and trigger fresh checks.
6. Do not merge unless the user separately asks. TA-003 is in stacked PR #50 at
   head `d9c7965e98ba3e26e123fe33c266c97be7b591b8`; CI `37185114010` and
   CodeQL `37185114003` passed. Continue with semantic replay and the other
   open workstreams; the product transformation remains incomplete.

The persistent prompt does not execute after a session ends. Resume by following
this checkpoint when the user starts/continues the task.


## Verified merge repair follow-up — 2026-10-05

PR #56 was merged as `5ad16f01d4e3916dc6f40591c8fcbef2c14c88b8`. Its tree
`ed5a421db97250eadea5e32910c299b871035ac7` equals the downloaded `03fdfd84`
snapshot. A subsequent merge had reintroduced duplicate registry gate definitions,
a malformed conditional and duplicate test fragments. The follow-up changes only
`src/traceatlas/workforce/source_registry.py` and `tests/test_source_fabric.py`
in executable code. Durable workforce runtime and all 26 qualification gates remain.
Negative tests retain unresolved terms, unresolved operational-owner evidence and
stale-state promotion checks.

Full local suite: **372 run, 369 passed, 3 skipped, zero failures** (88.957 seconds).
Compilation of src/tests/api/scripts/vercel_control.py passes; secret scan is clean.
Exact baseline, changed Git blob hashes and test-output hash are recorded in
`docs/verification/source-qualification-followup-2026-10-05.json`.
Earlier 329-test attribution to merged code remains withdrawn. The previous
synthetic benchmark record remains 12 lineage pairs (TP7/FP0/TN5/FN0) and 8
temporal pairs (TP3/FP0/TN5/FN0); these are not field-accuracy measurements.
Hosted checks are pending publication of this follow-up. Enterprise 8/10,
representative evaluation and live-source qualification remain open.
