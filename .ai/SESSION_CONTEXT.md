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
6. Do not merge unless the user separately asks. TA-003 is implemented locally
   with focused/full test results in `.ai/ACTIVE_WORK.md`; publish it as a
   stacked PR on top of PR #49, then check hosted CI/CodeQL. The product
   transformation remains incomplete while listed workstreams remain open.

The persistent prompt does not execute after a session ends. Resume by following
this checkpoint when the user starts/continues the task.
