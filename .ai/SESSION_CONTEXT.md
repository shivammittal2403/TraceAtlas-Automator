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
5. Create a GitHub branch/commit with parent exactly the currently verified
   main SHA. Create a PR, attach it to the task, and wait for CI/CodeQL.
6. Do not merge unless the user separately asks. After CI, continue the
   highest verified gap rather than claiming the transformation is complete.

The persistent prompt does not execute after a session ends. Resume by following
this checkpoint when the user starts/continues the task.
