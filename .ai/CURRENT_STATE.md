# Enterprise 8/10 program — current state

Updated: 2026-10-04

## Repository baseline

- Repository: `shivammittal2403/TraceAtlas-Automator`
- Program branch: `codex/source-maturity-taxonomy`
- Local checkout HEAD: `9a20b7f16980049380722602c0868f7958d86e4e`
- GitHub branch tip at session start: `83f13df9a8f043f7e4a2536d7d0a26ae674bcc30` (same source tree; local and remote commit metadata differ)
- Package version: `1.11.0`
- Fresh Python result after this session's code: 317 tests; 311 pass, 3 skip, 3 fail (all failures are OpenCTI connector prerequisite failures because the pinned submodule checkout is incomplete). See `docs/program/EVALUATION_RESULTS.md`.
- Node graph/target suite: 25/25 passed when `PYTHON` is set to the bundled Python executable.
- PGlite migration/RLS gate: 1/1 passed after `pnpm install --frozen-lockfile`. Employee UI workflow check passed; hosted/visual browser acceptance is not claimed.
- `compileall`, secret scan and `git diff --check`: passed; secret scan reports clean.
- Production-qualified sources: 0. No new live source was tested this session.

## Capability truth

The canonical local workforce path is coded and fixture-tested through approval,
bounded collection, evidence, verification, graph/timeline, draft and replay.
Twenty-five approval-driven adapters are coded; this is not 25 production
integrations. The eleven-state source maturity taxonomy and target-bound
deterministic investigation plan are coded on the current branch. Remote CI
checks for this branch have not been verified in this session.

Entity resolution is a human-review candidate queue, not a merge engine. It
does not auto-merge, but candidate quality has no representative precision,
recall, ranking or false-merge benchmark. The current Jaro-Winkler weighted
score is a ranking heuristic, not a calibrated identity probability.

## Entity-resolution implementation slice

Added exact-agreement/differing-field signals to the existing candidate result
and human review queue, without changing matching weights or thresholds. Added a
reproducible synthetic company-label evaluation suite and JSON report. At the
existing 0.72 possible-candidate threshold, the small synthetic set measured
precision 0.80, recall 1.00, F1 0.889, false-positive rate 0.05 and recall@1/3
1.00. The identified same-name false-positive candidate scored 0.7258 and
showed differing organization/domain/username/location values. This did not
create an identity merge. Automated merge count is zero, so false-merge rate is
undefined. Operational precision/recall and false-merge rate remain unmeasured.

Persistent scorecard, acceptance gates and program ledgers now exist under
`docs/program/`. This work does not close the representative entity-quality P0.

## Readiness

Overall enterprise score: **not calculated**. There is no accepted numeric
rubric or adequate representative/live evidence for a defensible weighted score.
All release gates remain open; see `docs/program/RELEASE_READINESS.md`.

## Evidence integrity diagnostic (2026-10-04)

Added a deterministic nine-case synthetic evaluation of the local custody ledger,
export bundle verifier and AI citation-ID contract. Eight expected outcomes
matched; five routine invalid cases were rejected. A local attacker who rewrites
captured bytes, the SQLite digest and the hash-chain entry together is accepted
because the local ledger has no independent trust anchor. The report is
[`docs/verification/evidence-integrity-synthetic-2026-10-04.json`](../docs/verification/evidence-integrity-synthetic-2026-10-04.json).
This harness scores 8/9 (0.8889), reports 5/6 (0.8333) rejection across invalid
cases, and is **FAIL**. EVIDENCE-001 remains open; external anchoring, immutable
storage, semantic citation correctness and deployed replay remain unverified.

## Remote synchronization

The authoritative GitHub branch `codex/source-maturity-taxonomy` is currently at
`083c39db42d271e9d6700c04c5f51f05a576aa6d`. The evidence evaluator is in commit
`d0c21249d813c88cffe8b0316067608866a112bc`; follow-up commits restore the
current 1.12.0 repository-state document and record the implementation ledger.
The local checkout still has `HEAD` at
`52def959113c721ad2ffc5753e8db9c6c36db2ff` and is missing the remote merge
ancestry. GitHub API writes were verified, but no workflow runs or status checks
were reported for the pushed commits. The incomplete OpenCTI submodule working
tree remains excluded from program changes.
