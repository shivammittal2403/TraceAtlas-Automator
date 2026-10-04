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

## Earlier evidence integrity diagnostic (2026-10-04; superseded by 14-case run)

Added a deterministic nine-case synthetic evaluation of the local custody ledger,
export bundle verifier and AI citation-ID contract. Eight expected outcomes
matched; five routine invalid cases were rejected. A local attacker who rewrites
captured bytes, the SQLite digest and the hash-chain entry together is accepted
because the local ledger has no independent trust anchor. The report is
[`docs/verification/evidence-integrity-synthetic-2026-10-04.json`](../docs/verification/evidence-integrity-synthetic-2026-10-04.json).
This harness scores 8/9 (0.8889), reports 5/6 (0.8333) rejection across invalid
cases, and is **FAIL**. EVIDENCE-001 remains open; external anchoring, immutable
storage, semantic citation correctness and deployed replay remain unverified.

## Opt-in ledger anchoring update

`LedgerAnchor` plus `HmacFileLedgerAnchor` now provide an opt-in external
checkpoint path through `EvidenceStore`; anchored exports carry signed receipts
and require the configured verifier. The expanded 14-case synthetic evaluation
matches 13/14 expected outcomes (0.9286), rejecting 8/9 invalid cases (0.8889).
The HMAC path rejects the tested coordinated local rewrite while the key and
receipt remain separately protected. The unanchored compatibility path still
accepts it. File-backed HMAC cannot prove monotonic freshness or stop an old
receipt rollback. No production key service, remote append-only anchor or
immutable storage has been tested; EVIDENCE-001 remains open. Citation
membership is not semantic support. See `docs/EVIDENCE_ANCHORING.md`.

## Remote synchronization

The GitHub branch `codex/source-maturity-taxonomy` contains the evidence
evaluator commit `d0c21249d813c88cffe8b0316067608866a112bc` and the opt-in HMAC
anchoring implementation commit `b47c331327ae50679a10b59b870c11df86c6342b`.
The remote diff and CLI hook were verified through the GitHub API. The latest
code commit had no associated workflow runs or commit status checks when queried.
The local checkout still has `HEAD` at
`52def959113c721ad2ffc5753e8db9c6c36db2ff` and is missing the remote merge
ancestry. The incomplete OpenCTI submodule working
tree remains excluded from program changes.



## Source independence slice (2026-10-04)

Removed hostname equality as a positive source-origin link after a 12-pair
synthetic benchmark showed that separate tenants on one hostname could be
falsely grouped. Reviewed `ownership_group` metadata remains the way to group
separate pages from a known publisher. The post-change synthetic result is
12/12 expected pairs (TP=7, FP=0, TN=5, FN=0); this is a diagnostic, not an
operational accuracy estimate. Focused evaluator tests passed 2/2, pipeline
tests 27 passed/1 skipped, and AI workforce tests 13/13. Full Python suite:
328 run, 321 pass, 3 skip, 4 fail (3 OpenCTI prerequisite failures and one
Windows loopback-console connection abort). Representative lineage labels and
contradiction recall remain unknown.


## Source independence slice — pushed

Source-origin grouping no longer treats hostname equality as proof of common
origin. Commit `7fa0431c5229ac14dbb2da8b657de6d8a2734749` adds the synthetic evaluator and preserves publisher
aggregation through explicit reviewed ownership metadata. Its 12 synthetic pairs
match (TP=7, FP=0, TN=5, FN=0); contradiction recall and representative lineage
quality remain unmeasured. Focused pipeline and AI tests pass; full suite has
three known OpenCTI checkout failures and one Windows loopback-console abort.


The two loopback-console tests passed on an isolated rerun. The single failure
seen in the full suite did not reproduce; root cause remains unknown and is
tracked as `ENV-WINLOOPBACK-001`.
