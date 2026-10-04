# Enterprise 8/10 program — current state

## Current repair checkpoint — 2026-10-04

The previous 329-test pass came from an unsynchronized local checkout and was
incorrectly attributed to merged commit `e2f39d3`; that attribution is withdrawn.
PR #54 merged while a repair was underway. Continued from exact main snapshot
`9d025c27a6d9d92294384df85dcbc3f479dae2ec`: all 678 tracked file contents matched.
This snapshot had duplicate merge fragments in the source registry, FabricStore,
qualification policy and source tests. The repair preserves the new 26-gate
qualification policy, same-case evidence validation and stricter LIVE_TESTED
versus LIVE_VERIFIED distinction. Negative tests cover missing prerequisites,
unresolved reviews, and promotion rejection despite a stale state projection.

Fresh result on that snapshot plus the four repair blobs: 354 tests run,
351 passed, 3 skipped, zero failures; compilation and secret scan pass.
Grouping remains TP=7/FP=0/TN=5/FN=0 on 12 synthetic pairs; temporal contradiction
remains TP=3/FP=0/TN=5/FN=0 on 8 synthetic pairs. These do not measure field accuracy.
Baseline, changed blob IDs and verification metadata are recorded in
`docs/verification/source-registry-merge-repair-2026-10-04.json`.
Branch: `codex/repair-qualification-20261004`. Hosted repair CI/CodeQL pending.
The Enterprise 8/10 objective and representative/live acceptance gates remain open.


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


## Temporal contradiction diagnostic (2026-10-04)

Extracted the pipeline's overlapping-valid-time, different-value, registered
single-value predicate rule into `workforce/contradictions.py` and reused it in
the pipeline. The synthetic set has 8 pairs (TP=3, FP=0, TN=5, FN=0). It covers
historical non-overlap, partial overlap, open-ended ranges, other subjects,
other predicates and multivalued DNS. This measures the predicate rule only,
not operational contradiction recall. Focused evaluator 3/3; pipeline 27 pass,
1 skip; AI workforce 13/13; full suite 329 run, 323 pass, 3 skip, 3 known
OpenCTI submodule failures. The Windows loopback failure did not recur.


The temporal contradiction refactor and paired synthetic diagnostic are pushed
in code commit `e9d1745790a2c4f42dedd08ffbf1dc0429690686` on `codex/source-maturity-taxonomy`. The synthetic
conflict set is 3/3 recall, but representative recall remains unmeasured. The
full suite passes all non-OpenCTI tests; the three source prerequisite failures
remain tied to the incomplete submodule.
# TraceAtlas engineering state

Baseline repository: `shivammittal2403/TraceAtlas-Automator`  
Baseline main SHA: `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`  
Baseline version: `1.11.0` (verified in `pyproject.toml` and `docs/README.md`; the prior CURRENT_STATE heading incorrectly said `1.12.0`)  
Program target: evidence-backed enterprise maturity 8.0/10 for defined workflows.

## Verified starting point

- The baseline main CI run `37181405185` failed in both Python compile jobs and
  the locked MCP Source Fabric gate. CodeQL run `37181405183` passed.
- Root cause verified locally: malformed duplicate edits in
  `src/traceatlas/workforce/source_registry.py` made `source_registry.py`
  syntactically invalid. The source maturity definitions also disagreed about
  canonical labels and qualification gates.
- This run repairs syntax, the shared 23-gate lifecycle ladder and bounded
  evidence-reference validation. Focused test state: 26 Source Fabric tests,
  25 passed and one optional MCP SDK case skipped. Broader local checks are
  recorded in `docs/program/IMPLEMENTATION_LEDGER.md`.
- Mainline documentation records 26 canonical adapters and zero
  production-qualified integrations. Keep this distinction until real runtime
  receipts qualify sources.

## Capability truth

The current product is a bounded, evidence-first local investigation workflow.
It is not yet a hosted, fully autonomous OSINT employee or an 8/10 enterprise
platform. SOCMINT, production source qualification, hosted IAM/tenant isolation,
distributed budgets, semantic multilingual planning and staging rollout remain
unverified or open as recorded in `docs/CURRENT_STATE.md` and `docs/ACCEPTANCE_GATES.md`.

This local engineering branch is based on a source archive of the baseline SHA;
it is not a clone of Git history. Proposed GitHub commits must use the verified
baseline main SHA as parent and be reviewed in a PR. Never force-push or merge
without authorization.

## Latest verification — 2026-10-04

- Earlier unsynchronized local checkout: 329 run, 326 passed, 3 skipped, 0 failures. The previous attribution to merged PR #52 is withdrawn; that revision failed compilation.
- The pinned OpenCTI submodule is at `55ca0dfa4129050cb607fdaf6b1a7457e0ae3476`, matching the superproject gitlink. Its 15 deeply nested files are present from the pinned blobs; sampled file hashes match. Focused OpenCTI tests passed 7/7. Windows Git status still cannot enumerate these long paths and may display false deletions; no gitlink change is intended.
- Overall maturity remains unscored and below any defensible 8/10 claim. Production-qualified sources remain 0; representative identity, lineage, contradiction, live-source, hosted deployment and other acceptance gates remain open.
