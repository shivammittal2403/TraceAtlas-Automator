# Source qualification ledger

## Qualification receipt and merge repair — 2026-10-05

Current checked base: `f30ba40a6dd51978c2072391081b8d159c16014a`; branch `codex/qualification-receipts-20261005`; version `1.11.0`.
CODED and locally TESTED: typed source/check/case/actor/runtime review receipts,
supporting-artifact and custody resolution, expiry/code binding, captured dispatch
code/runtime identity, cache partitioning, failed-review supersession and explicit
promotion bound to the exact receipt set. Unrelated artifact acceptance: 26/26
before, 0/26 after; synthetic false production promotion now rejects.

Current main integration had three registry copies, three shadowing source-test
classes and overlapping gateway authority/fetch code. Consolidated them while
preserving every distinct test, shared 26-gate policy, ConnectorFactory, request
revocation/retry/RDAP checks, semantic replay and custody anchoring. Added a
regression that detects duplicate critical definitions and hidden tests.

Actual final local verification: 439 Python run / 436 pass / 3 optional skips;
Node graph/target 25/25; PGlite 1/1; browser fixture flow, compileall, secret scan
and diff checks PASS. Controlled packs: core 12/12, source 78/78, enterprise
112/112 (105 drafts/replays, seven scope rejects). These are synthetic contracts,
not representative field accuracy. No live source/model request or source
promotion; 0 live-verified / 0 production-qualified in this clean audit workspace.
51 registered metadata sources / 37 coded shared API adapters; neither is a
qualified integration count. Enterprise category/weighted scores NOT ESTABLISHED.
Hosted CI/CodeQL on this proposed branch are a separate pending gate.

The full employee/platform objective remains active. Next: raw-to-normalized
replay; independently governed reviewers/source-specific assertions; IAM and
retention; representative ER/SOCMINT/multilingual evaluation; official India
source research and qualification. Staging, entitlements, approved expert labels
and independent security review need actual operator inputs. Other engineering
is OPEN, not bulk-blocked. See `docs/SOURCE_REVIEW_RECEIPTS.md`,
`docs/program/SESSION_REPORT_2026-10-05_RECEIPTS.md` and the hash-bound receipt
`docs/verification/source-review-receipts-2026-10-05.json`.

Earlier checkpoints below are historical and do not certify the current tree.

Updated: 2026-10-04. This ledger counts source maturity, not catalog volume.

| State | Count | Interpretation |
|---|---:|---|
| Coded canonical approval-driven adapters | 25 | Code exists in the canonical workforce. |
| Production-qualified sources | 0 | None has complete current terms, entitlement and intended-runtime evidence. |
| Live source qualifications added this session | 0 | No credentialed or direct live source was exercised. |
| Discovered/candidate catalog | 400 input entries; 351 deduplicated research rows in prior audit | Discovery metadata; not execution-ready sources. |

The 23 evidence gates and state transitions are defined in
[`docs/SOURCE_MATURITY.md`](../SOURCE_MATURITY.md). Per-source records remain in
[`docs/sources/SOURCE_AUDIT_MATRIX.csv`](../sources/SOURCE_AUDIT_MATRIX.csv) and
the source implementation/delivery ledger. Do not infer qualification from a
connector, fixture, configured key, injected response or historical proxy
reference response. Review each source's current terms, licence/access, owner,
runtime credentials, real request, parser, normalized output, captured evidence,
offline replay, costs, rate limits, timeouts, failures, schema drift, canary,
health and runbook before advancing its state.

Targets from the program brief: 25 / 50 / 100+ qualified sources. Current state
is zero; milestone A is not met.
Qualification is source- and runtime-specific. Keep registered metadata,
connector code, configuration, live test, live verification and production
qualification in separate counts.

| Metric | Baseline | Evidence | Rule |
|---|---:|---|---|
| Canonical workforce adapters | 26 | `docs/CURRENT_STATE.md` | Coded does not mean live |
| Production-qualified sources | 0 | `docs/CURRENT_STATE.md` | Remain zero until every qualification gate and runtime receipt passes |
| Qualification gates | 23 | `src/traceatlas/source_maturity.py` | Shared policy; each attestation must resolve to authorized immutable evidence |
| Live canaries in this repair | 0 | No live source request made | Never count fixture tests as live |

No credentials or source entitlements were supplied for this task. Resolve
evidence references against EvidenceStore and authorization before allowing
promotion; receipt text alone is not evidence. The local TA-003 change now
checks same-case hash membership while calculating promotion state and again
at promotion, with ledger integrity rechecked. PR #50 passed CI `37185114010`
and CodeQL `37185114003`.


## EVIDENCE-005: bundle binding and erased-history rejection — 2026-10-05

Baseline: PR #57 `46cdafdfb3264117edafa2f6df6a38b3f855182b`; its CI and
CodeQL passed. New master objective read from the 2026-10-05 attachment;
source-volume targets are targets only.

Three reproduced P0 integrity gaps: payload and provenance could be rewritten
in an anchored export while reusing its signed head; deleting both local ledger
and index bypassed the external checkpoint check. Bundle v2 now replays the
custody chain and binds exact digests/observations to the signed head. Empty
local histories consult the external anchor and fail closed on outage. Legacy
unanchored v1 is readable; anchored v1 requires re-export.

Expanded identical 18-case synthetic corpus: baseline 14/18, repair 17/18.
Invalid-case rejection improves from 9/13 to 12/13. The unanchored full-rewrite
case still fails, intentionally disclosed; EVIDENCE-001 remains OPEN. Full
suite before two additional compatibility tests: 376 run, 373 pass, 3 skip;
compilation and secret scan pass. Final exact-head hosted checks are separate.
Report: `docs/verification/evidence-integrity-2026-10-05.json`.

Remaining external dependencies: independently protected monotonic anchor,
operator-owned staging, source credentials/terms, representative reviewed labels.
No live source was contacted and no source was promoted. Overall 8/10 remains
NOT ESTABLISHED. Continue next with governed representative-evaluation intake
and metric denominators, rather than claiming fixture performance as field quality.
