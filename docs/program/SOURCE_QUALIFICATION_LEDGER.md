# Source qualification ledger

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


## ER-EVAL-002 intake implementation and EPSS development evidence — 2026-10-05

Implemented `resolve evaluate` over exact case-preserved corpus/protocol hashes.
Authorization, same-case authority/privacy/label-review artifacts, custody integrity,
2 MiB limits, strict schemas, supported public fields and protocol-before-corpus
capture order are enforced. Reports contain aggregate metrics/denominators and
are preserved as evidence. Null denominators fail thresholds. Passing a diagnostic
never grants enterprise qualification; local capture order does not prove
independent preregistration, reviewer identity or representative sampling.

Focused ER tests: 21/21. Full suite: 392 run, 389 passed, 3 skipped, zero failures
(105.961s); compilation and secret scan passed. No ranker weights were changed.
Representative data quality remains externally dependent on approved adjudicated
records. Input/output contract: `docs/ENTITY_RESOLUTION_EVALUATION.md`.

Also ran the public EPSS connector for CVE-2021-44228 through canonical authority,
plan, digest approval, live capture, graph/claim draft and offline replay. One
real request, two observations, cache miss, no source errors. Replay with socket
connections blocked passes with zero calls. This is local development evidence,
not production-like staging or live qualification. Zero sources promoted.
Summary: `docs/verification/epss-development-canary-2026-10-05.json`; raw artifacts
stay outside the repository in the private development workspace.

Prior evidence repair PR #58 head f434cd7 passed CI 37263783083 and CodeQL
37263783047; final full suite 378 run/375 passed/3 skipped. Separate AI findings
review failed and is not counted as completed review.

Next priorities: qualified monotonic anchoring; prevent engineering checklist
scores from masquerading as Enterprise 8/10; expand measured public-source
canaries and failure handling; semantic planning gaps; representative reviewed
corpora and named staging environment. The full master objective stays OPEN.
