# Active work

## Completed this session: ER-BENCH-001 and ER-SIGNALS-001

- Status: synthetic diagnostic complete; representative identity quality remains OPEN P0.
- Delivered: exact attribute agreement/difference flags; six synthetic company queries and 24 labeled pairs; deterministic evaluator/CLI and saved JSON results; malformed-label, sensitive-field, ranking and denominator tests.
- Measurement: precision 0.80, recall 1.00, F1 0.889, false-positive rate 0.05, recall@1/3 1.00. One namesake candidate was flagged at 0.7258; no merge was attempted.
- Limitation: synthetic data is not representative; the false-merge denominator is zero. Do not use the score as a probability or operational quality estimate.
- Next: ER-EVAL-002 requires an approved privacy-reviewed adjudication set and pre-registered thresholds; it cannot be completed with fabricated or public-person data.

## Current slice: EVIDENCE-004 anchoring path

- Added `src/traceatlas/evidence_anchor.py` with a `LedgerAnchor` contract and an opt-in `HmacFileLedgerAnchor`; `EvidenceStore` can require an external checkpoint, anchor ledger heads, embed receipts in bundles, and verify anchored exports.
- Added `docs/EVIDENCE_ANCHORING.md`, focused tests and expanded the synthetic evaluator from 9 to 14 cases.
- 13/14 expected outcomes match; 8/9 invalid cases reject. The opt-in HMAC adapter blocks the tested full local rewrite while key and receipt stay outside the attacker boundary. The legacy unanchored path still accepts that rewrite, so EVIDENCE-001 stays OPEN and the benchmark status is **FAIL**.
- This file adapter cannot prevent rollback of an old receipt, concurrent writers or operator-key service failures. No key manager, append-only remote service, immutable storage or hosted replay was tested.
- Citation evaluation verifies ID membership only, not semantic support. Next: implement and validate a monotonic remote anchor provider and wire authorized application paths to required anchoring; obtain reviewed citation labels before claiming citation accuracy.

## Session rules

Read `.ai/CURRENT_STATE.md`, `.ai/TASKS.md`, `.ai/KNOWN_ISSUES.md`, and the
active `docs/program/` ledger before extending this slice. Update current state,
tasks, gap register, evaluation results and implementation ledger after changes.



## Current slice: LINEAGE-005 synthetic diagnostic

- Added a deterministic 12-pair synthetic evaluator for source-origin grouping, covering declared upstreams, reviewed ownership, copies, canonical URLs and independent sources sharing one hostname.
- The benchmark exposed that hostname equality could merge separate tenants. Removed hostname-only merging; publisher grouping now requires explicit ownership metadata. Updated the same-publisher regression case to provide reviewed ownership.
- Focused evaluator: 2/2 passed; report: 12/12 expected pair decisions (TP=7, FP=0, TN=5, FN=0; precision/recall/specificity/F1 all 1.0 on this synthetic set). Pipeline tests 28 run, 27 pass, 1 skip; AI workforce tests 13/13; diff check passes.
- Full Python suite: 328 run; 321 passed, 3 skipped, 4 failed (3 known OpenCTI checkout failures plus one Windows loopback-console connection abort). Isolated console rerun passed 2/2; the failure did not reproduce in isolation, root cause remains unknown.
- LINEAGE-005 remains OPEN: synthetic pairs do not establish representative lineage accuracy or contradiction recall. Next: prepare an approved route for curated labels and investigate the non-reproducing full-suite console failure if it recurs.
