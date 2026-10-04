# Active work

## Completed this session: ER-BENCH-001 and ER-SIGNALS-001

- Status: synthetic diagnostic complete; representative identity quality remains OPEN P0.
- Delivered: exact attribute agreement/difference flags; six synthetic company queries and 24 labeled pairs; deterministic evaluator/CLI and saved JSON results; malformed-label, sensitive-field, ranking and denominator tests.
- Measurement: precision 0.80, recall 1.00, F1 0.889, false-positive rate 0.05, recall@1/3 1.00. One namesake candidate was flagged at 0.7258; no merge was attempted.
- Limitation: synthetic data is not representative; the false-merge denominator is zero. Do not use the score as a probability or operational quality estimate.
- Next: ER-EVAL-002 requires an approved privacy-reviewed adjudication set and pre-registered thresholds; it cannot be completed with fabricated or public-person data.

## Current slice: EVIDENCE-004 diagnostic

- Added `src/traceatlas/evidence_evaluation.py`, CLI `scripts/evaluate_evidence_integrity.py`, focused tests and a versioned JSON report.
- Nine synthetic cases cover clean ledger/bundle verification, routine ledger/raw-byte/bundle/citation mutations, and full local rewrite of evidence bytes + SQLite digest + hash chain.
- Observed 8/9 exact outcomes; five routine invalid cases were rejected, while a fully re-anchored local rewrite was accepted. The benchmark is **FAIL**, and EVIDENCE-001 stays OPEN.
- Citation checks prove allowed-ID membership only. The harness does not claim semantic support, authorship, immutable storage, external anchoring or hosted replay.
- Next: design an operator-controlled external anchor/immutable-store contract and test the local verifier against signed or remotely anchored manifests; require approved representative citation labels before claiming citation accuracy.

## Session rules

Read `.ai/CURRENT_STATE.md`, `.ai/TASKS.md`, `.ai/KNOWN_ISSUES.md`, and the
active `docs/program/` ledger before extending this slice. Update current state,
tasks, gap register, evaluation results and implementation ledger after changes.
