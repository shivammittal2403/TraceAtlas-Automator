# Entity resolution audit

Baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`, 2026-10-04. References: `src/traceatlas/resolution.py`, `docs/ENTITY_RESOLUTION.md`, `docs/ENTITY_MODEL.md` and synthetic workforce/golden tests.

## Capability status

**IMPLEMENTED / TESTED** for explainable, case-local public-record candidate creation and immutable analyst accept/reject decisions. Automatic identity merges are not performed. Conflicting identifiers and namesakes are treated cautiously.

**PARTIAL / NOT ESTABLISHED** for calibrated probabilistic resolution, temporal merge/split history, labeled-population performance and measured false-match rate. Existing G10 synthetic no-merge behavior is a narrow regression, not a precision benchmark.

## Gap and controls

- Candidate score/comparison logic is a triage aid, not identity proof.
- No global person identity should be inferred from a username, shared domain, name or single provider.
- Person/company assertions require cited case evidence; claims and allegations remain separately labeled.
- A reviewer decision records analyst judgment, not proof of identity or wrongdoing.
- Evaluate with consented or appropriately licensed labeled data, stratified namesakes/cross-jurisdiction cases, abstention thresholds, precision/recall and reviewer disagreement. Do not train or publish personal data from this audit.

No change to the entity matching algorithm is included in this PR; graph acceptance trust is fixed separately.
