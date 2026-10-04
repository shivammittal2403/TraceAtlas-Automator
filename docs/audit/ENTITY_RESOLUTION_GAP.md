# Entity resolution gap

Baseline: `641f159326d45afe9797ddf5624a5126640fdd19`, 2026-10-04. References: `src/traceatlas/resolution.py`, `docs/ENTITY_RESOLUTION.md`, `docs/ENTITY_MODEL.md`.

## Current state

**IMPLEMENTED / TESTED**: deterministic explainable, case-local public-record candidate proposals and authorized analyst accept/reject records. Identity does not auto-merge. Synthetic tests cover conflicts/namesakes and no automatic merge.

**NOT IMPLEMENTED / NOT ESTABLISHED**: full Entity Resolution V2 pipeline, temporal merge/split history, calibrated probability, labeled representative benchmark, benchmark precision/recall/F1, false merge/split rate, top-K recall or calibration. A score is a candidate-ranking aid, never proof of identity.

## Required V2 controls

Normalize only safe permitted attributes; block candidates with privacy/jurisdiction boundaries; compare exact identifiers, time, location, organization and public link evidence; search for conflicts; expose reasons and abstain on ambiguity. Never merge people on name, username, image, employer or city alone. Every material relationship must cite case evidence. Corrections append a new decision; reversibility must preserve prior evidence and reviewer history.

Benchmark only with consented/licensed, labeled cases stratified for namesakes, shared handles, transliteration, time changes, missing attributes and conflicting IDs. Report precision, recall, F1, false merge/split rate, top-K recall, calibration and reviewer disagreement. Do not claim population performance from synthetic fixtures.
