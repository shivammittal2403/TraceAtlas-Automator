# Entity resolution state

Existing `ResolutionService` provides explainable public-record candidates
and immutable analyst accept/reject decisions. It never automatically merges.
The new pipeline preserves case-local seed IDs, marks person/company candidates
POSSIBLE_MATCH and reports identifier conflicts; it does not call a namesake an
established shared identity.

Each compared field now records whether its normalized values exactly agree.
Candidate output also separates exact-agreement and differing field names so an
analyst can see a same-name collision such as `name` agreement alongside
organization/domain disagreement. These are comparison signals, not proof that
two records represent distinct entities or the same entity. The score and
classification thresholds are unchanged, and every candidate still requires
human review.

Calibrated probabilistic matching, canonical merge/split transactions and
reversible graph histories remain PARTIAL/MISSING. G10 verifies no automatic
merge during conflicting synthetic identifier handling, not population-level
entity-resolution precision. Run `python scripts/evaluate_entity_resolution.py`
for the deterministic synthetic company-label diagnostic suite. Its threshold
is the existing `possible_candidate` boundary, not a tuned probability. The
2026-10-04 run recorded 4 true positives, 1 false-positive candidate, 19 true
negatives and no false negatives across 24 pairs. All four expected candidates
ranked first. The false-positive namesake scored 0.7258 with differing
organization/domain/username/location fields. It was not merged. The dataset is
synthetic and does not estimate operational accuracy; false-merge rate remains
undefined because automatic merges attempted = 0. See
[`docs/verification/entity-resolution-synthetic-2026-10-04.json`](verification/entity-resolution-synthetic-2026-10-04.json)
and [`docs/program/GAP_REGISTER.md`](program/GAP_REGISTER.md).
