# Entity resolution state

Existing `ResolutionService` provides explainable public-record candidates
and immutable analyst accept/reject decisions. It never automatically merges.
The new pipeline preserves case-local seed IDs, marks person/company candidates
POSSIBLE_MATCH and reports identifier conflicts; it does not call a namesake an
established shared identity.

Calibrated probabilistic matching, canonical merge/split transactions and
reversible graph histories remain PARTIAL/MISSING. G10 verifies no automatic
merge during conflicting synthetic identifier handling, not population-level
entity-resolution precision. Reuse `resolution.py` for the next integration.
