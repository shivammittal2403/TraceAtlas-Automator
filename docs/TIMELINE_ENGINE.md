# Timeline semantics

Pipeline timeline entries carry observed_at/valid_to, retrieved_at,
observation/evidence/source IDs, statement and verification status. Sorting is
stable by valid time and observation ID. Captured source history is replayed,
never silently replaced by today's response.

Conflicts require same subject and registered single-valued predicate with
overlapping validity. DNS answers are set-valued. Records with no end time are
explicitly open-ended. A changed historical country outside the earlier validity
interval is not disputed merely because the value changed. Timestamp authenticity
and semantic freshness still require source review.
