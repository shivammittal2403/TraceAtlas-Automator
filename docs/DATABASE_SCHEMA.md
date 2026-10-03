# Persistence and derived indexes

`CaseDB` owns local SQLite canonical case state. `WorkforceStore` creates
local workforce authority/tasks/approvals/results, acquisitions, evidence
metadata, observations, lineage and verification indexes. `workforce_products`
stores one immutable product JSON/digest per task. Result/product/completed-state
writes share one SQLite transaction. Raw-file/custody capture is earlier and is
not part of a cross-filesystem transaction.

Original evidence bytes remain in the case EvidenceStore. Acquisition-aware
capture adds v2 metadata without changing existing v1 imports. Evidence metadata
and task/result/product digests are checked on replay. Lineage/verification
tables are current derived indexes; historical product snapshots retain decisions.

Hosted schema remains the existing Supabase migrations, including
`20260930115004_ai_workforce_v1.sql`. The new local product table has not been
added to hosted SQL. No hosted migration was executed by this delivery.
