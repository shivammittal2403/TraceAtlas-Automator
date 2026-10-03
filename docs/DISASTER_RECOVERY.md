# Recovery and evidence continuity

Use existing `operations restore-drill` to exercise a local SQLite online
backup and restoration. Back up the database and complete evidence directories,
including custody ledgers. Product digests alone cannot recover missing bytes.
After restoration run report/replay and ledger integrity checks before analysis.

Preserve failed/partial acquisitions and previous products. Never erase an
archive to make a replay or migration pass. Full multi-host/object-store recovery,
key restoration, external ledger anchors and measured recovery objectives remain
unverified. A local restore drill is not proof of Supabase cloud recovery.
