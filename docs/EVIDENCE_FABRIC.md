# Evidence fabric ownership

`EvidenceStore` owns captured bytes, SHA-256 metadata and hash-chained
custody. The workforce capture envelope binds task/case/trace/acquisition and the
strict source document. `WorkforceStore.capture_document` indexes acquisition,
source URI, retrieval time, parser/extractor versions, access/retention policy and
classification as EvidenceObject metadata.

Existing v1 evidence imports and metadata version append remain compatible.
Observation acquisition references and evidence case references are checked.
Replay validates actual bytes, stored metadata digest and custody ledger, not
only a syntactically valid hash. Integrity does not prove publisher authorship.
Filesystem capture is not atomic with every downstream SQLite index write;
append-only historical products preserve decisions while current indexes may
change. External ledger anchoring and immutable object storage remain gaps.
