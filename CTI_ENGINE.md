# Native CTI engine

TraceAtlas 0.9 adds a dependency-free cyber-threat-intelligence pipeline based
on independently implemented, interoperable concepts found during the supplied
repository review. It does not copy AGPL, proprietary, non-commercial or
ShareAlike source code or datasets.

## Implemented workflow

```bash
# Extract observable facts and an entity co-occurrence graph
./start.sh cti extract --case demo-001 --file report.txt --authorized

# Optional operator-authored term → ATT&CK mapping (inferences stay labelled)
./start.sh cti extract --case demo-001 --file report.txt \
  --mapping-file attack-map.json --authorized

# Ingest an approved JSON, JSONL, RSS or Atom export and deduplicate it
./start.sh cti feed-ingest --case demo-001 --file advisories.json \
  --source vendor-advisories --authorized

./start.sh cti trends --case demo-001

# Exchange the result with OpenCTI, MISP or another STIX 2.1 consumer
./start.sh cti export-stix --case demo-001 \
  --graph cases/cti/demo-001/report.graph.json \
  --output reports/report.stix.json --authorized
```

The extractor recognizes IPv4 addresses, domains, URLs, email addresses,
MD5/SHA-1/SHA-256 hashes, CVE identifiers and MITRE ATT&CK technique IDs.
Relationships are recorded only as sentence-level co-occurrence and explicitly
do not claim causality or attribution. Operator mapping matches are stored as
inferences at confidence 50 with mandatory analyst validation.

Feed ingestion limits inputs to 10 MiB and 10,000 records, validates outbound
URLs syntactically, uses CVE-aware deterministic fingerprints, and retains at
most 50,000 normalized records per case. Trend output is descriptive only.

## External interoperability

| Engine family | TraceAtlas boundary |
|---|---|
| OpenCTI / MISP | STIX 2.1 bundles and approved export ingestion |
| IntelOwl | Separately deployed service or sanitized export |
| Watcher / ThreatWatch | Approved feed/export ingestion; no upstream feed lists copied |
| CTINexus / ZettelForge | Native graph plus optional external adapter/export |
| CTI-to-MITRE NLP | Operator-supplied mappings; research dataset/model not bundled |
| SearXNG | Operator-controlled loopback search service or allowlisted MCP |
| ScrapeGraphAI | Loopback `/extract` worker; generated code and sessions blocked |

Acquisition is not implicit. Every import/extraction is attached to an existing
case, requires authorization, preserves a SHA-256 evidence record and keeps
observations separate from analyst/model inferences.
