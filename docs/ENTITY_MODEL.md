# Entity and assertion semantics

Seeds have domain/IP/person/company/CVE/vulnerability/package types and exact registered scope.
Person/company identifiers are local case associations, not global identities.
The graph supports existing node types plus URL/ASN/certificate/hash/malware/
vulnerability/TTP/dataset types; adding a node type does not add its collector.

Structured facts use a closed predicate registry; observations are OBSERVATION,
claims remain CLAIM and verification is a separate field. No new assertion is
silently labeled FACT. Proposed graph edges keep evidence/observation/lineage,
time, uncertainty and proposal state. Identity/causation edges are never created
by this runner.
