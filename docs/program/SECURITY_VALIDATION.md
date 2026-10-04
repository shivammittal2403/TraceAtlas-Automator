# Security validation ledger

## Invariants

- Analyst-provided evidence or explicitly authorized public research only.
- Imported content is untrusted. Models cannot expand authority or execute
  unapproved tools.
- Keep the service loopback-bound until reviewed authentication, authorization
  and tenant isolation exist.
- No contact, account action, auth bypass, credential collection, exploitation,
  malware, intrusive scan, publication or unsupervised identity merge.
- Preserve fixed-host transport, bounded requests, kill switch, evidence
  immutability, privacy and fail-closed behavior.

## This repair

Source maturity evidence references now have syntax/length bounds. This is not
yet independent verification that a reference resolves to an authorized case
artifact. Promotion continues to require FabricStore integrity checks and
analyst authorization; verify all references individually as TA-003.

No live sources, subjects, accounts, external actions or hosted services were
used for this repair. Local secret scanning passed. Final diff review and
GitHub CI/CodeQL remain pending; independent security review, source-reference
resolution, deployment, and tenant isolation remain open acceptance gates.
