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
yet proof of truth. FabricStore review additionally requires explicit analyst
authorization and the exact SHA-256 of an artifact preserved in the same case.
Promotion re-verifies case custody and rejects unresolved evidence references,
including legacy/direct-database rows. The focused test covers fabricated,
cross-case, valid, and legacy references. This follow-up is implemented locally;
hosted checks are pending.

No live sources, subjects, accounts, external actions or hosted services were
used for this repair. Local secret scanning and final diff review passed. PR #49
code/test head `1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI
`37184302223` and CodeQL `37184302217`. Independent security review,
source-reference resolution, deployment, and tenant isolation remain open.
