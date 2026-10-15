# CRYPTOINT

**Family:** fin_scam  
**State:** offline_adapter; not source-qualified / live-verified.  
**Sensitive:** No special gate beyond case policy

## Task
Interpret evidence supplied by the canonical case system. Never collect autonomously, bypass a policy gate, resolve real identities without verification, or assert a claim as proven.

## Domain-preferred fields
- `chain`
- `tx_hash`
- `block_number`
- `value`

## Input / output
Read a bounded list of source-labelled records using `run(records, authorized=False, case_id='case')`. Output a deterministic, hash-sealed report containing observations, evidence refs, claim candidates, gaps, and contradictions. Escalate to canonical evidence verification before reporting.
