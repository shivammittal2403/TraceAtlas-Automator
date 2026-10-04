# Source qualification ledger

Qualification is source- and runtime-specific. Keep registered metadata,
connector code, configuration, live test, live verification and production
qualification in separate counts.

| Metric | Baseline | Evidence | Rule |
|---|---:|---|---|
| Canonical workforce adapters | 26 | `docs/CURRENT_STATE.md` | Coded does not mean live |
| Production-qualified sources | 0 | `docs/CURRENT_STATE.md` | Remain zero until every qualification gate and runtime receipt passes |
| Qualification gates | 23 | `src/traceatlas/source_maturity.py` | Shared policy; each attestation must resolve to authorized immutable evidence |
| Live canaries in this repair | 0 | No live source request made | Never count fixture tests as live |

No credentials or source entitlements were supplied for this task. Resolve
evidence references against EvidenceStore and authorization before allowing
promotion; receipt text alone is not evidence.
