# Offline replay

`workforce replay --task TASK_ID` checks task/result/product and evidence metadata
digests, custody ledger, captured input bytes, case/task/acquisition bindings and
recorded workflow/parser/policy versions. It reconstructs source records and
recomputes substantive observations, claims, decisions, graph/timeline/gaps.
Decision wall-clock time is excluded from analysis digest so equality measures
historical inputs and deterministic decisions. Replay invokes neither provider
nor model and does not renew expired authority or dispatch new work.

Manifest records case/task/trace, envelope digest, workflow/parser/policy/worker
versions, connector versions, source timestamps/outcomes, execution parameters,
model/prompt state, dataset versions and canonical evidence objects. Unconfigured
sources are gaps, not fabricated manifest entries. Future new versions require an
explicit compatible replay adapter; version mismatch fails closed.

Current replay requires the original local workspace paths (or a restored archive
at the same paths). Existing evidence ZIP export provides portable integrity
verification, but relocating/importing an entire workforce product and custody
ledger is not implemented. Keep full database and evidence backups; a Markdown
report or manifest without original captured bytes cannot reproduce analysis.

## Current semantic contracts

New canonical workflow `evidence-investigation/1.5.0` and its explicit legacy
`1.4.0` adapter use normalizer `structured-fact/5`. New task approvals bind the
workflow version; unbound historical tasks retain 1.4.0 semantics. Submitted documents stay unchanged. Input and regenerated
fact digests are separate. Replay re-extracts all provider/structured JSON facts
and compares substantive analysis and rendered draft. Connector, extractor,
source timestamp, case/task/trace and acquisition bindings fail closed.
Unknown historical versions require the original runtime.

Unstructured analyst assertions remain unverified. The normalization contract
can pass while `semantic_normalization_verified` is false;
`unverified_assertion_sources` identifies these inputs. Hashes do not prove truth.

Employee portable export uses `traceatlas.autonomous.replay.v2` and
`employee-analysis/2`. Its offline verifier runs the same extraction, lineage,
verification, knowledge-state and graph rules on preserved normalized records at
the recorded analysis clock. It compares report/graph even when bundle hashes
are rewritten. It performs no database writes, model calls or provider requests.
Execution telemetry and model advisory prose are not semantically replayed.

Raw-to-redacted provider normalization and source authenticity remain
unverified; privacy policy may withhold raw responses. Legacy v1 bundles receive
integrity verification with `semantic_analysis_verified=false`. Exporting an
unsupported historical report fails closed. Preserve custody backups and a
trusted external manifest hash when transporting bundles.

## Competing-hypothesis review

Workflow 1.5.0 recomputes the versioned hypothesis review and canonical semantic
result fields, verifies both stored result copies, and binds report scope and
authority to the task. Removing a review or downgrading a manifest cannot bypass
the approved version constraint. Genuine 1.4.0 compatibility is checked using a
case/report produced by pinned old code, then replayed by the current runtime.
See [COMPETING_HYPOTHESES.md](COMPETING_HYPOTHESES.md).

Discipline `traceatlas-employees replay --task TASK` verifies preserved native
review semantics for v2 HYPOTHESISINT/FALSIFICATIONINT products. Its verification
scope is the canonical review, not arbitrary callback prose. Older v1 discipline
products return explicit integrity-only verification without semantic claims.
