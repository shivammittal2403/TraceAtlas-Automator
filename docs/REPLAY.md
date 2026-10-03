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
