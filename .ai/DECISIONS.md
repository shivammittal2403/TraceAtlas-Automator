# Program decisions

| Date | Decision | Reason / consequence |
|---|---|---|
| 2026-10-04 | Continue from `codex/source-maturity-taxonomy`; local and GitHub branch trees match, but the SHAs differ. | Preserve the user's pushed work; verify ancestry/ref before the next push. |
| 2026-10-04 | Start with a synthetic entity-resolution benchmark, not a new social connector. | False-merge risk is critical and unmeasured; a provider integration cannot be qualified without terms, entitlement and runtime proof. |
| 2026-10-04 | Leave matching weights/thresholds unchanged during benchmark implementation. | Prevent tuning against a small synthetic suite and keep the benchmark diagnostic rather than a performance claim. |
| 2026-10-04 | Report false-merge rate as undefined when no automatic merge is attempted. | Zero merges means the metric denominator is zero; reporting 0% would imply evidence that does not exist. |
| 2026-10-04 | Keep Enterprise score uncalculated until category scoring is evidence-backed. | Implementation volume and fixture counts do not establish an 8/10 production capability. |
| 2026-10-04 | Do not infer source independence from hostname equality alone. | Shared hosting and CDN domains may contain separate tenants; explicit reviewed ownership is required to group distinct pages from one publisher. |
| 2026-10-04 | Keep temporal contradiction predicate shared between production pipeline and synthetic evaluator. | The diagnostic must exercise the same subject/predicate/value/time-overlap rule; representative real-world contradiction recall remains open. |
# Engineering decisions

## D-001 — Keep scope governed

Use only analyst-provided evidence and explicitly authorized public research.
Do not add account actions, autonomous contact, auth bypass, credential
harvesting, exploitation, malware execution, publication or intrusive scanning.

## D-002 — Preserve existing authorities

The source registry supplies maturity metadata; FabricStore owns persisted
qualification reviews/promotions; EvidenceStore owns case evidence and integrity.
Do not persist qualification proposals as trusted state without artifact checks.

## D-003 — One maturity vocabulary

`src/traceatlas/source_maturity.py` is canonical for lifecycle labels and gates.
Legacy spellings normalize at read/serialization boundaries. Fixture or
configured-source success never counts as live verification.

## D-004 — Level score requires measured evidence

Do not produce numeric category or overall scores until repeatable evaluation
results and a documented rubric exist. Missing measurements are UNKNOWN, not 0
or assumed passing.

## D-005 — PRs are the review boundary

Implementation changes target a new branch and reviewable PR. Never merge into
main from this autonomous engineering loop.
