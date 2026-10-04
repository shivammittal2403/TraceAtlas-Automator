# Program decisions

| Date | Decision | Reason / consequence |
|---|---|---|
| 2026-10-04 | Continue from `codex/source-maturity-taxonomy`; local and GitHub branch trees match, but the SHAs differ. | Preserve the user's pushed work; verify ancestry/ref before the next push. |
| 2026-10-04 | Start with a synthetic entity-resolution benchmark, not a new social connector. | False-merge risk is critical and unmeasured; a provider integration cannot be qualified without terms, entitlement and runtime proof. |
| 2026-10-04 | Leave matching weights/thresholds unchanged during benchmark implementation. | Prevent tuning against a small synthetic suite and keep the benchmark diagnostic rather than a performance claim. |
| 2026-10-04 | Report false-merge rate as undefined when no automatic merge is attempted. | Zero merges means the metric denominator is zero; reporting 0% would imply evidence that does not exist. |
| 2026-10-04 | Keep Enterprise score uncalculated until category scoring is evidence-backed. | Implementation volume and fixture counts do not establish an 8/10 production capability. |
