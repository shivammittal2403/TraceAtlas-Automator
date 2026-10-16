# Canonical competing hypotheses and falsification review

New investigation tasks bind `evidence-investigation/1.5.0` before approval.
The pipeline compares preserved, deterministically grounded source assertions
with the existing single-value predicate and inclusive temporal-overlap rules.
Instruction-like source content is preserved as a gap and excluded from candidate
generation. A lone assertion, agreeing assertions, historical changes and multiple
DNS addresses do not cause invented competing explanations.

Every incompatible assertion pair produces two unverified candidates for its
exact overlapping interval. Each has supporting and contrary observation/evidence
IDs, reported lineage groups and candidate-specific falsification criteria.
An authenticated primary record showing a different exclusive value during that
overlap would challenge the candidate. Existing contrary source assertions are
cited as counterassertions, not declared verified falsifications. Proposed checks
remain pending human review and grant no source/tool authority. No probability,
attribution or verified independence is inferred.

The review is stored in `analysis.hypothesis_review` and projected into the
existing strict `ResultEnvelope.hypotheses` contract. The rendered draft shows
both sides, interval, evidence and pending checks. Source text is rendered as
literal text in the new report format. At most 50 pair comparisons / 100 candidate
entries are returned; total and omitted counts plus a review gap disclose the
bound. Pair candidates are not a count of unique real-world explanations and
are not ranked by how often copied records appear.

## Native discipline review

`HYPOTHESISINT` and `FALSIFICATIONINT` canonical runs write
`traceatlas-discipline-product/v2`. The task binds this review schema and the
native/runtime/review source identity before approval. Projection independently
recomputes the existing native processor from the preserved input; callback
artifacts cannot establish canonical hypotheses or alter review scores.

HYPOTHESISINT retains its existing per-asserted-origin weighting and sensitivity
logic, now with accepted record/source/origin/stance provenance. These origins
remain supplied assertions. Canonical propositions cite the single captured
input artifact; record pointers identify their locations inside that artifact.
The 100-proposition bound and overlong/invalid statements produce explicit
omissions rather than truncating a proposition into a different claim.

FALSIFICATIONINT retains passing records, counterexamples, missing values and
declared-scope limitations from its existing allowlisted tests. A standalone
protocol supplies a hypothesis ID without a required proposition: its review
does not invent a canonical proposition. Existing native truth/coverage caveats
remain visible.

Other discipline outputs retain their v1 shape. Unexecuted discipline approvals
from an older runtime must be replanned when their source identity differs.
Completed runs retain idempotent stored output.

## Offline verification and compatibility

`traceatlas-employees --workspace PATH replay --task TASK` verifies custody,
preserved input, canonical acquisition and task/product/result bindings without
source/model calls or enabling execution. For v2 it recomputes and compares the
review, canonical propositions and provenance. The receipt verifies the
canonical review only; arbitrary callback draft prose is not semantically
certified. Legacy v1 discipline products receive integrity-only receipts with
`semantic_recomputed=false`.

Pipeline replay explicitly supports recorded 1.4.0 and 1.5.0 semantics. Tasks
created by the old runtime lack the new version constraint and retain 1.4.0
analysis/report bytes. New tasks cannot downgrade to 1.4.0 by rewriting a mutable
manifest. New replay derives semantic result fields from captured inputs and
compares both canonical and product result copies; matching rewritten hashes
alone are insufficient. Report scope and authority bind the registered task.

CI produces a real legacy case using pinned commit
`b8fe5e3d94ab797c9fac3630447def09c1f74503`, then opens the same database,
evidence and original report expectation with the new runtime. This compatibility
check runs in separate processes on Windows/Linux Python 3.10/3.12. Pure-kernel,
canonical lifecycle, CLI, adversarial replay and full regression gates also run.

No local tests ran while the Windows sandbox was unavailable. Hosted checks are
pending at commit creation; the exact PR head's checks provide final evidence.
This implementation does not complete exact external 139-catalog reconciliation,
Manager → Team Lead dispatch, live-provider qualification, empirical calibration
or security triage. Source authenticity and factual entailment remain unverified.
