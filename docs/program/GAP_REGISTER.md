# Enterprise transformation gap register

Updated: 2026-10-04. Gaps remain open until their acceptance criteria pass.

| ID | Title / domain | Severity | Current state and root cause | Impact | Dependencies | Acceptance criteria / metric | Status |
|---|---|---|---|---|---|---|---|
| ER-BENCH-001 | Synthetic ER evaluation harness | P0 | Previously there was no reproducible ranking metric; added a six-query synthetic company-label set and evaluator. | Makes ranker behavior inspectable but does not estimate deployed identity quality. | None for synthetic diagnostics. | Deterministic 24-pair report; confusion metrics, top-k ranking recall, malformed-label and sensitive-field tests; no automatic merges; limitations disclosed. | COMPLETE: precision 0.80, recall 1.00, F1 0.889, FPR 0.05; one synthetic false-positive candidate. |
| ER-QUALITY-001 | Operational identity quality | P0 | No authorized representative adjudicated dataset; synthetic results cannot establish field accuracy. A same-name synthetic candidate with identifier differences scored 0.7258. | False identity links can harm investigations and subjects; candidate review can be noisy. | Legal/privacy owner, approved cases, adjudication protocol. | Pre-registered thresholds; representative set including collisions and ambiguous cases; measured false merge/split rate with confidence interval. | OPEN / data unavailable; zero auto-merges makes false-merge rate undefined. |
| SRC-PROD-001 | Production source qualification | P0 | 25 coded adapters, zero production-qualified. Terms, entitlements and sustained intended-runtime evidence absent. | No defensible service-level or source coverage claim. | Provider approvals/credentials, source owner, deployed canary. | At least target workflow coverage equivalent to 50 qualified sources; every claimed source passes its evidence gates. | OPEN |
| EVIDENCE-001 | Evidence integrity/citation acceptance | P0 | Added opt-in `LedgerAnchor`, HMAC receipt adapter and environment wiring. 14 synthetic cases match 13/14 expected outcomes; HMAC mode rejects tested local rewrite when key/receipt are outside the workspace, but legacy unanchored mode still accepts it. No rollback-safe remote anchor or semantic citation proof. | Legacy-default cases can be rewritten inside one local trust boundary; citation membership does not prove claim support. | Monotonic external anchor/immutable store; managed key provider; labeled citations and approved adversarial corpus. | Tamper/citation benchmarks pass with no accepted corrupt state across required modes; rollback, immutable storage and replay acceptance verified. | OPEN / opt-in HMAC mode wired; rollback-safe provider and default-required policy absent |
| LINEAGE-001 | Source independence/contradiction evaluation | P0 | 12 synthetic source pairs pass after hostname-only grouping was removed. Added eight labeled pairs around the production temporal contradiction rule (3 conflicts, 5 non-conflicts; all correct). Representative syndication and contradiction recall remain unknown. | Duplicate sources may be overcounted or conflicts missed; conservative host handling can miss common publishers without reviewed ownership metadata. | Curated labeled corpus, source provenance, reviewed publisher ownership. | Predefined pairwise precision/recall thresholds and adversarial duplicate/temporal/contradiction cases pass on approved representative records. | PARTIAL / synthetic diagnostics pass; representative gate OPEN |
| TENANT-001 | Hosted tenant and worker isolation | P0 | RLS/worker contracts exist but no live tenant/Auth/staging test. | Cross-case/tenant leakage cannot be excluded in production. | Disposable staging project and operator credentials. | Cross-tenant read/write, IDOR, evidence/cache/report/AI-context leakage tests all fail closed. | BLOCKED on staging |
| OPS-001 | Production operations and recovery | P0 | No production-like deployment evidence, distributed quota or restore drill in this session. | Availability, budget, cancellation and recovery behavior unknown. | Operator infra, monitoring and backup services. | Deployment, SLO/alert, backup/restore, load and incident runbook gates pass. | BLOCKED on infrastructure |
| SOCMINT-001 | Lawful public social workflows | P1 | No demonstrated multi-family canonical public-social workflow. | Primary program scope cannot yet claim SOCMINT maturity. | Terms, APIs, privacy review, source contracts. | Two or more permitted source families with evidence/replay and collision evaluation; no access-control bypass. | OPEN |
| LANG-IN-001 | Hindi/Romanized Hindi and India country pack | P1 | No validated transliteration/query lineage and operational India pack. | Reduced recall and country-specific workflow utility. | Official source research, allowed-use review, labeled corpus. | Original/native/transliterated queries preserved; official sources tested; no translation replaces original evidence. | OPEN |
| GOLDEN-001 | Representative end-to-end evaluation | P1 | Existing 12 controlled cases are synthetic/fixtures. | Fixture success does not predict investigator outcomes. | Approved realistic dataset and reviewers. | 100+ realistic controlled cases plus adversarial cases; autonomous defensible rate and hard quality metrics reported. | OPEN |

## Closure rule

Keep historical findings. Update status, evidence, test result, metric and commit
in the implementation/evaluation ledgers; do not close a gap when only code or
fixtures exist.

## Exact-snapshot merge repair — 2026-10-04

REGISTRY-MERGE-002 (P0): exact main 9d025c compilation failures repaired; 26-gate requirements and same-case review validation preserved. Local 354-test suite passes; hosted repair verification pending.


## Verified merge repair follow-up — 2026-10-05

PR #56 was merged as `5ad16f01d4e3916dc6f40591c8fcbef2c14c88b8`. Its tree
`ed5a421db97250eadea5e32910c299b871035ac7` equals the downloaded `03fdfd84`
snapshot. A subsequent merge had reintroduced duplicate registry gate definitions,
a malformed conditional and duplicate test fragments. The follow-up changes only
`src/traceatlas/workforce/source_registry.py` and `tests/test_source_fabric.py`
in executable code. Durable workforce runtime and all 26 qualification gates remain.
Negative tests retain unresolved terms, unresolved operational-owner evidence and
stale-state promotion checks.

Full local suite: **372 run, 369 passed, 3 skipped, zero failures** (88.957 seconds).
Compilation of src/tests/api/scripts/vercel_control.py passes; secret scan is clean.
Exact baseline, changed Git blob hashes and test-output hash are recorded in
`docs/verification/source-qualification-followup-2026-10-05.json`.
Earlier 329-test attribution to merged code remains withdrawn. The previous
synthetic benchmark record remains 12 lineage pairs (TP7/FP0/TN5/FN0) and 8
temporal pairs (TP3/FP0/TN5/FN0); these are not field-accuracy measurements.
Hosted checks are pending publication of this follow-up. Enterprise 8/10,
representative evaluation and live-source qualification remain open.
