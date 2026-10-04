# Program changelog

## 2026-10-04 — Temporal contradiction diagnostic

- Extracted registered single-value, same-subject, differing-value, overlapping-valid-time logic into `workforce/contradictions.py` and reused it from the investigation pipeline.
- Added eight synthetic temporal conflict/non-conflict pairs to the source lineage report: TP=3, FP=0, TN=5, FN=0. This is a unit-level diagnostic, not representative recall.
- Focused evaluator tests pass 3/3; pipeline tests pass 27 with 1 skipped; full suite runs 329 with 323 passing, 3 skipped and 3 OpenCTI submodule failures.


## 2026-10-04 — Source independence diagnostic

- Added a 12-pair synthetic source grouping benchmark and JSON report. The initial hostname heuristic caused a false merge for separate tenants sharing one host.
- Removed hostname equality as an automatic grouping signal. Explicit reviewed ownership metadata still groups separate records from one publisher.
- Focused evaluator: 2/2 pass; synthetic pair metrics: TP=7, FP=0, TN=5, FN=0 (precision/recall/specificity/F1=1.0). Pipeline tests 27 pass/1 skip; AI workforce 13/13. Full suite 328 run: 321 pass, 3 skip, 4 fail (three OpenCTI checkout failures and one Windows loopback-console abort). Representative contradiction recall remains open.


## 2026-10-04 — Session baseline

- Read repository engineering guidance, current state, acceptance gates, current completion audit, gap analysis, security review, entity-resolution notes and golden-suite documentation.
- Verified local source-maturity branch tree against its GitHub branch tip; branch is one commit ahead of main at the start of this program.
- Ran 310 Python tests: 304 passed, 3 skipped, and 3 OpenCTI-submodule failures. Ran Node graph/target tests after selecting the bundled Python runtime: 25/25 passed. Python compilation, secret scan and whitespace check passed.
- PGlite database tests are blocked because the pinned package is not installed. No new live source or browser test was performed.
- Selected ER-BENCH-001 as the first program task: quantify current synthetic candidate-ranking behavior without tuning the algorithm or claiming live accuracy.
- Added exact-agreement/differing-field signals to ER comparisons; added a synthetic six-query/24-pair evaluator, CLI, tests and captured result. Observed 0.80 pair precision and one namesake false-positive candidate at score 0.7258; false-merge rate remains undefined because no merge is attempted.
- Installed the pinned JavaScript dev dependencies from the lockfile and verified PGlite 1/1, graph/target 25/25 and the local employee workflow. Visual/hosted browser acceptance remains unverified.

## 2026-10-04 — Evidence integrity diagnostic

- Added a deterministic nine-case evaluator around the actual local EvidenceStore ledger/bundle verifier and AI citation-ID validator, with a CLI, focused tests and saved JSON output.
- Five routine invalid cases were rejected. The synthetic re-anchoring mutation rewrote preserved bytes, the SQLite digest and the local ledger consistently and was accepted. Exact-outcome score: 8/9 (0.8889); invalid-case rejection: 5/6 (0.8333); benchmark status: FAIL.
- Kept EVIDENCE-001 open. The harness establishes a concrete need for an independent trust anchor or immutable store; it does not establish semantic citation correctness, external authorship or deployed replay.
- Focused evaluator tests passed 2/2. Full suite: 319 run, 313 passed, 3 skipped, 3 failed (same OpenCTI prerequisite: source files unavailable and vendor count 72/308). `compileall`, secret scan (clean) and `git diff --check` passed.

## 2026-10-04 — Opt-in evidence ledger anchoring

- Added `LedgerAnchor` and `HmacFileLedgerAnchor`; anchored `EvidenceStore` captures fail closed on invalid/missing checkpoints, and anchored exports carry signed receipts that require the verifier/key provider.
- Added external-path enforcement, HMAC-SHA256 signing from an injected 32-byte-or-stronger key provider, same-sequence conflict/rollback checks, and explicit requirements for `require_anchor=True`.
- Expanded the synthetic benchmark to 14 cases: 13/14 expected outcomes; 8/9 invalid cases rejected. The HMAC mode rejected the tested full local rewrite; unanchored legacy mode still accepts it and drives benchmark status FAIL.
- Focused evidence/anchor/bundle tests passed 16/16. Full suite: 326 run, 320 passed, 3 skipped, 3 failed (same OpenCTI submodule prerequisite; missing source files and vendor count 72/308). `compileall`, secret scan and `git diff --check` pass.
- No production key manager, immutable store or remote monotonic anchor was connected. HMAC-file receipts do not prevent old-receipt rollback; EVIDENCE-001 remains open.

