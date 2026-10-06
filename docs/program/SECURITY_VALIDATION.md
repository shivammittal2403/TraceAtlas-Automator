# Security validation ledger

## Receipt/custody integration repair — 2026-10-06

Base: `5dda70b6b95741227dfc55f51fe1b63fee6c1398`; branch
`codex/qualification-custody-integration-20261006`. PR #65 was integrated and
merged externally as `5dda70b`; its CI failed with a concatenated gateway module
and malformed store promotion branch. Its CodeQL pass does not establish runtime health.

The combined repair retains typed 26-gate receipts, code/runtime/cache binding,
frozen explicit promotion and current canary/review custody revalidation.
Custody is checked once per case within each projection and rechecked on the
next read. Latest invalid/FAIL/expired reviews never fall back to older passes.
Canonical factory, transport revocation, ER evaluation intake and honest maturity
outputs remain. Generic artifacts in custody tests are replaced with typed
synthetic receipts; no actual source is thereby qualified.

Local verification: 479 Python run, 476 pass, three optional skips (238.108s);
Node graph/target/database 26 pass; browser fixture flow, compilation, secret
scan and 214-file Python structure checks PASS. No live provider/model request,
source promotion or deployment by this session. Zero actual LIVE_VERIFIED and
PRODUCTION_QUALIFIED in the clean audit workspace; representative golden cases
0; Enterprise 8/10 score NOT ESTABLISHED. Proposed-head hosted checks are pending.
See `docs/verification/qualification-custody-integration-2026-10-06.json`.

The full employee objective remains active. Next: raw-to-normalized source
replay, governed reviewer IAM, representative evaluation, retention/tenant
isolation and official India source coverage. Earlier records below are
historical and do not certify this tree.

## Qualification receipt and merge repair — 2026-10-05

Current checked base: `f30ba40a6dd51978c2072391081b8d159c16014a`; branch `codex/qualification-receipts-20261005`; version `1.11.0`.
CODED and locally TESTED: typed source/check/case/actor/runtime review receipts,
supporting-artifact and custody resolution, expiry/code binding, captured dispatch
code/runtime identity, cache partitioning, failed-review supersession and explicit
promotion bound to the exact receipt set. Unrelated artifact acceptance: 26/26
before, 0/26 after; synthetic false production promotion now rejects.

Current main integration had three registry copies, three shadowing source-test
classes and overlapping gateway authority/fetch code. Consolidated them while
preserving every distinct test, shared 26-gate policy, ConnectorFactory, request
revocation/retry/RDAP checks, semantic replay and custody anchoring. Added a
regression that detects duplicate critical definitions and hidden tests.

Actual final local verification: 439 Python run / 436 pass / 3 optional skips;
Node graph/target 25/25; PGlite 1/1; browser fixture flow, compileall, secret scan
and diff checks PASS. Controlled packs: core 12/12, source 78/78, enterprise
112/112 (105 drafts/replays, seven scope rejects). These are synthetic contracts,
not representative field accuracy. No live source/model request or source
promotion; 0 live-verified / 0 production-qualified in this clean audit workspace.
51 registered metadata sources / 37 coded shared API adapters; neither is a
qualified integration count. Enterprise category/weighted scores NOT ESTABLISHED.
Hosted CI/CodeQL on this proposed branch are a separate pending gate.

The full employee/platform objective remains active. Next: raw-to-normalized
replay; independently governed reviewers/source-specific assertions; IAM and
retention; representative ER/SOCMINT/multilingual evaluation; official India
source research and qualification. Staging, entitlements, approved expert labels
and independent security review need actual operator inputs. Other engineering
is OPEN, not bulk-blocked. See `docs/SOURCE_REVIEW_RECEIPTS.md`,
`docs/program/SESSION_REPORT_2026-10-05_RECEIPTS.md` and the hash-bound receipt
`docs/verification/source-review-receipts-2026-10-05.json`.

Earlier checkpoints below are historical and do not certify the current tree.

## Semantic employee integration — 2026-10-05

Base: `5ad16f01d4e3916dc6f40591c8fcbef2c14c88b8`; branch:
`codex/semantic-employee-integration`. This integration preserves the latest
source portfolio, 26-gate qualification policy, external HMAC anchor option,
entity/lineage/contradiction diagnostics and durable workforce execution.

CODED: captured provider/structured fact recomputation; normalized-record
employee semantic replay; request-level Fabric revocation and kill checks;
evidence-linked knowledge states and human review priorities; bounded console
framing; idempotent evidence import; 112 synthetic investigation contracts.
Durable leases, cumulative reservations, immutable capture recovery and atomic
completion/outbox are preserved, with semantic replay applied to recovery.

Merged registry/test fragments are repaired without weakening source authority.
TESTED locally: Python 388 run / 385 passed / 3 skipped (173.397 seconds);
112/112 contracts, 105 draft replays and seven pre-capture scope rejects;
Node graph/PGlite 26/26, browser flow, compilation and secret scan PASS. Proposed-head CI/CodeQL
remain a separate required gate. See
`docs/program/SESSION_REPORT_2026-10-04.md` and `docs/REPLAY.md`.

No live provider/model request, source promotion, main merge or deployment was
performed. Production-qualified sources: 0. Enterprise score: NOT ESTABLISHED.
Remaining engineering is OPEN: receipt semantics, raw-to-redacted replay,
representative identity/SOCMINT/multilingual coverage, IAM/retention, distributed
quotas and observability. Source rights/entitlements, authorized expert labels,
independent security review and staging access require actual operator inputs.
The unanchored full-local-rewrite weakness remains open; optional file HMAC
anchoring is not an independently operated, rollback-safe anchor.

Historical checkpoints below retain their original scope and limitations.



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
PR #50 head `d9c7965e98ba3e26e123fe33c266c97be7b591b8` passed hosted CI
`37185114010` and CodeQL `37185114003`.

No live sources, subjects, accounts, external actions or hosted services were
used for this repair. Local secret scanning and final diff review passed. PR #49
code/test head `1767708adc27e9dc05e0384a4682571e3797d6c4` passed CI
`37184302223` and CodeQL `37184302217`. Independent security review,
source-reference resolution, deployment, and tenant isolation remain open.


## 2026-10-05

Evidence bundle v2 tamper/reset regressions passed (PR #58, CI/CodeQL green).
ER corpus intake adds 14 focused authorization, cross-case, hash, bounds, schema,
ordering, CLI and metric tests; all pass. No real individual records were used.
The EPSS canary read public CVE metadata only and offline replay made zero socket
calls. Hosted IAM/tenant and independent security review remain unverified.
