# Source qualification review receipts

Source Fabric qualification uses `traceatlas-source-review/v1` receipts. An
unrelated preserved file is no longer sufficient for a review gate. Each review
names its source, case, gate, reviewer, runtime, required check, method, outcome,
implementation digest, review time, expiry and supporting evidence hashes.
The required check identifiers are defined in `source_fabric/review_receipts.py`.

Generate an incomplete form:

```powershell
traceatlas --workspace ./cases source-fabric review-template --source dns --check terms --case qualification-case --actor reviewer --runtime-id staging-eu-1 > review.json
```

Perform the actual check and preserve its supporting documents/test artifacts
using the existing `EvidenceStore.preserve_file` SDK in the same case. Fill the
form with their hashes, a concrete method, timezone-aware `reviewed_at` and
`expires_at`, and the actual outcome (`PASS` or `FAIL`). A form initially has
`UNREVIEWED`, missing times and empty references; it cannot qualify a source.
Then submit the completed form:

```powershell
traceatlas --workspace ./cases source-fabric review --source dns --check terms --case qualification-case --actor reviewer --receipt review.json --authorized
```

Alternatively, `--evidence-hash HASH` submits a receipt already in custody.
Receipt submissions are capped at 64 KiB. A rejected submitted receipt stays
in immutable custody; it creates no successful review. Preserve supporting
evidence before submitting. Secrets and personal evidence belong in approved
case storage, never the repository.

Receipts require 1–32 distinct same-case supporting SHA-256 hashes. Their
validity cannot exceed 30 days. Every state projection, portfolio qualification
and promotion rechecks the receipt, support bytes, case ledger, expiry and
implementation. Latest reviews supersede prior reviews for that source/check;
failure, corruption or expiry cannot fall back to an older pass. A typed `FAIL`
can revoke an earlier check without requiring a successful provider response.

Passing `live_request`, `canary` and `intended_runtime` checks additionally name
an execution completed no more than seven days before review. It must be live,
uncached, successful, without drift, and have at least one request attempt.
Its provider metadata must identify the source and non-fixture mode, and bind
the raw response digest and size to preserved supporting bytes. The code digest
and runtime label must match those recorded at dispatch. Collection refuses
to promote evidence if code or runtime changes while the request is running.
Caches are also partitioned by code digest and runtime label.

Set `TRACEATLAS_RUNTIME_ID` to the operator's environment identifier before
collection. Without it, a local OS/Python label is recorded. This is an operator
label, not independent verification of deployment or jurisdiction. All required
reviews must describe one runtime; cross-runtime passes cannot be combined.
Shared execution/security code changes invalidate old receipts conservatively.

`LIVE_VERIFIED` needs all 24 live gates. `PRODUCTION_QUALIFIED` additionally needs
operational owner and runbook, plus explicit analyst promotion. Promotion binds
the exact receipt set and runtime. Replacing a receipt requires fresh promotion.
Legacy review rows and promotions remain in history but receive no qualification
credit until replaced by valid typed receipts and an explicit promotion.

The local CLI assumes a trusted authorized operator. Receipt structure does
not authenticate a reviewer, establish legal entitlement, prove sustained
availability, or determine whether the supporting material truthfully proves a
check. A malicious operator who fabricates receipts and rewrites the local
database can still lie. Independent identities, reviewed source-specific
criteria, managed signing/anchoring and intended-runtime evaluation remain
enterprise gates. Privacy-withheld raw responses cannot pass these runtime
receipt gates until a separately evaluated safe normalization proof exists.
The workforce registry's `persisted=False` maturity proposals are planning
helpers, not resolved runtime qualification.

All new positive tests use synthetic receipts and rows. They validate contracts;
they make no live-source or production-qualification claim.
