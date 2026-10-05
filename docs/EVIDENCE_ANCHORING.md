# Evidence ledger anchoring

## Current implementation

`EvidenceStore` accepts an optional `LedgerAnchor`. When configured with
`require_anchor=True`, new captures are rejected if the existing ledger or its
latest anchor does not verify. A successful capture appends the local hash-chain
entry, publishes the new entry count and head digest, and includes the signed
receipt in evidence exports. Verification of an anchored ZIP requires the
corresponding anchor verifier and rejects bundles without a receipt when
`require_anchor=True`.

The built-in `HmacFileLedgerAnchor` is a portable adapter, not a production
service. Configure it with an anchor directory outside the case workspace and a
`key_resolver` backed by an operator-controlled secret manager. The key is never
written to the ledger, receipt, bundle or repository. Keys must be at least 32
bytes. The adapter rejects a receipt directory inside the workspace, checks
signed receipt fields, and will not advance a checkpoint backwards or replace
a different head at the same sequence.

Example wiring (the key provider is deliberately operator supplied):

```python
anchor = HmacFileLedgerAnchor(
    root=operator_anchor_directory,
    workspace_root=case_workspace,
    key_resolver=operator_key_provider,
    key_id=operator_key_version,
)
store = EvidenceStore(
    case_workspace, db, case_id, anchor=anchor, require_anchor=True,
)
```

For bundle verification, pass the same configured verifier:

```python
EvidenceStore.verify_bundle(bundle_path, anchor=anchor, require_anchor=True)
```

All application `EvidenceStore` call sites can opt in through process
configuration, so collection, report replay and ledger verification share the
same anchor without separate module wiring. Set these variables at process
startup; populate the key through an operator-managed secret provider, never a
checked-in file:

```text
TRACEATLAS_EVIDENCE_ANCHOR_DIR=<absolute directory outside the workspace>
TRACEATLAS_EVIDENCE_ANCHOR_KEY_HEX=<at least 64 hexadecimal characters>
TRACEATLAS_EVIDENCE_ANCHOR_KEY_ID=<operator key version>
TRACEATLAS_EVIDENCE_ANCHOR_REQUIRED=1
```

Setting the anchor directory requires anchoring for every configured workspace.
The CLI's `evidence-verify` command loads the same verifier configuration. If
required configuration is incomplete or the path is inside the workspace,
initialization fails closed. Keep the anchor directory protected separately
from case data; environment delivery and access controls are operator duties.

Existing cases do not become anchored automatically. After comparing the
existing custody history and evidence to a separately trusted record, an
operator can explicitly call `store.bootstrap_anchor_after_review(review_id)`.
This appends an `anchor_bootstrap` custody event containing the review reference
before publishing the first receipt. The method verifies local consistency but
cannot determine whether the pre-existing history was already rewritten; the
review reference must identify the actual human change-control record.

## Trust boundary and remaining work

The synthetic benchmark demonstrates that the ordinary unanchored compatibility
path accepts a fully re-written local database, evidence file and ledger. The
opt-in HMAC mode rejects that mutation when the signing key and checkpoint
receipt remain outside the attacker's control. This is a local fixture result,
not an operational key-manager integration or deployment result.

The file adapter does not provide an append-only remote log or rollback-safe
freshness. An attacker who can restore an older valid receipt together with the
matching older workspace state may roll the local view back. A production
`LedgerAnchor` implementation must obtain signatures from an operator-controlled
key service and store checkpoints in a monotonic or object-locked external
system; it must expose the latest checkpoint to `verify`. Key rotation,
concurrent writers, backup/restore and failure recovery need provider-specific
acceptance tests.

The HMAC proves that the configured key signed a case identifier and ledger
head. It does not prove who published the underlying source, that a cited item
semantically supports a claim, or that the source assertion is true. Citation
quality still requires representative human-labeled evaluation. EVIDENCE-001
therefore remains OPEN.



## Bundle v2 and reset protection (2026-10-05)

New exports use `traceatlas-evidence-export/v2` and include `ledger.jsonl`.
Verification replays every custody hash, checks its final head and entry count,
compares ordered observation metadata, and requires exact equality between the
preserved digests and bundled files. Only then is the head checked against the
anchor receipt. A rewritten payload/manifest checksum cannot reuse the original
signed head. Original custody paths appear in the bundle as hashed provenance;
the verifier never opens these paths. Review that metadata before sharing.

V1 unanchored bundles remain readable as legacy checksum-only artifacts. V1
bundles claiming an anchor are rejected because they lack the custody records
needed to bind their payload to that receipt. Re-export from the verified
original case to obtain v2; changing only the schema label is insufficient.

An absent ledger and empty local evidence index count as a new case only when
the configured external anchor confirms no prior checkpoint. An anchor outage
or surviving checkpoint causes verification and new capture to fail closed.

A valid older v2 bundle is a historical snapshot, not proof of current state.
Live case verification checks the latest external receipt. Rolling back both
the workspace and the external HMAC receipt remains outside this adapter's
protection and still requires independent monotonic storage.
