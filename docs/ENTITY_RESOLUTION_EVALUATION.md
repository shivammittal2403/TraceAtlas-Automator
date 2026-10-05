# Preserved entity-resolution evaluation

`traceatlas resolve evaluate` evaluates the existing ranker against exact
case-preserved labels. It does not collect data, change ranking weights, merge
entities, authenticate reviewers or qualify an enterprise release.

## Inputs and order

1. The authorized data owner prepares minimized, permitted records and preserves
   authority, privacy-review and label-review artifacts in the evaluation case.
2. Finalize the held-out corpus bytes and calculate their SHA-256.
3. Preserve the protocol JSON below before preserving the corpus itself.
4. Preserve the exact corpus bytes in the same case using `EvidenceStore.preserve_file`.
5. Evaluate using the returned corpus and protocol digests. Configure the
   independent anchor before case capture when required by the deployment.

The local capture order is checked. It does not prove that a reviewer is genuine,
that permission is legally valid, that labels were not seen earlier, or that the
thresholds were independently preregistered. Those require external review.

Corpus schema: `traceatlas-reviewed-er-corpus/v1`; exact top-level fields:
`schema`, `dataset_id`, `dataset_kind` (`synthetic` or `authorized-reviewed`),
`cases`. Each case uses the query/candidate/boolean-label contract of the
existing entity-resolution evaluator. Records support only name, organization,
domain, username and location; values must be bounded strings. Unknown fields,
contact/credential fields, nested values and ambiguous labels are rejected.

Protocol schema: `traceatlas-er-protocol/v1`; exact fields:

```json
{
  "schema": "traceatlas-er-protocol/v1",
  "corpus_sha256": "<exact corpus SHA-256>",
  "purpose": "<approved evaluation purpose>",
  "split": "held-out",
  "threshold": 0.72,
  "minimum_cases": 100,
  "minimum_precision": 0.95,
  "minimum_recall": 0.90,
  "maximum_false_positive_rate": 0.01,
  "authority_ref": "<same-case preserved SHA-256>",
  "privacy_review_ref": "<same-case preserved SHA-256>",
  "label_review_ref": "<same-case preserved SHA-256>"
}
```

These numeric values illustrate configuration, not an accepted release rubric.
Choose and independently register thresholds for the intended investigation
population before evaluating; do not tune them until a small test passes.
Every referenced artifact is limited to 2 MiB and must match preserved bytes.

```text
traceatlas --workspace PRIVATE_WORKSPACE resolve evaluate --case EVALUATION_CASE --corpus-sha256 CORPUS_DIGEST --protocol-sha256 PROTOCOL_DIGEST --authorized
```

Output contains aggregate pair/ranking metrics, explicit denominators, threshold
checks, input/review digests and the preserved report hash. It omits per-candidate
records and IDs. The report is itself captured by the canonical EvidenceStore.
The CLI returns 0 when configured dataset thresholds pass, 2 for a failed
diagnostic or invalid inputs. Failed thresholds still produce a preserved report;
invalid inputs do not produce a report.

## Interpretation

Zero denominators stay null and fail applicable threshold checks. No automated
merge is attempted, so false-merge rate remains undefined. Operator-declared
representativeness is not independently verified. Even a complete diagnostic
pass always returns `enterprise_gate_passed: false`. Representative evaluation,
confidence/calibration analysis and independent review remain separate gates.
Do not commit real corpus records, review artifacts or case databases.
