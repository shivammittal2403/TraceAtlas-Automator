# COLRF research-framework integration

## Origin and scope

This additive integration maps the user-supplied research paper
**Open-Source Intelligence (OSINT) for Cybersecurity: A Solution-Oriented
Framework for Threat Intelligence, Reliability, Automation, and Ethical
Operations**, by Yogesh Kumar Agrahari, to TraceAtlas's existing bounded
investigation product. The paper proposes the **Cybersecurity OSINT Lifecycle
and Reliability Framework (COLRF)**. The framework is conceptual: its
operational improvements have **not** been demonstrated in a controlled
empirical study.

The mapping is implemented in `src/traceatlas/workforce/colrf.py` and
called from the canonical `InvestigationPipeline`. It is an evidence-review
overlay, **not** a new policy owner, agent runtime, source connector,
authorization mechanism, independent confidence scorer or report release path.

## Canonical integration

- `run()` uses captured, normalized `SourceDocument` inputs, canonical
  `EvidenceObject` records, source outcomes, existing source-lineage
  groupings and `VerificationDecision` results.
- `product["colrf_review"]` contains a versioned nine-stage lifecycle,
  eight separate reliability dimensions per claim, source/failure metadata,
  evidence IDs, contradictory observations and the existing human-release gate.
- The rendered Markdown investigation report displays the lifecycle and
  finding-level review, explicitly marking unmeasured reliability and
  uncalibrated confidence.
- `replay()` re-derives the overlay from captured case artifacts and
  compares it to the stored review. No new network requests or LLM calls.
- Older products without `colrf_review` still render and replay using
  their existing format. No SQLite migration or contract replacement.

## Lifecycle mapping

| COLRF stage | TraceAtlas mapping and limitation |
| --- | --- |
| Intelligence requirement | Approved task objective and typed target scope |
| Source planning | Recorded source outcomes, not a guarantee of source coverage |
| Collection | Captured/partial/empty distinction and failed or restricted sources |
| Preservation and provenance | Canonical evidence and acquisition receipts |
| Normalization | Existing structured observations and deterministic parsers |
| Correlation and hypotheses | Existing claim links; alternative hypotheses **not yet tested** |
| Verification | Existing independent-lineage and contradiction-aware claim decisions |
| Confidence and reporting | Uncalibrated statuses, draft report, analyst release required |
| Operational feedback | Explicitly `NOT_COLLECTED` until outcome data exist |

## Eight independent dimensions

`relevance`, `source_reliability`, `temporal_validity`, `provenance`,
`corroboration`, `analytical_confidence`,
`legal_ethical_compliance`, and `actionability`.

These are categorical review labels, **not** an aggregate score. A verified
hash is not a truth guarantee. Timestamps do not establish freshness without
a task-specific threshold. Different source-lineage groups are not necessarily
independent in reality. Authorized collection does not certify compliance
with all laws. Even `SUPPORTED` claims remain draft-only.

## Validation and engineering constraints

The module uses only Python's standard library, has no direct network or
filesystem activity and does not create new action permissions. Focused
regression tests cover 9 stages/8 dimensions, lineage deduplication, disputed
claims, partial collection, deterministic replay and cross-case rejection.
The canonical pipeline integration test checks report visibility and
rejects a modified overlay despite a rehashed stored product.

Run:

```sh
PYTHONPATH=src python -m unittest tests.test_colrf_review -v
PYTHONPATH=src python -m unittest discover -s tests -q
python scripts/check_secrets.py
```

Existing CI/CodeQL, optional adapter and browser gates still apply. No
claim of deployment, empirical validation, complete hypothesis testing,
provider reliability measurements or operational utility improvement is made.
