# Enterprise 8/10 scorecard

Updated: 2026-10-04. This is a baseline, not a readiness declaration.

## Scoring method

No repository-wide, evidence-backed 0–10 rubric exists yet. Therefore category
scores and the weighted total are **UNSCORED**, not zero and not inferred from
implementation volume. Each category must define representative acceptance data,
metric, threshold, evidence source and intended deployment before a numeric score
is assigned. A fixture pass is software-contract evidence only.

| Category | Baseline state | Evidence and missing measurement |
|---|---|---|
| Source Fabric | Partial; unscored | 25 coded approval-driven adapters; 0 production-qualified. Live availability, parser success and source freshness not measured in intended runtime. |
| SOCMINT | Missing/partial; unscored | Export/import and catalog surfaces do not demonstrate multiple lawful live source families or cross-platform accuracy. |
| Person/entity resolution | Partial; unscored | Explainable candidate queue and analyst accept/reject; 24 synthetic pairs measure candidate metrics only (precision .80, recall 1.00); no representative precision/recall, calibrated confidence or measurable false-merge rate. |
| Domain/IP/infrastructure | Fixture/injected-response verified; unscored | Canonical path and controlled tests exist; direct transport qualification is environment-limited. |
| Company intelligence | Partial; unscored | Exact-identifier connectors exist; live entitlements, country breadth and ownership coverage are not qualified. |
| Graph intelligence | Partial; unscored | Typed offline graph, filters and bounded algorithms; investigation-level relationship precision and UX acceptance are not measured. |
| Temporal intelligence | Partial; unscored | Temporal conflict/freshness primitives and fixtures; representative dated record accuracy is unmeasured. |
| Evidence/provenance | Strong local contracts; unscored | Byte hashes, custody, references and replay tests; independent external integrity anchor and citation accuracy remain open. |
| Source independence | Partial; unscored | Synthetic pair diagnostic passes 12/12 after removing hostname-only grouping; approved representative lineage and contradiction recall remain unmeasured. |
| Contradiction analysis | Partial; unscored | Structured temporal/multivalue tests exist; representative contradiction recall is unknown. |
| Semantic planning | Partial; unscored | Deterministic target-bound plan exists; free-form, multilingual and semantically measured planning do not. |
| Information gaps / NBA | Partial; unscored | Bounded deterministic gap and next-action outputs exist; information gain is not calibrated. |
| AI employee | Partial; unscored | Typed, human-approved local workflow; autonomous defensible investigation rate is not measured. |
| Multilingual | Missing; unscored | No validated Hindi/Romanized Hindi workflow or query lineage evaluation. |
| Country intelligence | Missing/partial; unscored | No operational India country pack verified against live official sources and terms. |
| CTI | Partial; unscored | CVE/advisory/package workflow and fixtures; no full independent source qualification or incident workflow acceptance. |
| Investigator UX | Partial; unscored | Local console and graph tests; operator usability study and hosted workflow evidence absent. |
| IAM/security | Partial; unscored | Local authority gates and hosted RLS tests; live tenant/Auth isolation and independent security evaluation absent. |
| Observability | Partial; unscored | Local source events/health exist; end-to-end deployed trace and SLO evidence absent. |
| Deployment/operations | Not production-proven; unscored | CI/build/release assets exist; staging/pilot, restore, load and incident drills not demonstrated. |
| Evaluation | Partial; unscored | 12 controlled investigations; 100+ realistic golden suite and ER-quality measurements not available. |

## Current outcome

- Weighted score: **not calculated**.
- Mandatory release gates: **open**.
- No category may be called 8/10 until its acceptance evidence and threshold
  are reviewed. No critical category may be below 7 at release.
- Session evidence and limitations: [Evaluation Results](EVALUATION_RESULTS.md),
  [Release Readiness](RELEASE_READINESS.md).
