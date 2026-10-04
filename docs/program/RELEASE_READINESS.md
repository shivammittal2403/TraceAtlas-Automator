# Enterprise release readiness

Status: **NOT READY — program baseline only** (updated 2026-10-04).

| Requirement | State | Proof needed |
|---|---|---|
| 50+ production-qualified sources or measured primary-workflow coverage | BLOCKED / 0 qualified | Terms, entitlement and sustained live canaries per source. |
| SOCMINT V2 across lawful public source families | OPEN | Two or more permitted source families, canonical evidence/replay, identity evaluation. |
| Entity resolution thresholds and false-merge controls | OPEN | Representative adjudicated benchmark, confidence intervals, review and reversible decisions. |
| Evidence, independence, contradiction and temporal quality | OPEN / PARTIAL | Opt-in HMAC receipt code is synthetic-tested; unanchored mode still accepts a full local rewrite. Synthetic source grouping (12 pairs) and temporal contradiction rule (8 pairs) pass; need monotonic external anchor, immutable storage, representative citation/lineage/contradiction tests, and staging replay acceptance. |
| Semantic planner, gaps and next-best action | PARTIAL | Calibrated evaluation and bounded end-to-end loop. |
| Multilingual and operational India pack | OPEN | Validated Hindi/Romanized Hindi and official source/legal verification. |
| AI employee and local model | PARTIAL | Local model workflow, contract/failure tests and unsupported-claim KPI. |
| CTI and cross-domain primary workflows | PARTIAL | Independently qualified source families and representative investigation tests. |
| IAM and tenant isolation | BLOCKED on staging | Live OIDC/RBAC/cross-tenant tests and independent review. |
| Operations / observability / backup restore | BLOCKED on infrastructure | Staging run, SLOs, tracing, quota, recovery and incident drills. |
| 100+ realistic golden investigations | OPEN | Approved realistic suite, metrics and adversarial evaluations. |
| Branch CI, CodeQL and release artifacts | NOT VERIFIED this session | Green checks for exact release candidate SHA and signed/verified artifacts. |

The 8/10 score must remain uncalculated until a published, weighted rubric is
populated with reviewed evidence. No critical primary workflow may be below 7.
Open gaps are tracked in [GAP_REGISTER.md](GAP_REGISTER.md), and the formal
acceptance conditions are in [ACCEPTANCE_GATES.md](ACCEPTANCE_GATES.md).

