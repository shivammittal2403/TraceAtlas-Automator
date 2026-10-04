# Enterprise readiness audit

Baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`, 2026-10-04.

| Domain | Status | Evidence / open gate |
|---|---|---|
| Local deterministic core | TESTED | CI includes Python, JS, DB fixture suites per current state |
| Source gateway and evidence replay | TESTED / selected LIVE_TESTED | Direct transport/entitlement gates remain |
| Tenant authentication / isolation | PARTIAL | Synthetic RLS tests exist; live JWT/Auth and concurrent tenant validation not evidenced |
| Deployment / operations | NOT VERIFIED | Current docs say hosted worker and private product view are not deployed/verified |
| Observability and failure recovery | PARTIAL | Local traces/health/replay exist; distributed quota, recovery and sustained operations open |
| Privacy, retention, legal terms | PARTIAL | Controls documented; provider-specific entitlement and retention review must be completed |
| AI governance | PARTIAL | Advisory/model-free path exists; remote model privacy, spend, evaluations and provider failover open |
| Security assurance | PARTIAL | Changed-path reviews and CodeQL/CI are not a penetration test or production certification |
| Release maturity | NOT PRODUCTION_QUALIFIED | Hosted runtime acceptance and live source quality evidence absent |

Enterprise readiness is **NOT PRODUCTION_QUALIFIED**. Production release needs intended-environment CI/security evidence, authenticated multi-tenant tests, backup/restore and cancellation drills, key/retention operations, source legal/entitlement review, incident ownership, recovery objectives, support model and end-to-end golden cases with measured analyst outcomes. Do not infer any of these from repository docs or fixtures alone.
