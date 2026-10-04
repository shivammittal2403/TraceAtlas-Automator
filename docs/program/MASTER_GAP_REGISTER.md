# Master gap register

| ID | Priority | Gap | Current proof | Acceptance to close | State |
|---|---|---|---|---|---|
| TA-001 | P0 | Main source-registry syntax/lifecycle regression after PR #48 | CI 37181405185 failed compile and MCP gate; local compile reproduced syntax error; local suite now passes | Full checks pass on a PR based on current main and hosted CI green | IN_PROGRESS |
| TA-002 | P0 | Source-gate vocabulary and evidence-attestation integrity | Main had conflicting duplicated 20/23-gate definitions | One shared 23-gate policy; bounded refs; strict stages; regression tests | IMPLEMENTED LOCALLY; PR PENDING |
| TA-003 | P0 | Qualification evidence reference resolution is incomplete | FabricStore review now requires explicit authorization and a case-preserved artifact hash; promotion and reported state re-resolve every reference against that same case | Resolve every ref against case evidence, reverify custody at promotion, and reject unresolved legacy rows | IMPLEMENTED LOCALLY; HOSTED CI PENDING |
| TA-004 | P1 | AI employee remains deterministic for registered target types | Current-state docs explicitly limit semantic hypotheses/multilingual planning | Typed plan, policy-bound tools, resumable bounded loop, evaluated synthetic cases | OPEN |
| TA-005 | P1 | SOCMINT coverage gap | Current state explicitly says no social-platform investigation workflow | Terms-approved public API workflows; provenance/identity uncertainty; lawful test set | OPEN |
| TA-006 | P1 | Enterprise IAM/tenant and hosted operation | Local package only; production/hosted state unverified | Threat model, authz, tenant tests, staging evidence, review, runbooks | OPEN |
| TA-007 | P1 | Source production qualification | 26 canonical adapters; zero production-qualified claims | Receipts and current-runtime canaries meeting every source gate | OPEN |
| TA-008 | P1 | Semantic replay and golden benchmark | Controlled fixtures exist; no 100-case benchmark | Version-aware recomputation and >=100 authorized/de-identified cases | OPEN |
| TA-009 | P2 | Multilingual/country packs and calibrated planner | Existing docs mark them as gaps | Jurisdiction/source coverage, expert-reviewed corpus, calibrated metrics | OPEN |
| TA-010 | P2 | Durable distributed worker budgets and observability | Current docs identify process-local limits and hosted gaps | Cross-worker quotas, tracing, cost data, crash recovery, restore/load evidence | OPEN |
| TA-011 | P2 | Competitor benchmark | Public-feature comparison only | Reproducible workflow benchmark with limitations and no parity inflation | OPEN |
| TA-012 | P2 | Package version drift in current-state heading | `pyproject.toml` and `docs/README.md` specify 1.11.0; stale current-state heading was 1.12.0 | Keep docs aligned to release metadata; change package version only with release evidence | DOC FIXED; POLICY OPEN |

Reprioritize only after inspecting current code and tests. Each closure must link
to commit, checks, artifact and remaining limitations.
