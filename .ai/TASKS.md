# Persistent task checklist

Status key: OPEN, IN_PROGRESS, VERIFIED, BLOCKED_EXTERNAL. A task is VERIFIED
only with the evidence named in its acceptance criteria.

## P0 — release blockers

- [x] TA-P0-001 Identify main CI break at `dd3085b` from failed Actions jobs.
- [x] TA-P0-002 Repair malformed unified source maturity module and strict gate
  evaluation; focused Source Fabric suite passes locally.
- [x] TA-P0-003 Run compileall and full Python, Node, PGlite/browser, restore,
  golden replay, supply-chain and secret checks; document any environment gaps.
- [x] TA-P0-004 Review patch against authorization, evidence, fixed-host, graph,
  credential and fail-closed requirements; update state docs; open PR #49.
- [x] TA-P0-005 Verify green GitHub CI and CodeQL on PR #49 code/test head
  `1767708adc27e9dc05e0384a4682571e3797d6c4`: CI `37184302223` and CodeQL
  `37184302217` passed, including hosted worker-image verification.

## Level-8 workstreams

- [ ] TA-FOUNDATION: clean install/config/migrations and one canonical service
  path for CLI, UI, API, MCP and worker.
- [ ] TA-EVIDENCE: immutable raw bytes, acquisition provenance, typed
  observations/claims, source lineage, citations and semantic replay.
- [ ] TA-GRAPH: temporal edges, human-reviewed identity decisions, reversible
  decisions, uncertainty, contradictions, candidate-resolution benchmark.
- [ ] TA-SOURCES: source terms/rights ledger, connector contract, authenticated
  operator configuration, bounded canaries, signed/verified qualification
  receipts, drift/health/runbooks; no candidate-count inflation.
- [ ] TA-EMPLOYEE: typed worker envelopes; task decomposition; human-approved
  authority; durable bounded jobs; checkpoint/resume; explainable stop reasons;
  no generated text treated as evidence.
- [ ] TA-GOVERNANCE: authentication, authorization, tenant isolation, audit,
  retention, secret handling and independent security review before any
  non-loopback exposure.
- [ ] TA-OPERATIONS: durable queues, distributed limits, idempotency,
  observability, cost tracking, backup/restore and staging verification.
- [ ] TA-EVALUATION: >=100 synthetic/authorized golden cases, replay and
  entity-resolution/source-independence metrics; competitor matrix based on
  reproducible tests, not marketing counts.
- [ ] TA-SOCMINT: lawful public-source workflows only, terms-approved APIs,
  exact provenance and authorization. Private access, login/bypass, contact,
  account action and covert collection remain forbidden.
- [ ] TA-COUNTRY: India pack and multilingual retrieval only after jurisdiction,
  source rights, language evaluation and expert review are specified.

## Prompt coverage map

The detailed prompt sections are tracked by workstream: roles/principles/score
policy → scorecard; continuation and memory → `.ai/`; audit/gaps/gates → program
register; source fabric/connector SDK → TA-SOURCES; planner/policy/evidence/
observations/claims → TA-EVIDENCE and TA-EMPLOYEE; entity resolution/source
independence/contradictions/verification/knowledge gaps/next action → TA-GRAPH
and TA-EVALUATION; agent contracts/model/local modes → TA-EMPLOYEE; SOCMINT,
country, CTI, media and dark intelligence → separate scoped capability reviews;
IAM/security/operations/distribution/cost/observability → TA-GOVERNANCE and
TA-OPERATIONS; golden cases/KPIs/competitor comparisons → TA-EVALUATION;
definition of done, regressions, recovery, git and session report → acceptance
gates and session context.
