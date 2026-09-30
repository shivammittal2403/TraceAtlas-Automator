# Hybrid AI Workforce Migration Plan

Status: **RELEASE-ONE REPOSITORY IMPLEMENTED / DEPLOYMENT GATED**. Audit review
authorized repository implementation on 2026-09-30. This does not authorize
remote-provider onboarding, production migration or external data collection.

## 1. Delivery policy

- Preserve the existing deterministic platform; no repository rewrite.
- Migrate one vertical slice behind feature flags.
- Version contracts and schemas before runtime orchestration.
- Every phase has evidence-based entry and exit gates.
- Catalog size, model count and agent count do not count as maturity.
- Report `PLANNED`, `CODED`, `TESTED`, `DEPLOYED` and `VERIFIED` separately.
- A phase cannot use credentials, production tenants or consequential actions
  without a distinct approval and operational runbook.

## 2. Dependency map

```text
A Audit (complete for baseline)
  -> B Architecture/gap review
    -> C Canonical contracts
      -> D Evidence Fabric v2
      -> E Employee registry
      -> F Model interfaces
      -> G Tool/MCP facade
        -> H First specialist vertical slice
          -> I Verification/source independence
            -> J Temporal graph integration
              -> K Human review/release workflow
                -> L Evaluation, red team and deployment gates
```

Contract and evidence work can proceed in parallel after review. Specialist
employees cannot start until both are stable.

## 3. Phase plan

### Phase A — Repository audit

**State:** completed for commit `9d64aaf2...`.

Outputs:

- `docs/AI_WORKFORCE_GAP_ANALYSIS.md`
- `docs/AI_WORKFORCE_ARCHITECTURE.md`
- this migration plan

Exit gate: reviewers accept the status taxonomy, canonical-owner decisions,
P0 gaps and first vertical slice. Any disputed inventory row is corrected before
coding.

### Phase B — Architecture decisions and documentation baseline

Create decision records for canonical contracts, graph ownership, model egress,
source-independence semantics and employee admission. Reconcile or explicitly
retire overlapping `modules/` prototypes. Create/update the requested root
documents only after ownership is agreed: `PRD.md`, `RULES.md`, `PHASES.md`,
`DESIGN.md` and `MEMORY.md`.

Exit criteria:

- one owner per policy, evidence, entity, graph and task state;
- backward-compatibility and rollback rules documented;
- no document claims an external runtime is verified without a recorded run.

Difficulty: Medium. Risk: documentation drift if delayed.

### Phase C — Canonical contracts

Implement versioned schemas for EmployeeDefinition, AuthorizationContext,
TaskEnvelope, ResultEnvelope, EvidenceObject, Observation, Claim, Hypothesis,
SourceLineage, VerificationDecision, CostRecord and TraceSpan.

Tests:

- round-trip and unknown-field rejection;
- size/depth/identifier/timezone bounds;
- unknown evidence/case/task references fail closed;
- authority cannot be self-asserted;
- old `Finding`, event and Employee task adapters preserve semantics;
- malicious instruction text remains data.

Exit gate: contract tests pass on Python 3.10/3.12 and JS consumers; migration
fixtures are deterministic. Difficulty: High. Dependency: Phase B.

### Phase D — Evidence Fabric v2

Extend the current evidence store with append-only metadata versions, acquisition
records, parser/extractor versions, access/retention policy, derived-artifact links
and a provenance query service. Preserve existing hashes, ledger and bundle format
through a versioned compatibility adapter.

Tests: tamper, replay, parser upgrade, duplicate content across cases, retention,
legal hold, bundle compatibility and crash recovery.

Exit gate: a v1 case exports and verifies under v2 without changing original
evidence bytes. Difficulty: High. Dependency: Phase C.

### Phase E — Employee registry and scheduler

Build a data-driven registry with exactly five initial definitions: Case Manager,
Planner, WEBINT/INFRAINT Specialist, Verification Supervisor and Report Analyst.
Add deterministic eligibility, permission intersection, time/tool/action budgets,
leases, idempotency, stop reasons and result validation.

Do not copy the standalone AgentLoop as-is. Absorb only useful bounded-loop ideas
behind the existing Employee service, policy and evidence owners.

Exit gate: irrelevant roles are not instantiated; a forged tool/action is blocked;
retry cannot duplicate evidence; provider absence still yields a deterministic
result. Difficulty: High. Dependencies: C and D.

### Phase F — Provider-neutral model fabric

Create interfaces for registry, capability metadata, routing, health, cost and
fallback. Adapt loopback Ollama first. Add a null/deterministic adapter for tests.
Remote providers remain disabled until official-doc, DPA/privacy, retention,
jurisdiction, quota, pricing and structured-output checks are recorded.

Tests: incompatible model rejection, health/circuit behavior, quota and cost caps,
schema failure, timeout, fallback, provider outage and zero-provider operation.

Exit gate: no application service branches on provider name and case evidence is
not sent outside an approved boundary. Difficulty: High. Dependency: C.

### Phase G — Tool and MCP fabric

Expose existing application services through internal capability interfaces and,
later, a TraceAtlas MCP server. Every call resolves case, authorization, scope,
actor, trace and policy context server-side. MCP remains transport only.

Tests: tool allowlist, privilege reduction, staged files, SSRF, prompt/tool
injection, output caps, cancellation, idempotency and evidence capture.

Exit gate: direct service and MCP calls produce equivalent validated result
envelopes and evidence records. Difficulty: Medium/High. Dependencies: C and D.

### Phase H — First domain investigation vertical slice

Implement the domain path described below. Limit acquisition to existing approved
DNS, RDAP, archive and one search source. No new aggressive scanner is required.

Exit gate: the golden case replays from fixed fixtures, degraded-source and
no-model variants pass, and a human must approve finalization. Difficulty: High.
Dependencies: C–G.

### Phase I — Source independence and three-layer verification

Implement deterministic lineage groups, similarity/citation/ownership reasons and
the material-claim verification state machine. Add a bounded adversarial supervisor
that can only return cited critiques or explicit gaps.

Exit gate: syndicated copies count once; circular sourcing is detected; an
unsupported model claim cannot reach `SUPPORTED`; disputes remain visible.
Difficulty: High. Dependencies: D and H.

### Phase J — Temporal knowledge graph

Add versioned Observation/Claim/Evidence/Source/Acquisition nodes and temporal,
provenance-rich edges. Adapt existing spider and hosted graph records. Add
merge/split/retraction history without automatic identity merges.

Exit gate: old graph imports remain valid; temporal conflicts and superseded claims
are queryable; every material edge resolves to evidence. Difficulty: High.
Dependencies: C, D and I.

### Phase K — Human review and release workflow

Extend immutable approvals to scope changes, identity attribution, material claim
status, external communication and report release. Bind decisions to case, policy,
evidence, graph and report digests. Approval never implies automatic external action.

Exit gate: stale evidence invalidates review; last-owner and tenant controls hold;
all consequential transitions have an audit record. Difficulty: Medium/High.
Dependencies: H–J.

### Phase L — Evaluation, red team and operational verification

Create golden investigations, model/provider scorecards and adversarial fixtures.
Test hallucinated evidence, fabricated citations, false merges, indirect prompt
injection, poisoned datasets, loops, runaway cost, outages, graph corruption,
duplicates, contradictions and stale sources.

Exit gate for deployment consideration:

- evaluation thresholds pass on representative fixtures;
- hosted RLS and tenant-isolation tests pass against a disposable deployment;
- backup/restore, monitoring, incident and rollback drills are recorded;
- provider/tool licences and data-processing terms are approved;
- an authorized human signs the release evidence bundle.

Difficulty: High and continuous.

## 4. First vertical slice: owned-domain investigation

### Scope

Input: one syntactically valid public domain and an immutable assertion of
organization ownership/authority. Exclude person profiling, active exploitation,
credential collection, notifications and remediation.

### Stages and acceptance criteria

| Stage | Owner | Required output | Acceptance criterion |
|---|---|---|---|
| Objective | Human | case objective and lawful purpose | 10–500 chars, explicit domain and purpose |
| Authorization | Deterministic policy | AuthorizationContext digest | domain matches enrolled/attested scope; expiry valid |
| Planning | Planner proposal + validator | typed DAG | only eligible sources/tools, budgets and stop conditions |
| Routing | Deterministic router | selected WEBINT/INFRAINT employee | no irrelevant role instantiated |
| Collection | Existing hubs/runners | source runs and raw artifacts | DNS/RDAP/archive/search calls bounded and independently logged |
| Evidence | Evidence Fabric | versioned EvidenceObjects | hashes/ledger/source/acquisition/parser metadata validate |
| Entity resolution | Deterministic + human | domain/IP/org candidates | reasons visible; no automatic merge |
| Graph | Graph service | temporal nodes/edges | every material edge cites observations/evidence |
| Analysis | Specialist | claims/hypotheses/gaps | schema-valid; hypotheses not facts |
| Independence | Lineage engine | source groups and score | common-origin sources collapse correctly |
| Adversarial review | Supervisor | cited alternatives/contradictions | no uncited critique promoted to a claim |
| Human review | Investigator | immutable decision | digest matches current case and evidence |
| Output | Report service | report + replay manifest | all material claims have status and traceable citations |

### Required failure scenarios

- one provider unavailable;
- all model providers unavailable;
- source contains prompt injection;
- two sources repeat one original article;
- DNS and archive evidence conflict in time;
- proposed organization match is a namesake;
- collection exceeds time/action/cost budget;
- evidence changes after review starts;
- replay is attempted with a different parser version.

### Success metrics

- evidence citation correctness: 100% for material claims;
- unsupported material claims released: 0;
- known contradictions surfaced: 100% in golden fixtures;
- common-origin sources overcounted: 0;
- automatic identity merges: 0;
- authorization escapes and unapproved tool calls: 0;
- deterministic degraded report produced with model outage: yes;
- replay manifest reproduces task/source/evidence graph from fixtures: yes;
- cost/runtime/tool limits enforced: yes.

## 5. Golden investigations

Start with four synthetic, legally safe cases:

1. **Domain baseline:** consistent DNS/RDAP/archive evidence.
2. **Circular sourcing:** three URLs derived from one primary notice.
3. **Identity ambiguity:** same organization name in two jurisdictions.
4. **Adversarial evidence:** prompt injection, stale timestamps and a fabricated citation.

Each fixture includes raw artifacts, expected hashes, observations, claims,
lineage groups, contradictions, entity decisions, terminal verification status,
budgets and report assertions. Results are deterministic except explicitly scored
model suggestions.

## 6. Metrics and release gates

| Metric | Initial gate |
|---|---:|
| Material-claim citation correctness | 100% |
| Unsupported-claim release rate | 0% |
| Evidence integrity verification | 100% |
| Known contradiction detection | 100% on golden fixtures |
| Source-lineage grouping precision | reviewed threshold defined before rollout |
| Entity-resolution precision | reviewed threshold defined per entity type |
| Unauthorized tool/action rate | 0% |
| Budget overrun | 0 unapproved overruns |
| Deterministic fallback success | 100% on golden fixtures |
| Replay success | 100% for released fixtures |

Do not invent a percentage-complete product score. Track pass/fail gates and
execution evidence.

## 7. Security and rollback

- New tables/fields are additive until replay and export compatibility pass.
- Workforce execution is disabled by default behind one server-side feature flag.
- Employee definitions are versioned and hash-pinned per task.
- A kill switch disables model and employee scheduling while preserving manual,
  deterministic investigation access.
- Provider adapters use separate scoped secrets and egress rules.
- Rollback never deletes evidence; it stops scheduling and reads existing v2
  records through compatibility adapters.
- Migrations receive downgrade/read-compatibility tests before deployment.

## 8. Deferred work

FININT, broad country packs, deepfake/speaker production models, direct dark-web
acquisition, high-impact automated actions and a large specialist roster are not
part of the first slice. Each needs separate legal, data, model, connector,
security and evaluation approval.

## 9. Immediate review decisions

Before coding, maintainers should decide:

1. canonical package/location for the new contracts;
2. whether the `modules/` prototypes are retired or converted to fixtures;
3. local SQLite and hosted Supabase migration compatibility policy;
4. the first domain golden fixtures and claim materiality policy;
5. whether any remote model provider is permitted in the first release (recommended: no);
6. retention and jurisdiction representation in AuthorizationContext;
7. reviewer roles allowed to finalize claim status and reports.

After these decisions, Phase C is the only authorized implementation starting
point. Adding more agents before Phase C would increase ambiguity and risk.
