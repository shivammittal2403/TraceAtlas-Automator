# Hybrid AI Investigation Workforce Architecture

Status: **ACCEPTED RELEASE-ONE DESIGN**, based on repository audit at
`9d64aaf2ce9ec6f75e199be2e428007a384e0436`. The repository implementation map
and exact test/deployment status are in `DESIGN.md` and `PHASES.md`; acceptance
does not claim hosted deployment or production provider verification.

## 1. Architecture objective

Add bounded reasoning workers around the existing evidence-first platform while
keeping deterministic services authoritative. AI proposes plans, interpretations,
hypotheses and report language. Policy, acquisition bounds, schema validation,
hashing, identity state, evidence custody, graph operations and consequential
decisions remain outside the model.

```text
Human investigator / compliance approver
                    |
          AuthorizationContext
                    v
       Deterministic case state machine
                    |
        Case Manager + Planner proposal
                    v
        Deterministic domain/tool router
                    |
       Dynamic specialist task envelopes
                    v
   Existing tools / APIs / MCP / datasets
                    |
           Evidence Fabric v2
                    v
 Observation -> Claim -> Hypothesis graph
                    |
 Lineage + corroboration + contradiction checks
                    v
          Adversarial supervisor
                    |
            Human review gate
                    v
 Evidence-linked report + replay manifest
```

## 2. Non-negotiable invariants

1. Evidence bytes and deterministic records are the source of truth; model output is not.
2. An employee cannot widen scope, grant authority, install a tool or create credentials.
3. Every model/tool call is derived from a validated task envelope and allowlist.
4. Every analytical claim cites stored observations and evidence IDs.
5. Three renderings of one primary source count as one lineage group.
6. Contradictions and uncertainty are retained, not averaged away.
7. Entity matches never silently merge records.
8. Consequential actions require an authorized human decision bound to an immutable digest.
9. Stopping conditions are explicit and enforced outside the model.
10. A provider outage degrades reasoning assistance, not evidence integrity or case access.

## 3. Canonical ownership

| Concern | Canonical owner | Existing foundation | AI authority |
|---|---|---|---|
| Scope and lawful purpose | Policy service | `policy.py`, sensitive gates, RLS | None |
| Case transitions | Investigation state machine | `employee/service.py`, `db.py` | Propose only |
| Tool selection | Domain/tool router | registries and contracts | Rank candidates only |
| Tool execution | Existing runners/hubs | integrations, intelligence, capability hub | None |
| Evidence integrity | Evidence Fabric | `evidence.py` | None |
| Parsing/normalization | Deterministic adapters | collectors/parsers/providers | None |
| Entity merge state | Resolution service + human | `resolution.py` | Explain/propose only |
| Graph truth state | Knowledge Graph service | spider/graph APIs | Propose claims/edges only |
| Verification status | Verification engine | benchmark/fusion primitives | Adversarial suggestions only |
| Report release | Human review service | review tasks/decisions | Draft only |

The standalone prototypes in `modules/` should either become test fixtures or be
absorbed behind these owners. They must not become parallel sources of policy,
evidence or entity truth.

## 4. Proposed typed contracts

The first implementation artifact should be a versioned schema package. The
following are logical fields; exact serialization and migrations require review.

### EmployeeDefinition

```json
{
  "schema_version": "1.0",
  "employee_id": "webint-researcher",
  "name": "WEBINT Researcher",
  "version": "1.0.0",
  "role": "specialist",
  "domain": "WEBINT",
  "objective": "Collect and interpret public web evidence within an approved case",
  "allowed_tools": ["search.execute", "evidence.retrieve"],
  "allowed_sources": ["approved-public-web"],
  "allowed_datasets": [],
  "allowed_actions": ["propose_query", "request_collection", "propose_claim"],
  "prohibited_actions": ["change_scope", "contact_subject", "execute_code"],
  "input_schema": "traceatlas.task-envelope/v1",
  "output_schema": "traceatlas.result-envelope/v1",
  "evidence_requirements": {"claims_require_evidence": true},
  "confidence_policy": "model confidence is advisory",
  "escalation_policy": ["identity_attribution", "scope_change", "material_dispute"],
  "budget_limit": {"currency": "USD", "amount": 1.00},
  "runtime_limit": 120,
  "tool_call_limit": 8,
  "model_policy": ["structured-output", "no-training-on-case-data"],
  "privacy_policy": ["minimum-necessary", "no-secret-egress"],
  "jurisdiction_policy": ["inherit-case-policy"],
  "audit_policy": ["trace-every-call", "retain-model-metadata"]
}
```

### TaskEnvelope

Required fields: `schema_version`, `task_id`, `case_id`, `parent_task_id`,
`trace_id`, `objective`, `scope`, `authorization_context_id`, `policy_digest`,
`target_entities`, `required_capabilities`, `evidence_context_ids`, `constraints`,
`budget`, `deadline`, `stop_conditions`, `created_by` and `created_at`.

It contains references, not raw secrets. Authority is resolved from a server-side,
immutable context; an employee cannot self-assert authorization.

### ResultEnvelope

Required fields: `schema_version`, `task_id`, `employee_id`, `observations`,
`evidence_ids`, `entities`, `relationships`, `claims`, `hypotheses`,
`contradictions`, `uncertainties`, `confidence`, `source_independence`,
`information_gaps`, `recommended_next_actions`, `cost`, `latency`, `model_used`,
`tool_calls`, `execution_trace`, `stop_reason` and `completed_at`.

Validation rules:

- an observation cites an EvidenceObject and an acquisition record;
- a claim cites one or more observations;
- a hypothesis is never emitted as fact;
- model confidence is stored separately from evidence/corroboration confidence;
- unknown IDs, unapproved tools and extra schema fields fail closed;
- results cannot mutate case scope or employee permissions.

## 5. Evidence and analytical model

### EvidenceObject v2

```text
evidence_id, version, prior_version_id, case_id, source_id, source_uri,
acquisition_id, acquisition_method, retrieved_at, content_hash, mime_type,
raw_artifact_pointer, parser, parser_version, extractor, extractor_version,
observation_ids, chain_of_custody, access_policy, retention_policy,
classification, created_at
```

Existing content-addressed files and ledger entries remain immutable. New metadata
is appended. Parser or extractor changes create a derived version; they never
overwrite the original evidence.

### Semantic classes

- **FACT**: a claim that completed the configured verification policy; still scoped and time-bound.
- **OBSERVATION**: what a specific source exposed at a specific acquisition time.
- **CLAIM**: an analytical proposition linked to observations.
- **INFERENCE**: a reasoned interpretation, explicitly non-observed.
- **HYPOTHESIS**: a testable proposition requiring more evidence.
- **ALLEGATION**: a source-attributed assertion not independently established.
- **UNKNOWN**: missing or indeterminate information.

The terms are stored as enums with migration rules, not inferred from prose labels.

### Claim chain

```text
Claim
  -> supported_by / contradicted_by Observation
  -> extracted_from EvidenceObject version
  -> acquired_by Acquisition
  -> retrieved_from Source
  -> grouped_by SourceLineage
```

## 6. Temporal knowledge graph

The target graph extends rather than replaces the existing event and entity graphs.

Node families: Case, Task, Employee, Person, Organization, Company, Account,
Domain, IP, Email, Phone, Username, Device, Document, Location, Event, Asset,
Supplier, Facility, Software, Hardware, AIModel, ThreatActor, Campaign, Indicator,
Transaction, Evidence, Observation, Claim, Hypothesis, Source and Acquisition.

Every analytical relationship stores:

- `edge_id`, `edge_type`, `case_id` and schema version;
- evidence/observation IDs and source-lineage group;
- valid-from/valid-to and observed/retrieved timestamps;
- classification, confidence basis and uncertainty;
- proposed-by, reviewed-by and decision state;
- supersedes/retracted-by references.

Deterministic graph traversal never upgrades a correlation to causation. Entity
resolution outputs `MATCH`, `LIKELY_MATCH`, `POSSIBLE_MATCH`, `CONFLICT` or
`NO_MATCH`, with reasons. Only a human decision changes canonical identity state.

## 7. Source-independence engine

Source records add publisher, original source, publication/retrieval time,
citation chain, content fingerprint/similarity, ownership group, source type and
reliability metadata. Deterministic rules group:

- exact and near-identical content;
- explicit citations and canonical URLs;
- syndication/republication;
- common publisher ownership when known;
- multiple model outputs derived from the same evidence set.

The engine returns an independence group and reasons. AI may propose uncertain
lineage links, but they enter a review queue. Corroboration uses independent groups,
not URL or model counts.

## 8. Verification engine

Material claims move through a deterministic state machine:

1. **Integrity:** evidence exists, hashes and ledger validate, acquisition/source,
   timestamps and parser/extractor versions are present.
2. **Corroboration:** identity and timeline constraints pass; required independent
   lineage groups support the claim; contradictions remain attached.
3. **Adversarial review:** a bounded supervisor searches for alternative
   explanations, circular sourcing, unsupported assumptions, identity errors,
   stale evidence and missing context. Every proposed criticism cites evidence or
   is labeled an information gap.

Terminal review statuses: `SUPPORTED`, `PARTIALLY_SUPPORTED`, `DISPUTED`,
`INCONCLUSIVE`, `UNSUPPORTED`. Policy determines which statuses require a human
decision. No model vote can set a terminal status by itself.

## 9. Bounded workforce

Employees are definitions loaded on demand, not permanent processes.

```text
Level 0: Human Investigator, Human Supervisor, Compliance Approver
Level 1: Case Manager, Investigation Planner, Research Coordinator
Level 2: selected domain specialists only
Level 3: selected analytical specialists only
Level 4: integrity, corroboration, independence, contradiction, adversarial review
Level 5: report, executive brief and evidence-package drafts
```

Initial registry should contain only five definitions: Case Manager, Planner,
WEBINT/INFRAINT Specialist, Verification Supervisor and Report Analyst. More roles
are admitted only when they have unique tools/data, evaluation cases and a failure
mode that the deterministic system can contain.

## 10. Model fabric

Proposed components:

- `ModelRegistry`: provider/model metadata, data location, retention and availability.
- `ModelCapabilityRegistry`: structured output, modality, context and evaluated tasks.
- `ModelRouter`: deterministic policy filter followed by scored selection.
- `ProviderHealthMonitor`: bounded failures, quotas and circuit state.
- `CostTracker`: estimated and actual tokens/currency/latency per task.
- `FallbackManager`: compatible alternatives and deterministic/no-model fallback.

Routing order: privacy/jurisdiction and authorization eligibility → required
capabilities → evaluation threshold → provider health/quota → cost/latency →
stable tie-break. Business logic never branches on a provider name.

The existing loopback Ollama path becomes the first adapter. Remote OpenAI,
Gemini, Claude, Grok, Qwen, DeepSeek or Mistral adapters remain **PLANNED** until
official API, privacy, pricing, structured-output and deployment checks are done.

## 11. Tool and MCP fabric

Existing registries remain the source for tool availability and policy. A future
TraceAtlas MCP server exposes business capabilities, not raw binaries:

```text
investigation.create / investigation.plan
search.execute / search.query
evidence.store / evidence.retrieve / evidence.verify
graph.query / graph.expand
entity.resolve
dataset.search / country.sources / cti.search / supplychain.expand
model.route / verification.run / report.generate
```

Every call carries `case_id`, authorization-context reference, scope, `trace_id`,
actor and policy digest. MCP handlers call deterministic application services;
they do not duplicate policy, evidence or graph logic.

## 12. Investigation state machine and stopping

```text
DRAFT -> AUTHORIZED -> PLANNED -> COLLECTING -> ANALYZING -> VERIFYING
      -> HUMAN_REVIEW -> FINALIZED
                        \-> ESCALATED
Any active state -> STOPPED / FAILED / EXPIRED
```

The scheduler stops on scope boundary, budget/time/tool-call exhaustion, rate
limit, source exhaustion, negligible information gain, satisfied verification
policy or required human review. “Search until truth” is prohibited.

Next-best-action scoring is deterministic and explainable:

```text
eligible = policy_allowed AND within_budget AND source_healthy
score = expected_information_gain / max(expected_cost, floor)
```

AI may estimate information gain with uncertainty; a configured ceiling and
stable fallback rule remain authoritative.

## 13. Observability and cost

Propagate one trace across Case → Plan → Task → Employee → Model/MCP/Tool →
Source → Acquisition → Evidence → Observation → Claim → Report. Store bounded,
non-secret spans with status, latency, token counts, estimated/actual cost,
fallback, retries, tool calls and evidence/result IDs. Do not log prompts or raw
sensitive evidence by default.

Existing `source_runs`, connector health, request IDs and collaboration events are
inputs to this design, not a complete distributed trace.

## 14. Security and responsible-AI boundaries

- Least-privilege employee capabilities are immutable for a task.
- External content is data and never changes instructions or tool permissions.
- Model providers receive only policy-approved minimized context.
- Secrets remain environment/vault references and never enter envelopes.
- Staged-file, SSRF, path, output-size, rate and timeout controls stay deterministic.
- Dataset/model/tool provenance and licence are release gates.
- Sensitive-attribute inference is blocked unless a documented, necessary and
  lawful case policy explicitly permits the analytical question.
- Identity attribution, financial decisions, notifications, takedowns, blocking,
  law-enforcement escalation and production security actions require human approval.

## 15. First vertical slice

Use one **domain** investigation because the repository already has typed domain
policy, DNS/RDAP/archive sources, bounded search/service paths, evidence storage,
entity candidates, graph export, reviews and reports.

Success path:

```text
objective + owned-domain authority
-> immutable case/task envelope
-> deterministic planner validation
-> WEBINT/INFRAINT specialist selection
-> DNS + RDAP + archive + one approved search source
-> EvidenceObject v2 records
-> domain/IP/organization candidates
-> temporal claim graph
-> independent-source grouping
-> contradiction/adversarial review
-> human decision
-> evidence-linked report and replay manifest
```

Success requires byte-for-byte replay inputs, valid citations, visible failures,
no unsupported terminal claim, a bounded cost/runtime record and a run that still
produces a deterministic brief when the model adapter is unavailable.

## 16. Architecture decision gate

Every new employee proposal must answer the ten suitability questions in the
master brief and provide: unique role, minimum permissions, independent
verification method, hallucination containment, cost ceiling, stop policy,
provider-failure behavior and golden investigation. If deterministic code scores
better, no employee is created.
