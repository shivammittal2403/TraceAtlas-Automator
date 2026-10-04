# TraceAtlas Hybrid AI Workforce — Product Requirements

## Product outcome

TraceAtlas adds a bounded, evidence-first AI investigation workforce to the
existing deterministic platform. AI may propose plans, observations, claims,
hypotheses and report language. It never grants authority, changes scope,
installs tools, merges identities, promotes its own claim to fact or releases a
report.

## Initial users

- investigators who own a case and its lawful purpose;
- supervisors who approve scope, material claims and reports;
- compliance administrators who control retention, jurisdiction and providers;
- private workers that execute already-approved bounded tasks.

## Release-one workflow

The first supported slice is a passive investigation of an enrolled,
organisation-owned domain. It uses DNS, RDAP, archive metadata and one approved
search capability. It must work without a model and must stop at a human release
gate.

## Functional requirements

1. Strict versioned contracts reject unknown fields and unknown references.
2. Server-side AuthorizationContext binds case, actor, scope, tools, actions,
   jurisdiction, retention, expiry and policy digest.
3. The registry initially contains exactly five bounded employees.
4. Routing intersects task needs, employee permissions and server authority.
5. Tasks have immutable digests, explicit budgets, deadlines and stop reasons.
6. Evidence v1 bytes remain unchanged while v2 metadata versions append.
7. Observations cite evidence and acquisition records; claims cite observations.
8. Source independence groups syndication, citation and common origin.
9. Material claims pass integrity, corroboration and adversarial review.
10. Temporal graph edges retain provenance, uncertainty and review state.
11. Model routing is provider-neutral and always supports a deterministic
    no-model fallback.
12. Direct tool and MCP transports share the same capability facade.
13. Hosted tables use tenant RLS and authenticated clients cannot forge tasks,
    evidence, claims, results or traces.
14. Final report release remains an immutable human decision.

## Non-goals for release one

- autonomous person profiling, attribution or identity merging;
- active exploitation, credential collection, subject contact or takedowns;
- production remote-model enablement without legal/privacy/provider review;
- broad FININT, dark-web acquisition, deepfake production models or a large
  role catalogue;
- claiming deployment or provider verification from repository tests.

## Acceptance gates

- 100% evidence citations for material released claims;
- zero unsupported material claims released;
- zero unapproved tools, actions, identity merges or budget overruns;
- golden fixtures surface every known contradiction and circular source;
- no-model and provider-outage cases complete deterministically;
- local tests, PostgreSQL migration tests, tenant RLS tests and hosted review
  contract tests pass before deployment consideration.

## 2026-10-03 local slice extension

Release-one implementation now includes one integrated deterministic collection
cycle for domain/IP and approved-record person/company investigations. It returns
preserved evidence, typed assertions, graph, timeline, contradictions, visible
unknowns, verification, draft report and replay metadata. Same-name associations
remain unresolved identities. Unverified semantic extraction is INCONCLUSIVE.

The first production acceptance remains unfulfilled: approved live search,
semantic planning/adversarial search, private hosted worker/result UI, live provider
qualification and production operating gates are open. Broad CTI/malware/supply
labels in G01–G12 qualify only the common backbone, not complete domain engines.
