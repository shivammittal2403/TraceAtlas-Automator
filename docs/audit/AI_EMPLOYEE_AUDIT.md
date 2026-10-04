# AI employee audit

Baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`, 2026-10-04. Canonical references: `docs/AI_EMPLOYEE.md`, `docs/AI_WORKFORCE.md`, `docs/AI_WORKFORCE_ARCHITECTURE.md`, `docs/RULES.md`.

## Status

**IMPLEMENTED / TESTED within bounded scope.** The employee console produces authorized, bounded, reviewable workflows, deterministic analysis and cited drafts. Optional Ollama assistance is local/loopback and advisory. The five-role workforce design does not mean five independent always-running autonomous agents.

| Area | State |
|---|---|
| Deterministic planner/router and task limits | IMPLEMENTED; tests in CI |
| Source/evidence pipeline and replay | IMPLEMENTED; fixture and selected response replay evidence |
| AI-generated plans/claims | Model cannot grant authority; outputs remain advisory/unreviewed |
| Remote model registry/fallback/cost enforcement | PARTIAL / NOT production-qualified |
| Autonomous source expansion and semantic research | NOT_IMPLEMENTED |
| Report release, identity merge, contact, account actions | Human-controlled / prohibited from autonomous execution |
| Hosted workforce deployment | NOT VERIFIED |

A role is justified only where it has unique permissions/tools, independently evaluated outputs, cost/time caps, fail-closed behavior and a deterministic fallback. Keep evidence, policy, scope, hashing, identity state, source transport and stop conditions outside model control. Source content is untrusted.

The employee is a bounded assistant/workflow, not an unrestricted AI employee that performs every OSINT task automatically.
