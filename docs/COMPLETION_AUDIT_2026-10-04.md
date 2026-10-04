# Repository completion audit — 2026-10-04

This audit separates repository work that can be completed in code from external
acceptance gates that require an operator's infrastructure, credentials, terms
review or production evidence. It covers all 130 Markdown files in the checkout;
there are no unchecked Markdown task boxes.

## Completed repository work

- Merged PRs #32–#35 completed the exact-CVE, vulnerability and package source integration in the existing canonical workforce; the adapter count remains 24.
- The canonical workforce now has 24 approval-driven adapters. NVD, FIRST EPSS,
  OSV and npm use the same immutable authority, capability plan, gateway,
  evidence, verification, graph/timeline, draft and offline replay path as the
  existing domain, IP and company sources.
- Exact `cve`, `vulnerability` and `package` seed types are implemented in the
  CLI, contracts, employee permissions, default routing and source manifests.
  Scoped npm package names are supported.
- Provider records are bound to the requested identifier before they can create
  observations. NVD, EPSS, OSV and npm wrong-target responses fail closed in both
  IntelligenceHub and canonical workforce normalization.
- Structured CVSS, severity, EPSS probability/percentile, NVD-carried CISA KEV
  listing/remediation metadata, advisory aliases, affected packages, npm version
  and declared license observations are bounded and replayable. The CISA fields
  retain NVD evidence provenance and are not counted as an independent adapter.
  Security-source content has no instruction authority.
- The deterministic employee recommends asset or inventory applicability review
  and retains human report release. An advisory never becomes proof of an
  installed vulnerable package or observed exploitation.
- The fixture qualification pack now covers 24 adapters across success,
  authentication failure and schema drift: 72 of 72 scenarios pass with offline
  replay. Source count, workflow/parser versions and operator instructions are
  aligned across current-state, Source Fabric, live-source, workforce, entity,
  user-flow and runbook documents.
- The stale user-flow claim that pause/cancel/resume were absent was reconciled:
  the employee console supports checkpointed control, while canonical workforce
  runs retain kill-switch and timeout semantics.

## Verification evidence

| Gate | Result |
|---|---|
| Python regression suite | 305 run; 304 passed; one optional MCP-SDK test skipped |
| Controlled Source Fabric | 72/72 passed; replay success rate 1.0 |
| Node graph/target tests | 25/25 passed |
| PGlite migration/RLS test | 1/1 passed |
| Python compilation | Passed |
| Secret scan | Clean |
| Diff whitespace check | Passed |
| Local Playwright browser gate | Not run: Chromium binary is absent; repository CI installs it |

Fixture success proves contract behavior, not live-provider quality. Historical
gap analyses and verification snapshots remain immutable evidence of their
recorded checkpoints; current documents point to this audit and the delivery
ledger for the implemented state.

## External acceptance gates

The repository cannot honestly complete these without deployment-specific input:

- Production-qualified source count remains zero until current provider terms,
  account entitlements, intended-runtime canaries and sustained health evidence
  are reviewed.
- Hosted worker/UI rollout, Supabase staging validation, distributed quotas and
  billing reconciliation require operator infrastructure.
- Sanctions, beneficial ownership, procurement, geospatial country packs,
  multilingual semantic planning and calibrated information gain remain future
  programme scope. Candidate catalog rows do not grant execution.

These gates are intentionally not converted into placeholder connectors or false
readiness claims. They remain visible in `docs/sources/DELIVERY_LEDGER.md` and
`CURRENT_STATE.md`.
