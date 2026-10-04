# TraceAtlas Automator

Evidence-first OSINT investigation workflows with analyst-controlled authorization, bounded public-source collection, immutable evidence capture, cited observations, and offline replay.

TraceAtlas helps investigators organize approved research. It does not turn an AI model into an unrestricted operator: each collection run is scoped to an analyst-approved case and target, and consequential decisions remain with a human.

## Current capabilities

- Canonical workforce pipeline with typed targets, capability-based source planning, approval digests, bounded collection, evidence custody, verification, graph/timeline analysis, and replay.
- 24 approval-driven source adapters, including public DNS/RDAP, certificate transparency, passive URL and archive indexes, public IP context, company registries, NVD, FIRST EPSS, OSV, and npm metadata.
- Deterministic employee console with checkpointed local workflows and evidence/replay exports.
- Case storage and evidence handling backed by SQLite, with source provenance and target checks.
- Source manifests, readiness reporting, runbooks, and explicit limitations for integrations that still need credentials, terms review, live qualification, or deployment work.

A connector being present in code or catalogued does not mean that provider access is configured or production-qualified. Current qualification state and open acceptance gates are documented in [Current State](docs/CURRENT_STATE.md) and [Acceptance Gates](docs/ACCEPTANCE_GATES.md).

## Quick start

Requires Python 3.10 or newer.

```powershell
python -m pip install .
$env:TRACEATLAS_WORKFORCE_ENABLED = "1"
traceatlas --workspace ./cases employee serve
```

Open the local console at [http://127.0.0.1:8765](http://127.0.0.1:8765). Keep the server on loopback. Hosted use requires authentication, authorization, and tenant isolation first.

The console can use local records and configured public-source connectors. Provider credentials and optional integrations are operator-managed; see [Live Sources](docs/LIVE_SOURCES.md), [Deployment](docs/DEPLOYMENT.md), and [Runbook](docs/RUNBOOK.md).

## Safety and evidence rules

- Only analyst-provided evidence and explicitly authorized public research belong in a case.
- Source responses are untrusted data and do not carry instructions for the agent.
- Evidence bytes and their hashes are preserved as submitted; a hash does not establish that a claim is true.
- Observations, claims, inferences, hypotheses, allegations, and unknowns remain distinct and cite case evidence.
- No autonomous contact, authentication bypass, credential harvesting, exploitation, malware execution, publication, or account actions.
- A public vulnerability advisory does not prove an authorized asset is affected or that exploitation occurred.
- Reports remain drafts until human review and release.

## Documentation

Start at [Documentation Index](docs/README.md). Key references:

- [AI Employee](docs/AI_EMPLOYEE.md)
- [Workforce Architecture](docs/AI_WORKFORCE_ARCHITECTURE.md)
- [Source Fabric](docs/SOURCE_FABRIC.md)
- [Current State](docs/CURRENT_STATE.md)
- [Security](docs/SECURITY.md)
- [Completion Audit](docs/COMPLETION_AUDIT_2026-10-04.md)

## Development

Install the project and run the repository's CI workflow for the full verification suite. The suite includes controlled fixture investigations, replay checks, UI/database gates, supply-chain checks, and the bundled worker runtime. Fixtures verify software contracts; they do not qualify a provider for production.
