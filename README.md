# TraceAtlas Automator

Current package and console version: **1.11.0**.

The supplied 135-module intelligence suite is available through the case-bound
`archive analyze --action intelligence` workflow. See [module modes, setup and
verification](docs/INTELLIGENCE_SUITE.md); planning and unconfigured pipelines
are explicitly separated from supplied-record analysis and live integrations.

Evidence-first OSINT investigation workflows with analyst-controlled authorization, bounded public-source collection, immutable evidence capture, cited observations, and offline replay.

TraceAtlas helps investigators organize approved research. It does not turn an AI model into an unrestricted operator: each collection run is scoped to an analyst-approved case and target, and consequential decisions remain with a human.

## Current capabilities

- Compatible integration of the supplied TraceAtlas-OSINT and cute snapshots:
  seven case-bound offline analysis actions, an OSINT directory, and a 19-module
  Academy. All source/configuration/test/document files are preserved with
  provenance; original executable references use inert `.source` filenames.
  Imported scaffolds are not counted as working integrations.
  See [Archive integration](docs/ARCHIVE_INTEGRATION.md).
- Compatible preservation of the supplied `OSINT_Tool-main(2).zip` TypeScript
  workspace under `integrations/osint-tool-typescript/`, with a per-file
  manifest and a documented graduation path. It is intentionally not promoted
  as a production runtime until TraceAtlas-specific gates pass.

- Canonical workforce pipeline with typed targets, capability-based source planning, approval digests, bounded collection, evidence custody, verification, graph/timeline analysis, and replay.
- 26 approval-driven source adapters, including public DNS/RDAP, certificate transparency, passive URL and archive indexes, public IP context, company registries, NVD, CVE Program, FIRST EPSS, the exact-CVE CISA KEV catalog adapter, OSV, and npm metadata. CISA KEV facts are normalized only from the exact requested CVE match; the bounded raw feed is retained as source evidence for replay.
- Deterministic employee console with checkpointed local workflows and evidence/replay exports.
- Case storage and evidence handling backed by SQLite, with source provenance and target checks.
- Source manifests, readiness reporting, runbooks, and explicit limitations for integrations that still need credentials, terms review, live qualification, or deployment work.

A connector being present in code or catalogued does not mean that provider access is configured or production-qualified. Current qualification state and open acceptance gates are documented in [Current State](docs/CURRENT_STATE.md) and [Acceptance Gates](docs/ACCEPTANCE_GATES.md).

The persistent enterprise engineering program, baseline scorecard, acceptance
gates and resume checkpoint are tracked in [docs/program](docs/program/README.md)
and [.ai](.ai/SESSION_CONTEXT.md). Maturity scores remain unestablished until
representative workflows have reproducible evaluation evidence.

## Quick start

Requires Python 3.10 or newer.

List the archive actions with `traceatlas archive actions`. Run an approved
submitted file with `traceatlas --workspace ./cases archive analyze --case CASE
--action objective --input objective.json --authorized`; outputs use the existing
case/evidence/report pipeline. Educational pages are at `/directory/` and
`/academy/` in the static frontend, with no provider collection.

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
- [Source maturity and qualification](docs/SOURCE_MATURITY.md)
- [Current State](docs/CURRENT_STATE.md)
- [Security](docs/SECURITY.md)
- [Completion Audit](docs/COMPLETION_AUDIT_2026-10-04.md)

## Development

Install the project and run the repository's CI workflow for the full verification suite. The suite includes controlled fixture investigations, replay checks, UI/database gates, supply-chain checks, and the bundled worker runtime. Fixtures verify software contracts; they do not qualify a provider for production.
