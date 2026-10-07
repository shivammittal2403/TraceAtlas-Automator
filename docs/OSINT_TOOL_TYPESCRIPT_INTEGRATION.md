# OSINT Tool TypeScript Snapshot Integration

Canonical repository: `shivammittal2403/TraceAtlas-Automator`.

Supplied archive: `OSINT_Tool-main(2).zip`.

The archive has been merged as `integrations/osint-tool-typescript/` with a
per-file integrity manifest at
`integrations/osint-tool-typescript.traceatlas-manifest.json`.

## What Was Merged

- TypeScript entity schemas and evidence/case/investigation service scaffolds.
- pnpm/Turbo workspace configuration, lockfile, package manifests and tests.
- Governance material: CODEOWNERS, issue templates, PR template and CI workflow.
- Architecture, access-control, AI workflow, team assignment and execution docs.
- Existing audit and test-execution reports from the supplied snapshot.

## Compatibility Boundary

TraceAtlas remains the canonical Python, SQLite, evidence-first investigation
runtime. The incoming TypeScript tree is preserved as an integration snapshot,
not flattened into the root project. This prevents these risks:

- replacing TraceAtlas package metadata or CLI entry points;
- mixing two unrelated CI/package-manager contracts at repository root;
- silently claiming unfinished service scaffolds as operational source adapters;
- weakening the current human-approval and evidence-custody model.

## Graduation Path

The useful parts should graduate in small, testable slices:

1. Map TypeScript entity fields to `docs/ENTITY_MODEL.md` and the Python case
   evidence schema.
2. Port or bridge schema tests where they strengthen existing evidence,
   provenance, observation and source contracts.
3. Promote service routes only after authentication, authorization, tenancy,
   source bounds, replay and audit behavior are proven.
4. Keep the original snapshot intact until every promoted slice has a TraceAtlas
   owner, tests and rollback notes.

This merge improves repository continuity without pretending the uploaded
monorepo is already production-qualified.

