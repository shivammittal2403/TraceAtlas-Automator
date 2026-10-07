# TraceAtlas Integration Snapshots

This directory stores supplied project snapshots that are useful to TraceAtlas
but are not allowed to replace the canonical Python runtime, evidence ledger,
case model, source-fabric contracts, or hosted control plane.

## `osint-tool-typescript`

Source: `OSINT_Tool-main(2).zip`

Disposition: preserved as a versioned TypeScript reference integration. The
snapshot contains a pnpm/Turbo monorepo with entity and evidence schemas,
service scaffolds, workflow documentation, GitHub governance templates, and
tests. It is intentionally kept under `integrations/` so it can be reviewed,
adapted, and harvested without breaking the current TraceAtlas package layout.

Compatibility rules:

- Do not import it from the Python runtime by path mutation.
- Do not promote its services as production-ready until their own install,
  test, auth, data, and deployment gates pass inside TraceAtlas.
- Treat its docs as planning input, not authority over TraceAtlas safety rules.
- Reuse compatible schemas and tests through explicit adapters only.
- Keep provenance in `osint-tool-typescript.traceatlas-manifest.json`.

