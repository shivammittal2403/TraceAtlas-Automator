# Supplied archive integration status

This delivery audited the 44 ZIP files supplied for the TraceAtlas expansion.
The audit is reproducible with `traceatlas capabilities archive-audit` and its
machine-readable result is `docs/SUPPLIED_ARCHIVE_AUDIT.json`.

## Result

- 44 archives were hashed and inspected without extraction or execution.
- 43 archives map to registered capability contracts; the remaining archive is
  the TraceAtlas blueprint, which is classified as design input rather than an
  executable dependency.
- 3 byte-identical copies were detected: GeoCLIP, Geo Sleuth and GPT Researcher.
- 4 archives contain symbolic-link entries (Apify MCP, SearXNG, Stagehand and
  Watcher). They are recorded but rejected for automatic archive acceptance.
- 49 unique capability contracts are now represented: 10 adapters, 10 MCP
  boundaries, 8 services, 7 exports, 7 design-only entries, 4 workflows, one
  catalogue, one training boundary and one bundled integration.

## Meaning of integrated

Integration means a reviewed, named boundary with licence, safety, credential,
protocol and execution policy. It does **not** mean that every upstream source
tree was copied into TraceAtlas. This avoids dependency collisions, licence
contamination and accidental execution of instructions embedded in archives.

MIT/Apache-compatible projects use adapter, MCP or export contracts where the
runtime exists. AGPL projects stay behind separately deployed service/export
boundaries. Missing, conflicting, proprietary or non-commercial licences remain
non-executable. Xalgorix active exploitation and Stagehand persistent browser
sessions are explicitly disabled; a ZIP file cannot override those controls.

## Verification boundary

`archive_verified` means filename routing, SHA-256 provenance, central-directory
safety and licence metadata were inspected. `execution_verified` is separate and
is set only after a configured external runtime completes a governed call. No API
keys, deployment authority, target authorization or external runtimes were
provided by the archives, so this audit does not claim live-runtime verification.
