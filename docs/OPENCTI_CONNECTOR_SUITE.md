# OpenCTI Connector Suite Integration

TraceAtlas pins the complete supplied OpenCTI connector source under
`third_party/opencti-connectors` as a Git submodule and exposes a governed
integration layer. The pinned tree contains 308 connector packages across external import, enrichment,
file import/export, and stream categories.

## What is integrated

- Complete connector source, configuration schemas, Docker definitions,
  documentation, tests, SDK and templates at upstream commit
  `55ca0dfa4129050cb607fdaf6b1a7457e0ae3476`.
- Generated registry with package paths, upstream metadata, required environment
  variable names, secret-field names, container images, license boundaries and
  per-connector source digests.
- CLI discovery, filtering, inspection, readiness checks, integrity verification
  and non-executing deployment plans.
- Compatibility with TraceAtlas' existing STIX 2.1, approved OpenCTI export,
  evidence custody and investigation workflows.

## Truth boundary

These packages run against an independently deployed OpenCTI platform. Pinned
source does not make a connector live. No package is executed inside the
TraceAtlas process, no provider credential is bundled, and the generated registry
marks every connector `execution_enabled=false`. Upstream `verified` metadata is
reported separately from TraceAtlas live-execution evidence.

## Commands

```bash
traceatlas opencti-connectors list --category internal-enrichment --query shodan
traceatlas opencti-connectors show internal-enrichment/shodan
traceatlas opencti-connectors doctor
traceatlas opencti-connectors verify

# Produces a plan only. It never starts a container.
traceatlas opencti-connectors plan external-import/misp --authorized --owned-org
```

The default source root is `third_party/opencti-connectors`. A normal
`./start.sh` initializes the submodule automatically. For a manual or archival
checkout, run `git submodule update --init --depth 1`. Use `--vendor-root` when
running an installed wheel from outside the repository.

## Runtime gate

A plan reports `launch_ready=true` only when all of these are present:

1. connector source and its Compose file;
2. Docker on `PATH`;
3. every environment variable required by the connector's JSON Schema;
4. `TRACEATLAS_OPENCTI_CONNECTORS_ENABLED=1`;
5. explicit `--authorized` and `--owned-org` attestations.

TraceAtlas returns command argument arrays for operator review and does not run
them. Provider terms, subscription rights, target authority and data-retention
rules remain operator responsibilities.

## Licensing

The upstream default is Apache-2.0. The supplied snapshot contains separate
AGPL-3.0-only connector folders (`alienvault`, `crowdstrike`, `kaspersky`, and
`socprime`) and an MIT folder (`portspoof`). Those packages remain isolated under
`third_party`; TraceAtlas does not import or link them into its Apache-2.0 Python
package. Their local `LICENSE` files control redistribution and use.

## Provenance and security treatment

The input ZIP SHA-256, pinned upstream commit and upstream tree are recorded in
the generated registry and snapshot notice. The supplied archive was compared
against that tree: all 8,275 paths matched and only 19 public test/documentation
fixtures differed after the review copy had credential-shaped values sanitized.
The Git submodule preserves the authoritative upstream revision, while the
first-party secret scanner excludes that separately governed dependency.
`OPENCTI_SHA256SUMS` locks every file at the pinned revision.
