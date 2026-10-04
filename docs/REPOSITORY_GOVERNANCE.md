# Repository governance

- Canonical repository: `shivammittal2403/TraceAtlas-Automator`.
- `main` must pass CI and CodeQL before release or production promotion.
- Releases use semantic-version tags and attach the wheel, CycloneDX SBOM and checksums.
- CODEOWNERS review covers API, migration, worker, deployment and security changes.
- Dependabot updates require licence, provenance and privilege review.
- Credentials, `.env` files, evidence databases and reports must never be committed.
- Deployment mirrors are not sources of truth; production must expose the canonical commit.
