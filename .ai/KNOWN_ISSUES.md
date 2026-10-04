# Known issues and external blockers

- Baseline main CI failed on 2026-10-04 after PR #48: two Python compile jobs
  and the locked MCP Source Fabric gate. The local repair passes available
  checks; do not report GitHub CI as green until the PR run passes.
- Package/documentation version is 1.11.0 in `pyproject.toml` and `docs/README.md`.
  The stale `docs/CURRENT_STATE.md` heading was corrected. Confirm release
  policy before changing the package version.
- No production-qualified sources are documented. Operator credentials,
  licenses/terms, direct network access and sustained target-runtime canaries
  are not available as proof in this workspace.
- Production deployment, tenant IAM/isolation and independent security review
  are not verified. Keep services loopback-bound.
- No 100-case representative gold benchmark is established. Controlled
  fixtures are not golden investigations or live-source evidence.
- Social-platform source rights, entitlements and APIs need source-by-source
  review; SOCMINT is not a blanket authorized capability.
- “Future Record” was not verified as a product name in the prior comparison;
  treat Recorded Future as an assumption until the user confirms.
