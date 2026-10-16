# Extreme reconnaissance: requested 45-tool source catalog

There are 45 named items in the supplied list: 35 code projects and 10 web/API services. The 35 code projects consist of 33 newly pinned GitHub source repositories, an existing pinned and directly vendored theHarvester, and the GitLab-hosted nrich project (full commit not independently verified). Ten web/API services have no redistributable upstream source established by the request.

This commit deliberately separates SOURCE_AVAILABLE, ADAPTER_EXISTS, TESTED and LIVE_VERIFIED. It does not grant new scanning authority, launch subprocesses, make network calls, enable masscan/ZMap, install dependencies or claim 45 working live integrations.

## Exact source snapshots

Each newly added source path under third_party/extreme-recon is a Git submodule at an exact upstream 40-character commit. Unlike ordinary files under vendor_sources, submodule gitlinks do not display individual code files inside the parent GitHub repository.

Use selective checkout after cloning:

    git submodule update --init third_party/extreme-recon/amass
    git submodule update --init third_party/extreme-recon/subfinder

The full source is then locally available at its exact pinned revision. To inspect all 45 entries:

    traceatlas integrations extreme --json
    PYTHONPATH=src python -m traceatlas.integrations.extreme_recon --query dns

The existing 13 governed CLI adapters for requested tools remain connected to the original TraceAtlas IntegrationRunner, case policy and evidence store. Use the pre-existing authorized IntegrationRunner only for those known adapters. Several tools require --allow-active; being in a source catalog never bypasses this requirement.

## Why not copy every upstream project directly

Large projects (including Amass, nuclei, IVRE and reconFTW) contain extensive source and dependencies. Copying all into one working Python package causes licensing, dependency, build and supply-chain problems, and cannot establish feature-level integration. Submodules preserve exact upstream code and notices without silently turning unreviewed executables into first-party modules. Users wanting ordinary tracked source files require selective, security-reviewed vendoring; older theHarvester, OSINT-SPY and Mr.Holmes were already copied under vendor_sources.

The normal CI fetches only the original seven required submodules, not all 33 optional source trees. This avoids downloading potentially large and unnecessary tools on every test job.

## Current explicit gaps

- 33 source snapshots pinned, not independently installed, executed, or live-qualified.
- nrich on GitLab remains a source listing without a confirmed full hash.
- 10 web/API services need their own policy/credential/rate-limit agreements and cannot be treated as code repositories.
- All new upstream GPL/MIT/other license obligations require review before direct code copying or combined redistribution.
- Masscan, ZMap, high-rate DNS scanners and orchestration tools remain subject to security controls or blocked.
- Per-provider fixtures, parser contracts, coverage, provenance, source independence and live authorized replay are outstanding.

Do not call catalog inclusion, Git pinning, or a green integration test evidence of a working live collector.
