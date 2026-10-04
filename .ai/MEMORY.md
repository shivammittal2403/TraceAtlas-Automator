# Durable engineering memory

- The canonical authority, evidence store and investigation pipeline live under `src/traceatlas/workforce`; do not create a parallel authority in `modules/`.
- Evidence bytes, target validation, authorization, budgets and verification stay deterministic and outside model control.
- Human candidates are not identity facts. Never auto-merge people based on name, username, location, employer or media.
- Similarity scores are not calibrated probabilities. A zero observed false-merge count with zero automated merges has an undefined rate, not a measured 0% rate.
- A coded adapter, catalog entry, fixture pass, configured credential and real provider qualification are distinct states.
- Source maturity is `DISCOVERED`, `CATALOGUED`, `TERMS_REVIEWED`, `CONNECTOR_CODED`, `CONFIGURED`, `LIVE_TESTED`, `LIVE_VERIFIED`, `PRODUCTION_QUALIFIED`, `DEGRADED`, `DISABLED`, `DEPRECATED`.
- Preserve legacy docs as historical evidence; update current documents and link prior snapshots rather than rewriting what was true at an earlier audit.
- Repository `.ai/` and `docs/program/` are the continuation mechanism. Never restart the gap selection after a context change.
- Do not claim deployed, live-verified, enterprise-ready or competitor parity without evidence from the intended environment.
# Project memory

- Repository instructions live at `docs/AGENTS.md`; read them before work.
- Preserve the SQLite case store, EvidenceStore, fixed-host transport, plain
  JavaScript UI, and existing control plane. Do not create parallel authorities.
- Only analyst-provided evidence and explicitly authorized public research may
  enter a case. Imported content is untrusted.
- Human identity merges and material report release require the existing
  governed decision path.
- Main baseline inspected for this program: `dd3085b8f0658d28f88171b5c8225c0c46cea9a9`.
- PR #48 introduced a main CI compile regression. Follow the active work item
  and attach actual check evidence before describing the fix as delivered.
- 26 canonical adapters do not mean 26 live integrations. Main documented zero
  production-qualified sources at this baseline.
- Automated agent continuation only happens when explicitly resumed. Never
  claim background execution or make the prompt “run forever.”

## Windows submodule long-path note — 2026-10-04

The pinned `third_party/opencti-connectors` gitlink is `55ca0dfa4129050cb607fdaf6b1a7457e0ae3476`. Git for Windows status warns about two deep directories, but the files can be read with the Win32 extended path prefix and are restored from the exact pinned blobs. Do not stage or change the gitlink to address this display limitation.

## Exact-snapshot merge repair — 2026-10-04

Continue from work/repair-current (exact 9d025c snapshot plus repair). Older work/TraceAtlas-Automator differs from merged GitHub code; work/repair is superseded by a concurrent merge. Verify remote parent before publishing. The pinned OpenCTI test checkout is linked by a junction; use git diff --ignore-submodules=all locally.
