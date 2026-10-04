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
