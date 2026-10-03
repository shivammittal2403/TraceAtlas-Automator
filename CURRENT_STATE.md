# Current implementation state — 2026-10-03

Audit main: `fe51ba7b2e085038751a0de1fb546a2ec8453397`; historical requested
baseline `2a8789eb7cc401b327796e32458b9733674ecbc9` is its ancestor.

The local workforce now has an integrated typed-seed → authority → approved task
→ captured source-document bytes → observations → structured assertions → source
lineage → verification → temporal graph/timeline → draft report → offline replay
path. Person/company seeds use case-local public identifiers and approved records.
Domain/IP have fixed-host connector dispatch through the existing provider retry
and transport controls. No network pivot or model call occurs during analysis.

| Delivery state | Evidence |
|---|---|
| CODED | `workforce/documents.py`, `pipeline.py`, extended store/service/CLI |
| TESTED locally | `tests/test_investigation_pipeline.py`; G01–G12 pipeline evaluation |
| DEPLOYED | Not established for this new runner |
| Live VERIFIED | No new provider, cloud, model or entitlement validation |

Exact executed check results are recorded in `docs/IMPLEMENTATION_REPORT.md`.
`workforce golden` runs the controlled end-to-end pack. G05–G08 test shared
assertion handling, not native IOC hunting, malware execution, actor attribution
or supply-chain BOM parsing. No material report is automatically released.

The hosted workforce API retains its existing read/approve surface; this new
local runner has not been connected to a private hosted worker or UI result view.
RDAP redirects still fail closed. Broad search, semantic planning, calibrated
information gain, multi-model routing, isolated malware/DARKINT, country packs,
durable distributed workflows and production operating controls remain gaps.
See `docs/GAP_ANALYSIS.md`, `docs/ROADMAP.md` and `docs/ACCEPTANCE_GATES.md`.
