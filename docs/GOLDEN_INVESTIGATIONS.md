# Controlled end-to-end pack

`workforce golden` executes twelve controlled investigations through case,
authority, approval, capture, analysis, draft and replay. Pack source:
`workforce/data/pipeline_investigations.json`; evaluator: `workforce/golden.py`.

| ID | Scenario | Qualification |
|---|---|---|
| G01 | Person label | Approved records, no identity merge |
| G02 | Company country | Structured source corroboration |
| G03 | Domain resolution | Controlled DNS assertion |
| G04 | IP port metadata | No actual target probing |
| G05 | IOC assertion | Backbone only; no new CTI hunting |
| G06 | Malware assertion | Inert text; no specimen execution |
| G07 | Actor assertion | No attribution decision |
| G08 | Supply dependency | Backbone only; no BOM parser |
| G09 | Conflicting countries | Both claims disputed |
| G10 | Namesake identifiers | Review required, no merge |
| G11 | Provider outage | Fixture transport, partial evidence and bounded retries |
| G12 | Source prompt injection | Data preserved; INCONCLUSIVE; no tool escalation |

All source domains ending `.example` and identity labels are synthetic. The live
mode in G11 uses an injected fixture transport; it performs no Internet calls.
Every fixture validates captured-byte offline replay and zero material release.
