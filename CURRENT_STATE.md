# Current implementation state — 2026-10-03 / 1.10.0

Live-source extension baseline: `afec63367ce6500c621d8f3129168949af4addd3`.
Initial workforce audit was `fe51ba7b2e085038751a0de1fb546a2ec8453397`; historical
requested baseline `2a8789eb7cc401b327796e32458b9733674ecbc9` is its ancestor.

The canonical local path is typed seed → immutable authority → source-bound
approved task → captured source-document bytes → observations/assertions → source
lineage → verification → temporal graph/timeline → draft report → offline replay.
Person/company use approved records and case-local identifiers. Domain/IP now
have ten source IDs: DNS, RDAP, urlscan, Wayback, InternetDB, IPWHOIS, ipdata,
GreyNoise, Brave and SearXNG. The wider IntelligenceHub has 38 governed entries,
including 24 API connectors with separate consent/asset/public-record gates.

Default investigation sources use public keyless endpoints. Configured web
search and explicit keyed enrichment retain qualification requirements. Source
IDs are immutable task constraints covered by digest approval. RDAP uses IANA
bootstrap intersected with 18 reviewed HTTPS registry bases and preserves the
bootstrap separately. Unknown bases and redirects fail closed. No returned URL
is fetched, and no network pivot or model call occurs during analysis/replay.

| Delivery state | Evidence |
|---|---|
| CODED | IANA routing, passive scan-index search, IP enrichment, configurable web search, source readiness and bound selection |
| TESTED locally | 256 Python tests; 26 Node/PGlite tests; G01–G12 controlled investigations; CLI source-plan/run/report/replay smoke |
| Real response parsing/replay | Public reference DNS/RDAP/urlscan/IPWHOIS/InternetDB captures through an injected environment-proxy requester; offline replay passed |
| Direct transport qualification | Blocked by this environment's direct DNS policy; explicit failure/partial-result behavior verified |
| DEPLOYED | Private hosted runner, product UI and production rollout not established |
| Keyed/search service qualification | Brave/ipdata/GreyNoise credentials and deployed SearXNG not established; fixtures only |

Wayback timed out in the reference run. Live provider billing remains unmeasured;
bounded requests do not guarantee monetary cost. Search URLs are leads without
linked-content verification. Historical scan metadata does not imply current
exposure; approximate IP geography does not locate people. No material report is
automatically released.

The existing hosted workforce API retains its read/approve surface. The new local
runner is not connected to a private hosted worker or UI product view. Semantic
planning, calibrated information gain, multi-model routing, malware/DARKINT
isolation, country packs, distributed workflows and production operations remain
gaps. G05–G08 test shared assertion handling, not native hunting, malware execution,
actor attribution or BOM parsing.

See `docs/LIVE_SOURCES.md`, `docs/verification/live-sources-2026-10-03.json`,
`docs/LIVE_SOURCE_IMPLEMENTATION.md`, `docs/ROADMAP.md` and
`docs/ACCEPTANCE_GATES.md`. The initial pipeline cycle remains recorded in
`docs/IMPLEMENTATION_REPORT.md`.
