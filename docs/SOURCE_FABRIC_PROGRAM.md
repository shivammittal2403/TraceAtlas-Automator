# Governed source intelligence program

The 650/600/450/300/200/125 source targets are acceptance requirements. They are
not completed integration claims. The implemented portfolio report compares
observed canonical registry and case-store data against each threshold. The
15 family minima total 645; at least five additional unique sources are needed
to meet the portfolio minimum of 650. A source receives one primary family.

## Implemented commands

```sh
traceatlas source-fabric portfolio
traceatlas source-fabric portfolio --source nvd
traceatlas source-fabric portfolio --file reviewed-research.json
traceatlas source-fabric portfolio --capability vulnerability --budget 1
traceatlas source-fabric health
traceatlas source-fabric portfolio --html dashboard.html
```

Research imports support every requested metadata field, including API/auth,
terms/license/redistribution/commercial use, geography/language, privacy/residency,
freshness/history/pagination, streaming/webhooks/bulk export, independence,
quality, capabilities and status. Unknown facts remain null. Import is atomic,
bounded to 1000 records/2 MiB, rejects duplicate identities and URL credentials,
and never imports executable code, changes an API origin, or grants collection
authority. Source maturity in imported data is ignored. Research-only records
never increase registered-source or implemented-connector counts.
The governed total additionally requires reviewed canonical documentation,
manifest/terms/license/privacy receipts, a primary family, a dataset identity,
and documented unique value or fallback justification. Family coverage counts
these governed records rather than classifying incomplete metadata as qualified.

The source ID must refer to an implementation added through normal reviewed
code and provider contracts before it contributes to registration. Discovery,
research metadata, aliases, endpoint variants, upstream packages and local
protocol primitives do not qualify a source. Distinct datasets from one provider
require documented unique value or justified fallback and separate upstream
provenance before they can be treated as independently useful sources.

## Independence, ranking and health

The graph models provider, dataset, upstream dataset, publisher and API nodes.
Shared upstream datasets collapse transitively. Missing dataset ancestry is
conservatively grouped as unknown; it cannot supply independent corroboration.
The graph does not establish that claims from different groups are true.

SourceScore is the product of the eight requested quality factors divided by
one plus the five normalized penalties. All factors must be supplied within
[0,1]. Missing factors produce a null score and a list of unknowns. These are
uncalibrated policy heuristics; no mathematical-truth or benchmark claim follows.

The portfolio planner produces four conditional waves: initial inexpensive
sources, independent corroboration, remaining specialized capabilities, and
costly/slow sources if gaps remain. It excludes undocumented sources, unknown
costs, unresolved country/language coverage, unavailable connectors and sources
whose privacy risk is not reviewed as NONE/LOW. Plans grant no execution and must
also have source-specific terms/license/privacy receipts resolved in the case
store. Recorded access obstacles exclude a source from the plan. Plans must
be dispatched through existing typed-input, authority, budget and evidence gates.
It does not query the entire catalog. Existing executable router behavior is
preserved; this research planner is separately exposed for review and adoption.

Health is calculated from the last 100 non-cache live executions per source.
It reports observed latency/failure/schema/auth/rate-limit metrics, with all
eight requested health states. Fixture calls are excluded; no automatic network
probe occurs. State older than seven days is UNKNOWN. Unmeasured quota,
evidence-capture and replay failures stay null. HEALTHY does not mean qualified.
The self-contained HTML dashboard exposes every required count independently,
reviewed family coverage, source health, maturity, last observation and recorded
obstacles. It escapes untrusted metadata and loads no remote scripts. It is an
explicit snapshot rather than a continuously polling monitor.

## Connector factory and qualification

`source_fabric.primitives` implements BaseConnector plus REST, GraphQL, RSS,
STIX, TAXII, MISP, RDAP, DNS, Search, Archive, Dataset, FileFeed and Webhook
primitives. Shared transport wraps existing reviewed fixed-host adapters.
Generic envelope decoders are bounded offline parsers; they do not imply that
a platform-specific transport has been implemented. Every instance exposes
manifest, capabilities, validate_config, health, estimate_cost, rate_limit_status,
search, fetch, normalize, extract_observations, capture_evidence, replay and close.
Unsupported searches fail explicitly. RSS rejects DTD/entity expansion; feed
decoders bound record counts; webhook decoding requires a previously preserved
authenticated payload digest and does not create an HTTP receiver.

Factory network calls require an authorization callback and recheck it for each
underlying transport request. Evidence capture uses the canonical IntelligenceHub
policy gate and EvidenceStore, preserving sanitized source assertions. Offline
replay checks captured raw-byte digests and reruns provider-specific validation
and normalization without querying current APIs. Raw evidence must have been
preserved by the canonical gateway where retention/privacy policy permits it.

A successful request now reports LIVE_TESTED until the live-verification reviews
resolve to recent, same-case preserved artifacts. Qualification additionally
requires explicit privacy, replay and intended-runtime reviews, bringing the
shared checklist to 26 gates. Production promotion rechecks custody and artifact
membership. Legacy promotions cannot bypass the expanded checklist.

## Remaining acceptance work

Official-documentation research and reviewed unique-value records for 650 sources
remain open, as do 600 mapped sources and 450 usable provider implementations.
Source-specific integration-test receipts, authorized live canaries, credentials,
licensing/terms decisions and operational runbooks are needed to establish the
300/200/125 runtime targets. Integration-tested totals stay unknown rather than
being inferred from fixture or parser tests. Required family counts use only
documentation-reviewed canonical records. The program must not be presented as
complete until both portfolio totals and all family thresholds are satisfied.

Use `blocked_reason` and a canonical `blocked_evidence` reference to record an
individual external access/legal/provider obstacle. An unimplemented connector
or missing research is open engineering work, not an external blocker. No bulk
blocked claim is made for unresearched integrations.
