# API Mega List integration

TraceAtlas can import the supplied `cporter202/API-mega-list` ZIP as a searchable
discovery catalog:

```bash
./start.sh integrations catalog-import --file API-mega-list-main.zip
./start.sh integrations catalog-stats
./start.sh integrations catalog-search "threat intelligence" --limit 25
```

The importer reads only Markdown API table rows directly from the archive. It
does not extract files, execute bundled JavaScript, call listed services, install
actors, or accept a catalog entry as a connector. HTTP(S) URL validation,
archive/member size limits, tracking-parameter-aware URL deduplication, category
reconciliation and source SHA-256 provenance are enforced.

Every imported row has:

- `source: cporter202/API-mega-list`;
- `execution: catalog-only`;
- `execution_enabled_by_catalog: false`;
- `license_status: unverified`.

The upstream repository did not declare a GitHub license when reviewed on
2026-09-30. TraceAtlas therefore includes the importer and attribution, but does
not vendor or relicense the upstream catalog snapshot. Operators keep their
authorized source ZIP outside the repository and import it into their workspace.

## Promotion to a working connector

A catalog row becomes executable only through the existing source-contract
workflow: verify service identity and terms, document data provenance and lawful
use, define typed inputs and fixed hosts, keep credentials server-side, set
request/page/response/time and monetary limits, implement schema/error fixtures,
run an authorized scoped canary, and record a maintenance owner. Scrapers that
collect private data, bypass authentication, acquire credentials, or perform
unapproved active testing remain excluded.
