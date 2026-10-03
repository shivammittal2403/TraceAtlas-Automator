# Source strategy

Prefer implemented official/public read-only providers governed by source
contracts. Domain defaults are DNS, IANA-routed RDAP, urlscan search and Wayback
CDX. IP defaults are RDAP, IPWHOIS, InternetDB (IPv4) and urlscan search. Explicit
IP selections can also use ipdata and GreyNoise. Person/company records require
approved provenance, exact subject scope and review. Source text cannot become
a fetch instruction.

Brave and numeric-loopback SearXNG are bound search adapters. Configure one before
authority registration and planning. Source IDs become immutable task constraints
covered by digest approval. Missing keys/service configuration, timeouts, rate
limits and empty responses remain visible. Search listings are leads, not
verification of linked content. No returned URL is fetched. Secret values never
enter plans. Additional keyed sources require explicit selection and qualification.

RDAP downloads IANA's exact DNS/IPv4/IPv6 bootstrap file and intersects the longest
matching service with reviewed HTTPS registry bases. Bootstrap bytes are preserved
even if routing fails. Unknown bases and all redirects remain blocked. Catalogs,
country URLs, OpenCTI packages and model names do not imply executable or qualified
sources. License/ownership, freshness and independence remain reviewer duties.

See [LIVE_SOURCES.md](LIVE_SOURCES.md) for setup and qualification boundaries.
