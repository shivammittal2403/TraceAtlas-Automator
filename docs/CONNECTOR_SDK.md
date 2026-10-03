# Connector contract and capture

Reuse `intelligence/contracts.py`, `provider.py`, `rdap.py` and `transport.py`.
Versioned contracts specify input types, actions, hosts, credentials, page/size/
time limits and execution state. Failures use stable codes without URLs, headers,
secrets or response bodies.

Pipeline parsers validate DNS names, RDAP exact domain/IP allocation, enrichment
provider IP, urlscan page target, exact search query, InternetDB IP and archive
rows/timestamps. Response text becomes immutable SourceDocument evidence after
shape checks, with acquisition/time/parser/provenance metadata. Eight actual HTTP
attempts including retries share a 120-second task ceiling; five seconds are
reserved for capture, analysis and commit. HTTP 429 is surfaced without retries
because reset metadata is unavailable in this transport contract.

RDAP contract v2 uses IANA bootstrap plus a reviewed registry base, with at most
two successful requests. Retries of either request consume attempts. Bootstrap
is a separate preserved acquisition without assertions. Unknown registry bases
and all redirects fail closed. The public HTTPS transport retains public DNS
validation, pinned TLS, no proxy, bounded bodies and fixed approved hosts.
SearXNG's separate direct transport permits numeric loopback HTTP `/search` only;
it bypasses proxies and DNS and cannot follow redirects.

Readiness reports environment variable names and configuration state, never keys
or invented health. Missing configuration does not poison the failure circuit.
Provider billing is unmeasured: live actual cost is unknown and request limits
are not monetary guarantees. Entitlements, deployed transport and content quality
need qualification. The full authenticate/health/search/fetch/normalize SDK is
still only partly unified.

Approved structured exports use `schema: traceatlas-structured-source/v1` and an
exact StructuredFact `facts` array. Unstructured text remains captured but its
supplied extraction cannot become SUPPORTED without a verified parser. A schema
proves what a captured record asserts, not who authored it or whether it is true.
