# Connector contract and capture

Reuse `intelligence/contracts.py`, `provider.py` and `transport.py`.
Versioned source contracts specify implemented input types, actions, hosts,
credentials, page/size/time limits and truthful execution state. Provider errors
are stable codes without URLs, headers, secrets or response bodies.

Pipeline adapters validate DNS question/answer target, RDAP exact domain or IP
allocation range, InternetDB IP and archive domain/row/timestamps. Responses are
captured as SourceDocument content after provider shape checks; every capture
has acquisition/time/parser/provenance and immutable bytes. Up to eight actual
network attempts share a 120-second task ceiling; retries consume attempts.

RDAP bootstrap redirects still fail closed. Entitlements, real provider health
and source content quality remain externally unverified. The master brief's full
authenticate/health/search/fetch/normalize SDK interface is only partially unified.

Approved structured exports encode source assertions as JSON with
`schema: traceatlas-structured-source/v1` and a `facts` array using the exact
StructuredFact fields. Unstructured text remains captured but its supplied
extraction cannot become SUPPORTED without a verified parser. This schema proves
what the captured record asserts, not who authored it or whether it is true.
