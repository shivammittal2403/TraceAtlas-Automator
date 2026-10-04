# Changed-path security review — 2026-10-03

Scope: local workforce service/store/registry/tool facade, source records,
collection pipeline, lineage, verification and replay; existing hosted API and
RLS reviewed for compatibility. This is a bounded code/fixture review, not an
independent penetration test or a clean production security certification.

| Finding | Severity / confidence | Prior path and preconditions | Impact | Remediation / proof |
|---|---|---|---|---|
| Approved authority not rechecked at execution | Medium / confirmed | `workforce/service.py`; task approved before expiry | Late collection outside registered time | Issuance/expiry/deadline/actor/case/scope checks before execution and each request; expiry regression |
| Cached kill switch | Medium / confirmed | Long-lived service created while enabled | Emergency operator stop does not prevent new work | Dynamic environment kill check; dispatch regression |
| Partial capability fallback | Medium / confirmed | `registry.py`; required capabilities only partially covered | Task routed to worker lacking capability | Require complete capability coverage; negative routing test |
| Missed transitive origin/copy links | Medium / confirmed | `lineage.py`; owner/upstream chain across grouped records | Corroboration overcount | Pairwise connected components; direct upstream/common publisher/empty/order tests |
| Tool argument nested secrets/scope | Medium / confirmed | `tools.py`; secrets nested below top level or wrong target | Sensitive forwarding or wrong-scope handler call | Recursive field/nesting rejection and scope/time checks; blocked-handler tests |
| Reference-only evidence check | Medium / confirmed | Direct verifier receives valid-looking hash/object references | Tampered bytes could retain favorable status | New runner always supplies store byte/metadata/case validator; raw/product/result/metadata tamper tests |
| Supplied semantic assertion accepted from substring | Medium / confirmed in initial implementation cycle | Source contains value but no verified subject/predicate extraction | False support of unrelated text | Fixed provider parser or exact structured-source assertion required; otherwise INCONCLUSIVE regression |

Capture data has no instruction authority. The runner calls anonymous or explicitly configured,
fixed-host read-only providers and performs no network pivots/model calls/identity
merges/report release. Wrong-target DNS/RDAP/IP/archive records fail before claims.
Results use stable error codes; provider messages/headers/query-secret strings are
not copied into failure telemetry. Secret scanning passed on repository source.

Existing hosted workforce tables enable RLS, explicitly revoke client writes and
grant tenant-visible reads; approval is a narrow actor/case/digest-checked function
with explicit empty search path and revoked PUBLIC/anon execution. Existing
PGlite/Auth-shim tests cover synthetic cross-tenant denial and replay; no live
Supabase Auth/JWT/storage/concurrent production validation is claimed. No hosted
API/table grants or schema were changed. Review combined grants/RLS rather than
assuming row policies alone control API exposure; official methodology references:
[Supabase API security](https://supabase.com/docs/guides/api/securing-your-api) and
[database testing](https://supabase.com/docs/guides/database/testing).

Residual gaps: local authority is operator attestation, not identity proofing or
ownership verification; local OS administrators can rewrite data and hashes;
source lineage/ownership may be incomplete; hashes prove integrity, not author
identity; dynamic kill does not interrupt a request already in flight; capture is
not atomically transactional with every derived index; hosted leases/resume/
cancellation, encryption/KMS, immutable storage, independent adversarial semantic
search and remote model cost reservations remain unqualified. The existing generic
model router's full spend/fallback/provider-output guarantees were not remediated
by this no-model runner. Malware isolation was not tested because no specimen runs.

## Live-source extension

RDAP uses IANA bootstrap intersected with exact reviewed HTTPS bases; all redirects
remain rejected. Public provider DNS/IP/TLS checks remain unchanged. SearXNG is a
separate numeric-loopback-only `/search` transport without proxy, hostname lookup,
credentials or redirect handling. Tests reject private/unreviewed bootstrap bases,
wrong targets/queries, loopback escape, compression and oversized responses.

Source IDs are immutable task constraints covered by approval. Current authority
and kill state are checked on both bootstrap and registry dispatch; cancellation
is not downgraded to a source failure. Completion also rechecks the kill switch.
Configured keys enter server-side request headers/query construction only, not
plans, reports or failure telemetry. Search URLs are preserved leads and never
fetched. Actual provider billing remains unknown. Fixture tests and proxy-based
public reference collection do not qualify the deployed direct transport or a
real SearXNG/Brave service. No hosted schema, API grant or worker deployment changed.


## Enterprise audit follow-up — 2026-10-04

At baseline `d698ed519be078ec72092b33dacda9f92ffdb42c`, confirmed P0:
`TemporalClaimGraph.add_edge` treated a caller-supplied `ACCEPTED` value as human
acceptance for `same_as`, `identity_merge` and `caused` relationships. The
graph has no authorization context or durable review-decision lookup, so that
check did not prove that a reviewer acted. A related helper could set
`canonical_merge` from a boolean argument alone. The PR fix closes both paths:
the graph rejects accepted identity/causation edges, and the helper never changes
canonical state. Analyst decisions continue through the existing authorized
`ResolutionService`; this does not create global identity truth. Regression
coverage checks the sensitive edge types and caller-supplied acceptance.

Review status: code changed; regression tests added; CI result pending. This is a
focused code review, not a penetration test, and does not qualify the hosted
identity or analyst-authentication environment.
