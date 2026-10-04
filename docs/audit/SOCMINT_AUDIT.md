# SOCMINT capability audit

Audit baseline: `d698ed519be078ec72092b33dacda9f92ffdb42c`, 2026-10-04.

## Capability status

**NOT_IMPLEMENTED** as an integrated social-platform investigation workflow. TraceAtlas has public search leads and public GitHub organization metadata among its narrower tools, but these do not establish a social account discovery, cross-platform identity analysis or social evidence workflow.

| Requirement | Status | Evidence / limitation |
|---|---|---|
| Public source search lead | PARTIAL / IMPLEMENTED | Search adapters may return URLs; links are leads, not automatically fetched or attributed |
| Public GitHub organization metadata | IMPLEMENTED | Explicit public org route; does not represent personal account investigation |
| Approved profile/post collection | NOT_IMPLEMENTED as a general workflow | No common multi-network provider and evidence contract demonstrated |
| Cross-platform identity correlation | NOT_IMPLEMENTED | Existing entity candidates are case-local and require human review |
| Relationship and timeline analysis | PARTIAL | Graph primitives exist; no integrated social case vertical or golden evaluation |
| Private, authenticated or access-controlled data | PROHIBITED | No login, bypass, credential harvesting, contact, private-group access or account action |
| Evidence capture and source citations | IMPLEMENTED in canonical pipeline | New social connectors must use existing authority, acquisition, evidence and replay services |

## Safe implementation gate

Any future SOCMINT work must require documented case authority, public/approved source allowlists, minimum-necessary collection, fixed-host and rate limits, evidence preservation, provenance and lineage, untrusted-content handling, uncertainty labels, source terms review, collision/false-attribution evaluation, and analyst review. Search URLs remain unverified leads. No connector is called implemented until its code path, tests and runtime evidence exist.

No claim of Social Links parity is supported by this audit.
