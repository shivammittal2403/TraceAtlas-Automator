# Reviewed trust boundaries

The new runtime enforces registered actor/case/scope/policy/digest authority,
current issuance/expiry/deadline, dynamic kill switch and per-dispatch permissions.
Only fixed-host anonymous providers are used. Existing HTTPS transport pins a
public DNS destination, validates TLS and refuses redirects/proxies/compression.
Source data cannot execute code, install tools, grant authority or release drafts.

Stored task/result/product/evidence metadata digests, case/acquisition links,
raw bytes and custody are checked. Tool arguments reject nested secret fields.
Local records depend on OS/workspace access control; they are not an OIDC tenant
boundary or digitally signed source authorship. No new hosted SQL/API privilege
is granted. See SECURITY_REVIEW.md for confirmed fixes and residual gaps.
