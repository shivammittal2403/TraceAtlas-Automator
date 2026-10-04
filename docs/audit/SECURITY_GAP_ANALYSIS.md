# Security gap analysis

Baseline: `641f159326d45afe9797ddf5624a5126640fdd19`, 2026-10-04. Review type: code/docs/CI review, not a penetration test.

## Addressed in main

PR #44 rejected caller-created accepted identity/causation edges in the analytical graph and removed boolean-based canonical merge. Its CI and CodeQL passed. The automated code-scanning AI job failed from monthly quota exhaustion (HTTP 402), returning no code finding.

## Open material risks

- Hosted Supabase Auth/JWT, tenant/session isolation, concurrent access and restore are not live-validated.
- Local authorization is operator-attested, not identity proofing; local administrators can alter local state.
- Source terms, privacy, retention, credentials, direct runtime behavior and paid entitlements are source-specific.
- Source text is untrusted; future social/media/model routes must not treat it as instruction.
- Per-process quotas do not protect multiple workers; a request already in flight may outlast a kill-switch change.
- Hashes identify bytes, not authorship or truth; local hash storage has no independent external anchor.

## Non-negotiable boundaries

Only analyst-provided evidence or explicitly authorized public research belongs in a case. No credential harvesting, authentication/CAPTCHA bypass, unauthorized private access, exploitation, malware execution, autonomous contact, account actions or publication. Keep the unauthenticated local service on loopback. Fixes require tests and must not weaken these controls.
