# Trust boundaries and attacks

Assets are authority/task digests, source bytes/custody, observations,
claim state, private case state and draft reports. Attackers may control imported
source text/facts, remote response bodies, URLs referenced by those bodies or
malicious model advice. Local DB/filesystem administrators remain trusted in
this deployment model; hashes are not protection against a full rewrite by them.

Primary chains: stale approved authority → unauthorized dispatch; copied sources
→ false corroboration; wrong-target provider response → false assertion; source
instructions → tool escalation; byte/metadata tamper → invalid replay; namesakes
→ identity merge. Dedicated negative tests cover these boundaries. Hosted
cross-tenant isolation is exercised separately in the existing PGlite shim, not
qualified on a live Supabase project. Malware escape is outside this runner.
