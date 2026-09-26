# TraceAtlas remediation status

This register prevents roadmap text, adapter counts and licensed-provider ambitions
from being reported as working capability. Status is based on executable code and
verification evidence in TraceAtlas 1.7.

## Closed in the repository

| Gap | Implemented control | Verification |
|---|---|---|
| Provider outages and schema drift | Bounded 429/5xx/transport retry, size limit, per-source JSON contracts | Mocked retry, drift and secret-leak tests |
| Identity false merges | Persistent public-label candidates, symmetric dedupe, required human rationale, no auto-merge | Resolution lifecycle tests |
| Missing analyst review lifecycle | Local resolution queue; hosted review tasks and case notes | SQLite tests, API/static UI tests, Supabase RLS assertions |
| External binary drift | SHA-256 integration lock and verification | Mutation regression test |
| Marketing ahead of runtime | Core/production/competitive readiness gates | Negative-claim regression test |
| Worker output without review handoff | One review task per completed evidence job | Cloud-worker regression test |
| Secret exposure in connector failures | Stable error codes; no URL, header or body persistence | Secret non-disclosure test and repository secret scan |
| Source depth was mostly credentialed | Five keyless fixed-host live connectors plus 1-12 source budget/circuit orchestration | Provider contract and circuit-breaker regression tests |
| IntelOwl was registry-only | Host-allowlisted service adapter with explicit analyzer/TLP constraints and evidence preservation | Mock service contract and evidence-ledger test |
| Supplied analyzer list was marketing-only | 187-entry typed module registry plus live IntelOwl config discovery and exact target-contract resolution | Inventory, remote-shape, disabled/unsupported and endpoint tests |
| Provider runs lacked per-attempt provenance | Durable source runs store fingerprints, counts, attempts, bytes, durations and stable failure codes | Success/failure history tests |
| Social results lacked a common review contract | GitHub, GitLab, Bluesky and Hacker News normalize handles, labels, links and bounded metrics without identity merging | Profile and source-run tests |
| Privileged membership lifecycle was incomplete | AAL2 owner-only role/remove RPCs, last-owner protection and serialized owner-set changes | SQL control assertions and pgTAP contract |
| AI claims lacked hard citations | Claim objects require bounded confidence and existing event IDs; OCR/transcripts carry injection labels | Citation/injection regression tests |
| Dark-web feeds lacked a structured boundary | Approved STIX/MISP/OpenCTI/IntelOwl/AIL exports reduce to fingerprints and counts; onion fetch remains disabled | Content non-retention regression test |
| Model output could fall back to opaque prose | Strict JSON field/type/size contracts; invalid advisories are rejected | Schema rejection regression test |
| Case view was fragmented | Deterministic coverage, health, timeline, review queue and next-action workspace | Local workspace regression test and RLS-backed API |
| Hosted audit/retention gaps | Append-only audit trigger, source-run provenance, retention/legal-hold RPC and request IDs | Migration marker and gateway tests |
| Invalid case-note RLS policy | Removed reference to nonexistent `assigned_to` column | Migration regression assertion |
| Bundled runtime regression blind spot | Dedicated locked OpenOSINT runtime CI job | TraceAtlas and upstream runtime have separate CI jobs |

## Partially closed

| Gap | Current boundary | What remains |
|---|---|---|
| Interactive analyst graph | Authenticated case graph plus richer bundled OpenOSINT graph | Native drag/drop transforms, saved layouts and reversible merge/split history |
| Team collaboration | Tenant RLS, roles, notes, review decisions, append-only audit and request IDs | Presence, comments/mentions, conflict resolution and notification delivery |
| External integrations | 34 governed adapters plus binary lock | Install/version matrix and five real execution-verified priority tools per deployment |
| Continuous monitoring | Durable local schedules, diffs and local alerts | Hosted scheduler, outbound notification channels and dead-letter operations |
| AI/media | Local metadata, OCR, transcription, hashes, integrity signals and schema-validated loopback model path | Benchmarked geolocation, deepfake, speaker and frame-analysis models |
| CTI | IOC/CVE/ATT&CK extraction and STIX export | Contextual NLP, campaign ontology and bidirectional MISP/TheHive/SIEM adapters |
| Enterprise operations | Supabase RLS, isolated worker, retention/legal hold, append-only audit and readiness doctor | Hosted restore drill, SSO/SCIM/MFA policy, KMS, SLA/SLO and external assessment |

## Not solvable by repository code alone

- Social Links/Recorded Future-scale coverage requires licensed datasets, provider
  contracts, collection operations and legal review.
- Private social accounts, credential access, CAPTCHA bypass, covert surveillance
  and unauthorised enumeration remain prohibited rather than "missing features".
- Vercel, Supabase and private-worker production readiness cannot be claimed until
  real resources are configured and hosted tenant/queue/recovery tests pass.
- Vendor API quotas, historical breach corpora, commercial passive DNS and dark-web
  datasets must be procured lawfully; TraceAtlas will not fabricate them.

Run `./start.sh readiness --production --json` for the current environment. A
registered adapter or source is not treated as installed or execution verified.
