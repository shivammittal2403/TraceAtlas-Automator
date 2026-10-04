# SOCMINT gap analysis

Baseline: `641f159326d45afe9797ddf5624a5126640fdd19`, 2026-10-04.

## Capability assessment

**NOT_IMPLEMENTED** as an integrated public/authorized social investigation workflow. Search adapters return leads; public GitHub organization metadata covers one narrow organization route. Neither is a general account/profile, posts, interactions or cross-platform identity workflow.

| Workflow requirement | State | Limitation |
|---|---|---|
| Public profile discovery and normalization | NOT_IMPLEMENTED as common fabric | No provider-neutral profile contract or multi-provider run |
| Alias/username correlation | NOT_IMPLEMENTED | Existing candidate-resolution service is not a social-platform crawler |
| Posts/comments/media/mentions | NOT_IMPLEMENTED as integrated workflow | No common evidence-backed collection and analysis loop |
| Public relationships/community analysis | PARTIAL primitives | Graph data model exists; no social graph acquisition/UX vertical |
| Cross-platform correlation | NOT_IMPLEMENTED | No calibrated match benchmark; identity claims remain case-local |
| Temporal and language analysis | PARTIAL primitives | Timestamps/metadata exist; no SOCMINT temporal or multilingual evaluation |
| Evidence provenance and review | IMPLEMENTED in core | Future adapters must reuse authority, capture, lineage, verification and replay |
| Restricted/private content | PROHIBITED | No bypass, credential theft, CAPTCHA circumvention, stolen sessions, private-account access or contact |

## Safe acceptance plan

Start with approved public APIs/feeds and explicitly authorized customer connectors. For each provider, review terms and purpose, minimize fields, fix host and rate limits, preserve raw response bytes, mark content untrusted, retain source lineage and timestamps, and require analyst review for identity/relationship inference. Test copied content, namesakes, same usernames, deletions, unavailable APIs, schema drift and prompt-injection text. Keep observed data distinct from inference and verification.

A future workflow must pass the Social-Links-class acceptance gate in the master prompt using repeatable accuracy/usability measurements. No parity claim is supported.
