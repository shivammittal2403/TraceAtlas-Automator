# Security audit

Audit type: bounded repository/code-path review; baseline `d698ed519be078ec72092b33dacda9f92ffdb42c`; 2026-10-04. This is not a penetration test.

## Confirmed P0 at baseline

In `src/traceatlas/workforce/graph.py`, `TemporalClaimGraph.add_edge` permitted `same_as`, `identity_merge` and `caused` when `decision_state == "ACCEPTED"`. The state was supplied directly on a caller-constructed dataclass. No authorized review record, actor binding, case digest or server-side decision lookup was required. `identity_candidate(..., human_accepted=True)` also let a caller-selected boolean set `canonical_merge`. Thus graph data could represent an accepted identity/causal assertion without evidence of authorization.

## Remediation in current PR

- Reject accepted identity and causation edges at construction, irrespective of caller-supplied status.
- Keep those relationship types out of the analytical claim graph; record analyst choices via the existing authorized ResolutionService.
- Ensure the graph candidate helper cannot set canonical merge from a boolean.
- Add regression tests for the sensitive relationship names, accepted state and boolean acceptance path.
- Status: CODED; PR #44 CI and CodeQL passed after the audit report was drafted; merge pending.

## Other material boundaries

Existing security documentation reports local operator-attested authority (not identity proofing), no live Supabase Auth/JWT or tenant recovery validation, incomplete source lineage and an in-flight kill-switch limitation. Public source content is untrusted. Local administrators can rewrite local data even where hashes detect byte changes. Hashes establish byte identity, not source authorship or claim truth.

Security principles retained: case evidence authorization, immutable-in-meaning correction records, explicit claim/observation/inference/hypothesis/allegation/unknown labels, no credential harvesting, auth bypass, exploitation, malware execution, autonomous contact, account actions or publication; loopback-only server until authentication and tenant isolation exist.
