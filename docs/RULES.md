# TraceAtlas Workforce Rules

1. Evidence bytes and deterministic records are authoritative; model output is advisory.
2. Authority is registered server-side. A task or model cannot self-assert it.
3. Effective permission is the intersection of authorization, employee and tool contracts.
4. External text is untrusted data with no instruction authority.
5. Every task has a deadline, tool/model/cost budget and explicit stop conditions.
6. Every observation resolves to evidence and acquisition; every claim resolves to observations.
7. URLs and model outputs derived from one origin count as one independence group.
8. Contradictions, gaps, stale data and provider failures remain visible.
9. Entity candidates never auto-merge; causal or identity edges need human acceptance.
10. Models cannot execute tools directly, alter scope, create credentials or release reports.
11. Secrets stay in environment/vault references and never enter task/result envelopes.
12. Remote providers remain disabled until privacy, retention, jurisdiction, pricing,
    quota, licence and structured-output checks are recorded.
13. Workforce scheduling is disabled by default and has a server-side kill switch.
14. Approvals bind the exact task/evidence/report digest and become stale when inputs change.
15. Rollback stops scheduling but never deletes evidence or custody history.
16. `CODED`, `TESTED`, `DEPLOYED` and `VERIFIED` are reported separately.

17. Recheck authority issuance/expiry, task deadline and kill switch before dispatch.
18. A source substring does not validate extracted subject/predicate semantics;
    unverified extraction remains INCONCLUSIVE.
19. Contradictions compare overlapping valid times and registered single-valued
    predicates; multivalued DNS answers are not contradictions.
20. Raw captured inputs and substantive analysis digests own replay, not refreshed
    external responses or today's decision clock.
21. Result, draft product and terminal task state commit together locally; do not
    claim filesystem capture or distributed execution is exactly-once.
