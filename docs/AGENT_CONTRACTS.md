# Task and result contracts

TaskEnvelope binds immutable case/trace/objective/scope/authority/policy,
targets, evidence context, constraints, budget, deadline and stop conditions.
ResultEnvelope contains typed observations/claims/hypotheses, evidence/graph
references, uncertainties, lineage groups, gaps, next actions, cost and spans.

Observation, claim, hypothesis and trace-span IDs are unique within their own
collections. Observations must reference included evidence; claims must reference
included observations. Every listed hypothesis and span evidence reference must
also occur in the result evidence header.

Before completion, the store resolves that header to canonical evidence in the
task's case, checks both evidence lookup keys, object digests and preserved bytes,
and verifies the canonical acquisition's source, method and retrieval timestamp.
Observation acquisitions must match their resolved evidence; spans must carry the
task trace. These checks also apply when no draft product is supplied, before
result/product/outbox writes. Empty deterministic results and prior same-case
evidence remain supported. Malformed historical results now fail closed on read.
These checks establish structural/custody binding, not factual support or source
authenticity. Service checks task/employee/tool
identity, authority time/scope, employee definition digest, time/spend/model
ceilings. Pipeline checks permissions and network attempts before each dispatch.
No natural-language agent conversation can grant permissions.

Distributed leases, checkpointing, cancellation propagation and cost reservations
are not implemented by these local envelopes. See FAILURE_HANDLING.md.
