# Task and result contracts

TaskEnvelope binds immutable case/trace/objective/scope/authority/policy,
targets, evidence context, constraints, budget, deadline and stop conditions.
ResultEnvelope contains typed observations/claims/hypotheses, evidence/graph
references, uncertainties, lineage groups, gaps, next actions, cost and spans.

Observations must reference included evidence; claims must reference included
observations. Store checks acquisition binding. Service checks task/employee/tool
identity, authority time/scope, employee definition digest, time/spend/model
ceilings. Pipeline checks permissions and network attempts before each dispatch.
No natural-language agent conversation can grant permissions.

Distributed leases, checkpointing, cancellation propagation and cost reservations
are not implemented by these local envelopes. See FAILURE_HANDLING.md.
