# Worker registry

`workforce/registry.py` is the canonical five-definition EmployeeRegistry.
Definitions contain version, role/domain, capabilities, allowed tools/sources/
actions, prohibitions, budget and model/escalation policies. Selection must cover
every required capability; partial-capability fallback is now rejected.

Authority and runtime tool contracts still intersect the registry's maximum
permissions. A registry capability is not live provider verification. New
specialists require a unique capability, minimum authority, measurable evaluation
and independent evidence validation; do not add roles for catalog size.

WEBINT/INFRAINT Specialist is version 1.1.0 for the added IP/approved-record
capabilities. Changed definitions invalidate previous execution approvals;
create and approve a fresh task while preserving earlier captured products.
