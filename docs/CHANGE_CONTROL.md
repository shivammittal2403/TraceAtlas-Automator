# Change and compatibility control

This cycle is additive under workforce and preserves existing CLI/domain
commands, evidence v1 import, existing UI/API and hosted SQL. New local
workforce_products is created by the existing store initialization. No database
rows or evidence files are deleted for migration/rollback.

Task/employee changes invalidate their exact digests; approvals cannot authorize
changed definitions. Workflow/parser/policy versions are pinned for replay;
unsupported versions fail rather than silently replay with different semantics.
Disable new dispatch using the kill switch for rollback and keep historical
products/bytes readable with the qualified version. GitHub publication must be
fast-forward and based on refreshed main; production promotion stays separately
gated by CI/CodeQL/staging proof.
