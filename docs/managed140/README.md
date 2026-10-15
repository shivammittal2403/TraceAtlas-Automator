# Managed140 + SpiderFoot optional integration

This is an additive namespace beneath the existing TraceAtlas canonical skill contracts. It does NOT overwrite the case manager, EvidenceStore, source fabric, existing domains, integrations, or the 136 archived legacy modules.

- 140 separate importable offline domain adapters with individual SKILL.md files.
- Common deterministic parsing/observation/contradiction runtime, sensitive-domain authorization check, report SHA-256 seal and bounded input.
- Optional adapter to existing \`traceatlas.skills.contracts.SkillResult\`.
- Read-only SpiderFoot 4.0 JSON-export parser. It DOES NOT launch scans, grant network permissions or certify SpiderFoot results.

## Execute

\`\`\`bash
PYTHONPATH=src python -m traceatlas.skills.managed140 list
PYTHONPATH=src python -m traceatlas.skills.managed140 run DOMAININT --input records.json --output report.json
PYTHONPATH=src python -m unittest discover -s tests -p test_managed140.py -v
git submodule update --init third_party/spiderfoot
\`\`\`

Sample input \`records.json\`:
\`\`\`json
{"records":[{"source_id":"fixture:1","independence_group":"fixture:1","data":{"domain":"example.org"}}]}
\`\`\`

## SpiderFoot v4.0 source

Pinned submodule: \`third_party/spiderfoot\` at commit \`0f815a203afebf05c98b605dba5cf0475a0ee5fd\` (2023-11-05), matching the supplied spiderfoot-master.zip source commit. Copyright Steve Micallef and contributors, MIT License; upstream LICENSE is preserved within submodule. Do NOT silently install all dependencies in the main TraceAtlas environment. Use its own virtualenv/container and explicitly approved scope. Import JSON exports with \`traceatlas.skills.managed140.spiderfoot_adapter.imported_records\`.

This is an older upstream snapshot. No SpiderFoot live scan, runtime upgrade, or dependency security audit is claimed.

## Critical limits

- These domain adapters are **not** the exact previously generated \`traceatlas_140\` v0.2 package or complete 419K-line uploaded original; the existing legacy recovery remains under \`extras/osint_module_recovery_20261015\`.
- Registry/catalog membership does not imply production capability or source completeness.
- Independent-source claims remain user-reported; hashes establish local integrity, not factual truth.
- No live collector, payment/telecom interception, credential extraction, sensitive identity profiling, external requests, or person-contact automation is added.
- CI and canonical end-to-end integration are separately required before merging to main.
