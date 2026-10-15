# Offline case management for Managed140

140 specialist modules are grouped under the existing 11 case-relevant domain families. The canonical TraceAtlas workforce retains all real source, policy, acquisition, case-store and report-release authority.

\`\`\`bash
PYTHONPATH=src python -m traceatlas.skills.managed140.workforce \
  --input records.json --case-id demo-case --goal "corporate ownership" \
  --output case.json
PYTHONPATH=src python -m unittest discover -s tests -p 'test_managed140*.py' -v
\`\`\`

Manager performs bounded deterministic selection (default max 12 domains), groups by family, runs only supplied-evidence analyzers and seals a case-level integrity receipt. A sensitive module is not auto-selected without an explicit domain-level authorization assertion; explicit selection without permission results in BLOCKED.

This is **not** an autonomous AI employee network worker or a live SpiderFoot collector. Do not directly persist results as verified case facts: feed them through existing canonical evidence contracts after approval.
