# External 817 cybersecurity skills ZIP (reference-only integration)

The user-supplied archive \`skills(2).zip\` was inspected. It contains 7,225 ZIP entries (including directories), 817 valid \`SKILL.md\` procedures, 1,096 Python source scripts and one additional folder (\`detecting-fileless-malware-techniques\`) without a primary \`SKILL.md\`. Its SHA-256 is \`f5d170a3ea41f92f7c528cf0527878b540931190ac094d84766718014d2853f8\`. This analysis describes the user-provided bytes only; the archive itself is **not** committed to GitHub by this PR.

## Commands

Provide the ZIP explicitly. Nothing is fetched or run in the background.

\`\`\`bash
traceatlas-employees external-skills --archive "/path/to/skills(2).zip" --query threat-intelligence --limit 25
traceatlas-employees external-skill investigating-public-dns --archive "/path/to/skills(2).zip"
python -m unittest tests.test_external_skills -v
\`\`\`

Use a real slug listed by the catalog for \`external-skill\`. The reader validates archives against ZIP traversal, unsafe path aliases, case-insensitive duplicate names, symlinks, encrypted members, size limits, compression bombs, malformed frontmatter and mismatched identifiers. Importing never executes \`scripts/*.py\` or any commands embedded in the supplied documentation.

**Integration boundary:** these 817 third-party procedures remain \`UNTRUSTED_REFERENCE_ONLY\` and cannot become native TraceAtlas employee authority, executable tools, automatic source collectors or production-qualified skills. The existing 139 domain employees plus OSINT continue to use their previously verified canonical \`SKILL.md\` and evidence/approval pipeline. Human review is required before any further capability promotion. In particular credential extraction, exploitation and subject-contact instructions must not be granted unrestricted agent execution.

Archive bytes must be supplied to an authorized operator's runtime, under its own approved storage/retention controls. This repository change only adds the safe discover/preview integration and regression tests.
