# Complete external cybersecurity skill source import

## Exact origin and provenance

User upload: `skills(2).zip`, SHA-256 `f5d170a3ea41f92f7c528cf0527878b540931190ac094d84766718014d2853f8`. It contains 818 skill folders, 817 primary `SKILL.md` files, 4,483 files and 1,096 `.py` scripts. The single missing SKILL.md is `detecting-fileless-malware-techniques/SKILL.md`.

The original source matches <https://github.com/mukul975/Anthropic-Cybersecurity-Skills> at commit `54a798831d2266a3ca61ce68a7acb80b81160d57` (Git subtree `82fac49869491010960184cbdbbe91cf668148d5`) after restoring that one file. File contents and directory Git tree hashes were checked, not inferred from names.

**Destination:** `vendor_sources/anthropic_cybersecurity_skills/skills/` with all original directory/file names and byte contents preserved, including Markdown, LICENSEs, assets, Python, PowerShell and YARA. This vendor tree is intentionally outside the installable `src/traceatlas` package and outside automated collection. It has no execution authority.

## Usage

```bash
python -m pip install .
traceatlas-employees external-skills --query dns --limit 50
traceatlas-employees external-skill analyzing-dns-logs-for-exfiltration
traceatlas-employees external-skills --directory vendor_sources/anthropic_cybersecurity_skills/skills
traceatlas-employees skills
```

The native 140 employee procedures remain separate. Imported external skills are **untrusted source references**, not executable tools or independent live source integrations. Inspect scripts and obtain case-specific authorization before building any narrowly scoped adapter. Credential access, exploitation and interception instructions have no active AI routing. Preserve licensing/attribution for downstream distribution.

## Verification and known caveats

- Upstream Git commit and entire skills subtree are pinned, checked before and after import.
- Vendor includes one restored file that was absent from the uploaded ZIP (apparently omitted/quarantined); original 4,483 files remain identical.
- The existing secret scanner keeps detecting newly introduced credentials. Twelve known public examples that resemble keys are excepted **only if the entire source file SHA-256 remains exactly pinned**; modifications re-enable scanning. Do not regard examples as live secrets.
- These 1,096 scripts have **not** been individually tested or approved for execution. Their presence in GitHub is not evidence of correct functionality.
- Docker/Vercel build contexts exclude vendored files to avoid shipping unrelated code.
