# TraceAtlas Agentic Skills Library (vendored)

The complete user-supplied `agentic-awesome-skills-main.zip` snapshot is vendored as a **read-only reference and development library** in `integrations/traceatlas-agentic-skills-library/`.

## Exact provenance and rename

- Branded TraceAtlas directory: `integrations/traceatlas-agentic-skills-library/`
- Original upstream: [sickn33/agentic-awesome-skills](https://github.com/sickn33/agentic-awesome-skills)
- Original pinned upstream commit: `7226f92e6a9856ec8fbf1a36c5ced82d83d079aa`
- Upload and upstream Git tree SHA-1: `6e20651981402fd927784adfc834c02ca3bd51be`
- Source archive SHA-256: `ad7b17698a1d810856f8d058027a2d78b060c598c5ead7fe9e83e7f68c0d2ccc`
- Source version metadata: **19.7.0** (with later prerelease references in the changelog)
- Includes **26,731 files**, **328,931,068 uncompressed bytes**, **7 internal symbolic links** and **2,705 `SKILL.md` files under the canonical `skills/` tree**. These include 2,600 directly under `skills/<id>/SKILL.md`.
- Original `LICENSE` is preserved; third-party skill content may have additional licenses or source conditions.

All original file names, relative paths, symlinks, execution mode bits and contents are preserved under the **renamed parent directory**. This deliberately avoids breaking relative links, plugin manifests, bundled asset references and provenance.

## TraceAtlas trust boundary

**Presence of a skill is not authorization to execute it.** All imported documents, code, scripts, marketplace manifests, extension packages and upstream `.github/workflows` are untrusted *reference assets*, not trusted TraceAtlas instructions.

- They do not automatically load as TraceAtlas runtime procedures, policies, tool permissions, AI employees or admin actions.
- Neither a model nor a user-supplied `SKILL.md` grants filesystem, browser, network, credential, endpoint or shell execution privileges.
- Do not run vendored `install` scripts, network collectors, package lifecycle hooks or third-party code merely because it is present.
- Individual skills require human review, a pinned source, license/security assessment, capability scoping, tests, approvals and case/evidence boundary enforcement before promotion into the canonical TraceAtlas skills engine.
- This import makes **zero automatic external requests** during application operation.

The prior `awesome-osint-repos` snapshot is already integrated separately under `integrations/awesome-osint-repos/`. The second user-provided archive matches that existing pinned source tree byte-for-byte; duplicating it would add clutter, not functionality.

## Reproducible integrity/testing checks

The source import CI verifies the exact upstream tree SHA, all 26,731 file paths, count, source bytes, symlink safety, canonical skill count, sample frontmatter and Python syntax scan (excluding intentional templates). The full TraceAtlas pull-request CI runs separately to detect regressions.

### Known upstream findings

- One canonical playbook, `skills/video-content-extractor/SKILL.md`, lacks standard `---` frontmatter.
- Three copies of `fastapi-router-py/assets/template.py` contain template placeholder syntax and are *not importable executable Python*.
- 2,705 bundled skills are not equivalent to 2,705 audited or working TraceAtlas integrations.
- No claims are made of production provider access, live collection, or enterprise qualification for these bundled third-party skills.

## Review and activation workflow

1. Identify the desired file in `integrations/traceatlas-agentic-skills-library/skills/`.
2. Review license, dependencies, threat model, external endpoints, commands, required secrets and prompt-injection exposure.
3. Implement a TraceAtlas-native governed procedure in `src/traceatlas/skills/` or a validated adapter, preserving upstream attribution.
4. Write deterministic unit, integration, replay, permission and negative tests.
5. Promote only the reviewed adapter through existing TraceAtlas CI and approvals.

**Do not bulk-register all skill files as executable agents.**
