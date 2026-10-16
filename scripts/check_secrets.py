#!/usr/bin/env python3
"""Fail CI when common credential formats are committed."""

from __future__ import annotations

import re
import sys
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git", ".venv", ".openosint-test-venv", ".traceatlas", "build", "dist",
    "cases", "__pycache__", "node_modules",
}

# Exactly pinned third-party public examples that intentionally resemble credentials.
# Do not ignore any changed bytes or unrelated files: those still fail the scan.
KNOWN_VENDOR_SAMPLES = {
    "vendor_sources/anthropic_cybersecurity_skills/skills/deploying-ransomware-canary-files/scripts/agent.py": "70626a4f30e74d9a58519a1431a788c1fab7725c77bd4e18941f22f8c26e101d",
    "vendor_sources/anthropic_cybersecurity_skills/skills/detecting-aws-credential-exposure-with-trufflehog/references/api-reference.md": "5f513515e35a92c800c303d8489c3e28ec745197a12ac3ef64ebab5376fd98e0",
    "vendor_sources/anthropic_cybersecurity_skills/skills/detecting-aws-credential-exposure-with-trufflehog/SKILL.md": "aafe742fca6245cdaaf75366e6a1f3a2062ecc70727150661efe324bf952a641",
    "vendor_sources/anthropic_cybersecurity_skills/skills/detecting-compromised-cloud-credentials/references/api-reference.md": "7636302b9d9b4e634e02bc0479b45171adf66f832755b974fa63b6dc6162dd8e",
    "vendor_sources/anthropic_cybersecurity_skills/skills/detecting-cryptomining-in-cloud/SKILL.md": "401b2b47c9c753aa2d2e9344a49cb69818dd3d40fd6369ab10b1fa7f220d8611",
    "vendor_sources/anthropic_cybersecurity_skills/skills/implementing-canary-tokens-for-network-intrusion/SKILL.md": "91478d919212791e38629117928269803ec605801a59aa3c356a753364aef71c",
    "vendor_sources/anthropic_cybersecurity_skills/skills/implementing-honeypot-for-ransomware-detection/scripts/process.py": "434e18183034c7ad4fd39957f227659ffac6e622f61e2facd8fa779f39bcaddf",
    "vendor_sources/anthropic_cybersecurity_skills/skills/implementing-llm-guardrails-for-security/references/api-reference.md": "37fcb04bab7b12727dbb08537c675d2bcdec77a48a093a696fa70946a674bbce",
    "vendor_sources/anthropic_cybersecurity_skills/skills/implementing-secret-scanning-with-gitleaks/assets/template.md": "9823e7b3ea0bbf35d1cd987b0fd4bbbd9c0ce04d8b4c172099832c96e7c75801",
    "vendor_sources/anthropic_cybersecurity_skills/skills/implementing-secret-scanning-with-gitleaks/references/api-reference.md": "4320f48b138106322a0a4d1ebb708a909e8f67781894e91956aa74eae561320e",
    "vendor_sources/anthropic_cybersecurity_skills/skills/performing-cryptographic-audit-of-application/scripts/process.py": "76ecc404d9fecf47119ccc5f7000ee0fabfcc6001f1147a4da09097bbacfc8d8",
    "vendor_sources/anthropic_cybersecurity_skills/skills/testing-for-sensitive-data-exposure/references/api-reference.md": "f10e1d9dacbff59ca936fca16938faf17d6a4bbc16632919163d33535f4d3279",
}

# Only explicitly reviewed public training examples from the immutable upstream tree.
# Any changed byte invalidates a pin and must be reviewed again. No directory-wide exclusions.
KNOWN_VENDOR_SAMPLES.update({
    "integrations/traceatlas-agentic-skills-library/docs/maintainers/full-repo-audit-2026-05-23.md": "e11922219e9aa7371ec0eab6deb6c0a91256118ff117e52cf94b64e8b7b58e3e",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills-claude/skills/argocd-gitops/SKILL.md": "b1100bb899a6f0ebefed4cc2dd6cbde9cb637b084e1c9258deffb7a68edf3489",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills-claude/skills/cloud-iam-deep/SKILL.md": "0efa5e2f8211b0b024e202b2dc10141ca3cc3dd49ad767fcdec75c3fe60f9c56",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills-claude/skills/comfyui-gateway/references/integration.md": "ada39508446ca392b2d52b5c3e353e9d7c6d30d8d2be78c80234d383c474ce9a",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills-claude/skills/offensive-osint/references/helpers-and-automation.md": "33afbf50ffe66ab4183133d0a97f542796aaf7003ba0565720536634c71e1f2a",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills-claude/skills/offensive-osint/references/secret-patterns.md": "6215d215a7d13be433db27bbd82e873b28e8403260e68a5c9c225aecb1a3f592",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills-claude/skills/rclone-cli/references/providers/sftp.md": "cb8965104586336e45100c6f738906823406ac35b99d508a26cbb1076b3e3ddc",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills/skills/argocd-gitops/SKILL.md": "b1100bb899a6f0ebefed4cc2dd6cbde9cb637b084e1c9258deffb7a68edf3489",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills/skills/cloud-iam-deep/SKILL.md": "0efa5e2f8211b0b024e202b2dc10141ca3cc3dd49ad767fcdec75c3fe60f9c56",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills/skills/comfyui-gateway/references/integration.md": "ada39508446ca392b2d52b5c3e353e9d7c6d30d8d2be78c80234d383c474ce9a",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills/skills/offensive-osint/references/helpers-and-automation.md": "33afbf50ffe66ab4183133d0a97f542796aaf7003ba0565720536634c71e1f2a",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills/skills/offensive-osint/references/secret-patterns.md": "6215d215a7d13be433db27bbd82e873b28e8403260e68a5c9c225aecb1a3f592",
    "integrations/traceatlas-agentic-skills-library/plugins/agentic-awesome-skills/skills/rclone-cli/references/providers/sftp.md": "cb8965104586336e45100c6f738906823406ac35b99d508a26cbb1076b3e3ddc",
    "integrations/traceatlas-agentic-skills-library/skills/argocd-gitops/SKILL.md": "b1100bb899a6f0ebefed4cc2dd6cbde9cb637b084e1c9258deffb7a68edf3489",
    "integrations/traceatlas-agentic-skills-library/skills/cloud-iam-deep/SKILL.md": "0efa5e2f8211b0b024e202b2dc10141ca3cc3dd49ad767fcdec75c3fe60f9c56",
    "integrations/traceatlas-agentic-skills-library/skills/comfyui-gateway/references/integration.md": "ada39508446ca392b2d52b5c3e353e9d7c6d30d8d2be78c80234d383c474ce9a",
    "integrations/traceatlas-agentic-skills-library/skills/offensive-osint/references/helpers-and-automation.md": "33afbf50ffe66ab4183133d0a97f542796aaf7003ba0565720536634c71e1f2a",
    "integrations/traceatlas-agentic-skills-library/skills/offensive-osint/references/secret-patterns.md": "6215d215a7d13be433db27bbd82e873b28e8403260e68a5c9c225aecb1a3f592",
    "integrations/traceatlas-agentic-skills-library/skills/openclaw-local-mac-mini/SKILL.md": "4d1ee8bdb74caeec3915e598a3c2a9d77cb95b3450250f2d950eb9513651917b",
    "integrations/traceatlas-agentic-skills-library/skills/rclone-cli/references/providers/sftp.md": "cb8965104586336e45100c6f738906823406ac35b99d508a26cbb1076b3e3ddc",
    "integrations/traceatlas-agentic-skills-library/tools/scripts/tests/docs_security_content.test.js": "ae2fe326cc75f0428169827613c2d11f7683de4cc1f162e4f8cd76edcfc7815c",
    "integrations/traceatlas-agentic-skills-library/tools/scripts/tests/test_skill_scanner_report_boundaries.py": "0bc1b3070da343779411e6e1b1bf4f59339220c40409ad69f0f9b6ab18d9b0e6",
})

SKIP_PREFIXES = {("third_party", "opencti-connectors")}
PATTERNS = {
    "GitHub token": re.compile(rb"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})"),
    "OpenAI-style key": re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Supabase secret key": re.compile(rb"\bsb_secret_[A-Za-z0-9_-]{20,}\b"),
}


def files() -> list[Path]:
    result = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in parts):
            continue
        if any(parts[:len(prefix)] == prefix for prefix in SKIP_PREFIXES):
            continue
        result.append(path)
    return result


def main() -> int:
    findings: list[str] = []
    for path in files():
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:4096] or len(data) > 5 * 1024 * 1024:
            continue
        relative = path.relative_to(ROOT).as_posix()
        pinned_hash = KNOWN_VENDOR_SAMPLES.get(relative)
        if pinned_hash:
            observed_hash = hashlib.sha256(data).hexdigest()
            if observed_hash == pinned_hash:
                continue  # exact reviewed public example, no blind source exclusions
            findings.append(f"{relative}: pinned source bytes differ: expected={pinned_hash} observed={observed_hash}")
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(data):
                findings.append(f"{path.relative_to(ROOT)}: possible {name}")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("Secret scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
