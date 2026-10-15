# Recon-ng integration (governed optional connector)

TraceAtlas retains its existing canonical Source Fabric, \`IntegrationRunner\`, case DB, EvidenceStore, employee taxonomy and 140 domain skills.

## Exact upstream source (complete, separate GPLv3 projects)

- \`third_party/recon-ng\` pins official Recon-ng core at commit \`32b08fe7b6993ca1f2d8f76ba8f5d23c7f34a11d\`.
- \`third_party/recon-ng-marketplace\` pins official module marketplace at commit \`9527714d2bb38886422bab5f1c4724d4a20d3057\` (109 Python modules identified in this revision).
- Both repositories are **GPL-3.0**, not Apache-2.0. They remain legally and technically separate pinned upstream code. Consult counsel before distributing a combined binary or modifying them.

\`\`\`bash
git submodule update --init third_party/recon-ng third_party/recon-ng-marketplace
PYTHONPATH=src python -m traceatlas.integrations.recon_ng
PYTHONPATH=src python -m unittest discover -s tests -p 'test_recon_ng_integration.py' -v
\`\`\`

## Runtime

The existing TraceAtlas \`recon-ng\` IntegrationRunner is now restricted to exactly two reviewed public-domain passive source modules:

- \`recon/domains-hosts/certificate_transparency\` (crt.sh)
- \`recon/domains-hosts/hackertarget\` (HackerTarget)

The other marketplace modules are listed as \`catalog_only\`, not production-qualified or executable through this integration. Do not enable modules that collect credentials, exploit services, brute force networks, deanonymize private people or run unverified third-party code.

Execution requires an existing case and \`authorized=True\`, a domain target, a matching pinned module, the optional Recon-ng dependencies installed in a **separate** Python environment, and an installed \`recon-cli\` executable. Nothing is automatically installed or contacted when modules are listed.

At execution time, only the named allowlisted module is SHA-verified then copied into a fresh temporary \`HOME\`; the actual Recon-ng \`-w\` workspace is keyed by the hashed TraceAtlas case identifier. \`--stealth\` disables Recon-ng's marketplace/version/analytics network checks, although the selected approved module may contact its documented public API. Shell expansion is disabled, a bounded subprocess timeout applies, and the temp workspace is removed afterward.

Only in-scope domains/hostnames from the Recon-ng SQLite workspace are converted into the canonical TraceAtlas evidence/event flow. Passwords, user profiles, unscoped IP addresses, contacts, and sensitive records are not exported. The sanitized workspace receipt stores the original SQLite SHA-256 for provenance without copying the private Recon-ng DB. Raw terminal output is not stored for Recon-ng.

## Current limitations and required verification

- Third-party Recon-ng dependencies need independent install, license/security and runtime checks; no live external API verification is claimed here.
- Marketplace import is AST-only and never imports arbitrary modules.
- The two chosen public API modules have been reviewed for passive functionality in the pinned marketplace; their versions may be outdated and API output or rate limits may have changed.
- Recon-ng can internally swallow exceptions, so exit code 0 without structured results is classified **partial**, not a successful investigation.
- Secure execution isolation is best-effort at the Python/temporary HOME boundary. It is not a container sandbox, network firewall or OS-level jail. Review and containerize the pinned source before enterprise deployment.
- A domain-specific claim still requires independent source verification.
