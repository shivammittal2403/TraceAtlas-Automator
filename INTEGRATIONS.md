# External Tool Integrations

## Operating model

TraceAtlas integrates tools as governed subprocess adapters. An adapter defines
accepted target types, operating mode, a fixed command template, timeout,
machine-readable output format and normalized event type. The runner:

1. validates the target and case;
2. checks authorization and active-probing consent;
3. resolves an installed binary from `PATH`;
4. creates an argument array without a shell;
5. enforces a timeout and 10 MiB output capture ceiling;
6. parses JSON, JSONL, lines or Nmap XML;
7. filters domain/URL/email events to the root scope;
8. stores normalized events in the Spider graph;
9. preserves output with SHA-256 evidence custody.

Third-party tools are not bundled, auto-installed or silently updated. API keys
remain in their native tool configuration or environment.

## Adapter matrix

| Tool | Mode | Accepted target | Normalized purpose |
|---|---|---|---|
| Amass | Passive | Domain | Attack-surface/subdomain events |
| Subfinder | Passive | Domain | Passive subdomain events |
| Assetfinder | Passive | Domain | Related subdomain events |
| Findomain | Passive | Domain | Subdomain events |
| theHarvester | Passive | Domain | Host/email/indicator events |
| Recon-ng | Passive | Domain/email/username/text | Selected installed module output |
| GAU | Passive | Domain | Archived URL events |
| Waybackurls | Passive | Domain | Wayback URL events |
| WHOIS | Passive | Domain/IP | Registration observation |
| Uncover | Passive | Domain/IP/text | Configured internet-intelligence results |
| DNSx | Active | Domain | DNS record events |
| HTTPx | Active | Domain/URL/IP | HTTP response events |
| TLSx | Active | Domain/IP | TLS/certificate events |
| WhatWeb | Active | Domain/URL | Technology events |
| Katana | Active | URL | In-scope endpoint events |
| Naabu | Active | Domain/IP | Common open-port events |
| Nmap | Active | Domain/IP | Common open-port/service events |
| Nuclei | Active | Domain/URL | Template finding events |
| Gobuster | Active | URL | In-scope content events |
| FFUF | Active | URL | In-scope content events |
| Dirsearch | Active | URL | In-scope content events |
| Nikto | Active | Domain/URL | Web assessment events |
| DNSRecon | Active | Domain | DNS record events |
| Fierce | Active | Domain | DNS/network mapping events |
| SpiderFoot | Passive | Multiple | External SpiderFoot indicator events |
| ExifTool | Local | File | Metadata events |
| TruffleHog | Local | Path | Redacted secret-candidate events |
| Gitleaks | Local | Path | Redacted secret-candidate events |
| Sherlock | Identity | Username | Unverified account candidates |

The registry also detects but refuses to execute Masscan, ZMap, Hydra, SQLmap
and Metasploit. Their default operating models exceed this tool's controlled
reconnaissance boundary.

## Recon-ng

Recon-ng modules are installed separately through its marketplace. TraceAtlas
uses `recon-cli`, creates/uses a case-named workspace, enables stealth switches
and runs one explicitly selected module:

```bash
traceatlas integrations run --case demo-001 --tool recon-ng \
  --target-type domain --target example.com --authorized \
  --tool-option module=recon/domains-hosts/hackertarget
```

Module availability and API requirements remain Recon-ng concerns. TraceAtlas
captures and normalizes its resulting console output.

## Wordlist adapters

Gobuster and FFUF require an explicit wordlist path. TraceAtlas does not choose
or download one implicitly:

```bash
traceatlas integrations run --case demo-001 --tool gobuster \
  --target-type url --target https://example.com \
  --authorized --allow-active \
  --tool-option wordlist=/absolute/path/words.txt
```

## Safety boundary

- Passive network and identity tools require `--authorized`.
- Direct-probing tools additionally require `--allow-active`.
- Commands execute with `shell=False`.
- Required files must exist before execution.
- Runtime is capped at one hour per adapter.
- Domain and URL observations outside the root scope are dropped.
- Secret values are redacted and represented by hashes.
- Failed tools retain available diagnostics and produce a partial/failed scan.
- Profiles skip missing binaries instead of failing the whole workflow.

## Chained domain pipeline

The domain pipeline runs installed passive discovery adapters, deduplicates
in-scope domain events and can feed a bounded asset set to installed DNS, HTTP,
TLS and technology validators:

```bash
traceatlas integrations pipeline --case demo-001 --domain example.com \
  --authorized --verify --allow-active --max-assets 25
```

The default maximum is 25 assets and the hard maximum is 100. Verification is
off unless explicitly requested.
