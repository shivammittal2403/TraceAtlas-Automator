# TraceAtlas × OpenOSINT fusion

Version 0.6 keeps both projects intact and connects them through a deliberately
narrow compatibility boundary.

## Layout

| Component | Location | Responsibility |
|---|---|---|
| TraceAtlas core | `src/traceatlas` | Cases, playbooks, evidence, graphs and reports |
| OpenOSINT upstream | `packages/openosint` | Preserved MIT-licensed 2.29.0 package |
| Compatibility bridge | `src/traceatlas/openosint_bridge.py` | Authorization, allowlisting, isolation and redaction |
| RedKross console | `public`, `api` | Vercel-safe local command planner and catalog |

OpenOSINT uses `.traceatlas/openosint-venv`; the TraceAtlas core uses
`.traceatlas/venv`. An upstream dependency conflict therefore cannot replace
or contaminate the core runtime.

## Setup and use

```bash
./start.sh
./start.sh openosint doctor --json

./start.sh init rk-001 --title "Authorised review" \
  --purpose "Defensive review of an organisation-owned domain"

./start.sh openosint run --case rk-001 --authorized --owned-asset \
  -- dns example.com
```

The compatibility bridge permits direct `email`, `username`, `shodan`,
`virustotal`, `censys`, `github`, `dns`, `abuseipdb`, `ip2location` and
`playbook` workflows. It does not expose the interactive shell, upstream web
server, proxy controls, remote binding or anti-bot scraping. Provider secrets
belong in documented environment variables and are rejected on the bridge
command line.

## Vercel boundary

The deployed RedKross site is intentionally a stateless planner, not a hosted
reconnaissance service. It serves the feature catalog, validates consent and
returns argv templates. The target remains in browser memory and is inserted
into a shell-safe command locally. No target, credential, scan result or case
database is sent to or stored by the Vercel functions.

This division makes the public interface safe to deploy while keeping network
collection, credentials and evidence on the authorised operator's machine.
