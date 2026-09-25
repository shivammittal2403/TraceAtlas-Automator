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

The planner remains stateless and never receives its target. The optional
signed-in control plane separately stores only explicitly enrolled,
organisation-owned domains, public IPs, public URLs and hashes, then queues
fixed passive jobs for an isolated worker. Vercel executes no reconnaissance
and receives no provider or worker secrets. Identity investigations stay local.
