# TraceAtlas Modules

This directory holds the **Feature Registry** and future modular extensions that map the 687 unique upstream OSINT capabilities into governed TraceAtlas components.

## Current contents

- `FEATURE_REGISTRY_687.md` — Complete mapping of every unique feature extracted from the upstream corpus (Abster, Firecrawl, Crawl4AI, IntelOwl, Agent-Reach, Claude-OSINT, Geo*, MCP servers, etc.) to TraceAtlas status (`implemented` / `bridged` / `planned` / `design` / `out-of-scope`).

## Development Rules

1. **No feature is claimed as implemented** until it passes the readiness scorecard and authorization gates.
2. All external engines stay behind explicit adapters / MCP / service boundaries.
3. Sensitive workflows require dual confirmation + recorded lawful purpose.
4. Credentials, cookies, private data and automatic identity claims are never accepted.
5. New modules must update both this registry and `CAPABILITY_MATRIX.md`.

## Priority Order for next modules

1. Entity-resolution queue UI + Leaflet map visualization
2. Expanded IntelOwl explicit analyzer readiness states
3. Local-first browser export/import (Abster-style)
4. Additional deterministic Claude-OSINT skills
5. Optional TUI for agentic observation loops

## Commands

```bash
./start.sh capabilities doctor --json
./start.sh capabilities list
./start.sh capabilities show <engine>
```

See also:
- [CAPABILITY_MATRIX.md](../CAPABILITY_MATRIX.md)
- [INTELLIGENCE_HUB.md](../INTELLIGENCE_HUB.md)
- [FUSION.md](../FUSION.md)
- [RESEARCH_ENGINE.md](../RESEARCH_ENGINE.md)
