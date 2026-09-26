# TraceAtlas Modules

This directory holds governed extensions derived from the 687 unique upstream features.

## Contents

| File | Purpose | Features covered |
|------|---------|------------------|
| `FEATURE_REGISTRY_687.md` | Complete mapping of all 687 unique features → status | All |
| `__init__.py` | Package marker | — |
| `entity_resolution.py` | Entity types, confidence, resolution queue (no auto-merge) | 197-211, 273-278 |
| `timeline.py` | Multi-source timeline + date parsers | 221-231 |
| `osint_tools.py` | WHOIS / DNS / Shodan IDB / Wayback / HIBP + ToolResult | 232-238 |
| `agent_loop.py` | Bounded Planner→Decide→Call→Observe→Done loop | 337-345, 351-353 |

## Development Rules

1. No feature is claimed as “implemented” until it passes the readiness scorecard and authorization gates.
2. All external engines stay behind explicit adapters / MCP / service boundaries.
3. Sensitive workflows require dual confirmation + recorded lawful purpose.
4. Credentials, cookies, private data and automatic identity claims are never accepted.
5. New modules must update both this README and `FEATURE_REGISTRY_687.md`.

## Usage examples

```python
from modules.entity_resolution import Entity, EntityType, EntityResolutionQueue
from modules.timeline import build_timeline, parse_date
from modules.osint_tools import whois_lookup, dns_lookup, shodan_internetdb
from modules.agent_loop import AgentLoop

# Entity resolution (requires --authorized + authority)
q = EntityResolutionQueue()
cand = q.propose(
    case_id="demo-001",
    left=Entity(id="e1", type=EntityType.DOMAIN, name="example.com"),
    right=Entity(id="e2", type=EntityType.ORGANIZATION, name="Example Org"),
    authority="Written approval from asset owner",
    authorized=True,
)

# Timeline
events = build_timeline(
    entities=[{"name": "example.com", "type": "DOMAIN", "start_date": "2024-03-15"}],
    chat_messages=["Meeting happened yesterday"],
)

# OSINT tools
print(whois_lookup("example.com").summary)
print(dns_lookup("example.com").summary)
print(shodan_internetdb("8.8.8.8").summary)
```

## Priority for next modules

1. Leaflet / GeoJSON map helper
2. Expanded IntelOwl analyzer readiness states
3. Local-first case export/import (Abster-style)
4. Additional deterministic Claude-OSINT skills
5. Optional TUI for agent observation loops

See also:
- [CAPABILITY_MATRIX.md](../CAPABILITY_MATRIX.md)
- [INTELLIGENCE_HUB.md](../INTELLIGENCE_HUB.md)
- [FUSION.md](../FUSION.md)
