# Spider Event Engine

## Model

The engine uses a bounded event bus inspired by modular OSINT scanners:

1. A typed seed event enters a FIFO queue.
2. Every event is persisted before processing.
3. Modules declaring the event type in `watches` receive it.
4. Modules emit typed child events with source, parent, confidence and tags.
5. `(event_type, canonical data)` fingerprints remove duplicates per scan.
6. Processing stops at `max_depth` or `max_events`.
7. Explainable correlation rules evaluate the stored event set.

```mermaid
flowchart TD
    Seed[Typed seed] --> Queue[Bounded event queue]
    Queue --> Store[(SQLite events)]
    Queue --> Match{Subscribed modules}
    Match --> Module[Passive module]
    Module --> Child[Typed child event]
    Child --> Dedup{New fingerprint?}
    Dedup -->|Yes| Queue
    Dedup -->|No| Drop[Drop duplicate]
    Store --> Rules[Correlation rules]
    Store --> Export[JSON or GEXF]
```

## Event fields

| Field | Purpose |
|---|---|
| `event_type` | Stable uppercase data type |
| `data` | JSON-serializable observation |
| `source_module` | Module that emitted the event |
| `parent_id` | Provenance edge to the triggering event |
| `depth` | Distance from the seed |
| `confidence` | Confidence in this observation, 0–100 |
| `risk` | `info`, `low`, `medium`, `high` or `critical` |
| `tags` | Qualifiers such as `candidate`, `ptr`, `san` |
| `fingerprint` | SHA-256 of canonical type and data |

## Module contract

```python
class MyModule(SpiderModule):
    name = "my_module"
    description = "Explain exactly what is observed."
    watches = frozenset({"DOMAIN"})
    produces = frozenset({"MY_EVENT"})
    passive = True

    def handle(self, event: Event) -> list[Event]:
        return [child(
            event, "MY_EVENT", {"observation": "value"}, self.name,
            confidence=70, tags=["primary-source"],
        )]
```

Instantiate it in `spider/modules.py::MODULES`. A production module should:

- use a documented public data source;
- set strict timeouts and source-specific rate limits;
- never bypass access controls or authentication;
- emit observations rather than identity/intent conclusions;
- refuse network pivots outside the authorized scope;
- catch malformed third-party data at the module boundary.

## Correlation policy

Correlation rules are deterministic and explain their basis. Current rules flag
multiple resolved addresses, non-public DNS results, redirects and unobserved
common response-security headers. “Not observed” never means “does not exist,”
and every rule sets `requires_review: true`.

## Safety envelope

- Passive mode only.
- No port scanning, brute force, credential testing or exploit execution.
- Local/private/link-local network fetches are blocked.
- Network and identity seeds require `--authorized` in the CLI.
- Account URLs are tagged as unverified candidates.
- Recursion and total output have hard limits.

