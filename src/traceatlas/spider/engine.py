from __future__ import annotations

from collections import Counter, deque
from typing import Iterable
from uuid import uuid4

from ..db import CaseDB
from ..policy import PolicyError
from .correlation import correlate
from .events import Event, SEED_TYPES
from .modules import MODULES, SpiderModule


class SpiderEngine:
    def __init__(self, db: CaseDB):
        self.db = db

    def scan(self, case_id: str, seed_type: str, seed_value: str, *,
             enabled_modules: Iterable[str] | None = None, mode: str = "passive",
             max_events: int = 250, max_depth: int = 3) -> dict:
        seed_type = seed_type.upper()
        if seed_type not in SEED_TYPES:
            raise PolicyError(f"Unsupported spider seed type: {seed_type}")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        if mode != "passive":
            raise PolicyError("Only passive mode is implemented in this release")
        if not 1 <= max_events <= 5000 or not 0 <= max_depth <= 8:
            raise PolicyError("max-events must be 1..5000 and max-depth must be 0..8")
        selected = self._select(enabled_modules)
        scan_id = str(uuid4())
        self.db.start_spider_scan(scan_id, case_id, seed_type, seed_value, mode)
        seed = Event(seed_type, seed_value, "seed", scan_id, case_id, confidence=100)
        queue = deque([seed])
        processed: set[tuple[str, str]] = set()
        emitted = 0
        errors: list[str] = []
        module_counts: Counter[str] = Counter()
        while queue and emitted < max_events:
            event = queue.popleft()
            if not self.db.add_spider_event(event.to_dict()):
                continue
            emitted += 1
            if event.depth >= max_depth:
                continue
            for module in selected:
                if event.event_type not in module.watches:
                    continue
                key = (module.name, event.fingerprint)
                if key in processed:
                    continue
                processed.add(key)
                try:
                    children = module.handle(event)
                    module_counts[module.name] += 1
                    queue.extend(children)
                except Exception as exc:
                    errors.append(f"{module.name}: {type(exc).__name__}: {exc}")
        events = self.db.spider_events(scan_id)
        edges = self.db.spider_edges(scan_id)
        rules = correlate(events, edges)
        stats = {
            "events": len(events), "edges": len(edges),
            "event_types": dict(Counter(e["event_type"] for e in events)),
            "module_runs": dict(module_counts), "correlations": len(rules),
            "truncated": bool(queue), "errors": errors,
        }
        self.db.end_spider_scan(scan_id, "partial" if errors else "completed", stats)
        return {"scan_id": scan_id, "status": "partial" if errors else "completed",
                "stats": stats, "correlations": rules}

    @staticmethod
    def _select(names: Iterable[str] | None) -> list[SpiderModule]:
        if names is None:
            return list(MODULES.values())
        selected = []
        for name in names:
            clean = name.strip()
            if not clean:
                continue
            if clean not in MODULES:
                raise PolicyError(f"Unknown spider module: {clean}")
            selected.append(MODULES[clean])
        return selected
