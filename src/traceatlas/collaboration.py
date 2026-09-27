"""Conflict-safe saved graph views and privacy-reduced collaboration events."""

from __future__ import annotations

import json
import math
import re
import sqlite3
from typing import Any
from uuid import uuid4

from .db import CaseDB
from .policy import PolicyError


SAFE_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@-]{1,119}$")
SAFE_VIEW_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")
FORBIDDEN_KEYS = {"__proto__", "constructor", "prototype"}


def _bounded_object(value: Any, field: str, maximum: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{field} must be a JSON object")
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > maximum:
        raise PolicyError(f"{field} exceeds its storage limit")

    def inspect(item: Any, depth: int = 0) -> None:
        if depth > 8:
            raise PolicyError(f"{field} nesting is too deep")
        if isinstance(item, dict):
            if len(item) > 500:
                raise PolicyError(f"{field} contains too many keys")
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 80 or key in FORBIDDEN_KEYS:
                    raise PolicyError(f"{field} contains an unsafe key")
                inspect(child, depth + 1)
        elif isinstance(item, list):
            if len(item) > 2000:
                raise PolicyError(f"{field} contains too many items")
            for child in item:
                inspect(child, depth + 1)
        elif isinstance(item, float) and not math.isfinite(item):
            raise PolicyError(f"{field} contains a non-finite number")
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise PolicyError(f"{field} contains an unsupported value")
        elif isinstance(item, str) and len(item) > 2000:
            raise PolicyError(f"{field} contains an oversized value")

    inspect(value)
    return value


class CollaborationService:
    """Store analyst layouts without last-write-wins data loss."""

    def __init__(self, db: CaseDB):
        self.db = db

    def save_view(self, case_id: str, *, name: str, actor: str,
                  layout: Any, filters: Any, expected_revision: int,
                  view_id: str | None = None, authorized: bool = False) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("Saving a shared investigation view requires --authorized")
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        name = str(name).strip()
        actor = str(actor).strip()
        if not 2 <= len(name) <= 120 or any(ord(char) < 32 for char in name):
            raise PolicyError("View name must contain 2-120 printable characters")
        if not SAFE_ACTOR.fullmatch(actor):
            raise PolicyError("Actor must contain 2-120 safe display characters")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise PolicyError("Expected revision must be an integer")
        if expected_revision < 0 or expected_revision > 1_000_000:
            raise PolicyError("Expected revision is outside the accepted range")
        identifier = view_id or f"view-{uuid4().hex}"
        if not SAFE_VIEW_ID.fullmatch(identifier):
            raise PolicyError("View ID must contain 2-64 safe characters")
        row = {
            "id": identifier, "case_id": case_id, "name": name, "owner": actor,
            "layout": _bounded_object(layout, "layout", 64 * 1024),
            "filters": _bounded_object(filters, "filters", 16 * 1024),
        }
        try:
            return self.db.save_graph_view(row, expected_revision)
        except ValueError as exc:
            if str(exc) == "revision_conflict":
                raise PolicyError("View revision conflict; reload before retrying") from exc
            raise
        except sqlite3.IntegrityError as exc:
            raise PolicyError("A view with this name already exists in the case") from exc

    def views(self, case_id: str) -> list[dict[str, Any]]:
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        return self.db.graph_views(case_id)

    def events(self, case_id: str, *, after_id: int = 0,
               limit: int = 200) -> list[dict[str, Any]]:
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        return self.db.collaboration_events(case_id, after_id=after_id, limit=limit)
