"""Fixed entry points and content identities for the supplied suite."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def catalog():
    return json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))


def contract(module_id):
    if not isinstance(module_id, str):
        raise ValueError("module must be a catalog ID")
    item = next((row for row in catalog()["modules"] if row["id"] == module_id), None)
    if item is None:
        raise ValueError("Unknown intelligence module; arbitrary imports are prohibited")
    path = ROOT / "modules" / (item["id"] + ".py")
    if hashlib.sha256(path.read_bytes()).hexdigest() != item["file_sha256"]:
        raise ValueError("Intelligence source differs from its versioned contract")
    return item
