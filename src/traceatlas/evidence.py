from __future__ import annotations

import hashlib
import json
import mimetypes
import shutil
from pathlib import Path
from typing import Any

from .db import CaseDB
from .models import utc_now


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class EvidenceStore:
    def __init__(self, root: Path, db: CaseDB, case_id: str):
        self.root = root / "evidence" / case_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = db
        self.case_id = case_id
        self.ledger = self.root / "ledger.jsonl"

    def preserve_file(self, source_path: Path, source: str) -> dict[str, Any]:
        digest = sha256_file(source_path)
        destination = self.root / f"{digest[:16]}_{source_path.name}"
        if not destination.exists():
            shutil.copy2(source_path, destination)
        media_type = mimetypes.guess_type(source_path.name)[0]
        self.db.add_evidence(
            self.case_id, digest, str(destination), source,
            destination.stat().st_size, media_type,
        )
        record = {
            "action": "preserve", "sha256": digest, "path": str(destination),
            "source": source, "timestamp": utc_now(),
        }
        self._append_ledger(record)
        return record

    def _append_ledger(self, record: dict[str, Any]) -> None:
        previous = "0" * 64
        if self.ledger.exists():
            lines = self.ledger.read_text(encoding="utf-8").splitlines()
            if lines:
                previous = json.loads(lines[-1])["entry_hash"]
        body = {**record, "previous_hash": previous}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        body["entry_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.ledger.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True) + "\n")

    def verify_ledger(self) -> tuple[bool, int]:
        previous = "0" * 64
        count = 0
        if not self.ledger.exists():
            return True, 0
        for line in self.ledger.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            claimed = entry.pop("entry_hash")
            if entry.get("previous_hash") != previous:
                return False, count
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            if hashlib.sha256(canonical.encode()).hexdigest() != claimed:
                return False, count
            previous = claimed
            count += 1
        return True, count

