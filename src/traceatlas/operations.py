"""Non-destructive operational verification drills."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from .db import CaseDB
from .models import utc_now


class SQLiteRestoreDrill:
    """Exercise online backup and restore without mutating the source database."""

    def __init__(self, db: CaseDB):
        self.db = db

    @staticmethod
    def _counts(connection: sqlite3.Connection) -> dict[str, int]:
        rows = connection.execute(
            """SELECT name FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"""
        ).fetchall()
        return {str(row[0]): int(connection.execute(
            f'SELECT count(*) FROM "{str(row[0]).replace(chr(34), chr(34) * 2)}"'
        ).fetchone()[0]) for row in rows}

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def run(self, output: Path) -> dict[str, Any]:
        output = output.resolve()
        output.mkdir(parents=True, exist_ok=True)
        backup_path = output / "traceatlas-backup.sqlite3"
        restored_path = output / "traceatlas-restored.sqlite3"
        receipt_path = output / "restore-drill.json"
        for path in (backup_path, restored_path, receipt_path):
            if path.exists():
                raise FileExistsError(f"Refusing to overwrite existing drill artifact: {path}")

        source_counts = self._counts(self.db.conn)
        backup = sqlite3.connect(backup_path)
        try:
            self.db.conn.backup(backup)
            backup.commit()
        finally:
            backup.close()
        backup = sqlite3.connect(backup_path)
        restored = sqlite3.connect(restored_path)
        try:
            backup.backup(restored)
            restored.commit()
        finally:
            backup.close()
            restored.close()
        verified = sqlite3.connect(restored_path)
        try:
            integrity = str(verified.execute("PRAGMA integrity_check").fetchone()[0])
            restored_counts = self._counts(verified)
            foreign_key_violations = len(verified.execute("PRAGMA foreign_key_check").fetchall())
        finally:
            verified.close()
        passed = integrity == "ok" and source_counts == restored_counts and foreign_key_violations == 0
        receipt = {
            "drill": "sqlite-online-backup-restore", "scope": "local-runtime",
            "completed_at": utc_now(), "status": "pass" if passed else "fail",
            "backup_sha256": self._sha256(backup_path),
            "restored_sha256": self._sha256(restored_path),
            "integrity_check": integrity,
            "foreign_key_violations": foreign_key_violations,
            "table_counts_match": source_counts == restored_counts,
            "table_counts": restored_counts,
            "limitations": [
                "This proves the local SQLite backup path only.",
                "Hosted Supabase point-in-time recovery must be drilled separately.",
            ],
        }
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        return {**receipt, "receipt": str(receipt_path)}
