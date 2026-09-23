from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, utc_now


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, purpose TEXT NOT NULL,
  created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
  method_id INTEGER NOT NULL, target_kind TEXT NOT NULL, target_value TEXT NOT NULL,
  started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL,
  error TEXT, FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, run_id INTEGER,
  title TEXT NOT NULL, value_json TEXT NOT NULL, source TEXT NOT NULL,
  confidence INTEGER NOT NULL, severity TEXT NOT NULL,
  observation TEXT NOT NULL, collected_at TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE IF NOT EXISTS evidence (
  sha256 TEXT PRIMARY KEY, case_id TEXT NOT NULL, path TEXT NOT NULL,
  source TEXT NOT NULL, captured_at TEXT NOT NULL, size INTEGER NOT NULL,
  media_type TEXT
);
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
  monitor_key TEXT NOT NULL, content_hash TEXT NOT NULL,
  captured_at TEXT NOT NULL, payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS spider_scans (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, seed_type TEXT NOT NULL,
  seed_value TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL,
  started_at TEXT NOT NULL, completed_at TEXT, stats_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE IF NOT EXISTS spider_events (
  id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, case_id TEXT NOT NULL,
  event_type TEXT NOT NULL, data_json TEXT NOT NULL, source_module TEXT NOT NULL,
  parent_id TEXT, depth INTEGER NOT NULL, confidence INTEGER NOT NULL,
  risk TEXT NOT NULL, tags_json TEXT NOT NULL, fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(scan_id, fingerprint),
  FOREIGN KEY(scan_id) REFERENCES spider_scans(id)
);
CREATE TABLE IF NOT EXISTS spider_edges (
  scan_id TEXT NOT NULL, parent_id TEXT NOT NULL, child_id TEXT NOT NULL,
  module TEXT NOT NULL, PRIMARY KEY(scan_id,parent_id,child_id,module)
);
CREATE TABLE IF NOT EXISTS sensitive_audit (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, workflow TEXT NOT NULL,
  target_fingerprint TEXT NOT NULL, lawful_purpose TEXT NOT NULL,
  attestations_json TEXT NOT NULL, status TEXT NOT NULL,
  started_at TEXT NOT NULL, completed_at TEXT, result_summary_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
"""


class CaseDB:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def create_case(self, case_id: str, title: str, purpose: str) -> None:
        self.conn.execute(
            "INSERT INTO cases(id,title,purpose,created_at) VALUES(?,?,?,?)",
            (case_id, title, purpose, utc_now()),
        )
        self.conn.commit()

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return dict(row) if row else None

    def start_run(self, case_id: str, method_id: int, kind: str, value: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs(case_id,method_id,target_kind,target_value,started_at,status) VALUES(?,?,?,?,?,?)",
            (case_id, method_id, kind, value, utc_now(), "running"),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def end_run(self, run_id: int, status: str, error: str | None = None) -> None:
        self.conn.execute(
            "UPDATE runs SET completed_at=?,status=?,error=? WHERE id=?",
            (utc_now(), status, error, run_id),
        )
        self.conn.commit()

    def add_findings(self, case_id: str, run_id: int, findings: Iterable[Finding]) -> int:
        import hashlib
        added = 0
        for item in findings:
            canonical = json.dumps(
                [case_id, item.title, item.value, item.source], sort_keys=True, default=str
            )
            fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
            cur = self.conn.execute(
                """INSERT OR IGNORE INTO findings
                (id,case_id,run_id,title,value_json,source,confidence,severity,observation,collected_at,fingerprint)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (item.id, case_id, run_id, item.title, json.dumps(item.value, default=str),
                 item.source, max(0, min(100, item.confidence)), item.severity,
                 item.observation, item.collected_at, fingerprint),
            )
            added += cur.rowcount
        self.conn.commit()
        return added

    def findings(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE case_id=? ORDER BY collected_at", (case_id,)
        ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["value"] = json.loads(item.pop("value_json"))
            item.pop("fingerprint", None)
            output.append(item)
        return output

    def runs(self, case_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM runs WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall()]

    def add_evidence(self, case_id: str, sha256: str, path: str, source: str,
                     size: int, media_type: str | None) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?)",
            (sha256, case_id, path, source, utc_now(), size, media_type),
        )
        self.conn.commit()

    def evidence(self, case_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM evidence WHERE case_id=? ORDER BY captured_at", (case_id,)
        ).fetchall()]

    def snapshot(self, case_id: str, key: str, content_hash: str, payload: Any) -> bool:
        previous = self.conn.execute(
            "SELECT content_hash FROM snapshots WHERE case_id=? AND monitor_key=? ORDER BY id DESC LIMIT 1",
            (case_id, key),
        ).fetchone()
        changed = previous is None or previous["content_hash"] != content_hash
        self.conn.execute(
            "INSERT INTO snapshots(case_id,monitor_key,content_hash,captured_at,payload_json) VALUES(?,?,?,?,?)",
            (case_id, key, content_hash, utc_now(), json.dumps(payload, default=str)),
        )
        self.conn.commit()
        return changed

    def start_spider_scan(self, scan_id: str, case_id: str, seed_type: str,
                          seed_value: str, mode: str) -> None:
        self.conn.execute(
            "INSERT INTO spider_scans(id,case_id,seed_type,seed_value,mode,status,started_at) VALUES(?,?,?,?,?,?,?)",
            (scan_id, case_id, seed_type, seed_value, mode, "running", utc_now()),
        )
        self.conn.commit()

    def end_spider_scan(self, scan_id: str, status: str, stats: dict[str, Any]) -> None:
        self.conn.execute(
            "UPDATE spider_scans SET status=?,completed_at=?,stats_json=? WHERE id=?",
            (status, utc_now(), json.dumps(stats), scan_id),
        )
        self.conn.commit()

    def add_spider_event(self, event: dict[str, Any]) -> bool:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO spider_events
            (id,scan_id,case_id,event_type,data_json,source_module,parent_id,depth,
             confidence,risk,tags_json,fingerprint,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (event["id"], event["scan_id"], event["case_id"], event["event_type"],
             json.dumps(event["data"], sort_keys=True, default=str), event["source_module"],
             event.get("parent_id"), event["depth"], event["confidence"], event["risk"],
             json.dumps(event.get("tags", [])), event["fingerprint"], event["created_at"]),
        )
        if cur.rowcount and event.get("parent_id"):
            self.conn.execute(
                "INSERT OR IGNORE INTO spider_edges(scan_id,parent_id,child_id,module) VALUES(?,?,?,?)",
                (event["scan_id"], event["parent_id"], event["id"], event["source_module"]),
            )
        self.conn.commit()
        return bool(cur.rowcount)

    def spider_events(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM spider_events WHERE scan_id=? ORDER BY depth,created_at,id", (scan_id,)
        ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["data"] = json.loads(item.pop("data_json"))
            item["tags"] = json.loads(item.pop("tags_json"))
            output.append(item)
        return output

    def spider_edges(self, scan_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM spider_edges WHERE scan_id=? ORDER BY parent_id,child_id", (scan_id,)
        ).fetchall()]

    def spider_scan(self, scan_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM spider_scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["stats"] = json.loads(result.pop("stats_json")) if result.get("stats_json") else None
        return result

    def spider_scans(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM spider_scans WHERE case_id=? ORDER BY started_at,id", (case_id,)
        ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["stats"] = json.loads(item.pop("stats_json")) if item.get("stats_json") else None
            output.append(item)
        return output

    def start_sensitive_audit(self, audit_id: str, case_id: str, workflow: str,
                              target_fingerprint: str, lawful_purpose: str,
                              attestations: dict[str, bool]) -> None:
        self.conn.execute(
            """INSERT INTO sensitive_audit
            (id,case_id,workflow,target_fingerprint,lawful_purpose,attestations_json,status,started_at)
            VALUES(?,?,?,?,?,?,?,?)""",
            (audit_id, case_id, workflow, target_fingerprint, lawful_purpose,
             json.dumps(attestations, sort_keys=True), "running", utc_now()),
        )
        self.conn.commit()

    def end_sensitive_audit(self, audit_id: str, status: str, summary: dict[str, Any]) -> None:
        self.conn.execute(
            "UPDATE sensitive_audit SET status=?,completed_at=?,result_summary_json=? WHERE id=?",
            (status, utc_now(), json.dumps(summary, sort_keys=True, default=str), audit_id),
        )
        self.conn.commit()

    def sensitive_audits(self, case_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM sensitive_audit WHERE case_id=? ORDER BY started_at,id", (case_id,)
        ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["attestations"] = json.loads(item.pop("attestations_json"))
            raw_summary = item.pop("result_summary_json")
            item["result_summary"] = json.loads(raw_summary) if raw_summary else None
            output.append(item)
        return output
