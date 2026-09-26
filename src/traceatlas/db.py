from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, utc_now


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
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
CREATE TABLE IF NOT EXISTS connector_health (
  source TEXT PRIMARY KEY, last_success_at TEXT, last_failure_at TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0, last_error_message TEXT
);
CREATE TABLE IF NOT EXISTS source_runs (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, source TEXT NOT NULL,
  mode TEXT NOT NULL CHECK(mode IN ('live','approved-export','service')),
  status TEXT NOT NULL CHECK(status IN ('running','completed','partial','failed')),
  target_fingerprint TEXT NOT NULL,
  records_received INTEGER NOT NULL DEFAULT 0,
  records_stored INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  bytes_received INTEGER NOT NULL DEFAULT 0,
  failure_code TEXT, duration_ms INTEGER,
  started_at TEXT NOT NULL, completed_at TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS integration_health (
  tool TEXT PRIMARY KEY, last_success_at TEXT, last_failure_at TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0, last_status TEXT NOT NULL,
  last_error_type TEXT
);
CREATE TABLE IF NOT EXISTS automation_jobs (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, name TEXT NOT NULL,
  method_key TEXT NOT NULL, target_kind TEXT NOT NULL, target_value TEXT NOT NULL,
  authority TEXT NOT NULL, interval_minutes INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1, next_run_at TEXT NOT NULL,
  lease_until TEXT, last_run_at TEXT, last_status TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS automation_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
  started_at TEXT NOT NULL, completed_at TEXT, status TEXT NOT NULL,
  baseline INTEGER NOT NULL DEFAULT 0, changed INTEGER NOT NULL DEFAULT 0,
  result_json TEXT, error_type TEXT,
  FOREIGN KEY(job_id) REFERENCES automation_jobs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, source TEXT NOT NULL,
  kind TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
  details_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL, acknowledged_at TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS case_notes (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, author TEXT NOT NULL,
  classification TEXT NOT NULL CHECK(classification IN ('fact','analysis','question')),
  body TEXT NOT NULL, created_at TEXT NOT NULL,
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS entity_resolution_candidates (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL, source TEXT NOT NULL,
  left_json TEXT NOT NULL, right_json TEXT NOT NULL,
  classification TEXT NOT NULL, score REAL, comparisons_json TEXT NOT NULL,
  fingerprint TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','accepted','rejected')),
  authority TEXT NOT NULL, created_at TEXT NOT NULL,
  decided_at TEXT, reviewer TEXT, rationale TEXT,
  UNIQUE(case_id,fingerprint),
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS automation_due_idx
  ON automation_jobs(enabled,next_run_at) WHERE enabled=1;
CREATE INDEX IF NOT EXISTS automation_runs_job_idx ON automation_runs(job_id,started_at);
CREATE INDEX IF NOT EXISTS alerts_case_status_idx ON alerts(case_id,status,created_at);
CREATE INDEX IF NOT EXISTS case_notes_case_idx ON case_notes(case_id,created_at);
CREATE INDEX IF NOT EXISTS resolution_queue_idx
  ON entity_resolution_candidates(case_id,status,created_at);
CREATE INDEX IF NOT EXISTS source_runs_case_idx
  ON source_runs(case_id,started_at);
CREATE INDEX IF NOT EXISTS source_runs_source_idx
  ON source_runs(source,status,started_at);
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

    def searchable_documents(self, case_id: str) -> list[dict[str, str]]:
        """Flatten case facts for local lexical search without creating another data copy."""
        documents: list[dict[str, str]] = []
        for row in self.findings(case_id):
            documents.append({
                "id": row["id"], "source_type": "finding",
                "text": " ".join((row["title"], row["observation"], row["source"],
                                    json.dumps(row["value"], ensure_ascii=False, default=str))),
            })
        rows = self.conn.execute(
            "SELECT id,event_type,data_json,source_module,tags_json FROM spider_events "
            "WHERE case_id=? ORDER BY created_at,id", (case_id,),
        ).fetchall()
        for row in rows:
            documents.append({
                "id": row["id"], "source_type": "spider_event",
                "text": " ".join((row["event_type"], row["source_module"],
                                    row["data_json"], row["tags_json"])),
            })
        return documents

    def record_connector_result(self, source: str, success: bool,
                                error: str | None = None) -> None:
        now = utc_now()
        if success:
            self.conn.execute(
                """INSERT INTO connector_health(source,last_success_at,consecutive_failures,last_error_message)
                VALUES(?,?,0,NULL) ON CONFLICT(source) DO UPDATE SET
                last_success_at=excluded.last_success_at,consecutive_failures=0,last_error_message=NULL""",
                (source, now),
            )
        else:
            self.conn.execute(
                """INSERT INTO connector_health(source,last_failure_at,consecutive_failures,last_error_message)
                VALUES(?,?,1,?) ON CONFLICT(source) DO UPDATE SET
                last_failure_at=excluded.last_failure_at,
                consecutive_failures=connector_health.consecutive_failures+1,
                last_error_message=excluded.last_error_message""",
                (source, now, (error or "connector request failed")[:300]),
            )
        self.conn.commit()

    def connector_health(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM connector_health ORDER BY source"
        ).fetchall()]

    def start_source_run(self, run_id: str, case_id: str, source: str,
                         mode: str, target_fingerprint: str) -> None:
        self.conn.execute(
            """INSERT INTO source_runs
            (id,case_id,source,mode,status,target_fingerprint,started_at)
            VALUES(?,?,?,?,'running',?,?)""",
            (run_id, case_id, source, mode, target_fingerprint, utc_now()),
        )
        self.conn.commit()

    def finish_source_run(self, run_id: str, status: str, *, records_received: int = 0,
                          records_stored: int = 0, attempts: int = 0,
                          bytes_received: int = 0, failure_code: str | None = None,
                          duration_ms: int = 0) -> None:
        self.conn.execute(
            """UPDATE source_runs SET status=?,records_received=?,records_stored=?,attempts=?,
            bytes_received=?,failure_code=?,duration_ms=?,completed_at=?
            WHERE id=? AND status='running'""",
            (status, max(0, records_received), max(0, records_stored), max(0, attempts),
             max(0, bytes_received), failure_code[:120] if failure_code else None,
             max(0, duration_ms), utc_now(), run_id),
        )
        self.conn.commit()

    def source_runs(self, case_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 5000))
        if case_id:
            rows = self.conn.execute(
                "SELECT * FROM source_runs WHERE case_id=? ORDER BY started_at DESC,id DESC LIMIT ?",
                (case_id, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM source_runs ORDER BY started_at DESC,id DESC LIMIT ?", (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_integration_result(self, tool: str, status: str,
                                  error_type: str | None = None) -> None:
        now = utc_now()
        success = status == "completed"
        if success:
            self.conn.execute(
                """INSERT INTO integration_health
                (tool,last_success_at,consecutive_failures,last_status,last_error_type)
                VALUES(?,?,0,?,NULL) ON CONFLICT(tool) DO UPDATE SET
                last_success_at=excluded.last_success_at,consecutive_failures=0,
                last_status=excluded.last_status,last_error_type=NULL""",
                (tool, now, status),
            )
        else:
            self.conn.execute(
                """INSERT INTO integration_health
                (tool,last_failure_at,consecutive_failures,last_status,last_error_type)
                VALUES(?,?,1,?,?) ON CONFLICT(tool) DO UPDATE SET
                last_failure_at=excluded.last_failure_at,
                consecutive_failures=integration_health.consecutive_failures+1,
                last_status=excluded.last_status,last_error_type=excluded.last_error_type""",
                (tool, now, status, (error_type or "ToolExecutionError")[:120]),
            )
        self.conn.commit()

    def integration_health(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM integration_health ORDER BY tool"
        ).fetchall()]

    def latest_snapshot_hash(self, case_id: str, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT content_hash FROM snapshots WHERE case_id=? AND monitor_key=? "
            "ORDER BY id DESC LIMIT 1", (case_id, key),
        ).fetchone()
        return str(row["content_hash"]) if row else None

    def add_automation_job(self, row: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO automation_jobs
            (id,case_id,name,method_key,target_kind,target_value,authority,interval_minutes,
             enabled,next_run_at,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (row["id"], row["case_id"], row["name"], row["method_key"],
             row["target_kind"], row["target_value"], row["authority"],
             row["interval_minutes"], 1, row["next_run_at"], row["created_at"],
             row["created_at"]),
        )
        self.conn.commit()

    def automation_jobs(self, case_id: str | None = None) -> list[dict[str, Any]]:
        if case_id:
            rows = self.conn.execute(
                "SELECT * FROM automation_jobs WHERE case_id=? ORDER BY created_at,id", (case_id,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM automation_jobs ORDER BY created_at,id"
            ).fetchall()
        return [dict(row) for row in rows]

    def automation_job(self, job_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM automation_jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def set_automation_enabled(self, job_id: str, enabled: bool) -> bool:
        cur = self.conn.execute(
            "UPDATE automation_jobs SET enabled=?,lease_until=NULL,updated_at=? WHERE id=?",
            (int(enabled), utc_now(), job_id),
        )
        self.conn.commit()
        return bool(cur.rowcount)

    def claim_due_automation_jobs(self, now: str, lease_until: str,
                                  limit: int) -> list[dict[str, Any]]:
        claimed: list[dict[str, Any]] = []
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute(
                """SELECT * FROM automation_jobs
                WHERE enabled=1 AND next_run_at<=? AND (lease_until IS NULL OR lease_until<?)
                ORDER BY next_run_at,id LIMIT ?""", (now, now, limit),
            ).fetchall()
            for row in rows:
                cur = self.conn.execute(
                    """UPDATE automation_jobs SET lease_until=?,updated_at=?
                    WHERE id=? AND enabled=1 AND (lease_until IS NULL OR lease_until<?)""",
                    (lease_until, now, row["id"], now),
                )
                if cur.rowcount:
                    claimed.append(dict(row))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return claimed

    def start_automation_run(self, job_id: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO automation_runs(job_id,started_at,status) VALUES(?,?,?)",
            (job_id, utc_now(), "running"),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_automation_run(self, run_id: int, job_id: str, status: str, *,
                              baseline: bool, changed: bool, result: Any,
                              error_type: str | None, next_run_at: str) -> None:
        now = utc_now()
        self.conn.execute(
            """UPDATE automation_runs SET completed_at=?,status=?,baseline=?,changed=?,
            result_json=?,error_type=? WHERE id=?""",
            (now, status, int(baseline), int(changed),
             json.dumps(result, sort_keys=True, default=str) if result is not None else None,
             error_type, run_id),
        )
        self.conn.execute(
            """UPDATE automation_jobs SET lease_until=NULL,last_run_at=?,last_status=?,
            next_run_at=?,updated_at=? WHERE id=?""",
            (now, status, next_run_at, now, job_id),
        )
        self.conn.commit()

    def automation_runs(self, job_id: str | None = None,
                        limit: int = 100) -> list[dict[str, Any]]:
        if job_id:
            rows = self.conn.execute(
                "SELECT * FROM automation_runs WHERE job_id=? ORDER BY id DESC LIMIT ?",
                (job_id, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM automation_runs ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            raw = item.pop("result_json")
            item["result"] = json.loads(raw) if raw else None
            output.append(item)
        return output

    def add_alert(self, row: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO alerts
            (id,case_id,source,kind,severity,message,details_json,status,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (row["id"], row["case_id"], row["source"], row["kind"], row["severity"],
             row["message"], json.dumps(row.get("details", {}), sort_keys=True, default=str),
             "open", row["created_at"]),
        )
        self.conn.commit()

    def alerts(self, case_id: str | None = None, open_only: bool = False,
               limit: int = 100) -> list[dict[str, Any]]:
        clauses, values = [], []
        if case_id:
            clauses.append("case_id=?")
            values.append(case_id)
        if open_only:
            clauses.append("status='open'")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.conn.execute(
            f"SELECT * FROM alerts{where} ORDER BY created_at DESC LIMIT ?",  # nosec: fixed clauses
            (*values, limit),
        ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            output.append(item)
        return output

    def acknowledge_alert(self, alert_id: str) -> bool:
        cur = self.conn.execute(
            """UPDATE alerts SET status='acknowledged',acknowledged_at=?
            WHERE id=? AND status='open'""", (utc_now(), alert_id),
        )
        self.conn.commit()
        return bool(cur.rowcount)

    def add_case_note(self, row: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO case_notes(id,case_id,author,classification,body,created_at)
            VALUES(?,?,?,?,?,?)""",
            (row["id"], row["case_id"], row["author"], row["classification"],
             row["body"], row["created_at"]),
        )
        self.conn.commit()

    def case_notes(self, case_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute(
            "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at,id", (case_id,),
        ).fetchall()]

    def add_resolution_candidate(self, row: dict[str, Any]) -> bool:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO entity_resolution_candidates
            (id,case_id,source,left_json,right_json,classification,score,comparisons_json,
             fingerprint,status,authority,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?)""",
            (row["id"], row["case_id"], row["source"],
             json.dumps(row["left"], sort_keys=True, ensure_ascii=False),
             json.dumps(row["right"], sort_keys=True, ensure_ascii=False),
             row["classification"], row.get("score"),
             json.dumps(row.get("comparisons", []), sort_keys=True), row["fingerprint"],
             row["authority"], row["created_at"]),
        )
        self.conn.commit()
        return bool(cur.rowcount)

    @staticmethod
    def _resolution_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["left"] = json.loads(item.pop("left_json"))
        item["right"] = json.loads(item.pop("right_json"))
        item["comparisons"] = json.loads(item.pop("comparisons_json"))
        item.pop("fingerprint", None)
        return item

    def resolution_candidate(self, candidate_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM entity_resolution_candidates WHERE id=?", (candidate_id,),
        ).fetchone()
        return self._resolution_row(row) if row else None

    def resolution_candidates(self, case_id: str, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.conn.execute(
                """SELECT * FROM entity_resolution_candidates
                WHERE case_id=? AND status=? ORDER BY created_at,id""", (case_id, status),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """SELECT * FROM entity_resolution_candidates
                WHERE case_id=? ORDER BY created_at,id""", (case_id,),
            ).fetchall()
        return [self._resolution_row(row) for row in rows]

    def decide_resolution_candidate(self, candidate_id: str, decision: str, *,
                                    reviewer: str, rationale: str) -> bool:
        cur = self.conn.execute(
            """UPDATE entity_resolution_candidates
            SET status=?,decided_at=?,reviewer=?,rationale=?
            WHERE id=? AND status='pending'""",
            (decision, utc_now(), reviewer, rationale, candidate_id),
        )
        self.conn.commit()
        return bool(cur.rowcount)

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
        child_id = event["id"]
        if not cur.rowcount:
            existing = self.conn.execute(
                "SELECT id FROM spider_events WHERE scan_id=? AND fingerprint=?",
                (event["scan_id"], event["fingerprint"]),
            ).fetchone()
            if existing:
                child_id = existing["id"]
        if event.get("parent_id") and child_id != event["parent_id"]:
            self.conn.execute(
                "INSERT OR IGNORE INTO spider_edges(scan_id,parent_id,child_id,module) VALUES(?,?,?,?)",
                (event["scan_id"], event["parent_id"], child_id, event["source_module"]),
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
