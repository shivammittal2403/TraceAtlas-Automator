"""Durable local execution fences and conservative request accounting.

Uses the existing case SQLite database, not a distributed queue. Unknown paid
charges retain their reservation until an explicit trusted billing receipt.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
from uuid import uuid4

SCHEMA = """
CREATE TABLE IF NOT EXISTS workforce_attempts (
 task_id TEXT PRIMARY KEY REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
 token TEXT NOT NULL, generation INTEGER NOT NULL, lease_until REAL NOT NULL,
 runtime_until REAL NOT NULL, started_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS workforce_request_budget (
 request_id TEXT PRIMARY KEY,
 task_id TEXT NOT NULL REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
 token TEXT NOT NULL, source_id TEXT NOT NULL, ceiling_microusd INTEGER NOT NULL,
 actual_microusd INTEGER, state TEXT NOT NULL
 CHECK(state IN ('reserved','uncertain','settled')), created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS workforce_request_task ON workforce_request_budget(task_id);
CREATE TABLE IF NOT EXISTS workforce_checkpoints (
 task_id TEXT NOT NULL REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
 step_id TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
 created_at REAL NOT NULL, PRIMARY KEY(task_id,step_id)
);
CREATE TABLE IF NOT EXISTS workforce_outbox (
 event_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES workforce_tasks(task_id) ON DELETE CASCADE,
 event_type TEXT NOT NULL, payload_json TEXT NOT NULL, created_at REAL NOT NULL,
 acknowledged_at REAL, UNIQUE(task_id,event_type)
);
"""


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def micros(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValueError('invalid request price')
    amount = Decimal(str(value))
    if not amount.is_finite() or not 0 <= amount <= 1_000_000:
        raise ValueError('invalid request price')
    return int((amount * 1_000_000).to_integral_value(rounding=ROUND_CEILING))


class ExecutionStopped(ValueError):
    """The attempt no longer owns dispatch or canonical completion."""


class ExecutionRuntime:
    def __init__(self, path, *, clock=time.time, lease_seconds=60):
        self.path, self.clock = str(path), clock
        if not 1 <= lease_seconds <= 300:
            raise ValueError('invalid execution lease')
        self.lease_seconds = lease_seconds

    @contextmanager
    def transaction(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        try:
            conn.execute('BEGIN IMMEDIATE')
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _task(self, conn, task_id):
        row = conn.execute('SELECT * FROM workforce_tasks WHERE task_id=?', (task_id,)).fetchone()
        if not row:
            raise ValueError('unknown workforce task')
        task = json.loads(row['envelope_json'])
        if hashlib.sha256(encode(task).encode()).hexdigest() != row['envelope_digest']:
            raise ExecutionStopped('stored task digest mismatch')
        return row, task

    def assert_current(self, conn, task_id, token):
        row, task = self._task(conn, task_id)
        attempt = conn.execute('SELECT * FROM workforce_attempts WHERE task_id=?', (task_id,)).fetchone()
        now = self.clock()
        if (not token or not attempt or attempt['token'] != token or row['status'] != 'running'
                or now >= min(attempt['lease_until'], attempt['runtime_until'],
                              datetime.fromisoformat(task['deadline']).timestamp())):
            raise ExecutionStopped('attempt is stale, expired or cancelled')
        return attempt, task

    def claim(self, task_id):
        with self.transaction() as conn:
            row, task = self._task(conn, task_id)
            if row['status'] != 'approved':
                raise ExecutionStopped('task is not approved or was already claimed')
            old = conn.execute('SELECT * FROM workforce_attempts WHERE task_id=?', (task_id,)).fetchone()
            now = self.clock()
            end = old['runtime_until'] if old else now + task['budget']['runtime_seconds']
            end = min(end, datetime.fromisoformat(task['deadline']).timestamp())
            if now >= end:
                raise ExecutionStopped('task runtime or deadline exhausted')
            token = uuid4().hex
            conn.execute('INSERT OR REPLACE INTO workforce_attempts VALUES(?,?,?,?,?,?)',
                         (task_id, token, old['generation'] + 1 if old else 1,
                          min(now + self.lease_seconds, end), end, old['started_at'] if old else now))
            conn.execute("UPDATE workforce_tasks SET status='running',completed_at=NULL WHERE task_id=?", (task_id,))
        return token

    def check(self, task_id, token):
        with self.transaction() as conn:
            attempt, _ = self.assert_current(conn, task_id, token)
            now = self.clock()
            conn.execute('UPDATE workforce_attempts SET lease_until=? WHERE task_id=?',
                         (min(now + self.lease_seconds, attempt['runtime_until']), task_id))
            return attempt['runtime_until'] - now

    def stop(self, task_id, *, token=None, cancel=False):
        with self.transaction() as conn:
            row, _ = self._task(conn, task_id)
            if row['status'] in {'completed', 'cancelled'}:
                return
            attempt = conn.execute('SELECT token FROM workforce_attempts WHERE task_id=?', (task_id,)).fetchone()
            if not cancel and (not attempt or attempt['token'] != token or row['status'] != 'running'):
                return
            conn.execute('UPDATE workforce_tasks SET status=?,completed_at=? WHERE task_id=?',
                         ('cancelled' if cancel else 'failed', datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(), task_id))
            conn.execute("UPDATE workforce_request_budget SET state='uncertain' WHERE task_id=? AND state='reserved'", (task_id,))

    def recover(self, task_id):
        with self.transaction() as conn:
            row, task = self._task(conn, task_id)
            attempt = conn.execute('SELECT * FROM workforce_attempts WHERE task_id=?', (task_id,)).fetchone()
            now = self.clock()
            if (not attempt or row['status'] not in {'running', 'failed'}
                    or row['status'] == 'running' and attempt['lease_until'] > now):
                raise ExecutionStopped('only failed or lease-expired tasks can be recovered')
            if now >= min(attempt['runtime_until'], datetime.fromisoformat(task['deadline']).timestamp()):
                raise ExecutionStopped('task runtime or deadline exhausted; create a new approved task')
            conn.execute("UPDATE workforce_request_budget SET state='uncertain' WHERE task_id=? AND state='reserved'", (task_id,))
            conn.execute("UPDATE workforce_tasks SET status='approved',completed_at=NULL WHERE task_id=?", (task_id,))

    def reserve(self, task_id, token, source_id, ceiling):
        price = micros(ceiling)
        with self.transaction() as conn:
            _, task = self.assert_current(conn, task_id, token)
            used = conn.execute('SELECT COUNT(*),COALESCE(SUM(COALESCE(actual_microusd,ceiling_microusd)),0) '
                                'FROM workforce_request_budget WHERE task_id=?', (task_id,)).fetchone()
            if used[0] >= task['budget']['tool_calls'] or used[1] + price > micros(task['budget']['amount']):
                raise ExecutionStopped('durable request or cost budget exhausted')
            request_id = uuid4().hex
            conn.execute('INSERT INTO workforce_request_budget VALUES(?,?,?,?,?,?,?,?)',
                         (request_id, task_id, token, source_id, price, None, 'reserved', self.clock()))
            return request_id

    def settle(self, task_id, token, request_id, *, actual=None):
        # Late accounting is allowed for that request only; it cannot finalize,
        # restore authority or dispatch another request after cancellation.
        amount = None if actual is None else micros(actual)
        with self.transaction() as conn:
            row = conn.execute('SELECT * FROM workforce_request_budget WHERE request_id=? AND task_id=? AND token=?',
                               (request_id, task_id, token)).fetchone()
            if not row:
                raise ExecutionStopped('request does not belong to this attempt')
            if row['state'] == 'settled':
                if amount != row['actual_microusd']:
                    raise ValueError('conflicting request settlement')
                return
            conn.execute('UPDATE workforce_request_budget SET actual_microusd=?,state=? WHERE request_id=?',
                         (amount, 'uncertain' if actual is None else 'settled', request_id))

    def checkpoint(self, task_id, token, step_id, payload):
        encoded = encode(payload)
        if not isinstance(step_id, str) or not 1 <= len(step_id) <= 160 or len(encoded.encode()) > 65536:
            raise ValueError('invalid checkpoint')
        with self.transaction() as conn:
            self.assert_current(conn, task_id, token)
            old = conn.execute('SELECT payload_json FROM workforce_checkpoints WHERE task_id=? AND step_id=?',
                               (task_id, step_id)).fetchone()
            if old and old[0] != encoded:
                raise ValueError('checkpoint is immutable')
            conn.execute('INSERT OR IGNORE INTO workforce_checkpoints VALUES(?,?,?,?,?)',
                         (task_id, step_id, encoded, hashlib.sha256(encoded.encode()).hexdigest(), self.clock()))

    def snapshot(self, task_id):
        with self.transaction() as conn:
            row, _ = self._task(conn, task_id)
            attempt = conn.execute('SELECT generation,lease_until,runtime_until FROM workforce_attempts WHERE task_id=?', (task_id,)).fetchone()
            charges = conn.execute('SELECT COUNT(*),COALESCE(SUM(COALESCE(actual_microusd,ceiling_microusd)),0), '
                                   "COALESCE(SUM(state != 'settled'),0) FROM workforce_request_budget WHERE task_id=?", (task_id,)).fetchone()
            checkpoints = []
            for item in conn.execute('SELECT * FROM workforce_checkpoints WHERE task_id=? ORDER BY step_id', (task_id,)):
                if hashlib.sha256(item['payload_json'].encode()).hexdigest() != item['payload_digest']:
                    raise ValueError('checkpoint digest mismatch')
                checkpoints.append({'step_id': item['step_id'], 'payload': json.loads(item['payload_json'])})
            events = [dict(e) for e in conn.execute('SELECT event_id,event_type,acknowledged_at FROM workforce_outbox WHERE task_id=?', (task_id,))]
            return {'status': row['status'], 'attempt': dict(attempt) if attempt else None,
                    'request_attempts': charges[0], 'accounted_usd': charges[1] / 1_000_000,
                    'unsettled_requests': charges[2], 'checkpoints': checkpoints, 'outbox': events,
                    'scope': 'local-sqlite', 'provider_billing_verified': False}
