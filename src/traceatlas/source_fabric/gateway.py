"""Parallel bounded transport with serialized case/evidence writes."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from ..employee.brief import digest
from ..evidence import EvidenceStore
from ..intelligence.hub import IntelligenceHub
from ..policy import PolicyError
from .primitives import ConnectorFactory
from .store import FabricStore, utc
from .review_receipts import implementation_digest, execution_runtime_id

_GLOBAL = threading.BoundedSemaphore(4)
_LOCK = threading.Lock()
_PROVIDERS, _LAST = {}, {}


def _shape(value):
    if isinstance(value, dict):
        return {k: type(v).__name__ for k, v in sorted(value.items())[:80]}
    if isinstance(value, list):
        return {"type": "list", "first_record": _shape(value[0]) if value else None}
    return type(value).__name__


def _secret_fields(value, depth=0):
    if depth > 30:
        return True
    if isinstance(value, dict):
        return any(str(k).casefold() in {"authorization", "api_key", "apikey", "access_token", "password", "secret"}
                   or _secret_fields(v, depth+1) for k, v in value.items())
    if isinstance(value, list):
        return any(_secret_fields(v, depth+1) for v in value)
    return False


class SourceGateway:
    def __init__(self, db, workspace, *, requester=None):
        self.db, self.workspace, self.requester = db, workspace, requester
        self.store = FabricStore(db)
        self.hub = IntelligenceHub(db, workspace)

    def _check_authority(self, case_id, action, attestations, authority_hash):
        """Read current immutable authority independently on each transport thread."""
        if os.getenv('TRACEATLAS_WORKFORCE_KILL_SWITCH', '').casefold() in {'1', 'yes', 'true'}:
            raise PolicyError('Source Fabric kill switch is active')
        try:
            # Never share the case writer connection across worker threads.
            uri = self.db.path.resolve().as_uri() + '?mode=ro'
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                row = conn.execute(
                    'SELECT manifest_json,status,cancel_requested FROM autonomous_investigations '
                    'WHERE case_id=? AND manifest_hash=?', (case_id, authority_hash)).fetchone()
            if not row or row[1] != 'running' or row[2]:
                raise PolicyError('Gateway requires active, uncancelled authorization')
            scope = json.loads(row[0])
            if (digest(scope) != authority_hash or scope['attestations'] != attestations or
                scope.get('case_id') != case_id):
                raise PolicyError('Gateway immutable authorization changed')
            if datetime.now(timezone.utc) >= datetime.fromisoformat(scope['expires_at']):
                raise PolicyError('Gateway authorization expired')
            if action is not None and action not in scope['actions']:
                raise PolicyError('Gateway action is outside immutable authorization')
            from ..employee.autonomous import skill_contract_digest
            if scope['skills_digest'] != skill_contract_digest(scope.get('source_fabric', False)):
                raise PolicyError('Gateway executable contracts changed')
            return scope
        except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
            raise PolicyError('Gateway authorization cannot be validated') from exc

    def _fetch(self, action, timeout, authorization_check):
        connector = ConnectorFactory.create(action["source"], requester=self.requester,
                                            authorization_check=authorization_check)
        provider = connector.definition["provider"]
        deadline = time.monotonic()+timeout
        def remaining():
            value = deadline-time.monotonic()
            if value <= 0:
                raise TimeoutError("source deadline")
            return value
        with _LOCK:
            lock = _PROVIDERS.setdefault(provider, threading.Lock())
        acquired = global_acquired = False
        try:
            global_acquired = _GLOBAL.acquire(timeout=remaining())
            if not global_acquired:
                raise TimeoutError("global concurrency budget")
            acquired = lock.acquire(timeout=remaining())
            if not acquired:
                raise TimeoutError("provider concurrency budget")
            wait = max(0, 1-(time.monotonic()-_LAST.get(provider, 0)))
            if wait >= remaining():
                raise TimeoutError("rate interval exceeds deadline")
            if wait:
                time.sleep(wait)
            _LAST[provider] = time.monotonic()
            authorization_check()
            response = connector.fetch(action["target_type"], action["target"], remaining())
            authorization_check()
            records = connector.normalize(action["target_type"], action["target"], response)
            return connector, response, records
        finally:
            if acquired:
                lock.release()
            if global_acquired:
                _GLOBAL.release()
            connector.close()

    def collect_batch(self, case_id, actions, attestations, authority_hash, *, timeout=30):
        if not 1 <= len(actions) <= 3 or not 0 < timeout <= 30:
            raise PolicyError("Gateway allows 1-3 concurrent source actions and at most 30 seconds each")
        scope = self._check_authority(case_id, None, attestations, authority_hash)
        if any(action not in scope["actions"] for action in actions):
            raise PolicyError("Gateway action is outside the immutable authorization manifest")
        store = EvidenceStore(self.workspace, self.db, case_id)
        if not store.verify_ledger()[0]:
            raise PolicyError("Existing case custody integrity failed")
        ready, completed = [], []
        for action in actions:
            self._check_authority(case_id, action, attestations, authority_hash)
            connector = ConnectorFactory.create(action["source"], requester=self.requester)
            if connector.definition["health"]["state"] == "DEGRADED":
                raise PolicyError("Known incompatible connector is disabled in Source Fabric")
            # Authorization is checked again on cache hits and every dispatch.
            self.hub._gate(case_id, connector.spec, authorized=True,
                **{k: bool(attestations.get(k)) for k in ("owned_asset", "owned_org", "subject_consent", "public_record_basis")})
            connector.validate_input(action["target_type"], action["target"])
            code_digest, runtime_id = implementation_digest(action["source"]), execution_runtime_id()
            key = digest([action["source"], action["target_type"], action["target"], connector.definition["contract"]["contract_version"], code_digest, runtime_id])
            execution_id = "source-execution-"+uuid4().hex
            mode = "fixture" if connector.fixture else "live"
            ttl = connector.definition["freshness"]["local_cache_ttl_seconds"]
            cutoff = (datetime.now(timezone.utc)-timedelta(seconds=ttl)).isoformat()
            cached = self.db.conn.execute("SELECT evidence_json FROM fabric_executions WHERE case_id=? AND source=? AND request_hash=? AND status='completed' AND cache_hit=0 AND drift=0 AND mode=? AND started_at>? ORDER BY started_at DESC LIMIT 1",
                (case_id, action["source"], key, mode, cutoff)).fetchone() if ttl else None
            self.db.conn.execute("INSERT INTO fabric_executions(id,source,case_id,request_hash,authority_hash,status,mode,started_at) VALUES(?,?,?,?,?,'running',?,?)",
                (execution_id, action["source"], case_id, key, authority_hash, mode, utc()))
            self.db.conn.commit()
            if cached:
                outcome = {**json.loads(cached["evidence_json"]), "cache_hit": True, "execution_id": execution_id}
                self.db.conn.execute("UPDATE fabric_executions SET status='completed',cache_hit=1,evidence_json=? WHERE id=?", (json.dumps(outcome), execution_id))
                self.db.conn.commit()
                completed.append({"action_id": action["action_id"], "state": "completed", "outcome": outcome, "duration_seconds": 0})
            else:
                try:
                    self.store.acquire_slot(execution_id, connector.definition["provider"], case_id, timeout)
                    ready.append((action, execution_id, key, code_digest, runtime_id))
                except PolicyError:
                    self.db.conn.execute("UPDATE fabric_executions SET status='failed',error_code='concurrency_budget' WHERE id=?", (execution_id,))
                    self.db.conn.commit()
                    completed.append({"action_id": action["action_id"], "state": "failed", "duration_seconds": 0,
                                      "outcome": {"source": action["source"], "error_type": "concurrency_budget", "execution_id": execution_id}})
        # Only network/parse work runs in threads. SQLite and custody ledger writes remain on this thread.
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="traceatlas-source") as pool:
            futures = {pool.submit(self._fetch, a, timeout,
                lambda action=a: self._check_authority(case_id, action, attestations, authority_hash)):
                (a, eid, key, code, runtime, time.monotonic())
                       for a, eid, key, code, runtime in ready}
            for future in as_completed(futures):
                action, execution_id, key, code_digest, runtime_id, started = futures[future]
                try:
                    connector, response, records = future.result()
                    # Revoked responses cannot be promoted after an in-flight request.
                    self._check_authority(case_id, action, attestations, authority_hash)
                    if implementation_digest(action["source"]) != code_digest or execution_runtime_id() != runtime_id:
                        raise PolicyError("Source implementation or runtime changed during collection")
                    signature = digest(_shape(response.data))
                    prior = self.db.conn.execute("SELECT schema_fingerprint FROM fabric_executions WHERE source=? AND mode=? AND status='completed' AND schema_fingerprint IS NOT NULL ORDER BY started_at DESC LIMIT 1", (action["source"], "fixture" if connector.fixture else "live")).fetchone()
                    drift = bool(prior and prior["schema_fingerprint"] != signature)
                    outcome = self.hub._store(case_id, connector.spec, records, mode="fabric:"+("fixture" if connector.fixture else "live"), target_fingerprint=key)
                    raw_refs = []
                    retain = (not connector.spec.personal_data and
                              action['source'] not in {'pypi', 'datacite'} and
                              not _secret_fields(response.data))
                    if retain and response.raw is not None:
                        with tempfile.TemporaryDirectory(prefix="traceatlas-raw-") as temporary:
                            path = Path(temporary)/"source-response.json"
                            path.write_bytes(response.raw)
                            raw_refs.append(store.preserve_file(path, "source-fabric:"+action["source"]+":raw")["sha256"])
                    outcome.update({"source": action["source"], "execution_id": execution_id, "cache_hit": False,
                        "implementation_sha256": code_digest, "runtime_id": runtime_id,
                        "raw_evidence_refs": raw_refs, "raw_retention": "retained" if raw_refs else "privacy-withheld",
                        "provider": connector.evidence_metadata(response), "schema_drift": drift})
                    self.db.conn.execute("UPDATE fabric_executions SET status='completed',duration_ms=?,bytes=?,attempts=?,evidence_json=?,schema_fingerprint=?,drift=? WHERE id=?",
                        (int((time.monotonic()-started)*1000), response.bytes_received, response.attempts, json.dumps(outcome), signature, int(drift), execution_id))
                    self.db.conn.commit()
                    if not connector.fixture:
                        self.db.record_connector_result(action["source"], not drift, "schema_field_drift" if drift else None)
                    completed.append({"action_id": action["action_id"], "state": "completed", "outcome": outcome,
                                      "duration_seconds": time.monotonic()-started})
                except Exception as exc:
                    code = getattr(exc, "code", type(exc).__name__)
                    self.db.conn.execute("UPDATE fabric_executions SET status='failed',duration_ms=?,attempts=?,error_code=? WHERE id=?",
                        (int((time.monotonic()-started)*1000), getattr(exc, "attempts", 0), str(code)[:100], execution_id))
                    self.db.conn.commit()
                    if self.requester is None:
                        self.db.record_connector_result(action["source"], False, str(code)[:100])
                    completed.append({"action_id": action["action_id"], "state": "failed",
                        "duration_seconds": time.monotonic()-started,
                        "outcome": {"source": action["source"], "error_type": str(code), "execution_id": execution_id,
                                    "quarantine": "failure metadata only; unvalidated body not promoted to evidence"}})
                finally:
                    self.store.release_slot(execution_id)
        return completed
