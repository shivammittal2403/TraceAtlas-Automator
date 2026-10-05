from __future__ import annotations

import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..evidence import EvidenceStore
from ..policy import PolicyError
from .registry import SOURCES, KNOWN_BROKEN
from ..source_maturity import SOURCE_QUALIFICATION_GATES, LIVE_VERIFICATION_GATES, normalize_maturity
from .review_receipts import validate_review, implementation_digest

QUALIFICATION_CHECKS = SOURCE_QUALIFICATION_GATES


def utc():
    return datetime.now(timezone.utc).isoformat()


class FabricStore:
    def __init__(self, db, workspace=None):
        self.db = db
        self.workspace = Path(workspace) if workspace is not None else db.path.parent
        db.conn.executescript("""
        CREATE TABLE IF NOT EXISTS fabric_executions (
          id TEXT PRIMARY KEY, source TEXT NOT NULL, case_id TEXT NOT NULL, request_hash TEXT NOT NULL,
          authority_hash TEXT NOT NULL, status TEXT NOT NULL, mode TEXT NOT NULL, started_at TEXT NOT NULL,
          duration_ms INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0,
          evidence_json TEXT DEFAULT '{}', schema_fingerprint TEXT, drift INTEGER DEFAULT 0,
          cache_hit INTEGER DEFAULT 0, error_code TEXT);
        CREATE TABLE IF NOT EXISTS fabric_reviews (
          id INTEGER PRIMARY KEY, source TEXT NOT NULL, check_name TEXT NOT NULL, case_id TEXT NOT NULL,
          evidence_hash TEXT NOT NULL, actor TEXT NOT NULL, at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fabric_promotions (
          source TEXT PRIMARY KEY, state TEXT NOT NULL, actor TEXT NOT NULL, at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fabric_candidates (
          candidate_id TEXT PRIMARY KEY, manifest_json TEXT NOT NULL, at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fabric_slots (
          id TEXT PRIMARY KEY, provider TEXT NOT NULL, case_id TEXT NOT NULL, expires_at TEXT NOT NULL);
        """)
        columns = {row[1] for row in db.conn.execute("PRAGMA table_info(fabric_promotions)")}
        for name in ("runtime_id", "review_digest"):
            if name not in columns:
                db.conn.execute("ALTER TABLE fabric_promotions ADD COLUMN " + name + " TEXT")
        db.conn.commit()

    def acquire_slot(self, identifier, provider, case_id, timeout):
        self.db.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = list(self.db.conn.execute("SELECT provider,case_id FROM fabric_slots WHERE expires_at>?", (utc(),)))
            if len(rows) >= 4 or sum(r["case_id"] == case_id for r in rows) >= 3 or any(r["provider"] == provider for r in rows):
                raise PolicyError("workspace concurrency budget exhausted")
            expires = (datetime.now(timezone.utc)+timedelta(seconds=timeout+10)).isoformat()
            self.db.conn.execute("INSERT INTO fabric_slots VALUES(?,?,?,?)", (identifier, provider, case_id, expires))
            self.db.conn.commit()
        except BaseException:
            self.db.conn.rollback()
            raise

    def release_slot(self, identifier):
        self.db.conn.execute("DELETE FROM fabric_slots WHERE id=?", (identifier,))
        self.db.conn.commit()

    def states(self, *, workspace=None):
        workspace = Path(workspace) if workspace is not None else self.workspace
        verified_cases = {}
        cutoff = (datetime.now(timezone.utc)-timedelta(days=7)).isoformat()
        result = {}
        seen = set()
        groups = {}
        for r in self.db.conn.execute("SELECT * FROM fabric_executions WHERE mode='live' AND cache_hit=0 AND started_at>? ORDER BY started_at DESC", (cutoff,)):
            if r['source'] not in SOURCES:
                continue
            if r["source"] in seen:
                continue
            seen.add(r["source"])
            if r["status"] == "completed" and not r["drift"]:
                groups[r["source"]] = self._review_groups(r["source"])
                result[r["source"]] = "LIVE_VERIFIED" if any(
                    LIVE_VERIFICATION_GATES.issubset(checks) for checks in groups[r["source"]].values()) else "LIVE_TESTED"
                if self._verified_case_hashes(r["case_id"], workspace, verified_cases) is None:
                    result[r["source"]] = "DEGRADED"
                    continue
                checks = self._resolved_checks(r["source"], workspace, verified_cases)
                result[r["source"]] = "LIVE_VERIFIED" if LIVE_VERIFICATION_GATES.issubset(checks) else "LIVE_TESTED"
            elif r["status"] == "failed" or r["drift"]:
                result[r["source"]] = "DEGRADED"
        for r in self.db.conn.execute("SELECT * FROM fabric_promotions"):
            if r["state"] in {"DISABLED", "BROKEN", "DEGRADED", "DEPRECATED"}:
                result[r["source"]] = normalize_maturity(r["state"])
            elif r["state"] == "PRODUCTION_QUALIFIED" and result.get(r["source"]) == "LIVE_VERIFIED" and r["at"] > cutoff:
                checks = groups[r["source"]].get(r["runtime_id"], {})
                if QUALIFICATION_CHECKS.issubset(checks) and self._review_digest(checks) == r["review_digest"]:
                review_cutoff = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
                reviews = list(self.db.conn.execute(
                    "SELECT check_name,case_id,evidence_hash FROM fabric_reviews WHERE source=? AND at>?",
                    (r["source"], review_cutoff)))
                # Recheck the current checklist so older promotions cannot survive
                # a qualification-policy expansion on their previous evidence set.
                # Also fail closed if a legacy/direct database row cites no artifact.
                reviewed = {row["check_name"] for row in reviews}
                evidence_by_case = {}
                refs_resolve = True
                for row in reviews:
                    case_id = row["case_id"]
                    if case_id not in evidence_by_case:
                        evidence_by_case[case_id] = self._verified_case_hashes(case_id, workspace, verified_cases)
                    if evidence_by_case[case_id] is None or row["evidence_hash"] not in evidence_by_case[case_id]:
                        refs_resolve = False
                        break
                if QUALIFICATION_CHECKS.issubset(reviewed) and refs_resolve:
                    result[r["source"]] = r["state"]
        result.update({source: "DEGRADED" for source in KNOWN_BROKEN})
        return result

    @staticmethod
    def _review_digest(checks):
        return hashlib.sha256(json.dumps(checks, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _review_groups(self, source, workspace=None):
        """Revalidate latest review per check; no fallback to superseded passes."""
        workspace = Path(workspace) if workspace is not None else self.db.path.parent
        now = datetime.now(timezone.utc)
        groups, seen = {}, set()
        code_digest = implementation_digest(source)
        for row in self.db.conn.execute(
                "SELECT * FROM fabric_reviews WHERE source=? ORDER BY id DESC", (source,)):
            if row['check_name'] in seen:
                continue
            seen.add(row['check_name'])
            try:
                receipt = validate_review(self.db, workspace, source, row['check_name'], row['case_id'],
                    row['evidence_hash'], row['actor'], now=now, code_digest=code_digest)
                recorded = datetime.fromisoformat(row['at'].replace('Z', '+00:00'))
                if recorded.tzinfo is None or not now - timedelta(days=30) <= recorded <= now:
                    continue
            except (PolicyError, OSError, ValueError, TypeError, KeyError):
                continue
            groups.setdefault(receipt['runtime_id'], {})[row['check_name']] = row['evidence_hash']
        return groups

    def _resolved_checks(self, source):
        groups = self._review_groups(source)
        return set(max(groups.values(), key=len, default={}))
    def _verified_case_hashes(self, case_id, workspace, verified_cases):
        """Revalidate preserved bytes and configured anchors once per projection."""
        if case_id not in verified_cases:
            try:
                valid, _ = EvidenceStore(workspace, self.db, case_id).verify_ledger()
                verified_cases[case_id] = ({item['sha256'] for item in self.db.evidence(case_id)}
                                           if valid else None)
            except (OSError, ValueError, TypeError):
                verified_cases[case_id] = None
        return verified_cases[case_id]

    def _resolved_checks(self, source, workspace=None, verified_cases=None):
        """Only recent reviews with currently intact same-case custody count."""
        workspace = Path(workspace) if workspace is not None else self.workspace
        verified_cases = {} if verified_cases is None else verified_cases
        cutoff = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
        checks, hashes = set(), {}
        for row in self.db.conn.execute(
                "SELECT check_name,case_id,evidence_hash FROM fabric_reviews WHERE source=? AND at>?", (source, cutoff)):
            if row['case_id'] not in hashes:
                hashes[row['case_id']] = self._verified_case_hashes(row['case_id'], workspace, verified_cases)
            if hashes[row['case_id']] is not None and row['evidence_hash'] in hashes[row['case_id']]:
                checks.add(row['check_name'])
        return checks

    def review(self, source, check_name, case_id, evidence_hash, actor, workspace, authorized=False):
        if authorized is not True or source not in SOURCES or check_name not in QUALIFICATION_CHECKS or not isinstance(actor, str) or len(actor.strip()) < 2:
            raise PolicyError("Explicit analyst authority, implemented source and named review check required")
        if Path(workspace).resolve() != self.db.path.parent.resolve():
            raise PolicyError("Review workspace must match the canonical case database")
        validate_review(self.db, workspace, source, check_name, case_id, evidence_hash, actor, require_pass=False)
        self.db.conn.execute("INSERT INTO fabric_reviews(source,check_name,case_id,evidence_hash,actor,at) VALUES(?,?,?,?,?,?)",
                             (source, check_name, case_id, evidence_hash, actor, utc()))
        self.db.conn.commit()

    def promote(self, source, actor, workspace, authorized=False):
        if authorized is not True or not isinstance(actor, str) or len(actor.strip()) < 2 or source not in SOURCES:
            raise PolicyError("Explicit local analyst authority is required")
        if self.states(workspace=workspace).get(source) not in {"LIVE_VERIFIED", "PRODUCTION_QUALIFIED"}:
            raise PolicyError("Recent successful non-fixture canary and resolved live-verification reviews required")
        canary = self.db.conn.execute("SELECT case_id FROM fabric_executions WHERE source=? AND mode='live' AND cache_hit=0 ORDER BY started_at DESC LIMIT 1", (source,)).fetchone()
        if not canary or not EvidenceStore(workspace, self.db, canary["case_id"]).verify_ledger()[0]:
            raise PolicyError("Canary artifact integrity failed")
        groups = self._review_groups(source, workspace)
        eligible = sorted(runtime for runtime, checks in groups.items() if QUALIFICATION_CHECKS.issubset(checks))
        if not eligible:
            raise PolicyError("Qualification review checklist is incomplete or its receipts do not resolve within one runtime")
        if len(eligible) != 1:
            raise PolicyError("Qualification runtime is ambiguous")
        runtime = eligible[0]
        self.db.conn.execute("INSERT INTO fabric_promotions(source,state,actor,at,runtime_id,review_digest) VALUES(?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET state=excluded.state,actor=excluded.actor,at=excluded.at,runtime_id=excluded.runtime_id,review_digest=excluded.review_digest",
                             (source, "PRODUCTION_QUALIFIED", actor, utc(), runtime, self._review_digest(groups[runtime])))
        self.db.conn.commit()
        return {"source": source, "state": "PRODUCTION_QUALIFIED", "validity_days": 7, "runtime_id": runtime}

    def metrics(self):
        rows = [dict(r) for r in self.db.conn.execute("SELECT * FROM fabric_executions")]
        live = [r for r in rows if r["mode"] == "live"]
        calls = [r for r in live if not r["cache_hit"]]
        successes = [r for r in calls if r["status"] == "completed"]
        def rate(n, denominator):
            return n/denominator if denominator else None
        return {"source_actions": len(live), "network_attempts": sum(r["attempts"] for r in calls),
                "fixture_actions_excluded": len(rows)-len(live), "retrieval_success_rate": rate(len(successes), len(calls)),
                "schema_drift_rate": rate(sum(r["drift"] for r in calls), len(calls)),
                "cache_hit_rate": rate(sum(r["cache_hit"] for r in live), len(live)),
                "average_latency_ms": rate(sum(r["duration_ms"] for r in calls), len(calls)),
                "useful_evidence_rate": rate(sum(bool(json.loads(r["evidence_json"]).get("stats", {}).get("records_stored")) for r in successes), len(successes)),
                "parser_success_rate": None,
                "healthy_source_percentage": rate(sum(state in {"LIVE_VERIFIED", "PRODUCTION_QUALIFIED"} for state in self.states().values()), len(set(self.states()) | {r["source"] for r in calls})),
                "average_api_cost_per_case": None, "compute_cost": None, "independent_evidence_yield": None,
                "completion_improvement": None, "unknown_metrics_are_not_zero": True}
