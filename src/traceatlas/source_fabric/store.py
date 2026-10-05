from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

from ..evidence import EvidenceStore
from ..policy import PolicyError
from .registry import SOURCES, KNOWN_BROKEN
from ..source_maturity import SOURCE_QUALIFICATION_GATES, LIVE_VERIFICATION_GATES, normalize_maturity

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
        for r in self.db.conn.execute("SELECT * FROM fabric_executions WHERE mode='live' AND cache_hit=0 AND started_at>? ORDER BY started_at DESC", (cutoff,)):
            if r['source'] not in SOURCES:
                continue
            if r["source"] in seen:
                continue
            seen.add(r["source"])
            if r["status"] == "completed" and not r["drift"]:
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
        if not authorized or source not in SOURCES or check_name not in QUALIFICATION_CHECKS or not isinstance(actor, str) or len(actor) < 2:
            raise PolicyError("Explicit analyst authority, implemented source and named review check required")
        if not EvidenceStore(workspace, self.db, case_id).verify_ledger()[0]:
            raise PolicyError("Review evidence integrity failed")
        if not any(r["sha256"] == evidence_hash for r in self.db.evidence(case_id)):
            raise PolicyError("Review must cite an artifact preserved in the case")
        self.db.conn.execute("INSERT INTO fabric_reviews(source,check_name,case_id,evidence_hash,actor,at) VALUES(?,?,?,?,?,?)",
                             (source, check_name, case_id, evidence_hash, actor, utc()))
        self.db.conn.commit()

    def promote(self, source, actor, workspace, authorized=False):
        if not authorized or not isinstance(actor, str) or len(actor) < 2 or source not in SOURCES:
            raise PolicyError("Explicit local analyst authority is required")
        if self.states(workspace=workspace).get(source) not in {"LIVE_VERIFIED", "PRODUCTION_QUALIFIED"}:
            raise PolicyError("Recent successful non-fixture canary and resolved live-verification reviews required")
        canary = self.db.conn.execute("SELECT case_id FROM fabric_executions WHERE source=? AND mode='live' AND cache_hit=0 ORDER BY started_at DESC LIMIT 1", (source,)).fetchone()
        if not canary or not EvidenceStore(workspace, self.db, canary["case_id"]).verify_ledger()[0]:
            raise PolicyError("Canary artifact integrity failed")
        cutoff = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
        reviews = [dict(r) for r in self.db.conn.execute("SELECT * FROM fabric_reviews WHERE source=? AND at>?", (source, cutoff))]
        if QUALIFICATION_CHECKS-set(r["check_name"] for r in reviews):
            raise PolicyError("Qualification review checklist is incomplete")
        for r in reviews:
            if not EvidenceStore(workspace, self.db, r["case_id"]).verify_ledger()[0]:
                raise PolicyError("Qualification review artifact integrity failed")
            if not any(item["sha256"] == r["evidence_hash"] for item in self.db.evidence(r["case_id"])):
                raise PolicyError("Qualification review reference does not resolve within its case")
        self.db.conn.execute("INSERT INTO fabric_promotions VALUES(?,?,?,?) ON CONFLICT(source) DO UPDATE SET state=excluded.state,actor=excluded.actor,at=excluded.at",
                             (source, "PRODUCTION_QUALIFIED", actor, utc()))
        self.db.conn.commit()
        return {"source": source, "state": "PRODUCTION_QUALIFIED", "validity_days": 7}

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
