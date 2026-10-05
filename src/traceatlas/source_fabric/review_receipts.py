"""Source-specific analyst attestations; preservation alone is not qualification.

Receipts bind reviews to a check, operator, runtime and implementation. They do
not authenticate an operator or establish the truth of their attestation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..evidence import EvidenceStore, sha256_file
from ..intelligence.contracts import source_contract
from ..policy import PolicyError
from ..source_maturity import SOURCE_QUALIFICATION_GATES

SCHEMA = "traceatlas-source-review/v1"
MAX_RECEIPT_BYTES = 64 * 1024
REQUIREMENTS = {
    "documentation": "official_documentation_checked",
    "manifest": "manifest_fields_reviewed",
    "capabilities": "capability_binding_tested",
    "connector": "connector_contract_tested",
    "terms": "permitted_use_reviewed",
    "license": "redistribution_reviewed",
    "authentication": "authentication_tested",
    "configured": "configuration_tested",
    "live_request": "real_request_executed",
    "normalization": "normalization_tested",
    "evidence": "evidence_capture_tested",
    "provenance": "provenance_tested",
    "failure": "timeout_retry_failure_tested",
    "fallback": "fallback_authorization_tested",
    "rate_limits": "rate_limits_tested",
    "cost": "cost_accounting_tested",
    "security": "security_reviewed",
    "schema_drift": "schema_validation_tested",
    "tests": "unit_integration_tests_passed",
    "canary": "sustained_health_tested",
    "health": "monitoring_enabled",
    "operational_owner": "operational_owner_assigned",
    "runbook": "runbook_reviewed",
    "privacy": "privacy_retention_reviewed",
    "replay": "captured_input_replay_tested",
    "intended_runtime": "runtime_environment_verified",
}
RUNTIME_CHECKS = frozenset({"live_request", "canary", "intended_runtime"})
FIELDS = frozenset({"schema", "source_id", "case_id", "check_name", "actor",
    "reviewed_at", "expires_at", "implementation_sha256", "runtime_id",
    "outcome", "requirement", "method", "supporting_evidence_hashes", "execution_id"})


def _text(value, name, maximum=200):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum or any(ord(c) < 32 for c in value):
        raise PolicyError("Review receipt requires bounded printable " + name)
    return value


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise PolicyError("Review receipt requires SHA-256 evidence and implementation hashes")
    return value


def _time(value):
    try:
        result = datetime.fromisoformat(_text(value, "timestamp", 40).replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError):
        raise PolicyError("Review receipt requires timezone-aware timestamps") from None


def implementation_digest(source):
    """Conservatively invalidate reviews when any shared execution code changes."""
    root = Path(__file__).resolve().parents[1]
    paths = sorted({p for folder in ("intelligence", "source_fabric")
                    for p in (root / folder).glob("*.py")} |
                   {root / name for name in ("source_maturity.py", "evidence.py", "evidence_anchor.py", "db.py", "policy.py")})
    body = {"contract": source_contract(source).to_dict(),
            "files": {p.relative_to(root).as_posix(): sha256_file(p) for p in paths}}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def execution_runtime_id():
    """Operator-assigned environment label; not independent deployment proof."""
    default = "local-" + sys.platform + "-python" + str(sys.version_info.major) + "." + str(sys.version_info.minor)
    return _text(os.environ.get("TRACEATLAS_RUNTIME_ID", default), "runtime_id")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("Review receipt contains duplicate JSON fields")
        result[key] = value
    return result


def _artifact(db, workspace, case_id, digest):
    row = next((r for r in db.evidence(case_id) if r["sha256"] == digest), None)
    if row is None:
        raise PolicyError("Review must cite an artifact preserved in the case")
    path = Path(row["path"]).resolve()
    if not path.is_relative_to((Path(workspace) / "evidence" / case_id).resolve()) or sha256_file(path) != digest:
        raise PolicyError("Review evidence integrity failed")
    return path


def validate_review(db, workspace, source, check_name, case_id, evidence_hash, actor, *, now=None, code_digest=None, require_pass=True):
    """Resolve receipt and supporting bytes every time a gate is reported/used."""
    now = now or datetime.now(timezone.utc)
    if not EvidenceStore(Path(workspace), db, case_id).verify_ledger()[0]:
        raise PolicyError("Review evidence integrity failed")
    path = _artifact(db, workspace, case_id, _hash(evidence_hash))
    if path.stat().st_size > MAX_RECEIPT_BYTES:
        raise PolicyError("Review receipt exceeds 64 KiB")
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, RecursionError):
        raise PolicyError("Review requires a typed JSON qualification receipt") from None
    if not isinstance(receipt, dict) or set(receipt) != FIELDS or receipt.get("schema") != SCHEMA:
        raise PolicyError("Review requires a typed JSON qualification receipt")
    if check_name not in SOURCE_QUALIFICATION_GATES or (
            receipt["source_id"], receipt["check_name"], receipt["case_id"], receipt["actor"]) != (source, check_name, case_id, actor):
        raise PolicyError("Review receipt source, check, case or actor binding mismatch")
    _text(actor, "actor")
    _text(receipt["runtime_id"], "runtime_id")
    _text(receipt["method"], "method", 2000)
    if receipt["requirement"] != REQUIREMENTS[check_name] or not isinstance(receipt["outcome"], str) or receipt["outcome"] not in {"PASS", "FAIL"} or (require_pass and receipt["outcome"] != "PASS"):
        raise PolicyError("Review receipt does not pass the named qualification requirement")
    reviewed, expires = _time(receipt["reviewed_at"]), _time(receipt["expires_at"])
    if not now - timedelta(days=30) <= reviewed <= now or not reviewed < expires <= reviewed + timedelta(days=30) or expires <= now:
        raise PolicyError("Review receipt is expired, future-dated or exceeds 30-day validity")
    if _hash(receipt["implementation_sha256"]) != (code_digest or implementation_digest(source)):
        raise PolicyError("Review receipt does not match the current implementation")
    supporting = receipt["supporting_evidence_hashes"]
    if not isinstance(supporting, list) or not 1 <= len(supporting) <= 32 or any(not isinstance(h, str) for h in supporting) or len(set(supporting)) != len(supporting):
        raise PolicyError("Review receipt requires 1-32 distinct supporting artifacts")
    for h in supporting:
        _artifact(db, workspace, case_id, _hash(h))
    if evidence_hash in supporting:
        raise PolicyError("Review receipt cannot support itself")
    execution_id = receipt["execution_id"]
    if receipt["outcome"] == "FAIL":
        # A failed check must supersede its earlier pass even when the provider
        # did not produce capturable bytes. Preserve supporting failure evidence.
        if execution_id is not None:
            _text(execution_id, "execution_id")
            execution = db.conn.execute("SELECT source,case_id FROM fabric_executions WHERE id=?", (execution_id,)).fetchone()
            if execution is None or (execution["source"], execution["case_id"]) != (source, case_id):
                raise PolicyError("Failed runtime review execution binding mismatch")
        return receipt
    if check_name in RUNTIME_CHECKS and execution_id is None:
        raise PolicyError("Runtime review requires a real captured execution")
    if execution_id is not None:
        _text(execution_id, "execution_id")
        execution = db.conn.execute("SELECT * FROM fabric_executions WHERE id=?", (execution_id,)).fetchone()
        if execution is None or execution["source"] != source or execution["case_id"] != case_id or execution["mode"] != "live" or execution["status"] != "completed" or execution["cache_hit"] or execution["drift"] or type(execution["attempts"]) is not int or execution["attempts"] < 1:
            raise PolicyError("Runtime review requires a successful non-fixture non-cached execution")
        started = _time(execution["started_at"])
        if not reviewed - timedelta(days=7) <= started <= reviewed:
            raise PolicyError("Runtime review execution is stale or occurred after review")
        try:
            outcome = json.loads(execution["evidence_json"])
            provider = outcome["provider"]
            response_hash = provider["response_sha256"]
            raw_refs = outcome["raw_evidence_refs"]
            valid = (outcome["source"] == source and outcome["execution_id"] == execution_id
                     and provider["source"] == source and provider["fixture"] is False
                     and outcome["implementation_sha256"] == receipt["implementation_sha256"]
                     and outcome["runtime_id"] == receipt["runtime_id"]
                     and isinstance(raw_refs, list) and response_hash in raw_refs and response_hash in supporting)
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise PolicyError("Runtime review must bind preserved raw response and provider provenance")
        response_path = _artifact(db, workspace, case_id, _hash(response_hash))
        if type(provider.get("response_bytes")) is not int or response_path.stat().st_size != execution["bytes"] or provider["response_bytes"] != execution["bytes"]:
            raise PolicyError("Runtime review response size mismatch")
    return receipt


def review_template(source, check_name, case_id, actor, runtime_id):
    """Return an incomplete form; never manufacture a passing review."""
    return {"schema": SCHEMA, "source_id": source, "case_id": case_id,
            "check_name": check_name, "actor": actor, "runtime_id": runtime_id,
            "reviewed_at": None, "expires_at": None,
            "implementation_sha256": implementation_digest(source), "outcome": "UNREVIEWED",
            "requirement": REQUIREMENTS[check_name], "method": None,
            "supporting_evidence_hashes": [], "execution_id": None}
