"""Conservative offline supplied-evidence analyzer; no network, shell, or model authority."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import re
from .registry import lookup

_SECRET = re.compile(r"(?:password|passwd|api.?key|access.?token|secret|private.?key|authorization|cookie|credential.?value)", re.I)
_DENY_FIELDS = {"source_code", "raw", "body", "private_notes", "password", "secret", "token"}
_HIGH_AUTHORITY = {"SIGINT", "COMINT", "ELINT", "HUMINT"}
_MAX_RECORDS = 2000
_MAX_VALUE = 4096

def _serialize(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)

def _hash(obj):
    return hashlib.sha256(_serialize(obj).encode("utf-8")).hexdigest()

def verify(report):
    if not isinstance(report, dict) or "report_sha256" not in report:
        return False
    body = {k: v for k, v in report.items() if k != "report_sha256"}
    return _hash(body) == report["report_sha256"]

def analyze(code, payload, *, authorized=False, case_id="local"):
    definition = lookup(code)
    result = {
        "schema": "traceatlas.managed140/result-v1",
        "module_id": definition["code"], "task_id": str(case_id), "skill_id": "managed140." + definition["code"].lower(),
        "family": definition["family"], "implementation_state": "offline_adapter",
        "status": "partial", "evidence": [], "observations": [], "entity_candidates": [],
        "relationship_candidates": [], "claim_candidates": [], "corroborations": [],
        "contradictions": [], "hypotheses": [], "uncertainties": [],
        "information_gaps": [], "errors": [], "execution_trace": [],
        "timestamps": [], "provenance": {"source_independence_verified": False},
        "cost": {"usd": 0, "tool_calls": 0}
    }
    def finish():
        result["report_sha256"] = _hash(result)
        return result
    if definition["sensitive"] and not authorized:
        result["status"] = "blocked"
        result["errors"].append({"code": "AUTHORIZATION_REQUIRED"})
        return finish()
    if isinstance(payload, dict):
        rows = payload.get("records", payload.get("evidence", []))
    else:
        rows = payload
    if not isinstance(rows, list) or len(rows) > _MAX_RECORDS:
        result["status"] = "failed"
        result["errors"].append({"code": "BAD_INPUT_OR_LIMIT", "max_records": _MAX_RECORDS})
        return finish()
    claim_groups = defaultdict(list)
    any_missing = False
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            result["information_gaps"].append({"index": i, "reason": "invalid_record"})
            any_missing = True
            continue
        src = row.get("source_id") or row.get("source")
        if not isinstance(src, str) or not src.strip():
            result["information_gaps"].append({"index": i, "reason": "missing_source"})
            any_missing = True
            continue
        if definition["code"] in _HIGH_AUTHORITY and not row.get("authorization_reference"):
            result["information_gaps"].append({"index": i, "reason": "missing_collection_authorization_provenance"})
            any_missing = True
            continue
        data = row.get("data", row)
        if not isinstance(data, dict):
            result["information_gaps"].append({"index": i, "reason": "invalid_data"})
            any_missing = True
            continue
        if definition["code"] in {"SIGINT", "COMINT", "ELINT"} and not data.get("collection_authority"):
            result["information_gaps"].append({"index": i, "reason": "missing_collection_authority"})
            any_missing = True
            continue
        clean = {}
        for field in definition["fields"]:
            if field not in data or field in _DENY_FIELDS or _SECRET.search(field):
                continue
            val = data[field]
            if isinstance(val, (str, int, float, bool)) and len(str(val)) <= _MAX_VALUE:
                clean[field] = val
        receipt = {"source_id": src.strip(), "original_sha256": _hash(row),
                   "independence_group": str(row.get("independence_group") or src),
                   "observed_at": str(row.get("observed_at") or "")}
        evid = _hash(receipt)
        result["evidence"].append({"evidence_id": evid, **receipt})
        for k, v in clean.items():
            result["observations"].append({"evidence_id": evid, "field": k, "value": v,
                                           "classification": "source_reported_not_verified"})
        if not clean:
            any_missing = True
            result["information_gaps"].append({"evidence_id": evid, "reason": "no_domain_fields",
                                               "expected": list(definition["fields"])})
        subject, pred, val = data.get("claim_subject"), data.get("claim_predicate"), data.get("claim_value")
        if isinstance(subject, str) and isinstance(pred, str) and isinstance(val, (str, int, float, bool)):
            claim_groups[(subject.strip().casefold(), pred.strip().casefold())].append(
                {"evidence_id": evid, "source_group": receipt["independence_group"], "value": val})
        edge_from, edge_to = data.get("relation_from"), data.get("relation_to")
        if isinstance(edge_from, str) and isinstance(edge_to, str) and edge_from and edge_to:
            result["relationship_candidates"].append({"from": edge_from[:256], "to": edge_to[:256],
                 "type": str(data.get("relation_type", "RELATED_TO"))[:80],
                 "evidence_id": evid, "verification": "unverified"})
        if receipt["observed_at"]:
            try:
                time = datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00"))
                if time.tzinfo is not None:
                    result["timestamps"].append({"evidence_id": evid, "utc": time.astimezone(timezone.utc).isoformat()})
            except ValueError:
                result["uncertainties"].append({"evidence_id": evid, "reason": "invalid_observation_time"})
        result["execution_trace"].append({"operation": "offline_analysis", "evidence_id": evid})
    for (subject, pred), group in sorted(claim_groups.items()):
        by_value = defaultdict(lambda: defaultdict(list))
        for item in group:
            by_value[_hash(item["value"])][item["source_group"]].append(item)
        for independent in by_value.values():
            members = [vals[0] for vals in independent.values()]
            result["claim_candidates"].append({
                "subject": subject, "predicate": pred, "value": members[0]["value"],
                "evidence_ids": [x["evidence_id"] for x in members],
                "independence_groups_reported": len(members), "status": "unverified_claim"})
            if len(members) > 1:
                result["corroborations"].append({"subject": subject, "predicate": pred,
                    "evidence_ids": [x["evidence_id"] for x in members],
                    "caveat": "Source independence is asserted by inputs, not established by this module."})
        if len(by_value) > 1:
            result["contradictions"].append({"subject": subject, "predicate": pred,
                "competing_values": [next(iter(v.values()))[0]["value"] for v in by_value.values()],
                "evidence_ids": [x["evidence_id"] for x in group],
                "note": "Disagreement is not automatic evidence of deception."})
    if not result["evidence"]:
        result["information_gaps"].append({"reason": "no_usable_authorized_evidence"})
    elif result["observations"] and not any_missing:
        result["status"] = "completed"
    if not claim_groups:
        result["uncertainties"].append({"reason": "no_testable_claims_supplied"})
    return finish()
