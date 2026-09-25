"""Isolated, allowlisted worker for the Supabase control plane."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .engine import Engine
from .integrations import IntegrationRunner
from .intelligence import IntelligenceHub
from .intelligence.sanitize import sanitize_record
from .policy import validate_target
from .spider import SpiderEngine


UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I,
)
WORKFLOWS = {"domain_passive": "domain", "ip_passive": "ip",
             "url_metadata": "url", "hash_reputation": "hash"}


class WorkerError(RuntimeError):
    pass


class SupabaseAdminGateway:
    """Small service-role client. Never import this module in browser code."""

    def __init__(self, url: str | None = None, secret: str | None = None, timeout: int = 20):
        self.url = (url or os.environ.get("SUPABASE_URL", "")).strip().rstrip("/")
        self.secret = (secret or os.environ.get("SUPABASE_SECRET_KEY", "")).strip()
        parsed = urllib.parse.urlparse(self.url)
        local = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
        hosted = parsed.scheme == "https" and bool(parsed.hostname) and parsed.hostname.endswith(".supabase.co")
        if not hosted and not (local and os.environ.get("TRACEATLAS_ALLOW_LOCAL_SUPABASE") == "1"):
            raise WorkerError("SUPABASE_URL must be an approved hosted or explicitly enabled local endpoint")
        if len(self.secret) < 20 or len(self.secret) > 4096 or any(char.isspace() for char in self.secret):
            raise WorkerError("SUPABASE_SECRET_KEY is missing or malformed")
        self.timeout = max(5, min(int(timeout), 60))

    def request(self, method: str, path: str, *, payload: Any = None,
                query: dict[str, str] | None = None, prefer: str | None = None) -> Any:
        if not path.startswith("/rest/v1/") or ".." in path:
            raise WorkerError("Blocked Supabase path")
        url = self.url + path
        if query:
            url += "?" + urllib.parse.urlencode(query, safe="(),.*:")
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json", "apikey": self.secret,
                   "Authorization": f"Bearer {self.secret}", "User-Agent": "TraceAtlas-Worker/1.1"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if prefer:
            headers["Prefer"] = prefer
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            raise WorkerError(f"Supabase request failed: {type(exc).__name__}") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise WorkerError("Supabase returned invalid JSON") from exc

    def rpc(self, name: str, payload: dict[str, Any] | None = None) -> Any:
        if name not in {"claim_next_investigation_job", "complete_investigation_job",
                        "recover_stale_investigation_jobs"}:
            raise WorkerError("Blocked worker RPC")
        return self.request("POST", f"/rest/v1/rpc/{name}", payload=payload or {})

    def select_one(self, table: str, row_id: str, columns: str) -> dict[str, Any]:
        if table not in {"assets", "cases"} or not UUID_RE.fullmatch(row_id):
            raise WorkerError("Blocked worker lookup")
        result = self.request("GET", f"/rest/v1/{table}", query={
            "id": f"eq.{row_id}", "select": columns, "limit": "1",
        })
        if not isinstance(result, list) or len(result) != 1:
            raise WorkerError(f"{table[:-1]} not found")
        return result[0]

    def insert(self, table: str, payload: dict[str, Any]) -> Any:
        if table not in {"job_events", "evidence_items", "graph_entities", "graph_edges"}:
            raise WorkerError("Blocked worker insert")
        return self.request("POST", f"/rest/v1/{table}", payload=payload, prefer="return=representation")

    def upsert(self, table: str, payload: dict[str, Any], conflict: str) -> Any:
        if table != "graph_entities" or conflict != "case_id,fingerprint":
            raise WorkerError("Blocked worker upsert")
        return self.request("POST", f"/rest/v1/{table}", payload=payload,
                            query={"on_conflict": conflict},
                            prefer="resolution=merge-duplicates,return=representation")


def worker_id(value: str | None = None) -> str:
    candidate = (value or os.environ.get("TRACEATLAS_WORKER_ID") or f"worker-{socket.gethostname()}").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{3,120}", candidate):
        raise WorkerError("TRACEATLAS_WORKER_ID is invalid")
    return candidate


def _redact(value: Any, target: str) -> Any:
    if isinstance(value, dict):
        return {str(key)[:120]: _redact(item, target) for key, item in list(value.items())[:200]}
    if isinstance(value, list):
        return [_redact(item, target) for item in value[:500]]
    if isinstance(value, str):
        return (value.replace(target, "<redacted-target>") if target else value)[:4000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:4000]


def _require_public_target(target_type: str, target: str) -> None:
    """Re-check database records immediately before a network workflow."""
    if target_type == "ip":
        if not ipaddress.ip_address(target).is_global:
            raise WorkerError("Cloud workers reject private or reserved IP targets")
        return
    if target_type == "hash":
        if not re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", target):
            raise WorkerError("Cloud worker received an invalid file hash")
        return
    parsed = urllib.parse.urlparse(target) if target_type == "url" else None
    host = parsed.hostname if parsed else target
    if not host or (parsed and (parsed.username or parsed.password)):
        raise WorkerError("Cloud worker received an invalid network target")
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise WorkerError("Cloud target did not resolve") from exc
    if not addresses or any(not ipaddress.ip_address(raw).is_global for raw in addresses):
        raise WorkerError("Cloud workers reject targets resolving to non-public addresses")


class CloudWorker:
    def __init__(self, workspace: Path, gateway: SupabaseAdminGateway | None = None,
                 identity: str | None = None):
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.gateway = gateway or SupabaseAdminGateway()
        self.identity = worker_id(identity)

    def recover_stale(self) -> int:
        return int(self.gateway.rpc("recover_stale_investigation_jobs") or 0)

    @staticmethod
    def _validate_job(job: dict[str, Any]) -> tuple[str, str, str, str]:
        values = tuple(str(job.get(key, "")) for key in ("id", "case_id", "asset_id", "organisation_id"))
        if not all(UUID_RE.fullmatch(value) for value in values):
            raise WorkerError("Claimed job contains invalid identifiers")
        if job.get("kind") not in WORKFLOWS or job.get("status") != "running":
            raise WorkerError("Claimed job violates workflow policy")
        return values  # type: ignore[return-value]

    def _run(self, job: dict[str, Any], asset: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
        kind = str(job["kind"])
        target_type = str(asset.get("target_type", ""))
        target = str(asset.get("target_value", ""))
        if WORKFLOWS[kind] != target_type:
            raise WorkerError("Job kind and asset type do not match")
        if asset.get("ownership_basis") not in {"owned_asset", "written_authorization"}:
            raise WorkerError("Asset lacks an accepted authority basis")
        validate_target(target_type, target)
        _require_public_target(target_type, target)

        local_case_id = "cloud-" + str(job["id"]).replace("-", "")[:24]
        engine = Engine(self.workspace)
        try:
            if not engine.db.get_case(local_case_id):
                engine.db.create_case(local_case_id, str(case.get("title", "Cloud investigation"))[:160],
                                      str(case.get("purpose", "Authorised defensive OSINT review"))[:1000])
            if kind == "domain_passive":
                result = IntegrationRunner(engine.db, self.workspace).run_domain_pipeline(
                    local_case_id, target, authorized=True, verify=False, allow_active=False, max_assets=25)
            elif kind in {"ip_passive", "url_metadata"}:
                seed_type = "IP_ADDRESS" if target_type == "ip" else "URL"
                enabled = ["reverse_dns"] if target_type == "ip" else ["url_domain"]
                result = SpiderEngine(engine.db).scan(local_case_id, seed_type, target,
                                                     enabled_modules=enabled, max_events=100, max_depth=2)
            elif kind == "hash_reputation":
                result = IntelligenceHub(engine.db, self.workspace).collect(
                    local_case_id, "virustotal", "hash", target, authorized=True, owned_asset=True)
            else:
                raise WorkerError("Unsupported workflow")

            findings = engine.db.findings(local_case_id)
            scans = engine.db.spider_scans(local_case_id)
            observations: list[dict[str, Any]] = []
            for finding in findings[:100]:
                observations.append({"type": "FINDING", "title": finding.get("title"),
                                     "value": finding.get("value"), "source": finding.get("source"),
                                     "confidence": finding.get("confidence"), "severity": finding.get("severity"),
                                     "observation": finding.get("observation")})
            for scan in scans[:20]:
                for event in engine.db.spider_events(str(scan["id"]))[:100]:
                    observations.append({"type": event.get("event_type"), "value": event.get("data"),
                                         "source": event.get("source"), "confidence": event.get("confidence"),
                                         "risk": event.get("risk"), "tags": event.get("tags")})
            return {"workflow": kind, "status": str(result.get("status", "completed")),
                    "review_required": True, "finding_count": len(findings), "scan_count": len(scans),
                    "summary": _redact(result, target),
                    "observations": _redact(sanitize_record(observations[:200]), target),
                    "local_case": local_case_id}
        finally:
            engine.close()

    def run_once(self) -> bool:
        claimed = self.gateway.rpc("claim_next_investigation_job", {"p_worker_id": self.identity})
        if not claimed:
            return False
        job = claimed[0] if isinstance(claimed, list) else claimed
        if not isinstance(job, dict):
            raise WorkerError("Invalid claimed job response")
        job_id, case_id, asset_id, organisation_id = self._validate_job(job)
        try:
            asset = self.gateway.select_one("assets", asset_id,
                "id,organisation_id,target_type,target_value,target_fingerprint,ownership_basis,label")
            case = self.gateway.select_one("cases", case_id, "id,organisation_id,title,purpose,status")
            if asset.get("organisation_id") != organisation_id or case.get("organisation_id") != organisation_id:
                raise WorkerError("Cross-organisation job references were rejected")
            if case.get("status") not in {"open", "review"}:
                raise WorkerError("Closed or archived cases cannot execute jobs")
            output = self._run(job, asset, case)
            canonical = json.dumps(output, sort_keys=True, separators=(",", ":")).encode("utf-8")
            content_hash = hashlib.sha256(canonical).hexdigest()
            evidence = self.gateway.insert("evidence_items", {
                "organisation_id": organisation_id, "case_id": case_id, "job_id": job_id,
                "source": f"traceatlas-worker:{job['kind']}", "classification": "observed",
                "content_hash": content_hash, "payload": output,
            })
            evidence_id = evidence[0]["id"] if isinstance(evidence, list) and evidence else None
            self.gateway.upsert("graph_entities", {
                "organisation_id": organisation_id, "case_id": case_id, "evidence_id": evidence_id,
                "entity_type": str(asset["target_type"]).upper(),
                "label": str(asset.get("label") or asset["target_value"])[:500],
                "confidence": 100, "classification": "observed",
                "properties": {"asset_id": asset_id, "target_fingerprint": asset.get("target_fingerprint")},
                "fingerprint": str(asset["target_fingerprint"]),
            }, "case_id,fingerprint")
            self.gateway.insert("job_events", {
                "organisation_id": organisation_id, "case_id": case_id, "job_id": job_id,
                "level": "info", "event_type": "worker_completed",
                "message": "Allowlisted workflow completed; analyst review is required.",
                "details": {"worker_id": self.identity, "content_hash": content_hash},
            })
            completed = self.gateway.rpc("complete_investigation_job", {
                "p_job_id": job_id, "p_worker_id": self.identity, "p_status": "completed",
                "p_result": {"status": output["status"], "review_required": True,
                             "finding_count": output["finding_count"], "scan_count": output["scan_count"],
                             "evidence_hash": content_hash},
            })
            if completed is not True:
                raise WorkerError("Job completion lease was rejected")
            return True
        except Exception as exc:
            try:
                self.gateway.insert("job_events", {
                    "organisation_id": organisation_id, "case_id": case_id, "job_id": job_id,
                    "level": "error", "event_type": "worker_failed", "message": "Allowlisted workflow failed.",
                    "details": {"worker_id": self.identity, "error_type": type(exc).__name__},
                })
            except Exception:
                pass
            completed = self.gateway.rpc("complete_investigation_job", {
                "p_job_id": job_id, "p_worker_id": self.identity, "p_status": "failed",
                "p_result": {"error": "worker_execution_failed", "error_type": type(exc).__name__,
                             "review_required": True},
            })
            if completed is not True:
                raise WorkerError("Failed job completion lease was rejected") from exc
            return True
