"""Deterministic evaluator for the four legally safe golden investigations."""
from __future__ import annotations

import hashlib
import json
from importlib.resources import files

from ..intelligence.ai import detect_instruction_injection
from .graph import TemporalClaimGraph
from .lineage import SourceIndependenceEngine, SourceRecord


def load_golden_investigations() -> dict:
    value = json.loads(files("traceatlas.workforce.data").joinpath("golden_investigations.json").read_text(encoding="utf-8"))
    if value.get("schema") != "traceatlas-workforce-golden/v1" or len(value.get("cases", [])) != 4:
        raise ValueError("unsupported or incomplete golden investigation pack")
    return value


def evaluate_golden_investigations() -> dict:
    pack = load_golden_investigations()
    results = []
    for fixture in pack["cases"]:
        sources = [SourceRecord(
            source_id=row["source_id"], uri=row["uri"], content=row["content"],
            original_source_id=row.get("original_source_id"), ownership_group=row.get("ownership_group"),
        ) for row in fixture["sources"]]
        lineage = SourceIndependenceEngine().group(sources)
        patterns = max(detect_instruction_injection(row.content)["instruction_like_patterns"] for row in sources)
        checks = {
            "independence_groups": len({row.independence_group for row in lineage}) == fixture["expected_independence_groups"],
            "instruction_patterns": int(patterns > 0) == fixture["expected_instruction_patterns"],
        }
        if "identity_candidate" in fixture:
            value = fixture["identity_candidate"]
            candidate = TemporalClaimGraph.identity_candidate(value["state"], tuple(value["reasons"]))
            checks["no_automatic_identity_merge"] = not candidate["canonical_merge"]
        canonical = json.dumps({"fixture": fixture, "lineage": [row.to_dict() for row in lineage]}, sort_keys=True, separators=(",", ":"))
        results.append({"id": fixture["id"], "passed": all(checks.values()), "checks": checks,
                        "replay_digest": hashlib.sha256(canonical.encode()).hexdigest()})
    return {"schema": pack["schema"], "passed": all(row["passed"] for row in results), "results": results}


def evaluate_pipeline_investigations() -> dict:
    """Run the complete local slice; domain labels are backbone fixtures, not live proof."""
    import tempfile
    from datetime import datetime, timedelta, timezone
    from pathlib import Path
    from .contracts import AuthorizationContext
    from .documents import SourceDocument
    from .pipeline import InvestigationPipeline
    from .service import WorkforceService
    from ..db import CaseDB
    pack = json.loads(files("traceatlas.workforce.data").joinpath("pipeline_investigations.json").read_text(encoding="utf-8"))
    results = []
    for fixture in pack["cases"]:
        with tempfile.TemporaryDirectory(prefix="traceatlas-golden-") as temp:
            root = Path(temp)
            db = CaseDB(root / "cases.db")
            try:
                db.create_case("golden-case", fixture["id"], "Controlled synthetic investigation, no subject contact")
                service = WorkforceService(db, enabled=True)
                stamp = datetime.now(timezone.utc) - timedelta(seconds=1)
                context = AuthorizationContext("1.0", "golden-auth", "golden-case", "golden-analyst",
                    "Controlled synthetic evidence-first evaluation", (fixture["seed"],),
                    ("request_collection", "propose_observation", "propose_claim"),
                    ("dns.lookup", "rdap.lookup", "archive.lookup", "ip.lookup", "search.execute", "evidence.retrieve"),
                    "IN", "fixture-only", stamp.isoformat(), (stamp+timedelta(hours=1)).isoformat(), "a"*64)
                service.register_authorization(context)
                kind, seed = fixture["seed"].split(":", 1)
                planned = service.create_investigation_task(context.context_id, kind, seed, fixture["objective"])
                task_id = planned["task"]["task_id"]
                service.approve(task_id, actor_id=context.actor_id, rationale="Approved synthetic exact-scope fixture only",
                                envelope_digest=planned["envelope_digest"], authorized=True)
                def requester(url, headers, timeout):
                    if url.startswith("https://dns.google/"):
                        return 200, b'{"Status":0,"Question":[{"name":"example.org.","type":1}],"Answer":[{"name":"example.org.","type":1,"data":"192.0.2.10"}]}'
                    if url.startswith("https://rdap.org/"):
                        return 503, b''
                    return 200, b'[]'
                pipeline = InvestigationPipeline(service, root, requester=requester)
                docs = tuple(SourceDocument.from_dict(row) for row in fixture.get("documents", []))
                product = pipeline.run(task_id, documents=docs, live=fixture.get("live", False), authorized=True)
                replay = pipeline.replay(task_id)
                analysis = product["analysis"]
                statuses = [row["status"] for row in analysis["verification"]]
                checks = {"offline_replay": replay["verified"],
                          "evidence_coverage": bool(product["replay_manifest"]["evidence"]),
                          "no_material_release": analysis["metrics"]["released_material_claims"] == 0,
                          "no_identity_merge": all(not row["canonical_merge"] for row in analysis["identity_candidates"]),
                          "expected_status": fixture["expected_status"] in statuses}
                if fixture.get("expected_gap"):
                    checks["expected_gap"] = fixture["expected_gap"] in analysis["information_gaps"]
                if fixture.get("live"):
                    checks["provider_failure_preserved"] = product["state"] == "PARTIAL" and any(r.get("reason") == "provider_unavailable" for r in product["replay_manifest"]["source_outcomes"])
                    checks["attempt_budget"] = product["network_attempts"] <= 8
                results.append({"id": fixture["id"], "domain": fixture["domain"], "passed": all(checks.values()),
                                "checks": checks, "metrics": analysis["metrics"], "verification_statuses": statuses})
            finally:
                db.close()
    return {"schema": pack["schema"], "passed": all(row["passed"] for row in results), "results": results,
            "limitations": "G01-G12 exercise the shared local backbone on controlled records; they do not qualify live person discovery, malware sandboxing, actor attribution or BOM analysis."}
