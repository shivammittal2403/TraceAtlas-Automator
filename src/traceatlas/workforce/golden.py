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
