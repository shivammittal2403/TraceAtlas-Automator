from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from ..policy import PolicyError


OBJECTIVE = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f]{10,500}$")
SOURCE_TASKS = {
    "organisation": ("legal-entity", "domains-asns", "dns-email", "cloud-saas", "public-cti"),
    "domain": ("ownership", "dns-email", "web-archive", "exposure-metadata", "public-cti"),
    "topic": ("authoritative-search", "recent-sources", "cross-source-cluster", "contradictions", "brief"),
    "person": ("consent-check", "public-professional-records", "exact-identifier", "corroboration", "minimisation"),
}


class ResearchWorkflow:
    """Deterministic Planner→Validator→Scheduler contract with no hidden collection."""

    @staticmethod
    def plan(objective: str, scope_type: str, authority: str, *, subject_consent: bool = False) -> dict[str, Any]:
        objective = objective.strip()
        authority = authority.strip()
        if not OBJECTIVE.fullmatch(objective):
            raise PolicyError("Objective must be 10-500 printable characters")
        if scope_type not in SOURCE_TASKS:
            raise PolicyError("Unsupported research scope type")
        if len(authority) < 10:
            raise PolicyError("A specific authority/lawful-purpose statement is required")
        if scope_type == "person" and not subject_consent:
            raise PolicyError("Person research requires explicit subject consent")
        stages = []
        previous: str | None = None
        for index, task in enumerate(SOURCE_TASKS[scope_type], start=1):
            task_id = f"T{index:02d}"
            stages.append({
                "id": task_id, "task": task, "depends_on": [previous] if previous else [],
                "state": "pending", "automation": "assisted" if task in {"corroboration", "contradictions", "brief"} else "high",
            })
            previous = task_id
        plan_id = hashlib.sha256(json.dumps([objective, scope_type, authority], sort_keys=True).encode()).hexdigest()[:16]
        return {
            "plan_id": plan_id, "objective": objective, "scope_type": scope_type,
            "authority_statement": authority, "stages": stages,
            "evidence_standard": ["source", "accessed_at", "observation", "confidence", "limitations", "classification"],
            "stopping_conditions": ["objective answered", "source categories exhausted", "authority boundary reached", "privacy risk exceeds value"],
            "facts": [], "inferences": [], "unanswered_questions": [],
        }

    @staticmethod
    def brief(records: list[dict[str, Any]]) -> dict[str, Any]:
        if len(records) > 5000:
            raise PolicyError("Research brief is limited to 5,000 records")
        facts, inferences, gaps = [], [], []
        fingerprints: set[str] = set()
        for row in records:
            if not isinstance(row, dict):
                continue
            observation = str(row.get("observation") or row.get("fact") or "").strip()[:4000]
            source = str(row.get("source") or "unknown")[:500]
            if not observation:
                continue
            fp = hashlib.sha256(json.dumps([source, observation], sort_keys=True).encode()).hexdigest()
            if fp in fingerprints:
                continue
            fingerprints.add(fp)
            entry = {"observation": observation, "source": source,
                     "confidence": max(0, min(100, int(row.get("confidence", 50)))),
                     "accessed_at": str(row.get("accessed_at") or datetime.now(timezone.utc).isoformat()),
                     "limitations": str(row.get("limitations") or "not independently verified")[:1000]}
            if row.get("type") == "inference":
                inferences.append(entry)
            else:
                facts.append(entry)
            for missing in ("source", "accessed_at", "confidence"):
                if missing not in row:
                    gaps.append(f"record {len(facts) + len(inferences)} missing {missing}")
        return {"facts": facts, "inferences": inferences, "evidence_gaps": sorted(set(gaps)),
                "record_count": len(facts) + len(inferences), "deduplicated": len(records) - len(facts) - len(inferences)}
