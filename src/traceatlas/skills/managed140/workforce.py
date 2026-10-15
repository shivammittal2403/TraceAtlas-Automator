"""Deterministic case -> team lead -> offline specialist routing.

Not a second source of truth: no external tool execution, case writes or authority creation.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .registry import CATALOG
from .engine import analyze, verify, _hash

MAX_DOMAINS = 12
GOAL_HINTS = {
    "academic": ("ACADEMICINT", "DATASETINT", "DOCINT", "CORROBORATIONINT"),
    "company": ("CORPINT", "OWNERSHIPINT", "REGINT", "CONTRACTINT"),
    "corporate": ("CORPINT", "OWNERSHIPINT", "REGINT", "CONTRACTINT"),
    "domain": ("DOMAININT", "DNSINT", "CERTINT", "TLSINT"),
    "cyber": ("CTI", "IOCINT", "VULNINT", "TTPINT"),
    "threat": ("CTI", "IOCINT", "TTPINT", "CAMPAIGNINT"),
    "procurement": ("PROCUREMENTINT", "CONTRACTINT", "VENDORINT"),
    "evidence": ("SOURCEINT", "PROVENANCEINT", "CORROBORATIONINT"),
    "shipping": ("LOGISTICSINT", "MARITIMEINT", "TRANSPORTINT"),
    "aircraft": ("AVIATIONINT", "GEOINT", "TIMELINEINT"),
}
def _rows(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return payload["records"]
    raise ValueError("Expected a list or an object with 'records' list")

def plan_case(payload, *, goal="", domains=None, allowed_sensitive=(), limit=MAX_DOMAINS):
    """Produce bounded, explainable selection; no model can grant itself authority."""
    records = _rows(payload)
    if not 1 <= limit <= MAX_DOMAINS:
        raise ValueError("Invalid domain budget")
    fields = set()
    for item in records[:2000]:
        if isinstance(item, dict):
            data = item.get("data", item)
            if isinstance(data, dict):
                fields.update(data)
    allowed = {str(x).upper() for x in allowed_sensitive}
    if domains is not None:
        chosen = []
        for name in domains:
            code = str(name).upper()
            if code not in CATALOG:
                raise KeyError(f"Unknown domain: {code}")
            if code not in chosen:
                chosen.append(code)
        if len(chosen) > limit:
            raise ValueError("Requested domains exceed case budget")
        reason = {c: "analyst_selected" for c in chosen}
    else:
        scores = {}
        goal_lower = str(goal).casefold()
        hints = set()
        for keyword, values in GOAL_HINTS.items():
            if keyword in goal_lower:
                hints.update(values)
        for code, meta in CATALOG.items():
            if meta["sensitive"] and code not in allowed:
                continue
            overlaps = len(fields & set(meta["fields"]))
            score = 2 * overlaps + (6 if code in hints else 0)
            if score:
                scores[code] = score
        chosen = sorted(scores, key=lambda c: (-scores[c], c))[:limit]
        reason = {c: f"field_goal_match:{scores[c]}" for c in chosen}
    leads = {}
    for code in chosen:
        lead = CATALOG[code]["family"]
        leads.setdefault(lead, []).append(code)
    return {"schema": "traceatlas.managed140/plan-v1",
            "goal": str(goal)[:500], "record_count": len(records),
            "domains": chosen, "team_leads": leads, "reasons": reason,
            "budget": {"max_domains": limit}, "external_actions": []}

def run_case(payload, *, case_id, goal="", domains=None, authorized=False,
             authorized_sensitive=(), limit=MAX_DOMAINS):
    """Run only eligible offline workers on already supplied evidence."""
    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("A stable nonempty case_id is required")
    allowed = set(str(x).upper() for x in authorized_sensitive) if authorized else set()
    plan = plan_case(payload, goal=goal, domains=domains, allowed_sensitive=allowed, limit=limit)
    reports = {}
    for code in plan["domains"]:
        can_run_sensitive = code in allowed
        reports[code] = analyze(code, payload, authorized=(authorized and (
            not CATALOG[code]["sensitive"] or can_run_sensitive)), case_id=case_id)
    output = {"schema": "traceatlas.managed140/case-v1",
              "case_id": case_id, "plan": plan, "reports": reports,
              "summary": {"executed": len(reports),
                "blocked": [k for k, v in reports.items() if v["status"] == "blocked"],
                "verified_subreports": all(verify(v) for v in reports.values())},
              "note": "Offline interpretation only; requires canonical case ingestion and analyst review."}
    output["receipt_sha256"] = _hash(output)
    return output

def verify_case(case):
    if not isinstance(case, dict) or not case.get("receipt_sha256"):
        return False
    data = {k:v for k,v in case.items() if k != "receipt_sha256"}
    return (_hash(data) == case["receipt_sha256"]
            and all(verify(r) for r in case.get("reports", {}).values()))

def main(argv=None):
    parser = argparse.ArgumentParser(prog="traceatlas-managed140-case")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--goal", default="")
    parser.add_argument("--domains", nargs="+")
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--authorized-sensitive", nargs="*", default=[])
    args = parser.parse_args(argv)
    if args.input.stat().st_size > 10 * 1024 * 1024:
        parser.error("Input exceeds 10 MB")
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    report = run_case(payload, case_id=args.case_id, goal=args.goal, domains=args.domains,
                      authorized=args.authorized, authorized_sensitive=args.authorized_sensitive)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if verify_case(report) else 2

if __name__ == "__main__":
    raise SystemExit(main())
