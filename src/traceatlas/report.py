from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import CaseDB
from .models import utc_now
from .spider.correlation import correlate


def _risk(findings: list[dict[str, Any]], spider_scans: list[dict[str, Any]]) -> dict[str, Any]:
    weights = {"info": 0, "low": 2, "medium": 5, "high": 8, "critical": 10}
    scores = [weights.get(item["severity"], 0) * item["confidence"] / 100 for item in findings]
    for scan in spider_scans:
        scores.extend(
            weights.get(event.get("risk", "info"), 0) * event.get("confidence", 0) / 100
            for event in scan["events"]
        )
    score = round(min(10, max(scores, default=0)), 1)
    return {"score": score, "label": "P1" if score >= 9 else "P2" if score >= 7 else "P3" if score >= 4 else "Informational"}


def build_report(db: CaseDB, case_id: str) -> dict[str, Any]:
    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Unknown case: {case_id}")
    findings = db.findings(case_id)
    spider_scans = []
    for scan in db.spider_scans(case_id):
        events = db.spider_events(scan["id"])
        spider_scans.append({
            **scan, "events": events, "edges": db.spider_edges(scan["id"]),
            "correlations": correlate(events),
        })
    return {
        "schema_version": "1.2", "generated_at": utc_now(), "case": case,
        "risk": _risk(findings, spider_scans), "runs": db.runs(case_id), "findings": findings,
        "spider_scans": spider_scans,
        "sensitive_audits": db.sensitive_audits(case_id),
        "evidence": db.evidence(case_id),
        "disclaimer": "Automated outputs are leads, not attribution. Human review and independent corroboration are required.",
    }


def write_reports(db: CaseDB, case_id: str, output_dir: Path) -> tuple[Path, Path]:
    report = build_report(db, case_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{case_id}.json"
    md_path = output_dir / f"{case_id}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        f"# OSINT Case Report: {report['case']['title']}", "",
        f"- Case ID: `{case_id}`", f"- Status: {report['case']['status']}",
        f"- Generated: {report['generated_at']}",
        f"- Automated risk: {report['risk']['label']} ({report['risk']['score']}/10)", "",
        "## Purpose", "", report["case"]["purpose"], "", "## Findings", "",
    ]
    for item in report["findings"]:
        lines.extend([
            f"### {item['title']}", "",
            f"- Confidence: {item['confidence']}%", f"- Severity: {item['severity']}",
            f"- Source: {item['source']}", "",
            "```json", json.dumps(item["value"], indent=2, ensure_ascii=False), "```", "",
        ])
    lines.extend(["## Spider, sensitive, and external-tool scans", ""])
    if not report["spider_scans"]:
        lines.extend(["No event-engine, sensitive, or external-tool scans recorded.", ""])
    for scan in report["spider_scans"]:
        lines.extend([
            f"### {scan['mode']} — {scan['seed_type']}", "",
            f"- Scan ID: `{scan['id']}`", f"- Status: {scan['status']}",
            f"- Events: {len(scan['events'])}", f"- Edges: {len(scan['edges'])}", "",
        ])
        for event in scan["events"]:
            lines.append(
                f"- `{event['event_type']}` via `{event['source_module']}` "
                f"(confidence {event['confidence']}%, risk {event['risk']}): "
                f"`{json.dumps(event['data'], ensure_ascii=False, default=str)[:500]}`"
            )
        if scan["correlations"]:
            lines.extend(["", "Correlations:"])
            for rule in scan["correlations"]:
                lines.append(f"- {rule['rule']}: {rule['summary']}")
        lines.append("")
    lines.extend(["## Sensitive workflow audit", ""])
    if not report["sensitive_audits"]:
        lines.extend(["No sensitive workflows recorded.", ""])
    for audit in report["sensitive_audits"]:
        lines.extend([
            f"### {audit['workflow']}", "",
            f"- Audit ID: `{audit['id']}`",
            f"- Status: {audit['status']}",
            f"- Target fingerprint: `{audit['target_fingerprint']}`",
            f"- Lawful purpose: {audit['lawful_purpose']}",
            "- Attestations: " + ", ".join(
                key for key, value in audit["attestations"].items() if value
            ), "",
        ])
    lines.extend(["## Evidence", ""])
    for item in report["evidence"]:
        lines.append(f"- `{item['sha256']}` — {item['source']} — {item['path']}")
    lines.extend(["", "## Analyst note", "", report["disclaimer"], ""])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
