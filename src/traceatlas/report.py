from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import CaseDB
from .models import utc_now
from .spider.correlation import correlate


def humanize_event(event: dict[str, Any]) -> str:
    """Render a concise observation while preserving full data in the JSON report."""
    kind, data = event.get("event_type", "UNKNOWN"), event.get("data")
    confidence, risk = event.get("confidence", 0), event.get("risk", "info")
    suffix = f" (confidence {confidence}%, risk: {risk})"
    if kind == "DOMAIN":
        return f"Domain observed: {data}{suffix}"
    if kind in {"IP_ADDRESS", "HOSTNAME", "CERTIFICATE_NAME"}:
        return f"{kind.replace('_', ' ').title()} observed: {data}{suffix}"
    if kind == "LINKED_URL":
        return f"Linked or redirected URL observed: {data}{suffix}"
    if kind == "ACCOUNT_CANDIDATE" and isinstance(data, dict):
        return f"Candidate {data.get('platform', 'account')} profile: {data.get('url', 'URL unavailable')}{suffix}"
    if kind == "TECHNOLOGY" and isinstance(data, dict):
        return f"Response technology marker: {data.get('header', 'field')} = {data.get('value', 'unknown')}{suffix}"
    if kind == "HTTP_RESPONSE" and isinstance(data, dict):
        return (f"HTTP {data.get('status', 'response')} observed for "
                f"{data.get('requested_url', 'the requested target')}; final URL "
                f"{data.get('final_url', 'unknown')}{suffix}")
    if kind == "TLS_CERTIFICATE" and isinstance(data, dict):
        subject = data.get("subject") or {}
        issuer = data.get("issuer") or {}
        return (f"TLS certificate observed for {subject.get('commonName', subject or 'unknown subject')}; "
                f"issuer {issuer.get('commonName', issuer or 'unknown')}; valid until "
                f"{data.get('notAfter', 'unknown')}{suffix}")
    if kind == "FILE_HASH" and isinstance(data, dict):
        return f"File {data.get('algorithm', 'hash')}: {data.get('value', 'unknown')}{suffix}"
    if kind == "FILE_METADATA" and isinstance(data, dict):
        return (f"File metadata: {data.get('name', 'unnamed')} ({data.get('size', 'unknown')} bytes, "
                f"type {data.get('suffix', 'unknown')}){suffix}")
    return (f"{kind.replace('_', ' ').title()} via {event.get('source_module', 'unknown')}{suffix}: "
            f"{json.dumps(data, ensure_ascii=False, default=str)[:500]}")


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
            "correlations": correlate(events, db.spider_edges(scan["id"])),
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
        material = [event for event in scan["events"] if event.get("risk") in {"critical", "high", "medium"}]
        event_types = {event["event_type"] for event in scan["events"]}
        lines.extend([
            f"### {scan['mode']} — {scan['seed_type']}", "",
            f"- Scan ID: `{scan['id']}`", f"- Status: {scan['status']}",
            f"- Events: {len(scan['events'])}", f"- Edges: {len(scan['edges'])}", "",
            (f"This scan recorded {len(scan['events'])} observations across {len(event_types)} event "
             f"types; {len(material)} were medium-or-higher risk. Automated labels remain leads "
             "requiring analyst review."), "",
        ])
        for heading, selected in (
            ("Priority observations", material),
            ("Additional observations", [event for event in scan["events"] if event not in material]),
        ):
            if selected:
                lines.extend([f"#### {heading}", ""])
                lines.extend(f"- {humanize_event(event)}" for event in selected)
        if scan["correlations"]:
            lines.extend(["", "#### Correlations", ""])
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
