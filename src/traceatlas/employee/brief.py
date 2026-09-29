"""Pure, bounded decision briefs shared by local and hosted entry points."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from ..intelligence.ai import detect_instruction_injection
from ..intelligence.sanitize import sanitize_record, sanitize_text
from .skills import REFERENCES, skill_catalog

MAX_OBSERVATIONS = 200
MAX_BRIEF_BYTES = 1024 * 1024
SECRET_TEXT = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|authorization|cookie)\b"
    r"\s*[:=]\s*(?:bearer\s+)?[^\s,;\"}]+"
)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.I)


def clean(value: str, maximum: int = 2000) -> str:
    # A CVE identifier is not a telephone number. Preserve this narrow public
    # identifier while using the repository's existing contact minimization.
    identifiers = {}
    def protect(match):
        key = "TRACEATLASCVE" + chr(65 + len(identifiers) // 26) + chr(65 + len(identifiers) % 26) + "END"
        identifiers[key] = match.group(0)
        return key
    text = CVE.sub(protect, SECRET_TEXT.sub(r"\1=[REDACTED]", value[:maximum]))
    text = sanitize_text(text, maximum * 2)
    for key, original in identifiers.items():
        text = text.replace(key, original)
    return text[:maximum]


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def _safe_json(value: Any) -> Any:
    # Check size/depth before the existing recursive sanitizer sees input.
    def check(node: Any, depth: int = 0) -> None:
        if depth > 12:
            raise ValueError("Evidence nesting exceeds 12 levels")
        if isinstance(node, dict):
            if len(node) > 200:
                raise ValueError("Evidence object is too large")
            for item in node.values():
                check(item, depth + 1)
        elif isinstance(node, list):
            if len(node) > 500:
                raise ValueError("Evidence array is too large")
            for item in node:
                check(item, depth + 1)
    check(value)
    if len(json.dumps(value, allow_nan=False).encode()) > 64 * 1024:
        raise ValueError("Individual evidence record exceeds 64 KiB")
    # Protect identifiers before sanitize_record applies its generic phone rule.
    identifiers = {}
    def protect(node):
        if isinstance(node, str):
            def replacement(match):
                key = "TRACECVE" + hashlib.sha256(match.group(0).encode()).hexdigest().translate(str.maketrans("0123456789", "ghijklmnop")) + "END"
                identifiers[key] = match.group(0)
                return key
            return CVE.sub(replacement, node)
        if isinstance(node, dict):
            return {k: protect(v) for k, v in node.items()}
        if isinstance(node, list):
            return [protect(v) for v in node]
        return node
    sanitized = sanitize_record(protect(value))
    def redact(node: Any) -> Any:
        if isinstance(node, str):
            for marker, original in identifiers.items():
                node = node.replace(marker, original)
            return clean(node)
        if isinstance(node, dict):
            return {clean(str(k), 120): redact(v) for k, v in node.items()}
        if isinstance(node, list):
            return [redact(v) for v in node]
        return node
    return redact(sanitized)


def normalize_observations(rows: list[dict], now: datetime) -> tuple[list[dict], list[dict]]:
    if not isinstance(rows, list) or len(rows) > MAX_OBSERVATIONS:
        raise ValueError(f"Brief accepts at most {MAX_OBSERVATIONS} observations")
    facts, withheld = [], []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Observation must be an object")
        rid, source = row.get("id"), row.get("source")
        if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", rid):
            raise ValueError("Observation requires a bounded stable ID")
        if rid in seen:
            raise ValueError("Duplicate observation ID")
        seen.add(rid)
        if not isinstance(source, str) or not source.strip() or len(source) > 500:
            raise ValueError("Observation requires a source")
        classification = row.get("classification", "unclassified")
        if classification not in {"observed", "source-observation"}:
            withheld.append({"id": rid, "reason": "not-an-observation", "classification": clean(str(classification), 80)})
            continue
        body = _safe_json(row.get("data", {}))
        title = clean(str(row.get("title") or "Source observation"), 240)
        injection = detect_instruction_injection(title + " " + json.dumps(body, ensure_ascii=False))
        collected = _time(row.get("collected_at"))
        if injection["review_required"]:
            withheld.append({"id": rid, "reason": "instruction-like-content", "classification": classification})
            continue
        age_days = (now - collected).total_seconds() / 86400 if collected else None
        excerpt = clean(json.dumps(body, ensure_ascii=False, sort_keys=True), 1400)
        facts.append({
            "id": rid, "classification": "source-observation", "title": title,
            "source": clean(source, 500), "data": body, "excerpt": excerpt,
            "collected_at": collected.isoformat() if collected else None,
            "freshness": "unknown" if age_days is None else "future-dated" if age_days < -1 else "stale" if age_days > 30 else "recent",
            "source_group": clean(str(row.get("source_group") or "unknown"), 200),
            "evidence_ids": [rid], "content_hash": digest(body),
            "interpretation": "The source returned this record; its real-world claim still requires validation.",
        })
    return facts, withheld


def _values(value: Any, names: set[str]) -> list[Any]:
    output = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold() in names:
                output.extend(item if isinstance(item, list) else [item])
            if isinstance(item, (dict, list)):
                output.extend(_values(item, names))
    elif isinstance(value, list):
        for item in value:
            output.extend(_values(item, names))
    return output


def build_brief(case_id: str, objective: str, observations: list[dict], *,
                mode: str = "osint", source_runs: list[dict] | None = None,
                now: datetime | None = None, truncated: bool = False) -> dict:
    if mode not in {"osint", "pt"}:
        raise ValueError("Mode must be osint or pt")
    if not isinstance(objective, str) or not 10 <= len(objective.strip()) <= 1000:
        raise ValueError("Objective must contain 10-1000 characters")
    if not isinstance(case_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", case_id):
        raise ValueError("Invalid case ID")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Brief clock must include a timezone")
    runs = source_runs or []
    if not isinstance(runs, list) or len(runs) > 500 or not all(isinstance(r, dict) for r in runs):
        raise ValueError("Source-run list must contain at most 500 objects")
    facts, withheld = normalize_observations(observations, now)
    skills = skill_catalog(objective, mode)[:10]
    scenarios, insights = [], []
    references = set()
    for skill in skills:
        references.update(skill["reference_ids"])
    unhealthy = [{"source": clean(str(row.get("source", "unknown")), 200),
                  "status": clean(str(row.get("status", "unknown")), 80),
                  "reason": clean(str(row.get("failure_code") or "incomplete coverage"), 120)}
                 for row in runs if row.get("status") != "completed"]
    questions = ["Which material claims have independent corroboration?",
                 "Do source dates and scope support a current decision?"]
    if not facts:
        questions.insert(0, "Collect or import attributable case evidence before drawing a conclusion.")

    def scenario(key: str, title: str, supporting: list[str], explanation: str,
                 alternative: str, check: str, reference: str) -> None:
        references.add(reference)
        scenarios.append({"id": key, "classification": "hypothesis", "title": title,
                          "statement": explanation, "evidence_ids": supporting[:20],
                          "alternative_explanation": alternative, "counter_evidence_ids": [],
                          "missing_evidence": check, "next_check": check,
                          "confidence": "unvalidated", "decision": "human-required",
                          "knowledge_reference_ids": [reference]})

    ports = [f["id"] for f in facts if _values(f["data"], {"ports", "port"})]
    vulnerabilities = [f["id"] for f in facts if any(
        re.fullmatch(r"CVE-\d{4}-\d{4,19}", str(v), re.I)
        for v in _values(f["data"], {"cve", "cve_id", "cves", "vulns", "vulnerabilities"}))]
    reputations = [f["id"] for f in facts if any(isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0
                                              for v in _values(f["data"], {"malicious", "malicious_count"}))]
    if ports:
        scenario("exposure", "Reported network exposure needs validation", ports,
                 "A source reports service or port metadata that may describe an exposed service.",
                 "The record may be stale, proxied, shared infrastructure, or an intended public service.",
                 "Confirm asset ownership, observation date and expected service before approving a bounded validation.", "nist-testing")
    if vulnerabilities:
        scenario("applicability", "Reported CVE may apply to the asset", vulnerabilities,
                 "The evidence includes CVE identifiers; applicability to the deployed system is unresolved.",
                 "The deployment may be patched, backported, differently configured, or misidentified.",
                 "Compare exact product/version and configuration against the vendor advisory, then assess impact.", "nvd")
    if reputations:
        scenario("reputation", "Adverse reputation merits triage", reputations,
                 "A provider reports at least one adverse classification.",
                 "Shared infrastructure, historical abuse or a false positive may explain the classification.",
                 "Check the detection date, source independence and authorized internal telemetry.", "stix")
    stale = [f["id"] for f in facts if f["freshness"] != "recent"]
    if stale:
        insights.append({"classification": "analysis", "statement": "Some evidence is stale, future-dated or lacks a usable collection timestamp.",
                         "evidence_ids": stale[:20], "method": "timestamp-check-v1"})
    # Only explicitly supplied subject/predicate pairs support contradiction
    # candidates. Different arbitrary JSON blobs are not contradictions.
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for fact in facts:
        data = fact["data"]
        if isinstance(data, dict) and all(isinstance(data.get(k), str) for k in ("subject", "predicate")) and "value" in data:
            groups[(data["subject"], data["predicate"])].append(fact)
    for group in groups.values():
        if len({digest(f["data"]["value"]) for f in group}) > 1:
            scenario("conflict-" + digest([f["id"] for f in group])[:12], "Different values require reconciliation",
                     [f["id"] for f in group], "Records report different values for the same explicit subject and predicate.",
                     "Time, scope or source semantics may differ; this is not automatically a factual contradiction.",
                     "Compare observation windows and original records before selecting a value.", "nist-forensics")
    scenarios = scenarios[:20]
    known_groups = {f["source_group"] for f in facts if f["source_group"] != "unknown"}
    evidence_digest = digest({"observations": observations, "source_runs": runs, "truncated": bool(truncated)})
    result = {
        "schema": "traceatlas.employee.brief.v1", "case_id": case_id,
        "objective": clean(objective, 1000), "mode": mode, "generated_at": now.isoformat(),
        "engine": "deterministic-evidence-rules-v1", "decision_owner": "human",
        "evidence_digest": evidence_digest, "status": "needs-evidence" if not facts else "ready-for-review",
        "summary": {"observations": len(facts), "withheld": len(withheld), "scenarios": len(scenarios),
                    "distinct_source_labels": len({f["source"] for f in facts}),
                    "known_lineage_groups": len(known_groups), "coverage_failures": len(unhealthy),
                    "truncated": bool(truncated)},
        "facts": facts, "insights": insights, "scenarios": scenarios,
        "coverage_gaps": unhealthy, "withheld": withheld, "questions": questions,
        "skills": skills, "knowledge_references": [{"id": k, **REFERENCES[k]} for k in sorted(references)],
        "recommended_actions": [{"id": "review-" + s["id"], "action": s["next_check"],
                                 "evidence_ids": s["evidence_ids"], "state": "proposed", "auto_execute": False}
                                for s in scenarios],
        "limitations": ["Source observations are not independently established real-world truth.",
                        "Unknown source lineage is not independent corroboration.",
                        "Missing or failed collection is not evidence of absence.",
                        "Methodology and research metadata are not evidence about the case subject.",
                        "Scenarios are rule-generated hypotheses; approval does not execute a scan."],
    }
    result["brief_digest"] = digest(result)
    if len(json.dumps(result, ensure_ascii=False).encode()) > MAX_BRIEF_BYTES:
        raise ValueError("Brief exceeds output budget; narrow the case scope")
    return result


def validate_model_advisory(value: Any, brief: dict) -> dict:
    """A reference check cannot prove entailment; all accepted prose stays draft."""
    if not isinstance(value, dict) or set(value) != {"insights", "scenarios", "questions"}:
        raise ValueError("Model advisory requires insights, scenarios and questions only")
    facts = {f["id"]: f for f in brief["facts"]}
    output = {"status": "unreviewed-model-draft", "factual_entailment_verified": False,
              "may_execute": False}
    for field in ("insights", "scenarios"):
        rows = value[field]
        if not isinstance(rows, list) or len(rows) > 10:
            raise ValueError("Too many model claims")
        accepted = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"statement", "evidence_ids", "supporting_quote", "alternative", "next_check"}:
                raise ValueError("Invalid model claim contract")
            refs = row["evidence_ids"]
            if not isinstance(refs, list) or not 1 <= len(refs) <= 10 or not all(isinstance(r, str) and r in facts for r in refs):
                raise ValueError("Unknown or missing model evidence citation")
            if not all(isinstance(row[k], str) and 1 <= len(row[k]) <= 1500 for k in ("statement", "supporting_quote", "alternative", "next_check")):
                raise ValueError("Model claim text is invalid")
            quote = row["supporting_quote"]
            if len(quote) < 8 or not any(quote in facts[r]["excerpt"] for r in refs):
                raise ValueError("Supporting quote was not present in the cited evidence")
            accepted.append({k: clean(v, 1500) if isinstance(v, str) else list(dict.fromkeys(v)) for k, v in row.items()})
        output[field] = accepted
    questions = value["questions"]
    if not isinstance(questions, list) or len(questions) > 10 or not all(isinstance(q, str) and 1 <= len(q) <= 500 for q in questions):
        raise ValueError("Invalid model questions")
    output["questions"] = [clean(q, 500) for q in questions]
    return output


def markdown_report(brief: dict) -> str:
    # Escape source-controlled Markdown so exports cannot smuggle links/images.
    def text(value: Any) -> str:
        return re.sub(r"([\\`*_{}\[\]()<>#!|])", r"\\\1", str(value)).replace("\n", " ")
    lines = ["# TraceAtlas employee decision brief", "", f"Case: {text(brief['case_id'])}",
             f"Objective: {text(brief['objective'])}", "Decision owner: human", "",
             f"Evidence digest: `{brief['evidence_digest']}`", "", "## Source observations", ""]
    for fact in brief["facts"]:
        lines.append(f"- [{text(fact['id'])}] {text(fact['source'])}: {text(fact['excerpt'])}")
    for heading, rows in (("Insights", brief["insights"]), ("Scenarios", brief["scenarios"])):
        lines += ["", "## " + heading, ""]
        for row in rows:
            lines.append(f"- {text(row['statement'])} Evidence: {text(', '.join(row['evidence_ids']))}")
            if "alternative_explanation" in row:
                lines.append(f"  Alternative: {text(row['alternative_explanation'])}")
                lines.append(f"  Next check: {text(row['next_check'])}")
    lines += ["", "## Questions and limitations", ""]
    lines.extend("- " + text(q) for q in brief["questions"] + brief["limitations"])
    return "\n".join(lines) + "\n"
