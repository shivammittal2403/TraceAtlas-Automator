from __future__ import annotations

from collections import Counter
from typing import Any


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply explainable, deterministic rules; never infer identity or intent."""
    output: list[dict[str, Any]] = []
    counts = Counter(event["event_type"] for event in events)
    if counts["IP_ADDRESS"] > 1:
        output.append({
            "rule": "multiple_resolved_addresses", "severity": "info", "confidence": 90,
            "summary": f"The scan observed {counts['IP_ADDRESS']} distinct address events.",
            "basis": "IP_ADDRESS event count", "requires_review": True,
        })
    private = [e for e in events if e["event_type"] == "IP_ADDRESS" and "non-public" in e["tags"]]
    if private:
        output.append({
            "rule": "non_public_dns_result", "severity": "medium", "confidence": 90,
            "summary": "A DNS pivot produced a non-public address; network modules did not follow it.",
            "basis": [e["id"] for e in private], "requires_review": True,
        })
    redirects = [e for e in events if e["event_type"] == "LINKED_URL" and "redirect" in e["tags"]]
    if redirects:
        output.append({
            "rule": "http_redirect_observed", "severity": "info", "confidence": 95,
            "summary": "The requested URL redirected to another URL.",
            "basis": [e["id"] for e in redirects], "requires_review": True,
        })
    weak_headers = []
    expected = {"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"}
    for event in events:
        if event["event_type"] != "HTTP_RESPONSE":
            continue
        observed = {key.title() for key in event["data"].get("security_headers", {})}
        missing = sorted(expected - observed)
        if missing:
            weak_headers.append({"event_id": event["id"], "missing": missing})
    if weak_headers:
        output.append({
            "rule": "security_headers_not_observed", "severity": "low", "confidence": 75,
            "summary": "Common response security headers were not observed in the sampled response.",
            "basis": weak_headers, "requires_review": True,
        })
    return output

