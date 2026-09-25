from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable


Correlation = dict[str, Any]
RuleHandler = Callable[[list[dict[str, Any]], list[dict[str, Any]]], list[Correlation]]


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    name: str
    handler: RuleHandler

    def apply(self, events: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[Correlation]:
        return self.handler(events, edges)


def _result(rule: str, summary: str, basis: Any, *, severity: str = "info",
            confidence: int = 85) -> Correlation:
    return {"rule": rule, "severity": severity, "confidence": confidence,
            "summary": summary, "basis": basis, "requires_review": True}


def _multiple_addresses(events: list[dict[str, Any]], _: list[dict[str, Any]]) -> list[Correlation]:
    count = sum(event["event_type"] == "IP_ADDRESS" for event in events)
    return [_result("multiple_resolved_addresses",
                    f"The scan observed {count} distinct address events.",
                    "IP_ADDRESS event count", confidence=90)] if count > 1 else []


def _non_public(events: list[dict[str, Any]], _: list[dict[str, Any]]) -> list[Correlation]:
    rows = [event for event in events
            if event["event_type"] == "IP_ADDRESS" and "non-public" in event.get("tags", [])]
    return [_result("non_public_dns_result",
                    "A DNS pivot produced a non-public address; network modules did not follow it.",
                    [event["id"] for event in rows], severity="medium", confidence=90)] if rows else []


def _redirects(events: list[dict[str, Any]], _: list[dict[str, Any]]) -> list[Correlation]:
    rows = [event for event in events
            if event["event_type"] == "LINKED_URL" and "redirect" in event.get("tags", [])]
    return [_result("http_redirect_observed", "The requested URL redirected to another URL.",
                    [event["id"] for event in rows], confidence=95)] if rows else []


def _weak_headers(events: list[dict[str, Any]], _: list[dict[str, Any]]) -> list[Correlation]:
    weak = []
    expected = {"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"}
    for event in events:
        if event["event_type"] != "HTTP_RESPONSE" or not isinstance(event.get("data"), dict):
            continue
        observed = {key.title() for key in event["data"].get("security_headers", {})}
        missing = sorted(expected - observed)
        if missing:
            weak.append({"event_id": event["id"], "missing": missing})
    return [_result("security_headers_not_observed",
                    "Common response security headers were not observed in the sampled response.",
                    weak, severity="low", confidence=75)] if weak else []


def _parents(events: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_id = {event["id"]: event for event in events}
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        parent = by_id.get(edge.get("parent_id"))
        if parent:
            output[str(edge.get("child_id"))].append(parent)
    for event in events:
        if event.get("parent_id") and by_id.get(event["parent_id"]):
            output[event["id"]].append(by_id[event["parent_id"]])
    return output


def _shared_infrastructure(events: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[Correlation]:
    parents = _parents(events, edges)
    output = []
    for event in events:
        if event["event_type"] != "IP_ADDRESS":
            continue
        domains = sorted({str(row["data"]).lower() for row in parents.get(event["id"], [])
                          if row["event_type"] in {"DOMAIN", "HOSTNAME"}})
        if len(domains) > 1:
            output.append(_result(
                "shared_infrastructure",
                f"{len(domains)} distinct domain or hostname observations resolved to the same IP.",
                {"ip_event": event["id"], "domains": domains}, confidence=95,
            ))
    return output


def _certificate_reuse(events: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[Correlation]:
    parents = _parents(events, edges)
    grouped: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
    for event in events:
        if event["event_type"] != "TLS_CERTIFICATE" or not isinstance(event.get("data"), dict):
            continue
        signature = json.dumps({key: event["data"].get(key) for key in ("subject", "issuer", "notAfter")},
                               sort_keys=True, default=str)
        for parent in parents.get(event["id"], []):
            if parent["event_type"] in {"DOMAIN", "HOSTNAME"}:
                grouped[signature].append((event, str(parent["data"]).lower()))
    output = []
    for rows in grouped.values():
        names = sorted({name for _, name in rows})
        if len(names) > 1:
            output.append(_result(
                "certificate_reuse",
                "The same observed certificate metadata appeared under multiple domain or hostname events.",
                {"domains": names, "events": sorted({row[0]["id"] for row in rows})}, confidence=90,
            ))
    return output


def _technology_match(events: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[Correlation]:
    parents = _parents(events, edges)
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for event in events:
        if event["event_type"] != "TECHNOLOGY" or not isinstance(event.get("data"), dict):
            continue
        signature = f"{event['data'].get('header', '')}:{event['data'].get('value', '')}".casefold()
        for parent in parents.get(event["id"], []):
            grouped[signature].append((event["id"], str(parent.get("data"))))
    output = []
    for signature, rows in grouped.items():
        sources = sorted({source for _, source in rows})
        if signature != ":" and len(sources) > 1:
            output.append(_result(
                "technology_stack_match",
                "The same response technology marker was observed for multiple parent targets.",
                {"marker": signature, "parents": sources, "events": [row[0] for row in rows]},
                confidence=70,
            ))
    return output


def _redirect_convergence(events: list[dict[str, Any]], _: list[dict[str, Any]]) -> list[Correlation]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        data = event.get("data")
        if event["event_type"] == "HTTP_RESPONSE" and isinstance(data, dict):
            requested, final = data.get("requested_url"), data.get("final_url")
            if requested and final and requested != final:
                grouped[str(final)].append(event)
    output = []
    for final, rows in grouped.items():
        requested = sorted({str(row["data"]["requested_url"]) for row in rows})
        if len(requested) > 1:
            output.append(_result(
                "redirect_chain_convergence",
                "Multiple independently requested URLs converged on the same final URL.",
                {"final_url": final, "requested_urls": requested,
                 "events": [row["id"] for row in rows]}, confidence=95,
            ))
    return output


RULES = (
    CorrelationRule("multiple_resolved_addresses", _multiple_addresses),
    CorrelationRule("non_public_dns_result", _non_public),
    CorrelationRule("http_redirect_observed", _redirects),
    CorrelationRule("security_headers_not_observed", _weak_headers),
    CorrelationRule("shared_infrastructure", _shared_infrastructure),
    CorrelationRule("certificate_reuse", _certificate_reuse),
    CorrelationRule("technology_stack_match", _technology_match),
    CorrelationRule("redirect_chain_convergence", _redirect_convergence),
)


def correlate(events: list[dict[str, Any]], edges: list[dict[str, Any]] | None = None) -> list[Correlation]:
    """Apply registered deterministic rules; never infer identity, ownership, or intent."""
    output: list[Correlation] = []
    for rule in RULES:
        output.extend(rule.apply(events, edges or []))
    return output
