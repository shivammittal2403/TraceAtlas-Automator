"""Native OSINT tool helpers.

Implements features 232-238 and core collectors:
- /whois (RDAP)
- /dns (DoH)
- /wayback (CDX)
- /shodan (InternetDB + optional key)
- /hibp (demo + live)
- ToolResult interface (summary + entities + relations)

All calls are direct and return structured data suitable for the evidence ledger.
No automatic identity claims are made.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolEntity:
    type: str
    name: str
    description: str = ""
    confidence: float = 0.7
    source: str = ""


@dataclass
class ToolRelation:
    source_name: str
    target_name: str
    type: str
    label: str = ""


@dataclass
class ToolResult:
    summary: str
    entities: List[ToolEntity] = field(default_factory=list)
    relations: List[ToolRelation] = field(default_factory=list)
    raw: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _get(url: str, timeout: int = 15) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "TraceAtlas/1.6"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data) if data.strip().startswith(("{", "[")) else {"text": data}
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode("utf-8", errors="replace")[:500]}
    except Exception as e:
        return {"error": str(e)}


def whois_lookup(domain_or_ip: str) -> ToolResult:
    """IANA RDAP lookup (keyless)."""
    target = domain_or_ip.strip().lower()
    if not target:
        return ToolResult(summary="Empty target", error="empty")

    # Prefer domain RDAP bootstrap
    url = f"https://rdap.org/domain/{urllib.parse.quote(target)}"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        url = f"https://rdap.org/ip/{target}"

    data = _get(url)
    if "error" in data:
        return ToolResult(summary=f"WHOIS failed: {data['error']}", error=data["error"], raw=data)

    entities = [ToolEntity(type="DOMAIN" if "." in target else "DEVICE", name=target, source="rdap")]
    summary_parts = [f"**WHOIS / RDAP** for `{target}`"]
    if "handle" in data:
        summary_parts.append(f"- Handle: {data['handle']}")
    if "name" in data:
        summary_parts.append(f"- Name: {data['name']}")
        entities.append(ToolEntity(type="ORGANIZATION", name=str(data["name"]), source="rdap"))

    return ToolResult(summary="\n".join(summary_parts), entities=entities, raw=data)


def dns_lookup(domain: str) -> ToolResult:
    """DNS-over-HTTPS via Google public resolver (keyless)."""
    domain = domain.strip().lower()
    if not domain:
        return ToolResult(summary="Empty domain", error="empty")

    url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type=A"
    data = _get(url)
    if "error" in data:
        return ToolResult(summary=f"DNS failed: {data['error']}", error=data["error"], raw=data)

    entities = [ToolEntity(type="DOMAIN", name=domain, source="doh")]
    answers = data.get("Answer") or []
    summary = [f"**DNS (DoH)** for `{domain}`"]
    for ans in answers:
        ip = ans.get("data", "")
        if ip:
            summary.append(f"- {ans.get('type')}: {ip}")
            entities.append(ToolEntity(type="DEVICE", name=ip, source="doh", description="A record"))

    return ToolResult(summary="\n".join(summary), entities=entities, raw=data)


def wayback_lookup(url: str, limit: int = 5) -> ToolResult:
    """Wayback Machine CDX (keyless)."""
    url = url.strip()
    if not url:
        return ToolResult(summary="Empty URL", error="empty")

    cdx = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={urllib.parse.quote(url)}&output=json&limit={limit}&fl=timestamp,original,statuscode"
    )
    data = _get(cdx)
    if "error" in data:
        return ToolResult(summary=f"Wayback failed: {data['error']}", error=data["error"], raw=data)

    rows = data if isinstance(data, list) else data.get("text", "").splitlines()
    summary = [f"**Wayback CDX** for `{url}` (up to {limit} snapshots)"]
    entities = [ToolEntity(type="DOMAIN", name=url, source="wayback")]

    # First row is often header
    for row in rows[1:limit + 1] if rows and isinstance(rows[0], list) else rows[:limit]:
        if isinstance(row, list) and len(row) >= 2:
            summary.append(f"- {row[0]} → {row[1]} (status {row[2] if len(row) > 2 else '?'})")

    return ToolResult(summary="\n".join(summary), entities=entities, raw={"rows": rows[:limit + 1]})


def shodan_internetdb(ip: str) -> ToolResult:
    """Shodan InternetDB (keyless, public)."""
    ip = ip.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return ToolResult(summary=f"`{ip}` is not a valid IPv4", error="invalid_ip")

    data = _get(f"https://internetdb.shodan.io/{ip}")
    if "error" in data:
        return ToolResult(summary=f"InternetDB failed: {data['error']}", error=data["error"], raw=data)

    entities = [ToolEntity(type="DEVICE", name=ip, source="shodan_idb")]
    summary = [f"**Shodan InternetDB** for `{ip}`"]
    for key in ("ports", "hostnames", "tags", "vulns", "cpes"):
        val = data.get(key)
        if val:
            summary.append(f"- {key}: {val}")
            if key == "hostnames":
                for h in val:
                    entities.append(ToolEntity(type="DOMAIN", name=h, source="shodan_idb"))

    return ToolResult(summary="\n".join(summary), entities=entities, raw=data)


def hibp_breached_account(email: str, api_key: Optional[str] = None) -> ToolResult:
    """Have I Been Pwned (requires key for live; demo mode without)."""
    email = email.strip().lower()
    if not email or "@" not in email:
        return ToolResult(summary="Invalid email", error="invalid_email")

    if not api_key:
        return ToolResult(
            summary=(
                f"**HIBP (demo mode)** for `{email}`\n"
                "- No API key supplied. Live lookup skipped.\n"
                "- Supply HIBP_API_KEY for live breach data."
            ),
            entities=[ToolEntity(type="EMAIL", name=email, source="hibp_demo")],
        )

    req = urllib.request.Request(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
        headers={
            "User-Agent": "TraceAtlas/1.6",
            "hibp-api-key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return ToolResult(
                summary=f"**HIBP** `{email}` — no breaches found",
                entities=[ToolEntity(type="EMAIL", name=email, source="hibp")],
            )
        return ToolResult(summary=f"HIBP error HTTP {e.code}", error=f"HTTP {e.code}")
    except Exception as e:
        return ToolResult(summary=f"HIBP error: {e}", error=str(e))

    summary = [f"**HIBP** `{email}` — {len(data)} breach(es)"]
    for b in data[:10]:
        summary.append(f"- {b.get('Name', '?')} ({b.get('BreachDate', '?')})")

    return ToolResult(
        summary="\n".join(summary),
        entities=[ToolEntity(type="EMAIL", name=email, source="hibp")],
        raw={"breaches": data},
    )
