"""Reviewed, read-only registry requests; targets never control destinations."""
from __future__ import annotations

import base64
import ipaddress
import os
import re
from urllib.parse import quote, urlencode

from ..policy import validate_target
from .provider import ProviderError


def company_identifier(source, value):
    """An explicit registry key avoids silently resolving namesake companies."""
    patterns = {
        "gleif": r"lei:([A-Z0-9]{18}[0-9]{2})",
        "companieshouse": r"gb:([A-Z0-9]{8})",
        "sec": r"cik:([0-9]{1,10})",
        "github": r"github:([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)",
        "opencorporates": r"([a-z]{2}(?:_[a-z0-9]{1,8})?):([A-Za-z0-9-]{1,40})",
    }
    match = re.fullmatch(patterns[source], value)
    if not match:
        raise ValueError("source requires an exact qualified company identifier")
    if source == "gleif":
        expanded = ''.join(str(ord(c) - 55) if c.isalpha() else c for c in match[1])
        if int(expanded) % 97 != 1:
            raise ValueError("invalid LEI check digits")
    return match.groups()


def _secret(name):
    from .hub import ConnectorNotConfigured
    value = os.environ.get(name, "").strip()
    if not value or len(value) > 512 or any(c.isspace() for c in value):
        raise ConnectorNotConfigured(name + " requires a valid secret reference")
    return value


def registry_request(source, kind, target):
    headers = {"User-Agent": "TraceAtlas-Automator/1.11", "Accept": "application/json"}
    if source in {"cloudflare_dns", "crtsh"}:
        if kind != "domain":
            raise ValueError("domain target required")
        target = validate_target(kind, target).value.lower()
        if source == "cloudflare_dns":
            headers["Accept"] = "application/dns-json"
            return "https://cloudflare-dns.com/dns-query?" + urlencode({"name": target, "type": "A"}), headers
        return "https://crt.sh/?" + urlencode({"q": target, "output": "json"}), headers
    if source == "ripestat":
        if kind != "ip" or not ipaddress.ip_address(target).is_global:
            raise ValueError("public IP required")
        return "https://stat.ripe.net/data/network-info/data.json?" + urlencode(
            {"resource": str(ipaddress.ip_address(target)), "sourceapp": "traceatlas", "preferred_version": "1.1"}), headers
    if kind != "company":
        raise ValueError("company target required")
    parts = company_identifier(source, target)
    if source == "gleif":
        return "https://api.gleif.org/api/v1/lei-records/" + parts[0], headers
    if source == "companieshouse":
        headers["Authorization"] = "Basic " + base64.b64encode((_secret("COMPANIES_HOUSE_API_KEY") + ":").encode()).decode()
        return "https://api.company-information.service.gov.uk/company/" + parts[0], headers
    if source == "sec":
        from .hub import ConnectorNotConfigured
        agent = os.environ.get("SEC_USER_AGENT", "").strip()
        if not 5 <= len(agent) <= 200 or "@" not in agent or any(ord(c) < 32 for c in agent):
            raise ConnectorNotConfigured("SEC_USER_AGENT requires an operator contact identity")
        headers["User-Agent"] = agent
        return "https://data.sec.gov/submissions/CIK" + parts[0].zfill(10) + ".json", headers
    if source == "github":
        # Public organization fields only. No credential is sent, even if a broad
        # GitHub token is present for a different workflow.
        headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        return "https://api.github.com/orgs/" + quote(parts[0], safe=""), headers
    if source == "opencorporates":
        return "https://api.opencorporates.com/v0.4/companies/" + '/'.join(quote(p, safe="") for p in parts) + "?" + urlencode(
            {"api_token": _secret("OPENCORPORATES_API_TOKEN"), "sparse": "true"}), headers
    raise ValueError("unregistered source")


def validate_shape(source, data):
    valid = isinstance(data, dict)
    if source == "crtsh":
        valid = isinstance(data, list) and len(data) <= 5000 and all(
            isinstance(r, dict) and isinstance(r.get("id"), int) and isinstance(r.get("name_value"), str)
            for r in data)
    elif source == "cloudflare_dns":
        valid = valid and type(data.get("Status")) is int and isinstance(data.get("Question"), list)
    elif source == "ripestat":
        valid = valid and data.get("status") == "ok" and isinstance(data.get("data"), dict)
        valid = valid and isinstance(data["data"].get("asns"), list) and isinstance(data.get("query_id"), str)
    elif source == "gleif":
        valid = valid and isinstance(data.get("data"), dict) and isinstance(data["data"].get("attributes"), dict)
        valid = valid and isinstance(data["data"]["attributes"].get("entity"), dict)
    elif source == "companieshouse":
        valid = valid and all(isinstance(data.get(k), str) for k in ("company_number", "company_name", "company_status"))
    elif source == "sec":
        valid = valid and isinstance(data.get("cik"), (int, str)) and isinstance(data.get("name"), str) and isinstance(data.get("filings"), dict)
    elif source == "opencorporates":
        valid = valid and isinstance(data.get("results"), dict) and isinstance(data["results"].get("company"), dict)
        valid = valid and all(isinstance(data["results"]["company"].get(k), str) for k in ("name", "company_number", "jurisdiction_code"))
    if not valid:
        raise ProviderError("provider_schema_mismatch")
