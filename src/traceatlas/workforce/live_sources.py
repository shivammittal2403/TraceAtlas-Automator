"""Implemented investigation sources, readiness and immutable plan selection."""
from __future__ import annotations

import os
import ipaddress
from urllib.parse import urlencode, urlsplit

from ..intelligence.contracts import source_contract
from ..intelligence.hub import IntelligenceHub, ConnectorNotConfigured
from ..intelligence.sources import SOURCES

from .source_registry import P0_BY_ID, SourceRegistry

SOURCE_TOOLS = {key: value["tool"] for key, value in P0_BY_ID.items()}
SOURCE_TOOLS["rdap_bootstrap"] = "rdap.lookup"
SOURCE_TYPES = {key: tuple(value["entity_types"]) for key, value in P0_BY_ID.items()}
SEARCH_SOURCES = frozenset({"brave", "searxng"})


def search_base():
    value = os.environ.get("SEARXNG_URL", "").strip()
    try:
        parsed = urlsplit(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        valid = (parsed.scheme == "http" and address.is_loopback and parsed.port is not None
                 and 1 <= parsed.port <= 65535 and parsed.path in {"", "/"}
                 and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
                 and not any(ord(c) < 33 for c in value))
    except ValueError:
        valid = False
    if not valid:
        raise ConnectorNotConfigured("SEARXNG_URL requires a numeric loopback HTTP origin and port")
    return value.rstrip("/")


def default_sources(kind, target):
    sources = (["dns", "rdap", "urlscan", "wayback"] if kind == "domain"
               else ["rdap", "ipwhois", "internetdb", "urlscan"] if kind == "ip"
               else ["nvd", "epss"] if kind == "cve"
               else ["osv"] if kind == "vulnerability"
               else ["npm"] if kind == "package" else [])
    if kind == "ip" and ipaddress.ip_address(target).version == 6:
        sources.remove("internetdb")
    search = os.environ.get("TRACEATLAS_SEARCH_PROVIDER", "").strip().lower()
    if kind in {"domain", "ip", "company"} and search:
        if search not in SEARCH_SOURCES:
            raise ValueError("TRACEATLAS_SEARCH_PROVIDER must be brave or searxng")
        sources.append(search)
    return tuple(sources)


def select_sources(kind, target, sources=None):
    selected = default_sources(kind, target) if sources is None else tuple(sources)
    if len(set(selected)) != len(selected) or len(selected) + ("rdap" in selected) > 8:
        raise ValueError("sources must be unique and fit eight captures including RDAP bootstrap")
    if sum(source in SEARCH_SOURCES for source in selected) > 1:
        raise ValueError("select one web search provider per task")
    for source in selected:
        if not SourceRegistry().supports(source, kind, target):
            raise ValueError("source does not support this investigation seed type")
        if kind == "ip" and source in {"internetdb", "greynoise"} and ipaddress.ip_address(target).version != 4:
            raise ValueError("selected source supports IPv4 only")
    if sources is not None and not selected:
        raise ValueError("explicit source selection cannot be empty")
    return selected


def request_spec(source, kind, target):
    if source not in SEARCH_SOURCES:
        return IntelligenceHub._live_request(SOURCES[source], kind, target)
    query = '"' + target + '"'
    headers = {"Accept": "application/json", "User-Agent": "TraceAtlas-Automator/1.10"}
    if source == "brave":
        key = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
        if not key or len(key) > 512 or any(char.isspace() for char in key):
            raise ConnectorNotConfigured("BRAVE_SEARCH_API_KEY is required")
        headers["X-Subscription-Token"] = key
        return "https://api.search.brave.com/res/v1/web/search?" + urlencode(
            {"q": query, "count": 10, "safesearch": "moderate", "spellcheck": "false"}), headers
    return search_base() + "/search?" + urlencode(
        {"q": query, "format": "json", "categories": "general", "pageno": 1, "safesearch": 1}), headers


def readiness():
    rows = []
    for source, kinds in SOURCE_TYPES.items():
        credentials = (("BRAVE_SEARCH_API_KEY",) if source == "brave" else ("SEARXNG_URL",)
                       if source == "searxng" else source_contract(source).credential_env)
        optional = source in {"urlscan", "greynoise", "github", "nvd"}
        missing = [name for name in credentials if not os.environ.get(name, "").strip()]
        state = "configured" if credentials and not missing else "keyless" if not credentials or optional else "not_configured"
        if source == "searxng" and not missing:
            try:
                search_base()
            except ConnectorNotConfigured:
                state = "invalid_configuration"
        rows.append({"source_id": source, "target_types": list(kinds), "tool": SOURCE_TOOLS[source],
                     "configuration_status": state, "credential_env": list(credentials),
                     "credentials_optional": optional, "live_validation": "deployment-required",
                     "selection": "capability-router-or-explicit-approved-plan"})
    return rows
