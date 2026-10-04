from __future__ import annotations

import json
from collections import Counter
from importlib.resources import files

from ..intelligence.sources import SOURCES
from ..intelligence.contracts import source_contract

STATES = frozenset({"DISCOVERED", "CATALOGUED", "DOCUMENTED", "CONNECTOR_IMPLEMENTED", "CONFIGURED",
                    "LIVE_VERIFIED", "PRODUCTION_QUALIFIED", "DEGRADED", "DISABLED", "DEPRECATED", "BROKEN"})
P0 = ("dns", "rdap", "wayback", "internetdb", "ripestat", "gleif", "github", "gitlab", "npm", "nvd",
      "epss", "osv", "crossref", "ipwhois", "greynoise", "shodan", "censys", "virustotal", "bluesky", "hackernews")
CAPABILITIES = {
    "dns": ("dns",), "cloudflare_dns": ("dns",), "rdap": ("registration",),
    "wayback": ("archive",), "urlscan": ("archive",), "crtsh": ("certificate-transparency",),
    "internetdb": ("exposure",), "ripestat": ("routing",), "gleif": ("company-record",),
    "companieshouse": ("company-record", "filings"), "sec": ("company-record", "filings"),
    "opencorporates": ("company-record",),
    "ipwhois": ("ip-context",), "ipdata": ("ip-context",), "greynoise": ("threat-context",),
    "shodan": ("exposure",), "censys": ("exposure",), "virustotal": ("threat-context",),
    "github": ("public-profile",), "gitlab": ("public-profile",), "hackernews": ("public-profile",),
    "bluesky": ("public-profile",), "mastodon": ("public-profile",), "orcid": ("public-profile",),
    "stackexchange": ("public-profile",), "dockerhub": ("package",), "npm": ("package",),
    "nvd": ("vulnerability",), "osv": ("vulnerability",), "epss": ("exploitation-probability",),
    "crossref": ("publication",), "youtube": ("media-profile",), "discord": ("community-metadata",),
}
DOCS = {
    'gleif': 'https://www.gleif.org/en/lei-data/gleif-api/',
    'ripestat': 'https://stat.ripe.net/docs/data-api/api-endpoints/network-info',
    'epss': 'https://api.first.org/epss/', 'osv': 'https://google.github.io/osv.dev/get-v1-vulns/',
    'dns': 'https://developers.google.com/speed/public-dns/docs/doh/json',
    'cloudflare_dns': 'https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/',
    'rdap': 'https://data.iana.org/rdap/', 'crtsh': 'https://crt.sh/',
    'wayback': 'https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server',
    'urlscan': 'https://urlscan.io/docs/api/',
    'companieshouse': 'https://developer.company-information.service.gov.uk/',
    'sec': 'https://www.sec.gov/search-filings/edgar-application-programming-interfaces',
    'opencorporates': 'https://api.opencorporates.com/documentation/API-Reference',
    'github': 'https://docs.github.com/en/rest/users/users', 'gitlab': 'https://docs.gitlab.com/api/users/',
    'hackernews': 'https://github.com/HackerNews/API',
    'crossref': 'https://www.crossref.org/documentation/retrieve-metadata/rest-api/',
    'ipwhois': 'https://ipwhois.io/documentation', 'shodan': 'https://developer.shodan.io/api',
    'virustotal': 'https://docs.virustotal.com/reference/overview',
    'censys': 'https://docs.censys.com/docs/platform-api',
    'npm': 'https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md',
    'bluesky': 'https://github.com/bluesky-social/atproto/blob/main/lexicons/app/bsky/actor/getProfile.json',
    'greynoise': 'https://docs.greynoise.io/reference/getcommunityip',
    'internetdb': 'https://internetdb.shodan.io/',
}
KNOWN_BROKEN = {}
PRIMARY = frozenset({"dns", "wayback", "gleif", "ripestat", "epss", "github", "gitlab", "npm", "crossref", "nvd",
                     "rdap", "crtsh", "companieshouse", "sec"})


def candidates():
    return json.loads(files("traceatlas.data").joinpath("source_fabric_candidates.json").read_text(encoding="utf-8"))["candidates"]


def manifest(source):
    spec, contract = SOURCES[source], source_contract(source)
    return {
        "source_id": source, "provider": {"internetdb": "shodan", "dns": "google"}.get(source, source),
        "name": spec.title, "category": spec.category, "capabilities": list(CAPABILITIES.get(source, ())),
        "entity_types": list(contract.inputs), "countries": [], "languages": [],
        "access_type": spec.acquisition, "official": None, "primary_source": source in PRIMARY,
        "auth_type": contract.authentication, "secret_references": list(contract.credential_env),
        "pricing_model": "unknown", "estimated_cost": {"amount": None, "currency": None},
        "rate_limit": {"provider_limit": None, "local_min_interval_seconds": 1},
        "freshness": {"provider_sla": None, "local_cache_ttl_seconds": 300 if not spec.personal_data else 0},
        "reliability": {"measured": False}, "legal_constraints": ["deployment terms and entitlement review required"],
        "license": "unknown", "privacy_classification": "personal-public" if spec.personal_data else "public-metadata",
        "health": {"state": "BROKEN" if source in KNOWN_BROKEN else "UNKNOWN", "reason": KNOWN_BROKEN.get(source)}, "fallback_sources": [],
        "implementation_status": "CONNECTOR_IMPLEMENTED" if spec.live_connector else "CATALOGUED",
        "execution_path": "traceatlas.intelligence.hub.IntelligenceHub.collect" if spec.live_connector else None,
        "documentation_url": DOCS.get(source), "documentation_review": "partial-documentation-review-2026-10-03" if source in DOCS else "unverified",
        "contract": contract.to_dict(), "p0": source in P0, "limitation": spec.limitation,
    }


def audit(db=None):
    rows = [manifest(source) for source in sorted(SOURCES)]
    catalogue = candidates()
    result = {"source_records": len(rows), "implemented_api_connectors": sum(bool(r["execution_path"]) for r in rows),
              "approved_export_only": sum(not bool(r["execution_path"]) for r in rows),
              "candidate_slots": len(catalogue), "canonical_candidate_slots": len({r["canonical_candidate_id"] for r in catalogue}),
              "duplicate_candidate_slots": sum(r["candidate_id"] != r["canonical_candidate_id"] for r in catalogue),
              "non_provider_candidate_slots": sum(r["candidate_kind"] != "named-candidate" for r in catalogue),
              "live_verified": 0, "production_qualified": 0, "broken": sorted(KNOWN_BROKEN), "mock_production_connectors": [],
              "unverified_live_connectors": [r["source_id"] for r in rows if r["execution_path"]],
              "p0_implemented": sum(SOURCES[s].live_connector for s in P0),
              "capability_coverage": dict(Counter(c for r in rows for c in r["capabilities"])),
              "jurisdiction_coverage": "not-qualified; no inferred worldwide coverage",
              "p0_gaps": ["beneficial-ownership", "procurement", "sanctions", "web-search", "geospatial"],
              "counting_note": "400 input slots include aliases and tools; external OpenCTI packages are not live local sources."}
    if db is not None:
        from .store import FabricStore
        store = FabricStore(db)
        qualified = store.states()
        result["live_verified"] = sum(v == "LIVE_VERIFIED" or v == "PRODUCTION_QUALIFIED" for v in qualified.values())
        result["production_qualified"] = sum(v == "PRODUCTION_QUALIFIED" for v in qualified.values())
        result["broken"] = sorted(set(KNOWN_BROKEN) | {s for s, state in qualified.items() if state == "BROKEN"})
        result["unverified_live_connectors"] = [s for s in result["unverified_live_connectors"] if qualified.get(s) not in {"LIVE_VERIFIED", "PRODUCTION_QUALIFIED"}]
        result["metrics"] = store.metrics()
    return result
