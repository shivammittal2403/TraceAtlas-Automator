from __future__ import annotations

import os

from ..policy import PolicyError
from .registry import SOURCES, CAPABILITIES, manifest
from .sdk import HubConnector
from .store import FabricStore

KEYWORDS = {
    "dns": ("dns", "resolve"), "registration": ("registration", "registrar", "ownership", "whois"),
    "archive": ("history", "historical", "archive"), "exposure": ("exposure", "ports", "services"),
    "routing": ("asn", "bgp", "routing", "network"), "ip-context": ("geography", "geolocation"),
    "company-record": ("company", "corporate", "lei"), "threat-context": ("threat", "reputation"),
    "vulnerability": ("vulnerability", "cve", "advisory"), "exploitation-probability": ("epss", "probability"),
    "package": ("package", "software"), "publication": ("doi", "publication"),
    "public-profile": ("profile", "username", "developer"), "sanctions": ("sanction",),
    "procurement": ("procurement", "contract award"), "filings": ("filing",),
    "beneficial-ownership": ("beneficial",), "certificate-transparency": ("certificate", "ct log"),
    "web-search": ("web search", "news", "dork"), "geospatial": ("satellite", "geospatial"),
}
DEFAULTS = {"domain": {"dns", "registration"}, "ip": {"routing", "registration"},
            "company": {"company-record"}, "lei": {"company-record"}, "cve": {"vulnerability", "exploitation-probability"},
            "vulnerability": {"vulnerability"}, "package": {"package"}, "doi": {"publication"}}


class SourceRouter:
    def __init__(self, db=None):
        self.db = db

    def plan(self, objective, kind, target, attestations, *, country=None, language=None):
        if not isinstance(kind, str) or not isinstance(target, str):
            raise PolicyError("Typed seed required")
        compatible = [manifest(s) for s in SOURCES if SOURCES[s].live_connector and kind in manifest(s)["entity_types"]]
        if not compatible:
            raise PolicyError("No implemented source accepts this identifier type")
        if kind in {"domain", "ip", "hash", "url"} and not attestations.get("owned_asset"):
            raise PolicyError("Written asset authority is required")
        required = {cap for cap, words in KEYWORDS.items() if any(word in objective.casefold() for word in words)}
        relevant = {c for m in compatible for c in m["capabilities"]}
        if not required.intersection(relevant):
            required |= DEFAULTS.get(kind, relevant)
        blocked, ranked = [], []
        states = FabricStore(self.db).states() if self.db else {}
        health = {r["source"]: r for r in self.db.connector_health()} if self.db else {}
        for m in compatible:
            source, spec = m["source_id"], SOURCES[m["source_id"]]
            covers = set(m["capabilities"]) & required
            if not covers:
                continue
            if spec.personal_data and not (attestations.get("subject_consent") or attestations.get("owned_org")):
                raise PolicyError("Personal/public-profile collection requires consent or owned-organization authority")
            if spec.public_record and not (attestations.get("public_record_basis") or attestations.get("owned_org")):
                raise PolicyError("Public-record basis is required")
            try:
                HubConnector(source).validate_input(kind, target)
            except (ValueError, PolicyError):
                blocked.append({"source": source, "reason": "input-or-configuration-incompatible"})
                continue
            contract = m["contract"]
            if m["health"]["state"] == "DEGRADED" or states.get(source) in {"DISABLED", "DEPRECATED", "DEGRADED"} or health.get(source, {}).get("consecutive_failures", 0) >= 3:
                blocked.append({"source": source, "reason": "source-unhealthy-or-disabled"})
                continue
            if contract["authentication"] == "secret-reference" or any(os.getenv(k) for k in contract["credential_env"]):
                blocked.append({"source": source, "reason": "unattended-entitlement-required"})
                continue
            covers = set(m["capabilities"]) & required
            if not covers:
                continue
            # These are explicit policy weights, not fabricated empirical estimates.
            score = 100*len(covers) + 15*int(m["primary_source"]) + 10*int(states.get(source) == "LIVE_VERIFIED")
            score -= 20*health.get(source, {}).get("consecutive_failures", 0)
            ranked.append({"source": source, "target_type": kind, "target": target,
                           "capabilities": sorted(covers), "score": score, "provider": m["provider"],
                           "rationale": {"capability_match": sorted(covers), "primary_source": m["primary_source"],
                                         "health_failures": health.get(source, {}).get("consecutive_failures", 0),
                                         "jurisdiction_fit": "unknown" if country else "not-constrained",
                                         "language_fit": "unknown" if language else "not-constrained",
                                         "pricing": "unknown; credentialed calls excluded", "expected_information_gain": "coverage heuristic"}})
        uncovered, initial, fallback = set(required), [], []
        for row in sorted(ranked, key=lambda r: (-r["score"], r["source"])):
            if uncovered.intersection(row["capabilities"]):
                initial.append({**row, "wave": 1})
                uncovered -= set(row["capabilities"])
            else:
                fallback.append({**row, "wave": 2})
        return {"requirements": sorted(required), "actions": initial+fallback,
                "uncovered_capabilities": sorted(uncovered), "blocked_sources": blocked,
                "selection": "greedy capability cover; fallback only for unresolved evidence gaps",
                "scope_expansion": False}
