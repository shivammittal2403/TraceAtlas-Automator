"""Canonical capability metadata over existing adapters; catalog rows grant no I/O."""
from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from importlib.resources import files
from urllib.parse import urlsplit

from ..intelligence.sources import SOURCES
from ..intelligence.contracts import source_contract
from ..intelligence.registry_requests import company_identifier
from ..source_maturity import (LIVE_VERIFICATION_GATES, MATURITY_STATES,
                               SOURCE_QUALIFICATION_GATES, normalize_maturity)

STATES = frozenset(MATURITY_STATES)
LIFECYCLE_TRANSITIONS = {
    "DISCOVERED": frozenset({"CATALOGUED", "DISABLED", "DEPRECATED"}),
    "CATALOGUED": frozenset({"TERMS_REVIEWED", "DISABLED", "DEPRECATED"}),
    "TERMS_REVIEWED": frozenset({"CONNECTOR_CODED", "DISABLED", "DEPRECATED"}),
    "CONNECTOR_CODED": frozenset({"CONFIGURED", "DISABLED", "DEPRECATED"}),
    "CONFIGURED": frozenset({"LIVE_TESTED", "DISABLED", "DEPRECATED"}),
    "LIVE_TESTED": frozenset({"LIVE_VERIFIED", "DEGRADED", "DISABLED", "DEPRECATED"}),
    "LIVE_VERIFIED": frozenset({"PRODUCTION_QUALIFIED", "DEGRADED", "DISABLED", "DEPRECATED"}),
    "PRODUCTION_QUALIFIED": frozenset({"DEGRADED", "DISABLED", "DEPRECATED"}),
    "DEGRADED": frozenset({"CONFIGURED", "LIVE_TESTED", "DISABLED", "DEPRECATED"}),
    "DISABLED": frozenset({"CONFIGURED", "DEPRECATED"}),
    "DEPRECATED": frozenset(),
}
LIFECYCLE_ORDER = ("DISCOVERED", "CATALOGUED", "TERMS_REVIEWED", "CONNECTOR_CODED",
                   "CONFIGURED", "LIVE_TESTED", "LIVE_VERIFIED", "PRODUCTION_QUALIFIED")
P0_DEFINITIONS = json.loads(files('traceatlas.workforce.data').joinpath('source_manifests.json').read_text())
P0_IDS = frozenset(r['source_id'] for r in P0_DEFINITIONS)
P0_BY_ID = {r['source_id']: r for r in P0_DEFINITIONS}
QUALIFICATION_GATES = SOURCE_QUALIFICATION_GATES
CATALOGUE_GATES = frozenset({"documentation", "manifest"})
TERMS_GATES = CATALOGUE_GATES | frozenset({"terms", "license"})
CONNECTOR_GATES = TERMS_GATES | frozenset({"connector", "security"})
CONFIGURATION_GATES = TERMS_GATES | frozenset({"connector", "authentication", "configured"})


@dataclass(frozen=True)
class SourceManifest:
    source_id: str
    provider: str
    name: str
    category: str
    capabilities: tuple[str, ...]
    entity_types: tuple[str, ...]
    countries: tuple[str, ...] = ("GLOBAL",)
    languages: tuple[str, ...] = ("en",)
    access_type: str = "API"
    official: bool = False
    primary_source: bool = False
    auth_type: str = "UNKNOWN"
    credential_refs: tuple[str, ...] = ()
    pricing_model: str = "UNKNOWN"
    estimated_request_cost: float | None = None
    currency: str = "USD"
    cache_ttl_seconds: int = 0
    provider_concurrency: int = 1
    rate_limit: str = "UNKNOWN"
    license: str = "UNKNOWN"
    legal_constraints: tuple[str, ...] = ("authorized-purpose", "operator-terms-review")
    privacy_classification: str = "PUBLIC_METADATA"
    upstream_group: str = "UNKNOWN"
    fallback_sources: tuple[str, ...] = ()
    implementation_status: str = "CATALOGUED"
    tool: str | None = None
    documentation_url: str | None = None
    documentation_checked_at: str | None = None
    contract_version: int = 1
    connector_implemented: bool = False

    def __post_init__(self):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,99}", self.source_id) or self.implementation_status not in STATES:
            raise ValueError("invalid source manifest identity/state")
        if type(self.connector_implemented) is not bool:
            raise ValueError("connector_implemented must be boolean")
        if any(not re.fullmatch(r"[a-z][a-z0-9_.-]{1,99}", c) for c in self.capabilities):
            raise ValueError("invalid capability")
        price = self.estimated_request_cost
        if price is not None and (isinstance(price, bool) or not math.isfinite(price) or price < 0):
            raise ValueError("invalid source price estimate")
        if not 0 <= self.cache_ttl_seconds <= 86400 or not 1 <= self.provider_concurrency <= 4:
            raise ValueError("invalid source limits")
        if self.documentation_url:
            p = urlsplit(self.documentation_url)
            if p.scheme != "https" or not p.hostname or p.username or p.password:
                raise ValueError("invalid documentation URL")

    def to_dict(self):
        value = asdict(self)
        value["implementation_status"] = normalize_maturity(self.implementation_status)
        value["maturity_state"] = value["implementation_status"]
        value.update(lifecycle_state=value["implementation_status"],
                     estimated_cost={'amount': self.estimated_request_cost, 'currency': self.currency,
                                     'basis': self.pricing_model, 'actual': None},
                     freshness={'max_cache_age_seconds': self.cache_ttl_seconds, 'provider_timestamp': 'preserved-when-supplied'},
                     reliability={'qualification': 'requires-runtime-evidence'},
                     health={'state': 'UNKNOWN', 'source': 'use-case-store-health-for-observed-status'})
        return value


def _manifests():
    result = []
    for source_id in sorted(set(SOURCES) | P0_IDS):
        spec = SOURCES.get(source_id)
        p = P0_BY_ID.get(source_id, {})
        contract = source_contract(source_id) if spec else None
        implemented = source_id in P0_IDS or bool(spec and spec.live_connector)
        refs = tuple(contract.credential_env) if contract else (("BRAVE_SEARCH_API_KEY",) if source_id == "brave" else ("SEARXNG_URL",))
        result.append(SourceManifest(source_id, p.get('provider', source_id), spec.title if spec else source_id,
            spec.category if spec else 'web-search', tuple(p.get('capabilities', ['legacy.' + source_id])),
            tuple(p.get('entity_types', contract.inputs if contract else ())),
            countries=tuple(p.get('countries', ['GLOBAL'])), official=p.get('official', False),
            primary_source=p.get('primary_source', False), credential_refs=refs,
            auth_type=contract.authentication if contract else 'secret-reference' if source_id == 'brave' else 'loopback-configuration',
            pricing_model=p.get('pricing_model', 'UNKNOWN'), estimated_request_cost=p.get('cost_per_request_usd'),
            cache_ttl_seconds=p.get('cache_ttl_seconds', 0), upstream_group=p.get('upstream_group', source_id),
            access_type='API' if implemented else 'APPROVED_EXPORT',
            implementation_status='CONNECTOR_CODED' if implemented else 'CATALOGUED',
            connector_implemented=implemented,
            tool=p.get('tool'), documentation_url=p.get('documentation_url'),
            documentation_checked_at=p.get('documentation_checked_at'), languages=tuple(p.get('languages', ['en'])),
            rate_limit=p.get('rate_limit', 'UNKNOWN'), license=p.get('license', 'UNKNOWN'),
            legal_constraints=tuple(p.get('legal_constraints', ['authorized-purpose', 'operator-terms-review'])),
            contract_version=contract.contract_version if contract else 1))
    return result


class SourceRegistry:
    def __init__(self, manifests=None):
        rows = list(_manifests() if manifests is None else manifests)
        self._sources = {r.source_id: r for r in rows}
        if len(rows) != len(self._sources) or len(rows) > 10000:
            raise ValueError('duplicate or excessive source definitions')

    def list(self):
        return tuple(self._sources[k] for k in sorted(self._sources))

    def get(self, source_id):
        try:
            return self._sources[source_id]
        except KeyError:
            raise ValueError('unknown source') from None

    def capabilities(self):
        return {cap: [r.source_id for r in self.list() if cap in r.capabilities]
                for cap in sorted({cap for r in self.list() for cap in r.capabilities})}

    def supports(self, source, kind, target):
        item = self.get(source)
        if kind not in item.entity_types or source not in P0_IDS:
            return False
        if kind == 'company' and source not in {'brave', 'searxng'}:
            try:
                company_identifier(source, target)
            except (KeyError, ValueError):
                return False
        if kind == 'ip' and source in {'internetdb', 'greynoise'}:
            import ipaddress
            return ipaddress.ip_address(target).version == 4
        return True

    def lifecycle_counts(self):
        from ..source_maturity import maturity_counts
        return maturity_counts(item.implementation_status for item in self._sources.values())

    def live_integrations(self):
        """Only LIVE_VERIFIED and PRODUCTION_QUALIFIED sources count as live."""
        return tuple(item for item in self.list()
                     if item.implementation_status in {"LIVE_VERIFIED", "PRODUCTION_QUALIFIED"})

    @staticmethod
    def qualification(gates, *, verified_runtime=False):
        """Derive the highest lifecycle stage supported by submitted evidence attestations."""
        if type(verified_runtime) is not bool:
            raise ValueError("verified_runtime must be boolean")
        if not isinstance(gates, dict) or set(gates) - QUALIFICATION_GATES:
            raise ValueError("unknown qualification gates")
        if not all(isinstance(v, dict) and set(v) == {"passed", "evidence_ref"} and type(v["passed"]) is bool
                   and isinstance(v["evidence_ref"], str) and 1 <= len(v["evidence_ref"].strip()) <= 512
                   and not any(ord(ch) < 32 for ch in v["evidence_ref"]) for v in gates.values()):
            raise ValueError("qualification requires evidence references")
        passed = {name for name, item in gates.items() if item["passed"]}
        missing = sorted(QUALIFICATION_GATES - passed)
        state = "DISCOVERED"
        if CATALOGUE_GATES.issubset(passed):
            state = "CATALOGUED"
        if TERMS_GATES.issubset(passed):
            state = "TERMS_REVIEWED"
        if TERMS_GATES.union({"connector"}).issubset(passed):
            state = "CONNECTOR_CODED"
        if CONFIGURATION_GATES.issubset(passed):
            state = "CONFIGURED"
        if CONFIGURATION_GATES.issubset(passed) and "live_request" in passed:
            state = "LIVE_TESTED"
        if LIVE_VERIFICATION_GATES.issubset(passed) and verified_runtime:
            state = "LIVE_VERIFIED"
        if QUALIFICATION_GATES.issubset(passed) and verified_runtime:
            state = "PRODUCTION_QUALIFIED"
        return {"state": state, "maturity_state": state, "missing_gates": missing,
                "runtime_verified": verified_runtime, "persisted": False}

    @classmethod
    def transition(cls, current, target, gates, *, verified_runtime=False):
        """Validate a proposed lifecycle transition without persisting a source status."""
        if current not in STATES or target not in STATES:
            raise ValueError("unknown source lifecycle state")
        if target not in LIFECYCLE_TRANSITIONS[current]:
            raise ValueError("source lifecycle transition is not allowed")
        qualification = cls.qualification(gates, verified_runtime=verified_runtime)
        if target in LIFECYCLE_ORDER and LIFECYCLE_ORDER.index(qualification["state"]) < LIFECYCLE_ORDER.index(target):
            raise ValueError("source lifecycle transition lacks required qualification evidence")
        return {"from": current, "state": target, "qualification": qualification, "persisted": False}
