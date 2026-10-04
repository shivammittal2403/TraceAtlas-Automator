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
P0_DEFINITIONS = json.loads(files('traceatlas.workforce.data').joinpath('source_manifests.json').read_text())
P0_IDS = frozenset(r['source_id'] for r in P0_DEFINITIONS)
P0_BY_ID = {r['source_id']: r for r in P0_DEFINITIONS}
QUALIFICATION_GATES = SOURCE_QUALIFICATION_GATES


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
    implementation_status: str = "DISCOVERED"
    tool: str | None = None
    documentation_url: str | None = None
    documentation_checked_at: str | None = None
    contract_version: int = 1

    def __post_init__(self):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,99}", self.source_id) or self.implementation_status not in STATES:
            raise ValueError("invalid source manifest identity/state")
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
        value.update(estimated_cost={'amount': self.estimated_request_cost, 'currency': self.currency,
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

    @staticmethod
    def qualification(gates, *, verified_runtime=False):
        """Evidence-backed ladder; fixtures and configured keys cannot promote."""
        if type(verified_runtime) is not bool:
            raise ValueError('runtime verification must be an explicit boolean')
        if not isinstance(gates, dict) or set(gates) - QUALIFICATION_GATES:
            raise ValueError('unknown qualification gates')
        if not all(isinstance(v, dict) and set(v) == {'passed', 'evidence_ref'} and type(v['passed']) is bool
                   and isinstance(v['evidence_ref'], str) and v['evidence_ref'].strip() for v in gates.values()):
            raise ValueError('qualification requires evidence references')
        passed = {key for key, value in gates.items() if value['passed']}
        missing = sorted(k for k in QUALIFICATION_GATES if k not in passed)
        if not {'documentation', 'manifest'}.issubset(passed):
            state = 'DISCOVERED'
        elif not {'terms', 'license'}.issubset(passed):
            state = 'CATALOGUED'
        elif 'connector' not in passed:
            state = 'TERMS_REVIEWED'
        elif not {'authentication', 'configured'}.issubset(passed):
            state = 'CONNECTOR_CODED'
        elif 'live_request' not in passed:
            state = 'CONFIGURED'
        elif not verified_runtime:
            state = 'LIVE_TESTED'
        elif LIVE_VERIFICATION_GATES.issubset(passed):
            state = 'PRODUCTION_QUALIFIED' if not missing else 'LIVE_VERIFIED'
        else:
            state = 'LIVE_TESTED'
        return {'state': state, 'maturity_state': state,
                'missing_gates': missing, 'runtime_verified': verified_runtime}
