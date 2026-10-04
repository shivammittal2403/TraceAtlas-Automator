"""Uniform adapter contract over reviewed requests and deterministic normalizers."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from ..intelligence.hub import ConnectorNotConfigured
from ..intelligence.provider import ProviderError, ResilientJSONClient
from ..intelligence.rdap import lookup as rdap_lookup
from .documents import DOCUMENT_SCHEMA, SourceDocument
from .live_sources import request_spec
from .normalization import live_facts
from .source_registry import SourceRegistry, P0_IDS


class CollectionStopped(ValueError):
    """An authority stop must never be translated into an ordinary source failure."""


@dataclass
class SourceResult:
    source_id: str
    query_id: str
    retrieval_time: str | None = None
    raw_evidence_id: str | None = None
    observations: list = field(default_factory=list)
    candidate_entities: list = field(default_factory=list)
    candidate_relationships: list = field(default_factory=list)
    timestamps: list = field(default_factory=list)
    source_metadata: dict = field(default_factory=dict)
    confidence_metadata: dict = field(default_factory=lambda: {'basis': 'source-assertion', 'identity_verified': False})
    provenance: dict = field(default_factory=dict)
    cost: dict = field(default_factory=lambda: {'estimated': None, 'actual': None, 'currency': 'USD'})
    latency_ms: int = 0
    errors: list = field(default_factory=list)


@dataclass
class SourceBatch:
    documents: tuple[SourceDocument, ...]
    status: str
    reason: str | None = None
    bootstrap_attempts: int = 0


class SourceConnector:
    def __init__(self, source_id, *, registry=None, state=None):
        self.registry = registry or SourceRegistry()
        self.manifest = self.registry.get(source_id)
        if source_id not in P0_IDS:
            raise ValueError('source has no canonical P0 adapter')
        self.source_id, self.state = source_id, state

    def health(self):
        return self.state.health(self.source_id) if self.state else {'state': 'UNKNOWN'}

    def capabilities(self):
        return self.manifest.capabilities

    def validate_input(self, kind, target):
        if not self.registry.supports(self.source_id, kind, target):
            raise ValueError('unsupported source input')
        from .documents import normalize_seed
        if normalize_seed(kind, target) != target:
            raise ValueError('source input must be normalized')

    def estimate_cost(self):
        return {'amount': self.manifest.estimated_request_cost, 'currency': 'USD',
                'basis': self.manifest.pricing_model, 'actual': None}

    def normalize(self, kind, target, data, retrieved_at):
        return live_facts(self.source_id, kind + ':' + target, data, retrieved_at)

    def evidence_metadata(self):
        return {'source_id': self.source_id, 'connector_version': self.manifest.contract_version,
                'upstream_group': self.manifest.upstream_group, 'instruction_authority': 'none'}

    def rate_limit_status(self):
        return {'state': self.health()['state'], 'provider_concurrency': self.manifest.provider_concurrency,
                'documented_quota': self.manifest.rate_limit, 'retry_429': False}

    def provenance(self):
        return {'provider': self.manifest.provider, 'documentation': self.manifest.documentation_url,
                'upstream_group': self.manifest.upstream_group}

    def close(self):
        return None

    def search(self, kind, target, requester, timeout):
        return self.fetch(kind, target, requester, timeout)

    def fetch(self, kind, target, requester, timeout):
        self.validate_input(kind, target)
        captured, documents = {}, []
        response_limit = 5 * 1024 * 1024 if self.source_id == 'cisa_kev' else 400 * 1024
        bootstrap_attempts = 0
        def receive(url, headers, remaining):
            status, raw = requester(url, headers, remaining)
            if status == 200 and len(raw) <= response_limit:
                # A malicious API echo must not put credentials in evidence.
                secrets = [v for k, v in headers.items() if k.lower() in {'authorization', 'x-apikey', 'api-key', 'key', 'x-subscription-token'}]
                secrets.extend(v for k, values in parse_qs(urlsplit(url).query).items()
                               if k.lower() in {'key', 'api_key', 'api-key', 'api_token'} for v in values)
                secrets.extend(os.environ.get(ref, '') for ref in self.manifest.credential_refs
                               if ref not in {'SEC_USER_AGENT', 'SEARXNG_URL'})
                if any(len(value) >= 4 and value.encode() in raw for value in secrets):
                    raise ProviderError('provider_secret_echo')
                captured[url] = raw
            return status, raw
        client = ResilientJSONClient(receive, max_body_bytes=response_limit, max_attempts=2, retry_rate_limits=False)
        url = None
        try:
            if self.source_id == 'rdap':
                def bootstrap(uri, result):
                    nonlocal bootstrap_attempts
                    bootstrap_attempts = result.attempts
                    documents.append(SourceDocument(DOCUMENT_SCHEMA, 'rdap_bootstrap', uri,
                        datetime.now(timezone.utc).isoformat(), captured[uri].decode('utf-8'), (), None, 'iana'))
                url, response = rdap_lookup(client, kind, target, timeout, on_bootstrap=bootstrap)
            else:
                url, headers = request_spec(self.source_id, kind, target)
                response = client.get(self.source_id, url, headers, timeout)
            stamp = datetime.now(timezone.utc).isoformat()
            facts = self.normalize(kind, target, response.data, stamp)
            uri = 'urn:traceatlas:provider:searxng:search' if self.source_id == 'searxng' else url.split('?', 1)[0]
            documents.append(SourceDocument(DOCUMENT_SCHEMA, self.source_id, uri, stamp,
                captured[url].decode('utf-8'), facts, None, self.manifest.upstream_group))
            return SourceBatch(tuple(documents), 'captured', bootstrap_attempts=bootstrap_attempts)
        except CollectionStopped as exc:
            exc.documents = tuple(documents)
            raise
        except (ProviderError, ConnectorNotConfigured, OSError, ValueError, KeyError, TypeError) as exc:
            reason = exc.code if isinstance(exc, (ProviderError, ConnectorNotConfigured)) else 'connector_contract_failure'
            if isinstance(exc, ConnectorNotConfigured):
                return SourceBatch(tuple(documents), 'skipped', reason, bootstrap_attempts)
            # Preserve bounded, decodable malformed responses with zero assertions.
            # Secret echoes and oversized responses are deliberately never preserved.
            if url in captured and reason != 'provider_secret_echo':
                try:
                    uri = 'urn:traceatlas:provider:searxng:search' if self.source_id == 'searxng' else url.split('?', 1)[0]
                    documents.append(SourceDocument(DOCUMENT_SCHEMA, self.source_id, uri,
                        datetime.now(timezone.utc).isoformat(), captured[url].decode('utf-8'), (), None, self.manifest.upstream_group))
                    return SourceBatch(tuple(documents), 'quarantined', reason, bootstrap_attempts)
                except (UnicodeDecodeError, ValueError):
                    pass
            return SourceBatch(tuple(documents), 'failed', reason, bootstrap_attempts)
