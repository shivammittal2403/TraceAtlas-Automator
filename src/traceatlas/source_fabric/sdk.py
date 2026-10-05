"""One bounded SDK adapter for existing fixed-origin provider implementations."""
from __future__ import annotations

import os
from typing import Protocol

from ..intelligence.hub import IntelligenceHub
from ..intelligence.provider import ResilientJSONClient
from ..intelligence.sources import SOURCES
from ..intelligence.transport import request
from ..policy import PolicyError
from .registry import manifest


class Connector(Protocol):
    def health(self): ...
    def capabilities(self): ...
    def validate_input(self, kind, target): ...
    def estimate_cost(self): ...
    def search(self, kind, target, timeout=30): ...
    def fetch(self, kind, target, timeout=30): ...
    def normalize(self, kind, target, response): ...
    def evidence_metadata(self, response): ...
    def rate_limit_status(self): ...
    def provenance(self): ...
    def close(self): ...


class HubConnector:
    def __init__(self, source, *, requester=None, authorization_check=None):
        self.source, self.spec = source, SOURCES[source]
        self.definition = manifest(source)
        if not self.definition["execution_path"]:
            raise PolicyError("Candidate has no executable connector")
        self.fixture = requester is not None
        transport = requester or request
        def guarded_request(url, headers, timeout):
            if authorization_check is not None:
                authorization_check()
            return transport(url, headers, timeout)
        self.client = ResilientJSONClient(guarded_request)

    def health(self):
        return {**self.definition["health"], "network_probe": False}

    def capabilities(self):
        return self.definition["capabilities"]

    def validate_input(self, kind, target):
        if kind not in self.definition["entity_types"] or not isinstance(target, str) or len(target) > 253:
            raise PolicyError("Unsupported source input")
        if self.source == "rdap":
            from ..intelligence.rdap import bootstrap_url
            bootstrap_url(kind, target)
        else:
            IntelligenceHub._live_request(self.spec, kind, target)
        return True

    def estimate_cost(self):
        return {"amount": None, "pricing_verified": False, "credentialed_calls_permitted": False}

    def fetch(self, kind, target, timeout=30):
        contract = self.definition["contract"]
        if contract["authentication"] == "secret-reference" or any(os.getenv(k) for k in contract["credential_env"]):
            raise PolicyError("Source Fabric requires a reviewed unattended entitlement for credentialed calls")
        self.validate_input(kind, target)
        if self.source == "rdap":
            from ..intelligence.rdap import lookup
            return lookup(self.client, kind, target, timeout)[1]
        url, headers = IntelligenceHub._live_request(self.spec, kind, target)
        return self.client.get(self.source, url, headers, timeout)

    def search(self, kind, target, timeout=30):
        raise PolicyError("This connector exposes exact fetch only")

    def normalize(self, kind, target, response):
        return IntelligenceHub._validated_records(self.source, kind, target, response.data)

    def evidence_metadata(self, response):
        return {"source": self.source, "connector_version": self.definition["contract"]["contract_version"],
                "parser_version": 1, "response_sha256": response.response_sha256, "response_bytes": response.bytes_received,
                "raw_retention_eligible": not self.spec.personal_data, "fixture": self.fixture}

    def rate_limit_status(self):
        return {"remaining_provider_quota": None, "local_min_interval_seconds": 1}

    def provenance(self):
        return {"source_id": self.source, "provider": self.definition["provider"],
                "documentation_url": self.definition["documentation_url"], "upstream_independence": "UNKNOWN"}

    def close(self):
        pass  # The HTTPS transport closes each bounded request.
