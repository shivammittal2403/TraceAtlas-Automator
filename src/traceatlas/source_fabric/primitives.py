"""Reusable connector primitives over reviewed transports and offline payloads.

These classes are protocol implementations, never additional source providers.
New origins still require a reviewed provider contract and canonical gateway.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from copy import deepcopy
from xml.etree import ElementTree

from ..intelligence.hub import IntelligenceHub
from ..intelligence.provider import ProviderResult, _validate_shape
from ..policy import PolicyError
from .sdk import HubConnector
from ..intelligence.transport import request


class BaseConnector:
    protocol = 'REST'
    max_bytes = 4 * 1024 * 1024

    def __init__(self, source, *, requester=None, authorization_check=None):
        self.authorization_check = authorization_check
        transport = requester or request
        def guarded_request(url, headers, timeout):
            self._authorize()
            return transport(url, headers, timeout)
        self.adapter = HubConnector(source, requester=guarded_request)
        self.adapter.fixture = requester is not None

    @property
    def spec(self):
        return self.adapter.spec

    @property
    def definition(self):
        return self.adapter.definition

    @property
    def fixture(self):
        return self.adapter.fixture

    def validate_input(self, kind, target):
        return self.adapter.validate_input(kind, target)

    def evidence_metadata(self, response):
        return {**self.adapter.evidence_metadata(response), 'primitive': self.protocol}

    def provenance(self):
        return self.adapter.provenance()

    def manifest(self):
        return {**deepcopy(self.adapter.definition), 'primitive': self.protocol}

    def capabilities(self):
        return self.adapter.capabilities()

    def validate_config(self):
        refs = self.adapter.definition['contract']['credential_env']
        missing = [ref for ref in refs if not os.environ.get(ref)]
        return {'configured': not missing, 'missing_secret_references': missing,
                'entitlement_verified': False, 'live_verified': False}

    def health(self):
        return self.adapter.health()

    def estimate_cost(self):
        return self.adapter.estimate_cost()

    def rate_limit_status(self):
        return self.adapter.rate_limit_status()

    def _authorize(self):
        if self.authorization_check is None:
            raise PolicyError('Canonical gateway authorization check required')
        self.authorization_check()

    def fetch(self, kind, target, timeout=30):
        self._authorize()
        return self.adapter.fetch(kind, target, timeout)

    def search(self, kind, target, timeout=30):
        self._authorize()
        return self.adapter.search(kind, target, timeout)

    def normalize(self, kind, target, response):
        return self.adapter.normalize(kind, target, response)

    def extract_observations(self, kind, target, response):
        return self.normalize(kind, target, response)

    def capture_evidence(self, hub, case_id, kind, target, response, *, attestations):
        self._authorize()
        if not isinstance(hub, IntelligenceHub):
            raise PolicyError('Canonical IntelligenceHub required for evidence capture')
        hub._gate(case_id, self.adapter.spec, **attestations)
        records = self.normalize(kind, target, response)
        return hub._store(case_id, self.adapter.spec, records,
                          mode='fabric:fixture' if self.adapter.fixture else 'fabric:live',
                          target_fingerprint=hashlib.sha256(json.dumps([self.adapter.source, kind, target]).encode()).hexdigest())

    def replay(self, kind, target, raw, expected_sha256):
        """Recompute provider normalization from captured bytes, without a network call."""
        if not isinstance(raw, bytes) or len(raw) > self.max_bytes:
            raise PolicyError('Bounded replay bytes required')
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected_sha256:
            raise PolicyError('Replay evidence digest mismatch')
        data = RESTConnector.decode_payload(raw)
        _validate_shape(self.adapter.source, data)
        result = ProviderResult(data, 0, len(raw), digest, raw)
        return {'observations': self.normalize(kind, target, result),
                'source_id': self.adapter.source, 'sha256': digest,
                'connector_version': self.adapter.definition['contract']['contract_version'],
                'network_attempts': 0, 'live_verification': False}

    def close(self):
        self.adapter.close()

    @classmethod
    def decode_payload(cls, raw):
        if not isinstance(raw, bytes) or len(raw) > cls.max_bytes:
            raise PolicyError('Payload must be bytes within the primitive size limit')
        value = json.loads(raw)
        if not isinstance(value, (list, dict)):
            raise PolicyError('Object or array payload required')
        return value


class RESTConnector(BaseConnector):
    protocol = 'REST'


class GraphQLConnector(BaseConnector):
    protocol = 'GRAPHQL'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, dict) or value.get('errors') or not isinstance(value.get('data'), dict):
            raise PolicyError('GraphQL response contains errors or missing data')
        return value['data']


class RSSConnector(BaseConnector):
    protocol = 'RSS'

    @classmethod
    def decode_payload(cls, raw):
        if not isinstance(raw, bytes) or len(raw) > cls.max_bytes:
            raise PolicyError('Bounded RSS payload required')
        # Reject DTD/entity expansion even when encoded with UTF-16/UTF-32.
        if b'<!doctype' in raw.lower().replace(b'\x00', b'') or b'<!entity' in raw.lower().replace(b'\x00', b''):
            raise PolicyError('RSS DTD and entities are forbidden')
        root = ElementTree.fromstring(raw)
        namespace = '{http://www.w3.org/2005/Atom}'
        if root.tag not in {'rss', namespace + 'feed'}:
            raise PolicyError('RSS or Atom root required')
        entries = root.findall('./channel/item') if root.tag == 'rss' else root.findall(namespace + 'entry')
        if len(entries) > 5000:
            raise PolicyError('RSS entry limit exceeded')
        return [{'title': e.findtext('title') or e.findtext(namespace+'title'),
                 'url': e.findtext('link') or next((l.get('href') for l in e.findall(namespace+'link') if l.get('rel', 'alternate') == 'alternate'), None),
                 'published': e.findtext('pubDate') or e.findtext(namespace+'published'),
                 'source_assertion': True} for e in entries]


class STIXConnector(BaseConnector):
    protocol = 'STIX'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, dict) or value.get('type') != 'bundle' or not isinstance(value.get('objects'), list):
            raise PolicyError('STIX bundle required')
        return value['objects']


class TAXIIConnector(BaseConnector):
    protocol = 'TAXII'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, dict) or not isinstance(value.get('objects'), list):
            raise PolicyError('TAXII objects envelope required')
        return {'objects': value['objects'], 'more': value.get('more'), 'next': value.get('next')}


class MISPConnector(BaseConnector):
    protocol = 'MISP'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, dict) or not isinstance(value.get('Event'), dict):
            raise PolicyError('MISP Event envelope required')
        return value['Event']


class RDAPConnector(BaseConnector):
    protocol = 'RDAP'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, dict) or not isinstance(value.get('objectClassName'), str):
            raise PolicyError('RDAP object class required')
        return value


class DNSConnector(BaseConnector):
    protocol = 'DNS_JSON'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, dict) or type(value.get('Status')) is not int:
            raise PolicyError('DNS JSON status required')
        return value


class SearchConnector(BaseConnector):
    protocol = 'SEARCH'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, dict) or not isinstance(value.get('results'), list):
            raise PolicyError('Search results envelope required')
        return value['results']


class ArchiveConnector(BaseConnector):
    protocol = 'ARCHIVE_CDX'

    @classmethod
    def decode_payload(cls, raw):
        value = super().decode_payload(raw)
        if not isinstance(value, list) or any(not isinstance(row, list) for row in value):
            raise PolicyError('CDX rows required')
        if not value:
            return []
        header, *rows = value
        if any(not isinstance(key, str) for key in header) or any(len(row) != len(header) for row in rows):
            raise PolicyError('CDX column mismatch')
        return [dict(zip(header, row)) for row in rows]


class DatasetConnector(BaseConnector):
    protocol = 'DATASET_JSON'


class FileFeedConnector(BaseConnector):
    protocol = 'FILE_FEED'

    @classmethod
    def decode_payload(cls, raw, *, format='jsonl'):
        if not isinstance(raw, bytes) or len(raw) > cls.max_bytes:
            raise PolicyError('Bounded file feed required')
        text = raw.decode('utf-8')
        if format == 'jsonl':
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        elif format in {'csv', 'tsv'}:
            rows = list(csv.DictReader(io.StringIO(text), delimiter='\t' if format == 'tsv' else ','))
        else:
            raise PolicyError('Unsupported file feed format')
        if len(rows) > 5000 or any(not isinstance(row, dict) for row in rows):
            raise PolicyError('File feed requires at most 5000 object records')
        return rows


class WebhookConnector(BaseConnector):
    protocol = 'WEBHOOK'

    @classmethod
    def decode_payload(cls, raw, *, expected_sha256=None):
        if not expected_sha256 or not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise PolicyError('Webhook payload must resolve to previously authenticated preserved evidence')
        return super().decode_payload(raw)


class ConnectorFactory:
    primitives = {c.protocol: c for c in (RESTConnector, GraphQLConnector, RSSConnector, STIXConnector,
                  TAXIIConnector, MISPConnector, RDAPConnector, DNSConnector, SearchConnector,
                  ArchiveConnector, DatasetConnector, FileFeedConnector, WebhookConnector)}

    @staticmethod
    def create(source, **options):
        primitive = {'rdap': RDAPConnector, 'dns': DNSConnector, 'cloudflare_dns': DNSConnector,
                     'wayback': ArchiveConnector, 'urlscan': SearchConnector}.get(source, RESTConnector)
        return primitive(source, **options)
