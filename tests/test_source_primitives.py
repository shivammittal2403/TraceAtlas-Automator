import hashlib
import json
import unittest

from traceatlas.policy import PolicyError
from traceatlas.source_fabric.primitives import (
    ConnectorFactory, GraphQLConnector, RSSConnector, STIXConnector, TAXIIConnector,
    MISPConnector, RDAPConnector, DNSConnector, SearchConnector, ArchiveConnector,
    FileFeedConnector, WebhookConnector,
)


class PrimitiveTests(unittest.TestCase):
    def test_complete_connector_contract(self):
        connector = ConnectorFactory.create('dns')
        for name in ('manifest', 'capabilities', 'validate_config', 'health', 'estimate_cost',
                     'rate_limit_status', 'search', 'fetch', 'normalize', 'extract_observations',
                     'capture_evidence', 'replay', 'close'):
            self.assertTrue(callable(getattr(connector, name)))
        self.assertEqual(connector.manifest()['primitive'], 'DNS_JSON')
        self.assertFalse(connector.adapter.fixture)

    def test_protocols_decode_real_envelopes(self):
        cases = [(GraphQLConnector, {'data': {'name': 'a'}}, {'name': 'a'}),
                 (STIXConnector, {'type': 'bundle', 'objects': [{'type': 'indicator'}]}, [{'type': 'indicator'}]),
                 (TAXIIConnector, {'objects': [], 'more': True, 'next': 'cursor'}, {'objects': [], 'more': True, 'next': 'cursor'}),
                 (MISPConnector, {'Event': {'info': 'synthetic'}}, {'info': 'synthetic'}),
                 (RDAPConnector, {'objectClassName': 'domain'}, {'objectClassName': 'domain'}),
                 (DNSConnector, {'Status': 0}, {'Status': 0}),
                 (SearchConnector, {'results': []}, []),
                 (ArchiveConnector, [['timestamp', 'original'], ['20250101', 'https://example.org']],
                  [{'timestamp': '20250101', 'original': 'https://example.org'}])]
        for cls, payload, expected in cases:
            with self.subTest(protocol=cls.protocol):
                self.assertEqual(cls.decode_payload(json.dumps(payload).encode()), expected)
                with self.assertRaises(PolicyError):
                    cls.decode_payload(b'{}')

    def test_rss_and_atom_and_xml_entity_rejection(self):
        rss = b'<rss><channel><item><title>Example</title><link>https://example.org</link></item></channel></rss>'
        self.assertEqual(RSSConnector.decode_payload(rss)[0]['title'], 'Example')
        atom = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Example</title><link href="https://example.org"/></entry></feed>'
        self.assertEqual(RSSConnector.decode_payload(atom)[0]['url'], 'https://example.org')
        for raw in (b'<!DOCTYPE rss [<!ENTITY a "x">]><rss/>', '<!DOCTYPE rss><rss/>'.encode('utf-16')):
            with self.assertRaises(PolicyError):
                RSSConnector.decode_payload(raw)

    def test_files_and_webhooks_do_not_authenticate_from_metadata(self):
        self.assertEqual(FileFeedConnector.decode_payload(b'{"id":1}\n'), [{'id': 1}])
        self.assertEqual(FileFeedConnector.decode_payload(b'id,title\n1,Example\n', format='csv'), [{'id': '1', 'title': 'Example'}])
        with self.assertRaises(PolicyError):
            WebhookConnector.decode_payload(b'{}')
        self.assertEqual(WebhookConnector.decode_payload(b'{}', expected_sha256=hashlib.sha256(b'{}').hexdigest()), {})

    def test_missing_authority_blocks_before_transport(self):
        calls = []
        connector = ConnectorFactory.create('dns', requester=lambda *args: calls.append(args))
        with self.assertRaises(PolicyError):
            connector.fetch('domain', 'example.org')
        self.assertEqual(calls, [])

    def test_replay_checks_hash_and_never_calls_transport(self):
        calls = []
        connector = ConnectorFactory.create('dns', requester=lambda *args: calls.append(args))
        raw = b'{"Status":0,"Answer":[{"name":"example.org.","type":1,"TTL":100,"data":"93.184.216.34"}]}'
        with self.assertRaises(PolicyError):
            connector.replay('domain', 'example.org', raw, '0'*64)
        replay = connector.replay('domain', 'example.org', raw, hashlib.sha256(raw).hexdigest())
        self.assertEqual(replay['network_attempts'], 0)
        self.assertFalse(replay['live_verification'])
        self.assertTrue(replay['observations'])
        self.assertEqual(calls, [])

    def test_authority_is_rechecked_before_a_retry(self):
        calls, checks = [], []
        def authorize():
            checks.append(1)
            if len(checks) >= 3:
                raise PolicyError('Authority revoked during request')
        def requester(*args):
            calls.append(args)
            return 503, b'{}'
        connector = ConnectorFactory.create('dns', requester=requester, authorization_check=authorize)
        connector.adapter.client.sleeper = lambda _: None
        with self.assertRaises(PolicyError):
            connector.fetch('domain', 'example.org')
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
