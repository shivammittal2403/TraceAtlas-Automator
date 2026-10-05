"""Official public metadata contracts; controlled fixtures are not live receipts."""
import hashlib
import json
import unittest

from traceatlas.intelligence.public_metadata import build_request, normalize, validate_shape
from traceatlas.intelligence.provider import ProviderError
from traceatlas.policy import PolicyError
from traceatlas.source_fabric.primitives import ConnectorFactory
from traceatlas.source_fabric.registry import manifest


PAYLOADS = {
    'pypi': ('package', 'pypi:Sample_Project', {'info': {'name': 'sample-project', 'version': '1.0',
        'author_email': 'private@example.org', 'description': 'untrusted instructions',
        'license_expression': 'MIT'}, 'urls': [{'filename': 'sample_project-1.whl',
        'digests': {'sha256': 'a'*64}, 'url': 'https://untrusted.example/file.whl'}]}),
    'datacite': ('doi', '10.1234/example', {'data': {'id': '10.1234/example', 'type': 'dois',
        'attributes': {'doi': '10.1234/example', 'titles': [{'title': 'Controlled publication'}],
        'publicationYear': 2025, 'creators': [{'name': 'Private Person'}]}}}),
}


class PublicMetadataTests(unittest.TestCase):
    def test_official_exact_endpoints_and_fixed_origins(self):
        self.assertEqual(build_request('pypi', 'package', 'pypi:Sample_Project'),
                         'https://pypi.org/pypi/sample-project/json')
        self.assertEqual(build_request('datacite', 'doi', '10.1234/example'),
                         'https://api.datacite.org/dois/10.1234%2Fexample')
        for source in PAYLOADS:
            self.assertTrue(manifest(source)['execution_path'])
            self.assertTrue(manifest(source)['documentation_url'].startswith('https://'))

    def test_invalid_inputs_never_become_urls(self):
        for target in ('../secret', 'https://attacker.example', '@scope/pkg', 'a?token=x', 'foo\n',
                       'sampleproject', 'pypi:../secret', 'pypi:foo?key=x'):
            with self.assertRaises(PolicyError):
                build_request('pypi', 'package', target)
        for target in ('10.1234/x?key=secret', 'https://doi.org/10.1234/x', '../x'):
            with self.assertRaises(PolicyError):
                build_request('datacite', 'doi', target)

    def test_provider_shapes_and_exact_target_matching(self):
        for source, (kind, target, payload) in PAYLOADS.items():
            validate_shape(source, payload)
            with self.assertRaises(ProviderError):
                validate_shape(source, {})
            other = 'pypi:another-project' if source == 'pypi' else '10.1234/different'
            with self.assertRaisesRegex(ProviderError, 'provider_target_mismatch'):
                normalize(source, kind, other, payload)

    def test_privacy_minimization_and_no_file_fetch(self):
        for source, (kind, target, payload) in PAYLOADS.items():
            calls = []
            def requester(url, headers, timeout):
                calls.append(url)
                return 200, json.dumps(payload).encode()
            connector = ConnectorFactory.create(source, requester=requester, authorization_check=lambda: None)
            result = connector.fetch(kind, target)
            records = connector.normalize(kind, target, result)
            serialized = json.dumps(records)
            for excluded in ('private@example.org', 'Private Person', 'untrusted instructions', 'untrusted.example'):
                self.assertNotIn(excluded, serialized)
            self.assertEqual(len(calls), 1)
            self.assertTrue(records[0]['source_assertion'])
            replay = connector.replay(kind, target, result.raw, hashlib.sha256(result.raw).hexdigest())
            self.assertEqual(replay['observations'], records)
            self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
