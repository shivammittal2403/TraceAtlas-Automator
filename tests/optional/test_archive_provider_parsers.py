"""Optional client parser fixtures; no external requests or live qualification."""
import unittest
import io
import tempfile
from pathlib import Path

from traceatlas.addons.osint_v1.search_discovery.providers.duckduckgo import _decode_href


class ArchiveProviderParserTests(unittest.TestCase):
    def test_optional_yaml_catalog_loads_without_import_shadowing(self):
        from traceatlas.addons.cute_v1.sources.registry import SourceRegistry
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'fixture.yaml').write_text(
                'sources:\n- slug: submitted-fixture\n  qualification: documented\n'
                '  capabilities: [fixture.lookup]\n', encoding='utf-8')
            registry = SourceRegistry.load_default(root)
            record = registry.get('submitted-fixture')
            self.assertIsNotNone(record)
            self.assertEqual(record.qualification, 'documented')
            self.assertEqual(record.capabilities, ('fixture.lookup',))

    def test_optional_yaml_parser_preserves_success_and_rejects_malformed_input(self):
        from traceatlas.addons.cute_v1.ingestion.parsers.generic_structured import YamlParser
        from traceatlas.addons.cute_v1.ingestion.limits import IngestionLimits
        parser = YamlParser()
        good = parser.parse(io.BytesIO(b'key: value\n'), artifact_id='fixture',
                            limits=IngestionLimits())
        self.assertTrue(good.ok, good.errors)
        bad = parser.parse(io.BytesIO(b'key: [unterminated\n'), artifact_id='fixture',
                           limits=IngestionLimits())
        self.assertFalse(bad.ok)
        self.assertTrue(bad.errors)

    def test_documented_wrapper_shape_and_protocol_relative_links(self):
        for prefix in ('https://duckduckgo.com', '//duckduckgo.com', 'https://html.duckduckgo.com'):
            with self.subTest(prefix=prefix):
                self.assertEqual(_decode_href(prefix + '/l/?uddg=https%3A%2F%2Fexample.org%2F'),
                                 'https://example.org/')

    def test_substring_hostname_and_userinfo_cannot_impersonate_wrapper(self):
        for prefix in ('https://duckduckgo.com.evil.test', 'https://evil-duckduckgo.com',
                       'https://duckduckgo.com@evil.test', 'https://user@duckduckgo.com',
                       'http://duckduckgo.com'):
            href = prefix + '/l/?uddg=https%3A%2F%2Fexample.org%2F'
            with self.subTest(prefix=prefix):
                self.assertEqual(_decode_href(href), href)


if __name__ == '__main__':
    unittest.main()
