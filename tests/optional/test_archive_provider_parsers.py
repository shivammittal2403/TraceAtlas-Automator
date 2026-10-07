"""Optional client parser fixtures; no external requests or live qualification."""
import unittest

from traceatlas.addons.osint_v1.search_discovery.providers.duckduckgo import _decode_href


class ArchiveProviderParserTests(unittest.TestCase):
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
