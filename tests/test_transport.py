import socket
import unittest
from unittest.mock import Mock, patch

from traceatlas.intelligence.transport import request, MAX_BYTES
from traceatlas.intelligence.provider import ProviderError, ResilientJSONClient


class TransportTests(unittest.TestCase):
    def test_unapproved_origins_and_private_dns_never_connect(self):
        for url in ['http://api.github.com/users/a', 'https://127.0.0.1/',
                    'https://api.github.com.evil.example/', 'https://user@api.github.com/',
                    'https://api.github.com:444/', 'https://api.github.com/#fragment']:
            with self.subTest(url=url), patch('socket.create_connection') as connect:
                with self.assertRaisesRegex(ProviderError, 'destination_rejected'):
                    request(url, {}, 1)
                connect.assert_not_called()
        for ip in ['127.0.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1']:
            with patch('socket.getaddrinfo', return_value=[(2,1,6,'',('8.8.8.8',443)), (2,1,6,'',(ip,443))]), \
                 patch('socket.create_connection') as connect:
                with self.assertRaisesRegex(ProviderError, 'destination_rejected'):
                    request('https://api.github.com/users/a', {}, 1)
                connect.assert_not_called()

    def response(self, status=200, headers=None, body=b'{"login":"fixture"}'):
        response = Mock(status=status)
        metadata = {'Content-Type': 'application/json', **(headers or {})}
        response.getheader.side_effect = lambda k, default=None: metadata.get(k, default)
        response.read.return_value = body
        return response

    def invoke(self, response):
        with patch('traceatlas.intelligence.transport._resolve', return_value='8.8.8.8'), \
             patch('socket.create_connection') as connect, \
             patch('ssl.create_default_context') as context, \
             patch('http.client.HTTPSConnection') as connection:
            connection.return_value.getresponse.return_value = response
            try:
                return request('https://api.github.com/users/fixture', {'Host': 'evil.example'}, 2)
            finally:
                self.assertEqual(connect.call_args.args[0], ('8.8.8.8', 443))
                self.assertEqual(context.return_value.wrap_socket.call_args.kwargs['server_hostname'], 'api.github.com')
                sent = connection.return_value.request.call_args.kwargs['headers']
                self.assertNotIn('Host', sent)
                self.assertEqual(sent['Accept-Encoding'], 'identity')
                connection.return_value.close.assert_called_once()

    def test_pinned_https_no_redirect_no_compression_and_bounded_body(self):
        self.assertEqual(self.invoke(self.response())[0], 200)
        for response, code in [
            (self.response(302, {'Location':'https://evil.example/'}), 'redirect_rejected'),
            (self.response(headers={'Content-Encoding':'gzip'}), 'encoding_rejected'),
            (self.response(headers={'Content-Type':'text/html'}), 'content_type_rejected'),
            (self.response(headers={'Content-Length':str(MAX_BYTES+1)}), 'response_too_large'),
            (self.response(body=b'x'*(MAX_BYTES+1)), 'response_too_large'),
        ]:
            with self.subTest(code=code), self.assertRaisesRegex(ProviderError, code):
                self.invoke(response)
        self.assertEqual(self.invoke(self.response(429)), (429, b''))

    def test_retry_budget_is_shared_and_late_success_is_rejected(self):
        now = [0.0]
        timeouts = []
        def requester(url, headers, timeout):
            timeouts.append(timeout)
            now[0] += 0.6
            return 503, b''
        def sleep(seconds):
            now[0] += seconds
        client = ResilientJSONClient(requester, sleeper=sleep, clock=lambda: now[0])
        with self.assertRaisesRegex(ProviderError, 'deadline_exceeded'):
            client.get('github', 'unused', {}, 1)
        self.assertEqual(len(timeouts), 2)
        self.assertLess(timeouts[1], 0.2)
        def late(*args):
            now[0] += 2
            return 200, b'{"login":"fixture"}'
        client = ResilientJSONClient(late, clock=lambda: now[0])
        with self.assertRaisesRegex(ProviderError, 'deadline_exceeded'):
            client.get('github', 'unused', {}, 1)


if __name__ == '__main__':
    unittest.main()
