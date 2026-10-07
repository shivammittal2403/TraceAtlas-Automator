from __future__ import annotations

import http.client
import io
import json
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from traceatlas.employee.console import make_server


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.server = make_server(Path(self.temp.name), 0, enabled=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.token = self.request('GET', '/api/session')[1]['csrf_token']

    def stop(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        values = {'Content-Type': 'application/json', 'X-TraceAtlas-CSRF': getattr(self, 'token', '')}
        values.update(headers or {})
        connection.request(method, path, None if body is None else json.dumps(body), values)
        response = connection.getresponse()
        raw = response.read()
        result = json.loads(raw) if response.getheader('Content-Type') == 'application/json' else raw
        status = response.status
        connection.close()
        return status, result

    def test_loopback_host_origin_csrf_and_static_page(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        status, page = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'Evidence graph', page)
        self.assertNotIn(b'innerHTML', page)
        self.assertEqual(self.request('GET', '/api/session', headers={'Host': 'evil.example'})[0], 400)
        self.assertEqual(self.request('GET', '/api/session', headers={'Origin': 'https://evil.example'})[0], 400)
        self.assertEqual(self.request('POST', '/api/cases', {}, {'X-TraceAtlas-CSRF': 'wrong'})[0], 403)
        self.assertEqual(self.request('POST', '/api/cases', {}, {'Origin': 'https://evil.example'})[0], 400)
        self.assertEqual(self.request('GET', '/api/cases')[1]['cases'], [])

    def test_duplicate_or_chunked_request_framing_cannot_write_case(self):
        for headers in ({'Content-Length': '1,2'}, {'Transfer-Encoding': 'chunked'}):
            connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
            try:
                connection.request('POST', '/api/cases', headers={'X-TraceAtlas-CSRF': self.token, **headers})
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                response.read()
            finally:
                connection.close()
        self.assertEqual(self.request('GET', '/api/cases')[1]['cases'], [])

    def test_console_rejects_filesystem_seeds_before_planning_or_probing(self):
        self.assertEqual(self.request('POST', '/api/cases', {'case_id': 'demo', 'title': 'Demo',
                            'purpose': 'Authorized fixture investigation'})[0], 201)
        body = {'case_id': 'demo', 'objective': 'Review submitted evidence', 'actor': 'analyst-1',
                'authorized': True, 'attestations': {'owned_asset': True}}
        with patch('traceatlas.employee.autonomous.AutonomousInvestigator.create') as create:
            for kind in ('file', 'path', 'unsupported'):
                status, result = self.request('POST', '/api/investigate',
                    {**body, 'seeds': [{'type': kind, 'value': '/etc/passwd'}]})
                self.assertEqual(status, 400)
            create.assert_not_called()

    def test_browser_api_case_to_evidence_zip(self):
        self.assertEqual(self.request('POST', '/api/cases', {'case_id': 'demo', 'title': 'Demo',
                            'purpose': 'Authorized fixture investigation'})[0], 201)
        self.assertEqual(len(self.request('GET', '/api/cases')[1]['cases']), 1)
        body = {'case_id': 'demo', 'objective': 'Review our DNS infrastructure', 'actor': 'analyst-1',
                'seeds': [{'type': 'domain', 'value': 'example.org'}], 'authorized': True,
                'attestations': {'owned_asset': True, 'public_record_basis': True}, 'max_actions': 1}
        with patch('traceatlas.intelligence.hub._request', return_value=(200, b'{"Status":0,"Answer":[{"type":1,"data":"1.1.1.1"}]}')) as network:
            status, selected = self.request('POST', '/api/investigate', body)
            self.assertEqual(status, 202)
            for _ in range(100):
                status, current = self.request('GET', '/api/investigation?case=demo&id=' + selected['investigation_id'])
                if current['status'] not in {'running', 'ready'}:
                    break
                time.sleep(.02)
            self.assertEqual(current['status'], 'partial')
            self.assertEqual(network.call_count, 1)
            self.assertEqual(len(current['report']['evidence']), 1)
        status, raw = self.request('POST', '/api/export', selected)
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertIn('report.json', archive.namelist())
            self.assertIn('replay.sha256', archive.namelist())
        self.assertEqual(self.request('GET', '/api/investigation?case=other&id=' + selected['investigation_id'])[0], 400)


if __name__ == '__main__':
    unittest.main()
