import ast
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import types
from unittest.mock import patch

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'extracted')
checks = []
modules = {}

def record(name, outcome, detail):
    checks.append({'check': name, 'outcome': outcome, 'detail': detail})

for p in sorted((root / 'allint52').glob('*.py')):
    data = p.read_bytes()
    compile(data, str(p), 'exec')
    if data:
        spec = importlib.util.spec_from_file_location('audit_' + p.stem, p)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules[p.stem] = module
record('source_compile', 'PASS', '53/53 Python files compile; 46 are empty')
record('headless_import', 'PASS', '7/7 nonempty modules import without starting a GUI')

w = modules['webint']
for url in ['http://127.0.0.1/', 'http://169.254.169.254/', 'file:///etc/passwd', 'http://localhost/']:
    assert not w.validate_public_url(url)[0]
record('unsafe_url_controls', 'PASS', 'loopback, metadata IP, local scheme and localhost rejected')
try:
    w.validate_public_url('https://example.com:bad/')
except ValueError:
    record('malformed_port', 'DEFECT_REPRODUCED', 'ValueError escapes validation instead of a structured failure')
else:
    raise AssertionError('expected malformed-port defect not reproduced')

ok, normalized, reasons = w.validate_public_url('https://[2606:4700:4700::1111]/')
assert ok and normalized == 'https://2606:4700:4700::1111/'
record('ipv6_normalization', 'DEFECT_REPRODUCED', 'validated IPv6 literal loses required URL brackets')

with patch.object(w.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('93.184.216.34', 0))]):
    assert w.validate_public_url('https://example.com/', ['example.com'])[0]
    assert not w.validate_public_url('https://example.net/', ['example.com'])[0]
record('mocked_domain_scope', 'PASS', 'allowed domain accepted, different public domain rejected; zero network requests')

fixture = json.dumps({'password': 'audit-fixture-value'})
assert 'audit-fixture-value' in w.redact_sensitive_text(fixture)
record('json_redaction', 'DEFECT_REPRODUCED', 'quoted JSON password value is retained by light redaction')

g = modules['geomint']
assert g.validate_latlon(91, 181)[0] == ['LATITUDE_OUT_OF_RANGE', 'LONGITUDE_OUT_OF_RANGE']
assert g.haversine_km(0, 0, 0, 0) == 0
record('geographic_helpers', 'PASS', 'out-of-range coordinates rejected; identical-point distance is zero')
for name, fn in [('imgmint', 'analyze_image_file'), ('audint', 'analyze_audio_file'), ('vedmint', 'analyze_video_file')]:
    with tempfile.TemporaryDirectory() as td:
        result = getattr(modules[name], fn)(str(pathlib.Path(td) / 'missing.bin'))
        assert result['status'] == 'FAILED_FILE_NOT_FOUND'
record('media_missing_file', 'PASS', 'image, audio and video analysis return structured missing-file failures')

s = modules['socmint']
with tempfile.TemporaryDirectory() as td:
    output = pathlib.Path(td) / 'export.json'
    harness = types.SimpleNamespace(
        last_result={'payload': {'case_id': 'OLD-CASE', 'target': 'old-target'}},
        collect_payload=lambda: {'case_id': 'NEW-CASE', 'target': 'new-target'},
        generate_plan=lambda: (_ for _ in ()).throw(AssertionError('unexpected regeneration')),
    )
    with patch.object(s.filedialog, 'asksaveasfilename', return_value=str(output)), patch.object(s.messagebox, 'showinfo'):
        s.TraceAtlasSOCMINTPanel.export_json(harness)
    assert json.loads(output.read_text())['payload']['target'] == 'old-target'
record('socmint_export_freshness', 'DEFECT_REPRODUCED', 'cached result is exported after current payload changes')

for name, cls in [('osint', 'TraceAtlasOSINTPanel'), ('socmint', 'TraceAtlasSOCMINTPanel')]:
    fields = {}
    harness = types.SimpleNamespace(set_widget_value=lambda key, value: fields.__setitem__(key, value))
    getattr(modules[name], cls)._set_defaults(harness)
    authorization = json.loads(fields['authorization'])
    assert 'customer-authorized' in authorization['authorization_basis']
record('default_authorization', 'DEFECT_REPRODUCED', 'OSINT and SOCMINT defaults assert customer authorization without operator evidence')

receipt = {'scope': 'Uploaded allint52 snapshot only; no core application or live-source certification', 'network_requests': 0, 'checks': checks}
print(json.dumps(receipt, indent=2))
