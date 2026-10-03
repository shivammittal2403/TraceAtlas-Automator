"""Sixty deterministic gateway investigations with explicit expected outcomes."""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from ..db import CaseDB
from .contracts import AuthorizationContext
from .pipeline import InvestigationPipeline
from .service import WorkforceService
from .source_registry import SourceRegistry


def evaluate_source_fabric():
    fixture = json.loads(files('traceatlas.workforce.data').joinpath('source_golden.json').read_text())
    results = []
    environment = {key: 'fixture-value-no-live-credentials' for item in SourceRegistry().list() for key in item.credential_refs}
    environment.update(SEC_USER_AGENT='Fixture contact@example.org', SEARXNG_URL='http://127.0.0.1:8123',
                       TRACEATLAS_WORKFORCE_KILL_SWITCH='', TRACEATLAS_SEARCH_PROVIDER='')
    # Fixture-only environment lives inside this bounded command, never operator config.
    with patch.dict(os.environ, environment), tempfile.TemporaryDirectory(prefix='traceatlas-source-golden-') as temporary:
        for source, (kind, target, payload) in fixture['fixtures'].items():
            for scenario in ('success', 'authentication_failure', 'schema_drift'):
                name = source + '-' + scenario
                workspace = Path(temporary) / name; workspace.mkdir()
                db = CaseDB(workspace / 'case.db')
                try:
                    db.create_case('golden-case', name, 'Synthetic source qualification')
                    service = WorkforceService(db, enabled=True)
                    stamp = datetime.now(timezone.utc)
                    authority = AuthorizationContext('1.0', 'golden-auth', 'golden-case', 'fixture-analyst', 'Controlled source tests',
                        (kind + ':' + target,), ('request_collection', 'propose_observation', 'propose_claim'),
                        ('dns.lookup', 'rdap.lookup', 'archive.lookup', 'ip.lookup', 'search.execute', 'registry.lookup', 'evidence.retrieve'),
                        'TEST', 'test-only', stamp.isoformat(), (stamp + timedelta(hours=1)).isoformat(), 'c' * 64)
                    service.register_authorization(authority)
                    planned = service.create_investigation_task('golden-auth', kind, target, 'Verify controlled source evidence', sources=[source], source_prices={source: 0})
                    task = planned['task']['task_id']
                    service.approve(task, actor_id='fixture-analyst', rationale='Approved exact fixture plan', envelope_digest=planned['envelope_digest'], authorized=True)
                    def request(url, *_):
                        if scenario == 'authentication_failure': return 401, b''
                        if scenario == 'schema_drift': return 200, b'{"changed_api":true}'
                        return 200, json.dumps(fixture['bootstrap'] if urlsplit(url).hostname == 'data.iana.org' else payload).encode()
                    runner = InvestigationPipeline(service, workspace, requester=request, search_requester=request)
                    product = runner.run(task, live=True, authorized=True)
                    replay = runner.replay(task)['verified']
                    observed = len(product['analysis']['observations'])
                    passed = replay and (observed > 0 if scenario == 'success' else observed == 0 and product['state'] == 'PARTIAL')
                    results.append({'case': name, 'passed': passed, 'expected': scenario, 'observations': observed,
                        'replay': replay, 'evidence': len(product['replay_manifest']['evidence']), 'network_attempts': product['network_attempts'],
                        'unsupported_released_claims': product['analysis']['metrics']['unsupported_material_claims_released']})
                finally:
                    db.close()
    return {'schema': 'traceatlas-source-golden-result/v1', 'mode': 'controlled-fixtures', 'production_qualification': False,
            'cases': results, 'total': len(results), 'passed': sum(r['passed'] for r in results),
            'replay_success_rate': sum(r['replay'] for r in results) / len(results)}
