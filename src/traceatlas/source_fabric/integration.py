"""Explicit source-specific live integration receipts in canonical case custody.

A receipt records transport/normalization/capture checks, not legal review,
independent provider authenticity or production qualification.
"""
import hashlib
import json
import platform
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..employee.brief import digest
from ..evidence import EvidenceStore
from ..policy import PolicyError
from .registry import SOURCES, manifest
from .store import FabricStore, utc


def implementation_digest(source):
    root = Path(__file__).resolve().parents[1]
    paths = ('intelligence/hub.py', 'intelligence/provider.py', 'intelligence/transport.py',
             'intelligence/rdap.py', 'intelligence/registry_requests.py', 'intelligence/public_metadata.py',
             'source_fabric/sdk.py', 'source_fabric/primitives.py', 'source_fabric/gateway.py')
    return digest({'manifest': manifest(source),
                   'code': {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths}})


class IntegrationReceipts:
    validity_days = 30

    def __init__(self, db, workspace=None):
        self.db = db
        self.workspace = Path(workspace) if workspace is not None else db.path.parent
        FabricStore(db)
        db.conn.execute('''CREATE TABLE IF NOT EXISTS fabric_integration_receipts (
            source TEXT NOT NULL, execution_id TEXT NOT NULL, case_id TEXT NOT NULL,
            evidence_hash TEXT NOT NULL, implementation_hash TEXT NOT NULL,
            actor TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(source,execution_id))''')
        db.conn.commit()

    def _execution(self, source, execution_id, case_id):
        row = self.db.conn.execute('SELECT * FROM fabric_executions WHERE id=? AND source=? AND case_id=?',
                                   (execution_id, source, case_id)).fetchone()
        if not row or row['status'] != 'completed' or row['mode'] != 'live' or row['cache_hit'] or row['drift']:
            raise PolicyError('Successful non-fixture, non-cache integration execution required')
        if row['attempts'] < 1 or row['bytes'] < 1:
            raise PolicyError('Measured network response required')
        try:
            stamp = datetime.fromisoformat(row['started_at'])
            age = (datetime.now(timezone.utc) - stamp).total_seconds()
            if not 0 <= age <= self.validity_days * 86400:
                raise PolicyError('Integration execution is stale')
            outcome = json.loads(row['evidence_json'])
            provider = outcome['provider']
            refs = outcome['evidence_refs']
            if (provider['fixture'] is not False or provider['source'] != source or
                not re.fullmatch(r'[a-f0-9]{64}', provider['response_sha256']) or
                outcome['stats']['records_stored'] < 1 or not refs or
                outcome['execution_id'] != execution_id or outcome['source'] != source):
                raise PolicyError('Integration provenance or normalized records are incomplete')
        except (KeyError, ValueError, TypeError) as exc:
            raise PolicyError('Integration execution metadata is invalid') from exc
        store = EvidenceStore(self.workspace, self.db, case_id)
        hashes = {e['sha256'] for e in self.db.evidence(case_id)}
        if not store.verify_ledger()[0] or any(ref not in hashes for ref in refs):
            raise PolicyError('Integration evidence does not resolve in canonical case custody')
        return dict(row), outcome

    def record(self, source, execution_id, case_id, actor, *, authorized=False):
        if not authorized or source not in SOURCES or not isinstance(actor, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{2,80}', actor):
            raise PolicyError('Explicit integration-test operator authority required')
        row, outcome = self._execution(source, execution_id, case_id)
        receipt = {'schema': 'traceatlas.source-integration/v1', 'source': source,
            'execution_id': execution_id, 'case_id': case_id, 'actor': actor,
            'at': utc(), 'implementation_hash': implementation_digest(source),
            'execution_hash': digest(row), 'normalized_evidence_refs': outcome['evidence_refs'],
            'checks': ['non-fixture-transport', 'provider-schema', 'exact-target-normalization',
                       'normalized-records-captured', 'response-digest', 'same-case-custody'],
            'scope': 'one exact public lookup in the observed local runtime',
            'observed_runtime': {'os': platform.system(), 'python': platform.python_version(),
                                 'implementation': platform.python_implementation()},
            'live_verified': False, 'production_qualified': False, 'raw_replay_verified': False}
        with tempfile.TemporaryDirectory(prefix='traceatlas-integration-') as temporary:
            path = Path(temporary) / 'source-integration-receipt.json'
            path.write_text(json.dumps(receipt, sort_keys=True), encoding='utf-8')
            evidence = EvidenceStore(self.workspace, self.db, case_id).preserve_file(path, 'source-integration:' + source)
        with self.db.conn:
            self.db.conn.execute('''INSERT INTO fabric_integration_receipts VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(source,execution_id) DO UPDATE SET evidence_hash=excluded.evidence_hash,
                implementation_hash=excluded.implementation_hash,actor=excluded.actor,at=excluded.at''',
                (source, execution_id, case_id, evidence['sha256'], receipt['implementation_hash'], actor, receipt['at']))
        return {**receipt, 'receipt_evidence_hash': evidence['sha256'], 'maturity_promoted': False}

    def verified(self):
        """Revalidate receipts against current code, executions and preserved bytes."""
        results = []
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.validity_days)).isoformat()
        for record in self.db.conn.execute('SELECT * FROM fabric_integration_receipts WHERE at>?', (cutoff,)):
            try:
                if record['source'] not in SOURCES or record['implementation_hash'] != implementation_digest(record['source']):
                    continue
                row, outcome = self._execution(record['source'], record['execution_id'], record['case_id'])
                artifact = next(e for e in self.db.evidence(record['case_id']) if e['sha256'] == record['evidence_hash'])
                path = Path(artifact['path'])
                if path.stat().st_size > 64000:
                    continue
                receipt = json.loads(path.read_text(encoding='utf-8'))
                if (receipt.get('schema') != 'traceatlas.source-integration/v1' or
                    receipt.get('source') != record['source'] or receipt.get('case_id') != record['case_id'] or
                    receipt.get('execution_id') != record['execution_id'] or receipt.get('actor') != record['actor'] or
                    receipt.get('implementation_hash') != record['implementation_hash'] or
                    receipt.get('execution_hash') != digest(row) or
                    receipt.get('normalized_evidence_refs') != outcome['evidence_refs']):
                    continue
                results.append(dict(record))
            except (PolicyError, OSError, ValueError, TypeError, KeyError, StopIteration):
                continue
        return results
