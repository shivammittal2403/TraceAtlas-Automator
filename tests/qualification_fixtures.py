"""Synthetic receipts and database rows, never actual source qualifications."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from traceatlas.evidence import EvidenceStore
from traceatlas.source_fabric.review_receipts import review_template, RUNTIME_CHECKS, implementation_digest


def preserve(root, db, case_id, data, source='synthetic:qualification'):
    path = Path(root) / ('fixture-' + uuid4().hex + '.json')
    path.write_text(json.dumps(data), encoding='utf-8')
    return EvidenceStore(Path(root), db, case_id).preserve_file(path, source)['sha256']


def make_execution(root, db, source, case_id, identifier='synthetic-execution', runtime='synthetic-runtime'):
    raw_hash = preserve(root, db, case_id, {'synthetic_response': source})
    path = Path(next(r['path'] for r in db.evidence(case_id) if r['sha256'] == raw_hash))
    size = path.stat().st_size
    outcome = {'source': source, 'execution_id': identifier, 'raw_evidence_refs': [raw_hash],
        'implementation_sha256': implementation_digest(source), 'runtime_id': runtime,
        'provider': {'source': source, 'fixture': False, 'response_sha256': raw_hash, 'response_bytes': size}}
    db.conn.execute("""INSERT INTO fabric_executions
        (id,source,case_id,request_hash,authority_hash,status,mode,started_at,attempts,bytes,evidence_json)
        VALUES(?,?,?,?,?,'completed','live',?,1,?,?)""",
        (identifier, source, case_id, 'a' * 64, 'b' * 64,
         datetime.now(timezone.utc).isoformat(), size, json.dumps(outcome)))
    db.conn.commit()
    return identifier, raw_hash


def make_receipt(root, db, source, check, case_id, actor='analyst', runtime='synthetic-runtime',
                 execution=None, supporting=None, **changes):
    if check in RUNTIME_CHECKS and execution is None:
        identifier = 'synthetic-' + source + '-' + case_id
        if db.conn.execute('SELECT 1 FROM fabric_executions WHERE id=?', (identifier,)).fetchone() is None:
            execution = make_execution(root, db, source, case_id, identifier, runtime)
        else:
            row = db.conn.execute('SELECT evidence_json FROM fabric_executions WHERE id=?', (identifier,)).fetchone()
            execution = identifier, json.loads(row[0])['raw_evidence_refs'][0]
    if supporting is None:
        supporting = [execution[1]] if execution else [preserve(root, db, case_id, {'synthetic_check': check})]
    now = datetime.now(timezone.utc)
    receipt = review_template(source, check, case_id, actor, runtime)
    receipt.update(reviewed_at=now.isoformat(), expires_at=(now + timedelta(days=2)).isoformat(),
                   outcome='PASS', method='Synthetic validation contract; no source review performed.',
                   supporting_evidence_hashes=supporting, execution_id=execution[0] if execution else None)
    receipt.update(changes)
    return preserve(root, db, case_id, receipt), receipt
