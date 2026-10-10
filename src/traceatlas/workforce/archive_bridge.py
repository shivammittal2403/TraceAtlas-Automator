"""Case-bound offline archive integration; the canonical EvidenceStore owns bytes."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from uuid import NAMESPACE_URL, uuid5

from ..evidence import EvidenceStore, sha256_file
from ..models import Finding
from ..policy import PolicyError
from .archive_actions import ACTION_DETAILS, JSON_ACTIONS, detect_file

MAX_INPUT_BYTES = 2 * 1024 * 1024
SCHEMA = 'traceatlas.archive.analysis.v1'
CASE_ID = re.compile(r'^[A-Za-z0-9_-]{2,64}$')
SECRET_FIELDS = re.compile(r'^(?:password|passwd|secret|api_key|access_token|refresh_token|'
                           r'authorization|cookie|otp|seed_phrase|private_key)$', re.I)


def _safe_json(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise PolicyError('Duplicate JSON keys are not permitted')
            if SECRET_FIELDS.fullmatch(key):
                raise PolicyError('Routine secrets and embedded authority are not accepted')
            obj[key] = value
        return obj
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda x: (_ for _ in ()).throw(ValueError('non-finite JSON')))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PolicyError('A finite UTF-8 JSON action contract is required') from exc
    if not isinstance(value, dict):
        raise PolicyError('Action input must be one JSON object')
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 20 or count > 30000:
            raise PolicyError('Action input exceeds nesting/record limits')
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise PolicyError('Non-finite JSON values are not accepted')
    return value


def _read_file(path):
    path = Path(path)
    if path.is_symlink():
        raise PolicyError('Symbolic-link action inputs are not accepted')
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
                raise PolicyError('Input must be a regular file of at most 2 MiB')
            raw = handle.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise PolicyError('Input exceeds 2 MiB')
        return raw
    except OSError as exc:
        raise PolicyError('Action input could not be read safely') from exc


class ArchiveBridge:
    """No network, imported DB, API, model or policy engine is dispatched here."""
    def __init__(self, engine):
        self.engine = engine

    @staticmethod
    def catalog():
        return {'schema': 'traceatlas.archive.actions.v1', 'actions': [
            {'id': key, 'namespace': 'traceatlas.addons.' + family, 'description': description,
             'execution_mode': 'OFFLINE_CASE_INPUT', 'live_verified': False,
             'model_calls': 0, 'network_calls': 0}
            for key, (family, description) in ACTION_DETAILS.items()],
            'canonical_case_store': 'traceatlas.db.CaseDB',
            'canonical_evidence_store': 'traceatlas.evidence.EvidenceStore',
            'archived_scaffolds_are_integrations': False}

    def analyze(self, case_id, action, path, *, approved_inputs=False):
        if approved_inputs is not True:
            raise PolicyError('Explicit approval to process the submitted local file is required')
        if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id) or not self.engine.db.get_case(case_id):
            raise PolicyError('An existing canonical case is required')
        if action not in ACTION_DETAILS:
            raise PolicyError('Unknown or non-graduated archive action')
        raw = _read_file(path)
        digest = hashlib.sha256(raw).hexdigest()
        store = EvidenceStore(self.engine.workspace, self.engine.db, case_id)
        if not store.verify_ledger()[0]:
            raise PolicyError('Canonical case custody must verify before analysis')
        case_rows = {r['sha256']: r for r in self.engine.db.evidence(case_id)}
        # Reuse only same-case, byte-verified canonical rows. @input denotes the
        # exact new submission, not an independently corroborating source.
        for row in case_rows.values():
            captured = Path(row['path']).resolve()
            if not captured.is_relative_to(store.root.resolve()) or sha256_file(captured) != row['sha256']:
                raise PolicyError('Canonical evidence path or bytes failed validation')
        evidence = {**case_rows, digest: {'sha256': digest, 'source': 'Submitted action input'}}
        try:
            if action == 'detect-file':
                result = detect_file(raw, Path(path).name)
            else:
                result = JSON_ACTIONS[action](_safe_json(raw), evidence, digest, case_id)
        except PolicyError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise PolicyError('Invalid archive action input; no evidence was added') from exc
        value = {'schema': SCHEMA, 'case_id': case_id, 'action': action,
                 'adapter_version': '1.0', 'namespace': ACTION_DETAILS[action][0],
                 'input_sha256': digest, 'evidence_ids': [digest],
                 'semantic_class': 'ANALYSIS_DRAFT', 'requires_human_review': True,
                 'authority_granted': False, 'network_calls': 0, 'model_calls': 0,
                 'result': result}
        # Verify serialisability and finite output before any custody writes.
        try:
            encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise PolicyError('Archive action produced an invalid output contract') from exc
        if len(encoded.encode('utf-8')) > 4 * MAX_INPUT_BYTES:
            raise PolicyError('Archive output exceeds the bounded report limit')
        if digest not in case_rows:
            # Snapshot the already validated bytes. Source-file races cannot
            # substitute different bytes between analysis and preservation.
            with tempfile.TemporaryDirectory(prefix='traceatlas-archive-input-') as temporary:
                snapshot = Path(temporary) / ('input' + Path(path).suffix[:12])
                snapshot.write_bytes(raw)
                record = store.preserve_file(snapshot, f'archive:{action}:submitted')
                if record['sha256'] != digest:
                    raise PolicyError('Analysis and preserved input differ')
        if not store.verify_ledger()[0]:
            raise PolicyError('Custody did not verify after preservation')
        run_id = self.engine.db.start_run(case_id, 0, 'archive-input', digest)
        try:
            # Imported engines can generate fresh UUIDs/times on every review.
            # Canonical effects use case/input/code identity, not those labels.
            identity = {}
            if action == 'intelligence':
                key = [SCHEMA, case_id, action, digest, result['module'],
                       result['module_sha256'], result['execution_profile_sha256']]
                identity['id'] = str(uuid5(NAMESPACE_URL, json.dumps(key)))
            finding = Finding(
                title=f'Archive analysis draft: {action}', source=f'archive:{action}',
                value=value, confidence=0,
                observation='Offline analysis of submitted evidence; reviewer decision required. '
                            'Hash integrity does not prove authenticity, entailment or identity.',
                **identity)
            added = self.engine.db.add_findings(case_id, run_id, [finding])
            if not added and action == 'intelligence':
                # Return the retained canonical draft, rather than regenerated
                # source-local IDs that were never stored as case evidence.
                retained = next(row for row in self.engine.db.findings(case_id)
                                if row['id'] == finding.id)
                value = retained['value']
            self.engine.db.end_run(run_id, 'completed')
        except Exception:
            self.engine.db.end_run(run_id, 'failed', 'Archive draft persistence failed')
            raise
        return {**value, 'findings_added': added, 'custody_verified': True}


def add_archive_parser(sub):
    root = sub.add_parser('archive', help='Compatible offline actions from the supplied source archives')
    commands = root.add_subparsers(dest='archive_command', required=True)
    commands.add_parser('actions', help='List graduated actions and their truth boundaries')
    commands.add_parser('modules', help='List supplied intelligence modules and execution modes')
    analyze = commands.add_parser('analyze', help='Analyze an approved file in an existing local case')
    analyze.add_argument('--case', required=True)
    analyze.add_argument('--action', required=True, choices=tuple(ACTION_DETAILS))
    analyze.add_argument('--input', required=True, type=Path)
    analyze.add_argument('--authorized', action='store_true', help='Approve processing this submitted file only')


def run_archive(args, engine):
    bridge = ArchiveBridge(engine)
    if args.archive_command == 'actions':
        return bridge.catalog()
    if args.archive_command == 'modules':
        from ..addons.intelligence_v1.registry import catalog
        return catalog()
    return bridge.analyze(args.case, args.action, args.input, approved_inputs=args.authorized)
