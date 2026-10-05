"""Case-preserved evaluation inputs and protocol-bound ER diagnostics.

Review artifacts are operator attestations, not independent proof of permission,
sampling quality or identity truth. No evaluation result changes entity links.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import tempfile
from pathlib import Path
from typing import Any

from .evidence import EvidenceStore
from .policy import PolicyError
from .resolution import _public_record
from .resolution_evaluation import evaluate_entity_resolution
from .research.analysis import MATCH_FIELDS

MAX_BYTES = 2 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("Evaluation JSON contains duplicate fields")
        result[key] = value
    return result


def _read_preserved(store: EvidenceStore, digest: str) -> bytes:
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise PolicyError("Evaluation references must be SHA-256 digests")
    row = next((r for r in store.db.evidence(store.case_id) if r['sha256'] == digest), None)
    if row is None:
        raise PolicyError("Evaluation artifact does not resolve in this case")
    path = Path(row['path']).resolve()
    if not path.is_relative_to(store.root.resolve()):
        raise PolicyError("Evaluation artifact is outside case evidence")
    try:
        with path.open('rb') as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError:
        raise PolicyError("Evaluation artifact cannot be read") from None
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != digest:
        raise PolicyError("Evaluation artifact size or hash is invalid")
    return data


def _json(data: bytes) -> dict[str, Any]:
    try:
        result = json.loads(data, object_pairs_hook=_unique_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise PolicyError("Evaluation artifact must be bounded, strict JSON") from None
    if not isinstance(result, dict):
        raise PolicyError("Evaluation artifact must be a JSON object")
    return result


def _text(value: Any, label: str) -> None:
    if (not isinstance(value, str) or not 1 <= len(value.strip()) <= 200
            or any(ord(c) < 32 for c in value)):
        raise PolicyError(f"Invalid evaluation {label}")


def evaluate_preserved_corpus(store: EvidenceStore, corpus_sha256: str,
                              protocol_sha256: str, *, authorized: bool = False) -> dict[str, Any]:
    """Evaluate exact preserved labels under an earlier preserved protocol.

    The caller is the local authorized operator. This does not provide hosted
    IAM or validate the legal authority asserted in a review document.
    """
    if authorized is not True:
        raise PolicyError("Corpus evaluation requires explicit authorization")
    if not store.verify_ledger()[0]:
        raise PolicyError("Evaluation requires a verified case custody ledger")
    corpus = _json(_read_preserved(store, corpus_sha256))
    protocol = _json(_read_preserved(store, protocol_sha256))
    required = {'schema', 'corpus_sha256', 'purpose', 'split', 'threshold', 'minimum_cases',
                'minimum_precision', 'minimum_recall', 'maximum_false_positive_rate',
                'authority_ref', 'privacy_review_ref', 'label_review_ref'}
    if set(protocol) != required or protocol['schema'] != 'traceatlas-er-protocol/v1':
        raise PolicyError("Invalid evaluation protocol schema")
    if protocol['corpus_sha256'] != corpus_sha256 or protocol['split'] != 'held-out':
        raise PolicyError("Protocol must bind this held-out corpus")
    _text(protocol['purpose'], 'purpose')
    for field in ('threshold', 'minimum_precision', 'minimum_recall', 'maximum_false_positive_rate'):
        value = protocol[field]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
            raise PolicyError("Protocol thresholds must be finite values between zero and one")
    if type(protocol['minimum_cases']) is not int or not 1 <= protocol['minimum_cases'] <= 10000:
        raise PolicyError("Protocol minimum_cases must be 1-10000")
    for field in ('authority_ref', 'privacy_review_ref', 'label_review_ref'):
        _read_preserved(store, protocol[field])
    if (set(corpus) != {'schema', 'dataset_id', 'dataset_kind', 'cases'}
            or corpus['schema'] != 'traceatlas-reviewed-er-corpus/v1'
            or corpus['dataset_kind'] not in {'synthetic', 'authorized-reviewed'}):
        raise PolicyError("Invalid evaluation corpus schema")
    _text(corpus['dataset_id'], 'dataset_id')
    cases = corpus['cases']
    if not isinstance(cases, list) or not 1 <= len(cases) <= 10000:
        raise PolicyError("Evaluation corpus requires 1-10000 cases")
    for case in cases:
        if not isinstance(case, dict) or set(case) != {'case_id', 'query', 'expected_match_id', 'candidates'}:
            raise PolicyError("Invalid evaluation case schema")
        _text(case['case_id'], 'case_id')
        if not isinstance(case['candidates'], list) or not 1 <= len(case['candidates']) <= 500:
            raise PolicyError("Evaluation requires 1-500 candidates per case")
        records = [case['query']]
        for candidate in case['candidates']:
            if not isinstance(candidate, dict) or set(candidate) != {'candidate_id', 'record', 'is_match'}:
                raise PolicyError("Invalid evaluation candidate schema")
            _text(candidate['candidate_id'], 'candidate_id')
            records.append(candidate['record'])
        for record in records:
            if not isinstance(record, dict) or set(record) - set(MATCH_FIELDS):
                raise PolicyError("Evaluation accepts only supported non-sensitive comparison fields")
            if any(not isinstance(v, str) for v in record.values()):
                raise PolicyError("Evaluation comparison values must be strings")
            _public_record(record)
    # This establishes local capture order only, not an independently witnessed
    # preregistration or freedom from prior threshold tuning.
    positions = {}
    for index, line in enumerate(store.ledger.read_text(encoding='utf-8').splitlines()):
        row = json.loads(line)
        if row.get('action') == 'preserve':
            positions.setdefault(row['sha256'], index)
    if positions[protocol_sha256] >= positions[corpus_sha256]:
        raise PolicyError("Protocol must be preserved before the corpus capture")
    result = evaluate_entity_resolution(cases, threshold=protocol['threshold'])
    metrics = result['pair_metrics']
    checks = {
        'minimum_cases': result['cases'] >= protocol['minimum_cases'],
        'minimum_precision': metrics['precision'] is not None and metrics['precision'] >= protocol['minimum_precision'],
        'minimum_recall': metrics['recall'] is not None and metrics['recall'] >= protocol['minimum_recall'],
        'maximum_false_positive_rate': metrics['false_positive_rate'] is not None and metrics['false_positive_rate'] <= protocol['maximum_false_positive_rate'],
    }
    result.pop('case_results')  # Avoid copying record/candidate IDs into aggregate reports.
    result.update({
        'schema': 'traceatlas-preserved-er-evaluation/v1',
        'dataset_kind': corpus['dataset_kind'],
        'corpus_sha256': corpus_sha256, 'protocol_sha256': protocol_sha256,
        'review_evidence': {f: protocol[f] for f in ('authority_ref', 'privacy_review_ref', 'label_review_ref')},
        'protocol_threshold_checks': checks,
        'protocol_thresholds_met': all(checks.values()),
        'threshold_provenance': 'exact earlier case-preserved protocol; independent preregistration not verified',
        'enterprise_gate_passed': False,
        'representativeness': 'OPERATOR_DECLARED_NOT_INDEPENDENTLY_VERIFIED',
        'metric_denominators': {
            'precision': metrics['true_positive'] + metrics['false_positive'],
            'recall': metrics['true_positive'] + metrics['false_negative'],
            'false_positive_rate': metrics['false_positive'] + metrics['true_negative'],
        },
    })
    result['limitations'].extend([
        'Review-artifact presence proves preserved membership, not reviewer identity, consent or sampling quality.',
        'Threshold checks are dataset diagnostics; independent adjudication and representative acceptance remain required.',
    ])
    if not store.verify_ledger()[0]:
        raise PolicyError("Case evidence changed during evaluation")
    with tempfile.TemporaryDirectory(prefix='traceatlas-er-report-') as directory:
        path = Path(directory) / 'resolution-evaluation.json'
        path.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        receipt = store.preserve_file(path, 'evaluation:entity-resolution:' + corpus_sha256)
    return {**result, 'report_evidence_sha256': receipt['sha256']}
