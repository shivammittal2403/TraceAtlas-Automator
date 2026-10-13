"""Allowlisted, network-free adapters over the two supplied source snapshots.

Imported policy objects are data. Canonical case custody and consent are checked
by ArchiveBridge; these functions cannot register authority or run providers.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from dataclasses import asdict
import math
import re

from ..policy import PolicyError

ACTION_DETAILS = {
    'objective': ('osint_v1', 'Parse an objective into advisory targets/questions'),
    'dual-review': ('osint_v1', 'Compare supplied analyst drafts; agreement is not corroboration'),
    'detect-file': ('cute_v1', 'Inspect byte signatures, MIME mismatch and quarantine flags'),
    'geo': ('cute_v1', 'Parse supplied coordinates and measure spherical distance'),
    'payments': ('cute_v1', 'Deduplicate submitted payment records and calculate per-currency totals'),
    'hypotheses': ('cute_v1', 'Build an explicit analyst-labelled competing-hypotheses matrix'),
    'attack-stix': ('cute_v1', 'Parse a supplied STIX bundle into versioned ATT&CK objects'),
    'intelligence': ('intelligence_v1', 'Review supplied records with a bounded, hash-pinned intelligence module'),
}


def fields(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise PolicyError('Archive input fields do not match the versioned action contract')
    return value


def text(value, name, maximum=2000, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise PolicyError(f'{name} must be bounded text')
    if any(ord(c) < 32 and c not in '\n\t' for c in value):
        raise PolicyError(f'{name} contains control characters')
    return value


def rows(value, name, maximum=200):
    if not isinstance(value, list) or len(value) > maximum:
        raise PolicyError(f'{name} must be a bounded array')
    return value


def evidence_refs(value, evidence, input_id):
    refs = rows(value, 'evidence_ids', 100)
    result = []
    for ref in refs:
        ref = input_id if ref == '@input' else ref
        if not isinstance(ref, str) or ref not in evidence:
            raise PolicyError('Evidence reference is absent from this verified case')
        if ref not in result:
            result.append(ref)
    return result


def objective(payload, evidence, input_id, case_id):
    from ..addons.osint_v1.core.objective import Objective
    from ..addons.osint_v1.objectives.parser import parse_objective
    fields(payload, {'objective'}, {'objective'})
    value = parse_objective(Objective(case_id=case_id, text=text(payload['objective'], 'objective', 4000)))
    # The incoming parser self-infers FULLY_AUTHORIZED from words like "I own".
    # Never project that field into canonical permission or execute its targets.
    return {'targets': value.target_entities,
            'required_answers': [asdict(answer) for answer in value.required_answers],
            'ambiguities': [asdict(item) if hasattr(item, '__dataclass_fields__') else item
                            for item in value.ambiguities],
            'needs_human_clarification': value.needs_human_clarification,
            'scope_status': 'ADVISORY_ONLY', 'grants_authority': False,
            'next_action': 'Create a canonical workforce task with separately registered scope.'}


def dual_review(payload, evidence, input_id, case_id):
    from ..addons.osint_v1.trust.case_memory import CaseMemory
    from ..addons.osint_v1.trust.dual_review import DualReviewer, ReviewPass
    from ..addons.osint_v1.trust.model import EvidenceRecord
    fields(payload, {'primary', 'secondary'}, {'primary', 'secondary'})
    memory = CaseMemory(case_id)
    # Temporary read projection only; this imported CaseMemory is never persisted.
    for eid, row in evidence.items():
        memory.evidence[eid] = EvidenceRecord(id=eid, description=row.get('source', 'Submitted record'),
                                             source_id=row.get('source', 'submitted'), artifact_hash=eid)
    passes = []
    for key, role in (('primary', 'primary_analyst'), ('secondary', 'independent_skeptic')):
        item = fields(payload[key], {'statements', 'evidence_ids'}, {'statements', 'evidence_ids'})
        statements = [text(s, 'statement') for s in rows(item['statements'], 'statements', 50)]
        passes.append(ReviewPass(reviewer_id=key, role=role, statements=statements,
                                 cited_evidence_ids=evidence_refs(item['evidence_ids'], evidence, input_id)))
    result = DualReviewer(memory).cross_check(case_id, *passes).to_dict()
    return {**result, 'review_type': 'SUPPLIED_DRAFT_COMPARISON',
            'factual_entailment_verified': False, 'semantic_class': 'INFERENCE',
            'source_independence_verified': False, 'model_calls': 0,
            'limitation': 'Matching drafts and existing citation IDs do not prove factual entailment.'}


def geo(payload, evidence, input_id, case_id):
    from ..addons.cute_v1.geoint.geolocation.coordinate_parser import parse_any
    from ..addons.cute_v1.geoint.geolocation.distance import haversine_meters
    fields(payload, {'coordinates'}, {'coordinates'})
    values = rows(payload['coordinates'], 'coordinates', 50)
    if not values:
        raise PolicyError('At least one supplied coordinate is required')
    points = []
    for value in values:
        point = parse_any(text(value, 'coordinate', 150))
        point.validate()
        if not math.isfinite(point.lat) or not math.isfinite(point.lon):
            raise PolicyError('Coordinates must be finite')
        points.append(point)
    return {'supplied_coordinates': [p.to_dict() for p in points],
            'segments_meters': [round(haversine_meters(a, b), 3) for a, b in zip(points, points[1:])],
            'method': 'haversine_sphere', 'location_verified': False,
            'limitation': 'Calculations over supplied coordinates do not locate or identify a person.'}


def payments(payload, evidence, input_id, case_id):
    from ..addons.cute_v1.scams.payment_ledger import PaymentEntry, PaymentLedger, PAYMENT_STATUSES
    fields(payload, {'entries'}, {'entries'})
    ledger = PaymentLedger(case_id)
    conflicts = []
    disputed_keys = set()
    by_key = {}
    for index, item in enumerate(rows(payload['entries'], 'entries', 500)):
        fields(item, {'direction', 'amount', 'currency', 'status', 'tx_ref', 'method',
                      'recipient_ref', 'evidence_ids'}, {'direction', 'status'})
        direction = item['direction']
        status = item['status']
        if direction not in {'OUT', 'IN', 'DISPLAY_ONLY'} or status not in PAYMENT_STATUSES:
            raise PolicyError('Unknown payment direction/status')
        raw_amount = item.get('amount')
        amount = None
        if raw_amount is not None:
            # Decimal strings avoid rounding and prohibit NaN/Infinity/exponent bombs.
            if not isinstance(raw_amount, str) or not re.fullmatch(r'\d{1,18}(?:\.\d{1,8})?', raw_amount):
                raise PolicyError('Payment amount must be a bounded non-negative decimal string')
            try:
                amount = Decimal(raw_amount)
            except InvalidOperation as exc:
                raise PolicyError('Invalid amount') from exc
        currency = text(item.get('currency', ''), 'currency', 12, empty=True).upper()
        if currency and not re.fullmatch(r'[A-Z0-9]{2,12}', currency):
            raise PolicyError('Invalid currency/ticker')
        refs = evidence_refs(item.get('evidence_ids', []), evidence, input_id)
        entry = PaymentEntry(entry_id=f'payment-{index}', case_id=case_id, direction=direction,
                             status=status, amount=amount, currency=currency,
                             tx_ref=text(item.get('tx_ref', ''), 'tx_ref', 150, empty=True),
                             method=text(item.get('method', ''), 'method', 50, empty=True),
                             recipient_ref=text(item.get('recipient_ref', ''), 'recipient_ref', 150, empty=True),
                             evidence_ids=tuple(refs), verification_state=(
                                 'DOCUMENTED_ARTIFACT' if refs else 'UNSUPPORTED_STATEMENT'))
        key = entry.dedup_key()
        previous = by_key.get(key)
        conflict = previous is not None and (
            previous.amount, previous.currency, previous.direction, previous.recipient_ref, previous.status
        ) != (entry.amount, entry.currency, entry.direction, entry.recipient_ref, entry.status)
        kept, duplicate = ledger.add(entry)
        if conflict or key in disputed_keys:
            # The archive silently picks a stronger duplicate. At the bridge we
            # retain a contradiction and exclude the entire disputed transaction.
            kept = ledger.correct(kept.entry_id, status='DISPUTED', verification_state='DISPUTED')
            disputed_keys.add(key)
            conflicts.append({'transaction': kept.tx_ref, 'entries': [previous.entry_id, entry.entry_id],
                              'reason': 'Conflicting duplicate; excluded from numerical totals'})
        by_key[key] = kept
    result = ledger.to_dict()
    totals = {cur: {k: str(v) for k, v in total.items()}
              for cur, total in ledger.totals_by_currency().items()}
    return {**result, 'totals': totals, 'conflicts': conflicts,
            'calculation_status': 'PROVISIONAL_SUBMITTED_RECORDS',
            'authenticity_verified': False, 'evidence_basis': 'SUBMITTED_RECORDS_NOT_AUTHENTICATED',
            'note': ledger.provisional_net_loss_note()}


def hypotheses(payload, evidence, input_id, case_id):
    from ..addons.cute_v1.hypotheses.ach import ACHVerdict, EvidenceItem, build_matrix
    from ..addons.cute_v1.hypotheses.model import Hypothesis
    fields(payload, {'question', 'hypotheses'}, {'question', 'hypotheses'})
    question = text(payload['question'], 'question')
    hyps = []
    used = set()
    for index, item in enumerate(rows(payload['hypotheses'], 'hypotheses', 20)):
        fields(item, {'statement', 'supporting_evidence_ids', 'opposing_evidence_ids'}, {'statement'})
        support = evidence_refs(item.get('supporting_evidence_ids', []), evidence, input_id)
        oppose = evidence_refs(item.get('opposing_evidence_ids', []), evidence, input_id)
        if set(support) & set(oppose):
            raise PolicyError('A hypothesis cannot label the same evidence both supporting and opposing')
        used.update(support + oppose)
        hyps.append(Hypothesis(hypothesis_id=f'hypothesis-{index}', case_id=case_id,
                               statement=text(item['statement'], 'hypothesis'),
                               supporting_evidence_ids=support, opposing_evidence_ids=oppose))
    if not hyps:
        raise PolicyError('At least one hypothesis is required')
    evs = [EvidenceItem(eid, evidence[eid].get('source', 'Submitted evidence')) for eid in sorted(used)]
    # Disable the incoming token-overlap fallback: it is not factual entailment.
    def explicit_classifier(hyp, ev):
        if ev.evidence_id in hyp.opposing_evidence_ids:
            return ACHVerdict.INCONSISTENT
        if ev.evidence_id in hyp.supporting_evidence_ids:
            return ACHVerdict.CONSISTENT
        return ACHVerdict.UNKNOWN
    result = build_matrix(question, hyps, evs, classifier=explicit_classifier).to_dict()
    return {**result, 'semantic_class': 'HYPOTHESIS', 'basis': 'SUBMITTED_EVIDENCE_LABELS',
            'factual_entailment_verified': False, 'probability_calibrated': False,
            'automatic_identity_merge': False, 'requires_human_review': True}


def attack_stix(payload, evidence, input_id, case_id):
    from ..addons.cute_v1.attack.loader import StixLoader
    fields(payload, {'type', 'id', 'spec_version', 'objects', 'x_mitre_version',
                     'x_traceatlas_attack_version'}, {'type', 'objects'})
    objects = rows(payload['objects'], 'objects', 1000)
    if payload['type'] != 'bundle' or any(not isinstance(item, dict) for item in objects):
        raise PolicyError('A local STIX bundle is required')
    version, records, relationships = StixLoader().load_bundle(payload)
    return {'attack_version': version, 'objects': [r.to_dict() for r in records],
            'relationships': relationships, 'authenticity_verified': False,
            'origin': 'SUBMITTED_STIX', 'external_updates': False,
            'limitation': 'Local bundle parsing does not authenticate the publisher or attribute an actor.'}


def intelligence(payload, evidence, input_id, case_id):
    from .intelligence import analyze
    return analyze(payload, evidence, input_id, case_id)


JSON_ACTIONS = {'objective': objective, 'dual-review': dual_review, 'geo': geo,
                'payments': payments, 'hypotheses': hypotheses, 'attack-stix': attack_stix,
                'intelligence': intelligence}


def detect_file(raw, filename):
    from ..addons.cute_v1.ingestion.type_detector import detect_type
    sample = raw[:65536]
    try:
        decoded = sample.decode('utf-8')
    except UnicodeDecodeError:
        decoded = None
    result = detect_type(sample, filename=filename, text_sample=decoded).to_dict()
    return {**result, 'sample_bytes': len(sample), 'executed': False,
            'archive_members_extracted': False, 'classification': 'BYTE_FORMAT_HEURISTIC'}
