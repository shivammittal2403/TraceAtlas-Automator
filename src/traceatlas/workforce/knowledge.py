"""Deterministic knowledge and review priorities over already verified records.

This projection owns no evidence, authority, identities or executable tools.
Scores are explicit heuristics, never probabilities or information-gain claims.
"""
from __future__ import annotations

STATES = frozenset({'SUPPORTED', 'PARTIALLY_SUPPORTED', 'DISPUTED', 'INCONCLUSIVE', 'UNSUPPORTED', 'STALE'})


def knowledge_state(claims, decisions, observations, *, gaps=(), identity_candidates=()):
    if len(claims) > 200 or len(observations) > 200 or len(decisions) != len(claims):
        raise ValueError('Knowledge projection exceeds bounds or lacks claim decisions')
    claim_index = {c['claim_id']: c for c in claims}
    decision_index = {d['claim_id']: d for d in decisions}
    observation_index = {o['observation_id']: o for o in observations}
    if len(claim_index) != len(claims) or len(decision_index) != len(decisions) or len(observation_index) != len(observations) or set(claim_index) != set(decision_index):
        raise ValueError('Knowledge projection contains duplicate or mismatched references')
    rows, counts = [], {state: 0 for state in sorted(STATES)}
    for cid, claim in sorted(claim_index.items()):
        decision = decision_index[cid]
        refs = claim['observation_ids']
        if not refs or any(ref not in observation_index for ref in refs) or decision['status'] not in STATES:
            raise ValueError('Knowledge claim lacks valid evidence-backed observations or state')
        state = decision['status']
        counts[state] += 1
        rows.append({'claim_id': cid, 'state': state, 'observation_ids': list(refs),
                     'evidence_ids': sorted({observation_index[ref]['evidence_id'] for ref in refs}),
                     'information_gaps': sorted(set(decision['information_gaps'])), 'human_review_required': True})
    return {'schema': 'traceatlas-knowledge-state/v1', 'claims': rows, 'state_counts': counts,
            'information_gaps': sorted(set(gaps)), 'unresolved_entities': [r['seed_id'] for r in identity_candidates if not r['canonical_merge']],
            'objective_satisfied': None, 'objective_assessment': 'requires-analyst-review',
            'limitations': 'These states describe verification of cited source assertions; they do not establish identity, causation or objective completion.'}


def rank_review_actions(actions, knowledge):
    if len(actions) > 100 or len({a['action_id'] for a in actions}) != len(actions):
        raise ValueError('Review actions require unique IDs within their bound')
    ranked = []
    for action in actions:
        if action.get('automatic_execution') is not False or type(action.get('priority')) is not int or not 1 <= action['priority'] <= 10:
            raise ValueError('Knowledge projection accepts bounded human review actions only')
        relevant = [r for r in knowledge['claims'] if r['state'] == 'DISPUTED'] if action['action_id'] == 'review-contradictions' else [r for r in knowledge['claims'] if r['state'] != 'SUPPORTED']
        factors = {'declared_priority': (11 - action['priority']) * 10,
                   'contradiction_review': 20 if action['action_id'] == 'review-contradictions' and relevant else 0,
                   'independence_review': 10 if action['action_id'] == 'seek-independent-corroboration' and relevant else 0}
        ranked.append({**action, 'score': sum(factors.values()), 'score_components': factors,
                       'claim_ids': [r['claim_id'] for r in relevant],
                       'evidence_ids': sorted({eid for r in relevant for eid in r['evidence_ids']}),
                       'expected_information_gain': None, 'score_calibration': 'unvalidated-rule-priority',
                       'requires_new_collection_authorization': action['action_id'] not in {'human-review-draft', 'review-contradictions'}})
    return sorted(ranked, key=lambda a: (-a['score'], a['action_id']))
