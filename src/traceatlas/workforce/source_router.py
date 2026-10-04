"""Transparent capability planning. Scores are heuristics, never calibrated IG."""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass

from .documents import normalize_seed
from .source_registry import SourceRegistry, P0_IDS, P0_BY_ID
from .source_state import stable_digest


@dataclass(frozen=True)
class ObjectiveSpec:
    case_id: str
    objective: str
    target_entities: tuple[str, ...]
    questions: tuple[str, ...]
    jurisdictions: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    required_outputs: tuple[str, ...]
    authorization_context_id: str

    def __post_init__(self):
        if len(self.target_entities) != 1 or not isinstance(self.objective, str) or not 5 <= len(self.objective.strip()) <= 4000:
            raise ValueError('one typed seed and a bounded objective are required')
        kind, target = self.target_entities[0].split(':', 1)
        if normalize_seed(kind, target) != target or kind not in self.allowed_domains:
            raise ValueError('objective seed outside declared domains')
        if len(self.questions) > 20 or any(not isinstance(q, str) or not 1 <= len(q) <= 500 for q in self.questions):
            raise ValueError('invalid objective questions')

    def to_dict(self):
        return asdict(self)


def requirements(kind, target, objective):
    text = objective.casefold()
    if kind == 'domain':
        caps = ['domain.registration', 'domain.dns']
        rules = [('cert', 'domain.certificates'), ('infrastructure', 'domain.certificates'),
                 ('history', 'web.archive'), ('archive', 'web.archive'), ('exposure', 'web.index')]
    elif kind == 'ip':
        caps = ['ip.ownership', 'ip.asn', 'ip.exposure']
        rules = [('rout', 'ip.routing'), ('location', 'ip.geolocation'), ('reputation', 'cti.indicator'), ('threat', 'cti.indicator')]
    elif kind == 'company':
        caps = ['code.organization'] if target.startswith('github:') else ['company.registration']
        rules = [('filing', 'company.filings'), ('ownership', 'company.ownership'), ('procure', 'company.procurement')]
    elif kind == 'cve':
        caps = ['vulnerability.advisory', 'vulnerability.exploitation_probability']
        rules = []
    elif kind == 'vulnerability':
        caps = ['vulnerability.advisory', 'vulnerability.affected_packages']
        rules = []
    elif kind == 'package':
        caps = ['package.metadata']
        rules = []
    else:
        return ()
    for term, cap in rules:
        if term in text:
            caps.append(cap)
    if any(term in text for term in ('search', 'web ', 'news', 'document')):
        caps.append('web.search')
    return tuple(dict.fromkeys(caps))


class SourceRouter:
    def __init__(self, registry=None, health=None, configured=None):
        self.registry = registry or SourceRegistry()
        self.health = health or (lambda source: {'state': 'UNKNOWN'})
        if configured is None:
            from .live_sources import readiness
            readiness_by_id = {r['source_id']: r for r in readiness()}
            configured = lambda source: readiness_by_id[source]['configuration_status'] in {'configured', 'keyless'}
        self.configured = configured

    def plan(self, objective, *, allowed_tools, capabilities=None, prices=None, max_calls=8, budget=1.0, explicit_sources=None, health_probe=False):
        if type(health_probe) is not bool or health_probe and (explicit_sources is None or len(explicit_sources) != 1):
            raise ValueError('health probe requires one explicitly selected source')
        kind, target = objective.target_entities[0].split(':', 1)
        needed = tuple(capabilities) if capabilities is not None else requirements(kind, target, objective.objective)
        if len(needed) > 20 or len(set(needed)) != len(needed) or any(not isinstance(c, str) or len(c) > 100 for c in needed):
            raise ValueError('invalid capability requirements')
        prices = dict(prices or {})
        if set(prices) - P0_IDS or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0 <= v <= budget for v in prices.values()):
            raise ValueError('invalid per-request price ceilings')
        candidates, selected = [], []
        for item in self.registry.list():
            matching = sorted(set(needed) & set(item.capabilities))
            if not matching and (explicit_sources is None or item.source_id not in explicit_sources):
                continue
            sid = item.source_id
            health = self.health(sid)
            price = prices.get(sid, item.estimated_request_cost)
            reasons = []
            if not self.registry.supports(sid, kind, target): reasons.append('input_not_supported')
            if item.tool not in allowed_tools: reasons.append('tool_not_authorized')
            if sid in P0_IDS and not self.configured(sid): reasons.append('not_configured')
            if health['state'] in {'DOWN', 'DISABLED', 'SCHEMA_CHANGED', 'AUTH_FAILURE', 'RATE_LIMITED'}: reasons.append('source_' + health['state'].lower())
            if price is None: reasons.append('unpriced_account_source')
            if price is not None and price > budget: reasons.append('cost_boundary')
            if item.implementation_status in {'BROKEN', 'DISABLED', 'DEPRECATED', 'DISCOVERED', 'CATALOGUED', 'DOCUMENTED'}: reasons.append('not_implemented')
            factors = {'capability_match': len(matching) * 100, 'official': 8 if item.official else 0,
                       'primary': 5 if item.primary_source else 0, 'free': 3 if price == 0 else 0,
                       'health': 2 if health['state'] == 'HEALTHY' else -3 if health['state'] == 'DEGRADED' else 0,
                       'cost_penalty': -(price or 0) * 10,
                       'priority': (len(P0_BY_ID) - list(P0_BY_ID).index(sid)) / 100 if sid in P0_BY_ID else 0}
            candidates.append({'source_id': sid, 'capabilities': matching, 'eligible': not reasons, 'rejections': reasons,
                'score': round(sum(factors.values()), 4), 'factors': factors, 'health': health['state'],
                'estimated_request_cost': price, 'upstream_group': item.upstream_group, 'country_coverage': item.countries})
        eligible = sorted([r for r in candidates if r['eligible']], key=lambda r: (-r['score'], r['source_id']))
        unresolved = set(needed)
        def fits(source):
            projected = sum((prices.get(s, self.registry.get(s).estimated_request_cost) or 0) * (2 if s == 'rdap' else 1)
                            for s in selected + [source])
            return len(selected) + 1 + ('rdap' in selected or source == 'rdap') <= max_calls and projected <= budget
        if explicit_sources is not None:
            from .live_sources import select_sources
            for sid in select_sources(kind, target, explicit_sources):
                # Explicit choices remain in the approved plan even if configuration
                # is missing. Gateway fails visibly before sending any request.
                if not fits(sid):
                    raise ValueError('selected sources exceed planned request or cost budget')
                selected.append(sid)
        else:
            while unresolved:
                options = [r for r in eligible if r['source_id'] not in selected and unresolved.intersection(r['capabilities']) and fits(r['source_id'])]
                if not options: break
                best = max(options, key=lambda r: (len(unresolved.intersection(r['capabilities'])), r['score']))
                selected.append(best['source_id']); unresolved.difference_update(best['capabilities'])
        primary = list(selected)
        fallback_for = {}
        if explicit_sources is None:
            for chosen in primary:
                caps = self.registry.get(chosen).capabilities
                for row in eligible:
                    sid = row['source_id']
                    if sid not in selected and fits(sid) and set(caps).intersection(row['capabilities']):
                        selected.append(sid); fallback_for[sid] = chosen
                        break
        covered = {cap for sid in primary for cap in self.registry.get(sid).capabilities}
        tasks = [{'source_id': sid, 'capabilities': list(self.registry.get(sid).capabilities),
                  'wave': 2 if sid in fallback_for else 1, 'fallback_for': fallback_for.get(sid),
                  'dependencies': [fallback_for[sid]] if sid in fallback_for else []} for sid in selected]
        return {'schema': 'traceatlas-source-plan/v1', 'objective_id': stable_digest(objective.to_dict()),
            'objective': objective.to_dict(), 'source_requirements': list(needed), 'sources': selected,
            'tasks': tasks, 'candidates': candidates, 'information_gaps': sorted(set(needed) - covered),
            'questions': list(objective.questions) or ['Which captured records support ' + cap + '?' for cap in needed],
            'falsification': ['Check target identifiers, timestamps, shared upstream sources and contradictory records.'],
            'price_ceilings': {sid: prices.get(sid, self.registry.get(sid).estimated_request_cost) for sid in selected},
            'estimated_cost': None if any(prices.get(sid, self.registry.get(sid).estimated_request_cost) is None for sid in selected)
                              else sum(prices.get(sid, self.registry.get(sid).estimated_request_cost) * (2 if sid == 'rdap' else 1) for sid in selected),
            'budget_usd': budget, 'request_limit': max_calls, 'score_calibration': 'transparent-heuristic-unvalidated',
            'automatic_pivots': False, 'production_qualified': False, 'health_probe': health_probe,
            'stop_conditions': ['capabilities_collected', 'sources_exhausted', 'budget_exhausted', 'time_exhausted', 'human_review_required']}
