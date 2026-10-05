"""Author deterministic synthetic contract cases; expectations never call the app."""
import json
from pathlib import Path

SEEDS = ('domain:example.org', 'ip:8.8.8.8', 'company:gb:00000001',
         'person:synthetic-candidate', 'cve:CVE-2024-12345',
         'vulnerability:GHSA-synthetic-0001', 'package:traceatlas-synthetic')
# Count expectations are authored rules, independent of production extraction.
SCENARIOS = {
    'single_source': (1, 1, ['PARTIALLY_SUPPORTED'], 1, 0),
    'independent_corroboration': (2, 1, ['SUPPORTED'], 2, 0),
    'same_origin': (2, 1, ['PARTIALLY_SUPPORTED'], 1, 0),
    'same_owner': (2, 1, ['PARTIALLY_SUPPORTED'], 1, 0),
    'copied_content': (2, 1, ['PARTIALLY_SUPPORTED'], 1, 0),
    'conflicting_current': (2, 2, ['DISPUTED', 'DISPUTED'], 2, 2),
    'historical_change': (2, 2, ['PARTIALLY_SUPPORTED', 'PARTIALLY_SUPPORTED'], 2, 0),
    'unverified_prose': (1, 1, ['INCONCLUSIVE'], 1, 0),
    'prompt_injection': (2, 1, ['INCONCLUSIVE'], 2, 0),
    'empty_response': (0, 0, [], 1, 0),
    'omitted_extraction': (1, 1, ['PARTIALLY_SUPPORTED'], 1, 0),
    'multilingual_label': (2, 1, ['SUPPORTED'], 2, 0),
    'multiple_values': (2, 2, ['PARTIALLY_SUPPORTED', 'PARTIALLY_SUPPORTED'], 2, 0),
    'scope_expansion': None,
    'unknown_schema': (1, 1, ['INCONCLUSIVE'], 1, 0),
    'nonoverlapping_corroboration': (2, 1, ['PARTIALLY_SUPPORTED'], 2, 0),
}


def build():
    cases = []
    for seed in SEEDS:
        for scenario, expected in SCENARIOS.items():
            contract = {'error': 'out-of-scope'} if expected is None else dict(zip(
                ('observations', 'claims', 'statuses', 'groups', 'contradictions'), expected))
            cases.append({'id': 'E%03d' % (len(cases) + 1), 'seed': seed,
                          'scenario': scenario, 'expected': contract})
    return {'schema': 'traceatlas-enterprise-cases/v1', 'synthetic': True, 'cases': cases}


if __name__ == '__main__':
    pack = build()
    target = Path(__file__).resolve().parents[1] / 'src/traceatlas/workforce/data/enterprise_cases.json'
    # One fixture per line keeps the 112 expectations readable in review.
    target.write_text('{"schema":"' + pack['schema'] + '","synthetic":true,"cases":[\n' +
                      ',\n'.join(json.dumps(c, ensure_ascii=False, separators=(',', ':')) for c in pack['cases']) +
                      '\n]}\n', encoding='utf-8')
