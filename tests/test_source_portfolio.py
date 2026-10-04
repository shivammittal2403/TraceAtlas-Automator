import math
import tempfile
import unittest
from pathlib import Path

from traceatlas.db import CaseDB
from traceatlas.policy import PolicyError
from traceatlas.source_fabric.portfolio import (
    FACTORS, PENALTIES, FIELDS, FAMILY_TARGETS, Portfolio,
    validate_record, source_score, independence_graph,
)


def candidate(sid='example'):
    return {'source_id': sid, 'provider_name': 'Example provider', 'official_name': sid + ' records',
            'source_family': 'CTI', 'capabilities': ['vulnerability'], 'dataset_id': sid}


class PortfolioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = CaseDB(Path(self.tmp.name) / 'case.db')
        self.portfolio = Portfolio(self.db)

    def tearDown(self):
        self.db.conn.close()
        self.tmp.cleanup()

    def test_schema_preserves_unknowns_and_refuses_imported_maturity(self):
        row = validate_record({**candidate(), 'qualification_status': 'PRODUCTION_QUALIFIED'})
        self.assertTrue(set(FIELDS).issubset(row))
        self.assertIsNone(row['rate_limits'])
        self.assertEqual(row['qualification_status'], 'UNVERIFIED')
        self.portfolio.import_records([row])
        actual = next(r for r in self.portfolio.records() if r['source_id'] == 'example')
        self.assertFalse(actual['registered'])
        self.assertEqual(actual['qualification_status'], 'DISCOVERED')

    def test_atomic_import(self):
        with self.assertRaises(PolicyError):
            self.portfolio.import_records([candidate(), {**candidate('bad'), 'base_api': 'https://api.example/?key=secret'}])
        self.assertEqual(self.portfolio.research(), [])

    def test_aliases_and_duplicate_provider_identity_do_not_count(self):
        self.portfolio.import_records([candidate()])
        with self.assertRaises(PolicyError):
            self.portfolio.import_records([{**candidate('alias'), 'official_name': 'example records'}])
        self.assertEqual(len(self.portfolio.research()), 1)

    def test_research_never_inflates_implementation(self):
        before = self.portfolio.report()['counts']
        self.portfolio.import_records([candidate()])
        after = self.portfolio.report()
        self.assertEqual(after['counts']['registered'], before['registered'])
        self.assertEqual(after['counts']['implemented'], before['implemented'])
        self.assertEqual(after['counts']['research_only'], 1)
        self.assertFalse(after['targets_satisfied'])
        self.assertIsNone(after['counts']['integration_tested'])
        self.assertEqual(sum(FAMILY_TARGETS.values()), 645)

    def test_unknowns_fail_closed_in_planner(self):
        self.portfolio.import_records([{**candidate('nvd'), 'official_documentation': 'https://nvd.nist.gov/'}])
        plan = self.portfolio.rank(['vulnerability'], budget=10)
        self.assertEqual([w['wave'] for w in plan['waves']], [1, 2, 3, 4])
        self.assertTrue(all(not w['sources'] for w in plan['waves']))
        self.assertFalse(plan['execution_granted'])
        self.assertIn('vulnerability', plan['information_gaps'])

    def test_transitive_upstream_datasets_collapse(self):
        rows = [{**candidate('a'), 'upstream_datasets': ['b']},
                {**candidate('b'), 'upstream_datasets': ['c']}, candidate('c')]
        groups = independence_graph(rows)['groups']
        self.assertEqual(list(groups.values()), [['a', 'b', 'c']])

    def test_unknown_ancestry_is_not_independent(self):
        rows = [candidate('a'), candidate('b')]
        for row in rows:
            del row['dataset_id']
        self.assertEqual(len(independence_graph(rows)['groups']), 1)

    def test_score_requires_every_factor_and_penalty(self):
        self.assertIsNone(source_score({'authority': 1})['score'])
        factors = {key: 1 for key in FACTORS}
        factors.update({key: 0 for key in PENALTIES})
        self.assertEqual(source_score(factors)['score'], 1)
        factors['privacy_risk'] = 1
        self.assertEqual(source_score(factors)['score'], .5)
        factors['availability'] = 0
        self.assertEqual(source_score(factors)['score'], 0)

    def test_rejects_nonfinite_and_boolean_numeric_values(self):
        for value in (math.nan, math.inf, True, -1, 2):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                source_score({'authority': value})
        for value in (math.inf, True, -1):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                self.portfolio.rank(['dns'], budget=value)

    def test_health_is_separate_from_live_verification(self):
        self.db.create_case('health-case', 'Synthetic health test', 'Public fixture')
        self.db.conn.execute("""INSERT INTO fabric_executions
            (id,source,case_id,request_hash,authority_hash,status,mode,started_at)
            VALUES('health','dns','health-case','request','authority','completed','live',datetime('now'))""")
        self.db.conn.commit()
        row = next(r for r in self.portfolio.health_report()['sources'] if r['source_id'] == 'dns')
        self.assertEqual(row['health'], 'HEALTHY')
        self.assertNotEqual(row['maturity'], 'LIVE_VERIFIED')
        self.assertEqual(row['observed_calls'], 1)

    def test_dashboard_escapes_untrusted_metadata_and_keeps_unknown_counts(self):
        from traceatlas.source_fabric.dashboard import render_dashboard
        self.portfolio.import_records([{**candidate(), 'official_name': '<script>alert(1)</script>'}])
        html = render_dashboard(self.portfolio.report(), self.portfolio.records(), self.portfolio.health_report())
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('<b>UNKNOWN</b><span>TESTED CONNECTORS</span>', html)

    def test_governed_count_and_planning_require_resolved_reviews(self):
        from traceatlas.evidence import EvidenceStore
        self.db.create_case('review-case', 'Synthetic metadata reviews', 'Controlled test')
        artifact = Path(self.tmp.name) / 'review.json'
        artifact.write_text('{"synthetic_metadata_review":true}', encoding='utf-8')
        preserved = EvidenceStore(Path(self.tmp.name), self.db, 'review-case').preserve_file(artifact, 'synthetic review')
        row = {**candidate('nvd'), 'official_documentation': 'https://nvd.nist.gov/developers/vulnerabilities',
               'documentation_evidence': {'case_id': 'review-case', 'sha256': preserved['sha256']},
               'unique_value': 'Synthetic unique-value declaration', 'PII_risk': 'LOW',
               'estimated_cost': 0, 'estimated_latency_ms': 50}
        self.portfolio.import_records([row])
        self.assertEqual(self.portfolio.report()['counts']['governed'], 0)
        for check in ('documentation', 'manifest', 'terms', 'license', 'privacy'):
            self.portfolio.fabric.review('nvd', check, 'review-case', preserved['sha256'],
                                         'fixture reviewer', Path(self.tmp.name), authorized=True)
        report = self.portfolio.report()
        self.assertEqual(report['counts']['governed'], 1)
        self.assertEqual(report['family_coverage']['CTI']['reviewed'], 1)
        plan = self.portfolio.rank(['vulnerability'])
        self.assertEqual(plan['waves'][0]['sources'][0]['source_id'], 'nvd')
        self.assertFalse(plan['execution_granted'])
        self.assertEqual(report['counts']['live_verified'], 0)


if __name__ == '__main__':
    unittest.main()
