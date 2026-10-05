import unittest

from traceatlas.workforce.enterprise_golden import evaluate_enterprise_investigations, load_cases


class EnterpriseGoldenTests(unittest.TestCase):
    def test_versioned_pack_has_seven_target_classes_and_sixteen_distinct_patterns(self):
        pack = load_cases()
        self.assertTrue(pack['synthetic'])
        self.assertEqual(len(pack['cases']), 112)
        self.assertEqual(len({c['seed'].split(':', 1)[0] for c in pack['cases']}), 7)
        self.assertEqual(len({c['scenario'] for c in pack['cases']}), 16)

    def test_full_synthetic_investigations_preserve_replay_authority_and_review(self):
        result = evaluate_enterprise_investigations(revision='controlled-test-revision')
        failed = [(r['id'], r['checks']) for r in result['results'] if not r['passed']]
        self.assertEqual(failed, [])
        self.assertEqual(result['passed'], result['total'])
        self.assertEqual(result['completed_drafts'], 105)
        self.assertEqual(result['expected_rejections'], 7)
        self.assertEqual(result['metrics']['network_requests'], 0)
        self.assertEqual(result['metrics']['replay_success_rate'], 1.0)
        self.assertIsNone(result['metrics']['real_world_factual_accuracy'])


if __name__ == '__main__':
    unittest.main()
