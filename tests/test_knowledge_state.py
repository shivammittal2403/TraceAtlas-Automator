import unittest

from traceatlas.workforce.knowledge import knowledge_state, rank_review_actions


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.claims = [{'claim_id': 'claim-a', 'observation_ids': ['observation-a']}]
        self.decisions = [{'claim_id': 'claim-a', 'status': 'DISPUTED', 'information_gaps': ['conflict']}]
        self.observations = [{'observation_id': 'observation-a', 'evidence_id': 'evidence-a'}]

    def test_projection_links_claim_state_to_evidence_without_declaring_objective_done(self):
        result = knowledge_state(self.claims, self.decisions, self.observations, gaps=['conflict'])
        self.assertEqual(result['claims'][0]['evidence_ids'], ['evidence-a'])
        self.assertEqual(result['state_counts']['DISPUTED'], 1)
        self.assertIsNone(result['objective_satisfied'])

    def test_unknown_reference_duplicate_claim_or_unregistered_state_fail_closed(self):
        for claims, decisions, observations in ((self.claims, self.decisions, []),
            (self.claims * 2, self.decisions * 2, self.observations),
            (self.claims, [{**self.decisions[0], 'status': 'KNOWN_TRUE'}], self.observations)):
            with self.assertRaises(ValueError):
                knowledge_state(claims, decisions, observations)

    def test_review_ranking_is_explained_bounded_and_cannot_authorize_execution(self):
        state = knowledge_state(self.claims, self.decisions, self.observations)
        actions = [{'action_id': 'human-review-draft', 'priority': 4, 'automatic_execution': False},
                   {'action_id': 'review-contradictions', 'priority': 1, 'automatic_execution': False}]
        ranked = rank_review_actions(actions, state)
        self.assertEqual(ranked[0]['action_id'], 'review-contradictions')
        self.assertEqual(ranked[0]['score'], sum(ranked[0]['score_components'].values()))
        self.assertEqual(ranked[0]['evidence_ids'], ['evidence-a'])
        self.assertIsNone(ranked[0]['expected_information_gain'])
        with self.assertRaises(ValueError):
            rank_review_actions([{**actions[0], 'automatic_execution': True}], state)
