"""Checklist output must never turn fixtures or configuration into acceptance."""
from contextlib import redirect_stdout
import io
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from traceatlas.cli import main
from traceatlas.db import CaseDB
from traceatlas.intelligence import SOURCES
from traceatlas.maturity import ProductMaturityScorecard
import test_source_integration_receipts as receipt_fixtures


class MaturityEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.db = CaseDB(self.workspace / 'traceatlas.db')
        self.addCleanup(self.db.close)
        self.card = ProductMaturityScorecard(self.db, self.workspace)

    @staticmethod
    def gates(result):
        return {g['name']: g for row in result['dimensions'] for g in row['gates']}

    def test_health_rows_cannot_upgrade_live_or_enterprise_evidence(self):
        before = self.card.run()
        for source in SOURCES:
            self.db.record_connector_result(source, True)
        for tool in ('misp', 'ollama'):
            self.db.record_integration_result(tool, 'completed')
        after = self.card.run()
        self.assertEqual(before['checklist'], after['checklist'])
        self.assertEqual(after['evidence_context']['healthy_connector_rows'], len(SOURCES))
        self.assertEqual(after['evidence_context']['revalidated_local_integration_sources'], 0)
        self.assertNotIn('verified_live_sources', after['evidence_context'])
        self.assertFalse(after['enterprise_assessment']['accepted'])
        self.assertIsNone(after['overall'])

    def test_configuration_and_markers_do_not_verify_hosted_acceptance(self):
        with patch.object(self.card, '_contains', return_value=True), patch(
                'traceatlas.maturity.DeploymentDoctor.run', return_value={
                    'production_configuration_ready': True, 'production_ready': True}):
            result = self.card.run(production=True)
        self.assertTrue(result['evidence_context']['production_configuration_ready'])
        self.assertFalse(result['evidence_context']['production_ready'])
        self.assertEqual(self.gates(result)['hosted_tenant_tests']['state'], 'fail')
        self.assertEqual(result['enterprise_assessment']['state'], 'NOT_ESTABLISHED')
        self.assertIsNone(result['enterprise_assessment']['score'])

    def test_missing_implementation_does_not_report_true_evidence(self):
        card = ProductMaturityScorecard(self.db, self.workspace, self.workspace)
        gate = self.gates(card.run())['schema_contracts']
        self.assertEqual(gate['state'], 'fail')
        self.assertIs(gate['evidence'], False)

    def test_checklist_denominators_are_explicit_and_consistent(self):
        result = self.card.run()
        self.assertEqual(result['schema'], 'traceatlas-engineering-checklist/v2')
        checklist = result['checklist']
        self.assertEqual(checklist['total_checks'], sum(r['total_checks'] for r in result['dimensions']))
        self.assertEqual(checklist['passed_checks'], sum(r['passed_checks'] for r in result['dimensions']))
        self.assertEqual(checklist['completion_percent'], round(
            100 * checklist['passed_checks'] / checklist['total_checks'], 1))
        self.assertTrue(all('score' not in r for r in result['dimensions']))

    def test_cli_labels_target_and_checklist_without_awarding_score(self):
        output = io.StringIO()
        with redirect_stdout(output):
            main(['--workspace', str(self.workspace), 'maturity'])
        text = output.getvalue()
        self.assertIn('Enterprise maturity: NOT ESTABLISHED (target 8/10)', text)
        self.assertIn('Engineering checks:', text)
        self.assertNotIn('Evidence-gated maturity:', text)

    def test_fixture_receipt_cannot_count_as_local_live_integration(self):
        fixture = receipt_fixtures.IntegrationReceiptTests('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        result = ProductMaturityScorecard(fixture.fixture.db, fixture.fixture.root).run()
        self.assertEqual(result['evidence_context']['revalidated_local_integration_sources'], 0)

    def test_revalidation_is_required_and_does_not_promote_enterprise(self):
        # Injected synthetic live row exercises bookkeeping, not actual network verification.
        fixture = receipt_fixtures.IntegrationReceiptTests('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.synthetic_live_row()
        fixture.record()
        card = ProductMaturityScorecard(fixture.fixture.db, fixture.fixture.root)
        result = card.run()
        self.assertEqual(result['evidence_context']['local_integration_sources'], ['dns'])
        self.assertFalse(result['enterprise_assessment']['accepted'])
        with patch('traceatlas.source_fabric.integration.implementation_digest', return_value='changed'):
            self.assertEqual(card.run()['evidence_context']['revalidated_local_integration_sources'], 0)
