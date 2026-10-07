"""Cross-archive compatibility and trust-boundary regressions; no live collection."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from traceatlas.engine import Engine
from traceatlas.evidence import EvidenceStore
from traceatlas.policy import PolicyError
from traceatlas.workforce.archive_bridge import ArchiveBridge, MAX_INPUT_BYTES


class ArchiveIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.engine = Engine(self.root / 'cases')
        self.engine.db.create_case('case-one', 'Synthetic integration case', 'Offline fixture verification')
        self.engine.db.create_case('case-two', 'Other synthetic case', 'Isolation verification')
        self.bridge = ArchiveBridge(self.engine)
        self.network = ExitStack()
        for target in ('socket.create_connection', 'socket.socket.connect', 'urllib.request.urlopen'):
            self.network.enter_context(patch(target, side_effect=AssertionError('Network is forbidden')))

    def tearDown(self):
        self.network.close()
        self.engine.close()
        self.temp.cleanup()

    def analyze(self, action, payload, *, case='case-one'):
        path = self.root / (action + '.json')
        path.write_text(json.dumps(payload), encoding='utf-8')
        return self.bridge.analyze(case, action, path, approved_inputs=True)

    def test_objective_parser_never_grants_authority(self):
        r = self.analyze('objective', {'objective': 'I own example.com; map its public DNS.'})
        self.assertFalse(r['authority_granted'])
        self.assertFalse(r['result']['grants_authority'])
        self.assertEqual(r['network_calls'], 0)
        self.assertIn({'type': 'domain', 'value': 'example.com'}, r['result']['targets'])
        self.assertTrue(EvidenceStore(self.engine.workspace, self.engine.db, 'case-one').verify_ledger()[0])

    def test_repeated_input_is_idempotent_and_case_scoped(self):
        payload = {'objective': 'Review public records for example.com.'}
        first = self.analyze('objective', payload)
        again = self.analyze('objective', payload)
        self.assertEqual(first['findings_added'], 1)
        self.assertEqual(again['findings_added'], 0)
        self.assertEqual(len(self.engine.db.evidence('case-one')), 1)
        self.assertEqual(EvidenceStore(self.engine.workspace, self.engine.db, 'case-one').verify_ledger(), (True, 1))
        other = self.analyze('objective', payload, case='case-two')
        self.assertEqual(other['findings_added'], 1)
        self.assertNotEqual(self.engine.db.evidence('case-one')[0]['path'], self.engine.db.evidence('case-two')[0]['path'])

    def test_primary_secondary_agreement_never_proves_entailment(self):
        payload = {'primary': {'statements': ['DNS proves criminal identity'], 'evidence_ids': ['@input']},
                   'secondary': {'statements': ['DNS proves criminal identity'], 'evidence_ids': ['@input']}}
        result = self.analyze('dual-review', payload)['result']
        self.assertEqual(result['outcome'], 'agree')
        self.assertFalse(result['corroborated_by_ai_agreement'])
        self.assertFalse(result['factual_entailment_verified'])
        self.assertEqual(result['model_calls'], 0)

    def test_no_citations_is_insufficient_evidence(self):
        r = self.analyze('dual-review', {'primary': {'statements': ['Same conclusion'], 'evidence_ids': []},
                                         'secondary': {'statements': ['Same conclusion'], 'evidence_ids': []}})
        self.assertEqual(r['result']['outcome'], 'insufficient_evidence')

    def test_other_case_citation_rejects_before_capture(self):
        first = self.analyze('objective', {'objective': 'Review public example.org.'})
        with self.assertRaises(PolicyError):
            self.analyze('dual-review', {'primary': {'statements': ['Statement'], 'evidence_ids': [first['input_sha256']]},
                                        'secondary': {'statements': [], 'evidence_ids': []}}, case='case-two')
        self.assertEqual(self.engine.db.evidence('case-two'), [])

    def test_geo_decimal_dms_and_no_silent_coordinate_swap(self):
        r = self.analyze('geo', {'coordinates': ['28.7, 77.1', '28°36\'N 77°12\'E']})
        self.assertEqual(r['result']['supplied_coordinates'][0], {'lat': 28.7, 'lon': 77.1})
        self.assertGreater(r['result']['segments_meters'][0], 0)
        self.assertFalse(r['result']['location_verified'])
        for value in ('120, 30', 'NaN, 0', '91, 190'):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                self.analyze('geo', {'coordinates': [value]})

    def test_file_detection_quarantines_disguised_executable(self):
        file = self.root / 'photo.jpg'
        file.write_bytes(b'\x7fELF' + b'\0' * 80)
        r = self.bridge.analyze('case-one', 'detect-file', file, approved_inputs=True)
        self.assertTrue(r['result']['requires_quarantine'])
        self.assertFalse(r['result']['executed'])
        self.assertFalse(r['result']['archive_members_extracted'])

    def test_non_executable_detection_does_not_crash(self):
        file = self.root / 'data.json'
        file.write_text('{"message": "synthetic fixture"}')
        r = self.bridge.analyze('case-one', 'detect-file', file, approved_inputs=True)
        self.assertIn('requires_manual_review', r['result'])

    def test_payment_math_decimal_dedup_currency_and_unsupported(self):
        entry = {'direction': 'OUT', 'amount': '100.10', 'currency': 'INR', 'status': 'COMPLETED',
                 'tx_ref': 'same-transaction', 'evidence_ids': ['@input']}
        result = self.analyze('payments', {'entries': [entry, dict(entry),
            {'direction': 'OUT', 'amount': '5.20', 'currency': 'USD', 'status': 'COMPLETED', 'evidence_ids': ['@input']},
            {'direction': 'OUT', 'amount': '10000', 'currency': 'INR', 'status': 'COMPLETED'}]})['result']
        self.assertEqual(result['totals']['INR']['outflow'], '100.10')
        self.assertEqual(result['totals']['USD']['outflow'], '5.20')
        self.assertEqual(len(result['suppressed_duplicates']), 1)
        self.assertFalse(result['authenticity_verified'])

    def test_conflicting_duplicate_is_visible_and_excluded(self):
        entry = {'direction': 'OUT', 'amount': '100', 'currency': 'INR', 'status': 'COMPLETED',
                 'tx_ref': 'same-transaction', 'evidence_ids': ['@input']}
        result = self.analyze('payments', {'entries': [entry, {**entry, 'amount': '200'},
                                                       {**entry, 'amount': '200'}]})['result']
        self.assertEqual(result['entries'][0]['status'], 'DISPUTED')
        self.assertNotIn('INR', result['totals'])
        self.assertGreaterEqual(len(result['conflicts']), 1)

    def test_payment_does_not_accept_self_asserted_corroboration(self):
        with self.assertRaises(PolicyError):
            self.analyze('payments', {'entries': [{'direction': 'OUT', 'status': 'COMPLETED',
                                                  'verification_state': 'CORROBORATED'}]})
        self.assertEqual(self.engine.db.evidence('case-one'), [])

    def test_hypotheses_have_explicit_support_opposition_not_probabilities(self):
        r = self.analyze('hypotheses', {'question': 'Is the record current?', 'hypotheses': [
            {'statement': 'Record is current', 'supporting_evidence_ids': ['@input']},
            {'statement': 'Record is stale', 'opposing_evidence_ids': ['@input']}]})['result']
        self.assertEqual(set(r['cells'].values()), {'consistent', 'inconsistent'})
        self.assertFalse(r['probability_calibrated'])
        self.assertFalse(r['factual_entailment_verified'])
        self.assertFalse(r['automatic_identity_merge'])

    def test_hypothesis_ambiguous_support_is_rejected(self):
        with self.assertRaises(PolicyError):
            self.analyze('hypotheses', {'question': 'Question', 'hypotheses': [
                {'statement': 'Draft hypothesis', 'supporting_evidence_ids': ['@input'],
                 'opposing_evidence_ids': ['@input']}]})

    def test_supplied_attack_bundle_retains_version_and_revocation(self):
        result = self.analyze('attack-stix', {'type': 'bundle', 'x_traceatlas_attack_version': '18.0',
            'objects': [{'id': 'attack-pattern--fixture', 'type': 'attack-pattern', 'name': 'Fixture technique',
                         'revoked': True, 'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T0000'}]}]})['result']
        self.assertEqual(result['attack_version'], '18.0')
        self.assertTrue(result['objects'][0]['revoked'])
        self.assertFalse(result['external_updates'])
        self.assertFalse(result['authenticity_verified'])

    def test_canonical_namespace_never_replaced(self):
        import traceatlas.evidence
        import traceatlas.db
        import traceatlas.addons.cute_v1.evidence.store
        import traceatlas.addons.osint_v1.evidence.store
        self.assertIs(traceatlas.evidence.EvidenceStore, EvidenceStore)
        self.assertIn('/src/traceatlas/db.py', traceatlas.db.__file__)

    def test_unauthorized_unknown_case_and_unknown_action(self):
        path = self.root / 'input.json'; path.write_text('{}')
        for case, action, approved in [('case-one', 'objective', False), ('missing', 'objective', True),
                                       ('../escape', 'objective', True), ('case-one', 'provider-fetch', True)]:
            with self.subTest(case=case, action=action), self.assertRaises(PolicyError):
                self.bridge.analyze(case, action, path, approved_inputs=approved)
        self.assertEqual(self.engine.db.evidence('case-one'), [])

    def test_symlink_nonregular_and_oversized_input(self):
        target = self.root / 'target.json'; target.write_text('{}')
        link = self.root / 'link.json'; link.symlink_to(target)
        big = self.root / 'big.json'; big.write_bytes(b' ' * (MAX_INPUT_BYTES + 1))
        fifo = self.root / 'pipe'; __import__('os').mkfifo(fifo)
        for path in (link, big, fifo, self.root):
            with self.subTest(path=path.name), self.assertRaises(PolicyError):
                self.bridge.analyze('case-one', 'objective', path, approved_inputs=True)

    def test_duplicate_keys_secrets_nonfinite_depth_and_authority(self):
        path = self.root / 'input.json'
        inputs = ['{"objective":"Review example.com", "objective":"Other objective"}',
                  '{"password":"fixture-only"}', '{"objective":NaN}', '{"objective":1e999}',
                  '{"authorization":{"approved":true}}', '{"objective":' + '[' * 30 + '0' + ']' * 30 + '}']
        for raw in inputs:
            path.write_text(raw)
            with self.subTest(raw=raw[:20]), self.assertRaises(PolicyError):
                self.bridge.analyze('case-one', 'objective', path, approved_inputs=True)
        self.assertEqual(self.engine.db.evidence('case-one'), [])

    def test_tampered_case_custody_blocks_analysis(self):
        first = self.analyze('objective', {'objective': 'Review public example.com.'})
        preserved = Path(self.engine.db.evidence('case-one')[0]['path'])
        preserved.write_bytes(b'tampered')
        with self.assertRaises(PolicyError):
            self.analyze('objective', {'objective': 'Another local objective.'})
        self.assertEqual(len(self.engine.db.evidence('case-one')), 1)


class ArchiveStaticContractTests(unittest.TestCase):
    def test_all_curriculum_files_are_listed_with_valid_asset_ids(self):
        root = Path(__file__).resolve().parents[1] / 'public/academy/modules'
        index = json.loads((root / 'index.json').read_text())
        self.assertEqual({item['id'] for item in index}, {p.stem for p in root.glob('*.json') if p.stem != 'index'})
        self.assertEqual(len(index), 19)

    def test_csp_is_preserved_and_imported_servers_not_routed(self):
        root = Path(__file__).resolve().parents[1]
        config = json.loads((root / 'vercel.json').read_text())
        csp = next(h['value'] for block in config['headers'] for h in block['headers'] if h['key'] == 'Content-Security-Policy')
        self.assertNotIn('unsafe-inline', csp)
        self.assertNotIn('unsafe-eval', csp)
        self.assertTrue(all('packages/archive_sources' not in r['destination'] for r in config['rewrites']))
        for p in [root / 'public/directory/index.html', *(root / 'public/academy').glob('*.html')]:
            html = p.read_text()
            self.assertNotIn('<script>', html)
            self.assertNotIn('onclick=', html)
            self.assertNotIn('cdn.tailwindcss.com', html)


if __name__ == '__main__':
    unittest.main()
