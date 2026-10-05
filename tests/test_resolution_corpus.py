import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from traceatlas.cli import main
from traceatlas.db import CaseDB
from traceatlas.evidence import EvidenceStore
from traceatlas.policy import PolicyError
from traceatlas.resolution_corpus import evaluate_preserved_corpus


class PreservedResolutionCorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = CaseDB(self.root / 'traceatlas.db')
        self.db.create_case('eval-case', 'Evaluation', 'Synthetic evaluation only')
        self.store = EvidenceStore(self.root, self.db, 'eval-case', use_environment_anchor=False)
        original = Path(__file__).parents[1] / 'src/traceatlas/benchmark_data/entity_resolution_synthetic.json'
        self.corpus = {'schema': 'traceatlas-reviewed-er-corpus/v1', 'dataset_id': 'fixture-v1',
                       'dataset_kind': 'synthetic', 'cases': json.loads(original.read_text())['cases']}
        review = self.preserve({'review': 'synthetic authorization/privacy/labels fixture'})
        self.protocol = {'schema': 'traceatlas-er-protocol/v1', 'corpus_sha256': self.digest(self.corpus),
                         'purpose': 'Synthetic regression evaluation', 'split': 'held-out', 'threshold': 0.72,
                         'minimum_cases': 6, 'minimum_precision': 0.9, 'minimum_recall': 0.9,
                         'maximum_false_positive_rate': 0.01,
                         'authority_ref': review, 'privacy_review_ref': review, 'label_review_ref': review}

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    @staticmethod
    def encoded(value):
        return json.dumps(value, sort_keys=True).encode()

    def digest(self, value):
        return hashlib.sha256(self.encoded(value)).hexdigest()

    def preserve(self, value):
        p = self.root / 'input.json'
        p.write_bytes(self.encoded(value))
        return self.store.preserve_file(p, 'synthetic-evaluation')['sha256']

    def inputs(self, corpus=None, protocol=None):
        corpus = self.corpus if corpus is None else corpus
        protocol = copy.deepcopy(self.protocol if protocol is None else protocol)
        protocol['corpus_sha256'] = self.digest(corpus)
        protocol_ref = self.preserve(protocol)
        return self.preserve(corpus), protocol_ref

    def evaluate(self, **kwargs):
        return evaluate_preserved_corpus(self.store, *self.inputs(**kwargs), authorized=True)

    def test_preserved_protocol_metrics_report_and_no_automatic_merge(self):
        result = self.evaluate()
        self.assertEqual(result['pair_metrics']['precision'], 0.8)
        self.assertEqual(result['metric_denominators'], {'precision': 5, 'recall': 4, 'false_positive_rate': 20})
        self.assertFalse(result['protocol_thresholds_met'])
        self.assertFalse(result['enterprise_gate_passed'])
        self.assertIsNone(result['false_merge_rate'])
        self.assertNotIn('case_results', result)
        self.assertIn(result['report_evidence_sha256'], {r['sha256'] for r in self.db.evidence('eval-case')})
        self.assertEqual(self.db.resolution_candidates('eval-case'), [])
        self.assertTrue(self.store.verify_ledger()[0])

    def test_threshold_pass_never_grants_enterprise_qualification(self):
        protocol = {**self.protocol, 'minimum_precision': 0.8, 'maximum_false_positive_rate': 0.05}
        result = self.evaluate(protocol=protocol)
        self.assertTrue(result['protocol_thresholds_met'])
        self.assertFalse(result['enterprise_gate_passed'])

    def test_authorization_required_before_read_or_write(self):
        before = self.db.evidence('eval-case')
        with self.assertRaisesRegex(PolicyError, 'authorization'):
            evaluate_preserved_corpus(self.store, 'a' * 64, 'b' * 64)
        self.assertEqual(self.db.evidence('eval-case'), before)

    def test_protocol_captured_after_corpus_is_rejected(self):
        corpus_ref = self.preserve(self.corpus)
        protocol_ref = self.preserve(self.protocol)
        with self.assertRaisesRegex(PolicyError, 'before'):
            evaluate_preserved_corpus(self.store, corpus_ref, protocol_ref, authorized=True)

    def test_missing_and_cross_case_review_artifacts_rejected(self):
        self.db.create_case('other-case', 'Other', 'Synthetic')
        other = EvidenceStore(self.root, self.db, 'other-case', use_environment_anchor=False)
        p = self.root / 'other.json'
        p.write_text('{"review":"other case"}')
        ref = other.preserve_file(p, 'fixture')['sha256']
        for value in ('a' * 64, ref):
            with self.subTest(value=value), self.assertRaisesRegex(PolicyError, 'this case'):
                self.evaluate(protocol={**self.protocol, 'privacy_review_ref': value})

    def test_threshold_and_schema_validation(self):
        for field, value in [('threshold', True), ('minimum_precision', float('nan')),
                             ('minimum_cases', 0), ('split', 'training')]:
            with self.subTest(field=field), self.assertRaises(PolicyError):
                self.evaluate(protocol={**self.protocol, field: value})

    def test_unknown_sensitive_and_nested_fields_rejected(self):
        for field, value in [('email', 'private@example.test'), ('unused', 'unknown'),
                             ('name', {'nested': 'bad'}), ('name', 'x' * 501)]:
            corpus = copy.deepcopy(self.corpus)
            corpus['cases'][0]['query'][field] = value
            with self.subTest(field=field), self.assertRaises(PolicyError):
                self.evaluate(corpus=corpus)

    def test_mutated_preserved_corpus_rejected(self):
        corpus_ref, protocol_ref = self.inputs()
        row = next(r for r in self.db.evidence('eval-case') if r['sha256'] == corpus_ref)
        Path(row['path']).write_text('{}')
        with self.assertRaisesRegex(PolicyError, 'custody'):
            evaluate_preserved_corpus(self.store, corpus_ref, protocol_ref, authorized=True)

    def test_zero_denominator_does_not_pass_threshold(self):
        corpus = copy.deepcopy(self.corpus)
        for case in corpus['cases']:
            case['expected_match_id'] = None
            for candidate in case['candidates']:
                candidate['is_match'] = False
        result = self.evaluate(corpus=corpus)
        self.assertIsNone(result['pair_metrics']['recall'])
        self.assertFalse(result['protocol_threshold_checks']['minimum_recall'])

    def test_cli_evaluates_preserved_case_inputs(self):
        corpus_ref, protocol_ref = self.inputs()
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(['--workspace', str(self.root), 'resolve', 'evaluate', '--case', 'eval-case',
                           '--corpus-sha256', corpus_ref, '--protocol-sha256', protocol_ref, '--authorized'])
        self.assertEqual(status, 2)
        self.assertFalse(json.loads(output.getvalue())['enterprise_gate_passed'])

    def test_duplicate_json_keys_are_rejected(self):
        p = self.root / 'duplicates.json'
        p.write_bytes(b'{"schema":"one","schema":"two"}')
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        protocol_ref = self.preserve({**self.protocol, 'corpus_sha256': digest})
        corpus_ref = self.store.preserve_file(p, 'synthetic')['sha256']
        with self.assertRaises(PolicyError):
            evaluate_preserved_corpus(self.store, corpus_ref, protocol_ref, authorized=True)

    def test_protocol_cannot_be_reused_for_different_corpus(self):
        protocol_ref = self.preserve(self.protocol)
        corpus = {**self.corpus, 'dataset_id': 'changed-v2'}
        corpus_ref = self.preserve(corpus)
        with self.assertRaisesRegex(PolicyError, 'bind'):
            evaluate_preserved_corpus(self.store, corpus_ref, protocol_ref, authorized=True)

    def test_report_is_repeatable_and_never_contains_record_values(self):
        refs = self.inputs()
        first = evaluate_preserved_corpus(self.store, *refs, authorized=True)
        second = evaluate_preserved_corpus(self.store, *refs, authorized=True)
        self.assertEqual(first, second)
        encoded = json.dumps(first)
        self.assertNotIn(self.corpus['cases'][0]['query']['name'], encoded)

    def test_preserved_artifact_size_bound(self):
        p = self.root / 'oversized.txt'
        p.write_bytes(b'x' * (2 * 1024 * 1024 + 1))
        oversized = self.store.preserve_file(p, 'synthetic')['sha256']
        with self.assertRaisesRegex(PolicyError, 'size'):
            self.evaluate(protocol={**self.protocol, 'label_review_ref': oversized})
