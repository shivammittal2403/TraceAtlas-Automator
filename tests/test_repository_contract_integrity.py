"""Prevent silent merge shadowing of security contracts and their regressions."""
import ast
import unittest
from collections import Counter
from pathlib import Path


class RepositoryContractIntegrityTests(unittest.TestCase):
    def test_critical_contracts_and_source_tests_have_no_duplicate_definitions(self):
        root = Path(__file__).resolve().parents[1]
        paths = ('src/traceatlas/source_maturity.py', 'src/traceatlas/workforce/source_registry.py',
                 'src/traceatlas/source_fabric/gateway.py', 'src/traceatlas/source_fabric/store.py',
                 'tests/test_source_fabric.py')
        for relative in paths:
            with self.subTest(path=relative):
                tree = ast.parse((root / relative).read_text(encoding='utf-8'))
                for scope in ast.walk(tree):
                    if not isinstance(scope, (ast.Module, ast.ClassDef)):
                        continue
                    names = Counter(n.name for n in scope.body
                                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
                    self.assertEqual({name: count for name, count in names.items() if count > 1}, {},
                                     relative + ': ' + getattr(scope, 'name', 'module'))

    def test_each_qualification_gate_has_a_specific_receipt_requirement(self):
        from traceatlas.source_maturity import SOURCE_QUALIFICATION_GATES
        from traceatlas.source_fabric.review_receipts import REQUIREMENTS
        self.assertEqual(set(REQUIREMENTS), SOURCE_QUALIFICATION_GATES)
        self.assertEqual(len(set(REQUIREMENTS.values())), len(REQUIREMENTS))
