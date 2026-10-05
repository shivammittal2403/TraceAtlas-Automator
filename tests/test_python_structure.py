"""Prevent concatenated modules and silently overridden regression tests."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('check_python_structure',
    Path(__file__).resolve().parents[1] / 'scripts/check_python_structure.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PythonStructureTests(unittest.TestCase):
    def test_duplicate_classes(self):
        self.assertEqual(len(checker.check_source('class A: pass\nclass A: pass\n')), 1)

    def test_duplicate_test_methods(self):
        self.assertEqual(len(checker.check_source(
            'class Tests:\n def test_a(self): pass\n def test_a(self): pass\n')), 1)

    def test_async_definition_replaces_sync(self):
        self.assertEqual(len(checker.check_source('def f(): pass\nasync def f(): pass\n')), 1)

    def test_mid_file_future_import(self):
        self.assertEqual(len(checker.check_source('x=1\nfrom __future__ import annotations\n')), 1)

    def test_independent_scopes(self):
        self.assertEqual(checker.check_source('class A:\n def f(self): pass\nclass B:\n def f(self): pass\n'), [])

    def test_property_accessors(self):
        self.assertEqual(checker.check_source(
            'class A:\n @property\n def x(self): pass\n @x.setter\n def x(self,v): pass\n'
            ' @x.deleter\n def x(self): pass\n'), [])

    def test_overloads(self):
        self.assertEqual(checker.check_source(
            '@overload\ndef f(x: int): ...\n@typing.overload\ndef f(x: str): ...\n'
            'def f(x): return x\n'), [])

    def test_duplicate_property_getters_rejected(self):
        self.assertEqual(len(checker.check_source(
            'class A:\n @property\n def x(self): pass\n @property\n def x(self): pass\n')), 1)


if __name__ == '__main__':
    unittest.main()
