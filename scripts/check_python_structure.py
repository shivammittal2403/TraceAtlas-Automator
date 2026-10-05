"""Reject syntax errors and definitions silently replaced in the same scope."""
from __future__ import annotations

import ast
from pathlib import Path
import sys
import tokenize

ROOT = Path(__file__).resolve().parents[1]
DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def check_source(source: str, filename: str = '<source>') -> list[str]:
    try:
        compile(source, filename, 'exec')
        tree = ast.parse(source, filename)
    except SyntaxError as exc:
        return [f'{filename}:{exc.lineno}: {exc.msg}']
    errors = []
    for scope in ast.walk(tree):
        if not isinstance(scope, (ast.Module, *DEFINITIONS)):
            continue
        seen = {}
        for node in scope.body:
            if not isinstance(node, DEFINITIONS):
                continue
            decorators = getattr(node, 'decorator_list', [])
            overload = any((isinstance(d, ast.Name) and d.id == 'overload') or
                           (isinstance(d, ast.Attribute) and d.attr == 'overload')
                           for d in decorators)
            if overload:
                continue
            previous = seen.get(node.name)
            property_update = previous is not None and any(
                isinstance(d, ast.Attribute) and d.attr in {'setter', 'deleter'} and
                isinstance(d.value, ast.Name) and d.value.id == node.name
                for d in decorators) and any(
                    (isinstance(d, ast.Name) and d.id == 'property') or
                    (isinstance(d, ast.Attribute) and d.attr in {'setter', 'deleter'} and
                     isinstance(d.value, ast.Name) and d.value.id == node.name)
                    for d in getattr(previous, 'decorator_list', []))
            if previous and not property_update:
                errors.append(f'{filename}:{node.lineno}: duplicate {node.name!r} '
                              f'(first defined at line {previous.lineno})')
            seen[node.name] = node
    return errors


def main() -> int:
    paths = [ROOT / 'vercel_control.py']
    for folder in ('src', 'tests', 'api', 'scripts'):
        paths.extend(sorted((ROOT / folder).rglob('*.py')))
    errors = []
    for path in paths:
        with tokenize.open(path) as handle:
            errors.extend(check_source(handle.read(), str(path.relative_to(ROOT))))
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print(f'Python structure: {len(paths)} files checked; no duplicate definitions or syntax errors')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
