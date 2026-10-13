#!/usr/bin/env python3
"""Passive static verification of TraceAtlas intelligence modules.

No module execution, network request, target contact, or external credentials.
Usage: python -m traceatlas.addons.intelligence_v1.modules._validate_modules
       python -m traceatlas.addons.intelligence_v1.modules._validate_modules --json
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
from typing import Any

MUTATING_METHODS = frozenset(("append", "extend", "add", "update", "insert"))

def check_module(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    def report(line: int, code: str, message: str) -> None:
        findings.append({"line": line, "code": code, "message": message})
    try:
        source = path.read_text(encoding="utf-8-sig")
        tree = ast.parse(source, filename=str(path))
        compile(tree, str(path), "exec")
    except (SyntaxError, UnicodeError) as exc:
        report(getattr(exc, "lineno", 0) or 0, "PYTHON_SYNTAX", str(exc))
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr in MUTATING_METHODS:
                    report(node.lineno, "METHOD_OVERWRITE", "Assignment to a mutating method instead of calling it: " + target.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and node.func.attr == "compile":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, (str, bytes)):
                    try:
                        re.compile(node.args[0].value)
                    except re.error as exc:
                        report(node.lineno, "BAD_REGEX", str(exc))
        if isinstance(node, ast.ClassDef):
            decorated = any(
                (isinstance(d, ast.Name) and d.id == "dataclass")
                or (isinstance(d, ast.Attribute) and d.attr == "dataclass")
                or (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == "dataclass")
                for d in node.decorator_list
            )
            if not decorated:
                continue
            has_default = False
            for item in node.body:
                if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                    continue
                if item.value is not None:
                    has_default = True
                elif has_default:
                    report(item.lineno, "DATACLASS_FIELD_ORDER", "Required field follows a default in " + node.name)
    return findings

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--path", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    root = args.path.resolve()
    modules = sorted(root.glob("*.py"))
    if not modules:
        parser.error("No Python modules found")
    errors = [
        {"file": path.name, **issue}
        for path in modules
        for issue in check_module(path)
    ]
    result = {
        "modules_scanned": len(modules),
        "error_count": len(errors),
        "errors": errors,
        "limitations": "Static syntax/regex/dataclass/method-assignment checks only; modules are not imported or functionally tested.",
    }
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"TraceAtlas intelligence modules: {len(modules)} scanned; {len(errors)} static issue(s)")
        for issue in errors:
            print(f"{issue['file']}:{issue['line']} {issue['code']}: {issue['message']}")
    return 1 if errors else 0

if __name__ == "__main__":
    raise SystemExit(main())
