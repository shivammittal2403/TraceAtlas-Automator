"""Produce repeatable local-only release evidence; never claims live readiness."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--browser', action='store_true', help='Requires pnpm install and Playwright Chromium')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    node = shutil.which('node')
    if not node:
        raise RuntimeError('Node.js is required')
    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'src'), 'PYTHON': sys.executable}
    commands = [
        ('python-regressions', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-q']),
        ('compile', [sys.executable, '-m', 'compileall', '-q', 'src', 'tests', 'api', 'vercel_control.py', 'scripts']),
        ('graph-and-target-tests', [node, '--test', 'tests/test_graph_model.cjs', 'tests/test_target_validation.cjs']),
        ('database-regressions', [node, '--test', 'tests/test_database.mjs']),
        ('secret-scan', [sys.executable, 'scripts/check_secrets.py']),
    ]
    for name in ['app', 'employee', 'graph-model', 'target-validation']:
        commands.append((f'javascript-syntax-{name}', [node, '--check', f'public/{name}.js']))
    if args.browser:
        commands.append(('browser-fixtures', [node, 'tests/test_employee_ui.cjs']))
    checks = []
    for label, command in commands:
        print(f'Checking {label}', flush=True)
        started = time.monotonic()
        run = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=180)
        log = run.stdout + '\n' + run.stderr
        (args.output / (label + '.log')).write_text(log, encoding='utf-8')
        exclusions = ['Bash syntax test skipped: Bash unavailable'] if label == 'python-regressions' and 'skipped=1' in log else []
        checks.append({'check': label, 'command': command, 'exit_code': run.returncode,
                       'seconds': round(time.monotonic() - started, 3), 'exclusions': exclusions,
                       'log': label + '.log'})
    sys.path.insert(0, str(ROOT / 'src'))
    from traceatlas.db import CaseDB
    from traceatlas.evidence import EvidenceStore
    from traceatlas.intelligence.hub import IntelligenceHub
    from traceatlas.benchmark import GuardrailBenchmark
    from traceatlas.operations import SQLiteRestoreDrill
    with tempfile.TemporaryDirectory(prefix='traceatlas-delivery-') as temp:
        root = Path(temp)
        db = CaseDB(root / 'cases.db')
        try:
            db.create_case('delivery-fixture', 'Synthetic delivery proof', 'Offline fixtures; no provider request')
            raw = b'{"ip":"8.8.8.8","ports":[443],"vulns":[],"tags":["synthetic-fixture"]}'
            IntelligenceHub(db, root, requester=lambda *_: (200, raw)).collect(
                'delivery-fixture', 'internetdb', 'ip', '8.8.8.8', authorized=True, owned_asset=True)
            store = EvidenceStore(root, db, 'delivery-fixture')
            bundle = args.output / 'synthetic-evidence.zip'
            receipt = store.export_bundle(bundle)
            receipt['verified'] = EvidenceStore.verify_bundle(bundle)
            (args.output / 'evidence-export.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
            restore = SQLiteRestoreDrill(db).run(args.output / 'sqlite-restore')
        finally:
            db.close()
    benchmark = GuardrailBenchmark().write(args.output / 'guardrail-benchmark.json')
    summary = {'scope': 'local-fixture-verification-only', 'python': platform.python_version(),
               'platform': platform.platform(), 'checks': checks,
               'evidence_bundle_verified': receipt['verified'], 'sqlite_restore_status': restore['status'],
               'guardrail_benchmark': benchmark, 'live_verified_connectors_this_run': 0,
               'production_proven': False, 'nine_of_ten_accepted': False,
               'limitations': ['Synthetic auth claims in one PostgreSQL session; not live JWT or storage testing.',
                               'No multi-session race/load proof.', 'No production deployment or external provider queries.',
                               'Guardrail fixtures are not a held-out analyst or Maltego benchmark.']}
    (args.output / 'verification.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    files = {p.relative_to(args.output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in args.output.rglob('*') if p.is_file()}
    (args.output / 'SHA256SUMS.json').write_text(json.dumps(files, indent=2), encoding='utf-8')
    passed = (all(check['exit_code'] == 0 for check in checks) and receipt['verified']
              and restore['status'] == 'pass' and benchmark['status'] == 'pass')
    print(json.dumps({'passed_local_checks': passed, 'output': str(args.output), 'checks': len(checks)}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
