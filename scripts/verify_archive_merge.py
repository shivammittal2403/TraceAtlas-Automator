"""Verify every retained archive byte and adapted runtime hash; no execution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT / 'docs/archive_merge_manifest.json').read_text())
    errors = []
    counts = {'preserved_files': 0, 'namespaced_python': 0, 'excluded_generated': 0}
    for archive in manifest['archives']:
        counts['excluded_generated'] += len(archive['excluded'])
        for row in archive['files']:
            counts['preserved_files'] += 1
            for key, hash_key in (('preserved_path', 'source_sha256'), ('runtime_path', 'runtime_sha256')):
                if not row.get(key):
                    continue
                path = (ROOT / row[key]).resolve()
                if not path.is_relative_to(ROOT) or not path.is_file():
                    errors.append(row[key] + ': absent/unsafe path')
                    continue
                if hashlib.sha256(path.read_bytes()).hexdigest() != row[hash_key]:
                    errors.append(row[key] + ': hash mismatch')
                if key == 'preserved_path' and Path(row['path']).suffix in {
                        '.py', '.pyw', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
                        '.html', '.sh', '.ps1', '.bat', '.cmd'} and path.suffix != '.source':
                    errors.append(row[key] + ': executable snapshot must be inert')
            if row.get('runtime_path'):
                counts['namespaced_python'] += 1
    print(json.dumps({'schema': 'traceatlas.archive.integrity.v1', 'passed': not errors,
                      **counts, 'errors': errors}, sort_keys=True))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
