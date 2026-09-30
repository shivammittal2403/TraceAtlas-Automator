"""Package the current local source without Git metadata, secrets or dependencies."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'GIT_CONFIG_COUNT': '0'}
    def git(*arguments):
        return subprocess.check_output(['git', '-c', f'safe.directory={ROOT.as_posix()}', *arguments], cwd=ROOT, env=env)
    paths = git('ls-files', '--cached', '--others', '--exclude-standard', '-z').decode().split('\0')
    paths = sorted(set(p for p in paths if p and (ROOT / p).is_file()))
    for name in paths:
        if any(part in {'.git', 'node_modules', '.temp', '.venv', '__pycache__'} for part in Path(name).parts):
            raise ValueError(f'Unexpected generated dependency in source selection: {name}')
        if Path(name).name.startswith('.env') and Path(name).name != '.env.example':
            raise ValueError('Environment file would enter source bundle')
        if not (ROOT / name).resolve().is_relative_to(ROOT.resolve()):
            raise ValueError('Source selection escapes repository')
    archive_path = args.output / 'TraceAtlas-source-checkpoint.zip'
    files = {}
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in paths:
            data = (ROOT / name).read_bytes()
            files[name] = hashlib.sha256(data).hexdigest()
            archive.writestr('TraceAtlas-Automator/' + name, data)
    manifest = {'base_head': git('rev-parse', 'HEAD').decode().strip(),
                'branch': git('branch', '--show-current').decode().strip(),
                'uncommitted': True, 'pushed': False, 'deployed': False,
                'source_zip': archive_path.name,
                'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                'files': files}
    (args.output / 'source-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    (args.output / 'tracked-changes.patch').write_bytes(git('diff', '--binary', 'HEAD'))
    (args.output / 'working-tree-status.txt').write_bytes(git('status', '--short'))
    # New files are in the source ZIP; tracked-changes.patch alone is not a complete delivery.
    print(json.dumps({'archive': str(archive_path), 'files': len(files), 'sha256': manifest['archive_sha256']}))


if __name__ == '__main__':
    main()
