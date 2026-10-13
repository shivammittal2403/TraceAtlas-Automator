#!/usr/bin/env python3
"""Verify and safely reconstruct the TraceAtlas 136-section repaired Python package.

The tracked base64 payload is a lossless, compressed transport archive, not code
executed during installation. User explicitly selects `run` to execute fixtures.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent
PAYLOAD = ROOT / 'payload'
NUM_PARTS = 81
BUNDLE_BYTES = 3_939_424
BUNDLE_SHA256 = 'a26b7730cd17748866024e03304c0560f386addf50ec58c4ba333bd3e2ff686b'
ORIGINAL_SHA256 = '5a5f51623f7ad13b0a40b12dcb05110da20262c1ae9d387bed290cd44555add5'
MAX_EXTRACTED_BYTES = 40_000_000
EXPECTED_FILES = 182


def verified_archive() -> bytes:
    expected = [PAYLOAD / f'part_{i:03d}.b64' for i in range(1, NUM_PARTS + 1)]
    actual = sorted(PAYLOAD.glob('part_*.b64'))
    if actual != expected:
        raise ValueError('Missing/extra source parts, refusing incomplete package')
    digest = hashlib.sha256()
    chunks = []
    count = 0
    for path in expected:
        encoded = path.read_text('ascii').strip()
        raw = base64.b64decode(encoded, validate=True)
        chunks.append(raw)
        digest.update(raw)
        count += len(raw)
    if count != BUNDLE_BYTES or digest.hexdigest() != BUNDLE_SHA256:
        raise ValueError('Bundle size/SHA-256 mismatch; extraction blocked')
    return b''.join(chunks)


def inventory(archive: bytes):
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:xz') as tar:
        members = tar.getmembers()
        if len(members) != EXPECTED_FILES:
            raise ValueError('Unexpected archive member count')
        total = 0
        names = set()
        for member in members:
            name = PurePosixPath(member.name)
            if (not member.isfile() or name.is_absolute() or '..' in name.parts
                    or str(name) in ('', '.') or '\\' in member.name
                    or member.name in names):
                raise ValueError('Unsafe or repeated archive member')
            names.add(member.name)
            total += member.size
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError('Decompressed size exceeds approved package limit')
        if 'archive/OSINT PYTHON.py' not in names or 'manifest.json' not in names:
            raise ValueError('Mandatory original-source or manifest missing')
        original = tar.extractfile('archive/OSINT PYTHON.py')
        if original is None or hashlib.sha256(original.read()).hexdigest() != ORIGINAL_SHA256:
            raise ValueError('Original uploaded source checksum mismatch')
        m = tar.extractfile('manifest.json')
        if m is None:
            raise ValueError('Missing manifest')
        manifest = json.load(m)
        if len(manifest.get('modules', [])) != 136:
            raise ValueError('Module inventory must contain 136 recovered sections')
        return {'files':len(members), 'uncompressed_bytes':total, 'module_sections':136, 'archive_sha256':BUNDLE_SHA256, 'original_sha256':ORIGINAL_SHA256}


def extract_to(directory: Path, archive: bytes):
    inventory(archive)
    directory = directory.expanduser().resolve()
    if directory.exists():
        raise FileExistsError(f'Refusing to overwrite: {directory}')
    directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.traceatlas-repair-',dir=directory.parent))
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:xz') as tar:
            for member in tar.getmembers():
                target = staging.joinpath(*PurePosixPath(member.name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError('Cannot read archive member')
                with source, target.open('xb') as dest:
                    shutil.copyfileobj(source, dest)
        digest = hashlib.sha256((staging / 'archive' / 'OSINT PYTHON.py').read_bytes()).hexdigest()
        if digest != ORIGINAL_SHA256:
            raise ValueError('Extracted original source hash mismatch')
        os.replace(staging, directory)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return directory


def main(argv=None):
    parser = argparse.ArgumentParser(description='TraceAtlas 136-section SHA-256 verified recovery package')
    parser.add_argument('action', choices=['verify','extract','run'])
    parser.add_argument('--to', default='TraceAtlas_OSINT_Repaired', help='Destination directory for extract')
    args, forwarded = parser.parse_known_args(argv)
    try:
        data = verified_archive()
        if args.action == 'verify':
            print(json.dumps(inventory(data),indent=2))
            return 0
        if args.action == 'extract':
            dest = extract_to(Path(args.to), data)
            print(f'Installed verified repaired source at {dest}')
            return 0
        if forwarded and forwarded[0] == '--':
            forwarded = forwarded[1:]
        if not forwarded:
            forwarded = ['verify']
        with tempfile.TemporaryDirectory(prefix='traceatlas-repaired-exec-') as tmp:
            restored = extract_to(Path(tmp) / 'project', data)
            return subprocess.call([sys.executable, str(restored/'traceatlas.py'), *forwarded])
    except (ValueError, OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(f'TraceAtlas recovery: {exc}',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
