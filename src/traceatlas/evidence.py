from __future__ import annotations

import hashlib
import json
import mimetypes
import shutil
import zipfile
from pathlib import Path
from typing import Any

from .db import CaseDB
from .models import utc_now


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class EvidenceStore:
    def __init__(self, root: Path, db: CaseDB, case_id: str):
        if not case_id or Path(case_id).name != case_id or case_id in {'.', '..'}:
            raise ValueError('Invalid evidence case identifier')
        self.root = root / "evidence" / case_id
        if not db.get_case(case_id) or not self.root.resolve().is_relative_to((root / "evidence").resolve()):
            raise ValueError("Evidence requires an existing case within the workspace")
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = db
        self.case_id = case_id
        self.ledger = self.root / "ledger.jsonl"

    def preserve_file(self, source_path: Path, source: str) -> dict[str, Any]:
        digest = sha256_file(source_path)
        destination = self.root / f"{digest[:16]}_{source_path.name}"
        if not destination.exists():
            shutil.copy2(source_path, destination)
        if sha256_file(destination) != digest:
            raise ValueError("Preserved evidence hash mismatch")
        media_type = mimetypes.guess_type(source_path.name)[0]
        self.db.add_evidence(
            self.case_id, digest, str(destination), source,
            destination.stat().st_size, media_type,
        )
        record = {
            "action": "preserve", "sha256": digest, "path": str(destination),
            "source": source, "timestamp": utc_now(),
        }
        self._append_ledger(record)
        return record

    def _append_ledger(self, record: dict[str, Any]) -> None:
        previous = "0" * 64
        if self.ledger.exists():
            lines = self.ledger.read_text(encoding="utf-8").splitlines()
            if lines:
                previous = json.loads(lines[-1])["entry_hash"]
        body = {**record, "previous_hash": previous}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        body["entry_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.ledger.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True) + "\n")

    def verify_ledger(self) -> tuple[bool, int]:
        previous = "0" * 64
        count = 0
        if not self.ledger.exists():
            return not bool(self.db.evidence(self.case_id)), 0
        verified_hashes = set()
        try:
            for line in self.ledger.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                claimed = entry.pop("entry_hash")
                if entry.get("previous_hash") != previous:
                    return False, count
                canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                if hashlib.sha256(canonical.encode()).hexdigest() != claimed:
                    return False, count
                if entry.get("action") == "preserve":
                    path = Path(entry["path"]).resolve()
                    if not path.is_relative_to(self.root.resolve()) or sha256_file(path) != entry["sha256"]:
                        return False, count
                    verified_hashes.add(entry['sha256'])
                previous = claimed
                count += 1
        except (OSError, ValueError, KeyError, TypeError):
            return False, count
        if verified_hashes != {row['sha256'] for row in self.db.evidence(self.case_id)}:
            return False, count
        return True, count

    def export_bundle(self, output: Path) -> dict[str, Any]:
        """Portable hash-verified ZIP. Hashes prove integrity, not authorship."""
        valid, count = self.verify_ledger()
        if not valid:
            raise ValueError("Evidence verification failed; export refused")
        if not count:
            raise ValueError("No preserved evidence to export")
        entries = [json.loads(line) for line in self.ledger.read_text(encoding='utf-8').splitlines()]
        blobs = {}
        observations = []
        total_bytes = 0
        for entry in entries:
            if entry.get('action') != 'preserve':
                continue
            digest = entry['sha256']
            name = 'evidence/' + digest
            if name not in blobs:
                total_bytes += Path(entry['path']).stat().st_size
                if total_bytes > 120 * 1024 * 1024:
                    raise ValueError('Evidence bundle exceeds 120 MiB export budget')
            # Re-read and hash the exact bytes placed into the archive (TOCTOU).
            data = Path(entry['path']).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('Evidence changed during export')
            blobs[name] = data
            observations.append({k: entry[k] for k in ('sha256', 'source', 'timestamp')})
        manifest = {'schema': 'traceatlas-evidence-export/v1', 'case_id': self.case_id,
                    'created_at': utc_now(), 'integrity': 'sha256-not-a-digital-signature',
                    'ledger_head': entries[-1]['entry_hash'], 'observations': observations,
                    'files': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                              for name, data in sorted(blobs.items())]}
        encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('manifest.json', encoded)
            archive.writestr('manifest.sha256', hashlib.sha256(encoded).hexdigest())
            for name, data in blobs.items():
                archive.writestr(name, data)
        return {'path': str(output), 'sha256': sha256_file(output), 'files': len(blobs), 'ledger_entries': count}

    @staticmethod
    def verify_bundle(path: Path) -> bool:
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                if len(names) != len(set(names)) or sum(i.file_size for i in archive.infolist()) > 128 * 1024 * 1024:
                    return False
                encoded = archive.read('manifest.json')
                if hashlib.sha256(encoded).hexdigest() != archive.read('manifest.sha256').decode('ascii'):
                    return False
                manifest = json.loads(encoded)
                if manifest['schema'] != 'traceatlas-evidence-export/v1':
                    return False
                if not isinstance(manifest.get('case_id'), str) or not manifest.get('files'):
                    return False
                expected = {'manifest.json', 'manifest.sha256'}
                for item in manifest['files']:
                    name = item['path']
                    if name != 'evidence/' + item['sha256'] or name in expected:
                        return False
                    data = archive.read(name)
                    if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                        return False
                    expected.add(name)
                if not manifest.get('observations') or any('evidence/' + row['sha256'] not in expected for row in manifest['observations']):
                    return False
                return set(names) == expected
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
            return False

