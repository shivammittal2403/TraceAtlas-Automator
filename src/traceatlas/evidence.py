from __future__ import annotations

import hashlib
import json
import mimetypes
import shutil
import zipfile
from pathlib import Path
from typing import Any

from .db import CaseDB
from .evidence_anchor import LedgerAnchor, configured_ledger_anchor
from .models import utc_now


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class EvidenceStore:
    def __init__(self, root: Path, db: CaseDB, case_id: str, *,
                 anchor: LedgerAnchor | None = None, require_anchor: bool = False,
                 use_environment_anchor: bool = True):
        if not case_id or Path(case_id).name != case_id or case_id in {'.', '..'}:
            raise ValueError('Invalid evidence case identifier')
        self.root = root / "evidence" / case_id
        if not db.get_case(case_id) or not self.root.resolve().is_relative_to((root / "evidence").resolve()):
            raise ValueError("Evidence requires an existing case within the workspace")
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = db
        self.case_id = case_id
        self.ledger = self.root / "ledger.jsonl"
        if anchor is None and use_environment_anchor:
            configured, configured_required = configured_ledger_anchor(root)
            anchor = configured
            require_anchor = require_anchor or configured_required
        if require_anchor and anchor is None:
            raise ValueError("An independent ledger anchor is required")
        self.anchor = anchor
        self.require_anchor = require_anchor
        if self.anchor is not None:
            self.anchor.assert_external_to(root)

    def preserve_file(self, source_path: Path, source: str) -> dict[str, Any]:
        if self.anchor is not None and not self.verify_ledger()[0]:
            raise ValueError("Evidence ledger or external anchor verification failed")
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
        ledger_head, entry_count = self._append_ledger(record)
        if self.anchor is not None:
            # If publishing the receipt fails, preserve_file fails closed. The
            # captured bytes remain available for recovery, but verification
            # will reject the unanchored ledger until an operator repairs it.
            try:
                self.anchor.publish(self.case_id, entry_count, ledger_head)
            except Exception:
                raise ValueError("Evidence anchor publication failed; capture needs operator recovery") from None
        return record

    def _append_ledger(self, record: dict[str, Any]) -> tuple[str, int]:
        previous = "0" * 64
        count = 0
        if self.ledger.exists():
            lines = self.ledger.read_text(encoding="utf-8").splitlines()
            if lines:
                previous = json.loads(lines[-1])["entry_hash"]
                count = len(lines)
        body = {**record, "previous_hash": previous}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        body["entry_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.ledger.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, sort_keys=True) + "\n")
        return body["entry_hash"], count + 1

    def verify_ledger(self) -> tuple[bool, int]:
        return self._verify_ledger(check_anchor=True)

    def _verify_ledger(self, *, check_anchor: bool) -> tuple[bool, int]:
        previous = "0" * 64
        count = 0
        if not self.ledger.exists():
            if self.db.evidence(self.case_id):
                return False, 0
            # A missing local case history is not a new case if an independent
            # checkpoint already exists. Also fail closed on anchor outages.
            if check_anchor and self.anchor is not None:
                try:
                    return self.anchor.current_receipt(self.case_id) is None, 0
                except Exception:
                    return False, 0
            return not (check_anchor and self.require_anchor), 0
        verified_hashes = set()
        try:
            for line in self.ledger.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                if not isinstance(entry, dict):
                    return False, count
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
        if check_anchor and self.require_anchor and self.anchor is None:
            return False, count
        if check_anchor and self.anchor is not None:
            try:
                if not self.anchor.verify(self.case_id, count, previous):
                    return False, count
            except Exception:
                return False, count
        return True, count

    def bootstrap_anchor_after_review(self, review_id: str) -> dict[str, Any]:
        """Anchor an existing locally verified case after operator review.

        This explicit migration records its review reference in the custody
        chain. It cannot establish that an already rewritten local history is
        truthful; reviewers must reconcile the case with their trusted source.
        """
        if self.anchor is None:
            raise ValueError("An external ledger anchor is not configured")
        if not isinstance(review_id, str) or not review_id.strip() or len(review_id) > 200:
            raise ValueError("A bounded operator review reference is required")
        try:
            if self.anchor.current_receipt(self.case_id) is not None:
                raise ValueError("This case already has an anchor receipt")
        except ValueError:
            raise
        except Exception:
            raise ValueError("Existing external anchor state could not be checked") from None
        valid, count = self._verify_ledger(check_anchor=False)
        if not valid or count == 0:
            raise ValueError("Existing evidence ledger must verify before reviewed anchoring")
        ledger_head, entry_count = self._append_ledger({
            "action": "anchor_bootstrap",
            "review_id": review_id.strip(),
            "timestamp": utc_now(),
        })
        try:
            receipt = self.anchor.publish(self.case_id, entry_count, ledger_head)
            if not self.anchor.verify(self.case_id, entry_count, ledger_head, receipt):
                raise ValueError("New anchor receipt failed verification")
        except Exception:
            raise ValueError("Reviewed anchor bootstrap failed; operator recovery is required") from None
        if not self.verify_ledger()[0]:
            raise ValueError("Anchored ledger failed final verification")
        return receipt

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
        manifest = {'schema': 'traceatlas-evidence-export/v2', 'case_id': self.case_id,
                    'created_at': utc_now(), 'integrity': 'sha256-not-a-digital-signature',
                    'ledger_head': entries[-1]['entry_hash'], 'ledger_entries': count,
                    'observations': observations,
                    'files': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                              for name, data in sorted(blobs.items())]}
        if self.anchor is not None:
            try:
                manifest['anchor_receipt'] = self.anchor.current_receipt(self.case_id)
                receipt_valid = self.anchor.verify(
                    self.case_id, count, entries[-1]['entry_hash'], manifest['anchor_receipt'],
                )
            except Exception:
                receipt_valid = False
            if not receipt_valid:
                raise ValueError('Evidence anchor receipt changed during export')
        encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('manifest.json', encoded)
            archive.writestr('manifest.sha256', hashlib.sha256(encoded).hexdigest())
            # Preserve the exact hashed fields, including original custody paths.
            # Verifiers treat paths as opaque strings and never access them.
            archive.writestr('ledger.jsonl', ''.join(
                json.dumps(entry, sort_keys=True) + '\n' for entry in entries))
            for name, data in blobs.items():
                archive.writestr(name, data)
        return {'path': str(output), 'sha256': sha256_file(output), 'files': len(blobs), 'ledger_entries': count}

    @staticmethod
    def verify_bundle(path: Path, *, anchor: LedgerAnchor | None = None,
                      require_anchor: bool = False) -> bool:
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                if len(names) != len(set(names)) or sum(i.file_size for i in archive.infolist()) > 128 * 1024 * 1024:
                    return False
                encoded = archive.read('manifest.json')
                if hashlib.sha256(encoded).hexdigest() != archive.read('manifest.sha256').decode('ascii'):
                    return False
                manifest = json.loads(encoded)
                if not isinstance(manifest, dict) or manifest.get('schema') not in {
                    'traceatlas-evidence-export/v1', 'traceatlas-evidence-export/v2',
                }:
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
                receipt = manifest.get('anchor_receipt')
                if manifest['schema'] == 'traceatlas-evidence-export/v2':
                    expected.add('ledger.jsonl')
                    previous = '0' * 64
                    observations = []
                    lines = archive.read('ledger.jsonl').decode('utf-8').splitlines()
                    if type(manifest.get('ledger_entries')) is not int or not lines:
                        return False
                    for line in lines:
                        entry = json.loads(line)
                        if not isinstance(entry, dict):
                            return False
                        claimed = entry.pop('entry_hash')
                        if entry.get('previous_hash') != previous:
                            return False
                        canonical = json.dumps(entry, sort_keys=True, separators=(',', ':')).encode()
                        if hashlib.sha256(canonical).hexdigest() != claimed:
                            return False
                        if entry.get('action') == 'preserve':
                            observations.append({k: entry[k] for k in ('sha256', 'source', 'timestamp')})
                        elif entry.get('action') != 'anchor_bootstrap':
                            return False
                        previous = claimed
                    if (len(lines) != manifest['ledger_entries']
                            or previous != manifest.get('ledger_head')
                            or observations != manifest['observations']
                            or {row['sha256'] for row in observations}
                            != {item['sha256'] for item in manifest['files']}):
                        return False
                elif receipt is not None or require_anchor:
                    # V1 exports omitted custody records, so a signed head could
                    # not authenticate their payload or observation metadata.
                    return False
                if require_anchor and receipt is None:
                    return False
                if receipt is not None:
                    entry_count = manifest.get('ledger_entries')
                    if anchor is None or isinstance(entry_count, bool) or not isinstance(entry_count, int):
                        return False
                    try:
                        valid_receipt = anchor.verify(
                            manifest['case_id'], entry_count, manifest['ledger_head'], receipt,
                        )
                    except Exception:
                        return False
                    if not valid_receipt:
                        return False
                return set(names) == expected
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
            return False


