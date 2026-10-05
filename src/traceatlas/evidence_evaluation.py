"""Controlled synthetic evaluation of evidence integrity and citation guards.

This measures whether the current local verification primitives accept or
reject known fixture mutations. It does not measure source truth or citation
semantic correctness.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable

from .db import CaseDB
from .evidence import EvidenceStore
from .evidence_anchor import HmacFileLedgerAnchor
from .intelligence.ai import ANALYSIS_CLAIM_FIELDS, ANALYSIS_KEYS, validate_ai_advisory


BENCHMARK_ID = "evidence-integrity-and-citation-guards"
BENCHMARK_VERSION = "1.1"


def _fixture(
    root: Path, case_id: str, *, anchor: HmacFileLedgerAnchor | None = None,
) -> tuple[CaseDB, EvidenceStore, Path]:
    db = CaseDB(root / f"{case_id}.sqlite3")
    db.create_case(case_id, "Synthetic evidence evaluation", "Controlled synthetic fixture only")
    store = EvidenceStore(
        root, db, case_id, anchor=anchor, require_anchor=anchor is not None,
        use_environment_anchor=False,
    )
    payload = root / f"{case_id}.txt"
    payload.write_bytes(b"TraceAtlas synthetic evidence fixture v1\n")
    store.preserve_file(payload, "synthetic-fixture")
    bundle = root / f"{case_id}.zip"
    store.export_bundle(bundle)
    return db, store, bundle


def _rewrite_zip(source: Path, destination: Path, transform: Callable[[zipfile.ZipFile, zipfile.ZipFile], None]) -> None:
    with zipfile.ZipFile(source, "r") as original, zipfile.ZipFile(destination, "w") as changed:
        transform(original, changed)


def _valid_advisory(evidence_id: str) -> dict[str, Any]:
    return {
        "executive_summary": "Synthetic observation for citation-contract evaluation.",
        "patterns": [{
            "statement": "Synthetic observation is present in the cited fixture.",
            "confidence": 80,
            "evidence_ids": [evidence_id],
        }],
        "contradictions": [], "risk_hypotheses": [],
        "corroboration_tasks": [], "limitations": [],
    }


def evaluate_evidence_integrity() -> dict[str, Any]:
    """Run deterministic accepted/rejected cases against real local guards."""
    scenarios = [
        ("ledger-valid", True, "ledger", "A preserved synthetic file verifies."),
        ("bundle-valid", True, "bundle", "An exported synthetic evidence bundle verifies."),
        ("local-rewrite-reanchored", False, "ledger", "A local attacker rewrites bytes, the SQLite digest, and the unanchored ledger consistently."),
        ("ledger-record-mutated", False, "ledger", "A custody record byte changed without a matching hash."),
        ("evidence-bytes-mutated", False, "ledger", "Preserved bytes changed after capture."),
        ("bundle-evidence-mutated", False, "bundle", "A bundle evidence member changed while its manifest stayed fixed."),
        ("bundle-unlisted-member", False, "bundle", "A bundle contains an unlisted member."),
        ("citation-known-id", True, "citation", "A claim cites an evidence identifier in its allowed set."),
        ("citation-unknown-id", False, "citation", "A claim cites an identifier absent from its allowed set."),
        ("anchored-ledger-valid", True, "anchored-ledger", "A clean ledger matches its external HMAC checkpoint."),
        ("anchored-local-rewrite", False, "anchored-ledger", "The same local rewrite cannot replace an independent HMAC checkpoint."),
        ("anchored-bundle-valid", True, "anchored-bundle", "An anchored bundle verifies with the external key provider."),
        ("anchor-receipt-mutated", False, "anchored-bundle", "A bundle receipt signature was altered."),
        ("required-anchor-missing", False, "required-bundle", "A legacy bundle fails when the verifier requires an anchor."),
        ("anchored-bundle-rewritten", False, "anchored-bundle", "Payload and manifest hashes are rewritten while retaining the signed ledger head."),
        ("anchored-provenance-rewritten", False, "anchored-bundle", "Observation provenance and manifest checksum are rewritten together."),
        ("anchored-history-deleted", False, "anchored-ledger", "Local ledger and evidence index are deleted while the external checkpoint survives."),
        ("anchored-history-rollback", False, "anchored-ledger", "Local history is restored to an older valid state after a newer checkpoint."),
    ]
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="traceatlas-evidence-eval-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        for case_id, expected, kind, description in scenarios:
            db = None
            try:
                anchored = kind.startswith("anchored-")
                anchor = HmacFileLedgerAnchor(
                    root / "external-anchor", workspace,
                    lambda: b"synthetic-only-test-key-32-bytes-minimum",
                    key_id="synthetic-test-v1",
                ) if anchored else None
                db, store, bundle = _fixture(workspace, case_id, anchor=anchor)
                if case_id in {"local-rewrite-reanchored", "anchored-local-rewrite"}:
                    row = db.evidence(case_id)[0]
                    evidence_path = Path(row["path"])
                    rewritten = b"attacker-controlled replacement evidence\n"
                    evidence_path.write_bytes(rewritten)
                    digest = hashlib.sha256(rewritten).hexdigest()
                    db.conn.execute(
                        "UPDATE evidence SET sha256=?, size=? WHERE case_id=? AND sha256=?",
                        (digest, len(rewritten), case_id, row["sha256"]),
                    )
                    db.conn.commit()
                    entry = json.loads(store.ledger.read_text(encoding="utf-8").splitlines()[0])
                    entry["sha256"] = digest
                    entry.pop("entry_hash")
                    entry["entry_hash"] = hashlib.sha256(
                        json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest()
                    store.ledger.write_text(json.dumps(entry, sort_keys=True) + "\n", encoding="utf-8")
                    observed = store.verify_ledger()[0]
                    row_result = {
                        "id": case_id, "kind": kind, "expected_accept": expected,
                        "accepted": observed, "pass": observed is expected,
                        "description": description,
                    }
                    if case_id == "local-rewrite-reanchored":
                        row_result["limitation_demonstrated"] = observed is True
                    rows.append(row_result)
                    continue
                elif case_id == "ledger-record-mutated":
                    raw = store.ledger.read_bytes()
                    store.ledger.write_bytes(raw.replace(b"synthetic-fixture", b"synthetic-fixturE", 1))
                    observed = store.verify_ledger()[0]
                elif case_id == "evidence-bytes-mutated":
                    evidence_path = Path(db.evidence(case_id)[0]["path"])
                    evidence_path.write_bytes(b"tampered synthetic evidence\n")
                    observed = store.verify_ledger()[0]
                elif case_id == "bundle-evidence-mutated":
                    mutated = root / "mutation-bundle-evidence-mutated.zip"

                    def mutate_evidence(original: zipfile.ZipFile, changed: zipfile.ZipFile) -> None:
                        for name in original.namelist():
                            data = original.read(name)
                            changed.writestr(name, b"tampered" if name.startswith("evidence/") else data)

                    _rewrite_zip(bundle, mutated, mutate_evidence)
                    observed = EvidenceStore.verify_bundle(mutated)
                elif case_id == "bundle-unlisted-member":
                    mutated = root / "mutation-bundle-unlisted-member.zip"

                    def add_unlisted(original: zipfile.ZipFile, changed: zipfile.ZipFile) -> None:
                        for name in original.namelist():
                            changed.writestr(name, original.read(name))
                        changed.writestr("unlisted.txt", b"extra")

                    _rewrite_zip(bundle, mutated, add_unlisted)
                    observed = EvidenceStore.verify_bundle(mutated)
                elif case_id == "anchored-ledger-valid":
                    observed = store.verify_ledger()[0]
                elif case_id == "anchored-history-deleted":
                    store.ledger.unlink()
                    db.conn.execute("DELETE FROM evidence WHERE case_id=?", (case_id,))
                    db.conn.commit()
                    observed = store.verify_ledger()[0]
                elif case_id == "anchored-history-rollback":
                    old_history = store.ledger.read_bytes()
                    store.preserve_file(Path(db.evidence(case_id)[0]['path']), 'second acquisition')
                    store.ledger.write_bytes(old_history)
                    observed = store.verify_ledger()[0]
                elif case_id in {"anchored-bundle-rewritten", "anchored-provenance-rewritten"}:
                    mutated = root / ("mutation-" + case_id + ".zip")

                    def rewrite_manifest(original: zipfile.ZipFile, changed: zipfile.ZipFile) -> None:
                        entries = {name: original.read(name) for name in original.namelist()}
                        manifest = json.loads(entries['manifest.json'])
                        if case_id == 'anchored-bundle-rewritten':
                            data = b'rewritten bundle bytes'
                            digest = hashlib.sha256(data).hexdigest()
                            entries.pop(manifest['files'][0]['path'])
                            entries['evidence/' + digest] = data
                            manifest['files'][0] = {'path': 'evidence/' + digest, 'sha256': digest, 'bytes': len(data)}
                            manifest['observations'][0]['sha256'] = digest
                        else:
                            manifest['observations'][0]['source'] = 'forged provenance'
                        encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
                        entries['manifest.json'] = encoded
                        entries['manifest.sha256'] = hashlib.sha256(encoded).hexdigest().encode()
                        for name, data in entries.items():
                            changed.writestr(name, data)

                    _rewrite_zip(bundle, mutated, rewrite_manifest)
                    observed = EvidenceStore.verify_bundle(mutated, anchor=anchor, require_anchor=True)
                elif case_id == "anchored-bundle-valid":
                    observed = EvidenceStore.verify_bundle(bundle, anchor=anchor, require_anchor=True)
                elif case_id == "anchor-receipt-mutated":
                    mutated = root / "mutation-anchor-receipt.zip"

                    def mutate_receipt(original: zipfile.ZipFile, changed: zipfile.ZipFile) -> None:
                        entries = {name: original.read(name) for name in original.namelist()}
                        manifest = json.loads(entries["manifest.json"])
                        receipt = manifest["anchor_receipt"]
                        receipt["signature"] = "0" * 64
                        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
                        entries["manifest.json"] = encoded
                        entries["manifest.sha256"] = hashlib.sha256(encoded).hexdigest().encode("ascii")
                        for name, data in entries.items():
                            changed.writestr(name, data)

                    _rewrite_zip(bundle, mutated, mutate_receipt)
                    observed = EvidenceStore.verify_bundle(mutated, anchor=anchor, require_anchor=True)
                elif case_id == "required-anchor-missing":
                    observed = EvidenceStore.verify_bundle(bundle, require_anchor=True)
                elif kind == "citation":
                    citation = "sha256:" + "a" * 64
                    allowed = {citation} if expected else {"sha256:" + "b" * 64}
                    try:
                        validate_ai_advisory(
                            _valid_advisory(citation), ANALYSIS_KEYS,
                            evidence_ids=allowed, claim_fields=ANALYSIS_CLAIM_FIELDS,
                        )
                        observed = True
                    except (TypeError, ValueError):
                        observed = False
                elif kind == "ledger":
                    observed = store.verify_ledger()[0]
                else:
                    observed = EvidenceStore.verify_bundle(bundle)
                rows.append({
                    "id": case_id, "kind": kind, "expected_accept": expected,
                    "accepted": observed, "pass": observed is expected,
                    "description": description,
                })
            except Exception as exc:  # Report fixture failures as failed cases, not benchmark crashes.
                rows.append({
                    "id": case_id, "kind": kind, "expected_accept": expected,
                    "accepted": None, "pass": False,
                    "description": description, "error_type": type(exc).__name__,
                })
            finally:
                if db is not None:
                    db.close()

    tp = sum(row["expected_accept"] is True and row["accepted"] is True for row in rows)
    fp = sum(row["expected_accept"] is False and row["accepted"] is True for row in rows)
    tn = sum(row["expected_accept"] is False and row["accepted"] is False for row in rows)
    fn = sum(row["expected_accept"] is True and row["accepted"] is False for row in rows)
    passed = sum(row["pass"] for row in rows)
    total = len(rows)
    return {
        "benchmark": BENCHMARK_ID,
        "version": BENCHMARK_VERSION,
        "corpus_sha256": hashlib.sha256(
            json.dumps(scenarios, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest(),
        "cases": total,
        "passed": passed,
        "score": round(passed / total, 4) if total else 0.0,
        "threshold": 1.0,
        "status": "pass" if passed == total else "fail",
        "confusion": {
            "accepted_expected_valid": tp,
            "accepted_expected_invalid": fp,
            "rejected_expected_invalid": tn,
            "rejected_expected_valid": fn,
        },
        "adversarial_rejection_rate": round(tn / (tn + fp), 4) if tn + fp else None,
        "results": rows,
        "limitations": [
            "All records and mutations are deterministic synthetic fixtures; no operational cases or sources were used.",
            "Citation checks verify identifier membership and output shape, not whether cited bytes semantically support a claim.",
            "The legacy unanchored path accepts a full local rewrite; the opt-in HMAC receipt rejects it only while the key and receipt remain outside the attacker's control.",
            "The file-backed HMAC adapter does not prevent rollback of an older signed receipt and is not an append-only remote anchor or immutable object store.",
            "The report does not verify a deployed key manager, immutable storage, remote monotonic anchoring, publisher authorship, or hosted replay.",
        ],
    }

