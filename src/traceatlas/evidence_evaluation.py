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
from .intelligence.ai import ANALYSIS_CLAIM_FIELDS, ANALYSIS_KEYS, validate_ai_advisory


BENCHMARK_ID = "evidence-integrity-and-citation-guards"
BENCHMARK_VERSION = "1.0"


def _fixture(root: Path, case_id: str) -> tuple[CaseDB, EvidenceStore, Path]:
    db = CaseDB(root / f"{case_id}.sqlite3")
    db.create_case(case_id, "Synthetic evidence evaluation", "Controlled synthetic fixture only")
    store = EvidenceStore(root, db, case_id)
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
    ]
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="traceatlas-evidence-eval-") as temporary:
        root = Path(temporary)
        for case_id, expected, kind, description in scenarios:
            db = None
            try:
                db, store, bundle = _fixture(root, case_id)
                if case_id == "local-rewrite-reanchored":
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
                    rows.append({
                        "id": case_id, "kind": kind, "expected_accept": expected,
                        "accepted": observed, "pass": observed is expected,
                        "description": description,
                        "limitation_demonstrated": observed is True,
                    })
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
            "Hash checks detect tested mutations but do not prove publisher authorship or resist an attacker who can rewrite and re-anchor all local records.",
            "The report does not verify immutable object storage, external ledger anchoring, or deployed replay behavior.",
        ],
    }
