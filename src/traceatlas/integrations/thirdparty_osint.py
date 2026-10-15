"""Three pinned OSINT frameworks: non-executable source catalog and case evidence importer.

External inputs are untrusted observations. Imports run no third-party code,
create no network connections, and cannot change investigation authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import tempfile
from typing import Any
from uuid import uuid4

from ..policy import PolicyError, validate_target

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 2000
MAX_DEPTH = 4
HOST = re.compile(r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SOURCES = {
    "theharvester": {
        "path": "third_party/theHarvester",
        "repository": "https://github.com/laramies/theHarvester",
        "commit": "49a38f8d33c32336bbf6a111ea723ea223116265",
        "license": "GPL-2.0-only",
        "runtime": "existing_separately_installed_cli",
        "python": ">=3.14",
    },
    "osint-spy": {
        "path": "third_party/OSINT-SPY",
        "repository": "https://github.com/SharadKumar97/OSINT-SPY",
        "commit": "03dcf4868f7a63a2d863996c4bbc62db1c60bc82",
        "license": "GPL-3.0",
        "runtime": "disabled_legacy_dependencies",
        "python": "unqualified",
    },
    "mr-holmes": {
        "path": "third_party/Mr.Holmes",
        "repository": "https://github.com/Lucksi/Mr.Holmes",
        "commit": "028bffba615c8b95db4cf1babe1b0e5925237eb4",
        "license": "GPL-3.0",
        "runtime": "disabled_identity_and_active_modules",
        "python": "unqualified",
    },
}

@dataclass(frozen=True)
class SourceObservation:
    event_type: str
    data: str
    source: str
    classification: str = "source_reported_unverified"

    def as_dict(self) -> dict[str, str]:
        return {"event_type": self.event_type, "data": self.data,
                "source": self.source, "classification": self.classification}


def catalog(*, repository_root: Path | None = None) -> list[dict[str, Any]]:
    root = Path(repository_root) if repository_root else Path(__file__).resolve().parents[3]
    output = []
    for name, metadata in SOURCES.items():
        p = root / metadata["path"]
        output.append({"id": name, **metadata,
                       "source_present": (p / "LICENSE").is_file(),
                       "execution_qualified": False if name != "theharvester" else None,
                       "live_verified": False,
                       "import_formats": ["json", "jsonl"]})
    return output


def _load_records(raw: bytes) -> list[dict[str, Any]]:
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Report must use UTF-8") from exc
    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        try:
            document = [json.loads(line) for line in content.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise ValueError("Input is not JSON or JSONL") from exc
    if isinstance(document, dict):
        document = [document]
    if not isinstance(document, list) or not document or len(document) > MAX_RECORDS:
        raise ValueError("Too many reports or invalid report structure")
    if not all(isinstance(x, dict) for x in document):
        raise ValueError("All top-level input records must be JSON objects")
    return document


def _in_scope_domain(value: Any, target: str) -> str | None:
    if not isinstance(value, str) or len(value) > 253:
        return None
    candidate = value.lower().strip().rstrip(".")
    root = target.lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if HOST.fullmatch(candidate) and (candidate == root or candidate.endswith("." + root)):
        return candidate
    return None


def _in_scope_url(value: Any, target: str) -> str | None:
    from urllib.parse import urlparse
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        return None
    hostname = _in_scope_domain(parsed.hostname, target)
    if not hostname:
        return None
    # Query, fragment AND path can carry credentials and personal tokens.
    # Capture only the safe origin, never the untrusted path.
    return f"{parsed.scheme}://{hostname}/"


def _flatten(document: Any, *, depth: int = 0):
    """Enumerate only explicit, recognized finding structures, not arbitrary text."""
    if depth > MAX_DEPTH:
        return
    if isinstance(document, list):
        for entry in document[:MAX_RECORDS]:
            yield from _flatten(entry, depth=depth + 1)
    elif isinstance(document, dict):
        if document.get("type") == "summary":
            return
        yield document
        for key in ("results", "findings", "records", "data", "hosts", "domains", "subdomains", "observations"):
            child = document.get(key)
            if isinstance(child, (list, dict)):
                yield from _flatten(child, depth=depth + 1)


def normalize(source: str, raw: bytes | str, *, target_type: str, target: str) -> dict[str, Any]:
    key = str(source).strip().lower()
    if key not in SOURCES:
        raise ValueError("Unknown source framework")
    if target_type != "domain":
        raise PolicyError("Three-framework importer only accepts authorized domain scope")
    validate_target(target_type, target)
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) > MAX_FILE_BYTES:
        raise ValueError("Report is not bounded bytes")
    records = _load_records(raw_bytes)
    observations: list[SourceObservation] = []
    seen: set[tuple[str, str]] = set()
    examined = dropped = 0
    for item in _flatten(records):
        if examined >= MAX_RECORDS:
            break
        examined += 1
        item_type = str(item.get("type", "")).casefold().replace("_", "-")
        # Native theHarvester JSONL uses "type":"hostname","value":"foo.example".
        values: list[tuple[str, Any]] = []
        if item_type in {"hostname", "domain", "host", "subdomain"}:
            values.append(("DOMAIN", item.get("value")))
        elif item_type in {"url", "website"}:
            values.append(("URL", item.get("value")))
        for field in ("domain", "hostname", "host", "subdomain"):
            if field in item:
                values.append(("DOMAIN", item[field]))
        if "url" in item:
            values.append(("URL", item["url"]))
        for field in ("hosts", "domains", "subdomains"):
            entries = item.get(field)
            if isinstance(entries, list):
                for part in entries[:MAX_RECORDS]:
                    if isinstance(part, str):
                        values.append(("DOMAIN", part))
        for kind, value in values:
            clean = _in_scope_domain(value, target) if kind == "DOMAIN" else _in_scope_url(value, target)
            if clean is None:
                dropped += 1
                continue
            fingerprint = (kind, clean)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            observations.append(SourceObservation(kind, clean, key))
            if len(observations) >= MAX_RECORDS:
                break
        if len(observations) >= MAX_RECORDS:
            break
    return {
        "schema": "traceatlas.thirdparty_osint/sanitized-v1",
        "source": key,
        "upstream_commit": SOURCES[key]["commit"],
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "scope": {"type": target_type, "target": target.lower()},
        "observations": [x.as_dict() for x in observations],
        "counts": {"source_records_examined": examined, "observations": len(observations),
                   "invalid_or_out_of_scope_dropped": dropped},
        "live_verified": False,
        "source_independence_verified": False,
        "caveat": "Supplied file data only; no factual validation or live source execution",
    }


def import_file(db, workspace: Path, *, case_id: str, source: str,
                file_path: Path, target: str, authorized: bool = False) -> dict[str, Any]:
    """Import sanitized domain observations into the canonical CaseDB/EvidenceStore.

    No file input is executed. Raw report contents are deliberately not retained
    to prevent accidental credential or unrelated-person disclosure.
    """
    if not authorized:
        raise PolicyError("A documented and approved case scope is required")
    if not db.get_case(case_id):
        raise PolicyError("Unknown investigation case")
    input_file = Path(file_path)
    if input_file.is_symlink() or not input_file.is_file():
        raise ValueError("File must be a regular input, not a symlink")
    if input_file.suffix.lower() not in {".json", ".jsonl"}:
        raise ValueError("Only JSON or JSONL reports are accepted")
    if input_file.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Report exceeds the 8 MiB ingestion limit")
    parsed = normalize(source, input_file.read_bytes(), target_type="domain", target=target)
    from ..evidence import EvidenceStore
    from ..spider.events import Event, child
    scan_id = str(uuid4())
    seed = Event("DOMAIN", target.lower(), f"external-import:{parsed['source']}",
                 scan_id, case_id, confidence=100)
    # The receipt does not contain raw upstream data, PII, API tokens or query strings.
    with tempfile.TemporaryDirectory(prefix="traceatlas-sanitized-") as temp:
        receipt = Path(temp) / "sanitized_report.json"
        receipt.write_text(json.dumps(parsed, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        store = EvidenceStore(Path(workspace), db, case_id)
        stored = store.preserve_file(receipt, f"external-import:{parsed['source']}:sanitized")
    db.start_spider_scan(scan_id, case_id, "DOMAIN", target.lower(), "offline-file-import")
    db.add_spider_event(seed.to_dict())
    for item in parsed["observations"]:
        event = child(seed, item["event_type"], item["data"],
                      f"external-import:{parsed['source']}", confidence=55,
                      tags=["offline", "source-reported", "unverified", parsed["source"]])
        db.add_spider_event(event.to_dict())
    status = "completed" if parsed["observations"] else "partial"
    db.end_spider_scan(scan_id, status, {
        "source": parsed["source"], "accepted_observations": len(parsed["observations"]),
        "invalid_or_out_of_scope_dropped": parsed["counts"]["invalid_or_out_of_scope_dropped"],
        "source_sha256": parsed["raw_sha256"], "validated_facts": 0, "network_calls": 0,
    })
    return {"scan_id": scan_id, "status": status, "source": parsed["source"],
            "accepted": len(parsed["observations"]), "validated_facts": 0,
            "raw_sha256": parsed["raw_sha256"], "receipt": stored}


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Safe offline case import of three OSINT frameworks")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("catalog")
    review = sub.add_parser("review")
    review.add_argument("--source", choices=sorted(SOURCES), required=True)
    review.add_argument("--file", type=Path, required=True)
    review.add_argument("--target", required=True)
    args = parser.parse_args(argv)
    if args.command == "catalog":
        print(json.dumps(catalog(), indent=2))
        return 0
    if args.file.is_symlink() or args.file.stat().st_size > MAX_FILE_BYTES:
        parser.error("Input is a symlink or exceeds 8 MiB")
    report = normalize(args.source, args.file.read_bytes(), target_type="domain", target=args.target)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
