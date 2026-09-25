from __future__ import annotations

import base64
import csv
import hashlib
import ipaddress
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from uuid import uuid4

from ..db import CaseDB
from ..evidence import EvidenceStore
from ..policy import PolicyError, validate_target
from ..spider.events import Event, child
from .sanitize import fingerprint, sanitize_record
from .sources import SOURCES, SourceSpec


MAX_IMPORT_BYTES = 10 * 1024 * 1024
Requester = Callable[[str, dict[str, str], int], tuple[int, bytes]]


def _request(url: str, headers: dict[str, str], timeout: int) -> tuple[int, bytes]:
    request = Request(url, headers=headers, method="GET")
    with urlopen(request, timeout=timeout) as response:
        return int(response.status), response.read(10 * 1024 * 1024)


class IntelligenceHub:
    def __init__(self, db: CaseDB, workspace: Path, requester: Requester | None = None):
        self.db = db
        self.workspace = workspace
        self.requester = requester or _request

    @staticmethod
    def sources() -> list[dict[str, Any]]:
        return [SOURCES[name].to_dict() for name in sorted(SOURCES)]

    def _gate(self, case_id: str, spec: SourceSpec, *, authorized: bool,
              subject_consent: bool, owned_org: bool, owned_asset: bool,
              public_record_basis: bool) -> None:
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        if not authorized:
            raise PolicyError("Intelligence collection requires explicit --authorized confirmation")
        if spec.personal_data and not (subject_consent or owned_org):
            raise PolicyError(
                f"{spec.title} personal/professional data requires --subject-consent or --owned-org"
            )
        if spec.category in {"internet-intelligence", "threat-intelligence"} and not owned_asset:
            raise PolicyError(f"{spec.title} collection requires --owned-asset")
        if spec.public_record and not (public_record_basis or owned_org):
            raise PolicyError(f"{spec.title} ingestion requires --public-record-basis or --owned-org")

    @staticmethod
    def _records(path: Path) -> list[Any]:
        if not path.is_file():
            raise PolicyError(f"Import file does not exist: {path}")
        if path.stat().st_size > MAX_IMPORT_BYTES:
            raise PolicyError("Intelligence import is limited to 10 MiB")
        text = path.read_text(encoding="utf-8", errors="replace")
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            records = []
            for line in text.splitlines():
                if line.strip():
                    records.append(json.loads(line))
            return records
        if suffix in {".csv", ".tsv"}:
            dialect = "excel-tab" if suffix == ".tsv" else "excel"
            return list(csv.DictReader(text.splitlines(), dialect=dialect))
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("data", "items", "results", "records", "entries"):
                if isinstance(data.get(key), list):
                    return data[key]
            return [data]
        raise PolicyError("Import must contain a JSON object/array, JSONL, CSV or TSV")

    def _store(self, case_id: str, spec: SourceSpec, records: list[Any], *,
               mode: str, target_fingerprint: str) -> dict[str, Any]:
        scan_id = str(uuid4())
        seed_value = f"{spec.name}:{target_fingerprint[:16]}"
        self.db.start_spider_scan(scan_id, case_id, "TEXT", seed_value, mode)
        seed = Event("TEXT", seed_value, "intel-seed", scan_id, case_id, confidence=100,
                     tags=["redacted-seed"])
        self.db.add_spider_event(seed.to_dict())
        normalized: list[dict[str, Any]] = []
        total_stats = {"redacted": 0, "removed": 0, "truncated": 0}
        for record in records[:5000]:
            stats = {"redacted": 0, "removed": 0, "truncated": 0}
            clean = sanitize_record(record, stats=stats)
            for key in total_stats:
                total_stats[key] += stats[key]
            item = {
                "source": spec.name,
                "category": spec.category,
                "observation": clean,
                "evidence_class": "observed-fact",
                "limitation": spec.limitation,
            }
            normalized.append(item)
            event = child(
                seed, spec.event_type, item, f"intel:{spec.name}", confidence=70,
                tags=["public-source", "analyst-review-required", spec.category],
            )
            self.db.add_spider_event(event.to_dict())
        with tempfile.TemporaryDirectory(prefix="traceatlas-intel-") as temp:
            safe_path = Path(temp) / f"{spec.name}-normalized.json"
            safe_path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False), encoding="utf-8")
            EvidenceStore(self.workspace, self.db, case_id).preserve_file(
                safe_path, f"intelligence:{spec.name}:normalized"
            )
        result = {
            "source": spec.name, "records_received": len(records),
            "records_stored": len(normalized), "records_truncated": max(0, len(records) - 5000),
            "privacy": total_stats,
        }
        self.db.end_spider_scan(scan_id, "completed", {**result, "events": len(normalized) + 1})
        return {"scan_id": scan_id, "status": "completed", "stats": result}

    def ingest(self, case_id: str, source: str, path: Path, *, authorized: bool = False,
               subject_consent: bool = False, owned_org: bool = False,
               owned_asset: bool = False, public_record_basis: bool = False) -> dict[str, Any]:
        if source not in SOURCES:
            raise ValueError(f"Unknown intelligence source: {source}")
        spec = SOURCES[source]
        self._gate(case_id, spec, authorized=authorized, subject_consent=subject_consent,
                   owned_org=owned_org, owned_asset=owned_asset,
                   public_record_basis=public_record_basis)
        records = self._records(path)
        source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        return self._store(case_id, spec, records, mode="intel:import", target_fingerprint=source_hash)

    @staticmethod
    def _live_request(spec: SourceSpec, target_type: str, target: str) -> tuple[str, dict[str, str]]:
        headers = {"User-Agent": "TraceAtlas-Automator/0.5"}
        if spec.name == "github":
            validate_target("username", target)
            token = os.environ.get("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            headers["Accept"] = "application/vnd.github+json"
            return f"https://api.github.com/users/{quote(target)}", headers
        if spec.name == "youtube":
            key = os.environ.get("YOUTUBE_API_KEY")
            if not key:
                raise PolicyError("YOUTUBE_API_KEY is required")
            if not target.strip() or len(target) > 128:
                raise PolicyError("Invalid YouTube channel ID")
            query = urlencode({"part": "snippet,statistics", "id": target.strip(), "key": key})
            return f"https://www.googleapis.com/youtube/v3/channels?{query}", headers
        if spec.name == "discord":
            code = target.strip().rsplit("/", 1)[-1]
            if not code or len(code) > 128 or not all(c.isalnum() or c in "-_" for c in code):
                raise PolicyError("Invalid public Discord invite code")
            return f"https://discord.com/api/v10/invites/{quote(code)}?with_counts=true", headers
        if spec.name in {"shodan", "censys"}:
            validate_target("ip", target)
            if not ipaddress.ip_address(target).is_global:
                raise PolicyError("Internet-intelligence connectors accept public IPs only")
            if spec.name == "shodan":
                key = os.environ.get("SHODAN_API_KEY")
                if not key:
                    raise PolicyError("SHODAN_API_KEY is required")
                return f"https://api.shodan.io/shodan/host/{quote(target)}?key={quote(key)}", headers
            api_id, secret = os.environ.get("CENSYS_API_ID"), os.environ.get("CENSYS_API_SECRET")
            if not api_id or not secret:
                raise PolicyError("CENSYS_API_ID and CENSYS_API_SECRET are required")
            credentials = base64.b64encode(f"{api_id}:{secret}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
            return f"https://search.censys.io/api/v2/hosts/{quote(target)}", headers
        if spec.name == "virustotal":
            key = os.environ.get("VIRUSTOTAL_API_KEY")
            if not key:
                raise PolicyError("VIRUSTOTAL_API_KEY is required")
            headers["x-apikey"] = key
            if target_type == "url":
                validate_target("url", target)
                identifier = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
                return f"https://www.virustotal.com/api/v3/urls/{identifier}", headers
            if target_type in {"domain", "ip"}:
                validate_target(target_type, target)
                plural = "domains" if target_type == "domain" else "ip_addresses"
                return f"https://www.virustotal.com/api/v3/{plural}/{quote(target)}", headers
            if target_type == "hash" and len(target) in {32, 40, 64} and all(c in "0123456789abcdefABCDEF" for c in target):
                return f"https://www.virustotal.com/api/v3/files/{target.lower()}", headers
            raise PolicyError("VirusTotal target must be a URL, domain, IP or MD5/SHA-1/SHA-256 hash")
        raise PolicyError(f"{spec.title} is export/API-ingestion only")

    def collect(self, case_id: str, source: str, target_type: str, target: str, *,
                authorized: bool = False, subject_consent: bool = False,
                owned_org: bool = False, owned_asset: bool = False,
                public_record_basis: bool = False) -> dict[str, Any]:
        if source not in SOURCES:
            raise ValueError(f"Unknown intelligence source: {source}")
        spec = SOURCES[source]
        if not spec.live_connector:
            raise PolicyError(f"{spec.title} requires an official/approved export; use intel ingest")
        self._gate(case_id, spec, authorized=authorized, subject_consent=subject_consent,
                   owned_org=owned_org, owned_asset=owned_asset,
                   public_record_basis=public_record_basis)
        try:
            url, headers = self._live_request(spec, target_type, target)
            status, raw = self.requester(url, headers, 30)
            if status != 200:
                raise ValueError(f"{spec.title} returned HTTP {status}")
            data = json.loads(raw.decode("utf-8"))
            records = data if isinstance(data, list) else [data]
            result = self._store(
                case_id, spec, records, mode="intel:live",
                target_fingerprint=fingerprint([source, target_type, target]),
            )
        except Exception as exc:
            # Never persist provider URLs, headers or response bodies: they may contain keys.
            self.db.record_connector_result(
                source, False, f"{type(exc).__name__}: connector request failed"
            )
            raise
        self.db.record_connector_result(source, True)
        return result
