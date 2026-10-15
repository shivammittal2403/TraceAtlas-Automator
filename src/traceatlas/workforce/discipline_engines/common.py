"""Shared evidence-bound contracts for deterministic discipline employees."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

ENGINE_VERSION = "1.0.0"
MAX_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 500
MAX_DEPTH = 20
MAX_TEXT = 262144


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _json(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("Employee input nesting exceeds its limit")
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("Employee input must contain valid Unicode") from exc
        if len(value) > MAX_TEXT:
            raise ValueError("Employee input text exceeds its limit")
        return
    if type(value) is int:
        if abs(value) > 10 ** 100:
            raise ValueError("Employee input integer exceeds its limit")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("Employee input requires finite numbers")
        return
    if type(value) is list:
        if len(value) > MAX_RECORDS:
            raise ValueError("Employee input arrays require at most 500 items")
        for item in value:
            _json(item, depth + 1)
        return
    if type(value) is dict:
        if len(value) > MAX_RECORDS or any(type(key) is not str for key in value):
            raise ValueError("Employee input requires bounded string-keyed objects")
        for key, item in value.items():
            _json(key, depth + 1)
            _json(item, depth + 1)
        return
    raise ValueError("Employee input must contain JSON values only")


def text(value: Any, name: str, *, maximum: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(name + " must be nonempty bounded text")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise ValueError(name + " contains control characters")
    return value


def identifier(value: Any, name: str) -> str:
    value = text(value, name, maximum=160)
    if value != value.strip() or any(character.isspace() for character in value):
        raise ValueError(name + " must not contain whitespace")
    return value


def instant(value: Any, name: str = "timestamp") -> datetime:
    value = text(value, name, maximum=80)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(name + " must be an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(name + " requires an explicit timezone")
    return parsed.astimezone(timezone.utc)


def number(value: Any, name: str, *, minimum: float | None = None,
           maximum: float | None = None) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(name + " must be a finite number")
    if minimum is not None and value < minimum or maximum is not None and value > maximum:
        raise ValueError(name + " is outside its allowed range")
    return float(value)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    record_id: str
    source_id: str
    data: dict[str, Any]
    observed_at: str | None = None


class AnalysisContext:
    """One immutable input snapshot; findings can cite only its registered records."""

    def __init__(self, payload: dict, *, evidence_ids: Iterable[str] = ()):
        _json(payload)
        if len(canonical(payload).encode("utf-8")) > MAX_BYTES:
            raise ValueError("Employee input exceeds 2 MiB")
        allowed = {"case_id", "task_id", "discipline", "objective", "as_of",
                   "sources", "records", "parameters"}
        required = allowed - {"parameters"}
        if not isinstance(payload, dict) or set(payload) - allowed or required - set(payload):
            raise ValueError("Employee input has missing or unknown fields")
        self.payload = deepcopy(payload)
        self.case_id = identifier(payload["case_id"], "case_id")
        self.task_id = identifier(payload["task_id"], "task_id")
        self.discipline = identifier(payload["discipline"], "discipline").upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9]{1,39}", self.discipline):
            raise ValueError("Invalid discipline label")
        self.objective = text(payload["objective"], "objective", maximum=4000)
        self.as_of = instant(payload["as_of"], "as_of")
        self.parameters = deepcopy(payload.get("parameters", {}))
        if not isinstance(self.parameters, dict):
            raise ValueError("parameters must be an object")
        sources = payload["sources"]
        records = payload["records"]
        if not isinstance(sources, list) or not isinstance(records, list):
            raise ValueError("sources and records must be arrays")
        self.sources = {}
        source_fields = {"source_id", "uri", "original_source_id", "publisher_id",
                         "retrieved_at", "content_sha256"}
        for source in sources:
            if not isinstance(source, dict) or set(source) - source_fields or {"source_id", "uri"} - set(source):
                raise ValueError("A source has missing or unknown fields")
            source_id = identifier(source["source_id"], "source_id")
            if source_id in self.sources:
                raise ValueError("Duplicate source_id")
            uri = text(source["uri"], "source uri", maximum=2048)
            if any(character.isspace() for character in uri):
                raise ValueError("Source URI must not contain whitespace")
            parsed = urlsplit(uri)
            if parsed.scheme not in {"http", "https", "urn"} or (parsed.scheme != "urn" and not parsed.netloc):
                raise ValueError("Source URI requires http, https or urn")
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("Source URI must not contain credentials")
            for key in ("original_source_id", "publisher_id"):
                if key in source:
                    identifier(source[key], key)
            if "retrieved_at" in source:
                instant(source["retrieved_at"], "retrieved_at")
            if "content_sha256" in source and (not isinstance(source["content_sha256"], str) or
                    not re.fullmatch(r"[0-9a-f]{64}", source["content_sha256"])):
                raise ValueError("content_sha256 must be a lowercase SHA-256 digest")
            self.sources[source_id] = deepcopy(source)
        converted = []
        record_ids = set()
        for record in records:
            if (not isinstance(record, dict) or
                    set(record) - {"record_id", "source_id", "data", "observed_at"} or
                    {"record_id", "source_id", "data"} - set(record)):
                raise ValueError("A record has missing or unknown fields")
            record_id = identifier(record["record_id"], "record_id")
            source_id = identifier(record["source_id"], "source_id")
            if record_id in record_ids:
                raise ValueError("Duplicate record_id")
            if source_id not in self.sources:
                raise ValueError("Record references an unknown source_id")
            if not isinstance(record["data"], dict):
                raise ValueError("Record data must be an object")
            observed_at = record.get("observed_at")
            if observed_at is not None:
                instant(observed_at, "observed_at")
            converted.append(EvidenceRecord(record_id, source_id, deepcopy(record["data"]), observed_at))
            record_ids.add(record_id)
        self.records = tuple(converted)
        self._records = {record.record_id: record for record in self.records}
        if isinstance(evidence_ids, (str, bytes)):
            raise ValueError("canonical evidence_ids must be an iterable of IDs")
        self.evidence_ids = tuple(sorted(set(identifier(item, "canonical evidence_id") for item in evidence_ids)))
        self.input_sha256 = digest(payload)
        self.findings: list[dict] = []
        self.issues: list[dict] = []
        self._finding_ids: set[str] = set()

    def finding(self, kind: str, summary: str, record_ids: Iterable[str],
                data: dict | None = None) -> dict:
        kind = identifier(kind, "finding kind")
        summary = text(summary, "finding summary", maximum=3500)
        if isinstance(record_ids, str):
            raise ValueError("Finding record_ids must be a sequence, not text")
        refs = sorted(set(record_ids))
        if not refs or any(ref not in self._records for ref in refs):
            raise ValueError("Finding must cite registered input records")
        data = {} if data is None else data
        if not isinstance(data, dict):
            raise ValueError("Finding data must be an object")
        _json(data)
        item = {"kind": kind, "summary": summary, "record_ids": refs,
                "source_ids": sorted(set(self._records[ref].source_id for ref in refs)),
                "canonical_evidence_ids": list(self.evidence_ids), "data": deepcopy(data)}
        identity = {"case_id": self.case_id, "task_id": self.task_id,
                    "discipline": self.discipline, **item}
        item["finding_id"] = "finding-" + digest(identity)[:32]
        if item["finding_id"] not in self._finding_ids and len(self.findings) >= 500:
            raise ValueError("Employee finding budget exhausted")
        if item["finding_id"] not in self._finding_ids:
            self._finding_ids.add(item["finding_id"])
            self.findings.append(item)
        return deepcopy(item)

    def issue(self, record_or_id: EvidenceRecord | str | None, code: str, message: str) -> dict:
        record_id = record_or_id.record_id if isinstance(record_or_id, EvidenceRecord) else record_or_id
        if record_id is not None and record_id not in self._records:
            raise ValueError("Issue references an unknown record")
        item = {"record_id": record_id, "code": identifier(code, "issue code"),
                "message": text(message, "issue message", maximum=4000)}
        if item not in self.issues:
            if len(self.issues) >= 500:
                raise ValueError("Employee issue budget exhausted")
            self.issues.append(item)
        return deepcopy(item)

    def output(self, metrics: dict | None = None, artifacts: dict | None = None,
               limitations: Iterable[str] = ()) -> dict:
        if metrics is not None and not isinstance(metrics, dict):
            raise ValueError("Employee metrics must be an object")
        if artifacts is not None and not isinstance(artifacts, dict):
            raise ValueError("Employee artifacts must be an object")
        limits = list(limitations)
        for limit in limits:
            text(limit, "limitation", maximum=4000)
        result = {"findings": deepcopy(self.findings), "issues": deepcopy(self.issues),
                  "metrics": deepcopy(metrics or {}), "artifacts": deepcopy(artifacts or {}),
                  "limitations": limits}
        _json(result)
        if len(canonical(result).encode("utf-8")) > MAX_BYTES:
            raise ValueError("Employee output exceeds 2 MiB")
        return result


def make_context(payload: dict, *, evidence_ids: Iterable[str] = ()) -> AnalysisContext:
    return AnalysisContext(payload, evidence_ids=evidence_ids)
