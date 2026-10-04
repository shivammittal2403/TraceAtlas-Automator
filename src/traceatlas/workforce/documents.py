"""Bounded source records. Export assertions never become facts by fiat."""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import ClassVar, Mapping, Any
from urllib.parse import urlsplit

from ..policy import validate_target
from .contracts import StrictContract, _id, _text, _utc

DOCUMENT_SCHEMA = "traceatlas-source-document/v1"
PREDICATES = frozenset({"resolves_to", "registry_handle", "registered_name", "registered_country",
                        "registration_status", "observed_port", "archived_url", "public_label",
                        "associated_with", "mentions", "indicator", "dependency", "search_result_url",
                        "indexed_url", "scan_observed_ip", "approximate_country", "network_asn",
                        "network_isp", "provider_classification", "provider_last_seen", "certificate_log_id",
                        "announced_prefix", "filing_accession", "repository_count", "organization_profile",
                        "provider_malicious_detections", "vulnerability_id", "vulnerability_alias",
                        "vulnerability_score", "vulnerability_severity", "exploitation_probability",
                        "exploitation_percentile", "cisa_kev_listed", "cisa_kev_added_date",
                        "cisa_kev_due_date", "cisa_kev_required_action", "cisa_kev_vulnerability_name",
                        "affected_package", "package_version", "package_license"})
MAX_DOCUMENT_BYTES = 512 * 1024
MAX_DOCUMENTS = 8


def normalize_seed(kind: str, value: str) -> str:
    if kind == "domain":
        return validate_target(kind, value).value.lower()
    if kind == "ip":
        address = ipaddress.ip_address(validate_target(kind, value).value)
        if not address.is_global:
            raise ValueError("IP investigations require an authorized public IP")
        return str(address)
    if kind in {"person", "company"}:
        return _id(value, "public seed identifier")
    if kind == "cve":
        result = value.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", result):
            raise ValueError("CVE seed must be one exact CVE identifier")
        return result
    if kind == "vulnerability":
        result = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{3,119}", result):
            raise ValueError("vulnerability seed must be one exact advisory identifier")
        return result
    if kind == "package":
        result = value.strip().lower()
        if not re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}", result):
            raise ValueError("package seed must be one exact npm package name")
        return result
    raise ValueError("supported seed types are domain, ip, person, company, cve, vulnerability and package")


@dataclass(frozen=True, slots=True)
class StructuredFact(StrictContract):
    subject: str
    predicate: str
    value: str
    valid_from: str
    valid_to: str | None
    fields: ClassVar[frozenset[str]] = frozenset({"subject", "predicate", "value", "valid_from", "valid_to"})

    def __post_init__(self):
        object.__setattr__(self, "subject", _id(self.subject, "subject"))
        if self.predicate not in PREDICATES:
            raise ValueError("unregistered structured predicate")
        object.__setattr__(self, "value", _text(self.value, "value", 1, 500))
        object.__setattr__(self, "valid_from", _utc(self.valid_from, "valid_from"))
        if self.valid_to is not None:
            object.__setattr__(self, "valid_to", _utc(self.valid_to, "valid_to"))
            if self.valid_to < self.valid_from:
                raise ValueError("valid_to precedes valid_from")
        if self.predicate in {"resolves_to", "scan_observed_ip"}:
            object.__setattr__(self, "value", str(ipaddress.ip_address(self.value)))
        if self.predicate == "observed_port" and (not self.value.isdigit() or not 1 <= int(self.value) <= 65535):
            raise ValueError("invalid observed port")
        if self.predicate == "vulnerability_score":
            try:
                score = float(self.value)
            except ValueError:
                raise ValueError("invalid vulnerability score") from None
            if not 0 <= score <= 10:
                raise ValueError("invalid vulnerability score")
        if self.predicate in {"exploitation_probability", "exploitation_percentile"}:
            try:
                probability = float(self.value)
            except ValueError:
                raise ValueError("invalid probability") from None
            if not 0 <= probability <= 1:
                raise ValueError("invalid probability")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]):
        return cls(**cls._strict(value))


@dataclass(frozen=True, slots=True)
class SourceDocument(StrictContract):
    schema_version: str
    source_id: str
    source_uri: str
    retrieved_at: str
    content: str
    facts: tuple[StructuredFact, ...]
    original_source_id: str | None
    ownership_group: str | None
    fields: ClassVar[frozenset[str]] = frozenset({"schema_version", "source_id", "source_uri", "retrieved_at",
                                               "content", "facts", "original_source_id", "ownership_group"})

    def __post_init__(self):
        if self.schema_version != DOCUMENT_SCHEMA:
            raise ValueError("unsupported source-document schema")
        object.__setattr__(self, "source_id", _id(self.source_id, "source_id"))
        object.__setattr__(self, "source_uri", _text(self.source_uri, "source_uri", 1, 2048))
        uri = urlsplit(self.source_uri)
        if uri.scheme not in {"https", "urn"} or uri.username or uri.password or uri.query or uri.fragment:
            raise ValueError("source URI requires credential-free HTTPS or URN provenance")
        if uri.scheme == "https" and not uri.hostname:
            raise ValueError("HTTPS source URI requires a host")
        object.__setattr__(self, "retrieved_at", _utc(self.retrieved_at, "retrieved_at"))
        if not isinstance(self.content, str) or len(self.content.encode()) > MAX_DOCUMENT_BYTES:
            raise ValueError("source content exceeds its byte bound")
        if not isinstance(self.facts, tuple) or len(self.facts) > 100 or any(not isinstance(f, StructuredFact) for f in self.facts):
            raise ValueError("facts must be a bounded typed tuple")
        for key in ("original_source_id", "ownership_group"):
            if getattr(self, key) is not None:
                object.__setattr__(self, key, _id(getattr(self, key), key))
        if len(json.dumps(self.to_dict(), ensure_ascii=False).encode()) > MAX_DOCUMENT_BYTES:
            raise ValueError("source document exceeds its total byte bound")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]):
        data = cls._strict(value)
        if not isinstance(data["facts"], (list, tuple)):
            raise ValueError("facts must be an array")
        data["facts"] = tuple(StructuredFact.from_dict(row) for row in data["facts"])
        return cls(**data)


def load_documents(path) -> tuple[SourceDocument, ...]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_DOCUMENTS * MAX_DOCUMENT_BYTES:
        raise ValueError("source input must be a bounded regular JSON file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_DOCUMENTS:
        raise ValueError("source input requires 1-8 documents")
    rows = tuple(SourceDocument.from_dict(row) for row in value)
    if len({row.source_id for row in rows}) != len(rows):
        raise ValueError("source IDs must be unique within a capture")
    return rows
