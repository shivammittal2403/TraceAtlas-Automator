"""Deterministic source-independence grouping; URL count is never corroboration."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .contracts import SourceLineage


@dataclass(frozen=True, slots=True)
class SourceRecord:
    source_id: str
    uri: str
    content: str
    original_source_id: str | None = None
    ownership_group: str | None = None


def _canonical_uri(uri: str) -> str:
    parsed = urlsplit(uri)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", "", ""))


def _tokens(content: str) -> frozenset[str]:
    # Two-character jurisdiction and country codes can be materially distinct;
    # dropping them would incorrectly collapse namesake registry records.
    return frozenset(re.findall(r"[a-z0-9]{2,}", content.casefold())[:5000])


class SourceIndependenceEngine:
    def __init__(self, similarity_threshold: float = 0.9):
        if not 0.5 <= similarity_threshold <= 1:
            raise ValueError("similarity threshold must be 0.5-1.0")
        self.threshold = similarity_threshold

    def group(self, records: list[SourceRecord]) -> tuple[SourceLineage, ...]:
        groups: list[tuple[str, SourceRecord, frozenset[str]]] = []
        result = []
        for record in sorted(records, key=lambda row: row.source_id):
            canonical = _canonical_uri(record.uri)
            normalized = " ".join(record.content.casefold().split())
            fingerprint = hashlib.sha256(normalized.encode()).hexdigest()
            tokens = _tokens(normalized)
            group_id, reasons = "", []
            for candidate_id, candidate, candidate_tokens in groups:
                same_origin = bool(record.original_source_id and record.original_source_id == candidate.original_source_id)
                same_owner = bool(record.ownership_group and record.ownership_group == candidate.ownership_group)
                union = tokens | candidate_tokens
                similarity = len(tokens & candidate_tokens) / len(union) if union else 1.0
                if fingerprint == hashlib.sha256(" ".join(candidate.content.casefold().split()).encode()).hexdigest():
                    group_id, reasons = candidate_id, ["exact_content"]
                elif same_origin:
                    group_id, reasons = candidate_id, ["declared_original_source"]
                elif similarity >= self.threshold:
                    group_id, reasons = candidate_id, ["near_duplicate_content"]
                elif canonical == _canonical_uri(candidate.uri):
                    group_id, reasons = candidate_id, ["canonical_uri"]
                elif same_owner:
                    group_id, reasons = candidate_id, ["common_ownership"]
                if group_id:
                    break
            if not group_id:
                group_id = "lineage-" + hashlib.sha256((record.original_source_id or canonical).encode()).hexdigest()[:16]
                reasons = ["distinct_origin"]
                groups.append((group_id, record, tokens))
            result.append(SourceLineage(
                lineage_id="source-lineage-" + hashlib.sha256(record.source_id.encode()).hexdigest()[:16],
                source_id=record.source_id, independence_group=group_id,
                original_source_id=record.original_source_id, content_fingerprint=fingerprint,
                ownership_group=record.ownership_group, reasons=tuple(reasons),
            ))
        return tuple(result)
