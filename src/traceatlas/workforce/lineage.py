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
        if len(records) > 128 or len({r.source_id for r in records}) != len(records):
            raise ValueError("source records require unique IDs and at most 128 entries")
        rows = sorted(records, key=lambda r: r.source_id)
        parent = list(range(len(rows)))
        reasons = [set() for _ in rows]
        normalized = [" ".join(r.content.casefold().split()) for r in rows]
        fingerprints = [hashlib.sha256(t.encode()).hexdigest() for t in normalized]
        tokens = [_tokens(t) for t in normalized]

        def root(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for i, row in enumerate(rows):
            for j in range(i):
                other = rows[j]
                links = set()
                if row.original_source_id and row.original_source_id in {other.source_id, other.original_source_id}:
                    links.add("declared_original_source")
                if other.original_source_id == row.source_id:
                    links.add("declared_original_source")
                if row.ownership_group and row.ownership_group == other.ownership_group:
                    links.add("common_ownership")
                if _canonical_uri(row.uri) == _canonical_uri(other.uri):
                    links.add("canonical_uri")
                # A shared hostname can be a multi-tenant host or CDN. Treating
                # it as proof of common origin can collapse independent records.
                # Publisher relationships must be supplied as reviewed ownership
                # metadata; host identity alone remains insufficient.
                if normalized[i] and fingerprints[i] == fingerprints[j]:
                    links.add("exact_content")
                union = tokens[i] | tokens[j]
                if tokens[i] and tokens[j] and len(tokens[i] & tokens[j]) / len(union) >= self.threshold:
                    links.add("near_duplicate_content")
                if links:
                    a, b = root(i), root(j)
                    parent[max(a, b)] = min(a, b)
                    reasons[i].update(links)
                    reasons[j].update(links)
        components = {}
        for i, row in enumerate(rows):
            components.setdefault(root(i), []).append(row.source_id)
        return tuple(SourceLineage(
            lineage_id="source-lineage-" + hashlib.sha256(row.source_id.encode()).hexdigest()[:16],
            source_id=row.source_id,
            independence_group="lineage-" + hashlib.sha256("|".join(components[root(i)]).encode()).hexdigest()[:16],
            original_source_id=row.original_source_id, content_fingerprint=fingerprints[i],
            ownership_group=row.ownership_group, reasons=tuple(sorted(reasons[i])) or ("distinct_origin",),
        ) for i, row in enumerate(rows))
