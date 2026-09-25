#!/usr/bin/env python3
"""Build the checked-in TraceAtlas research pack from the supplied XLSX.

The runtime pack intentionally excludes abstracts, comments, review assignments,
and workbook formulas. It contains public bibliographic metadata and corpus-local
gap/match hypotheses only. The builder uses the Python standard library so the
selection can be reproduced without adding a runtime dependency.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import posixpath
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET


MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CELL_REF = re.compile(r"^([A-Z]+)")
TITLE_NORMALIZER = re.compile(r"[^a-z0-9]+")
DOI_PREFIX = re.compile(r"^https?://(?:dx\.)?doi\.org/", re.I)
MAX_XLSX_BYTES = 64 * 1024 * 1024
MAX_XLSX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


def _column_index(reference: str) -> int:
    match = CELL_REF.match(reference)
    if not match:
        raise ValueError(f"Invalid XLSX cell reference: {reference}")
    value = 0
    for char in match.group(1):
        value = value * 26 + ord(char) - 64
    return value - 1


class XlsxReader:
    def __init__(self, path: Path):
        if path.stat().st_size > MAX_XLSX_BYTES:
            raise ValueError("XLSX exceeds the 64 MiB input limit")
        self.path = path
        self.archive = zipfile.ZipFile(path)
        if sum(item.file_size for item in self.archive.infolist()) > MAX_XLSX_UNCOMPRESSED_BYTES:
            self.archive.close()
            raise ValueError("XLSX exceeds the 256 MiB uncompressed limit")
        self.shared_strings = self._shared_strings()
        self.sheets = self._sheet_paths()

    def close(self) -> None:
        self.archive.close()

    def _shared_strings(self) -> list[str]:
        root = ET.fromstring(self.archive.read("xl/sharedStrings.xml"))
        return [
            "".join(node.text or "" for node in item.iter(f"{{{MAIN_NS}}}t"))
            for item in root.findall(f"{{{MAIN_NS}}}si")
        ]

    def _sheet_paths(self) -> dict[str, str]:
        workbook = ET.fromstring(self.archive.read("xl/workbook.xml"))
        relationships = ET.fromstring(self.archive.read("xl/_rels/workbook.xml.rels"))
        targets = {
            rel.attrib["Id"]: rel.attrib["Target"]
            for rel in relationships.findall(f"{{{PKG_REL_NS}}}Relationship")
        }
        result: dict[str, str] = {}
        sheets = workbook.find(f"{{{MAIN_NS}}}sheets")
        if sheets is None:
            raise ValueError("XLSX workbook has no sheets collection")
        for sheet in sheets:
            relation = sheet.attrib[f"{{{REL_NS}}}id"]
            result[sheet.attrib["name"]] = posixpath.normpath("xl/" + targets[relation])
        return result

    def _value(self, cell: ET.Element) -> Any:
        kind = cell.attrib.get("t", "n")
        value_node = cell.find(f"{{{MAIN_NS}}}v")
        if kind == "inlineStr":
            return "".join(node.text or "" for node in cell.iter(f"{{{MAIN_NS}}}t"))
        if value_node is None or value_node.text is None:
            return None
        raw = value_node.text
        if kind == "s":
            return self.shared_strings[int(raw)]
        if kind in {"str", "e"}:
            return raw
        if kind == "b":
            return raw == "1"
        try:
            number = float(raw)
            return int(number) if number.is_integer() else number
        except ValueError:
            return raw

    def records(self, sheet_name: str) -> list[dict[str, Any]]:
        if sheet_name not in self.sheets:
            raise ValueError(f"Missing worksheet: {sheet_name}")
        root = ET.fromstring(self.archive.read(self.sheets[sheet_name]))
        rows: list[list[Any]] = []
        for row in root.iter(f"{{{MAIN_NS}}}row"):
            values: dict[int, Any] = {}
            for cell in row.findall(f"{{{MAIN_NS}}}c"):
                values[_column_index(cell.attrib["r"])] = self._value(cell)
            if values:
                width = max(values) + 1
                rows.append([values.get(index) for index in range(width)])
        if not rows:
            return []
        headers = [str(value or "").strip() for value in rows[0]]
        output = []
        for row in rows[1:]:
            record = {
                headers[index]: value
                for index, value in enumerate(row)
                if index < len(headers) and headers[index]
            }
            if any(value not in (None, "") for value in record.values()):
                output.append(record)
        return output


def _normal_title(value: Any) -> str:
    return TITLE_NORMALIZER.sub(" ", str(value or "").casefold()).strip()


def _normal_doi(value: Any) -> str:
    return DOI_PREFIX.sub("", str(value or "").casefold().strip())


def _ids(value: Any) -> list[str]:
    return [item.strip() for item in str(value or "").split(";") if item.strip()]


def _quality(record: dict[str, Any]) -> float:
    citations = max(0.0, float(record.get("Citation Count") or 0))
    year = int(record.get("Year") or 0)
    return round(
        4 * math.log1p(citations)
        + 3 * bool(str(record.get("Abstract / Summary") or "").strip())
        + 1.5 * bool(str(record.get("Keywords") or "").strip())
        + 1.5 * bool(record.get("OA / PDF URL"))
        + 2 * bool(_normal_doi(record.get("DOI / Publication Number")))
        + max(0.0, min(3.0, (year - 2005) / 7)),
        4,
    )


def _valid_paper(record: dict[str, Any], max_year: int) -> bool:
    try:
        year = int(record.get("Year") or 0)
    except (TypeError, ValueError):
        return False
    locator = _normal_doi(record.get("DOI / Publication Number")) or str(
        record.get("Canonical URL") or ""
    ).startswith("http")
    return (
        "research paper" in str(record.get("Record Type") or "").casefold()
        and 1900 <= year <= max_year
        and len(str(record.get("Title") or "").strip()) >= 12
        and bool(locator)
    )


def _deduplicate(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for record in records:
        key = _normal_title(record.get("Title"))
        current = selected.get(key)
        if current is None or _quality(record) > _quality(current):
            selected[key] = record
    return list(selected.values())


def _quotas(groups: dict[str, list[dict[str, Any]]], total: int,
            forced_counts: Counter[str]) -> dict[str, int]:
    population = sum(len(records) for records in groups.values())
    quota = {
        name: min(
            len(records),
            max(64, forced_counts[name], round(total * len(records) / population)),
        )
        for name, records in groups.items()
    }
    while sum(quota.values()) > total:
        choices = [
            name for name in quota
            if quota[name] > max(64, forced_counts[name])
        ]
        if not choices:
            raise ValueError("Forced evidence prevents the requested balanced corpus size")
        quota[max(choices, key=lambda name: quota[name])] -= 1
    while sum(quota.values()) < total:
        choices = [name for name in quota if quota[name] < len(groups[name])]
        if not choices:
            raise ValueError("Not enough unique papers for requested corpus size")
        quota[max(choices, key=lambda name: len(groups[name]) - quota[name])] += 1
    return quota


def select_papers(master: list[dict[str, Any]], gaps: list[dict[str, Any]],
                  matches: list[dict[str, Any]], total: int,
                  max_year: int) -> list[dict[str, Any]]:
    unique = _deduplicate(record for record in master if _valid_paper(record, max_year))
    by_id = {str(record["Record ID"]): record for record in unique}
    forced_ids = {
        paper_id for gap in gaps for paper_id in _ids(gap.get("Evidence Research IDs"))
        if paper_id in by_id
    }
    forced_ids.update(
        str(match.get("Research Record ID") or "") for match in matches
        if str(match.get("Research Record ID") or "") in by_id
    )
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in unique:
        groups[str(record.get("Subtopic") or "Unclassified")].append(record)
    for records in groups.values():
        records.sort(
            key=lambda item: (
                str(item["Record ID"]) not in forced_ids,
                -_quality(item),
                -float(item.get("Citation Count") or 0),
                str(item["Record ID"]),
            )
        )
    forced_counts = Counter(
        str(by_id[paper_id].get("Subtopic") or "Unclassified") for paper_id in forced_ids
    )
    quota = _quotas(groups, total, forced_counts)
    selected = [record for name, records in groups.items() for record in records[:quota[name]]]
    if len(selected) != total:
        raise AssertionError(f"Expected {total} papers, selected {len(selected)}")
    return sorted(selected, key=lambda record: str(record["Record ID"]))


def paper_row(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(record["Record ID"]),
        "title": str(record.get("Title") or "").strip(),
        "authors": str(record.get("Authors / Inventors") or "").strip(),
        "year": int(record.get("Year") or 0),
        "publication_date": str(record.get("Publication Date") or "").strip() or None,
        "venue": str(record.get("Venue / Assignee") or "").strip(),
        "doi": _normal_doi(record.get("DOI / Publication Number")) or None,
        "url": str(record.get("Canonical URL") or "").strip(),
        "citations": max(0, int(float(record.get("Citation Count") or 0))),
        "subtopic": str(record.get("Subtopic") or "Unclassified"),
        "keywords": str(record.get("Keywords") or "").strip(),
        "oa_url": str(record.get("OA / PDF URL") or "").strip() or None,
        "abstract_available": bool(str(record.get("Abstract / Summary") or "").strip()),
        "quality_score": _quality(record),
    }


def patent_row(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(record["Record ID"]),
        "title": str(record.get("Title") or "").strip(),
        "year": int(record["Year"]) if isinstance(record.get("Year"), (int, float)) else None,
        "publication_number": str(record.get("DOI / Publication Number") or "").strip(),
        "url": str(record.get("Canonical URL") or "").strip(),
        "subtopic": str(record.get("Subtopic") or "Unclassified"),
    }


def gap_row(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(record["Gap ID"]),
        "subtopic": str(record.get("Subtopic") or ""),
        "theme": str(record.get("Theme") or ""),
        "dimension": str(record.get("Analysis Dimension") or ""),
        "research_count": int(float(record.get("Research Count") or 0)),
        "patent_count": int(float(record.get("Patent Count") or 0)),
        "research_patent_ratio": float(record.get("Research/Patent Ratio") or 0),
        "evidence_research_ids": _ids(record.get("Evidence Research IDs")),
        "evidence_patent_ids": _ids(record.get("Evidence Patent IDs")),
        "hypothesis": str(record.get("Gap Hypothesis") or ""),
        "opportunity": str(record.get("Opportunity Direction") or ""),
        "validation_test": str(record.get("Validation Test") or ""),
        "confidence": str(record.get("Confidence") or ""),
        "caveat": str(record.get("Important Caveat") or ""),
    }


def match_row(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(record["Match ID"]),
        "subtopic": str(record.get("Subtopic") or ""),
        "patent_id": str(record.get("Patent Record ID") or ""),
        "paper_id": str(record.get("Research Record ID") or ""),
        "similarity": float(record.get("Similarity Score") or 0),
        "shared_terms": [
            item.strip() for item in str(record.get("Shared Terms") or "").split(";")
            if item.strip()
        ],
        "note": str(record.get("Cross-check Note") or ""),
    }


def _write_jsonl_gz(path: Path, rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    payload = b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        for row in rows
    )
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
            compressed.write(payload)
    return {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "uncompressed_sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": path.stat().st_size,
    }


def build(source: Path, output: Path, paper_count: int, max_year: int) -> dict[str, Any]:
    reader = XlsxReader(source)
    try:
        master = reader.records("Master Corpus 5900")
        gaps = reader.records("Gap Analysis 1000")
        matches = reader.records("Cross-Matches 1000")
    finally:
        reader.close()
    papers = select_papers(master, gaps, matches, paper_count, max_year)
    patents = [
        record for record in master
        if "patent" in str(record.get("Record Type") or "").casefold()
    ]
    paper_ids = {str(record["Record ID"]) for record in papers}
    patent_ids = {str(record["Record ID"]) for record in patents}
    resolved_matches = [
        record for record in matches
        if str(record.get("Research Record ID") or "") in paper_ids
        and str(record.get("Patent Record ID") or "") in patent_ids
    ]
    output.mkdir(parents=True, exist_ok=True)
    datasets = {
        "papers": ("papers.jsonl.gz", [paper_row(record) for record in papers]),
        "patents": ("patents.jsonl.gz", [patent_row(record) for record in patents]),
        "gaps": ("gaps.jsonl.gz", [gap_row(record) for record in gaps]),
        "matches": ("matches.jsonl.gz", [match_row(record) for record in resolved_matches]),
    }
    metadata: dict[str, Any] = {}
    for name, (filename, rows) in datasets.items():
        metadata[name] = {"file": filename, "records": len(rows)}
        metadata[name].update(_write_jsonl_gz(output / filename, rows))
    evidence_ids = {
        paper_id for gap in gaps for paper_id in _ids(gap.get("Evidence Research IDs"))
    }
    match_paper_ids = {
        str(record.get("Research Record ID") or "") for record in matches
        if record.get("Research Record ID")
    }
    manifest = {
        "schema": "traceatlas-research-pack-1.0",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_description": "OSINT prior-art master metadata snapshot retrieved 2026-09-02",
        "selection": {
            "papers": paper_count,
            "max_year": max_year,
            "deduplication": "normalized title; highest metadata quality retained",
            "stratification": "proportional across 16 supplied subtopics; gap and resolvable match evidence forced",
            "abstracts_included": False,
            "unresolved_gap_paper_ids": sorted(evidence_ids - paper_ids),
            "source_cross_match_records": len(matches),
            "excluded_cross_match_records": len(matches) - len(resolved_matches),
            "excluded_match_research_ids": sorted(match_paper_ids - paper_ids),
            "unresolved_match_paper_ids": [],
        },
        "datasets": metadata,
        "limitations": [
            "Bibliographic metadata is not the full text of the papers.",
            "Quality scores are deterministic triage aids, not scientific merit scores.",
            "Gap and patent-match rows are metadata hypotheses, not novelty or legal opinions.",
            "English-indexed sources dominate the supplied workbook.",
        ],
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the TraceAtlas research metadata pack")
    parser.add_argument("source", type=Path)
    parser.add_argument(
        "--output", type=Path,
        default=Path("src/traceatlas/research/data"),
    )
    parser.add_argument("--papers", type=int, default=4096)
    parser.add_argument("--max-year", type=int, default=2026)
    args = parser.parse_args()
    if not args.source.is_file():
        parser.error("source workbook does not exist")
    if not 4000 <= args.papers <= 5000:
        parser.error("--papers must be between 4000 and 5000")
    print(json.dumps(build(args.source, args.output, args.papers, args.max_year), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
