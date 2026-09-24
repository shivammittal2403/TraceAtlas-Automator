from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .db import CaseDB
from .evidence import EvidenceStore
from .policy import PolicyError


MAX_CTI_BYTES = 10 * 1024 * 1024
NS = uuid.UUID("8fd4bfea-5590-4e1d-9b68-3c7f43ab95bb")
PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "attack-pattern": re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I),
    "url": re.compile(r"https?://[^\s<>\"']+", re.I),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.I),
    "ipv4": re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}\0{value.lower()}".encode()).hexdigest()[:24]


class CTIEngine:
    """Dependency-free, evidence-first CTI extraction and interchange engine."""

    def __init__(self, db: CaseDB, workspace: Path):
        self.db = db
        self.workspace = workspace

    def _case_dir(self, case_id: str) -> Path:
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        path = self.workspace / "cti" / case_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _read_text(path: Path) -> str:
        if not path.is_file() or path.stat().st_size > MAX_CTI_BYTES:
            raise PolicyError("CTI input must be a file up to 10 MiB")
        return path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _mapping(path: Path | None) -> dict[str, list[str]]:
        if path is None:
            return {}
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            raise PolicyError("ATT&CK mapping must be JSON up to 2 MiB")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicyError(f"Invalid ATT&CK mapping JSON: {exc}") from exc
        if not isinstance(raw, dict) or len(raw) > 5000:
            raise PolicyError("ATT&CK mapping must be an object with at most 5,000 terms")
        result: dict[str, list[str]] = {}
        for term, ids in raw.items():
            values = [ids] if isinstance(ids, str) else ids
            if not isinstance(values, list) or not values:
                continue
            clean = [str(item).upper() for item in values if PATTERNS["attack-pattern"].fullmatch(str(item))]
            if clean and 2 <= len(str(term).strip()) <= 100:
                result[str(term).strip().lower()] = sorted(set(clean))
        return result

    @staticmethod
    def extract_text(text: str, mapping: dict[str, list[str]] | None = None) -> dict[str, Any]:
        if len(text.encode()) > MAX_CTI_BYTES:
            raise PolicyError("CTI text exceeds 10 MiB")
        found: dict[tuple[str, str], dict[str, Any]] = {}
        occupied_urls: set[str] = set()
        for kind, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0).rstrip(".,);]")
                if kind == "ipv4":
                    try:
                        ipaddress.IPv4Address(value)
                    except ipaddress.AddressValueError:
                        continue
                if kind == "domain":
                    if any(value.lower() in url.lower() for url in occupied_urls) or PATTERNS["email"].fullmatch(value):
                        continue
                if kind == "url":
                    occupied_urls.add(value)
                canonical = value.upper() if kind in {"cve", "attack-pattern"} else value.lower()
                key = (kind, canonical)
                row = found.setdefault(key, {
                    "id": _stable_id(kind, canonical), "type": kind, "value": canonical,
                    "classification": "observed", "mentions": 0,
                })
                row["mentions"] += 1

        inferred: list[dict[str, Any]] = []
        lowered = text.lower()
        for term, techniques in (mapping or {}).items():
            if term in lowered:
                for technique in techniques:
                    key = ("attack-pattern", technique)
                    found.setdefault(key, {
                        "id": _stable_id(*key), "type": "attack-pattern", "value": technique,
                        "classification": "inferred", "mentions": 0,
                    })
                    inferred.append({
                        "technique": technique, "basis": f"operator mapping term: {term}",
                        "confidence": 50, "requires_analyst_validation": True,
                    })

        entities = sorted(found.values(), key=lambda row: (row["type"], row["value"]))
        relations: list[dict[str, Any]] = []
        sentences = re.split(r"(?<=[.!?])\s+|\n+", text)
        for sentence_no, sentence in enumerate(sentences[:10000], start=1):
            present = [row for row in entities if row["value"].lower() in sentence.lower()]
            for left_index, left in enumerate(present[:25]):
                for right in present[left_index + 1:25]:
                    relations.append({
                        "source": left["id"], "target": right["id"],
                        "type": "co-occurs-with", "sentence": sentence_no,
                        "classification": "observed", "causality_claimed": False,
                    })
        unique_relations = {json.dumps(row, sort_keys=True): row for row in relations}
        return {
            "schema": "traceatlas-cti-1.0", "generated_at": _now(),
            "entities": entities, "relationships": list(unique_relations.values()),
            "attack_mappings": inferred,
            "limitations": [
                "Pattern matches and co-occurrence are leads, not attribution.",
                "Inferred ATT&CK mappings require analyst validation.",
                "No remote enrichment or hidden model call was performed.",
            ],
        }

    def extract(self, case_id: str, path: Path, *, authorized: bool,
                mapping_file: Path | None = None) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("CTI extraction requires explicit --authorized confirmation")
        text = self._read_text(path)
        result = self.extract_text(text, self._mapping(mapping_file))
        result.update({"case_id": case_id, "source_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        output = self._case_dir(case_id) / f"{path.stem}.graph.json"
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, "cti:extract")
        return {"status": "completed", "entities": len(result["entities"]),
                "relationships": len(result["relationships"]), "output": str(output),
                "sha256": record["sha256"], "review_required": True}

    @staticmethod
    def _feed_rows(path: Path) -> list[dict[str, Any]]:
        text = CTIEngine._read_text(path)
        if path.suffix.lower() in {".xml", ".rss", ".atom"}:
            try:
                root = ET.fromstring(text)
            except ET.ParseError as exc:
                raise PolicyError(f"Invalid RSS/Atom XML: {exc}") from exc
            rows = []
            for item in list(root.iter("item")) + [node for node in root.iter() if node.tag.endswith("entry")]:
                def value(name: str) -> str:
                    node = next((child for child in item if child.tag.endswith(name)), None)
                    return (node.text or "").strip() if node is not None else ""
                link = value("link")
                if not link:
                    link_node = next((child for child in item if child.tag.endswith("link")), None)
                    link = str(link_node.attrib.get("href", "")) if link_node is not None else ""
                rows.append({"title": value("title"), "url": link,
                             "published": value("pubDate") or value("updated"),
                             "summary": value("description") or value("summary")})
            return rows
        try:
            raw = json.loads(text)
            rows = raw.get("items", raw.get("records", [])) if isinstance(raw, dict) else raw
        except json.JSONDecodeError:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        if not isinstance(rows, list):
            raise PolicyError("Feed must contain a JSON/JSONL record list or RSS/Atom XML")
        return [row for row in rows[:10000] if isinstance(row, dict)]

    def ingest_feed(self, case_id: str, path: Path, source: str, *, authorized: bool) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("CTI feed ingestion requires explicit --authorized confirmation")
        source = source.strip()[:100]
        if not source:
            raise PolicyError("A feed source label is required")
        output = self._case_dir(case_id) / "feed.json"
        existing = json.loads(output.read_text(encoding="utf-8")) if output.exists() else []
        indexed = {row["fingerprint"]: row for row in existing if isinstance(row, dict) and row.get("fingerprint")}
        added = 0
        for row in self._feed_rows(path):
            title = str(row.get("title") or row.get("name") or "")[:1000]
            url = str(row.get("url") or row.get("link") or "")[:2000]
            summary = str(row.get("summary") or row.get("description") or row.get("content") or "")[:10000]
            if url:
                parsed = urlparse(url)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    url = ""
            if not title and not summary:
                continue
            cves = sorted(set(item.upper() for item in PATTERNS["cve"].findall(f"{title} {summary}")))
            fingerprint = hashlib.sha256(json.dumps([title.lower(), url, cves], sort_keys=True).encode()).hexdigest()
            if fingerprint in indexed:
                continue
            indexed[fingerprint] = {
                "fingerprint": fingerprint, "source": source, "title": title, "url": url,
                "published": str(row.get("published") or row.get("date") or "")[:100],
                "ingested_at": _now(), "cves": cves,
                "classification": "unverified-feed-observation", "review_required": True,
            }
            added += 1
        records = sorted(indexed.values(), key=lambda row: (row["ingested_at"], row["fingerprint"]))[-50000:]
        output.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, "cti:feed")
        return {"status": "completed", "source": source, "added": added, "total": len(records),
                "deduplicated": len(self._feed_rows(path)) - added, "output": str(output), "sha256": record["sha256"]}

    def trends(self, case_id: str) -> dict[str, Any]:
        path = self._case_dir(case_id) / "feed.json"
        rows = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        cves = Counter(cve for row in rows for cve in row.get("cves", []))
        sources = Counter(str(row.get("source", "unknown")) for row in rows)
        return {"records": len(rows), "top_cves": cves.most_common(25),
                "sources": sources.most_common(),
                "limitation": "Counts reflect ingested records, not real-world prevalence."}

    @staticmethod
    def to_stix(graph: dict[str, Any]) -> dict[str, Any]:
        objects: list[dict[str, Any]] = []
        for row in graph.get("entities", []):
            kind, value = str(row.get("type")), str(row.get("value"))
            stix_type = "indicator"
            if kind == "cve":
                obj = {"type": "vulnerability", "spec_version": "2.1",
                       "id": f"vulnerability--{uuid.uuid5(NS, kind + ':' + value)}", "created": graph.get("generated_at", _now()),
                       "modified": graph.get("generated_at", _now()), "name": value,
                       "external_references": [{"source_name": "cve", "external_id": value}]}
            elif kind == "attack-pattern":
                obj = {"type": "attack-pattern", "spec_version": "2.1",
                       "id": f"attack-pattern--{uuid.uuid5(NS, kind + ':' + value)}", "created": graph.get("generated_at", _now()),
                       "modified": graph.get("generated_at", _now()), "name": value,
                       "external_references": [{"source_name": "mitre-attack", "external_id": value}]}
            else:
                observable = {"ipv4": "ipv4-addr:value", "domain": "domain-name:value",
                              "url": "url:value", "email": "email-addr:value"}.get(kind)
                if kind in {"md5", "sha1", "sha256"}:
                    algorithm = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[kind]
                    pattern = f"[file:hashes.'{algorithm}' = '{value}']"
                elif observable:
                    pattern = f"[{observable} = '{value.replace(chr(39), chr(92) + chr(39))}']"
                else:
                    continue
                obj = {"type": stix_type, "spec_version": "2.1",
                       "id": f"indicator--{uuid.uuid5(NS, kind + ':' + value)}", "created": graph.get("generated_at", _now()),
                       "modified": graph.get("generated_at", _now()), "name": f"{kind}: {value}",
                       "pattern_type": "stix", "pattern": pattern, "valid_from": graph.get("generated_at", _now())}
            objects.append(obj)
        return {"type": "bundle", "id": f"bundle--{uuid.uuid5(NS, json.dumps(objects, sort_keys=True))}", "objects": objects}

    def export_stix(self, case_id: str, graph_file: Path, output: Path, *, authorized: bool) -> dict[str, Any]:
        if not authorized:
            raise PolicyError("STIX export requires explicit --authorized confirmation")
        self._case_dir(case_id)
        graph = json.loads(self._read_text(graph_file))
        if graph.get("case_id") != case_id or not isinstance(graph.get("entities"), list):
            raise PolicyError("Graph file is invalid or belongs to another case")
        bundle = self.to_stix(graph)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
        record = EvidenceStore(self.workspace, self.db, case_id).preserve_file(output, "cti:stix-2.1")
        return {"status": "completed", "objects": len(bundle["objects"]), "output": str(output), "sha256": record["sha256"]}
