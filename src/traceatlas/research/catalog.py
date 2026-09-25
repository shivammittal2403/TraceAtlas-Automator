from __future__ import annotations

import gzip
import hashlib
import json
import math
import re
import unicodedata
from collections import Counter
from functools import lru_cache
from importlib.resources import files
from typing import Any, Iterable

from ..policy import PolicyError


TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in",
    "into", "is", "it", "of", "on", "or", "that", "the", "their", "this",
    "to", "using", "via", "with",
})
CONFIDENCE_WEIGHT = {"High": 3.0, "Medium-High": 2.0, "Low": 0.5}


def _tokens(value: Any) -> list[str]:
    normalized = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return [token for token in TOKEN.findall(normalized) if len(token) > 1 and token not in STOPWORDS]


def _resource_bytes(name: str) -> bytes:
    return files("traceatlas.research.data").joinpath(name).read_bytes()


@lru_cache(maxsize=None)
def _load_jsonl(name: str) -> tuple[dict[str, Any], ...]:
    with gzip.GzipFile(fileobj=__import__("io").BytesIO(_resource_bytes(name))) as stream:
        return tuple(
            json.loads(line) for line in stream.read().decode("utf-8").splitlines()
            if line.strip()
        )


@lru_cache(maxsize=1)
def _manifest() -> dict[str, Any]:
    return json.loads(_resource_bytes("manifest.json").decode("utf-8"))


def _paper_text(record: dict[str, Any]) -> list[str]:
    # Repeating important fields is a simple BM25F-style field weighting.
    return (
        _tokens(record["title"]) * 3
        + _tokens(record.get("keywords")) * 2
        + _tokens(record.get("subtopic")) * 2
        + _tokens(record.get("authors"))
        + _tokens(record.get("venue"))
    )


@lru_cache(maxsize=1)
def _paper_index() -> tuple[
    tuple[dict[str, Any], ...], tuple[Counter[str], ...], tuple[frozenset[str], ...],
    dict[str, int], float,
]:
    papers = _load_jsonl("papers.jsonl.gz")
    frequencies: list[Counter[str]] = []
    token_sets: list[frozenset[str]] = []
    document_frequency: Counter[str] = Counter()
    total_length = 0
    for record in papers:
        terms = _paper_text(record)
        frequency = Counter(terms)
        frequencies.append(frequency)
        token_set = frozenset(frequency)
        token_sets.append(token_set)
        document_frequency.update(token_set)
        total_length += sum(frequency.values())
    average_length = total_length / max(1, len(papers))
    return papers, tuple(frequencies), tuple(token_sets), dict(document_frequency), average_length


def _jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    a, b = set(left), set(right)
    return len(a & b) / len(a | b) if a or b else 0.0


class ResearchCatalog:
    """Search and explain the checked-in research metadata without network calls."""

    @staticmethod
    def status(*, verify: bool = False) -> dict[str, Any]:
        manifest = json.loads(json.dumps(_manifest()))
        result = {
            "schema": manifest["schema"],
            "source_sha256": manifest["source_sha256"],
            "selection": manifest["selection"],
            "datasets": manifest["datasets"],
            "limitations": manifest["limitations"],
        }
        if verify:
            checks = {}
            for name, metadata in manifest["datasets"].items():
                payload = _resource_bytes(metadata["file"])
                rows = _load_jsonl(metadata["file"])
                checks[name] = {
                    "sha256_valid": hashlib.sha256(payload).hexdigest() == metadata["sha256"],
                    "record_count_valid": len(rows) == metadata["records"],
                }
            result["integrity"] = checks
            result["valid"] = all(
                check["sha256_valid"] and check["record_count_valid"]
                for check in checks.values()
            )
        return result

    @staticmethod
    def subtopics() -> list[str]:
        return sorted({str(row["subtopic"]) for row in _load_jsonl("papers.jsonl.gz")})

    def search(self, query: str, *, limit: int = 10, subtopic: str | None = None,
               min_year: int | None = None, max_year: int | None = None,
               diversify: bool = True) -> list[dict[str, Any]]:
        query = query.strip()
        if not query or len(query) > 500:
            raise PolicyError("Research query must contain 1-500 characters")
        if not 1 <= limit <= 50:
            raise PolicyError("Research result limit must be between 1 and 50")
        query_terms = _tokens(query)
        if not query_terms:
            raise PolicyError("Research query has no searchable terms")
        papers, frequencies, token_sets, document_frequency, average_length = _paper_index()
        population = len(papers)
        candidates: list[dict[str, Any]] = []
        for index, record in enumerate(papers):
            if subtopic and str(record["subtopic"]).casefold() != subtopic.casefold():
                continue
            year = int(record["year"])
            if min_year is not None and year < min_year:
                continue
            if max_year is not None and year > max_year:
                continue
            frequency = frequencies[index]
            length = sum(frequency.values())
            bm25 = 0.0
            matched = []
            for term in set(query_terms):
                term_frequency = frequency.get(term, 0)
                if not term_frequency:
                    continue
                matched.append(term)
                document_count = document_frequency.get(term, 0)
                inverse = math.log(1 + (population - document_count + 0.5) / (document_count + 0.5))
                denominator = term_frequency + 1.5 * (
                    1 - 0.75 + 0.75 * length / max(1.0, average_length)
                )
                bm25 += inverse * (term_frequency * 2.5) / denominator
            if not matched:
                continue
            phrase_boost = 1.5 if query.casefold() in str(record["title"]).casefold() else 0.0
            quality_boost = min(0.75, math.log1p(int(record["citations"])) / 15)
            score = bm25 + phrase_boost + quality_boost
            candidates.append({
                "index": index,
                "record": record,
                "relevance": score,
                "matched_terms": sorted(matched),
            })
        candidates.sort(
            key=lambda item: (
                -item["relevance"], -float(item["record"]["quality_score"]),
                str(item["record"]["id"]),
            )
        )
        pool = candidates[: max(limit * 12, 100)]
        chosen: list[dict[str, Any]] = []
        if diversify and pool:
            maximum = max(item["relevance"] for item in pool)
            while pool and len(chosen) < limit:
                best = max(
                    pool,
                    key=lambda item: (
                        0.82 * item["relevance"] / max(0.0001, maximum)
                        - 0.18 * max(
                            (_jaccard(token_sets[item["index"]], token_sets[other["index"]])
                             for other in chosen),
                            default=0.0,
                        ),
                        item["relevance"],
                    ),
                )
                pool.remove(best)
                chosen.append(best)
        else:
            chosen = pool[:limit]
        output = []
        for rank, item in enumerate(chosen, 1):
            record = dict(item["record"])
            record.update({
                "rank": rank,
                "relevance_score": round(item["relevance"], 5),
                "matched_terms": item["matched_terms"],
            })
            output.append(record)
        return output

    def gaps(self, query: str, *, limit: int = 10, dimension: str | None = None,
             confidence: str | None = None) -> list[dict[str, Any]]:
        query = query.strip()
        if not query or len(query) > 500:
            raise PolicyError("Gap query must contain 1-500 characters")
        if not 1 <= limit <= 50:
            raise PolicyError("Gap result limit must be between 1 and 50")
        terms = set(_tokens(query))
        candidates = []
        for gap in _load_jsonl("gaps.jsonl.gz"):
            if dimension and gap["dimension"].casefold() != dimension.casefold():
                continue
            if confidence and gap["confidence"].casefold() != confidence.casefold():
                continue
            text = set(_tokens(" ".join(str(gap.get(field) or "") for field in (
                "subtopic", "theme", "dimension", "hypothesis", "opportunity", "validation_test"
            ))))
            overlap = terms & text
            if not overlap:
                continue
            score = (
                len(overlap) * 2.0
                + CONFIDENCE_WEIGHT.get(str(gap["confidence"]), 0.0)
                + (0.5 if int(gap["patent_count"]) == 0 else 0.0)
                + min(1.0, float(gap["research_patent_ratio"]) / 20)
            )
            candidates.append((score, gap, sorted(overlap)))
        candidates.sort(key=lambda item: (-item[0], item[1]["id"]))
        return [
            {**gap, "rank": rank, "triage_score": round(score, 4), "matched_terms": overlap}
            for rank, (score, gap, overlap) in enumerate(candidates[:limit], 1)
        ]

    def collection_plan(self, objective: str, *, limit: int = 8) -> dict[str, Any]:
        if not 1 <= limit <= 20:
            raise PolicyError("Collection-plan limit must be between 1 and 20")
        candidates = self.gaps(objective, limit=50)
        selected: list[dict[str, Any]] = []
        covered_dimensions: set[str] = set()
        covered_themes: set[str] = set()
        pool = list(candidates)
        while pool and len(selected) < limit:
            best = max(
                pool,
                key=lambda row: (
                    float(row["triage_score"])
                    + (1.5 if row["dimension"] not in covered_dimensions else 0)
                    + (1.0 if row["theme"] not in covered_themes else 0),
                    row["confidence"] == "High",
                    row["id"],
                ),
            )
            pool.remove(best)
            selected.append(best)
            covered_dimensions.add(best["dimension"])
            covered_themes.add(best["theme"])
        return {
            "objective": objective,
            "steps": selected,
            "coverage": {
                "dimensions": sorted(covered_dimensions),
                "themes": sorted(covered_themes),
            },
            "review_required": True,
            "caveat": (
                "This is a metadata-driven research plan. It does not establish novelty, "
                "legal authority, target permission, or the truth of any hypothesis."
            ),
        }

    @staticmethod
    def prior_art(paper_id: str) -> dict[str, Any]:
        paper_id = paper_id.strip()
        papers = {row["id"]: row for row in _load_jsonl("papers.jsonl.gz")}
        if paper_id not in papers:
            raise PolicyError("Paper ID is not present in the selected research pack")
        patents = {row["id"]: row for row in _load_jsonl("patents.jsonl.gz")}
        links = [row for row in _load_jsonl("matches.jsonl.gz") if row["paper_id"] == paper_id]
        return {
            "paper": papers[paper_id],
            "candidate_patent_links": [
                {**link, "patent": patents.get(link["patent_id"])} for link in links
            ],
            "review_required": True,
            "caveat": (
                "Title/keyword overlap is only a search lead. Read claims, families, "
                "citations and full text; do not treat this as a novelty or freedom-to-operate opinion."
            ),
        }
