from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from typing import Any


TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in",
    "into", "is", "it", "of", "on", "or", "that", "the", "their", "this",
    "to", "using", "via", "with",
})


def tokenize(value: Any) -> list[str]:
    normalized = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return [token for token in TOKEN.findall(normalized) if len(token) > 1 and token not in STOPWORDS]


def bm25_search(documents: list[dict[str, Any]], query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    """Rank small, trusted local document sets with dependency-free BM25."""
    terms = tokenize(query)
    if not terms:
        return []
    frequencies = [Counter(tokenize(row.get("text", ""))) for row in documents]
    population = len(documents)
    average_length = sum(sum(freq.values()) for freq in frequencies) / max(1, population)
    document_frequency = Counter(term for freq in frequencies for term in freq)
    ranked: list[tuple[float, dict[str, Any], list[str]]] = []
    for row, frequency in zip(documents, frequencies):
        length = sum(frequency.values())
        score = 0.0
        matched: list[str] = []
        for term in set(terms):
            term_frequency = frequency.get(term, 0)
            if not term_frequency:
                continue
            matched.append(term)
            count = document_frequency[term]
            inverse = math.log(1 + (population - count + 0.5) / (count + 0.5))
            denominator = term_frequency + 1.5 * (
                1 - 0.75 + 0.75 * length / max(1.0, average_length)
            )
            score += inverse * (term_frequency * 2.5) / denominator
        if matched:
            ranked.append((score, row, sorted(matched)))
    ranked.sort(key=lambda item: (-item[0], str(item[1].get("id", ""))))
    return [
        {**row, "score": round(score, 5), "matched_terms": matched}
        for score, row, matched in ranked[:limit]
    ]
