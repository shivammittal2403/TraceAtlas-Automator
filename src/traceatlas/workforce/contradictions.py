"""Deterministic temporal contradiction checks for registered single-value facts."""
from __future__ import annotations

from typing import Iterable

from .documents import StructuredFact


SINGLE_VALUE_PREDICATES = frozenset({
    "registry_handle", "registered_name", "registered_country",
    "package_version", "package_license",
})


def contradicts(left: StructuredFact, right: StructuredFact) -> bool:
    """Return true only for overlapping, different values of a single-value fact."""
    return (
        left.subject == right.subject
        and left.predicate == right.predicate
        and left.predicate in SINGLE_VALUE_PREDICATES
        and left.value != right.value
        and left.valid_from <= (right.valid_to or "9999")
        and right.valid_from <= (left.valid_to or "9999")
    )


def contradiction_pairs(facts: Iterable[StructuredFact]) -> tuple[tuple[int, int], ...]:
    """Return stable positional pairs that contradict within one bounded fact set."""
    rows = tuple(facts)
    return tuple(
        (left_index, right_index)
        for left_index, left in enumerate(rows)
        for right_index in range(left_index + 1, len(rows))
        if contradicts(left, rows[right_index])
    )
