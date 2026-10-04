"""Small deterministic diagnostics for source-independence grouping.

This synthetic set measures pairwise grouping behavior only. It is not a
representative estimate of real-world source independence or contradiction
recall.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .lineage import SourceIndependenceEngine, SourceRecord


@dataclass(frozen=True, slots=True)
class LineagePairCase:
    case_id: str
    left: SourceRecord
    right: SourceRecord
    same_origin: bool
    rationale: str


def _cases() -> tuple[LineagePairCase, ...]:
    return (
        LineagePairCase("upstream-copy", SourceRecord("up-a", "https://alpha.example/a", "Original filing record", "primary-1"), SourceRecord("up-b", "https://beta.example/a", "Copied filing record", "primary-1"), True, "shared declared original"),
        LineagePairCase("shared-owner", SourceRecord("owner-a", "https://alpha.example/a", "Distinct statement alpha", ownership_group="publisher-1"), SourceRecord("owner-b", "https://beta.example/b", "Distinct statement beta", ownership_group="publisher-1"), True, "shared ownership group"),
        LineagePairCase("same-publisher", SourceRecord("pub-a", "https://news.example/a", "Company announced a dated change", ownership_group="news-publisher"), SourceRecord("pub-b", "https://news.example/b", "Company announced a separate dated update", ownership_group="news-publisher"), True, "reviewed shared publisher ownership"),
        LineagePairCase("exact-copy", SourceRecord("copy-a", "https://one.example/a", "Registry entry updated on 12 March"), SourceRecord("copy-b", "https://two.example/b", "Registry entry updated on 12 March"), True, "exact content"),
        LineagePairCase("near-copy", SourceRecord("near-a", "https://one.example/a", "Registry company identifier changed during March after filing review"), SourceRecord("near-b", "https://two.example/b", "Registry company identifier changed during March after filing review today"), True, "near duplicate content"),
        LineagePairCase("canonical-url", SourceRecord("url-a", "https://registry.example/record/42?view=full", "First captured form"), SourceRecord("url-b", "https://registry.example/record/42#section", "Second captured form"), True, "same canonical URI"),
        LineagePairCase("distinct-registries", SourceRecord("ind-a", "https://registry-a.example/company", "Company registration in jurisdiction North; record 123"), SourceRecord("ind-b", "https://registry-b.example/company", "Company registration in jurisdiction South; record 987"), False, "separate registries with similar subject terms"),
        LineagePairCase("distinct-publishers", SourceRecord("ind-c", "https://paper-a.example/story", "The board approved the annual plan after review"), SourceRecord("ind-d", "https://paper-b.example/story", "The committee rejected the annual budget after debate"), False, "different publishers and materially different text"),
        LineagePairCase("different-hosted-sites", SourceRecord("ind-e", "https://hosting.example/tenant-a/page", "Tenant alpha registry profile"), SourceRecord("ind-f", "https://hosting.example/tenant-b/page", "Tenant beta registry profile"), False, "distinct tenants sharing a hostname"),
        LineagePairCase("unrelated-empty", SourceRecord("ind-g", "https://empty-a.example/", ""), SourceRecord("ind-h", "https://empty-b.example/", ""), False, "empty content and distinct origins"),
        LineagePairCase("similar-but-independent", SourceRecord("ind-i", "https://source-a.example/notice", "Alpha company filed annual report in April"), SourceRecord("ind-j", "https://source-b.example/notice", "Beta company filed annual report in October"), False, "shared generic vocabulary only"),
        LineagePairCase("different-path-same-publisher", SourceRecord("pub-c", "https://gazette.example/item/1", "Official notice about entity one", ownership_group="gazette-publisher"), SourceRecord("pub-d", "https://gazette.example/item/2", "Official notice about entity two", ownership_group="gazette-publisher"), True, "reviewed shared publisher ownership"),
    )


def evaluate_source_independence() -> dict:
    cases = _cases()
    engine = SourceIndependenceEngine()
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    results = []
    for case in cases:
        rows = engine.group([case.left, case.right])
        predicted_same = rows[0].independence_group == rows[1].independence_group
        if predicted_same and case.same_origin:
            counts["tp"] += 1
        elif predicted_same:
            counts["fp"] += 1
        elif not case.same_origin:
            counts["tn"] += 1
        else:
            counts["fn"] += 1
        results.append({"id": case.case_id, "expected_same_origin": case.same_origin,
                        "predicted_same_group": predicted_same, "rationale": case.rationale,
                        "group_reasons": [list(row.reasons) for row in rows]})
    precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
    recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
    specificity = counts["tn"] / (counts["tn"] + counts["fp"]) if counts["tn"] + counts["fp"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"suite": "source-independence-synthetic-v1", "status": "PASS" if counts["fp"] == 0 and counts["fn"] == 0 else "FAIL",
            "scope": "synthetic pairwise source grouping only", "case_count": len(cases),
            "counts": counts, "metrics": {"precision": precision, "recall": recall, "specificity": specificity, "f1": f1},
            "limitations": ["Synthetic cases do not estimate real-world performance.",
                            "Pairwise labels do not measure contradiction detection or recall.",
                            "Contradiction detection is outside this evaluator; reviewed ownership metadata is needed to group separate pages from one publisher."],
            "results": results}
