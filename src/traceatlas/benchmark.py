"""Versioned, deterministic AI evidence-contract benchmark."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .intelligence.ai import ANALYSIS_CLAIM_FIELDS, ANALYSIS_KEYS, validate_ai_advisory
from .models import utc_now
from .policy import PolicyError


class GuardrailBenchmark:
    """Measure schema/citation enforcement; this does not measure model truthfulness."""

    def __init__(self, corpus: Path | None = None):
        root = Path(__file__).resolve().parents[2]
        self.corpus = corpus or (root / "benchmarks" / "ai_advisory_v1.json")

    def run(self) -> dict[str, Any]:
        raw = self.corpus.read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            raise PolicyError("Benchmark corpus exceeds 2 MiB")
        try:
            corpus = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PolicyError("Benchmark corpus is not valid JSON") from exc
        cases = corpus.get("cases") if isinstance(corpus, dict) else None
        if not isinstance(cases, list) or not 5 <= len(cases) <= 500:
            raise PolicyError("Benchmark corpus must contain 5-500 cases")
        results = []
        passed = 0
        for case in cases:
            if not isinstance(case, dict) or set(case) != {
                "id", "expected_valid", "evidence_ids", "payload",
            }:
                raise PolicyError("Benchmark case contract is invalid")
            identifier = str(case["id"])
            if not identifier or len(identifier) > 80 or not isinstance(case["expected_valid"], bool):
                raise PolicyError("Benchmark case metadata is invalid")
            evidence_ids = case["evidence_ids"]
            if not isinstance(evidence_ids, list) or not all(
                isinstance(value, str) and 1 <= len(value) <= 128 for value in evidence_ids
            ):
                raise PolicyError("Benchmark evidence IDs are invalid")
            accepted = True
            error_type = None
            try:
                validate_ai_advisory(
                    case["payload"], ANALYSIS_KEYS,
                    evidence_ids=set(evidence_ids), claim_fields=ANALYSIS_CLAIM_FIELDS,
                )
            except (TypeError, ValueError) as exc:
                accepted = False
                error_type = type(exc).__name__
            success = accepted is case["expected_valid"]
            passed += int(success)
            results.append({
                "id": identifier, "expected_valid": case["expected_valid"],
                "accepted": accepted, "pass": success, "error_type": error_type,
            })
        total = len(results)
        score = round(passed / total, 4)
        return {
            "benchmark": "ai-evidence-contract", "version": str(corpus.get("version", "")),
            "generated_at": utc_now(), "corpus_sha256": hashlib.sha256(raw).hexdigest(),
            "cases": total, "passed": passed, "score": score,
            "threshold": 1.0, "status": "pass" if score == 1.0 else "fail",
            "results": results,
            "limitations": [
                "This suite measures output-contract and citation enforcement, not model factual accuracy.",
                "A separate representative model benchmark and human adjudication remain required.",
            ],
        }

    def write(self, output: Path) -> dict[str, Any]:
        result = self.run()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
