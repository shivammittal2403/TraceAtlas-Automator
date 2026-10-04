#!/usr/bin/env python3
"""Run the deterministic synthetic source-independence diagnostic."""
from __future__ import annotations

import json
from pathlib import Path

from traceatlas.workforce.lineage_evaluation import evaluate_source_independence


if __name__ == "__main__":
    report = evaluate_source_independence()
    output = Path("docs/verification/source-independence-synthetic-2026-10-04.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "case_count": report["case_count"],
                      "counts": report["counts"], "metrics": report["metrics"],
                      "report": str(output)}, indent=2))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
