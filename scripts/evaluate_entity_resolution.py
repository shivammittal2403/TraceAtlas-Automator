"""Run the checked-in synthetic entity-resolution diagnostic benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from traceatlas.resolution_evaluation import evaluate_entity_resolution  # noqa: E402


DATASET = ROOT / "src" / "traceatlas" / "benchmark_data" / "entity_resolution_synthetic.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.72,
                        help="diagnostic score threshold (default: existing possible_candidate boundary)")
    parser.add_argument("--output", type=Path,
                        help="optional UTF-8 JSON report path; parent directory must already exist")
    args = parser.parse_args()
    payload = json.loads(DATASET.read_text(encoding="utf-8"))
    report = evaluate_entity_resolution(payload["cases"], threshold=args.threshold)
    report["dataset_id"] = payload["dataset_id"]
    report["dataset_notice"] = payload["notice"]
    rendered = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
