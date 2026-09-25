from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

from .policy import PolicyError
from .research import ResearchCatalog, explainable_entity_match, temporal_analysis


MAX_JSON_BYTES = 10 * 1024 * 1024


def add_research_parser(subparsers: Any, name: str = "research") -> argparse.ArgumentParser:
    root = subparsers.add_parser(name, help="Search and apply the audited 4,096-paper research pack")
    commands = root.add_subparsers(dest="research_command", required=True)
    status = commands.add_parser("status", help="Show corpus coverage and integrity metadata")
    status.add_argument("--verify", action="store_true")
    search = commands.add_parser("search", help="BM25 search with diversity-aware reranking")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=10)
    search.add_argument("--subtopic")
    search.add_argument("--min-year", type=int)
    search.add_argument("--max-year", type=int)
    search.add_argument("--no-diversify", action="store_true")
    gaps = commands.add_parser("gaps", help="Search the 1,000 supplied gap hypotheses")
    gaps.add_argument("query")
    gaps.add_argument("--limit", type=int, default=10)
    gaps.add_argument("--dimension")
    gaps.add_argument("--confidence", choices=["High", "Medium-High", "Low"])
    plan = commands.add_parser("plan", help="Create a diverse, gap-driven validation plan")
    plan.add_argument("--objective", required=True)
    plan.add_argument("--limit", type=int, default=8)
    prior = commands.add_parser("prior-art", help="Show patent-overlap triage leads for one paper")
    prior.add_argument("--paper-id", required=True)
    match = commands.add_parser("match", help="Compare two non-sensitive public entity records")
    match.add_argument("--left", type=Path, required=True)
    match.add_argument("--right", type=Path, required=True)
    timeline = commands.add_parser("timeline", help="Find temporal conflicts and stale observations")
    timeline.add_argument("--file", type=Path, required=True)
    timeline.add_argument("--as-of", type=date.fromisoformat, required=True)
    timeline.add_argument("--half-life-days", type=int, default=90)
    return root


def _read_json(path: Path) -> Any:
    if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise PolicyError("Research JSON input must be a file up to 10 MiB")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Invalid research JSON input: {exc}") from exc


def run_research(args: argparse.Namespace) -> int:
    catalog = ResearchCatalog()
    if args.research_command == "status":
        result = catalog.status(verify=args.verify)
    elif args.research_command == "search":
        result = catalog.search(
            args.query, limit=args.limit, subtopic=args.subtopic,
            min_year=args.min_year, max_year=args.max_year,
            diversify=not args.no_diversify,
        )
    elif args.research_command == "gaps":
        result = catalog.gaps(
            args.query, limit=args.limit, dimension=args.dimension,
            confidence=args.confidence,
        )
    elif args.research_command == "plan":
        result = catalog.collection_plan(args.objective, limit=args.limit)
    elif args.research_command == "prior-art":
        result = catalog.prior_art(args.paper_id)
    elif args.research_command == "match":
        result = explainable_entity_match(_read_json(args.left), _read_json(args.right))
    elif args.research_command == "timeline":
        records = _read_json(args.file)
        if isinstance(records, dict):
            records = records.get("records", [])
        result = temporal_analysis(
            records, as_of=args.as_of, half_life_days=args.half_life_days
        )
    else:
        raise PolicyError("Unsupported research command")
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    if args.research_command == "status" and args.verify and not result.get("valid", False):
        return 2
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="traceatlas-research",
        description="Offline research intelligence for TraceAtlas",
    )
    subparsers = root.add_subparsers(dest="command", required=True)
    add_research_parser(subparsers, "research")
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(["research", *(argv if argv is not None else sys.argv[1:])])
        return run_research(args)
    except (PolicyError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
