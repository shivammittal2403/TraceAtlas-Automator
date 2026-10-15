"""Run isolated supplied-evidence modules. External collection is not part of this CLI."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .engine import analyze
from .registry import CATALOG

def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m traceatlas.skills.managed140")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    run = sub.add_parser("run")
    run.add_argument("domain", choices=sorted(CATALOG))
    run.add_argument("--input", type=Path, required=True)
    run.add_argument("--output", type=Path)
    run.add_argument("--case-id", default="local")
    run.add_argument("--authorized", action="store_true", help="Attest to approved case scope")
    args = parser.parse_args(argv)
    if args.command == "list":
        print(json.dumps(CATALOG, indent=2))
        return 0
    if args.input.stat().st_size > 10 * 1024 * 1024:
        parser.error("Input exceeds 10 MB")
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    report = analyze(args.domain, payload, authorized=args.authorized, case_id=args.case_id)
    out = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    return 0 if report["status"] in {"completed", "partial"} else 2

if __name__ == "__main__":
    raise SystemExit(main())
