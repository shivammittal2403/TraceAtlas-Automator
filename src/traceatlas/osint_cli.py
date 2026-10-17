"""CLI for the 140 requested OSINT disciplines and their reviewed routes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import sys

from .addons.intelligence_v1.registry import ROOT, catalog, contract
from .osint_taxonomy import GROUP_NAMES, GROUP_TERMS, catalog_routes, get_route
from .policy import PolicyError
from .workforce.intelligence import run_offline, validate_case_input

MAX_INPUT_BYTES = 2 * 1024 * 1024


class CLIError(ValueError):
    """A concise, user-facing command or input error."""


class JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise CLIError(message)


def _timeout(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer between 1 and 60") from exc
    if not 1 <= number <= 60:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 60")
    return number


def _parser():
    parser = JSONArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="List requested disciplines and their actual execution modes")
    listing.add_argument("--group", type=int, choices=range(1, 11))
    listing.add_argument("--json", action="store_true")
    planning = commands.add_parser("plan", help="Prepare an offline workflow for a stated objective")
    planning.add_argument("label")
    planning.add_argument("--objective", required=True)
    running = commands.add_parser("run", help="Process supplied JSON records through a reviewed native module")
    running.add_argument("label")
    running.add_argument("--input", type=Path, required=True)
    running.add_argument("--output", type=Path)
    running.add_argument("--timeout", type=_timeout, default=20)
    employees = commands.add_parser("employees", help="Run the140 dedicated employee analyzers and case team")
    employees.add_argument("employee_args", nargs=argparse.REMAINDER)
    commands.add_parser("check", help="Verify requested routes, native module hashes, and support-file hashes")
    return parser


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CLIError("Duplicate JSON object keys are not allowed")
        result[key] = value
    return result


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise CLIError("Non-finite JSON numbers are not allowed")
    return number


def _reject_constant(_value):
    raise CLIError("Non-finite JSON numbers are not allowed")


def load_json_object(path):
    """Read bounded UTF-8 JSON without coercion, duplicate keys or non-finite values."""
    with path.open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise CLIError("Input exceeds the 2 MiB limit")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                           parse_float=_finite_float, parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise CLIError("Input must contain valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CLIError("Input must be a JSON object")
    return value


def load_input(path):
    """Require a declared case for the established standalone analysis commands."""
    value = load_json_object(path)
    case_id = value.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        raise CLIError("Input requires a nonempty string case_id")
    validate_case_input(value, case_id)
    return value


def _json_text(value, *, ascii_only=False):
    return json.dumps(value, ensure_ascii=ascii_only, indent=2, allow_nan=False) + "\n"


def _emit(value, stream=None):
    # ASCII JSON remains valid Unicode JSON and works on legacy Windows consoles.
    (stream or sys.stdout).write(_json_text(value, ascii_only=True))


def _controls(timeout):
    resource_available = False
    if os.name == "posix":
        try:
            resource_available = importlib.util.find_spec("resource") is not None
        except (ImportError, ValueError):
            pass
    return {"platform": sys.platform, "audit_restrictions": True,
            "wall_clock_timeout_seconds": timeout,
            "posix_resource_limits_available": resource_available,
            "cpu_memory_hard_limits_available": resource_available,
            "os_sandbox": False}


def _list(args):
    routes = catalog_routes()
    if args.group is not None:
        routes = [route for route in routes if route["group_id"] == args.group]
    if args.json:
        _emit({"schema": "traceatlas.osint.list.v1", "count": len(routes), "disciplines": routes})
        return
    previous_group = None
    for route in routes:
        if route["group_id"] != previous_group:
            if previous_group is not None:
                sys.stdout.write("\n")
            sys.stdout.write(str(route["group_id"]) + ". " + route["group_name"] + "\n")
            previous_group = route["group_id"]
        sys.stdout.write("  {requested_discipline}: {canonical_id} | {route_kind} | {execution_mode}\n".format(**route))


def _plan(args):
    route = get_route(args.label)
    objective = args.objective.strip()
    if not objective:
        raise CLIError("Objective must not be empty")
    return {"schema": "traceatlas.osint.plan.v1", **route,
            "status": "PLANNING_ONLY", "objective": objective,
            "required_input": {"case_id": "A nonempty string identifying the supplied case",
                               "records": "Fields accepted by the resolved native module",
                               "authorization": "Supply any authorization required by that module; the CLI does not create it"},
            "workflow": [
                {"step": 1, "action": "prepare_input", "detail": "Prepare UTF-8 JSON containing the case_id and supplied records for the stated objective."},
                {"step": 2, "action": "review_route", "detail": route["scope_note"]},
                {"step": 3, "action": "run_offline", "argv": ["traceatlas-osint", "run", route["requested_discipline"], "--input", "records.json"]},
                {"step": 4, "action": "review_draft", "detail": "Review the returned native status, evidence gaps, limitations, and proposed next actions."}],
            "execution_performed": False, "network_calls": 0, "model_calls": 0,
            "authority_granted": False,
            "limitations": ["This plan does not verify sources or facts.",
                            "A parent-discipline route retains the scope of its native module.",
                            "Planning-only and unconfigured modules retain those modes during execution."]}


def _run(args):
    route = get_route(args.label)
    if args.output is not None and args.output.exists():
        raise CLIError("Output path already exists; choose a new path")
    data = load_input(args.input)
    item, draft = run_offline(route["canonical_id"], data, timeout=args.timeout)
    result = {"schema": "traceatlas.osint.run.v1", **route,
              "canonical_id": item["id"], "execution_mode": item["mode"],
              "case_id": data["case_id"], "status": "RETURNED",
              "draft_status": draft.get("status", "NOT_DECLARED") if isinstance(draft, dict) else "ARRAY_RESULT",
              "draft": draft, "worker_controls": _controls(args.timeout),
              "network_calls": 0, "model_calls": 0, "authority_granted": False,
              "source_authenticity_verified": False, "factual_entailment_verified": False,
              "requires_human_review": True}
    if args.output is not None:
        rendered = _json_text(result)
        # Exclusive creation closes the race after the existence preflight.
        with args.output.open("x", encoding="utf-8", newline="\n") as destination:
            destination.write(rendered)
    return result


def _check():
    manifest = catalog()
    rows = manifest["modules"]
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise CLIError("Native catalog contains duplicate module IDs")
    for module_id in ids:
        if not isinstance(module_id, str) or not module_id.isidentifier():
            raise CLIError("Native catalog contains an invalid module ID")
        contract(module_id)
    support = manifest.get("support_files_sha256", {})
    for name, digest in support.items():
        if not isinstance(name, str) or not name.isidentifier():
            raise CLIError("Native catalog contains an invalid support-file ID")
        content = (ROOT / "modules" / (name + ".py")).read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise CLIError("Support file differs from its versioned contract: " + name)
    routes = catalog_routes()
    expected = [term for group in GROUP_TERMS.values() for term in group.split()]
    labels = [route["requested_discipline"] for route in routes]
    if len(labels) != 140 or len(set(labels)) != 140 or set(labels) != set(expected):
        raise CLIError("Requested discipline inventory differs from the 140-label taxonomy")
    if set(GROUP_NAMES) != set(range(1, 11)):
        raise CLIError("Taxonomy must contain all ten groups")
    if any(route["canonical_id"] not in ids for route in routes):
        raise CLIError("A requested discipline resolves outside the pinned native catalog")
    return {"schema": "traceatlas.osint.check.v1", "status": "PASS",
            "requested_disciplines": len(routes), "canonical_modules": len(rows),
            "support_files": len(support), "groups": len(GROUP_NAMES),
            "live_verified": False, "hosted_verified": False,
            "verification_scope": "Route inventory and versioned source hashes; functional and live verification require separate tests"}


def main(argv=None):
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    if effective_argv and effective_argv[0] == "employees":
        from .workforce.discipline_cli import main as employee_main
        return employee_main(effective_argv[1:])
    try:
        args = _parser().parse_args(effective_argv)
        if args.command == "list":
            _list(args)
        elif args.command == "plan":
            _emit(_plan(args))
        elif args.command == "run":
            _emit(_run(args))
        else:
            _emit(_check())
        return 0
    except (CLIError, PolicyError, ValueError, TypeError, KeyError) as exc:
        _emit({"status": "ERROR", "error": str(exc)}, sys.stderr)
        return 2
    except OSError as exc:
        _emit({"status": "ERROR", "error": "File operation failed (" + type(exc).__name__ + ")"}, sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
