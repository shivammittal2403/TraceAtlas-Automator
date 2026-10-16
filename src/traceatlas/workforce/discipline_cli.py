"""Dedicated employees over supplied evidence and approved local case tasks."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from uuid import uuid4

from ..osint_cli import JSONArgumentParser, _emit, load_input, _json_text
from ..engine import Engine
from ..policy import PolicyError
from .contracts import AuthorizationContext
from .discipline_engines import invoke_employee
from .discipline_registry import employee_catalog
from .discipline_runtime import create_runtime, digest


def _parser():
    parser = JSONArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(".traceatlas"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("catalog", help="List requested and actually implemented employees")
    external = commands.add_parser("external-skills", help="Read third-party skill ZIP as an inert catalog")
    external.add_argument("--archive", type=Path)
    external.add_argument("--directory", type=Path)
    external.add_argument("--query", default="")
    external.add_argument("--limit", type=int, default=50)
    reference = commands.add_parser("external-skill", help="Inspect untrusted Markdown without executing scripts")
    reference.add_argument("skill_id")
    reference.add_argument("--archive", type=Path)
    reference.add_argument("--directory", type=Path)
    skill = commands.add_parser("skill", help="Read a validated discipline Markdown procedure")
    skill.add_argument("discipline")
    commands.add_parser("skills", help="Validate the entire installed Markdown skill catalog")
    analyze = commands.add_parser("analyze", help="Analyze supplied JSON without case persistence")
    analyze.add_argument("discipline")
    analyze.add_argument("--input", type=Path, required=True)
    analyze.add_argument("--output", type=Path)
    team = commands.add_parser("team", help="Coordinate explicit supplied-record employee assignments")
    team.add_argument("--input", type=Path, required=True)
    team.add_argument("--output", type=Path)
    reason = commands.add_parser("reason", help="Ask a configured local model to review an existing analysis draft")
    reason.add_argument("--input", type=Path, required=True)
    reason.add_argument("--model", default="qwen2.5:7b")
    reason.add_argument("--base-url", default="http://127.0.0.1:11434")
    reason.add_argument("--jurisdiction", default="ANY")
    reason.add_argument("--authorized", action="store_true")
    create = commands.add_parser("case", help="Create a canonical local case")
    for key in ("case", "title", "purpose"):
        create.add_argument("--" + key, required=True)
    auth = commands.add_parser("authorize", help="Register supplied-record authority")
    for key in ("case", "actor", "purpose", "jurisdiction"):
        auth.add_argument("--" + key, required=True)
    auth.add_argument("--hours", type=int, default=24)
    auth.add_argument("--retention", default="case-standard")
    auth.add_argument("--authorized", action="store_true")
    plan = commands.add_parser("plan", help="Preserve input bytes and plan one specialist")
    plan.add_argument("discipline")
    plan.add_argument("--context", required=True)
    plan.add_argument("--input", type=Path, required=True)
    plan.add_argument("--parent")
    manager = commands.add_parser("manager", help="Plan assignments; each child needs approval")
    manager.add_argument("--context", required=True)
    manager.add_argument("--input", type=Path, required=True)
    manager.add_argument("--disciplines", nargs="+", required=True)
    approve = commands.add_parser("approve", help="Approve an immutable task digest")
    for key in ("task", "actor", "envelope-digest", "rationale"):
        approve.add_argument("--" + key, required=True)
    approve.add_argument("--authorized", action="store_true")
    run = commands.add_parser("run", help="Execute approved task and preserve its draft")
    run.add_argument("--task", required=True)
    run.add_argument("--authorized", action="store_true")
    for name in ("show", "replay"):
        command = commands.add_parser(name)
        command.add_argument("--task", required=True)
    for name in ("cancel", "recover"):
        command = commands.add_parser(name)
        command.add_argument("--task", required=True)
        command.add_argument("--actor", required=True)
        command.add_argument("--authorized", action="store_true")
    return parser


def execute(args):
    if args.command == "catalog":
        return employee_catalog()
    if args.command == "external-skills":
        from ..skills.external_skills import open_external_skills
        return open_external_skills(archive=args.archive, directory=args.directory).catalog(query=args.query, limit=args.limit)
    if args.command == "external-skill":
        from ..skills.external_skills import open_external_skills
        return open_external_skills(archive=args.archive, directory=args.directory).reference(args.skill_id)
    if args.command == "skill":
        from .discipline_skills import get_skill_guide
        return get_skill_guide(args.discipline)
    if args.command == "skills":
        from .discipline_skills import skill_inventory
        return skill_inventory()
    if args.command == "analyze":
        data = load_input(args.input)
        label = args.discipline.strip().upper()
        if data.get("discipline", label) != label:
            raise ValueError("Input discipline differs from requested employee")
        data["discipline"] = label
        result = invoke_employee(data)
        if args.output is not None:
            with args.output.open("x", encoding="utf-8", newline="\n") as output:
                output.write(_json_text(result))
        return result
    if args.command == "team":
        from .discipline_team import run_team
        result = run_team(load_input(args.input))
        if args.output is not None:
            with args.output.open("x", encoding="utf-8", newline="\n") as output:
                output.write(_json_text(result))
        return result
    if args.command == "reason":
        if not args.authorized:
            raise ValueError("Local-model reasoning requires explicit --authorized")
        from .discipline_reasoning import LocalEmployeeReasoner
        from .model_fabric import ModelRouter, default_registry
        router = ModelRouter(default_registry(ollama_model=args.model, base_url=args.base_url))
        return LocalEmployeeReasoner(router).reason(load_input(args.input), jurisdiction=args.jurisdiction)
    engine = Engine(args.workspace)
    try:
        runtime = create_runtime(engine.db, engine.workspace)
        service = runtime.service
        if args.command == "case":
            engine.db.create_case(args.case, args.title, args.purpose)
            return {"case_id": args.case, "status": "CREATED"}
        if args.command == "authorize":
            if not args.authorized:
                raise ValueError("Authority registration requires --authorized")
            if not 1 <= args.hours <= 168:
                raise ValueError("Authority duration must be 1-168 hours")
            if not engine.db.get_case(args.case):
                raise ValueError("Create the canonical case before authority registration")
            now = datetime.now(timezone.utc)
            context = AuthorizationContext(
                "1.0", "auth-" + uuid4().hex, args.case, args.actor, args.purpose,
                ("provided_records:" + args.case,),
                ("propose_observation", "propose_claim", "propose_plan", "route_task"),
                ("discipline.analyze", "investigation.plan"), args.jurisdiction, args.retention,
                now.isoformat(), (now + timedelta(hours=args.hours)).isoformat(),
                digest({"case": args.case, "actor": args.actor, "purpose": args.purpose,
                        "issued_at": now.isoformat(), "scope": "provided_records_only"}))
            service.register_authorization(context)
            return {"authorization": context.to_dict(), "execution_enabled": service.enabled}
        if args.command == "plan":
            return runtime.plan(args.context, args.discipline, load_input(args.input), parent_task_id=args.parent)
        if args.command == "manager":
            return runtime.plan_manager(args.context, load_input(args.input), args.disciplines)
        if args.command == "approve":
            return service.approve(args.task, actor_id=args.actor, rationale=args.rationale,
                envelope_digest=args.envelope_digest, authorized=args.authorized)
        if args.command == "run":
            return runtime.run(args.task, authorized=args.authorized)
        if args.command == "replay":
            return runtime.replay(args.task)
        if args.command in {"cancel", "recover"}:
            return getattr(service, args.command)(args.task, actor_id=args.actor, authorized=args.authorized)
        return service.describe(args.task)
    finally:
        engine.close()


def main(argv=None):
    try:
        _emit(execute(_parser().parse_args(argv)))
        return 0
    except (ValueError, TypeError, KeyError, PolicyError) as exc:
        _emit({"status": "ERROR", "error": str(exc)}, sys.stderr)
        return 2
    except OSError as exc:
        _emit({"status": "ERROR", "error": "File operation failed (" + type(exc).__name__ + ")"}, sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
