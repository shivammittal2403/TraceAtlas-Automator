"""Public CLI surface for employee research, collection and decision records."""
from __future__ import annotations

import json
from pathlib import Path

from .knowledge import KnowledgeLibrary
from .service import ATTESTATIONS, COLLECTION, EmployeeService
from .skills import skill_catalog
from .catalog import tool_candidates


def add_employee_parser(sub):
    root = sub.add_parser("employee", help="Evidence-led OSINT/PT research employee; human decisions")
    commands = root.add_subparsers(dest="employee_command", required=True)
    console = commands.add_parser("serve", help="Open the loopback-only autonomous investigation console")
    console.add_argument("--port", type=int, default=8765)
    investigate = commands.add_parser("investigate", help="Authorize once and run a bounded autonomous public-source investigation")
    investigate.add_argument("--case", required=True)
    investigate.add_argument("--objective", required=True)
    investigate.add_argument("--seed", action="append", required=True, help="Exact type:value, e.g. domain:example.org; repeat for explicit scope")
    investigate.add_argument("--actor", required=True)
    investigate.add_argument("--subject-type", choices=["asset", "person", "company"], default="asset")
    investigate.add_argument("--subject-label", default="")
    investigate.add_argument("--max-actions", type=int, default=8)
    investigate.add_argument("--runtime-seconds", type=int, default=120)
    investigate.add_argument("--hours", type=int, default=24)
    investigate.add_argument("--model", help="Optional local Ollama model; absence uses deterministic analysis")
    investigate.add_argument("--plan-only", action="store_true")
    investigate.add_argument("--authorized", action="store_true")
    investigate.add_argument("--output", type=Path)
    for key in sorted(ATTESTATIONS):
        investigate.add_argument("--" + key.replace("_", "-"), action="store_true")
    commands.add_parser("executable-skills", help="List actual autonomous connector skills and input contracts")
    for verb in ("investigation-show", "investigation-run", "investigation-cancel", "investigation-export"):
        parser = commands.add_parser(verb)
        parser.add_argument("--case", required=True)
        parser.add_argument("--investigation", required=True)
        if verb in {"investigation-run", "investigation-cancel"}:
            parser.add_argument("--actor", required=True)
            parser.add_argument("--authorized", action="store_true")
        if verb == "investigation-run":
            parser.add_argument("--resume", action="store_true")
        if verb == "investigation-export":
            parser.add_argument("--output", required=True, type=Path)
    replay = commands.add_parser("verify-replay", help="Verify exported report, graph and evidence offline")
    replay.add_argument("--directory", required=True, type=Path)
    skills = commands.add_parser("skills", help="Search versioned analyst procedures")
    skills.add_argument("query", nargs="?", default="")
    skills.add_argument("--mode", choices=["osint", "pt"])
    tools = commands.add_parser("tools", help="Search all supplied tool candidates and their integration blockers")
    tools.add_argument("query", nargs="?", default="")
    tools.add_argument("--limit", type=int, default=20)
    knowledge = commands.add_parser("knowledge", help="Retrieve methodology and research metadata")
    knowledge.add_argument("query")
    knowledge.add_argument("--refresh", action="store_true", help="Fetch up to three fixed public methodology pages")
    assign = commands.add_parser("assign", help="Create a bounded research assignment for approval")
    assign.add_argument("--case", required=True)
    assign.add_argument("--objective", required=True)
    assign.add_argument("--mode", choices=["osint", "pt"], default="osint")
    assign.add_argument("--target-type", choices=sorted(COLLECTION))
    assign.add_argument("--target")
    assign.add_argument("--probe-http", action="store_true", help="Explicitly include one active httpx probe in the PT approval")
    for key in sorted(ATTESTATIONS):
        assign.add_argument("--" + key.replace("_", "-"), action="store_true")
    decide = commands.add_parser("decide", help="Approve/reject the exact assignment hash")
    decide.add_argument("--case", required=True)
    decide.add_argument("--task", required=True)
    decide.add_argument("--decision", required=True, choices=["approved", "rejected"])
    decide.add_argument("--plan-hash", required=True)
    decide.add_argument("--reviewer", required=True)
    decide.add_argument("--rationale", required=True)
    decide.add_argument("--authorized", action="store_true")
    run = commands.add_parser("run", help="Run a previously approved bounded assignment once")
    run.add_argument("--case", required=True)
    run.add_argument("--task", required=True)
    run.add_argument("--authorized", action="store_true")
    show = commands.add_parser("show", help="Show persisted plan, outcomes, brief and decisions")
    show.add_argument("--case", required=True)
    show.add_argument("--task", required=True)
    brief = commands.add_parser("brief", help="Analyze already stored case evidence without collection")
    brief.add_argument("--case", required=True)
    brief.add_argument("--objective", required=True)
    brief.add_argument("--mode", choices=["osint", "pt"], default="osint")
    brief.add_argument("--ollama", action="store_true", help="Add a locally generated, validated advisory draft")
    brief.add_argument("--model", default="qwen2.5:7b")
    brief.add_argument("--output", type=Path)
    review = commands.add_parser("review", help="Record a human decision on a stored brief; executes nothing")
    review.add_argument("--case", required=True)
    review.add_argument("--task", required=True)
    review.add_argument("--brief-digest", required=True)
    review.add_argument("--decision", required=True, choices=["accept-analysis", "reject-analysis", "request-evidence"])
    review.add_argument("--reviewer", required=True)
    review.add_argument("--rationale", required=True)
    review.add_argument("--authorized", action="store_true")


def run_employee(args, engine) -> dict:
    command = args.employee_command
    if command == "serve":
        from .console import serve
        serve(engine.workspace, args.port)
        return {"status": "console_stopped"}
    if command in {"investigate", "executable-skills", "verify-replay"} or command.startswith("investigation-"):
        from .autonomous import AutonomousInvestigator, executable_skills
        if command == "executable-skills":
            return {"skills": executable_skills(), "selection": "explicit-seed-and-authorization"}
        if command == "verify-replay":
            from .autonomous_analysis import verify_replay
            return verify_replay(args.directory)
        investigator = AutonomousInvestigator(engine.db, engine.workspace)
        if command == "investigate":
            seeds = []
            for value in args.seed:
                kind, separator, target = value.partition(":")
                if not separator:
                    raise ValueError("Seed must be type:value")
                seeds.append({"type": kind, "value": target})
            current = investigator.create(args.case, args.objective, seeds, actor=args.actor,
                attestations={key: getattr(args, key) for key in ATTESTATIONS}, authorized=args.authorized,
                subject_type=args.subject_type, subject_label=args.subject_label,
                max_actions=args.max_actions, runtime_seconds=args.runtime_seconds, hours=args.hours, model=args.model)
            if args.plan_only:
                return current
            # Emit the ID before collection so another local process can inspect/cancel it.
            import sys
            print("Investigation started: " + current["id"], file=sys.stderr, flush=True)
            current = investigator.run(args.case, current["id"], actor=args.actor, authorized=args.authorized)
            if args.output:
                current["export"] = investigator.export(args.case, current["id"], args.output)
            return current
        if command == "investigation-run":
            return investigator.run(args.case, args.investigation, actor=args.actor, authorized=args.authorized, resume=args.resume)
        if command == "investigation-cancel":
            return investigator.cancel(args.case, args.investigation, actor=args.actor, authorized=args.authorized)
        if command == "investigation-export":
            return investigator.export(args.case, args.investigation, args.output)
        return investigator.get(args.case, args.investigation)
    if command == "skills":
        return {"skills": skill_catalog(args.query, args.mode), "type": "analyst-procedures"}
    if command == "tools":
        return tool_candidates(args.query, args.limit)
    if command == "knowledge":
        library = KnowledgeLibrary(engine.db)
        refreshed = library.refresh() if args.refresh else []
        return {**library.search(args.query), "refresh": refreshed}
    employee = EmployeeService(engine.db, engine.workspace)
    if command == "assign":
        return employee.assign(args.case, args.objective, mode=args.mode, target_type=args.target_type,
                               target=args.target, probe_http=args.probe_http,
                               attestations={key: getattr(args, key) for key in ATTESTATIONS})
    if command == "decide":
        return employee.decide(args.case, args.task, args.decision, reviewer=args.reviewer,
                               rationale=args.rationale, expected_plan_hash=args.plan_hash, authorized=args.authorized)
    if command == "run":
        return employee.run(args.case, args.task, authorized=args.authorized)
    if command == "show":
        return employee.get(args.case, args.task)
    if command == "review":
        return employee.review(args.case, args.task, args.decision, reviewer=args.reviewer,
                               rationale=args.rationale, brief_digest=args.brief_digest, authorized=args.authorized)
    result = employee.brief(args.case, args.objective, mode=args.mode, use_ollama=args.ollama, model=args.model)
    if args.output:
        return {"report": employee.export(result, args.output), "summary": result["summary"]}
    return result
