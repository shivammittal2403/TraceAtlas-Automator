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
