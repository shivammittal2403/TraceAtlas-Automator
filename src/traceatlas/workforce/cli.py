"""CLI for the feature-flagged bounded workforce vertical slice."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from pathlib import Path

from .contracts import AuthorizationContext, SCHEMA_VERSION
from .registry import EmployeeRegistry
from .service import WorkforceService
from .documents import normalize_seed, load_documents
from .pipeline import InvestigationPipeline


TOOLS = ("dns.lookup", "rdap.lookup", "archive.lookup", "search.execute", "ip.lookup", "evidence.retrieve")
ACTIONS = ("request_collection", "propose_observation", "propose_claim")


def add_workforce_parser(sub) -> None:
    root = sub.add_parser("workforce", help="Bounded hybrid AI workforce; disabled unless explicitly enabled")
    commands = root.add_subparsers(dest="workforce_command", required=True)
    commands.add_parser("registry", help="List the five initial employee definitions")
    authorize = commands.add_parser("authorize-domain", help="Register an immutable local owned-domain authority")
    authorize.add_argument("--case", required=True)
    authorize.add_argument("--domain", required=True)
    authorize.add_argument("--actor", required=True)
    authorize.add_argument("--purpose", required=True)
    authorize.add_argument("--jurisdiction", required=True)
    authorize.add_argument("--retention", default="case-standard")
    authorize.add_argument("--hours", type=int, default=24)
    authorize.add_argument("--authorized", action="store_true")
    auth = commands.add_parser("authorize", help="Register exact authority for domain/IP or approved person/company records")
    for option in ("case", "target", "actor", "purpose", "jurisdiction"):
        auth.add_argument("--" + option, required=True)
    auth.add_argument("--target-type", choices=("domain", "ip", "person", "company"), required=True)
    auth.add_argument("--retention", default="case-standard")
    auth.add_argument("--hours", type=int, default=24)
    auth.add_argument("--authorized", action="store_true")
    generic = commands.add_parser("plan", help="Plan a bounded typed investigation")
    generic.add_argument("--context", required=True)
    generic.add_argument("--target-type", choices=("domain", "ip", "person", "company"), required=True)
    generic.add_argument("--target", required=True)
    generic.add_argument("--objective", required=True)
    collect = commands.add_parser("run", help="Execute approved collection, verification and draft reporting")
    collect.add_argument("--task", required=True)
    modes = collect.add_mutually_exclusive_group(required=True)
    modes.add_argument("--documents", type=Path, help="Approved source-document JSON")
    modes.add_argument("--live", action="store_true", help="Fixed-host owned-domain/IP collection")
    collect.add_argument("--authorized", action="store_true")
    replay = commands.add_parser("replay", help="Verify and reanalyse captured bytes without network/model calls")
    replay.add_argument("--task", required=True)
    report = commands.add_parser("report", help="Return immutable investigation draft")
    report.add_argument("--task", required=True)
    commands.add_parser("golden", help="Execute G01-G12 controlled end-to-end investigations")
    plan = commands.add_parser("plan-domain", help="Create a bounded owned-domain task")
    plan.add_argument("--context", required=True)
    plan.add_argument("--domain", required=True)
    plan.add_argument("--objective", required=True)
    approve = commands.add_parser("approve", help="Approve the exact immutable task digest")
    approve.add_argument("--task", required=True)
    approve.add_argument("--actor", required=True)
    approve.add_argument("--envelope-digest", required=True)
    approve.add_argument("--rationale", required=True)
    approve.add_argument("--authorized", action="store_true")
    run = commands.add_parser("run-fallback", help="Complete an approved task without a model or network call")
    run.add_argument("--task", required=True)
    run.add_argument("--authorized", action="store_true")
    show = commands.add_parser("show", help="Show one workforce task and validated result")
    show.add_argument("--task", required=True)


def run_workforce(args, engine) -> dict:
    if args.workforce_command == "registry":
        return {"employees": [item.to_dict() for item in EmployeeRegistry().list()], "count": 5}
    if args.workforce_command == "golden":
        from .golden import evaluate_pipeline_investigations
        return evaluate_pipeline_investigations()
    service = WorkforceService(engine.db)
    if args.workforce_command in {"authorize-domain", "authorize"}:
        if not args.authorized:
            raise ValueError("authority registration requires explicit --authorized confirmation")
        if not 1 <= args.hours <= 168:
            raise ValueError("authorization duration must be 1-168 hours")
        kind = "domain" if args.workforce_command == "authorize-domain" else args.target_type
        domain = normalize_seed(kind, args.domain if kind == "domain" and args.workforce_command == "authorize-domain" else args.target)
        now = datetime.now(timezone.utc)
        effective_tools = {"domain": ("dns.lookup", "rdap.lookup", "archive.lookup", "evidence.retrieve"),
                           "ip": ("rdap.lookup", "ip.lookup", "evidence.retrieve"),
                           "person": ("evidence.retrieve",), "company": ("evidence.retrieve",)}[kind]
        body = {"case": args.case, "target_type": kind, "target": domain, "tools": effective_tools, "actor": args.actor, "purpose": args.purpose,
                "jurisdiction": args.jurisdiction, "retention": args.retention, "issued_at": now.isoformat()}
        context = AuthorizationContext(
            schema_version=SCHEMA_VERSION, context_id="auth-" + uuid4().hex, case_id=args.case,
            actor_id=args.actor, lawful_purpose=args.purpose, scope=(kind + ":" + domain,),
            allowed_actions=ACTIONS, allowed_tools=effective_tools, jurisdiction=args.jurisdiction,
            retention_policy=args.retention, issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=args.hours)).isoformat(),
            policy_digest=hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(),
        )
        service.register_authorization(context)
        return {"authorization": context.to_dict(), "execution_enabled": service.enabled}
    if args.workforce_command == "plan-domain":
        return service.create_owned_domain_task(args.context, args.domain, args.objective)
    if args.workforce_command == "plan":
        return service.create_investigation_task(args.context, args.target_type, args.target, args.objective)
    pipeline = InvestigationPipeline(service, engine.workspace)
    if args.workforce_command == "run":
        documents = load_documents(args.documents) if args.documents else ()
        return pipeline.run(args.task, documents=documents, live=args.live, authorized=args.authorized)
    if args.workforce_command == "report":
        pipeline.replay(args.task)  # Refuse an export after byte/metadata tampering.
        return service.store.product(args.task)
    if args.workforce_command == "replay":
        return pipeline.replay(args.task)
    if args.workforce_command == "approve":
        return service.approve(args.task, actor_id=args.actor, rationale=args.rationale,
                               envelope_digest=args.envelope_digest, authorized=args.authorized)
    if args.workforce_command == "run-fallback":
        return service.execute(args.task, lambda *_: service.deterministic_no_model_result(args.task),
                               authorized=args.authorized)
    return service.describe(args.task)
